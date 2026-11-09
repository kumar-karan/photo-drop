#!/data/data/com.termux/files/usr/bin/bash
# pd-control.sh — the control surface the Photo Drop app drives.
#
# The app never touches Termux's files directly (it cannot read them), so this
# script is the bridge. It also copies the tunnel URL into the app's own
# external files dir, which the app *can* read.
#
#   pd-control.sh bootstrap <drop_token> <owner_token>
#   pd-control.sh start
#   pd-control.sh stop
#   pd-control.sh url

set -uo pipefail

HOME_DIR="/data/data/com.termux/files/home"
APP="$HOME_DIR/photo-drop"
STATE="$HOME_DIR/.photo-drop"
ENVF="$STATE/env"
VENV="$STATE/venv/bin/python"
LOGS="$STATE/logs"
EXPORT="/sdcard/Android/data/dev.photodrop.app/files"

mkdir -p "$STATE" "$LOGS"
[ -d "$EXPORT" ] || mkdir -p "$EXPORT" 2>/dev/null

# Shared /proc process helpers. The app runs this script from $HOME, while the
# checkout lives in $HOME/photo-drop, so try both locations.
for _lib in "$HOME/photo-drop/lib.sh" "/sdcard/photo-drop/lib.sh" "$(dirname "$0")/lib.sh"; do
  if [[ -f "$_lib" ]]; then
    # shellcheck disable=SC1090
    . "$_lib"
    break
  fi
done
if ! command -v ensure_dead >/dev/null 2>&1; then
  echo "lib.sh is missing — copy the whole photo-drop directory to ~/photo-drop." >&2
  exit 1
fi

cmd="${1:-}"

start_watchdog() {
  # Shuts the server and tunnel down when the app stops claiming them.
  #
  # The app's foreground service writes a heartbeat every 5s. If it goes stale
  # the service is gone, which means the task was swiped away or Android killed
  # us, and the user believes the server is off. An upload endpoint that keeps
  # serving after the app looks closed is the failure worth engineering against.
  #
  # The old heartbeat is cleared first so the watchdog cannot age out against a
  # timestamp left by a previous session. Until the app writes a new one the
  # watchdog waits, which is correct: a server started by hand from a shell is
  # not owned by the app and should not be killed by it.
  rm -f "$EXPORT/heartbeat" 2>/dev/null
  setsid bash -c '
    HB="/sdcard/Android/data/dev.photodrop.app/files/heartbeat"
    LIMIT=30
    while true; do
      sleep 10
      # No heartbeat ever appeared: the app has not claimed ownership yet.
      [ -f "$HB" ] || continue
      NOW=$(date +%s)
      THEN=$(stat -c %Y "$HB" 2>/dev/null || echo 0)
      AGE=$(( NOW - THEN ))
      if [ "$AGE" -gt "$LIMIT" ]; then
        kill_matching "photo-drop/server.py"
        kill_matching "cloudflared tunnel"
        exit 0
      fi
    done
  ' >"$LOGS/watchdog.log" 2>&1 < /dev/null &
  disown 2>/dev/null
}

case "$cmd" in
  bootstrap)
    DROP="${2:-}"
    OWNER="${3:-}"
    # The app owns the tokens: it mints them, persists them, and passes them
    # here. Termux env is derived state, so writing it is safe.
    if [[ -n "$DROP" && -n "$OWNER" ]]; then
      # Remember what the server is currently using.
      OLD=""
      if [[ -f "$ENVF" ]]; then
        OLD="$(grep '^PHOTO_DROP_TOKEN=' "$ENVF" 2>/dev/null | cut -d= -f2-)"
      fi

      # What the RUNNING process actually holds. The log appends across
      # restarts, so the LAST match is the current process — grep -m1 would
      # read a token from a previous run and wrongly conclude no restart is
      # needed.
      RUNNING=""
      if [[ -f "$LOGS/server.log" ]]; then
        RUNNING="$(grep -oE ':8080/d/[^ ]+' "$LOGS/server.log" 2>/dev/null | tail -1 | cut -d/ -f3)"
      fi

      cat > "$ENVF" <<EOF
PHOTO_DROP_TOKEN=$DROP
PHOTO_DROP_OWNER_TOKEN=$OWNER
PHOTO_DROP_DIR=/storage/emulated/0/DCIM/PhotoDrop
PHOTO_DROP_PORT=8080
PHOTO_DROP_HOST=127.0.0.1
PHOTO_DROP_RESERVE_BYTES=2147483648
EOF
      chmod 600 "$ENVF"
      # Restart only when the running process is holding a different secret.
      # OLD is what the env had; RUNNING is what the process logged. Either
      # one disagreeing means the app's token would 404 against the server,
      # which is exactly the "owner dashboard is broken" failure.
      NEEDS_RESTART=0
      if [ -n "$(pids_matching 'photo-drop/server.py')" ]; then
        if [[ -n "$RUNNING" && "$RUNNING" != "$DROP" ]]; then NEEDS_RESTART=1; fi
        if [[ -n "$OLD" && "$OLD" != "$DROP" ]]; then NEEDS_RESTART=1; fi
      fi
      if [[ "$NEEDS_RESTART" == "1" ]]; then
        ensure_dead 'photo-drop/server.py'
        export PATH="/data/data/com.termux/files/usr/bin:$PATH"
        ( set -a; . "$ENVF"; set +a
          setsid "$VENV" "$APP/server.py" > "$LOGS/server.log" 2>&1 < /dev/null &
          disown 2>/dev/null ) >/dev/null 2>&1
        echo "env written; server restarted with the new token"
      else
        echo "env written"
      fi
      exit 0
    fi
    echo "usage: pd-control.sh bootstrap <drop_token> <owner_token>" >&2
    exit 2
    ;;

  start)
    set -a; . "$ENVF" 2>/dev/null; set +a
    export PATH="/data/data/com.termux/files/usr/bin:$PATH"

    if [[ ! -x "$VENV" ]]; then
      echo "venv missing. Run install.sh in ~/photo-drop first." >&2
      exit 1
    fi
    ensure_dead 'photo-drop/server.py'
    termux-wake-lock 2>/dev/null || true

    setsid "$VENV" "$APP/server.py" > "$LOGS/server.log" 2>&1 < /dev/null &
    disown 2>/dev/null

    # Give it a moment, then bring up the tunnel so the link is shareable.
    for _ in $(seq 1 20); do
      curl -fsS "http://127.0.0.1:8080/healthz" >/dev/null 2>&1 && break
      sleep 0.5
    done

    if command -v cloudflared >/dev/null 2>&1; then
      rm -f "$EXPORT/public-url.txt" "$STATE/url" 2>/dev/null || true
      kill_matching 'cloudflared tunnel' || true
      setsid cloudflared tunnel --no-autoupdate \
        --protocol http2 --edge-ip-version 4 \
        --url http://127.0.0.1:8080 > "$LOGS/cloudflared.log" 2>&1 < /dev/null &
      disown 2>/dev/null

      echo "negotiating a public address"
      (
        for _ in $(seq 1 60); do
          URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOGS/cloudflared.log" 2>/dev/null | tail -1)"
          if [[ -n "$URL" ]]; then
            printf '%s' "$URL" > "$STATE/url"
            chmod 644 "$STATE/url" 2>/dev/null || true
            printf '%s' "$URL" > "$EXPORT/public-url.txt" 2>/dev/null || true
            chmod 644 "$EXPORT/public-url.txt" 2>/dev/null || true
            break
          fi
          sleep 1
        done
      ) &
      disown 2>/dev/null
    fi

    start_watchdog
    ;;

  stop)
    ensure_dead 'photo-drop/server.py'
    ensure_dead 'cloudflared tunnel'
    stop_watchdog
    sleep 0.5
    termux-wake-unlock 2>/dev/null || true
    rm -f "$EXPORT/public-url.txt" "$STATE/url" "$EXPORT/heartbeat" 2>/dev/null || true
    echo "stopped"
    ;;

  url)
    [[ -f "$EXPORT/public-url.txt" ]] && cat "$EXPORT/public-url.txt" && echo
    ;;

  *)
    echo "usage: pd-control.sh {bootstrap|start|stop|url}" >&2
    exit 2
    ;;
esac
