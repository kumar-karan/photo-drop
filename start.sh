#!/data/data/com.termux/files/usr/bin/bash
# start.sh — bring up the drop server and put a public link in front of it.
#
#   bash start.sh          local only (for testing on your own Wi-Fi)
#   bash start.sh --tunnel also expose it on the internet via Cloudflare

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVFILE="$HOME/.photo-drop/env"
URLFILE="$HOME/.photo-drop/url"
LOGDIR="$HOME/.photo-drop/logs"
WANT_TUNNEL=0
[[ "${1:-}" == "--tunnel" ]] && WANT_TUNNEL=1

mkdir -p "$HOME/.photo-drop" "$LOGDIR"

if [[ ! -f "$ENVFILE" ]]; then
  echo "No $ENVFILE — run install.sh first." >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENVFILE"; set +a

DEST="${PHOTO_DROP_DIR:-/storage/emulated/0/DCIM/PhotoDrop}"
PORT="${PHOTO_DROP_PORT:-8080}"
VENV="$HOME/.photo-drop/venv"
mkdir -p "$DEST"

# Prefer the venv created by install.sh — a bare `pip install` is refused by
# Termux's PEP 668 guard.
PY="python"
[[ -x "$VENV/bin/python" ]] && PY="$VENV/bin/python"

# Keep the phone awake for the session. Several hours plugged in is fine;
# without this Android will doze the process and uploads will stall.
termux-wake-lock 2>/dev/null || true

# --- stop anything left over from a previous run ----------------------------
pkill -f 'photo-drop/server.py' 2>/dev/null
pkill -f 'cloudflared tunnel'    2>/dev/null
sleep 1

# --- the server ------------------------------------------------------------
"$PY" "$DIR/server.py" >>"$LOGDIR/server.log" 2>&1 &
echo $! > "$HOME/.photo-drop/server.pid"

printf 'waiting for the server'
for _ in $(seq 1 30); do
  if curl -fsS -H "X-PD-Token: $PHOTO_DROP_TOKEN" "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then break; fi
  printf '.'; sleep 0.5
done
echo

if ! curl -fsS -H "X-PD-Token: $PHOTO_DROP_TOKEN" "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  echo "Server did not come up. Last 30 log lines:" >&2
  tail -30 "$LOGDIR/server.log" >&2
  exit 1
fi

LOCAL="http://127.0.0.1:$PORT/d/$PHOTO_DROP_TOKEN"
echo
echo "  local : $LOCAL"
echo "  owner : http://127.0.0.1:$PORT/owner/$PHOTO_DROP_OWNER_TOKEN"

# --- optional public tunnel ------------------------------------------------
if (( WANT_TUNNEL )); then
  # Only the Termux-packaged cloudflared works here — the upstream static
  # linux-arm64 binary needs glibc and Termux is bionic.
  CF="$(command -v cloudflared || true)"

  if [[ -z "$CF" ]] || ! cloudflared --version >/dev/null 2>&1; then
    echo
    echo "  cloudflared is missing or unusable — no public link."
    echo "  Fix with:  pkg install cloudflared"
    echo "  The local link below still works on this Wi-Fi."
    exit 0
  fi

  rm -f "$URLFILE"

  # --protocol http2 + --edge-ip-version 4 works around Android's resolver
  # returning addresses cloudflared can't dial (cloudflare/cloudflared#793).
  "$CF" tunnel --no-autoupdate \
      --protocol http2 --edge-ip-version 4 \
      --url "http://127.0.0.1:$PORT" \
      >>"$LOGDIR/cloudflared.log" 2>&1 &

  echo "negotiating a public address"
  PUBLIC=""
  for _ in $(seq 1 60); do
    if [[ -s "$URLFILE" ]]; then
      PUBLIC="$(cat "$URLFILE")"
      break
    fi
    # cloudflared prints the hostname; harvest it as a fallback.
    PUBLIC="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOGDIR/cloudflared.log" 2>/dev/null | tail -1)"
    [[ -n "$PUBLIC" ]] && break
    printf '.'; sleep 1
  done
  echo

  if [[ -z "$PUBLIC" ]]; then
    echo "  Tunnel did not produce a URL. See $LOGDIR/cloudflared.log" >&2
    echo "  The local link still works on this Wi-Fi." >&2
    exit 0
  fi

  echo "$PUBLIC" > "$URLFILE"
  echo
  echo "  ╭──────────────────────────────────────────╮"
  printf '  │  %-40s  │\n' "SEND THIS TO YOUR FRIEND"
  echo "  ├──────────────────────────────────────────┤"
  printf '  │  %-40s  │\n' "$PUBLIC/d/$PHOTO_DROP_TOKEN"
  echo "  ╰──────────────────────────────────────────╯"
  echo
  echo "  This link is the password. Anyone who has it can upload."
  # Path form, not ?k= — query strings leak into logs and Referer headers.
  echo "  Owner dashboard: $PUBLIC/owner/$PHOTO_DROP_OWNER_TOKEN"
fi