#!/data/data/com.termux/files/usr/bin/bash
# stop.sh — shut everything down and release the wake lock.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for _lib in "$DIR/lib.sh" "$HOME/photo-drop/lib.sh" "/sdcard/photo-drop/lib.sh"; do
  if [[ -f "$_lib" ]]; then
    # shellcheck disable=SC1090
    . "$_lib"
    break
  fi
done
if ! command -v ensure_dead >/dev/null 2>&1; then
  echo "lib.sh is missing next to stop.sh — copy the whole photo-drop directory." >&2
  exit 1
fi

ensure_dead 'photo-drop/server.py'
ensure_dead 'cloudflared tunnel'
stop_watchdog

termux-wake-unlock 2>/dev/null || true
rm -f "$HOME/.photo-drop/url" \
      "/sdcard/Android/data/dev.photodrop.app/files/public-url.txt" \
      "/sdcard/Android/data/dev.photodrop.app/files/heartbeat" 2>/dev/null || true

echo "stopped."
echo "upload history is still in $HOME/.photo-drop/logs/server.log"
