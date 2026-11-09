#!/data/data/com.termux/files/usr/bin/bash
# stop.sh — shut everything down and release the wake lock.
set -uo pipefail

pkill -f 'photo-drop/server.py' 2>/dev/null
pkill -f 'cloudflared tunnel'    2>/dev/null
sleep 1

termux-wake-unlock 2>/dev/null || true
rm -f "$HOME/.photo-drop/url"

echo "stopped."
echo "photos are still in $HOME/.photo-drop/logs/server.log for the record."