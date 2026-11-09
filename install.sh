#!/data/data/com.termux/files/usr/bin/bash
# install.sh — one-time setup for Photo Drop inside Termux.
#
# Safe to re-run. Everything it installs is idempotent.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$HOME/.photo-drop"
VENV="$STATE/venv"

banner() { printf '\n\033[1m%s\033[0m\n' "$1"; }

banner "1/6  packages"
pkg update -y >/dev/null 2>&1 || true
for p in python termux-api cloudflared; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    echo "  installing $p"
    pkg install -y "$p" >/dev/null
  else
    echo "  $p already installed"
  fi
done

# cloudflared must come from Termux's repo. The upstream linux-arm64 static
# binary is linked against glibc; Termux is bionic, so it will not run.
if cloudflared --version >/dev/null 2>&1; then
  echo "  cloudflared: $(cloudflared --version 2>&1 | head -1)"
else
  echo "  !! cloudflared unusable — the public link will not work"
fi

banner "2/6  python environment"
# Termux python is PEP 668 externally-managed, so a bare `pip install` is
# refused. A venv is the clean way through.
if [[ ! -x "$VENV/bin/python" ]]; then
  python -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/python" -m pip install --quiet flask
"$VENV/bin/python" - <<'PY'
from importlib.metadata import version
print(f"  flask {version('flask')} in venv")
PY

banner "3/6  storage permission"
if [[ ! -e "$HOME/storage" ]]; then
  echo "  granting shared-storage access — tap ALLOW on the next dialog..."
  termux-setup-storage || true
fi
if [[ -d /storage/emulated/0/DCIM ]]; then
  echo "  shared storage OK"
else
  echo "  !! /storage/emulated/0/DCIM unreachable."
  echo "     Run 'termux-setup-storage' manually and grant access, then re-run this."
  exit 1
fi

banner "4/6  Termux:API app"
# termux-media-scan shells out to the companion APK. If that APK is missing the
# command hangs forever rather than failing, so probe it with a timeout.
if command -v termux-media-scan >/dev/null 2>&1; then
  if timeout 8 termux-media-scan >/dev/null 2>&1; then
    echo "  termux-media-scan responds"
  else
    echo "  !! termux-media-scan did not respond."
    echo "     Install the 'Termux:API' ANDROID APP from the SAME source you"
    echo "     installed Termux from (F-Droid->F-Droid, Play->Play). A mismatch"
    echo "     means a different signature and termux-media-scan will hang."
  fi
else
  echo "  !! termux-media-scan not on PATH"
fi

banner "5/6  tokens and destination"
mkdir -p "$STATE"
ENVFILE="$STATE/env"
if [[ ! -f "$ENVFILE" ]]; then
  "$VENV/bin/python" - <<'PY' > "$ENVFILE"
import secrets
print(f"PHOTO_DROP_TOKEN={secrets.token_urlsafe(18)}")
print(f"PHOTO_DROP_OWNER_TOKEN={secrets.token_urlsafe(18)}")
print(f"PHOTO_DROP_DIR=/storage/emulated/0/DCIM/PhotoDrop")
print(f"PHOTO_DROP_PORT=8080")
print(f"PHOTO_DROP_HOST=127.0.0.1")
print(f"PHOTO_DROP_RESERVE_BYTES={2 * 1024**3}")
PY
  echo "  generated $ENVFILE"
else
  echo "  keeping existing $ENVFILE"
fi

mkdir -p /storage/emulated/0/DCIM/PhotoDrop
echo "  destination ready: /storage/emulated/0/DCIM/PhotoDrop"

banner "6/6  media scan capability probe"
bash "$DIR/media_scan.sh" --selftest

banner "done — start it with"
echo "  bash $DIR/start.sh --tunnel"
echo
echo "Keep the phone awake and unplugged-optimised: Settings -> Apps ->"
echo "Termux -> Battery -> Unrestricted."