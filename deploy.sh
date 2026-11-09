#!/usr/bin/env bash
# deploy.sh — push Photo Drop onto a USB-connected Android phone.
#
#   ./deploy.sh          push the files and print the command to run in Termux
#   ./deploy.sh --run    also try to launch install.sh over adb via Termux's
#                        RUN_COMMAND intent (needs the permission granted once)
#
# Run this from the repo's apps/photo-drop directory.

set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="/sdcard/photo-drop"
WANT_RUN=0
[[ "${1:-}" == "--run" ]] && WANT_RUN=1

say() { printf '\033[1m%s\033[0m\n' "$1"; }
die() { printf 'error: %s\n' "$1" >&2; exit 1; }

# --- pick a device ---------------------------------------------------------
SERIAL="$(adb devices | awk 'NR>1 && $2=="device" {print $1}')"
COUNT="$(printf '%s\n' "$SERIAL" | grep -c . || true)"

if [[ -z "$SERIAL" ]]; then
  die "no device. Plug in USB and accept the 'Allow USB debugging?' prompt on the phone."
fi
if [[ "$COUNT" -gt 1 ]]; then
  die "more than one device attached. Disconnect the extras, or pass ADB_SERIAL=..."
fi

say "1/5  device"
echo "  $SERIAL"
MODEL="$(adb -s "$SERIAL" shell getprop ro.product.model | tr -d '\r')"
ANDROID="$(adb -s "$SERIAL" shell getprop ro.build.version.release | tr -d '\r')"
SDK="$(adb -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"
echo "  $MODEL, Android $ANDROID (API $SDK)"

# --- sanity check Termux ---------------------------------------------------
if ! adb -s "$SERIAL" shell pm list packages 2>/dev/null | grep -q '^package:com.termux$'; then
  die "Termux is not installed (com.termux missing). Install it first from F-Droid."
fi
say "2/5  Termux present"

# --- push ------------------------------------------------------------------
say "3/5  uploading files"
adb -s "$SERIAL" shell rm -rf "$STAGE" >/dev/null 2>&1
adb -s "$SERIAL" shell mkdir -p "$STAGE" >/dev/null 2>&1
for f in server.py media_scan.sh install.sh start.sh stop.sh pd-control.sh README.md LICENSE .gitignore; do
  adb -s "$SERIAL" push -q "$SRC/$f" "$STAGE/$f" >/dev/null || die "push failed: $f"
done
adb -s "$SERIAL" push -q "$SRC/tests" "$STAGE/tests" >/dev/null || die "push failed: tests/"
echo "  $(ls -1 "$SRC" | wc -l | tr -d ' ') files + tests/"

# Termux cannot read /sdcard directly; it needs them under its own home.
say "4/5  next step on the phone"

RUN_ME='mkdir -p ~/photo-drop && cp -r /sdcard/photo-drop/. ~/photo-drop/ && chmod +x ~/photo-drop/*.sh && bash ~/photo-drop/install.sh'
SHORT="${RUN_ME:0:60}..."

if (( WANT_RUN )); then
  say "5/5  launching install over adb"
  # Termux's RUN_COMMAND service. Will fail unless the permission was granted
  # previously; fall back to doing it by hand.
  if adb -s "$SERIAL" shell am start -n com.termux/.app.RunCommandService \
      -a com.termux.RUN_COMMAND --es com.termux.RUN_COMMAND_PATH '/data/data/com.termux/files/usr/bin/bash' \
      --esa com.termux.RUN_COMMAND_ARGUMENTS "$SHORT" \
      --ez com.termux.RUN_COMMAND_BACKGROUND false >/dev/null 2>&1; then
    echo "  sent. Watch the phone: it will ask for storage permission."
  else
    echo "  could not launch. Run it by hand instead."
  fi
else
  echo "5/5  skipped (pass --run to try automating this step)"
fi

cat <<EOF

  Open Termux on the phone and run:

    $SHORT

  It will ask for storage permission once. Tap ALLOW.

  Then start it:

    bash ~/photo-drop/start.sh --tunnel

  Keep the phone plugged in and set
  Settings -> Apps -> Termux -> Battery -> Unrestricted.

EOF