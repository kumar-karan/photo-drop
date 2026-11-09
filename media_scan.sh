#!/data/data/com.termux/files/usr/bin/bash
# media_scan.sh — tell Android's MediaProvider that a file exists.
#
# Google Photos does not walk the filesystem. It queries MediaStore. So a file
# written to /storage/emulated/0/DCIM/... is invisible to Google Photos (and to
# Samsung Gallery) until MediaProvider is notified. This script escalates
# through the known techniques, most reliable first, and reports which one stuck
# — so the owner dashboard can tell us what actually works on this device.
#
# Usage:
#   media_scan.sh <file> [<file> ...]   scan each file
#   media_scan.sh --selftest            report which techniques are available
#
# Exit: 0 if some technique was believed to have worked, 1 otherwise.

set -uo pipefail

SELFTEST=0
if [[ "${1:-}" == "--selftest" ]]; then
  SELFTEST=1
  shift
fi

# termux-media-scan shells out to the Termux:API Android app. If that app is
# missing (or installed from a different source, so signatures mismatch) the
# command HANGS instead of failing. Always run it under a timeout.
run_bounded() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 12 "$@"
  else
    "$@" &
    local p=$!
    ( sleep 12; kill -9 "$p" 2>/dev/null ) &
    local w=$!
    wait "$p" 2>/dev/null; local rc=$?
    kill -9 "$w" 2>/dev/null
    return $rc
  fi
}

have_termux_api=0; command -v termux-media-scan >/dev/null 2>&1 && have_termux_api=1
have_am=0;         command -v am          >/dev/null 2>&1 && have_am=1
have_content=0;    command -v content     >/dev/null 2>&1 && have_content=1
have_timeout=0;    command -v timeout     >/dev/null 2>&1 && have_timeout=1

# Is this a Samsung? Their media provider exposes an extra MTP scan broadcast
# that is more reliable than the generic one on some Galaxy models.
is_samsung=0
getprop ro.product.manufacturer 2>/dev/null | grep -qi samsung && is_samsung=1
[[ -n "${ANDROID_MANUFACTURER:-}" ]] && is_samsung=1

if (( SELFTEST )); then
  echo "termux-media-scan : $( ((have_termux_api)) && echo yes || echo no)"
  echo "am (broadcast)    : $( ((have_am)) && echo yes || echo no)"
  echo "content (call)    : $( ((have_content)) && echo yes || echo no)"
  echo "timeout           : $( ((have_timeout)) && echo yes || echo no)"
  echo "samsung extras    : $( ((is_samsung)) && echo yes || echo no)"
  echo "storage linked    : $( [[ -d /storage/emulated/0/DCIM ]] && echo yes || echo no)"
  exit 0
fi

[[ $# -eq 0 ]] && { echo "usage: media_scan.sh <file>..." >&2; exit 2; }

ok=0
for f in "$@"; do
  [[ -f "$f" ]] || continue
  done_scan=0

  # 1. Termux:API — the documented route, usually the most reliable.
  if (( have_termux_api )); then
    if run_bounded termux-media-scan "$f" >/dev/null 2>&1; then
      echo "scanned(termux-api): $f" >&2; ok=1; done_scan=1
    fi
  fi

  # 2. Samsung's MTP scan broadcast, when present.
  if (( !done_scan && is_samsung && have_am )); then
    if am broadcast \
        -a com.samsung.intent.action.MTP_FILE_SCAN \
        -n com.android.providers.media/.MediaScannerReceiver \
        -d "file://$f" >/dev/null 2>&1; then
      echo "scanned(samsung-mtp): $f" >&2; ok=1; done_scan=1
    fi
  fi

  # 3. The legacy MEDIA_SCANNER_SCAN_FILE broadcast. Restricted since
  #    Android 10 but still accepted on plenty of devices.
  if (( !done_scan && have_am )); then
    if am broadcast \
        -a android.intent.action.MEDIA_SCANNER_SCAN_FILE \
        -d "file://$f" >/dev/null 2>&1; then
      echo "scanned(am-broadcast): $f" >&2; ok=1; done_scan=1
    fi
  fi

  # 4. Call MediaProvider's hidden scan_file method directly. SCAN_FILE_CALL is
  #    literally "scan_file" in MediaStore.java. external_primary is the
  #    non-removable volume; external covers all volumes.
  if (( !done_scan && have_content )); then
    for vol in external/file external_primary/file; do
      if content call \
          --uri "content://media/$vol" \
          --method scan_file \
          --arg "$f" >/dev/null 2>&1; then
        echo "scanned(content-call:$vol): $f" >&2; ok=1; done_scan=1; break
      fi
    done
  fi

  (( done_scan )) || echo "scan-failed(no-method-worked): $f" >&2
done

exit $(( ok ? 0 : 1 ))