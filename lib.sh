#!/data/data/com.termux/files/usr/bin/bash
# lib.sh — process helpers shared by start.sh, stop.sh and pd-control.sh.
#
# Termux's toybox pkill/pgrep cannot see setsid'd Python processes, so the
# obvious "pkill -f" cleanup misses the server and leaves it holding :8080.
# Everything here scans /proc directly and is safe to source from the scripts.

# Print PIDs whose command line contains $1. The kill_matching exclusion avoids
# matching the helper shell itself, whose command line contains the needle.
pids_matching() {
  local needle="$1" d cmd
  for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
    case "$cmd" in
      *"$needle"*)
        case "$cmd" in *kill_matching*) continue ;; esac
        echo "${d#/proc/}" ;;
    esac
  done 2>/dev/null
}

kill_matching() {
  local needle="$1"; shift
  local p
  for p in $(pids_matching "$needle"); do
    kill "$@" "$p" 2>/dev/null || true
  done
}

# TERM, grace period, then SIGKILL any survivors. Returns only once /proc no
# longer shows a matching process, so the next start cannot race a stale one.
ensure_dead() {
  local needle="$1"
  kill_matching "$needle"
  local tries=0
  while [ "$tries" -lt 20 ]; do
    [ -z "$(pids_matching "$needle")" ] && break
    sleep 0.2
    tries=$((tries + 1))
  done
  if [ -n "$(pids_matching "$needle")" ]; then
    kill_matching "$needle" -9
  fi
  tries=0
  while [ "$tries" -lt 20 ]; do
    [ -z "$(pids_matching "$needle")" ] && break
    sleep 0.2
    tries=$((tries + 1))
  done
}

# Shut down the heartbeat watchdog started by pd-control.sh.
# Its command line contains "HB=", but pids_matching excludes anything whose
# command line contains "kill_matching", which would also exclude the watchdog.
stop_watchdog() {
  local d cmd
  for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
    case "$cmd" in
      *"HB="*) kill -9 "${d#/proc/}" 2>/dev/null || true ;;
    esac
  done 2>/dev/null
}

# The watchdog itself is a bash -c child, so these need to be exported for it.
export -f pids_matching kill_matching ensure_dead 2>/dev/null || true
