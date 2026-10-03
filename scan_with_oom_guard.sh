#!/bin/bash
# scan_with_oom_guard.sh <logfile> <command...>
# Runs the scanner, KILLS it immediately on any OOM/CUDA error,
# and samples GPU memory every 10s into <logfile>.vram
set -u
LOG="$1"; shift
rm -f "${LOG}.oom"
"$@" > "$LOG" 2>&1 &
PID=$!
while kill -0 "$PID" 2>/dev/null; do
  if grep -qE "out of memory|CUDA error|CUDA out|malloc.*failed|\bOOM\b" "$LOG" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    sleep 2
    kill -9 "$PID" 2>/dev/null
    echo "OOM DETECTED at $(date '+%F %T')" > "${LOG}.oom"
    break
  fi
  nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits >> "${LOG}.vram" 2>/dev/null
  sleep 10
done
wait "$PID"
rc=$?
if [ -f "${LOG}.oom" ]; then
  echo "WATCHDOG: OOM detected - scan was STOPPED"
  exit 99
fi
exit $rc
