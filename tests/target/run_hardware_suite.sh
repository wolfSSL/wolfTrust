#!/usr/bin/env bash
# Run a port's hardware scenarios through the shared hardware runner, holding
# the board lock for the whole batch, and report them like the emulator suite:
# RUN/PASS/FAIL per scenario, the tagged "  [check] " lines, the log path and
# PASS/FAIL: hardware/all at the end. Skips without the board, never a silent
# pass.
#
#   tests/target/run_hardware_suite.sh <port> [smoke|qualification|optin|<scenario>...]
#
# smoke is the minimum every board runs (tests/target/lib/scenarios.py
# HARDWARE_MINIMUM); qualification adds the port's merge-gating extras.
set -u

repo="$(cd "$(dirname "$0")/../.." && pwd)"
lib="$repo/tests/target/lib"
ports="$(python3 "$lib/scenario_matrix.py" --list-ports)"
usage() { echo "usage: $0 <$(echo "$ports" | tr ' ' '|')> [smoke|qualification|optin|<scenario>...]" >&2; exit 2; }

port="${1:-}"
case " $ports " in
  *" $port "*) ;;
  *) usage ;;
esac
shift
tier="${1:-${WT_HW_TIER:-smoke}}"
case "$tier" in
  smoke|qualification|optin)
    scenarios="$(python3 "$lib/scenarios.py" --port "$port" --hardware-tier "$tier")" ;;
  *) scenarios="$*" ;;
esac
[ -n "$scenarios" ] || { echo "no scenarios for $port tier $tier" >&2; exit 2; }

cd "$repo" || exit 2
runner="${WT_HW_SUITE_RUNNER:-$repo/tests/target/run_hardware.sh}"
# The profile's detect runs in a subshell the way the runner would see it.
detect() {
  if [ -n "${WT_HW_SUITE_DETECT:-}" ]; then
    "$WT_HW_SUITE_DETECT"
  else
    bash -c '. tests/target/lib/scenario.sh; . tests/target/lib/hw_pyocd.sh; . tests/target/lib/hw_stcli.sh;
             here="$PWD/tests/target"; repo="$PWD"; port="$1"; . "tests/target/ports/$1/hw.sh"; hw_detect' _ "$port"
  fi
}
if ! detect >/dev/null 2>&1; then
  echo "SKIP: $port hardware suite ($(detect 2>&1 | tail -1))"
  exit 0
fi

logs="${WT_HW_SUITE_LOGS:-$repo/logs/$port-hw-suite}"
lock="${WT_HW_SUITE_LOCK:-$repo/logs/$port-hw.lock}"
mkdir -p "$logs" "$(dirname "$lock")"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$lock"
  if ! flock -n 9; then
    echo "WAIT: another $port hardware batch holds $lock"
    flock 9
  fi
else
  echo "NOTE: no flock on this host; the board lock is not held"
fi
export WT_HW_LOCKED=1

rc=0
for s in $scenarios; do
  echo "RUN: hardware/$s"
  if "$runner" "$port" "$s" > "$logs/$s.log" 2>&1; then
    grep -F '  [check] ' "$logs/$s.log" || true
    if grep -q '^SKIP: ' "$logs/$s.log"; then
      # The board or a tool went away mid-batch: a skip is never a pass.
      echo "SKIP: hardware/$s ($(grep '^SKIP: ' "$logs/$s.log" | tail -1))"
      rc=1
    else
      echo "PASS: hardware/$s"
    fi
  else
    grep -F '  [check] ' "$logs/$s.log" || true
    echo "FAIL: hardware/$s (tail of $logs/$s.log):"
    tail -15 "$logs/$s.log" || true
    rc=1
  fi
  echo "LOG: $logs/$s.log"
done
echo "LOGS: $logs"
if [ "$rc" -eq 0 ]; then echo "PASS: hardware/all"; else echo "FAIL: hardware/all"; fi
exit "$rc"
