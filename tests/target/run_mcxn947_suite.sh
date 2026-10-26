#!/usr/bin/env bash
# wolfTrust MCXN947 hardware suite, the FRDM-MCXN947 sibling of
# run_rt700_suite.sh: the positive chain, the guest isolation and peripheral
# negatives, the restart budget, and the PSA client lifecycle, each built and
# flashed to the board on the host that owns its MCU-Link. Without a board
# detect_mcxn947.sh reports why and the suite SKIPs; it never silently passes.
#
# Its logs live under logs/, never build/: every runner cleans build/ before
# it builds, so evidence there would not survive the next scenario. One batch
# at a time owns the board, through a lock the runner shares.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
runner="${MCXN947_SUITE_RUNNER:-$repo/tests/target/run_mcxn947_hardware.sh}"
detect="${MCXN947_SUITE_DETECT:-$repo/tests/target/detect_mcxn947.sh}"
scenarios="${WT_MCXN947_SCENARIOS:-positive sauneg periphneg restart psa}"
spsdk_venv="${MCXN947_SPSDK_VENV:-$HOME/spsdk-venv}"
logs="${MCXN947_SUITE_LOGS:-$repo/logs/mcxn947-suite}"
lock="${MCXN947_HW_LOCK:-$repo/logs/mcxn947-hw.lock}"

# The runner puts the SPSDK venv on PATH itself; detection needs it first.
if [ -d "$spsdk_venv/bin" ]; then
  PATH="$spsdk_venv/bin:$PATH"
  export PATH
fi
if ! "$detect" >/dev/null 2>&1; then
  echo "SKIP: MCXN947 hardware suite ($("$detect" 2>&1))"
  exit 0
fi

mkdir -p "$logs" "$(dirname "$lock")"
exec 9>"$lock"
if ! flock -n 9; then
  echo "WAIT: another MCXN947 hardware batch holds $lock"
  flock 9
fi
export MCXN947_HW_LOCKED=1

rc=0
for s in $scenarios; do
  echo "RUN: hardware/$s"
  if "$runner" "$s" >"$logs/$s.log" 2>&1; then
    grep -F '  [check] ' "$logs/$s.log" || true
    echo "PASS: hardware/$s"
  else
    grep -F '  [check] ' "$logs/$s.log" || true
    echo "FAIL: hardware/$s (tail of $logs/$s.log):"
    tail -15 "$logs/$s.log" || true
    rc=1
  fi
done
echo "LOGS: $logs"

if [ "$rc" -eq 0 ]; then echo "PASS: hardware/all"; else echo "FAIL: hardware/all"; exit 1; fi
