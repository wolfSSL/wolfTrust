#!/usr/bin/env bash
# wolfTrust MCXN947 hardware suite, the FRDM-MCXN947 sibling of
# run_rt700_suite.sh: the positive chain, the guest isolation and peripheral
# negatives, the restart budget, and the PSA client lifecycle, each built and
# flashed to the board on the host that owns its MCU-Link. Without a board
# detect_mcxn947.sh reports why and the suite SKIPs; it never silently passes.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
runner="$repo/tests/target/run_mcxn947_hardware.sh"
scenarios="${WT_MCXN947_SCENARIOS:-positive sauneg periphneg restart psa}"
spsdk_venv="${MCXN947_SPSDK_VENV:-$HOME/spsdk-venv}"

# The runner puts the SPSDK venv on PATH itself; detection needs it first.
if [ -d "$spsdk_venv/bin" ]; then
  PATH="$spsdk_venv/bin:$PATH"
  export PATH
fi
if ! "$repo/tests/target/detect_mcxn947.sh" >/dev/null 2>&1; then
  echo "SKIP: MCXN947 hardware suite ($("$repo/tests/target/detect_mcxn947.sh" 2>&1))"
  exit 0
fi

logs="$repo/build/mcxn947-suite"
mkdir -p "$logs"
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

if [ "$rc" -eq 0 ]; then echo "PASS: hardware/all"; else echo "FAIL: hardware/all"; exit 1; fi
