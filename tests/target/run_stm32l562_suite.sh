#!/usr/bin/env bash
# wolfTrust STM32L562 hardware suite, the STM32L562E-DK sibling of
# run_mcxn947_suite.sh: the positive chain, the GTZC and peripheral negatives,
# the restart budget, the PSA client lifecycle, the guest fence refusal and
# the armed fence (the one reversible option byte write a batch makes, always
# released), each built and flashed to the board on the host that owns its
# ST-LINK.
# Without a board detect_stm32l562.sh reports why and the suite SKIPs; it
# never silently passes.
#
# Its logs live under logs/, never build/: every runner cleans build/ before
# it builds, so evidence there would not survive the next scenario. One batch
# at a time owns the board, through a lock the runner shares.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
runner="${STM32L562_SUITE_RUNNER:-$repo/tests/target/run_stm32l562_hardware.sh}"
detect="${STM32L562_SUITE_DETECT:-$repo/tests/target/detect_stm32l562.sh}"
scenarios="${WT_STM32L562_SCENARIOS:-positive gtzcneg periphneg restart psa wrpoff wrpfence}"
logs="${STM32L562_SUITE_LOGS:-$repo/logs/stm32l562-suite}"
lock="${STM32L562_HW_LOCK:-$repo/logs/stm32l562-hw.lock}"

if ! "$detect" >/dev/null 2>&1; then
  echo "SKIP: STM32L562 hardware suite ($("$detect" 2>&1))"
  exit 0
fi

# wrpfence's verdict needs OpenOCD's WRPERR report; the default list skips it
# on another backend rather than failing.
# shellcheck source=lib/stm32l562_probe.sh disable=SC1091
. "$repo/tests/target/lib/stm32l562_probe.sh"
if [ -z "${WT_STM32L562_SCENARIOS:-}" ] && [ "$(l5_tool 2>/dev/null || true)" != openocd ]; then
  scenarios="${scenarios% wrpfence}"
  echo "SKIP: hardware/wrpfence (needs the OpenOCD backend; set STM32L562_PROBE_TOOL=openocd)"
fi

mkdir -p "$logs" "$(dirname "$lock")"
exec 9>"$lock"
if ! flock -n 9; then
  echo "WAIT: another STM32L562 hardware batch holds $lock"
  flock 9
fi
export STM32L562_HW_LOCKED=1

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
