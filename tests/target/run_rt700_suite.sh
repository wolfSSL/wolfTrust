#!/usr/bin/env bash
# wolfTrust MIMXRT700 hardware suite, the RT700 sibling of run_h5_suite.sh: the
# positive chain, the guest isolation negative, and the XSPI guest-fence set,
# each built and flashed to the EVK on the host that owns the probe. Without a
# board detect_rt700.sh reports why and the suite SKIPs; it never silently passes.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
runner="$repo/tests/target/run_rt700_hardware.sh"
scenarios="${WT_RT700_SCENARIOS:-positive ahbscneg wrpfence wrpoff wrpneg}"
spsdk_venv="${RT700_SPSDK_VENV:-$HOME/spsdk-venv}"

# The runner puts the SPSDK venv on PATH itself; detection needs it first.
if [ -d "$spsdk_venv/bin" ]; then
  PATH="$spsdk_venv/bin:$PATH"
  export PATH
fi
if ! "$repo/tests/target/detect_rt700.sh" >/dev/null 2>&1; then
  echo "SKIP: RT700 hardware suite ($("$repo/tests/target/detect_rt700.sh" 2>&1))"
  exit 0
fi

logs="$repo/build/rt700-suite"
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
