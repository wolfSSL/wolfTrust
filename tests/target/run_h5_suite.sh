#!/usr/bin/env bash
# wolfTrust H5 hardware equivalence suite: the positive lifecycle plus the
# restart-recovery and cross-domain-isolation negatives, each built and flashed
# to a real Nucleo-H563ZI. The on-silicon counterpart of `make test-target`
# (which runs the same scenarios under the M33MU emulator).
#
# Build and flash live in different environments on the lab box (the ARM
# toolchain is only in the CI container, the ST-Link only on the host), so each
# scenario builds via WT_H5_DOCKER_IMAGE when set and flashes on the host.
# Without a board detect_h5.sh reports why and the suite SKIPs — it never
# silently passes.
set -euo pipefail
set -o pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
runner="$repo/tests/target/run_h5_hardware.sh"
img="${WT_H5_DOCKER_IMAGE:-}"
scenarios="${WT_H5_SCENARIOS:-positive restart crossdomain confboot}"
. "$repo/tests/target/lib/engine.sh"

if ! "$repo/tests/target/detect_h5.sh" >/dev/null 2>&1; then
  echo "SKIP: H5 hardware suite ($("$repo/tests/target/detect_h5.sh" 2>&1))"
  exit 0
fi

build_one() {
  if [ -n "$img" ]; then
    docker run --rm -e WT_ENGINE="$WT_ENGINE" \
      -v "$repo":/work -w /work "$img" \
      bash tests/target/run_h5_hardware.sh build "$1"
  else
    "$runner" build "$1"
  fi
}

rc=0
for s in $scenarios; do
  echo "RUN: hardware/$s"
  if build_one "$s" >"/tmp/h5-suite-build-$s.log" 2>&1 && \
     "$runner" flash "$s" >"/tmp/h5-suite-flash-$s.log" 2>&1; then
    grep -F '  [check] ' "/tmp/h5-suite-flash-$s.log" || true
    echo "PASS: hardware/$s"
  else
    grep -F '  [check] ' "/tmp/h5-suite-flash-$s.log" 2>/dev/null || true
    echo "FAIL: hardware/$s (tails):"
    tail -15 "/tmp/h5-suite-build-$s.log" 2>/dev/null || true
    tail -15 "/tmp/h5-suite-flash-$s.log" 2>/dev/null || true
    rc=1
  fi
done

if [ "$rc" -eq 0 ]; then echo "PASS: hardware/all"; else echo "FAIL: hardware/all"; exit 1; fi
