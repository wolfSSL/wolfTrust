#!/bin/sh
# Toggling an architectural-context probe inside one build directory must
# invalidate the secure build-mode stamp every secure object depends on, so
# a probe build never reuses production objects or the reverse.
set -eu

build=${1:?usage: test_probe_stamp.sh <build-dir>}
root=$(cd "$(dirname "$0")/../../.." && pwd)
case "$build" in
    /*) ;;
    *) build=$(pwd)/$build ;;
esac
stamp=$build/secure_build_mode.stamp
checks=0
failures=0

gen() {
    (cd "$root" && make -s BUILD_DIR="$build" "$@" "$stamp" >/dev/null)
}

check() {
    checks=$((checks + 1))
    if [ "$1" -eq 0 ]; then
        echo "  [check] PASS  $2"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $2"
    fi
}

rm -rf "$build"
mkdir -p "$build"

gen
cp "$stamp" "$build/default.stamp"
if grep -q '^WT_FP_NEG_PROBE=0$' "$stamp" &&
   grep -q '^WT_SEAL_NEG_PROBE=0$' "$stamp" &&
   grep -q '^WT_MSP_OVF_PROBE=0$' "$stamp" &&
   grep -q '^WT_BUSFAULT_NEG_PROBE=0$' "$stamp" &&
   grep -q '^WT_XN_NEG_PROBE=0$' "$stamp" &&
   grep -q '^WT_SVC_NEG_PROBE=0$' "$stamp" &&
   grep -q '^WT_MANIFEST_RUNTIME_CHECK=0$' "$stamp"; then st=0; else st=1; fi
check $st "default stamp records every probe off"

for probe in WT_FP_NEG_PROBE WT_SEAL_NEG_PROBE WT_MSP_OVF_PROBE \
        WT_BUSFAULT_NEG_PROBE WT_XN_NEG_PROBE WT_SVC_NEG_PROBE \
        WT_MANIFEST_RUNTIME_CHECK; do
    gen "$probe=1"
    if grep -q "^$probe=1\$" "$stamp" &&
       ! cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
    check $st "$probe=1 invalidates the stamp"

    cp -p "$stamp" "$build/probe.stamp"
    gen "$probe=1"
    if [ "$stamp" -nt "$build/probe.stamp" ]; then st=1; else st=0; fi
    check $st "$probe=1 again leaves the stamp untouched"

    gen
    if cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
    check $st "dropping $probe restores the default stamp"
done

for probe in 1 2; do
    gen WT_MANIFEST_NEG_PROBE=$probe
    if grep -q '^WT_MANIFEST_RUNTIME_CHECK=1$' "$stamp"; then st=0; else st=1; fi
    check $st "WT_MANIFEST_NEG_PROBE=$probe forces the boot-time manifest check"
done
gen WT_MANIFEST_NEG_PROBE=3
if grep -q '^WT_MANIFEST_RUNTIME_CHECK=0$' "$stamp"; then st=0; else st=1; fi
check $st "WT_MANIFEST_NEG_PROBE=3 keeps the default build-time check"

gen WT_VNET_TIMEOUT_TICKS=100
if grep -q '^WT_VNET_TIMEOUT_TICKS=100$' "$stamp" &&
   ! cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "WT_VNET_TIMEOUT_TICKS=100 invalidates the stamp"
gen
if cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "dropping WT_VNET_TIMEOUT_TICKS restores the default stamp"

echo "probe build stamp tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: probe_build_stamp"
    exit 0
fi
echo "FAIL: probe_build_stamp"
exit 1
