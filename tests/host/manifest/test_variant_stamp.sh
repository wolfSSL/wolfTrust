#!/bin/sh
# WT-FFM-0005: switching the manifest variant inside one build directory must
# regenerate the processed manifest instead of reusing the stale stamp.
set -eu

build=${1:?usage: test_variant_stamp.sh <build-dir>}
root=$(cd "$(dirname "$0")/../../.." && pwd)
case "$build" in
    /*) ;;
    *) build=$(pwd)/$build ;;
esac
header=$build/manifest/wolftrust_manifest_generated.h
checks=0
failures=0

gen() {
    (cd "$root" && make -s BUILD_DIR="$build" "$@" \
        "$build/manifest/.stamp" >/dev/null)
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
if grep -q PARTITION_VNET "$header"; then st=1; else st=0; fi
check $st "default manifest carries no VNET partition"
if grep -q PARTITION_FWU "$header"; then st=1; else st=0; fi
check $st "default manifest leaves the update partition out (WT_FWU=0)"

gen WT_FWU=1
if grep -q PARTITION_FWU "$header"; then st=0; else st=1; fi
check $st "WT_FWU=1 regenerates with the update partition"

gen CONFIG_VNET=y
if grep -q PARTITION_VNET "$header"; then st=0; else st=1; fi
check $st "CONFIG_VNET=y regenerates and adds the VNET partition"

gen WT_CONFORMANCE=1
if grep -q SERVER_PARTITION "$header"; then st=0; else st=1; fi
check $st "WT_CONFORMANCE=1 regenerates with the test partitions"

gen
if grep -q "PARTITION_VNET\|SERVER_PARTITION\|PARTITION_FWU" "$header"; then st=1; else st=0; fi
check $st "returning to the default drops the variant partitions"

echo "manifest variant stamp tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: manifest_variant_stamp"
    exit 0
fi
echo "FAIL: manifest_variant_stamp"
exit 1
