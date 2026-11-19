#!/bin/sh
# Compile the host and every Armv8-M port under a static-analysis build tracer.
set -eu

make test

# Every registered port and engine, with the attestation setting its default
# build uses (port/<soc>/port.json build). The plan is a checked file: a
# producer that fails must fail the job, not empty the loop.
plan="$(mktemp)"
trap 'rm -f "$plan" "$plan.json"' EXIT
python3 tests/target/lib/scenario_matrix.py --build-plan > "$plan.json"
python3 -c 'import json, sys
for b in json.load(open(sys.argv[1])):
    print(b["port"], b["engine"], b["attest_cose"])' "$plan.json" > "$plan"
[ -s "$plan" ] || { echo "the build plan is empty" >&2; exit 1; }
while read -r target engine attest_cose; do
    make TARGET="$target" WT_ENGINE="$engine" \
        WT_ATTEST_COSE="$attest_cose" \
        BUILD_DIR="build/static-analysis-$target-$engine" \
        TOOLPREFIX=arm-none-eabi- secure-image
done < "$plan"
