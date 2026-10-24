#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
target_dir="$root/tests/firmware/stm32h563-tpm"
runner="$target_dir/run_tpm_test.sh"
fixture="$root/tests/host/manifest/interface_runner_fixture.sh"
checks=0
failures=0

check_run() {
    mode=$1
    checks=$((checks + 1))
    if WT_TPM_TEST_MODE="$mode" WT_PKCS11_SUITE=all M33MU="$fixture" \
            SECURE_BIN=unused GUEST0_BIN=unused GUEST1_BIN=unused \
            sh "$runner" >/dev/null; then
        echo "  [check] PASS  $mode runner expects its provider markers"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $mode runner provider marker mismatch"
    fi
}

check_recipe() {
    target=$1
    needle=$2
    description=$3
    output=$(make -n -C "$target_dir" MAKE=true "$target")
    checks=$((checks + 1))
    if printf '%s\n' "$output" | grep -Fq "$needle"; then
        echo "  [check] PASS  $description"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $description"
    fi
}

check_run tpm
check_run pkcs11
check_recipe pkcs11 "WT_GUEST1_FLASH_SIZE=0x00040000" \
    "PKCS11 secure image grants the provider 256 KiB"
check_recipe pkcs11-provider "freertos-workspace" \
    "PKCS11 provider provisions FreeRTOS"
check_recipe pkcs11-freertos-app "freertos-workspace" \
    "PKCS11 application provisions FreeRTOS"
check_recipe tpm-freertos-app "freertos-workspace" \
    "TPM application provisions FreeRTOS"

# Required API rows must distinguish a real pass from a successful skip.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/tests/target"
cp "$root/tests/target/run_suite.sh" "$work/tests/target/run_suite.sh"
cat > "$work/tests/target/run_qemu_a_scenario.sh" <<'EOF'
#!/bin/sh
case "$WT_FAKE_RESULT" in
    skip) echo 'SKIP: qemu-a/tpm: unavailable' ;;
    missing) echo 'no terminal verdict' ;;
    pass) echo 'PASS: qemu-a/tpm (fixture)' ;;
    fail) exit 1 ;;
esac
EOF
chmod +x "$work/tests/target/run_qemu_a_scenario.sh"
check_verdict() {
    checks=$((checks + 1))
    if WT_FAKE_RESULT="$1" WT_REQUIRE_SCENARIO_PASS="$2" \
            bash "$work/tests/target/run_suite.sh" qemu-a tpm \
            > "$work/out" 2>&1; then actual=0; else actual=1; fi
    if [ "$actual" -eq "$3" ]; then
        echo "  [check] PASS  verdict=$1 required=$2 (WT-FFM-0054)"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  verdict=$1 required=$2"
    fi
}
check_verdict skip 0 0
check_verdict skip 1 1
check_verdict missing 1 1
check_verdict pass 1 0
check_verdict fail 1 1

echo "Interface runner guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: interface_runner_guard"
    exit 0
fi
echo "FAIL: interface_runner_guard"
exit 1
