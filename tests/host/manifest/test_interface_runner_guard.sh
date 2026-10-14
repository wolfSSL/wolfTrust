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

echo "Interface runner guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: interface_runner_guard"
    exit 0
fi
echo "FAIL: interface_runner_guard"
exit 1
