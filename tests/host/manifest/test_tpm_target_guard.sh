#!/bin/sh
# The optional application interfaces may only be selected for ports whose
# Secure manifest exposes the matching service.
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
checks=0
failures=0

check_make() {
    config=$1
    target=$2
    arch=$3
    engine=$4
    expected=$5
    checks=$((checks + 1))
    if (cd "$root" && make -s ARCH="$arch" TARGET="$target" \
            TOOLPREFIX= WT_ENGINE="$engine" "$config=y" FORCE \
            >/dev/null 2>&1); then
        actual=pass
    else
        actual=fail
    fi

    if [ "$actual" = "$expected" ]; then
        echo "  [check] PASS  $config=y $expected for $target"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $config=y should $expected for $target"
    fi
}

check_conflict() {
    config=$1
    target=$2
    arch=$3
    engine=$4
    checks=$((checks + 1))
    if (cd "$root" && make -s ARCH="$arch" TARGET="$target" \
            TOOLPREFIX= WT_ENGINE="$engine" "$config=y" CONFIG_VNET=y \
            FORCE >/dev/null 2>&1); then
        failures=$((failures + 1))
        echo "  [check] FAIL  $config=y accepted CONFIG_VNET=y for $target"
    else
        echo "  [check] PASS  $config=y rejects CONFIG_VNET=y for $target"
    fi
}

check_make CONFIG_TPM stm32h563 armv8m native pass
check_make CONFIG_TPM mimxrt700 armv8m native pass
check_make CONFIG_TPM qemuvirt aarch64 native pass
check_make CONFIG_TPM versal aarch64 native pass
check_make CONFIG_TPM unsupported armv8m native fail
check_make CONFIG_TPM stm32h563 armv8m hsm fail
check_make CONFIG_TPM qemuvirt aarch64 hsm fail

check_make CONFIG_PKCS11 stm32h563 armv8m hsm pass
check_make CONFIG_PKCS11 mimxrt700 armv8m hsm pass
check_make CONFIG_PKCS11 qemuvirt aarch64 hsm pass
check_make CONFIG_PKCS11 versal aarch64 hsm pass
check_make CONFIG_PKCS11 unsupported armv8m hsm fail

for target_arch in "stm32h563 armv8m" "mimxrt700 armv8m" \
        "qemuvirt aarch64" "versal aarch64"; do
    set -- $target_arch
    check_conflict CONFIG_TPM "$1" "$2" native
    check_conflict CONFIG_PKCS11 "$1" "$2" hsm
done

echo "Interface target guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: tpm_target_guard"
    exit 0
fi
echo "FAIL: tpm_target_guard"
exit 1
