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

# Every registered port lists both variants; stm32l562 builds native only.
for selected_engine in native hsm; do
    for selected_config in CONFIG_TPM CONFIG_PKCS11; do
        for port in stm32h563 mimxrt700 mcxn947; do
            check_make "$selected_config" "$port" armv8m "$selected_engine" pass
        done
        check_make "$selected_config" unsupported armv8m "$selected_engine" fail
        check_make "$selected_config" stm32h563 armv8m invalid fail
    done
done
check_make CONFIG_TPM stm32l562 armv8m native pass
check_make CONFIG_PKCS11 stm32l562 armv8m native pass

for port in stm32h563 mimxrt700 mcxn947; do
    check_conflict CONFIG_TPM "$port" armv8m native
    check_conflict CONFIG_PKCS11 "$port" armv8m hsm
done

echo "Interface target guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: tpm_target_guard (WT-FFM-0054, both provider engines)"
    exit 0
fi
echo "FAIL: tpm_target_guard"
exit 1
