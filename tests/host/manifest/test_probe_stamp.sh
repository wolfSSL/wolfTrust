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
    (cd "$root" && env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL \
        make -s BUILD_DIR="$build" WT_LAYOUT_CPP="${CC:-cc}" "$@" \
        "$stamp" >/dev/null)
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

if grep -q '^WT_MAX_GUESTS=1$' "$build/default.stamp"; then st=0; else st=1; fi
check $st "default stamp records the one-guest image"
gen WT_MAX_GUESTS=2
if grep -q '^WT_MAX_GUESTS=2$' "$stamp" &&
   ! cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "WT_MAX_GUESTS=2 invalidates the stamp"
gen
if cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "dropping WT_MAX_GUESTS restores the default stamp"

if grep -q '^WT_FWU=0$' "$build/default.stamp"; then st=0; else st=1; fi
check $st "default stamp records the image without the update service"
gen WT_FWU=1
if grep -q '^WT_FWU=1$' "$stamp" &&
   ! cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "WT_FWU=1 invalidates the stamp"
gen
if cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "dropping WT_FWU restores the default stamp"
if (cd "$root" && make -s BUILD_DIR="$build" WT_BOOTUPDATE_PROBE=1 \
        "$stamp" >/dev/null 2>"$build/bootupdate.err"); then st=1;
elif grep -q 'build it with WT_FWU=1' "$build/bootupdate.err"; then st=0;
else st=1; fi
check $st "WT_BOOTUPDATE_PROBE=1 without WT_FWU=1 stops the build"
if (cd "$root" && make -s BUILD_DIR="$build" CONFIG_VNET=y \
        "$stamp" >/dev/null 2>"$build/vnet.err"); then st=1;
elif grep -q 'CONFIG_VNET=y needs both guests' "$build/vnet.err"; then st=0;
else st=1; fi
check $st "CONFIG_VNET=y with one guest stops the build"
plan=$(cd "$root" && make -n -s TARGET=stm32h563 WT_CONFORMANCE=1 \
    WT_LAYOUT_CPP="${CC:-cc}" BUILD_DIR="$build/refuse" \
    "$build/refuse/wolftrust.elf" 2>/dev/null || true)
case "$plan" in
*"needs the 256 KiB Secure slot"*) st=0 ;;
*) st=1 ;;
esac
check $st "WT_CONFORMANCE=1 in the 128 KiB STM32H563 slot refuses the link"
plan=$(cd "$root" && make -n -s TARGET=stm32h563 WT_CONFORMANCE=1 \
    WT_SECURE_FLASH_SIZE=0x00040000 WT_LAYOUT_CPP="${CC:-cc}" \
    BUILD_DIR="$build/refuse" "$build/refuse/wolftrust.elf" 2>/dev/null || true)
case "$plan" in
*"needs the 256 KiB Secure slot"*) st=1 ;;
*) st=0 ;;
esac
check $st "WT_CONFORMANCE=1 in the 256 KiB slot links"
plan=$(cd "$root" && make -n -s TARGET=stm32h563 test-target 2>/dev/null | tr '\n' ' ')
case "$plan" in
*"WT_PROFILE=default WT_SUITE_LOG_DIR=logs/default"*"WT_PROFILE=extended WT_SUITE_LOG_DIR=logs/extended"*) st=0 ;;
*) st=1 ;;
esac
check $st "make test-target runs default then extended, each with its own logs"
plan=$(cd "$root" && make -n -s TARGET=stm32h563 WT_PROFILE=default test-target 2>/dev/null | tr '\n' ' ')
case "$plan" in
*"WT_PROFILE=extended"*) st=1 ;;
*"WT_PROFILE=default WT_SUITE_LOG_DIR=logs "*) st=0 ;;
*) st=1 ;;
esac
check $st "make test-target WT_PROFILE=default runs only the default profile"

if grep -q '^WT_SHA256_FAST=0$' "$build/default.stamp"; then st=0; else st=1; fi
check $st "default stamp records the looped SHA-256 transform"
gen WT_SHA256_FAST=1
if grep -q '^WT_SHA256_FAST=1$' "$stamp" &&
   ! cmp -s "$stamp" "$build/default.stamp"; then st=0; else st=1; fi
check $st "WT_SHA256_FAST=1 invalidates the stamp"
if (cd "$root" && make -s BUILD_DIR="$build" WT_SHA256_FAST=2 \
        "$stamp" >/dev/null 2>"$build/sha256.err"); then st=1;
elif grep -q 'unsupported WT_SHA256_FAST' "$build/sha256.err"; then st=0;
else st=1; fi
check $st "WT_SHA256_FAST=2 stops the build"
gen

for value in 2 "0 1"; do
    if (cd "$root" && make -s BUILD_DIR="$build" \
            WT_MANIFEST_RUNTIME_CHECK="$value" "$stamp" >/dev/null \
            2>"$build/rtcheck.err"); then st=1;
    elif grep -q 'unsupported WT_MANIFEST_RUNTIME_CHECK' "$build/rtcheck.err"; then st=0;
    else st=1; fi
    check $st "WT_MANIFEST_RUNTIME_CHECK='$value' stops the build"
done
for value in lean full compat "default extended"; do
    if (cd "$root" && WT_TARGET_SCENARIOS=1 make -s WT_PROFILE="$value" \
            test-target >/dev/null 2>"$build/profile.err"); then st=1;
    elif grep -q 'unsupported WT_PROFILE' "$build/profile.err"; then st=0;
    else st=1; fi
    check $st "make test-target WT_PROFILE='$value' fails"
done
if (cd "$root" && WT_TARGET_SCENARIOS=1 make -s WT_PROFILE=tiny \
        test-target >/dev/null 2>"$build/profile.err"); then st=1;
elif grep -q "unsupported test profile 'tiny'" "$build/profile.err"; then st=0;
else st=1; fi
check $st "make test-target WT_PROFILE=tiny fails, no scenario set registers it"
# shellcheck source=../../target/lib/profile.sh disable=SC1091
. "$root/tests/target/lib/profile.sh"
for value in tiny small default extended; do
    want=$(cd "$root" && make -s --no-print-directory TARGET=stm32h563 \
        WT_PROFILE="$value" print-profile)
    # shellcheck disable=SC2046
    got=$(cd "$root" && make -s --no-print-directory TARGET=stm32h563 \
        $(scenario_profile_flags "$value") print-profile)
    case "$want" in
    *"WT_SECURE_PSA_PROFILE=$value "*) st=0 ;;
    *) st=1 ;;
    esac
    [ "$want" = "$got" ] || st=1
    check $st "profile.sh and mk/profile.mk agree on $value"
done
for cfg in CONFIG_TPM=y CONFIG_PKCS11=y; do
    if (cd "$root" && make -s --no-print-directory TARGET=stm32l562 "$cfg" \
            WT_PROFILE=extended print-profile >/dev/null 2>"$build/profile.err"); then
        st=1
    elif grep -q 'no update partition' "$build/profile.err"; then st=0;
    else st=1; fi
    check $st "stm32l562 $cfg refuses the extended profile's update partition"
    got=$(cd "$root" && make -s --no-print-directory TARGET=stm32l562 "$cfg" \
        WT_PROFILE=extended WT_FWU=0 print-profile 2>/dev/null)
    case "$got" in
    *"WT_SECURE_PSA_PROFILE=extended "*"WT_FWU=0 "*) st=0 ;;
    *) st=1 ;;
    esac
    check $st "stm32l562 $cfg builds extended with WT_FWU=0"
done
# ECC leaves a build only when no feature asks for it; each row is
# "<make arguments>|<expected tail of print-profile>".
while IFS='|' read -r args want; do
    # shellcheck disable=SC2086
    got=$(cd "$root" && make -s --no-print-directory TARGET=stm32h563 $args \
        print-profile 2>/dev/null)
    case "$got" in
    *" $want") st=0 ;;
    *) st=1 ;;
    esac
    check $st "'$args' resolves $want"
done <<'EOF'
WT_PROFILE=tiny|WT_ATTEST_KEY=hmac WT_VAULT_ECC=0 WT_NO_ECC=1
WT_PROFILE=small|WT_ATTEST_KEY=ecc WT_VAULT_ECC=1 WT_NO_ECC=0
WT_PROFILE=default|WT_ATTEST_KEY=ecc WT_VAULT_ECC=1 WT_NO_ECC=0
WT_PROFILE=extended|WT_ATTEST_KEY=ecc WT_VAULT_ECC=1 WT_NO_ECC=0
WT_PROFILE=tiny WT_ATTEST_KEY=ecc|WT_ATTEST_KEY=ecc WT_VAULT_ECC=0 WT_NO_ECC=0
WT_PROFILE=tiny WT_VAULT_ECC=1|WT_ATTEST_KEY=hmac WT_VAULT_ECC=1 WT_NO_ECC=0
WT_PROFILE=tiny CONFIG_TPM=y|WT_ATTEST_KEY=hmac WT_VAULT_ECC=0 WT_NO_ECC=0
WT_PROFILE=tiny WT_SECURE_PSA=0|WT_ATTEST_KEY=hmac WT_VAULT_ECC=0 WT_NO_ECC=1
WT_PROFILE=tiny WT_ENGINE=hsm|WT_ATTEST_KEY=ecc WT_VAULT_ECC=1 WT_NO_ECC=0
WT_PROFILE=small WT_ATTEST_KEY=hmac WT_VAULT_ECC=0|WT_ATTEST_KEY=hmac WT_VAULT_ECC=0 WT_NO_ECC=0
EOF
while IFS='|' read -r args want; do
    # shellcheck disable=SC2086
    if (cd "$root" && make -s --no-print-directory TARGET=stm32h563 $args \
            print-profile >/dev/null 2>"$build/profile.err"); then st=1;
    elif grep -q "$want" "$build/profile.err"; then st=0;
    else st=1; fi
    check $st "'$args' stops the build"
done <<'EOF'
WT_ATTEST_KEY=rsa|unsupported WT_ATTEST_KEY
WT_VAULT_ECC=2|unsupported WT_VAULT_ECC
WT_ATTEST_KEY=hmac WT_ATTEST_DEV_KEY=2|unsupported WT_ATTEST_DEV_KEY
WT_ENGINE=hsm WT_ATTEST_KEY=hmac|WT_ATTEST_KEY=hmac requires WT_ENGINE=native
WT_ENGINE=hsm WT_VAULT_ECC=0|WT_VAULT_ECC=0 requires WT_ENGINE=native
EOF
gen

for target in stm32h563 mimxrt700 mcxn947; do
    deps=$(cd "$root" && make -pq TARGET=$target BUILD_DIR="$build" "$stamp" \
        2>/dev/null | grep "^$build/wt_sec_wolftrust_manifest_generated.o:" || true)
    case "$deps" in
        *port/common/armv8m/platform_caps.h*) st=0 ;;
        *) st=1 ;;
    esac
    check $st "$target: the generated manifest object rebuilds on platform_caps.h"
done

echo "probe build stamp tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: probe_build_stamp"
    exit 0
fi
echo "FAIL: probe_build_stamp"
exit 1
