#!/bin/sh
# The PKCS#11 provider build must pass a requested PIN attempt limit to the
# compiler and refuse a limit that is not a positive integer.
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
scripts="$root/tests/firmware/stm32h563-tpm/scripts"
script="$scripts/build_freertos_pkcs11_provider.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
checks=0
failures=0
unset WT_PKCS11_PIN_MAX_FAILURES 2>/dev/null || true

mkdir -p "$work/freertos/FreeRTOS/Source" "$work/bin"
: > "$work/implib.o"
# Append: a build tracer such as CodeQL may run a new compiler again to probe it.
cat > "$work/bin/cc" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> "$work/cc.args"
EOF
cat > "$work/bin/nm" <<'EOF'
#!/bin/sh
printf '%s\n' wt_pkcs11_provider_dispatch WP11_GetSlotList
if [ "$WT_ENGINE" = hsm ]; then
    printf '%s\n' wt_hsm_psa_transport_cb
else
    printf '%s\n' wt_crypto_native_random
fi
EOF
printf '#!/bin/sh\nexit 0\n' > "$work/bin/true"
chmod +x "$work/bin/cc" "$work/bin/nm" "$work/bin/true"

run_build() {
    rm -f "$work/cc.args"
    env WT_ENGINE=hsm FREERTOS_DIR="$work/freertos" SECURE_CMSE_IMPLIB="$work/implib.o" \
        BUILD_DIR="$work/build" GUEST_CC="$work/bin/cc" \
        GUEST_NM="$work/bin/nm" GUEST_OBJCOPY="$work/bin/true" \
        GUEST_SIZE="$work/bin/true" "$@" sh "$script" >/dev/null 2>&1
}

report() {
    checks=$((checks + 1))
    if [ "$1" -eq 0 ]; then
        echo "  [check] PASS  $2"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $2"
    fi
}

rc=0
run_build WT_PKCS11_PIN_MAX_FAILURES=5 || rc=1
if [ "$rc" -eq 0 ] &&
        grep -qx -- '-DWT_PKCS11_PIN_MAX_FAILURES=5U' "$work/cc.args"; then
    report 0 "a requested PIN limit reaches the provider compiler"
else
    report 1 "a requested PIN limit reaches the provider compiler"
fi

rc=0
run_build || rc=1
if [ "$rc" -eq 0 ] && [ -f "$work/cc.args" ] &&
        ! grep -q -- 'WT_PKCS11_PIN_MAX_FAILURES' "$work/cc.args"; then
    report 0 "the default PIN limit adds no compiler override"
else
    report 1 "the default PIN limit adds no compiler override"
fi

for bad in 0 07 abc -1; do
    rc=0
    run_build WT_PKCS11_PIN_MAX_FAILURES="$bad" || rc=1
    if [ "$rc" -ne 0 ] && [ ! -f "$work/cc.args" ]; then
        report 0 "PIN limit '$bad' is refused before compiling"
    else
        report 1 "PIN limit '$bad' is refused before compiling"
    fi
done

for engine in native hsm; do
    rc=0
    run_build WT_ENGINE="$engine" || rc=1
    if [ "$engine" = native ]; then
        if [ "$rc" -eq 0 ] &&
                grep -q '/crypto_native_client.c' "$work/cc.args" &&
                ! grep -q '/wh_client.c' "$work/cc.args" &&
                ! grep -q 'WOLFPKCS11_DEFAULT_DEVID' "$work/cc.args"; then
            report 0 "native PKCS11 uses direct wolfCrypt and the native RNG (WT-FFM-0054)"
        else
            report 1 "native PKCS11 uses direct wolfCrypt and the native RNG (WT-FFM-0054)"
        fi
    elif [ "$rc" -eq 0 ] && grep -q '/wh_client.c' "$work/cc.args" &&
            grep -q -- '-DWOLFPKCS11_DEFAULT_DEVID=0x5748534D' "$work/cc.args"; then
        report 0 "HSM PKCS11 selects the mediated HSM callback (WT-FFM-0054)"
    else
        report 1 "HSM PKCS11 selects the mediated HSM callback (WT-FFM-0054)"
    fi
done

# The AArch64 Secure image builds the provider through make; TOOLPREFIX is
# empty so the layout probe uses the host preprocessor.
run_make() {
    make -n -C "$root" ARCH=aarch64 TARGET=qemuvirt TOOLPREFIX= \
        CONFIG_PKCS11=y WT_ENGINE=hsm BUILD_DIR="$work/aarch64" "$@" \
        > "$work/make.out" 2>&1
}

rc=0
run_make WT_PKCS11_PIN_MAX_FAILURES=5 || rc=1
if [ "$rc" -eq 0 ] && grep 'pkcs11_provider\.c' "$work/make.out" |
        grep -q -- '-DWT_PKCS11_PIN_MAX_FAILURES=5U'; then
    report 0 "a requested PIN limit reaches the AArch64 provider compile"
else
    report 1 "a requested PIN limit reaches the AArch64 provider compile"
fi

rc=0
run_make || rc=1
if [ "$rc" -eq 0 ] && grep -q 'pkcs11_provider\.c' "$work/make.out" &&
        ! grep -q -- '-DWT_PKCS11_PIN_MAX_FAILURES=' "$work/make.out" &&
        ! grep -q -- '-DPBKDF2_ITERATIONS=' "$work/make.out"; then
    report 0 "the default AArch64 provider build keeps both defaults"
else
    report 1 "the default AArch64 provider build keeps both defaults"
fi

for bad in 0 07 abc -1; do
    rc=0
    run_make WT_PKCS11_PIN_MAX_FAILURES="$bad" || rc=1
    if [ "$rc" -ne 0 ] && grep -q 'must be > 0' "$work/make.out"; then
        report 0 "AArch64 PIN limit '$bad' is refused"
    else
        report 1 "AArch64 PIN limit '$bad' is refused"
    fi
done

echo "PKCS11 PIN limit guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: pkcs11_pin_limit_guard"
    exit 0
fi
echo "FAIL: pkcs11_pin_limit_guard"
exit 1
