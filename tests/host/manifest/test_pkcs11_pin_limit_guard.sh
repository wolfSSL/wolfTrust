#!/bin/sh
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# Secure PKCS11 builds propagate PIN policy and select either crypto engine.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
checks=0
failures=0
unset WT_PKCS11_PIN_MAX_FAILURES WT_PKCS11_TEST_PBKDF2_ITERATIONS 2>/dev/null || true

report() {
    checks=$((checks + 1))
    if [ "$1" -eq 0 ]; then
        echo "  [check] PASS  $2"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $2"
    fi
}

run_make() {
    make -n -C "$root" ARCH="$arch" TARGET="$target" TOOLPREFIX= \
        CONFIG_PKCS11=y CONFIG_TPM=n WT_ENGINE="$engine" \
        BUILD_DIR="$work/$arch-$engine" "$@" > "$work/make.out" 2>&1
}

for arch in armv8m aarch64; do
    case "$arch" in
        armv8m) target=stm32h563 ;;
        aarch64) target=qemuvirt ;;
    esac
    for engine in native hsm; do
        rc=0
        run_make WT_PKCS11_PIN_MAX_FAILURES=5 || rc=1
        if [ "$rc" -eq 0 ] && grep 'pkcs11_provider\.c' "$work/make.out" |
                grep -q -- '-DWT_PKCS11_PIN_MAX_FAILURES=5U'; then
            report 0 "$arch/$engine requested PIN limit reaches the Secure compiler"
        else
            report 1 "$arch/$engine requested PIN limit reaches the Secure compiler"
        fi
        rc=0
        run_make || rc=1
        if [ "$rc" -eq 0 ] && grep -q 'pkcs11_provider\.c' "$work/make.out" &&
                ! grep -q -- '-DWT_PKCS11_PIN_MAX_FAILURES=' "$work/make.out" &&
                ! grep -q -- '-DPBKDF2_ITERATIONS=' "$work/make.out"; then
            report 0 "$arch/$engine production PIN policy keeps its defaults"
        else
            report 1 "$arch/$engine production PIN policy keeps its defaults"
        fi
        if [ "$engine" = hsm ]; then
            if grep 'pkcs11_provider\.c' "$work/make.out" |
                    grep -q -- '-DWOLFPKCS11_DEFAULT_DEVID=0x5748534D'; then
                report 0 "$arch HSM PKCS11 selects the HSM callback (WT-FFM-0054)"
            else
                report 1 "$arch HSM PKCS11 selects the HSM callback (WT-FFM-0054)"
            fi
        elif grep 'pkcs11_provider\.c' "$work/make.out" |
                grep -q -- 'WOLFPKCS11_DEFAULT_DEVID'; then
            report 1 "$arch native PKCS11 uses wolfCrypt without an HSM callback"
        else
            report 0 "$arch native PKCS11 uses wolfCrypt without an HSM callback"
        fi
        for bad in 0 07 abc -1; do
            rc=0
            run_make WT_PKCS11_PIN_MAX_FAILURES="$bad" || rc=1
            if [ "$rc" -ne 0 ] && grep -q 'must be > 0' "$work/make.out"; then
                report 0 "$arch/$engine PIN limit '$bad' is refused"
            else
                report 1 "$arch/$engine PIN limit '$bad' is refused"
            fi
        done
    done
done

echo "PKCS11 PIN limit guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: pkcs11_pin_limit_guard"
    exit 0
fi
echo "FAIL: pkcs11_pin_limit_guard"
exit 1
