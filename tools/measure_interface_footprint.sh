#!/usr/bin/env bash
# measure_interface_footprint.sh
#
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

# Run in the M33MU CI image after initializing dependencies and FreeRTOS.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
out="${1:-$root/build/interface-footprint}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
export FREERTOS_DIR="${FREERTOS_DIR:-$root/tests/firmware/zephyr-stm32h5/.workspace/freertos}"
export WT_CRYPTO_PROFILE="${WT_CRYPTO_PROFILE:-default}"
export WT_LTO="${WT_LTO:-1}"
export WT_SECURE_FLASH_BASE=0x0C060000 WT_SECURE_FLASH_SIZE=0x40000
export WT_MAX_GUESTS=1
printf 'api,engine,role,text,data,bss,flash\n' > "$out/sizes.csv"
{
    git rev-parse HEAD
    git diff --stat HEAD --ignore-submodules=all
    git status --porcelain --ignore-submodules=all
    arm-none-eabi-gcc --version | head -1
    printf 'profile=%s lto=%s guests=%s\n' "$WT_CRYPTO_PROFILE" "$WT_LTO" "$WT_MAX_GUESTS"
} > "$out/configuration.txt"
record()
{
    local text data bss rest
    read -r text data bss rest < <(arm-none-eabi-size "$4" | tail -1)
    arm-none-eabi-nm -S --size-sort "$4" > "$4.symbols.txt"
    arm-none-eabi-size -A -d "$4" > "$4.sections.txt"
    printf '%s,%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$text" "$data" "$bss" "$((text + data))" >> "$out/sizes.csv"
}
for WT_ENGINE in native hsm; do
    export WT_ENGINE
    for api in psa pkcs11 tpm; do
        secure="$out/$api-$WT_ENGINE-secure"
        config=(CONFIG_PKCS11=n CONFIG_TPM=n)
        case "$api" in
            pkcs11) config=(CONFIG_PKCS11=y CONFIG_TPM=n) ;;
            tpm) config=(CONFIG_TPM=y CONFIG_PKCS11=n) ;;
        esac
        echo "BUILD $api $WT_ENGINE"
        make -j"${JOBS:-4}" TARGET=stm32h563 BUILD_DIR="$secure" \
            "${config[@]}" secure-image > "$out/$api-$WT_ENGINE-secure.log" 2>&1
        record "$api" "$WT_ENGINE" secure "$secure/wolftrust.elf"
        export SECURE_CMSE_IMPLIB="$secure/secure_cmse_implib.o"
        export BUILD_DIR="$out/$api-$WT_ENGINE-app"
        mkdir -p "$BUILD_DIR"
        if [ "$api" = psa ]; then
            bash tests/firmware/zephyr-stm32h5/scripts/build_freertos_guest.sh > "$BUILD_DIR/build.log" 2>&1
            record "$api" "$WT_ENGINE" app "$BUILD_DIR/freertos_guest1.elf"
        else
            export WT_PKCS11_SUITE=all
            [ "$WT_CRYPTO_PROFILE" != default ] || export WT_PKCS11_SUITE=profile
            bash "tests/firmware/stm32h563-tpm/scripts/build_freertos_$api.sh" > "$BUILD_DIR/build.log" 2>&1
            record "$api" "$WT_ENGINE" app "$BUILD_DIR/guest0.elf"

        fi
    done
done
cat "$out/sizes.csv"
