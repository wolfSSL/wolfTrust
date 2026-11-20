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

# Secure image and application sizes of the PSA, TPM 2.0 and PKCS#11 builds on
# every registered port and engine, in the layout the emulator runs use.
#   tools/measure_interface_footprint.sh [out-dir]
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
out="${1:-$root/interface-footprint}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
# Every cell rebuilds build/ from scratch, so the results must live elsewhere.
case "$out/" in
    "$root/build/"*) echo "Refusing an output directory under build/: $out" >&2; exit 1 ;;
esac
export WT_INTERFACE_PROFILE="${WT_INTERFACE_PROFILE:-default}"
if [ -n "${WT_PKCS11_TEST_PBKDF2_ITERATIONS:-}" ]; then
    echo 'Refusing footprint measurement with emulator-only PIN settings' >&2
    exit 1
fi
matrix="$root/tests/target/lib/scenario_matrix.py"

printf 'port,api,engine,role,flash,ram\n' > "$out/sizes.csv"
{
    git rev-parse HEAD
    git status --porcelain --ignore-submodules=all
    git ls-tree HEAD lib/
    arm-none-eabi-gcc --version | head -1
    printf 'profile=%s\n' "$WT_INTERFACE_PROFILE"
} > "$out/configuration.txt"

flash()
{
    local text data rest
    read -r text data rest < <(arm-none-eabi-size "$1" | tail -1)
    echo "$((text + data))"
}

# Each port builds in the layout its emulator run uses (tests/target/ports).
layout='here="$PWD/tests/target"; repo="$PWD"; . "$here/ports/$1/m33mu.sh"; port_layout_env; shift; exec "$@"'
for port in $(python3 "$matrix" --list-ports); do
    for engine in $(python3 "$matrix" --port "$port" --get build.engines); do
        for api in psa tpm pkcs11; do
            config=()
            case "$api" in
                tpm) config=(CONFIG_TPM=y) ;;
                pkcs11) config=(CONFIG_PKCS11=y) ;;
            esac
            cell="$port-$api-$engine"
            echo "BUILD $cell"
            rm -rf build
            bash -c "$layout" _ "$port" env "${config[@]}" WT_ENGINE="$engine" \
                make -j"${JOBS:-4}" TARGET="$port" secure-image \
                > "$out/$cell-secure.log" 2>&1
            cp build/wolftrust.elf "$out/$cell-secure.elf"
            ram=$(python3 tools/secure_ram.py build/wolftrust.map |
                sed -n 's/^Reserved Secure RAM: \([0-9]*\) bytes$/\1/p')
            printf '%s,%s,%s,secure,%s,%s\n' "$port" "$api" "$engine" \
                "$(flash build/wolftrust.elf)" "$ram" >> "$out/sizes.csv"
            guest=interface-guest
            [ "$api" != psa ] || guest=psa-guest
            make -C "tests/firmware/$guest" TARGET="$port" clean > /dev/null
            bash -c "$layout" _ "$port" env "${config[@]}" WT_ENGINE="$engine" \
                make -C "tests/firmware/$guest" TARGET="$port" \
                WT_INTERFACE="$api" build/guest0.bin \
                > "$out/$cell-app.log" 2>&1
            elf="tests/firmware/$guest/build/guest0.elf"
            cp "$elf" "$out/$cell-app.elf"
            printf '%s,%s,%s,app,%s,\n' "$port" "$api" "$engine" \
                "$(flash "$elf")" >> "$out/sizes.csv"
        done
    done
done
python3 tools/check_interface_footprint.py "$out/sizes.csv" \
    ${WT_INTERFACE_MAX_OVERHEAD:+--max-overhead "$WT_INTERFACE_MAX_OVERHEAD"}
