#!/bin/sh
# Keep every public STM32H563 firmware runner on the manifest's guest layout.
set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
checks=0
failures=0

check_value() {
    directory=$1
    variable=$2
    expected=$3
    description=$4
    actual=$(make -s -C "$directory" -pn 2>/dev/null |
        awk -v key="$variable" '$1 == key && $2 == "=" { print $3; exit }')
    checks=$((checks + 1))
    if [ "$actual" = "$expected" ]; then
        echo "  [check] PASS  $description"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $description: expected $expected, found $actual"
    fi
}

check_recipe() {
    directory=$1
    target=$2
    needle=$3
    description=$4
    output_file=$(mktemp)
    checks=$((checks + 1))
    if MAKEFLAGS= MFLAGS= BUILD_DIR=build \
            make -n -C "$directory" "$target" \
            >"$output_file" 2>/dev/null &&
       grep -Fq "$needle" "$output_file"; then
        echo "  [check] PASS  $description"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $description"
    fi
    rm -f "$output_file"
}

check_file() {
    file=$1
    needle=$2
    description=$3
    checks=$((checks + 1))
    if grep -Fq "$needle" "$file"; then
        echo "  [check] PASS  $description"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $description"
    fi
}

check_rejected_size() {
    build_dir=$(mktemp -d)
    log_file="$build_dir/rejected-size.log"
    checks=$((checks + 1))
    if MAKEFLAGS= MFLAGS= make -s -C "$root" TARGET=stm32h563 \
            WT_GUEST0_FLASH_SIZE=0x00020000 BUILD_DIR="$build_dir" \
            "$build_dir/manifest/.stamp" >"$log_file" 2>&1; then
        rejected=0
    else
        rejected=1
    fi
    if [ "$rejected" -eq 1 ] &&
       grep -Fq 'expected 0x80a0000:0x20000' "$log_file"; then
        echo "  [check] PASS  manifest rejects a runner slot-size mismatch"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  manifest accepts a runner slot-size mismatch"
    fi
    rm -f "$log_file"
    rmdir "$build_dir/manifest" 2>/dev/null || true
    rmdir "$build_dir" 2>/dev/null || true
}

bare="$root/tests/firmware/stm32h563"
vnet="$root/tests/firmware/stm32h563-vnet"
zephyr="$root/tests/firmware/zephyr-stm32h5"
pkcs11_app="$root/tests/firmware/stm32h563-tpm/scripts/build_freertos_pkcs11.sh"

for directory in "$bare" "$vnet"; do
    check_value "$directory" WT_GUEST0_FLASH_ORIGIN 0x080A0000 \
        "$(basename "$directory") guest 0 links at the manifest base"
    check_value "$directory" WT_GUEST1_FLASH_ORIGIN 0x080E0000 \
        "$(basename "$directory") guest 1 links at the manifest base"
    check_value "$directory" WT_GUEST0_FLASH_SIZE 0x00040000 \
        "$(basename "$directory") guest 0 uses the manifest flash size"
    check_value "$directory" WT_GUEST1_FLASH_SIZE 0x00020000 \
        "$(basename "$directory") guest 1 uses the manifest flash size"
    check_value "$directory" WT_GUEST0_EMU_OFFSET 0xA0000 \
        "$(basename "$directory") guest 0 loads at its link offset"
    check_value "$directory" WT_GUEST1_EMU_OFFSET 0xE0000 \
        "$(basename "$directory") guest 1 loads at its link offset"
done

check_value "$zephyr" WT_GUEST0_FLASH_BASE 0x080A0000 \
    "Zephyr guest 0 links at the manifest base"
check_value "$zephyr" WT_GUEST1_FLASH_BASE 0x080E0000 \
    "Zephyr companion links at the manifest base"
check_value "$zephyr" WT_GUEST0_FLASH_SIZE 0x00040000 \
    "Zephyr guest 0 uses the manifest flash size"
check_value "$zephyr" WT_GUEST1_FLASH_SIZE 0x00020000 \
    "Zephyr companion uses the manifest flash size"
check_value "$zephyr" WT_GUEST0_EMU_OFFSET 0xA0000 \
    "Zephyr guest 0 loads at its link offset"
check_value "$zephyr" WT_GUEST1_EMU_OFFSET 0xE0000 \
    "Zephyr companion loads at its link offset"

check_recipe "$bare" ../../../build/wolftrust.bin \
    "WT_GUEST0_FLASH_BASE=0x080A0000" \
    "baremetal runner forwards its layout to the Secure build"
check_recipe "$bare" ../../../build/wolftrust.bin \
    "WT_GUEST0_FLASH_SIZE=0x00040000" \
    "baremetal runner forwards guest 0's flash size"
check_recipe "$bare" ../../../build/wolftrust.bin \
    "WT_GUEST1_FLASH_SIZE=0x00020000" \
    "baremetal runner forwards guest 1's flash size"
check_recipe "$vnet" secure "WT_GUEST1_FLASH_BASE=0x080E0000" \
    "VNET runner forwards its layout to the Secure build"
check_recipe "$vnet" secure "WT_GUEST0_FLASH_SIZE=0x00040000" \
    "VNET runner forwards guest 0's flash size"
check_recipe "$vnet" secure "WT_GUEST1_FLASH_SIZE=0x00020000" \
    "VNET runner forwards guest 1's flash size"
check_recipe "$zephyr" secure 'WT_GUEST0_FLASH_BASE="0x080A0000"' \
    "Zephyr runner forwards its layout to the Secure build"
check_recipe "$zephyr" secure 'WT_GUEST0_FLASH_SIZE="0x00040000"' \
    "Zephyr runner forwards guest 0's flash size"
check_recipe "$zephyr" secure 'WT_GUEST1_FLASH_SIZE="0x00020000"' \
    "Zephyr runner forwards guest 1's flash size"
check_file "$pkcs11_app" \
    'WT_GUEST0_FLASH_SIZE="${WT_GUEST0_FLASH_SIZE:-0x00020000}"' \
    "standalone PKCS11 application defaults to its non-overlapping slot"
check_file "$zephyr/patches/zephyr/0002-boards-arm-nucleo_h563zi-add-wolftrust-ns-reference.patch" \
    'reg = <0x000a0000 DT_SIZE_K(256)>;' \
    "Zephyr board partition matches the manifest window"
check_file "$zephyr/patches/zephyr/0002-boards-arm-nucleo_h563zi-add-wolftrust-ns-reference.patch" \
    '+flash: 256' \
    "Zephyr board metadata reports the manifest flash window"
check_file "$zephyr/patches/zephyr/0002-boards-arm-nucleo_h563zi-add-wolftrust-ns-reference.patch" \
    '+ram: 64' \
    "Zephyr board metadata reports the manifest RAM window"
check_rejected_size

echo "Guest runner layout tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: guest_runner_layout"
    exit 0
fi
echo "FAIL: guest_runner_layout"
exit 1
