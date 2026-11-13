#!/usr/bin/env bash
# Board-present check for the STM32L562E-DK rig: a probe tool
# (STM32CubeProgrammer's CLI, else OpenOCD; lib/stm32l562_probe.sh), the DK's
# on-board ST-LINK (the one attached whose board is an STM32L562E-DK, or
# STM32L562_STLINK_SN when it is one), its virtual COM port, every host and
# Arm tool the runner and its builds call, and flock for the board lock.
# Exit 0 when usable; otherwise print one SKIP reason and exit 1.
set -u

here="$(cd "${0%/*}" && pwd)"
# shellcheck source=lib/stm32l562_probe.sh disable=SC1091
. "$here/lib/stm32l562_probe.sh"
sn="${STM32L562_STLINK_SN:-}"
byid="${STM32L562_BYID_DIR:-/dev/serial/by-id}"

# shellcheck disable=SC2034  # read by the sourced probe library
if ! L5_TOOL="$(l5_tool)"; then
    l5_tool_missing
    exit 1
fi
for tool in arm-none-eabi-gcc arm-none-eabi-gcc-nm arm-none-eabi-nm \
        arm-none-eabi-objcopy arm-none-eabi-objdump arm-none-eabi-size \
        make python3 stty sha256sum flock timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool not installed"
        exit 1
    fi
done
listed="$(l5_dk_serials)"
if [ -n "$sn" ]; then
    listed="$(printf '%s\n' "$listed" | grep -Fx "$sn" || true)"
fi
if [ -z "$listed" ]; then
    echo "STM32L562E-DK ST-LINK not attached (set STM32L562_STLINK_SN for another)"
    exit 1
fi
if [ "$(printf '%s\n' "$listed" | grep -c .)" -gt 1 ]; then
    echo "more than one STM32L562E-DK attached (set STM32L562_STLINK_SN)"
    exit 1
fi
console="${STM32L562_CONSOLE:-}"
if [ -z "$console" ]; then
    for tty in "$byid"/*STLINK*"$listed"*-if0[0-9]; do
        [ -c "$tty" ] && console="$tty" && break
    done
fi
if [ -z "$console" ] || [ ! -c "$console" ]; then
    echo "board console not present (STM32L562_CONSOLE)"
    exit 1
fi
exit 0
