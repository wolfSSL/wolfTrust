#!/usr/bin/env bash
# Reset control for the MIMXRT700-EVK rig: a Raspberry Pi 4 GPIO drives the
# board reset line (GPIO20 high = released, low = held in reset; SRAM survives).
# Runs from pi5 or anywhere that can ssh to the pi4.
# Usage: rt700_reset.sh release|hold|reset|status
set -euo pipefail

RT700_POWER_HOST="${RT700_POWER_HOST:-pi4}"
RT700_POWER_GPIO="${RT700_POWER_GPIO:-20}"
RT700_POWER_OFF_SECONDS="${RT700_POWER_OFF_SECONDS:-2}"
RT700_POWER_SETTLE_SECONDS="${RT700_POWER_SETTLE_SECONDS:-4}"

# The GPIO number lands in a command the remote shell parses.
case "$RT700_POWER_GPIO" in
    ''|*[!0-9]*)
        echo "RT700_POWER_GPIO must be a GPIO number, got '$RT700_POWER_GPIO'" >&2
        exit 2
        ;;
esac

gpio() {
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$RT700_POWER_HOST" \
        "raspi-gpio $*"
}

case "${1:-status}" in
    release) gpio set "$RT700_POWER_GPIO" op dh ;;
    hold)    gpio set "$RT700_POWER_GPIO" op dl ;;
    reset)
        gpio set "$RT700_POWER_GPIO" op dl
        sleep "$RT700_POWER_OFF_SECONDS"
        gpio set "$RT700_POWER_GPIO" op dh
        sleep "$RT700_POWER_SETTLE_SECONDS"
        ;;
    status) gpio get "$RT700_POWER_GPIO" ;;
    *)
        echo "usage: $0 release|hold|reset|status" >&2
        exit 2
        ;;
esac
