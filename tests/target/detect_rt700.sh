#!/usr/bin/env bash
# Board-present check for the MIMXRT700-EVK rig: the on-board MCU-Link probe
# (NXP 1fc9:0143), its VCOM, and a pyOCD with the MIMXRT798S pack. Exit 0 when
# usable; otherwise print one SKIP reason and exit 1.
set -u

RT700_SERIAL="${RT700_SERIAL:-/dev/ttyACM0}"
RT700_PYOCD="${RT700_PYOCD:-pyocd}"

if ! command -v lsusb >/dev/null 2>&1 || ! lsusb 2>/dev/null | grep -q "1fc9:0143"; then
    echo "MCU-Link probe (1fc9:0143) not attached"
    exit 1
fi
if [ ! -c "$RT700_SERIAL" ]; then
    echo "board console $RT700_SERIAL not present"
    exit 1
fi
if ! command -v "$RT700_PYOCD" >/dev/null 2>&1; then
    echo "pyocd not installed"
    exit 1
fi
if ! "$RT700_PYOCD" pack find mimxrt798 2>/dev/null | grep -q "True"; then
    echo "pyocd MIMXRT798S pack not installed (pyocd pack install MIMXRT798S)"
    exit 1
fi
if ! command -v nxpimage >/dev/null 2>&1; then
    echo "spsdk (nxpimage) not installed"
    exit 1
fi
exit 0
