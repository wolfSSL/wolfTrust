#!/usr/bin/env bash
# Board-present check for the FRDM-MCXN947 rig: the on-board MCU-Link probe
# (NXP 1fc9:0143), its VCOM, a pyOCD with the MCXN947 pack, and SPSDK's blhost
# for the ISP life-cycle path. Exit 0 when usable; otherwise print one SKIP
# reason and exit 1.
set -u

MCXN947_SERIAL="${MCXN947_SERIAL:-/dev/ttyACM0}"
MCXN947_PYOCD="${MCXN947_PYOCD:-pyocd}"

if ! command -v lsusb >/dev/null 2>&1 || ! lsusb 2>/dev/null | grep -q "1fc9:0143"; then
    echo "MCU-Link probe (1fc9:0143) not attached"
    exit 1
fi
if [ ! -c "$MCXN947_SERIAL" ]; then
    echo "board console $MCXN947_SERIAL not present"
    exit 1
fi
if ! command -v "$MCXN947_PYOCD" >/dev/null 2>&1; then
    echo "pyocd not installed"
    exit 1
fi
if ! "$MCXN947_PYOCD" pack find mcxn947 2>/dev/null | grep -q "True"; then
    echo "pyocd MCXN947 pack not installed (pyocd pack install MCXN947)"
    exit 1
fi
if ! command -v blhost >/dev/null 2>&1; then
    echo "spsdk (blhost) not installed"
    exit 1
fi
exit 0
