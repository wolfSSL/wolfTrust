#!/usr/bin/env bash
# Board-present check for the FRDM-MCXN947 rig: the on-board MCU-Link probe
# (the one pyOCD lists as "MCU-LINK FRDM-MCXN947", or MCXN947_PROBE_UID), its
# VCOM, a pyOCD with the MCXN947 pack, and SPSDK's blhost for the ISP
# life-cycle path. Exit 0 when usable; otherwise print one SKIP reason and
# exit 1.
set -u

MCXN947_PYOCD="${MCXN947_PYOCD:-pyocd}"
MCXN947_SPSDK_VENV="${MCXN947_SPSDK_VENV:-$HOME/spsdk-venv}"

if ! command -v "$MCXN947_PYOCD" >/dev/null 2>&1; then
    if [ -x "$MCXN947_SPSDK_VENV/bin/pyocd" ]; then
        PATH="$MCXN947_SPSDK_VENV/bin:$PATH"
        export PATH
    else
        echo "pyocd not installed"
        exit 1
    fi
fi
probes="$("$MCXN947_PYOCD" list 2>/dev/null | grep -F "FRDM-MCXN947" || true)"
if [ -n "${MCXN947_PROBE_UID:-}" ]; then
    probes="$("$MCXN947_PYOCD" list 2>/dev/null | grep -F "$MCXN947_PROBE_UID" || true)"
fi
if [ -z "$probes" ]; then
    echo "MCU-Link FRDM-MCXN947 probe not attached (set MCXN947_PROBE_UID for another)"
    exit 1
fi
console="${MCXN947_CONSOLE:-}"
if [ -z "$console" ]; then
    for tty in /dev/serial/by-id/*FRDM-MCXN947*-if02; do
        [ -c "$tty" ] && console="$tty" && break
    done
fi
if [ -z "$console" ] || [ ! -c "$console" ]; then
    echo "board console not present (MCXN947_CONSOLE)"
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
