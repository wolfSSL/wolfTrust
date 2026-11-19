#!/bin/sh
# Copyright (C) 2026 wolfSSL Inc. — GPLv3 (see Makefile header)
#
# Launches m33mu with the secure firmware + two NS guests, captures UART
# output via --uart-stdout, and asserts on the end-to-end success needle:
# guest0 prints "ping reply from 10.0.0.2 seq=N" once wolfIP's ICMP echo
# round-trips through the secure-monitor VNET.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EMU_CMD="${M33MU:-m33mu}"
EMU_TIMEOUT="${EMU_TIMEOUT:-60}"
SECURE_BIN="${SECURE_BIN:-$SCRIPT_DIR/../../../build/wolftrust.bin}"
GUEST0_BIN="${GUEST0_BIN:-$SCRIPT_DIR/build/guest0.bin}"
GUEST1_BIN="${GUEST1_BIN:-$SCRIPT_DIR/build/guest1.bin}"
WT_GUEST0_EMU_OFFSET="${WT_GUEST0_EMU_OFFSET:-0x20000}"
WT_GUEST1_EMU_OFFSET="${WT_GUEST1_EMU_OFFSET:-0x40000}"

LOG_FILE=$(mktemp)
RC_FILE=$(mktemp)
trap 'rm -f "$LOG_FILE" "$RC_FILE"' EXIT INT TERM

set +e
# m33mu emits a [TZ_WARN] line on every secure->NS branch whose target
# differs from VTOR_NS[1] — i.e. on every dispatch after the first.
# It's benign chatter that drowns the actual UART traffic; filter it
# out of the live stream but keep the raw log untouched in case a
# real fault needs investigating.
( stdbuf -oL -eL "$EMU_CMD" --cpu stm32h563 --timeout "$EMU_TIMEOUT" \
      --uart-stdout --quit-on-faults \
      "$SECURE_BIN" \
      "$GUEST0_BIN:$WT_GUEST0_EMU_OFFSET" \
      "$GUEST1_BIN:$WT_GUEST1_EMU_OFFSET" 2>&1
  echo $? >"$RC_FILE"
) | tee "$LOG_FILE" | grep --line-buffered -vE '^\[TZ_WARN\]' || true
set -e
EMU_STATUS=$(cat "$RC_FILE")

CLEAN_LOG=$(mktemp)
awk '{
    s = $0
    suppress_nl = 0
    while (match(s, /\[UART\] [0-9a-fA-F]+ attached to [^ ]+/)) {
        prefix = substr(s, 1, RSTART - 1)
        rest = substr(s, RSTART + RLENGTH)
        if (rest == "") suppress_nl = 1
        s = prefix rest
    }
    if (suppress_nl) printf "%s", s
    else print s
}' "$LOG_FILE" >"$CLEAN_LOG"

if grep -Eq '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)' "$CLEAN_LOG"; then
    echo "FAIL: secure fault observed" >&2
    rm -f "$CLEAN_LOG"
    exit 1
fi

NEEDLES="\
vnet-guest0: alive|\
vnet-guest1: alive|\
ping seq=1 to 10.0.0.2|\
ping reply from 10.0.0.2 seq=1"

missing=
IFS='|'
set -f
for needle in $NEEDLES; do
    [ -n "$needle" ] || continue
    if ! grep -Fq "$needle" "$CLEAN_LOG"; then
        missing="${missing}${missing:+, }${needle}"
    fi
done
set +f
unset IFS
rm -f "$CLEAN_LOG"
if [ -n "$missing" ]; then
    echo "missing expected output: $missing" >&2
    exit 1
fi

# m33mu returns 127 on --timeout fire; with two infinite guests that is
# the normal exit once the needles have been seen.
if [ "$EMU_STATUS" -eq 127 ]; then
    exit 0
fi
exit "$EMU_STATUS"
