#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR="$SCRIPT_DIR/build"
SECURE_BIN="${SECURE_BIN:-$SCRIPT_DIR/../../../build/wolftrust.bin}"
LOG_FILE=$(mktemp)
EMU_CMD="${M33MU:-m33mu}"
EMU_TIMEOUT="${EMU_TIMEOUT:-300}"
WT_ENGINE_HSM="${WT_ENGINE_HSM:-0}"
WT_MAX_GUESTS="${WT_MAX_GUESTS:-2}"
WT_CO_STACK_SIZE="${WT_CO_STACK_SIZE:-24576}"
WT_WOLFCRYPT_SP_ASM="${WT_WOLFCRYPT_SP_ASM:-1}"
WT_WOLFCRYPT_ARMASM="${WT_WOLFCRYPT_ARMASM:-1}"
WT_SHARED_UART="${WT_SHARED_UART:-3}"
WT_GUEST0_FLASH_ORIGIN="${WT_GUEST0_FLASH_ORIGIN:-0x08020000}"
WT_GUEST1_FLASH_ORIGIN="${WT_GUEST1_FLASH_ORIGIN:-0x08040000}"
WT_GUEST_FLASH_SIZE="${WT_GUEST_FLASH_SIZE:-0x00020000}"
WT_GUEST_FLASH_LENGTH="${WT_GUEST_FLASH_LENGTH:-$WT_GUEST_FLASH_SIZE}"
WT_GUEST_RAM_SIZE="${WT_GUEST_RAM_SIZE:-0x00008000}"
WT_BENCH_MIN_RUNTIME_SEC="${WT_BENCH_MIN_RUNTIME_SEC:-0.0}"
WT_GUEST0_EMU_OFFSET="${WT_GUEST0_EMU_OFFSET:-0x20000}"
WT_GUEST1_EMU_OFFSET="${WT_GUEST1_EMU_OFFSET:-0x40000}"

cleanup() {
    if [ -n "${EMU_PID:-}" ] && kill -0 "$EMU_PID" 2>/dev/null; then
        kill "$EMU_PID" 2>/dev/null || true
        wait "$EMU_PID" 2>/dev/null || true
    fi
    if [ -n "${UART2_CAT_PID:-}" ]; then
        kill "$UART2_CAT_PID" 2>/dev/null || true
    fi
    if [ -n "${UART3_CAT_PID:-}" ]; then
        kill "$UART3_CAT_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE"
}

trap cleanup EXIT INT TERM

make -C "$SCRIPT_DIR" WT_ENGINE_HSM="$WT_ENGINE_HSM" \
    WT_MAX_GUESTS="$WT_MAX_GUESTS" WT_CO_STACK_SIZE="$WT_CO_STACK_SIZE" \
    WT_WOLFCRYPT_SP_ASM="$WT_WOLFCRYPT_SP_ASM" \
    WT_WOLFCRYPT_ARMASM="$WT_WOLFCRYPT_ARMASM" \
    WT_GUEST0_FLASH_ORIGIN="$WT_GUEST0_FLASH_ORIGIN" \
    WT_GUEST1_FLASH_ORIGIN="$WT_GUEST1_FLASH_ORIGIN" \
    WT_GUEST_FLASH_SIZE="$WT_GUEST_FLASH_SIZE" \
    WT_GUEST_FLASH_LENGTH="$WT_GUEST_FLASH_LENGTH" \
    WT_GUEST_RAM_SIZE="$WT_GUEST_RAM_SIZE" \
    WT_BENCH_MIN_RUNTIME_SEC="$WT_BENCH_MIN_RUNTIME_SEC" \
    WT_GUEST0_EMU_OFFSET="$WT_GUEST0_EMU_OFFSET" \
    WT_GUEST1_EMU_OFFSET="$WT_GUEST1_EMU_OFFSET" \
    WT_SHARED_UART="$WT_SHARED_UART" all >/dev/null

stdbuf -oL -eL "$EMU_CMD" --cpu stm32h563 --timeout "$EMU_TIMEOUT" --quit-on-faults \
    "$SECURE_BIN" "$BUILD_DIR/guest0.bin:$WT_GUEST0_EMU_OFFSET" "$BUILD_DIR/guest1.bin:$WT_GUEST1_EMU_OFFSET" \
    >"$LOG_FILE" 2>&1 &
EMU_PID=$!

UART2_PTY=""
UART3_PTY=""
UART2_CAT_PID=""
UART3_CAT_PID=""
TRIES=0
while [ "$TRIES" -lt 100 ]; do
    if [ -z "$UART2_PTY" ]; then
        UART2_PTY=$(sed -n 's/.*\[UART\] 40004400 attached to \(.*\)$/\1/p' "$LOG_FILE" | tail -n 1)
        if [ -n "$UART2_PTY" ]; then
            stdbuf -oL cat "$UART2_PTY" 2>/dev/null | sed 's/^/[USART2] /' &
            UART2_CAT_PID=$!
        fi
    fi
    if [ -z "$UART3_PTY" ]; then
        UART3_PTY=$(sed -n 's/.*\[UART\] 40004800 attached to \(.*\)$/\1/p' "$LOG_FILE" | tail -n 1)
        if [ -n "$UART3_PTY" ]; then
            stdbuf -oL cat "$UART3_PTY" 2>/dev/null | sed 's/^/[USART3] /' &
            UART3_CAT_PID=$!
        fi
    fi
    if [ -n "$UART2_PTY" ] && [ -n "$UART3_PTY" ]; then
        break
    fi
    if ! kill -0 "$EMU_PID" 2>/dev/null; then
        break
    fi
    TRIES=$((TRIES + 1))
    sleep 0.1
done

set +e
wait "$EMU_PID"
EMU_STATUS=$?
set -e

sed -n '/^\[UART\]/p;/^\[BKPT\]/p;/^\[MEMFAULT\]/p;/^\[HARDFLT\]/p;/^HardFault/p;/^SecureFault/p;/^Execution stopped/p' "$LOG_FILE"

if [ "$EMU_STATUS" -eq 127 ]; then
    exit 0
fi
if grep -Eq '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)' "$LOG_FILE"; then
    exit 1
fi
exit "$EMU_STATUS"
