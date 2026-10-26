#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TPM_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ROOT=$(CDPATH= cd -- "$TPM_DIR/../../.." && pwd)

. "$ROOT/tests/target/lib/guest_build.sh"

APP_DIR="$TPM_DIR/freertos-pkcs11"
FREERTOS_DIR="${FREERTOS_DIR:-$ROOT/tests/firmware/zephyr-stm32h5/.workspace/freertos}"
FREERTOS_KERNEL="$FREERTOS_DIR/FreeRTOS/Source"
FREERTOS_PORT="$FREERTOS_KERNEL/portable/GCC/ARM_CM33_NTZ/non_secure"
if [ "${WT_CRYPTO_PROFILE:-default}" = default ]; then
    WT_PKCS11_SUITE="${WT_PKCS11_SUITE:-profile}"
else
    WT_PKCS11_SUITE="${WT_PKCS11_SUITE:-all}"
fi
BUILD_DIR="${BUILD_DIR:-$TPM_DIR/build/pkcs11-${WT_PKCS11_SUITE}}"
SECURE_CMSE_IMPLIB="${SECURE_CMSE_IMPLIB:-$ROOT/build/secure_cmse_implib.o}"

WT_GUEST0_FLASH_BASE="${WT_GUEST0_FLASH_BASE:-0x080A0000}"
WT_GUEST0_FLASH_SIZE="${WT_GUEST0_FLASH_SIZE:-0x00020000}"
WT_GUEST0_RAM_BASE="${WT_GUEST0_RAM_BASE:-0x20000000}"
WT_GUEST_RAM_SIZE="${WT_GUEST_RAM_SIZE:-0x00010000}"

case "$WT_PKCS11_SUITE" in
    profile)  SUITE_DEF=WT_PKCS11_SUITE_PROFILE ;;
    core)     SUITE_DEF=WT_PKCS11_SUITE_CORE ;;
    objects)  SUITE_DEF=WT_PKCS11_SUITE_OBJECTS ;;
    crypto)   SUITE_DEF=WT_PKCS11_SUITE_CRYPTO ;;
    negative) SUITE_DEF=WT_PKCS11_SUITE_NEGATIVE ;;
    all)      SUITE_DEF=WT_PKCS11_SUITE_ALL ;;
    *)
        echo "WT_PKCS11_SUITE must be profile, core, objects, crypto, negative, or all" >&2
        exit 2
        ;;
esac

if [ ! -d "$FREERTOS_KERNEL" ]; then
    echo "missing FreeRTOS workspace: $FREERTOS_KERNEL" >&2
    echo "run make -C tests/firmware/zephyr-stm32h5 clone first" >&2
    exit 1
fi
if [ ! -f "$SECURE_CMSE_IMPLIB" ]; then
    echo "missing CMSE import library: $SECURE_CMSE_IMPLIB" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

GUEST_CC="${GUEST_CC:-arm-none-eabi-gcc}"
GUEST_OBJCOPY="${GUEST_OBJCOPY:-arm-none-eabi-objcopy}"
GUEST_NM="${GUEST_NM:-arm-none-eabi-nm}"
GUEST_SIZE="${GUEST_SIZE:-arm-none-eabi-size}"

WOLFPKCS11_DIR="$ROOT/lib/wolfPKCS11"

FREERTOS_SRCS="
$FREERTOS_KERNEL/tasks.c
$FREERTOS_KERNEL/list.c
$FREERTOS_KERNEL/queue.c
$FREERTOS_PORT/port.c
$FREERTOS_PORT/portasm.c
$FREERTOS_KERNEL/portable/MemMang/heap_4.c"

CLIENT_SRCS="
$ROOT/src/client/pkcs11_proxy.c
$ROOT/src/pkcs11/pkcs11_wire.c"

# Keep the real PBKDF2 token path while bounding emulator runtime. This value
# is test-only; production builds retain wolfPKCS11's configured iteration count.
wt_guest_prepare_profile

CFLAGS="
-std=c99
-mcpu=cortex-m33 -mthumb -mgeneral-regs-only -mno-unaligned-access
-ffreestanding -fno-builtin -nostdlib -Os -g $WT_GUEST_LTO_FLAGS
-Wall -Wextra -Wno-unused-function -Wno-unused-variable
-Wno-unused-parameter -Wno-type-limits
-ffunction-sections -fdata-sections
-I$APP_DIR
-I$FREERTOS_KERNEL/include
-I$FREERTOS_PORT
-I$ROOT/include
-I$ROOT/port/stm32h563
-I$WOLFPKCS11_DIR
-DWOLFPKCS11_USER_SETTINGS -DWOLFPKCS11_NO_ENV
-D$SUITE_DEF=1
-DWT_M33MU_EXPECT_BKPT=1
-include time.h
-include $APP_DIR/user_settings.h"

CFLAGS="$CFLAGS $WT_GUEST_PROFILE_FLAGS"

LDFLAGS="$WT_GUEST_LTO_FLAGS $WT_GUEST_KEEP_FLAGS
-Wl,-u,vTaskStartScheduler,-u,C_GetFunctionList,-u,wt_pkcs11_psa_call

-Wl,-T$APP_DIR/guest0.ld
-Wl,--defsym=GUEST_FLASH_ORIGIN=$WT_GUEST0_FLASH_BASE
-Wl,--defsym=GUEST_FLASH_LENGTH=$WT_GUEST0_FLASH_SIZE
-Wl,--defsym=GUEST_RAM_ORIGIN=$WT_GUEST0_RAM_BASE
-Wl,--defsym=GUEST_RAM_LENGTH=$WT_GUEST_RAM_SIZE
-Wl,--gc-sections"

# shellcheck disable=SC2086
wt_guest_compile_platform "$APP_DIR/main.c" $FREERTOS_SRCS \
    "$ROOT/tests/firmware/stm32h563/nonsecure/libc_stubs_guest.c" "$ROOT/src/client/psa_ffm_client.c" "$ROOT/src/client/pkcs11_psa_transport.c"

# shellcheck disable=SC2086
$GUEST_CC $CFLAGS $LDFLAGS \
    -o "$BUILD_DIR/guest0.elf" \
    "$APP_DIR/pkcs11_tests.c" \
    $WT_GUEST_PLATFORM_OBJECTS \
    $CLIENT_SRCS \
    "$SECURE_CMSE_IMPLIB" \
    -lgcc

NM_OUT=$($GUEST_NM --defined-only "$BUILD_DIR/guest0.elf") || {
    echo "FAIL: nm on the FreeRTOS PKCS11 guest failed" >&2
    exit 1
}
printf '%s\n' "$NM_OUT" | grep -q 'vTaskStartScheduler' || {
    echo "FAIL: FreeRTOS scheduler missing from PKCS11 guest" >&2
    exit 1
}
printf '%s\n' "$NM_OUT" | grep -q 'C_GetFunctionList' || {
    echo "FAIL: PKCS11 proxy entry point missing from application guest" >&2
    exit 1
}
printf '%s\n' "$NM_OUT" | grep -q 'wt_pkcs11_psa_call' || {
    echo "FAIL: SERVICE_PKCS11 transport missing from application guest" >&2
    exit 1
}
if printf '%s\n' "$NM_OUT" | grep -Eq 'WP11_|wolfTPM|TPM2_'; then
    echo "FAIL: PKCS11 provider or TPM implementation linked into app guest" >&2
    exit 1
fi
if printf '%s\n' "$NM_OUT" | \
        grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then
    echo "FAIL: retired direct veneer linked into PKCS11 guest" >&2
    exit 1
fi

wt_guest_reject_psa_crypto "$NM_OUT"

$GUEST_OBJCOPY -O binary "$BUILD_DIR/guest0.elf" "$BUILD_DIR/guest0.bin"
$GUEST_SIZE "$BUILD_DIR/guest0.elf"
