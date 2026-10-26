#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TPM_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ROOT=$(CDPATH= cd -- "$TPM_DIR/../../.." && pwd)

. "$ROOT/tests/target/lib/guest_build.sh"

. "$ROOT/tests/target/lib/engine.sh"

APP_DIR="$TPM_DIR/freertos-pkcs11-provider"
FREERTOS_DIR="${FREERTOS_DIR:-$ROOT/tests/firmware/zephyr-stm32h5/.workspace/freertos}"
FREERTOS_KERNEL="$FREERTOS_DIR/FreeRTOS/Source"
FREERTOS_PORT="$FREERTOS_KERNEL/portable/GCC/ARM_CM33_NTZ/non_secure"
BUILD_DIR="${BUILD_DIR:-$TPM_DIR/build/pkcs11}"
SECURE_CMSE_IMPLIB="${SECURE_CMSE_IMPLIB:-$ROOT/build/secure_cmse_implib.o}"
WT_GUEST1_FLASH_BASE="${WT_GUEST1_FLASH_BASE:-0x080C0000}"
WT_GUEST1_FLASH_SIZE="${WT_GUEST1_FLASH_SIZE:-0x00040000}"
WT_GUEST1_RAM_BASE="${WT_GUEST1_RAM_BASE:-0x20010000}"
WT_GUEST_RAM_SIZE="${WT_GUEST_RAM_SIZE:-0x00010000}"

if [ ! -d "$FREERTOS_KERNEL" ]; then
    echo "missing FreeRTOS workspace: $FREERTOS_KERNEL" >&2
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

WOLFSSL_DIR="$ROOT/lib/wolfSSL"
WOLFHSM_DIR="$ROOT/lib/wolfHSM"
WOLFPKCS11_DIR="$ROOT/lib/wolfPKCS11"
WOLFHSM_GLUE="$ROOT/tests/firmware/zephyr-stm32h5/module/wolfhsm-client/src/wolfhsm_client_glue.c"
NS_DIR="$ROOT/tests/firmware/stm32h563/nonsecure"
WH_CFG_DIR="$BUILD_DIR/wh_include"
mkdir -p "$WH_CFG_DIR"
printf '#include "%s"\n' "$NS_DIR/wh_settings_guest.h" > "$WH_CFG_DIR/wolfhsm_cfg.h"

FREERTOS_SRCS="
$FREERTOS_KERNEL/tasks.c
$FREERTOS_KERNEL/list.c
$FREERTOS_KERNEL/queue.c
$FREERTOS_PORT/port.c
$FREERTOS_PORT/portasm.c
$FREERTOS_KERNEL/portable/MemMang/heap_4.c"

WOLFCRYPT_SRCS="
$WOLFSSL_DIR/wolfcrypt/src/aes.c
$WOLFSSL_DIR/wolfcrypt/src/cryptocb.c
$WOLFSSL_DIR/wolfcrypt/src/ecc.c
$WOLFSSL_DIR/wolfcrypt/src/random.c
$WOLFSSL_DIR/wolfcrypt/src/sha256.c
$WOLFSSL_DIR/wolfcrypt/src/asn.c
$WOLFSSL_DIR/wolfcrypt/src/coding.c
$WOLFSSL_DIR/wolfcrypt/src/error.c
$WOLFSSL_DIR/wolfcrypt/src/hash.c
$WOLFSSL_DIR/wolfcrypt/src/hmac.c
$WOLFSSL_DIR/wolfcrypt/src/memory.c
$WOLFSSL_DIR/wolfcrypt/src/sha.c
$WOLFSSL_DIR/wolfcrypt/src/sha512.c
$WOLFSSL_DIR/wolfcrypt/src/kdf.c
$WOLFSSL_DIR/wolfcrypt/src/pwdbased.c
$WOLFSSL_DIR/wolfcrypt/src/sp_cortexm.c
$WOLFSSL_DIR/wolfcrypt/src/sp_int.c
$WOLFSSL_DIR/wolfcrypt/src/wolfmath.c
$WOLFSSL_DIR/wolfcrypt/src/wc_port.c
$WOLFSSL_DIR/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
$WOLFSSL_DIR/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c"

WOLFHSM_SRCS="
$WOLFHSM_DIR/src/wh_client.c
$WOLFHSM_DIR/src/wh_client_crypto.c
$WOLFHSM_DIR/src/wh_client_cryptocb.c
$WOLFHSM_DIR/src/wh_comm.c
$WOLFHSM_DIR/src/wh_crypto.c
$WOLFHSM_DIR/src/wh_keyid.c
$WOLFHSM_DIR/src/wh_message_comm.c
$WOLFHSM_DIR/src/wh_message_crypto.c
$WOLFHSM_DIR/src/wh_message_keystore.c
$WOLFHSM_DIR/src/wh_message_nvm.c
$WOLFHSM_DIR/src/wh_message_customcb.c
$WOLFHSM_DIR/src/wh_message_counter.c
$WOLFHSM_DIR/src/wh_utils.c"

WOLFPKCS11_SRCS="
$WOLFPKCS11_DIR/src/wolfpkcs11.c
$WOLFPKCS11_DIR/src/internal.c
$WOLFPKCS11_DIR/src/slot.c
$WOLFPKCS11_DIR/src/crypto.c"

WT_SRCS="
$ROOT/src/pkcs11/pkcs11_wire.c
$ROOT/src/pkcs11/pkcs11_provider.c
"

ENGINE_DEFS="-DWT_ENGINE_NATIVE=1"
ENGINE_SRCS="$ROOT/src/client/crypto_native_client.c"
if [ "$WT_ENGINE" = hsm ]; then
    ENGINE_DEFS="-DWT_ENGINE_HSM=1 -DWOLFHSM_CFG -DWOLF_CRYPTO_CB
        -DWOLFPKCS11_DEFAULT_DEVID=0x5748534D"
    ENGINE_SRCS="$WOLFHSM_SRCS $WOLFHSM_GLUE
        $ROOT/src/client/hsm_psa_transport.c"
fi

# Production keeps wolfPKCS11's 600,000-round PIN PBKDF2; only the M33MU
# emulator gate lowers it, explicitly, because emulated SHA-256 is too slow.
PBKDF2_TEST_DEF=
if [ -n "${WT_PKCS11_TEST_PBKDF2_ITERATIONS:-}" ]; then
    echo "NOTE: emulator-only PIN PBKDF2 iterations=$WT_PKCS11_TEST_PBKDF2_ITERATIONS" >&2
    PBKDF2_TEST_DEF="-DPBKDF2_ITERATIONS=$WT_PKCS11_TEST_PBKDF2_ITERATIONS"
fi

# No trusted clock here: WOLFPKCS11_NO_TIME drops wolfPKCS11's lockout and
# pkcs11_provider.c enforces WT_PKCS11_PIN_MAX_FAILURES instead.
PIN_LIMIT_DEF=
if [ -n "${WT_PKCS11_PIN_MAX_FAILURES:-}" ]; then
    case "$WT_PKCS11_PIN_MAX_FAILURES" in
        *[!0-9]*|0*)
            echo "FAIL: WT_PKCS11_PIN_MAX_FAILURES must be > 0" >&2
            exit 1
            ;;
    esac
    PIN_LIMIT_DEF="-DWT_PKCS11_PIN_MAX_FAILURES=${WT_PKCS11_PIN_MAX_FAILURES}U"
fi

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
-I$WOLFSSL_DIR
-I$WOLFHSM_DIR
-I$WOLFPKCS11_DIR
-I$NS_DIR
-I$WH_CFG_DIR
-DWOLFSSL_USER_SETTINGS -DWOLFPKCS11_USER_SETTINGS
-DWOLFPKCS11_NO_STORE -DWOLFPKCS11_NO_TIME -DWOLFPKCS11_NO_ENV
$ENGINE_DEFS
-DWT_WOLFHSM_CLIENT_ID=2
-DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM
-DWOLFSSL_ARM_ARCH=8 -DWOLFSSL_ARMASM
-DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_ARMASM_INLINE
-DWOLFSSL_ARMASM_NO_NEON -DWOLFSSL_ARMASM_THUMB2
-DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT
-DWC_RESEED_INTERVAL=1000000 $PBKDF2_TEST_DEF $PIN_LIMIT_DEF
-include time.h
-include $APP_DIR/user_settings.h"

if [ "$WT_ENGINE" = hsm ]; then
    WT_GUEST_KEEP_FLAGS="$WT_GUEST_KEEP_FLAGS -Wl,-u,wt_hsm_psa_transport_cb"
else
    WT_GUEST_KEEP_FLAGS="$WT_GUEST_KEEP_FLAGS -Wl,-u,wt_crypto_native_random"
fi

wt_guest_hsm_ecc_flags
CFLAGS="$CFLAGS $WT_GUEST_PROFILE_FLAGS $WT_GUEST_HSM_ECC_FLAGS"
if wt_guest_profile_enabled pkcs11 C_GetSlotList; then
    WT_GUEST_KEEP_FLAGS="$WT_GUEST_KEEP_FLAGS -Wl,-u,WP11_GetSlotList"
fi

LDFLAGS="$WT_GUEST_LTO_FLAGS $WT_GUEST_KEEP_FLAGS
-Wl,-u,vTaskStartScheduler,-u,wt_pkcs11_provider_dispatch

-Wl,-T$APP_DIR/guest1.ld
-Wl,--defsym=GUEST_FLASH_ORIGIN=$WT_GUEST1_FLASH_BASE
-Wl,--defsym=GUEST_FLASH_LENGTH=$WT_GUEST1_FLASH_SIZE
-Wl,--defsym=GUEST_RAM_ORIGIN=$WT_GUEST1_RAM_BASE
-Wl,--defsym=GUEST_RAM_LENGTH=$WT_GUEST_RAM_SIZE
-Wl,--gc-sections"

# shellcheck disable=SC2086
wt_guest_compile_platform "$APP_DIR/main.c" $FREERTOS_SRCS \
    "$NS_DIR/libc_stubs_guest.c" "$ROOT/src/client/psa_ffm_client.c" "$ROOT/src/client/pkcs11_psa_transport.c"

# shellcheck disable=SC2086
$GUEST_CC $CFLAGS $LDFLAGS -o "$BUILD_DIR/guest1.elf" \
    $WT_GUEST_PLATFORM_OBJECTS $WOLFCRYPT_SRCS $ENGINE_SRCS \
    $WOLFPKCS11_SRCS $WT_SRCS "$SECURE_CMSE_IMPLIB" -lgcc

NM_OUT=$($GUEST_NM --defined-only "$BUILD_DIR/guest1.elf") || exit 1
printf '%s\n' "$NM_OUT" | grep -q 'wt_pkcs11_provider_dispatch' || {
    echo "FAIL: PKCS11 provider dispatch missing from provider guest" >&2
    exit 1
}
if [ "$WT_ENGINE" = hsm ]; then
printf '%s\n' "$NM_OUT" | grep -q 'wt_hsm_psa_transport_cb' || {
    echo "FAIL: provider is not connected to SERVICE_HSM" >&2
    exit 1
}
else
    printf '%s\n' "$NM_OUT" | grep -q 'wt_crypto_native_random' || exit 1
    if printf '%s\n' "$NM_OUT" | grep -q 'wh_Client_'; then
        echo "FAIL: native provider links a wolfHSM client" >&2
        exit 1
    fi
fi
if wt_guest_profile_enabled pkcs11 C_GetSlotList; then
    printf '%s\n' "$NM_OUT" | grep -q 'WP11_GetSlotList' || {
        echo "FAIL: wolfPKCS11 provider implementation missing" >&2
        exit 1
    }
fi
if printf '%s\n' "$NM_OUT" | grep -Eq 'wt_tpm_psa_|TPM2_SWTPM|wolfTPM'; then
    echo "FAIL: TPM transport linked into independent PKCS11 provider" >&2
    exit 1
fi
if printf '%s\n' "$NM_OUT" | \
        grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then
    echo "FAIL: retired direct veneer linked into provider guest" >&2
    exit 1
fi

wt_guest_reject_psa_crypto "$NM_OUT"

$GUEST_OBJCOPY -O binary "$BUILD_DIR/guest1.elf" "$BUILD_DIR/guest1.bin"
$GUEST_SIZE "$BUILD_DIR/guest1.elf"
