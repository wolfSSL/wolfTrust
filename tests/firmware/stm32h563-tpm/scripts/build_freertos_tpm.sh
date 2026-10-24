#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TPM_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ROOT=$(CDPATH= cd -- "$TPM_DIR/../../.." && pwd)

. "$ROOT/tests/target/lib/engine.sh"

APP_DIR="$TPM_DIR/freertos-tpm"
TEST_DIR="$TPM_DIR/tpm-app"
FREERTOS_DIR="${FREERTOS_DIR:-$ROOT/tests/firmware/zephyr-stm32h5/.workspace/freertos}"
FREERTOS_KERNEL="$FREERTOS_DIR/FreeRTOS/Source"
FREERTOS_PORT="$FREERTOS_KERNEL/portable/GCC/ARM_CM33_NTZ/non_secure"
BUILD_DIR="${BUILD_DIR:-$TPM_DIR/build/tpm-freertos}"
SECURE_CMSE_IMPLIB="${SECURE_CMSE_IMPLIB:-$ROOT/build/secure_cmse_implib.o}"

WT_GUEST0_FLASH_BASE="${WT_GUEST0_FLASH_BASE:-0x080A0000}"
WT_GUEST0_FLASH_SIZE="${WT_GUEST0_FLASH_SIZE:-0x00040000}"
WT_GUEST0_RAM_BASE="${WT_GUEST0_RAM_BASE:-0x20000000}"
WT_GUEST_RAM_SIZE="${WT_GUEST_RAM_SIZE:-0x00010000}"

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

WOLFSSL_DIR="$ROOT/lib/wolfSSL"
WOLFTPM_DIR="$ROOT/lib/wolfTPM"

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
$WOLFSSL_DIR/wolfcrypt/src/sp_cortexm.c
$WOLFSSL_DIR/wolfcrypt/src/sp_int.c
$WOLFSSL_DIR/wolfcrypt/src/wolfmath.c
$WOLFSSL_DIR/wolfcrypt/src/wc_port.c
$WOLFSSL_DIR/wolfcrypt/src/sha512.c
$WOLFSSL_DIR/wolfcrypt/src/kdf.c
$WOLFSSL_DIR/wolfcrypt/src/pwdbased.c
$WOLFSSL_DIR/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
$WOLFSSL_DIR/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c"

WOLFTPM_SRCS="
$WOLFTPM_DIR/src/tpm2.c
$WOLFTPM_DIR/src/tpm2_util.c
$WOLFTPM_DIR/src/tpm2_packet.c
$WOLFTPM_DIR/src/tpm2_wrap.c
$WOLFTPM_DIR/src/tpm2_asn.c
$WOLFTPM_DIR/src/tpm2_crypto.c
$WOLFTPM_DIR/src/tpm2_param_enc.c
$WOLFTPM_DIR/src/tpm2_cryptocb.c"

ENGINE_DEFS="-DWT_ENGINE_NATIVE=1"
ENGINE_SRCS="$ROOT/src/client/crypto_native_client.c"
if [ "$WT_ENGINE" = hsm ]; then
    mkdir -p "$BUILD_DIR/wh_include"
    printf '#include "%s"\n' "$ROOT/tests/firmware/stm32h563/nonsecure/wh_settings_guest.h" > "$BUILD_DIR/wh_include/wolfhsm_cfg.h"
    ENGINE_DEFS="-DWT_ENGINE_HSM=1 -DWOLFHSM_CFG
        -I$ROOT/lib/wolfHSM -I$BUILD_DIR/wh_include
        -DWT_WOLFHSM_CLIENT_ID=1"
    ENGINE_SRCS="$ROOT/src/client/hsm_psa_transport.c
        $ROOT/tests/firmware/zephyr-stm32h5/module/wolfhsm-client/src/wolfhsm_client_glue.c"
    for source in wh_client wh_client_crypto wh_client_cryptocb wh_comm \
        wh_crypto wh_keyid wh_message_comm wh_message_crypto \
        wh_message_keystore wh_message_nvm wh_message_customcb \
        wh_message_counter wh_utils; do
        ENGINE_SRCS="$ENGINE_SRCS $ROOT/lib/wolfHSM/src/$source.c"
    done
fi

CLIENT_SRCS="
$ROOT/src/client/psa_ffm_client.c
$ENGINE_SRCS
$ROOT/src/client/tpm_psa_transport.c
$ROOT/tests/firmware/stm32h563/nonsecure/libc_stubs_guest.c"

CFLAGS="
-std=c99
-mcpu=cortex-m33 -mthumb -mgeneral-regs-only -mno-unaligned-access
-ffreestanding -fno-builtin -nostdlib -Os -g
-Wall -Wextra -Wno-unused-function -Wno-unused-variable
-Wno-unused-parameter -Wno-type-limits
-ffunction-sections -fdata-sections
-I$APP_DIR
-I$TEST_DIR
-I$FREERTOS_KERNEL/include
-I$FREERTOS_PORT
-I$ROOT/include
-I$ROOT/port/stm32h563
-I$WOLFSSL_DIR
-I$WOLFTPM_DIR
-DWOLFSSL_USER_SETTINGS -DWOLFTPM_USER_SETTINGS
-DWOLFTPM_SWTPM -DWOLFTPM_SMALL_STACK
-DWOLF_CRYPTO_CB
$ENGINE_DEFS -DWT_TPM_APP_NAME=\"tpm-freertos\"
-DWT_M33MU_EXPECT_BKPT=1
-DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM -DWOLFSSL_ARM_ARCH=8
-DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_ARMASM_INLINE
-DWOLFSSL_ARMASM_NO_NEON -DWOLFSSL_ARMASM_THUMB2
-DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT
-DWC_RESEED_INTERVAL=1000000
-include $APP_DIR/user_settings.h"

LDFLAGS="
-Wl,-T$TPM_DIR/freertos-pkcs11/guest0.ld
-Wl,--defsym=GUEST_FLASH_ORIGIN=$WT_GUEST0_FLASH_BASE
-Wl,--defsym=GUEST_FLASH_LENGTH=$WT_GUEST0_FLASH_SIZE
-Wl,--defsym=GUEST_RAM_ORIGIN=$WT_GUEST0_RAM_BASE
-Wl,--defsym=GUEST_RAM_LENGTH=$WT_GUEST_RAM_SIZE
-Wl,--gc-sections"

# shellcheck disable=SC2086
$GUEST_CC $CFLAGS $LDFLAGS \
    -o "$BUILD_DIR/guest0.elf" \
    "$APP_DIR/main.c" \
    "$TEST_DIR/tpm_tests.c" \
    $FREERTOS_SRCS \
    $WOLFCRYPT_SRCS \
    $WOLFTPM_SRCS \
    $CLIENT_SRCS \
    "$SECURE_CMSE_IMPLIB" \
    -lgcc

NM_OUT=$($GUEST_NM "$BUILD_DIR/guest0.elf") || {
    echo "FAIL: nm on the FreeRTOS TPM guest failed" >&2
    exit 1
}
printf '%s\n' "$NM_OUT" | grep -q 'vTaskStartScheduler' || {
    echo "FAIL: FreeRTOS scheduler missing from TPM guest" >&2
    exit 1
}
printf '%s\n' "$NM_OUT" | grep -q 'wt_tpm_psa_submit' || {
    echo "FAIL: SERVICE_TPM transport missing from application guest" >&2
    exit 1
}
printf '%s\n' "$NM_OUT" | grep -q 'TPM2_SWTPM_SendCommand' || {
    echo "FAIL: wolfTPM client is not routed through SERVICE_TPM" >&2
    exit 1
}
if printf '%s\n' "$NM_OUT" | grep -q 'FWTPM_ProcessCommand'; then
    echo "FAIL: fwTPM provider linked into TPM application guest" >&2
    exit 1
fi
if printf '%s\n' "$NM_OUT" | \
        grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then
    echo "FAIL: retired direct veneer linked into TPM guest" >&2
    exit 1
fi

$GUEST_OBJCOPY -O binary "$BUILD_DIR/guest0.elf" "$BUILD_DIR/guest0.bin"
$GUEST_SIZE "$BUILD_DIR/guest0.elf"
