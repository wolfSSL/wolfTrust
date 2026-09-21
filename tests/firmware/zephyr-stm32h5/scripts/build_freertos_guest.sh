#!/bin/sh
set -eu

# Build the FreeRTOS NS guest1 image: FreeRTOS kernel + ARM_CM33_NTZ port +
# wolfCrypt + wolfPSA + the OS-neutral FF-M client core, linked against the
# secure-side CMSE veneer import library. Every secure request goes through
# the SPM-mediated SERVICE_HSM relay — there is no raw wolfHSM transport.
# Output:
#   build/freertos_guest1/freertos_guest1.{elf,bin}
#
# The clone of FreeRTOS is owned by scripts/clone_freertos.sh (idempotent;
# this script just verifies the workspace is there).

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUBTREE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ROOT=$(CDPATH= cd -- "$SUBTREE_DIR/../../.." && pwd)

FREERTOS_DIR="${FREERTOS_DIR:-${SUBTREE_DIR}/.workspace/freertos}"
FREERTOS_KERNEL="${FREERTOS_DIR}/FreeRTOS/Source"
FREERTOS_PORT="${FREERTOS_KERNEL}/portable/GCC/ARM_CM33_NTZ/non_secure"
APP_DIR="${SUBTREE_DIR}/apps/freertos_guest1"
BUILD_DIR="${SUBTREE_DIR}/build/freertos_guest1"
SECURE_CMSE_IMPLIB="${SECURE_CMSE_IMPLIB:-${ROOT}/build/secure_cmse_implib.o}"

WT_GUEST1_FLASH_BASE="${WT_GUEST1_FLASH_BASE:-0x08040000}"
WT_GUEST1_RAM_BASE="${WT_GUEST1_RAM_BASE:-0x20010000}"
WT_GUEST_FLASH_SIZE="${WT_GUEST_FLASH_SIZE:-0x00020000}"
WT_GUEST_RAM_SIZE="${WT_GUEST_RAM_SIZE:-0x00008000}"

WOLFSSL_DIR="${ROOT}/lib/wolfSSL"
WOLFPSA_DIR="${ROOT}/lib/wolfPSA"
WOLFHSM_DIR="${ROOT}/lib/wolfHSM"
BAREMETAL_NS_DIR="${ROOT}/tests/firmware/stm32h563/nonsecure"
WOLFHSM_MODULE_DIR="${SUBTREE_DIR}/module/wolfhsm-client"
. "${ROOT}/tests/target/lib/engine.sh"

if [ ! -d "${FREERTOS_KERNEL}" ]; then
    echo "missing FreeRTOS workspace: ${FREERTOS_KERNEL}" >&2
    echo "run scripts/clone_freertos.sh first" >&2
    exit 1
fi

if [ ! -f "${SECURE_CMSE_IMPLIB}" ]; then
    echo "missing CMSE implib: ${SECURE_CMSE_IMPLIB}" >&2
    exit 1
fi

mkdir -p "${BUILD_DIR}"

GUEST_CC="${GUEST_CC:-arm-none-eabi-gcc}"
GUEST_OBJCOPY="${GUEST_OBJCOPY:-arm-none-eabi-objcopy}"

# Sources -- everything compiled as one TU set fed to gcc.
FREERTOS_KERNEL_SRCS="\
${FREERTOS_KERNEL}/tasks.c \
${FREERTOS_KERNEL}/list.c \
${FREERTOS_KERNEL}/queue.c \
${FREERTOS_PORT}/port.c \
${FREERTOS_PORT}/portasm.c \
${FREERTOS_KERNEL}/portable/MemMang/heap_4.c"

WOLFCRYPT_GUEST_SRCS="\
${WOLFSSL_DIR}/wolfcrypt/src/aes.c \
${WOLFSSL_DIR}/wolfcrypt/src/cryptocb.c \
${WOLFSSL_DIR}/wolfcrypt/src/ecc.c \
${WOLFSSL_DIR}/wolfcrypt/src/random.c \
${WOLFSSL_DIR}/wolfcrypt/src/sha256.c \
${WOLFSSL_DIR}/wolfcrypt/src/asn.c \
${WOLFSSL_DIR}/wolfcrypt/src/coding.c \
${WOLFSSL_DIR}/wolfcrypt/src/error.c \
${WOLFSSL_DIR}/wolfcrypt/src/hash.c \
${WOLFSSL_DIR}/wolfcrypt/src/hmac.c \
${WOLFSSL_DIR}/wolfcrypt/src/memory.c \
${WOLFSSL_DIR}/wolfcrypt/src/sha.c \
${WOLFSSL_DIR}/wolfcrypt/src/sp_cortexm.c \
${WOLFSSL_DIR}/wolfcrypt/src/sp_int.c \
${WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c \
${WOLFSSL_DIR}/wolfcrypt/src/wc_port.c \
${WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c \
${WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c"

# wolfPSA subset for the PSA Crypto front-end (psa_crypto_init /
# psa_generate_random / psa_hash_compute); the rest of the API rides the
# neutral FF-M client directly.
WOLFPSA_SRCS="\
${WOLFPSA_DIR}/src/psa_engine.c \
${WOLFPSA_DIR}/src/psa_crypto.c \
${WOLFPSA_DIR}/src/psa_random.c \
${WOLFPSA_DIR}/src/psa_hash_engine.c"

# wolfHSM client subset: the same single mediated crypto path guest0 uses —
# wolfCrypt (WH_DEV_ID) -> cryptocb -> wh_Client -> the SERVICE_HSM relay
# (WT-FFM-0054). No raw WolfTrust_HSM_* CMSE transport.
WOLFHSM_CLIENT_SRCS="\
${WOLFHSM_DIR}/src/wh_client.c \
${WOLFHSM_DIR}/src/wh_client_crypto.c \
${WOLFHSM_DIR}/src/wh_client_cryptocb.c \
${WOLFHSM_DIR}/src/wh_comm.c \
${WOLFHSM_DIR}/src/wh_crypto.c \
${WOLFHSM_DIR}/src/wh_keyid.c \
${WOLFHSM_DIR}/src/wh_message_comm.c \
${WOLFHSM_DIR}/src/wh_message_crypto.c \
${WOLFHSM_DIR}/src/wh_message_keystore.c \
${WOLFHSM_DIR}/src/wh_message_nvm.c \
${WOLFHSM_DIR}/src/wh_message_customcb.c \
${WOLFHSM_DIR}/src/wh_message_counter.c \
${WOLFHSM_DIR}/src/wh_utils.c"

# OS-neutral wolfTrust NS client core: psa_connect/call/close over the
# WolfTrust_FFM_* veneers, plus the engine-specific client: the
# wolfHSM-over-psa_call transport + cryptocb glue (hsm), or the native wire
# client whose only secure crossing is the vault RNG seed (native).
if [ "${WT_ENGINE}" = "native" ]; then
WOLFHSM_CLIENT_SRCS=""
WT_CLIENT_SRCS="\
${ROOT}/src/client/psa_ffm_client.c \
${ROOT}/src/client/crypto_native_client.c"

GUEST_GLUE_SRCS="\
${BAREMETAL_NS_DIR}/libc_stubs_guest.c"
else
WT_CLIENT_SRCS="\
${ROOT}/src/client/psa_ffm_client.c \
${ROOT}/src/client/hsm_psa_transport.c"

GUEST_GLUE_SRCS="\
${BAREMETAL_NS_DIR}/libc_stubs_guest.c \
${WOLFHSM_MODULE_DIR}/src/wolfhsm_client_glue.c"
fi

# wh_settings.h picks up config via `#ifdef WOLFHSM_CFG / #include
# "wolfhsm_cfg.h"`; generate the trampolines pointing at the shared guest
# settings (mirrors tests/firmware/stm32h563/Makefile).
WH_CFG_DIR="${BUILD_DIR}/wh_include"
mkdir -p "${WH_CFG_DIR}"
printf '#include "%s"\n' "${BAREMETAL_NS_DIR}/wh_settings_guest.h" \
    > "${WH_CFG_DIR}/wolfhsm_cfg.h"
printf '#include "%s"\n' "${BAREMETAL_NS_DIR}/wh_settings_guest.h" \
    > "${WH_CFG_DIR}/wolfhsm_guest_cfg.h"

APP_SRCS="${APP_DIR}/main.c"

if [ "${WT_ENGINE}" = "native" ]; then
WT_ENGINE_DEFS="-DWT_ENGINE_NATIVE=1"
else
WT_ENGINE_DEFS="-DWOLFHSM_CFG -DWOLF_CRYPTO_CB -DWT_ENGINE_HSM=1 -DWT_WOLFHSM_CLIENT_ID=2"
fi

CFLAGS="\
-mcpu=cortex-m33 -mthumb -mgeneral-regs-only \
-ffreestanding -fno-builtin -nostdlib -Os -g \
-Wall -Wextra -Wno-unused-function -Wno-unused-variable \
-Wno-unused-parameter -Wno-type-limits \
-ffunction-sections -fdata-sections \
-I${APP_DIR} \
-I${FREERTOS_KERNEL}/include \
-I${FREERTOS_PORT} \
-I${ROOT}/include \
-I${WOLFSSL_DIR} \
-I${WOLFHSM_DIR} \
-I${WOLFPSA_DIR} \
-I${WOLFPSA_DIR}/wolfpsa \
-I${WOLFPSA_DIR}/src \
-I${BAREMETAL_NS_DIR} \
-I${WH_CFG_DIR} \
-I${ROOT}/port/stm32h563 \
-DWOLFSSL_USER_SETTINGS \
-DWOLFSSL_PSA_ENGINE \
-DWOLFPSA_NO_TRACE \
${WT_ENGINE_DEFS} \
-DWC_RESEED_INTERVAL=1000000 \
-include ${SUBTREE_DIR}/module/wolfpsa/wolfpsa_no_trace.h \
-DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM -DWOLFSSL_ARM_ARCH=8 \
-DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_ARMASM_INLINE \
-DWOLFSSL_ARMASM_NO_NEON -DWOLFSSL_ARMASM_THUMB2 \
-DNO_ERROR_STRINGS \
-DWOLFSSL_PUBLIC_MP \
-DWC_RSA_DIRECT \
-include ${APP_DIR}/user_settings.h"

LDFLAGS="\
-Wl,-T${APP_DIR}/freertos_guest1.ld \
-Wl,--defsym=GUEST_FLASH_ORIGIN=${WT_GUEST1_FLASH_BASE} \
-Wl,--defsym=GUEST_FLASH_LENGTH=${WT_GUEST_FLASH_SIZE} \
-Wl,--defsym=GUEST_RAM_ORIGIN=${WT_GUEST1_RAM_BASE} \
-Wl,--defsym=GUEST_RAM_LENGTH=${WT_GUEST_RAM_SIZE} \
-Wl,--gc-sections"

# shellcheck disable=SC2086
${GUEST_CC} ${CFLAGS} ${LDFLAGS} \
    -o "${BUILD_DIR}/freertos_guest1.elf" \
    ${APP_SRCS} \
    ${FREERTOS_KERNEL_SRCS} \
    ${WOLFCRYPT_GUEST_SRCS} \
    ${WOLFPSA_SRCS} \
    ${WOLFHSM_CLIENT_SRCS} \
    ${WT_CLIENT_SRCS} \
    ${GUEST_GLUE_SRCS} \
    "${SECURE_CMSE_IMPLIB}" \
    -lgcc

# Mediated-path proof (WT-FFM-0054): the wolfHSM client must reach the secure
# side ONLY through the SPM-mediated psa_call transport — assert the transport
# is linked and the retired direct veneers are absent.
NM_OUT=$(arm-none-eabi-nm "${BUILD_DIR}/freertos_guest1.elf") || {
    echo "FAIL: nm on the guest1 image failed" >&2
    exit 1
}
if [ "${WT_ENGINE}" = "native" ]; then
    if ! printf '%s\n' "${NM_OUT}" | grep -q "wt_crypto_native_call"; then
        echo "guest1 is not wired to the native crypto wire client" >&2
        exit 1
    fi
    if printf '%s\n' "${NM_OUT}" | grep -q "wh_Client"; then
        echo "FAIL: wolfHSM client linked into a native-engine guest1" >&2
        exit 1
    fi
elif ! printf '%s\n' "${NM_OUT}" | grep -q "wt_hsm_psa_transport_cb"; then
    echo "guest1 is not wired to the SPM-mediated wolfHSM transport" >&2
    exit 1
fi
if printf '%s\n' "${NM_OUT}" | \
        grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then
    echo "FAIL: retired direct veneers linked into guest1" >&2
    exit 1
fi

"${GUEST_OBJCOPY}" -O binary \
    "${BUILD_DIR}/freertos_guest1.elf" \
    "${BUILD_DIR}/freertos_guest1.bin"

arm-none-eabi-size "${BUILD_DIR}/freertos_guest1.elf"
