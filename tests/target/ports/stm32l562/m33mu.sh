# shellcheck shell=bash disable=SC2034,SC2154
# STM32L562 emulator profile for tests/target/run_target.sh: upstream M33MU
# plus the carried STM32L552 TrustZone model (--cpu stm32l552, the same die)
# and upstream wolfBoot's stm32l5-tz-wolftrust first stage, relaid by make.

PORT_BOARD=STM32L562
M33MU_REF=268fbef3be5c00e5dbd4473e3e819c4ed105aa85
M33MU_PATCH="$here/ports/stm32l562/m33mu-stm32l562.patch"
M33MU_CMAKE_EXTRA="-DM33MU_BUILD_TESTS=ON -DM33MU_ENABLE_RUST_PLUGINS=OFF -DM33MU_ENABLE_TPM_LIBTPMS=OFF"

WOLFBOOT_REPO=https://github.com/wolfSSL/wolfBoot.git
WOLFBOOT_REF=8c1f19e71d67b3762b4e735b3decc60d1264951c
WOLFBOOT_CONFIG=config/examples/stm32l5-tz-wolftrust.config
WOLFBOOT_PATCHES=""
WOLFBOOT_DIR_OVERRIDE="${STM32L562_WOLFBOOT_DIR:-}"

IMG_SECURE_OFF=0xC000
IMG_UPDATE_OFF=""
SIGN_SECTOR_SIZE=0x800
# The byte authneg flips after the digest is pinned: past the vector table.
TAMPER_OFFSET=0x40

# The conformance layout, also used by TPM 2.0 and PKCS#11: its 160 KiB slot
# and bank-spanning guest 0 move the wolfBoot update slot so its trailer page
# stays erased; it never swaps.
stm32l562_layout() {
    case " ${SC_SECURE:-} " in
        *" WT_CONFORMANCE=1 "*|*" CONFIG_TPM=y "*|*" CONFIG_PKCS11=y "*) echo conformance ;;
        *) echo production ;;
    esac
}

port_wolfboot_variant() {
    local layout
    layout="$(stm32l562_layout)"
    WOLFBOOT_DIR="${STM32L562_WOLFBOOT_DIR:-/tmp/wolfboot_stm32l562_$layout}"
    if [ "$layout" = "conformance" ]; then
        WOLFBOOT_MAKE_ARGS=(WOLFBOOT_PARTITION_SIZE=0x28000
                            WOLFBOOT_PARTITION_UPDATE_ADDRESS=0x0C04C000
                            WOLFBOOT_PARTITION_SWAP_ADDRESS=0x0C074000)
    else
        WOLFBOOT_MAKE_ARGS=(WOLFBOOT_PARTITION_UPDATE_ADDRESS=0x0C050000
                            WOLFBOOT_PARTITION_SWAP_ADDRESS=0x0C070000)
    fi
}

port_layout_env() {
    if [ "$(stm32l562_layout)" = "conformance" ]; then
        M33MU_CPU="--cpu stm32l552 --secwm1=0:103 --secwm2=104:127"
        IMG_GUEST0_OFF=0x34000
        IMG_GUEST1_OFF=0x70000
    else
        M33MU_CPU="--cpu stm32l552 --secwm1=0:87 --secwm2=32:127"
        IMG_GUEST0_OFF=0x2C000
        IMG_GUEST1_OFF=0x40000
    fi
}

# The host suite tests a copy of wolfBoot's RDP-to-lifecycle map, and the
# carried model's FLASH register security is unit tested before it is trusted.
port_pre_boot() {
    local mbuild
    mbuild="$(dirname "$M33MU")"
    if [ -f "$mbuild/CMakeCache.txt" ]; then
        [ -x "$mbuild/stm32l552_flash_tz_test" ] ||
            cmake --build "$mbuild" --target stm32l552_flash_tz_test -j"$(nproc)" >/dev/null ||
            fail "could not build the m33mu stm32l552_flash_tz_test"
        "$mbuild/stm32l552_flash_tz_test" || fail "the m33mu STM32L552 FLASH TrustZone model failed its unit test"
    else
        log "Prebuilt M33MU: skipping the stm32l552_flash_tz_test unit test"
    fi
    cmp -s "$WOLFBOOT_DIR/hal/stm32l5_lifecycle.h" \
        "$repo/tests/host/stm32l562_lifecycle/stm32l5_lifecycle.h" ||
        fail "wolfBoot's hal/stm32l5_lifecycle.h differs from the copy tests/host/stm32l562_lifecycle tests"
}
