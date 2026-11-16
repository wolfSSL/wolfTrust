# shellcheck shell=bash disable=SC2034,SC2154
# STM32H563 emulator profile for tests/target/run_target.sh: the pinned
# upstream emulator, the secure-app wolfBoot first stage (stm32h5-tz-wolftrust)
# and the runner layout the Zephyr and FreeRTOS guests are linked for, which
# the Secure image is built with so both sides see one map.

PORT_BOARD=STM32H563
M33MU_REF=f3c03675260264cdec815adebe4b020bb6fe57b8
M33MU_PATCH=""
M33MU_CPU=""
M33MU_CMAKE_EXTRA=""

WOLFBOOT_REPO=https://github.com/aidangarske/wolfBoot.git
WOLFBOOT_REF=d85fa9dbdf6c36f47b7e96eba5c9df750ad3c963
WOLFBOOT_CONFIG=config/examples/stm32h5-tz-wolftrust.config
WOLFBOOT_PATCHES=""
# The hardware runner signs with this checkout too (both stage it here).
WOLFBOOT_DIR_DEFAULT="$repo/wolfBoot"
WOLFBOOT_DIR_OVERRIDE="${H5_WOLFBOOT_DIR:-}"
WOLFBOOT_MAKE_ARGS=()

IMG_SECURE_OFF=0x60000
IMG_GUEST0_OFF=0xA0000
IMG_GUEST1_OFF=0xE0000
IMG_UPDATE_OFF=0x100000
SIGN_SECTOR_SIZE=0x2000
# The byte authneg flips after the digest is pinned: past the Zephyr header.
TAMPER_OFFSET=0x400

port_wolfboot_variant() {
    WOLFBOOT_DIR="${H5_WOLFBOOT_DIR:-$WOLFBOOT_DIR_DEFAULT}"
}

# The wolfBoot configuration reserves the wolfTrust partition at the first
# 128-KiB-aligned secure slot; guest0 is 256K (the dev_apis crypto image
# outgrew 128K) and guest1 keeps 128K ending at the bank watermark.
port_layout_env() {
    export CROSS_COMPILE=/usr/local/bin/arm-none-eabi-
    export ZEPHYR_TOOLCHAIN_VARIANT=cross-compile
    export ZEPHYR_BOARD=nucleo_h563zi/stm32h563xx/ns
    export WT_SECURE_FLASH_BASE=0x0C060000
    export WT_SECURE_FLASH_SIZE=0x00040000
    export WOLFBOOT_PARTITION_SIZE=0x40000
    export WOLFBOOT_PARTITION_SWAP_ADDRESS=0x0C140000
    export WT_GUEST0_FLASH_BASE=0x080A0000
    export WT_GUEST1_FLASH_BASE=0x080E0000
    export WT_GUEST0_FLASH_SIZE=0x00040000
    export WT_GUEST_RAM_SIZE=0x00010000
    export WT_GUEST1_RAM_BASE=0x20010000
    export WT_ZEPHYR_DTC_OVERLAY_FILE=boards/wolfboot-stm32h563.overlay
    export WT_MAX_GUESTS=2
    case "$1" in
        restartidle) export WT_MAX_GUESTS=1 ;;
    esac
}

# The Zephyr PSA guest and the FreeRTOS guest, linked into the runner layout.
port_build_os_guests() {
    local guest_flags="$1" secure_flags="$2"
    make -C tests/firmware/zephyr-stm32h5 clone
    # shellcheck disable=SC2086
    env $guest_flags $secure_flags WT_REUSE_SECURE_BUILD=1 \
        WT_EXPECTED_LIFECYCLE=0x1000u WT_ATTESTATION_DEVELOPMENT_PROFILE=1 \
        make -C tests/firmware/zephyr-stm32h5 build-guest0-psa build-freertos-guest1
    G0_IMG="$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
    G1_IMG="$repo/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"
}

# The bare-metal wolfIP guests, relinked into the standard NS windows.
# port_build_vnet_guests emulator|hardware: the exit breakpoint ends an
# emulator run and would fault on silicon.
port_build_vnet_guests() {
    local extra=""
    [ "$1" = "emulator" ] && extra="-DWT_VNET_EXIT_BKPT=1"
    rm -rf tests/firmware/stm32h563-vnet/build
    make -C tests/firmware/stm32h563-vnet build/guest0.bin build/guest1.bin \
        WT_GUEST0_FLASH_ORIGIN=0x080A0000 WT_GUEST1_FLASH_ORIGIN=0x080E0000 \
        WT_GUEST0_RAM_BASE=0x20000000 WT_GUEST1_RAM_BASE=0x20010000 \
        WT_GUEST_RAM_SIZE=0x00010000 \
        GUEST_EXTRA_CFLAGS="$extra"
    G0_IMG="$repo/tests/firmware/stm32h563-vnet/build/guest0.bin"
    G1_IMG="$repo/tests/firmware/stm32h563-vnet/build/guest1.bin"
}

port_pre_boot() {
    case "$1" in
        restartidle)
            M33MU="$M33MU" bash tests/target/test_systick_idle.sh ;;
        revneg)
            # Production image on revision Z silicon (ES0565 2.2.9): the
            # emulator reports the refused IDCODE through the real DBGMCU read.
            if ! grep -aq M33MU_STM32H5_IDCODE "$M33MU"; then
                fail "$M33MU lacks M33MU_STM32H5_IDCODE; rebuild M33MU at $M33MU_REF or later"
            fi
            export M33MU_STM32H5_IDCODE=0x10016484 ;;
    esac
}
