# shellcheck shell=bash disable=SC2034,SC2154
# MIMXRT700 emulator profile for tests/target/run_target.sh: the pinned
# emulator with the carried RT700 model patch, the upstream wolfBoot
# TrustZone first stage with the carried life cycle and guest fence patches,
# and where the images sit in the NOR the emulator boots from.

PORT_BOARD=RT700
M33MU_REF=f3c03675260264cdec815adebe4b020bb6fe57b8
M33MU_PATCH="$here/m33mu-imxrt700.patch"
M33MU_CPU="--cpu imxrt700"
M33MU_CMAKE_EXTRA="-DM33MU_BUILD_TESTS=OFF -DM33MU_ENABLE_RUST_PLUGINS=OFF"

WOLFBOOT_REPO=https://github.com/wolfSSL/wolfBoot.git
WOLFBOOT_REF=e6d169c7218d82e33bd04e2c086146ed37ec0cca
WOLFBOOT_CONFIG=config/examples/imx-rt700-tz.config
WOLFBOOT_PATCHES="$here/wolfboot-imxrt700-lifecycle.patch $here/wolfboot-imxrt700-guest-fence.patch"
WOLFBOOT_DIR_DEFAULT=/tmp/wolfboot_rt700
WOLFBOOT_DIR_OVERRIDE="${RT700_WOLFBOOT_DIR:-}"

# M33MU has no RT700 boot ROM or FCB and takes the reset vector from the
# start of the NOR, so wolfBoot links at the NOR base instead of 0x28004000;
# the hardware profile drops these for the MBI the ROM executes.
WOLFBOOT_EMU_MAKE_ARGS=(ARCH_FLASH_OFFSET=0x28000000 BOOTLOADER_PARTITION_SIZE=0x40000)
WOLFBOOT_MAKE_ARGS=()
WOLFBOOT_FENCE_CFLAGS=""

IMG_SECURE_OFF=0x40000
IMG_GUEST0_OFF=0x80000
IMG_GUEST1_OFF=0x100000
IMG_UPDATE_OFF=""
SIGN_SECTOR_SIZE=0x1000
# The byte authneg flips after the digest is pinned: inside the vector table.
TAMPER_OFFSET=0x40

# shellcheck source=fence.sh disable=SC1091
. "$here/ports/mimxrt700/fence.sh"

# The XSPI guest fence: wrpfence and wrpneg arm it in wolfBoot, wrpoff proves
# the Secure image refuses every guest behind a first stage without it.
port_wolfboot_variant() {
    local fence cflags=""
    case "$1" in
        wrpfence|wrpneg) fence=1 ;;
        wrpoff) fence=0 ;;
        *) fence="${WT_XSPI_GUEST_FENCE:-${WT_GUEST_FLASH_WRP:-0}}" ;;
    esac
    if [ "$fence" = "1" ]; then
        cflags="$(rt700_fence_cflags)" || return 1
        WOLFBOOT_DIR="${RT700_WOLFBOOT_DIR:-${WOLFBOOT_DIR_DEFAULT}_fence}"
        case "$1" in
            wrpneg)
                cflags="$cflags -DXSPI_FLASH_PROTECT_SELFTEST"
                WOLFBOOT_DIR="${RT700_WOLFBOOT_DIR:-${WOLFBOOT_DIR_DEFAULT}_fence_selftest}" ;;
        esac
    else
        WOLFBOOT_DIR="${RT700_WOLFBOOT_DIR:-$WOLFBOOT_DIR_DEFAULT}"
    fi
    WOLFBOOT_FENCE_CFLAGS="$cflags"
    WOLFBOOT_MAKE_ARGS=("${WOLFBOOT_EMU_MAKE_ARGS[@]}" "CFLAGS_EXTRA=$cflags")
}

port_layout_env() {
    :
}

port_pre_boot() {
    :
}
