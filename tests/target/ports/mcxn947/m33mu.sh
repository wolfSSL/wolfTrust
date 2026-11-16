# shellcheck shell=bash disable=SC2034,SC2154
# MCXN947 emulator profile for tests/target/run_target.sh: the pinned
# emulator with the carried EdgeLock RND_REQ model patch, the pinned
# mcxn-tz-wolftrust wolfBoot first stage with the carried life cycle patch
# (built against the MCUXpresso SDK), and where the images sit in the flash
# the emulator boots from (wolfBoot at 0, BOOT at 0x40000, every image offset
# physical).

PORT_BOARD=MCXN947
M33MU_REF=87f693a3cbc4c1315ed3676cef962c092eb2f7be
M33MU_PATCH="$here/m33mu-mcxn947.patch"
M33MU_CPU="--cpu mcxn947"
M33MU_CMAKE_EXTRA="-DM33MU_BUILD_TESTS=OFF -DM33MU_ENABLE_RUST_PLUGINS=OFF"

WOLFBOOT_REPO=https://github.com/aidangarske/wolfBoot.git
WOLFBOOT_REF=1d47fa7b622b654a8e6a53cf53e7811c42618505
WOLFBOOT_CONFIG=config/examples/mcxn-tz-wolftrust.config
WOLFBOOT_PATCHES="$here/wolfboot-mcxn947-lifecycle.patch"
WOLFBOOT_DIR_DEFAULT=/tmp/wolfboot_mcxn947
WOLFBOOT_DIR_OVERRIDE="${MCXN947_WOLFBOOT_DIR:-}"
WOLFBOOT_MAKE_ARGS=()
WOLFBOOT_NEEDS_SDK=1

IMG_SECURE_OFF=0x40000
IMG_GUEST0_OFF=0x80000
IMG_GUEST1_OFF=0x100000
IMG_UPDATE_OFF=""
SIGN_SECTOR_SIZE=0x2000
TAMPER_OFFSET=0x40

port_wolfboot_variant() {
    WOLFBOOT_DIR="${MCXN947_WOLFBOOT_DIR:-$WOLFBOOT_DIR_DEFAULT}"
}

port_layout_env() {
    :
}

port_pre_boot() {
    :
}
