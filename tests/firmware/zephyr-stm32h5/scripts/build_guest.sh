#!/bin/sh
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 guest0|guest0_psa|guest1" >&2
    exit 2
fi

APP_NAME=$1
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUBTREE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ROOT=$(CDPATH= cd -- "$SUBTREE_DIR/../../.." && pwd)
WORKSPACE="${ZEPHYR_WORKSPACE:-$SUBTREE_DIR/.workspace/zephyrproject}"
WEST_BIN="${WEST_BIN:-$SUBTREE_DIR/.venv/bin/west}"
ZEPHYR_BASE="$WORKSPACE/zephyr"
APP_DIR="$SUBTREE_DIR/apps/$APP_NAME"
BUILD_DIR="$SUBTREE_DIR/build/$APP_NAME"
MODULE_DIR="$SUBTREE_DIR/module"
BOARD="${ZEPHYR_BOARD:-nucleo_h563zi/stm32h563xx/ns}"
SECURE_BIN="${SECURE_BIN:-$ROOT/build/wolftrust.bin}"
SECURE_CMSE_IMPLIB="${SECURE_CMSE_IMPLIB:-$ROOT/build/secure_cmse_implib.o}"
WT_ZEPHYR_DTC_OVERLAY_FILE="${WT_ZEPHYR_DTC_OVERLAY_FILE:-}"
WT_EXPECTED_MEASUREMENT_HEX="${WT_EXPECTED_MEASUREMENT_HEX:-}"
WT_EXPECTED_LIFECYCLE="${WT_EXPECTED_LIFECYCLE:-0x3000u}"
WT_ATTESTATION_DEVELOPMENT_PROFILE="${WT_ATTESTATION_DEVELOPMENT_PROFILE:-0}"
WT_M33MU_EXPECT_BKPT="${WT_M33MU_EXPECT_BKPT:-0}"
WT_GUEST_FAULT_PROBE="${WT_GUEST_FAULT_PROBE:-0}"
WT_ATTEST_NEG_PROBE="${WT_ATTEST_NEG_PROBE:-0}"
WT_FWU_PROBE="${WT_FWU_PROBE:-0}"
WT_WRITE_ONCE_RESET_PROBE="${WT_WRITE_ONCE_RESET_PROBE:-0}"
WT_HSM_ATTACK_PROBE="${WT_HSM_ATTACK_PROBE:-0}"
WT_MPU_BYPASS_PROBE="${WT_MPU_BYPASS_PROBE:-0}"
. "$ROOT/tests/target/lib/engine.sh"

if [ ! -d "$APP_DIR" ]; then
    echo "unknown guest app: $APP_NAME" >&2
    exit 2
fi

make -C "$ROOT" build/wolftrust.bin build/secure_cmse_implib.o

if [ ! -d "$ZEPHYR_BASE" ]; then
    echo "missing Zephyr workspace: $ZEPHYR_BASE" >&2
    exit 1
fi

if [ ! -f "$SECURE_BIN" ] || [ ! -f "$SECURE_CMSE_IMPLIB" ]; then
    echo "missing secure build artifacts under $ROOT/build" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

export ZEPHYR_BASE

set -- \
    "-DZEPHYR_EXTRA_MODULES=$MODULE_DIR/wolftrust-tee;$MODULE_DIR/wolfhsm-client;$MODULE_DIR/wolfpsa;$ROOT/lib/wolfSSL" \
    "-DWOLFTRUST_CMSE_IMPLIB=$SECURE_CMSE_IMPLIB" \
    "-DWT_EXPECTED_LIFECYCLE=$WT_EXPECTED_LIFECYCLE" \
    "-DWT_ATTESTATION_DEVELOPMENT_PROFILE=$WT_ATTESTATION_DEVELOPMENT_PROFILE" \
    "-DWT_M33MU_EXPECT_BKPT=$WT_M33MU_EXPECT_BKPT" \
    "-DWT_GUEST_FAULT_PROBE=$WT_GUEST_FAULT_PROBE" \
    "-DWT_ATTEST_NEG_PROBE=$WT_ATTEST_NEG_PROBE" \
    "-DWT_FWU_PROBE=$WT_FWU_PROBE" \
    "-DWT_WRITE_ONCE_RESET_PROBE=$WT_WRITE_ONCE_RESET_PROBE" \
    "-DWT_HSM_ATTACK_PROBE=$WT_HSM_ATTACK_PROBE" \
    "-DWT_MPU_BYPASS_PROBE=$WT_MPU_BYPASS_PROBE"

if [ "$WT_ENGINE" = "native" ]; then
    set -- "$@" \
        "-DCONFIG_WOLFTRUST_WOLFHSM_CLIENT=n" \
        "-DCONFIG_WOLFTRUST_NATIVE_CLIENT=y"
else
    set -- "$@" \
        "-DCONFIG_WOLFTRUST_WOLFHSM_CLIENT=y" \
        "-DCONFIG_WOLFTRUST_NATIVE_CLIENT=n"
fi

if [ -n "${ZEPHYR_TOOLCHAIN_VARIANT:-}" ]; then
    set -- "$@" "-DZEPHYR_TOOLCHAIN_VARIANT=$ZEPHYR_TOOLCHAIN_VARIANT"
fi
if [ -n "${CROSS_COMPILE:-}" ]; then
    set -- "$@" "-DCROSS_COMPILE=$CROSS_COMPILE"
fi

if [ -n "$WT_ZEPHYR_DTC_OVERLAY_FILE" ]; then
    case "$WT_ZEPHYR_DTC_OVERLAY_FILE" in
        /*) ;;
        *) WT_ZEPHYR_DTC_OVERLAY_FILE="$SUBTREE_DIR/$WT_ZEPHYR_DTC_OVERLAY_FILE" ;;
    esac
    set -- "$@" "-DEXTRA_DTC_OVERLAY_FILE=$WT_ZEPHYR_DTC_OVERLAY_FILE"
fi

if [ -n "$WT_EXPECTED_MEASUREMENT_HEX" ]; then
    set -- "$@" "-DWT_EXPECTED_MEASUREMENT_HEX=$WT_EXPECTED_MEASUREMENT_HEX"
fi

if [ "${WT_RUN_CONFORMANCE:-0}" = "1" ]; then
    # Reclaim the deep attestation stack (skipped in the conformance guest) so
    # the Arm val NSPE framework fits guest0's 32 KiB NS RAM window.
    set -- "$@" "-DWT_RUN_CONFORMANCE=1" "-DCONFIG_MAIN_STACK_SIZE=10240"
fi

if [ -n "${WT_CONF_SUITE:-}" ]; then
    set -- "$@" "-DWT_CONF_SUITE=$WT_CONF_SUITE"
fi

if [ -n "${WT_ATTEST_CBOR:-}" ]; then
    set -- "$@" "-DWT_ATTEST_CBOR=$WT_ATTEST_CBOR"
fi

"$WEST_BIN" build -p auto \
    -d "$BUILD_DIR" \
    -b "$BOARD" \
    "$APP_DIR" \
    -- "$@"

# Mediated-path proof (WT-FFM-0054): no retired direct veneer may appear in
# any NS guest image, and the SPM-mediated wolfHSM transport must be linked.
NM_OUT=$(arm-none-eabi-nm "$BUILD_DIR/zephyr/zephyr.elf") || {
    echo "FAIL: nm on the $APP_NAME image failed" >&2
    exit 1
}
if printf '%s\n' "$NM_OUT" | \
        grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then
    echo "FAIL: retired direct veneers linked into $APP_NAME" >&2
    exit 1
fi
if [ "$WT_ENGINE" = "native" ]; then
    if ! printf '%s\n' "$NM_OUT" | grep -q 'wt_crypto_native_call'; then
        echo "FAIL: $APP_NAME is not wired to the native crypto wire client" >&2
        exit 1
    fi
    if printf '%s\n' "$NM_OUT" | grep -q 'wh_Client'; then
        echo "FAIL: wolfHSM client linked into a native-engine $APP_NAME" >&2
        exit 1
    fi
elif ! printf '%s\n' "$NM_OUT" | grep -q 'wt_hsm_psa_transport_cb'; then
    echo "FAIL: $APP_NAME is not wired to the SPM-mediated wolfHSM transport" >&2
    exit 1
fi
