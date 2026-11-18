#!/usr/bin/env bash
# wolfTrust hardware runner for every port: the on-silicon counterpart of
# run_target.sh. Builds the same authenticated chain (wolfBoot -> wolfTrust ->
# guests) the emulator boots, programs it through the port's profile
# (tests/target/ports/<port>/hw.sh), boots the board, captures its console,
# reads the Secure image's latches and the guests' mailboxes over SWD, and
# hands that evidence to the judge in tests/target/lib/scenarios.py with
# --env hardware. REAL hardware evidence, kept under logs/<port>-hw/.
#
#   tests/target/run_hardware.sh <port> <scenario> [build|flash|all]
#
# build stops after signing and records what it built (build/hw-stamp.sh);
# flash takes that record on the host that owns the board, so a checkout
# shared between a toolchain container and the probe host runs the two halves
# in turn. all (the default) does both.
#
# Rules every profile keeps: the probe is bound by serial for every tool call,
# the preflight only reads, and no option byte, fuse or life-cycle state is
# ever written here (provisioning_ctrl.sh owns those, gated).
#
# Environment (all optional):
#   WT_ENGINE              native (default) or hsm
#   WT_HW_PROBE            the probe serial to bind when several are attached
#   WT_HW_CONSOLE          the board console device
#   WT_HW_CAPTURE_SECONDS  overrides the scenario's console window
#   ARM_NM                 a host-visible nm for the flash half
#   <PORT>_WOLFBOOT_DIR    a first stage built by lib/wolfboot_stage.sh
set -eu
unset TARGET MAKEFLAGS MFLAGS

port="${1:-}"
scenario_in="${2:-}"
mode="${3:-all}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
lib="$here/lib"

# shellcheck source=lib/scenario.sh disable=SC1091
. "$lib/scenario.sh"
# shellcheck source=lib/engine.sh disable=SC1091
. "$lib/engine.sh"

# The hardware suites build, flash and assert both guests, so only the full
# profile runs on silicon; its flags go ahead of every scenario's own.
case "${WT_PROFILE:-full}" in
  full) ;;
  *) echo "WT_PROFILE=$WT_PROFILE is not supported on hardware (the suite asserts both guests; use WT_PROFILE=full)" >&2; exit 2 ;;
esac
scenario_profile_reset
# shellcheck disable=SC2046
export $(scenario_profile_flags full)

ports="$(python3 "$lib/scenario_matrix.py" --list-ports)"
case " $ports " in
  *" $port "*) ;;
  *) echo "usage: $0 <$(echo "$ports" | tr ' ' '|')> <scenario> [build|flash|all]" >&2; exit 2 ;;
esac
[ -n "$scenario_in" ] || { echo "usage: $0 $port <scenario> [build|flash|all]" >&2; exit 2; }
case "$mode" in build|flash|all) ;; *) echo "usage: $0 $port $scenario_in build|flash|all" >&2; exit 2 ;; esac

eval "$(python3 "$lib/scenarios.py" --port "$port" --scenario "$scenario_in" \
    --engine "$WT_ENGINE" --env hardware --shell)"
scenario="$SC_SCENARIO"
case " $SC_ENGINES " in
  *" $WT_ENGINE "*) ;;
  *) echo "$scenario exists only under WT_ENGINE=$SC_ENGINES" >&2; exit 2 ;;
esac
if [ -n "$SC_MISSING" ]; then
  echo "$scenario needs a capability port/$port declares absent: $SC_MISSING" >&2
  exit 2
fi
known="$(python3 "$lib/scenarios.py" --port "$port" --hardware-tier qualification) $(python3 "$lib/scenarios.py" --port "$port" --hardware-tier optin)"
case " $known " in
  *" $scenario "*) ;;
  *) echo "$port does not run $scenario on hardware (port/$port/port.json hardware)" >&2; exit 2 ;;
esac

# The emulator profile holds the pins and signing geometry; the hardware
# profile holds the board.
# shellcheck source=ports/stm32h563/m33mu.sh disable=SC1090,SC1091
. "$here/ports/$port/m33mu.sh"
# shellcheck source=lib/wolfboot_stage.sh disable=SC1091
. "$lib/wolfboot_stage.sh"
# shellcheck source=lib/hw_runner.sh disable=SC1091
. "$lib/hw_runner.sh"
# shellcheck source=lib/hw_pyocd.sh disable=SC1091
. "$lib/hw_pyocd.sh"
# shellcheck source=lib/hw_stcli.sh disable=SC1091
. "$lib/hw_stcli.sh"
# shellcheck source=ports/stm32h563/hw.sh disable=SC1090,SC1091
. "$here/ports/$port/hw.sh"
hw_require_hooks

cd "$repo"
work="$repo/logs/$port-hw"
evidence="$work/$scenario-$WT_ENGINE"
stamp="$repo/build/hw-stamp.sh"
port_layout_env "$scenario"
port_wolfboot_variant "$scenario"
if declare -F hw_first_stage >/dev/null; then
  hw_first_stage "$scenario"
fi
# shellcheck disable=SC2034  # the ELFs are read by lib/hw_runner.sh
G0_IMG=""; G1_IMG=""; G0_ELF=""; G1_ELF=""; HW_WOLFBOOT_BIN=""
expected_measurement=""; v2_measurement=""; update_img=""
probe_addr="$(awk -F':= *' '/^GUEST_ISO_PROBE_ADDR/ { sub(/u$/, "", $2); print $2 }' "$repo/tests/firmware/boards/$port/board.mk")"
fault_addr="$(awk '/define GUEST_SECURE_RAM_ADDR/ { sub(/u$/, "", $3); print $3 }' "$repo/tests/firmware/boards/$port/board.h")"
periph_addr="$(awk '/define GUEST_PERIPH_NS_ADDR/ { sub(/u$/, "", $3); print $3 }' "$repo/tests/firmware/boards/$port/board.h")"

# --- The Secure image and the guests: the recipe run_target.sh boots, minus
#     the emulator-only breakpoint the plan already dropped for hardware. ---
do_build() {
  if [ -n "$SC_SECURE" ]; then
    # shellcheck disable=SC2086,SC2163
    export $SC_SECURE
  fi
  l3_layout_load "$repo" "$port"
  wolfboot_build "$WOLFBOOT_DIR" ${WOLFBOOT_MAKE_ARGS[@]+"${WOLFBOOT_MAKE_ARGS[@]}"} || fail "wolfBoot build failed"
  git -c "safe.directory=$repo" -c "safe.directory=$repo/*" submodule update --init --single-branch
  export WT_SECURE_IMAGE_HEADER_SIZE=0x400
  rm -rf build tests/firmware/zephyr-stm32h5/build
  mkdir -p build
  if [ -n "$SC_SECURE" ]; then
    # shellcheck disable=SC2086,SC2163
    export $SC_SECURE
  fi
  stage "build wolfTrust secure image + CMSE import library ${SC_SECURE:-(production)}"
  make -s TARGET="$port" secure-image TOOLPREFIX=arm-none-eabi-
  cp build/wolftrust.bin build/wolftrust-unsigned.bin
  cp build/wolftrust.elf build/wolftrust-signed.elf
  "${ARM_NM:-arm-none-eabi-nm}" build/wolftrust-signed.elf > build/wolftrust-signed.syms

  if [ -n "$SC_PREBUILD" ]; then
    "$repo/$SC_PREBUILD" >/dev/null
  fi
  case "$SC_GUEST0/$SC_GUEST1" in
    zephyr/freertos)
      stage "build the Zephyr PSA guest and the FreeRTOS guest ${SC_GUEST_FLAGS:-(no probes)}"
      port_build_os_guests "$SC_GUEST_FLAGS" "$SC_SECURE"
      G0_ELF="${G0_IMG%/*}/zephyr.elf"
      G1_ELF="${G1_IMG%.bin}.elf" ;;
    vnet/vnet)
      stage "build the wolfIP network guests"
      port_build_vnet_guests hardware ;;
    *)
      for kind in baremetal psa; do
        [ "$SC_GUEST0" = "$kind" ] || [ "$SC_GUEST1" = "$kind" ] || continue
        case "$kind" in
          baremetal) dir=tests/firmware/baremetal-guest ;;
          psa)       dir=tests/firmware/psa-guest ;;
        esac
        flags=""
        [ "$SC_GUEST0" = "$kind" ] && flags="$SC_GUEST_FLAGS"
        stage "build the Non-secure guests from $dir ${flags:-(no probes)}"
        make -s -C "$repo/$dir" clean
        # shellcheck disable=SC2086
        make -s -C "$repo/$dir" TARGET="$port" WT_EXPECTED_LIFECYCLE="${HW_EXPECTED_LIFECYCLE:-0x1000u}" $flags
        [ "$SC_GUEST0" = "$kind" ] && G0_IMG="$repo/$dir/build/guest0.bin" && G0_ELF="$repo/$dir/build/guest0.elf"
        [ "$SC_GUEST1" = "$kind" ] && G1_IMG="$repo/$dir/build/guest1.bin" && G1_ELF="$repo/$dir/build/guest1.elf"
      done ;;
  esac
  [ -s "$G0_IMG" ] && [ -s "$G1_IMG" ] || fail "guest images missing ($G0_IMG, $G1_IMG)"

  stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
  cp build/wolftrust-unsigned.bin build/wolftrust.bin
  python3 tools/measure/patch_guest_digests.py build/wolftrust.bin \
      "0:${WT_GUEST0_VERSION:-1}:$G0_IMG" "1:${WT_GUEST1_VERSION:-1}:$G1_IMG"
  sign_image 1
  expected_measurement="$(python3 tests/scripts/read_wolfboot_measurement.py build/wolftrust_v1_signed.bin)"
  if [ "$SC_UPDATE" = "1" ]; then
    sign_image 2
    v2_measurement="$(python3 tests/scripts/read_wolfboot_measurement.py build/wolftrust_v2_signed.bin)"
    update_img="build/wolftrust_v2_signed.bin"
  fi
  if [ "$SC_TAMPER" = "1" ]; then
    python3 - "$G0_IMG" "$TAMPER_OFFSET" <<'PYEOF'
import sys
offset = int(sys.argv[2], 0)
with open(sys.argv[1], "r+b") as f:
    f.seek(offset)
    byte = f.read(1)
    f.seek(offset)
    f.write(bytes([byte[0] ^ 0x01]))
PYEOF
  fi
  # The flash half may run on another host sharing only the checkout: the
  # images it flashes are copied under build/hw and recorded relative to it.
  rm -rf build/hw
  mkdir -p build/hw
  cp "$WOLFBOOT_DIR/wolfboot.bin" build/hw/wolfboot.bin
  cp "$G0_IMG" build/hw/guest0.bin
  cp "$G1_IMG" build/hw/guest1.bin
  if [ -s "$G0_ELF" ]; then cp "$G0_ELF" build/hw/guest0.elf; fi
  if [ -s "$G1_ELF" ]; then cp "$G1_ELF" build/hw/guest1.elf; fi
  HW_WOLFBOOT_BIN=build/hw/wolfboot.bin
  G0_IMG=build/hw/guest0.bin; G1_IMG=build/hw/guest1.bin
  G0_ELF=build/hw/guest0.elf; G1_ELF=build/hw/guest1.elf
  {
    printf 'HW_STAMP_PORT=%q\nHW_STAMP_SCENARIO=%q\nHW_STAMP_ENGINE=%q\n' "$port" "$scenario" "$WT_ENGINE"
    printf 'HW_WOLFBOOT_BIN=%q\nG0_IMG=%q\nG1_IMG=%q\nG0_ELF=%q\nG1_ELF=%q\n' "$HW_WOLFBOOT_BIN" "$G0_IMG" "$G1_IMG" "$G0_ELF" "$G1_ELF"
    printf 'expected_measurement=%q\nv2_measurement=%q\nupdate_img=%q\n' "$expected_measurement" "$v2_measurement" "$update_img"
    for name in $(set | grep -oE '^L3_[A-Z0-9_]+' || true); do
      printf '%s=%q\n' "$name" "$(eval "printf '%s' \"\$$name\"")"
    done
  } > "$stamp"
  log "BUILD OK: $port $scenario ($WT_ENGINE), images recorded in $stamp"
}

sign_image() {
  # shellcheck disable=SC2086
  IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 \
  WOLFBOOT_SECTOR_SIZE="$SIGN_SECTOR_SIZE" \
    "$WOLFBOOT_DIR/tools/keytools/sign" --ecc256 ${HW_SIGN_EXTRA:-} build/wolftrust.bin \
    "$WOLFBOOT_DIR/wolfboot_signing_private_key.der" "$1"
  [ -s "build/wolftrust_v${1}_signed.bin" ] || fail "signing version $1 produced no image"
}

# --- Program, boot, observe, judge. A scenario with its own flow (two boots,
#     a ROM smoke image) supplies hw_scenario_<name>; the rest share one path.
do_board() {
  local capture_s
  if ! hw_detect; then
    log "SKIP: $port hardware ($(hw_detect 2>&1 || true))"
    exit 0
  fi
  hw_take_lock "$repo/logs/$port-hw.lock"
  hw_probe_bind
  [ -n "${HW_PROBE:-}" ] || fail "hw_probe_bind left no HW_PROBE"
  rm -rf "$evidence"
  mkdir -p "$evidence"
  stage "preflight (read-only) on probe $HW_PROBE"
  hw_preflight
  for image in "$HW_WOLFBOOT_BIN" build/wolftrust_v1_signed.bin "$G0_IMG" "$G1_IMG"; do
    [ -s "$image" ] || fail "image missing: $image (run the build half first)"
  done

  capture_s="${WT_HW_CAPTURE_SECONDS:-$(hw_capture_seconds "$scenario")}"
  if declare -F "hw_scenario_$scenario" >/dev/null; then
    "hw_scenario_$scenario"
  else
    stage "program the chain"
    hw_program "$HW_WOLFBOOT_BIN" build/wolftrust_v1_signed.bin "$G0_IMG" "$G1_IMG" "$update_img"
    stage "boot the chain, console window ${capture_s}s"
    hw_boot "$capture_s"
    if [ "${HW_VERIFY_AFTER_BOOT:-1}" = "1" ]; then
      # An update scenario's boot swaps the v2 candidate into the slot.
      hw_verify_image "$HW_SECURE_ADDR" "${update_img:-build/wolftrust_v1_signed.bin}"
      hw_verify_image "$HW_GUEST0_ADDR" "$G0_IMG"
      hw_verify_image "$HW_GUEST1_ADDR" "$G1_IMG"
    fi
    stage "collect the SWD evidence"
    hw_collect_words
  fi
  [ -s "$evidence/console.log" ] || : > "$evidence/console.log"

  local judge_args=(--log "$evidence/console.log" --syms build/wolftrust-signed.syms
                    --swd "$evidence/swd.txt"
                    --var "board=$PORT_BOARD" --var "expected_measurement=$expected_measurement"
                    --var "v2_measurement=$v2_measurement" --var "probe_addr=$probe_addr"
                    --var "fault_addr=$fault_addr" --var "periph_addr=$periph_addr")
  for name in $(set | grep -oE '^L3_[A-Z0-9_]+' || true); do
    judge_args+=(--var "$name=$(eval "printf '%s' \"\$$name\"")")
  done
  if [ -s "$evidence/vars.txt" ]; then
    while IFS= read -r line; do judge_args+=(--var "$line"); done < "$evidence/vars.txt"
  fi
  stage "judge"
  if python3 "$lib/scenarios.py" --port "$port" --scenario "$scenario" --engine "$WT_ENGINE" \
      --env hardware judge "${judge_args[@]}"; then
    hw_write_result pass
    log "  [evidence] $evidence (console.log, swd.txt, readback-*.bin, program.log, result.json)"
    log "PASS: hardware/$port/$scenario"
  else
    hw_write_result fail
    fail "hardware/$port/$scenario"
  fi
}

case "$mode" in
  build)
    do_build ;;
  flash)
    [ -s "$stamp" ] || fail "no build record at $stamp; run the build half first"
    # shellcheck source=/dev/null
    . "$stamp"
    [ "$HW_STAMP_PORT/$HW_STAMP_SCENARIO/$HW_STAMP_ENGINE" = "$port/$scenario/$WT_ENGINE" ] ||
      fail "the build record is for $HW_STAMP_PORT $HW_STAMP_SCENARIO ($HW_STAMP_ENGINE), not $port $scenario ($WT_ENGINE)"
    if [ -n "$SC_SECURE" ]; then
      # shellcheck disable=SC2086,SC2163
      export $SC_SECURE
    fi
    do_board ;;
  all)
    do_build
    do_board ;;
esac
