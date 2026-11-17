#!/usr/bin/env bash
# wolfTrust target-scenario runner for every port under the M33MU emulator.
# Builds the authenticated wolfBoot -> wolfTrust -> guests chain the port's
# profile (tests/target/ports/<port>/m33mu.sh) describes, boots it, and hands
# the evidence to the one judge in tests/target/lib/scenarios.py, which holds
# every scenario's assertions and decides which apply to this port. Run
# inside the port's CI container (port.json ci.image); never bare-metal on a
# host checkout, so every file under the repo stays root-owned and consistent.
#
#   tests/target/run_target.sh <port> <scenario>
#
# Environment (all optional):
#   WT_ENGINE           native (default) or hsm: the crypto engine under test
#   WT_PROFILE          default or full: the build profile (unset: the one the
#                       scenario is registered on, full when both)
#   M33MU               a prebuilt emulator at the port's pin; otherwise the
#                       pin is built under /tmp
#   <PORT>_WOLFBOOT_DIR a wolfBoot tree built by lib/wolfboot_stage.sh with
#                       the same pin, config, patches and arguments
#   WT_TARGET_TIMEOUT   overrides the scenario's wall-clock budget (seconds)
set -eu
# make test-target hands TARGET and MAKEFLAGS to every child make; wolfBoot's
# own TARGET must come from its config, so drop both before any build.
unset TARGET MAKEFLAGS MFLAGS

port="${1:-}"
scenario_in="${2:-}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
lib="$here/lib"

# shellcheck source=lib/scenario.sh disable=SC1091
. "$lib/scenario.sh"
# shellcheck source=lib/engine.sh disable=SC1091
. "$lib/engine.sh"

ports="$(python3 "$lib/scenario_matrix.py" --list-ports)"
case " $ports " in
  *" $port "*) ;;
  *) echo "usage: $0 <$(echo "$ports" | tr ' ' '|')> <scenario>" >&2; exit 2 ;;
esac
[ -n "$scenario_in" ] || { echo "usage: $0 $port <scenario>" >&2; exit 2; }

# The build profile, and with it the guest count the plan's end mode and
# checks follow.
canonical="$(python3 "$lib/scenarios.py" --scenario "$scenario_in" --canonical)"
profile="$(scenario_profile "$port" "$canonical")" ||
  fail "$port does not run $canonical on profile '${WT_PROFILE:-}'"
guests="$(scenario_profile_guests "$profile")"

# The resolved plan: the canonical name, the guest pair, the flags, the end
# mode and budget, the trace boot and the applicable assertion blocks.
eval "$(python3 "$lib/scenarios.py" --port "$port" --scenario "$scenario_in" \
    --engine "$WT_ENGINE" --guests "$guests" --shell)"
scenario="$SC_SCENARIO"
case " $SC_ENGINES " in
  *" $WT_ENGINE "*) ;;
  *) echo "$scenario exists only under WT_ENGINE=$SC_ENGINES" >&2; exit 2 ;;
esac
if [ -n "$SC_MISSING" ]; then
  echo "$scenario needs a capability port/$port declares absent: $SC_MISSING" >&2
  exit 2
fi
known="$(python3 "$lib/scenario_matrix.py" --port "$port" --tier full --flat)"
case " $known " in
  *" $scenario "*) ;;
  *) echo "$port does not run $scenario (port/$port/port.json m33mu.groups)" >&2; exit 2 ;;
esac

# The build profile goes ahead of the scenario's own flags, and ahead of the
# port hooks below, so a hook's scenario setting wins over the profile's.
scenario_profile_reset
profile_flags="$(scenario_profile_flags "$profile")"
if [ -n "$profile_flags" ]; then
  # shellcheck disable=SC2086,SC2163
  export $profile_flags
fi
echo "Build profile: $profile ($guests guest(s))"

# shellcheck source=ports/stm32h563/m33mu.sh disable=SC1090,SC1091
. "$here/ports/$port/m33mu.sh"
port_wolfboot_variant "$scenario"
port_layout_env "$scenario"
# A port hook may set the guest count for one scenario (restartidle); judge
# the image it builds.
guests="${WT_MAX_GUESTS:-1}"
# shellcheck source=lib/m33mu.sh disable=SC1091
. "$lib/m33mu.sh"
# shellcheck source=lib/wolfboot_stage.sh disable=SC1091
. "$lib/wolfboot_stage.sh"

cd "$repo"
logdir="${WT_SUITE_LOG_DIR:-logs}"
case "$logdir" in /*) ;; *) logdir="$repo/$logdir" ;; esac
mkdir -p "$logdir"
log="$logdir/target-$port-$scenario.boot.log"
trace_log="$logdir/target-$port-$scenario.trace.log"
guest0_log="$logdir/target-$port-$scenario.guest0.log"
timeout_s="${WT_TARGET_TIMEOUT:-$SC_TIMEOUT}"

# The container runs as root while a host clone is owned by the login user;
# without this git rejects every submodule with "dubious ownership".
git config --global --add safe.directory '*' >/dev/null 2>&1 || true

# The layout follows the build mode (engine, update stack, conformance, VNET),
# so the scenario's Secure flags are in place before it is read.
if [ -n "$SC_SECURE" ]; then
  # shellcheck disable=SC2086,SC2163
  export $SC_SECURE
fi
l3_layout_load "$repo" "$port"
m33mu_prepare "$port"

wolfboot_build "$WOLFBOOT_DIR" ${WOLFBOOT_MAKE_ARGS[@]+"${WOLFBOOT_MAKE_ARGS[@]}"} || fail "wolfBoot build failed"

# --- The Secure image under the scenario's probe flags. Exported, not passed
#     once: the guest builds re-enter the secure Makefile for the CMSE implib,
#     and a build-mode mismatch there would relink the image and drop the
#     wolftrust.bin this runner goes on to patch and sign. ---
git submodule update --init --single-branch
export WT_SECURE_IMAGE_HEADER_SIZE=0x400
rm -rf build tests/firmware/zephyr-stm32h5/build
mkdir -p build
if [ -n "$SC_SECURE" ]; then
  # shellcheck disable=SC2086,SC2163
  export $SC_SECURE
fi
stage "build wolfTrust secure image + CMSE import library ${SC_SECURE:-(production)}"
make -s TARGET="$port" secure-image TOOLPREFIX=arm-none-eabi-
# The guest builds may relink build/wolftrust.elf; the image signed below is
# this one, and its elf keeps the symbols the judge checks.
cp build/wolftrust.bin build/wolftrust-unsigned.bin
cp build/wolftrust.elf build/wolftrust-signed.elf
arm-none-eabi-nm build/wolftrust-signed.elf > build/wolftrust-signed.syms

# --- The guests, by kind. guest0 carries the scenario's probe flags; guest1
#     is the peer that must keep running. ---
if [ -n "$SC_PREBUILD" ]; then
  "$repo/$SC_PREBUILD" >/dev/null
fi
G0_IMG=""
G1_IMG=""
build_shared_guests() {
  local dir="$1" flags="$2"
  stage "build the Non-secure guests from $dir ${flags:-(no probes)}"
  make -s -C "$repo/$dir" TARGET="$port" clean
  # The emulator boots with the development lifecycle the attestation token
  # reports; the guest's verify pins it.
  # shellcheck disable=SC2086
  make -s -C "$repo/$dir" TARGET="$port" WT_EXPECTED_LIFECYCLE=0x1000u $flags
}
case "$SC_GUEST0/$SC_GUEST1" in
  zephyr/freertos)
    stage "build the Zephyr PSA guest and the FreeRTOS guest ${SC_GUEST_FLAGS:-(no probes)}"
    port_build_os_guests "$SC_GUEST_FLAGS" "$SC_SECURE" ;;
  vnet/vnet)
    stage "build the wolfIP network guests"
    port_build_vnet_guests emulator ;;
  *)
    for kind in baremetal psa; do
      [ "$SC_GUEST0" = "$kind" ] || [ "$SC_GUEST1" = "$kind" ] || continue
      case "$kind" in
        baremetal) dir=tests/firmware/baremetal-guest ;;
        psa)       dir=tests/firmware/psa-guest ;;
      esac
      flags=""
      [ "$SC_GUEST0" = "$kind" ] && flags="$SC_GUEST_FLAGS"
      build_shared_guests "$dir" "$flags"
      [ "$SC_GUEST0" = "$kind" ] && G0_IMG="$repo/$dir/build/guest0.bin"
      [ "$SC_GUEST1" = "$kind" ] && G1_IMG="$repo/$dir/build/guest1.bin"
    done ;;
esac
[ -s "$G0_IMG" ] && [ -s "$G1_IMG" ] || fail "guest images missing ($G0_IMG, $G1_IMG)"
echo "Guest vector tables (SP, reset PC):"
od -An -tx4 -N8 "$G0_IMG"
od -An -tx4 -N8 "$G1_IMG"

# --- Pin both guest measurements into the Secure image, then sign: the
#     wolfBoot signature covers the pins (patch-then-sign, WT-FFM-0049). ---
stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
cp build/wolftrust-unsigned.bin build/wolftrust.bin
python3 tools/measure/patch_guest_digests.py build/wolftrust.bin \
    "0:${WT_GUEST0_VERSION:-1}:$G0_IMG" "1:${WT_GUEST1_VERSION:-1}:$G1_IMG"
sign_image() {
  IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 \
  WOLFBOOT_SECTOR_SIZE="$SIGN_SECTOR_SIZE" \
    "$WOLFBOOT_DIR/tools/keytools/sign" --ecc256 build/wolftrust.bin \
    "$WOLFBOOT_DIR/wolfboot_signing_private_key.der" "$1"
  [ -s "build/wolftrust_v${1}_signed.bin" ] || fail "signing version $1 produced no image"
}
sign_image 1
# The harness, not the guest, holds wolfBoot's measurement of the signed image
# and matches the attestation token's reported value against it.
expected_measurement="$(python3 tests/scripts/read_wolfboot_measurement.py \
    build/wolftrust_v1_signed.bin)"
v2_measurement=""
update_img=""
if [ "$SC_UPDATE" = "1" ]; then
  # The same patched image signed again at version 2: the version lives inside
  # the hashed header, so v2 carries a higher version and a different
  # measurement; it is the candidate wolfBoot swaps in on the armed reboot.
  sign_image 2
  v2_measurement="$(python3 tests/scripts/read_wolfboot_measurement.py \
      build/wolftrust_v2_signed.bin)"
  update_img="build/wolftrust_v2_signed.bin:$IMG_UPDATE_OFF"
fi
if [ "$SC_TAMPER" = "1" ]; then
  # One byte of guest0 flips after its digest was pinned and signed: launch
  # verification must refuse guest0 while guest1 and the platform keep running.
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

port_pre_boot "$scenario"

# --- Boot. A console boot of guests that idle forever ends on the wall-clock
#     budget (M33MU status 127), a guest that ends on its clean breakpoint
#     exits 0, and a --quit-on-faults boot ends at the first delivered fault.
emu_unbuf=()
command -v stdbuf >/dev/null 2>&1 && emu_unbuf=(stdbuf -oL -eL)
boot_chain() {
  local out="$1"
  shift
  set +e
  # M33MU's wall-clock stop calls _exit(), which drops buffered fault lines.
  # shellcheck disable=SC2086
  ${emu_unbuf[@]+"${emu_unbuf[@]}"} "$M33MU" $M33MU_CPU "$WOLFBOOT_DIR/wolfboot.bin" \
      "build/wolftrust_v1_signed.bin:$IMG_SECURE_OFF" \
      "$G0_IMG:$IMG_GUEST0_OFF" "$G1_IMG:$IMG_GUEST1_OFF" \
      ${update_img:+"$update_img"} --timeout "$timeout_s" "$@" > "$out" 2>&1
  emu_status=$?
  set -e
  echo "M33MU exit status: $emu_status"
}
boot_args=(--uart-stdout)
case "$SC_END" in
  bkpt:*) boot_args+=(--expect-bkpt "${SC_END#bkpt:}") ;;
  *) [ "$SC_GUEST0_END" = "bkpt" ] && boot_args+=(--expect-bkpt 0x7f) ;;
esac
[ "$SC_QUIT_ON_FAULTS" = "1" ] && boot_args+=(--quit-on-faults)
stage "boot the chain under M33MU ($port, ${timeout_s}s budget, end $SC_END)"
boot_chain "$log" "${boot_args[@]}"
cat "$log"
main_status="$emu_status"

judge_args=(--log "$log" --syms build/wolftrust-signed.syms
            --var "emu_status=$main_status" --var "board=$PORT_BOARD"
            --var "expected_measurement=$expected_measurement"
            --var "v2_measurement=$v2_measurement"
            --var "conf_want=$repo/tests/target/ffm_ipc_results.txt"
            --var "conf_rev=$(cat "$repo/tests/upstream/psa-arch-tests.rev")")
if [ "$SC_GUEST0" = "zephyr" ]; then
  # Both H5 guests write USART3: guest1's records can splice a guest0 line, so
  # guest0's markers are read from the reconstructed view.
  python3 "$lib/m33mu_console.py" "$log" > "$guest0_log"
  judge_args+=(--guest0-log "$guest0_log")
fi
for name in $(set | grep -oE '^L3_[A-Z0-9_]+' || true); do
  judge_args+=(--var "$name=$(eval "printf '%s' \"\$$name\"")")
done
# Where guest0's isolation probe stores and its restart probe reads
# (tests/firmware/boards/$port), and the SPM peripheral's Non-secure alias.
probe_addr="$(awk -F':= *' '/^GUEST_ISO_PROBE_ADDR/ { sub(/u$/, "", $2); print $2 }' \
    "$repo/tests/firmware/boards/$port/board.mk")"
fault_addr="$(awk '/define GUEST_SECURE_RAM_ADDR/ { sub(/u$/, "", $3); print $3 }' \
    "$repo/tests/firmware/boards/$port/board.h")"
periph_ns="$(printf '0x%08x' $((L3_SPM_PERIPHERAL - 0x10000000)))"
judge_args+=(--var "probe_addr=$probe_addr" --var "fault_addr=$fault_addr"
             --var "periph_ns=$periph_ns")

if [ -n "$SC_TRACE" ]; then
  # Why a guest's access faulted comes from M33MU's protection-unit trace,
  # which names the attribution behind a fault; it runs between every console
  # byte, so this boot leaves the console off and stops at the first delivered
  # fault: the emulator is deterministic, so that is the probe's access.
  stage "boot again with the protection-unit trace, stopping at the first fault"
  M33MU_PROT_TRACE=1 boot_chain "$trace_log" --quit-on-faults
  judge_args+=(--trace-log "$trace_log" --var "trace_status=$emu_status")
fi

stage "judge"
python3 "$lib/scenarios.py" --port "$port" --scenario "$scenario" \
    --engine "$WT_ENGINE" --env emulator --guests "$guests" judge \
    "${judge_args[@]}"
log "PASS: target/$port/$scenario"
