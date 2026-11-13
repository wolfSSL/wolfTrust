#!/usr/bin/env bash
# wolfTrust on the ST STM32L562 under the M33MU emulator (--cpu stm32l552, the
# model of the same die, with TrustZone enforcement): the chain
# the STM32L562E-DK boots (wolfBoot -> wolfTrust secure -> two baremetal
# guests), the MCXN947 scenario names, asserted from the emulator log. This is
# emulator evidence, never silicon evidence.
#
#   positive  wolfBoot verifies wolfTrust; both guests launch, reach the SPM
#             through the SG veneers and finish with no fault anywhere.
#   gtzcneg   positive plus the fabric isolation negative: guest0, its MPU
#             off, stores into guest1's RAM window, which the GTZC MPCBB
#             curtain keeps Secure. The store faults (contained, guest0
#             relaunched through its restart budget) or is discarded; either
#             way the sentinel never lands and guest1 keeps running.
#
# rollbackneg, remeasureneg, manifestneg, spbudgetneg, and sealbootneg are the
# shared Secure-verdict scenarios from lib/scenario.sh: each ends on the
# verdict breakpoint its probe emits, asserted by the port-independent table.
# crossdomain and keystoreneg fault the storage SP on an out-of-domain read;
# spfaultneg and panicneg fault an SP on its first entry and prove the SPM
# restarts it in place while both guests finish; fpneg proves only that the
# relay's FP instruction takes a NOCP UsageFault. restart spends guest0's
# restart budget on a launch-time fault; authneg refuses a tampered guest0 at
# launch. guest1 runs on through all of them. wrpoff builds wolfTrust to
# require a guest flash fence this port does not have, so neither guest runs.
#
# bothpsa, bothiso, attestneg, hsmattackneg, and fwustage run the portable
# PSA test guest (tests/firmware/psa-guest) in both windows; hsmattackneg
# drives the raw wolfHSM client wire; this port builds the native engine only.
#
# confboot, devstorage, devcrypto, devattest, devattestqcbor, vaultrecover, and
# vaultrecoversec host Arm's unmodified psa-arch-tests val NSPE in the PSA guest
# (guest0) against the conformance Secure image; guest1 is the small bare-metal
# guest so the boot cycles of the IPC suite's panic tests stay cheap.
#
# Environment (all optional):
#   M33MU                   prebuilt emulator whose STM32L552 model enforces
#                           TrustZone; otherwise M33MU_REPO at M33MU_REF is
#                           built under /tmp
#   STM32L562_WOLFBOOT_DIR  wolfBoot tree holding wolfboot.bin, tools/keytools/
#                           sign and wolfboot_signing_private_key.der, built by
#                           lib/stm32l562_wolfboot.sh for this scenario's
#                           layout; otherwise the pinned ref is built under /tmp
#   STM32L562_M33MU_TIMEOUT emulator wall-clock budget in seconds (default 60,
#                           180 for the PSA guest scenarios)
set -eu
# make test-target hands TARGET and MAKEFLAGS to every child make; wolfBoot's
# own TARGET must come from its config, so drop both before any build.
unset TARGET MAKEFLAGS MFLAGS

scenario="${1:-}"
# The scenario table in lib/scenario_matrix.py is the one list of names.
known="$(python3 "$(dirname "$0")/lib/scenario_matrix.py" --port stm32l562 \
  --tier full --flat)"
case " $known " in
  *" $scenario "*) ;;
  *) echo "usage: $0 $(echo "$known" | tr ' ' '|')" >&2; exit 2 ;;
esac
if [ "${WT_ENGINE:-native}" != "native" ]; then
  echo "TARGET=stm32l562 builds the native engine only" >&2
  exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
case "$scenario" in
  bothpsa|bothiso|attestneg|hsmattackneg|fwustage|deputyneg|hsmpinneg|hsmfaultneg|bandneg[1-6]|restartneg[1-3]|periphspneg|sealneg|sealpivotneg|svcneg)
    guest_dir="tests/firmware/psa-guest"
    guest1_dir="$guest_dir"
    timeout_s="${STM32L562_M33MU_TIMEOUT:-180}" ;;
  confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
    guest_dir="tests/firmware/psa-guest"
    guest1_dir="tests/firmware/stm32l562-baremetal"
    timeout_s="${STM32L562_M33MU_TIMEOUT:-900}" ;;
  *)
    guest_dir="tests/firmware/stm32l562-baremetal"
    guest1_dir="$guest_dir"
    timeout_s="${STM32L562_M33MU_TIMEOUT:-60}" ;;
esac
guest_build="$repo/$guest_dir/build"
guest1_build="$repo/$guest1_dir/build"

# shellcheck source=lib/stm32l562_wolfboot.sh disable=SC1091
. "$here/lib/stm32l562_wolfboot.sh"
log="$repo/build/stm32l562_m33mu_$scenario.log"

# M33MU with the STM32L552 TrustZone model (GTZC MPCBB, flash watermarks,
# TZSC, TZEN at power-up), pinned on the fork until it merges upstream.
M33MU_REPO=https://github.com/aidangarske/m33mu.git
M33MU_REF=0510c53a882b0794b8e7a30466f779d4bf724aac

# The guests' manifest restart budget (port/stm32l562/partitions.c): a
# faulting guest0 is relaunched this many times before quarantine.
restart_limit=3
# Where guest0's probe stores: inside guest1's RAM window (GUEST_PROBE_ADDR in
# tests/firmware/stm32l562-baremetal/Makefile).
probe_addr=0x20034100
# Where guest0's restart probe reads: Secure RAM (GUEST_FAULT_ADDR there).
fault_addr=0x30001000

# shellcheck source=lib/scenario.sh disable=SC1091
. "$here/lib/scenario.sh"
l3_layout_load "$repo" stm32l562

# Port markers the shared verdict assertions match against.
# shellcheck disable=SC2034  # matched inside lib/scenario.sh
GUEST_STARTED_RE='wolfTrust STM32L562 guest[01]: start'
# shellcheck disable=SC2034
GUEST_DONE_RE='wolfTrust STM32L562 guest[01]: FF-M connect ok, done'

# --- The pinned M33MU with the STM32L552 TrustZone model. ---
m33mu_stamp="$M33MU_REPO $M33MU_REF"
if [ -n "${M33MU:-}" ] && [ -x "$M33MU" ]; then
  log "Using prebuilt M33MU: $M33MU"
elif stm32l562_owned_dir /tmp/m33mu_stm32l562_src &&
     [ -x /tmp/m33mu_stm32l562_src/build/m33mu ] &&
     [ "$(cat /tmp/m33mu_stm32l562_src/.wt_m33mu 2>/dev/null)" = "$m33mu_stamp" ]; then
  M33MU=/tmp/m33mu_stm32l562_src/build/m33mu
  log "Reusing M33MU from a prior scenario: $M33MU"
else
  stage "build M33MU $M33MU_REF"
  rm -rf /tmp/m33mu_stm32l562_src
  git clone --no-checkout "$M33MU_REPO" /tmp/m33mu_stm32l562_src
  git -C /tmp/m33mu_stm32l562_src fetch --depth 1 origin "$M33MU_REF"
  git -C /tmp/m33mu_stm32l562_src checkout --detach "$M33MU_REF"
  cmake -S /tmp/m33mu_stm32l562_src -B /tmp/m33mu_stm32l562_src/build \
        -DM33MU_ENABLE_WOLFSSL=OFF -DM33MU_BUILD_TESTS=OFF \
        -DM33MU_ENABLE_RUST_PLUGINS=OFF
  cmake --build /tmp/m33mu_stm32l562_src/build --target m33mu -j"$(nproc)"
  printf '%s\n' "$m33mu_stamp" > /tmp/m33mu_stm32l562_src/.wt_m33mu
  M33MU=/tmp/m33mu_stm32l562_src/build/m33mu
fi

# --- Secure-app wolfBoot first stage from the pinned stm32l5-tz-wolftrust
#     config. The conformance image and its Arm test guests need the larger
#     slot (port/stm32l562/memory_map.h), so those scenarios rebuild wolfBoot
#     with it; the update slot then aliases the top of bank 2, whose trailer
#     page stays erased. ---
case "$scenario" in
  confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
    layout=conformance
    part_size=0x28000
    guest0_off=0x40000
    guest1_off=0x7C000
    trailer_off=0x7F800
    # The PSA guest makefile also links a guest1 this layout never loads
    # (guest1 is the baremetal guest), so give that one guest0's window.
    guest_windows="GUEST0_FLASH_ORIGIN=0x08040000 GUEST0_FLASH_LENGTH=0x3C000 GUEST0_RAM_LENGTH=0x14000 GUEST1_FLASH_ORIGIN=0x08040000 GUEST1_FLASH_LENGTH=0x3C000 GUEST1_RAM_ORIGIN=0x20028000 GUEST1_RAM_LENGTH=0x14000"
    guest1_windows="GUEST0_FLASH_ORIGIN=0x08040000 GUEST0_FLASH_LENGTH=0x3C000 GUEST0_RAM_LENGTH=0x14000 GUEST1_FLASH_ORIGIN=0x0807C000 GUEST1_FLASH_LENGTH=0x3800 GUEST1_RAM_ORIGIN=0x2003C000 GUEST1_RAM_LENGTH=0x4000"
    secwm2="" ;;
  *)
    layout=production
    part_size=0x20000
    guest0_off=0x60000
    guest1_off=0x70000
    trailer_off=0x5F800
    guest_windows=""
    guest1_windows=""
    secwm2="--secwm2=0:63" ;;
esac
wolfboot_make="WOLFBOOT_PARTITION_SIZE=$part_size"
if [ "$layout" = "conformance" ]; then
  wolfboot_make="$wolfboot_make WOLFBOOT_PARTITION_UPDATE_ADDRESS=0x0C058000"
fi
wolfboot_dir="${STM32L562_WOLFBOOT_DIR:-/tmp/wolfboot_stm32l562_$layout}"
if [ -n "${STM32L562_WOLFBOOT_DIR:-}" ]; then
  # shellcheck disable=SC2086
  stm32l562_wolfboot_current "$wolfboot_dir" "$(stm32l562_wolfboot_stamp $wolfboot_make)" || \
    fail "wolfboot.bin in STM32L562_WOLFBOOT_DIR=$wolfboot_dir was not built from $STM32L562_WOLFBOOT_REF with $STM32L562_WOLFBOOT_CONFIG for the $layout layout; rebuild it there (tests/target/lib/stm32l562_wolfboot.sh) or unset it"
else
  stage "wolfBoot $STM32L562_WOLFBOOT_REF (stm32l5-tz-wolftrust, $layout layout)"
  # shellcheck disable=SC2086
  stm32l562_wolfboot_build "$wolfboot_dir" $wolfboot_make || fail "wolfBoot build failed"
fi
# The host suite tests a copy of the life cycle mapping this wolfBoot runs.
cmp -s "$wolfboot_dir/hal/stm32l5_lifecycle.h" \
    "$repo/tests/host/stm32l562_lifecycle/stm32l5_lifecycle.h" || \
  fail "wolfBoot's hal/stm32l5_lifecycle.h differs from tests/host/stm32l562_lifecycle"

# --- wolfTrust and both guests, measurements pinned, signed for the boot
#     partition. ---
cd "$repo"
git submodule update --init --single-branch
# The wolfBoot config uses a 1024-byte image header, so wolfTrust links at the
# boot base + 0x400 and is signed with a matching header.
export WT_SECURE_IMAGE_HEADER_SIZE=0x400
rm -rf build
mkdir -p build

secure_flags="$(scenario_secure_flags "$scenario")"
# Exported, not passed once: the guest build below re-enters the secure
# Makefile for the CMSE implib, and a build-mode mismatch there would relink
# the image and drop the wolftrust.bin this runner goes on to patch and sign.
if [ -n "$secure_flags" ]; then
  # shellcheck disable=SC2086,SC2163
  export $secure_flags
fi
stage "build wolfTrust secure image + CMSE import library ${secure_flags:-(production)}"
make -s TARGET=stm32l562 secure-image TOOLPREFIX=arm-none-eabi-

guest_flags=""
case "$scenario" in
  gtzcneg)      guest_flags="WT_SAU_PROBE=1" ;;
  periphneg)    guest_flags="WT_PERIPH_NEG_PROBE=1" ;;
  # The secure probe fires inside a partition; guest0 ends the run on its
  # breakpoint once its lifecycle is done, as the H5 level 3 runs do.
  deputyneg|hsmpinneg|hsmfaultneg|bandneg[1-6]|restartneg[1-3]|periphspneg|sealneg|sealpivotneg|svcneg)
                guest_flags="WT_M33MU_EXPECT_BKPT=1"
                # guest0's own tasklet faults, so the peer ends the run.
                if [ "$scenario" = "hsmfaultneg" ]; then
                    guest_flags="$guest_flags WT_M33MU_BKPT_GUEST=1"
                fi ;;
  restart)      guest_flags="WT_GUEST_FAULT_PROBE=1" ;;
  attestneg)    guest_flags="WT_ATTEST_NEG_PROBE=1" ;;
  hsmattackneg) guest_flags="WT_HSM_ATTACK_PROBE=1" ;;
  # 0x12000 bytes of body reach sector 9 of the 16-sector update partition;
  # the 27-byte tail ends off a double-word, so FINISH sees a padded block.
  fwustage)     guest_flags="WT_FWU_PROBE=1 WT_FWU_PROBE_STREAM_BYTES=0x12000u WT_FWU_PROBE_SEQUENTIAL=1 WT_FWU_PROBE_TAIL_BYTES=27u" ;;
  confboot)     guest_flags="WT_RUN_CONFORMANCE=1 WT_M33MU_EXPECT_BKPT=1" ;;
  devstorage)   guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=storage WT_M33MU_EXPECT_BKPT=1" ;;
  devcrypto|vaultrecover|vaultrecoversec)
                guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=crypto WT_M33MU_EXPECT_BKPT=1" ;;
  devattest)    guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation WT_M33MU_EXPECT_BKPT=1" ;;
  devattestqcbor)
                tests/upstream/fetch_qcbor.sh >/dev/null
                guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation WT_ATTEST_CBOR=qcbor WT_M33MU_EXPECT_BKPT=1" ;;
esac
stage "build the Non-secure guests from $guest_dir ${guest_flags:-(no probes)}"
make -s -C "$guest_dir" clean
# The emulator boots with TZEN=1 and RDP level 0, which wolfBoot reports as
# the PSA_ROT_PROVISIONING life cycle; the guest's verify pins it.
# shellcheck disable=SC2086
make -s -C "$guest_dir" TARGET=stm32l562 WT_EXPECTED_LIFECYCLE=0x2000u $guest_windows $guest_flags
if [ "$guest1_dir" != "$guest_dir" ]; then
  make -s -C "$guest1_dir" clean
  # shellcheck disable=SC2086
  make -s -C "$guest1_dir" TARGET=stm32l562 $guest1_windows
fi

stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
python3 tools/measure/patch_guest_digests.py build/wolftrust.bin \
    "0:1:$guest_build/guest0.bin" "1:1:$guest1_build/guest1.bin"
IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=$part_size WOLFBOOT_SECTOR_SIZE=0x800 \
    "$wolfboot_dir/tools/keytools/sign" --ecc256 --sha256 build/wolftrust.bin \
    "$wolfboot_dir/wolfboot_signing_private_key.der" 1
[ -s build/wolftrust_v1_signed.bin ] || fail "signing produced no image"
# The harness, not the guest, holds wolfBoot's measurement of the signed image
# and matches the attestation token's reported value against it.
expected_measurement="$(python3 tests/scripts/read_wolfboot_measurement.py \
    build/wolftrust_v1_signed.bin)"

if [ "$scenario" = "authneg" ]; then
  # One byte of guest0 flips after its digest was pinned: launch verification
  # must refuse guest0 while guest1 and the platform keep running.
  python3 - "$guest_build/guest0.bin" <<'PYEOF'
import sys
with open(sys.argv[1], "r+b") as f:
    f.seek(0x40)
    byte = f.read(1)
    f.seek(0x40)
    f.write(bytes([byte[0] ^ 0x01]))
PYEOF
fi

# The guests idle forever once done, so a console boot ends on the wall-clock
# budget (M33MU status 127) and a --quit-on-faults boot at the fault (0).
# One factory image holds the whole 512 KiB flash: wolfBoot at 0, the signed
# Secure image at 0xC000 and the guests at this layout's offsets. No image may
# touch the update partition's trailer page, which must stay erased.
factory="$repo/build/stm32l562_factory.bin"
python3 - "$factory" "$trailer_off" "$wolfboot_dir/wolfboot.bin:0x0" \
    "build/wolftrust_v1_signed.bin:0xC000" "$guest_build/guest0.bin:$guest0_off" \
    "$guest1_build/guest1.bin:$guest1_off" <<'FLASHEOF'
import sys
flash = bytearray(b"\xff" * 0x80000)
trailer = int(sys.argv[2], 16)
for spec in sys.argv[3:]:
    path, offset = spec.rsplit(":", 1)
    data = open(path, "rb").read()
    base = int(offset, 16)
    if base + len(data) > len(flash):
        raise SystemExit("%s does not fit at %s" % (path, offset))
    if base < trailer + 0x800 and base + len(data) > trailer:
        raise SystemExit("%s overlaps the update trailer page at %#x" %
                         (path, trailer))
    flash[base:base + len(data)] = data
open(sys.argv[1], "wb").write(flash)
FLASHEOF
boot_chain() {
    local want="$1"
    local out="$2"
    local status
    shift 2
    set +e
    # shellcheck disable=SC2086
    "$M33MU" --cpu stm32l552 $secwm2 "$factory" \
        --timeout "$timeout_s" "$@" > "$out" 2>&1
    status=$?
    set -e
    check "$(printf '%s' "$status" | grep -qE "^($want)$"; echo $?)" \
        "M33MU exited with status $want (got $status)"
}

end="$(scenario_end "$scenario")"
case "$scenario" in
  confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
    # The val guest ends on its own breakpoint; the suite's panic tests reset
    # the whole chain mid-run and val resumes off its flash boot flag.
    end="bkpt:0x7f" ;;
  fpneg|xnneg|mspovfneg)
    # M33MU ends these runs at the fault (NOCP, the fetch denial, STKOF).
    end="fault" ;;
  deputyneg|hsmpinneg|hsmfaultneg|bandneg[1-6]|restartneg[1-3]|periphspneg|sealneg|sealpivotneg|svcneg)
    end="bkpt:0x7f" ;;
esac
stage "boot the chain under M33MU (--cpu stm32l552, ${timeout_s}s budget)"
case "$end" in
  bkpt:*) boot_chain 0 "$log" --uart-stdout --expect-bkpt "${end#bkpt:}" ;;
  fault)  boot_chain "0|1" "$log" --uart-stdout --quit-on-faults ;;
  *)      boot_chain 127 "$log" --uart-stdout ;;
esac

# wolfBoot's L5 console is LPUART1, which M33MU does not attach; a guest only
# starts once the Secure image has consumed wolfBoot's verified handoff. The
# verdict and fault scenarios end before any guest, on their own markers.
if [ "$end" = "idle" ] && [ "$scenario" != "wrpoff" ] && [ "$scenario" != "authneg" ]; then
    expect_re "wolfBoot verified wolfTrust and handed off to it" \
        '(wolfTrust STM32L562 guest1: start|guest1: alive)'
fi
if [ "$end" = "idle" ]; then
  refute_re "wolfTrust never panicked (bkpt 0x7e)" '\[BKPT\] imm=0x7e'
  refute_re "the monitor never lost every guest (bkpt 0x7d)" '\[BKPT\] imm=0x7d'
  refute_re "no HardFault escalation" '\[HARDFLT\]'
  refute_re "no guest reported a failed FF-M handshake" 'guest[01]: FAIL'
  refute_re "no PSA guest lifecycle step failed" \
      'guest[01]: .*(FAILED|failed|NOT re|SUCCEEDED|accepted|unavailable|wrong data|not refused|not rejected)'
  expect "the run ended on the wall-clock budget, not a trap" "wall-clock limit"
elif [ "${end}" = "bkpt:0x7f" ]; then
  expect "the val guest ran to its clean exit breakpoint" "[EXPECT BKPT] Success"
elif [ "$end" = "fault" ]; then
  expect "the run stopped at the first delivered fault" "Execution stopped"
else
  expect "the emulator stopped on the expected verdict breakpoint" \
      "[EXPECT BKPT] Success"
  scenario_assert_verdict "$scenario"
fi

# The Arm suite prints its report once at the end; guest1's lines can splice
# it, so the totals are read from the log with guest1 stripped and unwrapped.
conf_totals() {
    local flat
    flat="$(sed 's/guest1:.*$//' "$log" | tr -d '\r\n')"
    conf_passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    conf_skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    conf_failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${conf_passed:=-1}"; : "${conf_skipped:=-1}"; : "${conf_failed:=-1}"
}

# A guest fault relaunches that guest, so exact launch counts also prove that
# nothing faulted where nothing should have.
case "$scenario" in
  positive|crossdomain|keystoreneg|spfaultneg|panicneg)
    for guest in guest0 guest1; do
        expect_n "$guest launched exactly once (no fault, no relaunch)" 1 \
            "wolfTrust STM32L562 $guest: start"
        expect_n "$guest reached the SPM through the SG veneers and finished" 1 \
            "wolfTrust STM32L562 $guest: FF-M connect ok, done"
    done
    # The deliberate SP probe faults are Secure faults the guests above prove
    # the system rode out. M33MU's own fault dumps go to a buffered stdout
    # that its wall-clock exit drops, so each probe is shown by a second boot
    # that stops at the first delivered fault.
    if [ "$scenario" = "positive" ] || [ "$scenario" = "spfaultneg" ]; then
        expect_n "both guests reached the storage service" 2 ": storage connect ok"
    elif [ "$scenario" = "panicneg" ]; then
        # The panic unblocks the client it was serving with an error; the
        # restarted SP serves the other guest.
        expect_n "the restarted storage SP served the guest after the panic" 1 \
            ": storage connect ok"
    fi
    if [ "$scenario" = "spfaultneg" ] || [ "$scenario" = "panicneg" ]; then
        # The relay (spfaultneg) runs an undefined instruction on its first
        # entry; the storage SP (panicneg) closes an error handle, which the SPM
        # must panic it for by resuming it on one.
        stage "boot again, stopping at the first delivered fault"
        log="$repo/build/stm32l562_m33mu_${scenario}_trace.log"
        boot_chain 0 "$log" --quit-on-faults
        expect "the traced run stopped at a delivered fault" "Execution stopped"
        expect_n_re "the probed SP took a Secure-Thread UsageFault" 1 \
            '\[USGFLT\] enter sec=1 mode=0'
        expect "the fault was the undefined instruction" "[USGFLT] CFSR=0x00010000"
    elif [ "$scenario" != "positive" ]; then
        # The storage SP's probe faults on its first wake, so the guests'
        # storage connect never succeeds while their own lifecycle survives.
        refute_re "the probed storage SP never served a guest connect" \
            ": storage connect ok"
        case "$scenario" in
          crossdomain) neg_addr="$L3_SPM_RAM" ;;
          keystoreneg) neg_addr="$L3_VAULT_BAND" ;;
        esac
        stage "boot again with the protection-unit trace, stopping at the first fault"
        log="$repo/build/stm32l562_m33mu_${scenario}_trace.log"
        M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
        expect "the traced run stopped at a delivered fault" "Execution stopped"
        expect_re "the fault was the SP's out-of-domain read at the band address" \
            "\[MEMFAULT_CAUSE\] sec=S type=READ addr=$neg_addr reason=mpu-ap"
    fi
    ;;
  deputyneg|hsmpinneg|hsmfaultneg|bandneg[1-6]|restartneg[1-3]|periphspneg|sealneg|sealpivotneg|svcneg)
    expect_n "guest0 launched exactly once" 1 "guest0: alive"
    if [ "$scenario" = "hsmfaultneg" ]; then
        expect "guest1 ran its whole PSA lifecycle to the end breakpoint" \
            "guest1: done"
    else
        expect "guest0 ran its whole PSA lifecycle to the end breakpoint" \
            "guest0: done"
        expect "guest1 ran beside the partition under test" "guest1: alive"
    fi
    case "$scenario" in
      deputyneg)
        l3_assert_probe_linked build/wolftrust.elf \
            wt_platform_deputy_flash_probe ;;
      hsmpinneg)
        l3_assert_probe_linked build/wolftrust.elf wt_platform_hsm_pin_probe ;;
      *)
        scenario_assert_l3 "$scenario" ;;
    esac
    case "$scenario" in
      deputyneg|hsmpinneg|bandneg[1-6]|restartneg[1-3])
        # The probed partition is restarted (or never faults) and serves on.
        if [ "$scenario" = "deputyneg" ] || [ "$scenario" = "hsmpinneg" ]; then
            refute_re "no fault markers in the boot log" \
                '^(\[MEMFAULT\]|\[USGFLT\]|\[HARDFLT\]|HardFault|SecureFault)'
        fi
        expect "mediated crypto dispatch verified" \
            "guest0: wolfTrust FF-M mediated crypto dispatch verified"
        expect "ITS set/get verified" "guest0: wolfTrust ITS set/get verified"
        expect "PS sealed set/get verified" \
            "guest0: wolfTrust PS sealed set/get verified"
        expect "key-ops sign/verify verified" \
            "guest0: wolfTrust key-ops sign/verify verified"
        expect "attestation COSE_Sign1 verified" \
            "guest0: wolfTrust attestation: COSE_Sign1 verified"
        ;;
      hsmfaultneg)
        expect "the other guest kept being served" \
            "guest1: psa_hash_compute(SHA-256) KAT verified" ;;
      svcneg)
        # The stateless ITS client reports the unblocked call as an error.
        expect_re "the pinned ITS client was unblocked with an error" \
            'guest[01]: psa_its_set failed st=-1(32|45)'
        expect "the restarted ITS partition served the other guest" \
            "wolfTrust ITS set/get verified"
        expect "sealed storage path unaffected" \
            "guest0: wolfTrust PS sealed set/get verified" ;;
      periphspneg)
        refute_re "the probed storage SP never served ITS" \
            'guest[01]: wolfTrust ITS set/get verified' ;;
    esac
    ;;
  xnneg|mspovfneg)
    scenario_assert_verdict "$scenario"
    ;;
  fpneg)
    # The relay's FP instruction must hit a disabled coprocessor: NOCP, not the
    # fallback undefined-instruction fault. Restart and guest survival are the
    # silicon leg's to show (docs/Testing.md).
    expect_n_re "the relay took a Secure-Thread UsageFault" 1 \
        '\[USGFLT\] enter sec=1 mode=0'
    expect "the fault was the NOCP trap (Secure FP disabled)" \
        "[USGFLT] CFSR=0x00080000"
    refute_re "no HardFault escalation" '\[HARDFLT\]'
    ;;
  restart)
    faults=$((restart_limit + 1))
    expect_n "guest0 relaunched through its restart budget, then quarantined" \
        "$faults" "wolfTrust STM32L562 guest0: start"
    refute_re "guest0 never got past its launch-time fault" \
        "wolfTrust STM32L562 guest0: FF-M connect ok"
    expect_n "guest1 launched once, untouched by guest0's faults" 1 \
        "wolfTrust STM32L562 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust STM32L562 guest1: FF-M connect ok, done"
    stage "boot again with the protection-unit trace, stopping at the first fault"
    log="$repo/build/stm32l562_m33mu_${scenario}_trace.log"
    M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
    expect "the traced run stopped at a delivered fault" "Execution stopped"
    refused="\[MEMFAULT_CAUSE\] sec=NS type=READ addr=$fault_addr reason=secure-attr"
    expect_n_re "the fault was guest0's read of Secure RAM, refused as Secure" \
        1 "$refused"
    sau_refusals="$(grep -A1 -E -- "$refused" "$log" | grep -c "src=SAU" || true)"
    check "$([ "$sau_refusals" -eq 1 ]; echo $?)" \
        "the refusal came from the SAU"
    ;;
  wrpoff)
    refute_re "no guest entered its domain without a guest flash fence" \
        "wolfTrust STM32L562 guest[01]: start"
    ;;
  authneg)
    refute_re "the tampered guest0 never entered its domain" \
        "wolfTrust STM32L562 guest0: start"
    expect_n "guest1 launched once after guest0's refusal" 1 \
        "wolfTrust STM32L562 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust STM32L562 guest1: FF-M connect ok, done"
    expect_n "guest1 reached the storage service" 1 \
        "wolfTrust STM32L562 guest1: storage connect ok"
    ;;
  bothpsa|bothiso|attestneg|hsmattackneg|fwustage)
    for guest in guest0 guest1; do
        expect_n "$guest launched exactly once (no fault, no relaunch)" 1 \
            "$guest: alive"
        expect_n "$guest ran its whole PSA lifecycle" 1 "$guest: done"
    done
    case "$scenario" in
      bothpsa)
        # The same PSA client behaviour from both guests in one boot.
        for guest in guest0 guest1; do
            expect "$guest: mediated SERVICE_CRYPTO SHA-256 KAT" \
                "$guest: wolfTrust FF-M mediated crypto dispatch verified"
            expect "$guest: PSA psa_generate_random" \
                "$guest: psa_generate_random st=0"
            expect "$guest: PSA psa_hash_compute(SHA-256) KAT" \
                "$guest: psa_hash_compute(SHA-256) KAT verified"
            expect "$guest: PSA AES-CTR through a volatile key" \
                "$guest: psa_cipher_encrypt(AES-CTR) st=0"
            expect "$guest: ITS set/get through SERVICE_ITS" \
                "$guest: wolfTrust ITS set/get verified"
            expect "$guest: PS sealed set/get through SERVICE_PS" \
                "$guest: wolfTrust PS sealed set/get verified"
            expect "$guest: key-ops sign/verify through the mediated path" \
                "$guest: wolfTrust key-ops sign/verify verified"
            expect "$guest: cross-key verify refused" \
                "$guest: wolfTrust key negatives verified"
            expect "$guest: initial attestation token issued" \
                "$guest: psa_initial_attestation st=0"
            expect "$guest: COSE_Sign1 token verified against the IAK" \
                "$guest: wolfTrust attestation: COSE_Sign1 verified"
            expect "$guest: token measurement equals wolfBoot's measurement of the signed image" \
                "$guest: wolfTrust attestation: token measurement=$expected_measurement"
        done
        ;;
      bothiso)
        # The SPM rejects the same abuse from both guests, and each guest
        # still gets served afterwards.
        for guest in guest0 guest1; do
            expect "$guest: forged-handle call rejected" \
                "$guest: wolfTrust FF-M forged-handle call rejected"
            expect "$guest: oversized-vector call rejected" \
                "$guest: wolfTrust FF-M oversized-vector call rejected"
            expect "$guest: cross-guest vector refused (caller-banded memcheck)" \
                "$guest: wolfTrust FF-M cross-guest vector rejected"
            expect "$guest: unknown-SID connect refused" \
                "$guest: wolfTrust FF-M unknown-SID connect refused"
            expect "$guest: still served after the negatives" \
                "$guest: psa_hash_compute(SHA-256) KAT verified"
        done
        ;;
      attestneg)
        expect "attestation baseline token verified" \
            "guest0: wolfTrust attestation: COSE_Sign1 verified"
        expect "oversized challenge rejected st=-135" \
            "guest0: attestneg oversized challenge rejected st=-135"
        expect "zero token buffer rejected st=-135" \
            "guest0: attestneg zero token buffer rejected st=-135"
        expect "tampered token fails the guest verify" \
            "guest0: attestneg tampered token rejected"
        expect "misattributed lifecycle fails the guest verify" \
            "guest0: attestneg lifecycle mismatch rejected"
        expect "attestation negatives verified" \
            "guest0: wolfTrust attestation negatives verified"
        ;;
      hsmattackneg)
        expect "forged COMM_INIT attempted" \
            "guest0: hsmattackneg forged COMM_INIT"
        expect "IAK sign refused" "guest0: hsmattackneg IAK sign refused"
        expect "rollback NVM group refused" \
            "guest0: hsmattackneg rollback NVM group refused"
        expect "own-namespace crypto still works" \
            "guest0: hsmattackneg own-namespace crypto still works"
        ;;
      fwustage)
        expect "write before start refused on target" \
            "guest0: wolfTrust FWU write-before-start refused"
        expect "candidate body streamed across the update partition's data sectors" \
            "guest0: wolfTrust FWU streamed candidate body across the update partition"
        expect "candidate staged to the update partition and armed" \
            "guest0: wolfTrust FWU staged signed-header candidate to update partition, armed, verified"
        expect "reject disarms and clean restores READY" \
            "guest0: wolfTrust FWU reject disarmed and clean restored READY"
        expect "a write that skips ahead is refused and the session cleans" \
            "guest0: wolfTrust FWU out-of-order write refused and cleaned"
        expect "unrelated storage partitions unaffected" \
            "guest0: wolfTrust ITS set/get verified"
        ;;
    esac
    ;;
  confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover)
    expect "guest0 booted the PSA client" "guest0: wolfTrust FF-M psa_framework_version=0x0100"
    expect "conformance val_entry start" "guest0: wolfTrust FF-M conformance: val_entry start"
    conf_totals
    case "$scenario" in
      confboot)
        # 89 scheduled: 85 pass, the 4 heap tests report SKIPPED on this
        # zero-allocation image, as on the H5 and the RT700.
        check "$([ "$conf_failed" -eq 0 ] && [ "$conf_passed" -eq 85 ] && [ "$conf_skipped" -eq 4 ]; echo $?)" \
            "Arm FF-M IPC suite: ${conf_passed} passed, ${conf_skipped} skipped, ${conf_failed} failed (want 85/4/0)"
        ;;
      devstorage)
        check "$([ "$conf_failed" -eq 0 ] && [ "$((conf_passed + conf_skipped))" -eq 17 ]; echo $?)" \
            "dev_apis storage: ${conf_passed} passed, ${conf_skipped} skipped, ${conf_failed} failed (17 total)"
        ;;
      devcrypto|vaultrecover)
        check "$([ "$conf_failed" -eq 0 ] && [ "$((conf_passed + conf_skipped))" -eq 77 ]; echo $?)" \
            "dev_apis crypto: ${conf_passed} passed, ${conf_skipped} skipped, ${conf_failed} failed (77 scheduled)"
        ;;
      devattest|devattestqcbor)
        check "$([ "$conf_failed" -eq 0 ] && [ "$conf_passed" -eq 1 ]; echo $?)" \
            "dev_apis initial_attestation: ${conf_passed} passed, ${conf_failed} failed"
        ;;
    esac
    ;;
  vaultrecoversec)
    refute_re "no fault (fail closed, not a brick)" '\[HARDFLT\]|HardFault|SecureFault'
    expect "guest starts under fail-closed attestation" \
        "guest0: wolfTrust FF-M conformance: val_entry start"
    ;;
  periphneg)
    # The CPU leg: the SAU leaves the RNG page Secure, so the NS read faults;
    # Non-secure DMA copies out of Secure memory are silicon work.
    faults=$((restart_limit + 1))
    expect_n "guest0 relaunched through its restart budget" \
        "$faults" "wolfTrust STM32L562 guest0: start"
    refute_re "no NS read of the SPM's RNG ever returned" "periph probe LEAKED"
    expect_n "guest1 launched once, untouched by guest0's faults" 1 \
        "wolfTrust STM32L562 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust STM32L562 guest1: FF-M connect ok, done"
    stage "boot again with the protection-unit trace, stopping at the first fault"
    log="$repo/build/stm32l562_m33mu_${scenario}_trace.log"
    M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
    expect "the traced run stopped at a delivered fault" "Execution stopped"
    periph_ns="$(printf '0x%08x' $((L3_SPM_PERIPHERAL - 0x10000000)))"
    refused="\[MEMFAULT_CAUSE\] sec=NS type=READ addr=$periph_ns reason=secure-attr"
    expect_n_re "the fault was guest0's NS read of the SPM's RNG, refused as Secure" \
        1 "$refused"
    sau_refusals="$(grep -A1 -E -- "$refused" "$log" | grep -c "src=SAU" || true)"
    check "$([ "$sau_refusals" -eq 1 ]; echo $?)" "the refusal came from the SAU"
    ;;
  gtzcneg)
    # The GTZC curtain must stop the store at the fabric: it either faults the
    # initiating guest (contained, relaunched through its budget) or is
    # discarded (RAZ/WI, the guest reads it back absent). The peer never sees
    # the sentinel and keeps running.
    refute_re "peer RAM never receives the sentinel" "GTZC peer write LEAKED"
    expect "guest0 attempted the peer store" \
        "GTZC bypass probe: attempting peer write"
    faulted=0
    if ! grep -Fq "GTZC peer write blocked" "$log"; then
        faulted=1
        expect_n "guest0 relaunched through its restart budget" \
            "$((restart_limit + 1))" "wolfTrust STM32L562 guest0: start"
    fi
    expect_n "guest1 launched once, untouched by guest0's probe" 1 \
        "wolfTrust STM32L562 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust STM32L562 guest1: FF-M connect ok, done"
    if [ "$faulted" -eq 1 ]; then
        stage "boot again with the protection-unit trace, stopping at the first fault"
        log="$repo/build/stm32l562_m33mu_${scenario}_trace.log"
        M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
        expect "the traced run stopped at a delivered fault" "Execution stopped"
        refused="\[MEMFAULT_CAUSE\] sec=NS type=WRITE addr=$probe_addr reason=secure-attr"
        expect_n_re "the fault was guest0's store into guest1's RAM, refused as Secure" \
            1 "$refused"
        mpcbb_refusals="$(grep -A1 -E -- "$refused" "$log" | grep -c "src=MPCBB" || true)"
        check "$([ "$mpcbb_refusals" -eq 1 ]; echo $?)" \
            "the refusal came from the GTZC MPCBB: the peer window was Secure at dispatch"
    fi
    ;;
esac

log "PASS: stm32l562-m33mu/$scenario"
