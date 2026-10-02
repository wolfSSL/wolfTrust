#!/usr/bin/env bash
# wolfTrust FF-M target-scenario runner. Builds the authenticated
# wolfBoot -> wolfTrust -> guests chain and boots it under the M33MU emulator,
# asserting one scenario's markers. Run inside ghcr.io/wolfssl/wolfboot-ci-m33mu
# (the same image CI uses); never bare-metal on the host, so every file under
# the repo stays root-owned and consistent across runs.
#
#   run_m33mu_scenario.sh positive     lifecycle green, no faults
#   run_m33mu_scenario.sh restart      guest faults on boot; monitor restarts it
#                                       restart_limit times then leaves it FAULTED
#   run_m33mu_scenario.sh crossdomain  a probe inside the crypto SP reads
#                                       SPM-private RAM and the SP domain faults
#   run_m33mu_scenario.sh spfaultneg   the crypto SP faults once; wolfTrust
#                                       gracefully restarts it in place (no
#                                       reset) and it serves again, guests live
#   run_m33mu_scenario.sh hsmfaultneg  a guest HSM tasklet faults once;
#                                       the other guest survives without panic
#   run_m33mu_scenario.sh confboot     conformance image (Arm server/client SPs
#                                       scheduled, WT_CONFORMANCE=1) boots the
#                                       full positive lifecycle green
#   run_m33mu_scenario.sh devstorage   dev_apis ITS/PS suite (test_s001-s017)
#                                       runs Non-secure against SERVICE_ITS/PS
#   run_m33mu_scenario.sh devcrypto    dev_apis Crypto suite (test_c001-c080;
#                                       78 scheduled — upstream db skips
#                                       c064/c065 hash suspend/resume) runs
#                                       Non-secure against wolfPSA
#   run_m33mu_scenario.sh devattest    dev_apis Initial Attestation (test_a001)
#                                       runs Non-secure against SERVICE_ATTEST;
#                                       val parses the token via the wolfCOSE
#                                       qcbor shim
#   run_m33mu_scenario.sh devattestqcbor  same suite parsed with the reference
#                                       QCBOR library (fetched test-only)
#   run_m33mu_scenario.sh attestneg    production image + guest probe: invalid
#                                       attestation requests rejected over IPC,
#                                       tampered/misattributed tokens refused
#   run_m33mu_scenario.sh authneg      corrupt guest0 image vs its pinned
#                                       digest: authenticated launch fails
#                                       closed, guest1 keeps running
#   run_m33mu_scenario.sh rollbackneg  probe arms the NVM version floor above
#                                       the running image and reboots: the
#                                       downgraded boot is refused fail-closed
#   run_m33mu_scenario.sh bootupdate   full boot-and-update gate: v1 arms
#                                       wolfBoot's real update trigger for a
#                                       pre-staged signed v2 candidate and
#                                       reboots; wolfBoot swaps v2 in and boots
#                                       it; the post-swap token reports v2's
#                                       measurement (anti-rollback floor v1->v2)
#
# This is the single source the local make test-target harness, the box skill
# scripts, and the CI jobs all drive, so each scenario's markers stay identical.
set -euo pipefail
# make test-target hands TARGET and MAKEFLAGS to every child make; wolfBoot's
# own TARGET must come from its config, so drop both before any build.
unset TARGET MAKEFLAGS MFLAGS
set -o pipefail

scenario="${1:-}"
# The scenario table in lib/scenario_matrix.py is the one list of names.
known="$(python3 "$(dirname "$0")/lib/scenario_matrix.py" --port stm32h563 \
  --tier full --flat)"
case " $known " in
  *" $scenario "*) ;;
  *) echo "usage: $0 $(echo "$known" | tr ' ' '|')" >&2; exit 2 ;;
esac

# Variant scenarios carry their probe number in the name (bandneg3 = probe 3).
family="$scenario"
case "$scenario" in
  bandneg[1-6]) family=bandneg; band_probe="${scenario#bandneg}" ;;
  restartneg[1-3]) family=restartneg ;;
esac

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"

# Manifest guest restart_limit (port/stm32h563/manifest.json domain id 1).
RESTART_LIMIT=3

# The container runs as root while a host clone is owned by the login user;
# without this git rejects every submodule with "dubious ownership".
git config --global --add safe.directory '*'
git config --global --add safe.directory "$repo"

# --- Workflow env (wolfboot-wolftrust-m33mu job). Keep in sync with the yml. ---
# Crypto engine under test: hsm (wolfHSM server) or native (direct wolfCrypt).
# Flows into the secure image build and both guest builds.
. "$repo/tests/target/lib/engine.sh"
export CROSS_COMPILE=/usr/local/bin/arm-none-eabi-
export ZEPHYR_TOOLCHAIN_VARIANT=cross-compile
export WT_SECURE_FLASH_BASE=0x0C060000
export WT_SECURE_FLASH_SIZE=0x00040000
export WOLFBOOT_PARTITION_SIZE=0x40000
export WOLFBOOT_PARTITION_SWAP_ADDRESS=0x0C140000
export WT_SECURE_IMAGE_HEADER_SIZE=0x400
export WT_GUEST0_FLASH_BASE=0x080A0000
# The dev_apis crypto image (~200K) outgrew guest0's 128K window: guest0 is
# 256K (0xA0000-0xE0000) and guest1 keeps 128K at 0xE0000, ending exactly at
# the bank-1/bank-2 watermark boundary (0x08100000).
export WT_GUEST1_FLASH_BASE=0x080E0000
export WT_GUEST0_FLASH_SIZE=0x00040000
export WT_GUEST_RAM_SIZE=0x00010000
export WT_GUEST1_RAM_BASE=0x20010000
export WT_ZEPHYR_DTC_OVERLAY_FILE=boards/wolfboot-stm32h563.overlay
export WT_MAX_GUESTS=2
export ZEPHYR_BOARD=nucleo_h563zi/stm32h563xx/ns
WOLFBOOT_REF=d85fa9dbdf6c36f47b7e96eba5c9df750ad3c963
M33MU_REF=f3c03675260264cdec815adebe4b020bb6fe57b8

# --- Build the pinned M33MU emulator. Reuse a caller-supplied or already-built
#     binary so back-to-back scenarios in one container share the build (and a
#     fresh clone never lands in a non-empty /tmp/m33mu_src). ---
if [ -n "${M33MU:-}" ] && [ -x "${M33MU:-}" ]; then
  echo "Using prebuilt M33MU: $M33MU"
elif [ -x /tmp/m33mu_src/build/m33mu ]; then
  M33MU=/tmp/m33mu_src/build/m33mu
  echo "Reusing M33MU from a prior scenario: $M33MU"
else
  rm -rf /tmp/m33mu_src
  git clone --no-checkout https://github.com/danielinux/m33mu.git /tmp/m33mu_src
  cd /tmp/m33mu_src
  git fetch --depth 1 origin "$M33MU_REF"
  git checkout --detach "$M33MU_REF"
  cmake -S . -B build -DM33MU_ENABLE_WOLFSSL=OFF
  cmake --build build --target m33mu -j"$(nproc)"
  M33MU=/tmp/m33mu_src/build/m33mu
  cd "$repo"
fi

# --- wolfTrust dependencies + a clean secure build (drop any stale build/
#     whose generated wolfhsm_cfg.h bakes in a host-absolute path). The guest
#     CMake cache must go too: scenarios configure guest0_psa with different
#     -D sets and CMake refuses to regenerate over a conflicting cache. ---
git submodule update --init --single-branch
rm -rf build tests/firmware/zephyr-stm32h5/build

# --- Secure-app wolfBoot first stage. ---
rm -rf wolfBoot
git clone --no-checkout https://github.com/aidangarske/wolfBoot.git wolfBoot
cd wolfBoot
git -c protocol.version=2 fetch --depth 1 origin "$WOLFBOOT_REF"
git checkout --detach "$WOLFBOOT_REF"
git submodule update --init --single-branch
cp "$repo/wolfBoot/config/examples/stm32h5-tz-wolftrust.config" .config
# Build keytools serially first: a parallel keytools link races on the shared
# sp_* objects and intermittently fails "undefined reference".
make keytools
# Force -j1 for wolfboot.bin: wolfBoot FORCE-regenerates include/target.h in
# place and its objects don't depend on it, so any -j (including a jobserver
# inherited from `make test-target`) reads it half-written.
make -j1 wolfboot.bin wolfboot_signing_private_key.der
cd "$repo"

# --- Relocated wolfTrust secure runtime, signed for the reserved slot. The
#     Secure-image probe flags come from the shared per-scenario table; the
#     probe must land in this FIRST secure build, whose pre-patch stash below
#     is what gets signed and flashed. ---
# shellcheck source=lib/scenario.sh disable=SC1091
. "$repo/tests/target/lib/scenario.sh"
secure_flags="$(scenario_secure_flags "$scenario")"
# shellcheck disable=SC2086
env $secure_flags make build/wolftrust.bin build/secure_cmse_implib.o
# Stash the pre-patch image and matching elf: the guest build below can relink
# build/wolftrust.elf (poisoning post-mortem symbolization), and signing now
# happens only after the guest digests are stamped into the measurement slot
# (patch-then-sign, WT-FFM-0049), which needs the final guest binaries.
cp "$repo/build/wolftrust.bin" "$repo/build/wolftrust-unsigned.bin"
cp "$repo/build/wolftrust.elf" "$repo/build/wolftrust-signed.elf"

# --- Guests. The restart scenario injects a Non-secure fault probe in the PSA
#     guest; the others build it unmodified. ---
guest_flags=""
if [ "$scenario" = "restart" ]; then
  guest_flags="WT_GUEST_FAULT_PROBE=1"
elif [ "$scenario" = "confboot" ]; then
  guest_flags="WT_RUN_CONFORMANCE=1"
elif [ "$scenario" = "devstorage" ]; then
  guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=storage"
elif [ "$scenario" = "devcrypto" ] || [ "$scenario" = "vaultrecover" ] || \
     [ "$scenario" = "vaultrecoversec" ]; then
  guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=crypto"
elif [ "$scenario" = "devattest" ]; then
  guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation"
elif [ "$scenario" = "devattestqcbor" ]; then
  tests/upstream/fetch_qcbor.sh >/dev/null
  guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation WT_ATTEST_CBOR=qcbor"
elif [ "$scenario" = "attestneg" ]; then
  guest_flags="WT_ATTEST_NEG_PROBE=1"
elif [ "$scenario" = "hsmattackneg" ]; then
  guest_flags="WT_HSM_ATTACK_PROBE=1"
elif [ "$scenario" = "fwustage" ]; then
  guest_flags="WT_FWU_PROBE=1"
elif [ "$scenario" = "gtzcneg" ]; then
  guest_flags="WT_MPU_BYPASS_PROBE=1"
elif [ "$scenario" = "periphneg" ]; then
  guest_flags="WT_PERIPH_NEG_PROBE=1"
fi

# Guest images per scenario: the vnet scenario swaps the Zephyr/FreeRTOS pair
# for the bare-metal wolfIP guests, relinked into the standard NS windows.
g0_img="$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
g1_img="$repo/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"
if [ "$scenario" = "vnet" ] || [ "$scenario" = "vnetneg" ]; then
  rm -rf tests/firmware/stm32h563-vnet/build
  make -C tests/firmware/stm32h563-vnet build/guest0.bin build/guest1.bin \
    WT_GUEST0_FLASH_ORIGIN=0x080A0000 WT_GUEST1_FLASH_ORIGIN=0x080E0000 \
    WT_GUEST0_RAM_BASE=0x20000000 WT_GUEST1_RAM_BASE=0x20010000 \
    WT_GUEST_RAM_SIZE=0x00010000 \
    GUEST_EXTRA_CFLAGS="-DWT_VNET_EXIT_BKPT=1"
  g0_img="$repo/tests/firmware/stm32h563-vnet/build/guest0.bin"
  g1_img="$repo/tests/firmware/stm32h563-vnet/build/guest1.bin"
else
make -C tests/firmware/zephyr-stm32h5 clone
env $guest_flags $secure_flags WT_REUSE_SECURE_BUILD=1 WT_EXPECTED_LIFECYCLE=0x1000u \
  WT_ATTESTATION_DEVELOPMENT_PROFILE=1 WT_M33MU_EXPECT_BKPT=1 \
  make -C tests/firmware/zephyr-stm32h5 build-guest0-psa build-freertos-guest1
fi

echo "Guest vector tables (SP, reset PC):"
od -An -tx4 -N8 "$g0_img"
od -An -tx4 -N8 "$g1_img"

# --- Pin the guest measurements into the secure image, then sign: the wolfBoot
#     signature covers the pins, extending the chain of trust to the guests.
#     The harness (not the guest) holds the expected wolfBoot measurement and
#     asserts the token's reported value below. ---
cp "$repo/build/wolftrust-unsigned.bin" "$repo/build/wolftrust.bin"
python3 tools/measure/patch_guest_digests.py "$repo/build/wolftrust.bin" \
  "0:${WT_GUEST0_VERSION:-1}:$g0_img" \
  "1:${WT_GUEST1_VERSION:-1}:$g1_img"
IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x2000 \
  "$repo/wolfBoot/tools/keytools/sign" --ecc256 \
    "$repo/build/wolftrust.bin" \
    "$repo/wolfBoot/wolfboot_signing_private_key.der" 1
test -s "$repo/build/wolftrust_v1_signed.bin"
WT_EXPECTED_MEASUREMENT_HEX="$(python3 tests/scripts/read_wolfboot_measurement.py \
  build/wolftrust_v1_signed.bin)"

# bootupdate: sign the SAME patched image again at version 2. The version lives
# inside the hashed wolfBoot header, so v2 carries both a higher version and a
# different measurement — it is the candidate wolfBoot swaps into the boot slot
# on the armed reboot, and its measurement is what the post-swap token must show.
WT_V2_MEASUREMENT_HEX=""
update_img=""
if [ "$scenario" = "bootupdate" ]; then
  IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x2000 \
    "$repo/wolfBoot/tools/keytools/sign" --ecc256 \
      "$repo/build/wolftrust.bin" \
      "$repo/wolfBoot/wolfboot_signing_private_key.der" 2
  test -s "$repo/build/wolftrust_v2_signed.bin"
  WT_V2_MEASUREMENT_HEX="$(python3 tests/scripts/read_wolfboot_measurement.py \
    build/wolftrust_v2_signed.bin)"
  update_img="$repo/build/wolftrust_v2_signed.bin:0x100000"
fi

if [ "$scenario" = "authneg" ]; then
  # Corrupt one byte of the flashed guest0 image AFTER its digest was pinned
  # and signed: launch verification must fail closed for guest0 while guest1
  # and the platform keep running.
  python3 - "$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin" <<'PYEOF'
import sys
with open(sys.argv[1], "r+b") as f:
    f.seek(0x400)
    byte = f.read(1)
    f.seek(0x400)
    f.write(bytes([byte[0] ^ 0x01]))
PYEOF
fi

# --- Boot. The restart scenario must NOT pass --quit-on-faults: its guest fault
#     is handled by the monitor, which restarts the guest; halting on the fault
#     would defeat the count. The others halt on any unexpected fault. ---
quit_flag="--quit-on-faults"
expect_bkpt=0x7f
timeout_s=60
if [ "$scenario" = "vnet" ] || [ "$scenario" = "vnetneg" ]; then
  # wolfIP's initial ARP delay uses guest time, which can take longer than
  # 60 wall-clock seconds to advance on a shared CI runner.
  timeout_s=180
fi
if [ "$scenario" = "restart" ]; then
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "hsmfaultneg" ]; then
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "spbudgetneg" ]; then
  # The relay faults on every entry until its budget is exhausted; the run
  # ends on the fail-closed platform recovery marker, never a clean exit.
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "gtzcneg" ]; then
  # The peer-write probe faults the initiating guest on purpose; the run ends
  # on timeout with guest1's heartbeats as the containment evidence (like
  # authneg), or on the clean BKPT when the store is silently discarded.
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "fpneg" ]; then
  # The partition's FP instruction faults on purpose; do not quit on the fault.
  # M33MU ends the run itself when it raises NOCP, so nothing after the fault
  # executes here.
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "sealhaltneg" ]; then
  # The run must end on the seal-check halt, never at the success BKPT.
  expect_bkpt=0x6e
  timeout_s=40
elif [ "$scenario" = "sealbootneg" ]; then
  # The reset path refuses the damaged main-stack seal before any partition.
  expect_bkpt=0x7e
  timeout_s=40
elif [ "$scenario" = "mspovfneg" ]; then
  # The reset path overflows the main stack on purpose. M33MU escalates the
  # entry-time STKOF to HardFault and ends the run there, so the production
  # halt (BKPT 0x7E) is never reached on the emulator; see the H5 run.
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "xnneg" ]; then
  # The privileged gate executes from SPM RAM on purpose. M33MU pends the
  # synchronous fault instead of escalating it past the active SVC, so the
  # production halt (BKPT 0x7E) is proven on the H5; the emulator proves the
  # denied fetch. Do not quit on the fault.
  quit_flag=""
  timeout_s=40
elif [ "$scenario" = "spfaultneg" ] || [ "$scenario" = "panicneg" ] ||
     [ "$scenario" = "vnetneg" ] || [ "$scenario" = "sealneg" ] ||
     [ "$scenario" = "sealpivotneg" ] || [ "$scenario" = "svcneg" ] ||
     [ "$scenario" = "busfaultneg" ] || [ "$family" = "bandneg" ] ||
     [ "$family" = "restartneg" ]; then
  # The SP faults on purpose; wolfTrust catches the fault and restarts
  # the partition in place, so halting on the fault would defeat the
  # recovery. The rest of the lifecycle then completes normally through the
  # clean BKPT exit — the restarted SP serves the later requests.
  quit_flag=""
elif [ "$scenario" = "revneg" ]; then
  # Production image on revision Z silicon (ES0565 2.2.9): the emulator
  # reports the refused IDCODE through the real DBGMCU read.
  if ! grep -aq M33MU_STM32H5_IDCODE "$M33MU"; then
    echo "FAIL: $M33MU lacks M33MU_STM32H5_IDCODE; rebuild M33MU at $M33MU_REF or later" >&2
    exit 1
  fi
  export M33MU_STM32H5_IDCODE=0x10016484
elif [ "$scenario" = "authneg" ]; then
  # Guest0 is refused at launch so the BKPT scenario end never fires; the run
  # ends on timeout with guest1's heartbeats as the survival evidence.
  timeout_s=40
elif [ "$scenario" = "confboot" ]; then
  # Panic-test resets reboot the whole chain mid-suite: the must-panic checks,
  # i048/i049's by-design NS client faults (Secure iovec array pointer), the
  # SPE-caller variants of i048-i053 (out-of-domain vectors panic a Secure
  # caller), and the i002/i004-i012 connection/handle-misuse panics. The
  # emulator must not quit on faults — the conformance monitor answers them
  # with a system reset and val resumes off its boot flag; the suite report
  # and clean BKPT exit are the correctness gates.
  quit_flag=""
  timeout_s=1200
elif [ "$scenario" = "devstorage" ]; then
  # No panic tests in dev_apis storage, but keep faults non-fatal so any
  # val-internal reset does not abort; TOTAL FAILED and the BKPT exit gate.
  quit_flag=""
  timeout_s=600
elif [ "$scenario" = "devcrypto" ]; then
  # 78 tests with real ECC/AES math under emulation run at roughly a minute
  # per test; same non-fatal-fault policy as devstorage.
  quit_flag=""
  timeout_s=7200
elif [ "$scenario" = "bootupdate" ]; then
  # Two boots in one run: v1 arms the update trigger and reboots, then wolfBoot
  # swaps in v2, which runs the full lifecycle to the clean BKPT. The
  # SYSRESETREQ reboot is not a fault, so keep --quit-on-faults; give both
  # boots room.
  timeout_s=150
fi

log="$repo/ci-m33mu-$scenario.log"
set +e
"$M33MU" "$repo/wolfBoot/wolfboot.bin" \
  "$repo/build/wolftrust_v1_signed.bin:0x60000" \
  "$g0_img:0xA0000" \
  "$g1_img:0xE0000" \
  ${update_img:+"$update_img"} \
  --uart-stdout --expect-bkpt $expect_bkpt $quit_flag --timeout "$timeout_s" | tee "$log"
emu_status=${PIPESTATUS[0]}
set -e
echo "wolfBoot/wolfTrust M33MU exit status: $emu_status"

# Preserve raw evidence for guest1 and fault checks. Rejoin guest0 lines only
# across complete, recognized console interjections; retain normal newlines.
guest0_log="$repo/ci-m33mu-$scenario-guest0.log"
python3 "$repo/tests/target/lib/m33mu_console.py" "$log" > "$guest0_log"

# Per-assertion reporting so make test-target surfaces what each scenario
# actually checks, not just a single PASS. The Makefile greps these tagged
# lines out of the log; the full boot log stays underneath.
check_pass() { printf '  [check] PASS  %s\n' "$1"; }
check_fail() { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }
expect()     { if grep -Fq "$2" "$log"; then check_pass "$1"; \
               else check_fail "$1" "missing: $2"; fi; }
# Shared-UART tolerant match against the same guest0 view used by CI.
expect_flat() { if grep -Fq "$2" "$guest0_log"; then check_pass "$1"; \
                else check_fail "$1" "missing: $2"; fi; }
refute_re()  { if grep -Eq "$2" "$log"; then check_fail "$1" "unexpected: $2"; \
               else check_pass "$1"; fi; }

case "$scenario" in
  positive|deputyneg|hsmpinneg|periphneg|bandneg[1-6]|restartneg[1-3])
    if [ "$scenario" = "periphneg" ]; then
      # WT-FFM-0068: the guest reads and clears the SPM's RNG through its
      # Non-secure alias, proves an NS-to-NS GPDMA copy works, then needs a
      # transfer error with nothing landed for copies out of the Secure image
      # and Secure SRAM; Secure entropy must still work.
      refute_re "Secure peripheral and memory stay out of NS reach" \
        'wolfTrust periph probe (LEAKED|INCONCLUSIVE)'
      expect "NS RNG poke and NS DMA copies blocked" \
        "wolfTrust periph probe blocked"
    fi
    if [ "$family" = "restartneg" ]; then
      # The partition plants state in its own band and faults once (udf #0).
      # Its restarted instance traps again (udf #2) if the band did not
      # return to its link-time image, so exactly one fault must be seen.
      restart_faults=$(grep -cE '^\[USGFLT\] CFSR=0x00010000' "$log" || true)
      if [ "$restart_faults" -eq 1 ]; then
        check_pass "partition faulted once and restarted on a reset band"
      else
        check_fail "band reset on restart" \
          "expected 1 UNDEFINSTR UsageFault, saw $restart_faults"
      fi
      refute_re "the fault was the planted one" \
        '^\[USGFLT\] mem16\[[^]]*\]=0xde02'
      refute_re "fault was contained, not escalated" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    fi
    if [ "$family" = "bandneg" ]; then
      # The prober reads the other partition's band, is restarted, writes it,
      # and is restarted again: both accesses must MemManage-fault on the
      # prober's own stack, and neither may run on to the trap behind it.
      case "$band_probe" in
        1) band_addr=0x30075000; band_sp='0x3009[67]'
           band_what="crypto partition denied the vault's band" ;;
        2) band_addr=0x30077000; band_sp='0x3009[67]'
           band_what="crypto partition denied the attestation band" ;;
        3) band_addr=0x30075000; band_sp='0x3009[89]'
           band_what="attestation partition denied the vault's band" ;;
        4) band_addr=0x30077800; band_sp='0x3009[89]'
           band_what="attestation partition denied the crypto band" ;;
        5) band_addr=0x30077000; band_sp='0x300(8f|9[0-2])'
           band_what="vault denied the attestation band" ;;
        6) band_addr=0x30077800; band_sp='0x300(8f|9[0-2])'
           band_what="vault denied the crypto band" ;;
      esac
      band_faults=$(grep -cE "^\[MEMFAULT\].*addr=$band_addr" "$log" || true)
      if [ "$band_faults" -eq 2 ]; then
        check_pass "$band_what, read then write (2 MEMFAULTs at $band_addr)"
      else
        check_fail "$band_what" \
          "expected 2 MEMFAULTs at $band_addr, saw $band_faults"
      fi
      band_stacks=$(grep -cE "^\[MEMFAULT\] sp=$band_sp" "$log" || true)
      if [ "$band_stacks" -eq 2 ]; then
        check_pass "both faults taken on the prober's own stack"
      else
        check_fail "fault attribution" \
          "expected 2 faults on a stack matching $band_sp, saw $band_stacks"
      fi
      refute_re "no access ran past its fault, no keystore pin was open" \
        '^\[USGFLT\]'
      refute_re "faults were contained, not escalated" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
    fi
    if [ "$scenario" = "deputyneg" ]; then
      # The probe is called unconditionally at vault entry and faults the
      # partition on any leak, so a clean positive lifecycle only proves the
      # fix if the probe was actually linked in. Guard against a vacuous pass
      # from the probe being compiled out (WT_DEPUTY_NEG_PROBE not threaded).
      # Dump symbols to a file and grep the file: piping nm into `grep -q`
      # would trip pipefail when grep closes the pipe early and nm gets SIGPIPE.
      deputy_syms="$repo/build/deputy-syms.txt"
      "${CROSS_COMPILE}nm" "$repo/build/wolftrust-signed.elf" > "$deputy_syms"
      if grep -q ' wt_platform_deputy_flash_probe$' "$deputy_syms"; then
        check_pass "deputy probe linked into the secure image"
      else
        check_fail "deputy probe presence" \
          "wt_platform_deputy_flash_probe not in the secure image"
      fi
    fi
    if [ "$scenario" = "hsmpinneg" ]; then
      # Every relay pump forges the server pointers to an SPM-private address
      # right before the pin, so the guest crypto/attestation markers below can
      # only appear if the unprivileged relay re-pinned them before dereference;
      # a neutered pin faults instead. Guard against a vacuous pass with the
      # probe compiled out; grep a symbol file, not a pipe, to stay pipefail-safe.
      tasklet_syms="$repo/build/hsmpinneg-syms.txt"
      "${CROSS_COMPILE}nm" "$repo/build/wolftrust-signed.elf" > "$tasklet_syms"
      if grep -q ' wt_platform_hsm_pin_probe$' "$tasklet_syms"; then
        check_pass "HSM server pointer pin probe linked into the secure image"
      else
        check_fail "HSM server pointer pin probe presence" \
          "wt_platform_hsm_pin_probe not in the secure image"
      fi
    fi
    if [ "$family" != "bandneg" ] && [ "$family" != "restartneg" ]; then
      refute_re "no fault markers in boot log" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    fi
    expect_flat "TEE client initialized" "wolfTrust TEE client initialized"
    expect_flat "FF-M psa_framework_version=0x0100" \
      "wolfTrust FF-M psa_framework_version=0x0100"
    expect_flat "mediated crypto dispatch verified" \
      "wolfTrust FF-M mediated crypto dispatch verified"
    expect_flat "ITS set/get verified" \
      "wolfTrust ITS set/get verified"
    expect_flat "PS sealed set/get verified" \
      "wolfTrust PS sealed set/get verified"
    expect_flat "key-ops sign/verify verified" \
      "wolfTrust key-ops sign/verify verified"
    expect_flat "key negatives verified" \
      "wolfTrust key negatives verified"
    expect_flat "forged-handle call rejected" \
      "wolfTrust FF-M forged-handle call rejected"
    expect_flat "oversized-vector call rejected" \
      "wolfTrust FF-M oversized-vector call rejected"
    expect_flat "psa_hash_compute(SHA-256) KAT verified" \
      "psa_hash_compute(SHA-256) KAT verified"
    expect_flat "psa_initial_attestation st=0" "psa_initial_attestation st=0"
    expect_flat "attestation COSE_Sign1 verified" \
      "wolfTrust attestation: COSE_Sign1 verified"
    expect_flat "token measurement equals wolfBoot measurement of the signed image" \
      "wolfTrust attestation: token measurement=$WT_EXPECTED_MEASUREMENT_HEX"
    expect_flat "attestation fields verify=0 lifecycle=0x1000 measurement=ok cose=ES256" \
      "attestation verify=0 challenge=ok identity=ok lifecycle=0x1000 measurement=ok cose=ES256"
    expect "guest1 FF-M SHA-256 KAT through SERVICE_CRYPTO (P7-S3)" \
      "freertos_guest1: ffm sha256 ok"
    expect "guest1 vault-backed RNG through the SPM (WT-FFM-0054)" \
      "freertos_guest1: ffm rng ok"
    expect "guest1 wolfPSA front-end initialized" \
      "freertos_guest1: psa_crypto_init st=0"
    expect "guest1 psa_generate_random seeded through the FF-M RNG hook" \
      "freertos_guest1: psa rng ok"
    expect "guest1 psa_hash_compute KAT (PSA API parity)" \
      "freertos_guest1: psa hash ok"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/$scenario"
    ;;
  bothpsa)
    # Both-OS PSA parity gate: the SAME PSA client behavior from BOTH the
    # Zephyr guest (guest0) and the FreeRTOS guest (guest1) in one boot. Three
    # operations must pass identically from each OS: the mediated SERVICE_CRYPTO
    # SHA-256 KAT (both reach the same Secure Partition with the same input and
    # get the KAT digest), PSA RNG, and the PSA Crypto API SHA-256 KAT. guest0
    # markers can be spliced by guest1's console (expect_flat); guest1's own
    # markers are matched raw.
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect_flat "Zephyr: mediated SERVICE_CRYPTO SHA-256 KAT" \
      "wolfTrust FF-M mediated crypto dispatch verified"
    expect "FreeRTOS: mediated SERVICE_CRYPTO SHA-256 KAT" \
      "freertos_guest1: ffm sha256 ok"
    expect_flat "Zephyr: PSA psa_generate_random" \
      "psa_generate_random st=0"
    expect "FreeRTOS: PSA psa_generate_random" \
      "freertos_guest1: psa rng ok"
    expect_flat "Zephyr: PSA psa_hash_compute(SHA-256) KAT" \
      "psa_hash_compute(SHA-256) KAT verified"
    expect "FreeRTOS: PSA psa_hash_compute(SHA-256) KAT" \
      "freertos_guest1: psa hash ok"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/bothpsa"
    ;;
  bothiso)
    # Both-OS isolation gate: the SPM rejects a forged handle and an oversized
    # input vector from BOTH the Zephyr client (guest0) and the FreeRTOS client
    # (guest1), refuses a connect to an unknown SID, and neither guest faults
    # the platform. Isolation holds regardless of the non-secure operating
    # system. guest0 markers can be spliced by guest1's console (expect_flat);
    # guest1's own markers are matched raw.
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect_flat "Zephyr: forged-handle call rejected" \
      "wolfTrust FF-M forged-handle call rejected"
    expect_flat "Zephyr: oversized-vector call rejected" \
      "wolfTrust FF-M oversized-vector call rejected"
    expect "FreeRTOS: forged-handle call rejected" \
      "freertos_guest1: ffm forged-handle rejected"
    expect "FreeRTOS: oversized-vector call rejected" \
      "freertos_guest1: ffm oversized-vector rejected"
    expect "FreeRTOS: cross-guest vector refused (caller-banded memcheck)" \
      "freertos_guest1: ffm cross-guest vector rejected"
    expect "FreeRTOS: unknown-SID connect refused" \
      "freertos_guest1: ffm wrong-sid refused"
    expect "FreeRTOS survived: still serves mediated SERVICE_CRYPTO" \
      "freertos_guest1: ffm sha256 ok"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/bothiso"
    ;;
  rollbackneg)
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect "downgraded boot refused fail-closed (all guests quarantined)" \
      "[BKPT] imm=0x7d"
    refute_re "no guest entered a domain after the floor armed" \
      'guest0_psa alive'
    echo "PASS: target/rollbackneg"
    ;;
  authneg)
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    refute_re "tampered guest0 never entered its domain" \
      'guest0_psa alive'
    expect "guest1 (unrelated domain) still runs" \
      "freertos_guest1: heartbeat"
    expect "guest1 mediated SERVICE_CRYPTO still live" \
      "freertos_guest1: ffm sha256 ok"
    echo "PASS: target/authneg"
    ;;
  confboot)
    # The conformance guest is lean (no deep-stack attestation path) so the val
    # NSPE framework fits guest0's 32 KiB NS window; the full lifecycle is the
    # positive scenario's job. This proves the Arm SPs schedule and val runs.
    # No fault-marker check here: i048/i049 fault the NS client by design and
    # the monitor's conformance reset recovers; the suite's own FAILED count
    # and the clean BKPT exit gate correctness instead.
    expect "TEE client initialized" "wolfTrust TEE client initialized"
    expect "FF-M psa_framework_version=0x0100" \
      "wolfTrust FF-M psa_framework_version=0x0100"
    expect "mediated crypto dispatch verified" \
      "wolfTrust FF-M mediated crypto dispatch verified"
    expect "conformance val_entry start" \
      "wolfTrust FF-M conformance: val_entry start"
    # Panic tests reboot the chain mid-suite and val resumes off its
    # flash-backed boot flag (K2/K3): buffer/eoi panics (i047/i055/i057/
    # i064-i066), NS client faults the conformance monitor answers with a
    # system reset (i048/i049), SPE out-of-domain vector panics (i048-i053),
    # the i002/i004-i012 connection/handle-misuse panics, the
    # i024-i027+i054 psa_call handle/iovec/outvec panics, and the
    # i013-i023 server-misuse panics, and the i028-i046 message-access
    # misuse panics. i021 and i066
    # exercise the real LPUART1 NVIC route (P4.2c); i068-i087 exercise the
    # SAU/MPU isolation probes. 89 total: 85 pass, and the 4 heap tests
    # (i074, i078, i082, i086) report SKIPPED because the zero-allocation
    # image has no Secure Partition heap (SP_HEAP_MEM_SUPP undefined). Needs
    # the M33MU-1 SPSEL patch applied above.
    expect_flat "Arm suite TOTAL PASSED : 85" "TOTAL PASSED    : 85"
    expect_flat "Arm suite TOTAL SKIPPED : 4" "TOTAL SKIPPED   : 4"
    expect_flat "Arm suite TOTAL FAILED : 0" "TOTAL FAILED    : 0"
    # The totals alone would hide a pass and a skip trading places: hold the
    # run to the recorded per-test results for the pinned suite revision.
    conf_want="$repo/tests/target/ffm_ipc_results.txt"
    conf_rev="$(cat "$repo/tests/upstream/psa-arch-tests.rev")"
    if grep -Fq "$conf_rev" "$conf_want"; then
      check_pass "results recorded for psa-arch-tests $conf_rev"
    else
      check_fail "conformance evidence" \
        "$conf_want was not recorded for psa-arch-tests $conf_rev"
    fi
    conf_got="$repo/build/ffm-ipc-results.txt"
    grep -aoE 'Num=[0-9]+|Result=[A-Za-z]+' "$guest0_log" | \
      awk -F= '$1 == "Num" { num = $2 }
               $1 == "Result" { if (num != "") print num, $2; num = "" }' | \
      sort -n -u > "$conf_got"
    if grep -v '^#' "$conf_want" | grep -v '^$' | \
        diff - "$conf_got" > "$repo/build/ffm-ipc-results.diff"; then
      check_pass "every test matches its recorded result (89 tests)"
    else
      check_fail "per-test conformance results" \
        "$(tr '\n' ' ' < "$repo/build/ffm-ipc-results.diff")"
    fi
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/confboot"
    ;;
  devstorage)
    expect "TEE client initialized" "wolfTrust TEE client initialized"
    expect "conformance val_entry start" \
      "wolfTrust FF-M conformance: val_entry start"
    # Read suite totals from the reconstructed guest0 console: every storage
    # test must pass or skip, none FAIL.
    flat="$(cat "$guest0_log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
    if [ "$failed" = "0" ] && [ "$((passed + skipped))" -eq 17 ]; then
      check_pass "dev_apis storage: ${passed} passed, ${skipped} skipped, 0 failed (17 total)"
    else
      check_fail "dev_apis storage suite" \
        "passed=$passed skipped=$skipped failed=$failed (want failed=0, passed+skipped=17)"
    fi
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/devstorage"
    ;;
  devcrypto)
    expect "TEE client initialized" "wolfTrust TEE client initialized"
    expect "conformance val_entry start" \
      "wolfTrust FF-M conformance: val_entry start"
    flat="$(cat "$guest0_log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
    # c047 (Num 247) is dropped from the schedule by the crypto sched db (see
    # mk/common.mk): HMAC-key-with-CMAC-alg negative case, but
    # CMAC is compiled out so wolfPSA returns spec-permitted NOT_SUPPORTED, not
    # the test's assumed INVALID_ARGUMENT. Every scheduled test must pass or skip.
    if [ "$failed" -eq 0 ] && [ "$((passed + skipped))" -eq 77 ]; then
      check_pass "dev_apis crypto: ${passed} passed, ${skipped} skipped, 0 failed (77 scheduled; c047 CMAC config-skipped)"
    else
      check_fail "dev_apis crypto suite" \
        "passed=$passed skipped=$skipped failed=$failed (want failed=0, passed+skipped=77)"
    fi
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/devcrypto"
    ;;
  devattest|devattestqcbor)
    expect "TEE client initialized" "wolfTrust TEE client initialized"
    expect "conformance val_entry start" \
      "wolfTrust FF-M conformance: val_entry start"
    # test_a001 is the whole suite: get_token/get_token_size across all
    # challenge sizes plus val's own COSE_Sign1 verify of the returned token.
    flat="$(cat "$guest0_log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${failed:=-1}"
    if [ "$failed" = "0" ] && [ "$passed" -eq 1 ]; then
      check_pass "dev_apis initial_attestation: 1 passed, 0 failed"
    else
      check_fail "dev_apis initial_attestation suite" \
        "passed=$passed failed=$failed (want passed=1 failed=0)"
    fi
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/$scenario"
    ;;
  attestneg)
    # Production image + guest probe: the secure side must reject invalid
    # attestation requests over IPC and tampered/misattributed tokens must
    # fail the guest verify, with the positive lifecycle still green.
    expect "psa_initial_attestation st=0" "psa_initial_attestation st=0"
    expect "attestation COSE_Sign1 verified" \
      "wolfTrust attestation: COSE_Sign1 verified"
    expect "attestneg oversized challenge rejected st=-135" \
      "attestneg oversized challenge rejected st=-135"
    expect "attestneg zero token buffer rejected st=-135" \
      "attestneg zero token buffer rejected st=-135"
    expect "attestneg tampered token rejected" \
      "attestneg tampered token rejected"
    expect "attestneg lifecycle mismatch rejected" \
      "attestneg lifecycle mismatch rejected"
    expect "attestation negatives verified" \
      "wolfTrust attestation negatives verified"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/attestneg"
    ;;
  hsmattackneg)
    # Production image + guest probe: a forged COMM_INIT
    # claiming client_id=WH_CLIENT_ID_MAX must not reach the committed IAK,
    # an NVM-group packet must never reach the server, and the guest's own
    # crypto namespace must still work.
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect "forged COMM_INIT attempted" "hsmattackneg forged COMM_INIT"
    expect "IAK sign refused" "hsmattackneg IAK sign refused"
    expect "rollback NVM group refused" "hsmattackneg rollback NVM group refused"
    expect "own-namespace crypto still works" \
      "hsmattackneg own-namespace crypto still works"
    refute_re "IAK sign never succeeded" 'hsmattackneg IAK sign SUCCEEDED'
    refute_re "NVM group never succeeded" 'hsmattackneg rollback NVM group SUCCEEDED'
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/hsmattackneg"
    ;;
  vaultrecover)
    # The foreign-pool probe forces the boot-time vault recovery. In the
    # unlocked lifecycle it self-heals (reformat + re-provision), attestation
    # comes back, and the crypto suite passes -- proving the recovery neither
    # bricked the boot nor left the vault unusable. (The reformat counter is
    # read over SWD on the H5 board; the emulator asserts the suite instead.)
    expect "conformance val_entry start" \
      "wolfTrust FF-M conformance: val_entry start"
    flat="$(cat "$guest0_log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
    if [ "$failed" -eq 0 ] && [ "$((passed + skipped))" -eq 77 ]; then
      check_pass "crypto suite green after self-heal: ${passed} passed, ${skipped} skipped, 0 failed"
    else
      check_fail "crypto after self-heal" \
        "passed=$passed skipped=$skipped failed=$failed (want failed=0, passed+skipped=77)"
    fi
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/vaultrecover"
    ;;
  vaultrecoversec)
    # Forced SECURED lifecycle: the reformat is refused, attestation fails
    # closed (unavailable by design), so the suite is not the check. The proof
    # is that the secure boot survives and the guest still starts -- graceful
    # fail-closed, never a mute brick. The vault-not-wiped guarantee is asserted
    # over SWD on the H5 board (g_vault_reformatted=0, g_wt_attest_degraded=1).
    refute_re "no fault (fail closed, not a brick)" \
      '(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect "guest starts under fail-closed attestation" \
      "wolfTrust FF-M conformance: val_entry start"
    echo "PASS: target/vaultrecoversec"
    ;;
  restart)
    expected=$((RESTART_LIMIT + 1))
    banners=$(grep -c "guest0_psa alive" "$log" || true)
    if [ "$banners" -eq "$expected" ]; then
      check_pass "guest restarted $RESTART_LIMIT times then FAULTED (banners=$banners, expect $expected)"
      echo "PASS: target/restart"
      exit 0
    fi
    check_fail "guest restart count" "saw $banners banners, expected $expected"
    ;;
  crossdomain)
    if grep -Eq '\[MEMFAULT\].*addr=0x30028000' "$log"; then
      check_pass "cross-domain read of 0x30028000 denied by SP domain (MEMFAULT)"
      echo "PASS: target/crossdomain"
      exit 0
    fi
    check_fail "cross-domain isolation" "expected MEMFAULT at 0x30028000, none seen"
    ;;
  periphspneg)
    # WT-FFM-0068: the storage SP reads the SPM's RNG registers at their Secure
    # address; no partition domain maps an unassigned peripheral, so the read
    # must MemManage-fault at exactly that address.
    if grep -Eqi '\[MEMFAULT\].*addr=0x520c0800' "$log"; then
      check_pass "SP read of the SPM's RNG at 0x520C0800 denied (MEMFAULT)"
      echo "PASS: target/periphspneg"
      exit 0
    fi
    check_fail "SP peripheral isolation" "expected MEMFAULT at 0x520C0800, none seen"
    ;;
  keystoreneg)
    # A non-keystore partition (ITS) reads the vault's data band; its manifest
    # domain grants none of the keystore data bands, so the read must
    # MemManage-fault inside the ITS domain (WT-FFM-0062).
    if grep -Eq '\[MEMFAULT\].*addr=0x30075000' "$log"; then
      check_pass "keystore data band read of 0x30075000 denied to a non-keystore SP (MEMFAULT)"
      echo "PASS: target/keystoreneg"
      exit 0
    fi
    check_fail "keystore-band isolation" "expected MEMFAULT at 0x30075000, none seen"
    ;;
  spfaultneg)
    # The SERVICE_HSM relay SP faults once on its first entry (udf #0, an
    # undefined-instruction UsageFault). wolfTrust must catch the
    # Secure-Thread UsageFault, restart the partition in place, and the
    # RESTARTED relay must then serve every mediated crypto request from both
    # OS clients with no platform reset. (The pinned-client defined-error
    # unblock is host-proven in tests/host/sp_recovery — the entry probe
    # faults before any client connects.)
    if grep -Eq '\[USGFLT\].*CFSR=0x00010000' "$log"; then
      check_pass "relay SP faulted once (Secure-Thread UNDEFINSTR UsageFault)"
    else
      check_fail "SP fault" "expected UNDEFINSTR UsageFault, none seen"
    fi
    refute_re "fault was contained, not escalated" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    expect "restarted relay serves mediated key-ops" \
      "wolfTrust key-ops sign/verify verified"
    expect "unrelated storage partitions unaffected" \
      "wolfTrust ITS set/get verified"
    expect "restarted relay serves the mediated SHA KAT" \
      "psa_hash_compute(SHA-256) KAT verified"
    expect "unrelated guest booted and ran through the SP fault" \
      "freertos_guest1: alive"
    expect "restarted relay serves the other-OS client too" \
      "freertos_guest1: ffm sha256 ok"
    expect "full lifecycle completed after recovery" "[EXPECT BKPT] Success"
    echo "PASS: target/spfaultneg"
    ;;

  hsmfaultneg)
    # A guest0 HSM tasklet fault must not turn its post-fault stack-canary
    # check into a platform panic. Guest1 must keep running.
    expect "guest0 HSM tasklet faulted" "[USGFLT]"
    refute_re "HSM fault stayed contained" '(\[HARDFLT\]|HardFault|SecureFault|\[BKPT\] imm=0x7e)'
    expect "other guest remains functional" "freertos_guest1: ffm sha256 ok"
    expect "full chain exits cleanly" "[EXPECT BKPT] Success"
    echo "PASS: target/hsmfaultneg"
    ;;

  panicneg)
    # Secure-caller misuse (FF-M PROGRAMMER ERROR, WT-FFM-0063): the ITS SP
    # closes an error-status handle on its first entry, so the production SPM
    # must panic the partition (resume PC landed on udf #0x50 -> Secure-Thread
    # UNDEFINSTR UsageFault) and unblock the pinned client with
    # PSA_ERROR_COMMUNICATION_FAILURE. guest0 runs one lifecycle per boot, so
    # its ITS connect eats the -145; the restarted-SP-serves property is
    # spfaultneg's ground. A missed panic instead executes the probe's udf #3,
    # which fails the contained-fault checks below.
    if grep -Eq '\[USGFLT\].*CFSR=0x00010000' "$log"; then
      check_pass "ITS SP panicked once (Secure-Thread UNDEFINSTR UsageFault)"
    else
      check_fail "SP panic" "expected UNDEFINSTR UsageFault, none seen"
    fi
    refute_re "panic was contained, not escalated" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    expect "pinned client unblocked with COMMUNICATION_FAILURE" \
      "psa_connect(SERVICE_ITS) failed rc=0 handle=-145"
    expect "sealed storage path unaffected" \
      "wolfTrust PS sealed set/get verified"
    expect "unrelated guest booted and ran through the panic" \
      "freertos_guest1: alive"
    expect "full lifecycle completed after recovery" "[EXPECT BKPT] Success"
    echo "PASS: target/panicneg"
    ;;

  fwustage)
    # The isolated FWU Secure Partition stages a candidate into the real
    # wolfBoot update partition flash and verifies each block by read-back;
    # a clean start/write/finish/install with no platform fault proves the
    # update service end to end on target. The wolfBoot swap of the armed
    # image rides the full boot-and-update gate (P6-S6).
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect "guest booted and reached the FWU probe" "guest0_psa alive"
    expect_flat "write before start refused on target (WT-FWU-0003)" \
      "wolfTrust FWU write-before-start refused"
    expect_flat "candidate staged to the update partition and armed (WT-FWU-0002)" \
      "wolfTrust FWU staged signed-header candidate to update partition, armed, verified"
    expect_flat "reject disarms and clean restores READY (WT-FWU-0003)" \
      "wolfTrust FWU reject disarmed and clean restored READY"
    expect_flat "unrelated storage partitions unaffected" \
      "wolfTrust ITS set/get verified"
    expect "full lifecycle completed" "[EXPECT BKPT] Success"
    echo "PASS: target/fwustage"
    ;;

  remeasureneg)
    # WT-FFM-0052: after boot init + launch verification, an on-demand
    # re-measure of guest0 passes untampered, then a post-launch in-flash
    # tamper of the guest window is caught and quarantines the domain. The
    # secure probe emits bkpt 0x6c only when the untampered pass AND the
    # tamper-quarantine both hold; the tamper write itself must not fault.
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect "on-demand re-measure passed clean then caught a post-launch tamper" \
      "[BKPT] imm=0x6c"
    echo "PASS: target/remeasureneg"
    ;;

  bootupdate)
    # Full boot-and-update gate (phases.md:126). v1 arms wolfBoot's real update
    # trigger for the pre-staged signed v2 candidate and reboots; wolfBoot swaps
    # v2 into the boot slot and boots it. Proof the SWAP happened and v2 (not
    # v1) is running: the attestation token reports v2's wolfBoot measurement,
    # never v1's, and the swapped image completes the full FF-M lifecycle clean
    # with no fault. Anti-rollback advanced the version floor v1->v2 for the
    # swap to be accepted (a downgrade is refused by the rollbackneg scenario).
    refute_re "no fault markers across the update reboot" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect_flat "swapped image runs a clean FF-M lifecycle" \
      "wolfTrust FF-M mediated crypto dispatch verified"
    expect_flat "token measurement equals the v2 (swapped-in) image measurement" \
      "wolfTrust attestation: token measurement=$WT_V2_MEASUREMENT_HEX"
    refute_re "the pre-update v1 image is no longer the one attested" \
      "token measurement=$WT_EXPECTED_MEASUREMENT_HEX"
    expect "[EXPECT BKPT] Success clean exit after the swap" "[EXPECT BKPT] Success"
    echo "PASS: target/bootupdate"
    ;;
  vnet)
    # Mediated inter-guest networking (WT-FFM-0058): both bare-metal wolfIP
    # guests come up, guest0 sends an ICMP echo to guest1 through SERVICE_VNET
    # psa_call, guest1's wolfIP auto-replies through the same mediated path,
    # and guest0 prints the reply. No raw veneer exists in this image (the
    # link-time whitelist held during the secure build above).
    refute_re "no fault markers in boot log" \
      '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
    expect "guest0 alive" "vnet-guest0: alive"
    expect "guest1 alive" "vnet-guest1: alive"
    expect "guest0 sends the first mediated ping" "ping seq=1 to 10.0.0.2"
    expect "guest0 receives guest1's mediated echo reply" \
      "ping reply from 10.0.0.2 seq=1"
    expect "[EXPECT BKPT] Success clean exit on the first reply" \
      "[EXPECT BKPT] Success"
    echo "PASS: target/vnet"
    ;;
  vnetneg)
    # Confined SERVICE_VNET isolation proof: the unprivileged partition's read
    # of SPM RAM faults, its execute from the XN data band faults, each fault
    # quarantines only the vnet partition, and after the second restart the
    # mediated guest ping still completes end to end.
    expect "SPM-RAM read denied to the confined vnet SP (MEMFAULT)" \
      "addr=0x30028000"
    expect "execute from the XN vnet data band denied" \
      "0x30070000"
    refute_re "no HardFault escalation" '(\[HARDFLT\]|HardFault)'
    expect "guest0 alive through the quarantine" "vnet-guest0: alive"
    expect "guest1 alive through the quarantine" "vnet-guest1: alive"
    expect "mediated ping still completes after both restarts" \
      "ping reply from 10.0.0.2"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    echo "PASS: target/vnetneg"
    ;;
  manifestneg|manifestneg2|manifestneg3)
    # A corrupted manifest must fail activation closed BEFORE scheduling: the
    # boot halts on the production panic (BKPT 0x7E) and neither guest ever
    # starts. A guest banner in the log means the SPM scheduled work off an
    # invalid manifest and the gate fails.
    expect "boot halted on the production manifest-validation panic" \
      "[BKPT] imm=0x7e"
    refute_re "no guest scheduled off the corrupted manifest" \
      '(guest0_psa alive|freertos_guest1:|vnet-guest)'
    check_pass "refused variant built with $(scenario_secure_flags "$scenario")"
    echo "PASS: target/$scenario"
    ;;
  sealbootneg)
    expect "boot halted on the damaged main-stack seal" "[BKPT] imm=0x7e"
    expect "the emulator stopped on that halt" "[EXPECT BKPT] Success"
    refute_re "no guest scheduled after the refused boot" \
      '(guest0_psa alive|freertos_guest1:|vnet-guest)'
    echo "PASS: target/sealbootneg"
    ;;
  revneg)
    # Engineering-sample silicon must halt in wt_platform_init with the
    # refusal line and the production panic, before any partition or guest.
    expect "revision Z refused with the ES0565 2.2.9 console line" \
      "wolfTrust: halt, STM32H563 engineering sample (ES0565 2.2.9) IDCODE 0x10016484"
    expect "boot halted on the production panic" "[BKPT] imm=0x7e"
    refute_re "no partition or guest started on refused silicon" \
      '(Booting Zephyr|guest0_psa alive|freertos_guest1:|\[BKPT\] imm=0x7f)'
    echo "PASS: target/revneg"
    ;;
  gtzcneg)
    # A privileged NS guest disables its own NS MPU and stores a sentinel
    # into the peer guest's RAM. The GTZC curtain must stop the access at
    # the fabric: the store is either silently discarded (RAZ/WI, silicon
    # TZIC behavior, so the guest reads it back absent) or it faults the
    # initiating guest, which the monitor contains so guest0 never finishes
    # its lifecycle. Either way the sentinel never reaches the peer and the
    # peer guest keeps running (WT-FFM-0011). The fault-path restart count is
    # timing-dependent (how many contained cycles fit the window), not a
    # security property, so one attempt with no completion is sufficient.
    refute_re "peer RAM never receives the sentinel" \
      'wolfTrust GTZC peer write LEAKED'
    attempts=$(grep -cF "wolfTrust GTZC bypass probe: attempting peer write" \
      "$log" || true)
    if grep -Fq "wolfTrust GTZC peer write blocked" "$log"; then
      check_pass "peer store blocked without a fault (RAZ/WI)"
    elif [ "$attempts" -ge 1 ] && ! grep -Fq "guest0_psa done" "$log"; then
      check_pass "peer store faults the initiating guest, contained ($attempts attempt(s))"
    else
      check_fail "NS MPU bypass cannot reach peer guest RAM (WT-FFM-0011)" \
        "probe never attempted the store or guest0 completed unfaulted ($attempts attempt(s))"
    fi
    expect "peer guest keeps running through the containment" \
      "freertos_guest1: heartbeat"
    echo "PASS: target/gtzcneg"
    ;;
  spbudgetneg)
    # The relay partition faults on every entry: the declared restart budget
    # is spent restarting it, then the limit-plus-one fault escalates to the
    # registered fail-closed platform recovery (WT-FFM-0017/0051) instead of
    # a silent quarantine that would run on without the mandatory service.
    expect "restart budget exhaustion escalates to platform recovery" \
      "[BKPT] imm=0x7d"
    refute_re "no clean lifecycle exit after the mandatory service died" \
      '\[BKPT\] imm=0x7f'
    echo "PASS: target/spbudgetneg"
    ;;

  fpneg)
    # Containment only: NOCP (not the fallback UNDEFINSTR) shows the FP
    # instruction hit a disabled coprocessor. M33MU ends the run on NOCP, so
    # restart and guest survival are asserted on the H5 run (docs/Testing.md).
    if grep -Eq '\[USGFLT\].*CFSR=0x00080000' "$log"; then
      check_pass "partition FP instruction took the NOCP trap (Secure FP disabled)"
    else
      check_fail "FP NOCP fault" "expected NOCP UsageFault (CFSR=0x00080000), none seen"
    fi
    refute_re "FP fault did not escalate (containment only; recovery not proven here)" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    expect "the emulator ended the run at the fault, not on the wall clock" \
      "Execution stopped"
    refute_re "run did not reach the wall-clock budget" 'wall-clock'
    printf '  [check] INFO  partition restart and guest survival are not asserted on the emulator; see the H5 fpneg run\n'
    echo "PASS: target/fpneg (containment only)"
    ;;

  sealneg)
    # Software check only: the partition that overwrote its own seal is
    # resumed on the panic trap, so it alone takes a contained UsageFault and
    # restarts; the platform must not halt (no BKPT 0x6e or 0x7e).
    if grep -Eq '\[USGFLT\].*CFSR=0x00010000' "$log" &&
       grep -Eq '\[USGFLT\] mem16\[0x[0-9a-f]+\]=0xde50' "$log"; then
      check_pass "seal violation faulted the offending partition on the panic trap"
    else
      check_fail "seal violation" "expected the panic-trap UsageFault, none seen"
    fi
    refute_re "partition fault was contained, not escalated" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    refute_re "platform did not halt on the partition's seal" \
      '\[BKPT\] imm=0x(6e|7e|7d)'
    expect "unrelated guest kept running" "freertos_guest1: alive"
    expect "run reached the clean scenario end" "[EXPECT BKPT] Success"
    echo "PASS: target/sealneg"
    ;;

  sealpivotneg)
    # The partition's blocking wait is stacked on its stack top, over the seal
    # words; the SPM must still contain the fault to that partition.
    if grep -Eq '\[USGFLT\].*CFSR=0x00010000' "$log" &&
       grep -Eq '\[USGFLT\] mem16\[0x[0-9a-f]+\]=0xde50' "$log"; then
      check_pass "seal violation faulted the offending partition on the panic trap"
    else
      check_fail "seal violation" "expected the panic-trap UsageFault, none seen"
    fi
    refute_re "partition fault was contained, not escalated" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    refute_re "platform did not halt on the partition's seal" \
      '\[BKPT\] imm=0x(6e|7e|7d)'
    expect "unrelated guest kept running" "freertos_guest1: alive"
    expect "run reached the clean scenario end" "[EXPECT BKPT] Success"
    echo "PASS: target/sealpivotneg"
    ;;
  busfaultneg)
    # The SERVICE_HSM relay SP reads an MPU-permitted window past the end of
    # physical SRAM on its first entry: a precise BusFault with BFAR that the
    # SPM attributes to the partition, which restarts in place and then
    # serves both OS clients. Needs an emulator that vectors a data BusFault
    # (the matrix row lands with that pin bump).
    if grep -Eq '\[BUSFLT\] pc=0x[0-9a-f]+ addr=0x300a0000' "$log"; then
      check_pass "relay SP took a precise BusFault at the bus-error window"
    else
      check_fail "BusFault" "expected [BUSFLT] at 0x300a0000, none seen"
    fi
    refute_re "fault was contained, not escalated" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    refute_re "platform did not halt on the partition's fault" \
      '\[BKPT\] imm=0x(6e|7e|7d)'
    expect "restarted relay serves mediated key-ops" \
      "wolfTrust key-ops sign/verify verified"
    expect "restarted relay serves the mediated SHA KAT" \
      "psa_hash_compute(SHA-256) KAT verified"
    expect "unrelated guest booted and ran through the SP fault" \
      "freertos_guest1: alive"
    expect "restarted relay serves the other-OS client too" \
      "freertos_guest1: ffm sha256 ok"
    expect "full lifecycle completed after recovery" "[EXPECT BKPT] Success"
    echo "PASS: target/busfaultneg"
    ;;
  svcneg)
    # The ITS SP issues the scheduler's internal guest-return SVC (0x7F) on
    # its first entry. A PSP-origin caller is a PROGRAMMER ERROR: the SPM
    # resumes that partition on the panic trap (udf #0x50 -> Secure-Thread
    # UNDEFINSTR UsageFault), the pinned client is unblocked with
    # COMMUNICATION_FAILURE, and the platform keeps running. A missed reject
    # would halt the platform (BKPT 0x7E) or run the probe's udf #3.
    if grep -Eq '\[USGFLT\].*CFSR=0x00010000' "$log" &&
       grep -Eq '\[USGFLT\] mem16\[0x[0-9a-f]+\]=0xde50' "$log"; then
      check_pass "ITS SP panicked once on the panic trap (Secure-Thread UNDEFINSTR)"
    else
      check_fail "SP panic" "expected the panic-trap UsageFault, none seen"
    fi
    refute_re "panic was contained, not escalated" \
      '(\[HARDFLT\]|HardFault|SecureFault)'
    refute_re "platform did not halt on the partition's SVC" \
      '\[BKPT\] imm=0x(6e|7e|7d)'
    expect "pinned client unblocked with COMMUNICATION_FAILURE" \
      "psa_connect(SERVICE_ITS) failed rc=0 handle=-145"
    expect "sealed storage path unaffected" \
      "wolfTrust PS sealed set/get verified"
    expect "unrelated guest booted and ran through the panic" \
      "freertos_guest1: alive"
    expect "full lifecycle completed after recovery" "[EXPECT BKPT] Success"
    echo "PASS: target/svcneg"
    ;;
  xnneg)
    # The privileged SVC gate, running under a partition's thread domain,
    # calls a `bx lr` thunk copied into SPM .bss. The execute-never cover of
    # SPM RAM must fault the fetch (IACCVIOL at the thunk address) and the
    # SPM-origin fault halts the platform; a thunk that returned would run
    # the probe's udf #0x52 instead, a UsageFault the checks refuse.
    if grep -Eq '\[MEMFAULT\] pc=0x30[0-9a-f]{6} addr=0x30[0-9a-f]{6}' "$log"; then
      check_pass "privileged execution from SPM RAM faulted (IACCVIOL)"
    else
      check_fail "XN" "expected an instruction-fetch MemManage in SPM RAM, none seen"
    fi
    refute_re "the thunk never returned into the gate" '\[USGFLT\]'
    refute_re "no clean lifecycle after the SPM fault" '\[BKPT\] imm=0x7f'
    printf '  [check] INFO  the production halt is not executed by the emulator (synchronous fault pended past the SVC); see the H5 xnneg run\n'
    echo "PASS: target/xnneg (fetch denial only)"
    ;;
  mspovfneg)
    # The SPM pushes on its own stack until MSPLIM_S raises STKOF (CFSR bit
    # 20, no partition frame to blame). M33MU escalates the entry-time STKOF
    # to HardFault and ends the run without executing the handler, so the
    # emulator proves the limit; the H5 run proves the latch and the halt.
    if grep -Eq '\[(USGFLT|HARDFLT)\].*CFSR=0x00[1-9a-f][0-9a-f]0000' "$log"; then
      check_pass "main-stack overflow raised STKOF against MSPLIM_S"
    else
      check_fail "STKOF" "expected a STKOF fault (CFSR bit 20), none seen"
    fi
    expect "the emulator ended the run at the SPM fault, not on the wall clock" \
      "Execution stopped"
    refute_re "run did not reach the wall-clock budget" 'wall-clock'
    refute_re "no partition or guest ran after the fault" \
      '(guest0_psa alive|freertos_guest1:|vnet-guest|\[BKPT\] imm=0x7f)'
    printf '  [check] INFO  the production halt is not executed by the emulator; see the H5 mspovfneg run\n'
    echo "PASS: target/mspovfneg"
    ;;
  sealhaltneg)
    # The dedicated BKPT 0x6e separates the seal halt from an unrelated boot
    # panic (BKPT 0x7e); the damaged partition must never have run.
    expect "damaged seal halted the platform at dispatch" "[BKPT] imm=0x6e"
    expect "the emulator stopped on that halt" "[EXPECT BKPT] Success"
    check "$([ "$emu_status" -eq 0 ]; echo $?)" \
      "emulator exited clean on the halt (status $emu_status)"
    refute_re "partition with the damaged seal was never resumed" '\[USGFLT\]'
    refute_re "run did not reach a clean success exit" '\[BKPT\] imm=0x7f'
    echo "PASS: target/sealhaltneg"
    ;;
esac
