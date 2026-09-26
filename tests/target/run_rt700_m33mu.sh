#!/usr/bin/env bash
# wolfTrust on the i.MX RT700 under the M33MU emulator (--cpu imxrt700): the
# emulator sibling of run_rt700_hardware.sh. Same chain (wolfBoot -> wolfTrust
# secure -> two baremetal guests), same scenario names, asserted from the
# emulator log instead of over SWD.
#
#   positive  wolfBoot verifies wolfTrust; both guests launch, reach the SPM
#             through the SG veneers and finish with no fault anywhere.
#   ahbscneg  positive plus the CPU isolation negative: guest0 stores into
#             guest1's RAM window, which the per-dispatch SAU window keeps
#             Secure, so the store faults. The monitor contains it, relaunches
#             guest0 through its restart budget, quarantines it, and guest1
#             keeps running.
#
# rollbackneg, remeasureneg, manifestneg, and spbudgetneg are the shared
# Secure-verdict scenarios from lib/scenario.sh: each ends on the verdict
# breakpoint its probe emits, asserted by the port-independent table.
# crossdomain and keystoreneg fault the storage SP on an out-of-domain read;
# spfaultneg and panicneg fault an SP on its first entry and prove the SPM
# restarts it in place while both guests finish. restart spends guest0's
# restart budget on a launch-time fault; authneg refuses a tampered guest0 at
# launch. guest1 runs on through all of them.
#
# bothpsa, bothiso, attestneg, hsmattackneg, and fwustage run the portable
# PSA test guest (tests/firmware/psa-guest) in both windows: the H5 guest's
# crypto, storage, key, attestation, and FF-M negative lifecycle from a guest
# with no operating system. hsmattackneg drives the raw wolfHSM client wire,
# so it exists only under WT_ENGINE=hsm.
#
# confboot, devstorage, devcrypto, devattest, devattestqcbor, vaultrecover, and
# vaultrecoversec host Arm's unmodified psa-arch-tests val NSPE in the PSA guest
# (guest0) against the conformance Secure image, the same drop-in proof the
# H5 runs; guest1 is the small bare-metal guest so the ~90 boot cycles of the
# IPC suite's panic tests stay cheap.
#
# Environment (all optional):
#   M33MU               prebuilt emulator carrying tests/target/m33mu-imxrt700.patch;
#                       otherwise M33MU_REF is built under /tmp
#   RT700_WOLFBOOT_DIR  wolfBoot tree holding wolfboot.bin, tools/keytools/sign
#                       and wolfboot_signing_private_key.der, built with
#                       tests/target/wolfboot-imxrt700-lifecycle.patch applied;
#                       otherwise WOLFBOOT_REF is built from
#                       config/examples/imx-rt700-tz.config (the MCUXpresso
#                       SDK/DFP must be reachable exactly as for any RT700
#                       wolfBoot build)
#   RT700_M33MU_TIMEOUT emulator wall-clock budget in seconds (default 60,
#                       180 for the PSA guest scenarios)
set -eu
# make test-target hands TARGET and MAKEFLAGS to every child make; wolfBoot's
# own TARGET must come from its config, so drop both before any build.
unset TARGET MAKEFLAGS MFLAGS

scenario="${1:-}"
case "$scenario" in
  positive|ahbscneg|restart|authneg|crossdomain|keystoreneg|spfaultneg|panicneg|rollbackneg|remeasureneg|manifestneg|spbudgetneg|bothpsa|bothiso|attestneg|hsmattackneg|fwustage|confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec) ;;
  *) echo "usage: $0 positive|ahbscneg|restart|authneg|crossdomain|keystoreneg|spfaultneg|panicneg|rollbackneg|remeasureneg|manifestneg|spbudgetneg|bothpsa|bothiso|attestneg|hsmattackneg|fwustage|confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec" >&2
     exit 2 ;;
esac
if [ "$scenario" = "hsmattackneg" ] && [ "${WT_ENGINE:-native}" != "hsm" ]; then
  echo "hsmattackneg drives the raw wolfHSM client wire; run it with WT_ENGINE=hsm" >&2
  exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
case "$scenario" in
  bothpsa|bothiso|attestneg|hsmattackneg|fwustage)
    guest_dir="tests/firmware/psa-guest"
    guest1_dir="$guest_dir"
    timeout_s="${RT700_M33MU_TIMEOUT:-180}" ;;
  confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
    guest_dir="tests/firmware/psa-guest"
    guest1_dir="tests/firmware/mimxrt700-baremetal"
    timeout_s="${RT700_M33MU_TIMEOUT:-900}" ;;
  *)
    guest_dir="tests/firmware/mimxrt700-baremetal"
    guest1_dir="$guest_dir"
    timeout_s="${RT700_M33MU_TIMEOUT:-60}" ;;
esac
guest_build="$repo/$guest_dir/build"
guest1_build="$repo/$guest1_dir/build"
wolfboot_dir="${RT700_WOLFBOOT_DIR:-/tmp/wolfboot_rt700}"
log="$repo/build/rt700_m33mu_$scenario.log"

WOLFBOOT_REF=e6d169c7218d82e33bd04e2c086146ed37ec0cca
M33MU_REF=9733c2bf99995f33e7b1d4aa31e2f17bfa2d13c1

# The guests' manifest restart budget (port/mimxrt700/partitions.c): ahbscneg
# relaunches guest0 this many times before quarantining it.
restart_limit=3
# Where guest0's probe stores: inside guest1's RAM window (GUEST_PROBE_ADDR in
# tests/firmware/mimxrt700-baremetal/Makefile).
probe_addr=0x20170000
# Where guest0's restart probe reads: Secure RAM (GUEST_FAULT_ADDR there).
fault_addr=0x30188000

# shellcheck source=lib/scenario.sh disable=SC1091
. "$here/lib/scenario.sh"

# Port markers the shared verdict assertions match against.
# shellcheck disable=SC2034  # matched inside lib/scenario.sh
GUEST_STARTED_RE='wolfTrust RT700 guest[01]: start'
# shellcheck disable=SC2034
GUEST_DONE_RE='wolfTrust RT700 guest[01]: FF-M connect ok, done'

# --- The pinned M33MU with the model fix this chain needs: a Secure AHBSC
#     SRAM rule keeps the SAU's NSC veneer band callable. Drop the patch once
#     M33MU_REF carries it. ---
if [ -n "${M33MU:-}" ] && [ -x "$M33MU" ]; then
  log "Using prebuilt M33MU: $M33MU"
elif [ -x /tmp/m33mu_rt700_src/build/m33mu ]; then
  M33MU=/tmp/m33mu_rt700_src/build/m33mu
  log "Reusing M33MU from a prior scenario: $M33MU"
else
  stage "build M33MU $M33MU_REF with m33mu-imxrt700.patch"
  rm -rf /tmp/m33mu_rt700_src
  git clone --no-checkout https://github.com/danielinux/m33mu.git /tmp/m33mu_rt700_src
  git -C /tmp/m33mu_rt700_src fetch --depth 1 origin "$M33MU_REF"
  git -C /tmp/m33mu_rt700_src checkout --detach "$M33MU_REF"
  git -C /tmp/m33mu_rt700_src apply "$here/m33mu-imxrt700.patch"
  cmake -S /tmp/m33mu_rt700_src -B /tmp/m33mu_rt700_src/build \
        -DM33MU_ENABLE_WOLFSSL=OFF -DM33MU_BUILD_TESTS=OFF \
        -DM33MU_ENABLE_RUST_PLUGINS=OFF
  cmake --build /tmp/m33mu_rt700_src/build --target m33mu -j"$(nproc)"
  M33MU=/tmp/m33mu_rt700_src/build/m33mu
fi

# --- Secure-app wolfBoot first stage from upstream's RT700 TrustZone config.
#     M33MU has no RT700 boot ROM or FCB and takes the reset vector from the
#     start of the NOR, so wolfBoot links at the NOR base instead of
#     0x28004000, the same override the wolfBoot emulator tests apply. ---
# The cache is keyed on the wolfBoot ref and the lifecycle patch, so a first
# stage left by an earlier checkout is rebuilt rather than reused.
wolfboot_stamp="$WOLFBOOT_REF $(cksum "$here/wolfboot-imxrt700-lifecycle.patch" | cut -d' ' -f1)"
if [ ! -s "$wolfboot_dir/wolfboot.bin" ] || \
   [ "$(cat "$wolfboot_dir/.wt_first_stage" 2>/dev/null)" != "$wolfboot_stamp" ]; then
  if [ -n "${RT700_WOLFBOOT_DIR:-}" ]; then
    fail "wolfboot.bin in RT700_WOLFBOOT_DIR=$wolfboot_dir is missing or was built from another wolfBoot ref or lifecycle patch; rebuild it there or unset it"
  fi
  stage "build wolfBoot $WOLFBOOT_REF (imx-rt700-tz, emulator link offset)"
  rm -rf "$wolfboot_dir"
  git clone --no-checkout https://github.com/wolfSSL/wolfBoot.git "$wolfboot_dir"
  git -C "$wolfboot_dir" fetch --depth 1 origin "$WOLFBOOT_REF"
  git -C "$wolfboot_dir" checkout --detach "$WOLFBOOT_REF"
  # The RT700 HAL reports no PSA lifecycle at WOLFBOOT_REF, which leaves the
  # attestation service degraded; drop the patch once wolfBoot carries it.
  git -C "$wolfboot_dir" apply "$here/wolfboot-imxrt700-lifecycle.patch"
  git -C "$wolfboot_dir" submodule update --init --single-branch --depth 1
  cp "$wolfboot_dir/config/examples/imx-rt700-tz.config" "$wolfboot_dir/.config"
  # wolfBoot locates its key tools from the shell's working directory, so
  # build from inside the tree. keygen writes src/keystore.c, which the loader
  # links, so the key comes first: wolfboot.elf lists its objects before it.
  (
    cd "$wolfboot_dir"
    make keytools
    make -j1 wolfboot_signing_private_key.der
    make -j1 ARCH_FLASH_OFFSET=0x28000000 BOOTLOADER_PARTITION_SIZE=0x40000 \
         wolfboot.bin
  )
  printf '%s\n' "$wolfboot_stamp" > "$wolfboot_dir/.wt_first_stage"
fi
[ -x "$wolfboot_dir/tools/keytools/sign" ] || fail "keytools missing in $wolfboot_dir"
[ -s "$wolfboot_dir/wolfboot_signing_private_key.der" ] || \
    fail "signing key missing in $wolfboot_dir"

# --- wolfTrust and both guests, measurements pinned, signed for the boot
#     partition: the same recipe run_rt700_hardware.sh flashes. ---
cd "$repo"
git submodule update --init --single-branch
# RT700 wolfBoot uses a 1024-byte image header, so wolfTrust links at the boot
# base + 0x400 and is signed with a matching header.
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
make -s TARGET=mimxrt700 secure-image TOOLPREFIX=arm-none-eabi-

guest_flags=""
case "$scenario" in
  ahbscneg)     guest_flags="WT_AHBSC_PROBE=1" ;;
  restart)      guest_flags="WT_GUEST_FAULT_PROBE=1" ;;
  attestneg)    guest_flags="WT_ATTEST_NEG_PROBE=1" ;;
  hsmattackneg) guest_flags="WT_HSM_ATTACK_PROBE=1" ;;
  # 0x21000 bytes of body reach sector 33 of the 64-sector update partition.
  fwustage)     guest_flags="WT_FWU_PROBE=1 WT_FWU_PROBE_STREAM_BYTES=0x21000u WT_FWU_PROBE_SEQUENTIAL=1" ;;
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
# The emulator boots with the development lifecycle the attestation token
# reports; the guest's verify pins it.
# shellcheck disable=SC2086
make -s -C "$guest_dir" TARGET=mimxrt700 WT_EXPECTED_LIFECYCLE=0x1000u $guest_flags
if [ "$guest1_dir" != "$guest_dir" ]; then
  make -s -C "$guest1_dir" clean
  make -s -C "$guest1_dir" TARGET=mimxrt700
fi

stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
python3 tools/measure/patch_guest_digests.py build/wolftrust.bin \
    "0:1:$guest_build/guest0.bin" "1:1:$guest1_build/guest1.bin"
IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x1000 \
    "$wolfboot_dir/tools/keytools/sign" --ecc256 build/wolftrust.bin \
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
boot_chain() {
    local want="$1"
    local out="$2"
    local status
    shift 2
    set +e
    "$M33MU" --cpu imxrt700 "$wolfboot_dir/wolfboot.bin" \
        build/wolftrust_v1_signed.bin:0x40000 \
        "$guest_build/guest0.bin:0x80000" \
        "$guest1_build/guest1.bin:0x100000" \
        --timeout "$timeout_s" "$@" > "$out" 2>&1
    status=$?
    set -e
    check "$([ "$status" -eq "$want" ]; echo $?)" \
        "M33MU exited with status $want (got $status)"
}

end="$(scenario_end "$scenario")"
case "$scenario" in
  confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
    # The val guest ends on its own breakpoint; the suite's panic tests reset
    # the whole chain mid-run and val resumes off its flash boot flag.
    end="bkpt:0x7f" ;;
esac
stage "boot the chain under M33MU (--cpu imxrt700, ${timeout_s}s budget)"
case "$end" in
  bkpt:*) boot_chain 0 "$log" --uart-stdout --expect-bkpt "${end#bkpt:}" ;;
  *)      boot_chain 127 "$log" --uart-stdout ;;
esac

expect "wolfBoot brought up the SoC" "wolfBoot HAL init: MIMXRT798S"
expect "wolfBoot verified the wolfTrust image signature" "Verifying signature...done"
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
            "wolfTrust RT700 $guest: start"
        expect_n "$guest reached the SPM through the SG veneers and finished" 1 \
            "wolfTrust RT700 $guest: FF-M connect ok, done"
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
        log="$repo/build/rt700_m33mu_${scenario}_trace.log"
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
          crossdomain) neg_addr=0x30188000 ;;
          keystoreneg) neg_addr=0x301d5000 ;;
        esac
        stage "boot again with the protection-unit trace, stopping at the first fault"
        log="$repo/build/rt700_m33mu_${scenario}_trace.log"
        M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
        expect "the traced run stopped at a delivered fault" "Execution stopped"
        expect_re "the fault was the SP's out-of-domain read at the band address" \
            "\[MEMFAULT_CAUSE\] sec=S type=READ addr=$neg_addr reason=mpu-ap"
    fi
    ;;
  restart)
    faults=$((restart_limit + 1))
    expect_n "guest0 relaunched through its restart budget, then quarantined" \
        "$faults" "wolfTrust RT700 guest0: start"
    refute_re "guest0 never got past its launch-time fault" \
        "wolfTrust RT700 guest0: FF-M connect ok"
    expect_n "guest1 launched once, untouched by guest0's faults" 1 \
        "wolfTrust RT700 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust RT700 guest1: FF-M connect ok, done"
    stage "boot again with the protection-unit trace, stopping at the first fault"
    log="$repo/build/rt700_m33mu_${scenario}_trace.log"
    M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
    expect "the traced run stopped at a delivered fault" "Execution stopped"
    refused="\[MEMFAULT_CAUSE\] sec=NS type=READ addr=$fault_addr reason=secure-attr"
    expect_n_re "the fault was guest0's read of Secure RAM, refused as Secure" \
        1 "$refused"
    sau_refusals="$(grep -A1 -E -- "$refused" "$log" | grep -c "src=SAU" || true)"
    check "$([ "$sau_refusals" -eq 1 ]; echo $?)" \
        "the refusal came from the SAU"
    ;;
  authneg)
    refute_re "the tampered guest0 never entered its domain" \
        "wolfTrust RT700 guest0: start"
    expect_n "guest1 launched once after guest0's refusal" 1 \
        "wolfTrust RT700 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust RT700 guest1: FF-M connect ok, done"
    expect_n "guest1 reached the storage service" 1 \
        "wolfTrust RT700 guest1: storage connect ok"
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
        # zero-allocation image, as on the H5.
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
  ahbscneg)
    faults=$((restart_limit + 1))
    expect_n "guest0 relaunched through its restart budget" \
        "$faults" "wolfTrust RT700 guest0: start"
    expect_n "every guest0 launch completed the FF-M handshake before probing" \
        "$faults" "wolfTrust RT700 guest0: FF-M connect ok, done"
    expect_n "guest1 launched once, untouched by guest0's faults" 1 \
        "wolfTrust RT700 guest1: start"
    expect_n "guest1 completed the FF-M handshake" 1 \
        "wolfTrust RT700 guest1: FF-M connect ok, done"

    # The launch count above shows every attempt faulted; why it faulted comes
    # from M33MU's protection-unit trace, which names the attribution behind a
    # fault (the fault register dumps differ between M33MU builds, the trace
    # does not). The trace runs between every console byte, so this boot leaves
    # the console off, and it stops at the first delivered fault: the emulator
    # is deterministic, so that is guest0's first store.
    stage "boot again with the protection-unit trace, stopping at the first fault"
    log="$repo/build/rt700_m33mu_${scenario}_trace.log"
    M33MU_PROT_TRACE=1 boot_chain 0 "$log" --quit-on-faults
    expect "the traced run stopped at a delivered fault" "Execution stopped"
    refused="\[MEMFAULT_CAUSE\] sec=NS type=WRITE addr=$probe_addr reason=secure-attr"
    expect_n_re "the fault was guest0's store into guest1's RAM, refused as Secure" \
        1 "$refused"
    sau_refusals="$(grep -A1 -E -- "$refused" "$log" | grep -c "src=SAU" || true)"
    check "$([ "$sau_refusals" -eq 1 ]; echo $?)" \
        "the refusal came from the SAU: the peer window was Secure at dispatch"
    ;;
esac

log "PASS: rt700-m33mu/$scenario"
