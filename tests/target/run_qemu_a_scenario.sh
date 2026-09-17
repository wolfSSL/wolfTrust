#!/usr/bin/env bash
# wolfTrust AArch64 QEMU scenario runner, the emulator twin of
# run_m33mu_scenario.sh: build the images for one machine, boot them under
# qemu-system-aarch64, and assert one scenario's markers. Run inside
# ghcr.io/wolfssl/wolfboot-ci-aarch64 (the image CI uses) or anywhere
# qemu-system-aarch64 and aarch64-none-elf-gcc are on PATH.
#
#   run_qemu_a_scenario.sh smoke   the tests/firmware/aarch64-smoke image runs
#                                  at EL3, prints on the secure console,
#                                  reports the parked secondary cores, exits
#                                  through semihosting
#   run_qemu_a_scenario.sh boot    the wolfTrust EL3 monitor (make ARCH=aarch64
#                                  TARGET=qemuvirt|versal) boots on the boot
#                                  core, prints its banner, drops into Secure
#                                  EL1, and exits through the monitor
#   run_qemu_a_scenario.sh boot-smp2  the same image with a second core: the
#                                  secondary parks at EL3 inside the timed
#                                  handshake and only the boot core runs the
#                                  monitor (virt only; see the SKIP below)
#
#   MACHINE=virt|versal-virt (default virt)   GIC=2|3 (virt, default 3)
#   CPU=cortex-a35|cortex-a72 (virt, default cortex-a72)
#   SMP=<n> (virt: default 2 for smoke, 1 for boot, fixed 2 for boot-smp2;
#            versal-virt: default 4)
#   run_qemu_a_scenario.sh positive-secure  the same image; the neutral core
#                                  boots at Secure EL1 and every Secure
#                                  Partition initializes at Secure EL0
#                                  through the SVC gate before the SPMC
#                                  idles on FFA_MSG_WAIT
#
#   QEMU_TIMEOUT=<s> (default 120)  TOOLPREFIX (default aarch64-none-elf-)
set -euo pipefail

scenario="${1:-}"
case "$scenario" in
  smoke|boot|boot-smp2|positive-secure|crossdomain|spfaultneg|tablesneg|ffa-direct|ffa-sint|ns-smoke|ffa-discovery|ffa-guest-direct|psci|ffa-preempt|positive|guest1|smcfuzz|secramneg|resetneg|ffa-memneg|confboot|storage|devstorage) ;;
  *) echo "usage: $0 smoke|boot|boot-smp2|positive-secure|crossdomain|spfaultneg|tablesneg|ffa-direct|ffa-sint|ns-smoke|ffa-discovery|ffa-guest-direct|psci|ffa-preempt|positive|guest1|smcfuzz|secramneg|resetneg|ffa-memneg|confboot|storage|devstorage" >&2; exit 2 ;;
esac

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
. "$repo/tests/target/lib/expect.sh"

MACHINE="${MACHINE:-virt}"
GIC="${GIC:-3}"
CPU="${CPU:-cortex-a72}"
QEMU="${QEMU:-qemu-system-aarch64}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-120}"
# The conformance suite reboots the chain across its panic tests and logs 89
# tests, so it gets its own budget.
case "$scenario" in
  confboot)   QEMU_TIMEOUT="${QEMU_TIMEOUT_CONFBOOT:-1500}" ;;
  devstorage) QEMU_TIMEOUT="${QEMU_TIMEOUT_DEVSTORAGE:-600}" ;;
esac
TOOLPREFIX="${TOOLPREFIX:-aarch64-none-elf-}"

case "$MACHINE" in
  virt) tag="virt-gicv$GIC-$CPU"; target=qemuvirt ;;
  versal-virt) tag="versal-virt"; target=versal ;;
  *) echo "unsupported MACHINE=$MACHINE (virt or versal-virt)" >&2; exit 2 ;;
esac

# cpus = cores the image expects to see (boot core + parked secondaries).
# versal-virt models 2 A72 + 2 R5 and QEMU refuses fewer than 4 CPUs there;
# its APU core 1 is created powered off and the CRF/APU control blocks that
# release it on silicon are unimplemented stubs in QEMU 11, so no firmware
# write starts it: the smoke and boot run on core 0 alone and boot-smp2 skips.
case "$scenario:$MACHINE" in
  smoke:virt) SMP="${SMP:-2}"; cpus="$SMP" ;;
  boot:virt|positive-secure:virt|crossdomain:virt|spfaultneg:virt|tablesneg:virt|ffa-direct:virt|ffa-sint:virt|ns-smoke:virt|ffa-discovery:virt|ffa-guest-direct:virt|psci:virt|ffa-preempt:virt|positive:virt|guest1:virt|smcfuzz:virt|secramneg:virt|resetneg:virt|ffa-memneg:virt) SMP="${SMP:-1}"; cpus="$SMP" ;;
  boot-smp2:virt) SMP=2; cpus=2 ;;
  boot-smp2:versal-virt)
    echo "SKIP: qemu-a/boot-smp2 (versal-virt): QEMU xlnx-versal-virt keeps APU core 1 powered off and models the CRF and APU control blocks as unimplemented, so firmware cannot release it"
    exit 0 ;;
  secramneg:versal-virt)
    echo "SKIP: qemu-a/secramneg (versal-virt): QEMU xlnx-versal-virt does not model the XMPU/RISAF secure-memory controller, so the secure RAM is not fenced from the Normal world in the model; the fence is proven on the virt cells (VIRT_SECURE_MEM) and enforced by the XMPU/RISAF on silicon"
    exit 0 ;;
  *) SMP="${SMP:-4}"; cpus=1 ;;
esac
expected_mask=$(printf '0x%x' $(( (1 << cpus) - 2 )))
el3_base=0xFFFC0000

# --- Build the image for this scenario. ---
if [ "$scenario" = smoke ]; then
  fw="$repo/tests/firmware/aarch64-smoke"
  build="$fw/build/$tag"
  make -C "$fw" MACHINE="$MACHINE" TOOLPREFIX="$TOOLPREFIX" BUILD_DIR="build/$tag" \
    WT_SMOKE_CPUS="$cpus"
  image_bin="$build/smoke.bin"
  image_elf="$build/smoke.elf"
else
  build="$repo/build-aarch64-$tag-$scenario"
  probe=()
  case "$scenario" in
    crossdomain) probe=(WT_FFM_NEGATIVE_PROBE=1) ;;
    spfaultneg)  probe=(WT_SP_FAULT_PROBE=1) ;;
    tablesneg)   probe=(WT_TABLES_NEGATIVE=1) ;;
    confboot|devstorage) probe=(WT_CONFORMANCE=1 WT_EL3_NS_SMOKE=1) ;;
    ffa-direct|ffa-sint) probe=(WT_EL3_TEST_DRIVER=1) ;;
    ns-smoke|ffa-discovery|psci|positive|guest1|smcfuzz|secramneg|resetneg|ffa-memneg|storage) probe=(WT_EL3_NS_SMOKE=1) ;;
    ffa-guest-direct) probe=(WT_EL3_NS_SMOKE=1 WT_NS_GUEST_ECHO=1) ;;
    ffa-preempt) probe=(WT_EL3_NS_SMOKE=1 WT_NS_PREEMPT=1) ;;
  esac
  make ARCH=aarch64 TARGET="$target" TOOLPREFIX="$TOOLPREFIX" WT_GIC_VERSION="$GIC" \
    WT_CPU="$CPU" WT_PORT_BOOT_CPUS="$cpus" BUILD_DIR="build-aarch64-$tag-$scenario" \
    "${probe[@]}"
  image_elf="$build/wolftrust_el3.elf"
  spm_elf="$build/wolftrust.elf"
  # ns-smoke also builds the Normal-world payload the SPMD ERETs to; it loads
  # into NS DRAM at WT_NS_IMAGE_PA, above the virt DTB at the RAM base
  # (0x40000000-0x40100000) so QEMU does not reject an overlapping ROM region.
  ns_base=0x44000000
  if [ "$scenario" = ns-smoke ] || [ "$scenario" = ffa-discovery ] || \
     [ "$scenario" = ffa-guest-direct ] || [ "$scenario" = psci ] || \
     [ "$scenario" = ffa-preempt ] || [ "$scenario" = positive ] || \
     [ "$scenario" = guest1 ] || [ "$scenario" = smcfuzz ] || \
     [ "$scenario" = secramneg ] || [ "$scenario" = resetneg ] || \
     [ "$scenario" = ffa-memneg ] || [ "$scenario" = storage ] || \
     [ "$scenario" = confboot ] || [ "$scenario" = devstorage ]; then
    nsfw="$repo/tests/firmware/aarch64-ns-smoke"
    ns_echo=0
    [ "$scenario" = ffa-guest-direct ] && ns_echo=1
    ns_psci=0
    [ "$scenario" = psci ] && ns_psci=1
    ns_preempt=0
    [ "$scenario" = ffa-preempt ] && ns_preempt=1
    ns_psa=0
    ns_id=0
    [ "$scenario" = positive ] && ns_psa=1
    [ "$scenario" = guest1 ] && { ns_psa=1; ns_id=1; }
    ns_fuzz=0
    [ "$scenario" = smcfuzz ] && ns_fuzz=1
    ns_secram=0
    [ "$scenario" = secramneg ] && ns_secram=1
    ns_reset=0
    [ "$scenario" = resetneg ] && ns_reset=1
    ns_memneg=0
    [ "$scenario" = ffa-memneg ] && ns_memneg=1
    ns_storage=0
    [ "$scenario" = storage ] && ns_storage=1
    # confboot runs Arm's val NSPE from the payload against the conformance
    # image built above (its fetched upstream tree + generated test list).
    ns_conf=0
    ns_suite=ipc
    [ "$scenario" = confboot ] && ns_conf=1
    [ "$scenario" = devstorage ] && { ns_conf=1; ns_suite=storage; }
    # The secure keystore address to probe from NS and the conformance data
    # band the val PAL config names differ per target.
    ns_secure_probe=0x0E300000
    ns_confdata=0x0E2C0000
    [ "$target" = versal ] && { ns_secure_probe=0x7F300000; ns_confdata=0x7F2C0000; }
    # Per-scenario NS build dir, wiped each run so a changed -D flag (probe
    # address, guest id) is always recompiled and never a stale binary.
    rm -rf "$nsfw/build/$tag-$scenario"
    make -C "$nsfw" MACHINE="$MACHINE" TOOLPREFIX="$TOOLPREFIX" \
      BUILD_DIR="build/$tag-$scenario" WT_NS_BASE="$ns_base" \
      WT_NS_GUEST_ECHO="$ns_echo" WT_NS_GUEST_PSCI="$ns_psci" \
      WT_NS_PREEMPT="$ns_preempt" WT_NS_GUEST_PSA="$ns_psa" \
      WT_NS_GUEST_ID="$ns_id" WT_NS_GUEST_FUZZ="$ns_fuzz" \
      WT_NS_GUEST_SECRAM="$ns_secram" WT_NS_SECURE_PROBE_PA="$ns_secure_probe" \
      WT_NS_GUEST_RESET="$ns_reset" WT_NS_GUEST_MEMNEG="$ns_memneg" \
      WT_NS_GUEST_STORAGE="$ns_storage" WT_RUN_CONFORMANCE="$ns_conf" \
      WT_CONF_SUITE="$ns_suite" \
      WT_NS_CONF_UPSTREAM="$build/upstream/psa-arch-tests/api-tests" \
      WT_NS_CONFDATA_PA="$ns_confdata" \
      WT_NS_MANIFEST_INC="$build/manifest"
    ns_bin="$nsfw/build/$tag-$scenario/ns.bin"
  fi
  # virt boots one pflash image: the monitor at 0, the SPMC image behind it
  # at WT_SPM_FLASH_OFFSET (mk/target-qemuvirt.mk), copied to RAM by EL3.
  image_bin="$build/pflash.bin"
  cp "$build/wolftrust_el3.bin" "$image_bin"
  truncate -s $((0x100000)) "$image_bin"
  cat "$build/wolftrust.bin" >> "$image_bin"
fi

log="$repo/ci-qemu-a-$scenario-$tag.log"
ns_log="$repo/ci-qemu-a-$scenario-$tag-ns.log"
sec_log="$repo/ci-qemu-a-$scenario-$tag-secure.log"
qemu_out="$repo/ci-qemu-a-$scenario-$tag-qemu.log"
: > "$ns_log"; : > "$sec_log"

# virt: the first -serial is the Non-secure PL011, the second the secure one;
# the image boots from flash0 at 0. versal-virt: the loader places the ELF in
# OCM and points core 0 at it; UART0 is the NS console, UART1 the secure one.
if [ "$MACHINE" = virt ]; then
  args=(-M "virt,secure=on,gic-version=$GIC" -cpu "$CPU" -smp "$SMP" -m 1G
        -bios "$image_bin"
        -serial "file:$ns_log" -serial "file:$sec_log")
else
  args=(-M xlnx-versal-virt -smp "$SMP" -m 2G
        -device "loader,file=$image_elf")
  if [ "$scenario" != smoke ]; then
    args+=(-device "loader,file=$spm_elf")
  fi
  args+=(-device "loader,addr=$el3_base,cpu-num=0"
         -serial "file:$ns_log" -serial "file:$sec_log")
fi
if [ "$scenario" = ns-smoke ] || [ "$scenario" = ffa-discovery ] || \
   [ "$scenario" = ffa-guest-direct ] || [ "$scenario" = psci ] || \
   [ "$scenario" = ffa-preempt ] || [ "$scenario" = positive ] || \
   [ "$scenario" = guest1 ] || [ "$scenario" = smcfuzz ] || \
   [ "$scenario" = secramneg ] || [ "$scenario" = resetneg ] || \
   [ "$scenario" = ffa-memneg ] || [ "$scenario" = storage ] || \
   [ "$scenario" = confboot ] || [ "$scenario" = devstorage ]; then
  args+=(-device "loader,file=$ns_bin,addr=$ns_base")
fi
args+=(-nographic -monitor none -no-reboot
       -semihosting-config "enable=on,target=native")

echo "QEMU: $QEMU ${args[*]}"
set +e
timeout "$QEMU_TIMEOUT" "$QEMU" "${args[@]}" > "$qemu_out" 2>&1
emu_status=$?
set -e
{ cat "$ns_log" "$sec_log" "$qemu_out"; echo "[QEMU EXIT] status=$emu_status"; } > "$log"
if [ "$emu_status" -eq 0 ]; then echo "[EXPECT EXIT] Success" >> "$log"; fi
cat "$log"
echo "wolfTrust QEMU AArch64 exit status: $emu_status ($tag)"

export WT_EXPECT_LOG="$log"

case "$scenario" in
  smoke)
    expect "code runs at EL3 on $MACHINE" "[SMOKE] EL3 machine=$MACHINE"
    expect "generic timer frequency reported" " cntfrq="
    expect "secondary cores parked (PF-Q1, $cpus cores)" " parked_mask=$expected_mask"
    refute_re "no smoke failure marker" '\[SMOKE\] FAIL'
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  boot|boot-smp2)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "EL3 monitor banner on $MACHINE" "[EL3] wolfTrust monitor cntfrq="
    expect "GIC initialized as v$GIC" " gic=v$GIC "
    if [ "$GIC" = 3 ]; then
      expect "GICv3 redistributor woken" " rdist_woken=1 "
    fi
    expect "secondary cores parked ($cpus cores)" " secondaries parked mask=$expected_mask"
    expect "secure timer tick reached EL3 as a Group 0 FIQ" "[EL3] tick ok intid=29"
    expect "SPMD built the FF-A boot information blob" "[EL3] boot info at 0x"
    expect "SPMC image placed in its band" "[EL3] spmc image at 0x"
    expect "monitor dropped into Secure EL1" "[SPM] spmc entered at S-EL1"
    expect "SPMC consumed the boot information blob" "[SPM] boot info ok descs="
    expect "SPMC turned its stage-1 MMU on and still prints" "[SPM] mmu on ttbr0=0x"
    expect "secure timer tick reached the SPMC as a Group 0 FIQ at S-EL1" "[SPM] tick ok intid=29"
    expect "coroutine switch works at Secure EL1" "[SPM] coroutine ok"
    expect "unprivileged partition ran at S-EL0 and yielded through SVC" "[SPM] el0 svc ok"
    expect "a direct request was delivered to a waiting S-EL0 partition and echoed back" "[SPM] ffa direct ok"
    expect "a spinning S-EL0 partition was preempted by the secure timer tick" "[SPM] preempt ok"
    expect "a software-raised Secure SPI reached the SPMC as a Group 0 FIQ" "[SPM] sint gic ok intid=0x28"
    expect "an S-EL0 partition discovered every partition through FFA_PARTITION_INFO_GET" "[SPM] partinfo ok n=6"
    expect "an S-EL0 partition retrieved a page the SPMC shared, wrote it, relinquished it, and the owner reclaimed it" "[SPM] mem share ok handle="
    refute_re "the memory-sharing self-test did not fail" '\[SPM\] mem share FAIL'
    expect "FF-A version negotiated with the SPMD" "[SPM] ffa version 1.2 negotiated"
    expect "FF-A discovery at the Secure physical instance" "[SPM] ffa discovery ok id=0x8000 spmd=0x8001"
    expect "FFA_CONSOLE_LOG SMC32 logged through the SPMD" "[SPM] console32 ok"
    expect "FFA_CONSOLE_LOG SMC64 logged through the SPMD" "[SPM] console64 ok"
    expect "SPMC initialization completed with FFA_MSG_WAIT" "[EL3] spmc ready"
    expect "monitor exit call reached EL3" "[BKPT] imm=0x7f"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    if [ "$scenario" = boot-smp2 ]; then
      expect_once "exactly one EL3 banner (the secondary parked before main)" "[EL3] wolfTrust monitor cntfrq="
      expect_once "exactly one Secure EL1 entry" "[SPM] spmc entered at S-EL1"
      expect_once "exactly one monitor exit" "[BKPT] imm=0x7f"
    fi
    ;;
  positive-secure)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "monitor dropped into Secure EL1" "[SPM] spmc entered at S-EL1"
    for id in 8002 8003 8004 8005 8006 8007; do
      expect "partition 0x$id initialized through the SVC gate" "[SP] init id=0x$id"
    done
    expect "every partition initialized" "[SPM] partitions ready n=6"
    expect "SPMC idles on FFA_MSG_WAIT with no Normal world" "[EL3] spmc ready"
    expect "monitor exit call reached EL3" "[BKPT] imm=0x7f"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  confboot)
    # The unmodified Arm FF-M IPC suite (psa-arch-tests val NSPE, pinned rev,
    # zero test edits) runs from the Normal world over FF-A against the
    # conformance SPMC image. Panic tests reboot the whole chain mid-suite
    # (the SPMC's must-panic policy and the NS client's own abort vector both
    # answer with PSCI SYSTEM_RESET) and val resumes off the Secure NVM boot
    # flag, so partition faults are by design here: the suite's own totals
    # and the clean semihosting exit gate correctness. 89 scheduled: 85 pass,
    # the 4 heap tests report SKIPPED (zero-allocation image); i067 is not
    # scheduled (heap).
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "monitor dropped into Secure EL1" "[SPM] spmc entered at S-EL1"
    for id in 8002 8003 8004 8005 8006 8007 8008 8009; do
      expect "partition 0x$id initialized through the SVC gate" "[SP] init id=0x$id"
    done
    expect "every conformance partition initialized" "[SPM] partitions ready n=8"
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "val started from the payload" "[NS] conformance val_entry start"
    if [ "$MACHINE" = versal-virt ]; then
      # xlnx-versal-virt models no XMPU/RISAF (see secramneg): the seven
      # Normal-world fence tests (i048/i049 pass a Secure iovec array pointer
      # the client dereferences; i072/i073/i075/i076/i077 read Secure
      # data/stack/mmio from NS) read Secure RAM without faulting and report
      # Failed. Every other test must pass; the fence is proven on the virt
      # cells (VIRT_SECURE_MEM) and enforced by the XMPU/RISAF on silicon.
      expect_flat "Arm suite TOTAL PASSED : 78 (versal-virt: no NS fence model)" "TOTAL PASSED    : 78"
      expect_flat "Arm suite TOTAL SKIPPED : 4" "TOTAL SKIPPED   : 4"
      expect_flat "Arm suite TOTAL FAILED : 7" "TOTAL FAILED    : 7"
      # A reboot can split a test header across lines, so key on the Num=
      # token wherever it lands rather than on the Suite= line.
      failed=$(awk '/Num=[0-9]+/ {match($0, /Num=[0-9]+/); n = substr($0, RSTART + 4, RLENGTH - 4)}
                    /^Result=Failed/ && n != "" {print n}' "$log" | sort -un | tr '\n' ' ')
      if [ "$failed" = "48 49 72 73 75 76 77 " ]; then
        check_pass "only the Normal-world fence tests failed on the model"
      else
        check_fail "only the Normal-world fence tests failed on the model" "failed set: $failed"
      fi
    else
      expect_flat "Arm suite TOTAL PASSED : 85" "TOTAL PASSED    : 85"
      expect_flat "Arm suite TOTAL SKIPPED : 4" "TOTAL SKIPPED   : 4"
      expect_flat "Arm suite TOTAL FAILED : 0" "TOTAL FAILED    : 0"
    fi
    expect "val returned to the payload" "[NS] conformance val_entry returned"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  crossdomain)
    refute_re "the fault never escalated to a Secure EL1 exception" '^\[SYNC EL=1'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "a partition read outside its domain and took a data abort at S-EL0" "[SYNC EL=0 EC=0x24"
    expect "the offending partition was restarted under its manifest policy" "[SP] restarted id=0x"
    expect "the persistently-faulting partition was quarantined, the rest initialized" "[SPM] partitions ready n=5"
    expect "SPMC idles on FFA_MSG_WAIT with no Normal world" "[EL3] spmc ready"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  spfaultneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC EL=1'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "a partition faulted at S-EL0 during init" "[SYNC EL=0 EC=0x00"
    expect "the faulted partition was restarted under its manifest policy" "[SP] restarted id=0x"
    expect "every partition still reached initialization" "[SPM] partitions ready n=6"
    expect "SPMC idles on FFA_MSG_WAIT with no Normal world" "[EL3] spmc ready"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  tablesneg)
    refute_re "the SPMC never turned its MMU on" '\[SPM\] mmu on'
    refute_re "no partition initialized" '\[SPM\] partitions ready'
    refute_re "the run did not exit cleanly" '\[EXPECT EXIT\] Success'
    expect "a writable and executable region was refused when the SPM table was built (W^X)" "[SPM] FAIL domain x0=0x00000001"
    expect "the SPMC panicked through the monitor" "[EL3] panic code=0x000000f1"
    ;;
  ffa-direct)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no unexpected FF-A event at the SPMC" '\[SPM\] unexpected event'
    refute_re "the response was not judged bad" '\[EL3\] direct resp BAD'
    expect "the echo partition initialized alongside the six services" "[SPM] partitions ready n=7"
    expect "the SPMD sent a direct request to the echo partition" "[EL3] direct req to=0x80fe"
    expect "the SPMC relayed it at the NS-physical instance" "[SPM] direct req from=0x0000 to=0x80fe"
    expect "the echo partition's response reached the SPMD with the payload complemented" "[EL3] direct resp ok from=0x80fe x3=0xedcb5432"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-sint)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no unexpected FF-A event at the SPMC" '\[SPM\] unexpected event'
    expect "the echo partition initialized alongside the six services" "[SPM] partitions ready n=7"
    expect "a Secure interrupt was signalled to the owner while it waited" "[SPM] sint signaled id=0x28"
    expect "a Secure interrupt was queued for the owner while it ran" "[SPM] sint queued id=0x28"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ns-smoke)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world did not misread the version" '\[NS\] ffa version BAD'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    expect "the SPMD launched the Normal world" "[EL3] ns launch pc=0x44000000"
    expect "the Normal-world payload ran at NS-EL1" "[NS] hello el=1"
    expect "the Normal world negotiated FF-A 1.2 with the SPMD" "[NS] ffa version 1.2"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-discovery)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world did not misread discovery" '\[NS\] discovery BAD'
    expect "the Normal world negotiated FF-A 1.2 with the SPMD" "[NS] ffa version 1.2"
    expect "the Normal world discovered the partitions through the SPMC" "[NS] discovery ok n=6"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-guest-direct)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world did not misread the direct response" '\[NS\] direct resp BAD'
    expect "the Normal world discovered the partitions through the SPMC" "[NS] discovery ok n=6"
    expect "a guest direct request reached the Secure partition and echoed back" "[NS] direct resp ok x3=0x"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  psci)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the Normal world read the PSCI version from the SPMD" "[NS] psci version 1.1"
    expect "the Normal world powered off through PSCI" "[EL3] psci system_off"
    expect "the PSCI power-off ended the run cleanly" "[EXPECT BKPT] Success"
    ;;
  ffa-preempt)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the Normal world was running" "[NS] spinning"
    expect "a Secure tick preempted the Normal world at EL3" "[EL3] ns preempted intid=29"
    expect "the SPMC scheduled the Secure interrupt" "[SPM] ns preempt intid=0x1d"
    expect "the Normal world resumed after the preemption" "[NS] resumed after preempt"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  positive|guest1)
    [ "$scenario" = guest1 ] && guest_id=1 || guest_id=0
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the guest did not fail a PSA connect" '\[NS\] psa connect FAIL'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    expect "the Normal-world guest ran at NS-EL1" "[NS] hello el=1"
    expect "the guest discovered the partitions through the SPMC" "[NS] discovery ok n=6"
    expect "the SPMC fielded the guest's PSA requests at the framework endpoint" "[SPM] direct req from=0x0000 to=0x80fd"
    expect "the guest read the PSA framework version over the transport" "[NS] psa framework 0x100"
    expect "the guest read the service version over the transport" "[NS] psa version v=1"
    expect "the guest connected to a Secure service and got a handle" "[NS] psa connect ok handle="
    expect "an unknown service was refused by the gateway" "[NS] psa connect refused"
    refute_re "the data-carrying call was not misjudged" '\[NS\] psa call BAD'
    expect "the guest completed a data-carrying psa_call through the routed gateway" "[NS] psa call ok"
    expect "the wolfHSM client echoed a packet through the relay partition and the wolfHSM server" "[NS] hsm echo ok"
    expect "the guest closed its handle" "[NS] psa close ok"
    expect "the Normal-world guest reached the services and finished" "[NS] guest$guest_id ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  resetneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the Normal world asked for a system reset" "[NS] psci system_reset"
    expect "the first reset re-entered the boot chain" "[EL3] psci system_reset reboot"
    expect "the monitor booted the chain a second time" "[EL3] wolfTrust monitor cntfrq="
    expect "the second reset ended the run through the boot-flag path" "[EL3] psci system_reset done"
    expect "the re-entered chain exited cleanly" "[EXPECT BKPT] Success"
    ;;
  secramneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world never read Secure RAM" '\[NS\] secram LEAK'
    expect "the Normal world attempted the Secure-RAM read" "[NS] secram read 0x"
    expect "the Secure-RAM read was refused and the Normal world caught the fault" "[NS] secram refused"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  smcfuzz)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no function id was mishandled" '\[NS\] smcfuzz BAD'
    refute_re "the sweep did not fall short" '\[NS\] smcfuzz FAIL'
    expect "every unimplemented function id from the Normal world was refused cleanly" "[NS] smcfuzz ok swept="
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-memneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic on a malformed transaction" '\[SPM\] panic'
    refute_re "no malformed transaction was mishandled" '\[NS\] memneg BAD'
    expect "every malformed memory transaction was refused and a reclaimed handle is dead" "[NS] memneg ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  devstorage)
    # The unmodified Arm dev_apis storage suite (psa-arch-tests s001-s017)
    # runs from the Normal world: every ITS/PS call rides the routed PSA
    # client onto SERVICE_ITS / SERVICE_PS, whose VAULT hop is the SP-to-SP
    # path. No panic tests here; every test must pass or skip, none fail.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "the conformance SPMC image initialized every partition" "[SPM] partitions ready n=8"
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "val started from the payload" "[NS] conformance val_entry start"
    flat="$(tr -d '\r\n' < "$log")"
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
    expect "val returned to the payload" "[NS] conformance val_entry returned"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  storage)
    # SERVICE_ITS fronts the VAULT partition, so a guest ITS round trip is the
    # first request whose service calls a second partition: the SVC gate runs
    # VAULT from inside the ITS partition's handler and returns into it.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    refute_re "the ITS round trip was not misjudged" '\[NS\] its BAD'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    expect "the Normal-world guest ran at NS-EL1" "[NS] hello el=1"
    expect "an ITS object round-tripped through SERVICE_ITS and the VAULT partition behind it" "[NS] its ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
esac

echo "PASS: qemu-a/$scenario ($tag)"
