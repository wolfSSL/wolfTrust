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
  smoke|boot|boot-smp2|positive-secure) ;;
  *) echo "usage: $0 smoke|boot|boot-smp2|positive-secure" >&2; exit 2 ;;
esac

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
. "$repo/tests/target/lib/expect.sh"

MACHINE="${MACHINE:-virt}"
GIC="${GIC:-3}"
CPU="${CPU:-cortex-a72}"
QEMU="${QEMU:-qemu-system-aarch64}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-120}"
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
  boot:virt|positive-secure:virt) SMP="${SMP:-1}"; cpus="$SMP" ;;
  boot-smp2:virt) SMP=2; cpus=2 ;;
  boot-smp2:versal-virt)
    echo "SKIP: qemu-a/boot-smp2 (versal-virt): QEMU xlnx-versal-virt keeps APU core 1 powered off and models the CRF and APU control blocks as unimplemented, so firmware cannot release it"
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
  build="$repo/build-aarch64-$tag"
  make ARCH=aarch64 TARGET="$target" TOOLPREFIX="$TOOLPREFIX" WT_GIC_VERSION="$GIC" \
    WT_CPU="$CPU" WT_PORT_BOOT_CPUS="$cpus" BUILD_DIR="build-aarch64-$tag"
  image_elf="$build/wolftrust_el3.elf"
  spm_elf="$build/wolftrust.elf"
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
esac

echo "PASS: qemu-a/$scenario ($tag)"
