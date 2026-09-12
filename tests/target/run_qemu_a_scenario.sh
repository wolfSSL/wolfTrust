#!/usr/bin/env bash
# wolfTrust AArch64 QEMU scenario runner, the emulator twin of
# run_m33mu_scenario.sh: build the images for one machine, boot them under
# qemu-system-aarch64, and assert one scenario's markers. Run inside
# ghcr.io/wolfssl/wolfboot-ci-aarch64 (the image CI uses) or anywhere
# qemu-system-aarch64 and aarch64-none-elf-gcc are on PATH.
#
#   run_qemu_a_scenario.sh smoke   our code runs at EL3 on the machine, prints
#                                  on the secure console, reports which
#                                  secondary cores parked, exits via semihosting
#
#   MACHINE=virt|versal-virt (default virt)   GIC=2|3 (virt, default 3)
#   CPU=cortex-a35|cortex-a72 (virt, default cortex-a72)
#   SMP=<n> (default 2 on virt, 4 on versal-virt)
#   QEMU_TIMEOUT=<s> (default 60)   TOOLPREFIX (default aarch64-none-elf-)
set -euo pipefail

scenario="${1:-}"
case "$scenario" in
  smoke) ;;
  *) echo "usage: $0 smoke" >&2; exit 2 ;;
esac

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
. "$repo/tests/target/lib/expect.sh"

MACHINE="${MACHINE:-virt}"
GIC="${GIC:-3}"
CPU="${CPU:-cortex-a72}"
QEMU="${QEMU:-qemu-system-aarch64}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-60}"
TOOLPREFIX="${TOOLPREFIX:-aarch64-none-elf-}"

# versal-virt models 2 A72 + 2 R5 and QEMU refuses fewer than 4 CPUs there;
# A72 core 1 stays held in reset until firmware releases it (a loader entry
# with cpu-num=1 does not start it), so the smoke runs on core 0 alone.
case "$MACHINE" in
  virt) tag="virt-gicv$GIC-$CPU"; SMP="${SMP:-2}"; cpus="$SMP" ;;
  versal-virt) tag="versal-virt"; SMP="${SMP:-4}"; cpus=1 ;;
  *) echo "unsupported MACHINE=$MACHINE (virt or versal-virt)" >&2; exit 2 ;;
esac
expected_mask=$(printf '0x%x' $(( (1 << cpus) - 2 )))

fw="$repo/tests/firmware/aarch64-smoke"
build="$fw/build/$tag"
make -C "$fw" MACHINE="$MACHINE" TOOLPREFIX="$TOOLPREFIX" BUILD_DIR="build/$tag" \
  WT_SMOKE_CPUS="$cpus"

log="$repo/ci-qemu-a-$scenario-$tag.log"
ns_log="$repo/ci-qemu-a-$scenario-$tag-ns.log"
sec_log="$repo/ci-qemu-a-$scenario-$tag-secure.log"
qemu_out="$repo/ci-qemu-a-$scenario-$tag-qemu.log"
: > "$ns_log"; : > "$sec_log"

# virt: the first -serial is the Non-secure PL011, the second the secure one.
# versal-virt: UART0 (PL011) only; the image is placed in OCM by the loader
# and core 0 is pointed at it.
if [ "$MACHINE" = virt ]; then
  args=(-M "virt,secure=on,gic-version=$GIC" -cpu "$CPU" -smp "$SMP" -m 1G
        -bios "$build/smoke.bin"
        -serial "file:$ns_log" -serial "file:$sec_log")
else
  args=(-M xlnx-versal-virt -smp "$SMP" -m 2G
        -device "loader,file=$build/smoke.elf"
        -device "loader,addr=0xFFFC0000,cpu-num=0"
        -serial "file:$sec_log")
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
esac

echo "PASS: qemu-a/$scenario ($tag)"
