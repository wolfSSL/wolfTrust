#!/usr/bin/env bash
# build_acs.sh
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# Build the Arm FF-A ACS endpoint images (sp1..sp4 at S-EL0, vm1 as the
# Normal-world dispatcher) for a wolfTrust QEMU machine.
#
#   build_acs.sh <virt|versal-virt> <out-dir>
#
#   SUITE=<all|setup_discovery|direct_messaging|memory_manage|...> (default all)
#   TOOLPREFIX (default aarch64-none-elf-)   WT_ACS_SP_ID_BASE (default 0x8002)
set -euo pipefail

machine="${1:-}"
out="${2:-}"
if [ -z "$machine" ] || [ -z "$out" ]; then
  echo "usage: $0 <virt|versal-virt> <out-dir>" >&2
  exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
TOOLPREFIX="${TOOLPREFIX:-aarch64-none-elf-}"
SUITE="${SUITE:-all}"
sp_id_base="${WT_ACS_SP_ID_BASE:-0x8002}"

case "$machine" in
  virt)
    secure_base=0x0E000000
    ns_uart=0x09000000; s_uart=0x09040000
    gicd=0x08000000; gicc=0x08010000; gicr=0x080A0000 ;;
  versal-virt)
    secure_base=0x7F000000
    ns_uart=0xFF000000; s_uart=0xFF010000
    gicd=0xF9000000; gicc=0xF9040000; gicr=0xF9080000 ;;
  *) echo "unsupported machine $machine (virt or versal-virt)" >&2; exit 2 ;;
esac

mkdir -p "$out"
out="$(cd "$out" && pwd)"
acs="$out/ff-a-acs"
"$repo/tests/upstream/fetch_ffa_acs.sh" "$acs" >/dev/null

# Platform exclusions, each a recorded patch: the suite stays pinned and any
# test the platform cannot host skips by name instead of hanging the run. A
# rebuild in the same directory first drops the last build's patches, wherever
# they landed.
git -C "$acs" checkout -q -- .
for patch in "$here"/patches/*.patch; do
  git -C "$acs" apply "$patch"
done

target="$acs/platform/pal_baremetal/tgt_wolftrust_qemu"
rm -rf "$target"
cp -R "$here/tgt_wolftrust_qemu" "$target"

# The endpoint image bands sit behind the SPMC's own bands in Secure RAM:
# four 1 MB partition images, the 64 KB test NVM, one read-only test page.
cat > "$target/inc/wt_acs_machine.h" <<EOF
#ifndef WT_ACS_MACHINE_H
#define WT_ACS_MACHINE_H
#define WT_ACS_NS_UART_BASE $ns_uart
#define WT_ACS_S_UART_BASE  $s_uart
#define WT_ACS_GICD_BASE    $gicd
#define WT_ACS_GICC_BASE    $gicc
#define WT_ACS_GICR_BASE    $gicr
#define WT_ACS_NVM_BASE     $(printf '0x%X' $((secure_base + 0x800000)))
#define WT_ACS_RO_MEM_BASE  $(printf '0x%X' $((secure_base + 0x810000)))
#define WT_ACS_SP1_ID       $(printf '0x%X' $((sp_id_base + 0)))
#define WT_ACS_SP2_ID       $(printf '0x%X' $((sp_id_base + 1)))
#define WT_ACS_SP3_ID       $(printf '0x%X' $((sp_id_base + 2)))
#define WT_ACS_SP4_ID       $(printf '0x%X' $((sp_id_base + 3)))
#endif
EOF

build="$acs/build-$machine"
rm -rf "$build"
mkdir -p "$build"
( cd "$build" && cmake ../ -G"Unix Makefiles" \
    -DCROSS_COMPILE="$TOOLPREFIX" -DTARGET=tgt_wolftrust_qemu \
    -DPLATFORM_NS_HYPERVISOR_PRESENT=0 -DPLATFORM_SPMC_EL=1 \
    -DPLATFORM_SP_EL=0 -DPLATFORM_FFA_V_1_2=1 \
    -DINDIRECT_MESSAGE_UUID_SUPPORT=1 -DSUITE="$SUITE" \
    > cmake.log 2>&1 \
  && make -j"$(nproc 2>/dev/null || echo 4)" > make.log 2>&1 ) || {
    tail -40 "$build/cmake.log" "$build/make.log" 2>/dev/null >&2
    echo "FF-A ACS build failed" >&2
    exit 1
  }

for image in sp1 sp2 sp3 sp4 vm1; do
  cp "$build/output/$image.bin" "$out/$image.bin"
done
echo "$out"
