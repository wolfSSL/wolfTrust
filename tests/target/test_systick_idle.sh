#!/usr/bin/env bash
# test_systick_idle.sh
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


set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
build="${WT_SYSTICK_TEST_BUILD:-$repo/build/systick-idle}"
prefix="${TOOLPREFIX:-arm-none-eabi-}"
emulator="${M33MU:-m33mu}"
mkdir -p "$build"
build="$(cd "$build" && pwd)"
if [[ "$emulator" == */* && "$emulator" != /* ]]; then
  emulator="$PWD/$emulator"
fi
"${prefix}gcc" -mcpu=cortex-m33 -mthumb -mgeneral-regs-only -mcmse \
  -std=c99 -ffreestanding -fno-builtin -nostdlib -Os -g \
  -ffunction-sections -fdata-sections -Wall -Wextra \
  -I"$repo/include" -I"$repo/port/stm32h563" \
  -DWT_MAX_GUESTS=2 -DWT_TARGET_BUILD=1 \
  -Wl,--gc-sections -Wl,-T,"$repo/tests/firmware/systick-idle/test.ld" \
  -o "$build/test.elf" "$repo/tests/firmware/systick-idle/main.c" -lgcc
"${prefix}objcopy" -O binary "$build/test.elf" "$build/test.bin"
echo 'RUN: virtual SysTick idle preservation'
(cd "$build"; "$emulator" "$build/test.bin" --expect-bkpt 0x7f --timeout 10) \
  | tee "$build/test.log" || true
faultmask=1
if ! grep -Fq '[EXPECT BKPT] Success' "$build/test.log"; then
  # 0x7d: every check passed but the core drops FAULTMASK_NS writes.
  grep -Fq '[BKPT] imm=0x7d' "$build/test.log"
  faultmask=0
fi
echo 'PASS: virtual SysTick idle snapshot, repeat idle, resume, and interrupt ordering'
echo 'PASS: pre-entry restart tick does not resurrect timer state'
echo 'PASS: guest trap frame outside its own RAM is never read by the Secure tick'
echo 'PASS: guest capture keeps the banked MSP_NS for a PSP_NS frame'
if [[ "$faultmask" == 1 ]]; then
  echo 'PASS: Non-secure PRIMASK, BASEPRI and FAULTMASK never mask the Secure tick'
  echo 'PASS: guest Non-secure masks are saved and restored per guest'
else
  echo 'PASS: Non-secure PRIMASK and BASEPRI never mask the Secure tick'
  echo 'PASS: guest Non-secure PRIMASK and BASEPRI are saved and restored per guest'
  echo 'SKIP: FAULTMASK_NS checks; this core drops FAULTMASK_NS writes'
fi
echo 'PASS: guest restore drops a Secure entry mask left by a mid-entry restart'
echo 'PASS: abandoned guest IRQs retire innermost first, one per exit, never under FAULTMASK_NS'
echo 'PASS: abandoning a guest handler restarts the Secure entry stack at its sealed base'
echo 'PASS: a pended Non-secure PendSV stays with its guest and never reaches another'
