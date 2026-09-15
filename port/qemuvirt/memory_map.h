/* memory_map.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef WOLFTRUST_QEMUVIRT_MEMORY_MAP_H
#define WOLFTRUST_QEMUVIRT_MEMORY_MAP_H

/* QEMU virt with secure=on: flash0 at 0 is secure-only, the 16 MiB secure
 * SRAM sits at 0x0E000000, and the second PL011 is the secure console. */

#ifndef WT_EL3_TEXT_BASE
#define WT_EL3_TEXT_BASE      0x00000000u
#endif
#ifndef WT_EL3_RAM_BASE
#define WT_EL3_RAM_BASE       0x0E000000u
#endif
#ifndef WT_EL3_RAM_SIZE
#define WT_EL3_RAM_SIZE       0x00040000u
#endif
#define WT_RAM_S_BASE         0x0E040000u
#define WT_RAM_S_SIZE         0x00FC0000u
#define WT_SPM_BOOT_INFO_PA   0x0E040000u
#ifndef WT_SPM_IMAGE_PA
#define WT_SPM_IMAGE_PA       0x0E100000u
#endif
#ifndef WT_SPM_IMAGE_SIZE
#define WT_SPM_IMAGE_SIZE     0x00100000u
#endif
#ifndef WT_SPM_RAM_PA
#define WT_SPM_RAM_PA         0x0E200000u
#endif
#ifndef WT_SPM_RAM_SIZE
#define WT_SPM_RAM_SIZE       0x00040000u
#endif
#ifndef WT_SPM_KEYSTORE_PA
#define WT_SPM_KEYSTORE_PA    0x0E300000u
#endif
#ifndef WT_SPM_KEYSTORE_SIZE
#define WT_SPM_KEYSTORE_SIZE  0x00040000u
#endif
#ifndef WT_SPM_RXTX_PA
#define WT_SPM_RXTX_PA        0x0E340000u
#endif
#ifndef WT_SPM_RXTX_SIZE
#define WT_SPM_RXTX_SIZE      0x00002000u
#endif
/* Normal-world payload load/run address: NS DRAM, well clear of the secure
 * SRAM window (virt DRAM starts at 0x40000000). */
#ifndef WT_NS_IMAGE_PA
#define WT_NS_IMAGE_PA        0x44000000u
#endif

#define WT_GICD_BASE          0x08000000u
#define WT_GICC_BASE          0x08010000u
#define WT_GICR_BASE          0x080A0000u

#define WT_UART_NS_BASE       0x09000000u
#define WT_UART_S_BASE        0x09040000u
#define WT_UART_CLOCK_HZ      24000000u
#define WT_UART_BAUD          115200u

#endif /* WOLFTRUST_QEMUVIRT_MEMORY_MAP_H */
