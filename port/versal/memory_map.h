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

#ifndef WOLFTRUST_VERSAL_MEMORY_MAP_H
#define WOLFTRUST_VERSAL_MEMORY_MAP_H

/* AMD Versal (and QEMU xlnx-versal-virt): the EL3 monitor lives in the
 * 256 KiB OCM, the Secure band is carved out of DDR, GIC-500 is GICv3, and
 * both PS UARTs are PL011s (UART1 is the secure console). */

#ifndef WT_EL3_TEXT_BASE
#define WT_EL3_TEXT_BASE      0xFFFC0000u
#endif
#ifndef WT_EL3_RAM_BASE
#define WT_EL3_RAM_BASE       0xFFFE0000u
#endif
#ifndef WT_EL3_RAM_SIZE
#define WT_EL3_RAM_SIZE       0x00020000u
#endif
#define WT_RAM_S_BASE         0x7F000000u
#define WT_RAM_S_SIZE         0x01000000u
#define WT_SPM_BOOT_INFO_PA   0x7F000000u
#ifndef WT_SPM_IMAGE_PA
#define WT_SPM_IMAGE_PA       0x7F100000u
#endif
#ifndef WT_SPM_IMAGE_SIZE
#define WT_SPM_IMAGE_SIZE     0x00100000u
#endif
#ifndef WT_SPM_RAM_PA
#define WT_SPM_RAM_PA         0x7F200000u
#endif
#ifndef WT_SPM_RAM_SIZE
#define WT_SPM_RAM_SIZE       0x00040000u
#endif
#ifndef WT_SPM_KEYSTORE_PA
#define WT_SPM_KEYSTORE_PA    0x7F300000u
#endif
#ifndef WT_SPM_KEYSTORE_SIZE
#define WT_SPM_KEYSTORE_SIZE  0x00040000u
#endif

#define WT_GICD_BASE          0xF9000000u
#define WT_GICR_BASE          0xF9080000u

#define WT_UART_NS_BASE       0xFF000000u
#define WT_UART_S_BASE        0xFF010000u
#define WT_UART_CLOCK_HZ      100000000u
#define WT_UART_BAUD          115200u

#endif /* WOLFTRUST_VERSAL_MEMORY_MAP_H */
