/* mcxn947_regs.h
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

#ifndef WOLFTRUST_MCXN947_REGS_H
#define WOLFTRUST_MCXN947_REGS_H

#include <stdint.h>

/* Secure-alias peripheral bases (MCXN947 cm33_core0, NS alias = base -
 * 0x10000000). */
#define WT_PERIPH_NS_BASE        0x40000000u
#define WT_PERIPH_S_BASE         0x50000000u
#define WT_PERIPH_ALIAS_SIZE     0x10000000u

#define WT_SYSCON_BASE_S         0x50000000u
#define WT_FMU0_BASE_S           0x50043000u
#define WT_ELS_BASE_S            0x50054000u
#define WT_ELS_BASE_NS           0x40054000u
#define WT_LPUART4_BASE_S        0x500B4000u
#define WT_LPUART4_BASE_NS       0x400B4000u
#define WT_TRDC_BASE_S           0x500C7000u
#define WT_AHBSC_BASE_S          0x50120000u

/* Boot ROM through its Secure alias; the ROM flash API tree sits at its end. */
#define WT_ROM_BASE_S            0x13000000u
#define WT_ROM_SIZE              0x00040000u
#define WT_ROM_API_TREE          0x1303FC00u

#ifndef WT_REG32
#define WT_REG32(address)        (*(volatile uint32_t*)(address))
#endif

/* EdgeLock (ELS, S50) command interface; register offsets per the MCUXpresso
 * S50 peripheral header. */
#define WT_ELS_STATUS            WT_REG32(WT_ELS_BASE_S + 0x00u)
#define WT_ELS_CTRL              WT_REG32(WT_ELS_BASE_S + 0x04u)
#define WT_ELS_CMDCFG0           WT_REG32(WT_ELS_BASE_S + 0x08u)
#define WT_ELS_DMA_RES0          WT_REG32(WT_ELS_BASE_S + 0x38u)
#define WT_ELS_DMA_RES0_LEN      WT_REG32(WT_ELS_BASE_S + 0x3Cu)
#define WT_ELS_ERR_STATUS        WT_REG32(WT_ELS_BASE_S + 0x4Cu)
#define WT_ELS_ERR_STATUS_CLR    WT_REG32(WT_ELS_BASE_S + 0x50u)
#define WT_ELS_STATUS_BUSY       (1u << 0)
#define WT_ELS_STATUS_IRQ        (1u << 1)
#define WT_ELS_STATUS_ERR        (1u << 2)
#define WT_ELS_STATUS_LOCKED     (1u << 16)
#define WT_ELS_CTRL_EN           (1u << 0)
#define WT_ELS_CTRL_START        (1u << 1)
#define WT_ELS_CTRL_RESET        (1u << 2)
#define WT_ELS_CTRL_CMD(cmd)     (((uint32_t)(cmd) & 0x1Fu) << 3)
#define WT_ELS_CMD_RND_REQ       24u
#define WT_ELS_ERR_STATUS_CLR_ALL (1u << 0)
/* RND_REQ fills the DMA result buffer in whole words. */
#define WT_ELS_RND_ALIGN         4u

#endif /* WOLFTRUST_MCXN947_REGS_H */
