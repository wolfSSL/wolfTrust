/* mimxrt798_regs.h
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

#ifndef WOLFTRUST_MIMXRT798_REGS_H
#define WOLFTRUST_MIMXRT798_REGS_H

#include <stdint.h>

/* Secure-alias peripheral bases (MIMXRT798S cm33_core0, NS alias = base -
 * 0x10000000). */
#define WT_PERIPH_NS_BASE        0x40000000u
#define WT_PERIPH_S_BASE         0x50000000u
#define WT_PERIPH_ALIAS_SIZE     0x10000000u

#define WT_RSTCTL0_BASE_S        0x50000000u
#define WT_CLKCTL0_BASE_S        0x50001000u
#define WT_SYSCON0_BASE_S        0x50002000u
#define WT_IOPCTL0_BASE_S        0x50004000u
#define WT_ITRC_BASE_S           0x50012000u
#define WT_OCOTP_BASE_S          0x50018000u
#define WT_XCACHE0_BASE_S        0x50033000u
#define WT_XCACHE1_BASE_S        0x50034000u
#define WT_GPIO0_BASE_S          0x50100000u
#define WT_LPUART0_BASE_S        0x50110000u
#define WT_LPUART0_BASE_NS       0x40110000u
#define WT_LPUART1_BASE_S        0x50111000u
#define WT_AHBSC0_BASE_S         0x5017C000u
#define WT_GLIKEY0_BASE_S        0x5017CC00u
#define WT_XSPI0_BASE_S          0x50184000u
#define WT_XSPI1_BASE_S          0x50185000u
#define WT_TRNG_BASE_S           0x50187000u
#define WT_ELS_BASE_S            0x50190000u
#define WT_PUF_BASE_S            0x50194000u
#define WT_AHBSC3_BASE_S         0x50220000u
#define WT_GLIKEY1_BASE_S        0x50220C00u
#define WT_AHBSC4_BASE_S         0x50400000u
#define WT_GLIKEY2_BASE_S        0x50400C00u

#define WT_REG32(address)        (*(volatile uint32_t*)(address))

/* TRNG (NXP TRNG block). */
#define WT_TRNG_MCTL             WT_REG32(WT_TRNG_BASE_S + 0x000u)
#define WT_TRNG_MCTL_RST_DEF     (1u << 6)
#define WT_TRNG_MCTL_ENT_VAL     (1u << 10)
#define WT_TRNG_MCTL_ERR         (1u << 12)
#define WT_TRNG_MCTL_PRGM        (1u << 16)
#define WT_TRNG_ENT(index)       WT_REG32(WT_TRNG_BASE_S + 0x040u + 4u * (index))
#define WT_TRNG_ENT_COUNT        16u

/* GLIKEY write-enable state machine guarding each AHBSC instance. */
#define WT_GLIKEY_CTRL_0(base)   WT_REG32((base) + 0x0u)
#define WT_GLIKEY_CTRL_1(base)   WT_REG32((base) + 0x4u)
#define WT_GLIKEY_STATUS(base)   WT_REG32((base) + 0xCu)
#define WT_GLIKEY_CODEWORD_STEP1 0xF0C10F3Eu
#define WT_GLIKEY_CODEWORD_STEP2 0x0F1DF0E2u
#define WT_GLIKEY_CODEWORD_STEP3 0xF0B00F4Fu
#define WT_GLIKEY_CODEWORD_EN    0x0FFFF000u
#define WT_GLIKEY_CODEWORD_SEL_CTRL_1  0xF0u
#define WT_GLIKEY_CTRL_WR_EN_SHIFT     16u
#define WT_GLIKEY_CTRL_WR_EN_MASK      (0x3u << WT_GLIKEY_CTRL_WR_EN_SHIFT)
#define WT_GLIKEY_CTRL_0_SFT_RST       (1u << 18)
#define WT_GLIKEY_CTRL_0_INDEX_MASK    0xFFu
#define WT_GLIKEY_CTRL_1_SFR_LOCK_SHIFT 18u
#define WT_GLIKEY_CTRL_1_SFR_LOCK_MASK (0xFu << WT_GLIKEY_CTRL_1_SFR_LOCK_SHIFT)
#define WT_GLIKEY_SFR_UNLOCKED         0xAu
#define WT_GLIKEY_STATUS_ERROR_MASK    0x1Cu
#define WT_GLIKEY_STATUS_FSM_SHIFT     19u
#define WT_GLIKEY_FSM_WR_EN            0x1802u
/* GLIKEY0 write index guarding AHBSC0 MISC_CTRL bits 11:2. */
#define WT_GLIKEY0_INDEX_MISC_CTRL     1u

/* AHB secure controller: per-bus-master SRAM access enables and the global
 * check switch (secure control register at the end of each instance). */
#define WT_AHBSC_MISC_CTRL_REG(base)     WT_REG32((base) + 0xFFCu)
#define WT_AHBSC_MISC_CTRL_DP_REG(base)  WT_REG32((base) + 0xFF8u)
/* Bits 11:2 as one field: secure checking on (restrictive), privilege checks
 * off, a violation aborts (DISABLE_VIOLATION_ABORT=10b, not the detect-only
 * 01b), tier mode. This governs the non-CPU masters the AHBSC checks; CPU0
 * isolation is the SAU (RT700 RM 7.2.8, SRM 11.3.3.3). */
#define WT_AHBSC_MISC_CTRL_CHECK_MASK    0x00000FFCu
#define WT_AHBSC_MISC_CTRL_CHECK_ON      0x000006A4u
#define WT_AHBSC_MISC_CTRL_SECURE_CHECK_MASK 0x0000000Cu
#define WT_AHBSC_MISC_CTRL_SECURE_CHECK_ON   0x00000004u
/* AHBSC0 peripheral rule holding LP_FLEXCOMM0 (the LPUART0 console) in 1:0. */
#define WT_AHBSC0_AHB_PERIPHERAL0_SLAVE_RULE1 WT_REG32(WT_AHBSC0_BASE_S + 0x3C4u)
#define WT_AHBSC0_RULE_LP_FLEXCOMM0_MASK      0x3u
#define WT_AHBSC3_COMPUTE_APB_ACCESS     WT_REG32(WT_AHBSC3_BASE_S + 0xFA0u)
#define WT_AHBSC3_SENSE_APB_ACCESS       WT_REG32(WT_AHBSC3_BASE_S + 0xFA4u)
#define WT_AHBSC3_COMPUTE_AIPS_ACCESS    WT_REG32(WT_AHBSC3_BASE_S + 0xFB0u)
#define WT_AHBSC3_SENSE_AIPS_ACCESS      WT_REG32(WT_AHBSC3_BASE_S + 0xFB4u)

/* AHB secure controller RAM-partition rules. Compute SRAM partitions are not
 * uniform: P10 and P11 are the 512 KiB partitions at 0x20100000 (both guest
 * windows) and 0x20180000 (the Secure runtime bank), P12 the 1 MiB partition
 * at 0x20200000 (the RAM code band). Four rule words per partition, eight
 * two-bit minimum-tier fields per word (0 NS-user .. 3 S-priv). Rule writes
 * need no GLIKEY unlock. Even with secure checking on, P10 rules did not stop a
 * Non-secure CPU store on silicon, so no isolation is claimed from them. */
#define WT_AHBSC_RULE_ALL_SECURE      0x22222222u
#define WT_AHBSC0_SRAM11_RULE(index)  WT_REG32(WT_AHBSC0_BASE_S + 0x200u + 4u * (index))
#define WT_AHBSC0_SRAM12_RULE(index)  WT_REG32(WT_AHBSC0_BASE_S + 0x220u + 4u * (index))

/* XSPI0 controller, target group 0 (the only group this port drives). */
#define WT_XSPI0_MCR          WT_REG32(WT_XSPI0_BASE_S + 0x000u)
#define WT_XSPI0_RBSR         WT_REG32(WT_XSPI0_BASE_S + 0x10Cu)
#define WT_XSPI0_RBCT         WT_REG32(WT_XSPI0_BASE_S + 0x110u)
#define WT_XSPI0_TBDR         WT_REG32(WT_XSPI0_BASE_S + 0x154u)
#define WT_XSPI0_TBCT         WT_REG32(WT_XSPI0_BASE_S + 0x158u)
#define WT_XSPI0_SR           WT_REG32(WT_XSPI0_BASE_S + 0x15Cu)
#define WT_XSPI0_FR           WT_REG32(WT_XSPI0_BASE_S + 0x160u)
#define WT_XSPI0_SPTRCLR      WT_REG32(WT_XSPI0_BASE_S + 0x16Cu)
#define WT_XSPI0_RBDR0        WT_REG32(WT_XSPI0_BASE_S + 0x200u)
#define WT_XSPI0_LUTKEY       WT_REG32(WT_XSPI0_BASE_S + 0x300u)
#define WT_XSPI0_LCKCR        WT_REG32(WT_XSPI0_BASE_S + 0x304u)
#define WT_XSPI0_LUT(index)   WT_REG32(WT_XSPI0_BASE_S + 0x310u + 4u * (index))
#define WT_XSPI0_TG0MDAD      WT_REG32(WT_XSPI0_BASE_S + 0x900u)
#define WT_XSPI0_TGSFARS      WT_REG32(WT_XSPI0_BASE_S + 0x908u)
#define WT_XSPI0_TGIPCRS      WT_REG32(WT_XSPI0_BASE_S + 0x90Cu)
#define WT_XSPI0_MGC          WT_REG32(WT_XSPI0_BASE_S + 0x920u)
#define WT_XSPI0_FSMSTAT      WT_REG32(WT_XSPI0_BASE_S + 0x930u)
#define WT_XSPI0_ERRSTAT      WT_REG32(WT_XSPI0_BASE_S + 0x938u)
#define WT_XSPI0_SFP_TG_IPCR  WT_REG32(WT_XSPI0_BASE_S + 0x958u)
#define WT_XSPI0_SFP_TG_SFAR  WT_REG32(WT_XSPI0_BASE_S + 0x95Cu)

#define WT_XSPI_MCR_SWRSTSD      0x00000001u
#define WT_XSPI_MCR_SWRSTHD      0x00000002u
#define WT_XSPI_MCR_IPS_TG_RST   0x00000200u
#define WT_XSPI_MCR_CLR_RXF      0x00000400u
#define WT_XSPI_MCR_CLR_TXF      0x00000800u
#define WT_XSPI_MCR_MDIS         0x00004000u
#define WT_XSPI_SR_BUSY          0x00000001u
#define WT_XSPI_SR_IP_ACC        0x00000002u
#define WT_XSPI_SR_RXWE          0x00010000u
#define WT_XSPI_SR_TXFULL        0x08000000u
#define WT_XSPI_FR_TBFF          0x08000000u
#define WT_XSPI_SPTRCLR_ABRT_CLR 0x00010000u
#define WT_XSPI_TGSFARS_CLR      0x20000000u
#define WT_XSPI_TGSFARS_ERR      0x40000000u
#define WT_XSPI_TGSFARS_VLD      0x80000000u
#define WT_XSPI_TGIPCRS_CLR      0x10000000u
#define WT_XSPI_MGC_GVLDMDAD     0x20000000u
#define WT_XSPI_TG0MDAD_VLD      0x80000000u
#define WT_XSPI_FSMSTAT_STATE    0x00000003u
#define WT_XSPI_FSMSTAT_VLD      0x80000000u
#define WT_XSPI_RBSR_RDBFL       0x000000FFu
#define WT_XSPI_ERRSTAT_TG0SFAR  0x00000400u
#define WT_XSPI_ERRSTAT_TG0IPCR  0x00001000u
#define WT_XSPI_ERRSTAT_TO_ERR   0x00004000u
#define WT_XSPI_ERRSTAT_ERRORS   0x00007FFFu
#define WT_XSPI_ERRSTAT_ARB_WIN  0x10000000u
#define WT_XSPI_IPCR_SEQID(seq)  (((uint32_t)(seq) & 0xFu) << 24)
#define WT_XSPI_IPCR_IDATSZ(sz)  ((uint32_t)(sz) & 0xFFFFu)
#define WT_XSPI_LUT_KEY          0x5AF05AF0u
#define WT_XSPI_LCKCR_LOCK       0x00000001u
#define WT_XSPI_LCKCR_UNLOCK     0x00000002u

/* LUT instruction words: two instructions per word, each opcode:pad:operand. */
#define WT_XSPI_LUT_SEQ(cmd0, pad0, op0, cmd1, pad1, op1) \
    (((uint32_t)(op0) & 0xFFu) | (((uint32_t)(pad0) & 0x3u) << 8) | \
     (((uint32_t)(cmd0) & 0x3Fu) << 10) | (((uint32_t)(op1) & 0xFFu) << 16) | \
     (((uint32_t)(pad1) & 0x3u) << 24) | (((uint32_t)(cmd1) & 0x3Fu) << 26))
#define WT_XSPI_CMD_STOP       0x00u
#define WT_XSPI_CMD_DUMMY_SDR  0x03u
#define WT_XSPI_CMD_RADDR_DDR  0x0Au
#define WT_XSPI_CMD_READ_DDR   0x0Eu
#define WT_XSPI_CMD_WRITE_DDR  0x0Fu
#define WT_XSPI_CMD_DDR        0x11u
#define WT_XSPI_PAD_8          0x03u

/* CACHE64_CTRL0 sits in the XSPI0 read path; flush it after NOR changes. Its
 * base is shared with CACHE64_POLSEL0, so CCR is at +0x800. */
#define WT_CACHE64_CTRL0_CCR   WT_REG32(0x50035800u)
#define WT_CACHE64_CCR_INVW0   0x01000000u
#define WT_CACHE64_CCR_INVW1   0x04000000u
#define WT_CACHE64_CCR_GO      0x80000000u

#endif /* WOLFTRUST_MIMXRT798_REGS_H */
