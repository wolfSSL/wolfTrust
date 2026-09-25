/* xspi_nor.c
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

/* XSPI0 octal-DTR NOR program and erase for the MX25UM51345G, driven through
 * bounded target-group IP commands. The first loader leaves XSPI0 configured
 * for XIP; this driver only owns its LUT sequences and the IP transaction.
 * While a program or erase is in flight the NOR serves no XIP fetches, so the
 * transaction runs from the RAM band with interrupts masked and flushes the
 * XSPI read cache before returning to flash code. */

#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "mimxrt798_regs.h"
#include "xspi_nor.h"

#define WT_RAMFUNC       __attribute__((section(".ramfunc"), noinline))
#define WT_RAMFUNC_ENTRY __attribute__((section(".ramfunc"), noinline, long_call))
#define WT_RAMDATA       __attribute__((section(".ramfunc.data")))

#define WT_XSPI_POLL_LIMIT      100000u
#define WT_XSPI_BUSY_LIMIT      1000000u
#define WT_XSPI_NOR_PAGE        256u
#define WT_XSPI_TX_DEPTH_WORDS  256u
#define WT_XSPI_NOR_BASE        WT_FLASH_NS_BASE

#define WT_NOR_SEQ_RDSR    2u
#define WT_NOR_SEQ_WREN    4u
#define WT_NOR_SEQ_RDSCUR  6u
#define WT_NOR_SEQ_PP      7u
#define WT_NOR_SEQ_SE      8u
#define WT_NOR_SEQ_WORDS   5u

#define WT_NOR_SR_WIP      0x01u
#define WT_NOR_SR_WEL      0x02u
#define WT_NOR_SCUR_PFAIL  0x20u
#define WT_NOR_SCUR_EFAIL  0x40u

#define WT_LUT(c0, o0, c1, o1) \
    WT_XSPI_LUT_SEQ(c0, WT_XSPI_PAD_8, o0, c1, WT_XSPI_PAD_8, o1)

typedef struct wt_xspi_lut_seq {
    uint32_t seq;
    uint32_t words[WT_NOR_SEQ_WORDS];
} wt_xspi_lut_seq_t;

typedef struct wt_xspi_nor_window {
    uint32_t base;
    uint32_t size;
} wt_xspi_nor_window_t;

/* The only NOR ranges this path may program or erase; the wolfBoot swap area
 * and the reserved sectors between them stay closed. */
static const wt_xspi_nor_window_t g_wt_xspi_nor_writable[] = {
    { WT_FWU_UPDATE_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE + WT_FLASH_NS_BASE,
      WT_FWU_UPDATE_FLASH_SIZE },
    { WT_HSM_NVM_FLASH_BASE_NS, WT_HSM_NVM_FLASH_SIZE },
    { WT_CONF_NVM_FLASH_BASE_NS, WT_CONF_NVM_FLASH_SIZE },
};

/* Octal DTR command sets: each opcode is followed by its complement. The
 * status and security reads take a zero address and four dummy cycles; reads
 * move eight bytes to satisfy ERR052528. */
static const wt_xspi_lut_seq_t g_wt_xspi_lut[] WT_RAMDATA = {
    { WT_NOR_SEQ_RDSR, {
        WT_LUT(WT_XSPI_CMD_DDR, 0x05u, WT_XSPI_CMD_DDR, 0xFAu),
        WT_LUT(WT_XSPI_CMD_RADDR_DDR, 0x20u, WT_XSPI_CMD_DUMMY_SDR, 0x04u),
        WT_LUT(WT_XSPI_CMD_READ_DDR, 0x08u, WT_XSPI_CMD_STOP, 0x00u),
        0u, 0u } },
    { WT_NOR_SEQ_WREN, {
        WT_LUT(WT_XSPI_CMD_DDR, 0x06u, WT_XSPI_CMD_DDR, 0xF9u),
        0u, 0u, 0u, 0u } },
    { WT_NOR_SEQ_RDSCUR, {
        WT_LUT(WT_XSPI_CMD_DDR, 0x2Bu, WT_XSPI_CMD_DDR, 0xD4u),
        WT_LUT(WT_XSPI_CMD_RADDR_DDR, 0x20u, WT_XSPI_CMD_DUMMY_SDR, 0x04u),
        WT_LUT(WT_XSPI_CMD_READ_DDR, 0x08u, WT_XSPI_CMD_STOP, 0x00u),
        0u, 0u } },
    { WT_NOR_SEQ_PP, {
        WT_LUT(WT_XSPI_CMD_DDR, 0x12u, WT_XSPI_CMD_DDR, 0xEDu),
        WT_LUT(WT_XSPI_CMD_RADDR_DDR, 0x20u, WT_XSPI_CMD_WRITE_DDR, 0x08u),
        0u, 0u, 0u } },
    { WT_NOR_SEQ_SE, {
        WT_LUT(WT_XSPI_CMD_DDR, 0x21u, WT_XSPI_CMD_DDR, 0xDEu),
        WT_LUT(WT_XSPI_CMD_RADDR_DDR, 0x20u, WT_XSPI_CMD_STOP, 0x00u),
        0u, 0u, 0u } },
};

static uint32_t g_wt_xspi_page[WT_XSPI_NOR_PAGE / sizeof(uint32_t)];

static void WT_RAMFUNC wt_xspi_settle(void)
{
    uint32_t i;

    for (i = 0u; i < 10u; i++) {
        __asm volatile("nop");
    }
}

/* Reset the target-group queue and the flash and AHB domains after a hung
 * transaction; the module must be enabled to assert and disabled to release. */
static int WT_RAMFUNC wt_xspi_recover(void)
{
    WT_XSPI0_MCR |= WT_XSPI_MCR_IPS_TG_RST;
    WT_XSPI0_MCR &= ~WT_XSPI_MCR_MDIS;
    WT_XSPI0_MCR |= WT_XSPI_MCR_SWRSTSD | WT_XSPI_MCR_SWRSTHD;
    wt_xspi_settle();
    WT_XSPI0_MCR |= WT_XSPI_MCR_MDIS;
    WT_XSPI0_MCR &= ~(WT_XSPI_MCR_SWRSTSD | WT_XSPI_MCR_SWRSTHD);
    wt_xspi_settle();
    WT_XSPI0_MCR &= ~WT_XSPI_MCR_MDIS;
    WT_XSPI0_ERRSTAT = WT_XSPI0_ERRSTAT;
    return WT_XSPI_NOR_TIMEOUT;
}

static int WT_RAMFUNC wt_xspi_check_error(uint32_t err)
{
    err &= WT_XSPI_ERRSTAT_ERRORS;
    if (err == 0u) {
        return WT_XSPI_NOR_OK;
    }
    if ((err & WT_XSPI_ERRSTAT_TG0SFAR) != 0u) {
        WT_XSPI0_TGSFARS |= WT_XSPI_TGSFARS_CLR;
    }
    if ((err & WT_XSPI_ERRSTAT_TG0IPCR) != 0u) {
        WT_XSPI0_TGIPCRS |= WT_XSPI_TGIPCRS_CLR;
    }
    WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_TXF | WT_XSPI_MCR_CLR_RXF;
    WT_XSPI0_ERRSTAT = err;
    return WT_XSPI_NOR_BUS;
}

/* Queue one IP command: claim the address (the SFP validates it against the
 * MDAD/FRAD policy when armed), then win arbitration against XIP traffic. */
static int WT_RAMFUNC wt_xspi_ip_start(uint32_t address, uint32_t seq,
                                       uint32_t size)
{
    uint32_t t = WT_XSPI_POLL_LIMIT;
    uint32_t err;

    WT_XSPI0_ERRSTAT = WT_XSPI0_ERRSTAT;
    while (((WT_XSPI0_TGSFARS & WT_XSPI_TGSFARS_VLD) != 0u) && (t > 0u)) {
        t--;
    }
    if (t == 0u) {
        return wt_xspi_recover();
    }
    WT_XSPI0_SFP_TG_SFAR = address;
    if (((WT_XSPI0_MGC & WT_XSPI_MGC_GVLDMDAD) != 0u) &&
            ((WT_XSPI0_TG0MDAD & WT_XSPI_TG0MDAD_VLD) != 0u)) {
        t = WT_XSPI_POLL_LIMIT;
        do {
            err = WT_XSPI0_TGSFARS &
                  (WT_XSPI_TGSFARS_VLD | WT_XSPI_TGSFARS_ERR);
            if (err == WT_XSPI_TGSFARS_ERR) {
                WT_XSPI0_TGSFARS |= WT_XSPI_TGSFARS_CLR;
                return WT_XSPI_NOR_BUS;
            }
            t--;
        } while ((err != WT_XSPI_TGSFARS_VLD) && (t > 0u));
        if (t == 0u) {
            return wt_xspi_recover();
        }
    }
    WT_XSPI0_SFP_TG_IPCR = WT_XSPI_IPCR_IDATSZ(size) | WT_XSPI_IPCR_SEQID(seq);
    t = WT_XSPI_POLL_LIMIT;
    while (t > 0u) {
        err = WT_XSPI0_ERRSTAT;
        if ((err & WT_XSPI_ERRSTAT_ARB_WIN) != 0u) {
            break;
        }
        if ((err & WT_XSPI_ERRSTAT_ERRORS) != 0u) {
            (void)wt_xspi_check_error(err);
            WT_XSPI0_TGIPCRS |= WT_XSPI_TGIPCRS_CLR;
            WT_XSPI0_TGSFARS |= WT_XSPI_TGSFARS_CLR;
            return WT_XSPI_NOR_BUS;
        }
        t--;
    }
    if (t == 0u) {
        return wt_xspi_recover();
    }
    WT_XSPI0_ERRSTAT = WT_XSPI_ERRSTAT_ARB_WIN;
    return WT_XSPI_NOR_OK;
}

static int WT_RAMFUNC wt_xspi_ip_idle(void)
{
    uint32_t t = WT_XSPI_POLL_LIMIT;

    while (((WT_XSPI0_SR & WT_XSPI_SR_BUSY) != 0u) && (t > 0u)) {
        t--;
    }
    return (t == 0u) ? wt_xspi_recover() : WT_XSPI_NOR_OK;
}

static int WT_RAMFUNC wt_xspi_ip_released(void)
{
    uint32_t t = WT_XSPI_POLL_LIMIT;

    while (((WT_XSPI0_SR & WT_XSPI_SR_IP_ACC) != 0u) && (t > 0u)) {
        t--;
    }
    return (t == 0u) ? wt_xspi_recover() : WT_XSPI_NOR_OK;
}

static int WT_RAMFUNC wt_xspi_ip_command(uint32_t address, uint32_t seq)
{
    int rc;

    rc = wt_xspi_ip_start(address, seq, 0u);
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_ip_idle();
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_check_error(WT_XSPI0_ERRSTAT);
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_ip_released();
    }
    return rc;
}

/* One page-bounded program transfer of whole words. */
static int WT_RAMFUNC wt_xspi_ip_write(uint32_t address, uint32_t seq,
                                       const uint32_t* words, uint32_t size)
{
    uint32_t t;
    uint32_t i;
    uint32_t count = size / sizeof(uint32_t);
    int rc;

    rc = wt_xspi_ip_start(address, seq, size);
    if (rc != WT_XSPI_NOR_OK) {
        return rc;
    }
    WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_TXF;
    wt_xspi_settle();
    t = WT_XSPI_POLL_LIMIT;
    while (((WT_XSPI0_FSMSTAT & WT_XSPI_FSMSTAT_STATE) != 1u) && (t > 0u)) {
        t--;
    }
    if (t == 0u) {
        return wt_xspi_recover();
    }
    WT_XSPI0_TBCT = (WT_XSPI_TX_DEPTH_WORDS + 1u) - count;
    rc = wt_xspi_check_error(WT_XSPI0_ERRSTAT);
    for (i = 0u; (rc == WT_XSPI_NOR_OK) && (i < count); i++) {
        t = WT_XSPI_POLL_LIMIT;
        while (((WT_XSPI0_SR & WT_XSPI_SR_TXFULL) != 0u) && (t > 0u)) {
            t--;
        }
        if (t == 0u) {
            return wt_xspi_recover();
        }
        WT_XSPI0_TBDR = words[i];
    }
    if (rc != WT_XSPI_NOR_OK) {
        return rc;
    }
    WT_XSPI0_FR = WT_XSPI_FR_TBFF;
    rc = wt_xspi_ip_released();
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_ip_idle();
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_check_error(WT_XSPI0_ERRSTAT);
    }
    return rc;
}

/* A register read shorter than one word: one-word watermark, drain once. */
static int WT_RAMFUNC wt_xspi_ip_read_word(uint32_t address, uint32_t seq,
                                           uint32_t size, uint32_t* word)
{
    uint32_t t;
    int rc;

    WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_RXF;
    wt_xspi_settle();
    if ((WT_XSPI0_SR & WT_XSPI_SR_IP_ACC) != 0u) {
        return WT_XSPI_NOR_BUS;
    }
    WT_XSPI0_RBCT = 0u;
    rc = wt_xspi_ip_start(address, seq, size);
    if (rc != WT_XSPI_NOR_OK) {
        return rc;
    }
    if ((WT_XSPI0_FSMSTAT & WT_XSPI_FSMSTAT_VLD) == 0u) {
        WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_RXF;
        return WT_XSPI_NOR_BUS;
    }
    t = WT_XSPI_POLL_LIMIT;
    while (((WT_XSPI0_SR & WT_XSPI_SR_BUSY) == 0u) &&
           ((WT_XSPI0_SR & WT_XSPI_SR_IP_ACC) != 0u) && (t > 0u)) {
        t--;
    }
    if (t == 0u) {
        return wt_xspi_recover();
    }
    t = WT_XSPI_POLL_LIMIT;
    while (((WT_XSPI0_SR & WT_XSPI_SR_RXWE) == 0u) && (t > 0u)) {
        if ((WT_XSPI0_ERRSTAT & WT_XSPI_ERRSTAT_TO_ERR) != 0u) {
            WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_RXF;
            WT_XSPI0_ERRSTAT = WT_XSPI_ERRSTAT_TO_ERR;
            return wt_xspi_recover();
        }
        t--;
    }
    if (t == 0u) {
        return wt_xspi_recover();
    }
    if ((WT_XSPI0_RBSR & WT_XSPI_RBSR_RDBFL) != 1u) {
        WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_RXF;
        return WT_XSPI_NOR_BUS;
    }
    rc = wt_xspi_check_error(WT_XSPI0_ERRSTAT);
    if (rc != WT_XSPI_NOR_OK) {
        WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_RXF;
        return rc;
    }
    *word = WT_XSPI0_RBDR0;
    WT_XSPI0_MCR |= WT_XSPI_MCR_CLR_RXF;
    return wt_xspi_ip_idle();
}

/* RDSR and RDSCUR need a zero device address in octal DTR. */
static int WT_RAMFUNC wt_nor_read_reg(uint32_t seq, uint32_t* value)
{
    uint32_t word = 0u;
    int rc;

    rc = wt_xspi_ip_read_word(WT_XSPI_NOR_BASE, seq, 2u, &word);
    if (rc == WT_XSPI_NOR_OK) {
        *value = word & 0xFFu;
    }
    return rc;
}

static int WT_RAMFUNC wt_nor_wait_ready(void)
{
    uint32_t t = WT_XSPI_BUSY_LIMIT;
    uint32_t sr = WT_NOR_SR_WIP;
    int rc = WT_XSPI_NOR_OK;

    while ((rc == WT_XSPI_NOR_OK) && ((sr & WT_NOR_SR_WIP) != 0u) &&
           (t > 0u)) {
        rc = wt_nor_read_reg(WT_NOR_SEQ_RDSR, &sr);
        t--;
    }
    if ((rc == WT_XSPI_NOR_OK) && ((sr & WT_NOR_SR_WIP) != 0u)) {
        rc = WT_XSPI_NOR_TIMEOUT;
    }
    return rc;
}

static int WT_RAMFUNC wt_nor_write_enable(uint32_t address)
{
    uint32_t sr = 0u;
    int rc;

    rc = wt_xspi_ip_command(address, WT_NOR_SEQ_WREN);
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_read_reg(WT_NOR_SEQ_RDSR, &sr);
    }
    if ((rc == WT_XSPI_NOR_OK) && ((sr & WT_NOR_SR_WEL) == 0u)) {
        rc = WT_XSPI_NOR_DEVICE;
    }
    return rc;
}

/* WIP clearing alone is not success: the die latches a rejected program or
 * erase in the security register. */
static int WT_RAMFUNC wt_nor_check_fail(uint32_t mask)
{
    uint32_t scur = 0u;
    int rc;

    rc = wt_nor_read_reg(WT_NOR_SEQ_RDSCUR, &scur);
    if ((rc == WT_XSPI_NOR_OK) && ((scur & mask) != 0u)) {
        rc = WT_XSPI_NOR_DEVICE;
    }
    return rc;
}

/* Own the program/erase sequences whatever the loader left: rewrite them only
 * when they differ. Sequence 0 (the XIP read) is never touched. */
static int WT_RAMFUNC wt_xspi_lut_install(void)
{
    uint32_t s;
    uint32_t i;
    uint32_t differ = 0u;
    int rc = WT_XSPI_NOR_OK;

    for (s = 0u; s < (sizeof(g_wt_xspi_lut) / sizeof(g_wt_xspi_lut[0])); s++) {
        for (i = 0u; i < WT_NOR_SEQ_WORDS; i++) {
            if (WT_XSPI0_LUT(WT_NOR_SEQ_WORDS * g_wt_xspi_lut[s].seq + i) !=
                    g_wt_xspi_lut[s].words[i]) {
                differ = 1u;
            }
        }
    }
    if (differ != 0u) {
        rc = wt_xspi_ip_idle();
    }
    if ((rc == WT_XSPI_NOR_OK) && (differ != 0u)) {
        WT_XSPI0_LUTKEY = WT_XSPI_LUT_KEY;
        WT_XSPI0_LCKCR = WT_XSPI_LCKCR_UNLOCK;
        for (s = 0u; s < (sizeof(g_wt_xspi_lut) / sizeof(g_wt_xspi_lut[0]));
                s++) {
            for (i = 0u; i < WT_NOR_SEQ_WORDS; i++) {
                WT_XSPI0_LUT(WT_NOR_SEQ_WORDS * g_wt_xspi_lut[s].seq + i) =
                    g_wt_xspi_lut[s].words[i];
            }
        }
        WT_XSPI0_LUTKEY = WT_XSPI_LUT_KEY;
        WT_XSPI0_LCKCR = WT_XSPI_LCKCR_LOCK;
    }
    return rc;
}

/* Abort the AHB prefetch and invalidate CACHE64_CTRL0 so the next XIP or
 * memory-mapped read sees the new NOR contents. */
static int WT_RAMFUNC wt_xspi_read_path_flush(void)
{
    uint32_t t = WT_XSPI_POLL_LIMIT;
    int rc = WT_XSPI_NOR_OK;

    WT_XSPI0_SPTRCLR |= WT_XSPI_SPTRCLR_ABRT_CLR;
    while (((WT_XSPI0_SPTRCLR & WT_XSPI_SPTRCLR_ABRT_CLR) != 0u) && (t > 0u)) {
        t--;
    }
    if (t == 0u) {
        rc = WT_XSPI_NOR_TIMEOUT;
    }
    WT_CACHE64_CTRL0_CCR |= WT_CACHE64_CCR_INVW0 | WT_CACHE64_CCR_INVW1 |
                            WT_CACHE64_CCR_GO;
    t = WT_XSPI_POLL_LIMIT;
    while (((WT_CACHE64_CTRL0_CCR & WT_CACHE64_CCR_GO) != 0u) && (t > 0u)) {
        t--;
    }
    WT_CACHE64_CTRL0_CCR &= ~(WT_CACHE64_CCR_INVW0 | WT_CACHE64_CCR_INVW1);
    if ((rc == WT_XSPI_NOR_OK) && (t == 0u)) {
        rc = WT_XSPI_NOR_TIMEOUT;
    }
    __asm volatile("dsb sy\n\tisb" ::: "memory");
    return rc;
}

static int WT_RAMFUNC_ENTRY wt_xspi_nor_erase_sector_ram(uint32_t address)
{
    int rc;
    int flush_rc;

    rc = wt_xspi_lut_install();
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_wait_ready();
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_write_enable(address);
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_ip_command(address, WT_NOR_SEQ_SE);
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_wait_ready();
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_check_fail(WT_NOR_SCUR_EFAIL);
    }
    flush_rc = wt_xspi_read_path_flush();
    if (rc == WT_XSPI_NOR_OK) {
        rc = flush_rc;
    }
    return rc;
}

static int WT_RAMFUNC_ENTRY wt_xspi_nor_program_ram(uint32_t address,
                                                    const uint32_t* words,
                                                    uint32_t size)
{
    int rc;
    int flush_rc;

    rc = wt_xspi_lut_install();
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_wait_ready();
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_write_enable(address);
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_xspi_ip_write(address, WT_NOR_SEQ_PP, words, size);
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_wait_ready();
    }
    if (rc == WT_XSPI_NOR_OK) {
        rc = wt_nor_check_fail(WT_NOR_SCUR_PFAIL);
    }
    flush_rc = wt_xspi_read_path_flush();
    if (rc == WT_XSPI_NOR_OK) {
        rc = flush_rc;
    }
    return rc;
}

static uint32_t wt_xspi_irq_mask(void)
{
    uint32_t primask;

    __asm volatile("mrs %0, primask\n\tcpsid i" : "=r"(primask) :: "memory");
    return primask;
}

static void wt_xspi_irq_restore(uint32_t primask)
{
    __asm volatile("msr primask, %0" :: "r"(primask) : "memory");
}

/* The range must lie wholly inside one writable window. */
static int wt_xspi_nor_range_ok(uint32_t address, uint32_t size)
{
    const wt_xspi_nor_window_t* win;
    uint32_t offset;
    size_t i;

    for (i = 0u; i < (sizeof(g_wt_xspi_nor_writable) /
                      sizeof(g_wt_xspi_nor_writable[0])); i++) {
        win = &g_wt_xspi_nor_writable[i];
        offset = address - win->base;
        if ((address >= win->base) && (offset < win->size) &&
                (size <= win->size - offset)) {
            return 1;
        }
    }
    return 0;
}

int wt_xspi_nor_erase(uint32_t address, uint32_t size)
{
    uint32_t done;
    uint32_t primask;
    int rc = WT_XSPI_NOR_OK;

    if (((address & (WT_XSPI_NOR_SECTOR - 1u)) != 0u) ||
            ((size & (WT_XSPI_NOR_SECTOR - 1u)) != 0u) ||
            !wt_xspi_nor_range_ok(address, size)) {
        return WT_XSPI_NOR_ARGUMENT;
    }
    for (done = 0u; (rc == WT_XSPI_NOR_OK) && (done < size);
            done += WT_XSPI_NOR_SECTOR) {
        primask = wt_xspi_irq_mask();
        rc = wt_xspi_nor_erase_sector_ram(address + done);
        wt_xspi_irq_restore(primask);
    }
    return rc;
}

int wt_xspi_nor_program(uint32_t address, const uint8_t* data, uint32_t size)
{
    uint8_t* page = (uint8_t*)g_wt_xspi_page;
    volatile uint32_t* wipe = g_wt_xspi_page;
    uint32_t done = 0u;
    uint32_t chunk;
    uint32_t i;
    uint32_t primask;
    int rc = WT_XSPI_NOR_OK;

    if ((data == NULL) || ((address & (WT_XSPI_NOR_UNIT - 1u)) != 0u) ||
            ((size & (WT_XSPI_NOR_UNIT - 1u)) != 0u) ||
            !wt_xspi_nor_range_ok(address, size)) {
        return WT_XSPI_NOR_ARGUMENT;
    }
    while ((rc == WT_XSPI_NOR_OK) && (done < size)) {
        chunk = WT_XSPI_NOR_PAGE -
                ((address + done) & (WT_XSPI_NOR_PAGE - 1u));
        if (chunk > size - done) {
            chunk = size - done;
        }
        /* Stage in RAM: the caller's buffer may sit in XIP flash. */
        for (i = 0u; i < chunk; i++) {
            page[i] = data[done + i];
        }
        primask = wt_xspi_irq_mask();
        rc = wt_xspi_nor_program_ram(address + done, g_wt_xspi_page, chunk);
        wt_xspi_irq_restore(primask);
        done += chunk;
    }
    /* The page can hold keystore records; do not leave it in Secure RAM. */
    for (i = 0u; i < WT_XSPI_NOR_PAGE / sizeof(uint32_t); i++) {
        wipe[i] = 0u;
    }
    return rc;
}
