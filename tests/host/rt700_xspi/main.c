/* main.c
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

/* Host suite for the MIMXRT700 XSPI NOR driver: a register model of the XSPI
 * target-group IP path, the NOR status registers, and CACHE64, driven through
 * the same accessor macros the driver uses on the part. Every access advances
 * the model one tick, so the polling loops see the flags change the way the
 * controller raises them, and every fault the driver handles has a knob. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memory_map.h"
#include "mimxrt798_regs.h"
#include "xspi_nor.h"

/* Mirrors of the driver's private sequence ids and NOR status bits. */
#define SEQ_RDSR    2u
#define SEQ_WREN    4u
#define SEQ_RDSCUR  6u
#define SEQ_PP      7u
#define SEQ_SE      8u
#define SEQ_WORDS   5u
#define NOR_SR_WIP  0x01u
#define NOR_SR_WEL  0x02u
#define SCUR_PFAIL  0x20u
#define SCUR_EFAIL  0x40u

#define XSPI_OFF(address) ((uint32_t)(address) - WT_XSPI0_BASE_S)
#define OFF_MCR      0x000u
#define OFF_RBSR     0x10Cu
#define OFF_RBCT     0x110u
#define OFF_TBDR     0x154u
#define OFF_TBCT     0x158u
#define OFF_SR       0x15Cu
#define OFF_FR       0x160u
#define OFF_SPTRCLR  0x16Cu
#define OFF_RBDR0    0x200u
#define OFF_LUTKEY   0x300u
#define OFF_LCKCR    0x304u
#define OFF_LUT      0x310u
#define OFF_TG0MDAD  0x900u
#define OFF_TGSFARS  0x908u
#define OFF_TGIPCRS  0x90Cu
#define OFF_MGC      0x920u
#define OFF_FSMSTAT  0x930u
#define OFF_ERRSTAT  0x938u
#define OFF_IPCR     0x958u
#define OFF_SFAR     0x95Cu
#define CACHE64_CCR_ADDR 0x50035800u

#define LUT_WORDS    80u
#define FLASH_BASE   0x28180000u
#define FLASH_SIZE   0x00070000u
#define TX_WORDS     256u
#define XIP_SEQ_WORD 0x0A180411u
#define BUSY_TICKS   8

#define UPDATE_NS (WT_FWU_UPDATE_FLASH_BASE_S - WT_FLASH_S_ALIAS_BASE + \
                   WT_FLASH_NS_BASE)
#define LUT_WORD(c0, o0, c1, o1) \
    WT_XSPI_LUT_SEQ(c0, WT_XSPI_PAD_8, o0, c1, WT_XSPI_PAD_8, o1)

enum {
    R_MCR, R_RBSR, R_RBCT, R_TBDR, R_TBCT, R_SR, R_FR, R_SPTRCLR, R_RBDR0,
    R_LUTKEY, R_LCKCR, R_TG0MDAD, R_TGSFARS, R_TGIPCRS, R_MGC, R_FSMSTAT,
    R_ERRSTAT, R_IPCR, R_SFAR, R_CCR, R_LUT0,
    REG_COUNT = R_LUT0 + LUT_WORDS
};

typedef struct model_cfg {
    int arb_never;      /* never grant arbitration */
    int arb_error;      /* IPCR rejected with a target-group error */
    int busy_forever;   /* the transaction never goes idle */
    int wel_stuck;      /* WREN never sets WEL */
    int wip_forever;    /* WIP never clears after a program or erase */
    int rx_timeout;     /* a register read times out instead of filling RX */
    int pfail;          /* the die latches a program failure */
    int efail;          /* the die latches an erase failure */
    int ccr_stuck;      /* CACHE64 never completes the invalidate */
    int mdad;           /* the MDAD policy validates SFAR */
    uint32_t mdad_base; /* the only window the MDAD policy accepts */
    uint32_t mdad_size;
} model_cfg_t;

static uint32_t regs[REG_COUNT];
static model_cfg_t cfg;
static uint8_t flash[FLASH_SIZE];
static uint32_t tx[TX_WORDS];
static uint32_t tx_count;
static uint32_t tx_size;
static uint32_t nor_sr;
static uint32_t nor_scur;
static uint32_t wip_reads;
static uint32_t active_seq;
static int active;
static int busy_ticks;
static int abrt_ticks;
static int ccr_ticks;
static uint32_t bad_access;
static uint32_t recovers;
static uint32_t programs;
static uint32_t program_sizes[8];
static uint32_t erases;
static uint32_t unlocks;
static uint32_t dropped_lut_writes;

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static void model_reset(void)
{
    uint32_t i;

    memset(regs, 0, sizeof(regs));
    memset(&cfg, 0, sizeof(cfg));
    memset(flash, 0xFF, sizeof(flash));
    /* The loader's XIP read sequence sits in slot 0 and must survive. */
    for (i = 0u; i < SEQ_WORDS; i++) {
        regs[R_LUT0 + i] = XIP_SEQ_WORD + i;
    }
    regs[R_LCKCR] = WT_XSPI_LCKCR_LOCK;
    tx_count = 0u;
    tx_size = 0u;
    nor_sr = 0u;
    nor_scur = 0u;
    wip_reads = 0u;
    active_seq = 0u;
    active = 0;
    busy_ticks = 0;
    abrt_ticks = 0;
    ccr_ticks = 0;
    bad_access = 0u;
    recovers = 0u;
    programs = 0u;
    memset(program_sizes, 0, sizeof(program_sizes));
    erases = 0u;
    unlocks = 0u;
    dropped_lut_writes = 0u;
}

static void model_arm_mdad(uint32_t base, uint32_t size)
{
    cfg.mdad = 1;
    cfg.mdad_base = base;
    cfg.mdad_size = size;
    regs[R_MGC] = WT_XSPI_MGC_GVLDMDAD;
    regs[R_TG0MDAD] = WT_XSPI_TG0MDAD_VLD;
}

static int reg_index(uint32_t address)
{
    uint32_t off;

    if (address == CACHE64_CCR_ADDR) {
        return R_CCR;
    }
    if (address < WT_XSPI0_BASE_S) {
        return -1;
    }
    off = XSPI_OFF(address);
    if ((off >= OFF_LUT) && (off < OFF_LUT + 4u * LUT_WORDS)) {
        return (int)(R_LUT0 + (off - OFF_LUT) / 4u);
    }
    switch (off) {
        case OFF_MCR:     return R_MCR;
        case OFF_RBSR:    return R_RBSR;
        case OFF_RBCT:    return R_RBCT;
        case OFF_TBDR:    return R_TBDR;
        case OFF_TBCT:    return R_TBCT;
        case OFF_SR:      return R_SR;
        case OFF_FR:      return R_FR;
        case OFF_SPTRCLR: return R_SPTRCLR;
        case OFF_RBDR0:   return R_RBDR0;
        case OFF_LUTKEY:  return R_LUTKEY;
        case OFF_LCKCR:   return R_LCKCR;
        case OFF_TG0MDAD: return R_TG0MDAD;
        case OFF_TGSFARS: return R_TGSFARS;
        case OFF_TGIPCRS: return R_TGIPCRS;
        case OFF_MGC:     return R_MGC;
        case OFF_FSMSTAT: return R_FSMSTAT;
        case OFF_ERRSTAT: return R_ERRSTAT;
        case OFF_IPCR:    return R_IPCR;
        case OFF_SFAR:    return R_SFAR;
        default:          return -1;
    }
}

static void deliver_register(uint32_t value)
{
    if (cfg.rx_timeout) {
        regs[R_ERRSTAT] |= WT_XSPI_ERRSTAT_TO_ERR;
        return;
    }
    regs[R_RBDR0] = value;
    regs[R_RBSR] = 1u;
    regs[R_SR] |= WT_XSPI_SR_RXWE;
}

static void complete_transaction(void)
{
    uint32_t base = regs[R_SFAR] - FLASH_BASE;
    uint32_t i;
    uint32_t b;

    switch (active_seq) {
        case SEQ_WREN:
            if (!cfg.wel_stuck) {
                nor_sr |= NOR_SR_WEL;
            }
            break;
        case SEQ_RDSR:
            deliver_register(nor_sr);
            if (((nor_sr & NOR_SR_WIP) != 0u) && !cfg.wip_forever) {
                wip_reads--;
                if (wip_reads == 0u) {
                    nor_sr &= ~(NOR_SR_WIP | NOR_SR_WEL);
                }
            }
            break;
        case SEQ_RDSCUR:
            deliver_register(nor_scur);
            break;
        case SEQ_PP:
            if (programs < 8u) {
                program_sizes[programs] = tx_count * 4u;
            }
            programs++;
            for (i = 0u; i < tx_count; i++) {
                for (b = 0u; b < 4u; b++) {
                    if (base + 4u * i + b < FLASH_SIZE) {
                        flash[base + 4u * i + b] &=
                            (uint8_t)(tx[i] >> (8u * b));
                    }
                }
            }
            tx_count = 0u;
            nor_sr |= NOR_SR_WIP;
            wip_reads = 2u;
            if (cfg.pfail) {
                nor_scur |= SCUR_PFAIL;
            }
            break;
        case SEQ_SE:
            erases++;
            if (base + WT_XSPI_NOR_SECTOR <= FLASH_SIZE) {
                memset(&flash[base], 0xFF, WT_XSPI_NOR_SECTOR);
            }
            nor_sr |= NOR_SR_WIP;
            wip_reads = 2u;
            if (cfg.efail) {
                nor_scur |= SCUR_EFAIL;
            }
            break;
        default:
            break;
    }
    regs[R_SR] &= ~(WT_XSPI_SR_BUSY | WT_XSPI_SR_IP_ACC);
    regs[R_FSMSTAT] = 0u;
    regs[R_TGSFARS] = 0u;
    active = 0;
}

static void start_transaction(uint32_t ipcr)
{
    regs[R_IPCR] = ipcr;
    active_seq = (ipcr >> 24) & 0xFu;
    tx_size = ipcr & 0xFFFFu;
    if (cfg.arb_error) {
        regs[R_ERRSTAT] |= WT_XSPI_ERRSTAT_TG0IPCR;
        regs[R_TGIPCRS] = 1u;
        return;
    }
    if (cfg.arb_never) {
        return;
    }
    regs[R_ERRSTAT] |= WT_XSPI_ERRSTAT_ARB_WIN;
    regs[R_SR] |= WT_XSPI_SR_BUSY | WT_XSPI_SR_IP_ACC;
    regs[R_FSMSTAT] = WT_XSPI_FSMSTAT_VLD | 1u;
    active = 1;
    if (active_seq == SEQ_PP) {
        /* A program waits for the TX buffer to hold the whole transfer. */
        regs[R_FR] |= WT_XSPI_FR_TBFF;
        busy_ticks = -1;
    }
    else {
        busy_ticks = BUSY_TICKS;
    }
}

static void write_mcr(uint32_t value)
{
    uint32_t old = regs[R_MCR];

    if ((value & WT_XSPI_MCR_CLR_TXF) != 0u) {
        tx_count = 0u;
    }
    if ((value & WT_XSPI_MCR_CLR_RXF) != 0u) {
        regs[R_SR] &= ~WT_XSPI_SR_RXWE;
        regs[R_RBSR] = 0u;
    }
    if (((value & WT_XSPI_MCR_SWRSTSD) != 0u) &&
            ((old & WT_XSPI_MCR_SWRSTSD) == 0u)) {
        recovers++;
        active = 0;
        busy_ticks = 0;
        tx_count = 0u;
        regs[R_SR] = 0u;
        regs[R_RBSR] = 0u;
        regs[R_FSMSTAT] = 0u;
        regs[R_TGSFARS] = 0u;
    }
    regs[R_MCR] = value & ~(WT_XSPI_MCR_CLR_TXF | WT_XSPI_MCR_CLR_RXF);
}

static void apply_write(int i, uint32_t value)
{
    switch (i) {
        case R_ERRSTAT:
        case R_FR:
            regs[i] &= ~value;
            break;
        case R_TGSFARS:
            if ((value & WT_XSPI_TGSFARS_CLR) != 0u) {
                regs[i] = 0u;
            }
            break;
        case R_TGIPCRS:
            if ((value & WT_XSPI_TGIPCRS_CLR) != 0u) {
                regs[i] = 0u;
            }
            break;
        case R_MCR:
            write_mcr(value);
            break;
        case R_SPTRCLR:
            regs[i] = value;
            if ((value & WT_XSPI_SPTRCLR_ABRT_CLR) != 0u) {
                abrt_ticks = 1;
            }
            break;
        case R_CCR:
            regs[i] = value;
            if ((value & WT_CACHE64_CCR_GO) != 0u) {
                ccr_ticks = cfg.ccr_stuck ? -1 : 1;
            }
            break;
        case R_SFAR:
            regs[i] = value;
            /* Status reads are addressed at the NOR base; a policy on the
             * part admits it through a descriptor of its own. */
            if (cfg.mdad) {
                if (((value >= cfg.mdad_base) &&
                        (value - cfg.mdad_base < cfg.mdad_size)) ||
                        (value == WT_FLASH_NS_BASE)) {
                    regs[R_TGSFARS] = WT_XSPI_TGSFARS_VLD;
                }
                else {
                    regs[R_TGSFARS] = WT_XSPI_TGSFARS_ERR;
                }
            }
            break;
        case R_IPCR:
            start_transaction(value);
            break;
        case R_TBDR:
            if (tx_count < TX_WORDS) {
                tx[tx_count] = value;
            }
            tx_count++;
            if (active && (active_seq == SEQ_PP) && (busy_ticks < 0) &&
                    (tx_count * 4u >= tx_size)) {
                busy_ticks = BUSY_TICKS;
            }
            break;
        case R_LUTKEY:
        case R_RBCT:
        case R_TBCT:
            regs[i] = value;
            break;
        case R_LCKCR:
            /* The lock only moves when the key was written just before. */
            if (regs[R_LUTKEY] == WT_XSPI_LUT_KEY) {
                if ((value == WT_XSPI_LCKCR_UNLOCK) &&
                        (regs[i] != WT_XSPI_LCKCR_UNLOCK)) {
                    unlocks++;
                }
                regs[i] = value;
            }
            regs[R_LUTKEY] = 0u;
            break;
        default:
            if (i >= R_LUT0) {
                if (regs[R_LCKCR] == WT_XSPI_LCKCR_UNLOCK) {
                    regs[i] = value;
                }
                else {
                    dropped_lut_writes++;
                }
            }
            else {
                bad_access++;
            }
            break;
    }
}

static void tick(void)
{
    if (active && !cfg.busy_forever && (busy_ticks > 0)) {
        busy_ticks--;
        if (busy_ticks == 0) {
            complete_transaction();
        }
    }
    if (abrt_ticks > 0) {
        abrt_ticks--;
        if (abrt_ticks == 0) {
            regs[R_SPTRCLR] &= ~WT_XSPI_SPTRCLR_ABRT_CLR;
        }
    }
    if (ccr_ticks > 0) {
        ccr_ticks--;
        if (ccr_ticks == 0) {
            regs[R_CCR] &= ~WT_CACHE64_CCR_GO;
        }
    }
}

uint32_t wt_mock_read(uint32_t address)
{
    int idx = reg_index(address);
    uint32_t value = 0u;

    if (idx < 0) {
        bad_access++;
    }
    else {
        value = regs[idx];
    }
    tick();
    return value;
}

void wt_mock_write(uint32_t address, uint32_t value)
{
    int idx = reg_index(address);

    if (idx < 0) {
        bad_access++;
    }
    else {
        apply_write(idx, value);
    }
    tick();
}

static const uint8_t pattern[32] = {
    0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu,
    0x10u, 0x32u, 0x54u, 0x76u, 0x98u, 0xBAu, 0xDCu, 0xFEu,
    0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u,
    0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0x0Fu, 0xF0u
};

static int lut_seq_is(uint32_t seq, uint32_t word0)
{
    return regs[R_LUT0 + SEQ_WORDS * seq] == word0;
}

static int xip_seq_intact(void)
{
    uint32_t i;

    for (i = 0u; i < SEQ_WORDS; i++) {
        if (regs[R_LUT0 + i] != XIP_SEQ_WORD + i) {
            return 0;
        }
    }
    return 1;
}

static void test_program_and_lut(void)
{
    int rc;

    model_reset();
    rc = wt_xspi_nor_program(UPDATE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_OK, "program 16 bytes at the update partition");
    check(memcmp(&flash[UPDATE_NS - FLASH_BASE], pattern, 16u) == 0,
          "the page program landed the bytes");
    check(programs == 1u && program_sizes[0] == 16u,
          "one 16-byte IP write");
    check(lut_seq_is(SEQ_RDSR, LUT_WORD(WT_XSPI_CMD_DDR, 0x05u,
                                        WT_XSPI_CMD_DDR, 0xFAu)) &&
          lut_seq_is(SEQ_WREN, LUT_WORD(WT_XSPI_CMD_DDR, 0x06u,
                                        WT_XSPI_CMD_DDR, 0xF9u)) &&
          lut_seq_is(SEQ_RDSCUR, LUT_WORD(WT_XSPI_CMD_DDR, 0x2Bu,
                                          WT_XSPI_CMD_DDR, 0xD4u)) &&
          lut_seq_is(SEQ_PP, LUT_WORD(WT_XSPI_CMD_DDR, 0x12u,
                                      WT_XSPI_CMD_DDR, 0xEDu)) &&
          lut_seq_is(SEQ_SE, LUT_WORD(WT_XSPI_CMD_DDR, 0x21u,
                                      WT_XSPI_CMD_DDR, 0xDEu)),
          "the five owned sequences were installed at a five-word stride");
    check(xip_seq_intact() && regs[R_LUT0 + SEQ_WORDS * 1u] == 0u &&
          regs[R_LUT0 + SEQ_WORDS * 3u] == 0u,
          "the XIP read sequence and the unowned slots were left alone");
    check(unlocks == 1u && dropped_lut_writes == 0u &&
          regs[R_LCKCR] == WT_XSPI_LCKCR_LOCK,
          "the LUT was unlocked once and locked again");
    check(bad_access == 0u, "no access outside the modelled registers");
    check(regs[R_ERRSTAT] == 0u && (regs[R_FR] & WT_XSPI_FR_TBFF) == 0u &&
          regs[R_TGSFARS] == 0u,
          "arbitration and the buffer-fill flag were acknowledged");
    check((regs[R_CCR] & WT_CACHE64_CCR_GO) == 0u &&
          (regs[R_SPTRCLR] & WT_XSPI_SPTRCLR_ABRT_CLR) == 0u,
          "the read path flush completed");

    rc = wt_xspi_nor_program(UPDATE_NS + 16u, pattern + 16u, 16u);
    check(rc == WT_XSPI_NOR_OK && unlocks == 1u,
          "a matching LUT is left alone on the next program");
}

static void test_page_split(void)
{
    uint32_t addr = WT_HSM_NVM_FLASH_BASE_NS + 0xF0u;
    int rc;

    model_reset();
    rc = wt_xspi_nor_program(addr, pattern, 32u);
    check(rc == WT_XSPI_NOR_OK, "program across a page boundary");
    check(programs == 2u && program_sizes[0] == 16u &&
          program_sizes[1] == 16u,
          "the transfer split into two page-bounded writes");
    check(memcmp(&flash[addr - FLASH_BASE], pattern, 32u) == 0,
          "both halves landed contiguously");
}

static void test_windows(void)
{
    int rc;

    model_reset();
    rc = wt_xspi_nor_program(0x281C0000u, pattern, 16u);
    check(rc == WT_XSPI_NOR_ARGUMENT && programs == 0u,
          "the wolfBoot swap area is refused without a transaction");
    rc = wt_xspi_nor_program(UPDATE_NS + WT_FWU_UPDATE_FLASH_SIZE - 16u,
                             pattern, 32u);
    check(rc == WT_XSPI_NOR_ARGUMENT,
          "a write straddling the end of a window is refused");
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS + 8u, pattern, 16u);
    check(rc == WT_XSPI_NOR_ARGUMENT, "an unaligned program is refused");
    rc = wt_xspi_nor_erase(WT_HSM_NVM_FLASH_BASE_NS + 0x100u,
                           WT_XSPI_NOR_SECTOR);
    check(rc == WT_XSPI_NOR_ARGUMENT, "an unaligned erase is refused");
    rc = wt_xspi_nor_erase(0x281E4000u, WT_XSPI_NOR_SECTOR);
    check(rc == WT_XSPI_NOR_ARGUMENT && erases == 0u,
          "the reserved sectors between the stores are refused");
    rc = wt_xspi_nor_program(WT_CONF_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_OK, "the conformance NVM sector is writable");
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, NULL, 16u);
    check(rc == WT_XSPI_NOR_ARGUMENT, "a NULL buffer is refused");
}

static void test_erase(void)
{
    uint32_t addr = WT_HSM_NVM_FLASH_BASE_NS;
    int rc;

    model_reset();
    rc = wt_xspi_nor_program(addr, pattern, 16u);
    check(rc == WT_XSPI_NOR_OK, "seed the sector before the erase");
    rc = wt_xspi_nor_erase(addr, 2u * WT_XSPI_NOR_SECTOR);
    check(rc == WT_XSPI_NOR_OK && erases == 2u,
          "two sectors erased with one sector command each");
    check(flash[addr - FLASH_BASE] == 0xFFu &&
          flash[addr - FLASH_BASE + 15u] == 0xFFu,
          "the erased sector reads blank");
}

static void test_arbitration_timeout(void)
{
    int rc;

    model_reset();
    cfg.arb_never = 1;
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_TIMEOUT, "never winning arbitration times out");
    check(recovers >= 1u, "the driver reset the target group to recover");
    check(programs == 0u, "nothing was programmed");
}

static void test_bus_error(void)
{
    int rc;

    model_reset();
    cfg.arb_error = 1;
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_BUS, "a rejected IP command is a bus error");
    check(regs[R_ERRSTAT] == 0u && regs[R_TGIPCRS] == 0u,
          "the error status and the command slot were cleared");
    check(programs == 0u && recovers == 0u,
          "nothing was programmed and no reset was needed");
}

static void test_mdad_reject(void)
{
    int rc;

    model_reset();
    model_arm_mdad(WT_CONF_NVM_FLASH_BASE_NS, WT_CONF_NVM_FLASH_SIZE);
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_BUS && programs == 0u,
          "an address outside the MDAD policy is refused");
    check(regs[R_TGSFARS] == 0u, "the rejected address claim was cleared");
    rc = wt_xspi_nor_program(WT_CONF_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_OK && programs == 1u,
          "an address inside the MDAD policy programs");
}

static void test_busy_timeout(void)
{
    int rc;

    model_reset();
    cfg.busy_forever = 1;
    rc = wt_xspi_nor_erase(WT_HSM_NVM_FLASH_BASE_NS, WT_XSPI_NOR_SECTOR);
    check(rc == WT_XSPI_NOR_TIMEOUT, "a transaction that never idles times out");
    check(recovers >= 1u, "the hung transaction was reset");
}

static void test_read_timeout(void)
{
    int rc;

    model_reset();
    cfg.rx_timeout = 1;
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_TIMEOUT && programs == 0u,
          "a status read that times out stops before the program");
    check(recovers >= 1u && (regs[R_ERRSTAT] & WT_XSPI_ERRSTAT_TO_ERR) == 0u,
          "the timeout was acknowledged and the target group reset");
}

static void test_device_failures(void)
{
    int rc;

    model_reset();
    cfg.wel_stuck = 1;
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_DEVICE && programs == 0u,
          "a write enable the die ignores stops before the program");

    model_reset();
    cfg.pfail = 1;
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_DEVICE, "a latched program failure is reported");

    model_reset();
    cfg.efail = 1;
    rc = wt_xspi_nor_erase(WT_HSM_NVM_FLASH_BASE_NS, WT_XSPI_NOR_SECTOR);
    check(rc == WT_XSPI_NOR_DEVICE, "a latched erase failure is reported");

    model_reset();
    cfg.wip_forever = 1;
    rc = wt_xspi_nor_erase(WT_HSM_NVM_FLASH_BASE_NS, WT_XSPI_NOR_SECTOR);
    check(rc == WT_XSPI_NOR_TIMEOUT && erases == 1u,
          "a die that never leaves write-in-progress times out");
}

static void test_flush_failure(void)
{
    int rc;

    model_reset();
    cfg.ccr_stuck = 1;
    rc = wt_xspi_nor_program(WT_HSM_NVM_FLASH_BASE_NS, pattern, 16u);
    check(rc == WT_XSPI_NOR_TIMEOUT,
          "a cache invalidate that never completes fails the program");
    check(memcmp(&flash[WT_HSM_NVM_FLASH_BASE_NS - FLASH_BASE], pattern,
                 16u) == 0,
          "the bytes were programmed before the flush failed");
}

int main(void)
{
    test_program_and_lut();
    test_page_split();
    test_windows();
    test_erase();
    test_arbitration_timeout();
    test_bus_error();
    test_mdad_reject();
    test_busy_timeout();
    test_read_timeout();
    test_device_failures();
    test_flush_failure();
    if (failures == 0) {
        printf("PASS: unit/rt700_xspi (%d checks)\n", checks);
        return 0;
    }
    printf("FAIL: unit/rt700_xspi (%d/%d failed)\n", failures, checks);
    return 1;
}
