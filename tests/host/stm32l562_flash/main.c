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

/* The STM32L562 flash driver against the controller model: programs, page
 * erases by bank, WRP, ECC containment, bounded waits and the NS tamper. */

#include <stdio.h>
#include <string.h>

#include "flash_array.h"
#include "flash_port.h"
#include "memory_map.h"
#include "stm32l562_model.h"
#include "wolfhsm/wh_error.h"

#define SR_PROGERR  (1u << 3)
#define SR_WRPERR   (1u << 4)
#define SR_ERRORS   0x000000FAu
#define PAGE        WT_FLASH_PAGE_SIZE
#define SECTOR      WT_FLASH_SECTOR_SIZE
#define FWU_S       WT_FWU_UPDATE_FLASH_BASE_S
#define FWU_NS      (FWU_S - WT_FLASH_S_ALIAS_BASE + WT_FLASH_NS_BASE)

extern volatile uint32_t g_wt_flash_first_err_sr;

static int g_failed;

static void check(int ok, const char* what)
{
    printf("  [check] %s  %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failed++;
    }
}

static int clean_after(void)
{
    return wt_l5_model_locked() && !wt_l5_model_pg_set() &&
           wt_l5_model_irq_depth() == 0;
}

static void case_program(void)
{
    uint8_t data[64];
    uint8_t back[64];
    uint32_t programs = fa_programs();
    uint32_t i;

    printf(" case: program\n");
    for (i = 0u; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 7u + 1u);
    }
    g_wt_flash_first_err_sr = 0u;
    check(wt_port_flash_program(FWU_S, data, sizeof(data)) == WH_ERROR_OK,
          "a 64-byte program succeeds");
    check(fa_programs() - programs == sizeof(data) / WT_FLASH_PROGRAM_UNIT,
          "eight double-words were programmed");
    check(memcmp(fa_map(FWU_S, sizeof(data)), data, sizeof(data)) == 0,
          "the array holds the bytes");
    check(clean_after(), "PG cleared, the controller relocked, interrupts restored");
    check(wt_l5_model_sequence_errors() == 0u && g_wt_flash_first_err_sr == 0u,
          "no sequence or program error was raised");
    check(wt_l5_model_unmasked_array_accesses() == 0u,
          "every array access ran with interrupts masked");
    check(wt_port_flash_read(FWU_S, back, sizeof(back)) == WH_ERROR_OK &&
              memcmp(back, data, sizeof(back)) == 0,
          "the bytes read back");
    check(wt_port_flash_blank_check(FWU_S, sizeof(data)) == WH_ERROR_NOTBLANK,
          "a programmed range is not blank");
    check(wt_port_flash_program(FWU_S, data, WT_FLASH_PROGRAM_UNIT) ==
              WH_ERROR_ABORTED,
          "a reprogram of a programmed double-word fails");
    check((g_wt_flash_first_err_sr & SR_ERRORS) == SR_PROGERR,
          "the first error recorded is PROGERR");
    check(clean_after(), "the failed program relocked the controller");
}

static void case_erase(void)
{
    uintptr_t base = FWU_NS + SECTOR;
    uint32_t pages = wt_l5_model_page_erases();
    uint32_t p;
    int exact = 1;

    printf(" case: erase\n");
    check(wt_port_flash_erase(FWU_S + SECTOR, SECTOR) == WH_ERROR_OK,
          "a sector erase succeeds");
    check(wt_l5_model_page_erases() - pages == SECTOR / PAGE,
          "a sector is four page erases");
    for (p = 0u; p < SECTOR / PAGE; p++) {
        exact &= wt_l5_model_page_erased(base + p * PAGE) == 1u;
    }
    check(exact && wt_l5_model_page_erased(base - PAGE) == 0u &&
              wt_l5_model_page_erased(base + SECTOR) == 0u,
          "exactly the sector's four pages of bank 2 were erased");
    check(wt_l5_model_page_erased(base - WT_FLASH_BANK_SIZE) == 0u,
          "bank 1's page of the same number was not erased");
    check(fa_sector_erases(FWU_S + SECTOR) == 1u,
          "the array saw one sector erase");
    check(wt_port_flash_blank_check(FWU_S + SECTOR, SECTOR) == WH_ERROR_OK,
          "the sector is blank");
    check(clean_after(), "PER cleared and the controller relocked");

    wt_l5_model_protect_page(FWU_NS + 2u * SECTOR + 2u * PAGE);
    g_wt_flash_first_err_sr = 0u;
    check(wt_port_flash_erase(FWU_S + 2u * SECTOR, SECTOR) == WH_ERROR_ABORTED,
          "an erase over a write-protected page fails");
    check((g_wt_flash_first_err_sr & SR_ERRORS) == SR_WRPERR,
          "the first error recorded is WRPERR");
    check(wt_l5_model_page_erased(FWU_NS + 2u * SECTOR + 3u * PAGE) == 0u,
          "the erase stopped at the protected page");
    check(clean_after(), "the failed erase relocked the controller");
    wt_l5_model_reset();
}

static void case_ecc(void)
{
    uint8_t back[32];
    uint32_t i;
    int zero = 1;

    printf(" case: ECC containment\n");
    wt_l5_model_ecc_bad(FWU_S + 3u * SECTOR + 0x10u, 8u);
    (void)memset(back, 0x5A, sizeof(back));
    check(wt_port_flash_read(FWU_S + 3u * SECTOR, back, sizeof(back)) ==
              WH_ERROR_ABORTED,
          "a double ECC error inside the read is contained and fails it");
    for (i = 0u; i < sizeof(back); i++) {
        zero &= back[i] == 0u;
    }
    check(zero, "the aborted read returned no flash bytes");
    check(wt_l5_model_irq_depth() == 0, "the read restored interrupts");
    check(wt_port_flash_read(FWU_S + 4u * SECTOR, back, sizeof(back)) ==
              WH_ERROR_OK,
          "the next read elsewhere succeeds");

    wt_l5_model_swap_bank(1);
    check(wt_port_flash_read(FWU_S + 3u * SECTOR, back, sizeof(back)) ==
              WH_ERROR_ABORTED,
          "under SWAP_BANK the swapped bank number still names the window");
    check(wt_port_flash_erase(FWU_S + 5u * SECTOR, SECTOR) == WH_ERROR_OK &&
              wt_l5_model_page_erased(FWU_NS + 5u * SECTOR) == 1u &&
              wt_l5_model_page_erased(FWU_NS + 5u * SECTOR -
                                      WT_FLASH_BANK_SIZE) == 0u,
          "under SWAP_BANK the erase still lands on the addressed page");
    wt_l5_model_swap_bank(0);
    wt_l5_model_ecc_bad(0u, 0u);

    wt_l5_model_ecc_stale(1);
    check(wt_port_flash_read(FWU_S + 4u * SECTOR, back, sizeof(back)) ==
              WH_ERROR_OK,
          "a corrected error (ECCC alone) does not fail the read");
    wt_l5_model_ecc_stale(0);
    wt_l5_model_ecc_bad(FWU_S + 6u * SECTOR, 8u);
    wt_l5_model_ecc_stale(1);
    check(wt_port_flash_read(FWU_S + 6u * SECTOR, back, 8u) == WH_ERROR_ABORTED,
          "a stale ECCC does not hide an in-window double error");
    wt_l5_model_reset();
}

static void case_bounded(void)
{
    uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    printf(" case: bounded waits and refusals\n");
    wt_l5_model_keys_ignored(1);
    check(wt_port_flash_program(FWU_S + 7u * SECTOR, data, sizeof(data)) ==
              WH_ERROR_ABORTED &&
              fa_blank(FWU_S + 7u * SECTOR, sizeof(data)) == FA_OK,
          "a controller that stays locked refuses the program untouched");
    wt_l5_model_reset();
    wt_l5_model_busy(1);
    check(wt_port_flash_erase(FWU_S + 7u * SECTOR, SECTOR) == WH_ERROR_ABORTED,
          "a controller held busy fails the erase after a bounded wait");
    wt_port_flash_quiesce();
    check(wt_l5_model_busy_cr_writes() == 0u,
          "no SECCR write is issued while the controller stays busy");
    wt_l5_model_reset();
    wt_l5_model_busy(2);
    check(wt_port_flash_program(FWU_S + 7u * SECTOR, data, sizeof(data)) ==
              WH_ERROR_ABORTED && wt_l5_model_irq_depth() == 0,
          "a program that never completes fails and restores interrupts");
    wt_port_flash_quiesce();
    check(wt_l5_model_busy_cr_writes() == 0u,
          "the timed-out program and quiesce leave SECCR alone while busy");
    wt_l5_model_reset();
    wt_l5_model_busy(2);
    check(wt_port_flash_erase(FWU_S + 7u * SECTOR, SECTOR) == WH_ERROR_ABORTED &&
              wt_l5_model_irq_depth() == 0 &&
              wt_l5_model_busy_cr_writes() == 0u,
          "an erase that never completes fails without a busy SECCR write");
    wt_l5_model_reset();
    wt_l5_model_icache_stuck(1);
    check(wt_port_flash_erase(FWU_S + 8u * SECTOR, SECTOR) == WH_ERROR_ABORTED,
          "an ICACHE invalidate that never completes fails the erase");
    wt_l5_model_reset();
    check(wt_port_flash_program(FWU_S + 9u * SECTOR, data, sizeof(data)) ==
              WH_ERROR_OK,
          "the controller programs again once released");
    wt_port_flash_quiesce();
    check(wt_l5_model_locked(), "quiesce leaves the controller locked");
}

static void case_tamper(void)
{
    uintptr_t g0 = WT_GUEST0_FLASH_BASE;
    uint8_t* sector;
    uint32_t pages_erased = 0u;
    uint32_t blank = 1u;
    uint32_t i;

    printf(" case: remeasure tamper through the Non-secure controller\n");
    check(wt_port_flash_probe_tamper(g0 + PAGE) == WH_ERROR_BADARGS,
          "an address off a sector boundary is refused");
    sector = fa_map(WT_FLASH_TO_S_ALIAS(g0), SECTOR);
    check(sector != NULL, "guest 0's first sector is mapped");
    if (sector == NULL) {
        return;
    }
    memset(sector, 0x5A, SECTOR);
    check(wt_port_flash_probe_tamper(g0) == WH_ERROR_OK, "the tamper runs");
    for (i = 0u; i < SECTOR / PAGE; i++) {
        pages_erased += (wt_l5_model_page_erased(g0 + i * PAGE) == 1u) ? 1u : 0u;
    }
    for (i = WT_FLASH_PROGRAM_UNIT; i < SECTOR; i++) {
        blank &= (sector[i] == 0xFFu) ? 1u : 0u;
    }
    check(pages_erased == SECTOR / PAGE && blank == 1u,
          "every page of guest 0's first sector was erased");
    check(sector[0] == 0u && sector[7] == 0u,
          "the sector's first double-word was zeroed");
    check(wt_l5_model_page_erased(g0 + SECTOR) == 0u,
          "the page after the sector was left alone");
    check(wt_l5_model_locked(), "the Secure controller was never unlocked");
    wt_l5_model_reset();
    wt_l5_model_busy(2);
    check(wt_port_flash_probe_tamper(g0) == WH_ERROR_ABORTED &&
              wt_l5_model_irq_depth() == 0 &&
              wt_l5_model_busy_cr_writes() == 0u,
          "a tamper erase that never completes fails without a busy NSCR write");
    wt_l5_model_reset();
    sector = fa_map(WT_FLASH_TO_S_ALIAS(g0), SECTOR);
    if (sector != NULL) {
        memset(sector, 0x5A, SECTOR);
    }
    wt_l5_model_keys_ignored(1);
    check(wt_port_flash_probe_tamper(g0) == WH_ERROR_ABORTED &&
              sector != NULL && sector[0] == 0x5Au && sector[SECTOR - 1u] == 0x5Au &&
              wt_l5_model_page_erased(g0) == 0u &&
              wt_l5_model_locked_cr_writes() == 0u,
          "a Non-secure controller that stays locked refuses the tamper untouched");
    wt_l5_model_reset();
}

int main(void)
{
    printf("RUN: unit/stm32l562_flash\n");
    wt_l5_model_reset();
    case_program();
    case_erase();
    case_ecc();
    case_bounded();
    case_tamper();
    if (g_failed != 0) {
        printf("FAIL: unit/stm32l562_flash (%d checks failed)\n", g_failed);
        return 1;
    }
    printf("PASS: unit/stm32l562_flash\n");
    return 0;
}
