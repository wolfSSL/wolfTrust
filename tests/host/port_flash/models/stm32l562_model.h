/* stm32l562_model.h
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

#ifndef WT_TEST_STM32L562_MODEL_H
#define WT_TEST_STM32L562_MODEL_H

#include <stdint.h>

volatile uint32_t* wt_mock_flash_reg(uint32_t offset);
volatile uint32_t* wt_mock_icache_reg(uint32_t offset);
uint8_t wt_mock_flash_rd8(uintptr_t address);
void wt_mock_flash_wr32(uintptr_t address, uint32_t value);
uint32_t wt_flash_model_irq_save(void);
void wt_flash_model_irq_restore(uint32_t primask);

void wt_l5_model_reset(void);
void wt_l5_model_ecc_bad(uintptr_t s_addr, uint32_t size);
void wt_l5_model_ecc_stale(int stale);
void wt_l5_model_fail_erases_with(uint32_t sr_bits);
void wt_l5_model_protect_page(uintptr_t ns_page);
void wt_l5_model_swap_bank(int swapped);
void wt_l5_model_icache_stuck(int stuck);
void wt_l5_model_busy(int mode);
uint32_t wt_l5_model_busy_cr_writes(void);
uint32_t wt_l5_model_locked_cr_writes(void);
void wt_l5_model_keys_ignored(int ignored);
int wt_l5_model_locked(void);
int wt_l5_model_pg_set(void);
uint32_t wt_l5_model_page_erases(void);
uint32_t wt_l5_model_page_erased(uintptr_t ns_page);
uint32_t wt_l5_model_sequence_errors(void);
uint32_t wt_l5_model_unmasked_array_accesses(void);
int wt_l5_model_irq_depth(void);

#endif /* WT_TEST_STM32L562_MODEL_H */
