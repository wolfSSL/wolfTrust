/* mock_l5_flash.h
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

/* Force-included ahead of the driver: the real register and memory map
 * headers supply every offset and bit, then register accesses route through
 * the controller model in main.c and the flash moves to host memory. */
#ifndef WT_TEST_MOCK_L5_FLASH_H
#define WT_TEST_MOCK_L5_FLASH_H

#include <stdint.h>

#include "stm32l562_regs.h"
#include "memory_map.h"

volatile uint32_t* wt_mock_reg(uintptr_t address);
void wt_host_barrier(void);
uint32_t wt_host_irq_save(void);
void wt_host_cpsid(void);
void wt_host_irq_restore(uint32_t primask);
void wt_host_wfi(void);
uint8_t wt_host_flash_read8(const volatile uint8_t *p);

#undef WT_REG32
#define WT_REG32(address) (*wt_mock_reg((uintptr_t)(address)))

/* The flash is a host array seen through the Secure alias; its Non-secure
 * alias is the same array 0x04000000 lower, which the driver only computes
 * with (the build rewrites its alias mask as that subtraction). */
extern uint8_t g_l5_flash[];
#define WT_MOCK_HOST(real) \
    ((uintptr_t)&g_l5_flash[(uintptr_t)(real) - WT_FLASH_S_ALIAS_BASE])

enum {
    WT_MOCK_REAL_NVM_S = WT_HSM_NVM_FLASH_BASE_S,
    WT_MOCK_REAL_CONF_S = WT_CONF_NVM_FLASH_BASE_S,
    WT_MOCK_REAL_FWU_S = WT_FWU_UPDATE_FLASH_BASE_S
};

#undef WT_FLASH_NS_BASE
#undef WT_HSM_NVM_FLASH_BASE_S
#undef WT_CONF_NVM_FLASH_BASE_S
#undef WT_FWU_UPDATE_FLASH_BASE_S
#define WT_FLASH_NS_BASE            ((uintptr_t)g_l5_flash - 0x04000000u)
#define WT_HSM_NVM_FLASH_BASE_S     WT_MOCK_HOST(WT_MOCK_REAL_NVM_S)
#define WT_CONF_NVM_FLASH_BASE_S    WT_MOCK_HOST(WT_MOCK_REAL_CONF_S)
#define WT_FWU_UPDATE_FLASH_BASE_S  WT_MOCK_HOST(WT_MOCK_REAL_FWU_S)

#endif /* WT_TEST_MOCK_L5_FLASH_H */
