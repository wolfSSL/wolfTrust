/* armv8m.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFTRUST_ARCH_ARMV8M_ARMV8M_H
#define WOLFTRUST_ARCH_ARMV8M_ARMV8M_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Armv8-M-private, shared by the arch layer and the Cortex-M ports. */

/* PMSAv8: RBAR[2:1] = AP, RBAR[0] = XN, RLAR[3:1] = MAIR index. */
#define WT_MPU_RBAR_XN       (1u << 0)
#define WT_MPU_RBAR_AP_RW    (0u << 1)   /* privileged RW, no access from unpriv */
#define WT_MPU_RBAR_AP_RWRW  (1u << 1)   /* RW from any priv level */
#define WT_MPU_RBAR_AP_RO    (2u << 1)   /* privileged RO, no access from unpriv */
#define WT_MPU_RBAR_AP_RORO  (3u << 1)   /* RO from any priv level */
#define WT_MPU_RBAR_SH_INNER (3u << 3)

#define WT_MPU_RLAR_EN       (1u << 0)
#define WT_MPU_RLAR_ATTRIDX_NORMAL  (0u << 1)  /* MAIR[0] = normal memory */
#define WT_MPU_RLAR_ATTRIDX_DEVICE  (1u << 1)  /* MAIR[1] = device memory */
#define WT_MPU_RLAR_ATTRIDX_NOCACHE (2u << 1)  /* MAIR[2] = normal non-cacheable */

/* Inclusive 32-byte-aligned bounds. */
typedef struct wt_armv8m_sau_region {
    uint32_t base;
    uint32_t limit;
    bool nsc;
} wt_armv8m_sau_region_t;

typedef struct wt_armv8m_mpu_region {
    uintptr_t base;
    uintptr_t limit;
    uint32_t rbar_flags;
    uint32_t rlar_flags;
} wt_armv8m_mpu_region_t;

void wt_armv8m_sau_init(const wt_armv8m_sau_region_t* regions, size_t count);
/* Reprogram or (enable=false) disable one SAU region at runtime, SAU left on;
 * bounds are inclusive and 32-byte aligned. Used for per-dispatch guest RAM
 * isolation on ports where the CPU's attribution is the isolation layer. */
void wt_armv8m_sau_program_region(uint32_t rnr, uint32_t base,
                                  uint32_t limit_inclusive, bool nsc,
                                  bool enable);
/* PRIVDEFENA off; wt_arch_restore_spm_domain() replays this table. */
void wt_armv8m_mpu_s_init(const wt_armv8m_mpu_region_t* whitelist,
                          size_t count);

/* Exception-return path back to the Non-secure guest after an SVC. */
void wt_armv8m_svc_guest_return(void) __attribute__((noreturn));

void wt_armv8m_note_fault_address(uintptr_t fault_address);
void wt_armv8m_note_fault(uintptr_t fault_address, uintptr_t pc);
/* Branched to from the naked MemManage, UsageFault, and SecureFault vectors. */
void wt_armv8m_tasklet_fault_entry(void);

#endif /* WOLFTRUST_ARCH_ARMV8M_ARMV8M_H */
