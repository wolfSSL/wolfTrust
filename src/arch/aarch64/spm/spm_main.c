/* spm_main.c
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

/* SPMC entry at S-EL1: consume the FF-A boot information blob, negotiate
 * with the SPMD at the Secure physical instance, and complete
 * initialization with FFA_MSG_WAIT (5.5). The partitions arrive with the
 * tables and the SVC gate. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_boot_info.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/tables.h"

#define WT_SPMC_UNKNOWN_FID (WT_FFA_FID32_LAST - 0xFu)
#define WT_SPMC_BOOT_INFO_LIMIT 4096u
#define WT_SPMC_MAX_FILL 8u

extern uint8_t __data_lma[];

void wt_spm_main(uint64_t boot_info_pa);

/* The fill list outlives init: every partition table maps it EL1-only. */
static wt_memory_region_t g_fill[WT_SPMC_MAX_FILL];

static void spmc_fail(const char* what, uint64_t value)
{
    wt_el3_puts("[SPM] FAIL ");
    wt_el3_puts(what);
    wt_el3_puts(" x0=0x");
    wt_el3_puthex(value, 8u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
    (void)wt_mon_call(WT_MON_FID_PANIC, 0xF1u);
}

static void ffa_call(wt_ffa_regs_t* r, uint32_t fid, uint64_t x1)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = fid;
    r->x[1] = x1;
    wt_ffa_smc(r);
}

static void consume_boot_info(uint64_t boot_info_pa)
{
    const uint8_t* blob = (const uint8_t*)(uintptr_t)boot_info_pa;
    wt_ffa_boot_info_t info;
    wt_ffa_boot_info_desc_t desc;
    uint64_t handoff = 0u;
    int ret;

    ret = wt_ffa_boot_info_parse(blob, boot_info_pa, WT_SPMC_BOOT_INFO_LIMIT, &info);
    if (ret != WT_FFA_BOOT_INFO_OK) {
        spmc_fail("boot info", (uint64_t)(uint32_t)ret);
    }
    if (wt_ffa_boot_info_find(blob, &info, WT_FFA_BOOT_INFO_TYPE_WT_HANDOFF, &desc) ==
        WT_FFA_BOOT_INFO_OK) {
        handoff = desc.contents;
    }
    wt_el3_puts("[SPM] boot info ok descs=");
    wt_el3_putdec(info.desc_count);
    wt_el3_puts(" handoff=0x");
    wt_el3_puthex(handoff, 8u);
    wt_el3_puts("\r\n");
}

static void discover_spmd(void)
{
    wt_ffa_regs_t r;

    ffa_call(&r, WT_FFA_VERSION, WT_FFA_VERSION_1_2);
    if ((uint32_t)r.x[0] != WT_FFA_VERSION_1_2) {
        spmc_fail("ffa version", r.x[0]);
    }
    wt_el3_puts("[SPM] ffa version 1.2 negotiated\r\n");

    ffa_call(&r, WT_FFA_ID_GET, 0u);
    if (((uint32_t)r.x[0] != WT_FFA_SUCCESS32) || (r.x[2] != WT_FFA_ID_SPMC)) {
        spmc_fail("ffa id_get", r.x[0]);
    }
    ffa_call(&r, WT_FFA_SPM_ID_GET, 0u);
    if (((uint32_t)r.x[0] != WT_FFA_SUCCESS32) || (r.x[2] != WT_FFA_ID_SPMD)) {
        spmc_fail("ffa spm_id_get", r.x[0]);
    }
    ffa_call(&r, WT_FFA_FEATURES, WT_FFA_VERSION);
    if ((uint32_t)r.x[0] != WT_FFA_SUCCESS32) {
        spmc_fail("ffa features(version)", r.x[0]);
    }
    ffa_call(&r, WT_SPMC_UNKNOWN_FID, 0u);
    if (((uint32_t)r.x[0] != WT_FFA_ERROR) ||
        ((int32_t)(uint32_t)r.x[2] != WT_FFA_NOT_SUPPORTED)) {
        spmc_fail("ffa unknown fid", r.x[0]);
    }
    wt_el3_puts("[SPM] ffa discovery ok id=0x8000 spmd=0x8001\r\n");
}

static uintptr_t page_up(uintptr_t v)
{
    return (v + WT_TABLES_PAGE_SIZE - 1u) & ~(uintptr_t)(WT_TABLES_PAGE_SIZE - 1u);
}

/* SPM-only table (ASID 0): image text, the EL3 RAM band (data, bss,
 * stacks), the boot information page, the table pool, the board devices. */
void wt_domain_fail(int code)
{
    spmc_fail("domain", (uint64_t)(uint32_t)code);
}

static void enable_mmu(uint64_t boot_info_pa)
{
    wt_memory_region_t* fill = g_fill;
    const wt_memory_region_t* devices;
    size_t device_count = 0u;
    size_t n = 0u;
    size_t i;
    uint64_t ttbr0;

    fill[n].base = (uintptr_t)WT_EL3_TEXT_BASE;
    fill[n].size = page_up((uintptr_t)__data_lma) - (uintptr_t)WT_EL3_TEXT_BASE;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    n++;
    fill[n].base = (uintptr_t)WT_EL3_RAM_BASE;
    fill[n].size = (size_t)WT_EL3_RAM_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    n++;
    fill[n].base = (uintptr_t)boot_info_pa;
    fill[n].size = WT_TABLES_PAGE_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ;
    n++;
    fill[n].base = (uintptr_t)WT_SPM_TABLE_POOL_PA;
    fill[n].size = (size_t)WT_SPM_TABLE_POOL_PAGES * WT_TABLES_PAGE_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    n++;
    devices = wt_platform_board_device_regions(&device_count);
    for (i = 0u; (i < device_count) && (n < WT_SPMC_MAX_FILL); i++) {
        fill[n] = devices[i];
        n++;
    }

    ttbr0 = wt_domain_init(fill, n, (uint8_t*)(uintptr_t)WT_SPM_TABLE_POOL_PA,
                           WT_SPM_TABLE_POOL_PA,
                           (size_t)WT_SPM_TABLE_POOL_PAGES * WT_TABLES_PAGE_SIZE);
    if (ttbr0 == 0u) {
        spmc_fail("spm table", 0u);
    }
    wt_mmu_enable(ttbr0, WT_TABLES_MAIR_EL1, WT_TABLES_TCR_EL1);
    wt_el3_puts("[SPM] mmu on ttbr0=0x");
    wt_el3_puthex(ttbr0, 16u);
    wt_el3_puts(" pool_pages=");
    wt_el3_putdec(wt_domain_pool_pages_used());
    wt_el3_puts("\r\n");
}

void wt_spm_main(uint64_t boot_info_pa)
{
    wt_ffa_regs_t r;

    wt_el3_puts("[SPM] spmc entered at S-EL1\r\n");
    consume_boot_info(boot_info_pa);
    enable_mmu(boot_info_pa);
    discover_spmd();
    wt_platform_console_flush();

    /* Initialization complete; the SPMD owns the CPU until the first event. */
    ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    spmc_fail("msg_wait returned", r.x[0]);
}
