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
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/sched/coroutine.h"

#define WT_SPMC_UNKNOWN_FID (WT_FFA_FID32_LAST - 0xFu)
#define WT_SPMC_BOOT_INFO_LIMIT 4096u
#define WT_SPMC_MAX_FILL 12u

extern uint8_t _e_secure_text[];
extern uint8_t __image_end[];
extern uint8_t __spm_ram_end[];
extern uint8_t _e_keystore[];

void wt_spm_main(uint64_t boot_info_pa);
int wt_spm_prove_tick(void);

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

static void pack_chars(wt_ffa_regs_t* r, const char* text, unsigned int count,
                       unsigned int per_reg)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    for (i = 0u; i < count; i++) {
        r->x[2u + (i / per_reg)] |= (uint64_t)(uint8_t)text[i]
                                    << (8u * (i % per_reg));
    }
    r->x[1] = count;
}

/* 13.12 at the Secure physical instance: both conventions log through the
 * SPMD, and the count rules are enforced. */
static void prove_console_log(void)
{
    static const char msg32[] = "[SPM] console32 ok\r\n";
    static const char msg64[] = "[SPM] console64 ok\r\n";
    wt_ffa_regs_t r;

    ffa_call(&r, WT_FFA_CONSOLE_LOG32, 0u);
    if ((uint32_t)r.x[0] != WT_FFA_ERROR ||
        (int32_t)(uint32_t)r.x[2] != WT_FFA_INVALID_PARAMETERS) {
        spmc_fail("console_log count 0", r.x[0]);
    }
    ffa_call(&r, WT_FFA_CONSOLE_LOG32, 25u);
    if ((uint32_t)r.x[0] != WT_FFA_ERROR ||
        (int32_t)(uint32_t)r.x[2] != WT_FFA_INVALID_PARAMETERS) {
        spmc_fail("console_log count 25", r.x[0]);
    }
    pack_chars(&r, msg32, (unsigned int)(sizeof(msg32) - 1u), 4u);
    r.x[0] = WT_FFA_CONSOLE_LOG32;
    wt_ffa_smc(&r);
    if ((uint32_t)r.x[0] != WT_FFA_SUCCESS32) {
        spmc_fail("console_log32", r.x[0]);
    }
    pack_chars(&r, msg64, (unsigned int)(sizeof(msg64) - 1u), 8u);
    r.x[0] = WT_FFA_CONSOLE_LOG64;
    wt_ffa_smc(&r);
    if ((uint32_t)r.x[0] != WT_FFA_SUCCESS32) {
        spmc_fail("console_log64", r.x[0]);
    }
}

static uintptr_t page_up(uintptr_t v)
{
    return (v + WT_TABLES_PAGE_SIZE - 1u) & ~(uintptr_t)(WT_TABLES_PAGE_SIZE - 1u);
}

/* SPM-only table (ASID 0): image text, constant data, the SPM RAM band
 * (data, bss, stacks), the keystore band, the boot information page, the
 * table pool, the board devices. */
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

    fill[n].base = (uintptr_t)WT_SPM_IMAGE_PA;
    fill[n].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    n++;
    fill[n].base = (uintptr_t)_e_secure_text;
    fill[n].size = page_up((uintptr_t)__image_end) - (uintptr_t)_e_secure_text;
    fill[n].attributes = WT_MEM_ATTR_READ;
    n++;
    fill[n].base = (uintptr_t)WT_SPM_RAM_PA;
    fill[n].size = page_up((uintptr_t)__spm_ram_end) - (uintptr_t)WT_SPM_RAM_PA;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    n++;
    fill[n].base = (uintptr_t)WT_SPM_KEYSTORE_PA;
    fill[n].size = page_up((uintptr_t)_e_keystore) - (uintptr_t)WT_SPM_KEYSTORE_PA;
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

/* Prove the S-EL1 coroutine switch: run a privileged coroutine that yields
 * back, resumes, and yields again, checking its progress each time. */
static uint8_t g_prove_co_stack[4096] __attribute__((aligned(16)));
static volatile int g_prove_co_step;

static void prove_co_body(void* arg)
{
    g_prove_co_step = (int)(intptr_t)arg;
    wt_co_block();
    g_prove_co_step = 99;
    wt_co_block();
}

static int prove_coroutine(void)
{
    wt_co_t* co;

    wt_co_init();
    co = wt_co_create_blocked_ex(g_prove_co_stack, sizeof(g_prove_co_stack),
                                 prove_co_body, (void*)(intptr_t)7);
    if (co == NULL) {
        return 0;
    }
    wt_co_wake(co);
    if (wt_co_run(co) != 1u || g_prove_co_step != 7) {
        return 0;
    }
    wt_co_wake(co);
    if (wt_co_run(co) != 1u || g_prove_co_step != 99) {
        return 0;
    }
    return 1;
}

void wt_spm_main(uint64_t boot_info_pa)
{
    wt_ffa_regs_t r;

    wt_el3_puts("[SPM] spmc entered at S-EL1\r\n");
    consume_boot_info(boot_info_pa);
    enable_mmu(boot_info_pa);
    if (wt_spm_prove_tick()) {
        wt_el3_puts("[SPM] tick ok intid=29\r\n");
    }
    else {
        wt_el3_puts("[SPM] tick TIMEOUT\r\n");
    }
    if (prove_coroutine()) {
        wt_el3_puts("[SPM] coroutine ok\r\n");
    }
    else {
        wt_el3_puts("[SPM] coroutine FAIL\r\n");
    }
    discover_spmd();
    prove_console_log();
    wt_platform_console_flush();

    /* Initialization complete; the SPMD owns the CPU until the first event. */
    ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    spmc_fail("msg_wait returned", r.x[0]);
}

/* Nothing to run on the Secure side: every event the SPMD delivers is
 * reported until the Secure virtual instance dispatches them. */
void wt_spm_idle(void)
{
    wt_ffa_regs_t r;

    wt_platform_console_flush();
    ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    for (;;) {
        wt_el3_puts("[SPM] unexpected event x0=0x");
        wt_el3_puthex(r.x[0], 8u);
        wt_el3_puts("\r\n");
        ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    }
}
