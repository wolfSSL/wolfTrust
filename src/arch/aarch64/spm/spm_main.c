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
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/boot.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/manifest.h"
#include "wolftrust/sched/coroutine.h"

const wt_system_manifest_t* wt_generated_manifest_get(void);

#define WT_SPMC_UNKNOWN_FID (WT_FFA_FID32_LAST - 0xFu)
#define WT_SPMC_BOOT_INFO_LIMIT 4096u
#define WT_SPMC_MAX_FILL 24u

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

uintptr_t g_wt_spm_echo_stack_base;
uintptr_t g_wt_spm_echo_stack_size;

/* Manifest partition stacks sit one WT_SPMC_STACK_STRIDE apart; the test echo
 * partition takes the next slot, published as a shareable fill entry so its
 * own table maps it EL0 while every other table keeps it EL1-only. */
#define WT_SPMC_STACK_STRIDE 0x10000u

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
static size_t add_echo_band(wt_memory_region_t* fill, size_t n,
                            uintptr_t last_base, uintptr_t band_size)
{
    if ((band_size == 0u) || (n >= WT_SPMC_MAX_FILL)) {
        return n;
    }
    g_wt_spm_echo_stack_base = last_base + WT_SPMC_STACK_STRIDE;
    g_wt_spm_echo_stack_size = band_size;
    fill[n].base = g_wt_spm_echo_stack_base;
    fill[n].size = (size_t)band_size;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_DOMAIN_FILL_SHARED;
    return n + 1u;
}
#else
static size_t add_echo_band(wt_memory_region_t* fill, size_t n,
                            uintptr_t last_base, uintptr_t band_size)
{
    (void)fill;
    (void)last_base;
    (void)band_size;
    return n;
}
#endif

static void enable_mmu(uint64_t boot_info_pa)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    wt_memory_region_t* fill = g_fill;
    const wt_memory_region_t* devices;
    size_t device_count = 0u;
    size_t n = 0u;
    size_t i;
    uint64_t ttbr0;
    uintptr_t last_base = 0u;
    uintptr_t band_size = 0u;

    /* Shareable entries: a partition whose manifest region covers one takes
     * it over (EL0 + EL1); the SPM RAM band, boot page, pool, and devices
     * stay EL1-only in every table. */
    fill[n].base = (uintptr_t)WT_SPM_IMAGE_PA;
    fill[n].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC | WT_DOMAIN_FILL_SHARED;
    n++;
    fill[n].base = (uintptr_t)_e_secure_text;
    fill[n].size = page_up((uintptr_t)__image_end) - (uintptr_t)_e_secure_text;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_DOMAIN_FILL_SHARED;
    n++;
    fill[n].base = (uintptr_t)WT_SPM_RAM_PA;
    fill[n].size = page_up((uintptr_t)__spm_ram_end) - (uintptr_t)WT_SPM_RAM_PA;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
#if defined(WT_TABLES_NEGATIVE) && (WT_TABLES_NEGATIVE == 1)
    /* A writable+executable region must be refused at build (W^X), panicking
     * through wt_domain_fail before any partition initializes. */
    fill[n].attributes |= WT_MEM_ATTR_EXEC;
#endif
    n++;
    fill[n].base = (uintptr_t)WT_SPM_KEYSTORE_PA;
    fill[n].size = page_up((uintptr_t)_e_keystore) - (uintptr_t)WT_SPM_KEYSTORE_PA;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_DOMAIN_FILL_SHARED;
    n++;
    /* Partition stack bands from the manifest: the SPMC seeds and scrubs
     * them from EL1, the owning partition maps its own at EL0. */
    for (i = 0u; (i < manifest->domain_count) && (n < WT_SPMC_MAX_FILL); i++) {
        const wt_domain_descriptor_t* d = &manifest->domains[i];

        if (d->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION) {
            continue;
        }
        fill[n].base = d->stack_base & ~(uintptr_t)(WT_TABLES_PAGE_SIZE - 1u);
        fill[n].size = page_up(d->stack_base + d->stack_size) - fill[n].base;
        fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_DOMAIN_FILL_SHARED;
        if (fill[n].base > last_base) {
            last_base = fill[n].base;
            band_size = (uintptr_t)fill[n].size;
        }
        n++;
    }
    n = add_echo_band(fill, n, last_base, band_size);
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

/* Prove the S-EL0 path: an unprivileged coroutine confined to the shared
 * text band and one partition band runs at EL0, yields through SVC with a
 * token, resumes after the SVC, and yields again. */
extern void wt_sp_el0_probe(void);
static wt_secure_domain_t g_el0_domain;

static const wt_domain_descriptor_t* first_partition_domain(void)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    size_t i;

    for (i = 0u; i < manifest->domain_count; i++) {
        if (manifest->domains[i].domain_class == WT_DOMAIN_CLASS_SECURE_PARTITION) {
            return &manifest->domains[i];
        }
    }
    return NULL;
}

static int prove_el0(void)
{
    const wt_domain_descriptor_t* d = first_partition_domain();
    uint8_t* stack;
    wt_co_t* co;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)(uintptr_t)d->stack_base;
    g_el0_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_el0_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_el0_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_el0_domain.regions[1].base = (uintptr_t)stack;
    g_el0_domain.regions[1].size = (size_t)d->stack_size;
    g_el0_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_el0_domain.region_count = 2u;
    co = wt_co_create_blocked_ex(stack, (size_t)d->stack_size,
                                 (wt_co_entry_fn)wt_sp_el0_probe, (void*)0x11);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_el0_domain, 1u);
    wt_co_wake(co);
    if (wt_co_run(co) != 1u || wt_spm_yield_token() != 0x5Au) {
        return 0;
    }
    wt_co_wake(co);
    if (wt_co_run(co) != 1u || wt_spm_yield_token() != 0xA5u) {
        return 0;
    }
    return 1;
}

/* Prove FF-A direct messaging at the Secure virtual instance: an S-EL0 echo
 * partition parks in FFA_MSG_WAIT, is delivered two direct requests in turn
 * through its saved frame, and answers each by FFA_MSG_SEND_DIRECT_RESP32
 * with the ids swapped and the payload word complemented. */
static wt_secure_domain_t g_echo_domain;

static int prove_ffa_direct(void)
{
    static const uint32_t first[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        0x5A5A00FFu, 0u, 0u, 0u, 0u
    };
    static const uint32_t second[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        0x0000C3C3u, 0u, 0u, 0u, 0u
    };
    const wt_domain_descriptor_t* d = first_partition_domain();
    uint64_t req[8];
    uint64_t resp[8];
    uint8_t* stack;
    wt_co_t* co;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)(uintptr_t)d->stack_base;
    g_echo_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_echo_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_echo_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_echo_domain.regions[1].base = (uintptr_t)stack;
    g_echo_domain.regions[1].size = (size_t)d->stack_size;
    g_echo_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_echo_domain.region_count = 2u;
    co = wt_co_create_blocked_ex(stack, (size_t)d->stack_size,
                                 (wt_co_entry_fn)wt_sp_ffa_echo, (void*)0);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_echo_domain, 1u);
    wt_co_wake(co);
    if (wt_co_run(co) != 1u || wt_co_state(co) != WT_CO_BLOCKED) {
        return 0;
    }

    wt_ffa_direct_build(req, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, first);
    if (wt_spm_ffa_direct_deliver((struct wt_co*)co, req, resp) != 0) {
        return 0;
    }
    if (((uint32_t)resp[0] != WT_FFA_MSG_SEND_DIRECT_RESP32) ||
        (wt_ffa_direct_sender(resp[1]) != WT_FFA_ID_SP_FIRST) ||
        (wt_ffa_direct_receiver(resp[1]) != WT_FFA_ID_NS_PRIMARY) ||
        ((uint32_t)resp[2] != 0u) ||
        ((uint32_t)resp[3] != (uint32_t)~first[0])) {
        return 0;
    }

    wt_ffa_direct_build(req, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, second);
    if (wt_spm_ffa_direct_deliver((struct wt_co*)co, req, resp) != 0) {
        return 0;
    }
    if (((uint32_t)resp[0] != WT_FFA_MSG_SEND_DIRECT_RESP32) ||
        ((uint32_t)resp[3] != (uint32_t)~second[0]) ||
        (wt_co_state(co) != WT_CO_BLOCKED)) {
        return 0;
    }
    return 1;
}

/* Prove asynchronous preemption: an S-EL0 partition that never yields is
 * entered with the secure timer armed, taken by a Group 0 tick mid-spin, and
 * left runnable (not blocked or faulted) so the scheduler could resume it. */
static wt_secure_domain_t g_spin_domain;

static int prove_preempt(void)
{
    const wt_domain_descriptor_t* d = first_partition_domain();
    uint8_t* stack;
    wt_co_t* co;
    int preempted;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)(uintptr_t)d->stack_base;
    g_spin_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_spin_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_spin_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_spin_domain.regions[1].base = (uintptr_t)stack;
    g_spin_domain.regions[1].size = (size_t)d->stack_size;
    g_spin_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_spin_domain.region_count = 2u;
    co = wt_co_create_blocked_ex(stack, (size_t)d->stack_size,
                                 (wt_co_entry_fn)wt_sp_spin, (void*)0);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_spin_domain, 1u);
    wt_co_wake(co);
    wt_spm_preempt_timer_arm();
    (void)wt_co_run(co);
    wt_spm_preempt_timer_stop();
    preempted = (wt_co_state(co) == WT_CO_RUNNABLE) ? 1 : 0;
    wt_co_mark_faulted(co);
    return preempted;
}

uint32_t wt_spm_prove_sint(void);

void wt_spm_main(uint64_t boot_info_pa)
{
    wt_ffa_regs_t r;
    uint32_t sint_id;

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
    if (prove_el0()) {
        wt_el3_puts("[SPM] el0 svc ok\r\n");
    }
    else {
        wt_el3_puts("[SPM] el0 svc FAIL\r\n");
    }
    if (prove_ffa_direct()) {
        wt_el3_puts("[SPM] ffa direct ok\r\n");
    }
    else {
        wt_el3_puts("[SPM] ffa direct FAIL\r\n");
    }
    if (prove_preempt()) {
        wt_el3_puts("[SPM] preempt ok\r\n");
    }
    else {
        wt_el3_puts("[SPM] preempt FAIL\r\n");
    }
    sint_id = wt_spm_prove_sint();
    if (sint_id != 0u) {
        wt_el3_puts("[SPM] sint gic ok intid=0x");
        wt_el3_puthex(sint_id, 2u);
        wt_el3_puts("\r\n");
    }
    else {
        wt_el3_puts("[SPM] sint gic FAIL\r\n");
    }
    discover_spmd();
    prove_console_log();
    wt_platform_console_flush();

    /* The neutral core takes over: partitions, services, then the FF-A
     * idle through wt_spm_idle when no Normal world is runnable. */
    g_wt_spm_partitions_live = 1u;
    wt_boot_run();

    ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    spmc_fail("boot_run returned", r.x[0]);
}

/* Nothing to run on the Secure side: every event the SPMD delivers is
 * reported until the Secure virtual instance dispatches them. */
/* A direct request the SPMD relayed from the Normal world: validate it at the
 * NS-physical instance, deliver it to the waiting receiver, and send the
 * partition's response back with FFA_MSG_SEND_DIRECT_RESP32; that SMC's
 * return is the next event. A request no partition can take is answered with
 * FFA_ERROR instead. */
static void direct_request(wt_ffa_regs_t* r)
{
    uint64_t resp[8];
    struct wt_co* co = NULL;
    uint16_t receiver = wt_ffa_direct_receiver(r->x[1]);
    int ret = wt_ffa_direct_req_check(r->x, WT_FFA_INSTANCE_NS_PHYSICAL);
    unsigned int i;

    wt_el3_puts("[SPM] direct req from=0x");
    wt_el3_puthex(wt_ffa_direct_sender(r->x[1]), 4u);
    wt_el3_puts(" to=0x");
    wt_el3_puthex(receiver, 4u);
    wt_el3_puts("\r\n");
    if (ret == 0) {
        if (receiver == WT_FFA_ID_ECHO) {
            co = wt_spm_ffa_echo_partition();
        }
        ret = (co != NULL) ? wt_spm_ffa_direct_deliver(co, r->x, resp) : WT_FFA_BUSY;
    }
    if (ret == 0) {
        for (i = 0u; i < 8u; i++) {
            r->x[i] = resp[i];
        }
    }
    else {
        for (i = 0u; i < 8u; i++) {
            r->x[i] = 0u;
        }
        r->x[0] = WT_FFA_ERROR;
        r->x[2] = (uint64_t)(uint32_t)ret;
    }
    wt_platform_console_flush();
    wt_ffa_smc(r);
}

void wt_spm_idle(void)
{
    wt_ffa_regs_t r;

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
    /* With every partition initialized and waiting, route the test Secure
     * interrupt to the echo partition (signalled, then queued) before idling. */
    wt_spm_prove_sint_route(wt_spm_ffa_echo_partition());
#endif
    wt_platform_console_flush();
    ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    for (;;) {
        if ((uint32_t)r.x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32) {
            direct_request(&r);
            continue;
        }
        wt_el3_puts("[SPM] unexpected event x0=0x");
        wt_el3_puthex(r.x[0], 8u);
        wt_el3_puts("\r\n");
        ffa_call(&r, WT_FFA_MSG_WAIT, 0u);
    }
}
