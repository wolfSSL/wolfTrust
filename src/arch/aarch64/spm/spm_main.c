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
#include "wolftrust/arch/aarch64/ffa_manifest.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"
#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/boot.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/manifest.h"
#include "wolftrust/sched/coroutine.h"

#include <string.h>

const wt_system_manifest_t* wt_generated_manifest_get(void);

#define WT_SPMC_UNKNOWN_FID (WT_FFA_FID32_LAST - 0xFu)
#define WT_SPMC_BOOT_INFO_LIMIT 4096u
#define WT_SPMC_MAX_FILL 32u
/* Non-secure window the SPMC maps EL1-only to reach a guest's psa_call buffers
 * (the guest image plus its stack live at WT_NS_IMAGE_PA). */
#ifndef WT_PSA_NS_WINDOW_SIZE
#define WT_PSA_NS_WINDOW_SIZE 0x00100000u
#endif

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

uintptr_t g_wt_spm_handoff_pa;
size_t g_wt_spm_handoff_size;

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
        g_wt_spm_handoff_pa = (uintptr_t)desc.contents;
        g_wt_spm_handoff_size = (size_t)desc.size;
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

#if defined(WT_SPM_ECHO_SP)
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

#if defined(WT_FFA_ACS) && (WT_FFA_ACS == 1)
/* Each native partition's memory is a shareable fill entry: its own table maps
 * it at EL0 with the listed permissions, every other table keeps it EL1-only
 * so the SPMC can seed its stack and reach its message buffers. */
static size_t add_native_bands(wt_memory_region_t* fill, size_t n)
{
    const wt_ffa_native_sp_t* list;
    size_t count = 0u;
    size_t i;
    size_t j;

    list = wt_platform_ffa_native_partitions(&count);
    for (i = 0u; (list != NULL) && (i < count); i++) {
        for (j = 0u; (j < list[i].region_count) && (n < WT_SPMC_MAX_FILL); j++) {
            fill[n].base = list[i].regions[j].base;
            fill[n].size = list[i].regions[j].size;
            fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                                 WT_DOMAIN_FILL_SHARED;
            n++;
        }
    }
    return n;
}
#else
static size_t add_native_bands(wt_memory_region_t* fill, size_t n)
{
    (void)fill;
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
    /* The FF-A RX/TX buffer band (7.2): the SPMC writes partition information
     * into it at S-EL1, and the discovering partition maps and reads it at
     * S-EL0, so it is shareable and taken over by that partition's table. */
    fill[n].base = (uintptr_t)WT_SPM_RXTX_PA;
    fill[n].size = (size_t)WT_SPM_RXTX_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_DOMAIN_FILL_SHARED;
    n++;
    /* The memory-sharing self-test page: the SPMC seeds it at S-EL1 and a
     * partition maps it at S-EL0 only through FFA_MEM_RETRIEVE_REQ. */
    fill[n].base = (uintptr_t)WT_SPM_SHARE_PA;
    fill[n].size = (size_t)WT_SPM_SHARE_SIZE;
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
    n = add_native_bands(fill, n);
    fill[n].base = (uintptr_t)boot_info_pa;
    fill[n].size = WT_TABLES_PAGE_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ;
    if (g_wt_spm_handoff_pa != 0u) {
        /* The handoff record rides in this page and is cleared once consumed. */
        fill[n].attributes |= WT_MEM_ATTR_WRITE;
    }
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
#if defined(WT_EL3_NS_SMOKE)
    /* A guest's psa_call buffers live in Non-secure RAM: map the window
     * EL1-only and Non-secure so the SPMC (never a partition) can copy them. */
    if (n < WT_SPMC_MAX_FILL) {
        fill[n].base = (uintptr_t)WT_NS_IMAGE_PA;
        fill[n].size = (size_t)WT_PSA_NS_WINDOW_SIZE;
        fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                             WT_TABLES_ATTR_NS;
        n++;
    }
#endif

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
    uint64_t req[WT_FFA_MSG_REGS_EXT];
    uint64_t resp[WT_FFA_MSG_REGS_EXT];
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

/* Prove FF-A partition discovery: an S-EL0 partition calls
 * FFA_PARTITION_INFO_GET with a Nil UUID, the SPMC writes a descriptor per
 * configured partition into the partition's RX buffer, and the partition reads
 * the count and the first descriptor's id back out at S-EL0. */
static wt_secure_domain_t g_discover_domain;

static int prove_partinfo(uint32_t* out_count)
{
    const wt_domain_descriptor_t* d = first_partition_domain();
    const wt_ffa_partition_manifest_t* parts;
    size_t np = 0u;
    uint8_t* stack;
    wt_co_t* co;
    uint64_t token;

    parts = wt_generated_ffa_partitions_get(&np);
    if ((d == NULL) || (parts == NULL) || (np == 0u)) {
        return 0;
    }
    stack = (uint8_t*)(uintptr_t)d->stack_base;
    g_discover_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_discover_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_discover_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_discover_domain.regions[1].base = (uintptr_t)stack;
    g_discover_domain.regions[1].size = (size_t)d->stack_size;
    g_discover_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_discover_domain.regions[2].base = (uintptr_t)WT_SPM_RXTX_PA;
    g_discover_domain.regions[2].size = (size_t)WT_SPM_RXTX_SIZE;
    g_discover_domain.regions[2].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_discover_domain.region_count = 3u;
    co = wt_co_create_blocked_ex(stack, (size_t)d->stack_size,
                                 (wt_co_entry_fn)wt_sp_ffa_discover,
                                 (void*)(uintptr_t)WT_SPM_RXTX_PA);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_discover_domain, 1u);
    wt_co_wake(co);
    if (wt_co_run(co) != 1u) {
        return 0;
    }
    token = wt_spm_yield_token();
    *out_count = (uint32_t)(token & 0xFFFFu);
    /* The partition read the first descriptor's id from its RX buffer at S-EL0;
     * the SPMC assigns ids from WT_FFA_ID_SP_FIRST in creation order. */
    if ((uint32_t)((token >> 16) & 0xFFFFu) != (uint32_t)WT_FFA_ID_SP_FIRST) {
        return 0;
    }
    return (*out_count == (uint32_t)np) ? 1 : 0;
}

/* Prove FF-A memory sharing end to end: the SPMC (owner) seeds the share page
 * and shares it to the borrower endpoint; an S-EL0 partition retrieves it
 * through the SVC gate (which maps it into the partition's table), reads the
 * seeded bytes and writes a reply at S-EL0, relinquishes it (the gate unmaps
 * it), and the owner reclaims the handle, after which a retrieve is refused.
 * The partition's table changes only through the two transactions. */
static wt_secure_domain_t g_borrow_domain;
static uint8_t g_share_desc[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE +
                            WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                            WT_FFA_MEM_CONSTITUENT_SIZE];

static int prove_mem_share(uint64_t* out_handle)
{
    const wt_domain_descriptor_t* d = first_partition_domain();
    volatile uint8_t* share = (volatile uint8_t*)(uintptr_t)WT_SPM_SHARE_PA;
    uint8_t* rx = (uint8_t*)(uintptr_t)WT_SPM_RXTX_PA;
    uint8_t* tx = rx + WT_FFA_MEM_PAGE_SIZE;
    uint64_t* arg = (uint64_t*)(rx + WT_FFA_MEM_PAGE_SIZE - 64u);
    wt_ffa_mem_constituent_t cons;
    wt_ffa_mem_build_t in;
    uint8_t* stack;
    wt_co_t* co;
    uint64_t handle = 0u;
    size_t len = 0u;
    size_t req_len = 0u;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)(uintptr_t)d->stack_base;
    g_borrow_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_borrow_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_borrow_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_borrow_domain.regions[1].base = (uintptr_t)stack;
    g_borrow_domain.regions[1].size = (size_t)d->stack_size;
    g_borrow_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_borrow_domain.regions[2].base = (uintptr_t)WT_SPM_RXTX_PA;
    g_borrow_domain.regions[2].size = (size_t)WT_SPM_RXTX_SIZE;
    g_borrow_domain.regions[2].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_borrow_domain.region_count = 3u;

    share[0] = 0x5Au;
    share[1] = 0xA5u;
    share[2] = 0x3Cu;
    share[3] = 0xC3u;
    share[4] = 0u;

    (void)memset(&in, 0, sizeof(in));
    cons.address = (uint64_t)WT_SPM_SHARE_PA;
    cons.page_count = 1u;
    in.constituents = &cons;
    in.constituent_count = 1u;
    in.tag = 0u;
    in.handle = 0u;
    in.flags = 0u;
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = WT_FFA_ID_SPMC;
    in.receiver = WT_FFA_ID_MEM_BORROWER;
    in.attributes = (uint16_t)(WT_FFA_MEM_ATTR_TYPE_NORMAL |
                               (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT) |
                               WT_FFA_MEM_ATTR_SHARE_INNER);
    in.permissions = (uint8_t)WT_FFA_MEM_PERM_DATA_RW;
    /* The borrower exists before the share names it. */
    co = wt_co_create_blocked_ex(stack, (size_t)d->stack_size,
                                 (wt_co_entry_fn)wt_sp_ffa_borrow, (void*)arg);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_borrow_domain, 1u);
    if (wt_spm_mem_bind(WT_FFA_ID_MEM_BORROWER, co, &g_borrow_domain) != 0) {
        return 0;
    }
    if (wt_ffa_mem_txn_build(g_share_desc, sizeof(g_share_desc), &in, &len) != 0) {
        return 0;
    }
    if (wt_spm_mem_share(g_share_desc, len, WT_FFA_MEM_OP_SHARE, WT_FFA_ID_SPMC,
                         &handle) != 0) {
        return 0;
    }

    /* The borrower's retrieve request waits in its TX buffer; its arguments
     * sit at the tail of its RX buffer, clear of the retrieve response. */
    if (wt_ffa_mem_retrieve_req_build(tx, WT_FFA_MEM_PAGE_SIZE, handle,
                                      WT_FFA_ID_SPMC, WT_FFA_ID_MEM_BORROWER,
                                      in.permissions, &req_len) != 0) {
        return 0;
    }
    arg[0] = handle;
    arg[1] = (uint64_t)WT_SPM_SHARE_PA;
    arg[2] = (uint64_t)(uintptr_t)tx;
    arg[3] = (uint64_t)req_len;
    arg[4] = (uint64_t)WT_FFA_ID_MEM_BORROWER;

    /* Run 1: retrieve, read the seed, write the reply at S-EL0, yield the seed. */
    wt_co_wake(co);
    if (wt_co_run(co) != 1u) {
        return 0;
    }
    if ((uint32_t)wt_spm_yield_token() != 0xC33CA55Au) {
        return 0;
    }
    if (share[4] != 0xEEu) {
        return 0;
    }

    /* Run 2: relinquish, yield the status; the region is gone from the table. */
    wt_co_wake(co);
    if (wt_co_run(co) != 1u) {
        return 0;
    }
    if ((uint32_t)wt_spm_yield_token() != WT_FFA_SUCCESS32) {
        return 0;
    }

    if (wt_spm_mem_reclaim(handle, WT_FFA_ID_SPMC, 0u) != 0) {
        return 0;
    }
    if (wt_spm_mem_retrieve(tx, req_len, WT_FFA_ID_MEM_BORROWER, rx,
                            WT_FFA_MEM_PAGE_SIZE, &len) == 0) {
        return 0;
    }
    *out_handle = handle;
    return 1;
}

uint32_t wt_spm_prove_sint(void);

void wt_spm_main(uint64_t boot_info_pa)
{
    wt_ffa_regs_t r;
    uint32_t sint_id;
    uint32_t partinfo_n = 0u;
    uint64_t share_handle = 0u;

    wt_el3_puts("[SPM] spmc entered at S-EL1\r\n");
    consume_boot_info(boot_info_pa);
    enable_mmu(boot_info_pa);
    wt_spm_mem_init();
    wt_spm_mem_ns_window((uint64_t)WT_NS_IMAGE_PA,
                         (uint64_t)WT_PSA_NS_WINDOW_SIZE);
#if defined(WT_EL3_NS_SMOKE)
    wt_spm_psa_init((uint64_t)WT_NS_IMAGE_PA,
                    (uint64_t)WT_NS_IMAGE_PA + WT_PSA_NS_WINDOW_SIZE);
#endif
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
    if (prove_partinfo(&partinfo_n)) {
        wt_el3_puts("[SPM] partinfo ok n=");
        wt_el3_putdec(partinfo_n);
        wt_el3_puts("\r\n");
    }
    else {
        wt_el3_puts("[SPM] partinfo FAIL\r\n");
    }
    if (prove_mem_share(&share_handle)) {
        wt_el3_puts("[SPM] mem share ok handle=0x");
        wt_el3_puthex(share_handle, 4u);
        wt_el3_puts("\r\n");
    }
    else {
        wt_el3_puts("[SPM] mem share FAIL\r\n");
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

/* Answer a forwarded call: FFA_SUCCESS with w2/w3, or FFA_ERROR with ret. The
 * idle loop issues the reply SMC, whose return is the next event. */
static void ns_reply(wt_ffa_regs_t* r, int ret, uint64_t w2, uint64_t w3)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    if (ret == 0) {
        r->x[0] = WT_FFA_SUCCESS32;
        r->x[2] = w2;
        r->x[3] = w3;
    }
    else {
        r->x[0] = WT_FFA_ERROR;
        r->x[2] = (uint64_t)(uint32_t)ret;
    }
}

/* Answer with what an endpoint handed back: x0-x7, or x0-x17 for RESP2. */
static void ns_reply_regs(wt_ffa_regs_ext_t* e, const uint64_t* out)
{
    unsigned int count = wt_ffa_msg_reg_count(out[0]);
    unsigned int i;

    for (i = 0u; i < WT_FFA_MSG_REGS; i++) {
        e->base.x[i] = out[i];
    }
    for (i = WT_FFA_MSG_REGS; i < count; i++) {
        e->ext[i - WT_FFA_MSG_REGS] = out[i];
    }
}

/* Nothing to run on the Secure side: every event the SPMD delivers is
 * reported until the Secure virtual instance dispatches them. */
/* A direct request the SPMD relayed from the Normal world: validate it at the
 * NS-physical instance, deliver it to the waiting receiver, and send the
 * partition's response back with FFA_MSG_SEND_DIRECT_RESP32; that SMC's
 * return is the next event. A request no partition can take is answered with
 * FFA_ERROR instead. */
static void direct_request(wt_ffa_regs_ext_t* e)
{
    uint64_t req[WT_FFA_MSG_REGS_EXT];
    uint64_t resp[WT_FFA_MSG_REGS_EXT];
    wt_ffa_regs_t* r = &e->base;
    struct wt_co* co = NULL;
    uint16_t receiver = wt_ffa_direct_receiver(r->x[1]);
    int ret = wt_ffa_direct_req_check(r->x, WT_FFA_INSTANCE_NS_PHYSICAL);
    unsigned int i;

    wt_el3_puts("[SPM] direct req from=0x");
    wt_el3_puthex(wt_ffa_direct_sender(r->x[1]), 4u);
    wt_el3_puts(" to=0x");
    wt_el3_puthex(receiver, 4u);
    wt_el3_puts("\r\n");
    if ((ret == 0) &&
        (wt_ffa_direct_sender(r->x[1]) != WT_FFA_ID_NS_PRIMARY)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0 && receiver == WT_FFA_ID_PSA) {
        (void)wt_spm_psa_framework(r);
        return;
    }
    if (ret == 0) {
        if (receiver == WT_FFA_ID_ECHO) {
            co = wt_spm_ffa_echo_partition();
        }
        else {
            co = wt_spm_ffa_native_by_id(receiver);
        }
        for (i = 0u; i < WT_FFA_MSG_REGS; i++) {
            req[i] = r->x[i];
        }
        for (i = WT_FFA_MSG_REGS; i < WT_FFA_MSG_REGS_EXT; i++) {
            req[i] = e->ext[i - WT_FFA_MSG_REGS];
        }
        ret = (co != NULL) ? wt_spm_ffa_direct_deliver(co, req, resp)
                           : WT_FFA_INVALID_PARAMETERS;
    }
    if (ret != 0) {
        ns_reply(r, ret, 0u, 0u);
        return;
    }
    ns_reply_regs(e, resp);
}

/* The Normal-world endpoint's mailbox (7.2.2): the SPMC is the producer of its
 * RX buffer, so the pair and its ownership live here, not in the SPMD. */
static wt_ffa_mailbox_t g_ns_mailbox;

static int ns_range_ok(uint64_t addr, uint64_t len)
{
    uint64_t base = (uint64_t)WT_NS_IMAGE_PA;
    uint64_t limit = base + (uint64_t)WT_PSA_NS_WINDOW_SIZE;

    return ((len != 0u) && (addr >= base) && (addr < limit) &&
            (len <= (limit - addr))) ? 1 : 0;
}

/* FFA_RXTX_MAP from the Normal world: both buffers must lie in the window of
 * Non-secure memory the SPMC maps. */
static void ns_rxtx_map(wt_ffa_regs_t* r)
{
    uint64_t span = (uint64_t)((uint32_t)r->x[3] & 0x3Fu) * WT_FFA_MEM_PAGE_SIZE;
    int ret = 0;

    if ((g_ns_mailbox.mapped == 0u) &&
        ((ns_range_ok(r->x[1], span) == 0) || (ns_range_ok(r->x[2], span) == 0))) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        ret = wt_ffa_mailbox_map(&g_ns_mailbox, r->x[1], r->x[2],
                                 (uint32_t)r->x[3]);
    }
    ns_reply(r, ret, 0u, 0u);
}

static void ns_rxtx_unmap(wt_ffa_regs_t* r)
{
    int ret = ((((uint32_t)r->x[1] >> 16) & 0xFFFFu) == WT_FFA_ID_NS_PRIMARY)
                  ? wt_ffa_mailbox_unmap(&g_ns_mailbox)
                  : WT_FFA_INVALID_PARAMETERS;

    ns_reply(r, ret, 0u, 0u);
}

/* FFA_PARTITION_INFO_GET forwarded from the Normal world: descriptors go to
 * the guest's RX buffer, a count-only request needs none. */
static void ns_partition_info_get(wt_ffa_regs_t* r)
{
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret = wt_spm_partition_info(r->x, &g_ns_mailbox,
                                    (uint8_t*)(uintptr_t)g_ns_mailbox.rx,
                                    &count, &size);

    ns_reply(r, ret, count, size);
}

/* FFA_RUN forwarded from the Normal world: w1 bits 31:16 name the endpoint;
 * what it hands back (response, FFA_YIELD, FFA_MSG_WAIT) is the reply. */
static void ns_run(wt_ffa_regs_ext_t* e)
{
    uint64_t out[WT_FFA_MSG_REGS_EXT];
    struct wt_co* co =
        wt_spm_ffa_native_by_id((uint16_t)((uint32_t)e->base.x[1] >> 16));
    int ret = (co != NULL) ? wt_spm_ffa_run(co, WT_FFA_ID_NS_PRIMARY, out)
                           : WT_FFA_INVALID_PARAMETERS;

    if (ret != 0) {
        ns_reply(&e->base, ret, 0u, 0u);
        return;
    }
    ns_reply_regs(e, out);
}

/* FFA_INTERRUPT the SPMD signalled because a Secure interrupt preempted the
 * Normal world (Ch.9). The SPMD already serviced the GIC; the SPMC schedules
 * (nothing else is runnable here) and yields the CPU back with
 * FFA_NORMAL_WORLD_RESUME. The resume SMC's return is the next event. */
static void ns_interrupt(wt_ffa_regs_t* r)
{
    unsigned int i;

    wt_el3_puts("[SPM] ns preempt intid=0x");
    wt_el3_puthex(r->x[1], 2u);
    wt_el3_puts("\r\n");
    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_NORMAL_WORLD_RESUME;
}

/* FFA_MEM_SHARE forwarded from the Normal world (7.3): the guest's descriptor
 * is at the NS address in x3 with length in x1, both inside the SPMC's
 * Non-secure window. Validate and register it; reply with the handle in w2/w3
 * or an error. A malformed descriptor is refused, never a crash. The reply
 * SMC's return is the next event. */
static void ns_mem_send(wt_ffa_regs_t* r, wt_ffa_mem_op_t op)
{
    uint64_t addr = r->x[3];
    uint32_t total = (uint32_t)r->x[1];
    uint64_t handle = 0u;
    unsigned int i;
    int ret;

    /* x3 = 0 names the descriptor in the guest's TX buffer (11.1). */
    if ((addr == 0u) && (g_ns_mailbox.mapped != 0u) &&
        (total <= (g_ns_mailbox.pages * WT_FFA_MEM_PAGE_SIZE))) {
        addr = g_ns_mailbox.tx;
    }
    /* No fragmentation: the one fragment is the whole descriptor. */
    if ((ns_range_ok(addr, (uint64_t)total) == 0) ||
        ((uint32_t)r->x[2] != total)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    else {
        ret = wt_spm_mem_share((const uint8_t*)(uintptr_t)addr, (size_t)total,
                               op, WT_FFA_ID_NS_PRIMARY, &handle);
    }
    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    if (ret == 0) {
        r->x[0] = WT_FFA_SUCCESS32;
        r->x[2] = handle & 0xFFFFFFFFu;
        r->x[3] = handle >> 32;
    }
    else {
        r->x[0] = WT_FFA_ERROR;
        r->x[2] = (uint64_t)(uint32_t)ret;
    }
}

/* FFA_MEM_RECLAIM forwarded from the Normal world: w1/w2 = handle. */
static void ns_mem_reclaim(wt_ffa_regs_t* r)
{
    uint64_t handle = (uint64_t)(uint32_t)r->x[1] |
                      ((uint64_t)(uint32_t)r->x[2] << 32);
    unsigned int i;
    int ret = wt_spm_mem_reclaim(handle, WT_FFA_ID_NS_PRIMARY,
                                 (uint32_t)r->x[3]);

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    if (ret == 0) {
        r->x[0] = WT_FFA_SUCCESS32;
    }
    else {
        r->x[0] = WT_FFA_ERROR;
        r->x[2] = (uint64_t)(uint32_t)ret;
    }
}

/* FFA_PARTITION_INFO_GET_REGS forwarded from the Normal world. */
static void ns_partition_info_get_regs(wt_ffa_regs_ext_t* e)
{
    uint64_t out[WT_FFA_MSG_REGS_EXT];
    int ret = wt_spm_partition_info_regs(e->base.x, out);
    unsigned int i;

    if (ret != 0) {
        ns_reply(&e->base, ret, 0u, 0u);
        return;
    }
    for (i = 0u; i < WT_FFA_MSG_REGS; i++) {
        e->base.x[i] = out[i];
    }
    for (i = WT_FFA_MSG_REGS; i < WT_FFA_MSG_REGS_EXT; i++) {
        e->ext[i - WT_FFA_MSG_REGS] = out[i];
    }
}

/* One forwarded event; the reply is left in e for the loop's SMC. */
static void idle_dispatch(wt_ffa_regs_ext_t* e)
{
    wt_ffa_regs_t* r = &e->base;

    switch ((uint32_t)r->x[0]) {
        case WT_FFA_MSG_SEND_DIRECT_REQ32:
        case WT_FFA_MSG_SEND_DIRECT_REQ64:
        case WT_FFA_MSG_SEND_DIRECT_REQ2:
            direct_request(e);
            break;
        case WT_FFA_RUN:
            ns_run(e);
            break;
        case WT_FFA_PARTITION_INFO_GET:
            ns_partition_info_get(r);
            break;
        case WT_FFA_PARTITION_INFO_GET_REGS:
            ns_partition_info_get_regs(e);
            break;
        case WT_FFA_RXTX_MAP32:
        case WT_FFA_RXTX_MAP64:
            ns_rxtx_map(r);
            break;
        case WT_FFA_RXTX_UNMAP:
            ns_rxtx_unmap(r);
            break;
        case WT_FFA_RX_RELEASE:
            ns_reply(r, wt_ffa_mailbox_rx_release(&g_ns_mailbox), 0u, 0u);
            break;
        case WT_FFA_INTERRUPT:
            ns_interrupt(r);
            break;
        case WT_FFA_MEM_SHARE32:
        case WT_FFA_MEM_SHARE64:
            ns_mem_send(r, WT_FFA_MEM_OP_SHARE);
            break;
        case WT_FFA_MEM_LEND32:
        case WT_FFA_MEM_LEND64:
            ns_mem_send(r, WT_FFA_MEM_OP_LEND);
            break;
        case WT_FFA_MEM_DONATE32:
        case WT_FFA_MEM_DONATE64:
            ns_mem_send(r, WT_FFA_MEM_OP_DONATE);
            break;
        case WT_FFA_MEM_RETRIEVE_REQ32:
        case WT_FFA_MEM_RETRIEVE_REQ64:
        case WT_FFA_MEM_RELINQUISH:
            /* The Normal world only ever owns: nothing is lent to it. */
            ns_reply(r, WT_FFA_DENIED, 0u, 0u);
            break;
        case WT_FFA_MEM_RECLAIM:
            ns_mem_reclaim(r);
            break;
        default:
            wt_el3_puts("[SPM] unexpected event x0=0x");
            wt_el3_puthex(r->x[0], 8u);
            wt_el3_puts("\r\n");
            ns_reply(r, WT_FFA_NOT_SUPPORTED, 0u, 0u);
            break;
    }
}

void wt_spm_idle(void)
{
    wt_ffa_regs_ext_t e;
    uint32_t event = 0u;
    unsigned int i;

#if defined(WT_EL3_TEST_DRIVER) && (WT_EL3_TEST_DRIVER == 1)
    /* With every partition initialized and waiting, route the test Secure
     * interrupt to the echo partition (signalled, then queued) before idling. */
    wt_spm_prove_sint_route(wt_spm_ffa_echo_partition());
#endif
    (void)memset(&e, 0, sizeof(e));
    e.base.x[0] = WT_FFA_MSG_WAIT;
    for (;;) {
        /* Only an extended reply carries x8-x17 out of the SPMC. */
        if (wt_ffa_reply_is_ext(event, (uint32_t)e.base.x[0]) == 0) {
            for (i = 0u; i < (WT_FFA_MSG_REGS_EXT - WT_FFA_MSG_REGS); i++) {
                e.ext[i] = 0u;
            }
        }
        wt_platform_console_flush();
        wt_ffa_smc_ext(&e);
        event = (uint32_t)e.base.x[0];
        idle_dispatch(&e);
    }
}
