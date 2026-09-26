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
#include "wolftrust/arch/aarch64/ffa_notif.h"
#include "wolftrust/arch/aarch64/ffa_partinfo.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/psa_ffa.h"
#include "wolftrust/arch/aarch64/psci.h"
#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/sysreg.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/boot.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/manifest.h"
#include "wolftrust/platform.h"
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
extern uint8_t _e_secure_rodata[];
extern uint8_t __image_end[];
extern uint8_t __spm_ram_end[];
extern uint8_t _e_keystore[];

void wt_spm_main(uint64_t boot_info_pa);
int wt_spm_prove_tick(void);

/* The fill list outlives init: every partition table maps it EL1-only. */
static wt_memory_region_t g_fill[WT_SPMC_MAX_FILL];
/* The manifest domain each owned fill entry belongs to; WT_DOMAIN_ID_INVALID
 * marks one no manifest partition may name (the SPMC's, the echo's, a native
 * partition's). */
static uint32_t g_fill_owner[WT_SPMC_MAX_FILL];

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

    ffa_call(&r, WT_SMCCC_VERSION, 0u);
    if ((uint32_t)r.x[0] != WT_SMCCC_VERSION_1_2) {
        spmc_fail("smccc version", r.x[0]);
    }
    ffa_call(&r, WT_SMCCC_ARCH_FEATURES, WT_SMCCC_VERSION);
    if ((uint32_t)r.x[0] != 0u) {
        spmc_fail("smccc arch_features", r.x[0]);
    }
    wt_el3_puts("[SPM] smccc version 1.2\r\n");

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

/* A fill entry dropped for want of room would leave memory the SPMC writes
 * unmapped, so a full list fails closed instead. */
static void fill_check(size_t n)
{
    if (n >= WT_SPMC_MAX_FILL) {
        spmc_fail("fill full", (uint64_t)n);
    }
}

/* Manifest partition stacks sit on WT_SPMC_STACK_STRIDE boundaries; the test
 * echo partition takes the next one past the last, published as a shareable
 * fill entry so its own table maps it EL0 while every other table keeps it
 * EL1-only. */
#define WT_SPMC_STACK_STRIDE 0x10000u

#if defined(WT_SPM_ECHO_SP)
static size_t add_echo_band(wt_memory_region_t* fill, size_t n,
                            uintptr_t last_end, uintptr_t band_size)
{
    if (band_size == 0u) {
        return n;
    }
    fill_check(n);
    g_wt_spm_echo_stack_base = (last_end + WT_SPMC_STACK_STRIDE - 1u) &
                               ~(uintptr_t)(WT_SPMC_STACK_STRIDE - 1u);
    g_wt_spm_echo_stack_size = band_size;
    fill[n].base = g_wt_spm_echo_stack_base;
    fill[n].size = (size_t)band_size;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                         WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED;
    return n + 1u;
}
#else
static size_t add_echo_band(wt_memory_region_t* fill, size_t n,
                            uintptr_t last_end, uintptr_t band_size)
{
    (void)fill;
    (void)last_end;
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
        for (j = 0u; j < list[i].region_count; j++) {
            fill_check(n);
            fill[n].base = list[i].regions[j].base;
            fill[n].size = list[i].regions[j].size;
            fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                                 WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED;
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

/* No manifest partition may name memory an owned fill entry gives another
 * endpoint (the manifest validator never sees the echo, native, or SPMC
 * bands), since its table would take that entry over. */
static void check_fill_owners(const wt_system_manifest_t* manifest,
                              const wt_memory_region_t* fill, size_t n)
{
    const wt_domain_descriptor_t* d;
    const wt_memory_resource_t* r;
    wt_memory_region_t grants[WT_MAX_MEMORY_REGIONS];
    size_t count = 0u;
    size_t i;
    size_t j;

    for (i = 0u; i < manifest->domain_count; i++) {
        d = &manifest->domains[i];
        if (d->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION) {
            continue;
        }
        for (j = 0u; j < d->memory_resource_count; j++) {
            r = &d->memory_resources[j];
            if (wt_domain_fill_foreign(fill, g_fill_owner, n, (uint32_t)d->id,
                                       r->base, r->size) != 0) {
                spmc_fail("fill owner", (uint64_t)d->id);
            }
        }
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
        count = wt_platform_conf_sp_grants((int32_t)d->id, grants, 0u,
                                           WT_MAX_MEMORY_REGIONS);
#endif
        for (j = 0u; j < count; j++) {
            if (wt_domain_fill_foreign(fill, g_fill_owner, n, (uint32_t)d->id,
                                       grants[j].base, grants[j].size) != 0) {
                spmc_fail("fill owner", (uint64_t)d->id);
            }
        }
    }
}

static void enable_mmu(uint64_t boot_info_pa)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    wt_memory_region_t* fill = g_fill;
    const wt_memory_region_t* devices;
    size_t device_count = 0u;
    size_t n = 0u;
    size_t i;
    size_t j;
    uint64_t ttbr0;
    wt_memory_region_t band;
    wt_memory_region_t stack;
    uintptr_t last_end = 0u;
    uintptr_t band_size = 0u;

    /* Shareable entries: a partition whose regions cover one takes it over
     * (EL0 + EL1), and an owned one only the region that is exactly it; the
     * SPM RAM band, boot page, pool, and devices stay EL1-only in every
     * table. */
    for (i = 0u; i < WT_SPMC_MAX_FILL; i++) {
        g_fill_owner[i] = WT_DOMAIN_ID_INVALID;
    }
    fill[n].base = (uintptr_t)WT_SPM_IMAGE_PA;
    fill[n].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC | WT_DOMAIN_FILL_SHARED;
    n++;
    fill[n].base = (uintptr_t)_e_secure_text;
    fill[n].size = (uintptr_t)_e_secure_rodata - (uintptr_t)_e_secure_text;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_DOMAIN_FILL_SHARED;
    n++;
    /* Load images of initialized data (function pointers too) stay EL1-only. */
    if (page_up((uintptr_t)__image_end) > (uintptr_t)_e_secure_rodata) {
        fill[n].base = (uintptr_t)_e_secure_rodata;
        fill[n].size = page_up((uintptr_t)__image_end) -
                       (uintptr_t)_e_secure_rodata;
        fill[n].attributes = WT_MEM_ATTR_READ;
        n++;
    }
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
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                         WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED;
    n++;
    /* The memory-sharing self-test page: the SPMC seeds it at S-EL1 and a
     * partition maps it at S-EL0 only through FFA_MEM_RETRIEVE_REQ. */
    fill[n].base = (uintptr_t)WT_SPM_SHARE_PA;
    fill[n].size = (size_t)WT_SPM_SHARE_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                         WT_DOMAIN_FILL_SHARED | WT_DOMAIN_FILL_OWNED;
    n++;
    /* Every partition resource the SPMC itself writes from EL1 (the stack it
     * seeds and scrubs, a data band the fault scrub clears), whole; the owner
     * maps its own at EL0. */
    for (i = 0u; i < manifest->domain_count; i++) {
        const wt_domain_descriptor_t* d = &manifest->domains[i];

        if (d->domain_class != WT_DOMAIN_CLASS_SECURE_PARTITION) {
            continue;
        }
        for (j = 0u; j < d->memory_resource_count; j++) {
            if (wt_domain_spm_band(d, j, &band) == 0) {
                fill_check(n);
                fill[n] = band;
                fill[n].attributes |= WT_DOMAIN_FILL_SHARED |
                                      WT_DOMAIN_FILL_OWNED;
                g_fill_owner[n] = (uint32_t)d->id;
                n++;
            }
        }
        if ((wt_domain_stack_band(d, &stack) == 0) &&
            ((stack.base + stack.size) > last_end)) {
            last_end = stack.base + stack.size;
            band_size = (uintptr_t)stack.size;
        }
    }
    n = add_echo_band(fill, n, last_end, band_size);
    n = add_native_bands(fill, n);
    fill_check(n + 1u);
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
    for (i = 0u; i < device_count; i++) {
        fill_check(n);
        fill[n] = devices[i];
        n++;
    }
#if defined(WT_EL3_NS_SMOKE)
    /* A guest's psa_call buffers live in Non-secure RAM: map the window
     * EL1-only and Non-secure so the SPMC can copy them. A retrieve maps its
     * pages at EL0, so the window is non-global in every table. */
    fill_check(n);
    fill[n].base = (uintptr_t)WT_NS_IMAGE_PA;
    fill[n].size = (size_t)WT_PSA_NS_WINDOW_SIZE;
    fill[n].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE |
                         WT_TABLES_ATTR_NS | WT_TABLES_ATTR_NG;
    n++;
#endif
    check_fill_owners(manifest, fill, n);

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

/* The first configured partition and the stack band enable_mmu mapped for it,
 * which the boot proofs borrow. */
static const wt_domain_descriptor_t* first_partition_domain(
    wt_memory_region_t* band)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    size_t i;

    for (i = 0u; i < manifest->domain_count; i++) {
        if (manifest->domains[i].domain_class == WT_DOMAIN_CLASS_SECURE_PARTITION) {
            return (wt_domain_stack_band(&manifest->domains[i], band) == 0) ?
                   &manifest->domains[i] : NULL;
        }
    }
    return NULL;
}

static int prove_el0(void)
{
    wt_memory_region_t band;
    const wt_domain_descriptor_t* d = first_partition_domain(&band);
    uint8_t* stack;
    wt_co_t* co;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)band.base;
    g_el0_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_el0_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_el0_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_el0_domain.regions[1].base = (uintptr_t)stack;
    g_el0_domain.regions[1].size = band.size;
    g_el0_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_el0_domain.region_count = 2u;
    co = wt_co_create_blocked_ex(stack, band.size,
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
 * with the ids swapped and the payload word complemented. First, on the same
 * band, a partition that reports failed initialization with FFA_ERROR must
 * wait, never having initialized, and never run again. */
static wt_secure_domain_t g_echo_domain;
extern void wt_sp_ffa_init_fail(void);

static int prove_init_failure(uint8_t* stack, size_t size)
{
    static const uint32_t probe[WT_FFA_DIRECT_PAYLOAD_WORDS] = { 0u };
    uint64_t req[WT_FFA_MSG_REGS_EXT];
    uint64_t resp[WT_FFA_MSG_REGS_EXT];
    wt_co_t* co;
    int ok;

    co = wt_co_create_blocked_ex(stack, size,
                                 (wt_co_entry_fn)wt_sp_ffa_init_fail, (void*)0);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_echo_domain, 1u);
    wt_co_wake(co);
    (void)wt_co_run(co);
    /* 8.5 rule 3: it waits, neither initializing nor initialized, and a
     * request or FFA_RUN finds it not in a state to handle one. */
    wt_ffa_direct_build(req, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, probe);
    ok = ((wt_co_state(co) == WT_CO_BLOCKED) &&
          (wt_spm_sp_failed_init((const struct wt_co*)co) != 0) &&
          (wt_spm_sp_initializing((const struct wt_co*)co) == 0) &&
          (wt_spm_ffa_direct_deliver((struct wt_co*)co, req, resp) ==
           WT_FFA_DENIED) &&
          (wt_spm_ffa_run((struct wt_co*)co, WT_FFA_ID_NS_PRIMARY, resp) ==
           WT_FFA_DENIED)) ? 1 : 0;
    /* A scheduler that wakes it anyway never gets it running again. */
    wt_co_wake(co);
    (void)wt_co_run(co);
    return ((ok != 0) && (wt_co_state(co) == WT_CO_FAULTED) &&
            (wt_spm_yield_token() != 0xBADu)) ? 1 : 0;
}

static int prove_ffa_direct(void)
{
    static const uint32_t first[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        0x5A5A00FFu, 0u, 0u, 0u, 0u
    };
    static const uint32_t second[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        0x0000C3C3u, 0u, 0u, 0u, 0u
    };
    static const uint32_t complete[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        0x00005CCEu, 0u, 0u, 0u, 0u
    };
    unsigned int i;
    wt_memory_region_t band;
    const wt_domain_descriptor_t* d = first_partition_domain(&band);
    uint64_t req[WT_FFA_MSG_REGS_EXT];
    uint64_t resp[WT_FFA_MSG_REGS_EXT];
    uint8_t* stack;
    wt_co_t* co;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)band.base;
    g_echo_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_echo_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_echo_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_echo_domain.regions[1].base = (uintptr_t)stack;
    g_echo_domain.regions[1].size = band.size;
    g_echo_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_echo_domain.region_count = 2u;
    if (prove_init_failure(stack, band.size) == 0) {
        return 0;
    }
    co = wt_co_create_blocked_ex(stack, band.size,
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

    /* 15.2: completed with FFA_SUCCESS instead, the echo waits once more. */
    wt_ffa_direct_build(req, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, complete);
    if ((wt_spm_ffa_direct_deliver((struct wt_co*)co, req, resp) != 0) ||
        ((uint32_t)resp[0] != WT_FFA_SUCCESS32)) {
        return 0;
    }
    for (i = 1u; i < WT_FFA_MSG_REGS; i++) {
        if (resp[i] != 0u) {
            return 0;
        }
    }
    wt_ffa_direct_build(req, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, first);
    if ((wt_spm_ffa_direct_deliver((struct wt_co*)co, req, resp) != 0) ||
        ((uint32_t)resp[0] != WT_FFA_MSG_SEND_DIRECT_RESP32) ||
        ((uint32_t)resp[3] != (uint32_t)~first[0])) {
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
    static const uint32_t none[WT_FFA_DIRECT_PAYLOAD_WORDS];
    wt_memory_region_t band;
    const wt_domain_descriptor_t* d = first_partition_domain(&band);
    uint64_t req[WT_FFA_MSG_REGS_EXT];
    uint64_t resp[WT_FFA_MSG_REGS_EXT];
    wt_ffa_mailbox_t* mb;
    uint8_t* stack;
    wt_co_t* co;
    int preempted;
    int mapped;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)band.base;
    g_spin_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_spin_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_spin_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_spin_domain.regions[1].base = (uintptr_t)stack;
    g_spin_domain.regions[1].size = band.size;
    g_spin_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_spin_domain.region_count = 2u;
    co = wt_co_create_blocked_ex(stack, band.size,
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
    /* Retired for good, it lets go of its RX/TX pair, and a direct request or
     * FFA_RUN naming it is ABORTED (Tables 15.8, 14.14). */
    mb = wt_spm_sp_mailbox_of((const struct wt_co*)co);
    mapped = ((mb != NULL) &&
              (wt_ffa_mailbox_map(mb, (uint64_t)WT_SPM_RXTX_PA +
                                      WT_FFA_MEM_PAGE_SIZE,
                                  (uint64_t)WT_SPM_RXTX_PA, 1u) == 0)) ? 1 : 0;
    wt_spm_sp_retire((struct wt_co*)co);
    wt_ffa_direct_build(req, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, none);
    return ((preempted != 0) && (mapped != 0) && (mb->mapped == 0u) &&
            (wt_spm_ffa_direct_deliver((struct wt_co*)co, req, resp) ==
             WT_FFA_ABORTED) &&
            (wt_spm_ffa_run((struct wt_co*)co, WT_FFA_ID_NS_PRIMARY, resp) ==
             WT_FFA_ABORTED)) ? 1 : 0;
}

/* Prove FF-A partition discovery: an S-EL0 partition standing in for the
 * first configured partition (its domain and stack) calls
 * FFA_PARTITION_INFO_GET with a Nil UUID while no other partition exists. The
 * SPMC lists exactly that domain's descriptors, under the id FFA_ID_GET gives
 * the caller, in the RX buffer of the pair mapped for it; the partition reads
 * the count and the first descriptor's id back out at S-EL0. A Normal-world
 * FFA_MSG_SEND2 to it, a PSA partition, is then DENIED (Table 15.4). */
static wt_secure_domain_t g_discover_domain;
static uint8_t g_msg2_probe[WT_FFA_MSG2_HEADER_SIZE];

static int msg2_to_psa(uint16_t receiver)
{
    g_msg2_probe[8] = (uint8_t)WT_FFA_MSG2_HEADER_SIZE;
    g_msg2_probe[12] = (uint8_t)(receiver & 0xFFu);
    g_msg2_probe[13] = (uint8_t)(receiver >> 8);
    return wt_spm_msg2_deliver(WT_FFA_ID_NS_PRIMARY, WT_FFA_VERSION_1_2,
                               g_msg2_probe, (uint32_t)sizeof(g_msg2_probe),
                               WT_FFA_INSTANCE_NS_PHYSICAL, 0u, 0u);
}

static int prove_partinfo(uint32_t* out_count)
{
    wt_memory_region_t band;
    const wt_domain_descriptor_t* d = first_partition_domain(&band);
    const wt_ffa_partition_manifest_t* parts;
    wt_ffa_mailbox_t* mb;
    uint32_t expect = 0u;
    uint32_t ran;
    size_t np = 0u;
    size_t i;
    uint8_t* stack;
    wt_co_t* co;
    uint64_t token;

    parts = wt_generated_ffa_partitions_get(&np);
    if ((d == NULL) || (parts == NULL)) {
        return 0;
    }
    for (i = 0u; i < np; i++) {
        if (parts[i].domain_id == (uint32_t)d->id) {
            expect = parts[i].uuid_count;
        }
    }
    if (expect == 0u) {
        return 0;
    }
    stack = (uint8_t*)band.base;
    g_discover_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_discover_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_discover_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_discover_domain.regions[1].base = (uintptr_t)stack;
    g_discover_domain.regions[1].size = band.size;
    g_discover_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_discover_domain.regions[2].base = (uintptr_t)WT_SPM_RXTX_PA;
    g_discover_domain.regions[2].size = (size_t)WT_SPM_RXTX_SIZE;
    g_discover_domain.regions[2].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_discover_domain.region_count = 3u;
    g_discover_domain.domain_id = d->id;
    co = wt_co_create_blocked_ex(stack, band.size,
                                 (wt_co_entry_fn)wt_sp_ffa_discover,
                                 (void*)(uintptr_t)WT_SPM_RXTX_PA);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_discover_domain, 1u);
    mb = wt_spm_sp_mailbox_of((const struct wt_co*)co);
    if ((mb == NULL) ||
        (wt_ffa_mailbox_map(mb, (uint64_t)WT_SPM_RXTX_PA + WT_FFA_MEM_PAGE_SIZE,
                            (uint64_t)WT_SPM_RXTX_PA, 1u) != 0)) {
        return 0;
    }
    wt_co_wake(co);
    ran = wt_co_run(co);
    /* Its slot is reused by a real partition, which maps its own pair. */
    if ((wt_ffa_mailbox_unmap(mb) != 0) || (ran != 1u)) {
        return 0;
    }
    token = wt_spm_yield_token();
    *out_count = (uint32_t)(token & 0xFFFFu);
    if ((uint32_t)((token >> 16) & 0xFFFFu) !=
        (uint32_t)wt_spm_sp_ffa_id((struct wt_co*)co)) {
        return 0;
    }
    if (msg2_to_psa(wt_spm_sp_ffa_id((struct wt_co*)co)) != WT_FFA_DENIED) {
        return 0;
    }
    return (*out_count == expect) ? 1 : 0;
}

/* Prove FF-A memory sharing end to end: the SPMC (owner) seeds the share page
 * and shares it to the borrower endpoint; an S-EL0 partition retrieves it
 * through the SVC gate (which maps it into the partition's table), reads the
 * seeded bytes and writes a reply at S-EL0, relinquishes it (the gate unmaps
 * it), and the owner reclaims the handle, after which a retrieve is refused.
 * The partition's table changes only through the two transactions. */
static wt_secure_domain_t g_borrow_domain;
static uint8_t g_share_desc[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE_V12 +
                            WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                            WT_FFA_MEM_CONSTITUENT_SIZE];

/* The share, the borrower's two runs, and the reclaim, with the borrower
 * bound to the relayer. */
static int mem_share_exchange(wt_co_t* co, uint64_t* out_handle)
{
    volatile uint8_t* share = (volatile uint8_t*)(uintptr_t)WT_SPM_SHARE_PA;
    uint8_t* rx = (uint8_t*)(uintptr_t)WT_SPM_RXTX_PA;
    uint8_t* tx = rx + WT_FFA_MEM_PAGE_SIZE;
    uint64_t* arg = (uint64_t*)(rx + WT_FFA_MEM_PAGE_SIZE - 64u);
    wt_ffa_mem_constituent_t cons;
    wt_ffa_mem_build_t in;
    uint64_t handle = 0u;
    size_t len = 0u;
    size_t req_len = 0u;

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
    if (wt_ffa_mem_txn_build(g_share_desc, sizeof(g_share_desc), &in, &len) != 0) {
        return 0;
    }
    if (wt_spm_mem_share(g_share_desc, len, WT_FFA_MEM_OP_SHARE, WT_FFA_ID_SPMC,
                         &handle) != 0) {
        return 0;
    }
    *out_handle = handle;

    /* The borrower's retrieve request waits in its TX buffer; its arguments
     * sit at the tail of its RX buffer, clear of the retrieve response. */
    if (wt_ffa_mem_retrieve_req_build_at(tx, WT_FFA_MEM_PAGE_SIZE, handle,
                                         WT_FFA_ID_SPMC, WT_FFA_ID_MEM_BORROWER,
                                         in.permissions, WT_FFA_VERSION_1_2,
                                         &req_len) != 0) {
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
    return 1;
}

static int prove_mem_share(uint64_t* out_handle)
{
    wt_memory_region_t band;
    const wt_domain_descriptor_t* d = first_partition_domain(&band);
    uint64_t* arg = (uint64_t*)(uintptr_t)(WT_SPM_RXTX_PA +
                                           WT_FFA_MEM_PAGE_SIZE - 64u);
    wt_ffa_mailbox_t* mb;
    uint8_t* stack;
    wt_co_t* co;
    int ok;

    if (d == NULL) {
        return 0;
    }
    stack = (uint8_t*)band.base;
    g_borrow_domain.regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    g_borrow_domain.regions[0].size = (uintptr_t)_e_secure_text - (uintptr_t)WT_SPM_IMAGE_PA;
    g_borrow_domain.regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    g_borrow_domain.regions[1].base = (uintptr_t)stack;
    g_borrow_domain.regions[1].size = band.size;
    g_borrow_domain.regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_borrow_domain.regions[2].base = (uintptr_t)WT_SPM_RXTX_PA;
    g_borrow_domain.regions[2].size = (size_t)WT_SPM_RXTX_SIZE;
    g_borrow_domain.regions[2].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    g_borrow_domain.region_count = 3u;

    /* The borrower exists before the share names it. */
    co = wt_co_create_blocked_ex(stack, band.size,
                                 (wt_co_entry_fn)wt_sp_ffa_borrow, (void*)arg);
    if (co == NULL) {
        return 0;
    }
    wt_co_set_domain(co, &g_borrow_domain, 1u);
    /* The borrower's RX/TX pair is the band its domain maps, registered as
     * FFA_RXTX_MAP would. */
    mb = wt_spm_sp_mailbox_of(co);
    if (wt_ffa_mailbox_map(mb, (uint64_t)WT_SPM_RXTX_PA + WT_FFA_MEM_PAGE_SIZE,
                           (uint64_t)WT_SPM_RXTX_PA, 1u) != 0) {
        return 0;
    }
    ok = (wt_spm_mem_bind(WT_FFA_ID_MEM_BORROWER, co, &g_borrow_domain) == 0)
             ? mem_share_exchange(co, out_handle) : 0;
    /* The coroutine slot outlives the proof: a partition created in it later
     * must not inherit the borrower's binding or buffers. */
    wt_spm_mem_unbind(co);
    if (wt_ffa_mailbox_unmap(mb) != 0) {
        ok = 0;
    }
    /* However far the proof got, its share ends before any partition runs. */
    if ((wt_spm_mem_in_transaction((uint64_t)WT_SPM_SHARE_PA,
                                   WT_FFA_MEM_PAGE_SIZE) != 0) &&
        (wt_spm_mem_reclaim(*out_handle, WT_FFA_ID_SPMC, 0u) != 0)) {
        spmc_fail("mem share reclaim", *out_handle);
    }
    return ok;
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
#if defined(WT_FFA_ACS) && (WT_FFA_ACS == 1)
    /* The conformance partitions time their waits on the virtual counter
     * (CNTKCTL_EL1.EL0VCTEN); production partitions get no EL0 time source. */
    wt_write_cntkctl_el1(wt_read_cntkctl_el1() | 0x2u);
    wt_isb();
#endif
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
/* The SPMC's own receivers, the PSA framework endpoint and the test echo
 * partition, answer FFA_MSG_SEND_DIRECT_REQ32/64 only. */
#define WT_SPM_DIRECT_REQ_ONLY WT_FFA_PARTINFO_PROP_DIRECT_RECV

/* A direct request the SPMD relayed from the Normal world: validate it at the
 * NS-physical instance, deliver it to the waiting receiver, and send the
 * partition's response back with FFA_MSG_SEND_DIRECT_RESP32; that SMC's
 * return is the next event. A request is answered with FFA_ERROR instead:
 * DENIED when the receiver does not take that kind of request (Tables 15.8
 * and 15.16), INVALID_PARAMETERS when its id names no endpoint. */
static void direct_request(wt_ffa_regs_ext_t* e)
{
    uint64_t req[WT_FFA_MSG_REGS_EXT];
    uint64_t resp[WT_FFA_MSG_REGS_EXT];
    wt_ffa_regs_t* r = &e->base;
    struct wt_co* co = NULL;
    uint16_t receiver = wt_ffa_direct_receiver(r->x[1]);
    uint32_t fid = (uint32_t)r->x[0];
    uint32_t props = 0u;
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
    if ((ret == 0) && (receiver == WT_FFA_ID_PSA)) {
        ret = wt_ffa_direct_req_allowed(WT_SPM_DIRECT_REQ_ONLY, fid, 1);
        if (ret == 0) {
            (void)wt_spm_psa_framework(r);
            return;
        }
    }
    if ((ret == 0) && (receiver == WT_FFA_ID_ECHO)) {
        co = wt_spm_ffa_echo_partition();
        props = WT_SPM_DIRECT_REQ_ONLY;
        ret = (co != NULL) ? 0 : WT_FFA_INVALID_PARAMETERS;
    }
    else if (ret == 0) {
        ret = wt_spm_partition_props(receiver, &props);
        co = wt_spm_ffa_native_by_id(receiver);
    }
    if (ret == 0) {
        ret = wt_ffa_direct_req_allowed(props, fid, 1);
    }
    if (ret == 0) {
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

/* The version the Normal world negotiated (13.2.3.2): the SPMD forwards each
 * FFA_VERSION it makes until that version is locked. */
static wt_ffa_version_state_t g_ns_version;

static void ns_version(wt_ffa_regs_t* r)
{
    wt_ffa_fwk_version_resp(r->x, wt_ffa_version_negotiate(
        &g_ns_version, (uint32_t)r->x[3], WT_FFA_VERSION_1_2));
}

uint32_t wt_spm_ns_ffa_version(void)
{
    return wt_ffa_version_of(&g_ns_version, WT_FFA_VERSION_1_2);
}

static int ns_range_ok(uint64_t addr, uint64_t len)
{
    uint64_t base = (uint64_t)WT_NS_IMAGE_PA;
    uint64_t limit = base + (uint64_t)WT_PSA_NS_WINDOW_SIZE;

    return ((len != 0u) && (addr >= base) && (addr < limit) &&
            (len <= (limit - addr))) ? 1 : 0;
}

int wt_spm_ns_mailbox_overlaps(uint64_t base, uint64_t size)
{
    return wt_ffa_mailbox_overlaps(&g_ns_mailbox, base, size);
}

/* FFA_RXTX_MAP from the Normal world: both buffers must lie in the window of
 * Non-secure memory the SPMC maps, still the Normal world's and clear of every
 * memory transaction. */
static void ns_rxtx_map(wt_ffa_regs_t* r)
{
    uint64_t span = (uint64_t)((uint32_t)r->x[3] & 0x3Fu) * WT_FFA_MEM_PAGE_SIZE;
    int ret = 0;

    if ((g_ns_mailbox.mapped == 0u) &&
        ((ns_range_ok(r->x[1], span) == 0) || (ns_range_ok(r->x[2], span) == 0) ||
         (wt_spm_mem_ns_owns(r->x[1], span) == 0) ||
         (wt_spm_mem_ns_owns(r->x[2], span) == 0) ||
         (wt_spm_mem_in_transaction(r->x[1], span) != 0) ||
         (wt_spm_mem_in_transaction(r->x[2], span) != 0))) {
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

    if (ret == 0) {
        wt_spm_mem_frag_abort(WT_FFA_ID_NS_PRIMARY);
    }
    ns_reply(r, ret, 0u, 0u);
}

/* FFA_PARTITION_INFO_GET forwarded from the Normal world: descriptors go to
 * the guest's RX buffer, a count-only request needs none. */
static void ns_partition_info_get(wt_ffa_regs_t* r)
{
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret = wt_spm_partition_info(r->x, wt_spm_ns_ffa_version(),
                                    &g_ns_mailbox, &count, &size);

    ns_reply(r, ret, count, size);
}

/* FFA_RUN forwarded from the Normal world: w1 names the endpoint and its
 * vCPU; what it hands back (response, FFA_YIELD, FFA_MSG_WAIT) is the reply. */
static void ns_run(wt_ffa_regs_ext_t* e)
{
    uint64_t out[WT_FFA_MSG_REGS_EXT];
    struct wt_co* co = NULL;
    uint16_t id = 0u;
    int ret = wt_ffa_run_target((uint32_t)e->base.x[1], &id);

    if (ret == 0) {
        co = wt_spm_ffa_native_by_id(id);
        ret = (co != NULL) ? wt_spm_ffa_run(co, WT_FFA_ID_NS_PRIMARY, out)
                           : WT_FFA_INVALID_PARAMETERS;
    }

    if (ret != 0) {
        ns_reply(&e->base, ret, 0u, 0u);
        return;
    }
    ns_reply_regs(e, out);
}

/* FFA_INTERRUPT the SPMD signalled because a Secure interrupt preempted the
 * Normal world (Ch.9). It carries no id (12.4.1 item 3): the SPMC takes the
 * interrupt from the GIC, schedules (nothing else is runnable here) and yields
 * the CPU back with FFA_NORMAL_WORLD_RESUME. The resume SMC's return is the
 * next event. */
static void ns_interrupt(wt_ffa_regs_t* r)
{
    uint32_t intid = wt_spm_ns_sint_take();
    struct wt_co* owner;
    unsigned int i;

    if (intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_spm_twdog_tick();
        wt_el3_puts("[SPM] ns preempt intid=0x");
        wt_el3_puthex(intid, 2u);
        wt_el3_puts("\r\n");
    }
    else {
        owner = wt_spm_sint_owner(intid);
        if (owner != NULL) {
            /* Table 9.1: signal a waiting owner, queue for a busy one. */
            if (wt_spm_ffa_signal_deliver(owner, intid) != 0) {
                wt_spm_sint_queue_for(owner, intid);
            }
        }
        else {
            wt_el3_puts("[SPM] ns preempt intid=0x");
            wt_el3_puthex(intid, 3u);
            wt_el3_puts("\r\n");
        }
    }
    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_NORMAL_WORLD_RESUME;
}

/* At this physical instance FFA_MEM_FRAG_RX/TX carry the Owner's id in
 * w4[31:16], bits[15:0] SBZ (Table 4.7); the Normal-world owner is the primary
 * endpoint. */
#define WT_NS_FRAG_W4 ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16)

static void ns_frag_rx_reply(wt_ffa_regs_t* r, uint64_t handle, uint32_t offset)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        r->x[i] = 0u;
    }
    r->x[0] = WT_FFA_MEM_FRAG_RX;
    r->x[1] = handle & 0xFFFFFFFFu;
    r->x[2] = handle >> 32;
    r->x[3] = (uint64_t)offset;
    r->x[4] = WT_NS_FRAG_W4;
}

static void ns_handle_reply(wt_ffa_regs_t* r, int ret, uint64_t handle)
{
    unsigned int i;

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

/* FFA_MEM_SHARE / LEND / DONATE forwarded from the Normal world: the guest's
 * descriptor (length in w1, this fragment's in w2) is in its TX buffer inside
 * the SPMC's Non-secure window; w3/x3 and w4 name no dynamically allocated
 * buffer, which FFA_FEATURES does not offer. Validate and register it; reply
 * with the handle in w2/w3 or an error. A malformed descriptor is refused,
 * never a crash. The reply SMC's return is the next event. */
static void ns_mem_send(wt_ffa_regs_t* r, wt_ffa_mem_op_t op)
{
    uint64_t addr = 0u;
    uint32_t total = (uint32_t)r->x[1];
    uint32_t frag = (uint32_t)r->x[2];
    uint64_t handle = 0u;
    int ret;

    ret = wt_ffa_mem_tx_buffer(&g_ns_mailbox, r->x[3], (uint32_t)r->x[4], frag,
                               &addr);
    if ((ret == 0) && ((frag < 1u) || (frag > total) ||
                       (ns_range_ok(addr, (uint64_t)frag) == 0))) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        ret = wt_spm_mem_ns_send(op, (const uint8_t*)(uintptr_t)addr, frag,
                                 total, &handle);
    }
    if ((ret == 0) && (frag < total)) {
        ns_frag_rx_reply(r, handle, frag);
        return;
    }
    ns_handle_reply(r, ret, handle);
}

/* FFA_MEM_FRAG_TX forwarded from the Normal world: the next fragment of a
 * descriptor it began sending, in the TX buffer the first one used, which is
 * still mapped (an unmap aborts the transfer); the last one completes the
 * send. */
static void ns_mem_frag_tx(wt_ffa_regs_t* r)
{
    uint64_t handle = (uint64_t)(uint32_t)r->x[1] |
                      ((uint64_t)(uint32_t)r->x[2] << 32);
    uint32_t len = (uint32_t)r->x[3];
    const uint8_t* frag = NULL;
    uint64_t tx = 0u;
    uint32_t offset = 0u;
    int done = 0;
    int ret = WT_FFA_INVALID_PARAMETERS;

    if (((uint32_t)r->x[4] & 0xFFFF0000u) == (uint32_t)WT_NS_FRAG_W4) {
        if ((wt_ffa_mem_tx_buffer(&g_ns_mailbox, 0u, 0u, len, &tx) == 0) &&
            (ns_range_ok(tx, (uint64_t)len) != 0)) {
            frag = (const uint8_t*)(uintptr_t)tx;
        }
        ret = wt_spm_mem_frag_next(handle, WT_FFA_ID_NS_PRIMARY, frag, len,
                                   &offset, &done);
    }
    if ((ret == 0) && (done == 0)) {
        ns_frag_rx_reply(r, handle, offset);
        return;
    }
    if (ret == 0) {
        ret = wt_spm_mem_frag_share(handle, WT_FFA_ID_NS_PRIMARY);
    }
    ns_handle_reply(r, ret, handle);
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

/* The Normal-world scheduler's notification calls, forwarded by the SPMD.
 * The primary NS endpoint is both the only VM and its own scheduler. */
static void ns_notif_bind(wt_ffa_regs_t* r, unsigned int unbind)
{
    uint32_t w1 = (uint32_t)r->x[1];
    uint32_t w2 = (uint32_t)r->x[2];
    uint64_t bitmap = (uint64_t)(uint32_t)r->x[3] |
                      ((uint64_t)(uint32_t)r->x[4] << 32);
    int32_t ret;

    if (unbind != 0u) {
        ret = wt_ffa_notif_unbind(WT_FFA_ID_NS_PRIMARY, w1, w2, bitmap);
    }
    else {
        ret = wt_ffa_notif_bind(WT_FFA_ID_NS_PRIMARY, w1, w2, bitmap);
    }
    ns_reply(r, ret, 0u, 0u);
}

static void ns_notif_set(wt_ffa_regs_t* r)
{
    uint64_t bitmap = (uint64_t)(uint32_t)r->x[3] |
                      ((uint64_t)(uint32_t)r->x[4] << 32);

    ns_reply(r, wt_spm_notif_set(WT_FFA_ID_NS_PRIMARY, (uint32_t)r->x[1],
                                 (uint32_t)r->x[2], bitmap), 0u, 0u);
}

static void ns_notif_get(wt_ffa_regs_t* r)
{
    wt_ffa_notif_get_result_t got;
    int32_t ret = wt_ffa_notif_get(WT_FFA_ID_NS_PRIMARY, (uint32_t)r->x[1],
                                   (uint32_t)r->x[2], &got);

    ns_reply(r, (int)ret, 0u, 0u);
    if (ret == 0) {
        wt_ffa_mailbox_rx_claim(&g_ns_mailbox, got.framework);
        r->x[2] = (uint32_t)got.from_sp;
        r->x[3] = (uint32_t)(got.from_sp >> 32);
        r->x[4] = (uint32_t)got.from_vm;
        r->x[5] = (uint32_t)(got.from_vm >> 32);
        r->x[6] = (uint32_t)got.framework;
        r->x[7] = (uint32_t)(got.framework >> 32);
    }
}

static void ns_notif_info_get(wt_ffa_regs_t* r, unsigned int is64)
{
    wt_ffa_notif_info_result_t info;
    int32_t ret = wt_ffa_notif_info_get(WT_FFA_ID_NS_PRIMARY,
                                        (is64 != 0u) ? 1 : 0, &info);
    unsigned int i;

    ns_reply(r, (int)ret, 0u, 0u);
    if (ret == 0) {
        r->x[0] = (is64 != 0u) ? WT_FFA_SUCCESS64 : WT_FFA_SUCCESS32;
        r->x[2] = info.w2;
        for (i = 0u; i < WT_FFA_NOTIF_INFO_MAX_REGS; i++) {
            r->x[3u + i] = info.regs[i];
        }
    }
}

/* FFA_MSG_SEND2 (16.4), shared by both conduits: the partition message in
 * the caller's TX buffer is copied into the receiver's RX, whose RX-full
 * framework notification tells the Normal-world scheduler to run it. Only a
 * sender and a receiver whose properties advertise indirect messaging take
 * part. */
int wt_spm_msg2_deliver(uint16_t caller, uint32_t version, const uint8_t* tx,
                        uint32_t tx_size, wt_ffa_instance_t inst, uint32_t w1,
                        uint32_t w2)
{
    static const uint8_t ns_uuid[16];
    wt_ffa_msg2_t msg;
    const wt_ffa_native_sp_t* natives;
    const uint8_t* uuid = NULL;
    uint32_t properties = 0u;
    uint32_t rx_version = WT_FFA_VERSION_1_2;
    wt_ffa_mailbox_t* mb = NULL;
    size_t count = 0u;
    size_t i;
    uint64_t total;
    int ret;

    ret = wt_ffa_msg2_parse(tx, tx_size, caller, version, inst, w1, w2, &msg);
    if (ret == 0) {
        ret = wt_spm_msg2_sender_allowed(caller);
    }
    if (ret == 0) {
        if (msg.receiver == WT_FFA_ID_NS_PRIMARY) {
            uuid = ns_uuid;
            properties = WT_FFA_PARTINFO_PROP_INDIRECT;
            rx_version = wt_spm_ns_ffa_version();
            mb = &g_ns_mailbox;
        }
        else {
            natives = wt_spm_ffa_native_list(&count);
            for (i = 0u; i < count; i++) {
                if (wt_spm_ffa_native_id(i) == msg.receiver) {
                    uuid = natives[i].uuid;
                    properties = natives[i].properties;
                    rx_version = wt_spm_sp_ffa_version(
                        wt_spm_ffa_native_by_id(msg.receiver));
                    mb = wt_spm_sp_mailbox_of(
                        wt_spm_ffa_native_by_id(msg.receiver));
                }
            }
            if (uuid == NULL) {
                /* Table 15.4: a listed partition taking no indirect messages
                 * (a PSA partition) is DENIED, only an unknown id refused. */
                ret = (wt_spm_partition_props(msg.receiver, &properties) == 0) ?
                      WT_FFA_DENIED : WT_FFA_INVALID_PARAMETERS;
            }
            else if (wt_spm_sp_unavailable(
                         wt_spm_ffa_native_by_id(msg.receiver)) != 0) {
                ret = WT_FFA_DENIED;
            }
        }
    }
    if ((ret == 0) && ((properties & WT_FFA_PARTINFO_PROP_INDIRECT) == 0u)) {
        ret = WT_FFA_DENIED;
    }
    if ((ret == 0) && (wt_ffa_msg2_uuid_ok(msg.uuid, uuid) == 0)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        ret = wt_ffa_notif_frame_ready(msg.receiver);
    }
    if (ret == 0) {
        total = (uint64_t)wt_ffa_msg2_rx_offset(&msg, rx_version) +
                (uint64_t)msg.size;
        if ((mb != NULL) && (mb->mapped != 0u) &&
            (total > (uint64_t)(mb->pages * (uint32_t)WT_TABLES_PAGE_SIZE))) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
        else {
            ret = wt_ffa_mailbox_rx_post(mb);
        }
    }
    if (ret == 0) {
        wt_ffa_msg2_copy((uint8_t*)(uintptr_t)mb->rx,
                         mb->pages * (uint32_t)WT_TABLES_PAGE_SIZE,
                         rx_version, tx, &msg);
        (void)wt_ffa_notif_frame_rx_full(msg.receiver,
                                         wt_ffa_id_is_secure(caller));
    }
    return ret;
}

/* FFA_MSG_SEND2 forwarded from the Normal world. */
static void ns_msg_send2(wt_ffa_regs_t* r)
{
    int ret;

    if (g_ns_mailbox.mapped == 0u) {
        ns_reply(r, WT_FFA_DENIED, 0u, 0u);
        return;
    }
    ret = wt_spm_msg2_deliver(WT_FFA_ID_NS_PRIMARY, wt_spm_ns_ffa_version(),
                              (const uint8_t*)(uintptr_t)g_ns_mailbox.tx,
                              g_ns_mailbox.pages * (uint32_t)WT_TABLES_PAGE_SIZE,
                              WT_FFA_INSTANCE_NS_PHYSICAL,
                              (uint32_t)r->x[1], (uint32_t)r->x[2]);
    ns_reply(r, ret, 0u, 0u);
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
#if defined(WT_EL3_NS_SMOKE)
/* An 8-register event delivered over ERET must arrive with x8-x17 zero
 * (11.2), never with what the SPMC handed the monitor at its last SMC. */
static void eret_sbz_probe(const wt_ffa_regs_ext_t* e)
{
    static uint8_t seen;
    unsigned int i;
    int clean = 1;

    if (wt_ffa_msg_reg_count((uint32_t)e->base.x[0]) != WT_FFA_MSG_REGS) {
        return;
    }
    for (i = 0u; i < (WT_FFA_MSG_REGS_EXT - WT_FFA_MSG_REGS); i++) {
        if (e->ext[i] != 0u) {
            clean = 0;
        }
    }
    if (!clean) {
        wt_el3_puts("[SPM] eret sbz BAD\r\n");
    }
    else if (seen == 0u) {
        seen = 1u;
        wt_el3_puts("[SPM] eret sbz ok\r\n");
    }
}
#endif

static void idle_dispatch(wt_ffa_regs_ext_t* e)
{
    wt_ffa_regs_t* r = &e->base;

#if defined(WT_EL3_NS_SMOKE)
    eret_sbz_probe(e);
#endif
    switch ((uint32_t)r->x[0]) {
        case WT_FFA_MSG_SEND_DIRECT_REQ32:
        case WT_FFA_MSG_SEND_DIRECT_REQ64:
        case WT_FFA_MSG_SEND_DIRECT_REQ2:
            if (wt_ffa_fwk_version_is_req(r->x) != 0) {
                ns_version(r);
            }
            else {
                direct_request(e);
            }
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
            /* w1[15:0] names the VM whose RX buffer is released (Table
             * 13.21); only the primary endpoint has a pair here. */
            ns_reply(r,
                     (((uint32_t)r->x[1] & 0xFFFFu) == WT_FFA_ID_NS_PRIMARY)
                         ? wt_ffa_mailbox_rx_release(&g_ns_mailbox)
                         : WT_FFA_INVALID_PARAMETERS,
                     0u, 0u);
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
        case WT_FFA_MEM_FRAG_TX:
            ns_mem_frag_tx(r);
            break;
        case WT_FFA_MEM_FRAG_RX:
            /* Nothing is lent to the Normal world, so no retrieve response
             * is ever outstanding for it to ask the rest of. */
            ns_reply(r, WT_FFA_INVALID_PARAMETERS, 0u, 0u);
            break;
        case WT_FFA_NOTIFICATION_BITMAP_CREATE:
            ns_reply(r, wt_ffa_notif_bitmap_create(WT_FFA_ID_NS_PRIMARY,
                     (uint32_t)r->x[1], (uint32_t)r->x[2]), 0u, 0u);
            break;
        case WT_FFA_NOTIFICATION_BITMAP_DESTROY:
            ns_reply(r, wt_ffa_notif_bitmap_destroy(WT_FFA_ID_NS_PRIMARY,
                     (uint32_t)r->x[1]), 0u, 0u);
            break;
        case WT_FFA_NOTIFICATION_BIND:
            ns_notif_bind(r, 0u);
            break;
        case WT_FFA_NOTIFICATION_UNBIND:
            ns_notif_bind(r, 1u);
            break;
        case WT_FFA_NOTIFICATION_SET:
            ns_notif_set(r);
            break;
        case WT_FFA_NOTIFICATION_GET:
            ns_notif_get(r);
            break;
        case WT_FFA_NOTIFICATION_INFO_GET32:
            ns_notif_info_get(r, 0u);
            break;
        case WT_FFA_NOTIFICATION_INFO_GET64:
            ns_notif_info_get(r, 1u);
            break;
        case WT_FFA_MSG_SEND2:
            ns_msg_send2(r);
            break;
#if defined(WT_FFA_ACS) && (WT_FFA_ACS == 1)
        case WT_SPM_SVC_FID_TIMER_ARM:
            /* The ACS platform layer's test timer, from the Normal world:
             * the armed id keeps its Normal-world group so its expiry
             * preempts a running partition for the Normal world to take. */
            ns_reply(r, (wt_spm_twdog_arm(NULL, (uint32_t)r->x[1],
                                          (uint32_t)r->x[2]) == 0) ?
                        0 : WT_FFA_INVALID_PARAMETERS, 0u, 0u);
            break;
        case WT_SPM_SVC_FID_TIMER_STOP:
            wt_spm_twdog_stop(NULL);
            ns_reply(r, 0, 0u, 0u);
            break;
#endif
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
#if defined(WT_EL3_NS_SMOKE)
                /* Test only: a value the monitor must not hand back (11.2). */
                e.ext[i] = 0xC0DE0000u + i;
#else
                e.ext[i] = 0u;
#endif
            }
        }
        /* Every hand-off to the Normal world funnels through this SMC, so
         * pending notification work raises the schedule-receiver SGI here. */
        if (wt_ffa_notif_sri_take() != 0) {
            wt_gic->raise_ns_sgi(WT_FFA_SRI_INTID);
            wt_el3_puts("[SPM] sri sgi\r\n");
        }
        wt_platform_console_flush();
        wt_ffa_smc_ext(&e);
        event = (uint32_t)e.base.x[0];
        idle_dispatch(&e);
    }
}
