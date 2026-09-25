/* el3_main.c
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

/* EL3 boot core: bring up the board and the GIC, account for the parked
 * secondaries, prove the secure timer reaches EL3 as a Group 0 FIQ, print
 * the banner, and drop into the Secure EL1 entry. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_boot_info.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/sysreg.h"
#if defined(WT_EL3_TEST_HANDOFF)
#include "wolftrust/boot_handoff.h"
#include "psa/lifecycle.h"
#endif

#include <string.h>

#ifndef WT_PORT_BOOT_CPUS
#define WT_PORT_BOOT_CPUS 1u
#endif
#ifndef WT_SPM_BOOT_INFO_PA
#error "the target fragment must place the FF-A boot information page"
#endif
#ifndef WT_PORT_HANDOFF_PA
#define WT_PORT_HANDOFF_PA 0u
#endif
#ifndef WT_PORT_HANDOFF_SIZE
#define WT_PORT_HANDOFF_SIZE 0u
#endif
/* Every core the port declares but the boot core must park in the EL3 pen;
 * a core it does not declare may park there too. */
#define WT_EL3_PARK_EXPECTED ((uint32_t)((1u << WT_PORT_BOOT_CPUS) - 2u))
#define WT_SPM_BOOT_INFO_LIMIT 4096u
#define WT_EL3_PARK_WAIT_MS 200u
#define WT_EL3_TICK_PERIOD_MS 10u
#define WT_EL3_TICK_WAIT_MS 100u

/* Monitor panic codes for a boot that must not reach the Secure runtime. */
#define WT_EL3_PANIC_BOOT_INFO    0xB1u
#define WT_EL3_PANIC_NOT_PARKED   0xB2u
#define WT_EL3_PANIC_RDIST_ASLEEP 0xB3u
#define WT_EL3_PANIC_NO_TICK      0xB4u
#define WT_EL3_PANIC_MDCR         0xB5u

/* MDCR_EL3 fields every PE implements, plus the PMU, SPE, and TRBE ones the
 * PE reports; the rest are RES0 on some PEs and are left out of the compare. */
#define WT_MDCR_EL3_TPM   (1ull << 6)
#define WT_MDCR_EL3_TDA   (1ull << 9)
#define WT_MDCR_EL3_TDOSA (1ull << 10)
#define WT_MDCR_EL3_NSPB  (3ull << 12)
#define WT_MDCR_EL3_SPD32 (3ull << 14)
#define WT_MDCR_EL3_SDD   (1ull << 16)
#define WT_MDCR_EL3_SPME  (1ull << 17)
#define WT_MDCR_EL3_STE   (1ull << 18)
#define WT_MDCR_EL3_SCCD  (1ull << 23)
#define WT_MDCR_EL3_NSTB  (3ull << 24)

volatile uint8_t g_wt_el3_parked[WT_EL3_MAX_CPUS];
volatile uint32_t g_wt_el3_ready;

extern uint8_t __spm_stack_top[];

static uint64_t deadline_after_ms(uint32_t ms)
{
    return wt_read_cntpct_el0() + ((wt_read_cntfrq_el0() * ms) / 1000u);
}

static uint32_t parked_mask(void)
{
    uint32_t mask = 0u;
    uint32_t i;

    for (i = 0u; i < WT_EL3_MAX_CPUS; i++) {
        if (g_wt_el3_parked[i] != 0u) {
            mask |= (1u << i);
        }
    }
    return mask;
}

static uint32_t wait_for_secondaries(void)
{
    uint64_t deadline = deadline_after_ms(WT_EL3_PARK_WAIT_MS);
    uint32_t mask;

    do {
        mask = parked_mask();
    } while (((mask & WT_EL3_PARK_EXPECTED) != WT_EL3_PARK_EXPECTED) &&
             (wt_read_cntpct_el0() < deadline));
    return mask;
}

/* One secure timer period with FIQ unmasked at EL3: the tick must arrive as
 * INTID 29 through the vector table before the deadline. */
static int prove_tick(void)
{
    uint64_t deadline = deadline_after_ms(WT_EL3_TICK_WAIT_MS);

    g_wt_el3_tick_intid = 0u;
#if !defined(WT_EL3_BOOT_NEG_PROBE) || (WT_EL3_BOOT_NEG_PROBE != 2)
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
#endif
    wt_el3_timer_arm_ms(WT_EL3_TICK_PERIOD_MS);
    wt_daif_clear_fiq();
    while ((g_wt_el3_tick_intid == 0u) && (wt_read_cntpct_el0() < deadline)) {
    }
    wt_daif_set_fiq();
    wt_el3_timer_disable();
    wt_gic->disable(WT_GIC_INTID_SECURE_TIMER);

    if (g_wt_el3_tick_intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_el3_puts("[EL3] tick ok intid=29\r\n");
        return 0;
    }
    wt_el3_puts("[EL3] tick TIMEOUT intid=");
    wt_el3_putdec(g_wt_el3_tick_intid);
    wt_el3_puts("\r\n");
    return -1;
}

/* The single-PE isolation model and Secure preemption rest on these: stop
 * the boot through the monitor panic path instead of entering the Secure
 * runtime. */
/* The debug and PMU policy start.S must have set: Secure-state counting,
 * tracing, profiling, and self-hosted debug all disabled, nothing trapped.
 * *mask names the fields the PE implements; the value is what they must read. */
static uint64_t wt_el3_mdcr_expected(uint64_t* mask)
{
    uint64_t dfr0 = wt_read_id_aa64dfr0_el1();
    uint64_t pmuver = (dfr0 >> 8) & 0xFu;
    uint64_t want = WT_MDCR_EL3_SDD | (2ull << 14);

    *mask = WT_MDCR_EL3_TPM | WT_MDCR_EL3_TDA | WT_MDCR_EL3_TDOSA |
            WT_MDCR_EL3_SPD32 | WT_MDCR_EL3_SDD | WT_MDCR_EL3_SPME |
            WT_MDCR_EL3_STE;
    if ((pmuver >= 6u) && (pmuver != 0xFu)) {
        *mask |= WT_MDCR_EL3_SCCD;
        want |= WT_MDCR_EL3_SCCD;
    }
    if (((dfr0 >> 32) & 0xFu) != 0u) {
        *mask |= WT_MDCR_EL3_NSPB;
        want |= (2ull << 12);
    }
    if (((dfr0 >> 44) & 0xFu) != 0u) {
        *mask |= WT_MDCR_EL3_NSTB;
        want |= (2ull << 24);
    }
    return want;
}

static int wt_el3_mdcr_ok(void)
{
    uint64_t mask = 0u;
    uint64_t want = wt_el3_mdcr_expected(&mask);
    uint64_t got = wt_read_mdcr_el3();

    if ((got & mask) == want) {
        wt_el3_puts("[EL3] mdcr_el3 ok\r\n");
        return 1;
    }
    wt_el3_puts("[EL3] mdcr_el3 BAD 0x");
    wt_el3_puthex((uint32_t)got, 8u);
    wt_el3_puts("\r\n");
    return 0;
}

static void require_boot_invariant(int ok, uint64_t code)
{
    if (ok == 0) {
        (void)wt_el3_monitor_call(WT_MON_FID_PANIC, code);
    }
}

#if defined(WT_EL3_TEST_HANDOFF)
/* Stand in for the boot loader: an unlocked-lifecycle record whose measurement
 * is a fixed pattern. Never built into production images. */
static void synthesize_test_handoff(void)
{
    wt_boot_handoff_t* rec = (wt_boot_handoff_t*)(uintptr_t)WT_PORT_HANDOFF_PA;
    uint32_t i;

    (void)memset(rec, 0, WT_PORT_HANDOFF_SIZE);
    rec->magic = WT_BOOT_HANDOFF_MAGIC;
    rec->magic_inverse = ~WT_BOOT_HANDOFF_MAGIC;
    rec->version = (uint16_t)WT_BOOT_HANDOFF_VERSION;
    rec->size = (uint16_t)sizeof(*rec);
    rec->lifecycle = PSA_LIFECYCLE_ASSEMBLY_AND_TEST;
    rec->image_version = 1u;
    rec->hash_algorithm = (uint16_t)WT_BOOT_HANDOFF_HASH_SHA256;
    rec->measurement_size = (uint16_t)WT_BOOT_HANDOFF_DIGEST_SIZE;
    for (i = 0u; i < WT_BOOT_HANDOFF_DIGEST_SIZE; i++) {
        rec->measurement[i] = (uint8_t)(0xA0u + i);
    }
}
#endif

/* 5.4: one 4K page at the start of the SPM band; the wolfBoot handoff record
 * rides an IMPDEF descriptor when the port has one (WT-PORT-0020). */
static uint64_t build_boot_info(void)
{
    uint8_t* blob = (uint8_t*)(uintptr_t)WT_SPM_BOOT_INFO_PA;
    wt_ffa_boot_info_item_t item;
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret;

    item.source = (const void*)(uintptr_t)WT_PORT_HANDOFF_PA;
    item.value = 0u;
    item.name = WT_FFA_BOOT_INFO_NAME_WT_HANDOFF;
    item.size = WT_PORT_HANDOFF_SIZE;
    item.type = WT_FFA_BOOT_INFO_TYPE_WT_HANDOFF;
    item.name_format = WT_FFA_BOOT_INFO_NAME_STRING;
    item.contents_format = WT_FFA_BOOT_INFO_CONTENTS_ADDRESS;
    if ((WT_PORT_HANDOFF_PA != 0u) && (WT_PORT_HANDOFF_SIZE != 0u)) {
        count = 1u;
    }
    ret = wt_ffa_boot_info_build(blob, WT_SPM_BOOT_INFO_PA, WT_SPM_BOOT_INFO_LIMIT,
                                 WT_FFA_VERSION_1_2, &item, count, &size);
    if (ret != WT_FFA_BOOT_INFO_OK) {
        wt_el3_puts("[EL3] boot info build failed\r\n");
        (void)wt_el3_monitor_call(WT_MON_FID_PANIC, WT_EL3_PANIC_BOOT_INFO);
    }
    if (count != 0u) {
        /* The SPMC owns the only copy from here on. */
        (void)memset((void*)(uintptr_t)WT_PORT_HANDOFF_PA, 0, WT_PORT_HANDOFF_SIZE);
    }
    wt_el3_puts("[EL3] boot info at 0x");
    wt_el3_puthex(WT_SPM_BOOT_INFO_PA, 8u);
    wt_el3_puts(" size=");
    wt_el3_putdec(size);
    wt_el3_puts(" descs=");
    wt_el3_putdec(count);
    wt_el3_puts("\r\n");
    return WT_SPM_BOOT_INFO_PA;
}

void wt_el3_main(void)
{
    uint32_t mask;
    uint32_t woken;
    uint64_t boot_info;

    wt_platform_board_init();
    wt_gic->init_secure();
#if defined(WT_GIC_SPI_ROUTE_PROBE) && (WT_GIC_SPI_ROUTE_PROBE == 1) && \
    (WT_GIC_VERSION == 3)
    wt_el3_puts("[EL3] probe: every SPI routed to an absent PE\r\n");
#endif
    mask = wait_for_secondaries();
    woken = wt_gic_rdist_woken();
#if defined(WT_EL3_BOOT_NEG_PROBE) && (WT_EL3_BOOT_NEG_PROBE == 1)
    woken = 0u;
#endif

    wt_el3_puts("[EL3] wolfTrust monitor cntfrq=");
    wt_el3_putdec(wt_read_cntfrq_el0());
    wt_el3_puts(" gic=v");
    wt_el3_putdec(wt_gic->version);
    wt_el3_puts(" rdist_woken=");
    wt_el3_putdec(woken);
    wt_el3_puts(" secondaries parked mask=0x");
    wt_el3_puthex(mask, 1u);
    wt_el3_puts("\r\n");
    require_boot_invariant(
        (mask & WT_EL3_PARK_EXPECTED) == WT_EL3_PARK_EXPECTED,
        WT_EL3_PANIC_NOT_PARKED);
    require_boot_invariant(woken != 0u, WT_EL3_PANIC_RDIST_ASLEEP);
    require_boot_invariant(wt_el3_mdcr_ok(), WT_EL3_PANIC_MDCR);
    require_boot_invariant(prove_tick() == 0, WT_EL3_PANIC_NO_TICK);
#if defined(WT_EL3_TEST_HANDOFF)
    synthesize_test_handoff();
#endif
    boot_info = build_boot_info();

    wt_write_sctlr_el1(WT_SCTLR_EL1_RES1);
#if defined(WT_SPM_FLASH_OFFSET)
    /* The SPMC image sits behind the monitor in flash; a boot loader does
     * this copy on silicon. */
    (void)memcpy((void*)(uintptr_t)WT_SPM_IMAGE_PA,
                 (const void*)(uintptr_t)(WT_EL3_TEXT_BASE + WT_SPM_FLASH_OFFSET),
                 (size_t)WT_SPM_IMAGE_SIZE);
#endif
#if defined(WT_FFA_ACS_FLASH_OFFSET)
    /* Conformance image only: the FF-A ACS partition images and the suite's
     * test NVM ride behind the SPMC image in flash, since nothing else can
     * place them in Secure RAM on this machine. The partition images are laid
     * down fresh every boot, but the NVM (behind them, from WT_FFA_ACS_NVM_
     * OFFSET) records the suite's progress and must survive a reset: the
     * isolation tests fault a partition on purpose and resume off it. */
    (void)memcpy((void*)(uintptr_t)WT_FFA_ACS_BASE,
                 (const void*)(uintptr_t)(WT_EL3_TEXT_BASE + WT_FFA_ACS_FLASH_OFFSET),
                 (size_t)WT_FFA_ACS_NVM_OFFSET);
    if (wt_el3_reset_count() == 0u) {
        (void)memcpy((void*)(uintptr_t)(WT_FFA_ACS_BASE + WT_FFA_ACS_NVM_OFFSET),
                     (const void*)(uintptr_t)(WT_EL3_TEXT_BASE +
                                              WT_FFA_ACS_FLASH_OFFSET +
                                              WT_FFA_ACS_NVM_OFFSET),
                     (size_t)(WT_FFA_ACS_FLASH_SIZE - WT_FFA_ACS_NVM_OFFSET));
    }
#endif
    wt_el3_puts("[EL3] spmc image at 0x");
    wt_el3_puthex((uint64_t)WT_SPM_IMAGE_PA, 8u);
    wt_el3_puts("\r\n");
    wt_el3_enter_secure_el1((void (*)(void))(uintptr_t)WT_SPM_IMAGE_PA, 0u,
                            boot_info);
}
