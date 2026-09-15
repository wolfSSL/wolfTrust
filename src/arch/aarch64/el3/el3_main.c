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
#define WT_SPM_BOOT_INFO_LIMIT 4096u
#define WT_EL3_PARK_WAIT_MS 200u
#define WT_EL3_TICK_PERIOD_MS 10u
#define WT_EL3_TICK_WAIT_MS 100u

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
    uint32_t expected = (uint32_t)((1u << WT_PORT_BOOT_CPUS) - 2u);
    uint64_t deadline = deadline_after_ms(WT_EL3_PARK_WAIT_MS);
    uint32_t mask;

    do {
        mask = parked_mask();
    } while ((mask != expected) && (wt_read_cntpct_el0() < deadline));
    return mask;
}

/* One secure timer period with FIQ unmasked at EL3: the tick must arrive as
 * INTID 29 through the vector table before the deadline. */
static void prove_tick(void)
{
    uint64_t deadline = deadline_after_ms(WT_EL3_TICK_WAIT_MS);

    g_wt_el3_tick_intid = 0u;
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
    wt_el3_timer_arm_ms(WT_EL3_TICK_PERIOD_MS);
    wt_daif_clear_fiq();
    while ((g_wt_el3_tick_intid == 0u) && (wt_read_cntpct_el0() < deadline)) {
    }
    wt_daif_set_fiq();
    wt_el3_timer_disable();
    wt_gic->disable(WT_GIC_INTID_SECURE_TIMER);

    if (g_wt_el3_tick_intid == WT_GIC_INTID_SECURE_TIMER) {
        wt_el3_puts("[EL3] tick ok intid=29\r\n");
    }
    else {
        wt_el3_puts("[EL3] tick TIMEOUT intid=");
        wt_el3_putdec(g_wt_el3_tick_intid);
        wt_el3_puts("\r\n");
    }
}

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
        (void)wt_el3_monitor_call(WT_MON_FID_PANIC, 0xB1u);
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

void wt_el3_spmc_ready(void)
{
    wt_el3_puts("[EL3] spmc ready\r\n");
    wt_platform_console_flush();
#if defined(WT_EL3_NS_SMOKE) && (WT_EL3_NS_SMOKE == 1)
    /* Turn on the Normal world: ERET to the NS-EL1 payload the runner loaded.
     * EL1 system registers are not banked by security state on these cores, so
     * the SPMC left SCTLR_EL1.M set with its secure tables; reset SCTLR_EL1 to
     * an MMU-off state before the switch so the NS payload runs unmapped (the
     * SPMC is not resumed after this in B3.1). */
    wt_write_sctlr_el1(WT_SCTLR_EL1_RES1);
    wt_isb();
    wt_el3_puts("[EL3] ns launch pc=0x");
    wt_el3_puthex((uint64_t)WT_NS_IMAGE_PA, 8u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
    wt_el3_enter_ns((void (*)(void))(uintptr_t)WT_NS_IMAGE_PA, 0u, 0u);
#endif
    /* No Normal world (or the NS payload returned): the boot proof ends here. */
    (void)wt_el3_monitor_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
    for (;;) {
    }
}

void wt_el3_main(void)
{
    uint32_t mask;
    uint64_t boot_info;

    wt_platform_board_init();
    wt_gic->init_secure();
    mask = wait_for_secondaries();

    wt_el3_puts("[EL3] wolfTrust monitor cntfrq=");
    wt_el3_putdec(wt_read_cntfrq_el0());
    wt_el3_puts(" gic=v");
    wt_el3_putdec(wt_gic->version);
    wt_el3_puts(" rdist_woken=");
    wt_el3_putdec(wt_gic_rdist_woken());
    wt_el3_puts(" secondaries parked mask=0x");
    wt_el3_puthex(mask, 1u);
    wt_el3_puts("\r\n");

    prove_tick();
    boot_info = build_boot_info();

    wt_write_sctlr_el1(WT_SCTLR_EL1_RES1);
#if defined(WT_SPM_FLASH_OFFSET)
    /* The SPMC image sits behind the monitor in flash; a boot loader does
     * this copy on silicon. */
    (void)memcpy((void*)(uintptr_t)WT_SPM_IMAGE_PA,
                 (const void*)(uintptr_t)(WT_EL3_TEXT_BASE + WT_SPM_FLASH_OFFSET),
                 (size_t)WT_SPM_IMAGE_SIZE);
#endif
    wt_el3_puts("[EL3] spmc image at 0x");
    wt_el3_puthex((uint64_t)WT_SPM_IMAGE_PA, 8u);
    wt_el3_puts("\r\n");
    wt_el3_enter_secure_el1((void (*)(void))(uintptr_t)WT_SPM_IMAGE_PA, 0u,
                            boot_info);
}
