/* main.c
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

#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/types.h"

static volatile uint32_t g_test_csr;
static volatile uint32_t g_test_rvr;
static volatile uint32_t g_test_cvr;
static volatile uint32_t g_test_icsr;
static volatile uint32_t g_test_iabr[WT_MAX_IRQ_WORDS];
static volatile uint8_t g_test_ipr[WT_MAX_IRQ_WORDS * 32u];
static volatile uint32_t g_test_ticks;
static volatile uint32_t g_test_inject;
static volatile uint32_t g_test_handoff;
static volatile uint32_t g_test_mask_seen;
static volatile uint32_t g_test_bad_handoff;
static volatile uint32_t g_test_reset_owner;

static volatile uint32_t* test_reload_register(void);

#undef WT_SYST_NS_CSR
#undef WT_SYST_NS_RVR
#undef WT_SYST_NS_CVR
#undef WT_SCB_ICSR_NS
#undef WT_NVIC_IABR_NS
#undef WT_NVIC_IPR_NS
#define WT_SYST_NS_CSR g_test_csr
#define WT_SYST_NS_RVR (*test_reload_register())
#define WT_SYST_NS_CVR g_test_cvr
#define WT_SCB_ICSR_NS g_test_icsr
#define WT_NVIC_IABR_NS g_test_iabr
#define WT_NVIC_IPR_NS g_test_ipr

/* Stable NS register model; Secure SysTick and WFI execute on the Cortex-M. */
#include "../../../src/arch/armv8m/guest_context_armv8m.c"

extern uint32_t _estack;
extern uint32_t _sbss;
extern uint32_t _ebss;
void Reset_Handler(void);

__attribute__((section(".vectors")))
const uintptr_t g_test_vectors[16] = {
    [0] = (uintptr_t)&_estack,
    [1] = (uintptr_t)Reset_Handler,
    [3] = (uintptr_t)wt_platform_panic,
    [15] = (uintptr_t)SysTick_Handler
};

static volatile uint32_t* test_reload_register(void)
{
    if (g_test_inject != 0U) {
        g_test_inject = 0U;
        __asm volatile("mrs %0, primask" : "=r"(g_test_mask_seen));
        g_test_handoff = 1U;
        WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
        __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    }
    return &g_test_rvr;
}

/* Per-guest RAM for the CMSE checker double, above the test image's RAM;
 * an address no guest owns stands in for a guest-written MSP_NS. */
#define TEST_GUEST_RAM_BASE 0x20010000u
#define TEST_GUEST_RAM_SIZE 0x00008000u
#define TEST_BOGUS_MSP_NS   0x60000000u

static wt_guest_context_t g_test_context;
static volatile uint32_t g_test_capture;
static const wt_trap_frame_t* volatile g_test_frame;

bool wt_cmse_check_in_guest_ns_ram(wt_guest_id_t guest_id, const void* ptr,
                                   size_t size)
{
    uintptr_t base = TEST_GUEST_RAM_BASE +
                     (uintptr_t)guest_id * TEST_GUEST_RAM_SIZE;
    uintptr_t addr = (uintptr_t)ptr;

    return guest_id < 2U && addr >= base && size <= TEST_GUEST_RAM_SIZE &&
           addr - base <= TEST_GUEST_RAM_SIZE - size;
}

void wt_monitor_on_secure_timer(const wt_trap_frame_t* frame)
{
    g_test_frame = frame;
    if (g_test_capture != 0U) {
        g_test_capture = 0U;
        wt_arch_guest_context_capture(&g_test_context, frame);
    }
    g_test_ticks++;
    if (g_test_reset_owner != 0U) {
        g_test_reset_owner = 0U;
        wt_virtual_systick_reset(0U);
    }
    if (g_test_handoff != 0U && g_active_guest != UINT32_MAX) {
        g_test_bad_handoff++;
    }
}

void wt_platform_panic(void)
{
    __asm volatile("bkpt #0x7e");
    for (;;) {}
}

static void check(int ok)
{
    if (!ok) {
        wt_platform_panic();
    }
}

void Reset_Handler(void)
{
    uint32_t* p;
    uint32_t primask;
    uint32_t basepri;
    uint32_t faultmask;
    uint32_t faultmask_kept;
    uint32_t ticks;
    wt_virtual_systick_t saved;

    for (p = &_sbss; p < &_ebss; ++p) {
        *p = 0U;
    }
    wt_arch_init();
    g_systick_reload = 100000U;
    g_secure_wall_cycles = 1000000U;
    WT_SYST_RVR = g_systick_reload - 1U;
    WT_SYST_CVR = 0U;
    WT_SYST_CSR = WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT |
                  WT_SYST_CSR_CLKSOURCE;

    g_active_guest = 0U;
    g_test_csr = WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT |
                 WT_SYST_CSR_CLKSOURCE;
    g_test_rvr = 10000U;
    g_test_cvr = 4321U;
    g_test_icsr = WT_SCB_ICSR_PENDSTSET;
    g_test_inject = 1U;
    wt_arch_wait_for_interrupt();
    g_test_handoff = 0U;
    check(g_guest_systick[0].csr == 7U &&
          g_guest_systick[0].rvr == 10000U &&
          g_guest_systick[0].cvr == 4321U &&
          g_guest_systick[0].pending == 1U &&
          g_guest_systick[0].owed_ticks == 1U);
    check(g_active_guest == UINT32_MAX && g_test_csr == 0U &&
          g_test_icsr == WT_SCB_ICSR_PENDSTCLR);
    __asm volatile("mrs %0, primask" : "=r"(primask));
    check(g_test_mask_seen == 1U && primask == 0U &&
          g_test_bad_handoff == 0U && g_test_ticks == 1U);

    saved = g_guest_systick[0];
    wt_arch_wait_for_interrupt();
    check(g_guest_systick[0].csr == saved.csr &&
          g_guest_systick[0].rvr == saved.rvr &&
          g_guest_systick[0].cvr == saved.cvr &&
          g_guest_systick[0].pending == saved.pending &&
          g_guest_systick[0].owed_ticks == saved.owed_ticks &&
          g_guest_systick[0].last_accounted_cycles ==
              saved.last_accounted_cycles);

    g_secure_wall_cycles = saved.last_accounted_cycles;
    wt_virtual_systick_restore_arriving(0U);
    check(g_arriving_systick_csr == saved.csr &&
          g_test_rvr == saved.cvr && g_arriving_systick_inject == 1U);
    wt_virtual_systick_arm_arriving();
    check(g_test_csr == saved.csr && g_test_rvr == saved.rvr &&
          g_test_icsr == WT_SCB_ICSR_PENDSTSET);

    g_active_guest = 1U;
    g_test_csr = WT_SYST_CSR_CLKSOURCE;
    g_test_rvr = 321U;
    g_test_cvr = 123U;
    g_test_icsr = 0U;
    wt_arch_wait_for_interrupt();
    check(g_guest_systick[1].csr == WT_SYST_CSR_CLKSOURCE &&
          g_guest_systick[1].rvr == 321U &&
          g_guest_systick[1].cvr == 123U &&
          g_guest_systick[1].pending == 0U &&
          g_guest_systick[1].owed_ticks == 0U);

    /* A tick before the critical section completes before ownership is read. */
    g_active_guest = 0U;
    g_test_csr = 7U;
    g_test_reset_owner = 1U;
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
    __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    check(g_test_reset_owner == 0U);
    wt_arch_wait_for_interrupt();
    check(g_active_guest == UINT32_MAX &&
          g_guest_systick[0].csr == 0U &&
          g_guest_systick[0].rvr == 0U &&
          g_guest_systick[0].cvr == 0U &&
          g_guest_systick[0].pending == 0U &&
          g_guest_systick[0].owed_ticks == 0U);

    /* Only an aligned frame wholly inside the interrupted guest's RAM is
     * read; anything else becomes the empty frame. */
    g_active_guest = 0U;
    check(wt_guest_frame_checked((const wt_trap_frame_t*)TEST_GUEST_RAM_BASE) ==
          (const wt_trap_frame_t*)TEST_GUEST_RAM_BASE);
    check(wt_guest_frame_checked(
              (const wt_trap_frame_t*)(TEST_GUEST_RAM_BASE + 2U)) ==
          &g_wt_guest_no_frame);
    check(wt_guest_frame_checked((const wt_trap_frame_t*)(TEST_GUEST_RAM_BASE +
              TEST_GUEST_RAM_SIZE - 4U)) == &g_wt_guest_no_frame);
    check(wt_guest_frame_checked((const wt_trap_frame_t*)(TEST_GUEST_RAM_BASE +
              TEST_GUEST_RAM_SIZE)) == &g_wt_guest_no_frame);
    g_active_guest = UINT32_MAX;
    check(wt_guest_frame_checked((const wt_trap_frame_t*)TEST_GUEST_RAM_BASE) ==
          &g_wt_guest_no_frame);

    /* A guest-written MSP_NS outside its RAM: the Secure tick neither reads
     * through it nor faults, and the capture records no frame contents. */
    g_active_guest = 0U;
    __asm volatile("msr msp_ns, %0" : : "r"(TEST_BOGUS_MSP_NS));
    g_test_capture = 1U;
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
    __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    check(g_test_capture == 0U && g_test_frame == &g_wt_guest_no_frame &&
          g_test_context.pc == 0U && g_test_context.frame_stacked);
    __asm volatile("msr msp_ns, %0" : : "r"(0U));

    /* An RTOS guest's frame sits on PSP_NS: the capture keeps the banked
     * MSP_NS as the guest's main stack, never the frame address. */
    __asm volatile("msr msp_ns, %0" : : "r"(TEST_GUEST_RAM_BASE + 0x100U));
    wt_arch_guest_context_capture(&g_test_context,
        (const wt_trap_frame_t*)(TEST_GUEST_RAM_BASE + 0x40U));
    check(g_test_context.msp_ns == TEST_GUEST_RAM_BASE + 0x100U);
    __asm volatile("msr msp_ns, %0" : : "r"(WT_PLATFORM_GUEST_STACK_WINDOW_BASE +
                   WT_PLATFORM_GUEST_STACK_WINDOW_SIZE));
    wt_arch_guest_context_capture(&g_test_context,
        (const wt_trap_frame_t*)(TEST_GUEST_RAM_BASE + 0x40U));
    check(g_test_context.msp_ns == WT_PLATFORM_GUEST_STACK_WINDOW_BASE +
                                   WT_PLATFORM_GUEST_STACK_WINDOW_SIZE);
    __asm volatile("msr msp_ns, %0" : : "r"(0U));

    /* A core that drops FAULTMASK_NS writes (M33MU) skips its checks. */
    __asm volatile("msr faultmask_ns, %0" : : "r"(1U));
    __asm volatile("mrs %0, faultmask_ns" : "=r"(faultmask_kept));
    __asm volatile("msr faultmask_ns, %0" : : "r"(0U));

    /* No Non-secure PRIMASK, BASEPRI or FAULTMASK masks the Secure tick. */
    check((WT_SCB_AIRCR_S & WT_SCB_AIRCR_PRIS) != 0U &&
          ((WT_SCB_SHPR3_S >> WT_SCB_SHPR3_SYSTICK_SHIFT) & 0xFFU) ==
              WT_ARMV8M_SECURE_BAND_PRIO &&
          ((WT_SCB_SHPR3_S >> WT_SCB_SHPR3_PENDSV_SHIFT) & 0xFFU) ==
              WT_ARMV8M_SECURE_BAND_PRIO);
    g_active_guest = UINT32_MAX;
    ticks = g_test_ticks;
    __asm volatile("msr primask_ns, %0" : : "r"(1U));
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
    __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    check(g_test_ticks == ticks + 1U);
    __asm volatile("msr primask_ns, %0" : : "r"(0U));
    __asm volatile("msr basepri_ns, %0" : : "r"(0x20U));
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
    __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
    check(g_test_ticks == ticks + 2U);
    __asm volatile("msr basepri_ns, %0" : : "r"(0U));
    if (faultmask_kept != 0U) {
        __asm volatile("msr faultmask_ns, %0" : : "r"(1U));
        WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSTSET;
        __asm volatile("dsb 0xF\n isb 0xF" ::: "memory");
        check(g_test_ticks == ticks + 3U);
        __asm volatile("msr faultmask_ns, %0" : : "r"(0U));
    }

    /* Each guest's Non-secure masks are saved and restored with it. */
    __asm volatile("msr faultmask_ns, %0" : : "r"(1U));
    __asm volatile("msr primask_ns, %0" : : "r"(1U));
    __asm volatile("msr basepri_ns, %0" : : "r"(0x40U));
    wt_arch_guest_context_capture(&g_test_context,
        (const wt_trap_frame_t*)(TEST_GUEST_RAM_BASE + 0x40U));
    __asm volatile("msr primask_ns, %0" : : "r"(0U));
    __asm volatile("msr basepri_ns, %0" : : "r"(0U));
    __asm volatile("msr faultmask_ns, %0" : : "r"(0U));
    wt_restore_guest_masks(&g_test_context);
    __asm volatile("mrs %0, primask_ns" : "=r"(primask));
    __asm volatile("mrs %0, basepri_ns" : "=r"(basepri));
    __asm volatile("mrs %0, faultmask_ns" : "=r"(faultmask));
    check(g_test_context.primask_ns == 1U && primask == 1U &&
          g_test_context.basepri_ns == 0x40U && basepri == 0x40U &&
          (faultmask_kept == 0U ||
           (g_test_context.faultmask_ns == 1U && faultmask == 1U)));
    g_test_context.primask_ns = 0U;
    g_test_context.basepri_ns = 0U;
    g_test_context.faultmask_ns = 0U;
    wt_restore_guest_masks(&g_test_context);

    /* A guest restarted mid FF-M entry left the Secure entry mask raised. */
    __asm volatile("msr basepri, %0" : : "r"(WT_ARMV8M_NS_PRIO_FLOOR));
    wt_drop_secure_entry_mask();
    __asm volatile("mrs %0, basepri" : "=r"(basepri));
    check(basepri == 0U);

    /* Abandon records every active IRQ; a later exit retires them one at a
     * time, never into a guest holding FAULTMASK_NS, and a queued IRQ does not
     * count as one the guest left active. */
    g_test_iabr[2] = 0x5U;
    g_secure_entry_sp = 0U;
    wt_arch_guest_abandon_handler();
    check(g_secure_entry_sp == (uintptr_t)&_estack - 8u);
    g_test_context.faultmask_ns = 1U;
    check(g_retire_irqs[2] == 0x5U && !wt_arch_guest_irq_active() &&
          wt_next_retire_exc(&g_test_context) == 0U);
    g_test_context.faultmask_ns = 0U;
    /* IRQ 66 preempted IRQ 64, so it retires first despite its number. */
    g_test_ipr[64] = 0xC0U;
    g_test_ipr[66] = 0x40U;
    check(wt_next_retire_exc(&g_test_context) == 82U);
    g_test_iabr[2] = 0x1U;
    check(wt_next_retire_exc(&g_test_context) == 80U &&
          g_retire_irqs[2] == 0x1U);
    g_test_iabr[2] = 0x8U;
    check(wt_arch_guest_irq_active() &&
          wt_next_retire_exc(&g_test_context) == 0U && g_retire_irqs[2] == 0U);
    g_test_ipr[64] = 0U;
    g_test_ipr[66] = 0U;

    /* A guest switched out with PendSV pended takes it back with it. */
    g_test_icsr = WT_SCB_ICSR_PENDSVSET;
    g_test_context.pend_ns = 0U;
    wt_save_guest_pending(&g_test_context);
    check((g_test_context.pend_ns & WT_SCB_ICSR_PENDSVSET) != 0U &&
          g_test_icsr == WT_SCB_ICSR_PENDSVCLR);
    g_test_icsr = 0U;
    wt_restore_guest_pending(&g_test_context);
    check(g_test_icsr == WT_SCB_ICSR_PENDSVSET);
    /* A guest with nothing saved clears a pend another guest left. */
    g_test_context.pend_ns = 0U;
    wt_restore_guest_pending(&g_test_context);
    check(g_test_icsr == WT_SCB_ICSR_PENDSVCLR);
    /* The tasklet resume path gives the pends back like the full restore. */
    g_test_context.pend_ns = WT_SCB_ICSR_PENDSVSET;
    wt_arch_restore_guest_bank(&g_test_context);
    check(g_test_icsr == WT_SCB_ICSR_PENDSVSET);
    g_test_icsr = 0U;
    g_test_iabr[2] = 0U;

    if (faultmask_kept != 0U) {
        __asm volatile("bkpt #0x7f");
    }
    __asm volatile("bkpt #0x7d");
    for (;;) {}
}
