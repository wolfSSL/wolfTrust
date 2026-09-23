/* guest_context_armv8m.c
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


/* Armv8-M guest context switching, Secure exception entry and return, the
 * secure time slice, and the per-guest virtual SysTick. The naked handlers
 * name the statics below directly, so everything they touch lives in this
 * translation unit. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/monitor.h"
#include "wolftrust/static_assert.h"

#include "memory_map.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WT_ASM_STR2(x) #x
#define WT_ASM_STR(x) WT_ASM_STR2(x)

#define WT_GUEST_CONTEXT_PSP_NS_OFFSET     32U
#define WT_GUEST_CONTEXT_MSP_NS_OFFSET     36U
#define WT_GUEST_CONTEXT_CONTROL_NS_OFFSET 44U
#define WT_GUEST_CONTEXT_EXC_RETURN_OFFSET 48U
#define WT_GUEST_CONTEXT_PSPLIM_NS_OFFSET  68U
#define WT_EXC_RETURN_MODE_THREAD          0x08u
#define WT_EXC_RETURN_RETURN_TO_NONSECURE  0x00u
#define WT_EXC_RETURN_SECURITY_MASK        0x40u
#define WT_EXC_RETURN_SPSEL_PSP            0x04u

WT_STATIC_ASSERT(WT_GUEST_CONTEXT_PSP_NS_OFFSET == 32U, "unexpected psp_ns offset");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_MSP_NS_OFFSET == 36U, "unexpected msp_ns offset");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_CONTROL_NS_OFFSET == 44U, "unexpected control_ns offset");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_EXC_RETURN_OFFSET == 48U, "unexpected exc_return offset");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_PSP_NS_OFFSET == offsetof(wt_guest_context_t, psp_ns),
               "wt_guest_context_t layout changed");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_MSP_NS_OFFSET == offsetof(wt_guest_context_t, msp_ns),
               "wt_guest_context_t layout changed");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_CONTROL_NS_OFFSET == offsetof(wt_guest_context_t, control_ns),
               "wt_guest_context_t layout changed");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_EXC_RETURN_OFFSET == offsetof(wt_guest_context_t, exc_return),
               "wt_guest_context_t layout changed");
WT_STATIC_ASSERT(WT_GUEST_CONTEXT_PSPLIM_NS_OFFSET == offsetof(wt_guest_context_t, psplim_ns),
               "wt_guest_context_t layout changed");

/* Referenced by inline asm in SysTick_Handler; mark used so -Os does
 * not DCE them since the C code only touches them by name in __asm. */
static wt_guest_context_t g_return_context __attribute__((used));
static uint32_t g_live_r4_r11[8] __attribute__((used));
static uintptr_t g_live_exc_return __attribute__((used));
static uint32_t g_systick_reload;
static uint64_t g_secure_wall_cycles;
static uintptr_t g_secure_entry_sp __attribute__((used));
static volatile uint32_t g_last_fault_address;
static volatile uint32_t g_last_fault_pc;
static volatile uint32_t g_switch_count;
static volatile uint32_t g_active_guest;
static void (*g_secure_thread_resume_entry)(void)
    __attribute__((noreturn, used));

typedef struct wt_virtual_systick {
    uint32_t csr;
    uint32_t rvr;
    uint32_t cvr;
    uint64_t last_accounted_cycles;
    uint32_t owed_ticks;
    uint8_t pending;
    uint32_t accrued_ticks;
    uint32_t injected_ticks;
    uint32_t coalesced_ticks;
    uint32_t max_owed_ticks;
} wt_virtual_systick_t;

static wt_virtual_systick_t g_guest_systick[WT_MAX_GUESTS];
/* Deferred SysTick arm for the arriving guest: arming/injecting before the
 * NS bank is restored lets the tick preempt the dispatch window and stack
 * through the new VTOR_NS onto the departing guest's MSP_NS. */
static volatile uint32_t g_arriving_systick_csr;
static volatile uint32_t g_arriving_systick_inject;

void wt_arch_init(void)
{
    /* Route MemManage and UsageFault to their own handlers (otherwise
     * they escalate to HardFault and we lose the fault-status registers
     * by the time we get the trap). STKOF on PSPLIM_S overflow surfaces
     * as a UsageFault. */
    WT_SCB_SHCSR_S |= WT_SCB_SHCSR_MEMFAULTENA | WT_SCB_SHCSR_USGFAULTENA;
    /* Reset authority belongs to the Secure world. With SYSRESETREQS set, a
     * Non-secure SYSRESETREQ (e.g. a guest RTOS calling sys_reboot on a fault)
     * no longer resets the SoC — only Secure code can. This is the correct
     * Secure-Manager policy and stops a rogue NS reboot from tearing the whole
     * system down. Read-modify-write with VECTKEY, preserving the TrustZone
     * config bits (PRIS/BFHFNMINS/PRIGROUP). */
    WT_SCB_AIRCR_S = WT_SCB_AIRCR_VECTKEY |
                     (WT_SCB_AIRCR_S & WT_SCB_AIRCR_CFG_MASK) |
                     WT_SCB_AIRCR_SYSRESETREQS;
    /* PendSV and the secure SysTick must share the lowest priority: SysTick at
     * the reset default (0, highest) would preempt PendSV mid-coroutine switch,
     * and a nested exception return off the half-saved frame faults INVPC.
     * Equal priority makes the context switch atomic against the timer. */
    WT_SCB_SHPR3_S |= (0xFFu << WT_SCB_SHPR3_PENDSV_SHIFT) |
                      (0xFFu << WT_SCB_SHPR3_SYSTICK_SHIFT);
    WT_SCB_ICSR_S = WT_SCB_ICSR_PENDSVCLR;
    g_switch_count = 0u;
    g_active_guest = UINT32_MAX;
}

void wt_armv8m_note_fault_address(uintptr_t fault_address)
{
    g_last_fault_address = (uint32_t)fault_address;
}

void wt_armv8m_note_fault(uintptr_t fault_address, uintptr_t pc)
{
    g_last_fault_address = (uint32_t)fault_address;
    g_last_fault_pc = (uint32_t)pc;
}

static uint32_t wt_read_psp_ns(void)
{
    uint32_t value;
    __asm volatile("mrs %0, psp_ns" : "=r"(value));
    return value;
}

static uint32_t wt_read_control_ns(void)
{
    uint32_t value;
    __asm volatile("mrs %0, control_ns" : "=r"(value));
    return value;
}

static uint32_t wt_read_ipsr(void)
{
    uint32_t value;
    __asm volatile("mrs %0, ipsr" : "=r"(value));
    return value;
}

__attribute__((noreturn, used))
void wt_secure_thread_resume_trampoline(void)
{
    void (*entry)(void) __attribute__((noreturn)) = g_secure_thread_resume_entry;

    if (entry == NULL) {
        wt_platform_panic();
    }

    entry();
    wt_platform_panic();
    __builtin_unreachable();
}

bool wt_arch_in_handler_mode(void)
{
    return wt_read_ipsr() != 0u;
}

bool wt_arch_trap_from_guest_thread(void)
{
    return (g_live_exc_return &
            (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_SECURITY_MASK)) ==
           (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_RETURN_TO_NONSECURE);
}

bool wt_arch_trap_from_secure_thread(void)
{
    /* True only when the tick landed on a Secure Thread running on PSP —
     * i.e. a coroutine is physically executing, not merely named current
     * inside the bootstrap's do_switch/arch_enter window. Gates the HSM
     * tasklet preempt so an async SysTick cannot corrupt a mid-switch frame. */
    return (g_live_exc_return &
            (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_SPSEL_PSP |
             WT_EXC_RETURN_SECURITY_MASK)) ==
           (WT_EXC_RETURN_MODE_THREAD | WT_EXC_RETURN_SPSEL_PSP |
            WT_EXC_RETURN_SECURITY_MASK);
}

/* Naked: the synthetic frame must sit exactly at the handler's MSP, so the
 * checks stay in asm too and no prologue may push. */
__attribute__((naked, noreturn))
void wt_arch_return_to_secure_thread(
    void (*entry)(void) __attribute__((noreturn, unused)))
{
    __asm volatile(
        "cbz    r0, 1f                       \n"
        "mrs    r1, ipsr                     \n"
        "cbz    r1, 1f                       \n"
        "ldr    r1, =g_secure_thread_resume_entry \n"
        "str    r0, [r1]                     \n"
        "sub    sp, sp, #32                  \n"
        "movs   r1, #0                       \n"
        "str    r1, [sp, #0]                 \n"
        "str    r1, [sp, #4]                 \n"
        "str    r1, [sp, #8]                 \n"
        "str    r1, [sp, #12]                \n"
        "str    r1, [sp, #16]                \n"
        "str    r1, [sp, #20]                \n"
        "movw   r1, #:lower16:wt_secure_thread_resume_trampoline \n"
        "movt   r1, #:upper16:wt_secure_thread_resume_trampoline \n"
        "str    r1, [sp, #24]                \n"
        "movw   r1, #0x0000                  \n"
        "movt   r1, #0x0100                  \n"
        "str    r1, [sp, #28]                \n"
        "mvn    lr, #6                       \n"
        "bx     lr                           \n"
        "1:                                  \n"
        "b      wt_platform_panic            \n");
}

static void wt_exception_return_ns_msp(void) __attribute__((naked, noreturn));

static void wt_exception_return_ns_msp(void)
{
    __asm volatile(
        "ldr r2, =g_secure_entry_sp     \n"
        "ldr r2, [r2]                   \n"
        "mov sp, r2                     \n"
        "ldr r0, =g_return_context      \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_PSP_NS_OFFSET) "] \n"
        "msr psp_ns, r1                 \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_MSP_NS_OFFSET) "] \n"
        "msr msp_ns, r1                 \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_PSPLIM_NS_OFFSET) "] \n"
        "msr psplim_ns, r1              \n"
        /* MSP_NS is the exception stack shared with the secure transition;
         * keep its limit disabled until the port has a dedicated exception
         * stack. Restoring an RTOS task limit here can block the next secure
         * timer frame before the scheduler can switch guests. */
        "mov r1, #0                     \n"
        "msr msplim_ns, r1              \n"
        "ldr r1, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_CONTROL_NS_OFFSET) "] \n"
        "msr control_ns, r1             \n"
        /* NS bank is now consistent: arm/inject the guest's SysTick here,
         * never earlier in the dispatch window. */
        "bl wt_virtual_systick_arm_arriving \n"
        "ldr r0, =g_return_context      \n"
        "ldmia r0, {r4-r11}             \n"
        "ldr lr, [r0, #" WT_ASM_STR(WT_GUEST_CONTEXT_EXC_RETURN_OFFSET) "] \n"
        "bx lr                          \n"
    );
}

__attribute__((naked, noreturn))
void wt_armv8m_svc_guest_return(void)
{
    __asm volatile(
        "mrs r2, msp                    \n"
        "ldr r1, =g_secure_entry_sp    \n"
        "str r2, [r1]                  \n"
        "b wt_exception_return_ns_msp  \n"
    );
}

static void wt_jump_to_ns(uint32_t msp_ns, uint32_t reset_addr)
    __attribute__((naked, noreturn));

static void wt_jump_to_ns(uint32_t msp_ns __attribute__((unused)),
                          uint32_t reset_addr __attribute__((unused)))
{
    __asm volatile(
        "msr msp_ns, r0     \n"
        "bics r1, r1, #1    \n"
        "mov r4, r1         \n"
        "movs r2, #0        \n"
        "msr control_ns, r2 \n"
        /* See wt_exception_return_ns_msp — clear PSPLIM_NS / MSPLIM_NS
         * before the first BXNS so a guest that programs them later
         * doesn't inherit a stale value from the previous guest. */
        "msr psplim_ns, r2  \n"
        "msr msplim_ns, r2  \n"
        "bl wt_virtual_systick_arm_arriving \n"
        "isb 0xF            \n"
        "bxns r4            \n"
    );
}

static void wt_secure_systick_dispatch(const wt_trap_frame_t* frame)
    __attribute__((used));
static void wt_secure_fault_dispatch(const wt_trap_frame_t* frame)
    __attribute__((noreturn, used));

static void wt_secure_systick_dispatch(const wt_trap_frame_t* frame)
{
    g_secure_wall_cycles += g_systick_reload;
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    wt_spm_sched_hang_probe();
#endif
    wt_monitor_on_secure_timer(frame);
}

static void wt_secure_fault_dispatch(const wt_trap_frame_t* frame)
{
    g_last_fault_address = WT_SAU_SFAR;
    wt_monitor_on_guest_fault(frame, WT_FAULT_SECURE_ESCALATION);
    wt_platform_panic();
    __builtin_unreachable();
}

void wt_arch_start_secure_timer(uint32_t timeslice_ms)
{
    uint32_t reload;

    if (timeslice_ms == 0u) {
        wt_platform_panic();
    }

    reload = timeslice_ms * (WT_PLATFORM_CORE_CLOCK_HZ / 1000u);
    g_systick_reload = reload;
}

static void wt_arm_secure_timer(void)
{
    WT_SYST_CSR = 0u;
    WT_SYST_RVR = g_systick_reload - 1u;
    WT_SYST_CVR = 0u;
    WT_SYST_CSR = WT_SYST_CSR_CLKSOURCE |
                  WT_SYST_CSR_TICKINT |
                  WT_SYST_CSR_ENABLE;
}

static uint32_t wt_virtual_systick_period(const wt_virtual_systick_t* systick)
{
    return (systick->rvr & 0x00FFFFFFu) + 1u;
}

static bool wt_virtual_systick_active(const wt_virtual_systick_t* systick)
{
    return (systick->csr & WT_SYST_CSR_ENABLE) != 0u;
}

static bool wt_virtual_systick_irq_enabled(const wt_virtual_systick_t* systick)
{
    return (systick->csr & (WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT)) ==
           (WT_SYST_CSR_ENABLE | WT_SYST_CSR_TICKINT);
}

static void wt_virtual_systick_note_consumed(wt_virtual_systick_t* systick,
                                             bool hw_pending)
{
    if (systick->pending && !hw_pending) {
        if (systick->owed_ticks > 0u) {
            systick->owed_ticks--;
        }
        systick->pending = 0u;
    }
}

static void wt_virtual_systick_save_departing(void)
{
    wt_virtual_systick_t* systick;
    uint32_t csr;
    bool hw_pending;

    if (g_active_guest >= WT_MAX_GUESTS) {
        WT_SYST_NS_CSR = 0u;
        WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTCLR;
        return;
    }

    systick = &g_guest_systick[g_active_guest];
    csr = WT_SYST_NS_CSR;
    hw_pending = (WT_SCB_ICSR_NS & WT_SCB_ICSR_PENDSTSET) != 0u;

    wt_virtual_systick_note_consumed(systick, hw_pending);
    systick->csr = csr;
    systick->rvr = WT_SYST_NS_RVR;
    systick->cvr = WT_SYST_NS_CVR;
    systick->last_accounted_cycles = g_secure_wall_cycles;

    if (!systick->pending && hw_pending && wt_virtual_systick_irq_enabled(systick)) {
        systick->owed_ticks++;
        systick->pending = 1u;
        systick->accrued_ticks++;
        if (systick->owed_ticks > systick->max_owed_ticks) {
            systick->max_owed_ticks = systick->owed_ticks;
        }
    }

    WT_SYST_NS_CSR = 0u;
    WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTCLR;
}

static void wt_virtual_systick_account_elapsed(wt_virtual_systick_t* systick)
{
    uint64_t elapsed;
    uint32_t period;
    uint32_t remaining;
    uint64_t ticks;
    uint64_t rem;

    if (systick->last_accounted_cycles == 0u) {
        systick->last_accounted_cycles = g_secure_wall_cycles;
        return;
    }

    elapsed = g_secure_wall_cycles - systick->last_accounted_cycles;
    systick->last_accounted_cycles = g_secure_wall_cycles;
    if (!wt_virtual_systick_active(systick) || elapsed == 0u) {
        return;
    }

    period = wt_virtual_systick_period(systick);
    remaining = (systick->cvr == 0u || systick->cvr >= period) ? period :
                (systick->cvr + 1u);

    if (elapsed < remaining) {
        systick->cvr = remaining - (uint32_t)elapsed - 1u;
        return;
    }

    elapsed -= remaining;
    ticks = 1u + (elapsed / period);
    rem = elapsed % period;
    systick->cvr = (uint32_t)(period - rem - 1u);

    if (ticks > (uint64_t)(UINT32_MAX - systick->owed_ticks)) {
        systick->owed_ticks = UINT32_MAX;
    }
    else {
        systick->owed_ticks += (uint32_t)ticks;
    }

    if (ticks > (uint64_t)(UINT32_MAX - systick->accrued_ticks)) {
        systick->accrued_ticks = UINT32_MAX;
    }
    else {
        systick->accrued_ticks += (uint32_t)ticks;
    }

    if (systick->owed_ticks > systick->max_owed_ticks) {
        systick->max_owed_ticks = systick->owed_ticks;
    }
}

static void wt_virtual_systick_restore_arriving(wt_guest_id_t guest_id)
{
    wt_virtual_systick_t* systick;

    WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTCLR;
    if (guest_id >= WT_MAX_GUESTS) {
        return;
    }

    systick = &g_guest_systick[guest_id];
    wt_virtual_systick_account_elapsed(systick);

    WT_SYST_NS_CSR = 0u;
    WT_SYST_NS_RVR = systick->rvr;
    WT_SYST_NS_CVR = 0u;
    g_arriving_systick_csr = 0u;
    g_arriving_systick_inject = 0u;
    if (wt_virtual_systick_active(systick)) {
        g_arriving_systick_csr = systick->csr & ~WT_SYST_CSR_COUNTFLAG;
    }

    if (systick->owed_ticks > 0u && wt_virtual_systick_irq_enabled(systick)) {
        if (!systick->pending) {
            systick->pending = 1u;
            systick->injected_ticks++;
        }
        else {
            systick->coalesced_ticks++;
        }
        g_arriving_systick_inject = 1u;
    }
}

/* Called from the NS-entry asm once MSP/PSP/CONTROL_NS are restored, so a
 * tick taken here stacks on the arriving guest's own stack. */
static void wt_virtual_systick_arm_arriving(void) __attribute__((used));
static void wt_virtual_systick_arm_arriving(void)
{
    uint32_t csr = g_arriving_systick_csr;

    g_arriving_systick_csr = 0u;
    if (csr != 0u) {
        WT_SYST_NS_CSR = csr;
    }
    if (g_arriving_systick_inject != 0u) {
        g_arriving_systick_inject = 0u;
        WT_SCB_ICSR_NS = WT_SCB_ICSR_PENDSTSET;
    }
}

static void wt_virtual_systick_reset(wt_guest_id_t guest_id)
{
    wt_virtual_systick_t* systick;

    if (guest_id >= WT_MAX_GUESTS) {
        return;
    }
    systick = &g_guest_systick[guest_id];
    systick->csr = 0u;
    systick->rvr = 0u;
    systick->cvr = 0u;
    systick->last_accounted_cycles = g_secure_wall_cycles;
    systick->owed_ticks = 0u;
    systick->pending = 0u;
    systick->accrued_ticks = 0u;
    systick->injected_ticks = 0u;
    systick->coalesced_ticks = 0u;
    systick->max_owed_ticks = 0u;
}

void wt_arch_guest_context_prepare(wt_guest_id_t guest_id,
                                      const wt_guest_context_t* context)
{
    if (context == NULL) {
        return;
    }

    /* A non-secure RTOS must not be able to redirect Secure exception
     * dispatch through the shared PPB alias. Reassert wolfTrust's vector
     * table before every guest handoff so the next CMSE/HSM transition
     * always enters the relocated secure runtime. */
    WT_SCB_VTOR_S = WT_FLASH_IMAGE_BASE;
    wt_dsb();
    wt_isb();
    wt_virtual_systick_save_departing();

    WT_SCB_VTOR_NS = (uint32_t)context->vector_table_ns;
    g_active_guest = guest_id;
    wt_virtual_systick_restore_arriving(guest_id);
}

uintptr_t wt_arch_trap_pc(const wt_trap_frame_t* frame)
{
    return frame->pc;
}

void wt_arch_guest_context_capture(wt_guest_context_t* context,
                                       const wt_trap_frame_t* frame)
{
    wt_trap_frame_t* stacked;
    uintptr_t stacked_addr;

    if (context == NULL || frame == NULL) {
        wt_platform_panic();
    }

    stacked = (wt_trap_frame_t*)frame;
    context->psp_ns = wt_read_psp_ns();
    stacked_addr = (uintptr_t)stacked;
    /* A SecureFault can be raised before the NS exception frame exists (for
     * example, on a failed first BXNS). Preserve the configured guest MSP
     * in that case; replacing it with zero would make the recovery path
     * fabricate a frame at 0xffffffe0 and fault recursively. */
    if (stacked_addr >= WT_PLATFORM_GUEST_STACK_WINDOW_BASE &&
        stacked_addr <= (WT_PLATFORM_GUEST_STACK_WINDOW_BASE +
                         WT_PLATFORM_GUEST_STACK_WINDOW_SIZE -
                         sizeof(wt_trap_frame_t))) {
        context->msp_ns = stacked_addr;
    }
    context->control_ns = wt_read_control_ns();
    __asm volatile("mrs %0, psplim_ns" : "=r"(context->psplim_ns));
    context->exc_return = g_live_exc_return;
    context->r4_r11[0] = g_live_r4_r11[0];
    context->r4_r11[1] = g_live_r4_r11[1];
    context->r4_r11[2] = g_live_r4_r11[2];
    context->r4_r11[3] = g_live_r4_r11[3];
    context->r4_r11[4] = g_live_r4_r11[4];
    context->r4_r11[5] = g_live_r4_r11[5];
    context->r4_r11[6] = g_live_r4_r11[6];
    context->r4_r11[7] = g_live_r4_r11[7];
    context->pc = stacked->pc;
    context->lr = stacked->lr;
    context->xpsr = stacked->xpsr;
    context->frame_stacked = true;
}

void wt_arch_guest_context_restore(wt_guest_context_t* context)
{
    g_switch_count++;

    if (!context->frame_stacked) {
        if (wt_read_ipsr() == 0u) {
            wt_arm_secure_timer();
            wt_jump_to_ns((uint32_t)context->msp_ns, (uint32_t)context->pc);
        } else {
            wt_trap_frame_t* stacked;

            context->lr = 0u;
            context->xpsr = 0x01000000u;
            stacked = (wt_trap_frame_t*)(context->msp_ns - sizeof(wt_trap_frame_t));
            stacked->r0 = 0u;
            stacked->r1 = 0u;
            stacked->r2 = 0u;
            stacked->r3 = 0u;
            stacked->r12 = 0u;
            stacked->lr = context->lr;
            /* Vector-table reset handlers carry the Thumb marker in bit 0,
             * but an exception frame carries the aligned PC and restores
             * Thumb state from xPSR.T. Leaving bit 0 set causes INVEP on
             * STM32H563 during the first exception-based guest dispatch. */
            stacked->pc = context->pc & ~(uintptr_t)1u;
            stacked->xpsr = context->xpsr;
            context->msp_ns = (uintptr_t)stacked;
            context->frame_stacked = true;
        }
    }

    g_return_context = *context;
    wt_arm_secure_timer();
    if (wt_read_ipsr() == 0u) {
        __asm volatile("svc #0x7F");
        wt_platform_panic();
    }
    wt_exception_return_ns_msp();
}

void wt_arch_zero_guest_memory(uintptr_t base, size_t size)
{
    volatile uint32_t* ptr = (volatile uint32_t*)base;
    size_t words = size / sizeof(uint32_t);
    size_t i;

    for (i = 0; i < words; ++i) {
        ptr[i] = 0u;
    }
    if (base == WT_GUEST0_RAM_BASE && size >= WT_GUEST_RAM_SIZE) {
        wt_virtual_systick_reset(0u);
    }
    else if (base == WT_GUEST1_RAM_BASE && size >= WT_GUEST_RAM_SIZE) {
        wt_virtual_systick_reset(1u);
    }
}

uintptr_t wt_arch_read_fault_address(void)
{
    return g_last_fault_address;
}

void wt_arch_dmb(void)
{
    wt_dmb();
}

void wt_arch_dsb(void)
{
    wt_dsb();
}

bool wt_arch_guest_context_ready(const wt_guest_context_t* context)
{
    return (context != NULL) && (context->pc != 0u);
}

/* Rewrite the NS-banked stack/control registers from a guest's saved context.
 * A guest resumed through its blocked secure tasklet returns to NS via BXNS,
 * not the exception-return path, so nothing else reinstates its NS bank — the
 * previous guest's CONTROL_NS/MSP_NS would leak in and the thread resumes on
 * the wrong stack. Mirrors wt_exception_return_ns_msp (MSPLIM_NS stays 0). */
void wt_arch_restore_guest_bank(const wt_guest_context_t* context)
{
    uint32_t zero = 0u;

    __asm volatile(
        "msr psp_ns, %0     \n"
        "msr msp_ns, %1     \n"
        "msr psplim_ns, %2  \n"
        "msr msplim_ns, %3  \n"
        "msr control_ns, %4 \n"
        "isb                \n"
        :
        : "r"(context->psp_ns), "r"(context->msp_ns),
          "r"(context->psplim_ns), "r"(zero), "r"(context->control_ns));
}

uint32_t wt_arch_active_guest_id(void)
{
    return g_active_guest;
}

__attribute__((naked)) void SecureFault_Handler(void)
{
    __asm volatile(
        /* EXC_RETURN bit6 = secure frame, bit3 = Thread. A fault from Secure
         * Thread with a live tasklet is a Secure Partition/tasklet fault, not
         * a guest escalation: blaming the scheduled NS guest would restart an
         * innocent domain and leave the SP's CPU state live. Route it to the
         * tasklet recovery entry, which self-derives everything from its own
         * EXC_RETURN. (The M33MU can deliver a secure MPU violation through
         * this vector; silicon MemManage takes the direct handler.) */
        "tst lr, #0x40                  \n"
        "beq 1f                         \n"
        "tst lr, #0x08                  \n"
        "beq 1f                         \n"
        "ldr r0, =g_wt_co_current       \n"
        "ldr r0, [r0]                   \n"
        "ldr r1, =g_wt_co_bootstrap     \n"
        "cmp r0, r1                     \n"
        "beq 1f                         \n"
        "b wt_armv8m_tasklet_fault_entry \n"
        "1:                             \n"
        "mov r2, sp                     \n"
        "ldr r1, =g_secure_entry_sp     \n"
        "str r2, [r1]                   \n"
        "ldr r1, =g_live_r4_r11         \n"
        "stmia r1!, {r4-r11}            \n"
        "ldr r1, =g_live_exc_return     \n"
        "str lr, [r1]                   \n"
        "mrs r0, msp_ns                 \n"
        "b wt_secure_fault_dispatch     \n"
    );
}

__attribute__((naked)) void SysTick_Handler(void)
{
    __asm volatile(
        "mov r2, sp                     \n"
        "ldr r1, =g_secure_entry_sp     \n"
        "str r2, [r1]                   \n"
        "ldr r1, =g_live_r4_r11         \n"
        "stmia r1!, {r4-r11}            \n"
        "ldr r1, =g_live_exc_return     \n"
        "str lr, [r1]                   \n"
        "mrs r0, msp_ns                 \n"
        "b wt_secure_systick_dispatch   \n"
    );
}
