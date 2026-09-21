/* sp_fault_armv8m.c
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


/* Armv8-M Secure-side fault path for a scheduled Secure Partition or wolfHSM
 * tasklet: MemManage / UsageFault land here and the dead coroutine is
 * unwound onto the bootstrap without resetting the world. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/core_regs.h"
#include "wolftrust/spm_transport.h"
#include "wolftrust/ffm.h"
#include "wolftrust/sched/coroutine.h"

#include <stdint.h>

#include "wolftrust/sched/tasklet.h"
#ifdef WT_ENGINE_HSM
#include "wolftrust/services/hsm.h"
#endif

static volatile uint32_t g_tasklet_fault_count;
static volatile uint32_t g_tasklet_fault_cfsr;
static volatile uint32_t g_tasklet_fault_pc;
static volatile uint32_t g_tasklet_fault_exc_return;
static volatile uint32_t g_tasklet_fault_frame;
static volatile uint32_t g_tasklet_fault_xpsr;
static volatile uint32_t g_tasklet_fault_psp;
static volatile uint32_t g_tasklet_fault_icsr;
static volatile uint32_t g_tasklet_fault_co;
static volatile uint32_t g_tasklet_fault_co_sp;

/* -----------------------------------------------------------------------
 * Secure-side tasklet fault path.
 *
 * MemManage and UsageFault can fire from within a wolfHSM tasklet when:
 *   - PSPLIM_S is hit (UsageFault.STKOF) — tasklet stack overflow,
 *   - MPU_S blocks a wild read/write (MemManage IACCVIOL/DACCVIOL),
 *   - the tasklet executes an illegal instruction (UsageFault).
 *
 * Recovery model:
 *   1. C dispatcher logs the fault, identifies the running tasklet
 *      (g_tasklet_current via wt_tasklet_current), maps it back to a guest_id,
 *      hands the NS client a WH_ERROR_ABORTED via wt_hsm_signal_fault,
 *      drops any mutex held by the dying tasklet, and marks the
 *      tasklet WT_TASKLET_FAULTED.
 *   2. The naked handler asm restores MSP_S to the bootstrap SP that
 *      PendSV saved (r4-r11 push + preserved exception frame), pops
 *      r4-r11, and EXC_RETURNs through the preserved bootstrap frame —
 *      all in Handler mode, mirroring PendSV's bootstrap-resume path.
 *      Execution resumes inside wt_tasklet_run as if the tasklet had
 *      switched back; the scheduler picks up the next runnable tasklet —
 *      the faulted one is no longer on the runqueue. (An earlier design
 *      EXC_RETURNed into a Thread-mode thunk that then tried a second
 *      exception return; only Handler mode can exception-return on real
 *      silicon, so that worked on the M33MU and IACCVIOL-faulted on H5.)
 *
 * If the fault fires while bootstrap (monitor) is running there is no
 * tasklet to abandon and no saved frame to unwind to, so the C
 * dispatcher panics.
 * ----------------------------------------------------------------------- */
static void wt_secure_tasklet_fault_dispatch(uint32_t *frame,
                                             uint32_t exc_return)
    __attribute__((used));
static void wt_secure_tasklet_fault_dispatch(uint32_t *frame,
                                             uint32_t exc_return)
{
    uint32_t cfsr = WT_SCB_CFSR_S;

    /* First-wins forensic record: the first tasklet fault's CFSR, stacked PC
     * and EXC_RETURN survive any later cascade so a debugger post-mortem can
     * tell what faulted (MMFSR/UFSR bits), where (PC), and from which mode
     * (EXC_RETURN bit 3). The fault-address note below adds the data address. */
    if (g_tasklet_fault_cfsr == 0u) {
        uint32_t psp_now;

        g_tasklet_fault_cfsr = cfsr;
        g_tasklet_fault_pc = frame[6];
        g_tasklet_fault_exc_return = exc_return;
        /* Frame position vs the coroutine stack identifies which pusher
         * built it (SVC/tick 8-word vs NS-preempt callee+signature). */
        g_tasklet_fault_frame = (uint32_t)(uintptr_t)frame;
        g_tasklet_fault_xpsr = frame[7];
        __asm volatile("mrs %0, psp" : "=r"(psp_now));
        g_tasklet_fault_psp = psp_now;
        g_tasklet_fault_icsr = WT_SCB_ICSR_S;
        g_tasklet_fault_co = (uint32_t)(uintptr_t)wt_co_current();
        if (wt_co_current() != NULL) {
            g_tasklet_fault_co_sp = *(const uint32_t*)(const void*)
                                        wt_co_current();
        }
    }
    if ((cfsr & WT_SCB_CFSR_MMFSR_MMARVALID) != 0u) {
        wt_armv8m_note_fault_address(WT_SCB_MMFAR_S);
    }
    /* Write-1-to-clear so the next fault is observable. */
    WT_SCB_CFSR_S = cfsr;

    wt_tasklet_t *tasklet = wt_tasklet_current();
    if (tasklet == NULL) {
        /* Bootstrap took the fault — no tasklet to abandon. */
        wt_platform_panic();
    }

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
    /* The Arm isolation tests (i068+) fault inside a Secure Partition on
     * purpose and expect a system restart so val resumes off its flash boot
     * flag; the graceful quarantine below would leave the server partition
     * dead for every later test. Production keeps the quarantine (task #26). */
    wt_platform_system_reset();
#endif

    g_tasklet_fault_count++;

    /* Graceful recovery for a scheduled Secure Partition (WT-SYS-0008 /
     * WT-FFM-0017): mark it dead and pend the recovery; the SPM dispatch path
     * restarts it on the bootstrap thread under its manifest policy without
     * resetting the world. If the coroutine is not a scheduled SP this returns
     * an error and the guest-tasklet teardown below runs instead. */
    if (wt_spm_sp_fault(tasklet) == WT_FFM_SUCCESS) {
        return;
    }

#ifdef WT_ENGINE_HSM
    wt_guest_id_t gid = wt_hsm_guest_for_tasklet(tasklet);
    if (gid < WT_MAX_GUESTS) {
        (void)wt_hsm_signal_fault(gid);
    }
#endif

    wt_tasklet_mark_faulted(tasklet);
}

/* Shared tail for MemManage_Handler and UsageFault_Handler. Naked so
 * we control the stack layout the EXC_RETURN unwinds through. */
__attribute__((naked, used))
void wt_armv8m_tasklet_fault_entry(void)
{
    __asm volatile(
        /* r0 = the faulting context's stacked exception frame (EXC_RETURN
         * bit 2 selects the stack it was pushed to), r1 = EXC_RETURN. */
        "tst    lr, #4                              \n"
        "ite    eq                                  \n"
        "mrseq  r0, msp                             \n"
        "mrsne  r0, psp                             \n"
        "mov    r1, lr                              \n"
        "bl     wt_secure_tasklet_fault_dispatch    \n"
        /* Resume the bootstrap exactly like PendSV's bootstrap path:
         * g_wt_co_bootstrap.sp points at the r4-r11 PendSV pushed with the
         * preserved bootstrap exception frame above it. This is Handler
         * mode, so the final bx is a real exception return — a Thread-mode
         * thunk cannot exception-return on hardware (M33MU accepted it,
         * H5 silicon IACCVIOL-faults at 0xFFFFFFF8). */
        "ldr    r0, =g_wt_co_bootstrap              \n"
        "ldr    lr, [r0, #44]                       \n"
        "ldr    r0, [r0, #0]                        \n"
        "msr    msp, r0                             \n"
        "pop    {r4-r11}                            \n"
        /* Drop PSPLIM_S — wt_co_arch_switch reinstalls it for the next
         * tasklet. PSP_S itself is left pointing into the dead
         * tasklet's stack; harmless because CONTROL.SPSEL=0 on
         * return-to-Thread-MSP and arch_switch will overwrite PSP_S
         * before re-enabling PSP. */
        "movs   r0, #0                              \n"
        "msr    psplim, r0                          \n"
        /* An unprivileged Secure Partition coroutine dies here without
         * passing through PendSV's bootstrap path, so clear CONTROL.nPRIV
         * or the resumed bootstrap would run unprivileged. */
        "mrs    r0, control                         \n"
        "bic    r0, r0, #1                          \n"
        "msr    control, r0                         \n"
        /* EXC_RETURN = 0xFFFFFFF9: Secure Thread mode using MSP_S, no
         * FP context. mvn of 6 builds the value with no literal pool. */
        "mvn    lr, #6                              \n"
        "bx     lr                                  \n"
    );
}

__attribute__((naked)) void MemManage_Handler(void)
{
    __asm volatile("b wt_armv8m_tasklet_fault_entry \n");
}

__attribute__((naked)) void UsageFault_Handler(void)
{
    __asm volatile("b wt_armv8m_tasklet_fault_entry \n");
}
