/* world.c
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

/* Normal/Secure world switching at EL3. EL1 system registers are not banked by
 * security state on these cores (no Secure-EL2), so each world's full register
 * file and EL1 context are saved and restored around every SPMD entry. A guest
 * FF-A call the SPMD must forward resumes the SPMC where it blocked in its idle
 * FFA_MSG_WAIT; the SPMC's reply is delivered back to the guest the same way.
 * The switch edits the live trap frame and the vector epilogue ERETs into the
 * chosen world. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/sysreg.h"

#define WT_WORLD_SECURE 0u
#define WT_WORLD_NS     1u

/* Period after which the Secure timer preempts the Normal world (ffa-preempt). */
#ifndef WT_NS_PREEMPT_MS
#define WT_NS_PREEMPT_MS 50u
#endif

static wt_el3_world_t g_world[2];
static unsigned int g_world_cur = WT_WORLD_SECURE;
static unsigned int g_ns_pending = WT_NS_PENDING_NONE;

static void world_save(wt_el3_world_t* w, const wt_el3_frame_t* frame)
{
    w->frame = *frame;
    w->sp_el0 = wt_read_sp_el0();
    w->sp_el1 = wt_read_sp_el1();
    w->sctlr_el1 = wt_read_sctlr_el1();
    w->ttbr0_el1 = wt_read_ttbr0_el1();
    w->ttbr1_el1 = wt_read_ttbr1_el1();
    w->tcr_el1 = wt_read_tcr_el1();
    w->mair_el1 = wt_read_mair_el1();
    w->amair_el1 = wt_read_amair_el1();
    w->vbar_el1 = wt_read_vbar_el1();
    w->tpidr_el0 = wt_read_tpidr_el0();
    w->tpidrro_el0 = wt_read_tpidrro_el0();
    w->tpidr_el1 = wt_read_tpidr_el1();
    w->contextidr_el1 = wt_read_contextidr_el1();
    w->cpacr_el1 = wt_read_cpacr_el1();
    w->elr_el1 = wt_read_elr_el1();
    w->spsr_el1 = wt_read_spsr_el1();
    w->esr_el1 = wt_read_esr_el1();
    w->far_el1 = wt_read_far_el1();
    w->par_el1 = wt_read_par_el1();
    w->mdscr_el1 = wt_read_mdscr_el1();
}

/* Restore a world's EL1 context and ERET into it (never returns). SCR_EL3,
 * HCR_EL2.RW, the register file, ELR, and SPSR are programmed in the assembly
 * primitive immediately before the ERET; the EL1 system registers are written
 * here first (they take effect for EL1 across the exception return). */
static void world_restore(const wt_el3_world_t* w) __attribute__((noreturn));
static void world_restore(const wt_el3_world_t* w)
{
    wt_write_sp_el0(w->sp_el0);
    wt_write_sp_el1(w->sp_el1);
    wt_write_sctlr_el1(w->sctlr_el1);
    wt_write_ttbr0_el1(w->ttbr0_el1);
    wt_write_ttbr1_el1(w->ttbr1_el1);
    wt_write_tcr_el1(w->tcr_el1);
    wt_write_mair_el1(w->mair_el1);
    wt_write_amair_el1(w->amair_el1);
    wt_write_vbar_el1(w->vbar_el1);
    wt_write_tpidr_el0(w->tpidr_el0);
    wt_write_tpidrro_el0(w->tpidrro_el0);
    wt_write_tpidr_el1(w->tpidr_el1);
    wt_write_contextidr_el1(w->contextidr_el1);
    wt_write_cpacr_el1(w->cpacr_el1);
    wt_write_elr_el1(w->elr_el1);
    wt_write_spsr_el1(w->spsr_el1);
    wt_write_esr_el1(w->esr_el1);
    wt_write_far_el1(w->far_el1);
    wt_write_par_el1(w->par_el1);
    wt_write_mdscr_el1(w->mdscr_el1);
    wt_el3_world_eret(&w->frame, w->scr_el3);
}

static void world_switch(wt_el3_frame_t* frame, unsigned int to)
    __attribute__((noreturn));
static void world_switch(wt_el3_frame_t* frame, unsigned int to)
{
    world_save(&g_world[g_world_cur], frame);
    g_world_cur = to;
    world_restore(&g_world[to]);
}

#if defined(WT_EL3_NS_SMOKE) && (WT_EL3_NS_SMOKE == 1)
/* A fresh NS-EL1 payload: MMU off, entry at the port NS image base, EL1h with
 * DAIF masked; the payload maps its own memory and sets its own stack. */
static void world_init_ns(wt_el3_world_t* w)
{
    unsigned int i;

    for (i = 0u; i < 31u; i++) {
        w->frame.x[i] = 0u;
    }
    w->frame.elr = (uint64_t)WT_NS_IMAGE_PA;
    w->frame.spsr = WT_SPSR_EL1H_DAIF;
    w->frame.pad = 0u;
    w->scr_el3 = WT_SCR_EL3_NS;
    w->sp_el0 = 0u;
    w->sp_el1 = 0u;
    w->sctlr_el1 = WT_SCTLR_EL1_RES1;
    w->ttbr0_el1 = 0u;
    w->ttbr1_el1 = 0u;
    w->tcr_el1 = 0u;
    w->mair_el1 = 0u;
    w->amair_el1 = 0u;
    w->vbar_el1 = 0u;
    w->tpidr_el0 = 0u;
    w->tpidrro_el0 = 0u;
    w->tpidr_el1 = 0u;
    w->contextidr_el1 = 0u;
    w->cpacr_el1 = 0u;
    w->elr_el1 = 0u;
    w->spsr_el1 = 0u;
    w->esr_el1 = 0u;
    w->far_el1 = 0u;
    w->par_el1 = 0u;
    w->mdscr_el1 = 0u;
}
#endif

unsigned int wt_el3_world_ns_pending(void)
{
    return g_ns_pending;
}

void wt_el3_world_forward_to_secure(wt_el3_frame_t* frame)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        g_world[WT_WORLD_SECURE].frame.x[i] = frame->x[i];
    }
    g_ns_pending = WT_NS_PENDING_REPLY;
    world_switch(frame, WT_WORLD_SECURE);
}

void wt_el3_world_preempt_to_secure(wt_el3_frame_t* frame, uint32_t intid)
{
    unsigned int i;

    /* Hand the SPMC an FFA_INTERRUPT event; the preempted NS context is saved by
     * the switch and resumed unchanged once the SPMC yields the Normal world. */
    for (i = 0u; i < 8u; i++) {
        g_world[WT_WORLD_SECURE].frame.x[i] = 0u;
    }
    g_world[WT_WORLD_SECURE].frame.x[0] = WT_FFA_INTERRUPT;
    g_world[WT_WORLD_SECURE].frame.x[1] = (uint64_t)intid;
    g_ns_pending = WT_NS_PENDING_RESUME;
    world_switch(frame, WT_WORLD_SECURE);
}

void wt_el3_world_return_to_ns(wt_el3_frame_t* frame)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        g_world[WT_WORLD_NS].frame.x[i] = frame->x[i];
    }
    g_ns_pending = WT_NS_PENDING_NONE;
    world_switch(frame, WT_WORLD_NS);
}

void wt_el3_world_resume_ns(wt_el3_frame_t* frame)
{
    /* Resume the preempted Normal world exactly as it was: its saved frame is
     * restored unchanged (no reply registers). */
    g_ns_pending = WT_NS_PENDING_NONE;
    world_switch(frame, WT_WORLD_NS);
}

void wt_el3_world_launch_ns(wt_el3_frame_t* frame)
{
    wt_el3_puts("[EL3] spmc ready\r\n");
    wt_platform_console_flush();
#if defined(WT_EL3_NS_SMOKE) && (WT_EL3_NS_SMOKE == 1)
    /* Save the SPMC (blocked in its idle FFA_MSG_WAIT) and turn on the Normal
     * world; a later forwarded call resumes the SPMC from here. Its SCR_EL3 is a
     * fixed property of the Secure world (world_save carries only per-yield
     * state), so record it once. */
    world_save(&g_world[WT_WORLD_SECURE], frame);
    g_world[WT_WORLD_SECURE].scr_el3 = WT_SCR_EL3_SECURE;
    world_init_ns(&g_world[WT_WORLD_NS]);
    g_world_cur = WT_WORLD_NS;
    wt_el3_puts("[EL3] ns launch pc=0x");
    wt_el3_puthex((uint64_t)WT_NS_IMAGE_PA, 8u);
    wt_el3_puts("\r\n");
    wt_platform_console_flush();
#if defined(WT_NS_PREEMPT) && (WT_NS_PREEMPT == 1)
    /* Arm a one-shot Secure tick so it fires while the Normal world runs; with
     * SCR_EL3.FIQ set for NS it traps to EL3 as a lower-EL FIQ (ffa-preempt). */
    wt_gic->enable(WT_GIC_INTID_SECURE_TIMER);
    wt_el3_timer_arm_ms(WT_NS_PREEMPT_MS);
#endif
    world_restore(&g_world[WT_WORLD_NS]);
#else
    (void)frame;
    (void)wt_el3_monitor_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
    for (;;) {
    }
#endif
}
