/* irq_armv8m.c
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


/* Armv8-M NVIC operations behind the architecture contract: guest interrupt
 * masks, Secure-targeted partition interrupts, and guest-targeted routing. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/core_regs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void wt_arch_mask_all_guest_irqs(void)
{
    volatile uint32_t* icer = (volatile uint32_t*)0xE002E180u;
    size_t i;

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        icer[i] = 0xFFFFFFFFu;
    }
}

void wt_arch_apply_irq_mask(const wt_irq_mask_t* mask)
{
    volatile uint32_t* iser = (volatile uint32_t*)0xE002E100u;
    size_t i;

    if (mask == NULL) {
        return;
    }

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        iser[i] = mask->words[i];
    }
}

void wt_arch_quarantine_pending_irqs(const wt_irq_mask_t* allowed_mask)
{
    volatile uint32_t* icpr = (volatile uint32_t*)0xE002E280u;
    size_t i;

    if (allowed_mask == NULL) {
        return;
    }

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        icpr[i] = ~allowed_mask->words[i];
    }
}

void wt_arch_secure_irq_enable(uint32_t irq)
{
    volatile uint32_t* iser = (volatile uint32_t*)0xE000E100u;
    volatile uint32_t* icpr = (volatile uint32_t*)0xE000E280u;
    volatile uint32_t* itns = (volatile uint32_t*)0xE000E380u;
    uint32_t word = irq >> 5;
    uint32_t bit = irq & 31u;

    if (word >= WT_MAX_IRQ_WORDS) {
        return;
    }
    /* Route to Secure, drop any stale pending, lowest priority so the line
     * never preempts the active SVC gate, then unmask. */
    itns[word] &= ~(1u << bit);
    icpr[word] = (1u << bit);
    WT_NVIC_IPR_BASE[irq] = 0xFFu;
    __asm volatile("dsb\nisb" ::: "memory");
    iser[word] = (1u << bit);
}

void wt_arch_secure_irq_disable(uint32_t irq)
{
    volatile uint32_t* icer = (volatile uint32_t*)0xE000E180u;
    volatile uint32_t* icpr = (volatile uint32_t*)0xE000E280u;
    uint32_t word = irq >> 5;
    uint32_t bit = irq & 31u;

    if (word >= WT_MAX_IRQ_WORDS) {
        return;
    }
    icer[word] = (1u << bit);
    icpr[word] = (1u << bit);
    __asm volatile("dsb\nisb" ::: "memory");
}

void wt_arch_route_irq_to_guest(uint32_t irq)
{
    volatile uint32_t *itns = (volatile uint32_t *)0xE000E380u;
    uint32_t word = irq >> 5;
    uint32_t bit  = irq & 31u;

    if (word >= WT_MAX_IRQ_WORDS) return;
    /* ITNS only has a secure alias; mark this IRQ as NS-targeted.
     * Do NOT enable in NVIC ISER here — that comes from the per-guest
     * partition irq_mask when the monitor dispatches a guest that
     * actually wants to receive this IRQ. */
    itns[word] |= (1u << bit);
}

void wt_arch_set_guest_irq_pending(uint32_t irq, bool asserted)
{
    uint32_t word = irq >> 5;
    uint32_t bit  = irq & 31u;
    if (word >= WT_MAX_IRQ_WORDS) return;
    if (asserted) {
        volatile uint32_t *ispr_ns = (volatile uint32_t *)0xE002E200u;
        ispr_ns[word] = (1u << bit);
    } else {
        volatile uint32_t *icpr_ns = (volatile uint32_t *)0xE002E280u;
        icpr_ns[word] = (1u << bit);
    }
}
