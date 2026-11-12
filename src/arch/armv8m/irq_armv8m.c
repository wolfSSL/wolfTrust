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
#include "wolftrust/irq_claim.h"
#include "wolftrust/arch/armv8m/armv8m.h"
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

void wt_arch_read_guest_irq_enables(wt_irq_mask_t* out)
{
    volatile uint32_t* iser = (volatile uint32_t*)0xE002E100u;
    size_t i;

    for (i = 0; i < WT_MAX_IRQ_WORDS; ++i) {
        out->words[i] = iser[i];
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

#define WT_NVIC_ISER ((volatile uint32_t*)0xE000E100u)
#define WT_NVIC_ICER ((volatile uint32_t*)0xE000E180u)
#define WT_NVIC_ICPR ((volatile uint32_t*)0xE000E280u)
#define WT_NVIC_ITNS ((volatile uint32_t*)0xE000E380u)

static void wt_nvic_disable(uint32_t word, uint32_t mask)
{
    WT_NVIC_ICER[word] = mask;
}

static void wt_nvic_clear_pending(uint32_t word, uint32_t mask)
{
    WT_NVIC_ICPR[word] = mask;
}

static void wt_nvic_route_secure(uint32_t word, uint32_t mask)
{
    WT_NVIC_ITNS[word] &= ~mask;
}

static uint32_t wt_nvic_enabled(uint32_t word)
{
    return WT_NVIC_ISER[word];
}

static uint32_t wt_nvic_non_secure(uint32_t word)
{
    return WT_NVIC_ITNS[word];
}

static void wt_nvic_barrier(void)
{
    __asm volatile("dsb\nisb" ::: "memory");
}

static const wt_nvic_ops_t g_wt_nvic_ops = {
    wt_nvic_disable,
    wt_nvic_clear_pending,
    wt_nvic_route_secure,
    wt_nvic_enabled,
    wt_nvic_non_secure,
    wt_nvic_barrier
};

int wt_arch_secure_irq_claim(uint32_t irq)
{
    return wt_irq_claim(&g_wt_nvic_ops, irq, WT_ARMV8M_SECURE_IRQS / 32u);
}

void wt_arch_secure_irq_enable(uint32_t irq)
{
    uint32_t word = irq >> 5;
    uint32_t bit = 1u << (irq & 31u);

    if (irq >= WT_ARMV8M_SECURE_IRQS) {
        return;
    }
    /* Route to Secure, drop any stale pending, at the Secure band priority
     * (below the SVC gate, equal to SysTick/PendSV), then unmask. */
    WT_NVIC_ITNS[word] &= ~bit;
    WT_NVIC_ICPR[word] = bit;
    WT_NVIC_IPR_BASE[irq] = (uint8_t)WT_ARMV8M_SECURE_BAND_PRIO;
    __asm volatile("dsb\nisb" ::: "memory");
    WT_NVIC_ISER[word] = bit;
}

void wt_arch_secure_irq_disable(uint32_t irq)
{
    uint32_t word = irq >> 5;
    uint32_t bit = 1u << (irq & 31u);

    if (irq >= WT_ARMV8M_SECURE_IRQS) {
        return;
    }
    WT_NVIC_ICER[word] = bit;
    WT_NVIC_ICPR[word] = bit;
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
