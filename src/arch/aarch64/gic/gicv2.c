/* gicv2.c
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

/* GICv2 (GIC-400) secure-side driver: memory-mapped distributor and CPU
 * interface; Group 0 signals FIQ, Group 1 IRQ. */

#include "memory_map.h"
#include "wolftrust/arch/aarch64/gic.h"

#define GICD_CTLR        0x000u
#define GICD_TYPER       0x004u
#define GICD_IGROUPR     0x080u
#define GICD_ISENABLER   0x100u
#define GICD_ICENABLER   0x180u
#define GICD_IPRIORITYR  0x400u
#define GICD_CTLR_ENABLE_GRP0 (1u << 0)
#define GICD_CTLR_ENABLE_GRP1 (1u << 1)

#define GICC_CTLR        0x000u
#define GICC_PMR         0x004u
#define GICC_IAR         0x00Cu
#define GICC_EOIR        0x010u
#define GICC_CTLR_ENABLE_GRP0 (1u << 0)
#define GICC_CTLR_ENABLE_GRP1 (1u << 1)
#define GICC_CTLR_FIQ_EN      (1u << 3)

static volatile uint32_t* gicd(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_GICD_BASE + offset);
}

static volatile uint32_t* gicc(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_GICC_BASE + offset);
}

static uint32_t line_count(void)
{
    return ((*gicd(GICD_TYPER) & 0x1Fu) + 1u) * 32u;
}

static void gicv2_set_group0(uint32_t intid)
{
    volatile uint32_t* reg = gicd(GICD_IGROUPR + (intid / 32u) * 4u);

    *reg &= ~(1u << (intid % 32u));
}

static void gicv2_enable(uint32_t intid)
{
    *gicd(GICD_ISENABLER + (intid / 32u) * 4u) = 1u << (intid % 32u);
}

static void gicv2_disable(uint32_t intid)
{
    *gicd(GICD_ICENABLER + (intid / 32u) * 4u) = 1u << (intid % 32u);
}

static void gicv2_set_priority(uint32_t intid, uint8_t priority)
{
    volatile uint8_t* reg =
        (volatile uint8_t*)(uintptr_t)(WT_GICD_BASE + GICD_IPRIORITYR + intid);

    *reg = priority;
}

static uint32_t gicv2_ack_group0(void)
{
    return *gicc(GICC_IAR) & 0x3FFu;
}

static void gicv2_eoi_group0(uint32_t intid)
{
    *gicc(GICC_EOIR) = intid;
}

static void gicv2_init_secure(void)
{
    uint32_t lines = line_count();
    uint32_t i;

    *gicd(GICD_CTLR) = 0u;
    for (i = 0u; i < lines; i += 32u) {
        *gicd(GICD_ICENABLER + (i / 32u) * 4u) = 0xFFFFFFFFu;
        *gicd(GICD_IGROUPR + (i / 32u) * 4u) = 0xFFFFFFFFu;
    }
    gicv2_set_group0(WT_GIC_INTID_SECURE_TIMER);
    gicv2_set_priority(WT_GIC_INTID_SECURE_TIMER, 0x00u);
    *gicd(GICD_CTLR) = GICD_CTLR_ENABLE_GRP0 | GICD_CTLR_ENABLE_GRP1;
    *gicc(GICC_PMR) = 0xFFu;
    *gicc(GICC_CTLR) = GICC_CTLR_ENABLE_GRP0 | GICC_CTLR_ENABLE_GRP1 |
                       GICC_CTLR_FIQ_EN;
}

static const struct wt_gic_ops gicv2_ops = {
    gicv2_init_secure,
    gicv2_set_group0,
    gicv2_enable,
    gicv2_disable,
    gicv2_set_priority,
    gicv2_ack_group0,
    gicv2_eoi_group0,
    2u
};

const struct wt_gic_ops* const wt_gic = &gicv2_ops;

unsigned int wt_gic_rdist_woken(void)
{
    return 1u;
}
