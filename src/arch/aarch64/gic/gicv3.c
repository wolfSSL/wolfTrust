/* gicv3.c
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

/* GICv3 (GIC-500) secure-side driver: memory-mapped distributor and the boot
 * core's redistributor, system-register CPU interface; Group 0 signals FIQ. */

#include "memory_map.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/sysreg.h"

#define GICD_CTLR         0x0000u
#define GICD_TYPER        0x0004u
#define GICD_IGROUPR      0x0080u
#define GICD_ISENABLER    0x0100u
#define GICD_ISPENDR      0x0200u
#define GICD_ICENABLER    0x0180u
#define GICD_IPRIORITYR   0x0400u
#define GICD_IGRPMODR     0x0D00u
#define GICD_CTLR_ENABLE_GRP0   (1u << 0)
#define GICD_CTLR_ENABLE_GRP1NS (1u << 1)
#define GICD_CTLR_ENABLE_GRP1S  (1u << 2)
#define GICD_CTLR_ARE_S         (1u << 4)
#define GICD_CTLR_ARE_NS        (1u << 5)
#define GICD_CTLR_RWP           (1u << 31)

#define GICR_FRAME_SIZE   0x20000u
#define GICR_WAKER        0x0014u
#define GICR_WAKER_PROCESSOR_SLEEP (1u << 1)
#define GICR_WAKER_CHILDREN_ASLEEP (1u << 2)
#define GICR_SGI_BASE     0x10000u
#define GICR_IGROUPR0     (GICR_SGI_BASE + 0x0080u)
#define GICR_ISENABLER0   (GICR_SGI_BASE + 0x0100u)
#define GICR_ICENABLER0   (GICR_SGI_BASE + 0x0180u)
#define GICR_IPRIORITYR   (GICR_SGI_BASE + 0x0400u)
#define GICR_IGRPMODR0    (GICR_SGI_BASE + 0x0D00u)

#define ICC_SRE_SRE  (1u << 0)
#define ICC_SRE_DFB  (1u << 1)
#define ICC_SRE_DIB  (1u << 2)
#define ICC_SRE_EN   (1u << 3)

#define WAKE_POLL_LIMIT 1000000u

WT_SYSREG_WRITE(icc_sre_el3, "ICC_SRE_EL3")
WT_SYSREG_WRITE(icc_sre_el1, "ICC_SRE_EL1")
WT_SYSREG_WRITE(icc_pmr_el1, "ICC_PMR_EL1")
WT_SYSREG_WRITE(icc_igrpen0_el1, "ICC_IGRPEN0_EL1")
WT_SYSREG_WRITE(icc_ctlr_el3, "ICC_CTLR_EL3")
WT_SYSREG_WRITE(icc_eoir0_el1, "ICC_EOIR0_EL1")
WT_SYSREG_READ(icc_iar0_el1, "ICC_IAR0_EL1")

static unsigned int g_rdist_woken;

static volatile uint32_t* gicd(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_GICD_BASE + offset);
}

/* The boot core owns redistributor frame 0; secondaries park before they
 * would need theirs. */
static volatile uint32_t* gicr(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_GICR_BASE + offset);
}

static void gicd_wait_rwp(void)
{
    uint32_t spin = WAKE_POLL_LIMIT;

    while (((*gicd(GICD_CTLR) & GICD_CTLR_RWP) != 0u) && (spin > 0u)) {
        spin--;
    }
}

static void gicv3_set_group0(uint32_t intid)
{
    if (intid < 32u) {
        *gicr(GICR_IGROUPR0) &= ~(1u << intid);
        *gicr(GICR_IGRPMODR0) &= ~(1u << intid);
    }
    else {
        *gicd(GICD_IGROUPR + (intid / 32u) * 4u) &= ~(1u << (intid % 32u));
        *gicd(GICD_IGRPMODR + (intid / 32u) * 4u) &= ~(1u << (intid % 32u));
    }
}

static void gicv3_enable(uint32_t intid)
{
    if (intid < 32u) {
        *gicr(GICR_ISENABLER0) = 1u << intid;
    }
    else {
        *gicd(GICD_ISENABLER + (intid / 32u) * 4u) = 1u << (intid % 32u);
    }
}

static void gicv3_disable(uint32_t intid)
{
    if (intid < 32u) {
        *gicr(GICR_ICENABLER0) = 1u << intid;
    }
    else {
        *gicd(GICD_ICENABLER + (intid / 32u) * 4u) = 1u << (intid % 32u);
    }
}

static void gicv3_set_priority(uint32_t intid, uint8_t priority)
{
    volatile uint8_t* reg;

    if (intid < 32u) {
        reg = (volatile uint8_t*)(uintptr_t)(WT_GICR_BASE + GICR_IPRIORITYR + intid);
    }
    else {
        reg = (volatile uint8_t*)(uintptr_t)(WT_GICD_BASE + GICD_IPRIORITYR + intid);
    }
    *reg = priority;
}

static uint32_t gicv3_ack_group0(void)
{
    uint32_t intid = (uint32_t)wt_read_icc_iar0_el1() & 0xFFFFFFu;

    return intid;
}

static void gicv3_eoi_group0(uint32_t intid)
{
    wt_write_icc_eoir0_el1(intid);
    wt_isb();
}

static void wake_redistributor(void)
{
    uint32_t spin = WAKE_POLL_LIMIT;

    *gicr(GICR_WAKER) &= ~GICR_WAKER_PROCESSOR_SLEEP;
    while (((*gicr(GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP) != 0u) &&
           (spin > 0u)) {
        spin--;
    }
    g_rdist_woken = (spin > 0u) ? 1u : 0u;
}

static void gicv3_init_secure(void)
{
    uint32_t lines = ((*gicd(GICD_TYPER) & 0x1Fu) + 1u) * 32u;
    uint32_t scr;
    uint32_t i;

    wt_write_icc_sre_el3(ICC_SRE_SRE | ICC_SRE_DFB | ICC_SRE_DIB | ICC_SRE_EN);
    wt_isb();

    *gicd(GICD_CTLR) = 0u;
    gicd_wait_rwp();
    for (i = 32u; i < lines; i += 32u) {
        *gicd(GICD_ICENABLER + (i / 32u) * 4u) = 0xFFFFFFFFu;
        *gicd(GICD_IGROUPR + (i / 32u) * 4u) = 0xFFFFFFFFu;
        *gicd(GICD_IGRPMODR + (i / 32u) * 4u) = 0u;
    }
    gicd_wait_rwp();
    *gicd(GICD_CTLR) = GICD_CTLR_ARE_S | GICD_CTLR_ARE_NS;
    gicd_wait_rwp();
    *gicd(GICD_CTLR) = GICD_CTLR_ARE_S | GICD_CTLR_ARE_NS |
                       GICD_CTLR_ENABLE_GRP0 | GICD_CTLR_ENABLE_GRP1NS |
                       GICD_CTLR_ENABLE_GRP1S;
    gicd_wait_rwp();

    wake_redistributor();
    *gicr(GICR_ICENABLER0) = 0xFFFFFFFFu;
    *gicr(GICR_IGROUPR0) = 0xFFFFFFFFu;
    *gicr(GICR_IGRPMODR0) = 0u;
    gicv3_set_group0(WT_GIC_INTID_SECURE_TIMER);
    gicv3_set_priority(WT_GIC_INTID_SECURE_TIMER, 0x00u);

    /* ICC_SRE_EL1 is banked by Security state: write it for both worlds. */
    wt_write_icc_sre_el1(ICC_SRE_SRE | ICC_SRE_DFB | ICC_SRE_DIB);
    scr = (uint32_t)wt_read_scr_el3();
    wt_write_scr_el3(scr | WT_SCR_NS);
    wt_isb();
    wt_write_icc_sre_el1(ICC_SRE_SRE | ICC_SRE_DFB | ICC_SRE_DIB);
    wt_isb();
    wt_write_scr_el3(scr);
    wt_isb();

    wt_write_icc_ctlr_el3(0u);
    wt_write_icc_pmr_el1(0xFFu);
    wt_write_icc_igrpen0_el1(1u);
    wt_isb();
}

/* Make an interrupt pending in software (SPIs, id >= 32) so a test driver can
 * raise a Secure interrupt without external hardware. */
static void gicv3_set_pending(uint32_t intid)
{
    *gicd(GICD_ISPENDR + (intid / 32u) * 4u) = 1u << (intid % 32u);
}

static const struct wt_gic_ops gicv3_ops = {
    gicv3_init_secure,
    gicv3_set_group0,
    gicv3_enable,
    gicv3_disable,
    gicv3_set_priority,
    gicv3_ack_group0,
    gicv3_eoi_group0,
    gicv3_set_pending,
    3u
};

const struct wt_gic_ops* const wt_gic = &gicv3_ops;

unsigned int wt_gic_rdist_woken(void)
{
    return g_rdist_woken;
}
