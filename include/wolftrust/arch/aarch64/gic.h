/* gic.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_GIC_H
#define WOLFTRUST_ARCH_AARCH64_GIC_H

#include <stdint.h>

/* One driver per GIC architecture version, bound at build by WT_GIC_VERSION.
 * Secure interrupts are Group 0 (FIQ), Non-secure ones Group 1. */

#define WT_GIC_INTID_SPURIOUS  1023u
#define WT_GIC_INTID_SECURE_TIMER 29u

struct wt_gic_ops {
    void (*init_secure)(void);
    void (*set_group0)(uint32_t intid);
    void (*enable)(uint32_t intid);
    void (*disable)(uint32_t intid);
    void (*set_priority)(uint32_t intid, uint8_t priority);
    uint32_t (*ack_group0)(void);
    void (*eoi_group0)(uint32_t intid);
    unsigned int version;
};

extern const struct wt_gic_ops* const wt_gic;

/* 1 once a GICv3 redistributor reports its children awake; always 1 on GICv2. */
unsigned int wt_gic_rdist_woken(void);

#endif /* WOLFTRUST_ARCH_AARCH64_GIC_H */
