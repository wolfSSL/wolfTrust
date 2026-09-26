/* mock_trng_regs.h
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

/* Force-included ahead of rng_entropy.c: the real register header supplies the
 * bit layout, and MCTL and ENT route through the test's TRNG model. */
#ifndef WT_TEST_MOCK_TRNG_REGS_H
#define WT_TEST_MOCK_TRNG_REGS_H

#include <stdint.h>

#include "mimxrt798_regs.h"

volatile uint32_t* wt_mock_trng_mctl(void);
volatile uint32_t* wt_mock_trng_ent(uint32_t index);

#undef WT_TRNG_MCTL
#undef WT_TRNG_ENT
#define WT_TRNG_MCTL        (*wt_mock_trng_mctl())
#define WT_TRNG_ENT(index)  (*wt_mock_trng_ent(index))

#endif /* WT_TEST_MOCK_TRNG_REGS_H */
