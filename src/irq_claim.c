/* irq_claim.c
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

#include <stddef.h>

#include "wolftrust/irq_claim.h"

int wt_irq_claim(uint32_t irq, uint32_t words)
{
    uint32_t word = irq >> 5;
    uint32_t mask = 1u << (irq & 31u);

    if (word >= words) {
        return -1;
    }
    wt_arch_nvic_disable(word, mask);
    wt_arch_nvic_barrier();
    wt_arch_nvic_route_secure(word, mask);
    wt_arch_nvic_clear_pending(word, mask);
    wt_arch_nvic_barrier();
    if ((wt_arch_nvic_non_secure(word) & mask) != 0u ||
            (wt_arch_nvic_enabled(word) & mask) != 0u) {
        return -1;
    }
    return 0;
}
