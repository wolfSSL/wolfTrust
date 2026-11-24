/* boot_handoff.c
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

#include "wolftrust/boot_handoff.h"
#include "wolftrust/platform.h"
#include "wolftrust/arch.h"

#include <stddef.h>

int wt_boot_handoff_consume(wt_boot_handoff_t* handoff)
{
    volatile uint8_t* sourceBytes;
    uint8_t* outputBytes = (uint8_t*)handoff;
    size_t regionSize = 0u;
    size_t i;
    int ret = -1;

    if (handoff == NULL) {
        return -1;
    }

    sourceBytes = (volatile uint8_t*)wt_platform_boot_handoff_region(&regionSize);
    if (sourceBytes != NULL && regionSize >= sizeof(*handoff)) {
        wt_arch_dmb();
        for (i = 0u; i < sizeof(*handoff); ++i) {
            outputBytes[i] = sourceBytes[i];
        }
        if ((handoff->magic == WT_BOOT_HANDOFF_MAGIC) &&
            (handoff->magic_inverse == ~WT_BOOT_HANDOFF_MAGIC) &&
            (handoff->version == WT_BOOT_HANDOFF_VERSION) &&
            (handoff->size == sizeof(*handoff)) &&
            (handoff->hash_algorithm == WT_BOOT_HANDOFF_HASH_SHA256) &&
            (handoff->measurement_size == WT_BOOT_HANDOFF_DIGEST_SIZE)) {
            ret = 0;
        }
        for (i = 0u; i < sizeof(*handoff); ++i) {
            sourceBytes[i] = 0u;
        }
        wt_arch_dsb();
    }
    if (ret != 0) {
        for (i = 0u; i < sizeof(*handoff); ++i) {
            outputBytes[i] = 0u;
        }
    }

    return ret;
}

void wt_boot_handoff_clear(void)
{
    size_t regionSize = 0u;
    volatile uint8_t* regionBytes =
        (volatile uint8_t*)wt_platform_boot_handoff_region(&regionSize);
    size_t i;

    if (regionBytes != NULL) {
        for (i = 0u; i < regionSize; ++i) {
            regionBytes[i] = 0u;
        }
        wt_arch_dsb();
    }
}
