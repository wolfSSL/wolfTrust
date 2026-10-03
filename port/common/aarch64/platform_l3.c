/* platform_l3.c
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

/* Isolation level 3 platform hooks shared by every AArch64 port. The bands
 * come from l3_layout.h through the port's memory_map.h; the port's l3_port.h
 * names the one board input, a Secure peripheral only the SPM drives. */

#include "wolftrust/platform.h"
#include "wolftrust/priv_stack.h"
#include "memory_map.h"
#include "l3_port.h"

#include <stddef.h>
#include <stdint.h>

extern uint8_t _e_secure_text[];
extern uint8_t _e_secure_rodata[];

/* The code every partition executes: the SPMC image text (RX) and its
 * constant data (RO), shaped exactly like the SPMC's shareable fill entries
 * so the partition mapping replaces them (the manifest's executable
 * resource is policy only; the scheduler maps code from here). The load
 * images of initialized data that follow the constant data stay EL1-only. */
size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max)
{
    uintptr_t text_end = (uintptr_t)_e_secure_text;
    uintptr_t rodata_end = (uintptr_t)_e_secure_rodata;

    if (regions == NULL || max < 2u) {
        return 0u;
    }
    regions[0].base = (uintptr_t)WT_SPM_IMAGE_PA;
    regions[0].size = text_end - (uintptr_t)WT_SPM_IMAGE_PA;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    regions[1].base = text_end;
    regions[1].size = rodata_end - text_end;
    regions[1].attributes = WT_MEM_ATTR_READ;
    return 2u;
}

/* No peripheral is a partition's to own yet: every DEVICE resource is refused. */
const struct wt_periph* wt_platform_sp_peripherals(size_t* count)
{
    if (count != NULL) {
        *count = 0U;
    }
    return NULL;
}

/* SPM RAM (the SPMC's data, bss and stacks) stays EL1-only. */
size_t wt_platform_spm_private_regions(wt_memory_region_t* regions,
                                       size_t max)
{
    if (regions == NULL || max < 1u) {
        return 0u;
    }
    regions[0].base = (uintptr_t)WT_SPM_RAM_PA;
    regions[0].size = WT_SPM_RAM_SIZE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    return 1u;
}

int wt_platform_priv_stack_ok(const void *stack, size_t size)
{
    if (stack == NULL) {
        return 0;
    }
    return wt_priv_stack_ok((uintptr_t)stack, size, (uintptr_t)WT_SPM_RAM_PA,
                            (uintptr_t)WT_SPM_RAM_PA + WT_SPM_RAM_SIZE,
                            NULL, 0u);
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
size_t wt_platform_conf_shared_regions(wt_memory_region_t* regions,
                                       size_t max)
{
    if (regions == NULL || max < 1u) {
        return 0u;
    }
    regions[0].base = (uintptr_t)WT_SPM_CONFDATA_PA;
    regions[0].size = WT_SPM_CONFDATA_SIZE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    return 1u;
}
#endif

#if (defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)) || \
    (defined(WT_KEYSTORE_NEG_PROBE) && (WT_KEYSTORE_NEG_PROBE == 1)) || \
    (defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)) || \
    (defined(WT_PERIPH_SP_NEG_PROBE) && (WT_PERIPH_SP_NEG_PROBE == 1)) || \
    (defined(WT_MANIFEST_NEG_PROBE) && (WT_MANIFEST_NEG_PROBE == 3))
uintptr_t wt_platform_probe_address(unsigned int target)
{
    switch (target) {
    case WT_PROBE_VAULT_DATA_BAND:
        return (uintptr_t)WT_SPM_VAULT_PA;
    case WT_PROBE_ATTEST_DATA_BAND:
        return (uintptr_t)WT_SPM_ATTEST_PA;
    case WT_PROBE_HSM_DATA_BAND:
        return (uintptr_t)WT_SPM_HSMDATA_PA;
    case WT_PROBE_SPM_PERIPHERAL:
        return (uintptr_t)WT_L3_SPM_PERIPHERAL_BASE;
    default:
        return (uintptr_t)WT_SPM_RAM_PA;
    }
}
#endif
