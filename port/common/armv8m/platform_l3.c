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

/* Isolation level 3 platform hooks shared by every Armv8-M port. The layout
 * comes from l3_layout.h through the port's memory_map.h; the port's
 * l3_port.h supplies the few board inputs. */

#include "wolftrust/platform.h"
#include "wolftrust/priv_stack.h"

#include <stddef.h>
#include <stdint.h>

#include "memory_map.h"
#include "l3_port.h"

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
#include "psa_manifest/pid.h"
#endif

/* End of executable image code (secure.ld): partitions get RX below it and
 * read-only XN above it, so no partition executes constant data. */
extern char _e_secure_text[];

volatile void* wt_platform_boot_handoff_region(size_t* size)
{
    *size = WT_RAM_S_BASE - WT_BOOT_HANDOFF_ADDRESS;
    return (volatile void*)WT_BOOT_HANDOFF_ADDRESS;
}

/* No peripheral is assignable to a Secure Partition yet: the SPM drives every
 * Secure peripheral itself, so every partition DEVICE resource is refused. */
const struct wt_periph* wt_platform_sp_peripherals(size_t* count)
{
    if (count != NULL) {
        *count = 0U;
    }
    return NULL;
}

size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max)
{
    if (max < 2u) {
        return 0u;
    }
    regions[0].base = WT_FLASH_S_BASE;
    regions[0].size = (uintptr_t)_e_secure_text - WT_FLASH_S_BASE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    regions[1].base = (uintptr_t)_e_secure_text;
    regions[1].size = WT_FLASH_S_BASE + WT_FLASH_S_SIZE -
                      (uintptr_t)_e_secure_text;
    regions[1].attributes = WT_MEM_ATTR_READ;
    return 2u;
}

size_t wt_platform_spm_private_regions(wt_memory_region_t* regions,
                                       size_t max)
{
    uintptr_t first_band = WT_SP_VAULT_DATA_BASE;
    size_t count = 1u;

#if defined(WT_RAMFUNC_BASE)
    count = 2u;
#endif
    if (max < count) {
        return 0u;
    }
#if defined(CONFIG_VNET)
    first_band = WT_VNET_DATA_BASE;
#endif
    regions[0].base = WT_RAM_S_BASE;
    regions[0].size = first_band - WT_RAM_S_BASE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
#if defined(WT_RAMFUNC_BASE)
    /* A port's RAM code band holds the NSC gateway and flash routines. */
    regions[1].base = WT_RAMFUNC_BASE;
    regions[1].size = WT_RAMFUNC_SIZE;
    regions[1].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
#endif
    return count;
}

int wt_platform_priv_stack_ok(const void *stack, size_t size)
{
    /* A privileged coroutine stack must lie wholly in SPM-private RAM, below
     * the lowest partition-writable band (WT-FFM-0011). */
#if defined(CONFIG_VNET)
    uintptr_t priv_end = WT_VNET_DATA_BASE;
#else
    uintptr_t priv_end = WT_KEYSTORE_BASE;
#endif

    if (stack == NULL) {
        return 0;
    }
    return wt_priv_stack_ok((uintptr_t)stack, size, WT_RAM_S_BASE, priv_end,
                            NULL, 0u);
}

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Per-partition private data bands (secure.ld), each denied to other SPs. */
extern char _s_conf_server_data[];
extern char _e_conf_server_data[];
extern char _s_conf_driver_data[];
extern char _e_conf_driver_data[];

/* Append one RW grant segment to an SP's thread table (skips empty segments,
 * fails closed by granting nothing when the table is full). */
static size_t wt_conf_grant(wt_memory_region_t* regions, size_t count,
                            size_t max, uintptr_t base, uintptr_t end)
{
    if (base < end && count < max) {
        regions[count].base = base;
        regions[count].size = (uint32_t)(end - base);
        regions[count].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
        count++;
    }
    return count;
}

/* Grant a hosted Arm partition the conformance window minus every other
 * partition's data band and pseudo-MMIO hole, so the suite's cross-partition
 * tests (i047/i055/i057/i080/i084) hit a genuine out-of-domain access. */
size_t wt_platform_conf_sp_grants(int32_t partition_id,
                                  wt_memory_region_t* regions,
                                  size_t count, size_t max)
{
    uintptr_t conf_seg = WT_CONF_SP_DATA_BASE;

    /* The wolfTrust partitions in the image hold none of the suite's data. */
    if (partition_id != SERVER_PARTITION_ID &&
            partition_id != CLIENT_PARTITION_ID &&
            partition_id != DRIVER_PARTITION_ID) {
        return count;
    }
    if (partition_id != SERVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              (uintptr_t)_s_conf_server_data);
        conf_seg = (uintptr_t)_e_conf_server_data;
    }
    if (partition_id != DRIVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              (uintptr_t)_s_conf_driver_data);
        conf_seg = (uintptr_t)_e_conf_driver_data;
    }
    if (partition_id != SERVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              WT_CONF_SERVER_MMIO_BASE);
        conf_seg = WT_CONF_SERVER_MMIO_BASE + WT_CONF_SERVER_MMIO_SIZE;
    }
    if (partition_id != DRIVER_PARTITION_ID) {
        count = wt_conf_grant(regions, count, max, conf_seg,
                              WT_CONF_DRV_MMIO_BASE);
        conf_seg = WT_CONF_DRV_MMIO_BASE + WT_CONF_DRV_MMIO_SIZE;
    }
    count = wt_conf_grant(regions, count, max, conf_seg,
                          WT_CONF_SP_DATA_BASE + WT_CONF_SP_DATA_SIZE);
    return count;
}

size_t wt_platform_conf_shared_regions(wt_memory_region_t* regions,
                                       size_t max)
{
    if (max < 1u) {
        return 0u;
    }
    regions[0].base = WT_CONF_SP_DATA_BASE;
    regions[0].size = WT_CONF_SP_DATA_SIZE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
    return 1u;
}
#endif

#if (defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)) || \
    (defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1)) || \
    (defined(WT_KEYSTORE_NEG_PROBE) && (WT_KEYSTORE_NEG_PROBE == 1)) || \
    (defined(WT_PERIPH_SP_NEG_PROBE) && (WT_PERIPH_SP_NEG_PROBE == 1)) || \
    (defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)) || \
    (defined(WT_MANIFEST_NEG_PROBE) && (WT_MANIFEST_NEG_PROBE == 3))
uintptr_t wt_platform_probe_address(unsigned int target)
{
    switch (target) {
    case WT_PROBE_VAULT_DATA_BAND:
        return (uintptr_t)WT_SP_VAULT_DATA_BASE;
    case WT_PROBE_ATTEST_DATA_BAND:
        return (uintptr_t)WT_SP_ATTEST_DATA_BASE;
    case WT_PROBE_HSM_DATA_BAND:
        return (uintptr_t)WT_SP_HSM_DATA_BASE;
    case WT_PROBE_SPM_PERIPHERAL:
        return (uintptr_t)WT_L3_SPM_PERIPHERAL_BASE;
#if defined(CONFIG_VNET)
    case WT_PROBE_VNET_DATA_BAND:
        return (uintptr_t)WT_VNET_DATA_BASE;
#endif
    default:
        return (uintptr_t)WT_RAM_S_BASE;
    }
}
#endif
