/* ffa_partinfo.c
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

/* FFA_PARTITION_INFO_GET descriptor encoding (DEN0077A 1.2 6.1). The SPMC
 * walks its configured partitions and writes one Table 6.1 descriptor per
 * match into the caller's RX buffer, little-endian and byte-packed. */

#include "wolftrust/arch/aarch64/ffa_partinfo.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_manifest.h"

uint32_t wt_ffa_partinfo_desc_size(uint32_t caller_version)
{
    uint32_t major = WT_FFA_VERSION_MAJOR_OF(caller_version);
    uint32_t minor = WT_FFA_VERSION_MINOR_OF(caller_version);

    /* FF-A 1.1 added the UUID to the descriptor (6.1). */
    if ((major > 1u) || ((major == 1u) && (minor >= 1u))) {
        return WT_FFA_PARTINFO_DESC_V11;
    }
    return WT_FFA_PARTINFO_DESC_V10;
}

uint32_t wt_ffa_partinfo_props(uint32_t messaging)
{
    uint32_t props = 0u;

    if (messaging == WT_FFA_MESSAGING_DIRECT) {
        props |= WT_FFA_PARTINFO_PROP_DIRECT_RECV |
                 WT_FFA_PARTINFO_PROP_DIRECT_SEND;
    }
    if (messaging == WT_FFA_MESSAGING_INDIRECT) {
        props |= WT_FFA_PARTINFO_PROP_INDIRECT;
    }
    return props;
}

static int uuid_is_nil(const uint8_t* u)
{
    unsigned int i;

    for (i = 0u; i < 16u; i++) {
        if (u[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int uuid_equal(const uint8_t* a, const uint8_t* b)
{
    unsigned int i;

    for (i = 0u; i < 16u; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static void write_desc(uint8_t* dst, uint32_t desc_size,
                       const wt_ffa_partinfo_entry_t* p)
{
    unsigned int i;

    for (i = 0u; i < desc_size; i++) {
        dst[i] = 0u;
    }
    dst[0] = (uint8_t)(p->id & 0xFFu);
    dst[1] = (uint8_t)((p->id >> 8) & 0xFFu);
    dst[2] = (uint8_t)(p->exec_contexts & 0xFFu);
    dst[3] = (uint8_t)((p->exec_contexts >> 8) & 0xFFu);
    dst[4] = (uint8_t)(p->properties & 0xFFu);
    dst[5] = (uint8_t)((p->properties >> 8) & 0xFFu);
    dst[6] = (uint8_t)((p->properties >> 16) & 0xFFu);
    dst[7] = (uint8_t)((p->properties >> 24) & 0xFFu);
    if (desc_size >= WT_FFA_PARTINFO_DESC_V11) {
        for (i = 0u; i < 16u; i++) {
            dst[8u + i] = p->uuid[i];
        }
    }
}

int wt_ffa_partinfo_write(uint8_t* rx, size_t rx_size, uint32_t caller_version,
                          const wt_ffa_partinfo_entry_t* parts, size_t n,
                          const uint8_t* uuid16, uint32_t flags,
                          uint32_t* out_count, uint32_t* out_desc_size)
{
    uint32_t desc_size = wt_ffa_partinfo_desc_size(caller_version);
    uint32_t count = 0u;
    size_t off = 0u;
    size_t i;
    int nil;
    int count_only;

    if ((flags & ~WT_FFA_PARTINFO_FLAG_COUNT) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    nil = uuid_is_nil(uuid16);
    count_only = (flags & WT_FFA_PARTINFO_FLAG_COUNT) != 0u;

    for (i = 0u; i < n; i++) {
        if ((nil == 0) && (uuid_equal(uuid16, parts[i].uuid) == 0)) {
            continue;
        }
        if (count_only == 0) {
            if ((rx == NULL) || ((off + desc_size) > rx_size)) {
                return WT_FFA_NO_MEMORY;
            }
            write_desc(&rx[off], desc_size, &parts[i]);
            off += desc_size;
        }
        count++;
    }
    *out_count = count;
    *out_desc_size = (count_only != 0) ? 0u : desc_size;
    return 0;
}

static uint64_t uuid_half(const uint8_t* u)
{
    uint64_t v = 0u;
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        v |= (uint64_t)u[i] << (8u * i);
    }
    return v;
}

int wt_ffa_partinfo_regs(const wt_ffa_partinfo_entry_t* parts, size_t n,
                         const uint8_t* uuid16, uint16_t start, uint16_t tag,
                         uint64_t* out18)
{
    uint32_t matches = 0u;
    uint32_t written = 0u;
    uint32_t last;
    uint32_t reg;
    size_t i;
    int nil;

    if ((parts == NULL) || (uuid16 == NULL) || (out18 == NULL) || (tag != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < 18u; i++) {
        out18[i] = 0u;
    }
    nil = uuid_is_nil(uuid16);
    for (i = 0u; i < n; i++) {
        if ((nil == 0) && (uuid_equal(uuid16, parts[i].uuid) == 0)) {
            continue;
        }
        if ((matches >= start) && (written < WT_FFA_PARTINFO_REGS_PER_CALL)) {
            reg = 3u + (3u * written);
            out18[reg] = (uint64_t)parts[i].id |
                         ((uint64_t)parts[i].exec_contexts << 16) |
                         ((uint64_t)parts[i].properties << 32);
            out18[reg + 1u] = uuid_half(&parts[i].uuid[0]);
            out18[reg + 2u] = uuid_half(&parts[i].uuid[8]);
            written++;
        }
        matches++;
    }
    if ((matches == 0u) || (written == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    last = matches - 1u;
    out18[0] = WT_FFA_SUCCESS64;
    out18[2] = (uint64_t)last |
               ((uint64_t)((uint32_t)start + written - 1u) << 16) |
               ((uint64_t)WT_FFA_PARTINFO_DESC_V11 << 48);
    return 0;
}
