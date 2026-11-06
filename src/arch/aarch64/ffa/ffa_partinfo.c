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
#include "wolftrust/arch/aarch64/ffa_mem.h"

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

int wt_ffa_partinfo_from_manifest(const wt_ffa_partition_manifest_t* part,
                                  uint16_t id, wt_ffa_partinfo_entry_t* out,
                                  size_t cap, size_t* out_n)
{
    uint32_t u;
    unsigned int j;

    if ((part == NULL) || (out_n == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *out_n = 0u;
    if (id == 0u) {
        return 0;
    }
    if ((part->uuids == NULL) || (part->uuid_count == 0u) ||
        (part->uuid_count > WT_FFA_MANIFEST_MAX_UUIDS)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((out == NULL) || (cap < part->uuid_count)) {
        return WT_FFA_NO_MEMORY;
    }
    for (u = 0u; u < part->uuid_count; u++) {
        out[u].id = id;
        out[u].exec_contexts = (uint16_t)part->execution_contexts;
        out[u].properties = WT_FFA_PARTINFO_PROP_AARCH64;
        for (j = 0u; j < 16u; j++) {
            out[u].uuid[j] = part->uuids[u].bytes[j];
        }
    }
    *out_n = part->uuid_count;
    return 0;
}

int wt_ffa_partinfo_props_of(const wt_ffa_partinfo_entry_t* parts, size_t n,
                             uint16_t id, uint32_t* props)
{
    size_t i;
    int ret = WT_FFA_INVALID_PARAMETERS;

    if (props == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *props = 0u;
    for (i = 0u; (parts != NULL) && (i < n); i++) {
        if (parts[i].id == id) {
            *props |= parts[i].properties;
            ret = 0;
        }
    }
    return ret;
}

int wt_ffa_direct_req_allowed(uint32_t props, uint32_t fid, int receive)
{
    uint32_t need;

    if (fid == WT_FFA_MSG_SEND_DIRECT_REQ2) {
        need = (receive != 0) ? WT_FFA_PARTINFO_PROP_REQ2_RECV
                              : WT_FFA_PARTINFO_PROP_REQ2_SEND;
    }
    else {
        need = (receive != 0) ? WT_FFA_PARTINFO_PROP_DIRECT_RECV
                              : WT_FFA_PARTINFO_PROP_DIRECT_SEND;
    }
    return ((props & need) != 0u) ? 0 : WT_FFA_DENIED;
}

int wt_ffa_direct_req_authorize(const wt_ffa_partinfo_entry_t* parts, size_t n,
                                uint16_t sender, uint16_t receiver,
                                uint32_t fid)
{
    uint32_t props = 0u;
    int ret;

    /* A sender discovery does not list advertises nothing, so sends nothing. */
    if (wt_ffa_partinfo_props_of(parts, n, sender, &props) != 0) {
        props = 0u;
    }
    ret = wt_ffa_direct_req_allowed(props, fid, 0);
    if (ret == 0) {
        ret = wt_ffa_partinfo_props_of(parts, n, receiver, &props);
    }
    if (ret == 0) {
        ret = wt_ffa_direct_req_allowed(props, fid, 1);
    }
    return ret;
}

int wt_ffa_msg2_sender_allowed(const wt_ffa_partinfo_entry_t* parts, size_t n,
                               uint16_t sender)
{
    uint32_t props = 0u;

    if ((sender & 0x8000u) == 0u) {
        return 0;
    }
    if (wt_ffa_partinfo_props_of(parts, n, sender, &props) != 0) {
        props = 0u;
    }
    return ((props & WT_FFA_PARTINFO_PROP_INDIRECT) != 0u) ? 0 : WT_FFA_DENIED;
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
                       const wt_ffa_partinfo_entry_t* p, int nil)
{
    uint32_t props = p->properties;
    unsigned int i;

    if (desc_size < WT_FFA_PARTINFO_DESC_V11) {
        props &= WT_FFA_PARTINFO_PROP_V10_MASK;
    }
    for (i = 0u; i < desc_size; i++) {
        dst[i] = 0u;
    }
    dst[0] = (uint8_t)(p->id & 0xFFu);
    dst[1] = (uint8_t)((p->id >> 8) & 0xFFu);
    dst[2] = (uint8_t)(p->exec_contexts & 0xFFu);
    dst[3] = (uint8_t)((p->exec_contexts >> 8) & 0xFFu);
    dst[4] = (uint8_t)(props & 0xFFu);
    dst[5] = (uint8_t)((props >> 8) & 0xFFu);
    dst[6] = (uint8_t)((props >> 16) & 0xFFu);
    dst[7] = (uint8_t)((props >> 24) & 0xFFu);
    if ((nil != 0) && (desc_size >= WT_FFA_PARTINFO_DESC_V11)) {
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
            write_desc(&rx[off], desc_size, &parts[i], nil);
            off += desc_size;
        }
        count++;
    }
    *out_count = count;
    *out_desc_size = (count_only != 0) ? 0u : desc_size;
    return 0;
}

int wt_ffa_partinfo_get(const uint64_t* x, uint32_t caller_version,
                        wt_ffa_mailbox_t* mb,
                        const wt_ffa_partinfo_entry_t* parts, size_t n,
                        uint32_t* count, uint32_t* size)
{
    uint8_t uuid[16];
    uint32_t word;
    uint32_t flags;
    unsigned int i;
    int ret;

    if ((x == NULL) || (parts == NULL) || (n == 0u) || (count == NULL) ||
        (size == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Table 13.34: flag bits 31:1 are SBZ. */
    flags = (uint32_t)x[5] & WT_FFA_PARTINFO_FLAG_COUNT;
    for (i = 0u; i < 4u; i++) {
        word = (uint32_t)x[1u + i];
        uuid[4u * i + 0u] = (uint8_t)(word & 0xFFu);
        uuid[4u * i + 1u] = (uint8_t)((word >> 8) & 0xFFu);
        uuid[4u * i + 2u] = (uint8_t)((word >> 16) & 0xFFu);
        uuid[4u * i + 3u] = (uint8_t)((word >> 24) & 0xFFu);
    }
    ret = wt_ffa_partinfo_write(NULL, 0u, caller_version, parts, n, uuid,
                                flags | WT_FFA_PARTINFO_FLAG_COUNT, count,
                                size);
    if ((ret == 0) && (*count == 0u)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if ((ret != 0) || ((flags & WT_FFA_PARTINFO_FLAG_COUNT) != 0u)) {
        return ret;
    }
    if (wt_ffa_mailbox_rx_acquire(mb) != 0) {
        return WT_FFA_BUSY;
    }
    ret = wt_ffa_partinfo_write((uint8_t*)(uintptr_t)mb->rx,
                                (size_t)mb->pages * WT_FFA_MEM_PAGE_SIZE,
                                caller_version, parts, n, uuid, flags,
                                count, size);
    if (ret != 0) {
        (void)wt_ffa_mailbox_rx_release(mb);
    }
    return ret;
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

    if ((parts == NULL) || (uuid16 == NULL) || (out18 == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* The callee's tag is always 0: MBZ at start 0, stale after it (13.9.2). */
    if (tag != 0u) {
        return (start == 0u) ? WT_FFA_INVALID_PARAMETERS : WT_FFA_RETRY;
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
            if (nil != 0) {
                out18[reg + 1u] = uuid_half(&parts[i].uuid[0]);
                out18[reg + 2u] = uuid_half(&parts[i].uuid[8]);
            }
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

int wt_ffa_partinfo_regs_call(const wt_ffa_partinfo_entry_t* parts, size_t n,
                              const uint64_t* x, uint64_t* out18)
{
    uint8_t uuid[16];
    unsigned int i;

    if ((x == NULL) || (n == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < 16u; i++) {
        uuid[i] = (uint8_t)(x[1u + (i / 8u)] >> (8u * (i % 8u)));
    }
    /* Table 13.39: x3 bits 63:32 are SBZ. */
    return wt_ffa_partinfo_regs(parts, n, uuid, (uint16_t)(x[3] & 0xFFFFu),
                                (uint16_t)((x[3] >> 16) & 0xFFFFu), out18);
}
