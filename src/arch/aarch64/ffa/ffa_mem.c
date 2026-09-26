/* ffa_mem.c
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

/* FF-A Memory Management (DEN0140) transaction descriptor encode/decode and
 * the relayer validation a 1.2 SPMC runs before it acts on a lend, donate, or
 * share. Little-endian, byte-packed, over caller-provided buffers. */

#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_notif.h"

static uint32_t rd_u16(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t rd_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t* p)
{
    return (uint64_t)rd_u32(p) | ((uint64_t)rd_u32(&p[4]) << 32);
}

static void wr_u16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void wr_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void wr_u64(uint8_t* p, uint64_t v)
{
    wr_u32(p, (uint32_t)(v & 0xFFFFFFFFu));
    wr_u32(&p[4], (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

/* Both endpoint access descriptor layouts end in eight reserved (SBZ)
 * bytes. */
static int access_size_ok(uint32_t size)
{
    return (size == WT_FFA_MEM_ACCESS_SIZE) ||
           (size == WT_FFA_MEM_ACCESS_SIZE_V12);
}

static int layout_v10(uint32_t version)
{
    return (version != 0u) && (version < WT_FFA_VERSION_MAKE(1u, 1u));
}

/* The endpoint memory access descriptor of the reader's version (DEN0077A
 * 18.5.3): 16 bytes through FF-A 1.1, the 32-byte Table 1.16 from 1.2. */
static uint32_t access_size_for(uint32_t version)
{
    return ((version != 0u) && (version < WT_FFA_VERSION_1_2))
               ? WT_FFA_MEM_ACCESS_SIZE : WT_FFA_MEM_ACCESS_SIZE_V12;
}

/* Where a descriptor laid out for version keeps its access descriptors: Table
 * 1.20 names their size and offset and reserves [36, 48) (SBZ, ignored), the
 * v1.0 layout (Table 4.17) fixes them and reserves byte 3 and [24, 28) (MBZ).
 * 0, or INVALID_PARAMETERS for a short header or an MBZ byte set. */
static int txn_header(const uint8_t* buf, size_t len, uint32_t version,
                      uint32_t* acc_size, uint32_t* acc_off, uint32_t* hdr)
{
    if (layout_v10(version) != 0) {
        if ((len < WT_FFA_MEM_TXN_HDR_SIZE_V10) ||
            (buf[WT_FFA_MEM_TXN_OFF_ATTRS + 1u] != 0u) ||
            (rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_SIZE]) != 0u)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        *acc_size = WT_FFA_MEM_ACCESS_SIZE;
        *acc_off = WT_FFA_MEM_TXN_HDR_SIZE_V10;
        *hdr = WT_FFA_MEM_TXN_HDR_SIZE_V10;
        return 0;
    }
    if (len < WT_FFA_MEM_TXN_HDR_SIZE) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *acc_size = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_SIZE]);
    *acc_off = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET]);
    *hdr = WT_FFA_MEM_TXN_HDR_SIZE;
    return 0;
}

int wt_ffa_mem_attributes_check(uint16_t attributes)
{
    uint32_t type = (uint32_t)attributes & WT_FFA_MEM_ATTR_TYPE_MASK;
    uint32_t cache = (uint32_t)attributes & WT_FFA_MEM_ATTR_CACHE_MASK;
    uint32_t share = (uint32_t)attributes & WT_FFA_MEM_ATTR_SHARE_MASK;
    int ret = 0;

    if (type == WT_FFA_MEM_ATTR_TYPE_NORMAL) {
        if (((cache != WT_FFA_MEM_ATTR_CACHE_NC) &&
             (cache != WT_FFA_MEM_ATTR_CACHE_WB)) ||
            (share == WT_FFA_MEM_ATTR_SHARE_RSVD)) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
    }
    else if (type == WT_FFA_MEM_ATTR_TYPE_DEVICE) {
        if (share != 0u) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
    }
    else if ((type == WT_FFA_MEM_ATTR_TYPE_MASK) || (cache != 0u) ||
             (share != 0u)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    return ret;
}

/* Normal memory shareability in DEN0140 1.10.4 precedence order. */
static uint32_t share_rank(uint16_t attributes)
{
    uint32_t share = (uint32_t)attributes & WT_FFA_MEM_ATTR_SHARE_MASK;
    uint32_t rank = 0u;

    if (share == WT_FFA_MEM_ATTR_SHARE_INNER) {
        rank = 1u;
    }
    else if (share == WT_FFA_MEM_ATTR_SHARE_OUTER) {
        rank = 2u;
    }
    return rank;
}

/* Non-zero when valid, specified attributes asked are the same as or less
 * permissive than the Normal memory attributes limit, each attribute on its
 * own (1.10.4: Device < Normal, Non-cacheable < Write-Back, Non-shareable <
 * Inner Shareable < Outer Shareable). */
static int attributes_within(uint16_t asked, uint16_t limit)
{
    uint32_t type = (uint32_t)asked & WT_FFA_MEM_ATTR_TYPE_MASK;
    int within = 0;

    if (((uint32_t)limit & WT_FFA_MEM_ATTR_TYPE_MASK) ==
        WT_FFA_MEM_ATTR_TYPE_NORMAL) {
        if (type == WT_FFA_MEM_ATTR_TYPE_DEVICE) {
            within = 1;
        }
        else if (type == WT_FFA_MEM_ATTR_TYPE_NORMAL) {
            within = (((uint32_t)asked & WT_FFA_MEM_ATTR_CACHE_MASK) <=
                      ((uint32_t)limit & WT_FFA_MEM_ATTR_CACHE_MASK)) &&
                     (share_rank(asked) <= share_rank(limit));
        }
    }
    return within;
}

int wt_ffa_mem_send_attributes(uint16_t attributes, uint16_t* out)
{
    int ret = 0;

    if ((out == NULL) ||
        ((attributes & (WT_FFA_MEM_ATTR_RSVD_MASK | WT_FFA_MEM_ATTR_NS)) != 0u) ||
        (wt_ffa_mem_attributes_check(attributes) != 0)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    else if ((attributes & WT_FFA_MEM_ATTR_TYPE_MASK) == 0u) {
        attributes = (uint16_t)WT_FFA_MEM_ATTR_RELAYER;
    }
    else if (attributes_within(attributes,
                               (uint16_t)WT_FFA_MEM_ATTR_RELAYER) == 0) {
        ret = WT_FFA_DENIED;
    }
    else if (attributes != (uint16_t)WT_FFA_MEM_ATTR_RELAYER) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        *out = attributes;
    }
    return ret;
}

int wt_ffa_mem_txn_build(uint8_t* buf, size_t len,
                         const wt_ffa_mem_build_t* in, size_t* out_len)
{
    uint64_t total;
    uint32_t comp_off;
    uint32_t cons_base;
    uint32_t sum = 0u;
    uint32_t acc_size;
    uint32_t hdr;
    uint32_t i;
    uint8_t* c;

    if ((buf == NULL) || (in == NULL) || (out_len == NULL) ||
        ((in->constituents == NULL) && (in->constituent_count != 0u))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    acc_size = (in->access_desc_size != 0u) ? (uint32_t)in->access_desc_size
                                            : access_size_for(in->version);
    if ((access_size_ok(acc_size) == 0) ||
        ((layout_v10(in->version) != 0) &&
         (acc_size != WT_FFA_MEM_ACCESS_SIZE))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    hdr = (layout_v10(in->version) != 0) ? WT_FFA_MEM_TXN_HDR_SIZE_V10
                                         : WT_FFA_MEM_TXN_HDR_SIZE;

    /* With no constituents the receiver named the ranges itself: no
     * composite, and its offset is 0 (1.11.3.3). */
    comp_off = (in->constituent_count != 0u) ? (hdr + acc_size) : 0u;
    cons_base = hdr + acc_size + WT_FFA_MEM_COMPOSITE_HDR_SIZE;
    total = (in->constituent_count != 0u)
                ? ((uint64_t)cons_base +
                   (uint64_t)in->constituent_count * WT_FFA_MEM_CONSTITUENT_SIZE)
                : ((uint64_t)hdr + acc_size);
    if (total > (uint64_t)len) {
        return WT_FFA_NO_MEMORY;
    }

    for (i = 0u; i < (uint32_t)total; i++) {
        buf[i] = 0u;
    }

    wr_u16(&buf[WT_FFA_MEM_TXN_OFF_SENDER], in->sender);
    wr_u16(&buf[WT_FFA_MEM_TXN_OFF_ATTRS], in->attributes);
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_FLAGS], in->flags);
    wr_u64(&buf[WT_FFA_MEM_TXN_OFF_HANDLE], in->handle);
    wr_u64(&buf[WT_FFA_MEM_TXN_OFF_TAG], in->tag);
    if (layout_v10(in->version) == 0) {
        wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_SIZE], acc_size);
        wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET], hdr);
    }
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 1u);

    wr_u16(&buf[hdr + WT_FFA_MEM_ACC_OFF_RECEIVER], in->receiver);
    buf[hdr + WT_FFA_MEM_ACC_OFF_PERMS] = in->permissions;
    wr_u32(&buf[hdr + WT_FFA_MEM_ACC_OFF_COMP_OFF], comp_off);
    if ((in->impdef != NULL) && (acc_size == WT_FFA_MEM_ACCESS_SIZE_V12)) {
        for (i = 0u; i < WT_FFA_MEM_IMPDEF_SIZE; i++) {
            buf[hdr + WT_FFA_MEM_ACC_OFF_IMPDEF + i] = in->impdef[i];
        }
    }

    for (i = 0u; i < in->constituent_count; i++) {
        sum += in->constituents[i].page_count;
    }
    if (comp_off != 0u) {
        wr_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_PAGES], sum);
        wr_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_COUNT],
               in->constituent_count);
    }

    for (i = 0u; i < in->constituent_count; i++) {
        c = &buf[cons_base + i * WT_FFA_MEM_CONSTITUENT_SIZE];
        wr_u64(&c[WT_FFA_MEM_CONS_OFF_ADDR], in->constituents[i].address);
        wr_u32(&c[WT_FFA_MEM_CONS_OFF_PAGES], in->constituents[i].page_count);
    }

    *out_len = (size_t)total;
    return 0;
}

/* The count constituents at cons_base, already inside the buffer: each
 * page-aligned and non-empty, none overlapping another, summing to total
 * (1.11.3.1). 0 or INVALID_PARAMETERS. */
static int constituents_valid(const uint8_t* buf, uint64_t cons_base,
                              uint32_t count, uint32_t total)
{
    uint32_t sum_pages = 0u;
    uint32_t i;
    uint32_t j;

    for (i = 0u; i < count; i++) {
        const uint8_t* c = &buf[cons_base + (uint64_t)i * WT_FFA_MEM_CONSTITUENT_SIZE];
        uint64_t addr = rd_u64(&c[WT_FFA_MEM_CONS_OFF_ADDR]);
        uint32_t pages = rd_u32(&c[WT_FFA_MEM_CONS_OFF_PAGES]);
        uint64_t span;
        uint64_t a_end;

        if ((addr & (WT_FFA_MEM_PAGE_SIZE - 1u)) != 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if (pages < 1u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        span = (uint64_t)pages * WT_FFA_MEM_PAGE_SIZE;
        a_end = addr + span;
        if (a_end < addr) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        for (j = 0u; j < i; j++) {
            const uint8_t* p = &buf[cons_base + (uint64_t)j * WT_FFA_MEM_CONSTITUENT_SIZE];
            uint64_t paddr = rd_u64(&p[WT_FFA_MEM_CONS_OFF_ADDR]);
            uint64_t pend = paddr +
                            (uint64_t)rd_u32(&p[WT_FFA_MEM_CONS_OFF_PAGES]) *
                            WT_FFA_MEM_PAGE_SIZE;

            if ((addr < pend) && (paddr < a_end)) {
                return WT_FFA_INVALID_PARAMETERS;
            }
        }
        if (pages > (0xFFFFFFFFu - sum_pages)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        sum_pages += pages;
    }
    return (sum_pages == total) ? 0 : WT_FFA_INVALID_PARAMETERS;
}

int wt_ffa_mem_txn_validate(const uint8_t* buf, size_t len, wt_ffa_mem_op_t op,
                            uint16_t expect_sender, wt_ffa_mem_txn_t* out)
{
    return wt_ffa_mem_txn_validate_at(buf, len, op, expect_sender,
                                      WT_FFA_VERSION_1_2, out);
}

int wt_ffa_mem_txn_validate_at(const uint8_t* buf, size_t len,
                               wt_ffa_mem_op_t op, uint16_t expect_sender,
                               uint32_t version, wt_ffa_mem_txn_t* out)
{
    wt_ffa_mem_txn_t txn;
    uint64_t acc_end;
    uint64_t cons_base;
    uint64_t cons_end;
    uint32_t comp_off = 0u;
    uint32_t hdr = 0u;
    unsigned int r;

    if ((buf == NULL) || (out == NULL) ||
        (txn_header(buf, len, version, &txn.access_desc_size,
                    &txn.access_offset, &hdr) != 0)) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    txn.sender = (uint16_t)rd_u16(&buf[WT_FFA_MEM_TXN_OFF_SENDER]);
    /* Table 1.18 bits[15:7] are SBZ. */
    txn.attributes = (uint16_t)(rd_u16(&buf[WT_FFA_MEM_TXN_OFF_ATTRS]) &
                                ~WT_FFA_MEM_ATTR_RSVD_MASK);
    txn.flags = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_FLAGS]);
    txn.handle = rd_u64(&buf[WT_FFA_MEM_TXN_OFF_HANDLE]);
    txn.tag = rd_u64(&buf[WT_FFA_MEM_TXN_OFF_TAG]);
    txn.receiver_count = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT]);

    if (txn.sender != expect_sender) {
        return WT_FFA_DENIED;
    }
    if (access_size_ok(txn.access_desc_size) == 0) {
        return WT_FFA_NOT_SUPPORTED;
    }
    if (txn.receiver_count < 1u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((op == WT_FFA_MEM_OP_DONATE) && (txn.receiver_count != 1u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (wt_ffa_mem_attributes_check(txn.attributes) != 0) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* The security state is the relayer's to report in a retrieve response; a
     * sender leaves the NS bit clear (Table 5.18 usage). */
    if ((txn.attributes & WT_FFA_MEM_ATTR_NS) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Table 1.21: bit[1] asks for time slicing, which this relayer does not
     * do (MBZ); bits[31:2] are SBZ and ignored. */
    if ((txn.flags & WT_FFA_MEM_FLAG_TIME_SLICE) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    txn.flags &= WT_FFA_MEM_FLAG_ZERO;
    if ((op == WT_FFA_MEM_OP_SHARE) &&
        ((txn.flags & WT_FFA_MEM_FLAG_ZERO) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    if ((txn.access_offset < hdr) ||
        ((txn.access_offset % WT_FFA_MEM_ACC_OFFSET_ALIGN) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    acc_end = (uint64_t)txn.access_offset +
              (uint64_t)txn.receiver_count * txn.access_desc_size;
    if (acc_end > (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    for (r = 0u; r < txn.receiver_count; r++) {
        const uint8_t* acc = &buf[txn.access_offset + r * txn.access_desc_size];
        uint8_t perms = acc[WT_FFA_MEM_ACC_OFF_PERMS];
        uint32_t off = rd_u32(&acc[WT_FFA_MEM_ACC_OFF_COMP_OFF]);

        /* Its flags are MBZ in a send (1.10.1); its reserved tail and the
         * permission bits[7:4] are SBZ (Tables 1.15 and 1.16). */
        if (acc[WT_FFA_MEM_ACC_OFF_FLAGS] != 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if ((perms & WT_FFA_MEM_PERM_DATA_MASK) == WT_FFA_MEM_PERM_DATA_RSVD) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if ((perms & WT_FFA_MEM_PERM_INSTR_MASK) == WT_FFA_MEM_PERM_INSTR_MASK) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if (off == 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if (r == 0u) {
            comp_off = off;
        }
        else if (off != comp_off) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }

    /* The composite's bytes [8, 16) and each constituent's [12, 16) are SBZ
     * (Tables 1.13 and 1.14). */
    if ((comp_off < acc_end) ||
        (((uint64_t)comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE) > (uint64_t)len)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    txn.total_page_count = rd_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_PAGES]);
    txn.constituent_count = rd_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_COUNT]);
    if (txn.constituent_count < 1u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    cons_base = (uint64_t)comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE;
    cons_end = cons_base +
               (uint64_t)txn.constituent_count * WT_FFA_MEM_CONSTITUENT_SIZE;
    /* The length a sender states is the descriptor's, to the byte. */
    if (cons_end != (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Bounds the pairwise overlap scan below by what a handle can hold. */
    if (txn.constituent_count > WT_FFA_MEM_MAX_REGIONS) {
        return WT_FFA_NO_MEMORY;
    }

    if (constituents_valid(buf, cons_base, txn.constituent_count,
                           txn.total_page_count) != 0) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    txn.composite_offset = comp_off;
    *out = txn;
    return 0;
}

int wt_ffa_mem_send_validate(const uint8_t* buf, size_t len, wt_ffa_mem_op_t op,
                             uint16_t expect_sender, wt_ffa_mem_txn_t* out)
{
    return wt_ffa_mem_send_validate_at(buf, len, op, expect_sender,
                                       WT_FFA_VERSION_1_2, out);
}

int wt_ffa_mem_send_validate_at(const uint8_t* buf, size_t len,
                                wt_ffa_mem_op_t op, uint16_t expect_sender,
                                uint32_t version, wt_ffa_mem_txn_t* out)
{
    int ret = wt_ffa_mem_txn_validate_at(buf, len, op, expect_sender, version,
                                         out);

    if ((ret == 0) && (out->handle != 0u)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    return ret;
}

int wt_ffa_mem_receiver(const uint8_t* buf, size_t len,
                        const wt_ffa_mem_txn_t* txn, uint32_t index,
                        uint16_t* out_id, uint8_t* out_perms)
{
    const uint8_t* acc;

    if ((buf == NULL) || (txn == NULL) || (out_id == NULL) ||
        (out_perms == NULL) || (index >= txn->receiver_count)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (((uint64_t)txn->access_offset +
         (uint64_t)(index + 1u) * txn->access_desc_size) > (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    acc = &buf[txn->access_offset + index * txn->access_desc_size];
    *out_id = (uint16_t)rd_u16(&acc[WT_FFA_MEM_ACC_OFF_RECEIVER]);
    *out_perms = (uint8_t)(acc[WT_FFA_MEM_ACC_OFF_PERMS] &
                           ~WT_FFA_MEM_PERM_RSVD_MASK);
    return 0;
}

int wt_ffa_mem_receiver_impdef(const uint8_t* buf, size_t len,
                               const wt_ffa_mem_txn_t* txn, uint32_t index,
                               uint8_t* out16)
{
    const uint8_t* acc;
    uint32_t i;

    if ((buf == NULL) || (txn == NULL) || (out16 == NULL) ||
        (index >= txn->receiver_count) ||
        (((uint64_t)txn->access_offset +
          (uint64_t)(index + 1u) * txn->access_desc_size) > (uint64_t)len)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    acc = &buf[txn->access_offset + index * txn->access_desc_size];
    for (i = 0u; i < WT_FFA_MEM_IMPDEF_SIZE; i++) {
        out16[i] = (txn->access_desc_size == WT_FFA_MEM_ACCESS_SIZE_V12)
                       ? acc[WT_FFA_MEM_ACC_OFF_IMPDEF + i] : 0u;
    }
    return 0;
}

int wt_ffa_mem_constituent(const uint8_t* buf, size_t len,
                           const wt_ffa_mem_txn_t* txn, uint32_t index,
                           wt_ffa_mem_constituent_t* out)
{
    const uint8_t* c;
    uint64_t base;

    if ((buf == NULL) || (txn == NULL) || (out == NULL) ||
        (index >= txn->constituent_count)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    base = (uint64_t)txn->composite_offset + WT_FFA_MEM_COMPOSITE_HDR_SIZE +
           (uint64_t)index * WT_FFA_MEM_CONSTITUENT_SIZE;
    if ((base + WT_FFA_MEM_CONSTITUENT_SIZE) > (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    c = &buf[base];
    out->address = rd_u64(&c[WT_FFA_MEM_CONS_OFF_ADDR]);
    out->page_count = rd_u32(&c[WT_FFA_MEM_CONS_OFF_PAGES]);
    return 0;
}

int wt_ffa_mem_regions_from_txn(const uint8_t* buf, size_t len,
                                const wt_ffa_mem_txn_t* txn,
                                uint32_t receiver_index,
                                wt_ffa_mem_region_t* out, uint32_t max,
                                uint32_t* out_n)
{
    wt_ffa_mem_constituent_t c;
    uint16_t rid;
    uint8_t perms;
    uint8_t ns;
    uint32_t i;
    int ret;

    if ((out == NULL) || (out_n == NULL) || (txn == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (txn->constituent_count > max) {
        return WT_FFA_NO_MEMORY;
    }
    ret = wt_ffa_mem_receiver(buf, len, txn, receiver_index, &rid, &perms);
    if (ret != 0) {
        return ret;
    }
    (void)rid;
    ns = ((txn->attributes & WT_FFA_MEM_ATTR_NS) != 0u) ? 1u : 0u;
    for (i = 0u; i < txn->constituent_count; i++) {
        ret = wt_ffa_mem_constituent(buf, len, txn, i, &c);
        if (ret != 0) {
            return ret;
        }
        out[i].base = c.address;
        out[i].page_count = c.page_count;
        out[i].permissions = perms;
        out[i].ns = ns;
    }
    *out_n = txn->constituent_count;
    return 0;
}

int wt_ffa_mem_retrieve_req_build(uint8_t* buf, size_t len, uint64_t handle,
                                  uint16_t sender, uint16_t receiver,
                                  uint8_t permissions, size_t* out_len)
{
    return wt_ffa_mem_retrieve_req_build_at(buf, len, handle, sender, receiver,
                                            permissions,
                                            WT_FFA_VERSION_MAKE(1u, 1u),
                                            out_len);
}

int wt_ffa_mem_retrieve_req_build_at(uint8_t* buf, size_t len, uint64_t handle,
                                     uint16_t sender, uint16_t receiver,
                                     uint8_t permissions, uint32_t version,
                                     size_t* out_len)
{
    const uint32_t acc_size = access_size_for(version);
    const uint32_t hdr = (layout_v10(version) != 0)
                             ? WT_FFA_MEM_TXN_HDR_SIZE_V10
                             : WT_FFA_MEM_TXN_HDR_SIZE;
    const uint32_t total = hdr + acc_size;
    uint32_t i;

    if ((buf == NULL) || (out_len == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((uint64_t)total > (uint64_t)len) {
        return WT_FFA_NO_MEMORY;
    }
    for (i = 0u; i < total; i++) {
        buf[i] = 0u;
    }
    wr_u16(&buf[WT_FFA_MEM_TXN_OFF_SENDER], sender);
    wr_u64(&buf[WT_FFA_MEM_TXN_OFF_HANDLE], handle);
    /* Table 4.17 fixes the v1.0 access array at 32 and reserves [24, 28). */
    if (layout_v10(version) == 0) {
        wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_SIZE], acc_size);
        wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET], hdr);
    }
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 1u);
    wr_u16(&buf[hdr + WT_FFA_MEM_ACC_OFF_RECEIVER], receiver);
    buf[hdr + WT_FFA_MEM_ACC_OFF_PERMS] = permissions;
    *out_len = (size_t)total;
    return 0;
}

int wt_ffa_mem_retrieve_req_parse_ex(const uint8_t* buf, size_t len,
                                     wt_ffa_mem_retrieve_req_t* out)
{
    return wt_ffa_mem_retrieve_req_parse_at(buf, len, WT_FFA_VERSION_1_2, out);
}

/* The composite at comp that a retrieve request names for the receiver's
 * own ranges: past the access array, validated as a sender's (1.11.3.2), and
 * ending at *end. */
static int retrieve_ranges(const uint8_t* buf, size_t len, uint32_t comp,
                           uint64_t acc_end, wt_ffa_mem_retrieve_req_t* out,
                           uint64_t* end)
{
    uint64_t cons_base = (uint64_t)comp + WT_FFA_MEM_COMPOSITE_HDR_SIZE;
    const uint8_t* c;
    uint32_t total;
    uint32_t n;
    uint32_t i;

    if (((uint64_t)comp < acc_end) || (cons_base > (uint64_t)len)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    total = rd_u32(&buf[comp + WT_FFA_MEM_COMP_OFF_PAGES]);
    n = rd_u32(&buf[comp + WT_FFA_MEM_COMP_OFF_COUNT]);
    *end = cons_base + ((uint64_t)n * WT_FFA_MEM_CONSTITUENT_SIZE);
    if ((n < 1u) || (*end > (uint64_t)len)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (n > WT_FFA_MEM_MAX_REGIONS) {
        return WT_FFA_NO_MEMORY;
    }
    if (constituents_valid(buf, cons_base, n, total) != 0) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < n; i++) {
        c = &buf[cons_base + ((uint64_t)i * WT_FFA_MEM_CONSTITUENT_SIZE)];
        out->ranges[i].address = rd_u64(&c[WT_FFA_MEM_CONS_OFF_ADDR]);
        out->ranges[i].page_count = rd_u32(&c[WT_FFA_MEM_CONS_OFF_PAGES]);
    }
    out->range_count = n;
    return 0;
}

int wt_ffa_mem_retrieve_req_parse_at(const uint8_t* buf, size_t len,
                                     uint32_t version,
                                     wt_ffa_mem_retrieve_req_t* out)
{
    const uint8_t* acc;
    uint64_t end;
    uint32_t acc_size = 0u;
    uint32_t count;
    uint32_t comp;
    uint32_t off = 0u;
    uint32_t hdr = 0u;
    uint32_t i;
    uint32_t j;
    int ret;

    if ((buf == NULL) || (out == NULL) ||
        (txn_header(buf, len, version, &acc_size, &off, &hdr) != 0)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    count = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT]);
    if (access_size_ok(acc_size) == 0) {
        return WT_FFA_NOT_SUPPORTED;
    }
    if (count < 1u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (count > WT_FFA_MEM_MAX_BORROWERS) {
        return WT_FFA_NOT_SUPPORTED;
    }
    end = (uint64_t)off + ((uint64_t)count * acc_size);
    if ((off < hdr) || ((off % WT_FFA_MEM_ACC_OFFSET_ALIGN) != 0u) ||
        (end > (uint64_t)len)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    out->range_count = 0u;
    out->range_index = 0u;
    for (i = 0u; i < count; i++) {
        acc = &buf[off + (i * acc_size)];
        comp = rd_u32(&acc[WT_FFA_MEM_ACC_OFF_COMP_OFF]);
        /* One receiver may name the ranges it maps the memory at; every
         * other entry leaves them to the relayer (1.11.3.2). */
        if ((comp != 0u) && (out->range_count != 0u)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
        if (comp != 0u) {
            ret = retrieve_ranges(buf, len, comp,
                                  (uint64_t)off + ((uint64_t)count * acc_size),
                                  out, &end);
            if (ret != 0) {
                return ret;
            }
            out->range_index = i;
        }
        out->receivers[i] = (uint16_t)rd_u16(&acc[WT_FFA_MEM_ACC_OFF_RECEIVER]);
        /* Permission bits[7:4] and the reserved tail are SBZ. */
        out->permissions[i] = (uint8_t)(acc[WT_FFA_MEM_ACC_OFF_PERMS] &
                                        ~WT_FFA_MEM_PERM_RSVD_MASK);
        /* Bits[7:1] are SBZ: ignored at the higher EL (DEN0077A 7.2.2.3.2). */
        out->access_flags[i] = acc[WT_FFA_MEM_ACC_OFF_FLAGS];
        for (j = 0u; j < WT_FFA_MEM_IMPDEF_SIZE; j++) {
            out->impdef[i][j] = (acc_size == WT_FFA_MEM_ACCESS_SIZE_V12)
                                    ? acc[WT_FFA_MEM_ACC_OFF_IMPDEF + j] : 0u;
        }
    }
    if (end != (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    out->receiver_count = count;
    out->access_desc_size = acc_size;
    out->handle = rd_u64(&buf[WT_FFA_MEM_TXN_OFF_HANDLE]);
    out->tag = rd_u64(&buf[WT_FFA_MEM_TXN_OFF_TAG]);
    /* Table 1.22 bits[31:11] are SBZ. */
    out->flags = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_FLAGS]) &
                 WT_FFA_MEM_FLAG_RETRIEVE_MASK;
    out->sender = (uint16_t)rd_u16(&buf[WT_FFA_MEM_TXN_OFF_SENDER]);
    out->attributes = (uint16_t)(rd_u16(&buf[WT_FFA_MEM_TXN_OFF_ATTRS]) &
                                 ~WT_FFA_MEM_ATTR_RSVD_MASK);
    return 0;
}

int wt_ffa_mem_retrieve_req_parse(const uint8_t* buf, size_t len,
                                  uint64_t* out_handle, uint16_t* out_sender,
                                  uint16_t* out_receiver)
{
    wt_ffa_mem_retrieve_req_t req;
    int ret;

    if ((out_handle == NULL) || (out_sender == NULL) || (out_receiver == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_retrieve_req_parse_ex(buf, len, &req);
    if (ret != 0) {
        return ret;
    }
    if (req.receiver_count != 1u) {
        return WT_FFA_NOT_SUPPORTED;
    }
    *out_handle = req.handle;
    *out_sender = req.sender;
    *out_receiver = req.receivers[0];
    return 0;
}

int wt_ffa_mem_relinquish_build(uint8_t* buf, size_t len, uint64_t handle,
                                uint32_t flags, uint16_t endpoint,
                                size_t* out_len)
{
    const uint32_t total = WT_FFA_MEM_RELINQ_HDR_SIZE + 2u;
    uint32_t i;

    if ((buf == NULL) || (out_len == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((flags & ~WT_FFA_MEM_RELINQ_FLAG_MASK) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((uint64_t)total > (uint64_t)len) {
        return WT_FFA_NO_MEMORY;
    }
    for (i = 0u; i < total; i++) {
        buf[i] = 0u;
    }
    wr_u64(&buf[WT_FFA_MEM_RELINQ_OFF_HANDLE], handle);
    wr_u32(&buf[WT_FFA_MEM_RELINQ_OFF_FLAGS], flags);
    wr_u32(&buf[WT_FFA_MEM_RELINQ_OFF_COUNT], 1u);
    wr_u16(&buf[WT_FFA_MEM_RELINQ_OFF_ENDPOINTS], endpoint);
    *out_len = (size_t)total;
    return 0;
}

int wt_ffa_mem_relinquish_parse(const uint8_t* buf, size_t len,
                                uint64_t* out_handle, uint16_t* out_endpoint)
{
    uint32_t count;

    if ((buf == NULL) || (out_handle == NULL) || (out_endpoint == NULL) ||
        (len < WT_FFA_MEM_RELINQ_HDR_SIZE)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Table 2.25: bit[1] (time slicing) is MBZ here, bits[31:2] are SBZ. */
    if ((rd_u32(&buf[WT_FFA_MEM_RELINQ_OFF_FLAGS]) &
         WT_FFA_MEM_FLAG_TIME_SLICE) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    count = rd_u32(&buf[WT_FFA_MEM_RELINQ_OFF_COUNT]);
    if (count < 1u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (count != 1u) {
        return WT_FFA_NOT_SUPPORTED;
    }
    if (((uint64_t)WT_FFA_MEM_RELINQ_HDR_SIZE + 2u) > (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *out_handle = rd_u64(&buf[WT_FFA_MEM_RELINQ_OFF_HANDLE]);
    *out_endpoint = (uint16_t)rd_u16(&buf[WT_FFA_MEM_RELINQ_OFF_ENDPOINTS]);
    return 0;
}

int wt_ffa_mem_relinquish_parse_ex(const uint8_t* buf, size_t len,
                                   uint64_t* out_handle, uint16_t* out_endpoint,
                                   uint32_t* out_flags)
{
    int ret = wt_ffa_mem_relinquish_parse(buf, len, out_handle, out_endpoint);

    if ((ret == 0) && (out_flags != NULL)) {
        *out_flags = rd_u32(&buf[WT_FFA_MEM_RELINQ_OFF_FLAGS]) &
                     WT_FFA_MEM_RELINQ_FLAG_MASK;
    }
    return ret;
}

/* Table 2.31: bit[1] (time slicing) is MBZ here, bits[31:2] are SBZ. */
int wt_ffa_mem_reclaim_flags_check(uint32_t flags)
{
    return ((flags & WT_FFA_MEM_FLAG_TIME_SLICE) != 0u)
               ? WT_FFA_INVALID_PARAMETERS : 0;
}

int wt_ffa_rxtx_validate(uint64_t tx, uint64_t rx, uint32_t pages)
{
    uint64_t span;
    uint64_t tx_end;
    uint64_t rx_end;

    if ((pages < WT_FFA_RXTX_MIN_PAGES) || (pages > WT_FFA_RXTX_MAX_PAGES)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (((tx & (WT_FFA_MEM_PAGE_SIZE - 1u)) != 0u) ||
        ((rx & (WT_FFA_MEM_PAGE_SIZE - 1u)) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (tx == rx) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    span = (uint64_t)pages * WT_FFA_MEM_PAGE_SIZE;
    tx_end = tx + span;
    rx_end = rx + span;
    if ((tx_end < tx) || (rx_end < rx)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((tx < rx_end) && (rx < tx_end)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    return 0;
}

int wt_ffa_mailbox_map(wt_ffa_mailbox_t* mb, uint64_t tx, uint64_t rx,
                       uint32_t w3)
{
    uint32_t pages = WT_FFA_RXTX_PAGE_COUNT(w3);

    if (mb == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (mb->mapped != 0u) {
        return WT_FFA_DENIED;
    }
    if (wt_ffa_rxtx_validate(tx, rx, pages) != 0) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    mb->tx = tx;
    mb->rx = rx;
    mb->pages = pages;
    mb->mapped = 1u;
    mb->rx_full = 0u;
    return 0;
}

int wt_ffa_mailbox_unmap(wt_ffa_mailbox_t* mb)
{
    if ((mb == NULL) || (mb->mapped == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    mb->tx = 0u;
    mb->rx = 0u;
    mb->pages = 0u;
    mb->mapped = 0u;
    mb->rx_full = 0u;
    return 0;
}

int wt_ffa_mailbox_overlaps(const wt_ffa_mailbox_t* mb, uint64_t base,
                            uint64_t size)
{
    uint64_t span;

    if ((mb == NULL) || (mb->mapped == 0u) || (size == 0u)) {
        return 0;
    }
    span = (uint64_t)mb->pages * WT_FFA_MEM_PAGE_SIZE;
    return (((base < (mb->tx + span)) && (mb->tx < (base + size))) ||
            ((base < (mb->rx + span)) && (mb->rx < (base + size)))) ? 1 : 0;
}

int wt_ffa_mem_tx_buffer(const wt_ffa_mailbox_t* mb, uint64_t addr,
                         uint32_t pages, uint32_t len, uint64_t* out_tx)
{
    if ((out_tx == NULL) || (addr != 0u) || (pages != 0u) || (mb == NULL) ||
        (mb->mapped == 0u) ||
        ((uint64_t)len > ((uint64_t)mb->pages * WT_FFA_MEM_PAGE_SIZE))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *out_tx = mb->tx;
    return 0;
}

static int mailbox_rx_fill(wt_ffa_mailbox_t* mb, uint8_t state)
{
    if ((mb == NULL) || (mb->mapped == 0u)) {
        return WT_FFA_DENIED;
    }
    if (mb->rx_full != WT_FFA_RX_EMPTY) {
        return WT_FFA_BUSY;
    }
    mb->rx_full = state;
    return 0;
}

int wt_ffa_mailbox_rx_acquire(wt_ffa_mailbox_t* mb)
{
    return mailbox_rx_fill(mb, (uint8_t)WT_FFA_RX_OWNED);
}

int wt_ffa_mailbox_rx_post(wt_ffa_mailbox_t* mb)
{
    return mailbox_rx_fill(mb, (uint8_t)WT_FFA_RX_POSTED);
}

void wt_ffa_mailbox_rx_claim(wt_ffa_mailbox_t* mb, uint64_t framework)
{
    if ((mb != NULL) && (mb->rx_full == WT_FFA_RX_POSTED) &&
        ((framework & (WT_FFA_NOTIF_FW_SPM_RX_FULL |
                       WT_FFA_NOTIF_FW_NS_RX_FULL)) != 0u)) {
        mb->rx_full = (uint8_t)WT_FFA_RX_OWNED;
    }
}

/* Table 13.22: an endpoint without a registered pair owns no RX buffer, so
 * DENIED (the ACS ffa_rx_release test agrees); INVALID_PARAMETERS is for a
 * VM the Hypervisor names that has no pair. */
int wt_ffa_mailbox_rx_release(wt_ffa_mailbox_t* mb)
{
    if ((mb == NULL) || (mb->mapped == 0u) ||
        (mb->rx_full != WT_FFA_RX_OWNED)) {
        return WT_FFA_DENIED;
    }
    mb->rx_full = (uint8_t)WT_FFA_RX_EMPTY;
    return 0;
}

static uint8_t op_state(wt_ffa_mem_op_t op)
{
    uint8_t state;

    switch (op) {
        case WT_FFA_MEM_OP_SHARE:
            state = (uint8_t)WT_FFA_MEM_STATE_SHARED;
            break;
        case WT_FFA_MEM_OP_LEND:
            state = (uint8_t)WT_FFA_MEM_STATE_LENT;
            break;
        case WT_FFA_MEM_OP_DONATE:
            state = (uint8_t)WT_FFA_MEM_STATE_DONATED;
            break;
        default:
            state = (uint8_t)WT_FFA_MEM_STATE_FREE;
            break;
    }
    return state;
}

static wt_ffa_mem_handle_entry_t* find_handle(wt_ffa_mem_registry_t* reg,
                                              uint64_t handle)
{
    unsigned int i;

    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        if ((reg->entries[i].state != (uint8_t)WT_FFA_MEM_STATE_FREE) &&
            (reg->entries[i].handle == handle)) {
            return &reg->entries[i];
        }
    }
    return NULL;
}

void wt_ffa_mem_registry_init(wt_ffa_mem_registry_t* reg)
{
    unsigned int i;

    if (reg == NULL) {
        return;
    }
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        reg->entries[i].handle = WT_FFA_MEM_HANDLE_INVALID;
        reg->entries[i].owner = 0u;
        reg->entries[i].borrower = 0u;
        reg->entries[i].state = (uint8_t)WT_FFA_MEM_STATE_FREE;
        reg->entries[i].retrieved = 0u;
        reg->entries[i].region_count = 0u;
        reg->entries[i].borrower_count = 0u;
        reg->entries[i].attributes = 0u;
    }
    reg->next_handle = 1u;
}

uint64_t wt_ffa_mem_handle_reserve(wt_ffa_mem_registry_t* reg)
{
    uint64_t handle;

    if (reg == NULL) {
        return 0u;
    }
    handle = reg->next_handle & 0x7FFFFFFFFFFFFFFFull;
    reg->next_handle++;
    return handle;
}

int wt_ffa_mem_share_register_as(wt_ffa_mem_registry_t* reg,
                                 wt_ffa_mem_op_t op, uint16_t owner,
                                 uint16_t borrower,
                                 const wt_ffa_mem_region_t* regions,
                                 uint32_t n, uint64_t handle)
{
    unsigned int i;
    uint32_t r;

    if ((reg == NULL) || (handle == 0u) ||
        (op_state(op) == (uint8_t)WT_FFA_MEM_STATE_FREE)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((n > WT_FFA_MEM_MAX_REGIONS) || ((n > 0u) && (regions == NULL))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        if (reg->entries[i].state == (uint8_t)WT_FFA_MEM_STATE_FREE) {
            reg->entries[i].handle = handle;
            reg->entries[i].owner = owner;
            reg->entries[i].borrower = borrower;
            reg->entries[i].state = op_state(op);
            reg->entries[i].retrieved = 0u;
            reg->entries[i].tag = 0u;
            reg->entries[i].owner_cookie = 0u;
            reg->entries[i].attributes = 0u;
            reg->entries[i].borrower_count = 1u;
            reg->entries[i].borrowers[0].id = borrower;
            reg->entries[i].borrowers[0].permissions =
                (n > 0u) ? regions[0].permissions : 0u;
            reg->entries[i].borrowers[0].retrieved = 0u;
            reg->entries[i].borrowers[0].mapping = 0u;
            reg->entries[i].borrowers[0].ever_retrieved = 0u;
            for (r = 0u; r < WT_FFA_MEM_IMPDEF_SIZE; r++) {
                reg->entries[i].borrowers[0].impdef[r] = 0u;
            }
            reg->entries[i].region_count = (uint8_t)n;
            for (r = 0u; r < n; r++) {
                reg->entries[i].regions[r] = regions[r];
            }
            return 0;
        }
    }
    return WT_FFA_NO_MEMORY;
}

int wt_ffa_mem_share_register(wt_ffa_mem_registry_t* reg, wt_ffa_mem_op_t op,
                              uint16_t owner, uint16_t borrower,
                              const wt_ffa_mem_region_t* regions, uint32_t n,
                              uint64_t* out_handle)
{
    uint64_t handle;
    int ret;

    if ((reg == NULL) || (out_handle == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    handle = reg->next_handle & 0x7FFFFFFFFFFFFFFFull;
    ret = wt_ffa_mem_share_register_as(reg, op, owner, borrower, regions, n,
                                       handle);
    if (ret == 0) {
        reg->next_handle++;
        *out_handle = handle;
    }
    return ret;
}

static void copy_bytes(uint8_t* dst, const uint8_t* src, uint32_t len)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        dst[i] = src[i];
    }
}

int wt_ffa_mem_frag_expected(const uint8_t* frag, uint32_t frag_len,
                             int retrieve, uint64_t* size)
{
    return wt_ffa_mem_frag_expected_at(frag, frag_len, retrieve,
                                       WT_FFA_VERSION_1_2, size);
}

int wt_ffa_mem_frag_expected_at(const uint8_t* frag, uint32_t frag_len,
                                int retrieve, uint32_t version, uint64_t* size)
{
    uint32_t acc_size = WT_FFA_MEM_ACCESS_SIZE;
    uint32_t acc_count;
    uint32_t acc_off = WT_FFA_MEM_TXN_HDR_SIZE_V10;
    uint32_t hdr = (layout_v10(version) != 0) ? WT_FFA_MEM_TXN_HDR_SIZE_V10
                                              : WT_FFA_MEM_TXN_HDR_SIZE;
    uint32_t comp_off;
    uint32_t i;

    if ((frag == NULL) || (size == NULL) || (frag_len < hdr)) {
        return 0;
    }
    if (layout_v10(version) == 0) {
        acc_size = rd_u32(&frag[WT_FFA_MEM_TXN_OFF_ACC_SIZE]);
        acc_off = rd_u32(&frag[WT_FFA_MEM_TXN_OFF_ACC_OFFSET]);
    }
    acc_count = rd_u32(&frag[WT_FFA_MEM_TXN_OFF_ACC_COUNT]);
    if (retrieve != 0) {
        /* Only an access array the full parse accepts is walked: a zero
         * stride would never leave it. */
        if ((access_size_ok(acc_size) == 0) || (acc_off < hdr) ||
            ((acc_off % WT_FFA_MEM_ACC_OFFSET_ALIGN) != 0u)) {
            return 0;
        }
        *size = (uint64_t)acc_off + ((uint64_t)acc_count * acc_size);
        /* A receiver's own address ranges follow the access array, named by
         * any descriptor's offset, so each one must have arrived to tell. */
        for (i = 0u; i < acc_count; i++) {
            if (((uint64_t)acc_off + ((uint64_t)i * acc_size) +
                 WT_FFA_MEM_ACC_OFF_COMP_OFF + 4u) > (uint64_t)frag_len) {
                return 0;
            }
            comp_off = rd_u32(&frag[acc_off + (i * acc_size) +
                                    WT_FFA_MEM_ACC_OFF_COMP_OFF]);
            if (comp_off == 0u) {
                continue;
            }
            if (((uint64_t)comp_off + WT_FFA_MEM_COMP_OFF_COUNT + 4u) >
                (uint64_t)frag_len) {
                return 0;
            }
            *size = (uint64_t)comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                    ((uint64_t)rd_u32(&frag[comp_off + WT_FFA_MEM_COMP_OFF_COUNT]) *
                     WT_FFA_MEM_CONSTITUENT_SIZE);
            break;
        }
        return 1;
    }
    if (((uint64_t)acc_off + WT_FFA_MEM_ACC_OFF_COMP_OFF + 4u) >
        (uint64_t)frag_len) {
        return 0;
    }
    comp_off = rd_u32(&frag[acc_off + WT_FFA_MEM_ACC_OFF_COMP_OFF]);
    if (((uint64_t)comp_off + WT_FFA_MEM_COMP_OFF_COUNT + 4u) >
        (uint64_t)frag_len) {
        return 0;
    }
    *size = (uint64_t)comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE +
            ((uint64_t)rd_u32(&frag[comp_off + WT_FFA_MEM_COMP_OFF_COUNT]) *
             WT_FFA_MEM_CONSTITUENT_SIZE);
    return 1;
}

void wt_ffa_mem_frag_reset(wt_ffa_mem_frag_t* f)
{
    if (f != NULL) {
        f->active = 0u;
        f->handle = 0u;
        f->total = 0u;
        f->received = 0u;
        f->sender = 0u;
        f->op = 0u;
        f->aborted = 0u;
    }
}

int wt_ffa_mem_frag_begin(wt_ffa_mem_frag_t* f, uint64_t handle,
                          uint16_t sender, uint8_t op, const uint8_t* frag,
                          uint32_t frag_len, uint32_t total)
{
    if ((f == NULL) || (frag == NULL) || (frag_len == 0u) ||
        (frag_len >= total)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (total > WT_FFA_MEM_FRAG_MAX) {
        return WT_FFA_NO_MEMORY;
    }
    copy_bytes(f->buf, frag, frag_len);
    f->handle = handle;
    f->total = total;
    f->received = frag_len;
    f->sender = sender;
    f->op = op;
    f->active = 1u;
    f->aborted = 0u;
    return 0;
}

int wt_ffa_mem_frag_add(wt_ffa_mem_frag_t* f, uint64_t handle,
                        uint16_t sender, const uint8_t* frag,
                        uint32_t frag_len, int* done)
{
    if ((f == NULL) || (frag == NULL) || (done == NULL) || (f->active == 0u) ||
        (handle != f->handle) || (sender != f->sender) || (frag_len == 0u) ||
        (frag_len > (f->total - f->received))) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    copy_bytes(&f->buf[f->received], frag, frag_len);
    f->received += frag_len;
    *done = (f->received == f->total) ? 1 : 0;
    return 0;
}

int wt_ffa_mem_handle_alloc(wt_ffa_mem_registry_t* reg, wt_ffa_mem_op_t op,
                            uint16_t owner, uint16_t borrower,
                            uint64_t* out_handle)
{
    return wt_ffa_mem_share_register(reg, op, owner, borrower, NULL, 0u,
                                     out_handle);
}

int wt_ffa_mem_handle_regions(const wt_ffa_mem_registry_t* reg, uint64_t handle,
                              wt_ffa_mem_region_t* out, uint32_t max,
                              uint32_t* out_n)
{
    const wt_ffa_mem_handle_entry_t* e;
    uint32_t i;
    int ret;

    if ((out == NULL) || (out_n == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    ret = wt_ffa_mem_handle_lookup(reg, handle, &e);
    if (ret != 0) {
        return ret;
    }
    if ((uint32_t)e->region_count > max) {
        return WT_FFA_NO_MEMORY;
    }
    for (i = 0u; i < (uint32_t)e->region_count; i++) {
        out[i] = e->regions[i];
    }
    *out_n = (uint32_t)e->region_count;
    return 0;
}

int wt_ffa_mem_handle_lookup(const wt_ffa_mem_registry_t* reg, uint64_t handle,
                             const wt_ffa_mem_handle_entry_t** out)
{
    unsigned int i;

    if ((reg == NULL) || (out == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        if ((reg->entries[i].state != (uint8_t)WT_FFA_MEM_STATE_FREE) &&
            (reg->entries[i].handle == handle)) {
            *out = &reg->entries[i];
            return 0;
        }
    }
    return WT_FFA_INVALID_PARAMETERS;
}

void wt_ffa_mem_handle_set_meta(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                uint64_t tag, uint32_t owner_cookie)
{
    wt_ffa_mem_handle_entry_t* e = (reg != NULL) ? find_handle(reg, handle) : NULL;

    if (e != NULL) {
        e->tag = tag;
        e->owner_cookie = owner_cookie;
    }
}

void wt_ffa_mem_handle_set_attributes(wt_ffa_mem_registry_t* reg,
                                      uint64_t handle, uint16_t attributes)
{
    wt_ffa_mem_handle_entry_t* e = (reg != NULL) ? find_handle(reg, handle) : NULL;

    if (e != NULL) {
        e->attributes = attributes;
    }
}

wt_ffa_mem_borrower_t* wt_ffa_mem_handle_borrower(wt_ffa_mem_registry_t* reg,
                                                  uint64_t handle,
                                                  uint16_t borrower)
{
    wt_ffa_mem_handle_entry_t* e;
    uint32_t i;

    if (reg == NULL) {
        return NULL;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return NULL;
    }
    for (i = 0u; i < (uint32_t)e->borrower_count; i++) {
        if (e->borrowers[i].id == borrower) {
            return &e->borrowers[i];
        }
    }
    return NULL;
}

int wt_ffa_mem_handle_add_borrower(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                   uint16_t borrower, uint8_t permissions)
{
    wt_ffa_mem_handle_entry_t* e;
    uint32_t i;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if ((e == NULL) || (e->retrieved != 0u) || (e->owner == borrower) ||
        (wt_ffa_mem_handle_borrower(reg, handle, borrower) != NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((uint32_t)e->borrower_count >= WT_FFA_MEM_MAX_BORROWERS) {
        return WT_FFA_NO_MEMORY;
    }
    e->borrowers[e->borrower_count].id = borrower;
    e->borrowers[e->borrower_count].permissions = permissions;
    e->borrowers[e->borrower_count].retrieved = 0u;
    e->borrowers[e->borrower_count].mapping = 0u;
    e->borrowers[e->borrower_count].ever_retrieved = 0u;
    for (i = 0u; i < WT_FFA_MEM_IMPDEF_SIZE; i++) {
        e->borrowers[e->borrower_count].impdef[i] = 0u;
    }
    e->borrower_count++;
    return 0;
}

int wt_ffa_mem_registry_overlaps(const wt_ffa_mem_registry_t* reg,
                                 uint64_t base, uint32_t pages)
{
    const wt_ffa_mem_handle_entry_t* e;
    uint64_t end = base + ((uint64_t)pages * WT_FFA_MEM_PAGE_SIZE);
    uint64_t r_end;
    unsigned int i;
    uint32_t r;

    if (reg == NULL) {
        return 0;
    }
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        e = &reg->entries[i];
        if (e->state == (uint8_t)WT_FFA_MEM_STATE_FREE) {
            continue;
        }
        for (r = 0u; r < (uint32_t)e->region_count; r++) {
            r_end = e->regions[r].base +
                    ((uint64_t)e->regions[r].page_count * WT_FFA_MEM_PAGE_SIZE);
            if ((base < r_end) && (e->regions[r].base < end)) {
                return 1;
            }
        }
    }
    return 0;
}

int wt_ffa_mem_handle_retrieve(wt_ffa_mem_registry_t* reg, uint64_t handle,
                               uint16_t borrower)
{
    wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* b;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    b = wt_ffa_mem_handle_borrower(reg, handle, borrower);
    if (b == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (b->retrieved != 0u) {
        return WT_FFA_DENIED;
    }
    b->retrieved = 1u;
    b->ever_retrieved = 1u;
    e->retrieved++;
    return 0;
}

int wt_ffa_mem_handle_relinquish(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                 uint16_t borrower)
{
    wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_borrower_t* b;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    b = wt_ffa_mem_handle_borrower(reg, handle, borrower);
    if (b == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (b->retrieved == 0u) {
        return WT_FFA_DENIED;
    }
    b->retrieved = 0u;
    e->retrieved--;
    return 0;
}

int wt_ffa_mem_handle_free(wt_ffa_mem_registry_t* reg, uint64_t handle)
{
    wt_ffa_mem_handle_entry_t* e;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e->state = (uint8_t)WT_FFA_MEM_STATE_FREE;
    e->handle = WT_FFA_MEM_HANDLE_INVALID;
    return 0;
}

int wt_ffa_mem_handle_reclaim(wt_ffa_mem_registry_t* reg, uint64_t handle,
                              uint16_t owner)
{
    wt_ffa_mem_handle_entry_t* e;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (e->owner != owner) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (e->retrieved != 0u) {
        return WT_FFA_DENIED;
    }
    e->state = (uint8_t)WT_FFA_MEM_STATE_FREE;
    e->handle = WT_FFA_MEM_HANDLE_INVALID;
    return 0;
}

uint32_t wt_ffa_mem_type_flag(uint8_t state)
{
    uint32_t flag;

    switch (state) {
        case (uint8_t)WT_FFA_MEM_STATE_LENT:
            flag = WT_FFA_MEM_FLAG_TYPE_LEND;
            break;
        case (uint8_t)WT_FFA_MEM_STATE_DONATED:
            flag = WT_FFA_MEM_FLAG_TYPE_DONATE;
            break;
        default:
            flag = WT_FFA_MEM_FLAG_TYPE_SHARE;
            break;
    }
    return flag;
}

static const wt_ffa_mem_borrower_t* entry_borrower(
    const wt_ffa_mem_handle_entry_t* e, uint16_t id)
{
    uint32_t i;

    for (i = 0u; i < (uint32_t)e->borrower_count; i++) {
        if (e->borrowers[i].id == id) {
            return &e->borrowers[i];
        }
    }
    return NULL;
}

static int bytes_equal(const uint8_t* a, const uint8_t* b, uint32_t len)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

int wt_ffa_mem_retrieve_req_check(const wt_ffa_mem_handle_entry_t* e,
                                  const wt_ffa_mem_retrieve_req_t* rq,
                                  uint16_t receiver)
{
    const wt_ffa_mem_borrower_t* named;
    uint32_t type;
    uint32_t i;
    uint32_t j;
    int non_retrieval;
    int own;
    int repeated = 0;
    int ret = 0;

    if ((e == NULL) || (rq == NULL) ||
        (rq->receiver_count > WT_FFA_MEM_MAX_BORROWERS)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    /* FF-A 1.2: what the owner attached for a borrower is repeated by whoever
     * names that borrower in a retrieve request. */
    for (i = 0u; (ret == 0) && (i < rq->receiver_count); i++) {
        named = entry_borrower(e, rq->receivers[i]);
        if ((named == NULL) ||
            (bytes_equal(named->impdef, rq->impdef[i],
                         WT_FFA_MEM_IMPDEF_SIZE) == 0)) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
        /* Table 1.17 bit[0]: only the caller is retrieved for, so its own
         * entry has the flag clear and every other borrower's has it set. */
        own = (rq->receivers[i] == receiver) ? 1 : 0;
        non_retrieval = ((rq->access_flags[i] &
                          WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL) != 0u) ? 1 : 0;
        if (own == non_retrieval) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
        /* Another borrower exists only in a share or a lend to several, where
         * every instruction access is left unspecified (1.10.3 item 1). */
        if ((own == 0) &&
            (((rq->permissions[i] & WT_FFA_MEM_PERM_INSTR_MASK) !=
              WT_FFA_MEM_PERM_INSTR_NOT_SPEC) ||
             ((rq->permissions[i] & WT_FFA_MEM_PERM_DATA_MASK) ==
              WT_FFA_MEM_PERM_DATA_RSVD))) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
        for (j = 0u; j < i; j++) {
            if (rq->receivers[j] == rq->receivers[i]) {
                repeated = 1;
            }
        }
    }
    /* Every entry is a borrower, so the same count with no repeat is the
     * lender's whole list; the bypass flag's IMPLEMENTATION DEFINED action
     * (1.11.3.3) is that the receiver names itself alone. */
    if ((ret == 0) &&
        ((repeated != 0) ||
         (rq->receiver_count !=
          (((rq->flags & WT_FFA_MEM_FLAG_BYPASS_BORROWERS) != 0u)
               ? 1u : (uint32_t)e->borrower_count)))) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        type = rq->flags & WT_FFA_MEM_FLAG_TYPE_MASK;
        if ((rq->tag != e->tag) ||
            ((rq->flags & ~(WT_FFA_MEM_FLAG_SEND_MASK |
                            WT_FFA_MEM_FLAG_TYPE_MASK |
                            WT_FFA_MEM_FLAG_ZERO_AFTER |
                            WT_FFA_MEM_FLAG_BYPASS_BORROWERS)) != 0u) ||
            (((rq->flags & WT_FFA_MEM_FLAG_BYPASS_BORROWERS) != 0u) &&
             (e->borrower_count == 1u)) ||
            ((type != 0u) && (type != wt_ffa_mem_type_flag(e->state))) ||
            ((rq->attributes &
              (WT_FFA_MEM_ATTR_RSVD_MASK | WT_FFA_MEM_ATTR_NS)) != 0u)) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
    }
    /* Well formed, but not what was sent: only Normal memory is ever lent. */
    if ((ret == 0) && ((rq->attributes & WT_FFA_MEM_ATTR_TYPE_MASK) ==
                       WT_FFA_MEM_ATTR_TYPE_DEVICE)) {
        ret = WT_FFA_DENIED;
    }
    if (ret == 0) {
        ret = wt_ffa_mem_attributes_check(rq->attributes);
    }
    /* Attributes a borrower states are held against those its memory is
     * mapped with: more permissive ones fail validation (1.10.4.2 items 1 and
     * 2), less permissive ones the relayer cannot map (item 5). */
    if ((ret == 0) && ((rq->attributes & WT_FFA_MEM_ATTR_TYPE_MASK) != 0u)) {
        if (attributes_within(rq->attributes, e->attributes) == 0) {
            ret = WT_FFA_DENIED;
        }
        else if (rq->attributes != e->attributes) {
            ret = WT_FFA_INVALID_PARAMETERS;
        }
    }
    /* Every other borrower named must carry the data access the lender gave
     * it (1.10.2 item 1). */
    for (i = 0u; (ret == 0) && (i < rq->receiver_count); i++) {
        named = entry_borrower(e, rq->receivers[i]);
        if ((rq->receivers[i] != receiver) && (named != NULL) &&
            ((rq->permissions[i] & WT_FFA_MEM_PERM_DATA_MASK) !=
             (named->permissions & WT_FFA_MEM_PERM_DATA_MASK))) {
            ret = WT_FFA_DENIED;
        }
    }
    return ret;
}
