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

int wt_ffa_mem_txn_build(uint8_t* buf, size_t len,
                         const wt_ffa_mem_build_t* in, size_t* out_len)
{
    uint64_t total;
    uint32_t comp_off;
    uint32_t cons_base;
    uint32_t sum = 0u;
    uint32_t i;
    uint8_t* c;

    if ((buf == NULL) || (in == NULL) || (out_len == NULL) ||
        (in->constituents == NULL) || (in->constituent_count < 1u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    comp_off = WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE;
    cons_base = comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE;
    total = (uint64_t)cons_base +
            (uint64_t)in->constituent_count * WT_FFA_MEM_CONSTITUENT_SIZE;
    if (total > (uint64_t)len) {
        return WT_FFA_NO_MEMORY;
    }

    for (i = 0u; i < (uint32_t)total; i++) {
        buf[i] = 0u;
    }

    wr_u16(&buf[WT_FFA_MEM_TXN_OFF_SENDER], in->sender);
    wr_u16(&buf[WT_FFA_MEM_TXN_OFF_ATTRS], in->attributes);
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_FLAGS], in->flags);
    wr_u64(&buf[WT_FFA_MEM_TXN_OFF_TAG], in->tag);
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_SIZE], WT_FFA_MEM_ACCESS_SIZE);
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 1u);
    wr_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET], WT_FFA_MEM_TXN_HDR_SIZE);

    wr_u16(&buf[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_RECEIVER],
           in->receiver);
    buf[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_PERMS] = in->permissions;
    wr_u32(&buf[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_COMP_OFF], comp_off);

    for (i = 0u; i < in->constituent_count; i++) {
        sum += in->constituents[i].page_count;
    }
    wr_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_PAGES], sum);
    wr_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_COUNT], in->constituent_count);

    for (i = 0u; i < in->constituent_count; i++) {
        c = &buf[cons_base + i * WT_FFA_MEM_CONSTITUENT_SIZE];
        wr_u64(&c[WT_FFA_MEM_CONS_OFF_ADDR], in->constituents[i].address);
        wr_u32(&c[WT_FFA_MEM_CONS_OFF_PAGES], in->constituents[i].page_count);
    }

    *out_len = (size_t)total;
    return 0;
}

int wt_ffa_mem_txn_validate(const uint8_t* buf, size_t len, wt_ffa_mem_op_t op,
                            uint16_t expect_sender, wt_ffa_mem_txn_t* out)
{
    wt_ffa_mem_txn_t txn;
    uint64_t acc_end;
    uint64_t cons_base;
    uint64_t cons_end;
    uint32_t comp_off = 0u;
    uint32_t sum_pages = 0u;
    uint32_t i;
    uint32_t j;
    unsigned int r;

    if ((buf == NULL) || (out == NULL) || (len < WT_FFA_MEM_TXN_HDR_SIZE)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 36u; i < WT_FFA_MEM_TXN_HDR_SIZE; i++) {
        if (buf[i] != 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }

    txn.sender = (uint16_t)rd_u16(&buf[WT_FFA_MEM_TXN_OFF_SENDER]);
    txn.attributes = (uint16_t)rd_u16(&buf[WT_FFA_MEM_TXN_OFF_ATTRS]);
    txn.flags = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_FLAGS]);
    txn.handle = rd_u64(&buf[WT_FFA_MEM_TXN_OFF_HANDLE]);
    txn.tag = rd_u64(&buf[WT_FFA_MEM_TXN_OFF_TAG]);
    txn.access_desc_size = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_SIZE]);
    txn.receiver_count = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT]);
    txn.access_offset = rd_u32(&buf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET]);

    if (txn.sender != expect_sender) {
        return WT_FFA_DENIED;
    }
    if (txn.access_desc_size != WT_FFA_MEM_ACCESS_SIZE) {
        return WT_FFA_NOT_SUPPORTED;
    }
    if (txn.receiver_count < 1u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((op == WT_FFA_MEM_OP_DONATE) && (txn.receiver_count != 1u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((txn.attributes & WT_FFA_MEM_ATTR_RSVD_MASK) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((txn.attributes & WT_FFA_MEM_ATTR_TYPE_MASK) == WT_FFA_MEM_ATTR_TYPE_MASK) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((txn.flags & ~WT_FFA_MEM_FLAG_SEND_MASK) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((op == WT_FFA_MEM_OP_SHARE) &&
        ((txn.flags & WT_FFA_MEM_FLAG_ZERO) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    if (txn.access_offset < WT_FFA_MEM_TXN_HDR_SIZE) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    acc_end = (uint64_t)txn.access_offset +
              (uint64_t)txn.receiver_count * WT_FFA_MEM_ACCESS_SIZE;
    if (acc_end > (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    for (r = 0u; r < txn.receiver_count; r++) {
        const uint8_t* acc = &buf[txn.access_offset + r * WT_FFA_MEM_ACCESS_SIZE];
        uint8_t perms = acc[WT_FFA_MEM_ACC_OFF_PERMS];
        uint32_t off = rd_u32(&acc[WT_FFA_MEM_ACC_OFF_COMP_OFF]);
        unsigned int k;

        for (k = 8u; k < WT_FFA_MEM_ACCESS_SIZE; k++) {
            if (acc[k] != 0u) {
                return WT_FFA_INVALID_PARAMETERS;
            }
        }
        if ((perms & WT_FFA_MEM_PERM_RSVD_MASK) != 0u) {
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

    if ((comp_off < acc_end) ||
        (((uint64_t)comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE) > (uint64_t)len)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 8u; i < WT_FFA_MEM_COMPOSITE_HDR_SIZE; i++) {
        if (buf[comp_off + i] != 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }
    txn.total_page_count = rd_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_PAGES]);
    txn.constituent_count = rd_u32(&buf[comp_off + WT_FFA_MEM_COMP_OFF_COUNT]);
    if (txn.constituent_count < 1u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    cons_base = (uint64_t)comp_off + WT_FFA_MEM_COMPOSITE_HDR_SIZE;
    cons_end = cons_base +
               (uint64_t)txn.constituent_count * WT_FFA_MEM_CONSTITUENT_SIZE;
    if (cons_end > (uint64_t)len) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    for (i = 0u; i < txn.constituent_count; i++) {
        const uint8_t* c = &buf[cons_base + (uint64_t)i * WT_FFA_MEM_CONSTITUENT_SIZE];
        uint64_t addr = rd_u64(&c[WT_FFA_MEM_CONS_OFF_ADDR]);
        uint32_t pages = rd_u32(&c[WT_FFA_MEM_CONS_OFF_PAGES]);
        uint64_t span;
        uint64_t a_end;

        if (rd_u32(&c[12]) != 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
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
    if (sum_pages != txn.total_page_count) {
        return WT_FFA_INVALID_PARAMETERS;
    }

    txn.composite_offset = comp_off;
    *out = txn;
    return 0;
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
    *out_perms = acc[WT_FFA_MEM_ACC_OFF_PERMS];
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
    }
    reg->next_handle = 1u;
}

int wt_ffa_mem_handle_alloc(wt_ffa_mem_registry_t* reg, wt_ffa_mem_op_t op,
                            uint16_t owner, uint16_t borrower,
                            uint64_t* out_handle)
{
    unsigned int i;

    if ((reg == NULL) || (out_handle == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        if (reg->entries[i].state == (uint8_t)WT_FFA_MEM_STATE_FREE) {
            reg->entries[i].handle = reg->next_handle & 0x7FFFFFFFFFFFFFFFull;
            reg->entries[i].owner = owner;
            reg->entries[i].borrower = borrower;
            reg->entries[i].state = op_state(op);
            reg->entries[i].retrieved = 0u;
            reg->next_handle++;
            *out_handle = reg->entries[i].handle;
            return 0;
        }
    }
    return WT_FFA_NO_MEMORY;
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

int wt_ffa_mem_handle_retrieve(wt_ffa_mem_registry_t* reg, uint64_t handle,
                               uint16_t borrower)
{
    wt_ffa_mem_handle_entry_t* e;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (e->borrower != borrower) {
        return WT_FFA_DENIED;
    }
    if (e->retrieved != 0u) {
        return WT_FFA_DENIED;
    }
    e->retrieved = 1u;
    return 0;
}

int wt_ffa_mem_handle_relinquish(wt_ffa_mem_registry_t* reg, uint64_t handle,
                                 uint16_t borrower)
{
    wt_ffa_mem_handle_entry_t* e;

    if (reg == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    e = find_handle(reg, handle);
    if (e == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (e->borrower != borrower) {
        return WT_FFA_DENIED;
    }
    if (e->retrieved == 0u) {
        return WT_FFA_DENIED;
    }
    e->retrieved = 0u;
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
        return WT_FFA_DENIED;
    }
    if (e->retrieved != 0u) {
        return WT_FFA_DENIED;
    }
    e->state = (uint8_t)WT_FFA_MEM_STATE_FREE;
    e->handle = WT_FFA_MEM_HANDLE_INVALID;
    return 0;
}
