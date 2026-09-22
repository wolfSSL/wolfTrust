/* main.c
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

/* WT-FFA-0009: the DEN0140 memory transaction descriptor (lend/donate/share),
 * its composite and constituent sub-descriptors, the relayer validation, the
 * RX/TX buffer geometry, and the memory handle lifetime state machine. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static void put32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void put64(uint8_t* p, uint64_t v)
{
    put32(p, (uint32_t)(v & 0xFFFFFFFFu));
    put32(&p[4], (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

/* Encode a canonical two-constituent transaction for op with the given flags:
 * sender 0, borrower 0x8002, normal NS memory, read-write no-execute. The
 * constituents are page-aligned, adjacent, and total five pages. */
static size_t make_txn(uint8_t* buf, size_t cap, wt_ffa_mem_op_t op,
                       uint32_t flags)
{
    static const wt_ffa_mem_constituent_t cons[2] = {
        { 0x40000000ull, 2u },
        { 0x40002000ull, 3u }
    };
    wt_ffa_mem_build_t in;
    size_t out = 0u;

    memset(&in, 0, sizeof(in));
    in.constituents = cons;
    in.constituent_count = 2u;
    in.op = op;
    in.sender = 0u;
    in.receiver = 0x8002u;
    in.attributes = 0x2Fu;
    in.permissions = 0x06u;
    in.flags = flags;
    in.tag = 0x1122334455667788ull;
    if (wt_ffa_mem_txn_build(buf, cap, &in, &out) != 0) {
        return 0u;
    }
    return out;
}

/* WT-FFA-0009 (memory-management function ids). */
static void fid_rows(void)
{
    static const uint32_t mem32[] = {
        WT_FFA_MEM_DONATE32, WT_FFA_MEM_LEND32, WT_FFA_MEM_SHARE32,
        WT_FFA_MEM_RETRIEVE_REQ32, WT_FFA_MEM_RETRIEVE_RESP,
        WT_FFA_MEM_RELINQUISH, WT_FFA_MEM_RECLAIM,
        WT_FFA_MEM_FRAG_RX, WT_FFA_MEM_FRAG_TX
    };
    size_t n = sizeof(mem32) / sizeof(mem32[0]);
    size_t i;
    size_t j;
    int ok;

    ok = 1;
    for (i = 0u; i < n; i++) {
        ok = ok && wt_ffa_fid_in_range(mem32[i]);
        ok = ok && ((mem32[i] & 0x80000000u) != 0u);
    }
    check(ok, "every memory-management function id sits in the FF-A fast-call ranges");

    ok = 1;
    for (i = 0u; i < n; i++) {
        for (j = i + 1u; j < n; j++) {
            ok = ok && (mem32[i] != mem32[j]);
        }
    }
    check(ok, "memory-management function ids are unique");

    check(WT_FFA_MEM_DONATE64 == (WT_FFA_MEM_DONATE32 | 0x40000000u) &&
          WT_FFA_MEM_LEND64 == (WT_FFA_MEM_LEND32 | 0x40000000u) &&
          WT_FFA_MEM_SHARE64 == (WT_FFA_MEM_SHARE32 | 0x40000000u) &&
          WT_FFA_MEM_RETRIEVE_REQ64 == (WT_FFA_MEM_RETRIEVE_REQ32 | 0x40000000u),
          "donate, lend, share, and retrieve-request have paired SMC32 and SMC64 ids");
}

/* WT-FFA-0009 (descriptor round-trip). */
static void txn_rows(void)
{
    uint8_t buf[256];
    wt_ffa_mem_txn_t txn;
    wt_ffa_mem_constituent_t c;
    uint16_t rid;
    uint8_t perms;
    size_t len;

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    check(len == 112u,
          "a two-constituent share encodes header, one access descriptor, composite, and constituents");
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0,
          "the relayer accepts a well-formed share transaction");
    check(txn.sender == 0u && txn.receiver_count == 1u &&
          txn.composite_offset == 64u && txn.constituent_count == 2u &&
          txn.total_page_count == 5u && txn.tag == 0x1122334455667788ull,
          "the parsed header carries the sender, composite location, and page total");
    check(wt_ffa_mem_receiver(buf, len, &txn, 0u, &rid, &perms) == 0 &&
          rid == 0x8002u && perms == 0x06u,
          "the endpoint access descriptor names the borrower and its permissions");
    check(wt_ffa_mem_constituent(buf, len, &txn, 0u, &c) == 0 &&
          c.address == 0x40000000ull && c.page_count == 2u &&
          wt_ffa_mem_constituent(buf, len, &txn, 1u, &c) == 0 &&
          c.address == 0x40002000ull && c.page_count == 3u,
          "each constituent decodes its page-aligned base and page count");
    check(wt_ffa_mem_receiver(buf, len, &txn, 1u, &rid, &perms) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_constituent(buf, len, &txn, 2u, &c) == WT_FFA_INVALID_PARAMETERS,
          "out-of-range receiver and constituent indices are refused");

    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_DONATE, 0u, &txn) == 0,
          "a single-receiver donate is well formed");
    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_LEND, WT_FFA_MEM_FLAG_ZERO);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) == 0,
          "a lend may set the zero-memory flag");
}

/* WT-FFA-0009 (relayer rejections). Each row rebuilds a valid descriptor and
 * corrupts one field. */
static void reject_rows(void)
{
    uint8_t buf[256];
    wt_ffa_mem_txn_t txn;
    size_t len;

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    check(wt_ffa_mem_txn_validate(buf, WT_FFA_MEM_TXN_HDR_SIZE - 1u,
                                  WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a buffer shorter than the header is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0x9999u, &txn) ==
              WT_FFA_DENIED,
          "a sender that is not the caller is DENIED");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[24] = 24u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_NOT_SUPPORTED,
          "an access descriptor size this SPMC cannot parse is NOT_SUPPORTED");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[28] = 2u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_DONATE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a donate to more than one receiver is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[36] = 1u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a non-zero reserved header byte is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[2] = (uint8_t)(buf[2] | 0x80u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a reserved memory-attribute bit is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[2] = (uint8_t)((buf[2] & 0xCFu) | 0x30u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a reserved memory-type encoding is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[50] = 0x03u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a reserved data-access permission is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[50] = 0xF2u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "reserved permission bits are INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put32(&buf[52], 0u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a receiver with no composite offset is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put32(&buf[52], (uint32_t)len);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a composite offset past the buffer is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[80] = 1u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a misaligned constituent base is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put32(&buf[88], 0u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a zero-length constituent is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put32(&buf[64], 6u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a total page count that does not match the constituents is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put64(&buf[96], 0x40001000ull);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "overlapping constituents are INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put32(&buf[4], WT_FFA_MEM_FLAG_ZERO);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share that requests zeroing is INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put32(&buf[4], 0x400u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a reserved transaction flag bit is INVALID_PARAMETERS");
}

/* WT-FFA-0009 (RX/TX buffer geometry, 7.2.1). */
static void rxtx_rows(void)
{
    check(wt_ffa_rxtx_validate(0x1000ull, 0x2000ull, 1u) == 0,
          "a page-aligned, non-overlapping RX/TX pair is valid");
    check(wt_ffa_rxtx_validate(0x1001ull, 0x2000ull, 1u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a misaligned TX base is INVALID_PARAMETERS");
    check(wt_ffa_rxtx_validate(0x1000ull, 0x1000ull, 1u) ==
              WT_FFA_INVALID_PARAMETERS,
          "identical RX and TX bases are INVALID_PARAMETERS");
    check(wt_ffa_rxtx_validate(0x1000ull, 0x2000ull, 2u) ==
              WT_FFA_INVALID_PARAMETERS,
          "overlapping RX and TX ranges are INVALID_PARAMETERS");
    check(wt_ffa_rxtx_validate(0x1000ull, 0x2000ull, 0u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a zero page count is INVALID_PARAMETERS");
    check(wt_ffa_rxtx_validate(0x1000ull, 0x2000ull, WT_FFA_RXTX_MAX_PAGES + 1u) ==
              WT_FFA_INVALID_PARAMETERS,
          "more than the maximum page count is INVALID_PARAMETERS");
}

/* WT-FFA-0009 (RX/TX registration and RX buffer ownership, 7.2.2). */
static void mailbox_rows(void)
{
    wt_ffa_mailbox_t mb;

    memset(&mb, 0, sizeof(mb));
    check(wt_ffa_mailbox_unmap(&mb) == WT_FFA_INVALID_PARAMETERS,
          "FFA_RXTX_UNMAP with nothing mapped is INVALID_PARAMETERS");
    check(wt_ffa_mailbox_rx_release(&mb) == WT_FFA_DENIED,
          "FFA_RX_RELEASE with nothing mapped is DENIED");
    check(wt_ffa_mailbox_rx_acquire(&mb) == WT_FFA_DENIED,
          "an unmapped RX buffer cannot be acquired");
    check(wt_ffa_mailbox_map(&mb, 0x1000ull, 0x3000ull, 0x40u | 1u) ==
              WT_FFA_INVALID_PARAMETERS,
          "reserved bits above the page count are SBZ");
    check(wt_ffa_mailbox_map(&mb, 0x1001ull, 0x3000ull, 1u) ==
              WT_FFA_INVALID_PARAMETERS && mb.mapped == 0u,
          "bad geometry maps nothing");
    check(wt_ffa_mailbox_map(&mb, 0x1000ull, 0x3000ull, 1u) == 0 &&
              mb.mapped == 1u && mb.tx == 0x1000ull && mb.rx == 0x3000ull,
          "a valid pair is recorded");
    check(wt_ffa_mailbox_map(&mb, 0x5000ull, 0x7000ull, 1u) == WT_FFA_DENIED,
          "a second FFA_RXTX_MAP before an unmap is DENIED");
    check(wt_ffa_mailbox_rx_release(&mb) == WT_FFA_DENIED,
          "releasing an RX buffer the endpoint does not own is DENIED");
    check(wt_ffa_mailbox_rx_acquire(&mb) == 0 &&
              wt_ffa_mailbox_rx_acquire(&mb) == WT_FFA_BUSY,
          "a full RX buffer is BUSY until released");
    check(wt_ffa_mailbox_rx_release(&mb) == 0 &&
              wt_ffa_mailbox_rx_acquire(&mb) == 0,
          "FFA_RX_RELEASE hands the buffer back to the producer");
    check(wt_ffa_mailbox_unmap(&mb) == 0 && mb.mapped == 0u &&
              mb.rx_full == 0u,
          "FFA_RXTX_UNMAP forgets the pair and its ownership");
}

/* WT-FFA-0009 (handle lifetime state). */
static void registry_rows(void)
{
    wt_ffa_mem_registry_t reg;
    const wt_ffa_mem_handle_entry_t* e;
    uint64_t h[WT_FFA_MEM_MAX_HANDLES];
    uint64_t extra = 0u;
    unsigned int i;
    unsigned int j;
    int ok;

    wt_ffa_mem_registry_init(&reg);
    ok = 1;
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        ok = ok && (wt_ffa_mem_handle_alloc(&reg, WT_FFA_MEM_OP_SHARE, 0u,
                                            0x8002u, &h[i]) == 0);
    }
    check(ok, "the registry allocates a handle for every slot");

    ok = 1;
    for (i = 0u; i < WT_FFA_MEM_MAX_HANDLES; i++) {
        for (j = i + 1u; j < WT_FFA_MEM_MAX_HANDLES; j++) {
            ok = ok && (h[i] != h[j]);
        }
        ok = ok && ((h[i] & 0x8000000000000000ull) == 0u);
    }
    check(ok, "allocated handles are unique with the SPMC allocator bit clear");
    check(wt_ffa_mem_handle_alloc(&reg, WT_FFA_MEM_OP_SHARE, 0u, 0x8002u,
                                  &extra) == WT_FFA_NO_MEMORY,
          "a full registry refuses a further allocation");

    check(wt_ffa_mem_handle_lookup(&reg, h[0], &e) == 0 &&
          e->borrower == 0x8002u &&
          e->state == (uint8_t)WT_FFA_MEM_STATE_SHARED,
          "a live handle looks up its borrower and state");
    check(wt_ffa_mem_handle_lookup(&reg, 0xDEADBEEFull, &e) ==
              WT_FFA_INVALID_PARAMETERS,
          "an unknown handle does not look up");

    check(wt_ffa_mem_handle_retrieve(&reg, h[0], 0x9999u) == WT_FFA_DENIED,
          "the wrong borrower cannot retrieve a handle");
    check(wt_ffa_mem_handle_retrieve(&reg, h[0], 0x8002u) == 0,
          "the declared borrower retrieves the handle");
    check(wt_ffa_mem_handle_retrieve(&reg, h[0], 0x8002u) == WT_FFA_DENIED,
          "a handle cannot be retrieved twice");
    check(wt_ffa_mem_handle_reclaim(&reg, h[0], 0u) == WT_FFA_DENIED,
          "the owner cannot reclaim a handle the borrower still holds");
    check(wt_ffa_mem_handle_relinquish(&reg, h[0], 0x9999u) == WT_FFA_DENIED,
          "the wrong borrower cannot relinquish a handle");
    check(wt_ffa_mem_handle_relinquish(&reg, h[0], 0x8002u) == 0,
          "the borrower relinquishes the handle");
    check(wt_ffa_mem_handle_reclaim(&reg, h[0], 0x9999u) == WT_FFA_DENIED,
          "the wrong owner cannot reclaim a handle");
    check(wt_ffa_mem_handle_reclaim(&reg, h[0], 0u) == 0,
          "the owner reclaims the relinquished handle");
    check(wt_ffa_mem_handle_lookup(&reg, h[0], &e) == WT_FFA_INVALID_PARAMETERS,
          "a reclaimed handle is no longer known");
    check(wt_ffa_mem_handle_alloc(&reg, WT_FFA_MEM_OP_LEND, 0u, 0x8003u,
                                  &extra) == 0 && extra != h[0],
          "reclaiming a slot frees it for a new, distinct handle");
}

/* WT-FFA-0009 (share lifecycle: capture regions, map on retrieve, free on
 * reclaim). */
static void share_rows(void)
{
    uint8_t buf[256];
    wt_ffa_mem_txn_t txn;
    wt_ffa_mem_region_t regs[WT_FFA_MEM_MAX_REGIONS];
    wt_ffa_mem_registry_t reg;
    uint32_t n = 0u;
    uint64_t h = 0u;
    size_t len;

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    (void)wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn);

    check(wt_ffa_mem_regions_from_txn(buf, len, &txn, 0u, regs,
                                      WT_FFA_MEM_MAX_REGIONS, &n) == 0 &&
          n == 2u && regs[0].base == 0x40000000ull &&
          regs[0].page_count == 2u && regs[0].permissions == 0x06u &&
          regs[0].ns == 0u && regs[1].base == 0x40002000ull &&
          regs[1].page_count == 3u,
          "the mapping list carries each constituent with the borrower permissions; the relayer decides the security state");
    buf[2] = (uint8_t)(buf[2] | 0x40u);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a sender that sets the NS bit is INVALID_PARAMETERS");
    buf[2] = (uint8_t)(buf[2] & ~0x40u);
    check(wt_ffa_mem_regions_from_txn(buf, len, &txn, 0u, regs, 1u, &n) ==
              WT_FFA_NO_MEMORY,
          "a mapping list smaller than the constituent count is NO_MEMORY");

    wt_ffa_mem_registry_init(&reg);
    check(wt_ffa_mem_share_register(&reg, WT_FFA_MEM_OP_SHARE, 0u, 0x8002u,
                                    regs, 2u, &h) == 0,
          "a share registers a handle with its captured regions");
    check(wt_ffa_mem_handle_regions(&reg, h, regs, WT_FFA_MEM_MAX_REGIONS,
                                    &n) == 0 && n == 2u &&
          regs[0].base == 0x40000000ull && regs[1].page_count == 3u,
          "the relayer reads back the captured regions to map into the borrower");
    check(wt_ffa_mem_handle_retrieve(&reg, h, 0x8002u) == 0 &&
          wt_ffa_mem_handle_regions(&reg, h, regs, WT_FFA_MEM_MAX_REGIONS,
                                    &n) == 0,
          "the regions are still available after the borrower retrieves");
    check(wt_ffa_mem_handle_relinquish(&reg, h, 0x8002u) == 0 &&
          wt_ffa_mem_handle_reclaim(&reg, h, 0u) == 0 &&
          wt_ffa_mem_handle_regions(&reg, h, regs, WT_FFA_MEM_MAX_REGIONS,
                                    &n) == WT_FFA_INVALID_PARAMETERS,
          "a reclaimed handle exposes no regions");
    check(wt_ffa_mem_share_register(&reg, WT_FFA_MEM_OP_SHARE, 0u, 0x8002u,
                                    regs, WT_FFA_MEM_MAX_REGIONS + 1u, &h) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share with more regions than the cap is refused");
}

/* WT-FFA-0009 (retrieve request and relinquish descriptors, and the handle a
 * retrieve response carries). */
static void retrieve_rows(void)
{
    uint8_t buf[256];
    wt_ffa_mem_txn_t txn;
    uint64_t h = 0u;
    uint16_t sender = 0u;
    uint16_t receiver = 0u;
    size_t len = 0u;

    check(wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x1234ull, 0x8000u,
                                        0x80FBu, 0x06u, &len) == 0 &&
          len == 64u,
          "a retrieve request is a header plus one access descriptor");
    check(wt_ffa_mem_retrieve_req_parse(buf, len, &h, &sender, &receiver) == 0 &&
          h == 0x1234ull && sender == 0x8000u && receiver == 0x80FBu,
          "the retrieve request round-trips the handle, owner, and borrower");
    check(wt_ffa_mem_retrieve_req_parse(buf, WT_FFA_MEM_TXN_HDR_SIZE, &h,
                                        &sender, &receiver) ==
              WT_FFA_INVALID_PARAMETERS,
          "a retrieve request without its access descriptor is INVALID_PARAMETERS");

    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x1234ull, 0x8000u,
                                        0x80FBu, 0x06u, &len);
    buf[28] = (uint8_t)(WT_FFA_MEM_MAX_BORROWERS + 1u);
    check(wt_ffa_mem_retrieve_req_parse(buf, len, &h, &sender, &receiver) ==
              WT_FFA_NOT_SUPPORTED,
          "a retrieve request naming more receivers than a transaction holds is NOT_SUPPORTED");
    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x1234ull, 0x8000u,
                                        0x80FBu, 0x06u, &len);
    buf[24] = 24u;
    check(wt_ffa_mem_retrieve_req_parse(buf, len, &h, &sender, &receiver) ==
              WT_FFA_NOT_SUPPORTED,
          "a retrieve request with an unknown access descriptor size is NOT_SUPPORTED");
    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x1234ull, 0x8000u,
                                        0x80FBu, 0x06u, &len);
    put32(&buf[52], 64u);
    check(wt_ffa_mem_retrieve_req_parse(buf, len, &h, &sender, &receiver) ==
              WT_FFA_INVALID_PARAMETERS,
          "a retrieve request carrying a composite offset is INVALID_PARAMETERS");

    check(wt_ffa_mem_relinquish_build(buf, sizeof(buf), 0x1234ull, 0u, 0x80FBu,
                                      &len) == 0 && len == 18u,
          "a relinquish descriptor names one endpoint after its header");
    check(wt_ffa_mem_relinquish_parse(buf, len, &h, &receiver) == 0 &&
          h == 0x1234ull && receiver == 0x80FBu,
          "the relinquish descriptor round-trips the handle and endpoint");
    check(wt_ffa_mem_relinquish_parse(buf, WT_FFA_MEM_RELINQ_HDR_SIZE, &h,
                                      &receiver) == WT_FFA_INVALID_PARAMETERS,
          "a relinquish descriptor cut before its endpoint is INVALID_PARAMETERS");
    put32(&buf[12], 2u);
    check(wt_ffa_mem_relinquish_parse(buf, len, &h, &receiver) ==
              WT_FFA_NOT_SUPPORTED,
          "a relinquish naming more than one endpoint is NOT_SUPPORTED");
    put32(&buf[12], 1u);
    put32(&buf[8], 0x4u);
    check(wt_ffa_mem_relinquish_parse(buf, len, &h, &receiver) ==
              WT_FFA_INVALID_PARAMETERS,
          "a reserved relinquish flag is INVALID_PARAMETERS");
    check(wt_ffa_mem_relinquish_build(buf, sizeof(buf), 0x1234ull, 0x4u,
                                      0x80FBu, &len) == WT_FFA_INVALID_PARAMETERS,
          "the relinquish builder refuses a reserved flag");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put64(&buf[8], 0x55AAull);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0 &&
          txn.handle == 0x55AAull,
          "a descriptor carrying a handle (a retrieve response) parses it");
}

/* WT-FFA-0009 (several borrowers, the v1.2 access descriptor, send flags). */
static void borrower_rows(void)
{
    static const wt_ffa_mem_constituent_t cons[1] = { { 0x40000000ull, 2u } };
    wt_ffa_mem_registry_t reg;
    wt_ffa_mem_region_t region = { 0x40000000ull, 2u, 0x06u, 1u };
    wt_ffa_mem_retrieve_req_t rq;
    wt_ffa_mem_build_t in;
    wt_ffa_mem_txn_t txn;
    uint8_t buf[256];
    uint64_t h = 0u;
    uint64_t parsed = 0u;
    uint32_t flags = 0u;
    uint16_t ep = 0u;
    size_t len = 0u;

    wt_ffa_mem_registry_init(&reg);
    check(wt_ffa_mem_share_register(&reg, WT_FFA_MEM_OP_SHARE, 0u, 0x8002u,
                                    &region, 1u, &h) == 0 &&
          wt_ffa_mem_handle_add_borrower(&reg, h, 0x8003u, 0x05u) == 0,
          "a transaction names a second borrower with its own permissions");
    check(wt_ffa_mem_handle_add_borrower(&reg, h, 0x8003u, 0x05u) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_handle_add_borrower(&reg, h, 0u, 0x05u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a repeated borrower or the owner itself is refused");
    check(wt_ffa_mem_handle_add_borrower(&reg, h, 0x8004u, 0x05u) == 0 &&
          wt_ffa_mem_handle_add_borrower(&reg, h, 0x8005u, 0x05u) ==
              WT_FFA_NO_MEMORY,
          "borrowers past the per-transaction limit are NO_MEMORY");
    check(wt_ffa_mem_handle_borrower(&reg, h, 0x8003u) != NULL &&
          wt_ffa_mem_handle_borrower(&reg, h, 0x8003u)->permissions == 0x05u &&
          wt_ffa_mem_handle_borrower(&reg, h, 0x8009u) == NULL,
          "each borrower keeps what it was granted");
    check(wt_ffa_mem_handle_retrieve(&reg, h, 0x8002u) == 0 &&
          wt_ffa_mem_handle_retrieve(&reg, h, 0x8003u) == 0 &&
          wt_ffa_mem_handle_relinquish(&reg, h, 0x8002u) == 0 &&
          wt_ffa_mem_handle_reclaim(&reg, h, 0u) == WT_FFA_DENIED,
          "the owner cannot reclaim while any borrower still holds the region");
    check(wt_ffa_mem_handle_add_borrower(&reg, h, 0x8006u, 0x05u) ==
              WT_FFA_INVALID_PARAMETERS,
          "no borrower joins a transaction already retrieved");
    check(wt_ffa_mem_registry_overlaps(&reg, 0x40001000ull, 1u) != 0 &&
          wt_ffa_mem_registry_overlaps(&reg, 0x40002000ull, 4u) == 0,
          "pages a live handle holds are found, its neighbours are not");
    check(wt_ffa_mem_handle_relinquish(&reg, h, 0x8003u) == 0 &&
          wt_ffa_mem_handle_reclaim(&reg, h, 0u) == 0 &&
          wt_ffa_mem_registry_overlaps(&reg, 0x40001000ull, 1u) == 0,
          "reclaim frees the pages for a later transaction");

    memset(&in, 0, sizeof(in));
    in.constituents = cons;
    in.constituent_count = 1u;
    in.op = WT_FFA_MEM_OP_LEND;
    in.receiver = 0x8002u;
    in.attributes = 0x2Fu;
    in.permissions = 0x06u;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE_V12;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) == 0 &&
          len == 112u &&
          wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) == 0 &&
          txn.access_desc_size == WT_FFA_MEM_ACCESS_SIZE_V12 &&
          txn.composite_offset == 80u,
          "the 32-byte FF-A 1.2 access descriptor round-trips");
    buf[48u + 31u] = 1u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "its reserved tail must be zero");
    buf[48u + 31u] = 0u;
    buf[48u + 12u] = 0x5Au;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) == 0,
          "its implementation-defined bytes are the sender's to use");
    in.access_desc_size = 24u;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) ==
              WT_FFA_INVALID_PARAMETERS,
          "no other access descriptor size is built");

    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x77ull, 0u, 0x8002u,
                                        0x06u, &len);
    put64(&buf[16], 0xABCDull);
    put32(&buf[4], WT_FFA_MEM_FLAG_TYPE_LEND);
    check(wt_ffa_mem_retrieve_req_parse_ex(buf, len, &rq) == 0 &&
          rq.handle == 0x77ull && rq.tag == 0xABCDull &&
          rq.flags == WT_FFA_MEM_FLAG_TYPE_LEND && rq.receiver_count == 1u &&
          rq.receivers[0] == 0x8002u && rq.permissions[0] == 0x06u &&
          rq.access_desc_size == WT_FFA_MEM_ACCESS_SIZE,
          "a retrieve request yields its tag, flags, and asked-for permissions");

    (void)wt_ffa_mem_relinquish_build(buf, sizeof(buf), 0x77ull,
                                      WT_FFA_MEM_RELINQ_FLAG_ZERO, 0x8002u,
                                      &len);
    check(wt_ffa_mem_relinquish_parse_ex(buf, len, &parsed, &ep, &flags) == 0 &&
          parsed == 0x77ull && ep == 0x8002u &&
          flags == WT_FFA_MEM_RELINQ_FLAG_ZERO,
          "a relinquish descriptor yields its zero-memory flag");
}

/* WT-FFA-0009 (fragmented transmission, DEN0140 4.1.2): a descriptor sent
 * in pieces reassembles byte for byte at every split point, and only the
 * transaction's own sender and handle can add to it. */
static wt_ffa_mem_frag_t g_frag_row;

static void frag_rows(void)
{
    static uint8_t buf[256];
    wt_ffa_mem_registry_t reg;
    wt_ffa_mem_txn_t txn;
    size_t len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    uint32_t split;
    uint32_t off;
    uint32_t piece;
    uint64_t h1;
    uint64_t h2;
    const wt_ffa_mem_handle_entry_t* e = NULL;
    static uint8_t rbuf[128];
    size_t rlen = 0u;
    uint64_t size = 0u;
    int done = 0;
    int ok = 1;
    int ret;

    check(len > 32u, "the canonical descriptor spans several fragments");
    for (split = 1u; split < (uint32_t)len; split++) {
        ret = wt_ffa_mem_frag_begin(&g_frag_row, 7u, 0u, 1u, buf, split,
                                    (uint32_t)len);
        done = 0;
        for (off = split; (ret == 0) && (off < (uint32_t)len); off += piece) {
            piece = ((uint32_t)len - off > 5u) ? 5u : (uint32_t)len - off;
            ret = wt_ffa_mem_frag_add(&g_frag_row, 7u, 0u, &buf[off], piece,
                                      &done);
        }
        ok = ok && (ret == 0) && (done == 1) &&
             (g_frag_row.received == (uint32_t)len) &&
             (memcmp(g_frag_row.buf, buf, len) == 0);
        wt_ffa_mem_frag_reset(&g_frag_row);
    }
    check(ok, "a descriptor split at every offset reassembles byte for byte");

    check(wt_ffa_mem_frag_begin(&g_frag_row, 7u, 0u, 1u, buf, 0u, 64u) ==
          WT_FFA_INVALID_PARAMETERS,
          "an empty first fragment is refused");
    check(wt_ffa_mem_frag_begin(&g_frag_row, 7u, 0u, 1u, buf, 64u, 64u) ==
          WT_FFA_INVALID_PARAMETERS,
          "a first fragment that is the whole descriptor is not a fragmented send");
    check(wt_ffa_mem_frag_begin(&g_frag_row, 7u, 0u, 1u, buf, 16u,
                                WT_FFA_MEM_FRAG_MAX + 1u) == WT_FFA_NO_MEMORY,
          "a descriptor past the reassembly bound is NO_MEMORY");

    (void)wt_ffa_mem_frag_begin(&g_frag_row, 7u, 0u, 1u, buf, 16u, 64u);
    check(wt_ffa_mem_frag_add(&g_frag_row, 8u, 0u, &buf[16], 16u, &done) ==
          WT_FFA_INVALID_PARAMETERS,
          "a fragment for another handle is refused");
    check(wt_ffa_mem_frag_add(&g_frag_row, 7u, 0x8002u, &buf[16], 16u, &done) ==
          WT_FFA_INVALID_PARAMETERS,
          "a fragment from another sender is refused");
    check(wt_ffa_mem_frag_add(&g_frag_row, 7u, 0u, &buf[16], 0u, &done) ==
          WT_FFA_INVALID_PARAMETERS,
          "an empty fragment is refused");
    check(wt_ffa_mem_frag_add(&g_frag_row, 7u, 0u, &buf[16], 49u, &done) ==
          WT_FFA_INVALID_PARAMETERS,
          "a fragment past the declared total is refused");
    check(g_frag_row.received == 16u,
          "a refused fragment leaves the reassembly where it was");
    wt_ffa_mem_frag_reset(&g_frag_row);
    check(wt_ffa_mem_frag_add(&g_frag_row, 7u, 0u, buf, 16u, &done) ==
          WT_FFA_INVALID_PARAMETERS,
          "a fragment with no transfer in progress is refused");

    wt_ffa_mem_registry_init(&reg);
    h1 = wt_ffa_mem_handle_reserve(&reg);
    (void)wt_ffa_mem_share_register(&reg, WT_FFA_MEM_OP_SHARE, 0u, 0x8002u,
                                    NULL, 0u, &h2);
    check((h1 != 0u) && (h2 != h1),
          "a reserved handle is never handed to another transaction");
    check((wt_ffa_mem_share_register_as(&reg, WT_FFA_MEM_OP_SHARE, 0u, 0x8002u,
                                        NULL, 0u, h1) == 0) &&
          (wt_ffa_mem_handle_lookup(&reg, h1, &e) == 0) && (e->handle == h1),
          "the reserved handle names the region once the descriptor is whole");

    (void)wt_ffa_mem_frag_begin(&g_frag_row, h1, 0u, 1u, buf, 40u,
                                (uint32_t)len);
    (void)wt_ffa_mem_frag_add(&g_frag_row, h1, 0u, &buf[40],
                              (uint32_t)len - 40u, &done);
    check((done == 1) &&
          (wt_ffa_mem_txn_validate(g_frag_row.buf, g_frag_row.total,
                                   WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0),
          "a reassembled descriptor passes the relayer checks");
    wt_ffa_mem_frag_reset(&g_frag_row);

    check((wt_ffa_mem_frag_expected(buf, (uint32_t)len, 0, &size) == 1) &&
          (size == (uint64_t)len),
          "a whole first fragment states the descriptor's exact length");
    check((wt_ffa_mem_frag_expected(buf, (uint32_t)len - 16u, 0, &size) == 1) &&
          (size == (uint64_t)len),
          "the length is known before the last constituent has arrived");
    check(wt_ffa_mem_frag_expected(buf, WT_FFA_MEM_TXN_HDR_SIZE, 0, &size) == 0,
          "a fragment that stops before the composite header cannot tell");
    check((wt_ffa_mem_frag_expected(buf, (uint32_t)len, 0, &size) == 1) &&
          (size != (uint64_t)len + 0x10u),
          "a total longer than the descriptor it heads is caught");
    rlen = 0u;
    check((wt_ffa_mem_retrieve_req_build(rbuf, sizeof(rbuf), 0x1234u, 0u,
                                         0x8002u, 0x06u, &rlen) == 0) &&
          (wt_ffa_mem_frag_expected(rbuf, (uint32_t)rlen, 1, &size) == 1) &&
          (size == (uint64_t)rlen) && (size != WT_FFA_MEM_PAGE_SIZE + 1u),
          "a retrieve request states its length from its access descriptors");
}

int main(void)
{
    printf("WT-FFA-0009 (FF-A memory transaction descriptors and handle state)\n");

    fid_rows();
    txn_rows();
    reject_rows();
    rxtx_rows();
    mailbox_rows();
    registry_rows();
    share_rows();
    retrieve_rows();
    borrower_rows();
    frag_rows();

    printf("ffa_mem: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
