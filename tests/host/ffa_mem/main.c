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
    in.attributes = 0x6Fu;
    in.permissions = 0x0Au;
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
        WT_FFA_MEM_RELINQUISH, WT_FFA_MEM_RECLAIM
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
          rid == 0x8002u && perms == 0x0Au,
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
          regs[0].page_count == 2u && regs[0].permissions == 0x0Au &&
          regs[0].ns == 1u && regs[1].base == 0x40002000ull &&
          regs[1].page_count == 3u,
          "the mapping list carries each constituent with the borrower permissions and NS state");
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
                                        0x80FBu, 0x0Au, &len) == 0 &&
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
                                        0x80FBu, 0x0Au, &len);
    buf[28] = 2u;
    check(wt_ffa_mem_retrieve_req_parse(buf, len, &h, &sender, &receiver) ==
              WT_FFA_NOT_SUPPORTED,
          "a retrieve request for more than one receiver is NOT_SUPPORTED");
    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x1234ull, 0x8000u,
                                        0x80FBu, 0x0Au, &len);
    buf[24] = 24u;
    check(wt_ffa_mem_retrieve_req_parse(buf, len, &h, &sender, &receiver) ==
              WT_FFA_NOT_SUPPORTED,
          "a retrieve request with an unknown access descriptor size is NOT_SUPPORTED");
    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x1234ull, 0x8000u,
                                        0x80FBu, 0x0Au, &len);
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

int main(void)
{
    printf("WT-FFA-0009 (FF-A memory transaction descriptors and handle state)\n");

    fid_rows();
    txn_rows();
    reject_rows();
    rxtx_rows();
    registry_rows();
    share_rows();
    retrieve_rows();

    printf("ffa_mem: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
