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
 * RX/TX buffer geometry, the memory handle lifetime state machine, and the
 * SPMC relayer driving real partition tables. */

#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

#include "wolftrust/arch.h"
#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/ffa_notif.h"
#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

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

#define V10 WT_FFA_VERSION_MAKE(1u, 0u)

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
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
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
    uint16_t rid;
    uint8_t perms;
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
    buf[47] = 0xFFu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0,
          "the SBZ header bytes [36, 48) are ignored (Table 1.20)");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[2] = (uint8_t)(buf[2] | 0x80u);
    buf[3] = 0xFFu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0 &&
          txn.attributes == 0x2Fu,
          "the SBZ memory-attribute bits[15:7] are ignored and dropped (Table 1.18)");

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
    buf[50] = 0xF6u;
    buf[56] = 1u;
    buf[63] = 0xFFu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0 &&
          wt_ffa_mem_receiver(buf, len, &txn, 0u, &rid, &perms) == 0 &&
          perms == 0x06u,
          "the SBZ permission bits[7:4] and access descriptor tail are ignored and dropped (Tables 1.15, 1.16)");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[72] = 1u;
    buf[79] = 0xFFu;
    buf[92] = 1u;
    buf[111] = 0xFFu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0,
          "the SBZ composite bytes [8, 16) and constituent bytes [12, 16) are ignored (Tables 1.13, 1.14)");

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

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_LEND, 0u);
    put32(&buf[4], 0xFFFFFFFCu | WT_FFA_MEM_FLAG_ZERO);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) == 0 &&
          txn.flags == WT_FFA_MEM_FLAG_ZERO,
          "the SBZ transaction flag bits[31:2] are ignored and never kept (Table 1.21)");
}

/* Move everything after the header of a descriptor in buf by bytes, fixing up
 * the access array offset and, for a send, its composite offset. */
static size_t shift_access(uint8_t* buf, size_t len, uint32_t by,
                           int composite)
{
    size_t i;

    for (i = len; i > WT_FFA_MEM_TXN_HDR_SIZE; i--) {
        buf[i - 1u + by] = buf[i - 1u];
    }
    memset(&buf[WT_FFA_MEM_TXN_HDR_SIZE], 0, by);
    put32(&buf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET], WT_FFA_MEM_TXN_HDR_SIZE + by);
    if (composite != 0) {
        put32(&buf[WT_FFA_MEM_TXN_HDR_SIZE + by + WT_FFA_MEM_ACC_OFF_COMP_OFF],
              WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE + by);
    }
    return len + by;
}

/* WT-FFA-0009 (the access descriptor array sits at a 16-byte aligned offset,
 * Table 1.20). */
static void access_offset_rows(void)
{
    uint8_t buf[256];
    wt_ffa_mem_retrieve_req_t rq;
    wt_ffa_mem_txn_t txn;
    size_t len = 0u;

    len = shift_access(buf, make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u),
                       16u, 1);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0 &&
          txn.access_offset == 64u && txn.composite_offset == 80u,
          "a share whose access array sits at a later 16-byte aligned offset is accepted");
    len = shift_access(buf, make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u),
                       1u, 1);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share whose access array offset is 49 is INVALID_PARAMETERS");
    len = shift_access(buf, make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_LEND, 0u),
                       8u, 1);
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a lend whose access array is only 8-byte aligned is INVALID_PARAMETERS");

    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x77ull, 0u, 0x8002u,
                                        0x02u, &len);
    len = shift_access(buf, len, 16u, 0);
    check(wt_ffa_mem_retrieve_req_parse_ex(buf, len, &rq) == 0 &&
          rq.receivers[0] == 0x8002u,
          "a retrieve request whose access array sits at offset 64 is accepted");
    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x77ull, 0u, 0x8002u,
                                        0x02u, &len);
    len = shift_access(buf, len, 1u, 0);
    check(wt_ffa_mem_retrieve_req_parse_ex(buf, len, &rq) ==
              WT_FFA_INVALID_PARAMETERS,
          "a retrieve request whose access array offset is 49 is INVALID_PARAMETERS");
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
          "FFA_RX_RELEASE by an endpoint with no registered pair is DENIED: it "
          "owns no RX buffer (Table 13.22, ACS ffa_rx_release)");
    check(wt_ffa_mailbox_rx_acquire(&mb) == WT_FFA_DENIED,
          "an unmapped RX buffer cannot be acquired");
    check(wt_ffa_mailbox_map(&mb, 0x1000ull, 0x3000ull, 0xFFFFFFC0u | 1u) ==
              0 && mb.pages == 1u && wt_ffa_mailbox_unmap(&mb) == 0,
          "reserved SBZ bits above the page count are ignored (Table 13.25)");
    check(wt_ffa_mailbox_map(&mb, 0x1001ull, 0x3000ull, 1u) ==
              WT_FFA_INVALID_PARAMETERS && mb.mapped == 0u,
          "bad geometry maps nothing");
    check(wt_ffa_mailbox_map(&mb, 0x1000ull, 0x3000ull, 1u) == 0 &&
              mb.mapped == 1u && mb.tx == 0x1000ull && mb.rx == 0x3000ull,
          "a valid pair is recorded");
    check(wt_ffa_mailbox_map(&mb, 0x5000ull, 0x7000ull, 1u) == WT_FFA_DENIED,
          "a second FFA_RXTX_MAP before an unmap is DENIED");
    check(wt_ffa_mailbox_overlaps(&mb, 0x1000ull, 0x1000ull) != 0 &&
              wt_ffa_mailbox_overlaps(&mb, 0x2000ull, 0x2000ull) != 0 &&
              wt_ffa_mailbox_overlaps(&mb, 0x2000ull, 0x1000ull) == 0 &&
              wt_ffa_mailbox_overlaps(&mb, 0x4000ull, 0x1000ull) == 0,
          "a range holding a page of the mapped TX or RX buffer overlaps the pair");
    check(wt_ffa_mailbox_rx_release(&mb) == WT_FFA_DENIED,
          "releasing an RX buffer the endpoint does not own is DENIED");
    check(wt_ffa_mailbox_rx_acquire(&mb) == 0 &&
              wt_ffa_mailbox_rx_acquire(&mb) == WT_FFA_BUSY,
          "a full RX buffer is BUSY until released");
    check(wt_ffa_mailbox_rx_release(&mb) == 0 &&
              wt_ffa_mailbox_rx_acquire(&mb) == 0,
          "FFA_RX_RELEASE hands the buffer back to the producer");
    check(wt_ffa_mailbox_rx_release(&mb) == 0 &&
              wt_ffa_mailbox_rx_post(&mb) == 0 &&
              wt_ffa_mailbox_rx_post(&mb) == WT_FFA_BUSY &&
              wt_ffa_mailbox_rx_acquire(&mb) == WT_FFA_BUSY,
          "a partition message posted to RX makes the next one BUSY");
    check(wt_ffa_mailbox_rx_release(&mb) == WT_FFA_DENIED &&
              mb.rx_full == WT_FFA_RX_POSTED,
          "RX_RELEASE before the RX-full notification is retrieved is DENIED "
          "and the message stays (7.2.2.4.2 rule 2.1.1, Table 13.22)");
    wt_ffa_mailbox_rx_claim(&mb, WT_FFA_NOTIF_FW_SPM_MASK &
                                     ~WT_FFA_NOTIF_FW_SPM_RX_FULL);
    check(mb.rx_full == WT_FFA_RX_POSTED,
          "a GET that returns no RX-full notification hands nothing over");
    wt_ffa_mailbox_rx_claim(&mb, WT_FFA_NOTIF_FW_NS_RX_FULL);
    check(mb.rx_full == WT_FFA_RX_OWNED && wt_ffa_mailbox_rx_release(&mb) == 0,
          "retrieving the RX-full notification hands RX to the endpoint, "
          "which releases it");
    wt_ffa_mailbox_rx_claim(&mb, WT_FFA_NOTIF_FW_SPM_RX_FULL);
    check(mb.rx_full == WT_FFA_RX_EMPTY && wt_ffa_mailbox_rx_acquire(&mb) == 0,
          "an RX-full bit with no message posted claims nothing");
    check(wt_ffa_mailbox_unmap(&mb) == 0 && mb.mapped == 0u &&
              mb.rx_full == 0u &&
              wt_ffa_mailbox_overlaps(&mb, 0x1000ull, 0x1000ull) == 0,
          "FFA_RXTX_UNMAP forgets the pair and its ownership");
}

/* WT-FFA-0009 (a memory management descriptor rides in the caller's mapped TX
 * buffer, DEN0140 2.1.1.2 items 1-2, 2.4.1.2 items 1-2). */
static void tx_buffer_rows(void)
{
    wt_ffa_mailbox_t mb;
    uint64_t tx = 0u;

    memset(&mb, 0, sizeof(mb));
    check(wt_ffa_mem_tx_buffer(&mb, 0u, 0u, 64u, &tx) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_tx_buffer(NULL, 0u, 0u, 64u, &tx) ==
              WT_FFA_INVALID_PARAMETERS,
          "a caller with no RX/TX pair mapped is INVALID_PARAMETERS");
    (void)wt_ffa_mailbox_map(&mb, 0x5000ull, 0x7000ull, 1u);
    check(wt_ffa_mem_tx_buffer(&mb, 0u, 0u, 64u, &tx) == 0 && tx == 0x5000ull,
          "a mapped caller's descriptor is read from its TX buffer");
    check(wt_ffa_mem_tx_buffer(&mb, 0u, 0u, WT_FFA_MEM_PAGE_SIZE + 1u, &tx) ==
              WT_FFA_INVALID_PARAMETERS,
          "a descriptor longer than the TX buffer is INVALID_PARAMETERS");
    check(wt_ffa_mem_tx_buffer(&mb, 0x9000ull, 0u, 64u, &tx) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_tx_buffer(&mb, 0u, 1u, 64u, &tx) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_tx_buffer(&mb, 0x9000ull, 1u, 64u, &tx) ==
              WT_FFA_INVALID_PARAMETERS,
          "a dynamically allocated buffer address or page count is INVALID_PARAMETERS (4.1.1.3)");
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

    check(wt_ffa_mem_handle_retrieve(&reg, h[0], 0x9999u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a handle not sent to the caller cannot be retrieved: "
          "INVALID_PARAMETERS (DEN0140 1.11.1)");
    check(wt_ffa_mem_handle_retrieve(&reg, h[0], 0x8002u) == 0,
          "the declared borrower retrieves the handle");
    check(wt_ffa_mem_handle_retrieve(&reg, h[0], 0x8002u) == WT_FFA_DENIED,
          "a handle cannot be retrieved twice");
    check(wt_ffa_mem_handle_reclaim(&reg, h[0], 0u) == WT_FFA_DENIED,
          "the owner cannot reclaim a handle the borrower still holds");
    check(wt_ffa_mem_handle_relinquish(&reg, h[0], 0x9999u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a caller the handle was not sent to cannot relinquish it: "
          "INVALID_PARAMETERS (DEN0140 2.6.1.2 rules 1-2)");
    check(wt_ffa_mem_handle_relinquish(&reg, h[0], 0x8002u) == 0,
          "the borrower relinquishes the handle");
    check(wt_ffa_mem_handle_reclaim(&reg, h[0], 0x9999u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a caller that does not own the handle cannot reclaim it: "
          "INVALID_PARAMETERS (DEN0140 2.7.1.2 rule 1)");
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
    const wt_ffa_mem_handle_entry_t* e = NULL;
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
    h = 0u;
    check(wt_ffa_mem_share_register(&reg, (wt_ffa_mem_op_t)7, 0u, 0x8002u,
                                    regs, 2u, &h) == WT_FFA_INVALID_PARAMETERS &&
              h == 0u && wt_ffa_mem_handle_lookup(&reg, 1u, &e) ==
                             WT_FFA_INVALID_PARAMETERS &&
              reg.entries[0].state == (uint8_t)WT_FFA_MEM_STATE_FREE,
          "an operation that is not share, lend, or donate registers nothing "
          "and hands out no handle");
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

/* WT-FFA-0009 (the constituent count is held to what a handle captures
 * before any pairwise overlap scan runs). */
static void constituent_limit_rows(void)
{
    static wt_ffa_mem_constituent_t cons[4096];
    static uint8_t buf[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE +
                       WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                       (4096u * WT_FFA_MEM_CONSTITUENT_SIZE)];
    wt_ffa_mem_build_t in;
    wt_ffa_mem_txn_t txn;
    size_t len = 0u;
    uint32_t i;

    for (i = 0u; i < 4096u; i++) {
        cons[i].address = 0x40000000ull + ((uint64_t)i * WT_FFA_MEM_PAGE_SIZE);
        cons[i].page_count = 1u;
    }
    memset(&in, 0, sizeof(in));
    in.constituents = cons;
    in.op = WT_FFA_MEM_OP_SHARE;
    in.receiver = 0x8002u;
    in.attributes = 0x2Fu;
    in.permissions = 0x06u;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
    in.constituent_count = WT_FFA_MEM_MAX_REGIONS;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) == 0 &&
          wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0,
          "a descriptor with as many constituents as a handle holds is valid");
    in.constituent_count = WT_FFA_MEM_MAX_REGIONS + 1u;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) == 0 &&
          wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_NO_MEMORY,
          "one constituent more than a handle holds is NO_MEMORY");
    for (i = 0u; i < 4096u; i++) {
        cons[i].address = 0x40000000ull;
    }
    in.constituent_count = 4096u;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) == 0 &&
          wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_NO_MEMORY,
          "thousands of overlapping constituents are NO_MEMORY before any pair is compared");
}

/* WT-FFA-0009 (retrieve request and relinquish descriptors, and the handle a
 * retrieve response carries). */
static void retrieve_rows(void)
{
    uint8_t buf[256];
    wt_ffa_mem_txn_t txn;
    uint64_t h = 0u;
    uint32_t flags = 0u;
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
          "a retrieve request whose composite offset runs past it is INVALID_PARAMETERS");

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
    put32(&buf[8], 0xFFFFFFFCu | WT_FFA_MEM_RELINQ_FLAG_ZERO);
    check(wt_ffa_mem_relinquish_parse_ex(buf, len, &h, &receiver, &flags) == 0 &&
          flags == WT_FFA_MEM_RELINQ_FLAG_ZERO,
          "the SBZ relinquish flag bits[31:2] are ignored and dropped (Table 2.25)");
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
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) == 0,
          "its SBZ reserved tail is ignored");
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
    buf[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_PERMS] = 0xF6u;
    buf[WT_FFA_MEM_TXN_HDR_SIZE + 8u] = 1u;
    buf[WT_FFA_MEM_TXN_OFF_ATTRS + 1u] = 0x80u;
    buf[40] = 0xFFu;
    check(wt_ffa_mem_retrieve_req_parse_ex(buf, len, &rq) == 0 &&
          rq.permissions[0] == 0x06u && rq.attributes == 0u,
          "a retrieve request's SBZ permission bits, access tail, attribute bits, and header bytes are ignored and dropped");
    put32(&buf[WT_FFA_MEM_TXN_OFF_FLAGS], 0xFFFFF800u | WT_FFA_MEM_FLAG_TYPE_LEND);
    check(wt_ffa_mem_retrieve_req_parse_ex(buf, len, &rq) == 0 &&
          rq.flags == WT_FFA_MEM_FLAG_TYPE_LEND,
          "a retrieve request's SBZ flag bits[31:11] are ignored and dropped (Table 1.22)");

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
    put32(&rbuf[WT_FFA_MEM_TXN_OFF_ACC_SIZE], 0u);
    put32(&rbuf[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 0xFFFFFFFFu);
    check(wt_ffa_mem_frag_expected(rbuf, (uint32_t)rlen, 1, &size) == 0,
          "a retrieve request with a zero access descriptor size cannot tell, and is never walked");
    put32(&rbuf[WT_FFA_MEM_TXN_OFF_ACC_SIZE], WT_FFA_MEM_ACCESS_SIZE);
    put32(&rbuf[WT_FFA_MEM_TXN_OFF_ACC_OFFSET], 8u);
    check(wt_ffa_mem_frag_expected(rbuf, (uint32_t)rlen, 1, &size) == 0,
          "nor is one whose access array starts inside the header");
}

/* A transaction from owner 0 to borrowers 0x8002 onwards with tag 0x77. */
static const wt_ffa_mem_handle_entry_t* make_entry(wt_ffa_mem_registry_t* reg,
                                                   wt_ffa_mem_op_t op,
                                                   uint32_t borrowers)
{
    wt_ffa_mem_region_t region = { 0x40000000ull, 1u, 0x02u, 1u };
    const wt_ffa_mem_handle_entry_t* e = NULL;
    uint64_t h = 0u;
    uint32_t i;

    wt_ffa_mem_registry_init(reg);
    if (wt_ffa_mem_share_register(reg, op, 0u, 0x8002u, &region, 1u, &h) != 0) {
        return NULL;
    }
    for (i = 1u; i < borrowers; i++) {
        if (wt_ffa_mem_handle_add_borrower(reg, h, (uint16_t)(0x8002u + i),
                                           0x02u) != 0) {
            return NULL;
        }
    }
    wt_ffa_mem_handle_set_meta(reg, h, 0x77ull, 0u);
    wt_ffa_mem_handle_set_attributes(reg, h,
                                     (uint16_t)WT_FFA_MEM_ATTR_RELAYER);
    if (wt_ffa_mem_handle_lookup(reg, h, &e) != 0) {
        return NULL;
    }
    return e;
}

/* A retrieve request from self for e naming its first n borrowers in order,
 * each other borrower marked a non-retrieval borrower. */
static void make_rq_as(wt_ffa_mem_retrieve_req_t* rq,
                       const wt_ffa_mem_handle_entry_t* e, uint32_t n,
                       uint16_t self)
{
    uint32_t i;

    memset(rq, 0, sizeof(*rq));
    rq->handle = e->handle;
    rq->tag = 0x77ull;
    rq->receiver_count = n;
    rq->access_desc_size = WT_FFA_MEM_ACCESS_SIZE;
    for (i = 0u; i < n; i++) {
        rq->receivers[i] = (uint16_t)(0x8002u + i);
        rq->permissions[i] = 0x02u;
        if (rq->receivers[i] != self) {
            rq->access_flags[i] = WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
        }
    }
}

/* make_rq_as from the first borrower. */
static void make_rq(wt_ffa_mem_retrieve_req_t* rq,
                    const wt_ffa_mem_handle_entry_t* e, uint32_t n)
{
    make_rq_as(rq, e, n, 0x8002u);
}

/* WT-FFA-0009 (a retrieve request held against its transaction, 2.4.1.2). */
static void retrieve_check_rows(void)
{
    static wt_ffa_mem_registry_t reg;
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_retrieve_req_t rq;

    check(wt_ffa_mem_type_flag((uint8_t)WT_FFA_MEM_STATE_SHARED) ==
              WT_FFA_MEM_FLAG_TYPE_SHARE &&
          wt_ffa_mem_type_flag((uint8_t)WT_FFA_MEM_STATE_LENT) ==
              WT_FFA_MEM_FLAG_TYPE_LEND &&
          wt_ffa_mem_type_flag((uint8_t)WT_FFA_MEM_STATE_DONATED) ==
              WT_FFA_MEM_FLAG_TYPE_DONATE,
          "each live handle state reports its transaction type");

    e = make_entry(&reg, WT_FFA_MEM_OP_LEND, 1u);
    check(e != NULL, "a single-borrower lend registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 1u);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "a request naming the borrower with the owner's tag is accepted");
    rq.flags = WT_FFA_MEM_FLAG_TYPE_LEND;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "a request stating the transaction's own type is accepted");
    rq.flags = WT_FFA_MEM_FLAG_TYPE_SHARE;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a request stating another transaction type is INVALID_PARAMETERS");
    make_rq(&rq, e, 1u);
    rq.tag = 0x78ull;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a request with another tag is INVALID_PARAMETERS");
    make_rq(&rq, e, 1u);
    rq.flags = WT_FFA_MEM_FLAG_TIME_SLICE;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a retrieve flag the relayer does not implement is INVALID_PARAMETERS");
    make_rq(&rq, e, 1u);
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "the bypass flag with a single borrower is INVALID_PARAMETERS");
    make_rq(&rq, e, 1u);
    rq.attributes = (uint16_t)(WT_FFA_MEM_ATTR_TYPE_NORMAL |
                               WT_FFA_MEM_ATTR_CACHE_MASK |
                               WT_FFA_MEM_ATTR_SHARE_INNER | WT_FFA_MEM_ATTR_NS);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a request that sets the NS bit is INVALID_PARAMETERS");
    rq.attributes = (uint16_t)WT_FFA_MEM_ATTR_TYPE_DEVICE;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_DENIED,
          "a request for Device memory is DENIED");
    make_rq(&rq, e, 1u);
    rq.receivers[0] = 0x8009u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a request naming an endpoint that is not a borrower is INVALID_PARAMETERS");
    make_rq(&rq, e, 1u);
    rq.impdef[0][3] = 0x5Au;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a request that does not repeat the implementation-defined bytes is INVALID_PARAMETERS");

    e = make_entry(&reg, WT_FFA_MEM_OP_SHARE, 2u);
    check(e != NULL, "a two-borrower share registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 1u);
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "with several borrowers the bypass flag lets the caller name only itself");
}

/* WT-FFA-0009 (time slicing, DEN0140 4.1.3, is not implemented, so its flag
 * is INVALID_PARAMETERS in every call that carries it). */
static void time_slice_rows(void)
{
    static const wt_ffa_mem_op_t ops[3] = {
        WT_FFA_MEM_OP_SHARE, WT_FFA_MEM_OP_LEND, WT_FFA_MEM_OP_DONATE
    };
    static wt_ffa_mem_registry_t reg;
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_retrieve_req_t rq;
    wt_ffa_mem_txn_t txn;
    uint8_t buf[256];
    uint64_t h = 0u;
    uint16_t ep = 0u;
    size_t len = 0u;
    uint32_t i;
    int ok = 1;

    for (i = 0u; i < 3u; i++) {
        len = make_txn(buf, sizeof(buf), ops[i], WT_FFA_MEM_FLAG_TIME_SLICE);
        ok = ok && (len != 0u) &&
             (wt_ffa_mem_txn_validate(buf, len, ops[i], 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS);
    }
    check(ok, "a share, lend, or donate that asks for time slicing is INVALID_PARAMETERS");

    e = make_entry(&reg, WT_FFA_MEM_OP_LEND, 1u);
    check(e != NULL, "a lend to retrieve registers");
    if (e != NULL) {
        make_rq(&rq, e, 1u);
        rq.flags = WT_FFA_MEM_FLAG_TIME_SLICE;
        check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
                  WT_FFA_INVALID_PARAMETERS,
              "a retrieve request that asks for time slicing is INVALID_PARAMETERS");
    }

    (void)wt_ffa_mem_relinquish_build(buf, sizeof(buf), 0x1234ull, 0u, 0x8002u,
                                      &len);
    put32(&buf[8], WT_FFA_MEM_FLAG_TIME_SLICE);
    check(wt_ffa_mem_relinquish_parse(buf, len, &h, &ep) ==
              WT_FFA_INVALID_PARAMETERS,
          "a relinquish that asks for time slicing is INVALID_PARAMETERS");
    check(wt_ffa_mem_relinquish_build(buf, sizeof(buf), 0x1234ull,
                                      WT_FFA_MEM_FLAG_TIME_SLICE, 0x8002u,
                                      &len) == WT_FFA_INVALID_PARAMETERS,
          "the relinquish builder refuses the time-slicing flag");
    check(wt_ffa_mem_reclaim_flags_check(WT_FFA_MEM_FLAG_TIME_SLICE) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_reclaim_flags_check(WT_FFA_MEM_FLAG_TIME_SLICE |
                                         WT_FFA_MEM_RELINQ_FLAG_ZERO) ==
              WT_FFA_INVALID_PARAMETERS,
          "a reclaim that asks for time slicing is INVALID_PARAMETERS");
    check(wt_ffa_mem_reclaim_flags_check(0u) == 0 &&
          wt_ffa_mem_reclaim_flags_check(WT_FFA_MEM_RELINQ_FLAG_ZERO) == 0,
          "a reclaim may still ask for the memory to be zeroed");
    check(wt_ffa_mem_reclaim_flags_check(0xFFFFFFFCu) == 0,
          "the SBZ reclaim flag bits[31:2] are ignored (Table 2.31)");
}

/* WT-FFA-0009 (the Handle field of a lend/donate/share, 1.11.1: this SPMC
 * allocates every handle, so a sender leaves it zero). */
static void send_handle_rows(void)
{
    static const wt_ffa_mem_op_t ops[3] = {
        WT_FFA_MEM_OP_SHARE, WT_FFA_MEM_OP_LEND, WT_FFA_MEM_OP_DONATE
    };
    static uint8_t buf[256];
    static wt_ffa_mem_registry_t reg;
    wt_ffa_mem_txn_t txn;
    uint64_t h;
    size_t len = 0u;
    uint32_t i;
    int done = 0;
    int ok = 1;

    for (i = 0u; i < 3u; i++) {
        len = make_txn(buf, sizeof(buf), ops[i], 0u);
        ok = ok && (len != 0u) &&
             (wt_ffa_mem_send_validate(buf, len, ops[i], 0u, &txn) == 0);
    }
    check(ok, "a share, lend, or donate with a zero Handle field is accepted");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    put64(&buf[8], 0x55AAull);
    check(wt_ffa_mem_send_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a send naming a handle of its own is INVALID_PARAMETERS");
    put64(&buf[8], 0x8000000000000001ull);
    check(wt_ffa_mem_send_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a send carrying a Hypervisor-allocated handle is INVALID_PARAMETERS");
    check(wt_ffa_mem_send_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0x9999u,
                                   &txn) == WT_FFA_DENIED,
          "a send from the wrong sender is still DENIED first");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_LEND, 0u);
    wt_ffa_mem_registry_init(&reg);
    h = wt_ffa_mem_handle_reserve(&reg);
    ok = (wt_ffa_mem_frag_begin(&g_frag_row, h, 0u, (uint8_t)WT_FFA_MEM_OP_LEND,
                                buf, 40u, (uint32_t)len) == 0) &&
         (wt_ffa_mem_frag_add(&g_frag_row, h, 0u, &buf[40],
                              (uint32_t)len - 40u, &done) == 0) &&
         (done == 1);
    check(ok && (h != 0u) &&
          (wt_ffa_mem_send_validate(g_frag_row.buf, g_frag_row.total,
                                    WT_FFA_MEM_OP_LEND, 0u, &txn) == 0),
          "a fragmented send passes with its reserved handle held outside the descriptor");
    wt_ffa_mem_frag_reset(&g_frag_row);
}

/* WT-FFA-0009 (memory region attribute encodings, Table 1.18). */
static void attribute_rows(void)
{
    static const uint16_t valid[] = {
        0x00u, 0x24u, 0x26u, 0x27u, 0x2Cu, 0x2Eu, 0x2Fu,
        0x10u, 0x14u, 0x18u, 0x1Cu
    };
    static const uint16_t invalid[] = {
        0x20u, 0x23u, 0x28u, 0x2Bu, 0x25u, 0x2Du,
        0x11u, 0x1Fu, 0x04u, 0x01u, 0x30u
    };
    static wt_ffa_mem_registry_t reg;
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_retrieve_req_t rq;
    wt_ffa_mem_txn_t txn;
    uint8_t buf[256];
    size_t len;
    size_t i;
    int ok;

    ok = 1;
    for (i = 0u; i < sizeof(valid) / sizeof(valid[0]); i++) {
        ok = ok && (wt_ffa_mem_attributes_check(valid[i]) == 0);
    }
    check(ok, "Normal non-cacheable or write-back memory of any defined shareability, Device memory, and an unspecified type are valid");
    ok = 1;
    for (i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        ok = ok && (wt_ffa_mem_attributes_check(invalid[i]) ==
                    WT_FFA_INVALID_PARAMETERS);
    }
    check(ok, "reserved cacheability, reserved shareability, non-zero reserved bits, and the reserved type are INVALID_PARAMETERS");

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[2] = 0x2Bu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share of Normal memory with a reserved cacheability is INVALID_PARAMETERS");
    buf[2] = 0x2Du;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share of Normal memory with the reserved shareability is INVALID_PARAMETERS");
    buf[2] = 0x13u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share of Device memory with shareability bits set is INVALID_PARAMETERS");
    buf[2] = 0x1Cu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) == 0,
          "a share of Device-GRE memory is well formed");
    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_LEND, 0u);
    buf[2] = 0x0Fu;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "an unspecified type with cacheability or shareability bits set is INVALID_PARAMETERS");
    buf[2] = 0x00u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) == 0,
          "an unspecified type with its reserved bits clear is well formed");

    e = make_entry(&reg, WT_FFA_MEM_OP_SHARE, 1u);
    check(e != NULL, "a share to retrieve registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 1u);
    rq.attributes = 0x2Fu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "a retrieve request for Normal write-back inner-shareable memory is accepted");
    rq.attributes = 0x30u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a retrieve request for the reserved memory type is INVALID_PARAMETERS");
    rq.attributes = 0x2Bu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a retrieve request with a reserved Normal cacheability is INVALID_PARAMETERS");
    rq.attributes = 0x0Cu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_INVALID_PARAMETERS,
          "a retrieve request with an unspecified type and cacheability bits set is INVALID_PARAMETERS");
    rq.attributes = 0x1Fu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_DENIED,
          "a retrieve request for Device memory is DENIED before its reserved bits are read");
    rq.attributes = 0x2Eu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_DENIED,
          "a retrieve request for outer-shareable memory the lender made inner-shareable is DENIED");
    rq.attributes = 0x27u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a retrieve request for non-cacheable memory, which the relayer cannot map, is INVALID_PARAMETERS");
    rq.attributes = 0x2Cu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a retrieve request for non-shareable memory, which the relayer cannot map, is INVALID_PARAMETERS");
    rq.attributes = 0x00u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "a retrieve request that leaves the attributes unspecified is accepted");
    wt_ffa_mem_handle_set_attributes(&reg, e->handle, 0u);
    rq.attributes = 0x2Fu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_DENIED,
          "a transaction with no recorded attributes is held to none");
}

/* WT-FFA-0009 (the attributes a lend or share names are those every borrower
 * maps with, DEN0140 1.10.4.2). */
static void send_attribute_rows(void)
{
    static const uint16_t denied[] = { 0x2Eu, 0x26u };
    static const uint16_t unmappable[] = {
        0x27u, 0x24u, 0x2Cu, 0x10u, 0x14u, 0x18u, 0x1Cu
    };
    uint16_t out = 0u;
    size_t i;
    int ok;

    check(wt_ffa_mem_send_attributes(0x00u, &out) == 0 &&
          out == (uint16_t)WT_FFA_MEM_ATTR_RELAYER,
          "a send that leaves the attributes unspecified gets the relayer's Normal write-back inner-shareable");
    out = 0u;
    check(wt_ffa_mem_send_attributes(0x2Fu, &out) == 0 && out == 0x2Fu,
          "a send of Normal write-back inner-shareable memory keeps its attributes");
    ok = 1;
    for (i = 0u; i < sizeof(denied) / sizeof(denied[0]); i++) {
        ok = ok && (wt_ffa_mem_send_attributes(denied[i], &out) == WT_FFA_DENIED);
    }
    check(ok, "a send of outer-shareable memory, more permissive than the relayer maps, is DENIED");
    ok = 1;
    for (i = 0u; i < sizeof(unmappable) / sizeof(unmappable[0]); i++) {
        ok = ok && (wt_ffa_mem_send_attributes(unmappable[i], &out) ==
                    WT_FFA_INVALID_PARAMETERS);
    }
    check(ok, "a send of non-cacheable, non-shareable, or Device memory, which the relayer cannot map, is INVALID_PARAMETERS");
    check(wt_ffa_mem_send_attributes(0x2Bu, &out) == WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_send_attributes(0x6Fu, &out) == WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_mem_send_attributes(0x2Fu, NULL) == WT_FFA_INVALID_PARAMETERS,
          "a reserved encoding, the NS bit, or no output is INVALID_PARAMETERS");
}

/* WT-FFA-0009 (the endpoint access descriptor flags byte, 1.10.1). */
static void access_flag_rows(void)
{
    static wt_ffa_mem_registry_t reg;
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_retrieve_req_t rq;
    wt_ffa_mem_txn_t txn;
    uint8_t buf[256];
    size_t len = 0u;

    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_SHARE, 0u);
    buf[48u + WT_FFA_MEM_ACC_OFF_FLAGS] = WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_SHARE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "a share whose access descriptor sets a flag is INVALID_PARAMETERS");
    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_LEND, 0u);
    buf[48u + WT_FFA_MEM_ACC_OFF_FLAGS] = 0x80u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "every bit of a lend's access descriptor flags is MBZ");
    len = make_txn(buf, sizeof(buf), WT_FFA_MEM_OP_DONATE, 0u);
    buf[48u + WT_FFA_MEM_ACC_OFF_FLAGS] = 0x02u;
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_DONATE, 0u, &txn) ==
              WT_FFA_INVALID_PARAMETERS,
          "every bit of a donate's access descriptor flags is MBZ");

    (void)wt_ffa_mem_retrieve_req_build(buf, sizeof(buf), 0x77ull, 0u, 0x8002u,
                                        0x02u, &len);
    buf[48u + WT_FFA_MEM_ACC_OFF_FLAGS] = 0x81u;
    check(wt_ffa_mem_retrieve_req_parse_ex(buf, len, &rq) == 0 &&
          rq.access_flags[0] == 0x81u,
          "a retrieve request yields each access descriptor's flags");

    e = make_entry(&reg, WT_FFA_MEM_OP_LEND, 1u);
    check(e != NULL, "a single-borrower lend registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 1u);
    rq.access_flags[0] = WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "the only borrower marking itself a non-retrieval borrower is INVALID_PARAMETERS");
    rq.access_flags[0] = 0xFEu;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "the SBZ flag bits of a retrieve request are ignored");

    e = make_entry(&reg, WT_FFA_MEM_OP_SHARE, 2u);
    check(e != NULL, "a two-borrower share registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 2u);
    rq.access_flags[1] = 0u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "naming the other borrower without the non-retrieval flag is INVALID_PARAMETERS");
    rq.access_flags[1] = WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "naming the other borrower as a non-retrieval borrower is accepted");
    rq.access_flags[0] = WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "the caller's own entry marked a non-retrieval borrower is INVALID_PARAMETERS");
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) ==
              WT_FFA_INVALID_PARAMETERS,
          "the rule follows the caller, whichever entry is its own");
    rq.access_flags[1] = 0u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) == 0,
          "the second borrower retrieves with the first marked non-retrieval");
    make_rq(&rq, e, 1u);
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    rq.receiver_count = 2u;
    rq.receivers[1] = 0x8003u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "the bypass flag does not excuse another borrower's clear flag");
}

/* WT-FFA-0009 (without the bypass flag a retrieve request names the lender's
 * whole borrower list, 1.11.3.3 and Table 1.22 bit[10]). */
static void borrower_list_rows(void)
{
    static wt_ffa_mem_registry_t reg;
    const wt_ffa_mem_handle_entry_t* e;
    wt_ffa_mem_retrieve_req_t rq;

    e = make_entry(&reg, WT_FFA_MEM_OP_LEND, 2u);
    check(e != NULL, "a two-borrower lend registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 2u);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "the first borrower naming both borrowers is accepted");
    make_rq_as(&rq, e, 2u, 0x8003u);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) == 0,
          "the second borrower naming both borrowers is accepted");
    make_rq(&rq, e, 2u);
    rq.receivers[0] = 0x8003u;
    rq.receivers[1] = 0x8002u;
    rq.access_flags[0] = WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
    rq.access_flags[1] = 0u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "the borrowers may be named in any order");
    make_rq(&rq, e, 2u);
    rq.permissions[1] = WT_FFA_MEM_PERM_DATA_RO;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == WT_FFA_DENIED,
          "naming the other borrower with access the lender did not give it is DENIED");
    rq.permissions[1] = WT_FFA_MEM_PERM_DATA_RW;
    rq.permissions[0] = WT_FFA_MEM_PERM_DATA_RO;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "the caller's own entry may ask for less; the other's data access matches");
    rq.permissions[1] = WT_FFA_MEM_PERM_DATA_RW | WT_FFA_MEM_PERM_INSTR_NX;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "naming the other borrower's instruction access is INVALID_PARAMETERS (1.10.3 item 1)");
    rq.permissions[1] = WT_FFA_MEM_PERM_DATA_RW | WT_FFA_MEM_PERM_INSTR_X;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "so is naming it executable");
    rq.permissions[1] = WT_FFA_MEM_PERM_DATA_RSVD;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "and a reserved data access for the other borrower");
    make_rq(&rq, e, 1u);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "naming only itself without the bypass flag is INVALID_PARAMETERS");
    make_rq(&rq, e, 2u);
    rq.receivers[1] = 0x8002u;
    rq.access_flags[1] = 0u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "naming one borrower twice in place of the other is INVALID_PARAMETERS");
    make_rq(&rq, e, 3u);
    rq.receivers[2] = 0x8004u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "naming an endpoint the lender did not name is INVALID_PARAMETERS");
    make_rq(&rq, e, 1u);
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) == 0,
          "with the bypass flag the caller may still name only itself");

    e = make_entry(&reg, WT_FFA_MEM_OP_SHARE, 3u);
    check(e != NULL, "a three-borrower share registers");
    if (e == NULL) {
        return;
    }
    make_rq_as(&rq, e, 3u, 0x8003u);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) == 0,
          "naming all three borrowers is accepted");
    make_rq_as(&rq, e, 2u, 0x8003u);
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) ==
              WT_FFA_INVALID_PARAMETERS,
          "leaving a borrower out is INVALID_PARAMETERS");
    make_rq_as(&rq, e, 3u, 0x8003u);
    rq.receivers[2] = 0x8003u;
    rq.access_flags[2] = 0u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a repeat that hides a missing borrower is INVALID_PARAMETERS");
    make_rq_as(&rq, e, 2u, 0x8003u);
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) ==
              WT_FFA_INVALID_PARAMETERS,
          "with the bypass flag, naming itself and one other borrower is INVALID_PARAMETERS");
    make_rq_as(&rq, e, 3u, 0x8003u);
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) ==
              WT_FFA_INVALID_PARAMETERS,
          "with the bypass flag, naming every borrower is INVALID_PARAMETERS too");
    make_rq_as(&rq, e, 1u, 0x8003u);
    rq.receivers[0] = 0x8003u;
    rq.access_flags[0] = 0u;
    rq.flags = WT_FFA_MEM_FLAG_BYPASS_BORROWERS;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8003u) == 0,
          "with the bypass flag the second borrower names only itself");

    e = make_entry(&reg, WT_FFA_MEM_OP_LEND, 1u);
    check(e != NULL, "a single-borrower lend registers");
    if (e == NULL) {
        return;
    }
    make_rq(&rq, e, 2u);
    rq.receivers[1] = 0x8002u;
    rq.access_flags[1] = 0u;
    check(wt_ffa_mem_retrieve_req_check(e, &rq, 0x8002u) ==
              WT_FFA_INVALID_PARAMETERS,
          "a single borrower naming itself twice is INVALID_PARAMETERS");
}

static uint32_t get32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* A single-receiver retrieve request in the FF-A v1.0 layout (DEN0140 Table
 * 4.17): a 32-byte header, then one 16-byte access descriptor. */
static size_t v10_retrieve_req(uint8_t* buf, uint64_t handle, uint16_t owner,
                               uint16_t receiver, uint8_t perms)
{
    memset(buf, 0, 48u);
    buf[WT_FFA_MEM_TXN_OFF_SENDER] = (uint8_t)(owner & 0xFFu);
    buf[WT_FFA_MEM_TXN_OFF_SENDER + 1u] = (uint8_t)(owner >> 8);
    put64(&buf[WT_FFA_MEM_TXN_OFF_HANDLE], handle);
    put32(&buf[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 1u);
    buf[32] = (uint8_t)(receiver & 0xFFu);
    buf[33] = (uint8_t)(receiver >> 8);
    buf[32u + WT_FFA_MEM_ACC_OFF_PERMS] = perms;
    return 48u;
}

/* WT-FFA-0009 (a v1.0 caller's memory transaction descriptors use the v1.0
 * layout, DEN0077A 18.5.3 and DEN0140 4.2.1). */
static void v10_rows(void)
{
    static const wt_ffa_mem_constituent_t cons[1] = { { 0x40000000ull, 2u } };
    wt_ffa_mem_build_t in;
    wt_ffa_mem_txn_t txn;
    wt_ffa_mem_retrieve_req_t rq;
    uint8_t buf[128];
    uint8_t req[64];
    uint64_t size = 0u;
    size_t len = 0u;

    memset(&in, 0, sizeof(in));
    in.constituents = cons;
    in.constituent_count = 1u;
    in.op = WT_FFA_MEM_OP_LEND;
    in.sender = 0x8002u;
    in.receiver = 0x8003u;
    in.permissions = WT_FFA_MEM_PERM_DATA_RW;
    in.version = V10;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) == 0 &&
              len == 80u && get32(&buf[24]) == 0u && get32(&buf[28]) == 1u &&
              buf[32] == 0x03u && buf[33] == 0x80u &&
              get32(&buf[32u + WT_FFA_MEM_ACC_OFF_COMP_OFF]) == 48u &&
              get32(&buf[48]) == 2u && get32(&buf[64]) == 0x40000000u,
          "v1.0: a descriptor for a v1.0 reader has no access descriptor size "
          "or offset, and its access descriptors start at 32 (Table 4.17)");
    check(wt_ffa_mem_txn_validate_at(buf, len, WT_FFA_MEM_OP_LEND, 0x8002u,
                                     V10, &txn) == 0 &&
              txn.access_offset == 32u && txn.access_desc_size == 16u &&
              txn.composite_offset == 48u && txn.total_page_count == 2u,
          "v1.0: a v1.0 caller's lend is read in its own layout (18.5.3)");
    check(wt_ffa_mem_txn_validate(buf, len, WT_FFA_MEM_OP_LEND, 0x8002u,
                                  &txn) != 0,
          "v1.0: the same bytes are no Table 1.20 descriptor");
    check((wt_ffa_mem_frag_expected_at(buf, 64u, 0, V10, &size) == 1) &&
              (size == (uint64_t)len),
          "v1.0: a first fragment in the v1.0 layout names the whole length");
    buf[24] = 1u;
    check(wt_ffa_mem_txn_validate_at(buf, len, WT_FFA_MEM_OP_LEND, 0x8002u,
                                     V10, &txn) == WT_FFA_INVALID_PARAMETERS,
          "v1.0: the reserved word at offset 24 is MBZ");
    buf[24] = 0u;
    buf[3] = 1u;
    check(wt_ffa_mem_txn_validate_at(buf, len, WT_FFA_MEM_OP_LEND, 0x8002u,
                                     V10, &txn) == WT_FFA_INVALID_PARAMETERS,
          "v1.0: the reserved byte after the one-byte attributes is MBZ");
    in.version = 0u;
    check(wt_ffa_mem_txn_build(buf, sizeof(buf), &in, &len) == 0 &&
              wt_ffa_mem_txn_validate_at(buf, len, WT_FFA_MEM_OP_LEND, 0x8002u,
                                         V10, &txn) ==
                  WT_FFA_INVALID_PARAMETERS,
          "v1.0: a Table 1.20 descriptor from a v1.0 caller is refused");

    len = v10_retrieve_req(req, 0x1234ull, 0x8002u, 0x8003u,
                           WT_FFA_MEM_PERM_DATA_RW);
    check(wt_ffa_mem_retrieve_req_parse_at(req, len, V10, &rq) == 0 &&
              rq.receiver_count == 1u && rq.receivers[0] == 0x8003u &&
              rq.access_desc_size == 16u && rq.handle == 0x1234ull &&
              rq.sender == 0x8002u &&
              rq.permissions[0] == WT_FFA_MEM_PERM_DATA_RW,
          "v1.0: a v1.0 retrieve request is read in its own layout");
    check(wt_ffa_mem_retrieve_req_parse_ex(req, len, &rq) ==
              WT_FFA_NOT_SUPPORTED,
          "v1.0: the same request read as Table 1.20 names no access "
          "descriptor size");
    check((wt_ffa_mem_frag_expected_at(req, 40u, 1, V10, &size) == 1) &&
              (size == (uint64_t)len),
          "v1.0: a v1.0 retrieve request's first fragment names its length");
    (void)memset(req, 0xA5, sizeof(req));
    check(wt_ffa_mem_retrieve_req_build_at(req, sizeof(req), 0x1234ull,
                                           0x8002u, 0x8003u,
                                           WT_FFA_MEM_PERM_DATA_RW, V10,
                                           &len) == 0 &&
              len == 48u && get32(&req[24]) == 0u && get32(&req[28]) == 1u &&
              req[32] == 0x03u && req[33] == 0x80u &&
              wt_ffa_mem_retrieve_req_parse_at(req, len, V10, &rq) == 0 &&
              rq.receiver_count == 1u && rq.receivers[0] == 0x8003u &&
              rq.handle == 0x1234ull && rq.sender == 0x8002u &&
              rq.permissions[0] == WT_FFA_MEM_PERM_DATA_RW,
          "v1.0: a retrieve request built for a v1.0 reader has the 32-byte "
          "header and parses in the v1.0 layout (Table 4.17)");
}

/* The relayer maps and zeroes memory at its own address (VA == PA), so the
 * host backs the partitions' pages with memory below the table VA limit. */
#define RELAY_MEM_PAGES  16u
#define RELAY_POOL_PAGES 64u
#define RELAY_POOL_PA    0x0E100000ull
#define RELAY_ID_A       0x8002u
#define RELAY_ID_B       0x8003u
#define RELAY_ID_C       0x8004u
#define RELAY_RW         (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE)
/* Pages of the host backing: A's manifest-shared page, the image page every
 * partition maps, A's read-write pages 2-5, A's read-only page, A's own code
 * page, B's and C's own pages, the Normal world's window (10-11), A's Device
 * page, and A's page no fill entry names. Every other table holds each
 * partition's pages and the window as SPMC EL1-only fill entries, except
 * PG_GAP, which only A's table maps. */
#define PG_SHARED 0u
#define PG_IMAGE  1u
#define PG_FILL   2u
#define PG_RW     3u
#define PG_FILL2  5u
#define PG_RO     6u
#define PG_RX     7u
#define PG_B      8u
#define PG_DEV    12u
#define PG_C      9u
#define PG_NS     10u
#define PG_GAP    13u

static uint8_t g_relay_pool[RELAY_POOL_PAGES * WT_TABLES_PAGE_SIZE]
    __attribute__((aligned(4096)));
static uint8_t* g_mem;
static wt_memory_region_t g_relay_fill[8];
static wt_secure_domain_t g_dom_a;
static wt_secure_domain_t g_dom_b;
static wt_secure_domain_t g_dom_c;
static int g_co_a;
static int g_co_b;
static int g_co_c;
static unsigned int g_domain_fails;
static unsigned int g_cleans;
static uint64_t g_clean_va;
static uint64_t g_clean_size;
static int g_clean_zeroed;
static int g_clean_a_access;

#define CO_A ((struct wt_co*)(void*)&g_co_a)
#define CO_B ((struct wt_co*)(void*)&g_co_b)
#define CO_C ((struct wt_co*)(void*)&g_co_c)

void wt_mmu_switch_ttbr0(uint64_t ttbr0)
{
    (void)ttbr0;
}

void wt_mmu_tlbi_asid(uint64_t asid)
{
    (void)asid;
}

/* Records the last range the relayer cleaned, and whether it still held the
 * zeros when it did. */
void wt_mmu_dcache_clean_inval(uint64_t va, uint64_t size)
{
    const uint8_t* p = (const uint8_t*)(uintptr_t)va;
    uint64_t i;

    g_cleans++;
    g_clean_va = va;
    g_clean_size = size;
    g_clean_a_access = wt_domain_page_access(g_dom_a.regions,
                                             g_dom_a.region_count,
                                             (uintptr_t)va);
    g_clean_zeroed = 1;
    for (i = 0u; i < size; i++) {
        if (p[i] != 0u) {
            g_clean_zeroed = 0;
        }
    }
}

static unsigned int g_syncs;
static uint64_t g_sync_va;
static uint64_t g_sync_size;

/* Records the last range made fetchable after EL0 was let execute it. */
void wt_mmu_sync_icache(uint64_t va, uint64_t size)
{
    g_syncs++;
    g_sync_va = va;
    g_sync_size = size;
}

void wt_domain_fail(int code)
{
    (void)code;
    g_domain_fails++;
}

struct wt_co* wt_spm_sp_by_ffa_id(uint16_t id)
{
    (void)id;
    return NULL;
}

/* The partition the rows have taken out of service, if any. */
static const struct wt_co* g_aborted_co;

int32_t wt_spm_sp_unavailable(const struct wt_co* co)
{
    return ((co != NULL) && (co == g_aborted_co)) ? WT_FFA_ABORTED : 0;
}

/* The one RX/TX pair the rows map, standing in for every endpoint's. */
static wt_ffa_mailbox_t g_relay_mailbox;

/* A byte a racing Normal world rewrites in its TX buffer, landing at the
 * relayer's first mailbox check: after validation, before registration. */
static uint8_t* g_race_at;
static uint8_t g_race_to;

int wt_spm_mailbox_overlaps(uint64_t base, uint64_t size)
{
    if (g_race_at != NULL) {
        *g_race_at = g_race_to;
        g_race_at = NULL;
    }
    return wt_ffa_mailbox_overlaps(&g_relay_mailbox, base, size);
}

/* The versions A, B, and the Normal world negotiated, and whether B asked for
 * the NS bit, as the SVC gate and the SPMC report them. */
static uint32_t g_ver_a = WT_FFA_VERSION_1_2;
static uint32_t g_ver_b = WT_FFA_VERSION_1_2;
static uint32_t g_ver_ns = WT_FFA_VERSION_1_2;
static int g_ns_bit_b;

uint32_t wt_spm_sp_ffa_version(const struct wt_co* co)
{
    if (co == CO_A) {
        return g_ver_a;
    }
    return (co == CO_B) ? g_ver_b : WT_FFA_VERSION_1_2;
}

uint32_t wt_spm_ns_ffa_version(void)
{
    return g_ver_ns;
}

int wt_spm_sp_ffa_ns_bit(const struct wt_co* co)
{
    return wt_ffa_ns_bit_used(wt_spm_sp_ffa_version(co),
                              (co == CO_B) ? g_ns_bit_b : 0);
}

static uintptr_t page(unsigned int i);
static int cleaned(unsigned int pg);

size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max)
{
    if ((regions == NULL) || (max < 1u)) {
        return 0u;
    }
    regions[0].base = page(PG_IMAGE);
    regions[0].size = WT_TABLES_PAGE_SIZE;
    regions[0].attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
    return 1u;
}

static uint8_t* low_pages(size_t size)
{
    static const uint64_t hints[] = {
        0x10000000ull, 0x800000000ull, 0x2000000000ull, 0x40000000ull
    };
    void* p;
    size_t i;

    for (i = 0u; i < sizeof(hints) / sizeof(hints[0]); i++) {
        p = mmap((void*)(uintptr_t)hints[i], size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANON, -1, 0);
        if ((p != MAP_FAILED) &&
            (((uint64_t)(uintptr_t)p + size) <= WT_TABLES_VA_LIMIT)) {
            return (uint8_t*)p;
        }
        if (p != MAP_FAILED) {
            (void)munmap(p, size);
        }
    }
    return NULL;
}

static uintptr_t page(unsigned int i)
{
    return (uintptr_t)g_mem + ((uintptr_t)i * WT_TABLES_PAGE_SIZE);
}

static void set_region(wt_memory_region_t* r, unsigned int first,
                       unsigned int pages, uint32_t attributes)
{
    r->base = page(first);
    r->size = (size_t)pages * WT_TABLES_PAGE_SIZE;
    r->attributes = attributes;
}

static int relay_reset(void)
{
    (void)memset(g_mem, 0, (size_t)RELAY_MEM_PAGES * WT_TABLES_PAGE_SIZE);
    (void)memset(&g_dom_a, 0, sizeof(g_dom_a));
    (void)memset(&g_dom_b, 0, sizeof(g_dom_b));
    (void)memset(&g_dom_c, 0, sizeof(g_dom_c));
    set_region(&g_dom_a.regions[0], PG_FILL, 4u, RELAY_RW);
    set_region(&g_dom_a.regions[1], PG_RO, 1u, WT_MEM_ATTR_READ);
    set_region(&g_dom_a.regions[2], PG_SHARED, 1u,
               RELAY_RW | WT_MEMORY_ATTR_SHARED);
    set_region(&g_dom_a.regions[3], PG_IMAGE, 1u,
               WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC);
    set_region(&g_dom_a.regions[4], PG_RX, 1u,
               WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC);
    set_region(&g_dom_a.regions[5], PG_DEV, 1u,
               RELAY_RW | WT_MEM_ATTR_DEVICE);
    set_region(&g_dom_a.regions[6], PG_GAP, 1u, RELAY_RW);
    g_dom_a.region_count = 7u;
    set_region(&g_dom_b.regions[0], PG_B, 1u, RELAY_RW);
    g_dom_b.region_count = 1u;
    set_region(&g_dom_c.regions[0], PG_C, 1u, RELAY_RW);
    g_dom_c.region_count = 1u;
    set_region(&g_relay_fill[0], PG_FILL, 1u,
               RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[1], PG_FILL2, 1u,
               RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[2], PG_RW, 2u, RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[3], PG_RO, 1u, RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[4], PG_RX, 1u, RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[5], PG_B, 1u, RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[6], PG_C, 1u, RELAY_RW | WT_DOMAIN_FILL_SHARED);
    set_region(&g_relay_fill[7], PG_NS, 2u,
               RELAY_RW | WT_TABLES_ATTR_NS | WT_TABLES_ATTR_NG);
    g_domain_fails = 0u;
    if (wt_domain_init(g_relay_fill, 8u, g_relay_pool, RELAY_POOL_PA,
                       sizeof(g_relay_pool)) == 0u) {
        return 0;
    }
    wt_arch_program_sp_thread_domain(g_dom_a.regions, g_dom_a.region_count);
    wt_arch_program_sp_thread_domain(g_dom_b.regions, g_dom_b.region_count);
    wt_arch_program_sp_thread_domain(g_dom_c.regions, g_dom_c.region_count);
    wt_spm_mem_init();
    return (wt_spm_mem_bind(RELAY_ID_A, CO_A, &g_dom_a) == 0) &&
           (wt_spm_mem_bind(RELAY_ID_B, CO_B, &g_dom_b) == 0) &&
           (wt_spm_mem_bind(RELAY_ID_C, CO_C, &g_dom_c) == 0) &&
           (g_domain_fails == 0u);
}

/* A descriptor sending n constituents from A to B with the given memory
 * region attributes. */
static int relay_build_attrs(uint8_t* desc, size_t cap, wt_ffa_mem_op_t op,
                             const wt_ffa_mem_constituent_t* c, uint32_t n,
                             uint8_t perms, uint32_t flags, uint16_t attributes,
                             size_t* len)
{
    wt_ffa_mem_build_t in;

    (void)memset(&in, 0, sizeof(in));
    in.constituents = c;
    in.constituent_count = n;
    in.op = op;
    in.sender = RELAY_ID_A;
    in.receiver = RELAY_ID_B;
    in.permissions = perms;
    in.flags = flags;
    in.attributes = attributes;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
    return wt_ffa_mem_txn_build(desc, cap, &in, len);
}

/* A descriptor sending n constituents from A to B. */
static int relay_build(uint8_t* desc, size_t cap, wt_ffa_mem_op_t op,
                       const wt_ffa_mem_constituent_t* c, uint32_t n,
                       uint8_t perms, uint32_t flags, size_t* len)
{
    return relay_build_attrs(desc, cap, op, c, n, perms, flags, 0u, len);
}

/* Send n constituents from A to B; *ret gets the relayer's answer. */
static uint64_t relay_send(wt_ffa_mem_op_t op, const wt_ffa_mem_constituent_t* c,
                           uint32_t n, uint8_t perms, uint32_t flags, int* ret)
{
    uint8_t desc[256];
    uint64_t h = 0u;
    size_t len = 0u;

    *ret = relay_build(desc, sizeof(desc), op, c, n, perms, flags, &len);
    if (*ret == 0) {
        *ret = wt_spm_mem_share(desc, len, op, RELAY_ID_A, &h);
    }
    return h;
}

static int relay_retrieve(uint64_t h, uint8_t perms, uint32_t flags)
{
    uint8_t req[128];
    uint8_t resp[256];
    size_t len = 0u;
    size_t resp_len = 0u;
    int ret;

    ret = wt_ffa_mem_retrieve_req_build(req, sizeof(req), h, RELAY_ID_A,
                                        RELAY_ID_B, perms, &len);
    if (ret == 0) {
        put32(&req[WT_FFA_MEM_TXN_OFF_FLAGS], flags);
        ret = wt_spm_mem_retrieve(req, len, RELAY_ID_B, resp, sizeof(resp),
                                  &resp_len);
    }
    return ret;
}

static int relay_relinquish(uint64_t h, uint32_t flags)
{
    uint8_t rel[32];
    size_t len = 0u;
    int ret;

    ret = wt_ffa_mem_relinquish_build(rel, sizeof(rel), h, flags, RELAY_ID_B,
                                      &len);
    if (ret == 0) {
        ret = wt_spm_mem_relinquish(rel, len, RELAY_ID_B);
    }
    return ret;
}

static int access_of(const wt_secure_domain_t* d, unsigned int pg)
{
    return wt_domain_page_access(d->regions, d->region_count, page(pg));
}

/* What B's table holds at a page it does not reach: 1 for an SPMC EL1-only
 * entry, -1 for anything else. Probed by a grant and its undo. */
static int b_entry(unsigned int pg)
{
    int was = -1;

    if (wt_domain_grant(g_dom_b.regions, g_dom_b.region_count, page(pg), 1u,
                        WT_MEM_ATTR_READ, &was) != WT_TABLES_OK) {
        return -1;
    }
    if (wt_domain_revoke(g_dom_b.regions, g_dom_b.region_count, page(pg), 1u,
                         was) != WT_TABLES_OK) {
        return -1;
    }
    return was;
}

/* WT-FFA-0009 (the SPMC relayer: a lend maps into the borrower on retrieve,
 * a relinquish unmaps it, a reclaim hands it back to the owner). */
static void relay_rows(void)
{
    wt_ffa_mem_constituent_t c[2];
    uint64_t h;
    int ret = 0;

    g_mem = low_pages((size_t)RELAY_MEM_PAGES * WT_TABLES_PAGE_SIZE);
    check(g_mem != NULL, "the host backs the relayer's pages below the table VA limit");
    if (g_mem == NULL) {
        return;
    }
    check(relay_reset(), "two bound partitions over real tables");

    c[0].address = page(PG_RW);
    c[0].page_count = 2u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 && access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          access_of(&g_dom_a, PG_RW + 2u) == WT_DOMAIN_ACCESS_RW,
          "relayer: a lend takes the lent pages, and only those, from the owner");
    check(relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW &&
          access_of(&g_dom_b, PG_RW + 1u) == WT_DOMAIN_ACCESS_RW,
          "relayer: a retrieve maps the lent pages into the borrower");
    check(relay_relinquish(h, 0u) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          b_entry(PG_RW) == 1,
          "relayer: a relinquish unmaps them from the borrower");
    c[1].address = page(PG_RW + 2u);
    c[1].page_count = 1u;
    g_aborted_co = CO_B;
    (void)relay_send(WT_FFA_MEM_OP_LEND, &c[1], 1u, WT_FFA_MEM_PERM_DATA_RW,
                     0u, &ret);
    g_aborted_co = NULL;
    check(ret == WT_FFA_ABORTED && access_of(&g_dom_a, PG_RW + 2u) ==
                                       WT_DOMAIN_ACCESS_RW,
          "relayer: a transaction naming a borrower that has aborted is ABORTED and takes nothing");
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW &&
          access_of(&g_dom_a, PG_RW + 1u) == WT_DOMAIN_ACCESS_RW,
          "relayer: a reclaim gives the owner its access back");
    check(relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) != 0,
          "relayer: a reclaimed handle cannot be retrieved");
    check(g_domain_fails == 0u, "relayer: no domain operation failed closed");
}

/* WT-FFA-0009 (only memory the sender owns outright may be sent, 10.10). */
static void relay_owner_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    clock_t t0;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "owner: fixture");
        return;
    }
    c[0].address = page(PG_IMAGE);
    c[0].page_count = 1u;
    (void)relay_send(WT_FFA_MEM_OP_SHARE, c, 1u, WT_FFA_MEM_PERM_DATA_RO, 0u,
                     &ret);
    check(ret == WT_FFA_DENIED,
          "owner: the image every partition maps is DENIED, though the sender reaches it");
    c[0].address = page(PG_SHARED);
    (void)relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                     &ret);
    check(ret == WT_FFA_DENIED &&
          access_of(&g_dom_a, PG_SHARED) == WT_DOMAIN_ACCESS_RW,
          "owner: a region the manifest marks shared is DENIED and stays mapped");
    c[0].address = page(PG_DEV);
    c[0].page_count = 1u;
    (void)relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                     &ret);
    check(ret == WT_FFA_DENIED &&
          wt_spm_mem_in_transaction(page(PG_DEV), WT_TABLES_PAGE_SIZE) == 0,
          "owner: a lend of the sender's own Device page is DENIED");
    (void)relay_send(WT_FFA_MEM_OP_DONATE, c, 1u,
                     WT_FFA_MEM_PERM_DATA_NOT_SPEC, 0u, &ret);
    check(ret == WT_FFA_DENIED &&
          wt_spm_mem_in_transaction(page(PG_DEV), WT_TABLES_PAGE_SIZE) == 0,
          "owner: so is a donate of it");
    c[0].address = page(PG_RW + 2u);
    c[0].page_count = 0xFFFFFFFFu;
    t0 = clock();
    (void)relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RO, 0u,
                     &ret);
    check(ret == WT_FFA_DENIED && ((clock() - t0) < CLOCKS_PER_SEC),
          "owner: a range running past the sender's pages is DENIED at the first page it lacks");
}

/* B's retrieve of h asking for the given attributes; *resp_attrs gets the
 * attributes the response reports. */
static int relay_retrieve_attrs(uint64_t h, uint16_t attributes,
                                uint16_t* resp_attrs)
{
    uint8_t req[128];
    uint8_t resp[256];
    size_t len = 0u;
    size_t resp_len = 0u;
    int ret;

    ret = wt_ffa_mem_retrieve_req_build(req, sizeof(req), h, RELAY_ID_A,
                                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW,
                                        &len);
    if (ret == 0) {
        req[WT_FFA_MEM_TXN_OFF_ATTRS] = (uint8_t)(attributes & 0xFFu);
        req[WT_FFA_MEM_TXN_OFF_ATTRS + 1u] = (uint8_t)(attributes >> 8);
        ret = wt_spm_mem_retrieve(req, len, RELAY_ID_B, resp, sizeof(resp),
                                  &resp_len);
    }
    if (ret == 0) {
        *resp_attrs = (uint16_t)(resp[WT_FFA_MEM_TXN_OFF_ATTRS] |
                                 (resp[WT_FFA_MEM_TXN_OFF_ATTRS + 1u] << 8));
    }
    return ret;
}

/* WT-FFA-0009 (a lend or share keeps the attributes its borrowers map with,
 * holds each retrieve request to them, and reports them, 1.10.4.2). */
static void relay_attr_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint64_t h = 0u;
    uint16_t got = 0u;
    size_t len = 0u;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "attr: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    (void)relay_build_attrs(desc, sizeof(desc), WT_FFA_MEM_OP_SHARE, c, 1u,
                            WT_FFA_MEM_PERM_DATA_RW, 0u, 0x27u, &len);
    check(wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_SHARE, RELAY_ID_A, &h) ==
              WT_FFA_INVALID_PARAMETERS,
          "attr: a share of non-cacheable memory, which the relayer cannot map, is INVALID_PARAMETERS");
    (void)relay_build_attrs(desc, sizeof(desc), WT_FFA_MEM_OP_SHARE, c, 1u,
                            WT_FFA_MEM_PERM_DATA_RW, 0u, 0x2Eu, &len);
    check(wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_SHARE, RELAY_ID_A, &h) ==
              WT_FFA_DENIED,
          "attr: a share of outer-shareable memory is DENIED");
    (void)relay_build_attrs(desc, sizeof(desc), WT_FFA_MEM_OP_SHARE, c, 1u,
                            WT_FFA_MEM_PERM_DATA_RW, 0u, 0x2Fu, &len);
    ret = wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_SHARE, RELAY_ID_A, &h);
    check(ret == 0,
          "attr: neither refused share held the page, and a Normal write-back inner-shareable share of it is accepted");
    check(relay_retrieve_attrs(h, 0x27u, &got) == WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
          "attr: a retrieve asking for non-cacheable memory is INVALID_PARAMETERS and maps nothing");
    check(relay_retrieve_attrs(h, 0x2Eu, &got) == WT_FFA_DENIED &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
          "attr: a retrieve asking for more than the lender gave is DENIED and maps nothing");
    check(relay_retrieve_attrs(h, 0x2Fu, &got) == 0 && got == 0x2Fu &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "attr: a retrieve asking for the lender's attributes maps them and reports them");
    check(relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "attr: the share ends");
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    got = 0u;
    check(ret == 0 && relay_retrieve_attrs(h, 0u, &got) == 0 && got == 0x2Fu &&
          relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "attr: a lend to one borrower reports the Normal write-back inner-shareable mapping the relayer chose");
    check(g_domain_fails == 0u, "attr: no domain operation failed closed");
}

/* WT-FFA-0009 (relinquish holds the zero flag against the access the borrower
 * was given at retrieve, Table 2.25 bit[0]). */
static void relay_perm_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t* p;
    uint64_t h;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "perm: fixture");
        return;
    }
    p = (uint8_t*)page(PG_RW);
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    p[0] = 0xA5u;
    check(ret == 0 && relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RO, 0u) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RO,
          "perm: a borrower granted read-write may retrieve read-only");
    check(relay_relinquish(h, WT_FFA_MEM_RELINQ_FLAG_ZERO) == WT_FFA_DENIED &&
          p[0] == 0xA5u && access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RO,
          "perm: a borrower that retrieved read-only is DENIED the zero flag at relinquish");
    check(relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 && p[0] == 0xA5u,
          "perm: it relinquishes without the flag and the owner reclaims the memory intact");
}

/* WT-FFA-0009 (each region goes back to exactly the entry it replaced, in the
 * borrower's table and in the owner's). */
static void relay_region_rows(void)
{
    wt_ffa_mem_constituent_t c[3];
    uint64_t h;
    uint32_t attrs = 0u;
    size_t used;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "region: fixture");
        return;
    }
    c[0].address = page(PG_FILL);
    c[0].page_count = 1u;
    c[1].address = page(PG_RW);
    c[1].page_count = 1u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 2u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 && relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          relay_relinquish(h, 0u) == 0 && b_entry(PG_FILL) == 1 &&
          b_entry(PG_RW) == 1 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "region: a relinquish puts back the SPMC's entry for every region");

    c[0].address = page(PG_GAP);
    used = wt_domain_pool_pages_used();
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == WT_FFA_NO_MEMORY &&
          access_of(&g_dom_b, PG_GAP) == WT_DOMAIN_ACCESS_NONE &&
          wt_domain_pool_pages_used() == used &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "region: a page the borrower's table does not map is never retrieved, and no table page is taken for it");

    c[0].address = page(PG_FILL);
    c[1].address = page(PG_RW);
    c[2].address = page(PG_GAP);
    c[2].page_count = 1u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 3u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == WT_FFA_NO_MEMORY &&
          b_entry(PG_FILL) == 1 && b_entry(PG_RW) == 1 &&
          access_of(&g_dom_b, PG_GAP) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "region: a retrieve that cannot map its last region puts back each earlier one as it was");

    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    c[1].address = page(PG_RO);
    c[1].page_count = 1u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 2u, WT_FFA_MEM_PERM_DATA_RO, 0u,
                   &ret);
    check(ret == 0 && access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          access_of(&g_dom_a, PG_RO) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW &&
          access_of(&g_dom_a, PG_RO) == WT_DOMAIN_ACCESS_RO,
          "region: a reclaim gives the owner back each region's own access");
    c[0].address = page(PG_RX);
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RO, 0u,
                   &ret);
    check(ret == 0 && access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_NONE &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RO, 0u) == 0 &&
          relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          wt_domain_get_permissions(g_dom_a.regions, g_dom_a.region_count,
                                    page(PG_RX), &attrs) == WT_TABLES_OK &&
          attrs == (WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC),
          "region: a reclaim gives the owner back its own code page executable");
    check(g_domain_fails == 0u, "region: no domain operation failed closed");
}

/* WT-FFA-0009 (a mapped RX/TX pair is never sent in a memory transaction, and
 * memory a transaction covers is never mapped as one, DEN0077A 7.2.2.2). */
static void relay_mailbox_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint64_t h;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "mailbox: fixture");
        return;
    }
    (void)memset(&g_relay_mailbox, 0, sizeof(g_relay_mailbox));
    (void)wt_ffa_mailbox_map(&g_relay_mailbox, page(PG_RW), page(PG_RW + 1u),
                             1u);
    c[0].address = page(PG_RW + 1u);
    c[0].page_count = 1u;
    (void)relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                     &ret);
    check(ret == WT_FFA_DENIED &&
          access_of(&g_dom_a, PG_RW + 1u) == WT_DOMAIN_ACCESS_RW,
          "mailbox: a lend of a mapped RX buffer is DENIED and the owner keeps it");
    c[0].address = page(PG_RW);
    (void)relay_send(WT_FFA_MEM_OP_DONATE, c, 1u,
                     WT_FFA_MEM_PERM_DATA_NOT_SPEC, 0u, &ret);
    check(ret == WT_FFA_DENIED,
          "mailbox: a donate of a mapped TX buffer is DENIED");
    (void)relay_send(WT_FFA_MEM_OP_SHARE, c, 1u, WT_FFA_MEM_PERM_DATA_RO, 0u,
                     &ret);
    check(ret == WT_FFA_DENIED, "mailbox: so is a share of it");
    (void)wt_ffa_mailbox_unmap(&g_relay_mailbox);
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 &&
          wt_spm_mem_in_transaction(page(PG_RW), WT_TABLES_PAGE_SIZE) != 0 &&
          wt_spm_mem_in_transaction(page(PG_RW + 1u), WT_TABLES_PAGE_SIZE) == 0,
          "mailbox: once unmapped the page is lent, and the lend keeps it from any pair");
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          wt_spm_mem_in_transaction(page(PG_RW), WT_TABLES_PAGE_SIZE) == 0,
          "mailbox: a reclaim frees it for one again");
}

/* WT-FFA-0009 (a donate hands over no more data access than the owner had on
 * every page of it, whatever order its regions come in, 1.10.2 item 2). */
static void relay_donate_rows(void)
{
    wt_ffa_mem_constituent_t c[2];
    uint64_t h;
    int ret = 0;
    int order;

    for (order = 0; order < 2; order++) {
        if ((g_mem == NULL) || !relay_reset()) {
            check(0, "donate: fixture");
            return;
        }
        c[order].address = page(PG_RW);
        c[order].page_count = 1u;
        c[1 - order].address = page(PG_RO);
        c[1 - order].page_count = 1u;
        h = relay_send(WT_FFA_MEM_OP_DONATE, c, 2u,
                       WT_FFA_MEM_PERM_DATA_NOT_SPEC, 0u, &ret);
        check(ret == 0 &&
              relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == WT_FFA_DENIED &&
              access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
              access_of(&g_dom_b, PG_RO) == WT_DOMAIN_ACCESS_NONE,
              (order == 0)
                  ? "donate: a read-write then read-only donate is DENIED to a read-write retrieve"
                  : "donate: a read-only then read-write donate is DENIED to a read-write retrieve");
        check(relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RO, 0u) == 0 &&
              access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RO &&
              access_of(&g_dom_b, PG_RO) == WT_DOMAIN_ACCESS_RO,
              "donate: the receiver maps every page read-only");
    }
    check(g_domain_fails == 0u, "donate: no domain operation failed closed");
}

/* Append C as a second receiver, with B's permissions, to the send descriptor
 * relay_build laid out in desc; returns the new length. */
static size_t add_receiver_c(uint8_t* desc, size_t len)
{
    const size_t acc = WT_FFA_MEM_TXN_HDR_SIZE;
    const size_t comp = acc + WT_FFA_MEM_ACCESS_SIZE;
    size_t i;

    for (i = len; i > comp; i--) {
        desc[i - 1u + WT_FFA_MEM_ACCESS_SIZE] = desc[i - 1u];
    }
    memcpy(&desc[comp], &desc[acc], WT_FFA_MEM_ACCESS_SIZE);
    desc[comp + WT_FFA_MEM_ACC_OFF_RECEIVER] = (uint8_t)(RELAY_ID_C & 0xFFu);
    desc[comp + WT_FFA_MEM_ACC_OFF_RECEIVER + 1u] = (uint8_t)(RELAY_ID_C >> 8);
    put32(&desc[acc + WT_FFA_MEM_ACC_OFF_COMP_OFF],
          (uint32_t)(comp + WT_FFA_MEM_ACCESS_SIZE));
    put32(&desc[comp + WT_FFA_MEM_ACC_OFF_COMP_OFF],
          (uint32_t)(comp + WT_FFA_MEM_ACCESS_SIZE));
    put32(&desc[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 2u);
    return len + WT_FFA_MEM_ACCESS_SIZE;
}

/* Append a second endpoint memory access descriptor naming id with perms. */
static size_t add_receiver_as(uint8_t* desc, size_t len, uint16_t id,
                              uint8_t perms)
{
    const size_t second = WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE;

    len = add_receiver_c(desc, len);
    desc[second + WT_FFA_MEM_ACC_OFF_RECEIVER] = (uint8_t)(id & 0xFFu);
    desc[second + WT_FFA_MEM_ACC_OFF_RECEIVER + 1u] = (uint8_t)(id >> 8);
    desc[second + WT_FFA_MEM_ACC_OFF_PERMS] = perms;
    return len;
}

/* A sends page pg to B with op, also naming itself with self_perms: first in
 * the list when self_first, else second. self_perms of 0xFF names only A. */
static int relay_self_send(wt_ffa_mem_op_t op, int self_first,
                           uint8_t self_perms, uint8_t b_perms,
                           unsigned int pg, uint64_t* h)
{
    wt_ffa_mem_constituent_t c[1];
    wt_ffa_mem_build_t in;
    uint8_t desc[256];
    size_t len = 0u;
    int ret;

    c[0].address = page(pg);
    c[0].page_count = 1u;
    (void)memset(&in, 0, sizeof(in));
    in.constituents = c;
    in.constituent_count = 1u;
    in.op = op;
    in.sender = RELAY_ID_A;
    in.receiver = (self_first != 0) ? RELAY_ID_A : RELAY_ID_B;
    in.permissions = (self_first != 0) ? self_perms : b_perms;
    in.attributes = (op == WT_FFA_MEM_OP_SHARE) ? 0x2Fu : 0u;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
    ret = wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len);
    if ((ret == 0) && (b_perms != 0xFFu)) {
        len = add_receiver_as(desc, len,
                              (self_first != 0) ? RELAY_ID_B : RELAY_ID_A,
                              (self_first != 0) ? b_perms : self_perms);
    }
    if (ret == 0) {
        ret = wt_spm_mem_share(desc, len, op, RELAY_ID_A, h);
    }
    return ret;
}

/* WT-FFA-0009 (a share may name the lender itself with the lower data access
 * it keeps meanwhile, 1.11.3.1 and 2.3.1.2 item 10). */
static void relay_self_rows(void)
{
    uint64_t h = 0u;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "self: fixture");
        return;
    }
    check(relay_self_send(WT_FFA_MEM_OP_SHARE, 0, WT_FFA_MEM_PERM_DATA_RO,
                          WT_FFA_MEM_PERM_DATA_RW, PG_RW, &h) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RO &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "self: a share naming the lender read-only leaves it reading and the borrower writing");
    check(wt_domain_set_permissions(g_dom_a.regions, g_dom_a.region_count,
                                    page(PG_RW), 1u, RELAY_RW) !=
              WT_TABLES_OK &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RO,
          "self: the lender cannot re-permission the page while it is shared");
    check(relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "self: a reclaim gives the lender its write access back");
    check(relay_self_send(WT_FFA_MEM_OP_SHARE, 1, WT_FFA_MEM_PERM_DATA_RO,
                          WT_FFA_MEM_PERM_DATA_RW, PG_RW, &h) == 0 &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "self: the borrower keeps the access it was given when the lender comes first");
    g_cleans = 0u;
    check(relay_self_send(WT_FFA_MEM_OP_SHARE, 0, WT_FFA_MEM_PERM_DATA_RO,
                          WT_FFA_MEM_PERM_DATA_RW, PG_RW, &h) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, WT_FFA_MEM_RELINQ_FLAG_ZERO) == 0 &&
          cleaned(PG_RW) && g_clean_a_access == WT_DOMAIN_ACCESS_NONE &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "self: a reclaim that zeroes a page the lender kept reading wipes it with no EL0 access left, then gives write access back");
    check(relay_self_send(WT_FFA_MEM_OP_SHARE, 0, WT_FFA_MEM_PERM_DATA_RW,
                          WT_FFA_MEM_PERM_DATA_RO, PG_RO, &h) ==
              WT_FFA_DENIED &&
          access_of(&g_dom_a, PG_RO) == WT_DOMAIN_ACCESS_RO,
          "self: a lender cannot name itself more access than it has");
    check(relay_self_send(WT_FFA_MEM_OP_SHARE, 0,
                          (uint8_t)(WT_FFA_MEM_PERM_DATA_RO |
                                    WT_FFA_MEM_PERM_INSTR_NX),
                          WT_FFA_MEM_PERM_DATA_RW, PG_RW, &h) ==
              WT_FFA_INVALID_PARAMETERS,
          "self: its instruction access is the relayer's and stays unspecified");
    check(relay_self_send(WT_FFA_MEM_OP_LEND, 0, WT_FFA_MEM_PERM_DATA_RO,
                          WT_FFA_MEM_PERM_DATA_RW, PG_RW, &h) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "self: only a share names the lender");
    check(relay_self_send(WT_FFA_MEM_OP_SHARE, 1, WT_FFA_MEM_PERM_DATA_RO,
                          0xFFu, PG_RW, &h) == WT_FFA_INVALID_PARAMETERS,
          "self: a share naming only the lender has no borrower");
    check(g_domain_fails == 0u, "self: no domain operation failed closed");
}

/* WT-FFA-0009 (FFA_MEM_PERM_GET/SET, DEN0140 2.8 and 2.9: a partition
 * re-permissions its own pages, never ones the SPMC writes at S-EL1). */
static void relay_perm_set_rows(void)
{
    uint32_t perm = 0u;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "perm set: fixture");
        return;
    }
    (void)memset(&g_relay_mailbox, 0, sizeof(g_relay_mailbox));
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_IMAGE), 1u,
                              WT_FFA_PERM_DATA_RO) == WT_FFA_INVALID_PARAMETERS,
          "perm set: code every partition runs is INVALID_PARAMETERS (Table 2.41)");
    check(wt_spm_mem_rxtx_ok(&g_dom_a, page(PG_SHARED)) == 0,
          "rxtx: memory its manifest shares with another partition is never its RX/TX buffer");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_SHARED), 1u,
                              WT_FFA_PERM_DATA_NONE) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_SHARED), 1u,
                              WT_FFA_PERM_DATA_RO) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_a, PG_SHARED) == WT_DOMAIN_ACCESS_RW,
          "perm set: nor is it the partition's own to re-permission (INVALID_PARAMETERS)");
    check(wt_spm_mem_perm_get(&g_dom_a, page(PG_SHARED), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN),
          "perm get: it still reads back its access to memory it shares (Table 2.37)");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RO &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_RW), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0,
          "perm set: a relayer endpoint makes memory its manifest makes writable read-only, and back");
    wt_spm_mem_unbind(CO_C);
    check(wt_spm_mem_perm_set(&g_dom_c, &g_relay_mailbox, page(PG_C), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_c, PG_C) == WT_DOMAIN_ACCESS_RW &&
          wt_spm_mem_perm_set(&g_dom_c, &g_relay_mailbox, page(PG_C), 1u,
                              WT_FFA_PERM_DATA_NONE) == 0 &&
          wt_spm_mem_perm_set(&g_dom_c, &g_relay_mailbox, page(PG_C), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0,
          "perm set: an FF-M partition's writable manifest memory, which the gate writes at S-EL1, never becomes read-only (INVALID_PARAMETERS) but may go no-access");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_RW &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_RX), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN),
          "perm set: an image page the manifest leaves read-execute may become read-write");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              0xFFFFFFF8u | WT_FFA_PERM_DATA_RW |
                                  WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_RW,
          "perm set: the SBZ bits above the permissions are ignored (Table 2.40)");
    (void)wt_ffa_mailbox_map(&g_relay_mailbox, page(PG_RX), page(PG_GAP), 1u);
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_RW,
          "perm set: a page of the mapped RX/TX pair keeps its permissions (INVALID_PARAMETERS)");
    check(wt_spm_mem_perm_get(&g_dom_a, page(PG_RX), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_IMAGE), &perm) == 0 &&
          perm == WT_FFA_PERM_DATA_RO,
          "perm get: a page of the mapped pair and the partition's own code page read back (Table 2.37)");
    (void)wt_ffa_mailbox_unmap(&g_relay_mailbox);
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RO) == 0 &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_RX), &perm) == 0 &&
          perm == WT_FFA_PERM_DATA_RO,
          "perm set: once the pair is unmapped the page goes back to read-execute");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 0u,
                              WT_FFA_PERM_DATA_RO) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX) + 8u, 1u,
                              WT_FFA_PERM_DATA_RO) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_B), 1u,
                              WT_FFA_PERM_DATA_RO) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RW) ==
              WT_FFA_INVALID_PARAMETERS,
          "perm set: no pages, an unaligned base, another partition's page, and read-write-execute are INVALID_PARAMETERS");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_NONE) == 0 &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_RX), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_NONE | WT_FFA_PERM_XN),
          "perm set: no access takes the page from EL0 and reads back as no access, execute-never");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_RW,
          "perm set: a page made no-access is still the partition's to open again");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_NONE | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          b_entry(PG_RW) == 1 &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0,
          "perm set: manifest-writable memory may go no-access, which S-EL1 still writes");
    check(wt_spm_mem_perm_set(&g_dom_c, &g_relay_mailbox, page(PG_C), 1u,
                              WT_FFA_PERM_DATA_RO) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RO) == 0 &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_RW), &perm) == 0 &&
          perm == WT_FFA_PERM_DATA_RO &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0,
          "perm set: read-only and executable follows the same rule");
    check(wt_spm_mem_perm_get(&g_dom_a, page(PG_DEV), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_DEV), 1u,
                              WT_FFA_PERM_DATA_NONE | WT_FFA_PERM_XN) == 0 &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_DEV), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_NONE | WT_FFA_PERM_XN) &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_DEV), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0,
          "perm set: the partition's own Device page reads back and changes its data access");
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_DEV), 1u,
                              WT_FFA_PERM_DATA_RO) != 0 &&
          wt_spm_mem_perm_get(&g_dom_a, page(PG_DEV), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN),
          "perm set: a Device page is never made executable (2.9.0.0.1 rule 2)");
    check(g_domain_fails == 0u, "perm set: no domain operation failed closed");
}

/* Non-zero when the last instruction cache sync covered exactly page pg. */
static int synced(unsigned int pg)
{
    return (g_syncs != 0u) && (g_sync_va == (uint64_t)page(pg)) &&
           (g_sync_size == WT_TABLES_PAGE_SIZE);
}

/* WT-FFA-0009 (a page EL0 may execute again after it could be written has its
 * instructions made fetchable: FFA_MEM_PERM_SET and a reclaim that restores an
 * executable page; a retrieve never grants execution). */
static void relay_icache_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint64_t h;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "icache: fixture");
        return;
    }
    (void)memset(&g_relay_mailbox, 0, sizeof(g_relay_mailbox));
    g_syncs = 0u;
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0 &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) == 0 &&
          g_syncs == 0u,
          "icache: a page made writable or read-only data needs no sync");
    *(uint8_t*)page(PG_RX) = 0xD5u;
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RO) == 0 &&
          synced(PG_RX) && g_syncs == 1u,
          "icache: a page written as data and made executable is synced for fetch");
    c[0].address = page(PG_RX);
    c[0].page_count = 1u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RO, 0u,
                   &ret);
    g_syncs = 0u;
    check(ret == 0 && access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_NONE &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RO, 0u) == 0 &&
          relay_relinquish(h, 0u) == 0 && g_syncs == 0u,
          "icache: lending the executable page, and a borrower mapping it execute-never, need no sync");
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_RO &&
          synced(PG_RX) && g_syncs == 1u,
          "icache: a reclaim that gives the owner back an executable page syncs it");
    c[0].address = page(PG_FILL2);
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 && relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 && g_syncs == 1u,
          "icache: a reclaim that gives back execute-never data needs none");
    check(g_domain_fails == 0u, "icache: no domain operation failed closed");
}

/* who (B or C) retrieves h asking for perms, naming the other as a
 * non-retrieval borrower with the read-write access the lender gave it. */
static int relay_retrieve_of_two_as(uint64_t h, uint16_t who, uint8_t perms)
{
    uint8_t req[128];
    uint8_t resp[256];
    uint16_t other = (who == RELAY_ID_B) ? RELAY_ID_C : RELAY_ID_B;
    size_t len = 0u;
    size_t resp_len = 0u;
    int ret;

    ret = wt_ffa_mem_retrieve_req_build(req, sizeof(req), h, RELAY_ID_A, who,
                                        perms, &len);
    if (ret == 0) {
        memcpy(&req[len], &req[WT_FFA_MEM_TXN_HDR_SIZE], WT_FFA_MEM_ACCESS_SIZE);
        req[len + WT_FFA_MEM_ACC_OFF_RECEIVER] = (uint8_t)(other & 0xFFu);
        req[len + WT_FFA_MEM_ACC_OFF_RECEIVER + 1u] = (uint8_t)(other >> 8);
        req[len + WT_FFA_MEM_ACC_OFF_PERMS] = (uint8_t)WT_FFA_MEM_PERM_DATA_RW;
        req[len + WT_FFA_MEM_ACC_OFF_FLAGS] =
            (uint8_t)WT_FFA_MEM_ACC_FLAG_NON_RETRIEVAL;
        put32(&req[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 2u);
        ret = wt_spm_mem_retrieve(req, len + WT_FFA_MEM_ACCESS_SIZE, who, resp,
                                  sizeof(resp), &resp_len);
    }
    return ret;
}

/* who (B or C) retrieves h read-write, naming the other as a non-retrieval
 * borrower. */
static int relay_retrieve_of_two(uint64_t h, uint16_t who)
{
    return relay_retrieve_of_two_as(h, who, WT_FFA_MEM_PERM_DATA_RW);
}

static int relay_relinquish_as(uint64_t h, uint16_t who)
{
    uint8_t rel[32];
    size_t len = 0u;
    int ret;

    ret = wt_ffa_mem_relinquish_build(rel, sizeof(rel), h, 0u, who, &len);
    if (ret == 0) {
        ret = wt_spm_mem_relinquish(rel, len, who);
    }
    return ret;
}

/* B retrieves h from A asking for flags; *resp_flags gets the response's. */
static int relay_retrieve_flags(uint64_t h, uint32_t flags,
                                uint32_t* resp_flags)
{
    uint8_t req[128];
    uint8_t resp[256];
    size_t len = 0u;
    size_t resp_len = 0u;
    int ret;

    *resp_flags = 0xFFFFFFFFu;
    ret = wt_ffa_mem_retrieve_req_build(req, sizeof(req), h, RELAY_ID_A,
                                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW,
                                        &len);
    if (ret == 0) {
        put32(&req[WT_FFA_MEM_TXN_OFF_FLAGS], flags);
        ret = wt_spm_mem_retrieve(req, len, RELAY_ID_B, resp, sizeof(resp),
                                  &resp_len);
    }
    if (ret == 0) {
        *resp_flags = get32(&resp[WT_FFA_MEM_TXN_OFF_FLAGS]);
    }
    return ret;
}

/* WT-FFA-0009 (memory the owner asked to be zeroed is zeroed once, after the
 * owner's access is gone and before any borrower maps it, Table 1.21 bit[0]
 * and 1.11.4.1). */
static void relay_zero_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint8_t* p;
    uint64_t h = 0u;
    size_t len = 0u;
    uint32_t resp_flags = 0u;
    int ret;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "zero: fixture");
        return;
    }
    p = (uint8_t*)page(PG_RW);
    p[0] = 0x5Au;
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    ret = relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, WT_FFA_MEM_FLAG_ZERO, &len);
    if (ret == 0) {
        len = add_receiver_c(desc, len);
        ret = wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_LEND, RELAY_ID_A, &h);
    }
    check(ret == 0 && relay_retrieve_of_two(h, RELAY_ID_B) == 0 && p[0] == 0u,
          "zero: the owner's data is gone before the first borrower maps the lent page");
    p[0] = 0xB0u;
    check(relay_retrieve_of_two(h, RELAY_ID_C) == 0 && p[0] == 0xB0u &&
          access_of(&g_dom_c, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "zero: a second borrower's retrieve leaves what the first one wrote");
    check(relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          relay_relinquish_as(h, RELAY_ID_C) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 && p[0] == 0xB0u,
          "zero: nothing wipes the page again when the borrowers let go");
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW,
                   0xFFFFFFFCu, &ret);
    p[0] = 0xC1u;
    check(ret == 0 && relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 && p[0] == 0xC1u,
          "zero: a lend's SBZ flag bits are ignored and never ask the relayer for a wipe");
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW,
                   WT_FFA_MEM_FLAG_ZERO, &ret);
    check(ret == 0 &&
          relay_retrieve_flags(h, WT_FFA_MEM_FLAG_ZERO, &resp_flags) == 0 &&
          (resp_flags & WT_FFA_MEM_FLAG_ZERO) != 0u &&
          relay_relinquish(h, 0u) == 0,
          "zero: a borrower's first retrieval may ask for the wipe, and is told it ran");
    p[0] = 0xD2u;
    check(relay_retrieve_flags(h, WT_FFA_MEM_FLAG_ZERO, &resp_flags) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
          "zero: a repeated retrieval asking for it is INVALID_PARAMETERS (Table 1.22 bit[0])");
    check(relay_retrieve_flags(h, 0u, &resp_flags) == 0 &&
          (resp_flags & WT_FFA_MEM_FLAG_ZERO) == 0u && p[0] == 0xD2u &&
          relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "zero: one that does not is mapped and told no wipe ran before it (Table 1.23 bit[0])");
    check(g_domain_fails == 0u, "zero: no domain operation failed closed");
}

/* who (B or C) relinquishes h asking for it to be zeroed after. */
static int relay_relinquish_zero_as(uint64_t h, uint16_t who)
{
    uint8_t rel[32];
    size_t len = 0u;
    int ret;

    ret = wt_ffa_mem_relinquish_build(rel, sizeof(rel), h,
                                      WT_FFA_MEM_RELINQ_FLAG_ZERO, who, &len);
    if (ret == 0) {
        ret = wt_spm_mem_relinquish(rel, len, who);
    }
    return ret;
}

/* WT-FFA-0009 (with several borrowers, a wipe any of them asks for runs once
 * the last is unmapped: the relayer zeroes memory only once no other component
 * maps it, DEN0140 1.11.4.1 and Table 2.25 bit[0]). */
static void relay_multi_zero_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint8_t* p;
    uint64_t h = 0u;
    size_t len = 0u;
    int ret;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "multi zero: fixture");
        return;
    }
    p = (uint8_t*)page(PG_RW);
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    ret = relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, 0u, &len);
    if (ret == 0) {
        len = add_receiver_c(desc, len);
        ret = wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_LEND, RELAY_ID_A, &h);
    }
    check(ret == 0 && relay_retrieve_of_two(h, RELAY_ID_B) == 0 &&
          relay_retrieve_of_two(h, RELAY_ID_C) == 0,
          "multi zero: two borrowers map one lent page");
    p[0] = 0x77u;
    g_cleans = 0u;
    check(relay_relinquish_zero_as(h, RELAY_ID_B) == 0 && p[0] == 0x77u &&
          g_cleans == 0u && access_of(&g_dom_c, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "multi zero: the first to let go asking for a wipe leaves the page intact for the borrower still mapping it");
    check(relay_relinquish_as(h, RELAY_ID_C) == 0 && p[0] == 0u &&
          cleaned(PG_RW),
          "multi zero: the wipe runs when the last borrower is unmapped, though it did not ask");
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "multi zero: the owner reclaims the wiped page");
    ret = relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, 0u, &len);
    if (ret == 0) {
        len = add_receiver_c(desc, len);
        ret = wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_LEND, RELAY_ID_A, &h);
    }
    check(ret == 0 && relay_retrieve_of_two(h, RELAY_ID_B) == 0 &&
          relay_retrieve_of_two(h, RELAY_ID_C) == 0,
          "multi zero: the two borrowers map it again");
    p[0] = 0x66u;
    g_cleans = 0u;
    check(relay_relinquish_as(h, RELAY_ID_C) == 0 && p[0] == 0x66u &&
          g_cleans == 0u &&
          relay_relinquish_zero_as(h, RELAY_ID_B) == 0 && p[0] == 0u &&
          cleaned(PG_RW),
          "multi zero: in the other order the last to let go asks for the wipe, which runs at once");
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0 &&
          g_domain_fails == 0u,
          "multi zero: the owner reclaims it and no domain operation failed closed");
}

/* WT-FFA-0009 (a lend or share borrower states the data access it wants in
 * its retrieve request, DEN0140 1.10.2 item 1; a donate's receiver only should,
 * item 2, and one that does not is given the owner's). */
static void relay_own_access_rows(void)
{
    static const wt_ffa_mem_op_t ops[2] = {
        WT_FFA_MEM_OP_LEND, WT_FFA_MEM_OP_SHARE
    };
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint64_t h = 0u;
    size_t len = 0u;
    unsigned int i;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "own access: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    for (i = 0u; i < 2u; i++) {
        h = relay_send(ops[i], c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u, &ret);
        check(ret == 0 &&
              relay_retrieve(h, WT_FFA_MEM_PERM_DATA_NOT_SPEC, 0u) ==
                  WT_FFA_INVALID_PARAMETERS &&
              access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
              (i == 0u)
                  ? "own access: a lend borrower leaving its data access unspecified is INVALID_PARAMETERS"
                  : "own access: so is a share borrower");
        check(relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RSVD, 0u) ==
                  WT_FFA_INVALID_PARAMETERS &&
              relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
              access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW &&
              relay_relinquish(h, 0u) == 0 &&
              wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
              "own access: the reserved encoding too; stating it, the borrower retrieves");
    }
    ret = relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, 0u, &len);
    if (ret == 0) {
        len = add_receiver_c(desc, len);
        ret = wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_LEND, RELAY_ID_A, &h);
    }
    check(ret == 0 &&
          relay_retrieve_of_two_as(h, RELAY_ID_B,
                                   WT_FFA_MEM_PERM_DATA_NOT_SPEC) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          relay_retrieve_of_two_as(h, RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RO) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RO,
          "own access: so is one of two lend borrowers, which retrieves once it states it");
    check(relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "own access: the two-borrower lend is reclaimed");
    h = relay_send(WT_FFA_MEM_OP_DONATE, c, 1u, WT_FFA_MEM_PERM_DATA_NOT_SPEC,
                   0u, &ret);
    check(ret == 0 &&
          relay_retrieve(h, WT_FFA_MEM_PERM_DATA_NOT_SPEC, 0u) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "own access: a donate's receiver that leaves it unspecified gets the owner's read-write access");
    check(g_domain_fails == 0u, "own access: no domain operation failed closed");
}

/* Non-zero when the last clean covered exactly page pg, after it was zeroed. */
static int cleaned(unsigned int pg)
{
    return (g_cleans != 0u) && (g_clean_va == (uint64_t)page(pg)) &&
           (g_clean_size == WT_TABLES_PAGE_SIZE) && (g_clean_zeroed != 0);
}

/* WT-FFA-0009 (each wipe is cleaned to the point of coherency so memory, not
 * just the SPMC's cache, holds the zeros, 1.11.4.1). */
static void relay_clean_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint64_t h;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "clean: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    g_cleans = 0u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW,
                   WT_FFA_MEM_FLAG_ZERO, &ret);
    check(ret == 0 && cleaned(PG_RW),
          "clean: a lend that asks for zeroing cleans the zeroed page");
    g_cleans = 0u;
    check(relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          g_cleans == 0u,
          "clean: the retrieve that follows neither wipes nor cleans it again");
    check(relay_relinquish(h, WT_FFA_MEM_RELINQ_FLAG_ZERO) == 0 &&
          cleaned(PG_RW),
          "clean: a relinquish that asks for zeroing cleans the zeroed page");
    g_cleans = 0u;
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, WT_FFA_MEM_RELINQ_FLAG_ZERO) == 0 &&
          cleaned(PG_RW),
          "clean: a reclaim that asks for zeroing cleans the zeroed page");
    check(g_clean_a_access == WT_DOMAIN_ACCESS_NONE &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "clean: that wipe runs before the owner's mapping comes back (Table 2.31 bit[0])");
}

/* WT-FFA-0009 (a partition that faults gives up what it borrowed, zeroed if
 * its retrieve asked, Table 1.22 bit[2], and what it owned goes to the SPM,
 * 1.3.1 rule 9). */
static void relay_teardown_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint8_t* wiped;
    uint8_t* kept;
    uint64_t h1;
    uint64_t h2;
    uint64_t fh = 0u;
    uint32_t offset = 0u;
    size_t len = 0u;
    int done = 0;
    int ret = 0;
    int ret2 = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "teardown: fixture");
        return;
    }
    wiped = (uint8_t*)page(PG_RW);
    kept = (uint8_t*)page(PG_RW + 1u);
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    h1 = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                    &ret);
    c[0].address = page(PG_RW + 1u);
    h2 = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                    &ret2);
    wiped[0] = 0x5Au;
    kept[0] = 0x5Au;
    check(ret == 0 && ret2 == 0 &&
          relay_retrieve(h1, WT_FFA_MEM_PERM_DATA_RW,
                         WT_FFA_MEM_FLAG_ZERO_AFTER) == 0 &&
          relay_retrieve(h2, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0,
          "teardown: the borrower holds two lent pages, one to be zeroed after");
    wt_spm_mem_endpoint_teardown(CO_B);
    check(access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          access_of(&g_dom_b, PG_RW + 1u) == WT_DOMAIN_ACCESS_NONE &&
          b_entry(PG_RW) == 1 && b_entry(PG_RW + 1u) == 1,
          "teardown: a faulted borrower's table loses every page it retrieved");
    check(wiped[0] == 0u && kept[0] == 0x5Au,
          "teardown: only the page its retrieve asked to be zeroed is wiped");
    check(wt_spm_mem_reclaim(h1, RELAY_ID_A, 0u) == 0 &&
          wt_spm_mem_reclaim(h2, RELAY_ID_A, 0u) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "teardown: the owner reclaims what the faulted borrower held");

    c[0].address = page(PG_RW);
    h1 = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                    &ret);
    c[0].address = page(PG_FILL2);
    h2 = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                    &ret2);
    check(ret == 0 && ret2 == 0 &&
          relay_retrieve(h2, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0,
          "teardown: the owner lends two pages, the borrower retrieves one");
    (void)relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, 0u, &len);
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                40u, (uint32_t)len, &fh) == 0,
          "teardown: the owner starts a descriptor in fragments");
    wt_spm_mem_endpoint_teardown(CO_A);
    check(access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_reclaim(h1, RELAY_ID_A, 0u) == WT_FFA_INVALID_PARAMETERS,
          "teardown: what a faulted owner lent and nobody retrieved ends, its access left to the SPM");
    check(wt_spm_mem_frag_next(fh, RELAY_ID_A, &desc[40], (uint32_t)len - 40u,
                               &offset, &done) == WT_FFA_INVALID_PARAMETERS,
          "teardown: its unfinished fragmented descriptor is dropped");
    check(access_of(&g_dom_b, PG_FILL2) == WT_DOMAIN_ACCESS_RW &&
          access_of(&g_dom_a, PG_FILL2) == WT_DOMAIN_ACCESS_NONE,
          "teardown: what a borrower still maps stays mapped");
    check(relay_relinquish(h2, 0u) == 0 && b_entry(PG_FILL2) == 1 &&
          access_of(&g_dom_a, PG_FILL2) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_reclaim(h2, RELAY_ID_A, 0u) == WT_FFA_INVALID_PARAMETERS,
          "teardown: the last borrower to relinquish ends it, and the faulted owner never gets it back");
    check(g_domain_fails == 0u, "teardown: no domain operation failed closed");
}

/* B retrieves h from owner with a v1.0 retrieve request. */
static int relay_retrieve_v10(uint64_t h, uint16_t owner, uint8_t* resp,
                              size_t* resp_len)
{
    uint8_t req[64];
    size_t len = v10_retrieve_req(req, h, owner, RELAY_ID_B,
                                  WT_FFA_MEM_PERM_DATA_RW);

    return wt_spm_mem_retrieve(req, len, RELAY_ID_B, resp, 256u, resp_len);
}

static uint8_t ns_bit_told(uint64_t h, int* ret)
{
    uint8_t resp[256];
    size_t resp_len = 0u;

    memset(resp, 0, sizeof(resp));
    *ret = relay_retrieve_v10(h, WT_FFA_ID_NS_PRIMARY, resp, &resp_len);
    if (*ret == 0) {
        *ret = relay_relinquish(h, 0u);
    }
    return (uint8_t)(resp[WT_FFA_MEM_TXN_OFF_ATTRS] & WT_FFA_MEM_ATTR_NS);
}

/* WT-FFA-0009 (the relayer reads and answers each endpoint in the layout of
 * the version it negotiated, DEN0077A 18.5.3, and tells a v1.0 borrower the
 * NS bit only if it asked, DEN0140 Table 1.19). */
static void relay_v10_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    wt_ffa_mem_build_t in;
    uint8_t desc[256];
    uint8_t resp[256];
    uint64_t h = 0u;
    uint64_t fh = 0u;
    size_t len = 0u;
    size_t resp_len = 0u;
    uint32_t offset = 0u;
    uint8_t told;
    int done = 0;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "v1.0: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    memset(&in, 0, sizeof(in));
    in.constituents = c;
    in.constituent_count = 1u;
    in.op = WT_FFA_MEM_OP_LEND;
    in.sender = RELAY_ID_A;
    in.receiver = RELAY_ID_B;
    in.permissions = WT_FFA_MEM_PERM_DATA_RW;
    in.version = V10;
    g_ver_a = V10;
    g_ver_b = V10;
    (void)wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len);
    check(wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_LEND, RELAY_ID_A, &h) == 0,
          "v1.0: the relayer takes a lend from a v1.0 owner in its layout");
    memset(resp, 0xA5, sizeof(resp));
    check(relay_retrieve_v10(h, RELAY_ID_A, resp, &resp_len) == 0 &&
              resp_len == 80u && get32(&resp[24]) == 0u &&
              get32(&resp[28]) == 1u && resp[32] == (RELAY_ID_B & 0xFFu) &&
              get32(&resp[32u + WT_FFA_MEM_ACC_OFF_COMP_OFF]) == 48u &&
              get32(&resp[WT_FFA_MEM_TXN_OFF_HANDLE]) == (uint32_t)h &&
              get32(&resp[64]) == (uint32_t)page(PG_RW) &&
              access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "v1.0: a v1.0 borrower's retrieve is mapped and answered in the v1.0 "
          "layout");
    check(relay_relinquish(h, 0u) == 0 &&
              wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "v1.0: the lend ends");

    (void)wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len);
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                64u, (uint32_t)len, &fh) == 0 &&
              wt_spm_mem_frag_next(fh, RELAY_ID_A, &desc[64],
                                   (uint32_t)len - 64u, &offset, &done) == 0 &&
              done == 1 && wt_spm_mem_frag_share(fh, RELAY_ID_A) == 0 &&
              wt_spm_mem_reclaim(fh, RELAY_ID_A, 0u) == 0,
          "v1.0: a v1.0 owner's lend sent in fragments is taken in its layout");

    wt_spm_mem_ns_window(page(10u), 2u * WT_TABLES_PAGE_SIZE);
    g_ver_ns = V10;
    c[0].address = page(10u);
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = WT_FFA_ID_NS_PRIMARY;
    (void)wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len);
    check(wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_SHARE,
                           WT_FFA_ID_NS_PRIMARY, &h) == 0,
          "v1.0: a v1.0 Normal world shares its memory in the v1.0 layout");
    told = ns_bit_told(h, &ret);
    check(ret == 0 && told == 0u,
          "v1.0: a v1.0 borrower that never asked for the NS bit is not told "
          "it (Table 1.19 row 5)");
    g_ns_bit_b = 1;
    told = ns_bit_told(h, &ret);
    check(ret == 0 && told != 0u,
          "v1.0: one that asked through FFA_FEATURES is told it (row 6)");
    g_ns_bit_b = 0;
    g_ver_b = WT_FFA_VERSION_1_2;
    memset(resp, 0, sizeof(resp));
    ret = wt_ffa_mem_retrieve_req_build(desc, sizeof(desc), h,
                                        WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                                        WT_FFA_MEM_PERM_DATA_RW, &len);
    if (ret == 0) {
        ret = wt_spm_mem_retrieve(desc, len, RELAY_ID_B, resp, sizeof(resp),
                                  &resp_len);
    }
    check(ret == 0 &&
              (resp[WT_FFA_MEM_TXN_OFF_ATTRS] & WT_FFA_MEM_ATTR_NS) != 0u &&
              relay_relinquish(h, 0u) == 0,
          "v1.0: a v1.1+ borrower is always told it (row 7)");
    check(wt_spm_mem_reclaim(h, WT_FFA_ID_NS_PRIMARY, 0u) == 0,
          "v1.0: the Normal world reclaims its share");
    g_ver_a = WT_FFA_VERSION_1_2;
    g_ver_b = WT_FFA_VERSION_1_2;
    g_ver_ns = WT_FFA_VERSION_1_2;
    g_ns_bit_b = 0;
    check(g_domain_fails == 0u, "v1.0: no domain operation failed closed");
}

/* WT-FFA-0009 (a binding the SPMC made for a boot self-test is dropped with
 * what it holds, so a partition reusing the coroutine starts unbound). */
static void relay_unbind_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint64_t h;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "unbind: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 && relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == 0 &&
          wt_spm_mem_binding(CO_B) != NULL,
          "unbind: a bound borrower holds a lent page");
    wt_spm_mem_unbind(CO_B);
    check(wt_spm_mem_binding(CO_B) == NULL &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_binding(CO_A) != NULL,
          "unbind: the coroutine loses its binding and the page it held, no other");
    check(relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, 0u) == WT_FFA_DENIED &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "unbind: the unbound endpoint cannot retrieve and the owner reclaims");
}

/* Send n constituents from sender to receiver; *ret gets the relayer's
 * answer. */
static uint64_t relay_send_from(wt_ffa_mem_op_t op,
                                const wt_ffa_mem_constituent_t* c, uint32_t n,
                                uint16_t sender, uint16_t receiver,
                                uint8_t perms, int* ret)
{
    wt_ffa_mem_build_t in;
    uint8_t desc[256];
    uint64_t h = 0u;
    size_t len = 0u;

    (void)memset(&in, 0, sizeof(in));
    in.constituents = c;
    in.constituent_count = n;
    in.op = op;
    in.sender = sender;
    in.receiver = receiver;
    in.permissions = perms;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
    *ret = wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len);
    if (*ret == 0) {
        *ret = wt_spm_mem_share(desc, len, op, sender, &h);
    }
    return h;
}

static int relay_retrieve_by(uint64_t h, uint16_t sender, uint16_t receiver,
                             uint8_t perms)
{
    uint8_t req[128];
    uint8_t resp[256];
    size_t len = 0u;
    size_t resp_len = 0u;
    int ret;

    ret = wt_ffa_mem_retrieve_req_build(req, sizeof(req), h, sender, receiver,
                                        perms, &len);
    if (ret == 0) {
        ret = wt_spm_mem_retrieve(req, len, receiver, resp, sizeof(resp),
                                  &resp_len);
    }
    return ret;
}

static int ns_of(const wt_secure_domain_t* d, unsigned int pg)
{
    return wt_domain_page_ns(d->regions, d->region_count, page(pg));
}

/* WT-FFA-0009 (the Normal world donates its memory to a partition, which then
 * owns it: the Normal world cannot send it again, and the partition sends it
 * on as Non-secure memory, Table 1.24 and 1.3.1 rules 5 and 6). */
static void relay_ns_donate_rows(void)
{
    wt_ffa_mem_constituent_t c[2];
    uint64_t h;
    int ret = 0;
    int ok;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "ns donate: fixture");
        return;
    }
    wt_spm_mem_ns_window(page(10u), 2u * WT_TABLES_PAGE_SIZE);
    c[0].address = page(10u);
    c[0].page_count = 1u;
    h = relay_send_from(WT_FFA_MEM_OP_DONATE, c, 1u, WT_FFA_ID_NS_PRIMARY,
                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_NOT_SPEC, &ret);
    check(ret == 0 &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          access_of(&g_dom_b, 10u) == WT_DOMAIN_ACCESS_RW &&
          ns_of(&g_dom_b, 10u) != 0,
          "ns donate: the Normal world donates a page and the receiver maps it Non-secure");
    (void)relay_send_from(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_ID_NS_PRIMARY,
                          RELAY_ID_C, WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ret == WT_FFA_DENIED &&
          wt_spm_mem_ns_owns(page(10u), WT_TABLES_PAGE_SIZE) == 0 &&
          wt_spm_mem_ns_owns(page(11u), WT_TABLES_PAGE_SIZE) != 0,
          "ns donate: the donated page is no longer the Normal world's to send");
    h = relay_send_from(WT_FFA_MEM_OP_LEND, c, 1u, RELAY_ID_B, RELAY_ID_C,
                        WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ret == 0 && access_of(&g_dom_b, 10u) == WT_DOMAIN_ACCESS_NONE &&
          relay_retrieve_by(h, RELAY_ID_B, RELAY_ID_C,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          ns_of(&g_dom_c, 10u) != 0,
          "ns donate: its new owner lends it on, and the borrower maps it Non-secure too");
    check(relay_relinquish_as(h, RELAY_ID_C) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_B, 0u) == 0 &&
          access_of(&g_dom_b, 10u) == WT_DOMAIN_ACCESS_RW &&
          ns_of(&g_dom_b, 10u) != 0,
          "ns donate: a reclaim gives the owner the page back Non-secure");
    (void)relay_send_from(WT_FFA_MEM_OP_DONATE, c, 1u, RELAY_ID_B,
                          WT_FFA_ID_NS_PRIMARY, WT_FFA_MEM_PERM_DATA_NOT_SPEC,
                          &ret);
    ok = (ret == WT_FFA_DENIED) ? 1 : 0;
    (void)relay_send_from(WT_FFA_MEM_OP_LEND, c, 1u, RELAY_ID_B,
                          WT_FFA_ID_NS_PRIMARY, WT_FFA_MEM_PERM_DATA_RW, &ret);
    ok = ok && (ret == WT_FFA_DENIED);
    (void)relay_send_from(WT_FFA_MEM_OP_SHARE, c, 1u, RELAY_ID_B,
                          WT_FFA_ID_NS_PRIMARY, WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ok && (ret == WT_FFA_DENIED) &&
          wt_spm_mem_in_transaction(page(10u), WT_TABLES_PAGE_SIZE) == 0 &&
          access_of(&g_dom_b, 10u) == WT_DOMAIN_ACCESS_RW,
          "ns donate: its new owner cannot send it to the Normal world, no SP-to-NS-Endpoint send being a Table 1.7 combination");
    c[1].address = page(PG_B);
    c[1].page_count = 1u;
    (void)relay_send_from(WT_FFA_MEM_OP_LEND, c, 2u, RELAY_ID_B, RELAY_ID_C,
                          WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ret == WT_FFA_DENIED &&
          access_of(&g_dom_b, PG_B) == WT_DOMAIN_ACCESS_RW,
          "ns donate: a region mixing Non-secure and Secure pages is DENIED");
    check(g_domain_fails == 0u, "ns donate: no domain operation failed closed");
}

/* B retrieves h with a request laid out for req_version;
 * *resp_size gets the size the response's descriptors use. */
static int relay_retrieve_sized(uint64_t h, uint32_t req_version,
                                uint32_t* resp_size)
{
    uint8_t req[128];
    uint8_t resp[256];
    size_t len = 0u;
    size_t resp_len = 0u;
    int ret;

    ret = wt_ffa_mem_retrieve_req_build_at(req, sizeof(req), h, RELAY_ID_A,
                                           RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW,
                                           req_version, &len);
    if (ret == 0) {
        ret = wt_spm_mem_retrieve(req, len, RELAY_ID_B, resp, sizeof(resp),
                                  &resp_len);
    }
    if (ret == 0) {
        *resp_size = get32(&resp[WT_FFA_MEM_TXN_OFF_ACC_SIZE]);
        ret = ((size_t)(WT_FFA_MEM_TXN_HDR_SIZE + *resp_size +
                        WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                        WT_FFA_MEM_CONSTITUENT_SIZE) == resp_len) ? 0 : -1;
    }
    return ret;
}

/* WT-FFA-0009 (each endpoint gets the endpoint memory access descriptor of
 * the version it negotiated, whatever size it sent, DEN0077A 18.5 and DEN0140
 * Table 1.16). */
static void relay_access_size_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    wt_ffa_mem_build_t in;
    uint8_t desc[256];
    uint32_t size = 0u;
    size_t len = 0u;
    uint64_t h;
    int ret = 0;

    (void)memset(&in, 0, sizeof(in));
    c[0].address = 0x40000000ull;
    c[0].page_count = 1u;
    in.constituents = c;
    in.constituent_count = 1u;
    in.op = WT_FFA_MEM_OP_LEND;
    in.receiver = 0x8002u;
    in.permissions = WT_FFA_MEM_PERM_DATA_RW;
    check(wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len) == 0 &&
          get32(&desc[WT_FFA_MEM_TXN_OFF_ACC_SIZE]) == WT_FFA_MEM_ACCESS_SIZE_V12 &&
          len == 112u,
          "access size: a descriptor for an FF-A 1.2 reader uses the 32-byte access descriptor");
    in.version = WT_FFA_VERSION_MAKE(1u, 1u);
    check(wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len) == 0 &&
          get32(&desc[WT_FFA_MEM_TXN_OFF_ACC_SIZE]) == WT_FFA_MEM_ACCESS_SIZE &&
          len == 96u,
          "access size: one for an FF-A 1.1 reader keeps the 16-byte one");

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "access size: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    check(ret == 0 &&
          relay_retrieve_sized(h, WT_FFA_VERSION_MAKE(1u, 1u), &size) == 0 &&
          size == WT_FFA_MEM_ACCESS_SIZE_V12 && relay_relinquish(h, 0u) == 0,
          "access size: a 1.2 borrower's 16-byte request is answered in the 32-byte layout");
    g_ver_b = WT_FFA_VERSION_MAKE(1u, 1u);
    check(relay_retrieve_sized(h, WT_FFA_VERSION_1_2, &size) == 0 &&
          size == WT_FFA_MEM_ACCESS_SIZE && relay_relinquish(h, 0u) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "access size: a 1.1 borrower's 32-byte request is answered in the 16-byte layout");
    g_ver_b = WT_FFA_VERSION_1_2;
}

/* B's retrieve of h naming n address ranges of its own (1.11.3.2) in a
 * composite after its access descriptor; *resp_len and *resp_comp get the
 * response length and the composite offset it states. */
static int relay_retrieve_ranges(uint64_t h, const wt_ffa_mem_constituent_t* r,
                                 uint32_t n, uint32_t flags, size_t* resp_len,
                                 uint32_t* resp_comp)
{
    uint8_t req[256];
    uint8_t resp[256];
    size_t len = 0u;
    uint32_t comp;
    uint32_t total = 0u;
    uint32_t i;
    int ret;

    ret = wt_ffa_mem_retrieve_req_build(req, sizeof(req), h, RELAY_ID_A,
                                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW,
                                        &len);
    if (ret != 0) {
        return ret;
    }
    comp = (uint32_t)len;
    put32(&req[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_COMP_OFF], comp);
    put32(&req[WT_FFA_MEM_TXN_OFF_FLAGS], flags);
    (void)memset(&req[comp], 0, WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                                    (n * WT_FFA_MEM_CONSTITUENT_SIZE));
    for (i = 0u; i < n; i++) {
        put64(&req[comp + WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                   (i * WT_FFA_MEM_CONSTITUENT_SIZE)], r[i].address);
        put32(&req[comp + WT_FFA_MEM_COMPOSITE_HDR_SIZE +
                   (i * WT_FFA_MEM_CONSTITUENT_SIZE) + 8u], r[i].page_count);
        total += r[i].page_count;
    }
    put32(&req[comp + WT_FFA_MEM_COMP_OFF_PAGES], total);
    put32(&req[comp + WT_FFA_MEM_COMP_OFF_COUNT], n);
    len = comp + WT_FFA_MEM_COMPOSITE_HDR_SIZE + (n * WT_FFA_MEM_CONSTITUENT_SIZE);
    ret = wt_spm_mem_retrieve(req, len, RELAY_ID_B, resp, sizeof(resp),
                              resp_len);
    if (ret == 0) {
        *resp_comp = get32(&resp[WT_FFA_MEM_TXN_HDR_SIZE +
                                 WT_FFA_MEM_ACC_OFF_COMP_OFF]);
    }
    return ret;
}

/* WT-FFA-0009 (a receiver may name the address ranges its mapping uses,
 * 1.11.3.2; the relayer maps S-EL0 memory only at its own address and answers
 * with no composite, 1.11.3.3). */
static void relay_range_rows(void)
{
    wt_ffa_mem_constituent_t c[2];
    wt_ffa_mem_constituent_t r[2];
    wt_ffa_mem_retrieve_req_t rq;
    const uint8_t* whole;
    uint8_t req[256];
    uint8_t resp[256];
    uint64_t size = 0u;
    uint64_t fh = 0u;
    uint64_t h;
    size_t len = 0u;
    size_t resp_len = 0u;
    uint32_t comp = 1u;
    uint32_t offset = 0u;
    uint32_t total = 0u;
    uint32_t split;
    uint8_t op = 0u;
    int done = 0;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "ranges: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 2u;
    h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                   &ret);
    r[0].address = page(PG_RW);
    r[0].page_count = 2u;
    check(ret == 0 &&
          relay_retrieve_ranges(h, r, 1u, 0u, &resp_len, &comp) == 0 &&
          comp == 0u &&
          resp_len == (WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACCESS_SIZE_V12) &&
          access_of(&g_dom_b, PG_RW + 1u) == WT_DOMAIN_ACCESS_RW &&
          relay_relinquish(h, 0u) == 0,
          "ranges: a borrower naming the region's own addresses is mapped there and answered with no composite");
    r[0].page_count = 1u;
    r[1].address = page(PG_RW + 1u);
    r[1].page_count = 1u;
    check(relay_retrieve_ranges(h, r, 2u, 0u, &resp_len, &comp) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW &&
          relay_relinquish(h, 0u) == 0,
          "ranges: the same pages split into two ranges are mapped too");
    r[0].page_count = 3u;
    check(relay_retrieve_ranges(h, r, 1u, 0u, &resp_len, &comp) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
          "ranges: a size other than the sender's is INVALID_PARAMETERS (1.11.3.3)");
    r[0].address = page(PG_B);
    r[0].page_count = 2u;
    check(relay_retrieve_ranges(h, r, 1u, 0u, &resp_len, &comp) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
          "ranges: addresses the relayer cannot map the region at are INVALID_PARAMETERS");
    r[0].address = page(PG_RW);
    check(relay_retrieve_ranges(h, r, 1u, 1u << 9, &resp_len, &comp) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_NONE,
          "ranges: an alignment hint with them is INVALID_PARAMETERS (Table 1.22)");
    check(wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0, "ranges: the lend ends");

    (void)wt_ffa_mem_retrieve_req_build(req, sizeof(req), 0x77ull, RELAY_ID_A,
                                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW,
                                        &len);
    put32(&req[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_COMP_OFF],
          (uint32_t)len);
    (void)memset(&req[len], 0, 32u);
    put32(&req[len + WT_FFA_MEM_COMP_OFF_PAGES], 1u);
    put32(&req[len + WT_FFA_MEM_COMP_OFF_COUNT], 1u);
    put64(&req[len + 16u], 0x40000000ull);
    put32(&req[len + 24u], 1u);
    check(wt_ffa_mem_retrieve_req_parse_ex(req, len + 32u, &rq) == 0 &&
          rq.range_count == 1u && rq.range_index == 0u &&
          rq.ranges[0].address == 0x40000000ull &&
          rq.ranges[0].page_count == 1u &&
          wt_ffa_mem_frag_expected(req, (uint32_t)len + 20u, 1, &size) == 1 &&
          size == (uint64_t)(len + 32u),
          "ranges: a retrieve request's own composite is parsed and names its whole length to a first fragment");
    ret = 0;
    for (split = WT_FFA_MEM_TXN_HDR_SIZE; split < (uint32_t)len + 32u; split++) {
        size = 0u;
        if ((wt_ffa_mem_frag_expected(req, split, 1, &size) != 0) &&
            (size != (uint64_t)len + 32u)) {
            ret = -1;
        }
        done = 0;
        if ((wt_spm_mem_frag_begin(WT_SPM_MEM_FRAG_OP_RETRIEVE, RELAY_ID_B,
                                   req, split, (uint32_t)len + 32u, &fh) != 0) ||
            (wt_spm_mem_frag_next(fh, RELAY_ID_B, &req[split],
                                  (uint32_t)len + 32u - split, &offset,
                                  &done) != 0) ||
            (done != 1)) {
            ret = -1;
        }
        wt_spm_mem_frag_release(fh, RELAY_ID_B);
    }
    check(ret == 0,
          "ranges: a retrieve request naming its ranges is taken at every first-fragment boundary, a header-only one included");
    put32(&req[len + WT_FFA_MEM_COMP_OFF_PAGES], 2u);
    check(wt_ffa_mem_retrieve_req_parse_ex(req, len + 32u, &rq) ==
              WT_FFA_INVALID_PARAMETERS,
          "ranges: a composite whose page total is not its ranges' is INVALID_PARAMETERS");
    put32(&req[WT_FFA_MEM_TXN_OFF_ACC_SIZE], 0u);
    put32(&req[WT_FFA_MEM_TXN_OFF_ACC_COUNT], 0xFFFFFFFFu);
    put32(&req[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_COMP_OFF], 0u);
    check(wt_spm_mem_frag_begin(WT_SPM_MEM_FRAG_OP_RETRIEVE, RELAY_ID_B, req,
                                (uint32_t)len, (uint32_t)len + 32u, &fh) == 0 &&
          wt_spm_mem_frag_next(fh, RELAY_ID_B, &req[len], 32u, &offset,
                               &done) == 0 && done == 1,
          "ranges: a fragmented retrieve request with a zero access descriptor size is taken without walking it");
    whole = wt_spm_mem_frag_desc(fh, RELAY_ID_B, &total, &op);
    check(whole != NULL &&
          wt_spm_mem_retrieve(whole, total, RELAY_ID_B, resp, sizeof(resp),
                              &resp_len) == WT_FFA_NOT_SUPPORTED,
          "ranges: and the whole request is then refused (NOT_SUPPORTED)");
    wt_spm_mem_frag_release(fh, RELAY_ID_B);
    check(g_domain_fails == 0u, "ranges: no domain operation failed closed");
}

/* A window holding a 128 MB boundary (the largest a hint asks for) with room
 * for the fixture's pages around it; mapped lazily, so only those are backed. */
#define ALIGN_WINDOW (0x8000000ull + 0x80000ull)
#define ALIGN_128M   0x8000000ull
#define ALIGN_VALID  (1u << 9)

/* With the fixture moved so A's first lendable page sits at base, A lends it
 * to B and B retrieves it asking for alignment hint n: the retrieve's answer,
 * or -99 if the fixture fails. The lend ends either way. */
static int relay_align_at(uint64_t base, uint32_t n)
{
    wt_ffa_mem_constituent_t c[1];
    uint64_t h = 0u;
    int sent = -1;
    int ret = -99;

    g_mem = (uint8_t*)(uintptr_t)(base - ((uint64_t)PG_FILL *
                                          WT_TABLES_PAGE_SIZE));
    c[0].address = base;
    c[0].page_count = 1u;
    if (relay_reset()) {
        h = relay_send(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_MEM_PERM_DATA_RW, 0u,
                       &sent);
    }
    if (sent == 0) {
        ret = relay_retrieve(h, WT_FFA_MEM_PERM_DATA_RW, ALIGN_VALID | (n << 5));
        if ((ret == 0) && (relay_relinquish(h, 0u) != 0)) {
            ret = -99;
        }
        if (wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) != 0) {
            ret = -99;
        }
    }
    return ret;
}

/* WT-FFA-0009 (a retrieve's alignment hint n asks for a 2^n x 4 KB boundary,
 * DEN0140 Table 1.22 bits[8:5], and a region off it is DENIED). */
static void relay_align_rows(void)
{
    uint8_t* saved = g_mem;
    uint8_t* win;
    uint64_t x;
    uint64_t d;
    uint64_t y = 0u;
    uint64_t z = 0u;

    if (g_mem == NULL) {
        check(0, "align: fixture");
        return;
    }
    win = low_pages((size_t)ALIGN_WINDOW);
    check(win != NULL,
          "align: the host backs a window holding a 128 MB boundary below the table VA limit");
    if (win == NULL) {
        return;
    }
    x = ((uint64_t)(uintptr_t)win + (2u * WT_TABLES_PAGE_SIZE) + ALIGN_128M -
         1u) & ~(ALIGN_128M - 1u);
    /* y sits on a 24 KB boundary but not a 32 KB one, z on a 120 KB one. */
    for (d = WT_TABLES_PAGE_SIZE; d < 0x40000u; d += WT_TABLES_PAGE_SIZE) {
        if ((y == 0u) && (((x + d) % 0x6000u) == 0u) &&
            (((x + d) % 0x8000u) != 0u)) {
            y = x + d;
        }
        if ((z == 0u) && (((x + d) % 0x1E000u) == 0u)) {
            z = x + d;
        }
    }
    check(relay_align_at(x, 0u) == 0 && relay_align_at(x, 1u) == 0 &&
          relay_align_at(x, 3u) == 0 && relay_align_at(x, 15u) == 0,
          "align: a region on a 128 MB boundary is mapped for hints 0, 1, 3, and 15");
    check(relay_align_at(x + WT_TABLES_PAGE_SIZE, 0u) == 0 &&
          relay_align_at(x + WT_TABLES_PAGE_SIZE, 1u) == WT_FFA_DENIED,
          "align: hint 0 asks for 4 KB, which every page meets, and hint 1 for 8 KB");
    check(y != 0u && relay_align_at(y, 1u) == 0 &&
          relay_align_at(y, 3u) == WT_FFA_DENIED,
          "align: hint 3 asks for 32 KB, not 24 KB, so a page on a 24 KB boundary only is DENIED");
    check(z != 0u && relay_align_at(z, 15u) == WT_FFA_DENIED,
          "align: hint 15 asks for 128 MB, not 120 KB, so a page on a 120 KB boundary is DENIED");
    (void)munmap(win, (size_t)ALIGN_WINDOW);
    g_mem = saved;
    check(relay_reset() && g_domain_fails == 0u,
          "align: the fixture is back on its own pages");
}

/* WT-FFA-0009 (a donate makes the receiver the owner, Owner-EA, 2.4.1.2 item
 * 12: its permission and RX/TX calls treat the page as its own; an owner
 * cannot change the access of memory a transaction covers, 1.3.1 rule 7). */
static void relay_donated_perm_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint32_t perm = 0u;
    uint64_t h;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "donated perm: fixture");
        return;
    }
    (void)memset(&g_relay_mailbox, 0, sizeof(g_relay_mailbox));
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    h = relay_send_from(WT_FFA_MEM_OP_DONATE, c, 1u, RELAY_ID_A, RELAY_ID_B,
                        WT_FFA_MEM_PERM_DATA_NOT_SPEC, &ret);
    check(ret == 0 &&
          relay_retrieve_by(h, RELAY_ID_A, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          wt_spm_mem_perm_get(&g_dom_b, page(PG_RW), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN),
          "donated perm: the receiver reads back the page it was donated");
    check(wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RO &&
          wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_b, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "donated perm: and re-permissions it as its own");
    check(wt_spm_mem_rxtx_ok(&g_dom_b, page(PG_RW)) != 0 &&
          wt_spm_mem_rxtx_ok(&g_dom_b, page(PG_B)) != 0,
          "donated perm: it may map the donated page, like its own, as an RX/TX buffer");
    check(wt_spm_mem_perm_get(&g_dom_a, page(PG_RW), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_NONE | WT_FFA_PERM_XN) &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RW), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_rxtx_ok(&g_dom_a, page(PG_RW)) == 0,
          "donated perm: the donor has no access left to read, set, or map");
    c[0].address = page(PG_FILL2);
    h = relay_send_from(WT_FFA_MEM_OP_LEND, c, 1u, RELAY_ID_A, RELAY_ID_B,
                        WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ret == 0 &&
          relay_retrieve_by(h, RELAY_ID_A, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          wt_spm_mem_perm_get(&g_dom_b, page(PG_FILL2), &perm) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_FILL2), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_rxtx_ok(&g_dom_b, page(PG_FILL2)) == 0,
          "donated perm: a page it only borrows is never its own");
    check(relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "donated perm: the lend ends");
    c[0].address = page(PG_RX);
    check(wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0,
          "donated perm: the owner opens its image page for writing");
    h = relay_send_from(WT_FFA_MEM_OP_SHARE, c, 1u, RELAY_ID_A, RELAY_ID_B,
                        WT_FFA_MEM_PERM_DATA_RO, &ret);
    check(ret == 0 &&
          wt_spm_mem_perm_set(&g_dom_a, &g_relay_mailbox, page(PG_RX), 1u,
                              WT_FFA_PERM_DATA_NONE) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_a, PG_RX) == WT_DOMAIN_ACCESS_RW &&
          wt_spm_mem_reclaim(h, RELAY_ID_A, 0u) == 0,
          "donated perm: an owner cannot change the access of memory it shares until it reclaims it (1.3.1 rule 7)");
    wt_spm_mem_ns_window(page(PG_NS), 2u * WT_TABLES_PAGE_SIZE);
    c[0].address = page(PG_NS);
    h = relay_send_from(WT_FFA_MEM_OP_DONATE, c, 1u, WT_FFA_ID_NS_PRIMARY,
                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_NOT_SPEC, &ret);
    check(ret == 0 &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          wt_spm_mem_perm_get(&g_dom_b, page(PG_NS), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) &&
          wt_spm_mem_rxtx_ok(&g_dom_b, page(PG_NS)) == 0,
          "donated perm: Non-secure memory donated to it is its own but never an RX/TX buffer (DEN0077A 7.2.2.2 rule 3)");
    check(wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_NS), 1u,
                              WT_FFA_PERM_DATA_RO | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_b, PG_NS) == WT_DOMAIN_ACCESS_RO &&
          wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_NS), 1u,
                              WT_FFA_PERM_DATA_NONE) == 0 &&
          access_of(&g_dom_b, PG_NS) == WT_DOMAIN_ACCESS_NONE &&
          wt_spm_mem_ns_owns(page(PG_NS), WT_TABLES_PAGE_SIZE) == 0 &&
          wt_spm_mem_perm_get(&g_dom_b, page(PG_NS), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_NONE | WT_FFA_PERM_XN) &&
          wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_NS), 1u,
                              WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN) == 0 &&
          access_of(&g_dom_b, PG_NS) == WT_DOMAIN_ACCESS_RW &&
          ns_of(&g_dom_b, PG_NS) != 0 &&
          wt_spm_mem_rxtx_ok(&g_dom_b, page(PG_NS)) == 0,
          "donated perm: it re-permissions donated Non-secure memory read-only, no access (still not the Normal world's), and read-write, still Non-secure and never an RX/TX buffer");
    check(wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_NS), 1u,
                              WT_FFA_PERM_DATA_RO) ==
              WT_FFA_INVALID_PARAMETERS &&
          access_of(&g_dom_b, PG_NS) == WT_DOMAIN_ACCESS_RW &&
          wt_spm_mem_perm_get(&g_dom_b, page(PG_NS), &perm) == 0 &&
          perm == (WT_FFA_PERM_DATA_RW | WT_FFA_PERM_XN),
          "donated perm: but never makes it executable, and a refused change leaves it as it was");
    check(g_domain_fails == 0u, "donated perm: no domain operation failed closed");
}

/* WT-FFA-0009 (later fragments come through the buffer the first one did,
 * DEN0140 4.1.2 rule 6: a sender that unmaps it has its transfer aborted and
 * told so, rule 8). */
static void relay_frag_abort_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint64_t fh = 0u;
    uint64_t other = 0u;
    size_t len = 0u;
    uint32_t offset = 0u;
    uint32_t total = 0u;
    uint8_t op = 0u;
    int done = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "frag abort: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    (void)relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, 0u, &len);
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                40u, (uint32_t)len, &fh) == 0 &&
          wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_B, desc,
                                40u, (uint32_t)len, &other) == 0,
          "frag abort: two senders each start a descriptor in fragments");
    wt_spm_mem_frag_abort(RELAY_ID_A);
    check(wt_spm_mem_frag_next(fh, RELAY_ID_A, &desc[40], (uint32_t)len - 40u,
                               &offset, &done) == WT_FFA_ABORTED &&
          done == 0 &&
          wt_spm_mem_frag_next(fh, RELAY_ID_A, &desc[40], (uint32_t)len - 40u,
                               &offset, &done) == WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_in_transaction(page(PG_RW), WT_TABLES_PAGE_SIZE) == 0 &&
          access_of(&g_dom_a, PG_RW) == WT_DOMAIN_ACCESS_RW,
          "frag abort: the sender that unmapped its TX buffer is told ABORTED once, and nothing was sent");
    check(wt_spm_mem_frag_next(fh, RELAY_ID_A, NULL, 0u, &offset, &done) ==
              WT_FFA_INVALID_PARAMETERS,
          "frag abort: the aborted handle names no transfer afterwards");
    check(wt_spm_mem_frag_next(other, RELAY_ID_B, &desc[40],
                               (uint32_t)len - 40u, &offset, &done) == 0 &&
          done == 1 &&
          wt_spm_mem_frag_desc(other, RELAY_ID_B, &total, &op) != NULL,
          "frag abort: another sender's transfer goes on");
    wt_spm_mem_frag_release(other, RELAY_ID_B);
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                40u, (uint32_t)len, &fh) == 0,
          "frag abort: the sender may start over");
    wt_spm_mem_frag_abort(RELAY_ID_A);
    check(wt_spm_mem_frag_next(fh, RELAY_ID_A, NULL, (uint32_t)len - 40u,
                               &offset, &done) == WT_FFA_ABORTED &&
          wt_spm_mem_frag_desc(fh, RELAY_ID_A, &total, &op) == NULL,
          "frag abort: ABORTED even when no TX buffer is mapped to read the fragment from");
    check(g_domain_fails == 0u, "frag abort: no domain operation failed closed");
}

/* DEN0140 4.1.2 rules 6 and 9: a sender's unfinished transfer keeps its TX
 * buffer busy and is never dropped for a new one; the Normal world keeps a
 * slot no partition can take. */
static void relay_frag_busy_rows(void)
{
    wt_ffa_mem_constituent_t c[1];
    uint8_t desc[256];
    uint64_t fh = 0u;
    uint64_t again = 0u;
    uint64_t fb = 0u;
    uint64_t fc = 0u;
    uint64_t fns = 0u;
    size_t len = 0u;
    uint32_t offset = 0u;
    uint32_t total = 0u;
    uint8_t op = 0u;
    int done = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "frag busy: fixture");
        return;
    }
    c[0].address = page(PG_RW);
    c[0].page_count = 1u;
    (void)relay_build(desc, sizeof(desc), WT_FFA_MEM_OP_LEND, c, 1u,
                      WT_FFA_MEM_PERM_DATA_RW, 0u, &len);
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                40u, (uint32_t)len, &fh) == 0 &&
          wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                40u, (uint32_t)len, &again) == WT_FFA_BUSY,
          "frag busy: a second first fragment from a sender mid-transfer is BUSY");
    check(wt_spm_mem_frag_next(fh, RELAY_ID_A, &desc[40], (uint32_t)len - 40u,
                               &offset, &done) == 0 && done == 1 &&
          wt_spm_mem_frag_desc(fh, RELAY_ID_A, &total, &op) != NULL,
          "frag busy: and the transfer it began goes on to the end");
    wt_spm_mem_frag_release(fh, RELAY_ID_A);
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_A, desc,
                                40u, (uint32_t)len, &fh) == 0 &&
          wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_B, desc,
                                40u, (uint32_t)len, &fb) == 0 &&
          wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND, RELAY_ID_C, desc,
                                40u, (uint32_t)len, &fc) == WT_FFA_NO_MEMORY,
          "frag busy: partitions share their own slots, a third is NO_MEMORY");
    check(wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND,
                                WT_FFA_ID_NS_PRIMARY, desc, 40u,
                                (uint32_t)len, &fns) == 0 &&
          wt_spm_mem_frag_begin((uint8_t)WT_FFA_MEM_OP_LEND,
                                WT_FFA_ID_NS_PRIMARY, desc, 40u,
                                (uint32_t)len, &again) == WT_FFA_BUSY,
          "frag busy: the Normal world still starts one, and is BUSY for a second");
    wt_spm_mem_frag_release(fh, RELAY_ID_A);
    wt_spm_mem_frag_release(fb, RELAY_ID_B);
    wt_spm_mem_frag_release(fns, WT_FFA_ID_NS_PRIMARY);
    check(g_domain_fails == 0u, "frag busy: no domain operation failed closed");
}

/* WT-FFA-0009 (a copy the SPMC makes for the Normal world reaches only memory
 * it still has: none it lent or donated, or that a partition now owns, DEN0140
 * Table 1.3; a page it shares keeps its access, read-only where the share
 * named it so, 1.11.3.1). */
static void relay_ns_access_rows(void)
{
    const uint64_t pg = WT_TABLES_PAGE_SIZE;
    wt_ffa_mem_constituent_t c[1];
    wt_ffa_mem_build_t in;
    uint8_t desc[256];
    uint64_t base;
    uint64_t h;
    size_t len = 0u;
    int ret = 0;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "ns access: fixture");
        return;
    }
    wt_spm_mem_ns_window(page(PG_NS), 2u * WT_TABLES_PAGE_SIZE);
    base = (uint64_t)page(PG_NS);
    check(wt_spm_mem_ns_access(base + 16u, (2u * pg) - 32u, 0) == 1 &&
          wt_spm_mem_ns_access(base, 2u * pg, 1) == 1 &&
          wt_spm_mem_ns_access(base - 16u, 32u, 0) == 0 &&
          wt_spm_mem_ns_access(base + pg, pg + 1u, 1) == 0 &&
          wt_spm_mem_ns_access(0u, 0u, 1) == 1,
          "ns access: the Normal world reads and writes its own window, nothing past it");
    c[0].address = page(PG_NS);
    c[0].page_count = 1u;
    h = relay_send_from(WT_FFA_MEM_OP_LEND, c, 1u, WT_FFA_ID_NS_PRIMARY,
                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ret == 0 && wt_spm_mem_ns_access(base + 100u, 8u, 0) == 0 &&
          wt_spm_mem_ns_access(base + 100u, 8u, 1) == 0 &&
          wt_spm_mem_ns_access(base + pg - 4u, 8u, 0) == 0 &&
          wt_spm_mem_ns_access(base + pg, 8u, 1) == 1,
          "ns access: a page it lent is neither read nor written for it, even by a span that only reaches into it");
    check(relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 0) == 0 &&
          relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 0) == 0 &&
          wt_spm_mem_reclaim(h, WT_FFA_ID_NS_PRIMARY, 0u) == 0 &&
          wt_spm_mem_ns_access(base, pg, 1) == 1,
          "ns access: nor while a borrower maps it or may yet retrieve it; the reclaim gives it back");
    h = relay_send_from(WT_FFA_MEM_OP_SHARE, c, 1u, WT_FFA_ID_NS_PRIMARY,
                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_RW, &ret);
    check(ret == 0 && wt_spm_mem_ns_access(base, 8u, 1) == 1 &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 0) == 1 &&
          wt_spm_mem_ns_access(base, 8u, 1) == 1 &&
          relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          wt_spm_mem_reclaim(h, WT_FFA_ID_NS_PRIMARY, 0u) == 0,
          "ns access: a page it shares stays its to read and write, a borrower mapping it or not");
    (void)memset(&in, 0, sizeof(in));
    in.constituents = c;
    in.constituent_count = 1u;
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = WT_FFA_ID_NS_PRIMARY;
    in.receiver = RELAY_ID_B;
    in.permissions = WT_FFA_MEM_PERM_DATA_RW;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
    ret = wt_ffa_mem_txn_build(desc, sizeof(desc), &in, &len);
    if (ret == 0) {
        len = add_receiver_as(desc, len, WT_FFA_ID_NS_PRIMARY,
                              WT_FFA_MEM_PERM_DATA_RO);
        ret = wt_spm_mem_share(desc, len, WT_FFA_MEM_OP_SHARE,
                               WT_FFA_ID_NS_PRIMARY, &h);
    }
    check(ret == 0 && wt_spm_mem_ns_access(base, 8u, 0) == 1 &&
          wt_spm_mem_ns_access(base, 8u, 1) == 0 &&
          wt_spm_mem_reclaim(h, WT_FFA_ID_NS_PRIMARY, 0u) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 1) == 1,
          "ns access: a share naming it read-only leaves it reading until it reclaims");
    h = relay_send_from(WT_FFA_MEM_OP_DONATE, c, 1u, WT_FFA_ID_NS_PRIMARY,
                        RELAY_ID_B, WT_FFA_MEM_PERM_DATA_NOT_SPEC, &ret);
    check(ret == 0 && wt_spm_mem_ns_access(base, 8u, 0) == 0 &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          wt_spm_mem_in_transaction(base, pg) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 0) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 1) == 0 &&
          wt_spm_mem_ns_access(base + pg, 8u, 1) == 1,
          "ns access: a page it donated is never its again, before or after the receiver takes it");
    check(wt_spm_mem_perm_set(&g_dom_b, &g_relay_mailbox, page(PG_NS), 1u,
                              WT_FFA_PERM_DATA_NONE) == 0 &&
          wt_spm_mem_ns_access(base, 8u, 0) == 0,
          "ns access: nor once its new owner makes it no-access");
    check(g_domain_fails == 0u, "ns access: no domain operation failed closed");
}

/* WT-FFA-0009 (the Normal world can rewrite its TX buffer while the relayer
 * reads it: what is registered is the descriptor that was validated, whole or
 * reassembled from fragments, and one too large to copy is NO_MEMORY). */
static void relay_ns_snapshot_rows(void)
{
    static uint8_t big[WT_FFA_MEM_FRAG_MAX + 16u];
    wt_ffa_mem_constituent_t c[1];
    wt_ffa_mem_build_t in;
    uint8_t* recv;
    uint8_t tx[256];
    uint64_t h = 0u;
    uint32_t offset = 0u;
    size_t len = 0u;
    int done = 0;
    int ret;

    if ((g_mem == NULL) || !relay_reset()) {
        check(0, "ns snapshot: fixture");
        return;
    }
    wt_spm_mem_ns_window(page(PG_NS), 2u * WT_TABLES_PAGE_SIZE);
    c[0].address = page(PG_NS);
    c[0].page_count = 1u;
    (void)memset(&in, 0, sizeof(in));
    in.constituents = c;
    in.constituent_count = 1u;
    in.op = WT_FFA_MEM_OP_LEND;
    in.sender = WT_FFA_ID_NS_PRIMARY;
    in.receiver = RELAY_ID_B;
    in.permissions = WT_FFA_MEM_PERM_DATA_RW;
    in.access_desc_size = (uint8_t)WT_FFA_MEM_ACCESS_SIZE;
    ret = wt_ffa_mem_txn_build(tx, sizeof(tx), &in, &len);
    recv = &tx[WT_FFA_MEM_TXN_HDR_SIZE + WT_FFA_MEM_ACC_OFF_RECEIVER];
    g_race_at = recv;
    g_race_to = (uint8_t)(RELAY_ID_C & 0xFFu);
    if (ret == 0) {
        ret = wt_spm_mem_ns_send(WT_FFA_MEM_OP_LEND, tx, (uint32_t)len,
                                 (uint32_t)len, &h);
    }
    check(ret == 0 && g_race_at == NULL &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_C,
                            WT_FFA_MEM_PERM_DATA_RW) != 0 &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0,
          "ns snapshot: a descriptor rewritten mid-send lends to the borrower it was validated with");
    check(relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          wt_spm_mem_reclaim(h, WT_FFA_ID_NS_PRIMARY, 0u) == 0,
          "ns snapshot: and that borrower hands it back to the Normal world");
    *recv = (uint8_t)(RELAY_ID_B & 0xFFu);
    ret = wt_spm_mem_ns_send(WT_FFA_MEM_OP_LEND, tx, 40u, (uint32_t)len, &h);
    if (ret == 0) {
        ret = wt_spm_mem_frag_next(h, WT_FFA_ID_NS_PRIMARY, &tx[40],
                                   (uint32_t)len - 40u, &offset, &done);
    }
    g_race_at = recv;
    if ((ret == 0) && (done == 1)) {
        ret = wt_spm_mem_frag_share(h, WT_FFA_ID_NS_PRIMARY);
    }
    check(ret == 0 && g_race_at == NULL &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_C,
                            WT_FFA_MEM_PERM_DATA_RW) != 0 &&
          relay_retrieve_by(h, WT_FFA_ID_NS_PRIMARY, RELAY_ID_B,
                            WT_FFA_MEM_PERM_DATA_RW) == 0 &&
          relay_relinquish_as(h, RELAY_ID_B) == 0 &&
          wt_spm_mem_reclaim(h, WT_FFA_ID_NS_PRIMARY, 0u) == 0,
          "ns snapshot: so does one sent in fragments and rewritten once they are in");
    g_race_at = NULL;
    (void)memcpy(big, tx, len);
    check(wt_spm_mem_ns_send(WT_FFA_MEM_OP_LEND, big, (uint32_t)sizeof(big),
                             (uint32_t)sizeof(big), &h) == WT_FFA_NO_MEMORY &&
          wt_spm_mem_ns_send(WT_FFA_MEM_OP_LEND, big,
                             WT_FFA_MEM_FRAG_MAX + 1u,
                             WT_FFA_MEM_FRAG_MAX + 2u, &h) ==
              WT_FFA_NO_MEMORY &&
          wt_spm_mem_ns_send(WT_FFA_MEM_OP_LEND, tx, (uint32_t)len,
                             (uint32_t)len - 1u, &h) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_ns_send(WT_FFA_MEM_OP_LEND, tx, 0u, (uint32_t)len, &h) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_spm_mem_in_transaction(page(PG_NS), WT_TABLES_PAGE_SIZE) == 0,
          "ns snapshot: past the Secure copy is NO_MEMORY, a bad length INVALID_PARAMETERS, nothing registered");
    check(g_domain_fails == 0u, "ns snapshot: no domain operation failed closed");
}

int main(void)
{
    printf("WT-FFA-0009 (FF-A memory transaction descriptors and handle state)\n");

    fid_rows();
    txn_rows();
    reject_rows();
    access_offset_rows();
    rxtx_rows();
    mailbox_rows();
    tx_buffer_rows();
    registry_rows();
    share_rows();
    constituent_limit_rows();
    retrieve_rows();
    borrower_rows();
    frag_rows();
    retrieve_check_rows();
    time_slice_rows();
    send_handle_rows();
    attribute_rows();
    send_attribute_rows();
    access_flag_rows();
    borrower_list_rows();
    v10_rows();
    relay_rows();
    relay_owner_rows();
    relay_attr_rows();
    relay_perm_rows();
    relay_zero_rows();
    relay_multi_zero_rows();
    relay_own_access_rows();
    relay_clean_rows();
    relay_region_rows();
    relay_donate_rows();
    relay_mailbox_rows();
    relay_self_rows();
    relay_perm_set_rows();
    relay_icache_rows();
    relay_teardown_rows();
    relay_v10_rows();
    relay_unbind_rows();
    relay_ns_donate_rows();
    relay_donated_perm_rows();
    relay_access_size_rows();
    relay_range_rows();
    relay_align_rows();
    relay_frag_abort_rows();
    relay_frag_busy_rows();
    relay_ns_access_rows();
    relay_ns_snapshot_rows();

    if (g_mem != NULL) {
        (void)munmap(g_mem, (size_t)RELAY_MEM_PAGES * WT_TABLES_PAGE_SIZE);
    }
    printf("ffa_mem: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
