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

/* WT-FFA-0001 / WT-FFA-0002: the FF-A function-id table, status codes, id
 * spaces, and the version negotiation rules of DEN0077A 13.2. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_manifest.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/ffa_partinfo.h"

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

static const uint32_t g_fids[] = {
    WT_FFA_ERROR, WT_FFA_SUCCESS32, WT_FFA_SUCCESS64, WT_FFA_INTERRUPT,
    WT_FFA_VERSION, WT_FFA_FEATURES, WT_FFA_RX_RELEASE, WT_FFA_RXTX_MAP32,
    WT_FFA_RXTX_MAP64, WT_FFA_RXTX_UNMAP, WT_FFA_PARTITION_INFO_GET,
    WT_FFA_ID_GET, WT_FFA_MSG_WAIT, WT_FFA_YIELD, WT_FFA_RUN,
    WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_MSG_SEND_DIRECT_REQ64,
    WT_FFA_MSG_SEND_DIRECT_RESP32, WT_FFA_MSG_SEND_DIRECT_RESP64,
    WT_FFA_NORMAL_WORLD_RESUME, WT_FFA_NOTIFICATION_BITMAP_CREATE,
    WT_FFA_RX_ACQUIRE, WT_FFA_SPM_ID_GET, WT_FFA_MSG_SEND2,
    WT_FFA_CONSOLE_LOG32, WT_FFA_CONSOLE_LOG64,
    WT_FFA_PARTITION_INFO_GET_REGS, WT_FFA_MSG_SEND_DIRECT_REQ2,
    WT_FFA_MSG_SEND_DIRECT_RESP2
};

static const int32_t g_codes[] = {
    WT_FFA_NOT_SUPPORTED, WT_FFA_INVALID_PARAMETERS, WT_FFA_NO_MEMORY,
    WT_FFA_BUSY, WT_FFA_INTERRUPTED, WT_FFA_DENIED, WT_FFA_RETRY,
    WT_FFA_ABORTED, WT_FFA_NO_DATA, WT_FFA_NOT_READY
};

/* WT-FFA-0005: direct-message register encodings (15.2/15.3) and the relayer
 * checks of 7.4.2. */
static void direct_message_rows(void)
{
    static const uint32_t payload[WT_FFA_DIRECT_PAYLOAD_WORDS] = {
        0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u, 0x55555555u
    };
    uint64_t x[8];
    unsigned int i;
    int ok;

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, payload);
    ok = ((uint32_t)x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32) &&
         (wt_ffa_direct_sender(x[1]) == WT_FFA_ID_NS_PRIMARY) &&
         (wt_ffa_direct_receiver(x[1]) == WT_FFA_ID_SP_FIRST) && (x[2] == 0u);
    for (i = 0u; i < WT_FFA_DIRECT_PAYLOAD_WORDS; i++) {
        ok = ok && ((uint32_t)x[3u + i] == payload[i]);
    }
    check(ok, "a direct request packs ids in w1, keeps w2 zero, and carries the payload in x3-x7");

    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) == 0,
          "the SPMD relays a Normal-world request to a Secure partition");
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "the SPMC does not relay a Normal-world sender between partitions");

    x[2] = WT_FFA_DIRECT_FRAMEWORK_BIT;
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "a partition request with a non-zero w2 is INVALID_PARAMETERS");
    x[2] = 0u;

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_SP_FIRST,
                        WT_FFA_ID_SP_FIRST, payload);
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "a request whose sender equals its receiver is INVALID_PARAMETERS");

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ32, WT_FFA_ID_NS_PRIMARY,
                        0x0001u, payload);
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "a Normal-world request to a Normal-world receiver is INVALID_PARAMETERS");

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ32,
                        (uint16_t)(WT_FFA_ID_SP_FIRST + 1u), WT_FFA_ID_SP_FIRST,
                        payload);
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) == 0,
          "the SPMC relays a request between two Secure partitions");
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "the SPMD does not relay a Secure sender as a Normal-world request");

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_RESP32, WT_FFA_ID_SP_FIRST,
                        WT_FFA_ID_NS_PRIMARY, payload);
    check(wt_ffa_direct_resp_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) == 0 &&
          wt_ffa_direct_resp_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) == 0,
          "a Secure partition's response returns to the Normal-world requester");
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "a response frame is not accepted as a request");

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_RESP32, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, payload);
    check(wt_ffa_direct_resp_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "a response whose sender is not Secure is INVALID_PARAMETERS");

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ2, WT_FFA_ID_NS_PRIMARY,
                        WT_FFA_ID_SP_FIRST, payload);
    x[2] = 0x1122334455667788ull;
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) == 0,
          "FFA_MSG_SEND_DIRECT_REQ2 carries a UUID in x2, not a reserved word");
    check(wt_ffa_msg_reg_count(x[0]) == WT_FFA_MSG_REGS_EXT &&
              wt_ffa_msg_reg_count(WT_FFA_MSG_SEND_DIRECT_REQ64) ==
                  WT_FFA_MSG_REGS,
          "only REQ2 and RESP2 relay x8-x17");
    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_RESP2, WT_FFA_ID_SP_FIRST,
                        WT_FFA_ID_NS_PRIMARY, payload);
    check(wt_ffa_direct_resp_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) ==
              WT_FFA_INVALID_PARAMETERS,
          "FFA_MSG_SEND_DIRECT_RESP2 keeps x2 and x3 zero");
    x[3] = 0u;
    check(wt_ffa_direct_resp_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) == 0,
          "a well-formed RESP2 returns to the Normal-world requester");
}

static uint32_t rd_u16(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t rd_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* WT-FFA-0003 (6.1/6.2 discovery descriptors, Nil-UUID lists all) and
 * WT-FFA-0004 (7.2 RX buffer: producer zero-fills, NO_MEMORY when too small). */
static void partition_info_rows(void)
{
    static const wt_ffa_partinfo_entry_t parts[3] = {
        { 0x8002u, 1u, WT_FFA_PARTINFO_PROP_DIRECT_RECV |
                       WT_FFA_PARTINFO_PROP_DIRECT_SEND,
          { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10 } },
        { 0x8003u, 1u, WT_FFA_PARTINFO_PROP_DIRECT_RECV |
                       WT_FFA_PARTINFO_PROP_DIRECT_SEND,
          { 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
            0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20 } },
        { 0x8004u, 2u, WT_FFA_PARTINFO_PROP_INDIRECT,
          { 0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
            0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30 } }
    };
    static const uint8_t nil[16] = { 0 };
    uint8_t rx[128];
    uint64_t regs[18];
    uint32_t count;
    uint32_t size;
    int ret;
    int ok;
    unsigned int i;

    check(wt_ffa_partinfo_desc_size(WT_FFA_VERSION_MAKE(1u, 0u)) ==
              WT_FFA_PARTINFO_DESC_V10 &&
          wt_ffa_partinfo_desc_size(WT_FFA_VERSION_1_2) ==
              WT_FFA_PARTINFO_DESC_V11,
          "a 1.0 caller gets 8-byte descriptors, a 1.1+ caller 24-byte with the UUID");

    for (i = 0u; i < sizeof(rx); i++) {
        rx[i] = 0xEEu;
    }
    ret = wt_ffa_partinfo_write(rx, sizeof(rx), WT_FFA_VERSION_1_2, parts, 3u,
                                nil, 0u, &count, &size);
    check(ret == 0 && count == 3u && size == WT_FFA_PARTINFO_DESC_V11,
          "a Nil UUID lists every partition with the 1.2 descriptor size");
    check(rd_u16(&rx[0]) == 0x8002u && rd_u16(&rx[2]) == 1u &&
          rd_u32(&rx[4]) == (WT_FFA_PARTINFO_PROP_DIRECT_RECV |
                             WT_FFA_PARTINFO_PROP_DIRECT_SEND) &&
          rx[8] == 0x01u && rx[23] == 0x10u,
          "the first descriptor decodes id, context count, properties, and UUID");
    check(rx[5] == 0u && rx[6] == 0u && rx[7] == 0u,
          "the producer zeroes descriptor bytes it does not fill");
    check(rd_u16(&rx[WT_FFA_PARTINFO_DESC_V11]) == 0x8003u &&
          rd_u16(&rx[2u * WT_FFA_PARTINFO_DESC_V11]) == 0x8004u,
          "descriptors pack back to back at the descriptor size");

    for (i = 0u; i < sizeof(rx); i++) {
        rx[i] = 0xEEu;
    }
    ret = wt_ffa_partinfo_write(rx, sizeof(rx), WT_FFA_VERSION_1_2, parts, 3u,
                                parts[1].uuid, 0u, &count, &size);
    check(ret == 0 && count == 1u && rd_u16(&rx[0]) == 0x8003u,
          "a specific UUID returns only the matching partition");
    ok = 1;
    for (i = 8u; i < WT_FFA_PARTINFO_DESC_V11; i++) {
        ok = ok && (rx[i] == 0u);
    }
    check(ok, "a specific-UUID query leaves the descriptor UUID field zero (MBZ)");

    ret = wt_ffa_partinfo_write(NULL, 0u, WT_FFA_VERSION_1_2, parts, 3u, nil,
                                WT_FFA_PARTINFO_FLAG_COUNT, &count, &size);
    check(ret == 0 && count == 3u && size == 0u,
          "the count-only flag returns the count without writing descriptors");

    ret = wt_ffa_partinfo_write(rx, sizeof(rx), WT_FFA_VERSION_1_2, parts, 3u,
                                nil, 0x2u, &count, &size);
    check(ret == WT_FFA_INVALID_PARAMETERS,
          "a reserved flag bit is INVALID_PARAMETERS");

    ret = wt_ffa_partinfo_write(rx, WT_FFA_PARTINFO_DESC_V11 + 1u,
                                WT_FFA_VERSION_1_2, parts, 3u, nil, 0u, &count,
                                &size);
    check(ret == WT_FFA_NO_MEMORY,
          "an RX buffer too small for the matches is NO_MEMORY");

    ret = wt_ffa_partinfo_regs(parts, 3u, nil, 0u, 0u, regs);
    check(ret == 0 && (uint32_t)regs[0] == WT_FFA_SUCCESS64 &&
              (regs[2] & 0xFFFFu) == 2u && ((regs[2] >> 16) & 0xFFFFu) == 2u &&
              (regs[2] >> 48) == WT_FFA_PARTINFO_DESC_V11 &&
              (regs[3] & 0xFFFFu) == parts[0].id &&
              (regs[9] & 0xFFFFu) == parts[2].id && regs[12] == 0u,
          "FFA_PARTITION_INFO_GET_REGS packs every match from index 0");
    ret = wt_ffa_partinfo_regs(parts, 3u, nil, 2u, 0u, regs);
    check(ret == 0 && (regs[3] & 0xFFFFu) == parts[2].id &&
              ((regs[2] >> 16) & 0xFFFFu) == 2u && regs[6] == 0u,
          "a start index resumes the listing there");
    ret = wt_ffa_partinfo_regs(parts, 3u, nil, 0u, 0u, regs);
    check(ret == 0 && (uint8_t)regs[4] == parts[0].uuid[0] &&
              (uint8_t)(regs[5] >> 56) == parts[0].uuid[15] &&
              (uint8_t)regs[10] == parts[2].uuid[0],
          "a Nil-UUID query returns each UUID in two registers");
    ret = wt_ffa_partinfo_regs(parts, 3u, parts[1].uuid, 0u, 0u, regs);
    check(ret == 0 && (regs[2] & 0xFFFFu) == 0u &&
              (regs[3] & 0xFFFFu) == parts[1].id &&
              regs[4] == 0u && regs[5] == 0u,
          "a specific UUID selects its partition with the UUID registers zero (MBZ)");
    check(wt_ffa_partinfo_regs(parts, 3u, nil, 3u, 0u, regs) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_partinfo_regs(parts, 3u, rx, 0u, 0u, regs) ==
              WT_FFA_INVALID_PARAMETERS,
          "a start past the end or an unknown UUID is refused");
    check(wt_ffa_partinfo_regs(parts, 3u, nil, 0u, 1u, regs) ==
              WT_FFA_INVALID_PARAMETERS,
          "a nonzero tag at start index 0 is INVALID_PARAMETERS (MBZ)");
    check(wt_ffa_partinfo_regs(parts, 3u, nil, 1u, 1u, regs) == WT_FFA_RETRY &&
          wt_ffa_partinfo_regs(parts, 3u, nil, 1u, 0u, regs) == 0,
          "a continuation with a tag the callee did not hand out is RETRY");
}

/* Discovery records from the manifest: the id is the live endpoint id of the
 * partition running in the domain, and a domain nothing runs in is omitted. */
static void manifest_record_rows(void)
{
    static const wt_ffa_uuid_t uuids[1] = {
        { { 0x4fu, 0xd3u, 0xdau, 0x63u, 0x10u, 0x2cu, 0x5eu, 0xf8u,
            0x9eu, 0xadu, 0x37u, 0x6bu, 0xd7u, 0x22u, 0xc3u, 0x37u } }
    };
    static const wt_ffa_partition_manifest_t part = {
        uuids, 4u, 1u, 1u, WT_FFA_RUNTIME_EL_SEL0, WT_FFA_MESSAGING_DIRECT,
        WT_FFA_NS_INTERRUPT_QUEUED, 0u
    };
    static const wt_ffa_uuid_t uuids2[2] = {
        { { 0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
            0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu } },
        { { 0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
            0x28u, 0x29u, 0x2au, 0x2bu, 0x2cu, 0x2du, 0x2eu, 0x2fu } }
    };
    static const wt_ffa_partition_manifest_t two = {
        uuids2, 7u, 2u, 1u, WT_FFA_RUNTIME_EL_SEL0, WT_FFA_MESSAGING_DIRECT,
        WT_FFA_NS_INTERRUPT_QUEUED, 0u
    };
    static const wt_ffa_partition_manifest_t none = {
        uuids2, 8u, 0u, 1u, WT_FFA_RUNTIME_EL_SEL0, WT_FFA_MESSAGING_DIRECT,
        WT_FFA_NS_INTERRUPT_QUEUED, 0u
    };
    static const uint8_t nil[16] = { 0 };
    wt_ffa_partinfo_entry_t out[2];
    uint32_t count = 0u;
    uint32_t size = 0u;
    size_t n = 99u;
    int ret;

    ret = wt_ffa_partinfo_from_manifest(&part, 0x8002u, out, 2u, &n);
    check(ret == 0 && n == 1u && out[0].id == 0x8002u &&
              out[0].exec_contexts == 1u &&
              memcmp(out[0].uuid, uuids[0].bytes, 16u) == 0,
          "a manifest partition is listed under its live id with its UUID");
    check((out[0].properties & WT_FFA_PARTINFO_PROP_AARCH64) != 0u,
          "a manifest partition reports the AArch64 execution state (bit 8)");
    check(out[0].properties == WT_FFA_PARTINFO_PROP_AARCH64,
          "a manifest partition declaring direct messaging advertises no FF-A "
          "messaging, since its services are reached through the PSA endpoint");
    check(wt_ffa_partinfo_write(NULL, 0u, WT_FFA_VERSION_1_2, out, n,
                                uuids[0].bytes, WT_FFA_PARTINFO_FLAG_COUNT,
                                &count, &size) == 0 && count == 1u,
          "its UUID finds that record");
    n = 99u;
    ret = wt_ffa_partinfo_from_manifest(&part, 0u, out, 2u, &n);
    check(ret == 0 && n == 0u,
          "a domain no live partition runs in is omitted");
    n = 99u;
    ret = wt_ffa_partinfo_from_manifest(&part, 0x8007u, out, 0u, &n);
    check(ret == WT_FFA_NO_MEMORY && n == 0u,
          "no room for the record is NO_MEMORY");
    check(wt_ffa_partinfo_write(NULL, 0u, WT_FFA_VERSION_1_2, out, 0u, nil,
                                WT_FFA_PARTINFO_FLAG_COUNT, &count, &size) ==
              0 && count == 0u,
          "an empty listing counts zero");

    n = 99u;
    ret = wt_ffa_partinfo_from_manifest(&two, 0x8005u, out, 2u, &n);
    check(ret == 0 && n == 2u && out[0].id == 0x8005u &&
              out[1].id == 0x8005u &&
              memcmp(out[0].uuid, uuids2[0].bytes, 16u) == 0 &&
              memcmp(out[1].uuid, uuids2[1].bytes, 16u) == 0,
          "a partition exporting two UUIDs gets a record per UUID under one id");
    check(wt_ffa_partinfo_write(NULL, 0u, WT_FFA_VERSION_1_2, out, n, nil,
                                WT_FFA_PARTINFO_FLAG_COUNT, &count, &size) ==
              0 && count == 2u,
          "a Nil-UUID count covers every exported UUID");
    check(wt_ffa_partinfo_write(NULL, 0u, WT_FFA_VERSION_1_2, out, n,
                                uuids2[1].bytes, WT_FFA_PARTINFO_FLAG_COUNT,
                                &count, &size) == 0 && count == 1u,
          "the second UUID finds the partition too");
    n = 99u;
    check(wt_ffa_partinfo_from_manifest(&two, 0x8005u, out, 1u, &n) ==
              WT_FFA_NO_MEMORY && n == 0u,
          "room for fewer records than UUIDs is NO_MEMORY");
    check(wt_ffa_partinfo_from_manifest(&none, 0x8006u, out, 2u, &n) ==
              WT_FFA_INVALID_PARAMETERS,
          "a partition exporting no UUID is refused");
}

/* Tables 6.2, 15.8 and 15.16: a direct request goes only to an endpoint that
 * takes that kind (DENIED otherwise), and an id no partition has is
 * INVALID_PARAMETERS. */
static void direct_permission_rows(void)
{
    static const wt_ffa_partinfo_entry_t parts[3] = {
        { 0x8008u, 1u, 0x70Fu, { 0x01 } },
        { 0x8002u, 1u, WT_FFA_PARTINFO_PROP_AARCH64, { 0x02 } },
        { 0x8002u, 1u, WT_FFA_PARTINFO_PROP_NOTIF, { 0x03 } }
    };
    const uint32_t native = 0x70Fu;
    const uint32_t manifest = WT_FFA_PARTINFO_PROP_AARCH64;
    const uint32_t req_only = WT_FFA_PARTINFO_PROP_DIRECT_RECV;
    uint32_t props = 99u;

    check(wt_ffa_partinfo_props_of(parts, 3u, 0x8008u, &props) == 0 &&
              props == 0x70Fu,
          "a listed partition's properties are found by its id");
    check(wt_ffa_partinfo_props_of(parts, 3u, 0x8002u, &props) == 0 &&
              props == (WT_FFA_PARTINFO_PROP_AARCH64 |
                        WT_FFA_PARTINFO_PROP_NOTIF),
          "a partition listed once per UUID has the union of its records");
    check(wt_ffa_partinfo_props_of(parts, 3u, 0x8009u, &props) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_partinfo_props_of(parts, 0u, 0x8008u, &props) ==
              WT_FFA_INVALID_PARAMETERS,
          "an id no partition has is INVALID_PARAMETERS");

    check(wt_ffa_direct_req_allowed(native, WT_FFA_MSG_SEND_DIRECT_REQ32, 1) ==
              0 &&
          wt_ffa_direct_req_allowed(native, WT_FFA_MSG_SEND_DIRECT_REQ64, 1) ==
              0 &&
          wt_ffa_direct_req_allowed(native, WT_FFA_MSG_SEND_DIRECT_REQ2, 1) ==
              0 &&
          wt_ffa_direct_req_allowed(native, WT_FFA_MSG_SEND_DIRECT_REQ2, 0) ==
              0,
          "an endpoint advertising both kinds takes and sends both");
    check(wt_ffa_direct_req_allowed(manifest, WT_FFA_MSG_SEND_DIRECT_REQ32,
                                    1) == WT_FFA_DENIED &&
          wt_ffa_direct_req_allowed(manifest, WT_FFA_MSG_SEND_DIRECT_REQ64,
                                    1) == WT_FFA_DENIED &&
          wt_ffa_direct_req_allowed(manifest, WT_FFA_MSG_SEND_DIRECT_REQ2,
                                    1) == WT_FFA_DENIED,
          "a request to an endpoint that takes none is DENIED");
    check(wt_ffa_direct_req_allowed(req_only, WT_FFA_MSG_SEND_DIRECT_REQ32,
                                    1) == 0 &&
          wt_ffa_direct_req_allowed(req_only, WT_FFA_MSG_SEND_DIRECT_REQ2,
                                    1) == WT_FFA_DENIED,
          "FFA_MSG_SEND_DIRECT_REQ receipt does not imply REQ2 receipt");
    check(wt_ffa_direct_req_allowed(req_only, WT_FFA_MSG_SEND_DIRECT_REQ32,
                                    0) == WT_FFA_DENIED &&
          wt_ffa_direct_req_allowed(WT_FFA_PARTINFO_PROP_REQ2_SEND,
                                    WT_FFA_MSG_SEND_DIRECT_REQ2, 0) == 0,
          "sending is judged on the send bits, not the receive bits");
}

/* FFA_PARTITION_INFO_GET through the caller's mailbox (13.8, Table 13.36):
 * descriptors need its RX buffer mapped and free, a count needs none. */
static void partition_info_mailbox_rows(void)
{
    static const wt_ffa_partinfo_entry_t parts[2] = {
        { 0x8002u, 1u, 0u,
          { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10 } },
        { 0x8003u, 1u, 0u,
          { 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
            0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20 } }
    };
    static _Alignas(4096) uint8_t pair[2][4096];
    const uint32_t v12 = WT_FFA_VERSION_1_2;
    wt_ffa_mailbox_t mb;
    uint64_t x[8] = { WT_FFA_PARTITION_INFO_GET, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret;

    memset(&mb, 0, sizeof(mb));
    memset(pair, 0xEE, sizeof(pair));
    x[5] = WT_FFA_PARTINFO_FLAG_COUNT;
    ret = wt_ffa_partinfo_get(x, v12, NULL, parts, 2u, &count, &size);
    check(ret == 0 && count == 2u && size == 0u,
          "a count-only query needs no RX buffer");
    x[5] = 0u;
    check(wt_ffa_partinfo_get(x, v12, NULL, parts, 2u, &count, &size) ==
              WT_FFA_BUSY &&
          wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size) ==
              WT_FFA_BUSY && pair[1][0] == 0xEEu,
          "descriptors with no RX buffer mapped are BUSY and written nowhere");

    check(wt_ffa_mailbox_map(&mb, (uint64_t)(uintptr_t)pair[0],
                             (uint64_t)(uintptr_t)pair[1], 1u) == 0,
          "the caller maps its RX/TX pair");
    ret = wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size);
    check(ret == 0 && count == 2u && size == WT_FFA_PARTINFO_DESC_V11 &&
              rd_u16(&pair[1][0]) == 0x8002u &&
              rd_u16(&pair[1][WT_FFA_PARTINFO_DESC_V11]) == 0x8003u &&
              mb.rx_full != 0u,
          "descriptors land in the mapped RX buffer, which the caller now owns");
    check(wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size) ==
              WT_FFA_BUSY,
          "a second query before RX_RELEASE is BUSY");
    check(wt_ffa_mailbox_rx_release(&mb) == 0 &&
          wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size) == 0,
          "after RX_RELEASE the buffer takes descriptors again");
    check(wt_ffa_mailbox_rx_release(&mb) == 0,
          "the caller hands RX back after reading");

    x[1] = 0xDEADBEEFu;
    check(wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size) ==
              WT_FFA_INVALID_PARAMETERS && mb.rx_full == 0u,
          "an unknown UUID is refused before the RX buffer changes hands");
    x[1] = 0x14131211u;
    x[2] = 0x18171615u;
    x[3] = 0x1C1B1A19u;
    x[4] = 0x201F1E1Du;
    ret = wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size);
    check(ret == 0 && count == 1u && rd_u16(&pair[1][0]) == 0x8003u,
          "a UUID in w1-w4 selects its partition");
    check(wt_ffa_mailbox_rx_release(&mb) == 0 &&
          wt_ffa_mailbox_unmap(&mb) == 0 &&
          wt_ffa_partinfo_get(x, v12, &mb, parts, 2u, &count, &size) ==
              WT_FFA_BUSY,
          "once the pair is unmapped, descriptors are BUSY again");
}

/* 18.5.3: a caller that negotiated FF-A 1.0 gets the v1.0 partition
 * information descriptor (Table 18.22), a 1.1+ caller the 24-byte one. */
static void partition_info_version_rows(void)
{
    static const wt_ffa_partinfo_entry_t parts[2] = {
        { 0x8002u, 1u, 0x0000070Fu,
          { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10 } },
        { 0x8003u, 1u, 0x00000105u,
          { 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
            0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20 } }
    };
    static _Alignas(4096) uint8_t pair[2][4096];
    wt_ffa_mailbox_t mb;
    uint64_t x[8] = { WT_FFA_PARTITION_INFO_GET, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    uint32_t count = 0u;
    uint32_t size = 0u;
    unsigned int i;
    int ok;
    int ret;

    memset(&mb, 0, sizeof(mb));
    memset(pair, 0xEE, sizeof(pair));
    check(wt_ffa_mailbox_map(&mb, (uint64_t)(uintptr_t)pair[0],
                             (uint64_t)(uintptr_t)pair[1], 1u) == 0,
          "the v1.0 caller maps its RX/TX pair");
    ret = wt_ffa_partinfo_get(x, WT_FFA_VERSION_MAKE(1u, 0u), &mb, parts, 2u,
                              &count, &size);
    check(ret == 0 && count == 2u && size == WT_FFA_PARTINFO_DESC_V10 &&
              rd_u16(&pair[1][0]) == 0x8002u &&
              rd_u16(&pair[1][WT_FFA_PARTINFO_DESC_V10]) == 0x8003u,
          "a 1.0 caller gets 8-byte descriptors packed back to back");
    check(rd_u32(&pair[1][4]) == 0x7u &&
              rd_u32(&pair[1][WT_FFA_PARTINFO_DESC_V10 + 4u]) == 0x5u,
          "and only the property bits the v1.0 descriptor defines (2:0)");
    ok = 1;
    for (i = 2u * WT_FFA_PARTINFO_DESC_V10;
         i < (2u * WT_FFA_PARTINFO_DESC_V11); i++) {
        ok = ok && (pair[1][i] == 0xEEu);
    }
    check(ok, "nothing is written past the two v1.0 descriptors");
    check(wt_ffa_mailbox_rx_release(&mb) == 0, "the 1.0 caller hands RX back");

    ret = wt_ffa_partinfo_get(x, WT_FFA_VERSION_MAKE(1u, 1u), &mb, parts, 2u,
                              &count, &size);
    check(ret == 0 && count == 2u && size == WT_FFA_PARTINFO_DESC_V11 &&
              rd_u32(&pair[1][4]) == 0x70Fu && pair[1][8] == 0x01u &&
              rd_u16(&pair[1][WT_FFA_PARTINFO_DESC_V11]) == 0x8003u,
          "a 1.1 caller gets the 24-byte descriptor with every property and the UUID");
    check(wt_ffa_mailbox_rx_release(&mb) == 0 && wt_ffa_mailbox_unmap(&mb) == 0,
          "the caller releases and unmaps its pair");
}

/* WT-FFA-0002 (version renegotiation, 13.2). */
static void version_state_rows(void)
{
    wt_ffa_version_state_t st = { 0u, 0u };

    check(wt_ffa_version_negotiate(&st, WT_FFA_VERSION_MAKE(1u, 1u),
                                   WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2 &&
          wt_ffa_version_negotiate(&st, WT_FFA_VERSION_1_2,
                                   WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a caller may renegotiate before its first other call");
    wt_ffa_version_lock(&st, WT_FFA_VERSION_1_2);
    check(wt_ffa_version_negotiate(&st, WT_FFA_VERSION_MAKE(1u, 1u),
                                   WT_FFA_VERSION_1_2) == WT_FFA_NOT_SUPPORTED &&
          wt_ffa_version_negotiate(&st, WT_FFA_VERSION_1_2,
                                   WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "after it, only the settled version is accepted");
    st.version = 0u;
    st.locked = 0u;
    wt_ffa_version_lock(&st, WT_FFA_VERSION_1_2);
    check(wt_ffa_version_negotiate(&st, WT_FFA_VERSION_MAKE(1u, 1u),
                                   WT_FFA_VERSION_1_2) == WT_FFA_NOT_SUPPORTED,
          "a caller that never negotiated is held to the callee version");
}


/* The v1.2 partition message header of FFA_MSG_SEND2 (16.4) and the w1/w2
 * rules of Table 15.3 per instance, as its relayer validates them. */
static void msg2_rows(void)
{
    uint8_t tx[4096];
    wt_ffa_msg2_t m;
    const wt_ffa_instance_t ns = WT_FFA_INSTANCE_NS_PHYSICAL;
    const wt_ffa_instance_t sv = WT_FFA_INSTANCE_SECURE_VIRTUAL;
    static const uint8_t ep_uuid[16] = {
        1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u,
        9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u
    };
    unsigned int i;

    memset(tx, 0, sizeof(tx));
    /* offset 40, sender 0 receiver 0x8002, size 32, uuid = the endpoint's */
    tx[8] = 40u;
    tx[12] = 0x02u; tx[13] = 0x80u;
    tx[16] = 32u;
    for (i = 0u; i < 16u; i++) {
        tx[24u + i] = ep_uuid[i];
    }

    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u, 0u, &m) == 0,
          "a well-formed header parses");
    check((m.receiver == 0x8002u) && (m.offset == 40u) && (m.size == 32u),
          "and yields receiver, offset and size");
    check(wt_ffa_msg2_uuid_ok(m.uuid, ep_uuid) == 1,
          "the receiver's own UUID is accepted");
    tx[24] = 0xAAu;
    check(wt_ffa_msg2_uuid_ok(&tx[24], ep_uuid) == 0,
          "a foreign UUID is refused");
    memset(&tx[24], 0, 16u);
    check(wt_ffa_msg2_uuid_ok(&tx[24], ep_uuid) == 1,
          "a Nil UUID is accepted");

    check(wt_ffa_msg2_parse(tx, 39u, 0u, ns, 0u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS, "a TX smaller than the header is refused");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 1u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS, "reserved w1 bits are refused");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u, 0x1u, &m) ==
          WT_FFA_INVALID_PARAMETERS,
          "at the NS physical instance reserved flags are refused");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u,
                            WT_FFA_MSG2_FLAG_DELAY_SRI, &m) ==
          WT_FFA_INVALID_PARAMETERS,
          "and so is the delay-SRI hint, Secure virtual only");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0x8003u, sv, 0u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS,
          "a header sender other than the caller is refused");
    tx[14] = 0x03u; tx[15] = 0x80u;
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0x8003u, sv, 0u, 0u, &m) == 0,
          "a secure caller leaves the w1 sender zero");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0x8003u, sv, 0x80030000u, 0u,
                            &m) == WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_msg2_parse(tx, sizeof(tx), 0x8003u, sv, 0x00010000u, 0u,
                            &m) == WT_FFA_INVALID_PARAMETERS,
          "at the SVC conduit the w1 sender is MBZ, even the caller's own id");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0x8003u, sv, 0u, 0xFFFFFFFFu,
                            &m) == 0,
          "at the SVC conduit w2 is ignored");
    tx[14] = 0x01u; tx[15] = 0u;
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 1u, ns, 0x00010000u, 0u, &m) == 0,
          "at the NS physical instance w1 may name the sender VM");
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 1u, ns, 0x00020000u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS,
          "at the NS physical instance a w1 sender other than the caller is refused");
    tx[14] = 0u; tx[15] = 0u;
    tx[0] = 1u;
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS, "nonzero header flags are refused");
    tx[0] = 0u;
    tx[8] = 39u;
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS, "an offset inside the header is refused");
    tx[8] = 40u;
    tx[16] = 0xFFu; tx[17] = 0xFFu; tx[18] = 0xFFu; tx[19] = 0xFFu;
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS, "a payload past the TX end is refused");
    tx[16] = 32u; tx[17] = 0u; tx[18] = 0u; tx[19] = 0u;
    tx[12] = 0u; tx[13] = 0u;
    check(wt_ffa_msg2_parse(tx, sizeof(tx), 0u, ns, 0u, 0u, &m) ==
          WT_FFA_INVALID_PARAMETERS, "a receiver equal to the sender is refused");
}

int main(void)
{
    size_t n = sizeof(g_fids) / sizeof(g_fids[0]);
    size_t i;
    size_t j;
    int ok;
    uint64_t x32[8] = { WT_FFA_MSG_SEND_DIRECT_REQ32, 0x1111111100008002ull, 0u,
                        0x1125534411255344ull, 0xFFEEDDCC88776655ull, 0u, 0u,
                        0xBBAA9988CCBBAA99ull };
    uint64_t x64[8] = { WT_FFA_MSG_SEND_DIRECT_REQ64, 0x1111111100008002ull, 0u,
                        0x1125534411255344ull, 0u, 0u, 0u, 0u };

    printf("WT-FFA-0001 / WT-FFA-0002 (function ids, status codes, version)\n");

    ok = 1;
    for (i = 0u; i < n; i++) {
        ok = ok && wt_ffa_fid_in_range(g_fids[i]);
        ok = ok && ((g_fids[i] & 0x80000000u) != 0u);
    }
    check(ok, "every function id sits in the reserved FF-A fast-call ranges");

    ok = 1;
    for (i = 0u; i < n; i++) {
        for (j = i + 1u; j < n; j++) {
            ok = ok && (g_fids[i] != g_fids[j]);
        }
    }
    check(ok, "function ids are unique");

    check((WT_FFA_SUCCESS64 & 0x40000000u) != 0u &&
          (WT_FFA_SUCCESS32 & 0x40000000u) == 0u &&
          (WT_FFA_SUCCESS64 & 0xFFFFu) == (WT_FFA_SUCCESS32 & 0xFFFFu),
          "SMC64 variants differ from SMC32 only in bit 30");
    check(!wt_ffa_fid_in_range(WT_FFA_FID32_FIRST - 1u) &&
          !wt_ffa_fid_in_range(WT_FFA_FID32_LAST + 1u) &&
          !wt_ffa_fid_in_range(WT_FFA_FID64_FIRST - 1u) &&
          !wt_ffa_fid_in_range(WT_FFA_FID64_LAST + 1u) &&
          !wt_ffa_fid_in_range(0xC3000004u) &&
          wt_ffa_fid_in_range(WT_FFA_FID32_LAST) &&
          wt_ffa_fid_in_range(WT_FFA_FID64_FIRST),
          "range check excludes neighbours and the OEM test calls");

    ok = 1;
    for (i = 0u; i < sizeof(g_codes) / sizeof(g_codes[0]); i++) {
        ok = ok && (g_codes[i] == -(int32_t)(i + 1u));
    }
    check(ok, "status codes are -1..-10 in specification order");

    check(WT_FFA_VERSION_1_2 == WT_FFA_VERSION_MAKE(1u, 2u) &&
          WT_FFA_VERSION_MAJOR_OF(WT_FFA_VERSION_1_2) == 1u &&
          WT_FFA_VERSION_MINOR_OF(WT_FFA_VERSION_1_2) == 2u,
          "version 1.2 encodes as major 1 minor 2");
    check(WT_FFA_FEATURES_RXTX_MAX_PAGES(1u) == 0x00010000u &&
          (WT_FFA_FEATURES_RXTX_MAX_PAGES(1u) & 0x3u) == 0u &&
          WT_FFA_FEATURES_RXTX_MAX_PAGES(0u) == 0u,
          "FFA_FEATURES(FFA_RXTX_MAP) puts the page limit in w2 bits[31:16] "
          "with a 4K minimum in bits[1:0]");
    check(wt_ffa_features_retrieve_check(WT_FFA_VERSION_MAKE(1u, 0u), 0u) == 0 &&
          wt_ffa_features_retrieve_check(WT_FFA_VERSION_MAKE(1u, 0u),
                                         WT_FFA_FEATURES_RETRIEVE_NS_BIT) == 0,
          "a v1.0 partition may query FFA_MEM_RETRIEVE_REQ with or without "
          "requesting the NS bit (DEN0140 Table 1.19)");
    check(wt_ffa_features_retrieve_check(WT_FFA_VERSION_MAKE(1u, 1u), 0u) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_features_retrieve_check(WT_FFA_VERSION_1_2, 0u) ==
              WT_FFA_INVALID_PARAMETERS &&
          wt_ffa_features_retrieve_check(WT_FFA_VERSION_1_2,
                                         WT_FFA_FEATURES_RETRIEVE_NS_BIT) == 0,
          "a v1.1+ partition must request the NS bit (DEN0140 1.10.4.1.1)");
    check(wt_ffa_version_reply(WT_FFA_VERSION_1_2, WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a 1.2 caller is told 1.2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_MAKE(1u, 0u), WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a 1.0 caller is told the callee version 1.2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_MAKE(2u, 0u), WT_FFA_VERSION_1_2) ==
              WT_FFA_NOT_SUPPORTED &&
          wt_ffa_version_reply(WT_FFA_VERSION_MAKE(1u, 4u), WT_FFA_VERSION_1_2) ==
              WT_FFA_NOT_SUPPORTED &&
          wt_ffa_version_reply(0u, WT_FFA_VERSION_1_2) == WT_FFA_NOT_SUPPORTED,
          "an incompatible caller (other major, newer minor, version zero) is refused");
    wt_ffa_regs_normalize(x32);
    wt_ffa_regs_normalize(x64);
    check(x32[1] == 0x00008002ull && x32[3] == 0x11255344ull &&
          x32[4] == 0x88776655ull && x32[7] == 0xCCBBAA99ull,
          "a 32-bit function id is relayed with w1-w7 only");
    check(x64[1] == 0x1111111100008002ull && x64[3] == 0x1125534411255344ull,
          "a 64-bit function id keeps its full registers");
    check(wt_ffa_version_reply(0x80010002u, WT_FFA_VERSION_1_2) ==
              WT_FFA_NOT_SUPPORTED,
          "bit 31 set in the input version is NOT_SUPPORTED");
    check(wt_ffa_version_compatible(WT_FFA_VERSION_MAKE(1u, 0u), WT_FFA_VERSION_1_2) &&
          wt_ffa_version_compatible(WT_FFA_VERSION_1_2, WT_FFA_VERSION_1_2),
          "same major and caller minor <= callee minor is compatible");
    check(!wt_ffa_version_compatible(WT_FFA_VERSION_MAKE(1u, 3u), WT_FFA_VERSION_1_2) &&
          !wt_ffa_version_compatible(WT_FFA_VERSION_MAKE(2u, 0u), WT_FFA_VERSION_1_2),
          "greater minor or different major is incompatible");

    check((WT_FFA_ID_SPMC & 0x8000u) != 0u && (WT_FFA_ID_SPMD & 0x8000u) != 0u &&
          (WT_FFA_ID_SP_FIRST & 0x8000u) != 0u && WT_FFA_ID_SPMC != WT_FFA_ID_SPMD &&
          WT_FFA_ID_SP_FIRST > WT_FFA_ID_SPMD && WT_FFA_ID_NS_PRIMARY == 0u,
          "SPM-allocated ids carry bit 15, the primary NS endpoint is id 0");
    check(WT_FFA_FEATURES_IS_FID(WT_FFA_VERSION) && !WT_FFA_FEATURES_IS_FID(0x3u),
          "FFA_FEATURES tells function ids from feature ids by bit 31");

    direct_message_rows();
    msg2_rows();
    partition_info_rows();
    manifest_record_rows();
    partition_info_mailbox_rows();
    partition_info_version_rows();
    direct_permission_rows();
    version_state_rows();

    printf("ffa_abi: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
