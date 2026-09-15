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
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/ffa_partinfo.h"

#include <stdint.h>
#include <stdio.h>

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
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) == WT_FFA_DENIED,
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
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) == WT_FFA_DENIED,
          "a Normal-world request to a Normal-world receiver is DENIED");

    wt_ffa_direct_build(x, WT_FFA_MSG_SEND_DIRECT_REQ32,
                        (uint16_t)(WT_FFA_ID_SP_FIRST + 1u), WT_FFA_ID_SP_FIRST,
                        payload);
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) == 0,
          "the SPMC relays a request between two Secure partitions");
    check(wt_ffa_direct_req_check(x, WT_FFA_INSTANCE_NS_PHYSICAL) == WT_FFA_DENIED,
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
    check(wt_ffa_direct_resp_check(x, WT_FFA_INSTANCE_SECURE_VIRTUAL) == WT_FFA_DENIED,
          "a response whose sender is not Secure is DENIED");
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
    uint32_t count;
    uint32_t size;
    int ret;
    unsigned int i;

    check(wt_ffa_partinfo_desc_size(WT_FFA_VERSION_MAKE(1u, 0u)) ==
              WT_FFA_PARTINFO_DESC_V10 &&
          wt_ffa_partinfo_desc_size(WT_FFA_VERSION_1_2) ==
              WT_FFA_PARTINFO_DESC_V11,
          "a 1.0 caller gets 8-byte descriptors, a 1.1+ caller 24-byte with the UUID");
    check(wt_ffa_partinfo_props(WT_FFA_MESSAGING_DIRECT) ==
              (WT_FFA_PARTINFO_PROP_DIRECT_RECV | WT_FFA_PARTINFO_PROP_DIRECT_SEND) &&
          wt_ffa_partinfo_props(WT_FFA_MESSAGING_INDIRECT) ==
              WT_FFA_PARTINFO_PROP_INDIRECT,
          "properties reflect the manifest messaging kind");

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

    ret = wt_ffa_partinfo_write(rx, sizeof(rx), WT_FFA_VERSION_1_2, parts, 3u,
                                parts[1].uuid, 0u, &count, &size);
    check(ret == 0 && count == 1u && rd_u16(&rx[0]) == 0x8003u,
          "a specific UUID returns only the matching partition");

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
}

int main(void)
{
    size_t n = sizeof(g_fids) / sizeof(g_fids[0]);
    size_t i;
    size_t j;
    int ok;

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
          !wt_ffa_fid_in_range(0xC3800004u) &&
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
    check(wt_ffa_version_reply(WT_FFA_VERSION_1_2, WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a 1.2 caller is told 1.2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_MAKE(1u, 0u), WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "a 1.0 caller is told the callee version 1.2");
    check(wt_ffa_version_reply(WT_FFA_VERSION_MAKE(2u, 0u), WT_FFA_VERSION_1_2) ==
              (int32_t)WT_FFA_VERSION_1_2,
          "an incompatible 2.0 caller is told 1.2 rather than refused");
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
    partition_info_rows();

    printf("ffa_abi: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
