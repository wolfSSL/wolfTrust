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

/* WT-FFA-0001 / WT-FFA-0002 (SPMD rows): the Secure physical instance
 * dispatcher replies per 13.2 (version, locked after the SPMC's first other
 * call), 13.3 (features), 13.10/13.11 (ids), 13.12 (console log, both
 * conventions), zeroes every unused result register, and answers unknown
 * function ids with NOT_SUPPORTED. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
static int failures;
static char g_console[256];
static size_t g_console_len;

void wt_platform_console_putc(char c)
{
    if (g_console_len < sizeof(g_console) - 1u) {
        g_console[g_console_len++] = c;
        g_console[g_console_len] = '\0';
    }
}

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

static void call(wt_ffa_regs_t* r, uint32_t fid, uint64_t x1)
{
    memset(r, 0, sizeof(*r));
    r->x[0] = fid;
    r->x[1] = x1;
    wt_ffa_spmd_secure_call(r);
}

static int rest_zero(const uint64_t* x, unsigned int from, unsigned int to)
{
    unsigned int i;

    for (i = from; i <= to; i++) {
        if (x[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int is_error(const wt_ffa_regs_t* r, int32_t code)
{
    return ((uint32_t)r->x[0] == WT_FFA_ERROR) &&
           ((int32_t)(uint32_t)r->x[2] == code) && (r->x[1] == 0u) &&
           rest_zero(r->x, 3u, 7u);
}

static void reset_console(void)
{
    g_console_len = 0u;
    g_console[0] = '\0';
}

/* The Normal world negotiates a version: its FFA_VERSION is forwarded to the
 * SPMC as the Table 13.7 message and the SPMC's answer settles it. */
static void ns_settle(uint32_t version)
{
    uint64_t x[18];

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_VERSION;
    x[1] = version;
    (void)wt_ffa_spmd_ns_forward(x);
    wt_ffa_fwk_version_resp(x, (int32_t)version);
    wt_ffa_spmd_ns_reply(x);
}

static void ns_call(wt_ffa_regs_t* r, uint32_t fid)
{
    memset(r, 0, sizeof(*r));
    r->x[0] = fid;
    wt_ffa_spmd_ns_call(r);
}

/* The NS physical instance answers these function ids directly; every other id
 * in the FF-A ranges is NOT_SUPPORTED (discovery and direct messaging forward to
 * the SPMC, a separate concern from the SPMD's own dispatch). A call only a
 * message receiver makes is DENIED: the primary endpoint is never one. */
static int ns_defined_reply(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_VERSION:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_MSG_WAIT:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
        case WT_FFA_MSG_SEND_DIRECT_RESP2:
            return 1;
        default:
            return 0;
    }
}

static int ns_range_total(uint32_t first, uint32_t last)
{
    wt_ffa_regs_t r;
    uint32_t fid;

    for (fid = first; fid <= last; fid++) {
        ns_call(&r, fid);
        if (ns_defined_reply(fid)) {
            /* An implemented id is handled, never left to the catch-all
             * NOT_SUPPORTED; it may still reject bad arguments with a
             * specific error. */
            if (is_error(&r, WT_FFA_NOT_SUPPORTED)) {
                return 0;
            }
        }
        else if (!is_error(&r, WT_FFA_NOT_SUPPORTED)) {
            return 0;
        }
    }
    return 1;
}

static void fill_ext(uint64_t* x)
{
    unsigned int i;

    memset(x, 0, 18u * sizeof(x[0]));
    for (i = 8u; i < 18u; i++) {
        x[i] = 0x5A5A0000u + i;
    }
}

static int ext_filled(const uint64_t* x)
{
    unsigned int i;

    for (i = 8u; i < 18u; i++) {
        if (x[i] != (0x5A5A0000u + i)) {
            return 0;
        }
    }
    return 1;
}

/* The SPMD relays a Normal-world direct request only after the NS-physical
 * checks of 7.4.2, so no forwarded request speaks with a Secure sender id. */
static void ns_forward_rows(void)
{
    uint64_t x[18];

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ32;
    x[1] = ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16) | WT_FFA_ID_SP_FIRST;
    x[3] = 0x1234u;
    check(wt_ffa_spmd_ns_forward(x) == 1 &&
              (uint32_t)x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32 && x[3] == 0x1234u,
          "a well-formed Normal-world direct request is forwarded unchanged");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ32;
    x[1] = ((uint64_t)WT_FFA_ID_SPMD << 16) | WT_FFA_ID_SPMC;
    x[2] = 0x80000008u;
    x[3] = WT_FFA_VERSION_MAKE(1u, 0u);
    check(wt_ffa_spmd_ns_forward(x) == 0 &&
              is_error((const wt_ffa_regs_t*)x, WT_FFA_INVALID_PARAMETERS),
          "a Normal-world request claiming the SPMD's id is refused, not forwarded");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ2;
    x[1] = ((uint64_t)WT_FFA_ID_SP_FIRST << 16) | 0x8003u;
    check(wt_ffa_spmd_ns_forward(x) == 0 &&
              is_error((const wt_ffa_regs_t*)x, WT_FFA_INVALID_PARAMETERS),
          "a Normal-world REQ2 with a Secure sender is refused too");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_RXTX_MAP64;
    x[3] = 1u;
    check(wt_ffa_spmd_ns_forward(x) == 1 && (uint32_t)x[0] == WT_FFA_RXTX_MAP64,
          "a forwarded call that is not a direct request passes through");

    fill_ext(x);
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ64;
    x[1] = ((uint64_t)WT_FFA_ID_SP_FIRST << 16) | 0x8003u;
    check(wt_ffa_spmd_ns_forward(x) == 0 && rest_zero(x, 8u, 17u),
          "a refused SMC64 request comes back with x8-x17 zero");
    fill_ext(x);
    x[0] = WT_FFA_MEM_SHARE64;
    check(wt_ffa_spmd_ns_forward(x) == 1 && rest_zero(x, 8u, 17u),
          "a forwarded SMC64 call's x8-x17 are cleared, as its reply carries "
          "only x0-x7");
    fill_ext(x);
    x[0] = WT_FFA_MEM_SHARE32;
    check(wt_ffa_spmd_ns_forward(x) == 1 && ext_filled(x),
          "a forwarded SMC32 call keeps x8-x17, which SMCCC preserves");
    fill_ext(x);
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ2;
    x[1] = ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16) | WT_FFA_ID_SP_FIRST;
    check(wt_ffa_spmd_ns_forward(x) == 1 && ext_filled(x),
          "a forwarded REQ2 keeps its x8-x17 payload");
    fill_ext(x);
    x[0] = 0xC3000102u;
    check(wt_ffa_spmd_ns_forward(x) == 1 && ext_filled(x),
          "a forwarded call outside the FF-A ranges keeps x8-x17");
}

static uint32_t ns_version_call(uint32_t asked)
{
    wt_ffa_regs_t r;

    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_VERSION;
    r.x[1] = asked;
    wt_ffa_spmd_ns_call(&r);
    return (uint32_t)r.x[0];
}

/* 13.2.3.2: until the Normal world locks its version, each FFA_VERSION it
 * makes reaches the SPMC as the Table 13.7 message, and the SPMC's Table 13.8
 * answer is what the Normal world gets back. */
static void ns_version_rows(void)
{
    uint64_t x[18];
    wt_ffa_regs_t r;
    unsigned int i;
    int ok;

    check(wt_ffa_spmd_ns_forwards(WT_FFA_VERSION) == 1,
          "a Normal-world FFA_VERSION is forwarded while its version is open");
    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_VERSION;
    x[1] = WT_FFA_VERSION_MAKE(1u, 0u);
    x[5] = 0x55u;
    check(wt_ffa_spmd_ns_forward(x) == 1 &&
              (uint32_t)x[0] == WT_FFA_MSG_SEND_DIRECT_REQ32 &&
              (uint32_t)x[1] == 0x80018000u && (uint32_t)x[2] == 0x80000008u &&
              (uint32_t)x[3] == WT_FFA_VERSION_MAKE(1u, 0u) &&
              rest_zero(x, 4u, 7u) && wt_ffa_fwk_version_is_req(x),
          "it goes to the SPMC as the Table 13.7 framework message");

    wt_ffa_fwk_version_resp(x, (int32_t)WT_FFA_VERSION_1_2);
    check((uint32_t)x[0] == WT_FFA_MSG_SEND_DIRECT_RESP32 &&
              (uint32_t)x[1] == 0x80008001u && (uint32_t)x[2] == 0x80000009u &&
              (uint32_t)x[3] == WT_FFA_VERSION_1_2 && rest_zero(x, 4u, 7u),
          "the SPMC answers with the Table 13.8 framework message");
    wt_ffa_spmd_ns_reply(x);
    check((uint32_t)x[0] == WT_FFA_VERSION_1_2 && rest_zero(x, 1u, 7u),
          "the Normal world gets the SPMC's answer in w0 with x1-x7 zero");

    for (i = 0u; i < 8u; i++) {
        x[i] = 0xA0u + i;
    }
    wt_ffa_spmd_ns_reply(x);
    ok = 1;
    for (i = 0u; i < 8u; i++) {
        ok = ok && (x[i] == (0xA0u + i));
    }
    check(ok, "a reply to any other forwarded call is returned untouched");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_VERSION;
    x[1] = WT_FFA_VERSION_MAKE(2u, 0u);
    (void)wt_ffa_spmd_ns_forward(x);
    wt_ffa_fwk_version_resp(x, (int32_t)WT_FFA_VERSION_1_2);
    wt_ffa_spmd_ns_reply(x);
    check((uint32_t)x[0] == WT_FFA_VERSION_1_2,
          "a later version is answered with the SPMC's 1.2 (13.2.2)");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_VERSION;
    x[1] = WT_FFA_VERSION_MAKE(0u, 1u);
    (void)wt_ffa_spmd_ns_forward(x);
    wt_ffa_fwk_version_resp(x, WT_FFA_NOT_SUPPORTED);
    wt_ffa_spmd_ns_reply(x);
    check((int32_t)(uint32_t)x[0] == WT_FFA_NOT_SUPPORTED,
          "a version the SPMC refuses is NOT_SUPPORTED for the Normal world");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_VERSION;
    x[1] = WT_FFA_VERSION_1_2;
    (void)wt_ffa_spmd_ns_forward(x);
    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_SUCCESS32;
    wt_ffa_spmd_ns_reply(x);
    check((int32_t)(uint32_t)x[0] == WT_FFA_NOT_SUPPORTED,
          "an answer that is not a Table 13.8 message is NOT_SUPPORTED");

    memset(x, 0, sizeof(x));
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ32;
    x[1] = 0x80018000u;
    check(!wt_ffa_fwk_version_is_req(x),
          "a partition message between the same ids is not the version message");

    ns_settle(WT_FFA_VERSION_MAKE(1u, 0u));
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_FEATURES;
    r.x[1] = WT_FFA_MSG_SEND_DIRECT_REQ2;
    wt_ffa_spmd_ns_call(&r);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED) &&
              wt_ffa_spmd_ns_forwards(WT_FFA_MSG_SEND_DIRECT_REQ2) == 0 &&
              wt_ffa_spmd_ns_forwards(WT_FFA_NOTIFICATION_SET) == 0,
          "a Normal world settled at 1.0 is told DIRECT_REQ2 and NOTIFICATION_SET "
          "are NOT_SUPPORTED and neither is forwarded (13.2.2)");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_MSG_SEND_DIRECT_REQ2;
    r.x[1] = 0x00008002u;
    wt_ffa_spmd_ns_call(&r);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "and a DIRECT_REQ2 it sends anyway is NOT_SUPPORTED, not DENIED");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_FEATURES;
    r.x[1] = WT_FFA_MSG_SEND_DIRECT_REQ32;
    wt_ffa_spmd_ns_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 &&
              wt_ffa_spmd_ns_forwards(WT_FFA_MSG_SEND_DIRECT_REQ32) == 1,
          "while a 1.0 ABI is still implemented and forwarded for it");
    ns_settle(WT_FFA_VERSION_MAKE(1u, 1u));
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_FEATURES;
    r.x[1] = WT_FFA_NOTIFICATION_SET;
    wt_ffa_spmd_ns_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 &&
              wt_ffa_spmd_ns_forwards(WT_FFA_NOTIFICATION_SET) == 1 &&
              wt_ffa_spmd_ns_forwards(WT_FFA_MSG_SEND_DIRECT_REQ2) == 0,
          "settled at 1.1 the notifications are back and DIRECT_REQ2 still not");
    ns_settle(WT_FFA_VERSION_1_2);
    check(wt_ffa_spmd_ns_forwards(WT_FFA_MSG_SEND_DIRECT_REQ2) == 1,
          "settled at 1.2 every implemented ABI is forwarded");

    wt_ffa_spmd_ns_note(WT_FFA_ID_GET);
    check(wt_ffa_spmd_ns_forwards(WT_FFA_VERSION) == 0,
          "after its first other call the SPMD stops forwarding FFA_VERSION");
    check(ns_version_call(WT_FFA_VERSION_1_2) == WT_FFA_VERSION_1_2 &&
              ns_version_call(WT_FFA_VERSION_MAKE(2u, 0u)) == WT_FFA_VERSION_1_2 &&
              (int32_t)ns_version_call(WT_FFA_VERSION_MAKE(1u, 0u)) ==
                  WT_FFA_NOT_SUPPORTED,
          "and holds the Normal world to the 1.2 it settled on for 2.0, not a "
          "refused one");
}

int main(void)
{
    wt_ffa_regs_t r;
    uint64_t frame[19];
    unsigned int i;
    char expect[129];

    printf("WT-FFA-0001 / WT-FFA-0002 (SPMD Secure physical instance)\n");

    call(&r, WT_FFA_VERSION, WT_FFA_VERSION_1_2);
    check((uint32_t)r.x[0] == WT_FFA_VERSION_1_2 && rest_zero(r.x, 1u, 7u),
          "FFA_VERSION replies 1.2 in w0 with every other register zero");
    call(&r, WT_FFA_VERSION, 0x80010002u);
    check((int32_t)(uint32_t)r.x[0] == WT_FFA_NOT_SUPPORTED,
          "FFA_VERSION with bit 31 set is NOT_SUPPORTED");
    call(&r, WT_FFA_VERSION, WT_FFA_VERSION_MAKE(1u, 1u));
    check((uint32_t)r.x[0] == WT_FFA_VERSION_1_2,
          "the SPMC may renegotiate before its first other call");
    call(&r, WT_FFA_FEATURES, WT_FFA_CONSOLE_LOG32);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "an SPMC settled at 1.1 is told the 1.2 FFA_CONSOLE_LOG is "
          "NOT_SUPPORTED (13.2.2)");
    call(&r, WT_FFA_CONSOLE_LOG32, 1u);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED) && g_console_len == 0u,
          "and an FFA_CONSOLE_LOG it sends anyway logs nothing");
    call(&r, WT_FFA_FEATURES, WT_FFA_SPM_ID_GET);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32,
          "while the 1.1 FFA_SPM_ID_GET stays implemented for it");
    wt_ffa_spmd_secure_note(WT_FFA_VERSION);
    call(&r, WT_FFA_VERSION, WT_FFA_VERSION_1_2);
    check((uint32_t)r.x[0] == WT_FFA_VERSION_1_2,
          "FFA_VERSION itself does not end the SPMC's negotiation");
    wt_ffa_spmd_secure_note(WT_FFA_ID_GET);
    call(&r, WT_FFA_VERSION, WT_FFA_VERSION_MAKE(1u, 1u));
    check((int32_t)(uint32_t)r.x[0] == WT_FFA_NOT_SUPPORTED &&
              rest_zero(r.x, 1u, 7u),
          "after the SPMC's first other call a different version is NOT_SUPPORTED");
    call(&r, WT_FFA_VERSION, WT_FFA_VERSION_1_2);
    check((uint32_t)r.x[0] == WT_FFA_VERSION_1_2,
          "and the version it settled on is still accepted");
    call(&r, WT_FFA_VERSION, WT_FFA_VERSION_MAKE(1u, 3u));
    check((uint32_t)r.x[0] == WT_FFA_VERSION_1_2 && rest_zero(r.x, 1u, 7u),
          "while a later version is told the settled 1.2 (13.2.2)");

    call(&r, WT_FFA_FEATURES, WT_FFA_VERSION);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && rest_zero(r.x, 1u, 7u),
          "FFA_FEATURES reports an implemented function id with zero properties");
    call(&r, WT_FFA_FEATURES, WT_FFA_CONSOLE_LOG64);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32, "FFA_FEATURES knows FFA_CONSOLE_LOG SMC64");
    call(&r, WT_FFA_FEATURES, WT_FFA_RXTX_MAP32);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "FFA_FEATURES refuses a function the SPMD does not implement yet");
    call(&r, WT_FFA_FEATURES, 0x1u);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED), "FFA_FEATURES refuses feature ids");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_FEATURES;
    r.x[1] = WT_FFA_FEATURE_SRI;
    r.x[2] = 1u;
    wt_ffa_spmd_ns_call(&r);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "an SRI feature query with the MBZ input properties set is "
          "NOT_SUPPORTED (Table 13.11)");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_FEATURES;
    r.x[1] = WT_FFA_FEATURE_SRI;
    wt_ffa_spmd_ns_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && r.x[2] == WT_FFA_SRI_INTID,
          "and with w2 zero it reports the SRI");
    call(&r, WT_FFA_FEATURES, WT_FFA_NORMAL_WORLD_RESUME);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && rest_zero(r.x, 1u, 7u),
          "FFA_FEATURES reports FFA_NORMAL_WORLD_RESUME, which the SPMD serves");

    check(wt_ffa_spmd_is_ns_resume(WT_FFA_NORMAL_WORLD_RESUME) == 1,
          "FFA_NORMAL_WORLD_RESUME resumes a preempted Normal world");
    check(wt_ffa_spmd_is_ns_resume(WT_FFA_RUN) == 0,
          "FFA_RUN at the Secure physical instance is no alias for the resume (14.4)");
    call(&r, WT_FFA_NORMAL_WORLD_RESUME, 0u);
    check(is_error(&r, WT_FFA_DENIED),
          "FFA_NORMAL_WORLD_RESUME with no preempted Normal world is DENIED (14.4.1)");
    call(&r, WT_FFA_RUN, 0u);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "FFA_RUN from the SPMC is NOT_SUPPORTED at the Secure physical instance");

    call(&r, WT_FFA_ID_GET, 0u);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && r.x[2] == WT_FFA_ID_SPMC &&
          r.x[1] == 0u && rest_zero(r.x, 3u, 7u),
          "FFA_ID_GET at the Secure physical instance returns the SPMC id");
    call(&r, WT_FFA_SPM_ID_GET, 0u);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && r.x[2] == WT_FFA_ID_SPMD &&
          rest_zero(r.x, 3u, 7u),
          "FFA_SPM_ID_GET returns the SPMD id");
    call(&r, WT_FFA_FID32_LAST - 0xFu, 0x1234u);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "an unknown function id in the FF-A range is NOT_SUPPORTED with clean registers");
    call(&r, WT_FFA_MSG_SEND_DIRECT_REQ32, 0u);
    check(is_error(&r, WT_FFA_NOT_SUPPORTED),
          "a known but unimplemented function id is NOT_SUPPORTED");

    reset_console();
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_CONSOLE_LOG32;
    r.x[1] = 24u;
    for (i = 0u; i < 24u; i++) {
        r.x[2u + (i / 4u)] |= (uint64_t)(uint8_t)('A' + (char)i) << (8u * (i % 4u));
    }
    for (i = 2u; i < 8u; i++) {
        r.x[i] |= 0xDEADBEEF00000000ull;
    }
    wt_ffa_spmd_secure_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && rest_zero(r.x, 1u, 7u) &&
          strcmp(g_console, "ABCDEFGHIJKLMNOPQRSTUVWX") == 0,
          "SMC32 console log prints 24 characters from w2-w7 and ignores the upper halves");

    reset_console();
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_CONSOLE_LOG32;
    r.x[1] = 3u;
    r.x[2] = 0x00434241u;
    wt_ffa_spmd_secure_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && strcmp(g_console, "ABC") == 0,
          "a short SMC32 log prints only the counted characters");

    reset_console();
    call(&r, WT_FFA_CONSOLE_LOG32, 0u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS) && g_console_len == 0u,
          "count 0 is INVALID_PARAMETERS and prints nothing");
    call(&r, WT_FFA_CONSOLE_LOG32, 25u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS) && g_console_len == 0u,
          "count 25 on SMC32 is INVALID_PARAMETERS");
    call(&r, WT_FFA_CONSOLE_LOG32, 0x100u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS) && g_console_len == 0u,
          "the count is bits 7:0 alone, so 0x100 counts no character");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_CONSOLE_LOG32;
    r.x[1] = 0xFFFFFF03u;
    r.x[2] = 0x00434241u;
    wt_ffa_spmd_secure_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && strcmp(g_console, "ABC") == 0,
          "the SBZ bits 31:8 of the count are ignored");

    reset_console();
    memset(frame, 0, sizeof(frame));
    frame[0] = WT_FFA_CONSOLE_LOG64;
    frame[1] = 128u;
    for (i = 0u; i < 128u; i++) {
        expect[i] = (char)('0' + (i % 10u));
        frame[2u + (i / 8u)] |= (uint64_t)(uint8_t)expect[i] << (8u * (i % 8u));
    }
    expect[128] = '\0';
    frame[18] = 0x5555u;
    wt_ffa_spmd_console_call(frame, 1u);
    check((uint32_t)frame[0] == WT_FFA_SUCCESS32 && rest_zero(frame, 1u, 7u) &&
          strcmp(g_console, expect) == 0 && frame[18] == 0x5555u,
          "SMC64 console log prints 128 characters from x2-x17 and leaves x18 alone");
    check(rest_zero(frame, 8u, 17u),
          "the SMC64 reply returns x8-x17 zero, not the logged characters (11.2)");

    reset_console();
    memset(frame, 0, sizeof(frame));
    frame[0] = WT_FFA_CONSOLE_LOG64;
    frame[1] = 129u;
    for (i = 8u; i < 18u; i++) {
        frame[i] = 0x4141414141414141ull;
    }
    wt_ffa_spmd_console_call(frame, 1u);
    check((uint32_t)frame[0] == WT_FFA_ERROR &&
          (int32_t)(uint32_t)frame[2] == WT_FFA_INVALID_PARAMETERS &&
          g_console_len == 0u && rest_zero(frame, 8u, 17u),
          "count 129 on SMC64 is INVALID_PARAMETERS, with x8-x17 zero");

    ns_forward_rows();
    ns_version_rows();

    check(ns_range_total(WT_FFA_FID32_FIRST, WT_FFA_FID32_LAST) &&
          ns_range_total(WT_FFA_FID64_FIRST, WT_FFA_FID64_LAST),
          "the NS dispatch is total across the FF-A ranges: every unimplemented "
          "function id is NOT_SUPPORTED and no id is left unanswered");

    printf("ffa_spmd: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
