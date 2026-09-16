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
 * dispatcher replies per 13.2 (version), 13.3 (features), 13.10/13.11
 * (ids), 13.12 (console log, both conventions), zeroes every unused result
 * register, and answers unknown function ids with NOT_SUPPORTED. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/ffa.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"

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

static void ns_call(wt_ffa_regs_t* r, uint32_t fid)
{
    memset(r, 0, sizeof(*r));
    r->x[0] = fid;
    wt_ffa_spmd_ns_call(r);
}

/* The NS physical instance answers these function ids directly; every other id
 * in the FF-A ranges is NOT_SUPPORTED (discovery and direct messaging forward to
 * the SPMC, a separate concern from the SPMD's own dispatch). RX/TX mapping is
 * answered here too, though a malformed request is a specific error. */
static int ns_defined_reply(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_VERSION:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_RXTX_MAP32:
        case WT_FFA_RXTX_MAP64:
        case WT_FFA_RXTX_UNMAP:
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

static void ns_map(wt_ffa_regs_t* r, uint32_t fid, uint64_t tx, uint64_t rx,
                   uint64_t w3)
{
    memset(r, 0, sizeof(*r));
    r->x[0] = fid;
    r->x[1] = tx;
    r->x[2] = rx;
    r->x[3] = w3;
    wt_ffa_spmd_ns_call(r);
}

/* WT-FFA-0009 (SPMD RX/TX rows): the NS instance records a well-formed RX/TX
 * buffer pair (7.2.1), refuses a remap, unmaps, and rejects bad geometry. The
 * sequence ends unmapped so the totality sweep starts clean. */
static void rxtx_rows(void)
{
    wt_ffa_regs_t r;

    ns_map(&r, WT_FFA_RXTX_MAP32, 0x1000u, 0x2000u, 1u);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && rest_zero(r.x, 1u, 7u),
          "FFA_RXTX_MAP records a page-aligned, non-overlapping RX/TX pair");
    ns_map(&r, WT_FFA_RXTX_MAP32, 0x4000u, 0x5000u, 1u);
    check(is_error(&r, WT_FFA_DENIED),
          "a second FFA_RXTX_MAP before an unmap is DENIED");

    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_RXTX_UNMAP;
    wt_ffa_spmd_ns_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32 && rest_zero(r.x, 1u, 7u),
          "FFA_RXTX_UNMAP releases the recorded pair");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_RXTX_UNMAP;
    wt_ffa_spmd_ns_call(&r);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS),
          "FFA_RXTX_UNMAP with nothing mapped is INVALID_PARAMETERS");

    ns_map(&r, WT_FFA_RXTX_MAP32, 0x1001u, 0x3000u, 1u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS),
          "a misaligned buffer base is INVALID_PARAMETERS");
    ns_map(&r, WT_FFA_RXTX_MAP32, 0x1000u, 0x2000u, 2u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS),
          "overlapping RX and TX ranges are INVALID_PARAMETERS");
    ns_map(&r, WT_FFA_RXTX_MAP32, 0x1000u, 0x3000u, 0x40u | 1u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS),
          "reserved bits above the page count are SBZ");
    ns_map(&r, WT_FFA_RXTX_MAP32, 0x1000u, 0x3000u, 0u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS),
          "a zero page count is INVALID_PARAMETERS");

    ns_map(&r, WT_FFA_RXTX_MAP32, 0x1000u, 0x3000u, 1u);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32,
          "a valid pair maps again after the failed attempts");
    memset(&r, 0, sizeof(r));
    r.x[0] = WT_FFA_RXTX_UNMAP;
    wt_ffa_spmd_ns_call(&r);
    check((uint32_t)r.x[0] == WT_FFA_SUCCESS32,
          "the pair unmaps, leaving the NS instance clean");
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
    call(&r, WT_FFA_CONSOLE_LOG32, 0x100u | 3u);
    check(is_error(&r, WT_FFA_INVALID_PARAMETERS) && g_console_len == 0u,
          "reserved bits 31:8 of the count are SBZ");

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

    reset_console();
    memset(frame, 0, sizeof(frame));
    frame[0] = WT_FFA_CONSOLE_LOG64;
    frame[1] = 129u;
    wt_ffa_spmd_console_call(frame, 1u);
    check((uint32_t)frame[0] == WT_FFA_ERROR &&
          (int32_t)(uint32_t)frame[2] == WT_FFA_INVALID_PARAMETERS && g_console_len == 0u,
          "count 129 on SMC64 is INVALID_PARAMETERS");

    rxtx_rows();

    check(ns_range_total(WT_FFA_FID32_FIRST, WT_FFA_FID32_LAST) &&
          ns_range_total(WT_FFA_FID64_FIRST, WT_FFA_FID64_LAST),
          "the NS dispatch is total across the FF-A ranges: every unimplemented "
          "function id is NOT_SUPPORTED and no id is left unanswered");

    printf("ffa_spmd: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
