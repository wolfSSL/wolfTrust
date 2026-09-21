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

/* Native wire client suite: a scripted PSA transport stands in for the
 * SERVICE_HSM door so the client's connect caching, restart heal, retry
 * exhaustion, chunked randomness, response framing, and output-length
 * handling are all exercised without a Secure image. */

#include "psa/client.h"
#include "psa/error.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/crypto_native.h"
#include "wolftrust/crypto_native_client.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    }
    else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

/* ---- Scripted PSA transport ------------------------------------------- */
static int      g_connect_refuse;   /* refuse this many connects, then grant */
static int      g_call_fail;        /* fail this many calls, then serve */
static int32_t  g_resp_status;      /* wire status the served call reports */
static size_t   g_resp_payload;     /* served payload byte count */
static int      g_resp_len_override; /* forced outvec len, or -1 for real */
static int      g_connects;
static int      g_calls;
static int      g_closes;
static uint32_t g_last_random_usage;

static void mock_reset(void)
{
    g_connect_refuse = 0;
    g_call_fail = 0;
    g_resp_status = (int32_t)PSA_SUCCESS;
    g_resp_payload = 0U;
    g_resp_len_override = -1;
    g_connects = 0;
    g_calls = 0;
    g_closes = 0;
    g_last_random_usage = 0U;
}

uint32_t psa_framework_version(void) { return 0x0100u; }
uint32_t psa_version(uint32_t sid) { (void)sid; return 1u; }

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    (void)sid;
    (void)version;
    g_connects++;
    if (g_connect_refuse > 0) {
        g_connect_refuse--;
        return (psa_handle_t)PSA_ERROR_CONNECTION_REFUSED;
    }
    return (psa_handle_t)42;
}

void psa_close(psa_handle_t handle)
{
    (void)handle;
    g_closes++;
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    wt_crypto_wire_req_t hdr;
    uint8_t* out;
    int32_t wire_status;
    size_t payload;
    size_t i;

    (void)type;
    g_calls++;
    if (handle <= 0 || in_vec == NULL || in_len != 1U || out_vec == NULL ||
            out_len != 1U) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    if (g_call_fail > 0) {
        g_call_fail--;
        return PSA_ERROR_COMMUNICATION_FAILURE;
    }

    /* Serve a framed [status][payload] response. RANDOM echoes exactly the
     * requested byte count so the client's chunk reassembly is exercised. */
    (void)memset(&hdr, 0, sizeof(hdr));
    if (in_vec[0].len >= sizeof(hdr)) {
        (void)memcpy(&hdr, in_vec[0].base, sizeof(hdr));
    }
    payload = g_resp_payload;
    if (hdr.op == WT_CRYPTO_OP_RANDOM) {
        g_last_random_usage = hdr.usage;
        payload = hdr.usage;
    }
    out = (uint8_t*)out_vec[0].base;
    wire_status = g_resp_status;
    (void)memcpy(out, &wire_status, sizeof(wire_status));
    for (i = 0U; i < payload && sizeof(wire_status) + i < out_vec[0].len;
            i++) {
        out[sizeof(wire_status) + i] = (uint8_t)(0xA0U + (i & 0x0FU));
    }
    if (g_resp_len_override >= 0) {
        out_vec[0].len = (size_t)g_resp_len_override;
    }
    else {
        out_vec[0].len = sizeof(wire_status) + payload;
    }
    return PSA_SUCCESS;
}

/* The client caches its connection handle across calls. These drive it to a
 * known warm (handle cached) or cold (handle dropped) state before a test
 * asserts connect/call counts. Call mock_reset() afterwards to zero counters;
 * neither helper's handle state is disturbed by mock_reset. */
static void client_go_warm(void)
{
    uint8_t b[4];

    g_connect_refuse = 0;
    g_call_fail = 0;
    g_resp_status = (int32_t)PSA_SUCCESS;
    g_resp_payload = 0U;
    g_resp_len_override = -1;
    (void)wt_crypto_native_random(b, 4U);
}

static void client_go_cold(void)
{
    uint8_t b[4];

    g_connect_refuse = 1000000;
    g_call_fail = 1000000;
    (void)wt_crypto_native_random(b, 4U);
}

/* ---- Tests ------------------------------------------------------------- */
static void test_happy_and_status(void)
{
    uint8_t buf[64];
    psa_status_t st;

    mock_reset();
    g_resp_payload = 32U;
    st = wt_crypto_native_random(buf, 32U);
    check(st == PSA_SUCCESS && g_connects == 1 && g_calls == 1,
          "first request connects once and calls once");

    mock_reset();
    g_resp_status = (int32_t)PSA_ERROR_NOT_PERMITTED;
    st = wt_crypto_native_random(buf, 16U);
    check(st == PSA_ERROR_NOT_PERMITTED,
          "the secure-side status passes through unchanged");
}

static void test_heal_after_restart(void)
{
    uint8_t buf[32];
    psa_status_t st;

    /* One in-flight call fails as a partition restarts; the client closes the
     * torn handle, reconnects, and the retry succeeds. Start warm so the
     * first call uses the cached handle, as it would on a live guest. */
    client_go_warm();
    mock_reset();
    g_call_fail = 1;
    st = wt_crypto_native_random(buf, 16U);
    check(st == PSA_SUCCESS && g_closes >= 1 && g_calls == 2,
          "a torn call heals by reconnecting and retrying");
}

static void test_mutating_no_replay(void)
{
    wt_crypto_wire_req_t hdr;
    uint8_t out[16];
    size_t got = 0U;
    psa_status_t st;
    uint32_t muta[3];
    size_t i;

    /* A mutating op whose call fails after reaching the door is ambiguous: the
     * store may already be changed, so the client must NOT replay it. Unlike
     * idempotent RANDOM (test_heal_after_restart), it surfaces the failure
     * after exactly one call rather than retrying. */
    muta[0] = WT_CRYPTO_OP_KEY_GENERATE;
    muta[1] = WT_CRYPTO_OP_KEY_IMPORT;
    muta[2] = WT_CRYPTO_OP_KEY_DESTROY;
    for (i = 0U; i < 3U; i++) {
        client_go_warm();
        mock_reset();
        g_call_fail = 1;
        (void)memset(&hdr, 0, sizeof(hdr));
        hdr.op = muta[i];
        hdr.uid = 0x3001U;
        st = wt_crypto_native_call(&hdr, NULL, 0U, out, sizeof(out), &got);
        check(st == PSA_ERROR_COMMUNICATION_FAILURE && g_calls == 1 &&
              g_closes >= 1,
              "a failed mutating call surfaces the failure without replay");
    }
}

static void test_connect_refused(void)
{
    uint8_t buf[16];
    psa_status_t st;

    /* The door refuses every connect: no call is ever issued and the client
     * reports the refusal rather than spinning forever. */
    client_go_cold();
    mock_reset();
    g_connect_refuse = 1000000;
    st = wt_crypto_native_random(buf, 16U);
    check(st == PSA_ERROR_CONNECTION_REFUSED && g_calls == 0,
          "a permanently refused connection fails closed with no call");
}

static void test_retry_exhaustion(void)
{
    uint8_t buf[16];
    psa_status_t st;

    /* Every call fails: the client exhausts its bounded retries and returns
     * the transport failure instead of looping without end. */
    mock_reset();
    g_call_fail = 1000000;
    st = wt_crypto_native_random(buf, 16U);
    check(st == PSA_ERROR_COMMUNICATION_FAILURE && g_calls > 1 &&
          g_calls <= 64,
          "exhausted retries return the transport failure");
}

static void test_response_framing(void)
{
    wt_crypto_wire_req_t hdr;
    uint8_t out[128];
    size_t got = 999U;
    psa_status_t st;

    /* A response shorter than the status word is a framing failure. */
    mock_reset();
    g_resp_len_override = (int)sizeof(int32_t) - 1;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.op = WT_CRYPTO_OP_HASH;
    st = wt_crypto_native_call(&hdr, (const uint8_t*)"abc", 3U, out,
                               sizeof(out), &got);
    check(st == PSA_ERROR_COMMUNICATION_FAILURE,
          "a response shorter than the status word is refused");

    /* A payload larger than the caller's buffer yields BUFFER_TOO_SMALL. */
    mock_reset();
    g_resp_payload = 40U;
    got = 999U;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.op = WT_CRYPTO_OP_KEY_EXPORT_PUBLIC;
    hdr.uid = 7U;
    st = wt_crypto_native_call(&hdr, NULL, 0U, out, 16U, &got);
    check(st == PSA_ERROR_BUFFER_TOO_SMALL,
          "a payload larger than the output buffer is refused");

    /* A status-only success (no payload) reports zero output length. */
    mock_reset();
    got = 999U;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.op = WT_CRYPTO_OP_KEY_DESTROY;
    hdr.uid = 7U;
    st = wt_crypto_native_call(&hdr, NULL, 0U, NULL, 0U, &got);
    check(st == PSA_SUCCESS && got == 0U,
          "a status-only response reports no payload");
}

static void test_chunked_random(void)
{
    uint8_t buf[600];
    size_t i;
    int nonzero = 0;
    psa_status_t st;

    /* 600 bytes exceeds the 256-byte per-call cap, so the client must issue
     * three calls and stitch the pieces together. */
    mock_reset();
    (void)memset(buf, 0, sizeof(buf));
    st = wt_crypto_native_random(buf, sizeof(buf));
    for (i = 0U; i < sizeof(buf); i++) {
        if (buf[i] != 0U) {
            nonzero = 1;
        }
    }
    check(st == PSA_SUCCESS && g_calls == 3 && nonzero != 0,
          "a request above the per-call cap is split across calls");

    mock_reset();
    check(wt_crypto_native_random(NULL, 16U) == PSA_ERROR_INVALID_ARGUMENT &&
          wt_crypto_native_random(buf, 0U) == PSA_ERROR_INVALID_ARGUMENT,
          "random refuses a NULL buffer or a zero length");
}

static void test_rng_stub(void)
{
    uint8_t buf[8];

    mock_reset();
    check(wolftrust_guest_rng_stub(buf, sizeof(buf)) == 0,
          "the wolfCrypt RNG hook returns success when the wire serves");

    client_go_cold();
    mock_reset();
    g_connect_refuse = 1000000;
    check(wolftrust_guest_rng_stub(buf, sizeof(buf)) != 0,
          "the wolfCrypt RNG hook returns failure when the wire is down");
}

int main(void)
{
    test_happy_and_status();
    test_heal_after_restart();
    test_mutating_no_replay();
    test_connect_refused();
    test_retry_exhaustion();
    test_response_framing();
    test_chunked_random();
    test_rng_stub();

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: native crypto wire client recovery and framing\n");
    return 0;
}
