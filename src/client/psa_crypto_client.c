/* psa_crypto_client.c
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

/* Non-secure PSA Crypto client for WT_SECURE_PSA=1: every psa_* call runs in
 * the Secure crypto partition and operation objects hold only its token. A
 * one-shot too big for one message runs as the matching multi-part sequence. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "psa/crypto.h"

#include "wolftrust/crypto_native_client.h"
#include "wolftrust/services/hsm_relay.h"
#include "wolftrust/services/psa_crypto_wire.h"

#define WT_PSA_REQ_ROOM (WT_HSM_RELAY_MSG_MAX - sizeof(wt_crypto_wire_req_t))
#define WT_PSA_RESP_ROOM (WT_HSM_RELAY_MSG_MAX - sizeof(int32_t))
#define WT_PSA_IN_INLINE (WT_PSA_REQ_ROOM - sizeof(wt_psa_wire_args_t))
#define WT_PSA_OUT_INLINE (WT_PSA_RESP_ROOM - sizeof(wt_psa_wire_ret_t))
/* An update chunk whose output, up to one block more, still fits a reply. */
#define WT_PSA_IO_CHUNK \
    (((WT_PSA_IN_INLINE < WT_PSA_OUT_INLINE - 16U) ? WT_PSA_IN_INLINE : \
      (WT_PSA_OUT_INLINE - 16U)) & ~(size_t)15U)

typedef struct {
    uint32_t a[4];
    const uint8_t* in[WT_PSA_WIRE_IN_MAX];
    size_t in_len[WT_PSA_WIRE_IN_MAX];
    uint8_t* out[WT_PSA_WIRE_OUT_MAX];
    size_t out_cap[WT_PSA_WIRE_OUT_MAX];
    size_t out_len[WT_PSA_WIRE_OUT_MAX];
    uint32_t val;
} wt_psa_req_t;

static int g_wt_psa_ready;

/* One message: [hdr][args][inline bytes] in, [ret][inline bytes] out. */
static psa_status_t wt_psa_send(uint32_t fn, const wt_psa_wire_args_t* args,
                                const wt_psa_req_t* r, uint8_t* resp,
                                size_t* resp_len)
{
    wt_crypto_wire_req_t hdr;
    uint8_t payload[WT_PSA_REQ_ROOM];
    size_t len = sizeof(*args);
    size_t i;

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.op = WT_CRYPTO_OP_PSA;
    hdr.usage = fn;
    hdr.key_type = WT_PSA_WIRE_VERSION << WT_PSA_WIRE_VER_SHIFT;
    (void)memcpy(payload, args, sizeof(*args));
    for (i = 0U; r != NULL && i < WT_PSA_WIRE_IN_MAX; i++) {
        if (r->in_len[i] != 0U) {
            (void)memcpy(payload + len, r->in[i], r->in_len[i]);
            len += r->in_len[i];
        }
    }
    return wt_crypto_native_call(&hdr, payload, len, resp, WT_PSA_RESP_ROOM,
                                 resp_len);
}

static psa_status_t wt_psa_init_once(void)
{
    wt_psa_wire_args_t args;
    uint8_t resp[WT_PSA_RESP_ROOM];
    size_t got = 0U;
    psa_status_t status = PSA_SUCCESS;

    if (g_wt_psa_ready == 0) {
        (void)memset(&args, 0, sizeof(args));
        status = wt_psa_send(WT_PSA_FN_CRYPTO_INIT, &args, NULL, resp, &got);
        if (status == PSA_SUCCESS) {
            g_wt_psa_ready = 1;
        }
    }
    return status;
}

/* Run fn in one message; opaque, when given, carries the operation token
 * both ways. */
static psa_status_t wt_psa_run(uint32_t fn, wt_psa_req_t* r,
                               uintptr_t* opaque)
{
    wt_psa_wire_args_t args;
    wt_psa_wire_ret_t ret;
    uint8_t resp[WT_PSA_RESP_ROOM];
    size_t in_total = 0U;
    size_t out_total = 0U;
    size_t got = 0U;
    size_t i;
    psa_status_t status;

    status = wt_psa_init_once();
    (void)memset(&args, 0, sizeof(args));
    for (i = 0U; status == PSA_SUCCESS && i < WT_PSA_WIRE_IN_MAX; i++) {
        if (r->in[i] == NULL && r->in_len[i] != 0U) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        else if (r->in_len[i] > WT_PSA_IN_INLINE - in_total) {
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        else {
            in_total += r->in_len[i];
            args.in_len[i] = (uint32_t)r->in_len[i];
        }
    }
    for (i = 0U; status == PSA_SUCCESS && i < WT_PSA_WIRE_OUT_MAX; i++) {
        if (r->out[i] == NULL && r->out_cap[i] != 0U) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        if (r->out_cap[i] > WT_PSA_OUT_INLINE) {
            r->out_cap[i] = WT_PSA_OUT_INLINE;
        }
        out_total += r->out_cap[i];
    }
    /* An oversized data buffer yields its excess to the tag that follows it. */
    if (out_total > WT_PSA_OUT_INLINE &&
            r->out_cap[0] >= out_total - WT_PSA_OUT_INLINE) {
        r->out_cap[0] -= out_total - WT_PSA_OUT_INLINE;
        out_total = WT_PSA_OUT_INLINE;
    }
    if (status == PSA_SUCCESS && out_total > WT_PSA_OUT_INLINE) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    for (i = 0U; i < WT_PSA_WIRE_OUT_MAX; i++) {
        args.out_cap[i] = (uint32_t)r->out_cap[i];
    }
    (void)memcpy(args.a, r->a, sizeof(args.a));
    if (opaque != NULL) {
        args.a[0] = (uint32_t)*opaque;
    }
    if (status == PSA_SUCCESS) {
        status = wt_psa_send(fn, &args, r, resp, &got);
        if (got < sizeof(ret)) {
            return (status != PSA_SUCCESS) ? status :
                   PSA_ERROR_COMMUNICATION_FAILURE;
        }
        (void)memcpy(&ret, resp, sizeof(ret));
        if (opaque != NULL) {
            *opaque = (uintptr_t)ret.op;
        }
        r->val = ret.val;
        for (i = 0U; i < WT_PSA_WIRE_OUT_MAX; i++) {
            r->out_len[i] = ret.out_len[i];
            if (r->out_len[i] > r->out_cap[i]) {
                return PSA_ERROR_COMMUNICATION_FAILURE;
            }
        }
    }
    if (status == PSA_SUCCESS) {
        if (got != sizeof(ret) + r->out_len[0] + r->out_len[1]) {
            return PSA_ERROR_COMMUNICATION_FAILURE;
        }
        got = sizeof(ret);
        for (i = 0U; i < WT_PSA_WIRE_OUT_MAX; i++) {
            if (r->out_len[i] != 0U) {
                (void)memcpy(r->out[i], resp + got, r->out_len[i]);
                got += r->out_len[i];
            }
        }
    }
    return status;
}

static void wt_psa_req_init(wt_psa_req_t* r, uint32_t a0, uint32_t a1,
                            uint32_t a2)
{
    (void)memset(r, 0, sizeof(*r));
    r->a[0] = a0;
    r->a[1] = a1;
    r->a[2] = a2;
}

static void wt_psa_in(wt_psa_req_t* r, size_t i, const uint8_t* p,
                      size_t len)
{
    r->in[i] = p;
    r->in_len[i] = len;
}

static void wt_psa_out(wt_psa_req_t* r, size_t i, uint8_t* p, size_t cap)
{
    r->out[i] = p;
    r->out_cap[i] = cap;
}

/* One-shot call with an output whose length goes to *len. */
static psa_status_t wt_psa_run_out(uint32_t fn, wt_psa_req_t* r,
                                   uintptr_t* opaque, size_t* len)
{
    psa_status_t status;

    if (len == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *len = 0U;
    status = wt_psa_run(fn, r, opaque);
    if (status == PSA_SUCCESS) {
        *len = r->out_len[0];
    }
    return status;
}

static void wt_psa_wr32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t wt_psa_rd32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void wt_psa_attr_put(const psa_key_attributes_t* attr, uint8_t* p)
{
    wt_psa_wr32(p, (uint32_t)attr->type | ((uint32_t)attr->bits << 16));
    wt_psa_wr32(p + 4, (uint32_t)attr->lifetime);
    wt_psa_wr32(p + 8, (uint32_t)attr->policy.usage);
    wt_psa_wr32(p + 12, (uint32_t)attr->policy.alg);
    wt_psa_wr32(p + 16, (uint32_t)attr->policy.alg2);
    wt_psa_wr32(p + 20, (uint32_t)attr->id);
}

/* Key-creating call: attributes in input 0, the new id back in *key. */
static psa_status_t wt_psa_run_key(uint32_t fn, wt_psa_req_t* r,
                                   const psa_key_attributes_t* attr,
                                   uintptr_t* opaque, psa_key_id_t* key)
{
    uint8_t wire[WT_PSA_WIRE_ATTR_LEN];
    psa_status_t status;

    if (attr == NULL || key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *key = PSA_KEY_ID_NULL;
    wt_psa_attr_put(attr, wire);
    wt_psa_in(r, 0U, wire, sizeof(wire));
    status = wt_psa_run(fn, r, opaque);
    if (status == PSA_SUCCESS) {
        *key = (psa_key_id_t)r->val;
    }
    return status;
}

int wolfPSA_CryptoIsInitialized(void)
{
    return g_wt_psa_ready;
}

psa_status_t psa_crypto_init(void)
{
    return wt_psa_init_once();
}

psa_status_t psa_generate_random(uint8_t* output, size_t output_size)
{
    wt_psa_req_t r;
    size_t done;
    size_t chunk;
    psa_status_t status = PSA_SUCCESS;

    if (output == NULL && output_size != 0U) {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    for (done = 0U; status == PSA_SUCCESS && done < output_size;
            done += chunk) {
        chunk = output_size - done;
        if (chunk > WT_PSA_OUT_INLINE) {
            chunk = WT_PSA_OUT_INLINE;
        }
        wt_psa_req_init(&r, 0U, 0U, 0U);
        wt_psa_out(&r, 0U, output + done, chunk);
        status = wt_psa_run(WT_PSA_FN_GENERATE_RANDOM, &r, NULL);
    }
    return status;
}

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t* attributes)
{
    wt_psa_req_t r;
    uint8_t wire[WT_PSA_WIRE_ATTR_LEN];
    uint32_t tb;
    psa_status_t status;

    if (attributes == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *attributes = psa_key_attributes_init();
    wt_psa_req_init(&r, key, 0U, 0U);
    wt_psa_out(&r, 0U, wire, sizeof(wire));
    status = wt_psa_run(WT_PSA_FN_GET_KEY_ATTRIBUTES, &r, NULL);
    if (status == PSA_SUCCESS && r.out_len[0] != sizeof(wire)) {
        status = PSA_ERROR_COMMUNICATION_FAILURE;
    }
    if (status == PSA_SUCCESS) {
        tb = wt_psa_rd32(wire);
        attributes->type = (psa_key_type_t)(tb & 0xFFFFU);
        attributes->bits = (psa_key_bits_t)(tb >> 16);
        attributes->lifetime = (psa_key_lifetime_t)wt_psa_rd32(wire + 4);
        attributes->policy.usage = (psa_key_usage_t)wt_psa_rd32(wire + 8);
        attributes->policy.alg = (psa_algorithm_t)wt_psa_rd32(wire + 12);
        attributes->policy.alg2 = (psa_algorithm_t)wt_psa_rd32(wire + 16);
        attributes->id = (psa_key_id_t)wt_psa_rd32(wire + 20);
    }
    return status;
}

psa_status_t psa_import_key(const psa_key_attributes_t* attributes,
                            const uint8_t* data, size_t data_length,
                            psa_key_id_t* key)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_in(&r, 1U, data, data_length);
    return wt_psa_run_key(WT_PSA_FN_IMPORT_KEY, &r, attributes, NULL, key);
}

psa_status_t psa_generate_key(const psa_key_attributes_t* attributes,
                              psa_key_id_t* key)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, 0U, 0U);
    return wt_psa_run_key(WT_PSA_FN_GENERATE_KEY, &r, attributes, NULL, key);
}

psa_status_t psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t* attributes,
                          psa_key_id_t* target_key)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, source_key, 0U, 0U);
    return wt_psa_run_key(WT_PSA_FN_COPY_KEY, &r, attributes, NULL,
                          target_key);
}

psa_status_t psa_export_key(psa_key_id_t key, uint8_t* data,
                            size_t data_size, size_t* data_length)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, 0U, 0U);
    wt_psa_out(&r, 0U, data, data_size);
    return wt_psa_run_out(WT_PSA_FN_EXPORT_KEY, &r, NULL, data_length);
}

psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t* data,
                                   size_t data_size, size_t* data_length)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, 0U, 0U);
    wt_psa_out(&r, 0U, data, data_size);
    return wt_psa_run_out(WT_PSA_FN_EXPORT_PUBLIC_KEY, &r, NULL,
                          data_length);
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, 0U, 0U);
    return wt_psa_run(WT_PSA_FN_DESTROY_KEY, &r, NULL);
}

psa_status_t psa_purge_key(psa_key_id_t key)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, 0U, 0U);
    return wt_psa_run(WT_PSA_FN_PURGE_KEY, &r, NULL);
}

static psa_status_t wt_psa_op_setup(uint32_t fn, uintptr_t* opaque,
                                    psa_key_id_t key, psa_algorithm_t alg)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, key, alg);
    return wt_psa_run(fn, &r, opaque);
}

static psa_status_t wt_psa_op_in(uint32_t fn, uintptr_t* opaque,
                                 const uint8_t* in, size_t in_len)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_in(&r, 0U, in, in_len);
    return wt_psa_run(fn, &r, opaque);
}

static psa_status_t wt_psa_op_out(uint32_t fn, uintptr_t* opaque,
                                  uint8_t* out, size_t out_size,
                                  size_t* out_len)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_out(&r, 0U, out, out_size);
    return wt_psa_run_out(fn, &r, opaque, out_len);
}

static psa_status_t wt_psa_op_inout(uint32_t fn, uintptr_t* opaque,
                                    const uint8_t* in, size_t in_len,
                                    uint8_t* out, size_t out_size,
                                    size_t* out_len)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_in(&r, 0U, in, in_len);
    wt_psa_out(&r, 0U, out, out_size);
    return wt_psa_run_out(fn, &r, opaque, out_len);
}

static psa_status_t wt_psa_op_abort(uint32_t fn, uintptr_t* opaque)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, 0U, 0U, 0U);
    return wt_psa_run(fn, &r, opaque);
}

/* Feed in to fn in message-sized pieces, as a run of updates. */
static psa_status_t wt_psa_op_stream(uint32_t fn, uintptr_t* opaque,
                                     const uint8_t* in, size_t in_len)
{
    size_t done = 0U;
    size_t chunk;
    psa_status_t status;

    do {
        chunk = in_len - done;
        if (chunk > WT_PSA_IN_INLINE) {
            chunk = WT_PSA_IN_INLINE;
        }
        status = wt_psa_op_in(fn, opaque, (in != NULL) ? in + done : NULL,
                              chunk);
        done += chunk;
    } while (status == PSA_SUCCESS && done < in_len);
    return status;
}

/* The same for an update with output; a failure leaves no partial output. */
static psa_status_t wt_psa_op_stream_io(uint32_t fn, uintptr_t* opaque,
                                        const uint8_t* in, size_t in_len,
                                        uint8_t* out, size_t out_size,
                                        size_t* out_len)
{
    size_t done = 0U;
    size_t total = 0U;
    size_t chunk;
    size_t got;
    psa_status_t status;

    if (out_len == NULL || (out == NULL && out_size != 0U)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *out_len = 0U;
    do {
        chunk = in_len - done;
        if (chunk > WT_PSA_IO_CHUNK) {
            chunk = WT_PSA_IO_CHUNK;
        }
        got = 0U;
        status = wt_psa_op_inout(fn, opaque, (in != NULL) ? in + done : NULL,
                                 chunk, (out != NULL) ? out + total : NULL,
                                 out_size - total, &got);
        if (status == PSA_SUCCESS) {
            total += got;
        }
        done += chunk;
    } while (status == PSA_SUCCESS && done < in_len);
    if (status != PSA_SUCCESS && total != 0U) {
        (void)memset(out, 0, total);
        total = 0U;
    }
    *out_len = total;
    return status;
}

/* ---- Hash ---- */
/* A one-shot hash too big for one message, as setup, updates and finish or
 * verify; expect selects verify. */
static psa_status_t wt_psa_hash_parts(psa_algorithm_t alg, const uint8_t* in,
                                      size_t in_len, uint8_t* hash,
                                      size_t hash_size, size_t* hash_length,
                                      const uint8_t* expect,
                                      size_t expect_len)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t status;

    status = psa_hash_setup(&op, alg);
    if (status == PSA_SUCCESS) {
        status = psa_hash_update(&op, in, in_len);
    }
    if (status == PSA_SUCCESS && expect != NULL) {
        status = psa_hash_verify(&op, expect, expect_len);
    }
    else if (status == PSA_SUCCESS) {
        status = psa_hash_finish(&op, hash, hash_size, hash_length);
    }
    if (status != PSA_SUCCESS) {
        (void)psa_hash_abort(&op);
    }
    return status;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t* input,
                              size_t input_length, uint8_t* hash,
                              size_t hash_size, size_t* hash_length)
{
    wt_psa_req_t r;

    if (input_length > WT_PSA_IN_INLINE) {
        if (hash_length != NULL) {
            *hash_length = 0U;
        }
        return wt_psa_hash_parts(alg, input, input_length, hash, hash_size,
                                 hash_length, NULL, 0U);
    }
    wt_psa_req_init(&r, alg, 0U, 0U);
    wt_psa_in(&r, 0U, input, input_length);
    wt_psa_out(&r, 0U, hash, hash_size);
    return wt_psa_run_out(WT_PSA_FN_HASH_COMPUTE, &r, NULL, hash_length);
}

psa_status_t psa_hash_compare(psa_algorithm_t alg, const uint8_t* input,
                              size_t input_length, const uint8_t* hash,
                              size_t hash_length)
{
    wt_psa_req_t r;

    if (input_length + hash_length > WT_PSA_IN_INLINE) {
        if (hash == NULL) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return wt_psa_hash_parts(alg, input, input_length, NULL, 0U, NULL,
                                 hash, hash_length);
    }
    wt_psa_req_init(&r, alg, 0U, 0U);
    wt_psa_in(&r, 0U, input, input_length);
    wt_psa_in(&r, 1U, hash, hash_length);
    return wt_psa_run(WT_PSA_FN_HASH_COMPARE, &r, NULL);
}

psa_status_t psa_hash_setup(psa_hash_operation_t* operation,
                            psa_algorithm_t alg)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, alg, 0U);
    return wt_psa_run(WT_PSA_FN_HASH_SETUP, &r, &operation->opaque);
}

psa_status_t psa_hash_update(psa_hash_operation_t* operation,
                             const uint8_t* input, size_t input_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_stream(WT_PSA_FN_HASH_UPDATE, &operation->opaque, input,
                            input_length);
}

psa_status_t psa_hash_finish(psa_hash_operation_t* operation, uint8_t* hash,
                             size_t hash_size, size_t* hash_length)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_out(&r, 0U, hash, hash_size);
    return wt_psa_run_out(WT_PSA_FN_HASH_FINISH, &r, &operation->opaque,
                          hash_length);
}

psa_status_t psa_hash_verify(psa_hash_operation_t* operation,
                             const uint8_t* hash, size_t hash_length)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_in(&r, 0U, hash, hash_length);
    return wt_psa_run(WT_PSA_FN_HASH_VERIFY, &r, &operation->opaque);
}

psa_status_t psa_hash_abort(psa_hash_operation_t* operation)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, 0U, 0U);
    return wt_psa_run(WT_PSA_FN_HASH_ABORT, &r, &operation->opaque);
}

psa_status_t psa_hash_clone(const psa_hash_operation_t* source_operation,
                            psa_hash_operation_t* target_operation)
{
    wt_psa_req_t r;

    if (source_operation == NULL || target_operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, (uint32_t)source_operation->opaque, 0U);
    return wt_psa_run(WT_PSA_FN_HASH_CLONE, &r, &target_operation->opaque);
}

/* ---- MAC ---- */
/* A one-shot MAC too big for one message; expect selects verify. */
static psa_status_t wt_psa_mac_parts(psa_key_id_t key, psa_algorithm_t alg,
                                     const uint8_t* in, size_t in_len,
                                     uint8_t* mac, size_t mac_size,
                                     size_t* mac_length,
                                     const uint8_t* expect, size_t expect_len)
{
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status;

    status = (expect != NULL) ? psa_mac_verify_setup(&op, key, alg) :
             psa_mac_sign_setup(&op, key, alg);
    if (status == PSA_SUCCESS) {
        status = psa_mac_update(&op, in, in_len);
    }
    if (status == PSA_SUCCESS && expect != NULL) {
        status = psa_mac_verify_finish(&op, expect, expect_len);
    }
    else if (status == PSA_SUCCESS) {
        status = psa_mac_sign_finish(&op, mac, mac_size, mac_length);
    }
    if (status != PSA_SUCCESS) {
        (void)psa_mac_abort(&op);
    }
    return status;
}

psa_status_t psa_mac_compute(psa_key_id_t key, psa_algorithm_t alg,
                             const uint8_t* input, size_t input_length,
                             uint8_t* mac, size_t mac_size,
                             size_t* mac_length)
{
    wt_psa_req_t r;

    if (input_length > WT_PSA_IN_INLINE) {
        if (mac_length != NULL) {
            *mac_length = 0U;
        }
        return wt_psa_mac_parts(key, alg, input, input_length, mac, mac_size,
                                mac_length, NULL, 0U);
    }
    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, input, input_length);
    wt_psa_out(&r, 0U, mac, mac_size);
    return wt_psa_run_out(WT_PSA_FN_MAC_COMPUTE, &r, NULL, mac_length);
}

psa_status_t psa_mac_verify(psa_key_id_t key, psa_algorithm_t alg,
                            const uint8_t* input, size_t input_length,
                            const uint8_t* mac, size_t mac_length)
{
    wt_psa_req_t r;

    if (input_length + mac_length > WT_PSA_IN_INLINE) {
        if (mac == NULL) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return wt_psa_mac_parts(key, alg, input, input_length, NULL, 0U, NULL,
                                mac, mac_length);
    }
    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, input, input_length);
    wt_psa_in(&r, 1U, mac, mac_length);
    return wt_psa_run(WT_PSA_FN_MAC_VERIFY, &r, NULL);
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t* operation,
                                psa_key_id_t key, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_MAC_SIGN_SETUP, &operation->opaque, key,
                           alg);
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t* operation,
                                  psa_key_id_t key, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_MAC_VERIFY_SETUP, &operation->opaque,
                           key, alg);
}

psa_status_t psa_mac_update(psa_mac_operation_t* operation,
                            const uint8_t* input, size_t input_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_stream(WT_PSA_FN_MAC_UPDATE, &operation->opaque, input,
                            input_length);
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t* operation,
                                 uint8_t* mac, size_t mac_size,
                                 size_t* mac_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_out(WT_PSA_FN_MAC_SIGN_FINISH, &operation->opaque, mac,
                         mac_size, mac_length);
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t* operation,
                                   const uint8_t* mac, size_t mac_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_in(WT_PSA_FN_MAC_VERIFY_FINISH, &operation->opaque, mac,
                        mac_length);
}

psa_status_t psa_mac_abort(psa_mac_operation_t* operation)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_abort(WT_PSA_FN_MAC_ABORT, &operation->opaque);
}

/* ---- Cipher ---- */
/* A one-shot cipher too big for one message: the IV leads the ciphertext. */
static psa_status_t wt_psa_cipher_parts(int decrypt, psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t* in, size_t in_len,
                                        uint8_t* out, size_t out_size,
                                        size_t* out_len)
{
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t attr = psa_key_attributes_init();
    size_t iv_len = 0U;
    size_t total = 0U;
    size_t got = 0U;
    psa_status_t status;

    if (out_len == NULL || in == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *out_len = 0U;
    if (out == NULL) {
        return (out_size != 0U) ? PSA_ERROR_INVALID_ARGUMENT :
               PSA_ERROR_BUFFER_TOO_SMALL;
    }
    status = psa_get_key_attributes(key, &attr);
    if (status == PSA_SUCCESS) {
        iv_len = PSA_CIPHER_IV_LENGTH(psa_get_key_type(&attr), alg);
        status = (decrypt != 0) ? psa_cipher_decrypt_setup(&op, key, alg) :
                 psa_cipher_encrypt_setup(&op, key, alg);
    }
    if (status == PSA_SUCCESS && iv_len != 0U && decrypt != 0) {
        status = (in_len < iv_len) ? PSA_ERROR_INVALID_ARGUMENT :
                 psa_cipher_set_iv(&op, in, iv_len);
        in += iv_len;
        in_len -= (status == PSA_SUCCESS) ? iv_len : 0U;
    }
    else if (status == PSA_SUCCESS && iv_len != 0U) {
        status = (out_size < iv_len) ? PSA_ERROR_BUFFER_TOO_SMALL :
                 psa_cipher_generate_iv(&op, out, iv_len, &total);
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_update(&op, in, in_len, out + total,
                                   out_size - total, &got);
        total += (status == PSA_SUCCESS) ? got : 0U;
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(&op, out + total, out_size - total, &got);
        total += (status == PSA_SUCCESS) ? got : 0U;
    }
    if (status != PSA_SUCCESS) {
        (void)psa_cipher_abort(&op);
        if (total != 0U) {
            (void)memset(out, 0, total);
        }
        total = 0U;
    }
    *out_len = total;
    return status;
}

/* Fits one message: the input, and an output up to an IV and a block more. */
static int wt_psa_cipher_fits(size_t in_len)
{
    return (in_len <= WT_PSA_IN_INLINE && in_len <= WT_PSA_OUT_INLINE - 32U);
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg,
                                const uint8_t* input, size_t input_length,
                                uint8_t* output, size_t output_size,
                                size_t* output_length)
{
    wt_psa_req_t r;

    if (!wt_psa_cipher_fits(input_length)) {
        return wt_psa_cipher_parts(0, key, alg, input, input_length, output,
                                   output_size, output_length);
    }
    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, input, input_length);
    wt_psa_out(&r, 0U, output, output_size);
    return wt_psa_run_out(WT_PSA_FN_CIPHER_ENCRYPT, &r, NULL, output_length);
}

psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg,
                                const uint8_t* input, size_t input_length,
                                uint8_t* output, size_t output_size,
                                size_t* output_length)
{
    wt_psa_req_t r;

    if (!wt_psa_cipher_fits(input_length)) {
        return wt_psa_cipher_parts(1, key, alg, input, input_length, output,
                                   output_size, output_length);
    }
    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, input, input_length);
    wt_psa_out(&r, 0U, output, output_size);
    return wt_psa_run_out(WT_PSA_FN_CIPHER_DECRYPT, &r, NULL, output_length);
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t* operation,
                                      psa_key_id_t key, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_CIPHER_ENCRYPT_SETUP, &operation->opaque,
                           key, alg);
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t* operation,
                                      psa_key_id_t key, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_CIPHER_DECRYPT_SETUP, &operation->opaque,
                           key, alg);
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t* operation,
                                    uint8_t* iv, size_t iv_size,
                                    size_t* iv_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_out(WT_PSA_FN_CIPHER_GENERATE_IV, &operation->opaque, iv,
                         iv_size, iv_length);
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t* operation,
                               const uint8_t* iv, size_t iv_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_in(WT_PSA_FN_CIPHER_SET_IV, &operation->opaque, iv,
                        iv_length);
}

psa_status_t psa_cipher_update(psa_cipher_operation_t* operation,
                               const uint8_t* input, size_t input_length,
                               uint8_t* output, size_t output_size,
                               size_t* output_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_stream_io(WT_PSA_FN_CIPHER_UPDATE, &operation->opaque,
                               input, input_length, output, output_size,
                               output_length);
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t* operation,
                               uint8_t* output, size_t output_size,
                               size_t* output_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_out(WT_PSA_FN_CIPHER_FINISH, &operation->opaque, output,
                         output_size, output_length);
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t* operation)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_abort(WT_PSA_FN_CIPHER_ABORT, &operation->opaque);
}

/* ---- AEAD ---- */
/* A one-shot AEAD too big for one message, as the multi-part sequence. The
 * tag follows the ciphertext; a decrypt that fails leaves no plaintext. */
static psa_status_t wt_psa_aead_parts(int decrypt, psa_key_id_t key,
                                      psa_algorithm_t alg,
                                      const uint8_t* nonce, size_t nonce_len,
                                      const uint8_t* ad, size_t ad_len,
                                      const uint8_t* in, size_t in_len,
                                      uint8_t* out, size_t out_size,
                                      size_t* out_len)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_attributes_t attr = psa_key_attributes_init();
    uint8_t tail[PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE];
    uint8_t tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t tag_len = 0U;
    size_t data_len = in_len;
    size_t total = 0U;
    size_t got = 0U;
    size_t tgot = 0U;
    psa_status_t status;

    if (out_len == NULL || in == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *out_len = 0U;
    if (out == NULL) {
        return (out_size != 0U) ? PSA_ERROR_INVALID_ARGUMENT :
               PSA_ERROR_BUFFER_TOO_SMALL;
    }
    status = psa_get_key_attributes(key, &attr);
    if (status == PSA_SUCCESS) {
        tag_len = PSA_AEAD_TAG_LENGTH(psa_get_key_type(&attr),
                                      psa_get_key_bits(&attr), alg);
        if (decrypt != 0 && in_len < tag_len) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
        data_len = (decrypt != 0) ? in_len - tag_len : in_len;
    }
    if (status == PSA_SUCCESS) {
        status = (decrypt != 0) ? psa_aead_decrypt_setup(&op, key, alg) :
                 psa_aead_encrypt_setup(&op, key, alg);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_lengths(&op, ad_len, data_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_nonce(&op, nonce, nonce_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_update_ad(&op, ad, ad_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_update(&op, in, data_len, out, out_size, &total);
    }
    if (status == PSA_SUCCESS && decrypt != 0) {
        status = psa_aead_verify(&op, tail, sizeof(tail), &got,
                                 in + data_len, tag_len);
    }
    else if (status == PSA_SUCCESS) {
        status = psa_aead_finish(&op, tail, sizeof(tail), &got, tag,
                                 sizeof(tag), &tgot);
    }
    if (status == PSA_SUCCESS && got + tgot > out_size - total) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (status == PSA_SUCCESS) {
        (void)memcpy(out + total, tail, got);
        (void)memcpy(out + total + got, tag, tgot);
        total += got + tgot;
    }
    (void)memset(tail, 0, sizeof(tail));
    if (status != PSA_SUCCESS) {
        (void)psa_aead_abort(&op);
        if (total != 0U) {
            (void)memset(out, 0, total);
        }
        total = 0U;
    }
    *out_len = total;
    return status;
}

static psa_status_t wt_psa_aead_once(uint32_t fn, psa_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t* nonce, size_t nonce_len,
                                     const uint8_t* ad, size_t ad_len,
                                     const uint8_t* in, size_t in_len,
                                     uint8_t* out, size_t out_size,
                                     size_t* out_len)
{
    wt_psa_req_t r;

    if (nonce_len + ad_len + in_len > WT_PSA_IN_INLINE ||
            in_len > WT_PSA_OUT_INLINE - PSA_AEAD_TAG_MAX_SIZE) {
        return wt_psa_aead_parts((fn == WT_PSA_FN_AEAD_DECRYPT) ? 1 : 0, key,
                                 alg, nonce, nonce_len, ad, ad_len, in,
                                 in_len, out, out_size, out_len);
    }
    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, nonce, nonce_len);
    wt_psa_in(&r, 1U, ad, ad_len);
    wt_psa_in(&r, 2U, in, in_len);
    wt_psa_out(&r, 0U, out, out_size);
    return wt_psa_run_out(fn, &r, NULL, out_len);
}

psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg,
                              const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* additional_data,
                              size_t additional_data_length,
                              const uint8_t* plaintext,
                              size_t plaintext_length, uint8_t* ciphertext,
                              size_t ciphertext_size,
                              size_t* ciphertext_length)
{
    return wt_psa_aead_once(WT_PSA_FN_AEAD_ENCRYPT, key, alg, nonce,
                            nonce_length, additional_data,
                            additional_data_length, plaintext,
                            plaintext_length, ciphertext, ciphertext_size,
                            ciphertext_length);
}

psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg,
                              const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* additional_data,
                              size_t additional_data_length,
                              const uint8_t* ciphertext,
                              size_t ciphertext_length, uint8_t* plaintext,
                              size_t plaintext_size,
                              size_t* plaintext_length)
{
    return wt_psa_aead_once(WT_PSA_FN_AEAD_DECRYPT, key, alg, nonce,
                            nonce_length, additional_data,
                            additional_data_length, ciphertext,
                            ciphertext_length, plaintext, plaintext_size,
                            plaintext_length);
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t* operation,
                                    psa_key_id_t key, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_AEAD_ENCRYPT_SETUP, &operation->opaque,
                           key, alg);
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t* operation,
                                    psa_key_id_t key, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_AEAD_DECRYPT_SETUP, &operation->opaque,
                           key, alg);
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t* operation,
                                     uint8_t* nonce, size_t nonce_size,
                                     size_t* nonce_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_out(WT_PSA_FN_AEAD_GENERATE_NONCE, &operation->opaque,
                         nonce, nonce_size, nonce_length);
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t* operation,
                                const uint8_t* nonce, size_t nonce_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_in(WT_PSA_FN_AEAD_SET_NONCE, &operation->opaque, nonce,
                        nonce_length);
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t* operation,
                                  size_t ad_length, size_t plaintext_length)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ad_length > 0xFFFFFFFFU || plaintext_length > 0xFFFFFFFFU) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, (uint32_t)ad_length, (uint32_t)plaintext_length);
    return wt_psa_run(WT_PSA_FN_AEAD_SET_LENGTHS, &r, &operation->opaque);
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t* operation,
                                const uint8_t* input, size_t input_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_stream(WT_PSA_FN_AEAD_UPDATE_AD, &operation->opaque,
                            input, input_length);
}

psa_status_t psa_aead_update(psa_aead_operation_t* operation,
                             const uint8_t* input, size_t input_length,
                             uint8_t* output, size_t output_size,
                             size_t* output_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_stream_io(WT_PSA_FN_AEAD_UPDATE, &operation->opaque,
                               input, input_length, output, output_size,
                               output_length);
}

psa_status_t psa_aead_finish(psa_aead_operation_t* operation,
                             uint8_t* ciphertext, size_t ciphertext_size,
                             size_t* ciphertext_length, uint8_t* tag,
                             size_t tag_size, size_t* tag_length)
{
    wt_psa_req_t r;
    psa_status_t status;

    if (operation == NULL || ciphertext_length == NULL ||
            tag_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, 0U, 0U);
    wt_psa_out(&r, 0U, ciphertext, ciphertext_size);
    wt_psa_out(&r, 1U, tag, tag_size);
    status = wt_psa_run_out(WT_PSA_FN_AEAD_FINISH, &r, &operation->opaque,
                            ciphertext_length);
    *tag_length = (status == PSA_SUCCESS) ? r.out_len[1] : 0U;
    return status;
}

psa_status_t psa_aead_verify(psa_aead_operation_t* operation,
                             uint8_t* plaintext, size_t plaintext_size,
                             size_t* plaintext_length, const uint8_t* tag,
                             size_t tag_length)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_inout(WT_PSA_FN_AEAD_VERIFY, &operation->opaque, tag,
                           tag_length, plaintext, plaintext_size,
                           plaintext_length);
}

psa_status_t psa_aead_abort(psa_aead_operation_t* operation)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_abort(WT_PSA_FN_AEAD_ABORT, &operation->opaque);
}

/* ---- Key derivation ---- */
psa_status_t psa_key_derivation_setup(
    psa_key_derivation_operation_t* operation, psa_algorithm_t alg)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_setup(WT_PSA_FN_KDF_SETUP, &operation->opaque, alg, 0U);
}

psa_status_t psa_key_derivation_get_capacity(
    const psa_key_derivation_operation_t* operation, size_t* capacity)
{
    wt_psa_req_t r;
    uintptr_t token;
    psa_status_t status;

    if (operation == NULL || capacity == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    token = operation->opaque;
    wt_psa_req_init(&r, 0U, 0U, 0U);
    status = wt_psa_run(WT_PSA_FN_KDF_GET_CAPACITY, &r, &token);
    *capacity = (r.val == 0xFFFFFFFFU) ?
                PSA_KEY_DERIVATION_UNLIMITED_CAPACITY : (size_t)r.val;
    return status;
}

psa_status_t psa_key_derivation_set_capacity(
    psa_key_derivation_operation_t* operation, size_t capacity)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, (capacity >= 0xFFFFFFFFU) ? 0xFFFFFFFFU :
                    (uint32_t)capacity, 0U);
    return wt_psa_run(WT_PSA_FN_KDF_SET_CAPACITY, &r, &operation->opaque);
}

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t* operation,
    psa_key_derivation_step_t step, const uint8_t* data, size_t data_length)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, step, 0U);
    wt_psa_in(&r, 0U, data, data_length);
    return wt_psa_run(WT_PSA_FN_KDF_INPUT_BYTES, &r, &operation->opaque);
}

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t* operation,
    psa_key_derivation_step_t step, psa_key_id_t key)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, step, key);
    return wt_psa_run(WT_PSA_FN_KDF_INPUT_KEY, &r, &operation->opaque);
}

psa_status_t psa_key_derivation_key_agreement(
    psa_key_derivation_operation_t* operation,
    psa_key_derivation_step_t step, psa_key_id_t private_key,
    const uint8_t* peer_key, size_t peer_key_length)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, step, private_key);
    wt_psa_in(&r, 0U, peer_key, peer_key_length);
    return wt_psa_run(WT_PSA_FN_KDF_KEY_AGREEMENT, &r, &operation->opaque);
}

/* A read split over several messages must fail whole, as one read would: on
 * too little capacity the operation drains and nothing is output. */
static psa_status_t wt_psa_kdf_reserve(
    psa_key_derivation_operation_t* operation, size_t len, size_t limit)
{
    size_t cap = 0U;
    psa_status_t status = PSA_SUCCESS;

    if (len > limit) {
        status = psa_key_derivation_get_capacity(operation, &cap);
        if (status == PSA_SUCCESS && cap < len) {
            (void)psa_key_derivation_set_capacity(operation, 0U);
            status = PSA_ERROR_INSUFFICIENT_DATA;
        }
    }
    return status;
}

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t* operation, uint8_t* output,
    size_t output_length)
{
    size_t done = 0U;
    size_t chunk;
    size_t got = 0U;
    psa_status_t status;

    if (operation == NULL || (output == NULL && output_length != 0U)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_psa_kdf_reserve(operation, output_length, WT_PSA_OUT_INLINE);
    do {
        chunk = output_length - done;
        if (chunk > WT_PSA_OUT_INLINE) {
            chunk = WT_PSA_OUT_INLINE;
        }
        if (status == PSA_SUCCESS) {
            status = wt_psa_op_out(WT_PSA_FN_KDF_OUTPUT_BYTES,
                                   &operation->opaque,
                                   (output != NULL) ? output + done : NULL,
                                   chunk, &got);
        }
        if (status == PSA_SUCCESS && got != chunk) {
            status = PSA_ERROR_COMMUNICATION_FAILURE;
        }
        done += chunk;
    } while (status == PSA_SUCCESS && done < output_length);
    if (status != PSA_SUCCESS && output != NULL) {
        (void)memset(output, 0, output_length);
    }
    return status;
}

psa_status_t psa_key_derivation_output_key(
    const psa_key_attributes_t* attributes,
    psa_key_derivation_operation_t* operation, psa_key_id_t* key)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, 0U, 0U);
    return wt_psa_run_key(WT_PSA_FN_KDF_OUTPUT_KEY, &r, attributes,
                          &operation->opaque, key);
}

psa_status_t psa_key_derivation_input_integer(
    psa_key_derivation_operation_t* operation,
    psa_key_derivation_step_t step, uint64_t value)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, step, (uint32_t)value);
    r.a[3] = (uint32_t)(value >> 32);
    return wt_psa_run(WT_PSA_FN_KDF_INPUT_INTEGER, &r, &operation->opaque);
}

psa_status_t psa_key_derivation_verify_bytes(
    psa_key_derivation_operation_t* operation, const uint8_t* expected,
    size_t expected_length)
{
    psa_status_t status;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_psa_kdf_reserve(operation, expected_length,
                                WT_PSA_IN_INLINE);
    if (status == PSA_SUCCESS) {
        status = wt_psa_op_stream(WT_PSA_FN_KDF_VERIFY_BYTES,
                                  &operation->opaque, expected,
                                  expected_length);
    }
    return status;
}

psa_status_t psa_key_derivation_verify_key(
    psa_key_derivation_operation_t* operation, psa_key_id_t expected)
{
    wt_psa_req_t r;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    wt_psa_req_init(&r, 0U, expected, 0U);
    return wt_psa_run(WT_PSA_FN_KDF_VERIFY_KEY, &r, &operation->opaque);
}

psa_status_t psa_key_derivation_abort(
    psa_key_derivation_operation_t* operation)
{
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return wt_psa_op_abort(WT_PSA_FN_KDF_ABORT, &operation->opaque);
}

/* ---- Asymmetric ---- */
static psa_status_t wt_psa_sign(uint32_t fn, psa_key_id_t key,
                                psa_algorithm_t alg, const uint8_t* in,
                                size_t in_len, uint8_t* sig, size_t sig_size,
                                size_t* sig_len)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, in, in_len);
    wt_psa_out(&r, 0U, sig, sig_size);
    return wt_psa_run_out(fn, &r, NULL, sig_len);
}

static psa_status_t wt_psa_verify(uint32_t fn, psa_key_id_t key,
                                  psa_algorithm_t alg, const uint8_t* in,
                                  size_t in_len, const uint8_t* sig,
                                  size_t sig_len)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, in, in_len);
    wt_psa_in(&r, 1U, sig, sig_len);
    return wt_psa_run(fn, &r, NULL);
}

psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
                           const uint8_t* hash, size_t hash_length,
                           uint8_t* signature, size_t signature_size,
                           size_t* signature_length)
{
    return wt_psa_sign(WT_PSA_FN_SIGN_HASH, key, alg, hash, hash_length,
                       signature, signature_size, signature_length);
}

psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
                             const uint8_t* hash, size_t hash_length,
                             const uint8_t* signature,
                             size_t signature_length)
{
    return wt_psa_verify(WT_PSA_FN_VERIFY_HASH, key, alg, hash, hash_length,
                         signature, signature_length);
}

/* A message too big for one request is hashed here and signed as a hash,
 * which needs a key that may sign hashes. */
static psa_status_t wt_psa_msg_hash(psa_algorithm_t alg, const uint8_t* in,
                                    size_t in_len, uint8_t* hash,
                                    size_t hash_size, size_t* hash_len)
{
    psa_algorithm_t h = PSA_ALG_SIGN_GET_HASH(alg);

    if (!PSA_ALG_IS_HASH_AND_SIGN(alg) || h == 0U || h == PSA_ALG_ANY_HASH) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    return psa_hash_compute(h, in, in_len, hash, hash_size, hash_len);
}

psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg,
                              const uint8_t* input, size_t input_length,
                              uint8_t* signature, size_t signature_size,
                              size_t* signature_length)
{
    uint8_t hash[64];
    size_t hash_len = 0U;
    psa_status_t status;

    if (input_length <= WT_PSA_IN_INLINE) {
        return wt_psa_sign(WT_PSA_FN_SIGN_MESSAGE, key, alg, input,
                           input_length, signature, signature_size,
                           signature_length);
    }
    if (signature_length != NULL) {
        *signature_length = 0U;
    }
    status = wt_psa_msg_hash(alg, input, input_length, hash, sizeof(hash),
                             &hash_len);
    if (status == PSA_SUCCESS) {
        status = psa_sign_hash(key, alg, hash, hash_len, signature,
                               signature_size, signature_length);
    }
    return status;
}

psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg,
                                const uint8_t* input, size_t input_length,
                                const uint8_t* signature,
                                size_t signature_length)
{
    uint8_t hash[64];
    size_t hash_len = 0U;
    psa_status_t status;

    if (input_length + signature_length <= WT_PSA_IN_INLINE) {
        return wt_psa_verify(WT_PSA_FN_VERIFY_MESSAGE, key, alg, input,
                             input_length, signature, signature_length);
    }
    status = wt_psa_msg_hash(alg, input, input_length, hash, sizeof(hash),
                             &hash_len);
    if (status == PSA_SUCCESS) {
        status = psa_verify_hash(key, alg, hash, hash_len, signature,
                                 signature_length);
    }
    return status;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t* peer_key,
                                   size_t peer_key_length, uint8_t* output,
                                   size_t output_size, size_t* output_length)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, alg, private_key, 0U);
    wt_psa_in(&r, 0U, peer_key, peer_key_length);
    wt_psa_out(&r, 0U, output, output_size);
    return wt_psa_run_out(WT_PSA_FN_RAW_KEY_AGREEMENT, &r, NULL,
                          output_length);
}

psa_status_t psa_key_agreement(psa_key_id_t private_key,
                               const uint8_t* peer_key,
                               size_t peer_key_length, psa_algorithm_t alg,
                               const psa_key_attributes_t* attributes,
                               psa_key_id_t* key)
{
    uint8_t wire[WT_PSA_WIRE_ATTR_LEN];
    wt_psa_req_t r;
    psa_status_t status;

    if (attributes == NULL || key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *key = PSA_KEY_ID_NULL;
    wt_psa_attr_put(attributes, wire);
    wt_psa_req_init(&r, alg, private_key, 0U);
    wt_psa_in(&r, 0U, peer_key, peer_key_length);
    wt_psa_in(&r, 1U, wire, sizeof(wire));
    status = wt_psa_run(WT_PSA_FN_KEY_AGREEMENT, &r, NULL);
    if (status == PSA_SUCCESS) {
        *key = (psa_key_id_t)r.val;
    }
    return status;
}

static psa_status_t wt_psa_asym_crypt(uint32_t fn, psa_key_id_t key,
                                      psa_algorithm_t alg, const uint8_t* in,
                                      size_t in_len, const uint8_t* salt,
                                      size_t salt_len, uint8_t* out,
                                      size_t out_size, size_t* out_len)
{
    wt_psa_req_t r;

    wt_psa_req_init(&r, key, alg, 0U);
    wt_psa_in(&r, 0U, in, in_len);
    wt_psa_in(&r, 1U, salt, salt_len);
    wt_psa_out(&r, 0U, out, out_size);
    return wt_psa_run_out(fn, &r, NULL, out_len);
}

psa_status_t psa_asymmetric_encrypt(psa_key_id_t key, psa_algorithm_t alg,
                                    const uint8_t* input, size_t input_length,
                                    const uint8_t* salt, size_t salt_length,
                                    uint8_t* output, size_t output_size,
                                    size_t* output_length)
{
    return wt_psa_asym_crypt(WT_PSA_FN_ASYMMETRIC_ENCRYPT, key, alg, input,
                             input_length, salt, salt_length, output,
                             output_size, output_length);
}

psa_status_t psa_asymmetric_decrypt(psa_key_id_t key, psa_algorithm_t alg,
                                    const uint8_t* input, size_t input_length,
                                    const uint8_t* salt, size_t salt_length,
                                    uint8_t* output, size_t output_size,
                                    size_t* output_length)
{
    return wt_psa_asym_crypt(WT_PSA_FN_ASYMMETRIC_DECRYPT, key, alg, input,
                             input_length, salt, salt_length, output,
                             output_size, output_length);
}
