/* psa_storage_client.c
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

/* PSA Internal Trusted Storage / Protected Storage 1.0 client
 * (SRC-PSA-STORAGE): marshals the public psa_its_* and psa_ps_* calls onto the
 * SERVICE_ITS / SERVICE_PS wire protocol over the OS-neutral FF-M client
 * (psa_connect/psa_call/psa_close), with no operating-system dependency, so
 * every Non-secure client links the same code. Each operation runs one
 * connect/call/close round trip; the SPM stamps the caller identity, so the
 * vault namespaces every object under the calling guest automatically. The
 * wire matches src/services/storage_service.c: one concatenated input vector
 * [header][data] on writes, the header alone on reads, the reply in output
 * vector 0. */

#include <stdint.h>
#include <string.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "psa/error.h"
#include "psa/storage_common.h"
#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"
#include "wolftrust/zeroize.h"

/* Wire header + ops, kept in lockstep with storage_service.h (the SPM-side
 * definition pulls in Secure-only headers and is not includable here). */
typedef struct {
    uint64_t uid;
    uint32_t flags;
    uint32_t offset;
} wt_its_wire_t;

#define WT_ITS_WIRE_SET         1
#define WT_ITS_WIRE_GET         2
#define WT_ITS_WIRE_GET_INFO    3
#define WT_ITS_WIRE_REMOVE      4
#define WT_PS_WIRE_CREATE       5
#define WT_PS_WIRE_SET_EXTENDED 6
#define WT_PS_WIRE_GET_SUPPORT  7

/* The vault refuses objects larger than its copied-transfer bound; the
 * dev_apis Storage suite stays well under this (UID_MAX_SIZE 512). */
#define WT_NS_STORAGE_MAX 512U

/* Map the SERVICE reply (a PSA status) to the ITS/PS return type. Both PSA
 * storage APIs return psa_status_t, so the values pass through unchanged. */
static psa_status_t wt_storage_ns_write(uint32_t sid, int32_t op, uint64_t uid,
                                        uint32_t flags, uint32_t offset,
                                        const void* data, size_t len)
{
    uint8_t buffer[sizeof(wt_its_wire_t) + WT_NS_STORAGE_MAX];
    wt_its_wire_t hdr;
    psa_handle_t handle;
    psa_invec in_vec[1];
    psa_status_t status;

    /* PSA Storage 1.0: an inaccessible data pointer (NULL with a nonzero
     * length) is invalid before any marshalling; a valid object the local
     * bounce buffer cannot carry is an insufficient-storage condition, not an
     * argument error. */
    if (data == NULL && len > 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (len > WT_NS_STORAGE_MAX) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    hdr.uid = uid;
    hdr.flags = flags;
    hdr.offset = offset;
    (void)memcpy(buffer, &hdr, sizeof(hdr));
    if (len > 0U) {
        (void)memcpy(buffer + sizeof(hdr), data, len);
    }
    handle = psa_connect(sid, 1U);
    if (handle <= 0) {
        status = PSA_ERROR_GENERIC_ERROR;
    }
    else {
        in_vec[0].base = buffer;
        in_vec[0].len = sizeof(hdr) + len;
        status = psa_call(handle, op, in_vec, 1U, NULL, 0U);
        psa_close(handle);
    }
    wt_forceZero(buffer, sizeof(buffer));
    return status;
}

static psa_status_t wt_storage_ns_read(uint32_t sid, int32_t op, uint64_t uid,
                                       uint32_t offset, void* out,
                                       size_t out_cap, size_t* out_len)
{
    wt_its_wire_t hdr;
    psa_handle_t handle;
    psa_invec in_vec[1];
    psa_outvec out_vec[1];
    psa_status_t status;

    /* p_data_length must receive the bytes written on success (zero
     * included), so a NULL output pointer is an invalid argument — as is a
     * NULL data buffer with a nonzero capacity (the storage API pins -135,
     * where the raw FF-M vector check would classify a programmer error). */
    if (out_len == NULL || (out == NULL && out_cap != 0U)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    hdr.uid = uid;
    hdr.flags = 0U;
    hdr.offset = offset;
    handle = psa_connect(sid, 1U);
    if (handle <= 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    in_vec[0].base = &hdr;
    in_vec[0].len = sizeof(hdr);
    out_vec[0].base = out;
    out_vec[0].len = out_cap;
    status = psa_call(handle, op, in_vec, 1U, out_vec, 1U);
    psa_close(handle);
    *out_len = out_vec[0].len;
    return status;
}

static psa_status_t wt_storage_ns_get_info(uint32_t sid, uint64_t uid,
                                           struct psa_storage_info_t* info)
{
    /* The service replies with {capacity, size, flags, reserved} — the first
     * three fields translate to the PSA info struct. */
    uint32_t reply[4];
    size_t got = 0U;
    psa_status_t status;

    if (info == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wt_storage_ns_read(sid, WT_ITS_WIRE_GET_INFO, uid, 0U, reply,
                                sizeof(reply), &got);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (got < 3U * sizeof(uint32_t)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    info->capacity = (size_t)reply[0];
    info->size = (size_t)reply[1];
    info->flags = (psa_storage_create_flags_t)reply[2];
    return PSA_SUCCESS;
}

psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length,
                         const void* p_data,
                         psa_storage_create_flags_t create_flags)
{
    return wt_storage_ns_write(SERVICE_ITS_SID, WT_ITS_WIRE_SET, uid,
                               create_flags, 0U, p_data, data_length);
}

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset,
                         size_t data_size, void* p_data,
                         size_t* p_data_length)
{
    return wt_storage_ns_read(SERVICE_ITS_SID, WT_ITS_WIRE_GET, uid,
                              (uint32_t)data_offset, p_data, data_size,
                              p_data_length);
}

psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                              struct psa_storage_info_t* p_info)
{
    return wt_storage_ns_get_info(SERVICE_ITS_SID, uid, p_info);
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
    return wt_storage_ns_write(SERVICE_ITS_SID, WT_ITS_WIRE_REMOVE, uid, 0U,
                               0U, NULL, 0U);
}

psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length,
                        const void* p_data,
                        psa_storage_create_flags_t create_flags)
{
    return wt_storage_ns_write(SERVICE_PS_SID, WT_ITS_WIRE_SET, uid,
                               create_flags, 0U, p_data, data_length);
}

psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset,
                        size_t data_size, void* p_data,
                        size_t* p_data_length)
{
    return wt_storage_ns_read(SERVICE_PS_SID, WT_ITS_WIRE_GET, uid,
                              (uint32_t)data_offset, p_data, data_size,
                              p_data_length);
}

psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
                             struct psa_storage_info_t* p_info)
{
    return wt_storage_ns_get_info(SERVICE_PS_SID, uid, p_info);
}

psa_status_t psa_ps_remove(psa_storage_uid_t uid)
{
    return wt_storage_ns_write(SERVICE_PS_SID, WT_ITS_WIRE_REMOVE, uid, 0U,
                               0U, NULL, 0U);
}

psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity,
                           psa_storage_create_flags_t create_flags)
{
    /* The service advertises no SET_EXTENDED support, so create is refused
     * NOT_SUPPORTED; forward it faithfully rather than fake success. */
    return wt_storage_ns_write(SERVICE_PS_SID, WT_PS_WIRE_CREATE, uid,
                               create_flags, (uint32_t)capacity, NULL, 0U);
}

psa_status_t psa_ps_set_extended(psa_storage_uid_t uid, size_t data_offset,
                                 size_t data_length, const void* p_data)
{
    return wt_storage_ns_write(SERVICE_PS_SID, WT_PS_WIRE_SET_EXTENDED, uid,
                               0U, (uint32_t)data_offset, p_data,
                               data_length);
}

uint32_t psa_ps_get_support(void)
{
    uint32_t caps = 0U;
    size_t got = 0U;

    if (wt_storage_ns_read(SERVICE_PS_SID, WT_PS_WIRE_GET_SUPPORT, 0U, 0U,
                           &caps, sizeof(caps), &got) != PSA_SUCCESS ||
            got < sizeof(caps)) {
        return 0U;
    }
    return caps;
}
