/* pkcs11_provider.c
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

#include "wolftrust/pkcs11_provider.h"
#include "wolftrust/pkcs11/pkcs11_abi.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"
#include "wolftrust/zeroize.h"

#include "wolfpkcs11/pkcs11.h"
static CK_RV provider_backend_mechanism_info(CK_SLOT_ID slot,
    CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR info)
{
    return C_GetMechanismInfo(slot, mechanism, info);
}

#define WT_PKCS11_PROVIDER_BUILD
#include "wolftrust/crypto_profile.h"

#include <string.h>

#define WT_P11_TEMPLATE_MAX 32U
#define WT_P11_BLOB_OVERHEAD 4U
#define WT_P11_OUTPUT_OVERHEAD 8U
#define WT_P11_PIN_SLOTS 4U
#define WT_P11_PIN_FLAGS (CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | \
    CKF_USER_PIN_LOCKED | CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY | \
    CKF_SO_PIN_LOCKED)

#if WT_PKCS11_PIN_MAX_FAILURES < 1
#error "WT_PKCS11_PIN_MAX_FAILURES must allow at least one PIN attempt"
#endif

typedef union wt_provider_data {
    CK_ULONG alignment;
    uint8_t bytes[WT_PKCS11_MESSAGE_MAX];
} wt_provider_data_t;

static wt_provider_data_t g_provider_storage;
#define g_provider_data g_provider_storage.bytes

typedef struct wt_provider_pin_state {
    unsigned int user_failures;
    unsigned int so_failures;
} wt_provider_pin_state_t;

/* WOLFPKCS11_NO_TIME compiles out wolfPKCS11's clock-based lockout, so the
 * provider keeps its own count. It lives in RAM like the NO_STORE token. */
static wt_provider_pin_state_t g_provider_pin[WT_P11_PIN_SLOTS];

typedef struct wt_provider_mechanism {
    CK_MECHANISM mechanism;
    union {
        CK_AES_CTR_PARAMS ctr;
        CK_GCM_PARAMS gcm;
        CK_CCM_PARAMS ccm;
        CK_ECDH1_DERIVE_PARAMS ecdh;
    } params;
} wt_provider_mechanism_t;

static CK_ULONG provider_ulong(wt_pkcs11_reader_t* reader)
{
    return (CK_ULONG)wt_pkcs11_get_u32(reader);
}

/* A presence flag, then the bytes: NULL and non-NULL empty buffers differ. */
static uint8_t* provider_buffer(wt_pkcs11_reader_t* reader, size_t* length)
{
    uint32_t present = wt_pkcs11_get_u32(reader);
    uint8_t* data = wt_pkcs11_get_bytes(reader, length);

    if (reader->error != 0 || present > 1U ||
            (present == 0U && *length != 0U)) {
        reader->error = 1;
        *length = 0U;
        return NULL;
    }
    return present != 0U ? data : NULL;
}

static uint8_t* provider_blob(wt_pkcs11_reader_t* reader, CK_ULONG* length)
{
    uint32_t declared = wt_pkcs11_get_u32(reader);
    size_t actual = 0U;
    uint8_t* data = provider_buffer(reader, &actual);

    if (reader->error != 0 || actual != declared) {
        reader->error = 1;
        *length = 0U;
        return NULL;
    }
    *length = (CK_ULONG)actual;
    return data;
}

static int provider_scratch_reserve(size_t length, size_t* used,
                                    uint8_t** data)
{
    size_t offset = *used;
    size_t remainder = offset % sizeof(CK_ULONG);
    size_t padding = remainder != 0U ? sizeof(CK_ULONG) - remainder : 0U;

    if (offset > sizeof(g_provider_data) ||
            padding > sizeof(g_provider_data) - offset) {
        return -1;
    }
    offset += padding;
    if (length > sizeof(g_provider_data) - offset) {
        return -1;
    }
    *data = g_provider_data + offset;
    *used = offset + length;
    return 0;
}

static int provider_template(wt_pkcs11_reader_t* reader,
                             CK_ATTRIBUTE* attributes, CK_ULONG* count,
                             int output_values, CK_ULONG* capacities,
                             uint8_t* value_requested,
                             size_t* scratch_used, CK_ATTRIBUTE_PTR* pointer)
{
    CK_ULONG i;
    uint32_t present;

    if (scratch_used == NULL || pointer == NULL) {
        return -1;
    }
    *pointer = NULL;
    present = wt_pkcs11_get_u32(reader);
    *count = provider_ulong(reader);
    if (reader->error != 0 || *count > WT_P11_TEMPLATE_MAX ||
            present > 1U || (present == 0U && *count != 0U)) {
        return -1;
    }
    if (present != 0U) {
        *pointer = attributes;
    }
    for (i = 0U; i < *count; i++) {
        uint32_t has_value;
        size_t wire_len;
        uint8_t* wire_value;

        attributes[i].type = provider_ulong(reader);
        attributes[i].ulValueLen = provider_ulong(reader);
        if (capacities != NULL) {
            capacities[i] = attributes[i].ulValueLen;
        }
        has_value = wt_pkcs11_get_u32(reader);
        wire_value = wt_pkcs11_get_bytes(reader, &wire_len);
        if (reader->error != 0 || has_value > 1U) {
            return -1;
        }
        if (output_values != 0) {
            if (capacities == NULL || value_requested == NULL) {
                return -1;
            }
            value_requested[i] = (uint8_t)has_value;
            attributes[i].pValue = NULL;
            if (has_value == 0U) {
                capacities[i] = 0U;
            }
            if (wire_len != 0U) {
                return -1;
            }
        }
        else {
            if (wire_len != attributes[i].ulValueLen ||
                    (has_value == 0U && wire_len != 0U)) {
                return -1;
            }
            if (has_value != 0U) {
                uint8_t* aligned_value;

                if (provider_scratch_reserve(wire_len, scratch_used,
                                             &aligned_value) != 0) {
                    return -1;
                }
                if (wire_len != 0U) {
                    (void)memcpy(aligned_value, wire_value, wire_len);
                }
                attributes[i].pValue = aligned_value;
            }
            else {
                attributes[i].pValue = NULL;
            }
        }
    }
    return 0;
}

static int provider_prepare_attribute_outputs(
    CK_ATTRIBUTE* attributes, CK_ULONG count, const CK_ULONG* capacities,
    const uint8_t* value_requested, CK_ULONG* output_lengths,
    size_t payload_capacity, size_t* scratch_used, int* has_output)
{
    CK_ULONG i;
    size_t payload_used = 0U;
    int result = 0;

    *has_output = 0;
    for (i = 0U; i < count; i++) {
        CK_ULONG actual = attributes[i].ulValueLen;
        uint8_t* output;

        attributes[i].pValue = NULL;
        output_lengths[i] = 0U;
        if (value_requested[i] == 0U ||
                actual == CK_UNAVAILABLE_INFORMATION) {
            continue;
        }
        if (actual > capacities[i]) {
            result = 1;
            continue;
        }
        if (actual > UINT32_MAX || payload_used > payload_capacity ||
                (size_t)actual > payload_capacity - payload_used ||
                provider_scratch_reserve((size_t)actual, scratch_used,
                                         &output) != 0) {
            result = -1;
            break;
        }
        attributes[i].pValue = output;
        attributes[i].ulValueLen = actual;
        output_lengths[i] = actual;
        payload_used += (size_t)actual;
        *has_output = 1;
    }
    if (result < 0) {
        *scratch_used = 0U;
        *has_output = 0;
        for (i = 0U; i < count; i++) {
            attributes[i].pValue = NULL;
            output_lengths[i] = 0U;
        }
    }
    return result;
}

static uint32_t provider_mechanism_kind(CK_MECHANISM_TYPE mechanism)
{
    switch (mechanism) {
        case CKM_AES_CTR:
            return WT_P11_MECH_CTR;
        case CKM_AES_GCM:
            return WT_P11_MECH_GCM;
        case CKM_AES_CCM:
            return WT_P11_MECH_CCM;
        case CKM_ECDH1_DERIVE:
            return WT_P11_MECH_ECDH;
        default:
            return WT_P11_MECH_RAW;
    }
}

static int provider_raw_mechanism_supported(CK_MECHANISM_TYPE mechanism)
{
    switch (mechanism) {
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA224_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
        case CKM_DH_PKCS_DERIVE:
        case CKM_MD5_HMAC:
        case CKM_SHA1_HMAC:
        case CKM_SHA224_HMAC:
        case CKM_SHA256_HMAC:
        case CKM_SHA384_HMAC:
        case CKM_SHA512_HMAC:
        case CKM_SHA3_224_HMAC:
        case CKM_SHA3_256_HMAC:
        case CKM_SHA3_384_HMAC:
        case CKM_SHA3_512_HMAC:
        case CKM_TLS_MAC:
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_CTS:
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
            return 1;
        default:
            return 0;
    }
}

/* Mechanisms whose required parameters hold nested pointers, which the wire
 * cannot carry; they are hidden so no caller is offered one it cannot use. */
static int provider_mechanism_transportable(CK_MECHANISM_TYPE mechanism)
{
    if (!wt_profile_pkcs11_mechanism(mechanism)) {
        return 0;
    }
    switch (mechanism) {
        case CKM_RSA_PKCS_OAEP:
        case CKM_HKDF_DERIVE:
        case CKM_HKDF_DATA:
        case CKM_AES_CBC_ENCRYPT_DATA:
        case CKM_TLS12_MASTER_KEY_DERIVE:
        case CKM_TLS12_KEY_AND_MAC_DERIVE:
        case CKM_TLS12_MASTER_KEY_DERIVE_DH:
        case CKM_PKCS5_PBKD2:
            return 0;
        default:
            return 1;
    }
}

static CK_ULONG provider_filter_mechanisms(CK_MECHANISM_TYPE* mechanisms,
                                           CK_ULONG count, CK_SLOT_ID slot)
{
    CK_MECHANISM_INFO info;
    CK_ULONG kept = 0U;
    CK_ULONG i;

    for (i = 0U; i < count; i++) {
        if (provider_mechanism_transportable(mechanisms[i]) != 0 &&
                provider_backend_mechanism_info(slot, mechanisms[i], &info) == CKR_OK &&
                (wt_profile_pkcs11_flags(info.flags) &
                 (CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST | CKF_SIGN |
                  CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER |
                  CKF_GENERATE | CKF_GENERATE_KEY_PAIR | CKF_DERIVE |
                  CKF_WRAP | CKF_UNWRAP)) != 0U) {
            mechanisms[kept] = mechanisms[i];
            kept++;
        }
    }
    return kept;
}

static int provider_mechanism(wt_pkcs11_reader_t* reader,
                              wt_provider_mechanism_t* decoded,
                              CK_MECHANISM_PTR* mechanism,
                              size_t* scratch_used)
{
    uint32_t present = wt_pkcs11_get_u32(reader);
    uint32_t kind;
    size_t length;
    uint8_t* data;

    if (scratch_used == NULL) {
        return -1;
    }
    (void)memset(decoded, 0, sizeof(*decoded));
    if (present == 0U) {
        *mechanism = NULL;
        return reader->error != 0 ? -1 : 0;
    }
    if (present != 1U) {
        return -1;
    }
    decoded->mechanism.mechanism = provider_ulong(reader);
    kind = wt_pkcs11_get_u32(reader);
    if (kind != provider_mechanism_kind(decoded->mechanism.mechanism)) {
        return -1;
    }
    if (kind == WT_P11_MECH_CTR) {
        decoded->params.ctr.ulCounterBits = provider_ulong(reader);
        data = wt_pkcs11_get_bytes(reader, &length);
        if (length != sizeof(decoded->params.ctr.cb)) {
            return -1;
        }
        (void)memcpy(decoded->params.ctr.cb, data, length);
        decoded->mechanism.pParameter = &decoded->params.ctr;
        decoded->mechanism.ulParameterLen = sizeof(decoded->params.ctr);
    }
    else if (kind == WT_P11_MECH_GCM) {
        data = provider_buffer(reader, &length);
        decoded->params.gcm.pIv = data;
        decoded->params.gcm.ulIvLen = (CK_ULONG)length;
        decoded->params.gcm.ulIvBits = provider_ulong(reader);
        data = provider_buffer(reader, &length);
        decoded->params.gcm.pAAD = data;
        decoded->params.gcm.ulAADLen = (CK_ULONG)length;
        decoded->params.gcm.ulTagBits = provider_ulong(reader);
        decoded->mechanism.pParameter = &decoded->params.gcm;
        decoded->mechanism.ulParameterLen = sizeof(decoded->params.gcm);
    }
    else if (kind == WT_P11_MECH_CCM) {
        decoded->params.ccm.ulDataLen = provider_ulong(reader);
        data = provider_buffer(reader, &length);
        decoded->params.ccm.pIv = data;
        decoded->params.ccm.ulIvLen = (CK_ULONG)length;
        data = provider_buffer(reader, &length);
        decoded->params.ccm.pAAD = data;
        decoded->params.ccm.ulAADLen = (CK_ULONG)length;
        decoded->params.ccm.ulMacLen = provider_ulong(reader);
        decoded->mechanism.pParameter = &decoded->params.ccm;
        decoded->mechanism.ulParameterLen = sizeof(decoded->params.ccm);
    }
    else if (kind == WT_P11_MECH_ECDH) {
        decoded->params.ecdh.kdf = provider_ulong(reader);
        data = provider_buffer(reader, &length);
        decoded->params.ecdh.pSharedData = data;
        decoded->params.ecdh.ulSharedDataLen = (CK_ULONG)length;
        data = provider_buffer(reader, &length);
        decoded->params.ecdh.pPublicData = data;
        decoded->params.ecdh.ulPublicDataLen = (CK_ULONG)length;
        decoded->mechanism.pParameter = &decoded->params.ecdh;
        decoded->mechanism.ulParameterLen = sizeof(decoded->params.ecdh);
    }
    else if (kind == WT_P11_MECH_RAW) {
        uint8_t* aligned_data;

        data = provider_buffer(reader, &length);
        if (reader->error != 0) {
            return -1;
        }
        if (length != 0U &&
                provider_raw_mechanism_supported(
                    decoded->mechanism.mechanism) == 0) {
            return -1;
        }
        if (data != NULL) {
            if (provider_scratch_reserve(length, scratch_used,
                                         &aligned_data) != 0) {
                return -1;
            }
            if (length != 0U) {
                (void)memcpy(aligned_data, data, length);
            }
            decoded->mechanism.pParameter = aligned_data;
        }
        else {
            decoded->mechanism.pParameter = NULL;
        }
        decoded->mechanism.ulParameterLen = (CK_ULONG)length;
    }
    else {
        return -1;
    }
    *mechanism = &decoded->mechanism;
    return reader->error != 0 ? -1 : 0;
}

static void provider_response_begin(wt_pkcs11_writer_t* writer,
                                    uint8_t* response, size_t capacity)
{
    wt_pkcs11_writer_init(writer, response, capacity);
    wt_pkcs11_put_u32(writer, WT_PKCS11_WIRE_MAGIC);
    wt_pkcs11_put_u32(writer, WT_PKCS11_WIRE_VERSION);
    wt_pkcs11_put_u32(writer, 0U);
}

static void provider_response_rv(uint8_t* response, CK_RV rv)
{
    uint32_t value = (uint32_t)rv;

    response[8] = (uint8_t)value;
    response[9] = (uint8_t)(value >> 8);
    response[10] = (uint8_t)(value >> 16);
    response[11] = (uint8_t)(value >> 24);
}

static void provider_put_object(wt_pkcs11_writer_t* writer,
                                CK_OBJECT_HANDLE object)
{
    wt_pkcs11_put_u32(writer, (uint32_t)object);
}

static void provider_put_length(wt_pkcs11_writer_t* writer, CK_ULONG length)
{
    wt_pkcs11_put_u32(writer, length == CK_UNAVAILABLE_INFORMATION ?
        WT_PKCS11_WIRE_UNAVAILABLE : (uint32_t)length);
}

static void provider_put_output(wt_pkcs11_writer_t* writer, CK_RV rv,
                                CK_BYTE_PTR output, CK_ULONG actual,
                                CK_ULONG capacity)
{
    wt_pkcs11_put_u32(writer, (uint32_t)actual);
    if (output != NULL && rv == CKR_OK && actual <= capacity) {
        wt_pkcs11_put_bytes(writer, output, actual);
    }
    else {
        wt_pkcs11_put_bytes(writer, NULL, 0U);
    }
}

static CK_ULONG provider_output_capacity(const wt_pkcs11_writer_t* writer,
                                         CK_ULONG requested,
                                         size_t overhead)
{
    size_t available;

    if (writer->error != 0 || writer->used > writer->capacity ||
            overhead > writer->capacity - writer->used) {
        return 0U;
    }
    available = writer->capacity - writer->used - overhead;
    if (available > sizeof(g_provider_data)) {
        available = sizeof(g_provider_data);
    }
    if (requested < available) {
        available = (size_t)requested;
    }
    return (CK_ULONG)available;
}

static int provider_request_valid(const wt_pkcs11_reader_t* reader)
{
    return reader->error == 0 && reader->used == reader->length;
}

static unsigned int* provider_pin_failures(CK_SLOT_ID slot, int so)
{
    if (slot == 0U || slot > WT_P11_PIN_SLOTS) {
        return NULL;
    }
    return so != 0 ? &g_provider_pin[slot - 1U].so_failures :
                     &g_provider_pin[slot - 1U].user_failures;
}

/* Every wrong PIN surfaces as CKR_PIN_INCORRECT; any other failure, such as a
 * backend error after a correct PIN, neither consumes nor clears an attempt. */
static void provider_pin_record(unsigned int* failures, CK_RV rv)
{
    if (failures == NULL) {
        return;
    }
    if (rv == CKR_OK) {
        *failures = 0U;
    }
    else if (rv == CKR_PIN_INCORRECT &&
             *failures < WT_PKCS11_PIN_MAX_FAILURES) {
        (*failures)++;
    }
}

static CK_RV provider_pin_counter(CK_SESSION_HANDLE session, int set_pin,
                                  CK_USER_TYPE user, CK_SESSION_INFO* info,
                                  unsigned int** failures)
{
    CK_RV rv;
    int so;

    *failures = NULL;
    (void)memset(info, 0, sizeof(*info));
    rv = C_GetSessionInfo(session, info);
    if (rv == CKR_OK) {
        so = (set_pin != 0) ? (info->state == CKS_RW_SO_FUNCTIONS) :
                              (user == CKU_SO);
        *failures = provider_pin_failures(info->slotID, so);
        if (*failures == NULL) {
            rv = CKR_FUNCTION_FAILED;
        }
    }
    return rv;
}

static int provider_pin_len_valid(const CK_TOKEN_INFO* token,
                                  CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
    return pin != NULL && pin_len >= token->ulMinPinLen &&
           pin_len <= token->ulMaxPinLen;
}

/* The checks C_Login makes before it hashes the PIN: a locked PIN refuses
 * only a call that would really test it, so other errors keep their code. */
static int provider_login_tests_pin(const CK_SESSION_INFO* session,
                                    const CK_TOKEN_INFO* token,
                                    CK_USER_TYPE user, CK_UTF8CHAR_PTR pin,
                                    CK_ULONG pin_len)
{
    int tests = provider_pin_len_valid(token, pin, pin_len) &&
                (session->state == CKS_RO_PUBLIC_SESSION ||
                 session->state == CKS_RW_PUBLIC_SESSION);

    if (tests != 0 && user == CKU_SO) {
        tests = (token->flags & CKF_TOKEN_INITIALIZED) != 0U &&
                (session->flags & CKF_RW_SESSION) != 0U;
    }
    else if (tests != 0 && user == CKU_USER) {
        tests = (token->flags & CKF_USER_PIN_INITIALIZED) != 0U;
    }
    else {
        tests = 0;
    }
    return tests;
}

/* The checks C_SetPIN makes before it hashes the old PIN. */
static int provider_set_pin_tests_pin(const CK_SESSION_INFO* session,
                                      const CK_TOKEN_INFO* token,
                                      CK_UTF8CHAR_PTR old_pin,
                                      CK_ULONG old_len,
                                      CK_UTF8CHAR_PTR new_pin,
                                      CK_ULONG new_len)
{
    if (provider_pin_len_valid(token, old_pin, old_len) == 0 ||
            provider_pin_len_valid(token, new_pin, new_len) == 0) {
        return 0;
    }
    if (session->state == CKS_RW_SO_FUNCTIONS) {
        return 1;
    }
    return (session->state == CKS_RW_USER_FUNCTIONS ||
            session->state == CKS_RW_PUBLIC_SESSION) &&
           (token->flags & CKF_USER_PIN_INITIALIZED) != 0U;
}

static CK_RV provider_login(CK_SESSION_HANDLE session, CK_USER_TYPE user,
                            CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
    CK_SESSION_INFO info;
    CK_TOKEN_INFO token;
    unsigned int* failures = NULL;
    CK_RV rv = provider_pin_counter(session, 0, user, &info, &failures);

    if (rv == CKR_OK && *failures >= WT_PKCS11_PIN_MAX_FAILURES) {
        (void)memset(&token, 0, sizeof(token));
        rv = C_GetTokenInfo(info.slotID, &token);
        if (rv != CKR_OK || provider_login_tests_pin(&info, &token, user,
                                                     pin, pin_len) != 0) {
            rv = CKR_PIN_LOCKED;
        }
    }
    if (rv == CKR_OK) {
        rv = C_Login(session, user, pin, pin_len);
        provider_pin_record(failures, rv);
    }
    return rv;
}

static CK_RV provider_set_pin(CK_SESSION_HANDLE session,
                              CK_UTF8CHAR_PTR old_pin, CK_ULONG old_len,
                              CK_UTF8CHAR_PTR new_pin, CK_ULONG new_len)
{
    CK_SESSION_INFO info;
    CK_TOKEN_INFO token;
    unsigned int* failures = NULL;
    CK_RV rv = provider_pin_counter(session, 1, CKU_USER, &info, &failures);

    if (rv == CKR_OK && *failures >= WT_PKCS11_PIN_MAX_FAILURES) {
        (void)memset(&token, 0, sizeof(token));
        rv = C_GetTokenInfo(info.slotID, &token);
        if (rv != CKR_OK || provider_set_pin_tests_pin(&info, &token,
                old_pin, old_len, new_pin, new_len) != 0) {
            rv = CKR_PIN_LOCKED;
        }
    }
    if (rv == CKR_OK) {
        rv = C_SetPIN(session, old_pin, old_len, new_pin, new_len);
        provider_pin_record(failures, rv);
    }
    return rv;
}

static CK_RV provider_init_pin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin,
                               CK_ULONG pin_len)
{
    CK_SESSION_INFO info;
    unsigned int* failures = NULL;
    CK_RV rv = C_InitPIN(session, pin, pin_len);

    if (rv == CKR_OK) {
        (void)memset(&info, 0, sizeof(info));
        if (C_GetSessionInfo(session, &info) == CKR_OK) {
            failures = provider_pin_failures(info.slotID, 0);
        }
        if (failures != NULL) {
            *failures = 0U;
        }
    }
    return rv;
}

static CK_RV provider_init_token(CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin,
                                 CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
    CK_TOKEN_INFO info;
    unsigned int* failures = provider_pin_failures(slot, 1);
    CK_RV rv = CKR_OK;

    if (failures == NULL || *failures >= WT_PKCS11_PIN_MAX_FAILURES) {
        (void)memset(&info, 0, sizeof(info));
        rv = C_GetTokenInfo(slot, &info);
        if (rv == CKR_OK && failures == NULL) {
            rv = CKR_FUNCTION_FAILED;
        }
        /* A blank token has no SO PIN to guess, so it can always be set. */
        else if (rv == CKR_OK && (info.flags & CKF_TOKEN_INITIALIZED) != 0U &&
                 label != NULL &&
                 provider_pin_len_valid(&info, pin, pin_len) != 0) {
            rv = CKR_PIN_LOCKED;
        }
    }
    if (rv == CKR_OK) {
        rv = C_InitToken(slot, pin, pin_len, label);
        if (rv == CKR_OK) {
            g_provider_pin[slot - 1U].so_failures = 0U;
            g_provider_pin[slot - 1U].user_failures = 0U;
        }
        else {
            provider_pin_record(failures, rv);
        }
    }
    return rv;
}

/* Clear the counts only once C_Finalize really tore the token down: an extra
 * C_Initialize keeps the library, and the token, alive across one finalize. */
static void provider_pin_finalized(void)
{
#ifdef WOLFPKCS11_NO_STORE
    CK_INFO info;

    if (C_GetInfo(&info) == CKR_CRYPTOKI_NOT_INITIALIZED) {
        wt_forceZero(g_provider_pin, sizeof(g_provider_pin));
    }
#endif
}

static CK_FLAGS provider_pin_flags(unsigned int failures, CK_FLAGS low,
                                   CK_FLAGS final_try, CK_FLAGS locked)
{
    CK_FLAGS flags = 0U;

    if (failures > 0U) {
        flags |= low;
    }
    if (failures >= WT_PKCS11_PIN_MAX_FAILURES) {
        flags |= locked;
    }
    else if (failures + 1U == WT_PKCS11_PIN_MAX_FAILURES) {
        flags |= final_try;
    }
    return flags;
}

static void provider_token_pin_flags(CK_SLOT_ID slot, CK_TOKEN_INFO* info)
{
    const unsigned int* user = provider_pin_failures(slot, 0);
    const unsigned int* so = provider_pin_failures(slot, 1);

    info->flags &= ~(CK_FLAGS)WT_P11_PIN_FLAGS;
    if (user != NULL && so != NULL) {
        info->flags |= provider_pin_flags(*user, CKF_USER_PIN_COUNT_LOW,
            CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED);
        info->flags |= provider_pin_flags(*so, CKF_SO_PIN_COUNT_LOW,
            CKF_SO_PIN_FINAL_TRY, CKF_SO_PIN_LOCKED);
    }
}

int wt_pkcs11_provider_dispatch(uint8_t* request, size_t request_len,
                                uint8_t* response, size_t response_cap,
                                size_t* response_len, void* context)
{
    wt_pkcs11_reader_t reader;
    wt_pkcs11_writer_t writer;
    wt_provider_mechanism_t decoded_mechanism;
    CK_MECHANISM_PTR mechanism = NULL;
    CK_ATTRIBUTE attributes[WT_P11_TEMPLATE_MAX];
    CK_ATTRIBUTE private_attributes[WT_P11_TEMPLATE_MAX];
    CK_ATTRIBUTE_PTR template_ptr = NULL;
    CK_ATTRIBUTE_PTR private_template_ptr = NULL;
    CK_ULONG attribute_capacities[WT_P11_TEMPLATE_MAX];
    CK_ULONG attribute_output_lengths[WT_P11_TEMPLATE_MAX];
    uint8_t attribute_value_requested[WT_P11_TEMPLATE_MAX];
    CK_SLOT_ID slots[WT_PKCS11_LIST_MAX];
    CK_MECHANISM_TYPE mechanisms[WT_PKCS11_LIST_MAX];
    CK_OBJECT_HANDLE objects[WT_PKCS11_LIST_MAX];
    CK_ULONG count = 0U;
    CK_ULONG private_count = 0U;
    CK_ULONG capacity = 0U;
    CK_ULONG length = 0U;
    CK_ULONG second_length = 0U;
    size_t second_wire_length = 0U;
    CK_ULONG session;
    CK_ULONG value;
    CK_ULONG second_value;
    CK_ULONG i;
    CK_RV rv = CKR_ARGUMENTS_BAD;
    uint8_t* data = NULL;
    uint8_t* second_data = NULL;
    uint32_t function;
    uint32_t has_output;
    CK_ULONG wire_capacity;
    size_t provider_data_used = 0U;
    size_t attribute_payload_capacity;
    size_t attribute_wire_overhead;
    int attribute_output_status;
    int has_attribute_output;

    (void)context;
    if (request == NULL || request_len == 0U || response == NULL ||
            response_cap < 12U || response_len == NULL) {
        return -1;
    }
    wt_forceZero(g_provider_data, sizeof(g_provider_data));
    (void)memset(attributes, 0, sizeof(attributes));
    (void)memset(private_attributes, 0, sizeof(private_attributes));
    (void)memset(attribute_capacities, 0, sizeof(attribute_capacities));
    (void)memset(attribute_output_lengths, 0,
                 sizeof(attribute_output_lengths));
    (void)memset(attribute_value_requested, 0,
                 sizeof(attribute_value_requested));
    wt_pkcs11_reader_init(&reader, request, request_len);
    if (wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_MAGIC ||
            wt_pkcs11_get_u32(&reader) != WT_PKCS11_WIRE_VERSION) {
        return -1;
    }
    function = wt_pkcs11_get_u32(&reader);
    provider_response_begin(&writer, response, response_cap);
    if (!wt_profile_pkcs11_operation(function)) {
        provider_response_rv(response, CKR_FUNCTION_NOT_SUPPORTED);
        *response_len = writer.used;
        return 0;
    }

    switch (function) {
        case WT_P11_INITIALIZE:
        {
            CK_C_INITIALIZE_ARGS init;
            uint32_t bad_reserved = wt_pkcs11_get_u32(&reader);

            (void)memset(&init, 0, sizeof(init));
            if (bad_reserved != 0U) {
                init.pReserved = &init;
            }
            rv = provider_request_valid(&reader) ?
                C_Initialize(bad_reserved != 0U ? &init : NULL) :
                CKR_ARGUMENTS_BAD;
            break;
        }
        case WT_P11_FINALIZE:
            if (provider_request_valid(&reader)) {
                rv = C_Finalize(NULL);
                provider_pin_finalized();
            }
            break;
        case WT_P11_GET_INFO:
        {
            CK_INFO info;
            rv = provider_request_valid(&reader) ? C_GetInfo(&info) :
                                                   CKR_ARGUMENTS_BAD;
            wt_pkcs11_put_bytes(&writer, rv == CKR_OK ? &info : NULL,
                                rv == CKR_OK ? sizeof(info) : 0U);
            break;
        }
        case WT_P11_GET_SLOT_LIST:
        {
            CK_BBOOL present = (CK_BBOOL)wt_pkcs11_get_u32(&reader);
            has_output = wt_pkcs11_get_u32(&reader);
            capacity = provider_ulong(&reader);
            if (!provider_request_valid(&reader) || has_output > 1U) {
                rv = CKR_ARGUMENTS_BAD;
                count = 0U;
            }
            else {
                count = capacity < WT_PKCS11_LIST_MAX ? capacity :
                                                       WT_PKCS11_LIST_MAX;
                rv = C_GetSlotList(present, has_output != 0U ? slots : NULL,
                                   &count);
            }
            wt_pkcs11_put_u32(&writer, (uint32_t)count);
            value = (has_output != 0U && rv == CKR_OK) ? count : 0U;
            wt_pkcs11_put_u32(&writer, (uint32_t)value);
            for (i = 0U; i < value; i++) {
                wt_pkcs11_put_u32(&writer, (uint32_t)slots[i]);
            }
            break;
        }
        case WT_P11_GET_SLOT_INFO:
        {
            CK_SLOT_INFO info;
            value = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_GetSlotInfo((CK_SLOT_ID)value, &info) : CKR_ARGUMENTS_BAD;
            wt_pkcs11_put_bytes(&writer, rv == CKR_OK ? &info : NULL,
                                rv == CKR_OK ? sizeof(info) : 0U);
            break;
        }
        case WT_P11_GET_TOKEN_INFO:
        {
            CK_TOKEN_INFO info;
            value = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_GetTokenInfo((CK_SLOT_ID)value, &info) : CKR_ARGUMENTS_BAD;
            if (rv == CKR_OK) {
                provider_token_pin_flags((CK_SLOT_ID)value, &info);
            }
            wt_pkcs11_put_bytes(&writer, rv == CKR_OK ? &info : NULL,
                                rv == CKR_OK ? sizeof(info) : 0U);
            break;
        }
        case WT_P11_GET_MECHANISM_LIST:
            value = provider_ulong(&reader);
            has_output = wt_pkcs11_get_u32(&reader);
            capacity = provider_ulong(&reader);
            if (!provider_request_valid(&reader) || has_output > 1U) {
                rv = CKR_ARGUMENTS_BAD;
                count = 0U;
            }
            else {
                count = WT_PKCS11_LIST_MAX;
                rv = C_GetMechanismList((CK_SLOT_ID)value, mechanisms,
                                        &count);
                if (rv == CKR_BUFFER_TOO_SMALL) {
                    rv = CKR_DEVICE_MEMORY;
                }
                if (rv == CKR_OK) {
                    count = provider_filter_mechanisms(mechanisms, count,
                        (CK_SLOT_ID)value);
                    if (has_output != 0U && capacity < count) {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                else {
                    count = 0U;
                }
            }
            wt_pkcs11_put_u32(&writer, (uint32_t)count);
            second_value = (has_output != 0U && rv == CKR_OK) ? count : 0U;
            wt_pkcs11_put_u32(&writer, (uint32_t)second_value);
            for (i = 0U; i < second_value; i++) {
                wt_pkcs11_put_u32(&writer, (uint32_t)mechanisms[i]);
            }
            break;
        case WT_P11_GET_MECHANISM_INFO:
        {
            CK_MECHANISM_INFO info;
            (void)memset(&info, 0, sizeof(info));
            value = provider_ulong(&reader);
            second_value = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_GetMechanismInfo((CK_SLOT_ID)value,
                    (CK_MECHANISM_TYPE)second_value, &info) :
                CKR_ARGUMENTS_BAD;
            if (rv == CKR_OK) {
                info.flags = wt_profile_pkcs11_flags(info.flags);
                if ((info.flags & (CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST |
                        CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER |
                        CKF_VERIFY_RECOVER | CKF_GENERATE |
                        CKF_GENERATE_KEY_PAIR | CKF_DERIVE | CKF_WRAP |
                        CKF_UNWRAP)) == 0U) {
                    rv = CKR_MECHANISM_INVALID;
                }
            }
            if (rv == CKR_OK && provider_mechanism_transportable(
                    (CK_MECHANISM_TYPE)second_value) == 0) {
                (void)memset(&info, 0, sizeof(info));
                rv = CKR_MECHANISM_INVALID;
            }
            wt_pkcs11_put_u32(&writer, (uint32_t)info.ulMinKeySize);
            wt_pkcs11_put_u32(&writer, (uint32_t)info.ulMaxKeySize);
            wt_pkcs11_put_u32(&writer, (uint32_t)info.flags);
            break;
        }
        case WT_P11_INIT_TOKEN:
            value = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            second_data = wt_pkcs11_get_bytes(&reader, &second_wire_length);
            if (second_wire_length != 32U) {
                reader.error = 1;
            }
            rv = provider_request_valid(&reader) ?
                provider_init_token((CK_SLOT_ID)value, data, length,
                                    second_data) :
                CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_INIT_PIN:
            session = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            rv = provider_request_valid(&reader) ?
                provider_init_pin(session, data, length) : CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_SET_PIN:
            session = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            second_data = provider_blob(&reader, &second_length);
            rv = provider_request_valid(&reader) ?
                provider_set_pin(session, data, length, second_data,
                                 second_length) :
                CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_OPEN_SESSION:
        {
            CK_SESSION_HANDLE opened = CK_INVALID_HANDLE;
            value = provider_ulong(&reader);
            second_value = provider_ulong(&reader);
            has_output = wt_pkcs11_get_u32(&reader);
            rv = (provider_request_valid(&reader) && has_output <= 1U) ?
                C_OpenSession((CK_SLOT_ID)value, (CK_FLAGS)second_value,
                    NULL, NULL, has_output != 0U ? &opened : NULL) :
                CKR_ARGUMENTS_BAD;
            wt_pkcs11_put_u32(&writer, (uint32_t)opened);
            break;
        }
        case WT_P11_CLOSE_SESSION:
            session = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ? C_CloseSession(session) :
                                                   CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_CLOSE_ALL_SESSIONS:
            value = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_CloseAllSessions((CK_SLOT_ID)value) : CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_GET_SESSION_INFO:
        {
            CK_SESSION_INFO info;
            session = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_GetSessionInfo(session, &info) : CKR_ARGUMENTS_BAD;
            wt_pkcs11_put_bytes(&writer, rv == CKR_OK ? &info : NULL,
                                rv == CKR_OK ? sizeof(info) : 0U);
            break;
        }
        case WT_P11_LOGIN:
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            rv = provider_request_valid(&reader) ?
                provider_login(session, (CK_USER_TYPE)value, data, length) :
                CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_LOGOUT:
            session = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ? C_Logout(session) :
                                                   CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_CREATE_OBJECT:
        {
            CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
            session = provider_ulong(&reader);
            if (provider_template(&reader, attributes, &count, 0, NULL, NULL,
                                  &provider_data_used, &template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_CreateObject(session, template_ptr, count, &object);
            }
            provider_put_object(&writer, object);
            break;
        }
        case WT_P11_COPY_OBJECT:
        {
            CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            if (provider_template(&reader, attributes, &count, 0, NULL, NULL,
                                  &provider_data_used, &template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_CopyObject(session, (CK_OBJECT_HANDLE)value,
                                  template_ptr, count, &object);
            }
            provider_put_object(&writer, object);
            break;
        }
        case WT_P11_DESTROY_OBJECT:
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_DestroyObject(session, (CK_OBJECT_HANDLE)value) :
                CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_GET_OBJECT_SIZE:
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            length = 0U;
            rv = provider_request_valid(&reader) ?
                C_GetObjectSize(session, (CK_OBJECT_HANDLE)value, &length) :
                CKR_ARGUMENTS_BAD;
            provider_put_length(&writer, length);
            break;
        case WT_P11_GET_ATTRIBUTE_VALUE:
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            if (provider_template(&reader, attributes, &count, 1,
                                  attribute_capacities,
                                  attribute_value_requested,
                                  &provider_data_used, &template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_GetAttributeValue(session, (CK_OBJECT_HANDLE)value,
                                         template_ptr, count);
                if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
                        rv == CKR_ATTRIBUTE_TYPE_INVALID ||
                        rv == CKR_BUFFER_TOO_SMALL) {
                    attribute_wire_overhead = 4U +
                        ((size_t)count * WT_P11_OUTPUT_OVERHEAD);
                    attribute_payload_capacity = 0U;
                    if (writer.used <= writer.capacity &&
                            attribute_wire_overhead <=
                                writer.capacity - writer.used) {
                        attribute_payload_capacity = writer.capacity -
                            writer.used - attribute_wire_overhead;
                    }
                    attribute_output_status =
                        provider_prepare_attribute_outputs(attributes, count,
                            attribute_capacities,
                            attribute_value_requested,
                            attribute_output_lengths,
                            attribute_payload_capacity,
                            &provider_data_used, &has_attribute_output);
                    if (attribute_output_status >= 0 &&
                            has_attribute_output != 0) {
                        rv = C_GetAttributeValue(session,
                            (CK_OBJECT_HANDLE)value, template_ptr, count);
                    }
                    if (attribute_output_status < 0) {
                        rv = CKR_DEVICE_MEMORY;
                    }
                    else if (attribute_output_status > 0 && rv == CKR_OK) {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
            }
            else {
                count = 0U;
            }
            wt_pkcs11_put_u32(&writer, (uint32_t)count);
            for (i = 0U; i < count; i++) {
                provider_put_length(&writer, attributes[i].ulValueLen);
                if (attributes[i].pValue != NULL &&
                        attributes[i].ulValueLen != CK_UNAVAILABLE_INFORMATION &&
                        attributes[i].ulValueLen <= attribute_capacities[i] &&
                        attributes[i].ulValueLen <=
                            attribute_output_lengths[i]) {
                    wt_pkcs11_put_bytes(&writer, attributes[i].pValue,
                                        attributes[i].ulValueLen);
                }
                else {
                    wt_pkcs11_put_bytes(&writer, NULL, 0U);
                }
            }
            break;
        case WT_P11_SET_ATTRIBUTE_VALUE:
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            if (provider_template(&reader, attributes, &count, 0, NULL, NULL,
                                  &provider_data_used, &template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_SetAttributeValue(session, (CK_OBJECT_HANDLE)value,
                                         template_ptr, count);
            }
            break;
        case WT_P11_FIND_OBJECTS_INIT:
            session = provider_ulong(&reader);
            if (provider_template(&reader, attributes, &count, 0, NULL, NULL,
                                  &provider_data_used, &template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_FindObjectsInit(session, template_ptr, count);
            }
            break;
        case WT_P11_FIND_OBJECTS:
            session = provider_ulong(&reader);
            has_output = wt_pkcs11_get_u32(&reader);
            capacity = provider_ulong(&reader);
            capacity = capacity < WT_PKCS11_LIST_MAX ? capacity :
                                                        WT_PKCS11_LIST_MAX;
            rv = (provider_request_valid(&reader) && has_output <= 1U) ?
                C_FindObjects(session, has_output != 0U ? objects : NULL,
                              capacity, &count) :
                CKR_ARGUMENTS_BAD;
            if (rv != CKR_OK) {
                count = 0U;
            }
            wt_pkcs11_put_u32(&writer, (uint32_t)count);
            for (i = 0U; i < count; i++) {
                provider_put_object(&writer, objects[i]);
            }
            break;
        case WT_P11_FIND_OBJECTS_FINAL:
            session = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_FindObjectsFinal(session) : CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_ENCRYPT_INIT:
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0) {
                value = provider_ulong(&reader);
                rv = provider_request_valid(&reader) ?
                    C_EncryptInit(session, mechanism,
                        (CK_OBJECT_HANDLE)value) : CKR_ARGUMENTS_BAD;
            }
            break;
        case WT_P11_DECRYPT_INIT:
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0) {
                value = provider_ulong(&reader);
                rv = provider_request_valid(&reader) ?
                    C_DecryptInit(session, mechanism,
                        (CK_OBJECT_HANDLE)value) : CKR_ARGUMENTS_BAD;
            }
            break;
        case WT_P11_DIGEST_INIT:
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0) {
                rv = provider_request_valid(&reader) ?
                    C_DigestInit(session, mechanism) : CKR_ARGUMENTS_BAD;
            }
            break;
        case WT_P11_SIGN_INIT:
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0) {
                value = provider_ulong(&reader);
                rv = provider_request_valid(&reader) ?
                    C_SignInit(session, mechanism, (CK_OBJECT_HANDLE)value) :
                    CKR_ARGUMENTS_BAD;
            }
            break;
        case WT_P11_VERIFY_INIT:
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0) {
                value = provider_ulong(&reader);
                rv = provider_request_valid(&reader) ?
                    C_VerifyInit(session, mechanism,
                        (CK_OBJECT_HANDLE)value) : CKR_ARGUMENTS_BAD;
            }
            break;
        case WT_P11_ENCRYPT:
        case WT_P11_ENCRYPT_UPDATE:
        case WT_P11_DECRYPT:
        case WT_P11_DECRYPT_UPDATE:
        case WT_P11_DIGEST:
        case WT_P11_SIGN:
            session = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            has_output = wt_pkcs11_get_u32(&reader);
            capacity = provider_ulong(&reader);
            wire_capacity = provider_output_capacity(&writer, capacity,
                                                     WT_P11_OUTPUT_OVERHEAD);
            if (has_output > 1U || !provider_request_valid(&reader)) {
                rv = CKR_ARGUMENTS_BAD;
                second_length = 0U;
            }
            else {
                second_length = has_output != 0U ? wire_capacity : 0U;
                if (function == WT_P11_ENCRYPT) {
                    rv = C_Encrypt(session, data, length,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else if (function == WT_P11_ENCRYPT_UPDATE) {
                    rv = C_EncryptUpdate(session, data, length,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else if (function == WT_P11_DECRYPT) {
                    rv = C_Decrypt(session, data, length,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else if (function == WT_P11_DECRYPT_UPDATE) {
                    rv = C_DecryptUpdate(session, data, length,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else if (function == WT_P11_DIGEST) {
                    rv = C_Digest(session, data, length,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else {
                    rv = C_Sign(session, data, length,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
            }
            provider_put_output(&writer, rv,
                has_output != 0U ? g_provider_data : NULL,
                second_length, wire_capacity);
            break;
        case WT_P11_ENCRYPT_FINAL:
        case WT_P11_DECRYPT_FINAL:
        case WT_P11_DIGEST_FINAL:
        case WT_P11_SIGN_FINAL:
            session = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            has_output = wt_pkcs11_get_u32(&reader);
            capacity = provider_ulong(&reader);
            wire_capacity = provider_output_capacity(&writer, capacity,
                                                     WT_P11_OUTPUT_OVERHEAD);
            (void)data;
            if (length != 0U || has_output > 1U ||
                    !provider_request_valid(&reader)) {
                rv = CKR_ARGUMENTS_BAD;
                second_length = 0U;
            }
            else {
                second_length = has_output != 0U ? wire_capacity : 0U;
                if (function == WT_P11_ENCRYPT_FINAL) {
                    rv = C_EncryptFinal(session,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else if (function == WT_P11_DECRYPT_FINAL) {
                    rv = C_DecryptFinal(session,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else if (function == WT_P11_DIGEST_FINAL) {
                    rv = C_DigestFinal(session,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
                else {
                    rv = C_SignFinal(session,
                        has_output != 0U ? g_provider_data : NULL,
                        &second_length);
                }
            }
            provider_put_output(&writer, rv,
                has_output != 0U ? g_provider_data : NULL,
                second_length, wire_capacity);
            break;
        case WT_P11_DIGEST_UPDATE:
        case WT_P11_SIGN_UPDATE:
        case WT_P11_VERIFY_UPDATE:
        case WT_P11_VERIFY_FINAL:
        case WT_P11_SEED_RANDOM:
            session = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            if (!provider_request_valid(&reader)) {
                rv = CKR_ARGUMENTS_BAD;
            }
            else if (function == WT_P11_DIGEST_UPDATE) {
                rv = C_DigestUpdate(session, data, length);
            }
            else if (function == WT_P11_SIGN_UPDATE) {
                rv = C_SignUpdate(session, data, length);
            }
            else if (function == WT_P11_VERIFY_UPDATE) {
                rv = C_VerifyUpdate(session, data, length);
            }
            else if (function == WT_P11_VERIFY_FINAL) {
                rv = C_VerifyFinal(session, data, length);
            }
            else {
                rv = C_SeedRandom(session, data, length);
            }
            break;
        case WT_P11_DIGEST_KEY:
            session = provider_ulong(&reader);
            value = provider_ulong(&reader);
            rv = provider_request_valid(&reader) ?
                C_DigestKey(session, (CK_OBJECT_HANDLE)value) :
                CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_VERIFY:
            session = provider_ulong(&reader);
            data = provider_blob(&reader, &length);
            second_data = provider_blob(&reader, &second_length);
            rv = provider_request_valid(&reader) ?
                C_Verify(session, data, length, second_data, second_length) :
                CKR_ARGUMENTS_BAD;
            break;
        case WT_P11_GENERATE_KEY:
        {
            CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0 &&
                    provider_template(&reader, attributes, &count, 0,
                                      NULL, NULL, &provider_data_used,
                                      &template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_GenerateKey(session, mechanism, template_ptr, count,
                                   &key);
            }
            provider_put_object(&writer, key);
            break;
        }
        case WT_P11_GENERATE_KEY_PAIR:
        {
            CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
            CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0 &&
                    provider_template(&reader, attributes, &count, 0,
                                      NULL, NULL, &provider_data_used,
                                      &template_ptr) == 0 &&
                    provider_template(&reader, private_attributes,
                                      &private_count, 0, NULL, NULL,
                                      &provider_data_used,
                                      &private_template_ptr) == 0 &&
                    provider_request_valid(&reader)) {
                rv = C_GenerateKeyPair(session, mechanism, template_ptr,
                    count, private_template_ptr, private_count, &public_key,
                    &private_key);
            }
            provider_put_object(&writer, public_key);
            provider_put_object(&writer, private_key);
            break;
        }
        case WT_P11_DERIVE_KEY:
        {
            CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
            session = provider_ulong(&reader);
            if (provider_mechanism(&reader, &decoded_mechanism,
                                   &mechanism, &provider_data_used) == 0) {
                value = provider_ulong(&reader);
                if (provider_template(&reader, attributes, &count, 0,
                                      NULL, NULL, &provider_data_used,
                                      &template_ptr) == 0 &&
                        provider_request_valid(&reader)) {
                    rv = C_DeriveKey(session, mechanism,
                                     (CK_OBJECT_HANDLE)value, template_ptr,
                                     count, &key);
                }
            }
            provider_put_object(&writer, key);
            break;
        }
        case WT_P11_GENERATE_RANDOM:
            session = provider_ulong(&reader);
            has_output = wt_pkcs11_get_u32(&reader);
            length = provider_ulong(&reader);
            wire_capacity = provider_output_capacity(&writer, length,
                                                     WT_P11_BLOB_OVERHEAD);
            if (length > wire_capacity || has_output > 1U ||
                    (has_output == 0U && length != 0U) ||
                    !provider_request_valid(&reader)) {
                rv = CKR_ARGUMENTS_BAD;
            }
            else {
                rv = C_GenerateRandom(session,
                    has_output != 0U ? g_provider_data : NULL, length);
            }
            wt_pkcs11_put_bytes(&writer, rv == CKR_OK ? g_provider_data : NULL,
                                rv == CKR_OK ? length : 0U);
            break;
        default:
            rv = CKR_FUNCTION_NOT_SUPPORTED;
            break;
    }

    if (reader.error != 0) {
        rv = CKR_ARGUMENTS_BAD;
    }
    if (writer.error != 0) {
        wt_forceZero(g_provider_data, sizeof(g_provider_data));
        return -1;
    }
    provider_response_rv(response, rv);
    *response_len = writer.used;
    wt_forceZero(g_provider_data, sizeof(g_provider_data));
    return 0;
}
