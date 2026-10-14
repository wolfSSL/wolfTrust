/* pkcs11_wire.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef WOLFTRUST_PKCS11_PKCS11_WIRE_H
#define WOLFTRUST_PKCS11_PKCS11_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define WT_PKCS11_WIRE_MAGIC   0x57503131U
#define WT_PKCS11_WIRE_VERSION 1U
#define WT_PKCS11_WIRE_UNAVAILABLE UINT32_MAX

#define WT_P11_MECH_RAW  0U
#define WT_P11_MECH_CTR  1U
#define WT_P11_MECH_GCM  2U
#define WT_P11_MECH_CCM  3U
#define WT_P11_MECH_ECDH 4U

enum wt_pkcs11_function {
    WT_P11_INITIALIZE = 1,
    WT_P11_FINALIZE,
    WT_P11_GET_INFO,
    WT_P11_GET_SLOT_LIST,
    WT_P11_GET_SLOT_INFO,
    WT_P11_GET_TOKEN_INFO,
    WT_P11_GET_MECHANISM_LIST,
    WT_P11_GET_MECHANISM_INFO,
    WT_P11_INIT_TOKEN,
    WT_P11_INIT_PIN,
    WT_P11_SET_PIN,
    WT_P11_OPEN_SESSION,
    WT_P11_CLOSE_SESSION,
    WT_P11_CLOSE_ALL_SESSIONS,
    WT_P11_GET_SESSION_INFO,
    WT_P11_GET_OPERATION_STATE,
    WT_P11_SET_OPERATION_STATE,
    WT_P11_LOGIN,
    WT_P11_LOGOUT,
    WT_P11_CREATE_OBJECT,
    WT_P11_COPY_OBJECT,
    WT_P11_DESTROY_OBJECT,
    WT_P11_GET_OBJECT_SIZE,
    WT_P11_GET_ATTRIBUTE_VALUE,
    WT_P11_SET_ATTRIBUTE_VALUE,
    WT_P11_FIND_OBJECTS_INIT,
    WT_P11_FIND_OBJECTS,
    WT_P11_FIND_OBJECTS_FINAL,
    WT_P11_ENCRYPT_INIT,
    WT_P11_ENCRYPT,
    WT_P11_ENCRYPT_UPDATE,
    WT_P11_ENCRYPT_FINAL,
    WT_P11_DECRYPT_INIT,
    WT_P11_DECRYPT,
    WT_P11_DECRYPT_UPDATE,
    WT_P11_DECRYPT_FINAL,
    WT_P11_DIGEST_INIT,
    WT_P11_DIGEST,
    WT_P11_DIGEST_UPDATE,
    WT_P11_DIGEST_KEY,
    WT_P11_DIGEST_FINAL,
    WT_P11_SIGN_INIT,
    WT_P11_SIGN,
    WT_P11_SIGN_UPDATE,
    WT_P11_SIGN_FINAL,
    WT_P11_SIGN_RECOVER_INIT,
    WT_P11_SIGN_RECOVER,
    WT_P11_VERIFY_INIT,
    WT_P11_VERIFY,
    WT_P11_VERIFY_UPDATE,
    WT_P11_VERIFY_FINAL,
    WT_P11_VERIFY_RECOVER_INIT,
    WT_P11_VERIFY_RECOVER,
    WT_P11_DIGEST_ENCRYPT_UPDATE,
    WT_P11_DECRYPT_DIGEST_UPDATE,
    WT_P11_SIGN_ENCRYPT_UPDATE,
    WT_P11_DECRYPT_VERIFY_UPDATE,
    WT_P11_GENERATE_KEY,
    WT_P11_GENERATE_KEY_PAIR,
    WT_P11_WRAP_KEY,
    WT_P11_UNWRAP_KEY,
    WT_P11_DERIVE_KEY,
    WT_P11_SEED_RANDOM,
    WT_P11_GENERATE_RANDOM,
    WT_P11_GET_FUNCTION_STATUS,
    WT_P11_CANCEL_FUNCTION,
    WT_P11_WAIT_FOR_SLOT_EVENT
};

typedef struct wt_pkcs11_writer {
    uint8_t* buffer;
    size_t capacity;
    size_t used;
    int error;
} wt_pkcs11_writer_t;

typedef struct wt_pkcs11_reader {
    uint8_t* buffer;
    size_t length;
    size_t used;
    int error;
} wt_pkcs11_reader_t;

void wt_pkcs11_writer_init(wt_pkcs11_writer_t* writer, uint8_t* buffer,
                           size_t capacity);
void wt_pkcs11_put_u32(wt_pkcs11_writer_t* writer, uint32_t value);
void wt_pkcs11_put_bytes(wt_pkcs11_writer_t* writer, const void* data,
                         size_t length);

void wt_pkcs11_reader_init(wt_pkcs11_reader_t* reader, uint8_t* buffer,
                           size_t length);
uint32_t wt_pkcs11_get_u32(wt_pkcs11_reader_t* reader);
uint8_t* wt_pkcs11_get_bytes(wt_pkcs11_reader_t* reader, size_t* length);

#endif /* WOLFTRUST_PKCS11_PKCS11_WIRE_H */
