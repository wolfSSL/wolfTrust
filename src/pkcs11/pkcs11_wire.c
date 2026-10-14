/* pkcs11_wire.c
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

#include "wolftrust/pkcs11/pkcs11_wire.h"

#include <string.h>

void wt_pkcs11_writer_init(wt_pkcs11_writer_t* writer, uint8_t* buffer,
                           size_t capacity)
{
    writer->buffer = buffer;
    writer->capacity = capacity;
    writer->used = 0U;
    writer->error = (buffer == NULL || capacity == 0U);
}

void wt_pkcs11_put_u32(wt_pkcs11_writer_t* writer, uint32_t value)
{
    uint8_t encoded[4];

    encoded[0] = (uint8_t)value;
    encoded[1] = (uint8_t)(value >> 8);
    encoded[2] = (uint8_t)(value >> 16);
    encoded[3] = (uint8_t)(value >> 24);
    if (writer->error != 0 || writer->used > writer->capacity ||
            sizeof(encoded) > writer->capacity - writer->used) {
        writer->error = 1;
        return;
    }
    (void)memcpy(writer->buffer + writer->used, encoded, sizeof(encoded));
    writer->used += sizeof(encoded);
}

void wt_pkcs11_put_bytes(wt_pkcs11_writer_t* writer, const void* data,
                         size_t length)
{
    if (length > UINT32_MAX || (data == NULL && length != 0U)) {
        writer->error = 1;
        return;
    }
    wt_pkcs11_put_u32(writer, (uint32_t)length);
    if (writer->error != 0 || writer->used > writer->capacity ||
            length > writer->capacity - writer->used) {
        writer->error = 1;
        return;
    }
    if (length != 0U) {
        (void)memcpy(writer->buffer + writer->used, data, length);
        writer->used += length;
    }
}

void wt_pkcs11_reader_init(wt_pkcs11_reader_t* reader, uint8_t* buffer,
                           size_t length)
{
    reader->buffer = buffer;
    reader->length = length;
    reader->used = 0U;
    reader->error = (buffer == NULL || length == 0U);
}

uint32_t wt_pkcs11_get_u32(wt_pkcs11_reader_t* reader)
{
    const uint8_t* value;

    if (reader->error != 0 || reader->used > reader->length ||
            4U > reader->length - reader->used) {
        reader->error = 1;
        return 0U;
    }
    value = reader->buffer + reader->used;
    reader->used += 4U;
    return (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
           ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
}

uint8_t* wt_pkcs11_get_bytes(wt_pkcs11_reader_t* reader, size_t* length)
{
    uint32_t encoded_length;
    uint8_t* data;

    encoded_length = wt_pkcs11_get_u32(reader);
    if (reader->error != 0 || reader->used > reader->length ||
            encoded_length > reader->length - reader->used) {
        reader->error = 1;
        *length = 0U;
        return NULL;
    }
    data = reader->buffer + reader->used;
    reader->used += encoded_length;
    *length = encoded_length;
    return data;
}
