/* pkcs11_provider.h
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

#ifndef WOLFTRUST_PKCS11_PROVIDER_H
#define WOLFTRUST_PKCS11_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

int wt_pkcs11_provider_dispatch(uint8_t* request, size_t request_len,
                                uint8_t* response, size_t response_cap,
                                size_t* response_len, void* context);

#endif /* WOLFTRUST_PKCS11_PROVIDER_H */
