/* crypto_profile.h
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

#ifndef WOLFTRUST_CRYPTO_PROFILE_H
#define WOLFTRUST_CRYPTO_PROFILE_H

#include <stddef.h>
#include <stdint.h>
#include "wolfpkcs11/pkcs11.h"
#include "wolftrust/pkcs11/pkcs11_wire.h"

#ifdef WT_PKCS11_PROFILE_HEADER
#include WT_PKCS11_PROFILE_HEADER
#else
#define WT_P11_EXPORT(name) proxy_ ## name
static inline int wt_profile_pkcs11_operation(uint32_t operation)
{
    (void)operation;
    return 1;
}
static inline int wt_profile_pkcs11_mechanism(CK_MECHANISM_TYPE mechanism)
{
    (void)mechanism;
    return 1;
}
static inline CK_FLAGS wt_profile_pkcs11_flags(CK_FLAGS flags)
{
    return flags;
}
#endif
#endif /* WOLFTRUST_CRYPTO_PROFILE_H */
