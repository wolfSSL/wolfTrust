/* protected_storage.h
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

/* PSA Protected Storage API (SRC-PSA-STORAGE). Served by SERVICE_PS: every
 * object is AES-256 AEAD sealed under a device-unique wolfHSM key with default-on
 * rollback protection (WT-FFM-0048) — confidentiality and replay protection
 * are not optional features in wolfTrust. Definitions arrive with the NSPE
 * client shim (P4-S6); Secure-side dispatch is storage_service.c. */

#ifndef PSA_PROTECTED_STORAGE_H
#define PSA_PROTECTED_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_PS_API_VERSION_MAJOR 1
#define PSA_PS_API_VERSION_MINOR 0

psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length,
                        const void* p_data,
                        psa_storage_create_flags_t create_flags);

psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset,
                        size_t data_size, void* p_data,
                        size_t* p_data_length);

psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
                             struct psa_storage_info_t* p_info);

psa_status_t psa_ps_remove(psa_storage_uid_t uid);

psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity,
                           psa_storage_create_flags_t create_flags);

psa_status_t psa_ps_set_extended(psa_storage_uid_t uid, size_t data_offset,
                                 size_t data_length, const void* p_data);

uint32_t psa_ps_get_support(void);

#ifdef __cplusplus
}
#endif

#endif /* PSA_PROTECTED_STORAGE_H */
