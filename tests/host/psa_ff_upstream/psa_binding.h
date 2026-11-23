/* psa_binding.h
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

/* The psa_* client and service calls for host code, on the SPM core and its
 * fixture: the caller and the running partition come from identity ops. */

#ifndef WOLFTRUST_TESTS_PSA_BINDING_H
#define WOLFTRUST_TESTS_PSA_BINDING_H

#include "spm_host.h"

typedef struct wt_psa_host_identity {
    psa_client_id_t (*current_client)(void* context);
    int32_t (*current_partition)(void* context);
} wt_psa_host_identity_t;

int wt_psa_host_bind(const wt_psa_host_identity_t* identity, void* context);
void wt_psa_host_unbind(void);

#endif /* WOLFTRUST_TESTS_PSA_BINDING_H */
