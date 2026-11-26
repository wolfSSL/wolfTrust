/* spm_host.h
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

/* Host fixture for the SPM core: tables derived from a test manifest, bound
 * service loops run inline, and the synchronous client calls the Non-secure
 * gateway makes on target. */

#ifndef WOLFTRUST_TESTS_SPM_HOST_H
#define WOLFTRUST_TESTS_SPM_HOST_H

#include "wolftrust/spm_gate.h"
#include "spm_tables.h"

/* What the old port layer supplied: caller-memory checks standing in for
 * the gateway's, a service loop for every partition nothing bound, and the
 * panic a misused host psa_* binding raises. */
typedef struct wt_spm_host_ops {
    int (*check_read)(void* context, psa_client_id_t caller,
                      const void* address, size_t size);
    int (*check_write)(void* context, psa_client_id_t caller,
                       void* address, size_t size);
    wt_ffm_dispatch_fn dispatch;
    void (*panic)(void* context, int32_t partition_id);
} wt_spm_host_ops_t;

/* ops may be NULL: every address passes and only bound loops run. */
int wt_spm_host_init(const wt_system_manifest_t* manifest,
                     const wt_spm_host_ops_t* ops, void* context);
int wt_spm_host_bind(int32_t partition_id, wt_ffm_dispatch_fn dispatch,
                     void* context);
wt_ffm_runtime_t* wt_spm_host_runtime(void);
#if defined(WT_SP_RESTART) && (WT_SP_RESTART == 1)
int wt_spm_host_restarted(int32_t partition_id, psa_status_t status);
#endif

psa_handle_t wt_spm_host_connect(psa_client_id_t caller, uint32_t sid,
                                 uint32_t version);
psa_status_t wt_spm_host_call(psa_client_id_t caller, psa_handle_t handle,
                              int32_t type, const psa_invec* in_vec,
                              size_t in_len, psa_outvec* out_vec,
                              size_t out_len);
int wt_spm_host_close(psa_client_id_t caller, psa_handle_t handle);

/* The core's service side addressed by partition id; an unknown id fails. */
int wt_spm_host_wait(int32_t pid, psa_signal_t mask, psa_signal_t* asserted);
psa_status_t wt_spm_host_get(int32_t pid, psa_signal_t signal,
                             psa_msg_t* msg);
int wt_spm_host_reply(int32_t pid, psa_handle_t msg, psa_status_t status);
size_t wt_spm_host_read(int32_t pid, psa_handle_t msg, uint32_t idx,
                        void* buffer, size_t len);
size_t wt_spm_host_skip(int32_t pid, psa_handle_t msg, uint32_t idx,
                        size_t len);
int wt_spm_host_write(int32_t pid, psa_handle_t msg, uint32_t idx,
                      const void* buffer, size_t len);
int wt_spm_host_set_rhandle(int32_t pid, psa_handle_t msg, void* rhandle);
int wt_spm_host_clear(int32_t pid);
int wt_spm_host_eoi(int32_t pid, psa_signal_t irq_signal);
void wt_spm_host_panic(int32_t pid);

#endif /* WOLFTRUST_TESTS_SPM_HOST_H */
