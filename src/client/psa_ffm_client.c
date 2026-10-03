/* psa_ffm_client.c
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

/* Operating-system-neutral PSA Firmware Framework client core (P7-S1). It
 * implements the PSA client API (psa/client.h) over wolfTrust's Non-secure to
 * Secure CMSE veneers (WolfTrust_FFM_*), with no operating-system dependency,
 * so Zephyr, FreeRTOS, and any bare Non-secure client link exactly the same
 * client. Per-OS code is limited to init/bring-up elsewhere. The veneers
 * themselves are the port's Armv8-M code; a host test supplies stubs that route
 * to the in-process FF-M runtime to prove the marshaling. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "psa/client.h"
#include "wolftrust/ffm_veneer.h"

extern int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version);
extern int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                                  wt_ffm_veneer_iovec_t* ns_iovec);
extern void WolfTrust_FFM_Close(int32_t handle);
extern uint32_t WolfTrust_FFM_FrameworkVersion(void);
extern uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid);

uint32_t psa_framework_version(void)
{
    return WolfTrust_FFM_FrameworkVersion();
}

uint32_t psa_version(uint32_t sid)
{
    return WolfTrust_FFM_ServiceVersion(sid);
}

psa_handle_t psa_connect(uint32_t sid, uint32_t version)
{
    return (psa_handle_t)WolfTrust_FFM_Connect(sid, version);
}

void psa_close(psa_handle_t handle)
{
    WolfTrust_FFM_Close((int32_t)handle);
}

/* The veneer carries 32-bit counts and lengths: an LP64 value above them
 * saturates, so an over-count or an oversized vector stays invalid at the
 * Secure gateway instead of wrapping into an accepted one. */
static uint32_t veneer_size(size_t value)
{
#if SIZE_MAX > UINT32_MAX
    if (value > (size_t)UINT32_MAX) {
        return UINT32_MAX;
    }
#endif
    return (uint32_t)value;
}

psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len)
{
    wt_ffm_veneer_iovec_t iovec;
    psa_status_t status;
    size_t i;

    /* An over-count is forwarded as its raw count so the Secure gateway sees
     * the PROGRAMMER ERROR and drops the connection; a client-local return
     * would leave it usable. The vectors are marshalled only when the count is
     * within the ABI maximum, so a lying count never walks the caller's array
     * past PSA_MAX_IOVEC. */
    memset(&iovec, 0, sizeof(iovec));
    if (in_len <= WT_FFM_VENEER_IOVEC_MAX) {
        for (i = 0u; i < in_len; i++) {
            iovec.in[i].base = in_vec[i].base;
            iovec.in[i].len = veneer_size(in_vec[i].len);
        }
    }
    if (out_len <= WT_FFM_VENEER_IOVEC_MAX) {
        for (i = 0u; i < out_len; i++) {
            iovec.out[i].base = out_vec[i].base;
            iovec.out[i].len = veneer_size(out_vec[i].len);
        }
    }
    iovec.in_count = veneer_size(in_len);
    iovec.out_count = veneer_size(out_len);
    status = (psa_status_t)WolfTrust_FFM_Call((int32_t)handle, type, &iovec);
    if (out_len <= WT_FFM_VENEER_IOVEC_MAX) {
        for (i = 0u; i < out_len; i++) {
            out_vec[i].len = iovec.out[i].len;
        }
    }
    return status;
}
