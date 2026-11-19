/* ffm_nsc.c
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


/* Armv8-M NS entry mechanism for the FF-M gateway: the cmse_nonsecure_entry
 * veneers the NS guests link (the Zephyr wolftrust-tee driver's
 * tee_invoke_func dispatches into them) and the CMSE NS-range checks behind
 * the architecture contract. */

#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#include "wolftrust/arch/armv8m/cmse.h"
#include "wolftrust/ffm_gateway.h"
#include "wolftrust/types.h"

int wt_arch_ns_check_read(wt_guest_id_t guest_id,
                          const void* address, size_t size)
{
    return wt_cmse_check_ns_ro(address, size) &&
           wt_cmse_check_in_guest_ns_addr(guest_id, address, size);
}

int wt_arch_ns_check_write(wt_guest_id_t guest_id, void* address, size_t size)
{
    return wt_cmse_check_ns_rw(address, size) &&
           wt_cmse_check_in_guest_ns_ram(guest_id, address, size);
}

int wt_arch_ns_check_writable(const void* address, size_t size)
{
    return wt_cmse_check_ns_rw(address, size);
}

/* No Non-secure handler may preempt an entry and re-enter the FF-M core;
 * the Secure timer band, Secure IRQs and faults stay above the mask. */
static uint32_t wt_ns_entry_mask(void)
{
    uint32_t prev;

    __asm volatile("mrs %0, basepri" : "=r"(prev));
    __asm volatile("msr basepri_max, %0 \n"
                   "isb 0xF               \n"
                   : : "r"(WT_ARMV8M_NS_PRIO_FLOOR) : "memory");
    return prev;
}

static void wt_ns_entry_unmask(uint32_t prev)
{
    __asm volatile("msr basepri, %0" : : "r"(prev) : "memory");
}

__attribute__((cmse_nonsecure_entry))
int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version)
{
    uint32_t prev = wt_ns_entry_mask();
    int32_t ret = wt_ffm_gateway_connect(sid, version);

    wt_ns_entry_unmask(prev);
    return ret;
}

__attribute__((cmse_nonsecure_entry))
int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                          wt_ffm_veneer_iovec_t* ns_iovec)
{
    uint32_t prev = wt_ns_entry_mask();
    int32_t ret = wt_ffm_gateway_call(handle, type, ns_iovec);

    wt_ns_entry_unmask(prev);
    return ret;
}

__attribute__((cmse_nonsecure_entry))
void WolfTrust_FFM_Close(int32_t handle)
{
    uint32_t prev = wt_ns_entry_mask();

    wt_ffm_gateway_close(handle);
    wt_ns_entry_unmask(prev);
}

__attribute__((cmse_nonsecure_entry))
uint32_t WolfTrust_FFM_FrameworkVersion(void)
{
    return wt_ffm_gateway_framework_version();
}

__attribute__((cmse_nonsecure_entry))
uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid)
{
    return wt_ffm_gateway_service_version(sid);
}
