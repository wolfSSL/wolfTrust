/* conformance_pal.c
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

/* Bare-metal Non-secure PAL for the Arm psa-arch-tests val NSPE, the AArch64
 * twin of the Zephyr guest's conformance_pal.c: val prints through one char
 * sink, keeps its boot flag in the DRIVER partition's NVMEM service (shared
 * with the SPE val, backed by the Secure reset-surviving store) and reaches the
 * SPM through the same OS-neutral PSA client the production guest links. */

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

/* This TU implements the real PSA client API; without IPC the dev_apis builds
 * get pal_common.h's fallback psa_invec/psa_outvec typedefs, which collide
 * with psa/client.h. */
#ifndef IPC
#define IPC 1
#endif

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "pal_common.h"
#include "pal_interfaces_ns.h"

#include "psa/storage_common.h"
#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"

extern void ns_putc(char c);

uint8_t test_status_buffer[256] = {0};

int pal_print(uint8_t c)
{
    ns_putc((char)c);
    return 0;
}

int pal_print_ns(const char* str, int32_t data)
{
    (void)data;
    while ((str != NULL) && (*str != '\0')) {
        ns_putc(*str);
        str++;
    }
    return 0;
}

unsigned int pal_platform_init(void)
{
    return 0u;
}

bool_t pal_is_test_enabled(test_id_t test_id)
{
    (void)test_id;
    return 1;
}

void pal_set_custom_test_list(char* custom_test_list)
{
    (void)custom_test_list;
}

static psa_status_t wt_conf_nvm_call(uint32_t fn_type, uint32_t offset,
                                     void* buffer, size_t size)
{
    nvmem_param_t param;
    psa_invec invec[2];
    psa_outvec outvec[1];
    psa_handle_t handle;
    psa_status_t status;

    param.nvmem_fn_type = (nvmem_fn_type_t)fn_type;
    param.base = (addr_t)PLATFORM_NVM_BASE;
    param.offset = offset;
    param.size = (int)size;
    handle = psa_connect(DRIVER_NVMEM_SID, DRIVER_NVMEM_VERSION);
    if (handle <= 0) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }
    invec[0].base = &param;
    invec[0].len = sizeof(param);
    if (fn_type == (uint32_t)NVMEM_WRITE) {
        invec[1].base = buffer;
        invec[1].len = size;
        status = psa_call(handle, 0, invec, 2u, NULL, 0u);
    }
    else {
        outvec[0].base = buffer;
        outvec[0].len = size;
        status = psa_call(handle, 0, invec, 1u, outvec, 1u);
    }
    psa_close(handle);
    return status;
}

int pal_nvm_read(uint32_t offset, void* buffer, size_t size)
{
    if (buffer == NULL) {
        return 1;
    }
    if (wt_conf_nvm_call((uint32_t)NVMEM_READ, offset, buffer, size) !=
            PSA_SUCCESS) {
        return 1;
    }
    return 0;
}

int pal_nvm_write(uint32_t offset, void* buffer, size_t size)
{
    if (buffer == NULL) {
        return 1;
    }
    if (wt_conf_nvm_call((uint32_t)NVMEM_WRITE, offset, buffer, size) !=
            PSA_SUCCESS) {
        return 1;
    }
    return 0;
}

int pal_watchdog_enable(void)
{
    return 0;
}

int pal_watchdog_disable(void)
{
    return 0;
}

int pal_uart_init_ns(void)
{
    return 0;
}

int pal_wd_timer_init_ns(uint32_t time_us, uint32_t timer_tick_us)
{
    (void)time_us;
    (void)timer_tick_us;
    return 0;
}

int pal_wd_timer_enable_ns(void)
{
    return 0;
}

int pal_wd_timer_disable_ns(void)
{
    return 0;
}

int pal_system_reset(void)
{
    return 0;
}

void pal_terminate_simulation(void)
{
    pal_print_ns("wolfTrust FF-M conformance: val_entry returned\n", 0);
}

int32_t pal_crypto_function(int type, va_list valist)
{
    (void)type;
    (void)valist;
    return -1;
}

/* dev_apis storage: dispatch val's ITS/PS function codes (val_storage.h's
 * storage_function_type_t: ITS SET/GET/GET_INFO/REMOVE = 0x1..0x4, PS
 * SET/GET/GET_INFO/REMOVE/CREATE/SET_EXTENDED/GET_SUPPORT = 0x5..0xB) onto
 * the OS-neutral PSA storage client, which marshals each onto SERVICE_ITS /
 * SERVICE_PS over the routed gateway. */
uint32_t pal_its_function(int type, va_list valist)
{
    psa_storage_uid_t uid;
    uint32_t data_size;
    uint32_t offset;
    const void* p_write_data;
    void* p_read_data;
    size_t* p_data_length;
    psa_storage_create_flags_t create_flags;
    struct psa_storage_info_t* p_info;

    switch (type) {
    case 0x1:
        uid = va_arg(valist, psa_storage_uid_t);
        data_size = va_arg(valist, uint32_t);
        p_write_data = va_arg(valist, const void*);
        create_flags = va_arg(valist, psa_storage_create_flags_t);
        return (uint32_t)psa_its_set(uid, data_size, p_write_data,
                                     create_flags);
    case 0x2:
        uid = va_arg(valist, psa_storage_uid_t);
        offset = va_arg(valist, uint32_t);
        data_size = va_arg(valist, uint32_t);
        p_read_data = va_arg(valist, void*);
        p_data_length = va_arg(valist, size_t*);
        return (uint32_t)psa_its_get(uid, offset, data_size, p_read_data,
                                     p_data_length);
    case 0x3:
        uid = va_arg(valist, psa_storage_uid_t);
        p_info = va_arg(valist, struct psa_storage_info_t*);
        return (uint32_t)psa_its_get_info(uid, p_info);
    case 0x4:
        uid = va_arg(valist, psa_storage_uid_t);
        return (uint32_t)psa_its_remove(uid);
    default:
        return PAL_STATUS_UNSUPPORTED_FUNC;
    }
}

uint32_t pal_ps_function(int type, va_list valist)
{
    psa_storage_uid_t uid;
    uint32_t data_size;
    uint32_t size;
    uint32_t offset;
    const void* p_write_data;
    void* p_read_data;
    size_t* p_data_length;
    psa_storage_create_flags_t create_flags;
    struct psa_storage_info_t* p_info;

    switch (type) {
    case 0x5:
        uid = va_arg(valist, psa_storage_uid_t);
        data_size = va_arg(valist, uint32_t);
        p_write_data = va_arg(valist, const void*);
        create_flags = va_arg(valist, psa_storage_create_flags_t);
        return (uint32_t)psa_ps_set(uid, data_size, p_write_data,
                                    create_flags);
    case 0x6:
        uid = va_arg(valist, psa_storage_uid_t);
        offset = va_arg(valist, uint32_t);
        data_size = va_arg(valist, uint32_t);
        p_read_data = va_arg(valist, void*);
        p_data_length = va_arg(valist, size_t*);
        return (uint32_t)psa_ps_get(uid, offset, data_size, p_read_data,
                                    p_data_length);
    case 0x7:
        uid = va_arg(valist, psa_storage_uid_t);
        p_info = va_arg(valist, struct psa_storage_info_t*);
        return (uint32_t)psa_ps_get_info(uid, p_info);
    case 0x8:
        uid = va_arg(valist, psa_storage_uid_t);
        return (uint32_t)psa_ps_remove(uid);
    case 0x9:
        uid = va_arg(valist, psa_storage_uid_t);
        size = va_arg(valist, uint32_t);
        create_flags = va_arg(valist, psa_storage_create_flags_t);
        return (uint32_t)psa_ps_create(uid, size, create_flags);
    case 0xA:
        uid = va_arg(valist, psa_storage_uid_t);
        offset = va_arg(valist, uint32_t);
        data_size = va_arg(valist, uint32_t);
        p_write_data = va_arg(valist, const void*);
        return (uint32_t)psa_ps_set_extended(uid, offset, data_size,
                                             p_write_data);
    case 0xB:
        return psa_ps_get_support();
    default:
        return PAL_STATUS_UNSUPPORTED_FUNC;
    }
}

int32_t pal_attestation_function(int type, va_list valist)
{
    (void)type;
    (void)valist;
    return -1;
}
