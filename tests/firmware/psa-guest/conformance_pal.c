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

/* Non-secure PAL + PSA client shim for the Arm psa-arch-tests val NSPE (P3a-4a).
 * The val framework prints through a single char sink (pal_print) and reaches
 * the SPM through the PSA client API, which aliases wolfTrust's CMSE veneers.
 * pal_print_ns is unused (VERBOSITY path funnels to val_printf -> pal_print);
 * the crypto/storage/attestation PALs are unused by the IPC suite and refuse. */

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include "board.h"

/* This TU implements the real PSA client API; without IPC defined the
 * dev_apis builds get pal_common.h's fallback psa_invec/psa_outvec typedefs,
 * which collide with psa/client.h. */
#ifndef IPC
#define IPC 1
#endif

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "pal_common.h"
#include "wolftrust/ffm_veneer.h"

#include "psa/storage_common.h"
#include "psa/internal_trusted_storage.h"
#include "psa/protected_storage.h"

#if defined(INITIAL_ATTESTATION)
#include <wolftrust/attestation.h>
#endif

extern int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version);
extern int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                                  wt_ffm_veneer_iovec_t* ns_iovec);
extern void WolfTrust_FFM_Close(int32_t handle);

#if defined(WT_CONF_TRACE)
#define WT_CONF_TRACE_PRINT(...)
#else
#define WT_CONF_TRACE_PRINT(...)
#endif

/* psa_connect/psa_call/psa_close now come from the OS-neutral client core
 * (src/client/psa_ffm_client.c) that this build links (P7-S2); the val NSPE
 * reaches the SPM through the same neutral client the production guest uses. */

/* The val shared status region (PLATFORM_SHARED_REGION_BASE aliases this). The
 * NS framework records per-test status here; a plain BSS buffer suffices. */
uint8_t test_status_buffer[256] = {0};

static void guest_conf_line(const char* text)
{
    const char* p = GUEST_NAME ": ";

    while (*p != '\0') {
        guest_board_uart_putc(*p);
        p++;
    }
    while (*text != '\0') {
        guest_board_uart_putc(*text);
        text++;
    }
    guest_board_uart_putc('\r');
    guest_board_uart_putc('\n');
}

/* val's log sink: one character at a time to the guest console. */
int pal_print(uint8_t c)
{
    guest_board_uart_putc((char)c);
    return 0;
}

/* val records its per-test boot/status state in NVMEM. P3b routes both NS and
 * SPE val through the DRIVER partition's NVMEM service so the two frameworks
 * share one store (nvmem_param_t invec + data vec, the suite's own driver
 * protocol). The backing store is the SPE PAL's RAM block until the P5
 * reboot-continuity work makes it reset-surviving. */
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
    guest_conf_line("wolfTrust FF-M conformance: val_entry returned");
}

/* dev_apis Crypto builds compile the upstream pal_crypto_intf.c instead. */
#if !defined(CRYPTO)
int32_t pal_crypto_function(int type, va_list valist)
{
    (void)type;
    (void)valist;
    return -1;
}
#endif

/* dev_apis Storage (P4-S6): dispatch the val ITS/PS function codes to the
 * OS-neutral PSA storage client (src/client/psa_storage_client.c), which
 * marshals each onto SERVICE_ITS / SERVICE_PS over FF-M IPC. The code values
 * are val_storage.h's
 * storage_function_type_t: ITS SET/GET/GET_INFO/REMOVE = 0x1..0x4,
 * PS SET/GET/GET_INFO/REMOVE/CREATE/SET_EXTENDED/GET_SUPPORT = 0x5..0xB. */
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
    case 0x1: /* VAL_ITS_SET */
        uid = va_arg(valist, psa_storage_uid_t);
        data_size = va_arg(valist, uint32_t);
        p_write_data = va_arg(valist, const void*);
        create_flags = va_arg(valist, psa_storage_create_flags_t);
        return (uint32_t)psa_its_set(uid, data_size, p_write_data,
                                     create_flags);
    case 0x2: /* VAL_ITS_GET */
        uid = va_arg(valist, psa_storage_uid_t);
        offset = va_arg(valist, uint32_t);
        data_size = va_arg(valist, uint32_t);
        p_read_data = va_arg(valist, void*);
        p_data_length = va_arg(valist, size_t*);
        return (uint32_t)psa_its_get(uid, offset, data_size, p_read_data,
                                     p_data_length);
    case 0x3: /* VAL_ITS_GET_INFO */
        uid = va_arg(valist, psa_storage_uid_t);
        p_info = va_arg(valist, struct psa_storage_info_t*);
        return (uint32_t)psa_its_get_info(uid, p_info);
    case 0x4: /* VAL_ITS_REMOVE */
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
    case 0x5: /* VAL_PS_SET */
        uid = va_arg(valist, psa_storage_uid_t);
        data_size = va_arg(valist, uint32_t);
        p_write_data = va_arg(valist, const void*);
        create_flags = va_arg(valist, psa_storage_create_flags_t);
        return (uint32_t)psa_ps_set(uid, data_size, p_write_data,
                                    create_flags);
    case 0x6: /* VAL_PS_GET */
        uid = va_arg(valist, psa_storage_uid_t);
        offset = va_arg(valist, uint32_t);
        data_size = va_arg(valist, uint32_t);
        p_read_data = va_arg(valist, void*);
        p_data_length = va_arg(valist, size_t*);
        return (uint32_t)psa_ps_get(uid, offset, data_size, p_read_data,
                                    p_data_length);
    case 0x7: /* VAL_PS_GET_INFO */
        uid = va_arg(valist, psa_storage_uid_t);
        p_info = va_arg(valist, struct psa_storage_info_t*);
        return (uint32_t)psa_ps_get_info(uid, p_info);
    case 0x8: /* VAL_PS_REMOVE */
        uid = va_arg(valist, psa_storage_uid_t);
        return (uint32_t)psa_ps_remove(uid);
    case 0x9: /* VAL_PS_CREATE */
        uid = va_arg(valist, psa_storage_uid_t);
        size = va_arg(valist, uint32_t);
        create_flags = va_arg(valist, psa_storage_create_flags_t);
        return (uint32_t)psa_ps_create(uid, size, create_flags);
    case 0xA: /* VAL_PS_SET_EXTENDED */
        uid = va_arg(valist, psa_storage_uid_t);
        offset = va_arg(valist, uint32_t);
        data_size = va_arg(valist, uint32_t);
        p_write_data = va_arg(valist, const void*);
        return (uint32_t)psa_ps_set_extended(uid, offset, data_size,
                                             p_write_data);
    case 0xB: /* VAL_PS_GET_SUPPORT */
        return psa_ps_get_support();
    default:
        return PAL_STATUS_UNSUPPORTED_FUNC;
    }
}

/* dev_apis Initial Attestation builds compile the upstream
 * pal_attestation_intf.c/pal_attestation_crypto.c instead; the val-side
 * verify needs the device's real IAK public key, which is generated inside
 * the wolfHSM vault at provisioning and only reachable at runtime. */
#if defined(INITIAL_ATTESTATION)
int32_t tfm_initial_attest_get_public_key(uint8_t* public_key_buff,
    size_t public_key_buf_size, size_t* public_key_len,
    psa_ecc_family_t* elliptic_family_type)
{
    psa_status_t status;

    if ((public_key_buff == NULL) || (public_key_len == NULL) ||
            (elliptic_family_type == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = wolftrust_attestation_get_iak_public_key(public_key_buff,
                                                      public_key_buf_size,
                                                      public_key_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    *elliptic_family_type = PSA_ECC_FAMILY_SECP_R1;
    return PSA_SUCCESS;
}
#else
int32_t pal_attestation_function(int type, va_list valist)
{
    (void)type;
    (void)valist;
    return -1;
}
#endif
