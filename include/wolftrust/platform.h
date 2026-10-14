/* platform.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFTRUST_PLATFORM_H
#define WOLFTRUST_PLATFORM_H

/* SoC contract, implemented under port/<soc>/; see wolftrust/arch.h. */

/* Opaque: the architecture defines the concrete structs. */
struct wt_guest_context;
typedef struct wt_guest_context wt_guest_context_t;
struct wt_trap_frame;
typedef struct wt_trap_frame wt_trap_frame_t;
#include "wolftrust/types.h"

void wt_platform_init(void);
#if defined(WT_BUSFAULT_NEG_PROBE) && (WT_BUSFAULT_NEG_PROBE == 1)
/* busfaultneg: a readable region whose bus returns an error on this SoC. */
void wt_platform_busfault_probe_region(wt_memory_region_t* region);
#endif
/* Only asked of ports providing WT_PORT_CAPABILITY_TZ_FILTER. */
void wt_platform_program_memory_windows(const wt_memory_window_t* windows,
                                        size_t count);
void wt_platform_log_fault(wt_guest_id_t guest_id,
                           wt_fault_reason_t reason,
                           uintptr_t fault_address,
                           uintptr_t pc);
/* NULL with *count zero when no patched slot exists (fail-closed). */
struct wt_guest_measurement;
const struct wt_guest_measurement* wt_platform_guest_measurements(
    size_t* count);
int wt_platform_guest_flash_wrp_ok(uintptr_t window_base, size_t window_size);
void wt_platform_all_guests_faulted(void) __attribute__((noreturn));
void wt_platform_panic(void) __attribute__((noreturn));
void wt_platform_system_reset(void) __attribute__((noreturn));

#ifdef WT_ENGINE_HSM
bool wt_platform_secure_service_active(void);
void wt_platform_note_hsm_wait_skip(wt_guest_id_t guest_id);
#endif

/* NULL when the port has no boot-loader handoff region. */
volatile void* wt_platform_boot_handoff_region(size_t* size);

/* Returns the number of regions written (<= max). */
size_t wt_platform_sp_shared_regions(wt_memory_region_t* regions, size_t max);

/* Nonzero when [stack, stack+size) may back a PRIVILEGED coroutine: it must
 * not intersect any partition-writable band, or a partition could own a
 * privileged frame (WT-FFM-0011). The scheduler refuses creation otherwise. */
int wt_platform_priv_stack_ok(const void *stack, size_t size);

/* Peripherals a Secure Partition may own through a DEVICE resource
 * (WT-FFM-0068). NULL with *count 0 refuses every partition DEVICE region. */
struct wt_periph;
const struct wt_periph* wt_platform_sp_peripherals(size_t* count);

/* The RAM only the SPM may reach: no composed partition table may grant
 * any access to it. Returns the number of regions written. */
size_t wt_platform_spm_private_regions(wt_memory_region_t* regions,
                                       size_t max);
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
/* Grants for the hosted Arm test partitions only; every other partition's
 * table is returned unchanged. */
size_t wt_platform_conf_sp_grants(int32_t partition_id,
                                  wt_memory_region_t* regions,
                                  size_t count, size_t max);
/* The window the hosted Arm test partitions share by the suite's design. */
size_t wt_platform_conf_shared_regions(wt_memory_region_t* regions,
                                       size_t max);
#endif
#if (defined(WT_FFM_NEGATIVE_PROBE) && (WT_FFM_NEGATIVE_PROBE == 1)) || \
    (defined(WT_VNET_NEG_PROBE) && (WT_VNET_NEG_PROBE == 1)) || \
    (defined(WT_KEYSTORE_NEG_PROBE) && (WT_KEYSTORE_NEG_PROBE == 1)) || \
    (defined(WT_PERIPH_SP_NEG_PROBE) && (WT_PERIPH_SP_NEG_PROBE == 1)) || \
    (defined(WT_BAND_NEG_PROBE) && (WT_BAND_NEG_PROBE != 0)) || \
    (defined(WT_TPM_NEG_PROBE) && (WT_TPM_NEG_PROBE == 1)) || \
    (defined(WT_PKCS11_NEG_PROBE) && (WT_PKCS11_NEG_PROBE == 1)) || \
    (defined(WT_MANIFEST_NEG_PROBE) && (WT_MANIFEST_NEG_PROBE == 3))
/* Addresses the negative probes touch; test builds only. */
#define WT_PROBE_OUT_OF_DOMAIN   0u
#define WT_PROBE_KEYSTORE_BAND   1u
#define WT_PROBE_VAULT_DATA_BAND WT_PROBE_KEYSTORE_BAND
#define WT_PROBE_VNET_DATA_BAND  2u
#define WT_PROBE_ATTEST_DATA_BAND 3u
#define WT_PROBE_HSM_DATA_BAND   4u
#define WT_PROBE_SPM_PERIPHERAL  5u
#define WT_PROBE_TPM_DATA_BAND   6u
#define WT_PROBE_TPM_FTPM_RAM    7u
#define WT_PROBE_PKCS11_DATA_BAND 8u
#define WT_PROBE_PKCS11_PROVIDER_RAM 9u
uintptr_t wt_platform_probe_address(unsigned int target);
#endif

#if defined(WT_DEPUTY_NEG_PROBE) && (WT_DEPUTY_NEG_PROBE == 1)
/* Privileged-deputy proof (WT-FFM-0011), test builds only: a keystore
 * partition rewrites the partition-writable flash context to aim the shared
 * NVM singleton at SPM-private RAM, both by inflating the size and by
 * substituting the base, and drives every KEYSTORE_FLASH primitive through the
 * gate. Returns 1 only when the fix holds: each out-of-range offset is refused
 * with exactly WH_ERROR_BADARGS and the base-substituted read still returns the
 * immutable-geometry NVM bytes. Returns 0 if any SPM byte could leak or a
 * primitive failed to refuse (the fix is absent). */
int wt_platform_deputy_flash_probe(void);
#endif

#if defined(WT_HSM_PIN_NEG_PROBE) && (WT_HSM_PIN_NEG_PROBE == 1)
/* Test builds only: forge the pointer fields the wolfHSM server pumps follow;
 * the pin must heal them before the next pump. Returns 1. */
int wt_platform_hsm_pin_probe(void);
#endif

#if defined(WT_REMEASURE_PROBE)
void wt_platform_remeasure_probe(void);
#endif
#if defined(WT_BOOTUPDATE_PROBE)
void wt_platform_bootupdate_probe(uint32_t running_version);
#endif

#endif
