/* guest_verify.h
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

#ifndef WOLFTRUST_GUEST_VERIFY_H
#define WOLFTRUST_GUEST_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define WT_GUEST_MEAS_DIGEST_SIZE 32u
#define WT_GUEST_MEAS_MAX_RECORDS 4u
#define WT_GUEST_MEAS_NAME_LEN    16u

/* One pinned guest measurement. Records live in a slot inside the signed
 * wolfTrust image, stamped by the image-assembly patcher before wolfBoot
 * signs, so the pinned digests share wolfTrust's own root of trust. */
typedef struct wt_guest_measurement {
    uint32_t guest_id;
    uint32_t version;
    uint32_t image_size;
    uint8_t digest[WT_GUEST_MEAS_DIGEST_SIZE];
} wt_guest_measurement_t;

typedef enum wt_guest_verify_result {
    WT_GUEST_VERIFY_OK = 0,
    WT_GUEST_VERIFY_ERROR_ARGUMENT = -700,
    WT_GUEST_VERIFY_ERROR_LAYOUT = -701,
    WT_GUEST_VERIFY_ERROR_DIGEST = -702,
    WT_GUEST_VERIFY_ERROR_VERSION = -703,
    WT_GUEST_VERIFY_ERROR_HASH = -704,
    WT_GUEST_VERIFY_ERROR_CAPACITY = -705,
    WT_GUEST_VERIFY_ERROR_WRP = -706
} wt_guest_verify_result_t;

/* WT-SYS-0002 / WT-FFM-0049 launch predicate: SHA-256 the guest image bytes,
 * pin them to the recorded digest, and enforce the manifest version floor.
 * Any failure means the guest must not be entered. */
int wt_guest_verify_image(const void* image,
                          size_t window_size,
                          const wt_guest_measurement_t* record,
                          uint32_t min_version);

/* STM32H5-family flash write-protection predicate for a guest image window.
 * Each WRP bit protects a group of sectors_per_group consecutive sector_size
 * sectors within a bank, and a 0 bit means write-protected. Returns
 * WT_GUEST_VERIFY_OK only when every sector spanned by [window_base,
 * window_base + window_size) has its WRP group bit cleared, so a Non-secure
 * guest cannot reprogram the image a peer will later resume. Neutral and
 * host-tested; the port supplies WRPnR_CUR and the bank geometry. */
int wt_guest_flash_wrp_covers(uint32_t wrp_bitmap,
                              uintptr_t window_base, size_t window_size,
                              uintptr_t bank_base,
                              uint32_t sector_size,
                              uint32_t sectors_per_group);

/* One flash-region access descriptor (XSPI FRAD) as the port read it back.
 * start and end are inclusive addresses; write_acp is nonzero when any master
 * domain may write through it; locked means locked until the next hard reset. */
typedef struct wt_frad_region {
    uint32_t start;
    uint32_t end;
    uint32_t write_acp;
    uint32_t valid;
    uint32_t locked;
} wt_frad_region_t;

/* Descriptor-fenced flash write-protection predicate for a guest image window.
 * Returns WT_GUEST_VERIFY_OK only when [window_base, window_base + window_size)
 * is covered end to end by valid, locked, write-denying descriptors and no
 * valid write-granting or unlocked descriptor overlaps it. Neutral and
 * host-tested; the port supplies the normalized descriptor read-back. */
int wt_guest_flash_frad_covers(const wt_frad_region_t* regions, size_t count,
                               uintptr_t window_base, size_t window_size);

/* WT-FFM-0052 / WT-SYS-0013 runtime re-measurement decision. On demand after
 * boot, re-hash the domain's window against its pinned record. A guest with no
 * launch policy has nothing pinned and passes; a launch-required guest with no
 * window or record cannot be confirmed and fails closed. The result feeds
 * wt_runtime_verify_should_quarantine so a mismatch drives the domain through
 * the fault path instead of trusting the boot-time measurement. */
int wt_runtime_verify_decide(const void* window_base, size_t window_size,
                             const wt_guest_measurement_t* record,
                             uint32_t min_version, int launch_required);

/* True when a runtime re-measurement result must fail the domain closed. */
int wt_runtime_verify_should_quarantine(int verify_result);

/* Verified-launch measurement table consumed by Initial Attestation as the
 * per-guest software components. Only measurements that passed
 * wt_guest_verify_image may be recorded. */
int wt_guest_measurement_record(const wt_guest_measurement_t* record,
                                const char* name);
size_t wt_guest_measurement_count(void);
const wt_guest_measurement_t* wt_guest_measurement_get(size_t index,
                                                       const char** name);
void wt_guest_measurement_reset(void);

#endif
