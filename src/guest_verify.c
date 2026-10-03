/* guest_verify.c
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

#include "wolftrust/guest_verify.h"

#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hash.h"

#include <string.h>

typedef struct wt_guest_measurement_entry {
    wt_guest_measurement_t record;
    char name[WT_GUEST_MEAS_NAME_LEN];
} wt_guest_measurement_entry_t;

static wt_guest_measurement_entry_t g_measurements[WT_GUEST_MEAS_MAX_RECORDS];
static size_t g_measurement_count;

static int wt_guest_digest_equal(const uint8_t* a, const uint8_t* b)
{
    uint8_t diff = 0u;
    size_t i;

    for (i = 0u; i < WT_GUEST_MEAS_DIGEST_SIZE; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0u;
}

int wt_guest_verify_image(const void* image,
                          size_t window_size,
                          const wt_guest_measurement_t* record,
                          uint32_t min_version)
{
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    int ret = WT_GUEST_VERIFY_OK;

    if (image == NULL || record == NULL || window_size == 0u) {
        ret = WT_GUEST_VERIFY_ERROR_ARGUMENT;
    }

    if (ret == WT_GUEST_VERIFY_OK &&
            (record->image_size == 0u ||
             (size_t)record->image_size > window_size)) {
        ret = WT_GUEST_VERIFY_ERROR_LAYOUT;
    }

    if (ret == WT_GUEST_VERIFY_OK && record->version < min_version) {
        ret = WT_GUEST_VERIFY_ERROR_VERSION;
    }

    if (ret == WT_GUEST_VERIFY_OK) {
        if (wc_Sha256Hash((const byte*)image, (word32)record->image_size,
                          digest) != 0) {
            ret = WT_GUEST_VERIFY_ERROR_HASH;
        }
    }

    if (ret == WT_GUEST_VERIFY_OK &&
            !wt_guest_digest_equal(digest, record->digest)) {
        ret = WT_GUEST_VERIFY_ERROR_DIGEST;
    }

    return ret;
}

int wt_guest_flash_wrp_covers(uint32_t wrp_bitmap,
                              uintptr_t window_base, size_t window_size,
                              uintptr_t bank_base,
                              uint32_t sector_size,
                              uint32_t sectors_per_group)
{
    uintptr_t offset;
    uint32_t first_group;
    uint32_t last_group;
    uint32_t group;
    int ret = WT_GUEST_VERIFY_OK;

    if (window_size == 0u || sector_size == 0u || sectors_per_group == 0u ||
            window_base < bank_base) {
        return WT_GUEST_VERIFY_ERROR_ARGUMENT;
    }

    offset = window_base - bank_base;
    first_group = (uint32_t)((offset / sector_size) / sectors_per_group);
    last_group = (uint32_t)(((offset + (uintptr_t)window_size - 1u) /
                             sector_size) / sectors_per_group);

    /* A window that runs past the 32-group bank map cannot be confirmed from a
     * single bank's WRP register, so fail closed. */
    if (last_group >= 32u) {
        return WT_GUEST_VERIFY_ERROR_LAYOUT;
    }

    for (group = first_group; group <= last_group; ++group) {
        if ((wrp_bitmap & ((uint32_t)1U << group)) != 0U) {
            ret = WT_GUEST_VERIFY_ERROR_WRP;
            break;
        }
    }

    return ret;
}

static int wt_frad_region_denies_write(const wt_frad_region_t* region)
{
    return (region->valid != 0u && region->locked != 0u &&
            region->write_acp == 0u) ? 1 : 0;
}

int wt_guest_flash_frad_covers(const wt_frad_region_t* regions, size_t count,
                               uintptr_t window_base, size_t window_size)
{
    uintptr_t last;
    uintptr_t cursor;
    size_t i;
    size_t step;
    int covered = 0;
    int found;
    int ret = WT_GUEST_VERIFY_OK;

    if (regions == NULL || count == 0u || window_size == 0u) {
        return WT_GUEST_VERIFY_ERROR_ARGUMENT;
    }
    last = window_base + (uintptr_t)window_size - 1u;
    if (last < window_base) {
        return WT_GUEST_VERIFY_ERROR_ARGUMENT;
    }

    /* Overlapping descriptors resolve in hardware-defined order, so every
     * valid descriptor that touches the window must itself deny writes. */
    for (i = 0u; i < count && ret == WT_GUEST_VERIFY_OK; ++i) {
        if (regions[i].valid != 0u &&
                (uintptr_t)regions[i].start <= last &&
                (uintptr_t)regions[i].end >= window_base &&
                wt_frad_region_denies_write(&regions[i]) == 0) {
            ret = WT_GUEST_VERIFY_ERROR_WRP;
        }
    }

    cursor = window_base;
    for (step = 0u; step < count && ret == WT_GUEST_VERIFY_OK && covered == 0;
         ++step) {
        found = 0;
        for (i = 0u; i < count && found == 0; ++i) {
            if (wt_frad_region_denies_write(&regions[i]) != 0 &&
                    (uintptr_t)regions[i].start <= cursor &&
                    (uintptr_t)regions[i].end >= cursor) {
                found = 1;
                if ((uintptr_t)regions[i].end >= last) {
                    covered = 1;
                }
                else {
                    cursor = (uintptr_t)regions[i].end + 1u;
                }
            }
        }
        if (found == 0) {
            ret = WT_GUEST_VERIFY_ERROR_WRP;
        }
    }

    if (ret == WT_GUEST_VERIFY_OK && covered == 0) {
        ret = WT_GUEST_VERIFY_ERROR_WRP;
    }

    return ret;
}

int wt_runtime_verify_decide(const void* window_base, size_t window_size,
                             const wt_guest_measurement_t* record,
                             uint32_t min_version, int launch_required)
{
    if (launch_required == 0) {
        return WT_GUEST_VERIFY_OK;
    }
    if (window_base == NULL || record == NULL || window_size == 0u) {
        return WT_GUEST_VERIFY_ERROR_ARGUMENT;
    }
    return wt_guest_verify_image(window_base, window_size, record,
                                 min_version);
}

int wt_runtime_verify_should_quarantine(int verify_result)
{
    return verify_result != WT_GUEST_VERIFY_OK;
}

int wt_guest_measurement_record(const wt_guest_measurement_t* record,
                                const char* name)
{
    wt_guest_measurement_entry_t* entry;
    size_t name_length;

    if (record == NULL || name == NULL) {
        return WT_GUEST_VERIFY_ERROR_ARGUMENT;
    }

    if (g_measurement_count >= WT_GUEST_MEAS_MAX_RECORDS) {
        return WT_GUEST_VERIFY_ERROR_CAPACITY;
    }

    entry = &g_measurements[g_measurement_count];
    entry->record = *record;
    name_length = strlen(name);
    if (name_length >= sizeof(entry->name)) {
        name_length = sizeof(entry->name) - 1u;
    }
    (void)memcpy(entry->name, name, name_length);
    entry->name[name_length] = '\0';
    g_measurement_count++;

    return WT_GUEST_VERIFY_OK;
}

size_t wt_guest_measurement_count(void)
{
    return g_measurement_count;
}

const wt_guest_measurement_t* wt_guest_measurement_get(size_t index,
                                                       const char** name)
{
    if (index >= g_measurement_count) {
        return NULL;
    }

    if (name != NULL) {
        *name = g_measurements[index].name;
    }

    return &g_measurements[index].record;
}

void wt_guest_measurement_reset(void)
{
    (void)memset(g_measurements, 0, sizeof(g_measurements));
    g_measurement_count = 0u;
}
