/* ffa_boot_info.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_BOOT_INFO_H
#define WOLFTRUST_ARCH_AARCH64_FFA_BOOT_INFO_H

#include <stddef.h>
#include <stdint.h>

/* FF-A boot information protocol (DEN0077A 1.2, 5.4, Tables 5.8 and 5.9):
 * the blob the SPMD hands the SPMC in x0. Byte-wise little-endian access so
 * the code runs with the MMU off on either side. */

#define WT_FFA_BOOT_INFO_SIGNATURE        0x0FFAu
#define WT_FFA_BOOT_INFO_HEADER_SIZE      32u
#define WT_FFA_BOOT_INFO_DESC_SIZE        32u
#define WT_FFA_BOOT_INFO_NAME_SIZE        16u

#define WT_FFA_BOOT_INFO_TYPE_FDT         0x00u
#define WT_FFA_BOOT_INFO_TYPE_HOB         0x01u
#define WT_FFA_BOOT_INFO_TYPE_IMPDEF      0x80u
/* wolfTrust boot handoff record (WT-PORT-0020) rides an IMPDEF descriptor. */
#define WT_FFA_BOOT_INFO_TYPE_WT_HANDOFF  (WT_FFA_BOOT_INFO_TYPE_IMPDEF | 0x01u)
#define WT_FFA_BOOT_INFO_NAME_WT_HANDOFF  "wt.handoff"

#define WT_FFA_BOOT_INFO_NAME_STRING      0u
#define WT_FFA_BOOT_INFO_NAME_UUID        1u
#define WT_FFA_BOOT_INFO_CONTENTS_ADDRESS 0u
#define WT_FFA_BOOT_INFO_CONTENTS_VALUE   1u

#define WT_FFA_BOOT_INFO_OK                 0
#define WT_FFA_BOOT_INFO_ERROR_ARGUMENT   (-1)
#define WT_FFA_BOOT_INFO_ERROR_SIGNATURE  (-2)
#define WT_FFA_BOOT_INFO_ERROR_VERSION    (-3)
#define WT_FFA_BOOT_INFO_ERROR_LAYOUT     (-4)
#define WT_FFA_BOOT_INFO_ERROR_RESERVED   (-5)
#define WT_FFA_BOOT_INFO_ERROR_DESC       (-6)
#define WT_FFA_BOOT_INFO_ERROR_SPACE      (-7)
#define WT_FFA_BOOT_INFO_ERROR_NOT_FOUND  (-8)

/* One item the producer wants in the blob. Address-form items are copied
 * into the blob after the descriptor array so the blob stays self-contained;
 * value-form items carry `value` in the Contents field. */
typedef struct wt_ffa_boot_info_item {
    const void* source;
    uint64_t value;
    const char* name;
    uint32_t size;
    uint8_t type;
    uint8_t name_format;
    uint8_t contents_format;
} wt_ffa_boot_info_item_t;

/* One descriptor as the consumer reads it back. */
typedef struct wt_ffa_boot_info_desc {
    uint64_t contents;
    uint32_t size;
    uint16_t flags;
    uint8_t type;
    char name[WT_FFA_BOOT_INFO_NAME_SIZE];
} wt_ffa_boot_info_desc_t;

typedef struct wt_ffa_boot_info {
    uint64_t blob_pa;
    uint32_t version;
    uint32_t blob_size;
    uint32_t desc_count;
    uint32_t desc_offset;
} wt_ffa_boot_info_t;

size_t wt_ffa_boot_info_array_end(uint32_t desc_count);

int wt_ffa_boot_info_build(uint8_t* blob, uint64_t blob_pa, size_t blob_limit,
                           uint32_t version,
                           const wt_ffa_boot_info_item_t* items,
                           uint32_t count, uint32_t* blob_size);

/* Validates the header and every descriptor before reporting success. */
int wt_ffa_boot_info_parse(const uint8_t* blob, uint64_t blob_pa,
                           size_t blob_limit, wt_ffa_boot_info_t* out);

int wt_ffa_boot_info_desc(const uint8_t* blob, const wt_ffa_boot_info_t* info,
                          uint32_t index, wt_ffa_boot_info_desc_t* out);

int wt_ffa_boot_info_find(const uint8_t* blob, const wt_ffa_boot_info_t* info,
                          uint8_t type, wt_ffa_boot_info_desc_t* out);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_BOOT_INFO_H */
