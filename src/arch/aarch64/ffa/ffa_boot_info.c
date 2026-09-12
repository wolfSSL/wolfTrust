/* ffa_boot_info.c
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

/* FF-A boot information blob producer (SPMD side) and consumer (SPMC side),
 * DEN0077A 1.2 section 5.4. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_boot_info.h"

#define OFF_SIGNATURE   0u
#define OFF_VERSION     4u
#define OFF_BLOB_SIZE   8u
#define OFF_DESC_SIZE   12u
#define OFF_DESC_COUNT  16u
#define OFF_DESC_OFFSET 20u
#define OFF_RESERVED    24u

#define DESC_NAME       0u
#define DESC_TYPE       16u
#define DESC_RESERVED   17u
#define DESC_FLAGS      18u
#define DESC_SIZE       20u
#define DESC_CONTENTS   24u

#define FLAGS_NAME_MASK      0x0003u
#define FLAGS_CONTENTS_MASK  0x000Cu
#define FLAGS_CONTENTS_SHIFT 2u
#define FLAGS_RESERVED_MASK  0xFFF0u

static uint32_t rd32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t* p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static uint16_t rd16(const uint8_t* p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void wr32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t* p, uint64_t v)
{
    wr32(p, (uint32_t)v);
    wr32(p + 4, (uint32_t)(v >> 32));
}

static void wr16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static size_t align8(size_t v)
{
    return (v + 7u) & ~(size_t)7u;
}

/* Table 5.8: standard types are FDT (0) and HOB (1) only; a value-form
 * descriptor carries 1 to 8 bytes in its Contents field. */
static int type_and_size_ok(uint8_t type, uint8_t contents_format,
                            uint32_t size)
{
    if (((type & WT_FFA_BOOT_INFO_TYPE_IMPDEF) == 0u) &&
        (type > WT_FFA_BOOT_INFO_TYPE_HOB)) {
        return 0;
    }
    if ((contents_format == WT_FFA_BOOT_INFO_CONTENTS_VALUE) &&
        ((size < 1u) || (size > 8u))) {
        return 0;
    }
    return 1;
}

size_t wt_ffa_boot_info_array_end(uint32_t desc_count)
{
    return WT_FFA_BOOT_INFO_HEADER_SIZE +
           ((size_t)desc_count * WT_FFA_BOOT_INFO_DESC_SIZE);
}

static int name_ok(const uint8_t* name, uint16_t flags)
{
    unsigned int i;

    if ((flags & FLAGS_NAME_MASK) == WT_FFA_BOOT_INFO_NAME_UUID) {
        return 1;
    }
    for (i = 0u; i < WT_FFA_BOOT_INFO_NAME_SIZE; i++) {
        if (name[i] == 0u) {
            return 1;
        }
    }
    return 0;
}

static int put_name(uint8_t* dst, const wt_ffa_boot_info_item_t* item)
{
    unsigned int i;
    const uint8_t* src = (const uint8_t*)item->name;

    for (i = 0u; i < WT_FFA_BOOT_INFO_NAME_SIZE; i++) {
        dst[i] = 0u;
    }
    if (src == NULL) {
        return WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
    }
    if (item->name_format == WT_FFA_BOOT_INFO_NAME_UUID) {
        for (i = 0u; i < WT_FFA_BOOT_INFO_NAME_SIZE; i++) {
            dst[i] = src[i];
        }
        return WT_FFA_BOOT_INFO_OK;
    }
    for (i = 0u; (i < WT_FFA_BOOT_INFO_NAME_SIZE) && (src[i] != 0u); i++) {
        dst[i] = src[i];
    }
    if (i == WT_FFA_BOOT_INFO_NAME_SIZE) {
        return WT_FFA_BOOT_INFO_ERROR_DESC;
    }
    return WT_FFA_BOOT_INFO_OK;
}

int wt_ffa_boot_info_build(uint8_t* blob, uint64_t blob_pa, size_t blob_limit,
                           uint32_t version,
                           const wt_ffa_boot_info_item_t* items,
                           uint32_t count, uint32_t* blob_size)
{
    int ret = WT_FFA_BOOT_INFO_OK;
    size_t total;
    size_t cursor;
    size_t i;
    size_t k;
    uint8_t* desc;
    const uint8_t* src;
    uint16_t flags;

    if ((blob == NULL) || (blob_size == NULL) || ((count != 0u) && (items == NULL))) {
        return WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
    }
    if (((blob_pa & 7u) != 0u) || ((count != 0u) && (blob_limit > 0xFFFFFFFFu))) {
        return WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
    }
    total = wt_ffa_boot_info_array_end(count);
    for (i = 0u; i < count; i++) {
        if (items[i].contents_format == WT_FFA_BOOT_INFO_CONTENTS_ADDRESS) {
            total = align8(total) + items[i].size;
        }
    }
    total = align8(total);
    if ((total > blob_limit) || (total > 0xFFFFFFFFu)) {
        return WT_FFA_BOOT_INFO_ERROR_SPACE;
    }

    for (i = 0u; i < WT_FFA_BOOT_INFO_HEADER_SIZE; i++) {
        blob[i] = 0u;
    }
    wr32(blob + OFF_SIGNATURE, WT_FFA_BOOT_INFO_SIGNATURE);
    wr32(blob + OFF_VERSION, version);
    wr32(blob + OFF_BLOB_SIZE, (uint32_t)total);
    wr32(blob + OFF_DESC_SIZE, WT_FFA_BOOT_INFO_DESC_SIZE);
    wr32(blob + OFF_DESC_COUNT, count);
    wr32(blob + OFF_DESC_OFFSET, WT_FFA_BOOT_INFO_HEADER_SIZE);

    cursor = wt_ffa_boot_info_array_end(count);
    for (i = 0u; (i < count) && (ret == WT_FFA_BOOT_INFO_OK); i++) {
        desc = blob + WT_FFA_BOOT_INFO_HEADER_SIZE + (i * WT_FFA_BOOT_INFO_DESC_SIZE);
        if ((items[i].name_format > WT_FFA_BOOT_INFO_NAME_UUID) ||
            (items[i].contents_format > WT_FFA_BOOT_INFO_CONTENTS_VALUE) ||
            !type_and_size_ok(items[i].type, items[i].contents_format,
                              items[i].size)) {
            ret = WT_FFA_BOOT_INFO_ERROR_DESC;
            break;
        }
        ret = put_name(desc + DESC_NAME, &items[i]);
        if (ret != WT_FFA_BOOT_INFO_OK) {
            break;
        }
        flags = (uint16_t)(items[i].name_format |
                           (items[i].contents_format << FLAGS_CONTENTS_SHIFT));
        desc[DESC_TYPE] = items[i].type;
        desc[DESC_RESERVED] = 0u;
        wr16(desc + DESC_FLAGS, flags);
        wr32(desc + DESC_SIZE, items[i].size);
        if (items[i].contents_format == WT_FFA_BOOT_INFO_CONTENTS_VALUE) {
            wr64(desc + DESC_CONTENTS, items[i].value);
        }
        else {
            src = (const uint8_t*)items[i].source;
            if ((src == NULL) && (items[i].size != 0u)) {
                ret = WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
                break;
            }
            cursor = align8(cursor);
            wr64(desc + DESC_CONTENTS, blob_pa + cursor);
            for (k = 0u; k < items[i].size; k++) {
                blob[cursor + k] = src[k];
            }
            cursor += items[i].size;
        }
    }
    if (ret == WT_FFA_BOOT_INFO_OK) {
        while (cursor < total) {
            blob[cursor] = 0u;
            cursor++;
        }
        *blob_size = (uint32_t)total;
    }
    return ret;
}

static int desc_ok(const uint8_t* desc, const wt_ffa_boot_info_t* info)
{
    uint16_t flags = rd16(desc + DESC_FLAGS);
    uint64_t contents;
    uint32_t size;
    uint64_t end;

    if (desc[DESC_RESERVED] != 0u) {
        return WT_FFA_BOOT_INFO_ERROR_RESERVED;
    }
    if (((flags & FLAGS_RESERVED_MASK) != 0u) ||
        ((flags & FLAGS_NAME_MASK) > WT_FFA_BOOT_INFO_NAME_UUID) ||
        (((flags & FLAGS_CONTENTS_MASK) >> FLAGS_CONTENTS_SHIFT) >
         WT_FFA_BOOT_INFO_CONTENTS_VALUE)) {
        return WT_FFA_BOOT_INFO_ERROR_DESC;
    }
    if (!name_ok(desc + DESC_NAME, flags)) {
        return WT_FFA_BOOT_INFO_ERROR_DESC;
    }
    if (!type_and_size_ok(desc[DESC_TYPE],
                          (uint8_t)((flags & FLAGS_CONTENTS_MASK) >>
                                    FLAGS_CONTENTS_SHIFT),
                          rd32(desc + DESC_SIZE))) {
        return WT_FFA_BOOT_INFO_ERROR_DESC;
    }
    if (((flags & FLAGS_CONTENTS_MASK) >> FLAGS_CONTENTS_SHIFT) ==
        WT_FFA_BOOT_INFO_CONTENTS_ADDRESS) {
        contents = rd64(desc + DESC_CONTENTS);
        size = rd32(desc + DESC_SIZE);
        end = info->blob_pa + info->blob_size;
        if ((contents < info->blob_pa) || (contents > end) ||
            ((uint64_t)size > (end - contents))) {
            return WT_FFA_BOOT_INFO_ERROR_LAYOUT;
        }
    }
    return WT_FFA_BOOT_INFO_OK;
}

int wt_ffa_boot_info_parse(const uint8_t* blob, uint64_t blob_pa,
                           size_t blob_limit, wt_ffa_boot_info_t* out)
{
    int ret = WT_FFA_BOOT_INFO_OK;
    uint32_t i;
    uint64_t array_end;

    if ((blob == NULL) || (out == NULL)) {
        return WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
    }
    if (blob_limit < WT_FFA_BOOT_INFO_HEADER_SIZE) {
        return WT_FFA_BOOT_INFO_ERROR_LAYOUT;
    }
    if (rd32(blob + OFF_SIGNATURE) != WT_FFA_BOOT_INFO_SIGNATURE) {
        return WT_FFA_BOOT_INFO_ERROR_SIGNATURE;
    }
    out->blob_pa = blob_pa;
    out->version = rd32(blob + OFF_VERSION);
    out->blob_size = rd32(blob + OFF_BLOB_SIZE);
    out->desc_count = rd32(blob + OFF_DESC_COUNT);
    out->desc_offset = rd32(blob + OFF_DESC_OFFSET);
    if (((out->version & 0x80000000u) != 0u) ||
        (WT_FFA_VERSION_MAJOR_OF(out->version) != 1u)) {
        return WT_FFA_BOOT_INFO_ERROR_VERSION;
    }
    if ((rd32(blob + OFF_RESERVED) != 0u) || (rd32(blob + OFF_RESERVED + 4u) != 0u)) {
        return WT_FFA_BOOT_INFO_ERROR_RESERVED;
    }
    if ((rd32(blob + OFF_DESC_SIZE) != WT_FFA_BOOT_INFO_DESC_SIZE) ||
        (out->desc_offset < WT_FFA_BOOT_INFO_HEADER_SIZE) ||
        ((out->desc_offset & 7u) != 0u) ||
        (out->blob_size < WT_FFA_BOOT_INFO_HEADER_SIZE) ||
        ((size_t)out->blob_size > blob_limit)) {
        return WT_FFA_BOOT_INFO_ERROR_LAYOUT;
    }
    array_end = (uint64_t)out->desc_offset +
                ((uint64_t)out->desc_count * WT_FFA_BOOT_INFO_DESC_SIZE);
    if (array_end > (uint64_t)out->blob_size) {
        return WT_FFA_BOOT_INFO_ERROR_LAYOUT;
    }
    for (i = 0u; (i < out->desc_count) && (ret == WT_FFA_BOOT_INFO_OK); i++) {
        ret = desc_ok(blob + out->desc_offset + (i * WT_FFA_BOOT_INFO_DESC_SIZE),
                      out);
    }
    return ret;
}

int wt_ffa_boot_info_desc(const uint8_t* blob, const wt_ffa_boot_info_t* info,
                          uint32_t index, wt_ffa_boot_info_desc_t* out)
{
    const uint8_t* desc;
    unsigned int i;

    if ((blob == NULL) || (info == NULL) || (out == NULL)) {
        return WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
    }
    if (index >= info->desc_count) {
        return WT_FFA_BOOT_INFO_ERROR_NOT_FOUND;
    }
    desc = blob + info->desc_offset + (index * WT_FFA_BOOT_INFO_DESC_SIZE);
    for (i = 0u; i < WT_FFA_BOOT_INFO_NAME_SIZE; i++) {
        out->name[i] = (char)desc[DESC_NAME + i];
    }
    out->type = desc[DESC_TYPE];
    out->flags = rd16(desc + DESC_FLAGS);
    out->size = rd32(desc + DESC_SIZE);
    out->contents = rd64(desc + DESC_CONTENTS);
    return WT_FFA_BOOT_INFO_OK;
}

int wt_ffa_boot_info_find(const uint8_t* blob, const wt_ffa_boot_info_t* info,
                          uint8_t type, wt_ffa_boot_info_desc_t* out)
{
    uint32_t i;
    int ret;

    if ((blob == NULL) || (info == NULL) || (out == NULL)) {
        return WT_FFA_BOOT_INFO_ERROR_ARGUMENT;
    }
    for (i = 0u; i < info->desc_count; i++) {
        ret = wt_ffa_boot_info_desc(blob, info, i, out);
        if ((ret == WT_FFA_BOOT_INFO_OK) && (out->type == type)) {
            return WT_FFA_BOOT_INFO_OK;
        }
    }
    return WT_FFA_BOOT_INFO_ERROR_NOT_FOUND;
}
