/* main.c
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

/* WT-FFA-0008: the FF-A boot information blob (DEN0077A 1.2 section 5.4)
 * round-trips between the SPMD producer and the SPMC consumer, and every
 * malformed header or descriptor is refused before any descriptor is used. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_boot_info.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BLOB_PA 0x0E040000ull
#define BLOB_LIMIT 4096u

static int checks;
static int failures;
static uint8_t g_blob[BLOB_LIMIT];

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static const uint8_t g_record[20] = {
    0x57, 0x54, 0x48, 0x4F, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

static const uint8_t g_uuid[16] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3,
    0xC0, 0xC1, 0xC2, 0xC3, 0xD0, 0xD1, 0xD2, 0xD3
};

static uint32_t build_handoff(uint32_t version)
{
    wt_ffa_boot_info_item_t item;
    uint32_t size = 0u;
    int ret;

    memset(&item, 0, sizeof(item));
    item.name = WT_FFA_BOOT_INFO_NAME_WT_HANDOFF;
    item.type = WT_FFA_BOOT_INFO_TYPE_WT_HANDOFF;
    item.name_format = WT_FFA_BOOT_INFO_NAME_STRING;
    item.contents_format = WT_FFA_BOOT_INFO_CONTENTS_ADDRESS;
    item.source = g_record;
    item.size = (uint32_t)sizeof(g_record);
    memset(g_blob, 0xEE, sizeof(g_blob));
    ret = wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, version, &item, 1u,
                                 &size);
    return (ret == WT_FFA_BOOT_INFO_OK) ? size : 0u;
}

static void put32(uint32_t off, uint32_t v)
{
    g_blob[off] = (uint8_t)v;
    g_blob[off + 1u] = (uint8_t)(v >> 8);
    g_blob[off + 2u] = (uint8_t)(v >> 16);
    g_blob[off + 3u] = (uint8_t)(v >> 24);
}

static int parse_now(wt_ffa_boot_info_t* info)
{
    return wt_ffa_boot_info_parse(g_blob, BLOB_PA, BLOB_LIMIT, info);
}

int main(void)
{
    wt_ffa_boot_info_t info;
    wt_ffa_boot_info_desc_t desc;
    wt_ffa_boot_info_item_t items[3];
    uint32_t size;
    int ret;

    printf("WT-FFA-0008 (FF-A boot information protocol)\n");

    size = build_handoff(WT_FFA_VERSION_1_2);
    check(size == 88u, "header + one descriptor + 20-byte record padded to 8 = 88 bytes");
    check(g_blob[0] == 0xFA && g_blob[1] == 0x0F && g_blob[2] == 0 && g_blob[3] == 0,
          "signature 0x0FFA is little-endian at offset 0");
    check(parse_now(&info) == WT_FFA_BOOT_INFO_OK && info.version == WT_FFA_VERSION_1_2 &&
          info.blob_size == 88u && info.desc_count == 1u && info.desc_offset == 32u,
          "the consumer parses the header back");
    ret = wt_ffa_boot_info_find(g_blob, &info, WT_FFA_BOOT_INFO_TYPE_WT_HANDOFF, &desc);
    check(ret == WT_FFA_BOOT_INFO_OK && strcmp(desc.name, "wt.handoff") == 0 &&
          desc.type == 0x81u && desc.flags == 0u && desc.size == 20u &&
          desc.contents == BLOB_PA + 64u,
          "the handoff descriptor is IMPDEF type 0x81, string name, address form, at +64");
    check(memcmp(g_blob + 64u, g_record, sizeof(g_record)) == 0 &&
          g_blob[84] == 0 && g_blob[87] == 0,
          "address-form contents are copied into the blob and padded with zeros");
    check(wt_ffa_boot_info_find(g_blob, &info, WT_FFA_BOOT_INFO_TYPE_FDT, &desc) ==
              WT_FFA_BOOT_INFO_ERROR_NOT_FOUND &&
          wt_ffa_boot_info_desc(g_blob, &info, 1u, &desc) ==
              WT_FFA_BOOT_INFO_ERROR_NOT_FOUND,
          "a missing type or an index past the array is NOT_FOUND");

    memset(items, 0, sizeof(items));
    items[0].name = "fdt";
    items[0].type = WT_FFA_BOOT_INFO_TYPE_FDT;
    items[0].contents_format = WT_FFA_BOOT_INFO_CONTENTS_VALUE;
    items[0].value = 0x4000000000ull;
    items[0].size = 8u;
    items[1].name = (const char*)g_uuid;
    items[1].name_format = WT_FFA_BOOT_INFO_NAME_UUID;
    items[1].type = WT_FFA_BOOT_INFO_TYPE_IMPDEF | 0x7Fu;
    items[1].contents_format = WT_FFA_BOOT_INFO_CONTENTS_ADDRESS;
    items[1].source = g_record;
    items[1].size = 3u;
    items[2].name = "second";
    items[2].type = WT_FFA_BOOT_INFO_TYPE_HOB;
    items[2].contents_format = WT_FFA_BOOT_INFO_CONTENTS_ADDRESS;
    items[2].source = g_record + 4;
    items[2].size = 9u;
    ret = wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, items,
                                 3u, &size);
    check(ret == WT_FFA_BOOT_INFO_OK && size == 32u + 96u + 8u + 16u,
          "three descriptors: value form takes no space, address forms are 8-aligned");
    check(parse_now(&info) == WT_FFA_BOOT_INFO_OK && info.desc_count == 3u,
          "the three-descriptor blob parses");
    check(wt_ffa_boot_info_desc(g_blob, &info, 0u, &desc) == WT_FFA_BOOT_INFO_OK &&
          desc.flags == 0x4u && desc.contents == 0x4000000000ull && desc.size == 8u,
          "value form keeps the value in Contents with flags bits 3:2 = 1");
    items[0].size = 0u;
    check(wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, items, 1u,
                                 &size) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "a value-form descriptor with size 0 is refused");
    items[0].size = 9u;
    check(wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, items, 1u,
                                 &size) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "a value-form descriptor with size 9 is refused");
    items[0].size = 8u;
    items[0].type = 0x02u;
    check(wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, items, 1u,
                                 &size) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "a reserved standard type (not FDT or HOB) is refused");
    items[0].type = WT_FFA_BOOT_INFO_TYPE_FDT;
    check(wt_ffa_boot_info_desc(g_blob, &info, 1u, &desc) == WT_FFA_BOOT_INFO_OK &&
          desc.flags == 0x1u && memcmp(desc.name, g_uuid, 16) == 0 &&
          desc.contents == BLOB_PA + 128u && desc.size == 3u,
          "UUID names are 16 raw bytes with flags bits 1:0 = 1");
    check(wt_ffa_boot_info_desc(g_blob, &info, 2u, &desc) == WT_FFA_BOOT_INFO_OK &&
          desc.contents == BLOB_PA + 136u &&
          memcmp(g_blob + 136u, g_record + 4, 9) == 0,
          "the second address-form item follows the first at the next 8-byte boundary");

    ret = wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, NULL, 0u,
                                 &size);
    check(ret == WT_FFA_BOOT_INFO_OK && size == 32u && parse_now(&info) == WT_FFA_BOOT_INFO_OK &&
          info.desc_count == 0u,
          "an empty blob is the 32-byte header and parses");

    items[0].name = "0123456789abcdef";
    items[0].name_format = WT_FFA_BOOT_INFO_NAME_STRING;
    check(wt_ffa_boot_info_build(g_blob, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, items, 1u,
                                 &size) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "a 16-character string name has no room for its NUL");
    items[0].name = "fdt";
    check(wt_ffa_boot_info_build(g_blob, BLOB_PA, 100u, WT_FFA_VERSION_1_2, items, 3u,
                                 &size) == WT_FFA_BOOT_INFO_ERROR_SPACE,
          "a blob too small for the array and contents is refused");
    check(wt_ffa_boot_info_build(g_blob, BLOB_PA + 4u, BLOB_LIMIT, WT_FFA_VERSION_1_2, items,
                                 1u, &size) == WT_FFA_BOOT_INFO_ERROR_ARGUMENT &&
          wt_ffa_boot_info_build(NULL, BLOB_PA, BLOB_LIMIT, WT_FFA_VERSION_1_2, items, 1u,
                                 &size) == WT_FFA_BOOT_INFO_ERROR_ARGUMENT,
          "an unaligned blob address or a NULL blob is refused");

    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(0u, 0x0FFBu);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_SIGNATURE, "wrong signature");
    size = build_handoff(WT_FFA_VERSION_MAKE(2u, 0u));
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_VERSION, "major version 2 is refused");
    size = build_handoff(WT_FFA_VERSION_MAKE(1u, 0u));
    check(parse_now(&info) == WT_FFA_BOOT_INFO_OK, "version 1.0 blobs are accepted");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(12u, 16u);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT, "descriptor size other than 32");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(20u, 36u);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT, "descriptor offset not 8-aligned");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(16u, 3u);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT,
          "descriptor array running past the blob size");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(8u, BLOB_LIMIT + 8u);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT, "blob size past the memory limit");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(28u, 1u);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_RESERVED, "header reserved bytes not zero");
    size = build_handoff(WT_FFA_VERSION_1_2);
    g_blob[32u + 17u] = 1u;
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_RESERVED,
          "descriptor reserved byte not zero");
    size = build_handoff(WT_FFA_VERSION_1_2);
    g_blob[32u + 18u] = 0x10u;
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_DESC, "descriptor flags bit 4 set");
    size = build_handoff(WT_FFA_VERSION_1_2);
    g_blob[32u + 18u] = 0x08u;
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_DESC, "contents format b'10 is reserved");
    size = build_handoff(WT_FFA_VERSION_1_2);
    g_blob[32u + 18u] = 0x02u;
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_DESC, "name format b'10 is reserved");
    size = build_handoff(WT_FFA_VERSION_1_2);
    memset(g_blob + 32u, 'x', 16u);
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "a string name without a NUL inside 16 bytes");
    size = build_handoff(WT_FFA_VERSION_1_2);
    g_blob[32u + 18u] = 0x04u;
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "the consumer refuses a value-form descriptor whose size is not 1 to 8");
    size = build_handoff(WT_FFA_VERSION_1_2);
    g_blob[32u + 16u] = 0x02u;
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_DESC,
          "the consumer refuses a reserved standard type");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(32u + 24u, (uint32_t)(BLOB_PA + 80u));
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT,
          "address-form contents running past the blob");
    size = build_handoff(WT_FFA_VERSION_1_2);
    put32(32u + 24u, (uint32_t)(BLOB_PA - 8u));
    check(parse_now(&info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT,
          "address-form contents before the blob");
    check(wt_ffa_boot_info_parse(g_blob, BLOB_PA, 16u, &info) == WT_FFA_BOOT_INFO_ERROR_LAYOUT &&
          wt_ffa_boot_info_parse(NULL, BLOB_PA, BLOB_LIMIT, &info) ==
              WT_FFA_BOOT_INFO_ERROR_ARGUMENT,
          "a memory limit under the header or a NULL blob is refused");
    (void)size;

    printf("ffa_boot_info: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
