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

/* WT-SYS-0002 / WT-FFM-0049: the guest launch predicate accepts only an image
 * whose SHA-256 matches the pinned digest and whose version meets the manifest
 * floor, and fails closed on tamper, rollback, layout, and argument abuse. */

#include "wolftrust/guest_verify.h"

#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include <stdio.h>
#include <string.h>

static unsigned int g_checks;
static unsigned int g_failures;

#define EXPECT_RESULT(actual, expected) \
    do { \
        int actual_result = (actual); \
        int expected_result = (expected); \
        g_checks++; \
        if (actual_result != expected_result) { \
            (void)fprintf(stderr, "line %d: expected %d, received %d\n", \
                          __LINE__, expected_result, actual_result); \
            g_failures++; \
        } \
    } while (0)

#define EXPECT_TRUE(cond) \
    do { \
        g_checks++; \
        if (!(cond)) { \
            (void)fprintf(stderr, "line %d: condition failed\n", __LINE__); \
            g_failures++; \
        } \
    } while (0)

static uint8_t g_image[1024];

static wt_guest_measurement_t wt_make_record(uint32_t version,
                                             uint32_t image_size)
{
    wt_guest_measurement_t record;

    (void)memset(&record, 0, sizeof(record));
    record.guest_id = 0u;
    record.version = version;
    record.image_size = image_size;
    (void)wc_Sha256Hash(g_image, image_size, record.digest);
    return record;
}

static void wt_test_accept(void)
{
    wt_guest_measurement_t record = wt_make_record(2u, 512u);

    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_OK);
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 2u),
                  WT_GUEST_VERIFY_OK);
    /* The digest pins exactly image_size bytes, so a full-window image is
     * accepted when hashed at its recorded size. */
    record = wt_make_record(1u, (uint32_t)sizeof(g_image));
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_OK);
}

static void wt_test_tamper(void)
{
    wt_guest_measurement_t record = wt_make_record(2u, 512u);

    g_image[100] ^= 0x01u;
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_ERROR_DIGEST);
    g_image[100] ^= 0x01u;
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_OK);

    /* Tampering the pinned digest itself is also a refusal. */
    record.digest[0] ^= 0x80u;
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_ERROR_DIGEST);

    /* A byte beyond image_size is outside the pin and must not matter. */
    record = wt_make_record(2u, 512u);
    g_image[900] ^= 0xFFu;
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_OK);
    g_image[900] ^= 0xFFu;
}

static void wt_test_version(void)
{
    wt_guest_measurement_t record = wt_make_record(1u, 512u);

    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 2u),
                  WT_GUEST_VERIFY_ERROR_VERSION);
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 0u),
                  WT_GUEST_VERIFY_OK);
}

static void wt_test_layout(void)
{
    wt_guest_measurement_t record = wt_make_record(1u, 512u);

    record.image_size = 0u;
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_ERROR_LAYOUT);

    record.image_size = (uint32_t)sizeof(g_image) + 1u;
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_ERROR_LAYOUT);
}

static void wt_test_arguments(void)
{
    wt_guest_measurement_t record = wt_make_record(1u, 512u);

    EXPECT_RESULT(wt_guest_verify_image(NULL, sizeof(g_image), &record, 1u),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_verify_image(g_image, 0u, &record, 1u),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_verify_image(g_image, sizeof(g_image), NULL, 1u),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
}

static void wt_test_measurement_table(void)
{
    wt_guest_measurement_t record = wt_make_record(3u, 512u);
    const wt_guest_measurement_t* stored;
    const char* name = NULL;
    size_t i;

    wt_guest_measurement_reset();
    EXPECT_TRUE(wt_guest_measurement_count() == 0u);
    EXPECT_TRUE(wt_guest_measurement_get(0u, &name) == NULL);

    EXPECT_RESULT(wt_guest_measurement_record(&record, "guest-a"),
                  WT_GUEST_VERIFY_OK);
    EXPECT_TRUE(wt_guest_measurement_count() == 1u);
    stored = wt_guest_measurement_get(0u, &name);
    EXPECT_TRUE(stored != NULL);
    EXPECT_TRUE(stored != NULL &&
                memcmp(stored->digest, record.digest,
                       WT_GUEST_MEAS_DIGEST_SIZE) == 0);
    EXPECT_TRUE(stored != NULL && stored->version == 3u);
    EXPECT_TRUE(name != NULL && strcmp(name, "guest-a") == 0);

    EXPECT_RESULT(wt_guest_measurement_record(NULL, "guest-a"),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_measurement_record(&record, NULL),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);

    /* A name longer than the slot is truncated, never overflowed. */
    EXPECT_RESULT(wt_guest_measurement_record(&record,
                  "guest-name-way-beyond-the-slot"),
                  WT_GUEST_VERIFY_OK);
    stored = wt_guest_measurement_get(1u, &name);
    EXPECT_TRUE(stored != NULL && name != NULL &&
                strlen(name) == WT_GUEST_MEAS_NAME_LEN - 1u);

    for (i = wt_guest_measurement_count();
         i < WT_GUEST_MEAS_MAX_RECORDS; i++) {
        EXPECT_RESULT(wt_guest_measurement_record(&record, "guest-x"),
                      WT_GUEST_VERIFY_OK);
    }
    EXPECT_RESULT(wt_guest_measurement_record(&record, "guest-x"),
                  WT_GUEST_VERIFY_ERROR_CAPACITY);

    wt_guest_measurement_reset();
    EXPECT_TRUE(wt_guest_measurement_count() == 0u);
}

/* WT-SYS-0002 flash write-protection predicate over the production STM32H5
 * layout: 8 KiB sectors, 4 sectors per WRP group, a 0 bit meaning protected.
 * guest0 = 0x080A0000+0x40000 (sectors 80-111, groups 20-27); guest1 =
 * 0x080E0000+0x20000 (sectors 112-127, groups 28-31). */
#define WT_TEST_BANK1_BASE 0x08000000u
#define WT_TEST_SECTOR     0x2000u
#define WT_TEST_GROUP      4u
#define WT_TEST_GUEST0_BASE 0x080A0000u
#define WT_TEST_GUEST0_SIZE 0x40000u
#define WT_TEST_GUEST1_BASE 0x080E0000u
#define WT_TEST_GUEST1_SIZE 0x20000u

static void wt_test_flash_wrp(void)
{
    /* Both guests protected: groups 20-31 cleared (0x000FFFFF). */
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu, WT_TEST_GUEST0_BASE,
                  WT_TEST_GUEST0_SIZE, WT_TEST_BANK1_BASE, WT_TEST_SECTOR,
                  WT_TEST_GROUP), WT_GUEST_VERIFY_OK);
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu, WT_TEST_GUEST1_BASE,
                  WT_TEST_GUEST1_SIZE, WT_TEST_BANK1_BASE, WT_TEST_SECTOR,
                  WT_TEST_GROUP), WT_GUEST_VERIFY_OK);

    /* Factory default: all sectors open (0xFFFFFFFF) fails both closed. */
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0xFFFFFFFFu, WT_TEST_GUEST0_BASE,
                  WT_TEST_GUEST0_SIZE, WT_TEST_BANK1_BASE, WT_TEST_SECTOR,
                  WT_TEST_GROUP), WT_GUEST_VERIFY_ERROR_WRP);
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0xFFFFFFFFu, WT_TEST_GUEST1_BASE,
                  WT_TEST_GUEST1_SIZE, WT_TEST_BANK1_BASE, WT_TEST_SECTOR,
                  WT_TEST_GROUP), WT_GUEST_VERIFY_ERROR_WRP);

    /* One group of guest0 (bit 25) left open fails guest0 but not guest1. */
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu | (1u << 25),
                  WT_TEST_GUEST0_BASE, WT_TEST_GUEST0_SIZE, WT_TEST_BANK1_BASE,
                  WT_TEST_SECTOR, WT_TEST_GROUP), WT_GUEST_VERIFY_ERROR_WRP);
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu | (1u << 25),
                  WT_TEST_GUEST1_BASE, WT_TEST_GUEST1_SIZE, WT_TEST_BANK1_BASE,
                  WT_TEST_SECTOR, WT_TEST_GROUP), WT_GUEST_VERIFY_OK);

    /* Boundary: guest1's top group (bit 31) open fails guest1 closed. */
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu | (1u << 31),
                  WT_TEST_GUEST1_BASE, WT_TEST_GUEST1_SIZE, WT_TEST_BANK1_BASE,
                  WT_TEST_SECTOR, WT_TEST_GROUP), WT_GUEST_VERIFY_ERROR_WRP);

    /* Argument abuse: zero size, base below the bank, zero geometry. */
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu, WT_TEST_GUEST0_BASE,
                  0u, WT_TEST_BANK1_BASE, WT_TEST_SECTOR, WT_TEST_GROUP),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu,
                  WT_TEST_BANK1_BASE - 0x2000u, WT_TEST_GUEST0_SIZE,
                  WT_TEST_BANK1_BASE, WT_TEST_SECTOR, WT_TEST_GROUP),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x000FFFFFu, WT_TEST_GUEST0_BASE,
                  WT_TEST_GUEST0_SIZE, WT_TEST_BANK1_BASE, 0u, WT_TEST_GROUP),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);

    /* A window running past the 32-group bank map fails closed as layout. */
    EXPECT_RESULT(wt_guest_flash_wrp_covers(0x00000000u, WT_TEST_BANK1_BASE,
                  0x100001u, WT_TEST_BANK1_BASE, WT_TEST_SECTOR, WT_TEST_GROUP),
                  WT_GUEST_VERIFY_ERROR_LAYOUT);
}

/* WT-SYS-0002 descriptor-fenced predicate over the MIMXRT700 XSPI0 NOR layout:
 * guest0 = 0x28080000+0x80000, guest1 = 0x28100000+0x40000, fenced by one
 * 64 KiB-granular FRAD [0x28080000, 0x2813FFFF]. */
#define WT_TEST_NOR_BASE    0x28000000u
#define WT_TEST_NOR_LAST    0x2BFFFFFFu
#define WT_TEST_RT_G0_BASE  0x28080000u
#define WT_TEST_RT_G0_SIZE  0x80000u
#define WT_TEST_RT_G1_BASE  0x28100000u
#define WT_TEST_RT_G1_SIZE  0x40000u
#define WT_TEST_FRADS       8u

static void wt_frad_set(wt_frad_region_t* region, uint32_t start, uint32_t end,
                        uint32_t write_acp, uint32_t valid, uint32_t locked)
{
    region->start = start;
    region->end = end;
    region->write_acp = write_acp;
    region->valid = valid;
    region->locked = locked;
}

/* The planned wolfBoot layout: boot root, secure image, guest fence, rest. */
static void wt_frad_armed(wt_frad_region_t* regions)
{
    uint32_t i;

    (void)memset(regions, 0, sizeof(wt_frad_region_t) * WT_TEST_FRADS);
    wt_frad_set(&regions[0], WT_TEST_NOR_BASE, 0x2803FFFFu, 0u, 1u, 1u);
    wt_frad_set(&regions[1], 0x28040000u, 0x2807FFFFu, 3u, 1u, 1u);
    wt_frad_set(&regions[2], 0x28080000u, 0x2813FFFFu, 0u, 1u, 1u);
    wt_frad_set(&regions[3], 0x28140000u, WT_TEST_NOR_LAST, 3u, 1u, 1u);
    for (i = 4u; i < WT_TEST_FRADS; i++) {
        wt_frad_set(&regions[i], 0u, 0u, 0u, 0u, 1u);
    }
}

static void wt_test_flash_frad(void)
{
    wt_frad_region_t regions[WT_TEST_FRADS];
    wt_frad_region_t reversed[WT_TEST_FRADS];
    uint32_t i;

    wt_frad_armed(regions);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE), WT_GUEST_VERIFY_OK);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE), WT_GUEST_VERIFY_OK);

    /* A single granule at the fence start is covered. */
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, 0x10000u), WT_GUEST_VERIFY_OK);

    /* Descriptor order does not matter. */
    for (i = 0u; i < WT_TEST_FRADS; i++) {
        reversed[i] = regions[WT_TEST_FRADS - 1u - i];
    }
    EXPECT_RESULT(wt_guest_flash_frad_covers(reversed, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE), WT_GUEST_VERIFY_OK);

    /* Today's unfenced wolfBoot layout: everything above the boot root is
     * writable, so both guests fail closed. */
    (void)memset(regions, 0, sizeof(regions));
    wt_frad_set(&regions[0], WT_TEST_NOR_BASE, 0x2803FFFFu, 0u, 1u, 1u);
    wt_frad_set(&regions[1], 0x28040000u, WT_TEST_NOR_LAST, 3u, 1u, 1u);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);

    /* The fence itself unlocked, invalid, or write-granting fails closed. */
    wt_frad_armed(regions);
    regions[2].locked = 0u;
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);
    wt_frad_armed(regions);
    regions[2].valid = 0u;
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);
    wt_frad_armed(regions);
    regions[2].write_acp = 1u;
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);

    /* The fence split across two chained descriptors still covers; a 64 KiB
     * gap between them fails the guest it lands in and only that guest. */
    wt_frad_armed(regions);
    wt_frad_set(&regions[2], 0x28080000u, 0x280FFFFFu, 0u, 1u, 1u);
    wt_frad_set(&regions[4], 0x28100000u, 0x2813FFFFu, 0u, 1u, 1u);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE), WT_GUEST_VERIFY_OK);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE), WT_GUEST_VERIFY_OK);
    regions[4].start = 0x28110000u;
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE), WT_GUEST_VERIFY_OK);

    /* A valid write-granting descriptor overlapping one guest fails that guest
     * even though the fence also covers it. */
    wt_frad_armed(regions);
    wt_frad_set(&regions[5], 0x280C0000u, 0x280CFFFFu, 3u, 1u, 1u);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE),
                  WT_GUEST_VERIFY_ERROR_WRP);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE), WT_GUEST_VERIFY_OK);

    /* A window one byte past the fence reaches the writable rest of NOR. */
    wt_frad_armed(regions);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G1_BASE, WT_TEST_RT_G1_SIZE + 1u),
                  WT_GUEST_VERIFY_ERROR_WRP);

    /* Argument abuse: NULL, no descriptors, empty or wrapping window. */
    EXPECT_RESULT(wt_guest_flash_frad_covers(NULL, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, 0u,
                  WT_TEST_RT_G0_BASE, WT_TEST_RT_G0_SIZE),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  WT_TEST_RT_G0_BASE, 0u), WT_GUEST_VERIFY_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_guest_flash_frad_covers(regions, WT_TEST_FRADS,
                  UINTPTR_MAX - 0x10u, 0x100u),
                  WT_GUEST_VERIFY_ERROR_ARGUMENT);
}

int main(void)
{
    size_t i;

    for (i = 0u; i < sizeof(g_image); i++) {
        g_image[i] = (uint8_t)(i * 7u);
    }

    wt_test_accept();
    wt_test_tamper();
    wt_test_version();
    wt_test_layout();
    wt_test_arguments();
    wt_test_measurement_table();
    wt_test_flash_wrp();
    wt_test_flash_frad();

    if (g_failures != 0u) {
        (void)fprintf(stderr, "guest-verify checks failed: %u/%u\n",
                      g_failures, g_checks);
        return 1;
    }
    (void)printf("WT-SYS-0002/WT-FFM-0049 guest-verify checks passed: %u\n",
                 g_checks);
    return 0;
}
