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

/* The MCXN947 life cycle mapping wolfBoot hands wolfTrust, tested from the
 * copy in the carried patch: only an agreeing OEM state maps to PSA, and no
 * fault or open-debug state reads as SECURED. */

#include "mcxn_lifecycle.h"

#include <stdint.h>
#include <stdio.h>

static int checks;
static int failures;

#define EXPECT_LC(actual, expected) \
    do { \
        uint32_t a_ = (actual); \
        uint32_t e_ = (expected); \
        checks++; \
        if (a_ != e_) { \
            (void)fprintf(stderr, "line %d: expected 0x%04x, got 0x%04x\n", \
                          __LINE__, (unsigned)e_, (unsigned)a_); \
            failures++; \
        } \
    } while (0)

/* DAUTHSTATUS: each 2-bit field is 0b11 enabled, 0b10 implemented and disabled. */
#define DAUTH_CLOSED    0xAAu
#define DAUTH_NS_ONLY   0xABu
#define DAUTH_NSNID     0xAEu
#define DAUTH_SECURE    0xBAu
#define DAUTH_SNID      0xEAu
#define DAUTH_ALL       0xFFu

static void test_state_table(void)
{
    uint32_t lc;

    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_OPEN, MCXN_LC_OEM_OPEN),
              0x1000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_SECURE_WORLD_CLOSED,
              MCXN_LC_OEM_SECURE_WORLD_CLOSED), 0x2000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_CLOSED,
              MCXN_LC_OEM_CLOSED), 0x3000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_LOCKED,
              MCXN_LC_OEM_LOCKED), 0x3000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_FIELD_RETURN,
              MCXN_LC_OEM_FIELD_RETURN), 0x6000u);

    /* NXP-internal, blank, shredded, and every unlisted code are unknown. */
    for (lc = 0u; lc <= 0xFFu; lc++) {
        if (lc == MCXN_LC_OEM_OPEN || lc == MCXN_LC_OEM_SECURE_WORLD_CLOSED ||
                lc == MCXN_LC_OEM_CLOSED || lc == MCXN_LC_OEM_LOCKED ||
                lc == MCXN_LC_OEM_FIELD_RETURN) {
            continue;
        }
        EXPECT_LC(mcxn_lc_to_psa_lifecycle(lc, lc), 0x0000u);
    }
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_NXP_BLANK, MCXN_LC_NXP_BLANK),
              0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_NXP_FAB, MCXN_LC_NXP_FAB),
              0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_NXP_DEV, MCXN_LC_NXP_DEV),
              0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_NXP_FIELD_RETURN,
              MCXN_LC_NXP_FIELD_RETURN), 0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_SHREDDED, MCXN_LC_SHREDDED),
              0x0000u);
}

static void test_redundancy(void)
{
    /* The duplicate must agree, and nothing above the state byte may be set. */
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_OPEN,
              MCXN_LC_OEM_SECURE_WORLD_CLOSED), 0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_CLOSED, MCXN_LC_OEM_OPEN),
              0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(0x00000103u, 0x00000103u), 0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(0xFFFC0003u, 0xFFFC0003u), 0x0000u);
    EXPECT_LC(mcxn_lc_to_psa_lifecycle(MCXN_LC_OEM_OPEN, 0x00010003u),
              0x0000u);
}

static void test_debug_status(void)
{
    uint32_t lc = MCXN_LC_OEM_CLOSED;

    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, DAUTH_CLOSED), 0x3000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, DAUTH_NS_ONLY), 0x4000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, DAUTH_NSNID), 0x4000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, DAUTH_SECURE), 0x5000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, DAUTH_SNID), 0x5000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, DAUTH_ALL), 0x5000u);
    /* A malformed field (00 or 01) voids the whole register. */
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, 0x00u), 0x0000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, 0xA9u), 0x0000u);
    EXPECT_LC(mcxn_attestation_lifecycle(lc, lc, 0x6Au), 0x0000u);
    /* Debug state only refines SECURED; the open states ignore it. */
    EXPECT_LC(mcxn_attestation_lifecycle(MCXN_LC_OEM_OPEN, MCXN_LC_OEM_OPEN,
              0x00u), 0x1000u);
    EXPECT_LC(mcxn_attestation_lifecycle(MCXN_LC_OEM_SECURE_WORLD_CLOSED,
              MCXN_LC_OEM_SECURE_WORLD_CLOSED, DAUTH_ALL), 0x2000u);
    EXPECT_LC(mcxn_attestation_lifecycle(MCXN_LC_OEM_FIELD_RETURN,
              MCXN_LC_OEM_FIELD_RETURN, DAUTH_ALL), 0x6000u);
    EXPECT_LC(mcxn_attestation_lifecycle(MCXN_LC_OEM_LOCKED,
              MCXN_LC_OEM_LOCKED, DAUTH_CLOSED), 0x3000u);
}

/* The OTP fuse map SPSDK carries for the part (fuses.json, register
 * LIFE_CYCLE, index 1): LIFECYCLE[7:0] at bit 0 and its duplicate at bit 24
 * use the same codes the ROM reflects into SYSCON, and every ladder step only
 * sets fuse bits, which is what makes it one way. */
#define FUSE_LC_DEVELOP           3u
#define FUSE_LC_DEVELOP2          7u
#define FUSE_LC_IN_FIELD          15u
#define FUSE_LC_IN_FIELD_LOCKED   207u
#define FUSE_LC_FIELD_RETURN_OEM  31u
#define FUSE_LC_WORD(lc)          ((uint32_t)(lc) | ((uint32_t)(lc) << 24))

static void test_fuse_map(void)
{
    static const uint32_t ladder[][2] = {
        { MCXN_LC_OEM_OPEN, MCXN_LC_OEM_SECURE_WORLD_CLOSED },
        { MCXN_LC_OEM_SECURE_WORLD_CLOSED, MCXN_LC_OEM_CLOSED },
        { MCXN_LC_OEM_CLOSED, MCXN_LC_OEM_LOCKED },
        { MCXN_LC_OEM_CLOSED, MCXN_LC_OEM_FIELD_RETURN },
    };
    size_t i;

    EXPECT_LC(MCXN_LC_OEM_OPEN, FUSE_LC_DEVELOP);
    EXPECT_LC(MCXN_LC_OEM_SECURE_WORLD_CLOSED, FUSE_LC_DEVELOP2);
    EXPECT_LC(MCXN_LC_OEM_CLOSED, FUSE_LC_IN_FIELD);
    EXPECT_LC(MCXN_LC_OEM_LOCKED, FUSE_LC_IN_FIELD_LOCKED);
    EXPECT_LC(MCXN_LC_OEM_FIELD_RETURN, FUSE_LC_FIELD_RETURN_OEM);
    EXPECT_LC(FUSE_LC_WORD(MCXN_LC_OEM_SECURE_WORLD_CLOSED), 0x07000007u);
    EXPECT_LC(FUSE_LC_WORD(MCXN_LC_OEM_CLOSED), 0x0F00000Fu);
    for (i = 0; i < sizeof(ladder) / sizeof(ladder[0]); i++) {
        EXPECT_LC(FUSE_LC_WORD(ladder[i][0]) & ~FUSE_LC_WORD(ladder[i][1]),
                  0u);
        EXPECT_LC(mcxn_lc_to_psa_lifecycle(ladder[i][1], ladder[i][1]) != 0u,
                  1u);
    }
}

int main(void)
{
    test_state_table();
    test_redundancy();
    test_debug_status();
    test_fuse_map();
    printf("%s: %d checks, %d failures\n",
           (failures == 0) ? "PASS" : "FAIL", checks, failures);
    return (failures == 0) ? 0 : 1;
}
