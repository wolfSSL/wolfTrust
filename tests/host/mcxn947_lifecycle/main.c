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
 * copy inside the carried wolfBoot patch: only an agreeing OEM life cycle
 * maps to a PSA state, no NXP-internal, blank or shredded state does, and no
 * fault or debug state reads as SECURED. */

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

int main(void)
{
    test_state_table();
    test_redundancy();
    test_debug_status();
    printf("%s: %d checks, %d failures\n",
           (failures == 0) ? "PASS" : "FAIL", checks, failures);
    return (failures == 0) ? 0 : 1;
}
