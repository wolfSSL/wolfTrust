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

/* The MIMXRT700 life cycle mapping wolfBoot hands wolfTrust, tested from the
 * copy inside the carried wolfBoot patch: only an agreeing, known OTP life
 * cycle maps to a PSA state, and no fault or debug state reads as SECURED. */

#include "imx_rt7xx_lifecycle.h"

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

    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_DEVELOP,
              IMX_RT7XX_LC_DEVELOP), 0x1000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_DEVELOP2,
              IMX_RT7XX_LC_DEVELOP2), 0x2000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD), 0x3000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_IN_FIELD_LOCKED,
              IMX_RT7XX_LC_IN_FIELD_LOCKED), 0x3000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_IN_FIELD_RETURN,
              IMX_RT7XX_LC_IN_FIELD_RETURN), 0x6000u);

    /* NXP-internal, blank, bricked, and every unlisted code are unknown. */
    for (lc = 0u; lc <= 0xFFu; lc++) {
        if (lc == IMX_RT7XX_LC_DEVELOP || lc == IMX_RT7XX_LC_DEVELOP2 ||
                lc == IMX_RT7XX_LC_IN_FIELD ||
                lc == IMX_RT7XX_LC_IN_FIELD_LOCKED ||
                lc == IMX_RT7XX_LC_IN_FIELD_RETURN) {
            continue;
        }
        EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(lc, lc), 0x0000u);
    }
}

static void test_redundancy(void)
{
    /* The redundant copy must agree; a single flipped byte never promotes. */
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_DEVELOP), 0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(IMX_RT7XX_LC_DEVELOP,
              IMX_RT7XX_LC_IN_FIELD), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              0x00u, DAUTH_CLOSED), 0x0000u);

    /* A0/A1 bit-protection copies in bits 16-23 must agree with each byte. */
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x000F000Fu, 0x000F000Fu),
              0x3000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(0x000F000Fu, 0x000F000Fu,
              DAUTH_CLOSED), 0x3000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x0003000Fu, 0x000F000Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x000F000Fu, 0x0007000Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(0x0003000Fu, 0x0003000Fu,
              DAUTH_CLOSED), 0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x000F000Fu, 0x0000000Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x0000000Fu, 0x000F000Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x00030007u, 0x00030007u),
              0x0000u);

    /* Bits 8-15 and 24-31 are reserved on every revision. */
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x0000010Fu, 0x0000000Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x0000000Fu, 0x0000800Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_lc_to_psa_lifecycle(0x0100000Fu, 0x0100000Fu),
              0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(0x800F000Fu, 0x000F000Fu,
              DAUTH_CLOSED), 0x0000u);
}

static void test_debug_refinement(void)
{
    /* A secured part with debug closed attests SECURED. */
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, DAUTH_CLOSED), 0x3000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD_LOCKED,
              IMX_RT7XX_LC_IN_FIELD_LOCKED, DAUTH_CLOSED), 0x3000u);

    /* Any Secure debug open downgrades to recoverable PSA RoT debug. */
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, DAUTH_SECURE), 0x5000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, DAUTH_SNID), 0x5000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD_LOCKED,
              IMX_RT7XX_LC_IN_FIELD_LOCKED, DAUTH_ALL), 0x5000u);

    /* Only Non-secure debug open is non-PSA-RoT debug. */
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, DAUTH_NS_ONLY), 0x4000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, DAUTH_NSNID), 0x4000u);

    /* Not implemented, reserved, or mixed encodings never prove debug closed. */
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0x00u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0x55u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0x9Au), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0xA0u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0x20u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0x03u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0xA3u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD,
              IMX_RT7XX_LC_IN_FIELD, 0xF8u), 0x0000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD_LOCKED,
              IMX_RT7XX_LC_IN_FIELD_LOCKED, 0x3Bu), 0x0000u);

    /* Debug state never refines an open, provisioning, or returned part. */
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_DEVELOP,
              IMX_RT7XX_LC_DEVELOP, DAUTH_ALL), 0x1000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_DEVELOP2,
              IMX_RT7XX_LC_DEVELOP2, DAUTH_ALL), 0x2000u);
    EXPECT_LC(imx_rt7xx_attestation_lifecycle(IMX_RT7XX_LC_IN_FIELD_RETURN,
              IMX_RT7XX_LC_IN_FIELD_RETURN, DAUTH_ALL), 0x6000u);
}

int main(void)
{
    test_state_table();
    test_redundancy();
    test_debug_refinement();

    if (failures != 0) {
        (void)fprintf(stderr, "rt700 lifecycle checks failed: %d/%d\n",
                      failures, checks);
        return 1;
    }
    (void)printf("rt700 lifecycle checks passed: %d\n", checks);
    return 0;
}
