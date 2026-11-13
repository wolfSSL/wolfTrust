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

#include "wolftrust/spm.h"
#include "wolftrust_manifest_generated.h"

#include <stdio.h>

static unsigned int g_checks;
static unsigned int g_failures;

#define EXPECT_RESULT(actual, expected) \
    do { \
        int actual_result = (actual); \
        int expected_result = (expected); \
        g_checks++; \
        if (actual_result != expected_result) { \
            (void)fprintf(stderr, \
                "line %d: expected %d, received %d\n", \
                __LINE__, expected_result, actual_result); \
            g_failures++; \
        } \
    } while (0)

static void wt_test_valid_generated_manifest(void)
{
    const uint32_t supported_features = WT_MANIFEST_FEATURE_IPC |
                                        WT_MANIFEST_FEATURE_STATELESS;
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    wt_spm_t spm;

    EXPECT_RESULT(wt_spm_init(&spm, manifest, supported_features,
                              manifest->profile_capabilities),
                  WT_SPM_VALID);
    EXPECT_RESULT(wt_spm_ready(&spm), true);
    EXPECT_RESULT(wt_spm_manifest(&spm) == manifest, true);
    EXPECT_RESULT(wt_spm_validation_result(&spm), WT_MANIFEST_VALID);
}

static void wt_test_invalid_manifest_fails_closed(void)
{
    const uint32_t supported_features = WT_MANIFEST_FEATURE_IPC |
                                        WT_MANIFEST_FEATURE_STATELESS;
    const wt_system_manifest_t* generated = wt_generated_manifest_get();
    wt_system_manifest_t invalid = *generated;
    wt_spm_t spm;

    invalid.format_version++;
    EXPECT_RESULT(wt_spm_init(&spm, &invalid, supported_features,
                              generated->profile_capabilities),
                  WT_SPM_ERROR_VALIDATION);
    EXPECT_RESULT(wt_spm_ready(&spm), false);
    EXPECT_RESULT(wt_spm_manifest(&spm) == NULL, true);
    EXPECT_RESULT(wt_spm_validation_result(&spm), WT_MANIFEST_ERROR_FORMAT);

    EXPECT_RESULT(wt_spm_init(&spm, NULL, supported_features,
                              generated->profile_capabilities),
                  WT_SPM_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_spm_ready(&spm), false);
    EXPECT_RESULT(wt_spm_manifest(&spm) == NULL, true);
}

static void wt_test_null_context(void)
{
    const uint32_t supported_features = WT_MANIFEST_FEATURE_IPC;

    EXPECT_RESULT(wt_spm_init(NULL, wt_generated_manifest_get(),
                              supported_features,
                              wt_generated_manifest_get()->profile_capabilities),
                  WT_SPM_ERROR_ARGUMENT);
    EXPECT_RESULT(wt_spm_ready(NULL), false);
    EXPECT_RESULT(wt_spm_manifest(NULL) == NULL, true);
    EXPECT_RESULT(wt_spm_validation_result(NULL), WT_MANIFEST_ERROR_ARGUMENT);
}

static void wt_test_generated_manifest_binds_without_validator(void)
{
    const uint32_t supported_features = WT_MANIFEST_FEATURE_IPC;
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    wt_system_manifest_t invalid = *manifest;
    wt_spm_t spm;

    EXPECT_RESULT(wt_spm_init_generated(&spm, supported_features),
                  WT_SPM_VALID);
    EXPECT_RESULT(wt_spm_ready(&spm), true);
    EXPECT_RESULT(wt_spm_manifest(&spm) == manifest, true);
    EXPECT_RESULT(wt_spm_validation_result(&spm), WT_MANIFEST_VALID);

    EXPECT_RESULT(wt_spm_init_generated(NULL, supported_features),
                  WT_SPM_ERROR_ARGUMENT);

    /* The public initializer keeps validating in a default build. */
    invalid.format_version++;
    EXPECT_RESULT(wt_spm_init(&spm, &invalid, supported_features,
                              manifest->profile_capabilities),
                  WT_SPM_ERROR_VALIDATION);
    EXPECT_RESULT(wt_spm_ready(&spm), false);
}

int main(void)
{
    wt_test_valid_generated_manifest();
    wt_test_invalid_manifest_fails_closed();
    wt_test_null_context();
    wt_test_generated_manifest_binds_without_validator();

    if (g_failures != 0U) {
        (void)fprintf(stderr, "%u of %u SPM checks failed\n",
                      g_failures, g_checks);
        return 1;
    }

    (void)printf("SPM bootstrap checks passed: %u\n", g_checks);
    return 0;
}
