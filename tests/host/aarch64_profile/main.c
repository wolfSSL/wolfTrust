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

/* WT-PORT-0009 (AArch64 rows): a port claims security-state isolation, and
 * so any isolation level, only when its memory map fences the Secure bands
 * from the Normal world, and its own manifests validate against that claim. */

#include "wolftrust/spm.h"
#include "wolftrust/partition.h"
#include "wolftrust_manifest_generated.h"

#include <stdio.h>

#ifndef EXPECT_NS_FENCE
#error "EXPECT_NS_FENCE must name the port's expected Normal-world fence"
#endif

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s: %s\n", VARIANT_NAME, what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s: %s\n", VARIANT_NAME, what);
    }
}

void wt_el3_puts(const char* s)
{
    (void)s;
}

int main(void)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    const wt_profile_capabilities_t* platform =
        wt_partitions_profile_capabilities();
    wt_system_manifest_t claim;
    wt_profile_capabilities_t claim_caps;
    wt_spm_t spm;
    unsigned int level;
    int ok;

    check(wt_spm_init(&spm, manifest, WT_MANIFEST_FEATURE_IPC, platform) ==
              WT_SPM_VALID && wt_spm_ready(&spm),
          "the port's manifest validates against the port's own claim");

    if (EXPECT_NS_FENCE == 1) {
        check((platform->capabilities & WT_CAPABILITY_SECURITY_STATE) != 0U,
              "a fenced port claims security-state isolation");
        check(manifest->isolation_profile == WT_ISOLATION_PROFILE_LEVEL_3,
              "a fenced port's manifest declares isolation Level 3");
    }
    else {
        check((platform->capabilities & WT_CAPABILITY_SECURITY_STATE) == 0U,
              "an unfenced port claims no security-state isolation");
        check(manifest->isolation_profile ==
                  WT_ISOLATION_PROFILE_SERVICE_ONLY &&
                  (manifest->profile_capabilities->capabilities &
                   WT_CAPABILITY_SECURITY_STATE) == 0U,
              "an unfenced port's manifest declares no isolation level");

        claim = *manifest;
        claim_caps = *manifest->profile_capabilities;
        claim_caps.capabilities |= WT_CAPABILITY_SECURITY_STATE;
        claim.profile_capabilities = &claim_caps;
        ok = 1;
        for (level = (unsigned int)WT_ISOLATION_PROFILE_LEVEL_1;
                level <= (unsigned int)WT_ISOLATION_PROFILE_LEVEL_3; level++) {
            claim.isolation_profile = (wt_isolation_profile_t)level;
            if (wt_spm_init(&spm, &claim, WT_MANIFEST_FEATURE_IPC,
                            platform) != WT_SPM_ERROR_VALIDATION ||
                    wt_spm_ready(&spm)) {
                ok = 0;
            }
        }
        check(ok, "an isolation-level claim on an unfenced port fails closed");
    }

    printf("%s: %d checks, %d failures\n", VARIANT_NAME, checks, failures);
    return (failures == 0) ? 0 : 1;
}
