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

/* The boot path retains one boot seed and restores attestation from it. */

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "../../../src/boot.c"

static jmp_buf g_panic;
static int g_failures;
static int g_handoff_ret;
static int g_rng_ret;
static int g_attest_ret;
static unsigned g_attest_calls;
static uint8_t g_seen_seed[WT_ATTEST_BOOT_SEED_SIZE];
static uint8_t g_rng_fill;

void wt_monitor_init(void) {}
void wt_monitor_start(void) {}
void wt_co_init(void) {}
void wt_boot_handoff_clear(void) {}
void wt_hsm_set_boot_lifecycle(uint32_t lifecycle) { (void)lifecycle; }
int wt_native_init(void) { return 0; }
int wt_hsm_rollback_enforce(uint32_t image_version)
{
    (void)image_version;
    return 0;
}
int wt_hsm_attest_bootstrap(void) { return WH_ERROR_OK; }
int wt_ffm_boot_start_sched(void) { return WT_FFM_SUCCESS; }
wt_ffm_runtime_t* wt_ffm_boot_runtime_mut(void) { return NULL; }
void wt_ffm_set_lifecycle(wt_ffm_runtime_t* runtime, uint32_t lifecycle)
{
    (void)runtime;
    (void)lifecycle;
}

void wt_platform_panic(void)
{
    longjmp(g_panic, 1);
}

int wt_boot_handoff_consume(wt_boot_handoff_t* handoff)
{
    (void)memset(handoff, 0, sizeof(*handoff));
    return g_handoff_ret;
}

int wolftrust_rng_generate_block_direct(unsigned char* output,
                                        unsigned int sz)
{
    (void)memset(output, g_rng_fill, sz);
    return g_rng_ret;
}

int wt_initial_attest_init(const wt_boot_handoff_t* handoff,
    const uint8_t bootSeed[WT_ATTEST_BOOT_SEED_SIZE])
{
    (void)handoff;
    g_attest_calls++;
    (void)memcpy(g_seen_seed, bootSeed, sizeof(g_seen_seed));
    return g_attest_ret;
}

static void check(int ok, const char* what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_failures++;
    }
}

static void boot(int handoff_ret, int rng_ret, int attest_ret, uint8_t fill)
{
    g_handoff_ret = handoff_ret;
    g_rng_ret = rng_ret;
    g_attest_ret = attest_ret;
    g_rng_fill = fill;
    g_attest_calls = 0U;
    g_wt_attest_degraded = 0U;
    g_wt_boot_seed_valid = 0;
    g_wt_boot_handoff_ret = -1;
    (void)memset(g_seen_seed, 0, sizeof(g_seen_seed));
    if (setjmp(g_panic) == 0) {
        wt_boot_run();
    }
}

static int seed_is(uint8_t fill)
{
    size_t i;

    for (i = 0U; i < sizeof(g_seen_seed); i++) {
        if (g_seen_seed[i] != fill) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    boot(0, 0, WT_ATTEST_SUCCESS, 0x5AU);
    check(g_attest_calls == 1U && seed_is(0x5AU) && g_wt_attest_degraded == 0U,
          "boot initializes attestation from the generated seed");
    g_rng_fill = 0xC3U;
    (void)memset(g_seen_seed, 0, sizeof(g_seen_seed));
    check(wt_boot_restore_attestation() == WT_ATTEST_SUCCESS &&
          g_attest_calls == 2U && seed_is(0x5AU),
          "a partition restart restores attestation with the retained seed");

    boot(0, -1, WT_ATTEST_SUCCESS, 0x5AU);
    check(g_attest_calls == 0U && g_wt_attest_degraded == 1U,
          "an RNG failure degrades attestation without initializing it");
    check(wt_boot_restore_attestation() == WT_ATTEST_ERROR_NOT_READY &&
          g_attest_calls == 0U,
          "a restart after an RNG failure stays not ready");

    boot(-1, 0, WT_ATTEST_SUCCESS, 0x5AU);
    check(g_attest_calls == 0U &&
          wt_boot_restore_attestation() == WT_ATTEST_ERROR_NOT_READY,
          "a missing handoff never restores attestation");

    boot(0, 0, WT_ATTEST_ERROR_NOT_READY, 0x5AU);
    check(g_attest_calls == 1U && g_wt_attest_degraded == 1U,
          "an attestation init failure marks the boot degraded");

    return (g_failures == 0) ? 0 : 1;
}
