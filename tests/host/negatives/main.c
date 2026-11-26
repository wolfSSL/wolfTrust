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

/* Vault storage-face security negatives (WT-FFM-0044 / WT-FFM-0048). Keys no
 * longer live in the vault — they are held by the wolfHSM server keystore
 * reached through the SERVICE_HSM relay, and their cross-client isolation is
 * proven in tests/host/keystore_isolation. What remains here is the vault's
 * own storage face: every object is namespaced by the SPM-stamped caller
 * identity (the `owner` argument), which no partition can forge on target, so
 * these host calls with distinct owners model distinct partitions:
 *
 *   N1  a different sub_owner in the same owner is disjoint                0044
 *   N2  a forged sub_owner never crosses to another owner                 0044
 *   N3  a sealed object is invisible cross-owner and rolls back to auth   0048
 *   N4  the internal KEY / SEALED label flags cannot be forged from a
 *       storage SET, nor can an unknown flag bit be passed                0046/0048
 */

#include "wolftrust/services/vault_service.h"
#include "wolftrust/services/hsm.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include <stdio.h>
#include <string.h>

#define OWNER_A (-1)
#define OWNER_B (-2)

#define RAMSIM_SIZE   (64 * 1024)
#define RAMSIM_SECTOR 4096
#define RAMSIM_PAGE   8

static uint8_t g_flash_memory[RAMSIM_SIZE];
static whNvmContext g_nvm_ctx;

static int g_failures;

static void check(int ok, const char* what)
{
    if (ok) {
        (void)printf("PASS: %s\n", what);
    } else {
        (void)printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static int nvm_up(void)
{
    whFlashRamsimCfg ramsim_cfg;
    static whFlashRamsimCtx ramsim_ctx;
    static const whFlashCb ramsim_cb[1] = {WH_FLASH_RAMSIM_CB};
    whNvmFlashConfig nvm_flash_cfg;
    static whNvmFlashContext nvm_flash_ctx;
    static const whNvmCb nvm_cb[1] = {WH_NVM_FLASH_CB};
    whNvmConfig nvm_cfg;

    (void)memset(g_flash_memory, 0xFF, sizeof(g_flash_memory));
    (void)memset(&ramsim_cfg, 0, sizeof(ramsim_cfg));
    ramsim_cfg.memory = g_flash_memory;
    ramsim_cfg.size = RAMSIM_SIZE;
    ramsim_cfg.sectorSize = RAMSIM_SECTOR;
    ramsim_cfg.pageSize = RAMSIM_PAGE;
    ramsim_cfg.erasedByte = 0xFF;
    (void)memset(&ramsim_ctx, 0, sizeof(ramsim_ctx));
    (void)memset(&nvm_flash_cfg, 0, sizeof(nvm_flash_cfg));
    nvm_flash_cfg.cb = ramsim_cb;
    nvm_flash_cfg.context = &ramsim_ctx;
    nvm_flash_cfg.config = &ramsim_cfg;
    (void)memset(&nvm_flash_ctx, 0, sizeof(nvm_flash_ctx));
    (void)memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    nvm_cfg.cb = (whNvmCb*)nvm_cb;
    nvm_cfg.context = &nvm_flash_ctx;
    nvm_cfg.config = &nvm_flash_cfg;
    if (wh_Nvm_Init(&g_nvm_ctx, &nvm_cfg) != WH_ERROR_OK) {
        return -1;
    }
    if (wt_hsm_vault_init(&g_nvm_ctx) != 0 ||
            wt_hsm_seal_init(&g_nvm_ctx) != 0) {
        return -1;
    }
    wt_hsm_vault_set_sealer(&wt_hsm_sealer);
    return 0;
}

int main(void)
{
    static const uint8_t secret[] = "key-isolation-owner-a-secret";
    const wt_vault_backend_t* store = &wt_hsm_vault_backend;
    uint8_t probe[64];
    size_t got = 0U;
    psa_status_t status;

    if (nvm_up() != 0) {
        (void)fprintf(stderr, "bring-up failed\n");
        return 1;
    }

    /* N1: within an owner the delegated sub_owner partitions cleanly. */
    status = store->set(OWNER_A, 7, 0xD1ULL, 0U, secret, sizeof(secret));
    check(status == PSA_SUCCESS, "owner-A/sub-7 stores an object");
    status = store->get(OWNER_A, 8, 0xD1ULL, 0U, probe, sizeof(probe), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "N1 WT-FFM-0044 a different sub_owner in the same owner is disjoint");
    status = store->get(OWNER_A, 7, 0xD1ULL, 0U, probe, sizeof(probe), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret) &&
          memcmp(probe, secret, sizeof(secret)) == 0,
          "N1 the true (owner, sub) still reads its own object");

    /* N2: a forged sub_owner never reaches another owner's namespace. */
    status = store->get(OWNER_B, 7, 0xD1ULL, 0U, probe, sizeof(probe), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "N2 WT-FFM-0044 a forged sub_owner cannot cross to another owner");

    /* N3: a sealed PS object is invisible cross-owner; its ciphertext is
     * bound to its own label and rollback counter (no cross-object swap). */
    status = store->set(OWNER_A, 0, 0xE1ULL, WT_VAULT_FLAG_SEALED, secret,
                        sizeof(secret));
    check(status == PSA_SUCCESS, "owner-A stores a sealed object E1");
    status = store->get(OWNER_A, 0, 0xE1ULL, 0U, probe, sizeof(probe), &got);
    check(status == PSA_SUCCESS && got == sizeof(secret) &&
          memcmp(probe, secret, sizeof(secret)) == 0,
          "N3 the sealed object round-trips for its owner");
    status = store->get(OWNER_B, 0, 0xE1ULL, 0U, probe, sizeof(probe), &got);
    check(status == PSA_ERROR_DOES_NOT_EXIST,
          "N3 WT-FFM-0048 a sealed object is invisible cross-owner");

    /* N4: the internal KEY / SEALED label flags cannot be forged from a
     * storage client — they sit outside the accepted storage flag mask, so a
     * SET carrying them is rejected outright (never silently honoured). */
    status = store->set(OWNER_A, 0, 0xF1ULL, WT_VAULT_FLAG_KEY, secret,
                        sizeof(secret));
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "N4 WT-FFM-0046 a storage SET cannot forge the KEY flag");
    status = store->set(OWNER_A, 0, 0xF1ULL, 0x40000U, secret,
                        sizeof(secret));
    check(status == PSA_ERROR_INVALID_ARGUMENT,
          "N4 a storage SET cannot pass an unknown flag bit");

    if (g_failures != 0) {
        return 1;
    }
    (void)printf("PASS: vault storage-face security negatives\n");
    return 0;
}
