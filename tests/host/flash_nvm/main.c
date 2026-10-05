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

/* WT-FFM-0042 (P5 K2): the flash-backed survive-reset NVM logic in the
 * conformance DRIVER PAL. The real flash controller code (hsm_flash.c) is
 * target-only, so this drives the genuine pal_driver_intf.c shadow logic
 * against a faithful flash model that keeps its contents across a simulated
 * reset — proving load-on-boot, write-through, and reload semantics. Built
 * once per port, each with its own PAL and pal_config.h. */

#include "pal_config.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* PAL entry points under test (the port's conformance/pal_driver_intf.c). */
int pal_nvmem_write(uintptr_t base, uint32_t offset, void *buffer, int size);
int pal_nvmem_read(uintptr_t base, uint32_t offset, void *buffer, int size);
void wt_conf_drv_nvm_test_reset(void);

/* Faithful flash model backing the survive-reset seam: erased is 0xFF, a
 * program only clears bits, and the whole sector is erased before each store.
 * The buffer persists across wt_conf_drv_nvm_test_reset(), modelling a warm
 * reset that re-runs boot with flash intact. */
#define FLASH_SZ 0x2000u
static uint8_t g_flash[FLASH_SZ];
static int g_flash_powered;

static void flash_power_on(void)
{
    (void)memset(g_flash, 0xFF, sizeof(g_flash));
    g_flash_powered = 1;
}

/* The backend refusing every access (a rejected trap or a dead controller)
 * with the sector's contents intact. */
static void flash_backend_down(int down)
{
    g_flash_powered = (down != 0) ? 0 : 1;
}

/* The PAL interrupt hooks are irrelevant to the NVM logic under test. */
int wt_conf_irq_set(int on)
{
    (void)on;
    return 0;
}

int wt_conf_nvm_sync(uint8_t *buf, uint32_t len, int store)
{
    uint32_t i;

    if (!g_flash_powered || buf == NULL || len == 0u || len > FLASH_SZ) {
        return -1;
    }
    if (store == 0) {
        (void)memcpy(buf, g_flash, len);
        return 0;
    }
    (void)memset(g_flash, 0xFF, sizeof(g_flash));
    for (i = 0u; i < len; i++) {
        if (g_flash[i] != 0xFFu) {
            return -1; /* would require an erase first */
        }
        g_flash[i] = buf[i];
    }
    return 0;
}

static int g_failures;

static void check(int cond, const char *name)
{
    if (cond) {
        printf("PASS: %s\n", name);
    }
    else {
        printf("FAIL: %s\n", name);
        g_failures++;
    }
}

#define NVM_BYTES ((uint32_t)(NVMEM_0_END - NVMEM_0_START + 1u))

int main(void)
{
    uint8_t boot[4];
    uint8_t data[8];
    uint8_t readback[8];
    uint8_t edge = 0x5Au;

    flash_power_on();

    /* Write-through: a write lands in the persistent flash model, not only in
     * the RAM shadow. */
    (void)memcpy(boot, "BOOT", 4);
    check(pal_nvmem_write(0u, 0u, boot, 4) == 1, "nvmem write returns success");
    check(memcmp(g_flash, "BOOT", 4) == 0, "write reaches persistent flash");

    /* Round trip through the shadow. */
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1, "nvmem read returns success");
    check(memcmp(readback, "BOOT", 4) == 0, "read returns the written value");

    /* A second field at another offset must not clobber the first (whole-sector
     * read-modify-write preserves the rest of the store). */
    (void)memcpy(data, "FLAGDATA", 8);
    check(pal_nvmem_write(0u, 16u, data, 8) == 1, "second field write");
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1, "first field still readable");
    check(memcmp(readback, "BOOT", 4) == 0, "first field intact after 2nd write");

    /* Survive-reset: drop the shadow so the next access reloads from flash,
     * exactly as a post-AIRCR-reset boot does. Both fields must return. */
    wt_conf_drv_nvm_test_reset();
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1, "read after reset succeeds");
    check(memcmp(readback, "BOOT", 4) == 0, "boot field survives reset");
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 16u, readback, 8) == 1, "flag read after reset");
    check(memcmp(readback, "FLAGDATA", 8) == 0, "flag field survives reset");

    /* Every byte pal_config.h advertises is backed, and none past it. */
    check(pal_nvmem_write(0u, NVM_BYTES - 1u, &edge, 1) == 1,
          "the last advertised NVMEM byte is writable");
    wt_conf_drv_nvm_test_reset();
    readback[0] = 0u;
    check(pal_nvmem_read(0u, NVM_BYTES - 1u, readback, 1) == 1 &&
          readback[0] == 0x5Au, "and reads back after a reset");
    check(pal_nvmem_write(0u, NVM_BYTES, &edge, 1) == 0,
          "the first byte past the advertised range is refused");
    check(pal_nvmem_read(0u, NVM_BYTES, readback, 1) == 0,
          "and cannot be read");

    /* A fresh power-on with a blank sector reads back the 0xFF erased state,
     * matching the pre-flash RAM store's power-on behaviour. */
    flash_power_on();
    wt_conf_drv_nvm_test_reset();
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1, "read after blank power-on");
    check(readback[0] == 0xFFu && readback[3] == 0xFFu,
          "blank sector reads erased 0xFF");

    /* A backend that refuses the load must not fabricate a blank sector, and
     * a store it refuses must not show through the shadow. */
    check(pal_nvmem_write(0u, 0u, boot, 4) == 1, "write before the backend fails");
    flash_backend_down(1);
    wt_conf_drv_nvm_test_reset();
    (void)memset(readback, 0x55, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 0 && readback[0] == 0x55u,
          "a read whose reload the backend refuses fails and returns nothing");
    check(pal_nvmem_write(0u, 0u, data, 4) == 0,
          "a write whose reload the backend refuses fails");
    flash_backend_down(0);
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1 &&
              memcmp(readback, "BOOT", 4) == 0,
          "once the backend answers, the next access reloads the real contents");
    flash_backend_down(1);
    check(pal_nvmem_write(0u, 0u, data, 4) == 0,
          "a write whose store the backend refuses fails");
    flash_backend_down(0);
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1 &&
              memcmp(readback, "BOOT", 4) == 0,
          "and the shadow still reads the last committed value, not the "
          "rejected one");
    wt_conf_drv_nvm_test_reset();
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1 &&
              memcmp(readback, "BOOT", 4) == 0,
          "which is also what flash holds after a reset");

    if (g_failures == 0) {
        printf("PASS: flash_nvm survive-reset NVM\n");
        return 0;
    }
    printf("FAIL: flash_nvm (%d failures)\n", g_failures);
    return 1;
}
