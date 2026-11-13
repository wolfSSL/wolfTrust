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
 * reset — proving load-on-boot, write-through, and reload semantics. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* PAL entry points under test (port/stm32h563/conformance/pal_driver_intf.c). */
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
static int g_fail_store;
/* Knob: the next load of the persisted sector fails (an ECC or read error) */
static int g_load_fails;

static void flash_power_on(void)
{
    (void)memset(g_flash, 0xFF, sizeof(g_flash));
    g_flash_powered = 1;
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
        if (g_load_fails != 0) {
            g_load_fails = 0;
            return -1;
        }
        (void)memcpy(buf, g_flash, len);
        return 0;
    }
    if (g_fail_store != 0) {
        /* Model a sync that erased the sector and then failed to program. */
        (void)memset(g_flash, 0xFF, sizeof(g_flash));
        return -1;
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

int main(void)
{
    uint8_t boot[4];
    uint8_t data[8];
    uint8_t readback[8];

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

    /* A write that fails to persist is not visible to later reads, even when
     * the failed sync left the sector half programmed, and a later successful
     * write does not carry the rejected bytes to flash. */
    (void)memcpy(data, "LOSTBYTE", 8);
    g_fail_store = 1;
    check(pal_nvmem_write(0u, 32u, data, 8) == 0,
          "nvmem write reports a failed flash sync");
    g_fail_store = 0;
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 32u, readback, 8) == 1 &&
          readback[0] == 0xFFu && readback[7] == 0xFFu,
          "failed write is not served from the shadow");
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 16u, readback, 8) == 1 &&
          memcmp(readback, "FLAGDATA", 8) == 0,
          "failed write keeps the last good contents");
    (void)memcpy(boot, "BOT2", 4);
    check(pal_nvmem_write(0u, 0u, boot, 4) == 1 &&
          g_flash[32] == 0xFFu && memcmp(g_flash, "BOT2", 4) == 0,
          "later write does not persist rejected bytes");

    /* A fresh power-on with a blank sector reads back the 0xFF erased state,
     * matching the pre-flash RAM store's power-on behaviour. */
    flash_power_on();
    wt_conf_drv_nvm_test_reset();
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1, "read after blank power-on");
    check(readback[0] == 0xFFu && readback[3] == 0xFFu,
          "blank sector reads erased 0xFF");

#if defined(WT_CONF_NVM_LOAD_FAIL_CLOSED)
    /* A failed load is an error, never a blank store, and the write that
     * follows it must not persist a fabricated shadow over the real one. */
    (void)memcpy(boot, "KEEP", 4);
    check(pal_nvmem_write(0u, 0u, boot, 4) == 1, "a field is persisted");
    wt_conf_drv_nvm_test_reset();
    g_load_fails = 1;
    (void)memset(readback, 0, sizeof(readback));
    check(pal_nvmem_read(0u, 0u, readback, 4) == 0 && readback[0] == 0u,
          "a failed load fails the read");
    wt_conf_drv_nvm_test_reset();
    g_load_fails = 1;
    (void)memcpy(data, "OTHERFLD", 8);
    check(pal_nvmem_write(0u, 16u, data, 8) == 0 &&
          memcmp(g_flash, "KEEP", 4) == 0,
          "a failed load fails the write and leaves the store intact");
    check(pal_nvmem_read(0u, 0u, readback, 4) == 1 &&
          memcmp(readback, "KEEP", 4) == 0,
          "the next good load reads the persisted field");
#endif

    if (g_failures == 0) {
        printf("PASS: flash_nvm survive-reset NVM\n");
        return 0;
    }
    printf("FAIL: flash_nvm (%d failures)\n", g_failures);
    return 1;
}
