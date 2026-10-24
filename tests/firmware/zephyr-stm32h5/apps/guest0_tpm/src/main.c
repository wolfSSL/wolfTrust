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

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "tpm_tests.h"

void wt_tpm_puts(const char *text)
{
    printk("%s", text);
}

void wt_tpm_print_i32(int value)
{
    printk("%d", value);
}

void wt_tpm_wait(void)
{
    k_msleep(1);
}

int main(void)
{
    int rc;

    printk("tpm-zephyr: alive\r\n");
    rc = wt_tpm_run();
    if (rc == 0) {
        printk("tpm-zephyr: suite complete\r\n");
#if defined(WT_M33MU_EXPECT_BKPT) && (WT_M33MU_EXPECT_BKPT == 1)
        __asm volatile("bkpt 0x7f");
#endif
    }
    else {
        printk("tpm-zephyr: suite failed\r\n");
#if defined(WT_M33MU_EXPECT_BKPT) && (WT_M33MU_EXPECT_BKPT == 1)
        __asm volatile("bkpt 0x7e");
#endif
    }
    return rc;
}
