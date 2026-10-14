/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "pkcs11_tests.h"

void wt_pkcs11_puts(const char *text)
{
    printk("%s", text);
}

void wt_pkcs11_print_u32(unsigned int value)
{
    printk("%u", value);
}

void wt_pkcs11_wait(void)
{
    k_msleep(1);
}

int main(void)
{
    int rc;

    printk("pkcs11-zephyr: alive\r\n");
    rc = wt_pkcs11_run();
    if (rc == 0) {
        printk("pkcs11-zephyr: suite %s complete\r\n",
               wt_pkcs11_suite_name());
#if defined(WT_M33MU_EXPECT_BKPT) && (WT_M33MU_EXPECT_BKPT == 1)
        __asm volatile("bkpt 0x7f");
#endif
    }
    else {
        printk("pkcs11-zephyr: suite failed\r\n");
#if defined(WT_M33MU_EXPECT_BKPT) && (WT_M33MU_EXPECT_BKPT == 1)
        __asm volatile("bkpt 0x7e");
#endif
    }
    return rc;
}
