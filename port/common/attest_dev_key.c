/* attest_dev_key.c
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

/* The WT_ATTEST_DEV_KEY=1 attestation key of the reference boards. It is
 * public, so a token it authenticates proves nothing about a device. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolftrust/services/initial_attestation.h"

/* "wolfTrust-DEV-attestation-key-00" */
static const uint8_t g_attest_dev_key[WT_ATTEST_HMAC_KEY_SIZE] = {
    0x77, 0x6f, 0x6c, 0x66, 0x54, 0x72, 0x75, 0x73,
    0x74, 0x2d, 0x44, 0x45, 0x56, 0x2d, 0x61, 0x74,
    0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x30, 0x30
};

int wt_port_attest_hmac_key(uint8_t* key, size_t keySize)
{
    int ret = -1;

    if ((key != NULL) && (keySize == sizeof(g_attest_dev_key))) {
        (void)memcpy(key, g_attest_dev_key, sizeof(g_attest_dev_key));
        ret = 0;
    }
    return ret;
}
