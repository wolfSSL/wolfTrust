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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* WT-FFM-0011 Phase A: the secure per-partition stack carve. These compile-time
 * guards are the overlap check — if the layout ever moves so partitions overlap
 * each other, escape the secure RAM window, or lose MPU alignment, the build
 * fails here (and the matching ASSERT in secure.ld fails at link). */

#include "memory_map.h"
#include "wolftrust/static_assert.h"

#include <stdio.h>

/* Every Armv8-M MPU region base is 32-byte aligned. */
WT_STATIC_ASSERT(((WT_SP_VAULT_DATA_BASE | WT_SP_ATTEST_DATA_BASE |
                   WT_SP_HSM_DATA_BASE | WT_SP_PS_STACK_BASE |
                   WT_SP_ITS_STACK_BASE | WT_SP_VAULT_STACK_BASE |
                   WT_SP_CRYPTO_STACK_BASE | WT_SP_ATTEST_STACK_BASE |
                   WT_CONF_SP_DATA_BASE | WT_SP_FWU_STACK_BASE) & 0x1FU) == 0U,
               "a level 3 band or stack is not 32-byte aligned");

/* SPM RAM ends at the lowest partition band: VNET, the crypto stack and data
 * band, then the keystore, so the engine-sized crypto bands move no other
 * partition's stack. */
WT_STATIC_ASSERT(WT_L3_BANDS_BASE == WT_VNET_DATA_BASE,
               "the VNET band is not the lowest partition band");
WT_STATIC_ASSERT(WT_VNET_DATA_BASE + WT_VNET_DATA_SIZE ==
                   WT_SP_CRYPTO_STACK_BASE,
               "VNET band and crypto stack overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_CRYPTO_STACK_BASE + WT_SP_CRYPTO_STACK_SIZE ==
                   WT_SP_HSM_DATA_BASE,
               "crypto stack and data band overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_HSM_DATA_BASE + WT_SP_HSM_DATA_SIZE == WT_KEYSTORE_BASE,
               "crypto data band does not end at the keystore");
WT_STATIC_ASSERT(WT_KEYSTORE_BASE == WT_RAM_S_BASE + WT_L3_SPM_RAM_SIZE,
               "keystore does not start at the end of the SPM RAM window");
WT_STATIC_ASSERT(WT_L3_BANDS_BASE > WT_RAM_S_BASE,
               "partition bands leave no SPM RAM");

/* Isolation level 3: the vault and attestation partitions own disjoint,
 * adjacent data bands that exactly fill the keystore envelope. */
WT_STATIC_ASSERT(WT_SP_VAULT_DATA_BASE == WT_KEYSTORE_BASE,
               "vault data band does not start the keystore envelope");
WT_STATIC_ASSERT(WT_SP_VAULT_DATA_BASE + WT_SP_VAULT_DATA_SIZE ==
                   WT_SP_ATTEST_DATA_BASE,
               "vault and attestation data bands overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_ATTEST_DATA_BASE + WT_SP_ATTEST_DATA_SIZE ==
                   WT_KEYSTORE_BASE + WT_KEYSTORE_SIZE,
               "attestation data band does not end the keystore envelope");
WT_STATIC_ASSERT(WT_KEYSTORE_BASE + WT_KEYSTORE_SIZE == WT_SP_PS_STACK_BASE,
               "keystore envelope does not end at the PS stack");

/* Partition stacks are contiguous and non-overlapping. */
WT_STATIC_ASSERT(WT_SP_PS_STACK_BASE + WT_SP_PS_STACK_SIZE ==
                   WT_SP_ITS_STACK_BASE,
               "PS and ITS stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_ITS_STACK_BASE + WT_SP_ITS_STACK_SIZE ==
                   WT_SP_VAULT_STACK_BASE,
               "ITS and vault stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_VAULT_STACK_BASE + WT_SP_VAULT_STACK_SIZE ==
                   WT_SP_SECURE_RAM_BASE,
               "vault stack and the SP stack region overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_ATTEST_STACK_BASE == WT_SP_SECURE_RAM_BASE,
               "attest stack does not start the SP stack region");
WT_STATIC_ASSERT(WT_SP_ATTEST_STACK_BASE + WT_SP_ATTEST_STACK_SIZE ==
                   WT_SP_FF_SERVER_STACK_BASE,
               "attest and FF server SP stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_FF_SERVER_STACK_BASE + WT_SP_FF_STACK_SIZE ==
                   WT_SP_FF_DRIVER_STACK_BASE,
               "FF server and driver SP stacks overlap or leave a gap");
WT_STATIC_ASSERT(WT_SP_FF_DRIVER_STACK_BASE + WT_SP_FF_STACK_SIZE ==
                   WT_SP_FF_CLIENT_STACK_BASE,
               "FF driver and client SP stacks overlap or leave a gap");
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
WT_STATIC_ASSERT(WT_SP_FF_CLIENT_STACK_BASE + WT_SP_FF_STACK_SIZE ==
                   WT_SP_SECURE_RAM_END,
               "conformance SP stacks do not fill the SP stack region");
#else
WT_STATIC_ASSERT(WT_SP_SECURE_RAM_END == WT_SP_FF_SERVER_STACK_BASE,
               "a production build reserves the conformance SP stacks");
#endif

/* The conformance window follows the SP stacks; production reserves none. */
WT_STATIC_ASSERT(WT_CONF_SP_DATA_BASE == WT_SP_SECURE_RAM_END,
               "conformance window does not follow the SP stacks");
#if (defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)) || defined(CONFIG_VNET)
WT_STATIC_ASSERT(WT_CONF_SP_DATA_SIZE == 0x3000U,
               "conformance window is not reserved");
#else
WT_STATIC_ASSERT(WT_CONF_SP_DATA_SIZE == 0U,
               "a production build reserves the conformance window");
#endif

/* The update stack tops the layout, so WT_FWU moves no other stack. */
WT_STATIC_ASSERT(WT_SP_FWU_STACK_BASE ==
                   WT_CONF_SP_DATA_BASE + WT_CONF_SP_DATA_SIZE,
               "FWU stack does not sit above the conformance window");
#if defined(WT_FWU)
WT_STATIC_ASSERT(WT_L3_RAM_END ==
                   WT_SP_FWU_STACK_BASE + WT_SP_FWU_STACK_SIZE_RESERVED,
               "WT_FWU=1 does not reserve the FWU stack band");
#else
WT_STATIC_ASSERT(WT_L3_RAM_END == WT_SP_FWU_STACK_BASE,
               "WT_FWU=0 still reserves the FWU stack band");
#endif
WT_STATIC_ASSERT(WT_L3_RAM_END <= WT_RAM_S_BASE + WT_RAM_S_SIZE,
               "the level 3 layout overflows the secure RAM window");

int main(void)
{
    (void)printf("WT-FFM-0011 PASS SP secure RAM [0x%08lX,0x%08lX) size 0x%lX\n",
                 (unsigned long)WT_SP_SECURE_RAM_BASE,
                 (unsigned long)WT_SP_SECURE_RAM_END,
                 (unsigned long)WT_SP_SECURE_RAM_SIZE);
    (void)printf("WT-FFM-0011 PASS crypto stack 0x%08lX, attest stack 0x%08lX\n",
                 (unsigned long)WT_SP_CRYPTO_STACK_BASE,
                 (unsigned long)WT_SP_ATTEST_STACK_BASE);
    (void)printf("WT-FFM-0011 PASS vault band 0x%08lX, attest band 0x%08lX, "
                 "crypto band 0x%08lX\n",
                 (unsigned long)WT_SP_VAULT_DATA_BASE,
                 (unsigned long)WT_SP_ATTEST_DATA_BASE,
                 (unsigned long)WT_SP_HSM_DATA_BASE);
    (void)printf("PASS: sp_layout\n");
    return 0;
}
