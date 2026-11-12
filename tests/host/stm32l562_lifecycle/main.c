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

/* The STM32L562 life cycle mapping wolfBoot hands wolfTrust, tested from a
 * copy of the pinned wolfBoot header: FLASH_OPTR RDP under TZEN maps to PSA,
 * no TrustZone reads as unknown, and only RDP level 2 reads as SECURED. */

#include "stm32l5_lifecycle.h"
#include "psa/lifecycle.h"

#include <stdint.h>
#include <stdio.h>

#define LC_UNTOUCHED 0xDEADBEEFu

/* Every FLASH_OPTR bit but RDP[7:0] and TZEN: BOR, reset, watchdog, bank,
 * SRAM2 and boot options. */
#define OPTR_OTHER_BITS 0x7FFFFF00u

static int checks;
static int failures;

#define EXPECT(cond, what) \
    do { \
        checks++; \
        if (!(cond)) { \
            (void)fprintf(stderr, "line %d: %s\n", __LINE__, (what)); \
            failures++; \
        } \
    } while (0)

/* Returns the mapped state, or LC_UNTOUCHED when the call failed and left
 * the output alone. */
static uint32_t map(uint32_t optr)
{
    uint32_t lc = LC_UNTOUCHED;

    if (stm32l5_optr_to_psa_lifecycle(optr, &lc) != 0) {
        return (lc == LC_UNTOUCHED) ? LC_UNTOUCHED : 0u;
    }
    return lc;
}

static void test_ladder(void)
{
    const uint32_t tz = STM32L5_FLASH_OPTR_TZEN;

    EXPECT(map(tz | STM32L5_RDP_LEVEL_0) == PSA_LIFECYCLE_PSA_ROT_PROVISIONING,
           "TZEN at RDP level 0 is PSA-RoT provisioning");
    EXPECT(map(tz | STM32L5_RDP_LEVEL_0_5) ==
           PSA_LIFECYCLE_NON_PSA_ROT_DEBUG,
           "RDP level 0.5 is non-PSA-RoT debug");
    EXPECT(map(tz | 0xBBu) == PSA_LIFECYCLE_NON_PSA_ROT_DEBUG,
           "RDP level 1 is non-PSA-RoT debug");
    EXPECT(map(tz | STM32L5_RDP_LEVEL_2) == PSA_LIFECYCLE_SECURED,
           "RDP level 2 is SECURED");
    EXPECT(STM32L5_RDP_LEVEL_0 == 0xAAu && STM32L5_RDP_LEVEL_0_5 == 0x55u &&
           STM32L5_RDP_LEVEL_2 == 0xCCu,
           "the RDP codes are RM0438's 0xAA, 0x55 and 0xCC");
}

static void test_every_rdp(void)
{
    const uint32_t tz = STM32L5_FLASH_OPTR_TZEN;
    uint32_t rdp;
    uint32_t lc;
    int level1_ok = 1;
    int secured_once = 0;
    int no_tz_unknown = 1;

    for (rdp = 0u; rdp <= 0xFFu; rdp++) {
        lc = map(tz | rdp);
        if (lc == PSA_LIFECYCLE_SECURED) {
            secured_once++;
        }
        if (rdp != STM32L5_RDP_LEVEL_0 && rdp != STM32L5_RDP_LEVEL_0_5 &&
                rdp != STM32L5_RDP_LEVEL_2 &&
                lc != PSA_LIFECYCLE_NON_PSA_ROT_DEBUG) {
            level1_ok = 0;
        }
        if (map(rdp) != LC_UNTOUCHED ||
                map(rdp | OPTR_OTHER_BITS) != LC_UNTOUCHED) {
            no_tz_unknown = 0;
        }
    }
    EXPECT(level1_ok, "every RDP byte other than 0xAA, 0x55, 0xCC is level 1");
    EXPECT(secured_once == 1, "only 0xCC reads as SECURED");
    EXPECT(no_tz_unknown,
           "without TZEN every RDP is unknown and the output is untouched");
}

static void test_other_bits(void)
{
    const uint32_t tz = STM32L5_FLASH_OPTR_TZEN;

    EXPECT(map(tz | OPTR_OTHER_BITS | STM32L5_RDP_LEVEL_0) ==
           PSA_LIFECYCLE_PSA_ROT_PROVISIONING &&
           map(tz | OPTR_OTHER_BITS | STM32L5_RDP_LEVEL_0_5) ==
           PSA_LIFECYCLE_NON_PSA_ROT_DEBUG &&
           map(tz | OPTR_OTHER_BITS | STM32L5_RDP_LEVEL_2) ==
           PSA_LIFECYCLE_SECURED,
           "the other option bits never change the state");
    EXPECT((OPTR_OTHER_BITS & (STM32L5_FLASH_OPTR_TZEN |
                               STM32L5_FLASH_OPTR_RDP_MASK)) == 0u,
           "the other-bits mask leaves RDP and TZEN out");
    EXPECT(stm32l5_optr_to_psa_lifecycle(tz | STM32L5_RDP_LEVEL_2, NULL) != 0,
           "a missing output is refused");
}

int main(void)
{
    test_ladder();
    test_every_rdp();
    test_other_bits();
    printf("%s: %d checks, %d failures\n",
           (failures == 0) ? "PASS" : "FAIL", checks, failures);
    return (failures == 0) ? 0 : 1;
}
