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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void* XMALLOC(size_t size, void* heap, int type);
void XFREE(void* pointer, void* heap, int type);
void* XREALLOC(void* pointer, size_t size, void* heap, int type);

static int check(int condition, const char* label)
{
    if (!condition) {
        (void)fprintf(stderr, "FAIL: %s\n", label);
        return 1;
    }
    (void)printf("PASS: %s\n", label);
    return 0;
}

int main(void)
{
    uint8_t* first;
    uint8_t* replacement;
    uint8_t* reused;
    size_t fake_header[2];
    uint8_t outside = 0xA5U;
    size_t i;
    int intact = 1;
    int scrubbed = 1;
    int failed = 0;

    first = (uint8_t*)XMALLOC(64U, NULL, 0);
    failed |= check(first != NULL, "secure heap allocates an aligned block");
    if (first == NULL) {
        return 1;
    }
    failed |= check(((uintptr_t)first & 15U) == 0U,
                    "secure heap returns 16-byte alignment");

    fake_header[0] = 16U;
    fake_header[1] = 1U;
    (void)memcpy(first, fake_header, sizeof(fake_header));
    (void)memset(first + 16U, 0x5AU, 16U);
    XFREE(first + 16U, NULL, 0);
    for (i = 16U; i < 32U; ++i) {
        if (first[i] != 0x5AU) {
            intact = 0;
        }
    }
    failed |= check(intact,
                    "interior free cannot forge an allocation header");
    failed |= check(XREALLOC(first + 16U, 128U, NULL, 0) == NULL,
                    "interior realloc is refused");

    XFREE(&outside, NULL, 0);
    failed |= check(outside == 0xA5U,
                    "foreign free leaves memory unchanged");

    replacement = (uint8_t*)XREALLOC(first, 128U, NULL, 0);
    failed |= check(replacement != NULL,
                    "valid realloc grows an allocation");
    if (replacement == NULL) {
        return 1;
    }
    failed |= check(memcmp(replacement, fake_header, sizeof(fake_header)) == 0,
                    "valid realloc preserves allocation contents");

    (void)memset(replacement, 0xA5, 128U);
    XFREE(replacement, NULL, 0);
    for (i = 0U; i < 128U; ++i) {
        if (replacement[i] != 0U) {
            scrubbed = 0;
        }
    }
    failed |= check(scrubbed, "free scrubs the complete allocation");

    reused = (uint8_t*)XMALLOC(128U, NULL, 0);
    failed |= check(reused == first,
                    "free blocks coalesce and reuse the first span");
    XFREE(reused, NULL, 0);

    if (failed == 0) {
        (void)printf("PASS: secure PKCS11 heap pointer validation\n");
    }
    return failed != 0;
}
