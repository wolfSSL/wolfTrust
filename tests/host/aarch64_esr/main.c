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

/* Host rows for the AArch64 exception-syndrome decoder: every exception
 * class of the EL3 fault table maps to its wolfTrust fault reason, the
 * stack-guard and external-abort promotions apply in the documented order,
 * and the "[SYNC ...]" line is byte-exact. */

#include "wolftrust/arch/aarch64/esr.h"
#include "wolftrust/arch/aarch64/sysreg.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GUARD_BASE 0x0E010000ull
#define GUARD_SIZE 0x1000ull

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

static uint64_t esr_of(uint32_t ec, uint32_t iss)
{
    return ((uint64_t)ec << 26) | (uint64_t)(iss & 0x1FFFFFFu);
}

static wt_fault_reason_t classify(uint32_t ec, uint32_t iss, uint64_t far,
                                  int from_ns)
{
    return wt_esr_classify(esr_of(ec, iss), far, from_ns, GUARD_BASE,
                           GUARD_SIZE);
}

static const uint32_t g_illegal_ecs[] = {
    WT_ESR_EC_UNKNOWN, WT_ESR_EC_FP_ACCESS, WT_ESR_EC_ILLEGAL_STATE,
    WT_ESR_EC_SYSREG, WT_ESR_EC_BRK
};

static const uint32_t g_abort_ecs[] = {
    WT_ESR_EC_IABT_LOWER, WT_ESR_EC_IABT_SAME, WT_ESR_EC_DABT_LOWER,
    WT_ESR_EC_DABT_SAME
};

static const uint32_t g_align_ecs[] = {
    WT_ESR_EC_PC_ALIGN, WT_ESR_EC_SP_ALIGN
};

static const uint32_t g_platform_ecs[] = {
    WT_ESR_EC_SMC32, WT_ESR_EC_SMC64, WT_ESR_EC_SVC64, WT_ESR_EC_SERROR,
    0x3Fu
};

int main(void)
{
    char line[80];
    size_t i;
    size_t n;
    int ok;
    uint64_t far_outside = 0x40001000ull;
    uint64_t far_inside = GUARD_BASE + 0x10ull;
    uint32_t translation = 0x07u;

    printf("aarch64 exception-syndrome decoder (EL3 fault table)\n");

    ok = 1;
    for (i = 0u; i < sizeof(g_illegal_ecs) / sizeof(g_illegal_ecs[0]); i++) {
        ok = ok && (classify(g_illegal_ecs[i], 0u, 0u, 0) ==
                    WT_FAULT_ILLEGAL_INSTRUCTION);
        ok = ok && (classify(g_illegal_ecs[i], 0u, far_inside, 1) ==
                    WT_FAULT_ILLEGAL_INSTRUCTION);
    }
    check(ok, "unknown, FP access, illegal state, sysreg trap, and BRK are illegal instructions");

    ok = 1;
    for (i = 0u; i < sizeof(g_abort_ecs) / sizeof(g_abort_ecs[0]); i++) {
        ok = ok && (classify(g_abort_ecs[i], translation, far_outside, 0) ==
                    WT_FAULT_MEMORY_VIOLATION);
        ok = ok && (classify(g_abort_ecs[i], translation, far_outside, 1) ==
                    WT_FAULT_MEMORY_VIOLATION);
    }
    check(ok, "instruction and data aborts outside the guard are memory violations");

    ok = 1;
    for (i = 0u; i < sizeof(g_abort_ecs) / sizeof(g_abort_ecs[0]); i++) {
        ok = ok && (classify(g_abort_ecs[i], translation, far_inside, 0) ==
                    WT_FAULT_STACK_OVERFLOW);
        ok = ok && (classify(g_abort_ecs[i], translation, GUARD_BASE, 1) ==
                    WT_FAULT_STACK_OVERFLOW);
    }
    check(ok, "aborts whose FAR lands in the stack guard are stack overflows");

    check(classify(WT_ESR_EC_DABT_LOWER, translation,
                   GUARD_BASE + GUARD_SIZE, 0) == WT_FAULT_MEMORY_VIOLATION &&
          classify(WT_ESR_EC_DABT_LOWER, translation,
                   GUARD_BASE - 1ull, 0) == WT_FAULT_MEMORY_VIOLATION,
          "the guard window is [base, base + size)");
    check(wt_esr_classify(esr_of(WT_ESR_EC_DABT_LOWER, translation), far_inside,
                          0, GUARD_BASE, 0u) == WT_FAULT_MEMORY_VIOLATION,
          "a zero-sized guard never promotes to stack overflow");

    ok = 1;
    for (i = 0u; i < sizeof(g_abort_ecs) / sizeof(g_abort_ecs[0]); i++) {
        ok = ok && (classify(g_abort_ecs[i], WT_ESR_FSC_EXTERNAL, far_outside,
                             1) == WT_FAULT_SECURE_ESCALATION);
        ok = ok && (classify(g_abort_ecs[i], WT_ESR_FSC_EXTERNAL, far_outside,
                             0) == WT_FAULT_PLATFORM);
    }
    check(ok, "synchronous external aborts escalate from NS and are platform faults from Secure");
    check(classify(WT_ESR_EC_DABT_LOWER, WT_ESR_FSC_EXTERNAL, far_inside, 1) ==
              WT_FAULT_SECURE_ESCALATION &&
          classify(WT_ESR_EC_DABT_SAME, WT_ESR_FSC_EXTERNAL, far_inside, 0) ==
              WT_FAULT_PLATFORM,
          "an external abort inside the guard keeps its external classification");
    check(classify(WT_ESR_EC_DABT_LOWER, 0x1FFFFC0u | WT_ESR_FSC_EXTERNAL,
                   far_outside, 1) == WT_FAULT_SECURE_ESCALATION &&
          classify(WT_ESR_EC_DABT_LOWER, 0x1FFFFC0u | translation, far_outside,
                   1) == WT_FAULT_MEMORY_VIOLATION,
          "only the FSC bits of the ISS select the external abort");

    ok = 1;
    for (i = 0u; i < sizeof(g_align_ecs) / sizeof(g_align_ecs[0]); i++) {
        ok = ok && (classify(g_align_ecs[i], 0u, far_inside, 0) ==
                    WT_FAULT_MEMORY_VIOLATION);
    }
    check(ok, "PC and SP alignment faults are memory violations, never stack overflows");

    ok = 1;
    for (i = 0u; i < sizeof(g_platform_ecs) / sizeof(g_platform_ecs[0]); i++) {
        ok = ok && (classify(g_platform_ecs[i], 0u, far_inside, 1) ==
                    WT_FAULT_PLATFORM);
    }
    check(ok, "SMC, SVC, SError, and unlisted classes fall to the platform reason");
    check(classify(WT_ESR_EC_DABT_LOWER, translation, far_outside, 0) !=
              WT_FAULT_NONE &&
          classify(0x3Fu, 0u, 0u, 0) != WT_FAULT_NONE,
          "no syndrome decodes to no fault");

    n = wt_esr_format(line, sizeof(line), 1u,
                      esr_of(WT_ESR_EC_DABT_LOWER, 0x000047u), 0x0E001000ull);
    check(strcmp(line, "[SYNC EL=1 EC=0x24 ISS=0x0000047 FAR=0x000000000e001000]") == 0,
          "data abort line is byte-exact");
    check(n == strlen(line), "the returned length is the string length");

    n = wt_esr_format(line, sizeof(line), 3u,
                      esr_of(WT_ESR_EC_BRK, 0x1FFFFFFu) | (1ull << 25),
                      0xFFFFFFFFFFFFFFFFull);
    check(strcmp(line, "[SYNC EL=3 EC=0x3c ISS=0x1ffffff FAR=0xffffffffffffffff]") == 0,
          "ISS prints all 25 bits (bit 24 included, IL excluded), FAR 16 digits, EL one digit");
    check(n == 56u, "the widest line is 56 characters");

    n = wt_esr_format(line, sizeof(line), 2u, esr_of(WT_ESR_EC_SMC64, 0u), 0u);
    check(strcmp(line, "[SYNC EL=2 EC=0x17 ISS=0x0000000 FAR=0x0000000000000000]") == 0,
          "zero fields keep their fixed widths");

    memset(line, 'x', sizeof(line));
    n = wt_esr_format(line, 12u, 1u, esr_of(WT_ESR_EC_DABT_LOWER, 0x47u),
                      0x0E001000ull);
    check(n == 11u && line[11] == '\0' &&
          strcmp(line, "[SYNC EL=1 ") == 0 && line[12] == 'x',
          "a short buffer truncates at size-1 and stays NUL-terminated");
    memset(line, 'x', sizeof(line));
    n = wt_esr_format(line, 1u, 1u, 0u, 0u);
    check(n == 0u && line[0] == '\0', "a one-byte buffer holds only the NUL");
    check(wt_esr_format(NULL, sizeof(line), 1u, 0u, 0u) == 0u &&
          wt_esr_format(line, 0u, 1u, 0u, 0u) == 0u,
          "a NULL or empty buffer writes nothing");

    printf("aarch64_esr: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
