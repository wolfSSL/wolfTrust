/* esr.c
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

#include "wolftrust/arch/aarch64/esr.h"
#include "wolftrust/arch/aarch64/sysreg.h"

wt_fault_reason_t wt_esr_classify(uint64_t esr, uint64_t far, int from_ns,
                                  uint64_t guard_base, uint64_t guard_size)
{
    uint32_t ec = WT_ESR_EC(esr);
    wt_fault_reason_t reason;

    switch (ec) {
        case WT_ESR_EC_UNKNOWN:
        case WT_ESR_EC_FP_ACCESS:
        case WT_ESR_EC_ILLEGAL_STATE:
        case WT_ESR_EC_SYSREG:
        case WT_ESR_EC_BRK:
            reason = WT_FAULT_ILLEGAL_INSTRUCTION;
            break;
        case WT_ESR_EC_IABT_LOWER:
        case WT_ESR_EC_IABT_SAME:
        case WT_ESR_EC_DABT_LOWER:
        case WT_ESR_EC_DABT_SAME:
            if (WT_ESR_FSC(esr) == WT_ESR_FSC_EXTERNAL) {
                reason = (from_ns != 0) ? WT_FAULT_SECURE_ESCALATION
                                        : WT_FAULT_PLATFORM;
            }
            else if ((guard_size != 0u) && (far >= guard_base) &&
                     (far < (guard_base + guard_size))) {
                reason = WT_FAULT_STACK_OVERFLOW;
            }
            else {
                reason = WT_FAULT_MEMORY_VIOLATION;
            }
            break;
        case WT_ESR_EC_PC_ALIGN:
        case WT_ESR_EC_SP_ALIGN:
            reason = WT_FAULT_MEMORY_VIOLATION;
            break;
        default:
            reason = WT_FAULT_PLATFORM;
            break;
    }
    return reason;
}

static size_t put_text(char* out, size_t out_size, size_t pos, const char* text)
{
    while ((*text != '\0') && ((pos + 1u) < out_size)) {
        out[pos] = *text;
        pos++;
        text++;
    }
    return pos;
}

static size_t put_hex(char* out, size_t out_size, size_t pos, uint64_t value,
                      unsigned int digits)
{
    static const char table[] = "0123456789abcdef";
    unsigned int shift = digits * 4u;

    while ((shift > 0u) && ((pos + 1u) < out_size)) {
        shift -= 4u;
        out[pos] = table[(value >> shift) & 0xFu];
        pos++;
    }
    return pos;
}

size_t wt_esr_format(char* out, size_t out_size, uint32_t el, uint64_t esr,
                     uint64_t far)
{
    size_t pos = 0u;

    if ((out == NULL) || (out_size == 0u)) {
        return 0u;
    }
    pos = put_text(out, out_size, pos, "[SYNC EL=");
    pos = put_hex(out, out_size, pos, el, 1u);
    pos = put_text(out, out_size, pos, " EC=0x");
    pos = put_hex(out, out_size, pos, WT_ESR_EC(esr), 2u);
    pos = put_text(out, out_size, pos, " ISS=0x");
    pos = put_hex(out, out_size, pos, WT_ESR_ISS(esr), 7u);
    pos = put_text(out, out_size, pos, " FAR=0x");
    pos = put_hex(out, out_size, pos, far, 16u);
    pos = put_text(out, out_size, pos, "]");
    out[pos] = '\0';
    return pos;
}
