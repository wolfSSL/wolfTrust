/* monitor_calls.c
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

/* S-EL1 -> EL3 calls and the EL3 vector dispatch. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"
#include "wolftrust/arch/aarch64/sysreg.h"

uint64_t wt_el3_monitor_call(uint32_t fid, uint64_t arg)
{
    uint64_t result = WT_MON_NOT_SUPPORTED;

    switch (fid) {
        case WT_MON_FID_EXIT:
            wt_el3_puts("[BKPT] imm=0x");
            wt_el3_puthex(arg & 0xFFu, 2u);
            wt_el3_puts("\r\n");
            if ((arg & 0xFFu) == WT_MON_EXIT_SUCCESS) {
                wt_el3_puts("[EXPECT BKPT] Success\r\n");
            }
            wt_platform_console_flush();
            wt_el3_semihost_exit(((arg & 0xFFu) == WT_MON_EXIT_SUCCESS)
                                     ? 0u : (arg & 0xFFu));
            break;
        case WT_MON_FID_PANIC:
            wt_el3_puts("[EL3] panic code=0x");
            wt_el3_puthex(arg, 8u);
            wt_el3_puts("\r\n");
            wt_platform_console_flush();
            wt_el3_semihost_exit(WT_MON_EXIT_PANIC);
            break;
        default:
            break;
    }
    return result;
}

uint64_t wt_el3_exception(uint64_t kind, uint64_t x0, uint64_t x1)
{
    uint64_t esr = wt_read_esr_el3();

    if ((kind == WT_EL3_VEC_LOWER64_SYNC) &&
        (WT_ESR_EC(esr) == WT_ESR_EC_SMC64)) {
        if ((wt_read_scr_el3() & WT_SCR_NS) != 0u) {
            return WT_MON_NOT_SUPPORTED;
        }
        return wt_el3_monitor_call((uint32_t)x0, x1);
    }
    wt_el3_fault(kind, esr, wt_read_far_el3(), wt_read_elr_el3());
}
