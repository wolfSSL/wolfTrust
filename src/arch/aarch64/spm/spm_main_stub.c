/* spm_main_stub.c
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

/* Placeholder Secure EL1 payload until the SPM runs here: prove the drop
 * from EL3 landed, then leave through the monitor's exit call. */

#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/monitor_abi.h"

void wt_spm_main(void);

void wt_spm_main(void)
{
    wt_el3_puts("[SPM] stub entered at S-EL1\r\n");
    wt_platform_console_flush();
    (void)wt_mon_call(WT_MON_FID_EXIT, WT_MON_EXIT_SUCCESS);
}
