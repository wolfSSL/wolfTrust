/* secure_l3_symbols.ld
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

/* Stack symbols of the shared level 3 layout, INCLUDEd after MEMORY. */

_estack = ORIGIN(RAM) + LENGTH(RAM);
/* Secure main stack: MSPLIM_S is set to _sstack at reset. */
_sstack = _estack - WT_SPM_STACK_SIZE;
_wt_part_stacks_base = ORIGIN(FWUSTACK);
_wt_part_stacks_limit = ORIGIN(VAULTSTACK) + LENGTH(VAULTSTACK);
_wt_sp_stacks_base = ORIGIN(SPSTACKS);
_wt_sp_stacks_limit = ORIGIN(SPSTACKS) + LENGTH(SPSTACKS);
