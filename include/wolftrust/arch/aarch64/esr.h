/* esr.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_ESR_H
#define WOLFTRUST_ARCH_AARCH64_ESR_H

#include "wolftrust/types.h"

#include <stddef.h>
#include <stdint.h>

/* Pure decode of an exception syndrome; no system register access, so the
 * host suite can drive every row. */
wt_fault_reason_t wt_esr_classify(uint64_t esr, uint64_t far, int from_ns,
                                  uint64_t guard_base, uint64_t guard_size);

/* Writes "[SYNC EL=<n> EC=0x.. ISS=0x...... FAR=0x................]" and
 * returns the length written (the string is always NUL-terminated). */
size_t wt_esr_format(char* out, size_t out_size, uint32_t el, uint64_t esr,
                     uint64_t far);

#endif /* WOLFTRUST_ARCH_AARCH64_ESR_H */
