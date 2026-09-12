/* pl011.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_PL011_H
#define WOLFTRUST_ARCH_AARCH64_PL011_H

#include <stdint.h>

/* Polled PL011 console used by QEMU virt, versal-virt, and Versal silicon. */
void wt_pl011_init(uintptr_t base, uint32_t clock_hz, uint32_t baud);
void wt_pl011_putc(uintptr_t base, char c);
void wt_pl011_flush(uintptr_t base);

#endif /* WOLFTRUST_ARCH_AARCH64_PL011_H */
