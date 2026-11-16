/* rng_port.h
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

/* The entropy source a port supplies in port/<soc>/rng_drv.c.
 *
 * The shared entropy callback (port/common/rng_entropy.c) owns the
 * privilege gate and the failure policy: init runs once, lazily, with a
 * privileged thread, and a failed init is retried on the next request; fill
 * delivers the whole request or returns nonzero, after which the callback
 * zeroes the caller's buffer and refuses every later request until reset.
 * fill must never serve a word an earlier request already saw, and a port
 * whose device writes the request by DMA keeps that destination reserved so
 * a late completion cannot land in reused memory. Both run privileged. */

#ifndef WOLFTRUST_PORT_RNG_PORT_H
#define WOLFTRUST_PORT_RNG_PORT_H

int wt_port_rng_init(void);
int wt_port_rng_fill(unsigned char* out, unsigned int sz);

#endif /* WOLFTRUST_PORT_RNG_PORT_H */
