/* ffm_boot.h
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

#ifndef WOLFTRUST_FFM_BOOT_H
#define WOLFTRUST_FFM_BOOT_H

#include "wolftrust/ffm.h"

void wt_ffm_boot_init(void);
/* Starts every Secure Partition as a scheduled unprivileged coroutine, once
 * the coroutine scheduler is up. */
int wt_ffm_boot_start_sched(void);

#endif /* WOLFTRUST_FFM_BOOT_H */
