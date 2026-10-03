/* l3_port.h
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

/* Versal inputs to the shared AArch64 isolation level 3 layer. */

#ifndef WOLFTRUST_VERSAL_L3_PORT_H
#define WOLFTRUST_VERSAL_L3_PORT_H

#include "memory_map.h"

/* A Secure peripheral only the SPM drives, probed by the periphsp negative. */
#define WT_L3_SPM_PERIPHERAL_BASE WT_UART_S_BASE

#endif /* WOLFTRUST_VERSAL_L3_PORT_H */
