/* fwtpm.h
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

#ifndef WOLFTRUST_HOST_FWTPM_STUB_H
#define WOLFTRUST_HOST_FWTPM_STUB_H

#include <stdint.h>

/* Host seam: only the fwTPM state the provider touches. */
#define FWTPM_MAX_COMMAND_SIZE 512

typedef uint8_t byte;
typedef struct FWTPM_CTX {
    int wasStarted;
    int lockoutAuthFailed;
} FWTPM_CTX;

int FWTPM_Init(FWTPM_CTX* ctx);

#endif /* WOLFTRUST_HOST_FWTPM_STUB_H */
