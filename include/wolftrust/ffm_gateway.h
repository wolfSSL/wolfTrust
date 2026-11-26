/* ffm_gateway.h
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


#ifndef WOLFTRUST_FFM_GATEWAY_H
#define WOLFTRUST_FFM_GATEWAY_H

#include "wolftrust/ffm_veneer.h"

#include <stdint.h>

/* Called by the arch NS entry mechanism with raw NS arguments. */
int32_t wt_ffm_gateway_connect(uint32_t sid, uint32_t version);
int32_t wt_ffm_gateway_call(int32_t handle, int32_t type,
                            wt_ffm_veneer_iovec_t* ns_iovec);
void wt_ffm_gateway_close(int32_t handle);
uint32_t wt_ffm_gateway_framework_version(void);
uint32_t wt_ffm_gateway_service_version(uint32_t sid);

#endif /* WOLFTRUST_FFM_GATEWAY_H */
