/* hsm_flash.h
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

#ifndef WOLFTRUST_MIMXRT700_HSM_FLASH_H
#define WOLFTRUST_MIMXRT700_HSM_FLASH_H

#include <stdint.h>
#include "wolftrust/port_nvm.h"

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
#endif

#if defined(WT_REMEASURE_PROBE)
int wt_hsm_flash_remeasure_tamper(uintptr_t secure_base);
#endif

#endif /* WOLFTRUST_MIMXRT700_HSM_FLASH_H */
