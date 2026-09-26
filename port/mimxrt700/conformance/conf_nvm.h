/* conf_nvm.h
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

#ifndef WOLFTRUST_MIMXRT700_CONF_NVM_H
#define WOLFTRUST_MIMXRT700_CONF_NVM_H

#include <stdint.h>

/* Survive-reset NVM seam for the conformance DRIVER partition (P5 K2). The
 * unprivileged PAL calls this to persist its shadow: store==0 loads the flash
 * sector into buf, store!=0 writes buf back. Returns 0 on success. The target
 * build issues an SVC to the privileged flash driver; a host test links its
 * own flash-simulator implementation of this symbol instead. */
int wt_conf_nvm_sync(uint8_t *buf, uint32_t len, int store);

/* PAL interrupt source control (P4.2c): on!=0 drives the platform UART so its
 * NVIC line fires into the DRIVER partition's manifest interrupt signal; on==0
 * quiesces the source. The unprivileged PAL traps to the privileged device
 * poke via SVC; the interrupt itself is delivered through the real vector. */
int wt_conf_irq_set(int on);

#endif /* WOLFTRUST_MIMXRT700_CONF_NVM_H */
