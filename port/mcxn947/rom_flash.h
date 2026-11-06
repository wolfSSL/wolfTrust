/* rom_flash.h
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

#ifndef WOLFTRUST_MCXN947_ROM_FLASH_H
#define WOLFTRUST_MCXN947_ROM_FLASH_H

#include <stdint.h>

/* Internal flash through the boot ROM's flash API. Offsets are flash offsets
 * (the Secure alias less 0x10000000); the privileged SPM is the only caller.
 * A phrase is programmed once per erase: program refuses a non-blank phrase. */
#define WT_ROM_FLASH_OK            0
#define WT_ROM_FLASH_ERR_ARGS     -1
#define WT_ROM_FLASH_ERR_ROM      -2
#define WT_ROM_FLASH_ERR_NOTBLANK -3
#define WT_ROM_FLASH_ERR_GEOMETRY -4

int wt_rom_flash_init(void);
int wt_rom_flash_program(uint32_t offset, const uint8_t *data, uint32_t size);
int wt_rom_flash_erase(uint32_t offset, uint32_t size);
int wt_rom_flash_blank(uint32_t offset, uint32_t size);
uint32_t wt_rom_flash_last_status(void);

#endif /* WOLFTRUST_MCXN947_ROM_FLASH_H */
