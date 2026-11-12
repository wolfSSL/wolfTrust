/* flash_port.h
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

/* The flash device primitives a port supplies in port/<soc>/flash_drv.c.
 *
 * The shared backend (port/common/hsm_flash.c) is the port_nvm.h provider
 * and the FWU staging backend; it owns every policy (identity-bound
 * contexts, range and alignment checks, write locks, the privilege gate)
 * and calls these with a privileged thread and a range it already checked
 * against an immutable region. s_addr is the Secure-alias address; a program
 * covers a multiple of the port's WT_FLASH_PROGRAM_UNIT and an erase a
 * multiple of WT_FLASH_SECTOR_SIZE, while a read or blank check covers any
 * byte span inside the region (wolfHSM reads object fields as it finds
 * them). Results are wolfHSM codes:
 * WH_ERROR_OK, WH_ERROR_ABORTED for a device fault (a read then leaves dst
 * zeroed; a program or erase may leave the range partly changed, and the
 * caller treats it as dirty), WH_ERROR_NOTBLANK for a non-blank check and,
 * where the device tells it apart from a fault, for a unit programmed twice
 * (otherwise ABORTED; the backend fails either way). A primitive restores the
 * interrupt state it found on every return and wipes any plaintext it
 * staged. quiesce is bounded: it relocks the controller and waits for an
 * idle device for a finite time so a reset that follows cannot cut a program
 * short, and never spins forever.
 * The probe tamper (test builds only) erases the sector at the Non-secure
 * address and programs one zero unit at its start, outside any writable
 * window the port enforces. */

#ifndef WOLFTRUST_PORT_FLASH_PORT_H
#define WOLFTRUST_PORT_FLASH_PORT_H

#include <stdint.h>

int wt_port_flash_read(uintptr_t s_addr, uint8_t* dst, uint32_t size);
int wt_port_flash_program(uintptr_t s_addr, const uint8_t* src,
                          uint32_t size);
int wt_port_flash_erase(uintptr_t s_addr, uint32_t size);
int wt_port_flash_blank_check(uintptr_t s_addr, uint32_t size);
void wt_port_flash_quiesce(void);
#if defined(WT_REMEASURE_PROBE)
int wt_port_flash_probe_tamper(uintptr_t ns_addr);
#endif

#endif /* WOLFTRUST_PORT_FLASH_PORT_H */
