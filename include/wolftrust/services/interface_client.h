/* interface_client.h
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

#ifndef WOLFTRUST_SERVICES_INTERFACE_CLIENT_H
#define WOLFTRUST_SERVICES_INTERFACE_CLIENT_H

#include <stdint.h>

/* In the interface band. The monitor bumps it when the application guest
 * restarts or is quarantined; the provider then drops that client's state. */
extern volatile uint32_t g_wt_interface_client_epoch;

#endif /* WOLFTRUST_SERVICES_INTERFACE_CLIENT_H */
