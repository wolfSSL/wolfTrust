/* transport.h
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

#ifndef WT_TEST_PSA_TRANSPORT_H
#define WT_TEST_PSA_TRANSPORT_H

#include <stdint.h>

/* Client id stamped on the following calls (a guest is -(guest_id + 1)). */
void wt_test_set_client(int32_t client);

/* Restart the service process; its flash image persists. */
int wt_test_service_restart(void);

/* Drop the nth psa_call from now (1 = the next) as a lost request. */
void wt_test_fail_call(int nth);

#define WT_TEST_REPLY_SHORT    1 /* cut the reply inside its wt_psa_wire_ret_t */
#define WT_TEST_REPLY_OVERSIZE 2 /* claim more output than the call's capacity */
/* Damage the reply of the nth psa_call from now as mode says. */
void wt_test_mangle_reply(int nth, int mode);

#endif /* WT_TEST_PSA_TRANSPORT_H */
