/* spm_ops.h
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

#ifndef WOLFTRUST_SPM_OPS_H
#define WOLFTRUST_SPM_OPS_H

#include "wolftrust/ffm_domain.h"
#include "wolftrust/spm_gate.h"

/* Privileged ops the SPM runs for one confined owner. The dispatcher has
 * already pinned the caller; each op checks its buffer against the caller's
 * domain and returns the result the partition sees in ret_int. */
int wt_spm_keystore_op(const wt_secure_domain_t* domain, wt_spm_call_t* call);
int wt_spm_fwu_op(const wt_secure_domain_t* domain, wt_spm_call_t* call);
int wt_spm_measure_op(const wt_secure_domain_t* domain, wt_spm_call_t* call);

#endif /* WOLFTRUST_SPM_OPS_H */
