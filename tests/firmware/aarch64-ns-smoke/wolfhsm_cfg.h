/* wolfhsm_cfg.h
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

/* wolfHSM client configuration for the AArch64 Normal-world smoke guest: a
 * crypto-free client whose only transport is the SPM-mediated psa_call. */

#ifndef WT_NS_SMOKE_WOLFHSM_CFG_H
#define WT_NS_SMOKE_WOLFHSM_CFG_H

#define WOLFHSM_CFG_ENABLE_CLIENT
#define WOLFHSM_CFG_NO_CRYPTO

/* Must match the secure side (src/services/wolfhsm/runner/wh_settings_local.h). */
#define WOLFHSM_CFG_COMM_DATA_LEN 368

#define WOLFHSM_CFG_NO_SYS_TIME
#define WOLFHSM_CFG_HEXDUMP_DISABLE

#endif /* WT_NS_SMOKE_WOLFHSM_CFG_H */
