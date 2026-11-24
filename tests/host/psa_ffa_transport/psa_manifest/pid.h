/* pid.h
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

/* Host stand-in for the generated psa_manifest/pid.h; ids mirror the
 * production manifest (tests/host/spm production-generated). */

#ifndef PSA_MANIFEST_PID_H
#define PSA_MANIFEST_PID_H

#define PARTITION_ATTEST_ID 3
#define PARTITION_CRYPTO_ID 4
#define PARTITION_HSM_ID 4
#define PARTITION_VAULT_ID 5
#define PARTITION_ITS_ID 6
#define PARTITION_PS_ID 7
#define PARTITION_ATTEST PARTITION_ATTEST_ID
#define PARTITION_CRYPTO PARTITION_CRYPTO_ID
#define PARTITION_HSM PARTITION_HSM_ID
#define PARTITION_VAULT PARTITION_VAULT_ID
#define PARTITION_ITS PARTITION_ITS_ID
#define PARTITION_PS PARTITION_PS_ID

#endif /* PSA_MANIFEST_PID_H */
