/* provider_crypto.h
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

#ifndef WOLFTRUST_PROVIDER_CRYPTO_H
#define WOLFTRUST_PROVIDER_CRYPTO_H

#define WT_PROVIDER_HSM_NAMESPACE 1U
#define WT_PROVIDER_HSM_CLIENT_ID (WT_PROVIDER_HSM_NAMESPACE + 1U)

int wt_provider_crypto_init(void);
int wt_provider_crypto_prepare(void);
void wt_provider_crypto_hsm_restarted(void);

#endif /* WOLFTRUST_PROVIDER_CRYPTO_H */
