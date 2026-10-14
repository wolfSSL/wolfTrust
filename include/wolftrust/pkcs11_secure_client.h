/* pkcs11_secure_client.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

#ifndef WOLFTRUST_PKCS11_SECURE_CLIENT_H
#define WOLFTRUST_PKCS11_SECURE_CLIENT_H

#define WT_PKCS11_HSM_NAMESPACE 1U
#define WT_PKCS11_HSM_CLIENT_ID (WT_PKCS11_HSM_NAMESPACE + 1U)

int wt_pkcs11_secure_client_init(void);
int wt_pkcs11_secure_client_prepare(void);
void wt_pkcs11_secure_client_hsm_restarted(void);

#endif /* WOLFTRUST_PKCS11_SECURE_CLIENT_H */
