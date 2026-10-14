/* tpm_local_provider.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 */

#ifndef WOLFTRUST_SERVICES_TPM_LOCAL_PROVIDER_H
#define WOLFTRUST_SERVICES_TPM_LOCAL_PROVIDER_H

#include "wolftrust/services/tpm_relay.h"

int wt_tpm_local_provider_init(void** context);
int wt_tpm_local_provider_process(const uint8_t* command,
                                  size_t command_len,
                                  uint8_t* response,
                                  size_t response_cap,
                                  size_t* response_len,
                                  void* context);

#endif /* WOLFTRUST_SERVICES_TPM_LOCAL_PROVIDER_H */
