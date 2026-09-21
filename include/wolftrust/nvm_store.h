/* nvm_store.h
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

#ifndef WOLFTRUST_NVM_STORE_H
#define WOLFTRUST_NVM_STORE_H

#include "wolfhsm/wh_nvm.h"
#include "wolftrust/sync/mutex.h"

/* Engine-independent secure NVM store: the shared flash-backed object store
 * and its serialisation lock, linked in both crypto engines. The lifecycle
 * latch and rollback floors (wt_hsm_set_boot_lifecycle, wt_hsm_rollback_*)
 * ride this store and keep their public names in services/hsm.h. */

/* The single shared NVM context and its serialisation mutex. The mutex must
 * be initialised (wt_mutex_init) before wt_nvm_store_bind wires it in. */
extern whNvmContext g_wt_nvm_ctx;
extern wt_mutex_t   g_wt_nvm_lock_mutex;

/* Wire the port flash callbacks and the lock config, then initialise the
 * shared NVM context. Re-callable: the vault format/recovery path runs it
 * again against a freshly erased pool. Returns a WH_ERROR_* code. */
int wt_nvm_store_bind(void);

/* Nonzero when the wolfBoot-reported lifecycle permits destructive store
 * recovery (ASSEMBLY_AND_TEST or PSA_ROT_PROVISIONING); unset stays locked. */
int wt_nvm_reformat_allowed(void);

/* Record that the store was reformatted this boot (observability, reported
 * by wt_hsm_vault_was_reformatted). */
void wt_nvm_mark_reformatted(void);

#endif /* WOLFTRUST_NVM_STORE_H */
