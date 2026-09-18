/* wh_settings_local.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * wolfHSM build configuration for the wolfTrust STM32H563 secure partition.
 *
 * PICKUP MECHANISM NOTE: wolfhsm/wh_settings.h includes this file only if
 * the preprocessor symbol WOLFHSM_CFG is defined AND this header is reachable
 * as "wolfhsm_cfg.h" on the include path.  The Wave 2 Makefile agent must
 * arrange one of the following:
 *
 *   Option A (preferred): symlink or copy this file into the build tree as
 *     wolfhsm_cfg.h and add -DWOLFHSM_CFG to CFLAGS.
 *
 *   Option B: add to CFLAGS:
 *     -DWOLFHSM_CFG -include <abs-path>/wh_settings_local.h
 *     and ensure the compiler sees -DWOLFHSM_CFG so wh_settings.h still
 *     triggers its #include "wolfhsm_cfg.h" guard (which becomes a no-op
 *     because the guard in this file will already be defined).
 *
 * Either way, this file must be processed before wolfhsm/wh_settings.h
 * resolves its defaults.
 */

#ifndef WOLFTRUST_SECURE_WH_SETTINGS_LOCAL_H
#define WOLFTRUST_SECURE_WH_SETTINGS_LOCAL_H

/*---------------------------------------------------------------------------
 * Thread safety
 *
 * Enable the whLock vtable so multiple per-guest coroutines sharing one
 * whNvmContext serialise via our ARMv8-M mutex.  Without this, all lock
 * operations are compiled away as no-ops.
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_THREADSAFE

/*---------------------------------------------------------------------------
 * Communication buffer
 *
 * COMM_DATA_LEN is the wire payload budget; the 8 B whCommHeader rides in
 * front of it, so one packet is 376 B — inside the relay's
 * WT_HSM_RELAY_MSG_MAX (512 B) copied-IOVEC bound (hsm_relay.h).
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_COMM_DATA_LEN 368

/*---------------------------------------------------------------------------
 * Role: server only
 *
 * The secure-side build hosts the wolfHSM server.  wh_server.c is gated on
 * WOLFHSM_CFG_ENABLE_SERVER; without this, wh_Server_Init and friends are
 * absent at link time.  The client API is not compiled into the secure image
 * (each guest links its own client subset on the non-secure side).
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_ENABLE_SERVER

/*---------------------------------------------------------------------------
 * Crypto
 *
 * WOLFHSM_CFG_NO_CRYPTO is intentionally NOT defined: the server must
 * perform cryptographic operations on behalf of Normal-World clients.
 *---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
 * Key cache
 *
 * Four RAM key slots (one per key in concurrent use) with 256-byte buffers.
 * An ECC P-256 private key is ~110 bytes in DER form; 256 B provides margin.
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT   4
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 256

/*---------------------------------------------------------------------------
 * Custom callbacks
 *
 * No application-defined custom request handlers are registered.
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 0

/*---------------------------------------------------------------------------
 * NVM sizing for the target flash backend
 *
 * WOLFHSM_CFG_NVM_OBJECT_COUNT controls the directory table size in
 * wh_nvm_flash.h. The STM32H563 port reserves two 8 KiB internal-flash
 * sectors for the mirrored wolfHSM NVM partitions. Phase 4 backs PSA ITS/PS
 * objects here (plus the attestation key and the PS device key), so the
 * directory holds 32 slots; each slot costs ~80 bytes of the 8 KiB partition,
 * leaving ample data space for the small dev_apis storage objects.
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_NVM_OBJECT_COUNT       32

/* STM32H5 flash is programmed in 128-bit quadwords. Keep the wolfHSM journal
 * unit aligned with the physical programming unit so no quadword is written
 * more than once. */
#define WOLFHSM_CFG_FLASH_UNIT_SIZE         16

/*---------------------------------------------------------------------------
 * Disabled extensions (opt-in, so omitting the define is sufficient)
 *
 * WOLFHSM_CFG_SHE_EXTENSION    -- AutoSAR SHE not required
 * WOLFHSM_CFG_DMA               -- DMA address translation not used
 * WOLFHSM_CFG_ENABLE_AUTHENTICATION -- mutual auth handshake not used
 * WOLFHSM_CFG_LOGGING           -- log subsystem not used
 *
 * All four are #ifdef-gated in the wolfHSM headers; leaving them undefined
 * is the correct way to exclude them.  No #undef is needed.
 *---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
 * System time
 *
 * Suppress the wolfHSM port-time requirement.  Benchmarks and log timestamps
 * will read zero; that is acceptable for this bring-up configuration.
 *---------------------------------------------------------------------------*/
#define WOLFHSM_CFG_NO_SYS_TIME

/* The secure image is freestanding and leaves wolfHSM debug output disabled. */
#define WOLFHSM_CFG_PRINTF(...) ((int)0)

#endif /* WOLFTRUST_SECURE_WH_SETTINGS_LOCAL_H */
