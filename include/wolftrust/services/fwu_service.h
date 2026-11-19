/* fwu_service.h
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

#ifndef WOLFTRUST_SERVICES_FWU_SERVICE_H
#define WOLFTRUST_SERVICES_FWU_SERVICE_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_gate.h"
#include "psa/update.h"

/* SERVICE_FWU: the PSA Firmware Update service as an UNPRIVILEGED isolated
 * Secure Partition (SRC-PSA-FWU, WT-FWU-0001..0003). It holds no update
 * storage of its own: a candidate image is staged into the wolfBoot update
 * partition through the backend seam below and armed for swap on next boot.
 * The state machine rejects a malformed, oversize, or rolled-back candidate
 * before the swap is armed, and an abort restores the prior state without
 * arming a swap (WT-FWU-0003). The swapped image is still gated by
 * authenticated launch and anti-rollback at boot (WT-FWU-0002). */

/* psa_call request types (client face). */
#define WT_FWU_OP_QUERY   1
#define WT_FWU_OP_START   2
#define WT_FWU_OP_WRITE   3
#define WT_FWU_OP_FINISH  4
#define WT_FWU_OP_INSTALL 5
#define WT_FWU_OP_CANCEL  6
#define WT_FWU_OP_CLEAN   7
#define WT_FWU_OP_REJECT  8
#define WT_FWU_OP_REBOOT  9
#define WT_FWU_OP_ACCEPT  10

/* wolfTrust exposes a single updatable component (the secure/application
 * image). A request naming any other component is refused. */
#define WT_FWU_COMPONENT_PRIMARY 0u

/* wolfBoot on-flash update-trigger ABI (aidangarske/wolfBoot @ d85fa9d,
 * NVM_FLASH_WRITEONCE, non-inverted flags): the UPDATE partition reads as
 * 'update pending' when its trailer holds IMG_STATE_UPDATING at
 * partition_end-5 and the little-endian trailer magic 'BOOT' at
 * partition_end-4, so wolfBoot swaps the staged image on the next boot. */
#define WT_WOLFBOOT_MAGIC_TRAIL        0x544F4F42u  /* 'BOOT' */
#define WT_WOLFBOOT_IMG_STATE_UPDATING 0x70u

/* Client wire header. WRITE concatenates the block after the header in one
 * input vector ([wt_fwu_req_t][block]); QUERY reads psa_fwu_component_info_t
 * from outvec[0]; the other ops send the header alone. */
typedef struct wt_fwu_req {
    uint32_t component;
    uint32_t offset;   /* WRITE: image offset of this block */
    uint32_t size;     /* WRITE: block length (mirrors the invec tail length) */
    uint32_t version;  /* START: declared candidate version (anti-rollback) */
} wt_fwu_req_t;

/* START version meaning "no detached manifest": the PSA FWU 1.0 (NULL, 0)
 * call form. The candidate version is then bound from the staged image header
 * at FINISH; the erased-flash pattern can never be a real image version. */
#define WT_FWU_VERSION_UNDECLARED 0xFFFFFFFFu

/* Staging backend seam: the neutral state machine drives the wolfBoot update
 * partition entirely through these ops so the host test can supply a RAM
 * mock while the Secure Partition supplies the real flash + trigger backend.
 * Every op returns 0 on success and a negative value on failure. begin()
 * prepares (erases) the update partition; write() programs a block; arm()
 * writes the wolfBoot update trigger so the next boot swaps; disarm() clears
 * a pending trigger on abort. capacity is the update partition size; align is
 * the minimum write granularity (0 means byte-granular). */
typedef struct wt_fwu_backend {
    int (*begin)(void* ctx);
    int (*write)(void* ctx, uint32_t offset, const uint8_t* data,
                 uint32_t size);
    int (*arm)(void* ctx, uint32_t image_size, uint32_t version);
    int (*disarm)(void* ctx);
    uint32_t capacity;
    uint32_t align;
    /* Validates the staged bytes before CANDIDATE: full header coverage and
     * a parseable wolfBoot image header, returning the header's version so
     * the state machine can bind it to the caller-declared candidate. */
    int (*verify)(void* ctx, uint32_t staged_size, uint32_t* header_version);
} wt_fwu_backend_t;

/* Per-loop dispatch context, built on the Secure Partition's own stack and
 * carrying the live single-component state across messages. version_floor is
 * the anti-rollback minimum (seeded from the wolfHSM rollback floor on the
 * target); a candidate below it is refused before the swap is armed. */
typedef struct wt_fwu_service_ctx {
    wt_spm_transport_fn transport;
    const wt_fwu_backend_t* backend;
    void* backend_ctx;
    uint32_t version_floor;
    uint32_t state;
    uint32_t write_high;
    uint32_t candidate_version;
    uint32_t armed;
    psa_status_t error;     /* FAILED detail, cleared by clean (PSA FWU 1.0) */
    uint32_t active_version; /* running image; query's public version field */
    psa_client_id_t owner;  /* client that opened the active update; 0 = none.
                             * Only the owner may drive or reboot it. */
    uint32_t owner_tick;    /* scheduler tick of the owner's last activity; an
                             * owner idle past the timeout is reclaimed so one
                             * client cannot wedge updates for everyone (DoS). */
} wt_fwu_service_ctx_t;

/* Scheduler ticks (each ~one timeslice) an owned update may sit idle before a
 * different client may reclaim it. Generous: every owner operation refreshes
 * the clock, so this bounds only true abandonment, not a slow legitimate write. */
#define WT_FWU_OWNER_IDLE_TIMEOUT_TICKS 30000u

/* Reclaim predicate: non-zero when an owned session should be taken from an
 * idle owner because a different client is asking and the owner has been idle
 * past WT_FWU_OWNER_IDLE_TIMEOUT_TICKS. Neutral and host-tested. */
int wt_fwu_owner_expired(psa_client_id_t owner, uint32_t owner_tick,
                         uint32_t now_tick, psa_client_id_t caller);

/* Neutral state-machine transitions, driven directly by the host test and by
 * the dispatch loop below. Each returns a psa_status_t; a rejected or failed
 * transition never arms a swap and never advances the version floor. */
psa_status_t wt_fwu_start(wt_fwu_service_ctx_t* ctx, uint32_t component,
                          uint32_t version);
psa_status_t wt_fwu_write(wt_fwu_service_ctx_t* ctx, uint32_t component,
                          uint32_t offset, const uint8_t* data, uint32_t size);
psa_status_t wt_fwu_finish(wt_fwu_service_ctx_t* ctx, uint32_t component);
psa_status_t wt_fwu_install(wt_fwu_service_ctx_t* ctx);
psa_status_t wt_fwu_cancel(wt_fwu_service_ctx_t* ctx, uint32_t component);
psa_status_t wt_fwu_clean(wt_fwu_service_ctx_t* ctx, uint32_t component);
psa_status_t wt_fwu_reject(wt_fwu_service_ctx_t* ctx, psa_status_t error);
psa_status_t wt_fwu_request_reboot(wt_fwu_service_ctx_t* ctx);
psa_status_t wt_fwu_query(wt_fwu_service_ctx_t* ctx, uint32_t component,
                          psa_fwu_component_info_t* info);

/* Encode wolfBoot's WRITEONCE update-pending trigger into the topmost `len`
 * bytes of the UPDATE partition (the block maps to [size-len, size)), so
 * wolfBoot swaps the staged image on the next boot. Neutral and host-tested;
 * the target FWU backend programs the returned block into the trailer sector.
 * Returns 0 on success, -1 if the buffer cannot hold the trigger. */
int wt_fwu_wolfboot_arm_trailer(uint8_t* block, uint32_t len);

/* Backend verify helper: nonzero when staged_size, the logical image size
 * the service reports, is covered by programmed_end, the padded extent the
 * backend actually programmed, with less than one align unit of padding. */
int wt_fwu_staged_extent_ok(uint32_t staged_size, uint32_t programmed_end,
                            uint32_t align);

/* SERVICE_FWU's dispatch loop: wait, get, service one message through the
 * state machine, reply. Architecture-neutral: the host test drives real
 * wt_ffm round trips with a RAM backend; the target runs the same code as a
 * scheduled unprivileged coroutine. A NULL context fails closed. */
int wt_fwu_service_dispatch(void* context, wt_ffm_runtime_t* runtime,
                            int32_t partition_id);

#endif /* WOLFTRUST_SERVICES_FWU_SERVICE_H */
