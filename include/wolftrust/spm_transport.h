/* spm_transport.h
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

#ifndef WOLFTRUST_SPM_TRANSPORT_H
#define WOLFTRUST_SPM_TRANSPORT_H

#include "wolftrust/ffm.h"
#include "wolftrust/spm_sched.h"

#include <stdint.h>

struct wt_co;
struct wt_spm_call;
struct wt_trap_frame;

/* OR'd into an entry's arg by fault recovery so a restarted probe differs. */
#define WT_SP_FAULT_PROBE_RESTARTED 0x40000000
#define WT_SP_FAULT_PROBE_SECOND    0x20000000

/* Test builds only. A partition's own translation unit plants state in its
 * data band before a deliberate fault; after the restart the band must hold
 * its link-time image again. Returns 1 when it does. */
#define WT_RESTART_PROBE_DEFINE(name) \
    static volatile uint32_t name##_data = 0x5A5A5A5Au; \
    static volatile uint32_t name##_bss; \
    int name(int restarted) \
    { \
        if (restarted == 0) { \
            name##_data = 0xC0DEC0DEu; \
            name##_bss = 0xC0DEC0DEu; \
            return 1; \
        } \
        return (name##_data == 0x5A5A5A5Au) && (name##_bss == 0u); \
    }

#if defined(WT_RESTART_NEG_PROBE) && (WT_RESTART_NEG_PROBE != 0)
int wt_hsm_relay_restart_probe(int restarted);
int wt_attestation_restart_probe(int restarted);
int wt_vault_restart_probe(int restarted);
#endif

/* Re-issues a blocked call after each wake; the gate stamps the caller id. */
int wt_spm_sp_call(struct wt_spm_call* call);
int wt_spm_svc_transport(wt_ffm_runtime_t* runtime, struct wt_spm_call* call);

int wt_spm_dispatch_call(struct wt_spm_call* call, struct wt_trap_frame* frame);

/* Handler-mode half pends the recovery; the bootstrap-thread half runs it. */
int wt_spm_sp_fault(struct wt_co* faulted_co);
void wt_spm_recover_faulted(void);

void wt_spm_set_hsm_partition(int32_t partition_id);

#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
void wt_spm_sched_hang_probe(void);
void wt_spm_conf_irq(uint32_t irq);
/* Provided by the port. */
int wt_conf_nvm_flash_sync(uint8_t *buf, uint32_t len, int store);
void wt_conf_uart_irq_set(int on);
#endif

#endif /* WOLFTRUST_SPM_TRANSPORT_H */
