/* ffa_runtime.c
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

/* FF-A partition runtime state machine (DEN0077A Ch.8). The SPMC keeps one of
 * these per execution context and consults wt_ffa_rt_transition before it
 * enters a partition, so an illegal FF-A call can never resume a partition
 * from a state the framework forbids. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_runtime.h"

#include <stddef.h>

int wt_ffa_rt_transition(wt_ffa_rt_state_t *state, wt_ffa_rt_event_t event)
{
    wt_ffa_rt_state_t cur;

    if (state == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    cur = *state;

    switch (event) {
        case WT_FFA_RT_EV_RUN:
            /* FFA_RUN can allocate cycles to a waiting, blocked, or preempted
             * context (§8.1); a running one is DENIED. */
            if (cur == WT_FFA_RT_WAITING || cur == WT_FFA_RT_BLOCKED ||
                cur == WT_FFA_RT_PREEMPTED) {
                *state = WT_FFA_RT_RUNNING;
                return 0;
            }
            return WT_FFA_DENIED;
        case WT_FFA_RT_EV_DIRECT_REQ:
            /* A direct request lands only on a waiting receiver (§7.4); any
             * other state is BUSY, not DENIED. */
            if (cur == WT_FFA_RT_WAITING) {
                *state = WT_FFA_RT_RUNNING;
                return 0;
            }
            return WT_FFA_BUSY;
        case WT_FFA_RT_EV_MSG_WAIT:
        case WT_FFA_RT_EV_DIRECT_RESP:
            if (cur == WT_FFA_RT_RUNNING) {
                *state = WT_FFA_RT_WAITING;
                return 0;
            }
            return WT_FFA_DENIED;
        case WT_FFA_RT_EV_YIELD:
            if (cur == WT_FFA_RT_RUNNING) {
                *state = WT_FFA_RT_BLOCKED;
                return 0;
            }
            return WT_FFA_DENIED;
        case WT_FFA_RT_EV_INTERRUPT:
            if (cur == WT_FFA_RT_RUNNING) {
                *state = WT_FFA_RT_PREEMPTED;
                return 0;
            }
            return WT_FFA_DENIED;
        default:
            return WT_FFA_INVALID_PARAMETERS;
    }
}

int wt_ffa_rt_init_call(uint32_t fid, int target_initialized)
{
    switch (fid) {
        case WT_FFA_MSG_SEND_DIRECT_REQ32:
        case WT_FFA_MSG_SEND_DIRECT_REQ64:
        case WT_FFA_MSG_SEND_DIRECT_REQ2:
            return (target_initialized != 0) ? 0 : WT_FFA_DENIED;
        case WT_FFA_YIELD:
        case WT_FFA_RUN:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
        case WT_FFA_MSG_SEND_DIRECT_RESP2:
            return WT_FFA_DENIED;
        default:
            return 0;
    }
}

int wt_ffa_rt_success_check(const uint64_t* x)
{
    unsigned int i;

    if ((uint32_t)x[0] == WT_FFA_SUCCESS64) {
        for (i = 1u; i < 18u; i++) {
            if (x[i] != 0u) {
                return WT_FFA_INVALID_PARAMETERS;
            }
        }
        return 0;
    }
    for (i = 1u; i < 8u; i++) {
        if ((uint32_t)x[i] != 0u) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }
    return 0;
}

int wt_ffa_rt_error_check(const uint64_t* x)
{
    if (((uint32_t)x[1] != 0u) || ((int32_t)(uint32_t)x[2] >= 0)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    return 0;
}

int wt_ffa_rt_yield_check(const uint64_t* x)
{
    if (((uint32_t)x[1] | (uint32_t)x[2] | (uint32_t)x[3]) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    return 0;
}

int wt_ffa_rt_msg_wait_releases_rx(uint32_t version, const uint64_t* x)
{
    if ((version >= WT_FFA_VERSION_1_2) &&
        (((uint32_t)x[2] & WT_FFA_MSG_WAIT_RETAIN_RX) != 0u)) {
        return 0;
    }
    return 1;
}

const char *wt_ffa_rt_state_name(wt_ffa_rt_state_t state)
{
    switch (state) {
        case WT_FFA_RT_WAITING:
            return "waiting";
        case WT_FFA_RT_RUNNING:
            return "running";
        case WT_FFA_RT_PREEMPTED:
            return "preempted";
        case WT_FFA_RT_BLOCKED:
            return "blocked";
        default:
            return "invalid";
    }
}
