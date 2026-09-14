/* ffa_runtime.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_RUNTIME_H
#define WOLFTRUST_ARCH_AARCH64_FFA_RUNTIME_H

#include <stdint.h>

/* FF-A partition runtime state machine (DEN0077A Ch.8). Each partition's
 * execution context is in exactly one of these states; the SPMC drives the
 * transitions and rejects illegal ones so a partition can never be entered
 * from a state the framework does not allow. */

typedef enum wt_ffa_rt_state {
    WT_FFA_RT_WAITING = 0,  /* idle, ready to receive a message or FFA_RUN */
    WT_FFA_RT_RUNNING,      /* executing on this PE */
    WT_FFA_RT_PREEMPTED,    /* was running, preempted by a physical interrupt */
    WT_FFA_RT_BLOCKED       /* yielded or blocked on an outbound call */
} wt_ffa_rt_state_t;

typedef enum wt_ffa_rt_event {
    WT_FFA_RT_EV_RUN = 0,      /* FFA_RUN allocates cycles to this partition */
    WT_FFA_RT_EV_DIRECT_REQ,   /* a direct request is delivered to it */
    WT_FFA_RT_EV_MSG_WAIT,     /* it calls FFA_MSG_WAIT, returning to waiting */
    WT_FFA_RT_EV_DIRECT_RESP,  /* it sends a direct response, completing a req */
    WT_FFA_RT_EV_YIELD,        /* it calls FFA_YIELD or blocks on a call */
    WT_FFA_RT_EV_INTERRUPT     /* a physical interrupt preempts it */
} wt_ffa_rt_event_t;

/* Apply an FF-A runtime-model event to a partition state (Ch.8, Table 8.1).
 * On a legal transition updates *state and returns 0. On an illegal one the
 * state is left unchanged and a negative FF-A status is returned: BUSY for a
 * direct request to a partition that is not waiting (§7.4), DENIED for every
 * other illegal transition (§8.2), INVALID_PARAMETERS for a bad argument. */
int wt_ffa_rt_transition(wt_ffa_rt_state_t *state, wt_ffa_rt_event_t event);

const char *wt_ffa_rt_state_name(wt_ffa_rt_state_t state);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_RUNTIME_H */
