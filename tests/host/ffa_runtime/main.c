/* main.c
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

/* WT-FFA-0006 (runtime models): the FF-A partition runtime state machine of
 * DEN0077A Ch.8. Every legal transition moves the partition to the expected
 * state; every illegal one leaves the state untouched and reports DENIED
 * (or BUSY for a direct request to a non-waiting receiver, §7.4). */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_runtime.h"

#include <stdint.h>
#include <stdio.h>

static int checks;
static int failures;

static void check(int ok, const char* what)
{
    checks++;
    if (ok) {
        printf("  [check] PASS  %s\n", what);
    }
    else {
        failures++;
        printf("  [check] FAIL  %s\n", what);
    }
}

/* One transition expectation: from `state` on `event`, expect return code
 * `rc` and the state left at `next` (for an error, next == state). */
struct row {
    wt_ffa_rt_state_t state;
    wt_ffa_rt_event_t event;
    int rc;
    wt_ffa_rt_state_t next;
    const char* what;
};

static const struct row g_rows[] = {
    /* FFA_RUN allocates cycles to a waiting, blocked, or preempted context. */
    { WT_FFA_RT_WAITING,   WT_FFA_RT_EV_RUN,        0, WT_FFA_RT_RUNNING,
      "RUN wakes a waiting partition into running" },
    { WT_FFA_RT_BLOCKED,   WT_FFA_RT_EV_RUN,        0, WT_FFA_RT_RUNNING,
      "RUN resumes a blocked partition" },
    { WT_FFA_RT_PREEMPTED, WT_FFA_RT_EV_RUN,        0, WT_FFA_RT_RUNNING,
      "RUN resumes a preempted partition" },
    { WT_FFA_RT_RUNNING,   WT_FFA_RT_EV_RUN,        WT_FFA_DENIED, WT_FFA_RT_RUNNING,
      "RUN on a running partition is DENIED" },

    /* A direct request lands only on a waiting receiver; else BUSY. */
    { WT_FFA_RT_WAITING,   WT_FFA_RT_EV_DIRECT_REQ, 0, WT_FFA_RT_RUNNING,
      "a direct request enters a waiting receiver" },
    { WT_FFA_RT_RUNNING,   WT_FFA_RT_EV_DIRECT_REQ, WT_FFA_BUSY, WT_FFA_RT_RUNNING,
      "a direct request to a running receiver is BUSY" },
    { WT_FFA_RT_BLOCKED,   WT_FFA_RT_EV_DIRECT_REQ, WT_FFA_BUSY, WT_FFA_RT_BLOCKED,
      "a direct request to a blocked receiver is BUSY" },
    { WT_FFA_RT_PREEMPTED, WT_FFA_RT_EV_DIRECT_REQ, WT_FFA_BUSY, WT_FFA_RT_PREEMPTED,
      "a direct request to a preempted receiver is BUSY" },

    /* FFA_MSG_WAIT returns a running partition to waiting. */
    { WT_FFA_RT_RUNNING,   WT_FFA_RT_EV_MSG_WAIT,   0, WT_FFA_RT_WAITING,
      "MSG_WAIT returns a running partition to waiting" },
    { WT_FFA_RT_WAITING,   WT_FFA_RT_EV_MSG_WAIT,   WT_FFA_DENIED, WT_FFA_RT_WAITING,
      "MSG_WAIT from waiting is DENIED" },
    { WT_FFA_RT_BLOCKED,   WT_FFA_RT_EV_MSG_WAIT,   WT_FFA_DENIED, WT_FFA_RT_BLOCKED,
      "MSG_WAIT from blocked is DENIED" },
    { WT_FFA_RT_PREEMPTED, WT_FFA_RT_EV_MSG_WAIT,   WT_FFA_DENIED, WT_FFA_RT_PREEMPTED,
      "MSG_WAIT from preempted is DENIED" },

    /* A direct response completes a request and returns to waiting. */
    { WT_FFA_RT_RUNNING,   WT_FFA_RT_EV_DIRECT_RESP, 0, WT_FFA_RT_WAITING,
      "a direct response returns a running partition to waiting" },
    { WT_FFA_RT_WAITING,   WT_FFA_RT_EV_DIRECT_RESP, WT_FFA_DENIED, WT_FFA_RT_WAITING,
      "a direct response from waiting is DENIED" },
    { WT_FFA_RT_BLOCKED,   WT_FFA_RT_EV_DIRECT_RESP, WT_FFA_DENIED, WT_FFA_RT_BLOCKED,
      "a direct response from blocked is DENIED" },

    /* FFA_YIELD blocks a running partition. */
    { WT_FFA_RT_RUNNING,   WT_FFA_RT_EV_YIELD,      0, WT_FFA_RT_BLOCKED,
      "YIELD blocks a running partition" },
    { WT_FFA_RT_WAITING,   WT_FFA_RT_EV_YIELD,      WT_FFA_DENIED, WT_FFA_RT_WAITING,
      "YIELD from waiting is DENIED" },
    { WT_FFA_RT_BLOCKED,   WT_FFA_RT_EV_YIELD,      WT_FFA_DENIED, WT_FFA_RT_BLOCKED,
      "YIELD from blocked is DENIED" },
    { WT_FFA_RT_PREEMPTED, WT_FFA_RT_EV_YIELD,      WT_FFA_DENIED, WT_FFA_RT_PREEMPTED,
      "YIELD from preempted is DENIED" },

    /* A physical interrupt preempts only a running partition. */
    { WT_FFA_RT_RUNNING,   WT_FFA_RT_EV_INTERRUPT,  0, WT_FFA_RT_PREEMPTED,
      "an interrupt preempts a running partition" },
    { WT_FFA_RT_WAITING,   WT_FFA_RT_EV_INTERRUPT,  WT_FFA_DENIED, WT_FFA_RT_WAITING,
      "an interrupt event from waiting is DENIED" },
    { WT_FFA_RT_BLOCKED,   WT_FFA_RT_EV_INTERRUPT,  WT_FFA_DENIED, WT_FFA_RT_BLOCKED,
      "an interrupt event from blocked is DENIED" },
    { WT_FFA_RT_PREEMPTED, WT_FFA_RT_EV_INTERRUPT,  WT_FFA_DENIED, WT_FFA_RT_PREEMPTED,
      "an interrupt event from preempted is DENIED" }
};

static void run_table(void)
{
    wt_ffa_rt_state_t s;
    unsigned int i;
    int rc;

    for (i = 0u; i < sizeof(g_rows) / sizeof(g_rows[0]); i++) {
        s = g_rows[i].state;
        rc = wt_ffa_rt_transition(&s, g_rows[i].event);
        check(rc == g_rows[i].rc && s == g_rows[i].next, g_rows[i].what);
    }
}

/* A direct-request call chain threads the states end to end: a waiting SP is
 * entered by a request, blocks on an outbound call, is resumed by RUN,
 * responds, and lands back in waiting. */
static void run_chain(void)
{
    wt_ffa_rt_state_t s = WT_FFA_RT_WAITING;

    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_DIRECT_REQ) == 0 &&
          s == WT_FFA_RT_RUNNING, "chain: request enters the SP");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_YIELD) == 0 &&
          s == WT_FFA_RT_BLOCKED, "chain: SP blocks on an outbound call");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_DIRECT_REQ) == WT_FFA_BUSY &&
          s == WT_FFA_RT_BLOCKED, "chain: a request to the blocked SP is BUSY");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_RUN) == 0 &&
          s == WT_FFA_RT_RUNNING, "chain: RUN resumes the blocked SP");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_DIRECT_RESP) == 0 &&
          s == WT_FFA_RT_WAITING, "chain: the response returns it to waiting");

    /* Preemption and resume of the same SP. */
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_RUN) == 0 &&
          s == WT_FFA_RT_RUNNING, "chain: RUN wakes it again");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_INTERRUPT) == 0 &&
          s == WT_FFA_RT_PREEMPTED, "chain: an interrupt preempts it");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_RUN) == 0 &&
          s == WT_FFA_RT_RUNNING, "chain: RUN resumes the preempted SP");
    check(wt_ffa_rt_transition(&s, WT_FFA_RT_EV_MSG_WAIT) == 0 &&
          s == WT_FFA_RT_WAITING, "chain: MSG_WAIT parks it back at waiting");
}

int main(void)
{
    wt_ffa_rt_state_t s = WT_FFA_RT_RUNNING;

    printf("WT-FFA-0006 (FF-A partition runtime state machine)\n");

    run_table();
    run_chain();

    /* A NULL state pointer and an out-of-range event are rejected without a
     * side effect. */
    check(wt_ffa_rt_transition(NULL, WT_FFA_RT_EV_RUN) == WT_FFA_INVALID_PARAMETERS,
          "a NULL state pointer is INVALID_PARAMETERS");
    check(wt_ffa_rt_transition(&s, (wt_ffa_rt_event_t)0x7F) ==
          WT_FFA_INVALID_PARAMETERS && s == WT_FFA_RT_RUNNING,
          "an unknown event is INVALID_PARAMETERS and does not move the state");

    check(wt_ffa_rt_state_name(WT_FFA_RT_WAITING)[0] == 'w' &&
          wt_ffa_rt_state_name(WT_FFA_RT_RUNNING)[0] == 'r' &&
          wt_ffa_rt_state_name(WT_FFA_RT_PREEMPTED)[0] == 'p' &&
          wt_ffa_rt_state_name(WT_FFA_RT_BLOCKED)[0] == 'b' &&
          wt_ffa_rt_state_name((wt_ffa_rt_state_t)0x7F)[0] == 'i',
          "state names round-trip and an out-of-range state reads invalid");

    printf("ffa_runtime: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
