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

/* 8.5: an SP still initializing may message an SP that has initialized, and
 * nothing that hands its cycles to another endpoint. */
static void init_model_rows(void)
{
    check(wt_ffa_rt_init_call(WT_FFA_MSG_SEND_DIRECT_REQ32, 1) == 0 &&
          wt_ffa_rt_init_call(WT_FFA_MSG_SEND_DIRECT_REQ64, 1) == 0 &&
          wt_ffa_rt_init_call(WT_FFA_MSG_SEND_DIRECT_REQ2, 1) == 0,
          "init: a direct request to an initialized SP is allowed (rule 1)");
    check(wt_ffa_rt_init_call(WT_FFA_MSG_SEND_DIRECT_REQ32, 0) ==
          WT_FFA_DENIED,
          "init: a direct request to an SP not yet initialized is DENIED");
    check(wt_ffa_rt_init_call(WT_FFA_YIELD, 1) == WT_FFA_DENIED,
          "init: FFA_YIELD is DENIED (rule 4)");
    check(wt_ffa_rt_init_call(WT_FFA_MSG_SEND_DIRECT_RESP32, 1) ==
              WT_FFA_DENIED &&
          wt_ffa_rt_init_call(WT_FFA_MSG_SEND_DIRECT_RESP2, 1) ==
              WT_FFA_DENIED,
          "init: a direct response is DENIED (rule 5)");
    check(wt_ffa_rt_init_call(WT_FFA_RUN, 1) == WT_FFA_DENIED,
          "init: FFA_RUN is DENIED (rule 6)");
    check(wt_ffa_rt_init_call(WT_FFA_MSG_WAIT, 0) == 0 &&
          wt_ffa_rt_init_call(WT_FFA_ERROR, 0) == 0 &&
          wt_ffa_rt_init_call(WT_FFA_PARTITION_INFO_GET, 0) == 0,
          "init: FFA_MSG_WAIT, FFA_ERROR and setup calls are served");
}

/* The encodings a partition's FFA_SUCCESS (completing a direct request) and
 * FFA_ERROR (failing its initialization) must carry. */
static void status_encoding_rows(void)
{
    uint64_t x[18] = { 0 };

    x[0] = WT_FFA_SUCCESS32;
    x[4] = 0xFFFFFFFF00000000ull;
    x[9] = 1u;
    check(wt_ffa_rt_success_check(x) == 0,
          "FFA_SUCCESS32 is judged on w1-w7 alone");
    x[3] = 1u;
    check(wt_ffa_rt_success_check(x) == WT_FFA_INVALID_PARAMETERS,
          "FFA_SUCCESS32 with a nonzero w3 is INVALID_PARAMETERS");
    x[0] = WT_FFA_SUCCESS64;
    x[3] = 0u;
    x[4] = 0u;
    check(wt_ffa_rt_success_check(x) == WT_FFA_INVALID_PARAMETERS,
          "FFA_SUCCESS64 with a nonzero x9 is INVALID_PARAMETERS");
    x[9] = 0u;
    x[17] = 0x100000000ull;
    check(wt_ffa_rt_success_check(x) == WT_FFA_INVALID_PARAMETERS,
          "and so is one with a bit set in the upper half of x17");
    x[17] = 0u;
    check(wt_ffa_rt_success_check(x) == 0, "a clean FFA_SUCCESS64 is accepted");

    x[0] = WT_FFA_ERROR;
    x[2] = (uint32_t)WT_FFA_NO_MEMORY;
    check(wt_ffa_rt_error_check(x) == 0, "FFA_ERROR with an error code is accepted");
    x[1] = 0x8003u;
    check(wt_ffa_rt_error_check(x) == WT_FFA_INVALID_PARAMETERS,
          "FFA_ERROR naming a target in w1 (MBZ here) is INVALID_PARAMETERS");
    x[1] = 0u;
    x[2] = 0u;
    check(wt_ffa_rt_error_check(x) == WT_FFA_INVALID_PARAMETERS,
          "FFA_ERROR without an error code is INVALID_PARAMETERS");

    x[0] = WT_FFA_YIELD;
    x[4] = 0xFFFFFFFFu;
    x[7] = 1u;
    x[1] = 0xFFFFFFFF00000000ull;
    check(wt_ffa_rt_yield_check(x) == 0,
          "FFA_YIELD ignores its SBZ w4-w7 and reads w1-w3 alone");
    x[1] = 0x80030000u;
    check(wt_ffa_rt_yield_check(x) == WT_FFA_INVALID_PARAMETERS,
          "a partition's FFA_YIELD naming an endpoint in w1 (MBZ) is refused");
    x[1] = 0u;
    x[2] = 1000u;
    check(wt_ffa_rt_yield_check(x) == WT_FFA_INVALID_PARAMETERS,
          "and so is one asking for a timeout in w2, the Hypervisor's alone");
    x[2] = 0u;
    x[3] = 1u;
    check(wt_ffa_rt_yield_check(x) == WT_FFA_INVALID_PARAMETERS,
          "or in w3");
    x[3] = 0u;
}

/* FFA_MSG_WAIT's Retain RX Buffer Ownership flag (DEN0077A 1.2 REL0 Table
 * 14.3): w2 bit 0 keeps the buffer for a v1.2 caller; w2 was SBZ before. */
static void msg_wait_rx_rows(void)
{
    uint64_t x[8] = { 0 };

    x[0] = WT_FFA_MSG_WAIT;
    check(wt_ffa_rt_msg_wait_releases_rx(WT_FFA_VERSION_1_2, x) == 1,
          "MSG_WAIT with the retain flag clear hands the RX buffer back");
    x[2] = WT_FFA_MSG_WAIT_RETAIN_RX;
    check(wt_ffa_rt_msg_wait_releases_rx(WT_FFA_VERSION_1_2, x) == 0,
          "MSG_WAIT with w2 bit 0 set keeps a v1.2 caller's RX buffer");
    x[2] = 0xFFFFFFFFull;
    check(wt_ffa_rt_msg_wait_releases_rx(WT_FFA_VERSION_1_2, x) == 0,
          "SBZ w2 bits[31:1] do not cancel the retain flag");
    x[2] = 0xFFFFFFFEull | 0xFFFFFFFF00000000ull;
    check(wt_ffa_rt_msg_wait_releases_rx(WT_FFA_VERSION_1_2, x) == 1,
          "only w2 bit 0 retains: SBZ bits and the upper half are ignored");
    x[2] = WT_FFA_MSG_WAIT_RETAIN_RX;
    x[1] = 0xFFFFFFFFull;
    x[3] = 0xFFFFFFFFull;
    x[7] = 0xFFFFFFFFull;
    check(wt_ffa_rt_msg_wait_releases_rx(WT_FFA_VERSION_1_2, x) == 0,
          "SBZ w1 and w3-w7 do not change the retain decision");
    check(wt_ffa_rt_msg_wait_releases_rx(0x00010001u, x) == 1 &&
          wt_ffa_rt_msg_wait_releases_rx(0x00010000u, x) == 1,
          "a v1.1 or v1.0 caller's SBZ w2 never keeps the RX buffer");
}

int main(void)
{
    wt_ffa_rt_state_t s = WT_FFA_RT_RUNNING;

    printf("WT-FFA-0006 (FF-A partition runtime state machine)\n");

    run_table();
    run_chain();
    init_model_rows();
    status_encoding_rows();
    msg_wait_rx_rows();

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
