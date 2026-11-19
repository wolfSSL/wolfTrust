/* test_switch.c
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

#include <string.h>
#include "test_vnet.h"
#include "wolftrust/vnet/vnet_switch.h"
#include "wolftrust/vnet/vnet_errors.h"

#define NVM      3
#define POOL_N   4
#define FDB_N    8
#define RING_N   4

static vnet_vnic_t      g_vnics[NVM];
static vnet_frame_t     g_frames[POOL_N];
static vnet_fdb_entry_t g_fdb[FDB_N];
static vnet_rx_desc_t   g_ring0[RING_N];
static vnet_rx_desc_t   g_ring1[RING_N];
static vnet_rx_desc_t   g_ring2[RING_N];
static vnet_rx_desc_t  *g_rings[NVM];

static const vnet_mac_t MAC_A = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x0A}};
static const vnet_mac_t MAC_B = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x0B}};
static const vnet_mac_t MAC_C = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x0C}};
static const vnet_mac_t MAC_BCAST = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
static const vnet_mac_t MAC_MCAST = {{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}};
static const vnet_mac_t MAC_UNK = {{0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}};

static int setup_switch(vnet_switch_t *sw, bool flood)
{
    g_rings[0] = g_ring0;
    g_rings[1] = g_ring1;
    g_rings[2] = g_ring2;
    T_EQ_INT(vnet_switch_init(sw, g_vnics, NVM,
                              g_frames, POOL_N,
                              g_fdb, FDB_N,
                              g_rings, RING_N,
                              flood), WT_VNET_OK);
    return 0;
}

#define SETUP(sw, flood) do { if (setup_switch((sw), (flood))) return -1; } while (0)
#define DO(call) do { if ((call)) return -1; } while (0)

static void build_frame(uint8_t *buf, const vnet_mac_t *dst,
                        const vnet_mac_t *src, uint16_t payload_seed)
{
    (void)memset(buf, 0, 64U);
    memcpy(&buf[0], dst->b, VNET_MAC_LEN);
    memcpy(&buf[6], src->b, VNET_MAC_LEN);
    buf[12] = 0x08;
    buf[13] = 0x00;
    buf[14] = (uint8_t)(payload_seed & 0xFFU);
    buf[15] = (uint8_t)((payload_seed >> 8) & 0xFFU);
}

static int open_and_assign_two(vnet_switch_t *sw)
{
    vnet_info_t info;
    T_EQ_INT(vnet_switch_open(sw, 0, &info), WT_VNET_OK);
    T_EQ_INT(info.abi_version, WT_VNET_ABI_VERSION);
    T_EQ_INT(info.rx_irq, (int16_t)WT_VNET_RX_IRQ);
    T_EQ_INT(vnet_switch_open(sw, 1, NULL), WT_VNET_OK);
    T_EQ_INT(vnet_switch_open(sw, 2, NULL), WT_VNET_OK);
    T_EQ_INT(vnet_switch_assign_mac(sw, 0, &MAC_A), WT_VNET_OK);
    T_EQ_INT(vnet_switch_assign_mac(sw, 1, &MAC_B), WT_VNET_OK);
    T_EQ_INT(vnet_switch_assign_mac(sw, 2, &MAC_C), WT_VNET_OK);
    return 0;
}

static int test_open_assign(void)
{
    vnet_switch_t sw;
    vnet_info_t info;
    SETUP(&sw, false);

    T_EQ_INT(vnet_switch_open(&sw, 0, &info), WT_VNET_OK);
    T_EQ_INT(info.abi_version, WT_VNET_ABI_VERSION);
    T_CHECK(!info.mac_set);

    T_EQ_INT(vnet_switch_open(&sw, NVM, NULL), WT_VNET_E_BADARG);
    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_A), WT_VNET_OK);

    /* Re-open after assign reports the assigned MAC. */
    T_EQ_INT(vnet_switch_open(&sw, 0, &info), WT_VNET_OK);
    T_CHECK(info.mac_set);
    T_CHECK(vnet_mac_equals(&info.default_mac, &MAC_A));

    /* Idempotent re-assign of same MAC. */
    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_A), WT_VNET_OK);
    /* Different MAC rejected. */
    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_B), WT_VNET_E_DUP_MAC);
    return 0;
}

static int test_assign_rejections(void)
{
    vnet_switch_t sw;
    uint8_t f[64];

    SETUP(&sw, false);
    T_EQ_INT(vnet_switch_open(&sw, 0, NULL), WT_VNET_OK);
    T_EQ_INT(vnet_switch_open(&sw, 1, NULL), WT_VNET_OK);

    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_BCAST), WT_VNET_E_INVAL_MAC);
    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_MCAST), WT_VNET_E_INVAL_MAC);

    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_A), WT_VNET_OK);
    /* Guest 1 tries to claim guest 0's MAC. */
    T_EQ_INT(vnet_switch_assign_mac(&sw, 1, &MAC_A), WT_VNET_E_DUP_MAC);

    /* TX without open returns NOT_OPEN. */
    build_frame(f, &MAC_B, &MAC_A, 1);
    T_EQ_INT(vnet_switch_tx(&sw, 2, f, 64, 0), WT_VNET_E_NOT_OPEN);
    return 0;
}

static int test_tx_spoof(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    /* Guest 0 tries to send a frame with guest 1's MAC as source. */
    build_frame(f, &MAC_C, &MAC_B, 1);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_E_SPOOF);
    T_EQ_INT(vnet_switch_vnic_stats(&sw, 0)->err_spoof_src_mac, 1);

    /* Frame whose source MAC is multicast is malformed (rejected at L2). */
    build_frame(f, &MAC_C, &MAC_BCAST, 1);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_E_MALFORMED);

    /* Frame length below 14 is rejected. */
    build_frame(f, &MAC_B, &MAC_A, 1);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 13, 0), WT_VNET_E_FRAME_LEN);
    return 0;
}

static int test_unicast_delivery(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    vnet_rx_meta_t meta2;
    uint8_t out[64];
    int n;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    build_frame(f, &MAC_B, &MAC_A, 0x1234);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 100), WT_VNET_OK);

    /* B receives it, A and C do not. */
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_OK);
    T_EQ_INT(meta.len, 64);
    T_EQ_INT(meta.src_vm, 0);
    T_CHECK(vnet_switch_irq_pending(&sw, 1));

    T_EQ_INT(vnet_switch_poll_rx(&sw, 0, &meta), WT_VNET_E_EMPTY);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 2, &meta), WT_VNET_E_EMPTY);
    T_CHECK(!vnet_switch_irq_pending(&sw, 0));
    T_CHECK(!vnet_switch_irq_pending(&sw, 2));

    n = vnet_switch_read_rx(&sw, 1, meta.token_slot, meta.token_gen, out, 64);
    T_EQ_INT(n, 64);
    T_CHECK(memcmp(out, f, 64) == 0);

    /* Read does not auto-release: poll again still returns the same meta. */
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta2), WT_VNET_OK);
    T_EQ_INT(meta2.token_slot, meta.token_slot);
    T_EQ_INT(meta2.token_gen, meta.token_gen);

    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_E_EMPTY);
    T_EQ_INT(vnet_switch_irq_ack(&sw, 1), 0);
    T_CHECK(!vnet_switch_irq_pending(&sw, 1));
    T_EQ_INT(vnet_switch_global_stats(&sw)->rx_frames, 1);
    T_EQ_INT(vnet_switch_global_stats(&sw)->tx_frames, 1);
    return 0;
}

static int test_broadcast_delivery(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    build_frame(f, &MAC_BCAST, &MAC_A, 0xBEEF);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 200), WT_VNET_OK);

    /* B and C both receive; A does not. */
    T_EQ_INT(vnet_switch_poll_rx(&sw, 0, &meta), WT_VNET_E_EMPTY);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_OK);
    T_EQ_INT(meta.src_vm, 0);
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_OK);

    T_EQ_INT(vnet_switch_poll_rx(&sw, 2, &meta), WT_VNET_OK);
    T_EQ_INT(meta.src_vm, 0);
    T_EQ_INT(vnet_switch_release_rx(&sw, 2, meta.token_slot, meta.token_gen),
             WT_VNET_OK);

    /* Multicast destination uses the same broadcast-style fanout. */
    build_frame(f, &MAC_MCAST, &MAC_B, 0xCAFE);
    T_EQ_INT(vnet_switch_tx(&sw, 1, f, 64, 300), WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 0, &meta), WT_VNET_OK);
    T_EQ_INT(vnet_switch_release_rx(&sw, 0, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 2, &meta), WT_VNET_OK);
    T_EQ_INT(vnet_switch_release_rx(&sw, 2, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_E_EMPTY);
    return 0;
}

static int test_unknown_unicast_drop(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    build_frame(f, &MAC_UNK, &MAC_A, 0);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_E_DROPPED_UNKNOWN);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_E_EMPTY);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 2, &meta), WT_VNET_E_EMPTY);
    T_EQ_INT(vnet_switch_vnic_stats(&sw, 0)->drop_unknown_unicast, 1);
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), 0);
    return 0;
}

static int test_unknown_unicast_flood(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    SETUP(&sw, true);
    DO(open_and_assign_two(&sw));

    build_frame(f, &MAC_UNK, &MAC_A, 0);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_OK);
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 2, &meta), WT_VNET_OK);
    T_EQ_INT(vnet_switch_release_rx(&sw, 2, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    return 0;
}

static int test_queue_full(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    int i;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    /* RING_N is 4, so 4 broadcasts each pin one descriptor in B's
     * ring (and C's). The 5th broadcast cannot enqueue at B (or C)
     * because rings are full — but the rings fill via two
     * independent ASSIGNED destinations. With POOL_N=4, the pool
     * runs out before the per-vnic ring does. */
    build_frame(f, &MAC_B, &MAC_A, 0);
    for (i = 0; i < POOL_N; ++i) {
        T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, (uint32_t)i), WT_VNET_OK);
    }
    /* Pool now exhausted — next TX drops with E_POOL_FULL. */
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 100), WT_VNET_E_POOL_FULL);
    T_EQ_INT(vnet_switch_vnic_stats(&sw, 0)->drop_pool_full, 1);
    return 0;
}

static int test_queue_full_per_vnic(void)
{
    vnet_switch_t sw;
    vnet_vnic_t  vnics2[2];
    vnet_rx_desc_t r0[RING_N];
    vnet_rx_desc_t r1[RING_N];
    vnet_rx_desc_t *rings2[2];
    vnet_frame_t   frames_big[16];
    uint8_t f[64];
    int i;

    /* Use a larger pool so the per-vnic ring fills before the pool does. */
    rings2[0] = r0;
    rings2[1] = r1;
    T_EQ_INT(vnet_switch_init(&sw, vnics2, 2,
                              frames_big, 16,
                              g_fdb, FDB_N,
                              rings2, RING_N,
                              false), WT_VNET_OK);
    T_EQ_INT(vnet_switch_open(&sw, 0, NULL), WT_VNET_OK);
    T_EQ_INT(vnet_switch_open(&sw, 1, NULL), WT_VNET_OK);
    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_A), WT_VNET_OK);
    T_EQ_INT(vnet_switch_assign_mac(&sw, 1, &MAC_B), WT_VNET_OK);

    build_frame(f, &MAC_B, &MAC_A, 0);
    for (i = 0; i < RING_N; ++i) {
        T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, (uint32_t)i), WT_VNET_OK);
    }
    /* B's ring is full. Next TX accepts but delivers to 0 destinations —
     * unicast known dst, single recipient B's ring is full → drop_queue_full,
     * returns E_DROPPED_UNKNOWN (no delivery happened). */
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 100), WT_VNET_E_DROPPED_UNKNOWN);
    T_EQ_INT(vnet_switch_vnic_stats(&sw, 1)->drop_queue_full, 1);
    /* Pool is back to RING_N in use (the dropped slot was scratch-released). */
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), RING_N);
    return 0;
}

static int test_release_errors(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    build_frame(f, &MAC_B, &MAC_A, 0);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_OK);

    /* Wrong VM. */
    T_EQ_INT(vnet_switch_release_rx(&sw, 0, meta.token_slot, meta.token_gen),
             WT_VNET_E_EMPTY);

    /* Wrong cookie. */
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot,
                                    (uint16_t)(meta.token_gen + 100)),
             WT_VNET_E_NOT_OWNER);

    /* Correct release. */
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    /* Double release: queue is now empty. */
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_E_EMPTY);
    return 0;
}

static int test_timeout_reaper(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    uint16_t freed;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    build_frame(f, &MAC_B, &MAC_A, 0);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 100), WT_VNET_OK);
    T_CHECK(vnet_switch_irq_pending(&sw, 1));

    /* Reap at now=200 with timeout=500 — too soon, nothing freed. */
    freed = vnet_switch_drop_expired(&sw, 200, 500);
    T_EQ_INT(freed, 0);
    T_CHECK(vnet_switch_irq_pending(&sw, 1));

    /* Reap at now=700 — frame born at 100 is expired (age 600 >= 500). */
    freed = vnet_switch_drop_expired(&sw, 700, 500);
    T_EQ_INT(freed, 1);
    T_EQ_INT(vnet_switch_global_stats(&sw)->drop_timeout, 1);
    T_CHECK(!vnet_switch_irq_pending(&sw, 1));
    /* Poll skips the now-stale descriptor and returns EMPTY. */
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_E_EMPTY);
    return 0;
}

static int test_irq_ack_semantics(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    /* Two TX → B → two RX descriptors pending. */
    build_frame(f, &MAC_B, &MAC_A, 1);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_OK);
    build_frame(f, &MAC_B, &MAC_A, 2);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_OK);
    T_CHECK(vnet_switch_irq_pending(&sw, 1));

    /* Ack with queue non-empty leaves IRQ asserted. */
    T_EQ_INT(vnet_switch_irq_ack(&sw, 1), 1);
    T_CHECK(vnet_switch_irq_pending(&sw, 1));

    /* Drain first frame; queue still non-empty. */
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_OK);
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_switch_irq_ack(&sw, 1), 1);

    /* Drain second; queue empty; ack clears. */
    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta), WT_VNET_OK);
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta.token_slot, meta.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_switch_irq_ack(&sw, 1), 0);
    T_CHECK(!vnet_switch_irq_pending(&sw, 1));
    return 0;
}

static int test_release_decrements_refcount(void)
{
    vnet_switch_t sw;
    uint8_t f[64];
    vnet_rx_meta_t meta_b;
    vnet_rx_meta_t meta_c;
    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));

    /* Broadcast pins one frame at refcnt=2 (delivered to B and C). */
    build_frame(f, &MAC_BCAST, &MAC_A, 0);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_OK);
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), 1);

    T_EQ_INT(vnet_switch_poll_rx(&sw, 1, &meta_b), WT_VNET_OK);
    T_EQ_INT(vnet_switch_poll_rx(&sw, 2, &meta_c), WT_VNET_OK);
    T_EQ_INT(meta_b.token_slot, meta_c.token_slot);

    /* B releases — slot still pinned by C. */
    T_EQ_INT(vnet_switch_release_rx(&sw, 1, meta_b.token_slot, meta_b.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), 1);

    /* C releases — slot freed. */
    T_EQ_INT(vnet_switch_release_rx(&sw, 2, meta_c.token_slot, meta_c.token_gen),
             WT_VNET_OK);
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), 0);
    return 0;
}

/* A restarted or quarantined guest gets a clean port: its MAC binding, FDB
 * entries and queued frames do not outlive the instance that owned them. */
static int test_reset_vm(void)
{
    vnet_switch_t sw;
    vnet_info_t info;
    uint8_t f[64];

    SETUP(&sw, false);
    DO(open_and_assign_two(&sw));
    build_frame(f, &MAC_A, &MAC_B, 1);
    T_EQ_INT(vnet_switch_tx(&sw, 1, f, 64, 0), WT_VNET_OK);
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), 1);

    T_EQ_INT(vnet_switch_reset_vm(&sw, 0), WT_VNET_OK);
    T_EQ_INT(vnet_pool_in_use_count(&sw.pool), 0);
    T_EQ_INT(vnet_switch_tx(&sw, 0, f, 64, 0), WT_VNET_E_NOT_OPEN);
    T_EQ_INT(vnet_switch_open(&sw, 0, &info), WT_VNET_OK);
    T_CHECK(!info.mac_set);
    T_EQ_INT(vnet_switch_assign_mac(&sw, 0, &MAC_UNK), WT_VNET_OK);
    T_CHECK(!vnet_switch_irq_pending(&sw, 0));

    /* The peer's port is untouched and the released MAC is reusable. */
    T_EQ_INT(vnet_switch_assign_mac(&sw, 1, &MAC_B), WT_VNET_OK);
    T_CHECK(vnet_fdb_lookup(&sw.fdb, &MAC_A) == VNET_FDB_NO_VM);
    T_CHECK(vnet_fdb_lookup(&sw.fdb, &MAC_UNK) == 0U);
    T_EQ_INT(vnet_switch_reset_vm(&sw, NVM), WT_VNET_E_BADARG);
    return 0;
}

int run_switch_tests(void)
{
    int rc = 0;
    rc |= test_open_assign();
    rc |= test_assign_rejections();
    rc |= test_tx_spoof();
    rc |= test_unicast_delivery();
    rc |= test_broadcast_delivery();
    rc |= test_unknown_unicast_drop();
    rc |= test_unknown_unicast_flood();
    rc |= test_queue_full();
    rc |= test_queue_full_per_vnic();
    rc |= test_release_errors();
    rc |= test_timeout_reaper();
    rc |= test_irq_ack_semantics();
    rc |= test_release_decrements_refcount();
    rc |= test_reset_vm();
    return rc;
}
