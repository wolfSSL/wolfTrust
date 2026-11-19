/* vnet_switch.c
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

#include <stddef.h>
#include <string.h>
#include "wolftrust/vnet/vnet_switch.h"
#include "wolftrust/vnet/vnet_errors.h"

static void vnic_reset(vnet_vnic_t *v, vnet_rx_desc_t *ring_storage,
                       uint16_t ring_capacity)
{
    v->open = false;
    v->mac_set = false;
    memset(&v->mac, 0, sizeof(v->mac));
    v->mtu = (uint16_t)WT_VNET_FRAME_MAX;
    v->rx_irq_pending = false;
    vnet_ring_init(&v->rxq, ring_storage, ring_capacity);
    memset(&v->stats, 0, sizeof(v->stats));
}

int vnet_switch_init(vnet_switch_t    *sw,
                     vnet_vnic_t      *vnics,
                     uint32_t          nvm,
                     vnet_frame_t     *frame_storage,
                     uint16_t          frame_count,
                     vnet_fdb_entry_t *fdb_storage,
                     uint16_t          fdb_capacity,
                     vnet_rx_desc_t  **rx_ring_storage,
                     uint16_t          rx_ring_capacity,
                     bool              unknown_unicast_flood)
{
    uint32_t i;

    if (sw == NULL || vnics == NULL || frame_storage == NULL ||
        fdb_storage == NULL || rx_ring_storage == NULL) {
        return WT_VNET_E_BADARG;
    }
    if (nvm == 0U || frame_count == 0U || fdb_capacity == 0U ||
        rx_ring_capacity == 0U) {
        return WT_VNET_E_BADARG;
    }

    sw->vnics = vnics;
    sw->nvm = nvm;
    vnet_pool_init(&sw->pool, frame_storage, frame_count);
    vnet_fdb_init(&sw->fdb, fdb_storage, fdb_capacity);
    sw->unknown_unicast_flood = unknown_unicast_flood;
    memset(&sw->global_stats, 0, sizeof(sw->global_stats));

    for (i = 0U; i < nvm; ++i) {
        vnic_reset(&vnics[i], rx_ring_storage[i], rx_ring_capacity);
    }
    return WT_VNET_OK;
}

static vnet_vnic_t *vnic_of(vnet_switch_t *sw, uint32_t vm_id)
{
    if (sw == NULL || vm_id >= sw->nvm) return NULL;
    return &sw->vnics[vm_id];
}

static const vnet_vnic_t *vnic_of_const(const vnet_switch_t *sw, uint32_t vm_id)
{
    if (sw == NULL || vm_id >= sw->nvm) return NULL;
    return &sw->vnics[vm_id];
}

int vnet_switch_reset_vm(vnet_switch_t *sw, uint32_t vm_id)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    vnet_rx_desc_t desc;

    if (v == NULL) return WT_VNET_E_BADARG;
    while (vnet_ring_pop(&v->rxq, &desc) == WT_VNET_OK) {
        (void)vnet_pool_release(&sw->pool, desc.slot, desc.gen);
    }
    vnet_fdb_release(&sw->fdb, vm_id);
    vnic_reset(v, v->rxq.buf, v->rxq.capacity);
    return WT_VNET_OK;
}

int vnet_switch_open(vnet_switch_t *sw, uint32_t vm_id, vnet_info_t *info_out)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    if (v == NULL) return WT_VNET_E_BADARG;

    v->open = true;
    if (info_out != NULL) {
        memset(info_out, 0, sizeof(*info_out));
        info_out->abi_version = WT_VNET_ABI_VERSION;
        info_out->features = 0U;
        info_out->mtu = v->mtu;
        info_out->rx_irq = (int16_t)WT_VNET_RX_IRQ;
        if (v->mac_set) {
            vnet_mac_copy(&info_out->default_mac, &v->mac);
            info_out->mac_set = true;
        }
    }
    return WT_VNET_OK;
}

int vnet_switch_assign_mac(vnet_switch_t *sw, uint32_t vm_id,
                           const vnet_mac_t *mac)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    int rc;
    if (v == NULL || mac == NULL) return WT_VNET_E_BADARG;
    if (!v->open) return WT_VNET_E_NOT_OPEN;

    if (!vnet_mac_is_locally_administered_unicast(mac)) {
        v->stats.err_invalid_mac_assign++;
        sw->global_stats.err_invalid_mac_assign++;
        return WT_VNET_E_INVAL_MAC;
    }

    if (v->mac_set && !vnet_mac_equals(&v->mac, mac)) {
        v->stats.err_dup_mac_assign++;
        sw->global_stats.err_dup_mac_assign++;
        return WT_VNET_E_DUP_MAC;
    }

    rc = vnet_fdb_assign(&sw->fdb, vm_id, mac);
    if (rc != WT_VNET_OK) {
        if (rc == WT_VNET_E_DUP_MAC) {
            v->stats.err_dup_mac_assign++;
            sw->global_stats.err_dup_mac_assign++;
        } else if (rc == WT_VNET_E_INVAL_MAC) {
            v->stats.err_invalid_mac_assign++;
            sw->global_stats.err_invalid_mac_assign++;
        }
        return rc;
    }

    vnet_mac_copy(&v->mac, mac);
    v->mac_set = true;
    return WT_VNET_OK;
}

static int try_deliver_one(vnet_switch_t *sw, vnet_vnic_t *dst,
                           uint16_t slot, uint16_t gen, uint16_t len,
                           uint32_t src_vm)
{
    vnet_rx_desc_t desc;
    int rc;
    if (!dst->open) return WT_VNET_E_DROPPED_POLICY;

    desc.slot = slot;
    desc.gen = gen;
    desc.len = len;
    desc.flags = 0U;
    desc.src_vm = src_vm;

    rc = vnet_ring_push(&dst->rxq, &desc);
    if (rc != WT_VNET_OK) {
        dst->stats.drop_queue_full++;
        sw->global_stats.drop_queue_full++;
        return rc;
    }

    if (vnet_pool_ref(&sw->pool, slot, gen) != WT_VNET_OK) {
        /* This should not happen — the slot was just allocated with
         * refcnt=1 and is held by our scratch ref through delivery.
         * If it does, undo the queue push to keep accounting tight. */
        vnet_ring_t *r = &dst->rxq;
        if (r->count > 0U) {
            r->head = (r->head == 0U) ? (uint16_t)(r->capacity - 1U)
                                      : (uint16_t)(r->head - 1U);
            r->count = (uint16_t)(r->count - 1U);
        }
        return WT_VNET_E_NOTREADY;
    }

    dst->rx_irq_pending = true;
    dst->stats.rx_frames++;
    dst->stats.rx_bytes += len;
    sw->global_stats.rx_frames++;
    sw->global_stats.rx_bytes += len;
    return WT_VNET_OK;
}

int vnet_switch_tx(vnet_switch_t *sw, uint32_t src_vm,
                   const uint8_t *frame, uint16_t len,
                   uint32_t now_tick)
{
    vnet_vnic_t *src;
    vnet_mac_t dst_mac;
    vnet_mac_t src_mac;
    uint16_t slot;
    uint16_t gen;
    vnet_frame_t *f;
    uint32_t deliveries = 0U;
    uint32_t dst_vm;
    bool dst_multicast;

    if (sw == NULL || frame == NULL) return WT_VNET_E_BADARG;
    src = vnic_of(sw, src_vm);
    if (src == NULL) return WT_VNET_E_BADARG;
    if (!src->open) return WT_VNET_E_NOT_OPEN;
    if (!src->mac_set) {
        src->stats.err_spoof_src_mac++;
        sw->global_stats.err_spoof_src_mac++;
        return WT_VNET_E_NO_MAC;
    }

    if (len < WT_VNET_FRAME_MIN || len > (uint16_t)WT_VNET_FRAME_MAX) {
        src->stats.err_malformed++;
        sw->global_stats.err_malformed++;
        return WT_VNET_E_FRAME_LEN;
    }

    memcpy(dst_mac.b, &frame[0], VNET_MAC_LEN);
    memcpy(src_mac.b, &frame[VNET_MAC_LEN], VNET_MAC_LEN);

    if (vnet_mac_is_zero(&src_mac) || vnet_mac_is_multicast(&src_mac)) {
        src->stats.err_malformed++;
        sw->global_stats.err_malformed++;
        return WT_VNET_E_MALFORMED;
    }
    if (!vnet_mac_equals(&src_mac, &src->mac)) {
        src->stats.err_spoof_src_mac++;
        sw->global_stats.err_spoof_src_mac++;
        return WT_VNET_E_SPOOF;
    }

    /* Source-based learning. With an ASSIGNED entry already in place
     * this is a no-op success; we still call it so the FDB code path
     * is uniform for future scenarios where TX precedes assign. */
    (void)vnet_fdb_learn(&sw->fdb, src_vm, &src_mac);

    slot = vnet_pool_alloc(&sw->pool, now_tick);
    if (slot == VNET_POOL_BAD_SLOT) {
        src->stats.drop_pool_full++;
        sw->global_stats.drop_pool_full++;
        return WT_VNET_E_POOL_FULL;
    }
    f = &sw->pool.slots[slot];
    gen = f->gen;
    memcpy(f->data, frame, len);
    f->len = len;
    f->src_vm = src_vm;
    f->dst_mask = 0U;

    src->stats.tx_frames++;
    src->stats.tx_bytes += len;
    sw->global_stats.tx_frames++;
    sw->global_stats.tx_bytes += len;

    dst_multicast = vnet_mac_is_multicast(&dst_mac);
    if (vnet_mac_is_zero(&dst_mac)) {
        /* Zero dst — malformed. Drop without delivery. */
        src->stats.err_malformed++;
        sw->global_stats.err_malformed++;
        (void)vnet_pool_release(&sw->pool, slot, gen);
        return WT_VNET_E_MALFORMED;
    }

    if (!dst_multicast) {
        dst_vm = vnet_fdb_lookup(&sw->fdb, &dst_mac);
        if (dst_vm != VNET_FDB_NO_VM && dst_vm != src_vm) {
            vnet_vnic_t *dst = vnic_of(sw, dst_vm);
            if (dst != NULL &&
                try_deliver_one(sw, dst, slot, gen,
                                len, src_vm) == WT_VNET_OK) {
                deliveries++;
            }
        } else if (dst_vm == VNET_FDB_NO_VM && sw->unknown_unicast_flood) {
            uint32_t i;
            for (i = 0U; i < sw->nvm; ++i) {
                if (i == src_vm) continue;
                if (try_deliver_one(sw, &sw->vnics[i], slot, gen,
                                    len, src_vm) == WT_VNET_OK) {
                    deliveries++;
                }
            }
        }
    } else {
        uint32_t i;
        for (i = 0U; i < sw->nvm; ++i) {
            if (i == src_vm) continue;
            if (try_deliver_one(sw, &sw->vnics[i], slot, gen,
                                len, src_vm) == WT_VNET_OK) {
                deliveries++;
            }
        }
    }

    /* Drop the scratch ref. If deliveries == 0, the slot frees here. */
    (void)vnet_pool_release(&sw->pool, slot, gen);

    if (deliveries == 0U) {
        if (!dst_multicast) {
            src->stats.drop_unknown_unicast++;
            sw->global_stats.drop_unknown_unicast++;
            return WT_VNET_E_DROPPED_UNKNOWN;
        }
        src->stats.drop_policy++;
        sw->global_stats.drop_policy++;
        return WT_VNET_E_DROPPED_POLICY;
    }
    return WT_VNET_OK;
}

static void skip_stale_head(vnet_switch_t *sw, vnet_vnic_t *v)
{
    vnet_rx_desc_t desc;
    while (vnet_ring_peek(&v->rxq, &desc) == WT_VNET_OK) {
        if (vnet_pool_slot(&sw->pool, desc.slot, desc.gen) != NULL) return;
        (void)vnet_ring_drop_head(&v->rxq);
    }
}

int vnet_switch_poll_rx(vnet_switch_t *sw, uint32_t vm_id,
                        vnet_rx_meta_t *meta)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    vnet_rx_desc_t desc;
    int rc;
    if (v == NULL || meta == NULL) return WT_VNET_E_BADARG;
    if (!v->open) return WT_VNET_E_NOT_OPEN;

    skip_stale_head(sw, v);
    if (vnet_ring_empty(&v->rxq)) {
        v->rx_irq_pending = false;
        return WT_VNET_E_EMPTY;
    }
    rc = vnet_ring_peek(&v->rxq, &desc);
    if (rc != WT_VNET_OK) return rc;

    meta->token_slot = desc.slot;
    meta->token_gen = desc.gen;
    meta->len = desc.len;
    meta->flags = desc.flags;
    meta->src_vm = desc.src_vm;
    return WT_VNET_OK;
}

int vnet_switch_read_rx(vnet_switch_t *sw, uint32_t vm_id,
                        uint16_t slot, uint16_t gen,
                        uint8_t *dst, uint16_t dst_len)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    vnet_rx_desc_t head;
    vnet_frame_t *f;
    if (v == NULL || dst == NULL) return WT_VNET_E_BADARG;
    if (!v->open) return WT_VNET_E_NOT_OPEN;

    skip_stale_head(sw, v);
    if (vnet_ring_peek(&v->rxq, &head) != WT_VNET_OK) return WT_VNET_E_EMPTY;
    if (head.slot != slot || head.gen != gen) return WT_VNET_E_NOT_OWNER;

    f = vnet_pool_slot(&sw->pool, slot, gen);
    if (f == NULL) return WT_VNET_E_STALE_COOKIE;
    if (dst_len < f->len) return WT_VNET_E_BADARG;

    memcpy(dst, f->data, f->len);
    return (int)f->len;
}

int vnet_switch_release_rx(vnet_switch_t *sw, uint32_t vm_id,
                           uint16_t slot, uint16_t gen)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    vnet_rx_desc_t head;
    int rc;
    if (v == NULL) return WT_VNET_E_BADARG;
    if (!v->open) return WT_VNET_E_NOT_OPEN;

    skip_stale_head(sw, v);
    if (vnet_ring_peek(&v->rxq, &head) != WT_VNET_OK) {
        v->stats.err_release++;
        sw->global_stats.err_release++;
        return WT_VNET_E_EMPTY;
    }
    if (head.slot != slot || head.gen != gen) {
        v->stats.err_release++;
        sw->global_stats.err_release++;
        return WT_VNET_E_NOT_OWNER;
    }

    (void)vnet_ring_drop_head(&v->rxq);
    rc = vnet_pool_release(&sw->pool, slot, gen);
    if (rc < 0) {
        v->stats.err_release++;
        sw->global_stats.err_release++;
        return rc;
    }

    if (vnet_ring_empty(&v->rxq)) v->rx_irq_pending = false;
    return WT_VNET_OK;
}

int vnet_switch_irq_ack(vnet_switch_t *sw, uint32_t vm_id)
{
    vnet_vnic_t *v = vnic_of(sw, vm_id);
    if (v == NULL) return WT_VNET_E_BADARG;
    if (!v->open) return WT_VNET_E_NOT_OPEN;

    skip_stale_head(sw, v);
    if (vnet_ring_empty(&v->rxq)) {
        v->rx_irq_pending = false;
        return 0;
    }
    v->rx_irq_pending = true;
    return 1;
}

bool vnet_switch_irq_pending(const vnet_switch_t *sw, uint32_t vm_id)
{
    const vnet_vnic_t *v = vnic_of_const(sw, vm_id);
    if (v == NULL) return false;
    return v->rx_irq_pending;
}

uint16_t vnet_switch_drop_expired(vnet_switch_t *sw,
                                  uint32_t       now_tick,
                                  uint32_t       timeout_ticks)
{
    uint32_t i;
    uint16_t freed;
    if (sw == NULL) return 0U;
    freed = vnet_pool_drop_expired(&sw->pool, now_tick, timeout_ticks);
    if (freed > 0U) {
        sw->global_stats.drop_timeout += freed;
        for (i = 0U; i < sw->nvm; ++i) {
            skip_stale_head(sw, &sw->vnics[i]);
            if (vnet_ring_empty(&sw->vnics[i].rxq)) {
                sw->vnics[i].rx_irq_pending = false;
            }
        }
    }
    return freed;
}

const vnet_stats_t *vnet_switch_vnic_stats(const vnet_switch_t *sw,
                                           uint32_t             vm_id)
{
    const vnet_vnic_t *v = vnic_of_const(sw, vm_id);
    if (v == NULL) return NULL;
    return &v->stats;
}

const vnet_stats_t *vnet_switch_global_stats(const vnet_switch_t *sw)
{
    if (sw == NULL) return NULL;
    return &sw->global_stats;
}
