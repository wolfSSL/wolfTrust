/* vnet_pool.c
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
#include "wolftrust/vnet/vnet_pool.h"
#include "wolftrust/vnet/vnet_errors.h"
#include "wolftrust/zeroize.h"

void vnet_pool_init(vnet_pool_t *p, vnet_frame_t *storage, uint16_t count)
{
    uint16_t i;
    if (p == NULL) return;
    p->slots = storage;
    p->slot_count = (storage == NULL) ? 0U : count;
    p->in_use_count = 0U;
    for (i = 0U; i < p->slot_count; ++i) {
        wt_forceZero(p->slots[i].data, sizeof(p->slots[i].data));
        p->slots[i].refcnt = 0U;
        p->slots[i].gen = 0U;
        p->slots[i].len = 0U;
        p->slots[i].flags = 0U;
        p->slots[i].src_vm = 0U;
        p->slots[i].dst_mask = 0U;
        p->slots[i].born_tick = 0U;
    }
}

uint16_t vnet_pool_alloc(vnet_pool_t *p, uint32_t now_tick)
{
    uint16_t i;
    if (p == NULL || p->slots == NULL) return VNET_POOL_BAD_SLOT;
    for (i = 0U; i < p->slot_count; ++i) {
        if (p->slots[i].refcnt == 0U) {
            /* Bump gen — gen wraps but that's fine: a guest holding a
             * stale (slot, gen) cookie sees a mismatch eventually, and
             * the 16-bit space is wide enough that the race window is
             * vanishingly small in practice. */
            p->slots[i].gen = (uint16_t)(p->slots[i].gen + 1U);
            p->slots[i].refcnt = 1U;
            p->slots[i].len = 0U;
            p->slots[i].flags = 0U;
            p->slots[i].src_vm = 0U;
            p->slots[i].dst_mask = 0U;
            p->slots[i].born_tick = now_tick;
            p->in_use_count++;
            return i;
        }
    }
    return VNET_POOL_BAD_SLOT;
}

int vnet_pool_ref(vnet_pool_t *p, uint16_t slot, uint16_t gen)
{
    vnet_frame_t *f;
    if (p == NULL || p->slots == NULL) return WT_VNET_E_BADARG;
    if (slot >= p->slot_count) return WT_VNET_E_BADARG;
    f = &p->slots[slot];
    if (f->refcnt == 0U) return WT_VNET_E_STALE_COOKIE;
    if (f->gen != gen) return WT_VNET_E_STALE_COOKIE;
    if (f->refcnt == 0xFFFFU) return WT_VNET_E_BADARG;
    f->refcnt = (uint16_t)(f->refcnt + 1U);
    return WT_VNET_OK;
}

static void free_frame(vnet_pool_t *p, vnet_frame_t *f)
{
    size_t len = f->len;

    if (len > sizeof(f->data)) {
        len = sizeof(f->data);
    }
    wt_forceZero(f->data, len);
    f->len = 0U;
    f->refcnt = 0U;
    if (p->in_use_count > 0U) p->in_use_count--;
}

int vnet_pool_release(vnet_pool_t *p, uint16_t slot, uint16_t gen)
{
    vnet_frame_t *f;
    if (p == NULL || p->slots == NULL) return WT_VNET_E_BADARG;
    if (slot >= p->slot_count) return WT_VNET_E_BADARG;
    f = &p->slots[slot];
    if (f->gen != gen) return WT_VNET_E_STALE_COOKIE;
    if (f->refcnt == 0U) return WT_VNET_E_DOUBLE_RELEASE;
    if (f->refcnt == 1U) {
        free_frame(p, f);
        return 1;
    }
    f->refcnt = (uint16_t)(f->refcnt - 1U);
    return 0;
}

int vnet_pool_force_free(vnet_pool_t *p, uint16_t slot)
{
    vnet_frame_t *f;
    if (p == NULL || p->slots == NULL) return WT_VNET_E_BADARG;
    if (slot >= p->slot_count) return WT_VNET_E_BADARG;
    f = &p->slots[slot];
    if (f->refcnt == 0U) return WT_VNET_E_DOUBLE_RELEASE;
    free_frame(p, f);
    return WT_VNET_OK;
}

uint16_t vnet_pool_drop_expired(vnet_pool_t *p,
                                uint32_t      now_tick,
                                uint32_t      timeout_ticks)
{
    uint16_t i;
    uint16_t freed = 0U;
    if (p == NULL || p->slots == NULL) return 0U;
    if (timeout_ticks == 0U) return 0U;
    for (i = 0U; i < p->slot_count; ++i) {
        vnet_frame_t *f = &p->slots[i];
        uint32_t age;
        if (f->refcnt == 0U) continue;
        age = now_tick - f->born_tick;
        if (age >= timeout_ticks) {
            free_frame(p, f);
            freed++;
        }
    }
    return freed;
}

vnet_frame_t *vnet_pool_slot(vnet_pool_t *p, uint16_t slot, uint16_t gen)
{
    vnet_frame_t *f;
    if (p == NULL || p->slots == NULL) return NULL;
    if (slot >= p->slot_count) return NULL;
    f = &p->slots[slot];
    if (f->refcnt == 0U) return NULL;
    if (f->gen != gen) return NULL;
    return f;
}

uint16_t vnet_pool_free_count(const vnet_pool_t *p)
{
    if (p == NULL) return 0U;
    return (uint16_t)(p->slot_count - p->in_use_count);
}

uint16_t vnet_pool_in_use_count(const vnet_pool_t *p)
{
    if (p == NULL) return 0U;
    return p->in_use_count;
}
