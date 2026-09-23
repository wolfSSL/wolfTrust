/* test_pool.c
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

#include "test_vnet.h"
#include "wolftrust/vnet/vnet_pool.h"
#include "wolftrust/vnet/vnet_errors.h"

#define POOL_N 4

static vnet_frame_t g_storage[POOL_N];

static int test_pool_init_and_alloc(void)
{
    vnet_pool_t p;
    uint16_t s0, s1, s2, s3, s_full;
    vnet_pool_init(&p, g_storage, POOL_N);
    T_EQ_INT(vnet_pool_free_count(&p), POOL_N);
    T_EQ_INT(vnet_pool_in_use_count(&p), 0);

    s0 = vnet_pool_alloc(&p, 100);
    s1 = vnet_pool_alloc(&p, 101);
    s2 = vnet_pool_alloc(&p, 102);
    s3 = vnet_pool_alloc(&p, 103);
    T_CHECK(s0 != VNET_POOL_BAD_SLOT);
    T_CHECK(s1 != VNET_POOL_BAD_SLOT);
    T_CHECK(s2 != VNET_POOL_BAD_SLOT);
    T_CHECK(s3 != VNET_POOL_BAD_SLOT);

    s_full = vnet_pool_alloc(&p, 104);
    T_EQ_INT(s_full, VNET_POOL_BAD_SLOT);
    T_EQ_INT(vnet_pool_free_count(&p), 0);
    T_EQ_INT(vnet_pool_in_use_count(&p), POOL_N);
    return 0;
}

static int test_pool_release_lifecycle(void)
{
    vnet_pool_t p;
    uint16_t slot;
    uint16_t gen0;
    int rc;
    vnet_pool_init(&p, g_storage, POOL_N);

    slot = vnet_pool_alloc(&p, 10);
    T_CHECK(slot != VNET_POOL_BAD_SLOT);
    gen0 = g_storage[slot].gen;
    T_EQ_INT(g_storage[slot].refcnt, 1);

    /* Two extra refs (delivery to additional destinations). */
    T_EQ_INT(vnet_pool_ref(&p, slot, gen0), WT_VNET_OK);
    T_EQ_INT(vnet_pool_ref(&p, slot, gen0), WT_VNET_OK);
    T_EQ_INT(g_storage[slot].refcnt, 3);

    rc = vnet_pool_release(&p, slot, gen0);
    T_EQ_INT(rc, 0);
    T_EQ_INT(g_storage[slot].refcnt, 2);

    rc = vnet_pool_release(&p, slot, gen0);
    T_EQ_INT(rc, 0);
    T_EQ_INT(g_storage[slot].refcnt, 1);

    rc = vnet_pool_release(&p, slot, gen0);
    T_EQ_INT(rc, 1);
    T_EQ_INT(g_storage[slot].refcnt, 0);
    T_EQ_INT(vnet_pool_in_use_count(&p), 0);
    return 0;
}

static int test_pool_double_release_and_stale(void)
{
    vnet_pool_t p;
    uint16_t slot;
    uint16_t s2;
    uint16_t gen0, gen1;
    vnet_pool_init(&p, g_storage, POOL_N);

    slot = vnet_pool_alloc(&p, 10);
    T_CHECK(slot != VNET_POOL_BAD_SLOT);
    gen0 = g_storage[slot].gen;

    T_EQ_INT(vnet_pool_release(&p, slot, gen0), 1);
    /* Second release: refcnt is now zero. */
    T_EQ_INT(vnet_pool_release(&p, slot, gen0), WT_VNET_E_DOUBLE_RELEASE);

    /* Realloc same slot bumps gen. Old cookie must be rejected. */
    s2 = vnet_pool_alloc(&p, 20);
    T_EQ_INT(s2, slot);
    gen1 = g_storage[slot].gen;
    T_CHECK(gen1 != gen0);
    T_EQ_INT(vnet_pool_release(&p, slot, gen0), WT_VNET_E_STALE_COOKIE);
    T_EQ_INT(vnet_pool_ref(&p, slot, gen0), WT_VNET_E_STALE_COOKIE);
    T_EQ_INT(vnet_pool_release(&p, slot, gen1), 1);
    return 0;
}

static int test_pool_slot_accessor(void)
{
    vnet_pool_t p;
    uint16_t slot;
    uint16_t gen;
    vnet_frame_t *f;
    vnet_pool_init(&p, g_storage, POOL_N);

    slot = vnet_pool_alloc(&p, 1);
    gen = g_storage[slot].gen;
    f = vnet_pool_slot(&p, slot, gen);
    T_CHECK(f == &g_storage[slot]);

    T_CHECK(vnet_pool_slot(&p, slot, (uint16_t)(gen + 1U)) == NULL);
    T_CHECK(vnet_pool_slot(&p, POOL_N, gen) == NULL);

    vnet_pool_release(&p, slot, gen);
    T_CHECK(vnet_pool_slot(&p, slot, gen) == NULL);
    return 0;
}

static int test_pool_drop_expired(void)
{
    vnet_pool_t p;
    uint16_t s0, s1;
    uint16_t freed;
    vnet_pool_init(&p, g_storage, POOL_N);

    s0 = vnet_pool_alloc(&p, 100);
    s1 = vnet_pool_alloc(&p, 400);
    T_CHECK(s0 != VNET_POOL_BAD_SLOT);
    T_CHECK(s1 != VNET_POOL_BAD_SLOT);

    /* now=500, timeout=500: age(s0)=400, age(s1)=100 — neither expired. */
    freed = vnet_pool_drop_expired(&p, 500, 500);
    T_EQ_INT(freed, 0);

    /* now=700: age(s0)=600 (expired), age(s1)=300 (keep). */
    freed = vnet_pool_drop_expired(&p, 700, 500);
    T_EQ_INT(freed, 1);
    T_EQ_INT(g_storage[s0].refcnt, 0);
    T_EQ_INT(g_storage[s1].refcnt, 1);

    /* now=1000: age(s1)=600 (expired). */
    freed = vnet_pool_drop_expired(&p, 1000, 500);
    T_EQ_INT(freed, 1);
    T_EQ_INT(g_storage[s1].refcnt, 0);
    T_EQ_INT(vnet_pool_in_use_count(&p), 0);
    return 0;
}

static int test_pool_force_free(void)
{
    vnet_pool_t p;
    uint16_t slot;
    uint16_t gen;
    vnet_pool_init(&p, g_storage, POOL_N);

    slot = vnet_pool_alloc(&p, 5);
    gen = g_storage[slot].gen;
    vnet_pool_ref(&p, slot, gen);
    vnet_pool_ref(&p, slot, gen);
    T_EQ_INT(g_storage[slot].refcnt, 3);

    T_EQ_INT(vnet_pool_force_free(&p, slot), WT_VNET_OK);
    T_EQ_INT(g_storage[slot].refcnt, 0);
    T_EQ_INT(vnet_pool_in_use_count(&p), 0);

    T_EQ_INT(vnet_pool_force_free(&p, slot), WT_VNET_E_DOUBLE_RELEASE);
    return 0;
}

int run_pool_tests(void)
{
    int rc = 0;
    rc |= test_pool_init_and_alloc();
    rc |= test_pool_release_lifecycle();
    rc |= test_pool_double_release_and_stale();
    rc |= test_pool_slot_accessor();
    rc |= test_pool_drop_expired();
    rc |= test_pool_force_free();
    return rc;
}
