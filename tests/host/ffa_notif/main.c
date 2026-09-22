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

/* WT-FFA-0013: the FF-A v1.2 notification state machine (DEN0077A Ch.10) -
 * bitmap lifecycle, bind/unbind, set/get by source class, info-get list
 * encoding, and the schedule-receiver latch. The refusal rows transcribe the
 * FF-A ACS notifications group error-path tests verbatim. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_notif.h"

#include <stdint.h>
#include <stdio.h>

#define VM0     0x0000u
#define SP1     0x8002u
#define SP2     0x8003u
#define SP3     0x8004u
#define BAD_ID  0xFFFFu

#define IDS(sender, receiver) \
    ((uint32_t)(((uint32_t)(sender) << 16) | (uint32_t)(receiver)))
#define BIT(n)  (1ull << (n))

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

/* The B5 partition shape: one Normal-world VM and three partitions. */
static void fixture(void)
{
    wt_ffa_notif_reset();
    check(wt_ffa_notif_register(VM0, 0) == 0, "register the NS endpoint");
    check(wt_ffa_notif_register(SP1, 1) == 0, "register SP1");
    check(wt_ffa_notif_register(SP2, 1) == 0, "register SP2");
    check(wt_ffa_notif_register(SP3, 1) == 0, "register SP3");
}

/* The id values themselves live only in ffa_abi.h (the FID rule); these rows
 * hold the shape: all in the FF-A range, destroy through info-get contiguous
 * after bitmap-create, and the info-get pair differing only in convention. */
static void fid_rows(void)
{
    printf("[suite] function ids\n");
    check(wt_ffa_fid_in_range(WT_FFA_NOTIFICATION_BITMAP_CREATE) != 0,
          "BITMAP_CREATE is in range");
    check(WT_FFA_NOTIFICATION_BITMAP_DESTROY ==
          WT_FFA_NOTIFICATION_BITMAP_CREATE + 1u, "BITMAP_DESTROY follows");
    check(WT_FFA_NOTIFICATION_BIND ==
          WT_FFA_NOTIFICATION_BITMAP_CREATE + 2u, "BIND follows");
    check(WT_FFA_NOTIFICATION_UNBIND ==
          WT_FFA_NOTIFICATION_BITMAP_CREATE + 3u, "UNBIND follows");
    check(WT_FFA_NOTIFICATION_SET ==
          WT_FFA_NOTIFICATION_BITMAP_CREATE + 4u, "SET follows");
    check(WT_FFA_NOTIFICATION_GET ==
          WT_FFA_NOTIFICATION_BITMAP_CREATE + 5u, "GET follows");
    check(WT_FFA_NOTIFICATION_INFO_GET32 ==
          WT_FFA_NOTIFICATION_BITMAP_CREATE + 6u, "INFO_GET32 follows");
    check(WT_FFA_NOTIFICATION_INFO_GET64 ==
          (WT_FFA_NOTIFICATION_INFO_GET32 + 0x40000000u),
          "INFO_GET64 is the SMC64 form");
}

static void register_rows(void)
{
    printf("[suite] endpoint registration\n");
    fixture();
    check(wt_ffa_notif_register(SP1, 1) != 0, "a duplicate id is refused");
}

static void bitmap_rows(void)
{
    wt_ffa_notif_get_result_t got;

    printf("[suite] bitmap lifecycle\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(SP1, BAD_ID, 1u) == WT_FFA_NOT_SUPPORTED,
          "create from a partition is NOT_SUPPORTED before anything else");
    check(wt_ffa_notif_bitmap_destroy(SP1, BAD_ID) == WT_FFA_NOT_SUPPORTED,
          "destroy from a partition is NOT_SUPPORTED");
    check(wt_ffa_notif_bitmap_create(VM0, BAD_ID, 1u) ==
          WT_FFA_INVALID_PARAMETERS, "create with an unknown VM id is refused");
    check(wt_ffa_notif_bitmap_create(VM0, SP2, 1u) ==
          WT_FFA_INVALID_PARAMETERS, "create naming a partition is refused");
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 0u) ==
          WT_FFA_INVALID_PARAMETERS, "create with zero contexts is refused");
    check(wt_ffa_notif_bitmap_destroy(VM0, BAD_ID) ==
          WT_FFA_INVALID_PARAMETERS, "destroy with an unknown VM id is refused");
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == WT_FFA_DENIED,
          "destroy before any create is DENIED");
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0, "create succeeds");
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == WT_FFA_DENIED,
          "a second create is DENIED");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(3)) == 0,
          "the VM binds an id from SP1");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(3)) == 0,
          "SP1 signals it");
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == WT_FFA_DENIED,
          "destroy with a pending notification is DENIED");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SP, &got) == 0,
          "the VM drains the pending bit");
    check(got.from_sp == BIT(3), "the drained bitmap is the signaled bit");
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == 0,
          "destroy succeeds once drained");
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == WT_FFA_DENIED,
          "destroy again is DENIED");
}

static void bind_rows(void)
{
    printf("[suite] bind\n");
    fixture();
    check(wt_ffa_notif_bind(VM0, IDS(BAD_ID, VM0), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown sender half is refused");
    check(wt_ffa_notif_bind(VM0, IDS(SP3, BAD_ID), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown receiver half is refused");
    check(wt_ffa_notif_bind(VM0, IDS(SP3, VM0), 0x10u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "reserved flag bits are refused");
    check(wt_ffa_notif_bind(VM0, IDS(SP3, VM0), 0u, 0u) ==
          WT_FFA_INVALID_PARAMETERS, "an empty bitmap is refused");
    check(wt_ffa_notif_bind(VM0, IDS(VM0, VM0), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "sender equal to receiver is refused");
    check(wt_ffa_notif_bind(VM0, IDS(VM0, SP2), 0u, BIT(0)) == WT_FFA_DENIED,
          "binding another endpoint's ids is DENIED");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0)) == WT_FFA_DENIED,
          "a VM without a bitmap cannot bind");
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0, "create the bitmap");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0) | BIT(1)) == 0,
          "the VM binds two global ids from SP1");
    check(wt_ffa_notif_bind(VM0, IDS(SP3, VM0), 0u, BIT(1)) == WT_FFA_DENIED,
          "an already-bound id is DENIED");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "a partition binds a global id from the VM");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                            BIT(13)) == 0,
          "a partition binds a per-vCPU id from the VM");
}

static void unbind_rows(void)
{
    printf("[suite] unbind\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0, "create the bitmap");
    check(wt_ffa_notif_unbind(VM0, IDS(BAD_ID, VM0), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown sender half is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, BAD_ID), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown receiver half is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0x10u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "a nonzero reserved word is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0u, 0u) ==
          WT_FFA_INVALID_PARAMETERS, "an empty bitmap is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0u, BIT(5)) ==
          WT_FFA_INVALID_PARAMETERS, "an unbound id is refused");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(5)) == 0,
          "bind an id from SP1");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0u, BIT(5)) ==
          WT_FFA_INVALID_PARAMETERS,
          "unbinding with the wrong sender is refused");
    check(wt_ffa_notif_unbind(SP2, IDS(SP1, VM0), 0u, BIT(5)) ==
          WT_FFA_DENIED, "unbinding another endpoint's ids is DENIED");
    check(wt_ffa_notif_unbind(VM0, IDS(SP1, VM0), 0u, BIT(5)) == 0,
          "the receiver unbinds its id");
    check(wt_ffa_notif_bind(VM0, IDS(SP3, VM0), 0u, BIT(5)) == 0,
          "the freed id can be bound to a new sender");
}

/* The notification_set error rows: SP2 holds bit 12 global and bit 13
 * per-vCPU, both from the VM, as its server half arranges. */
static void set_rows(void)
{
    printf("[suite] set\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0, "create the bitmap");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "SP2 binds bit 12 global from the VM");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                            BIT(13)) == 0,
          "SP2 binds bit 13 per-vCPU from the VM");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0)) == 0,
          "the VM binds bit 0 global from SP1");
    check(wt_ffa_notif_set(VM0, IDS(VM0, BAD_ID), 0u, BIT(12)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown receiver is refused");
    check(wt_ffa_notif_set(VM0, IDS(BAD_ID, SP2), 0u, BIT(12)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown sender is refused");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), (2u << 16), BIT(13)) ==
          WT_FFA_INVALID_PARAMETERS,
          "a vCPU id without the per-vCPU flag is refused");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(13)) ==
          WT_FFA_INVALID_PARAMETERS,
          "a per-vCPU id signaled as global is refused");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                           BIT(12)) == WT_FFA_INVALID_PARAMETERS,
          "a global id signaled as per-vCPU is refused");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(16)) == WT_FFA_DENIED,
          "an unbound id is DENIED");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0x4u, BIT(12)) ==
          WT_FFA_INVALID_PARAMETERS, "reserved flag bits are refused");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2),
                           WT_FFA_NOTIF_FLAG_PER_VCPU | (1u << 16), BIT(13)) ==
          WT_FFA_INVALID_PARAMETERS,
          "a vCPU beyond the single context is refused");
    check(wt_ffa_notif_set(SP1, IDS(VM0, SP2), 0u, BIT(12)) == WT_FFA_DENIED,
          "a sender other than the caller is DENIED");
    check(wt_ffa_notif_set(SP3, IDS(SP3, VM0), 0u, BIT(0)) == WT_FFA_DENIED,
          "an id bound to a different sender is DENIED");
    check(wt_ffa_notif_sri_take() == 0, "no schedule-receiver work yet");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals SP2's global id");
    check(wt_ffa_notif_sri_pending() == 1, "the signal latches the SRI");
    check(wt_ffa_notif_sri_take() == 1, "the latch reads once");
    check(wt_ffa_notif_sri_take() == 0, "and clears");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2),
                           WT_FFA_NOTIF_FLAG_PER_VCPU, BIT(13)) == 0,
          "the VM signals SP2's per-vCPU id on vCPU 0");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), WT_FFA_NOTIF_FLAG_DELAY_SRI,
                           BIT(0)) == 0,
          "SP1 signals the VM with a delayed SRI");
}

static void get_rows(void)
{
    wt_ffa_notif_get_result_t got;

    printf("[suite] get\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0, "create the bitmap");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0)) == 0,
          "the VM binds bit 0 from SP1");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "SP2 binds bit 12 from the VM");
    check(wt_ffa_notif_get(VM0, BAD_ID, WT_FFA_NOTIF_GET_FLAG_VM, &got) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown receiver is refused");
    check(wt_ffa_notif_get(VM0, IDS(BAD_ID, VM0), WT_FFA_NOTIF_GET_FLAG_VM,
                           &got) == WT_FFA_INVALID_PARAMETERS,
          "a vCPU beyond the single context is refused");
    check(wt_ffa_notif_get(VM0, VM0, 0x10000u, &got) ==
          WT_FFA_INVALID_PARAMETERS, "reserved flag bits are refused");
    check(wt_ffa_notif_get(VM0, SP2, WT_FFA_NOTIF_GET_FLAG_VM, &got) ==
          WT_FFA_DENIED, "reading another endpoint's bitmap is DENIED");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(0)) == 0,
          "SP1 signals the VM");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals SP2");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0,
          "the VM asks for the wrong source class");
    check((got.from_vm == 0u) && (got.from_sp == 0u),
          "and gets nothing without disturbing the pending bit");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SP, &got) == 0,
          "the VM drains the partition class");
    check(got.from_sp == BIT(0), "the signaled bit comes back");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SP, &got) == 0,
          "a second drain succeeds");
    check(got.from_sp == 0u, "and is empty");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0,
          "SP2 drains the VM class");
    check(got.from_vm == BIT(12), "the signaled bit comes back");
    check(wt_ffa_notif_frame_rx_full(BAD_ID, 1) == WT_FFA_INVALID_PARAMETERS,
          "a framework signal to an unknown receiver is refused");
    check(wt_ffa_notif_frame_rx_full(SP2, 1) == 0,
          "a Secure sender's message pends RX-full for SP2");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "the framework bitmap drains");
    check(got.framework == WT_FFA_NOTIF_FW_SPM_RX_FULL,
          "a Secure sender's RX-full is bit 0");
    check(wt_ffa_notif_frame_rx_full(SP2, 0) == 0,
          "a Normal-world message pends RX-full for SP2");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_HYP, &got) == 0,
          "either framework flag drains it");
    check(got.framework == WT_FFA_NOTIF_FW_NS_RX_FULL,
          "a Normal-world sender's RX-full is bit 32");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "a second drain succeeds");
    check(got.framework == 0u, "and is empty");
}

static void info_rows(void)
{
    wt_ffa_notif_info_result_t info;
    wt_ffa_notif_get_result_t got;
    uint16_t id;
    unsigned int i;

    printf("[suite] info-get\n");
    fixture();
    check(wt_ffa_notif_info_get(SP1, 1, &info) == WT_FFA_NOT_SUPPORTED,
          "a partition may not ask");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "nothing pending is NO_DATA");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "SP2 binds a global id");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals it");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check(info.w2 == WT_FFA_NOTIF_INFO_COUNT(1u),
          "one all-global list and no more pending");
    check(info.regs[0] == SP2, "the list is the bare endpoint id");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0,
          "SP2 drains");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "drained work disappears from the list");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                            BIT(13)) == 0, "SP2 binds a per-vCPU id");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                           BIT(13)) == 0, "the VM signals it");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check(info.w2 == (WT_FFA_NOTIF_INFO_COUNT(1u) | (1u << 12)),
          "the list carries one vCPU id");
    check(info.regs[0] == SP2, "endpoint id then vCPU 0");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0,
          "SP2 drains");
    check(wt_ffa_notif_bind(SP3, IDS(VM0, SP3), 0u, BIT(1)) == 0,
          "SP3 binds a global id");
    check(wt_ffa_notif_bind(SP1, IDS(VM0, SP1), 0u, BIT(2)) == 0,
          "SP1 binds a global id");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP3), 0u, BIT(1)) == 0 &&
          wt_ffa_notif_set(VM0, IDS(VM0, SP1), 0u, BIT(2)) == 0,
          "the VM signals both");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check(info.w2 == WT_FFA_NOTIF_INFO_COUNT(2u), "two all-global lists");
    check(info.regs[0] == ((uint64_t)SP3 << 16 | SP1),
          "ids pack four to a doubleword in table order");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0, "the 32-bit form asks");
    check((info.regs[0] == ((uint64_t)SP3 << 16 | SP1)) &&
          (info.regs[1] == 0u), "ids pack two to a word");

    /* Truncation: more pending receivers than the 32-bit form's ten slots. */
    wt_ffa_notif_reset();
    check(wt_ffa_notif_register(VM0, 0) == 0, "register the NS endpoint");
    for (i = 0u; i < 11u; i++) {
        id = (uint16_t)(WT_FFA_ID_SP_FIRST + i);
        if (wt_ffa_notif_register(id, 1) != 0) {
            break;
        }
        if (wt_ffa_notif_bind((uint16_t)id, IDS(VM0, id), 0u, BIT(0)) != 0) {
            break;
        }
        if (wt_ffa_notif_set(VM0, IDS(VM0, id), 0u, BIT(0)) != 0) {
            break;
        }
    }
    check(i == 11u, "eleven partitions each hold pending work");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0, "the 32-bit form asks");
    check(info.w2 == (WT_FFA_NOTIF_INFO_COUNT(10u) | WT_FFA_NOTIF_INFO_MORE),
          "ten lists fit and more remain");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the 64-bit form asks");
    check(info.w2 == WT_FFA_NOTIF_INFO_COUNT(11u), "all eleven fit");
}

int main(void)
{
    printf("WT-FFA-0013 (FF-A notification bitmaps, binding, signaling)\n");

    fid_rows();
    register_rows();
    bitmap_rows();
    bind_rows();
    unbind_rows();
    set_rows();
    get_rows();
    info_rows();

    printf("ffa_notif: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
