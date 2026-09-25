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
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 2u) == WT_FFA_NO_MEMORY,
          "create for more vCPUs than the one context held is refused");
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 0xFFFFFFFFu) ==
          WT_FFA_NO_MEMORY, "and so is the largest count");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(3)) == WT_FFA_DENIED,
          "the refused create left no bitmap to bind into");
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
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == WT_FFA_DENIED,
          "destroy with a bound notification is DENIED");
    check(wt_ffa_notif_unbind(VM0, IDS(SP1, VM0), 0u, BIT(3)) == 0,
          "the refused destroy left the binding in place to unbind");
    check(wt_ffa_notif_bitmap_create(VM0, 0x10000u | VM0, 1u) ==
          WT_FFA_INVALID_PARAMETERS,
          "create refuses w1 bits 31:16, which are MBZ for it");
    check(wt_ffa_notif_bitmap_destroy(VM0, 0xFFFF0000u | VM0) == 0,
          "destroy succeeds once unbound and drained, ignoring the SBZ w1 "
          "bits 31:16");
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
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0xFFFFFFFEu, BIT(20)) == 0,
          "the Normal world's SBZ flag bits 31:1 are ignored");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0xFFFFFFFEu, BIT(14)) == 0,
          "a partition's SBZ flag bits 31:1 are ignored");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(14)) == 0,
          "and the id is bound as the global one flag bit 0 asked for");
}

static void unbind_rows(void)
{
    wt_ffa_notif_get_result_t got;

    printf("[suite] unbind\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0, "create the bitmap");
    check(wt_ffa_notif_unbind(VM0, IDS(BAD_ID, VM0), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown sender half is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, BAD_ID), 0u, BIT(0)) ==
          WT_FFA_INVALID_PARAMETERS, "an unknown receiver half is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0x10u, 0u) ==
          WT_FFA_INVALID_PARAMETERS,
          "a nonzero reserved word with an empty bitmap is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0u, 0u) ==
          WT_FFA_INVALID_PARAMETERS, "an empty bitmap is refused");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0u, BIT(5)) ==
          WT_FFA_INVALID_PARAMETERS, "an unbound id is refused");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(5)) == 0,
          "bind an id from SP1");
    check(wt_ffa_notif_unbind(VM0, IDS(SP3, VM0), 0u, BIT(5)) ==
          WT_FFA_DENIED, "unbinding an id bound to another sender is DENIED");
    check(wt_ffa_notif_unbind(SP2, IDS(SP1, VM0), 0u, BIT(5)) ==
          WT_FFA_DENIED, "unbinding another endpoint's ids is DENIED");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(5)) == 0,
          "SP1 signals the id");
    check(wt_ffa_notif_unbind(VM0, IDS(SP1, VM0), 0u, BIT(5)) ==
          WT_FFA_DENIED, "unbinding a pending id is DENIED");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SP, &got) == 0,
          "the VM drains it");
    check(got.from_sp == BIT(5), "the refused unbind left it signaled");
    check(wt_ffa_notif_unbind(VM0, IDS(SP1, VM0), 0x10u, BIT(5)) == 0,
          "the drained id unbinds and the reserved word is ignored");
    check(wt_ffa_notif_bind(VM0, IDS(SP3, VM0), 0u, BIT(5)) == 0,
          "the freed id can be bound to a new sender");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0u, BIT(6) | BIT(7)) == 0,
          "SP2 binds two ids from the VM");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(7)) == 0,
          "the VM signals one of them");
    check(wt_ffa_notif_unbind(SP2, IDS(VM0, SP2), 0u, BIT(6) | BIT(7)) ==
          WT_FFA_DENIED, "one pending id refuses the whole unbind");
    check(wt_ffa_notif_unbind(SP2, IDS(VM0, SP2), 0u, BIT(6)) == 0,
          "the idle id was left bound and unbinds alone");
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
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0) | BIT(1)) == 0,
          "the VM binds bits 0 and 1 global from SP1");
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
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_DELAY_SRI,
                           BIT(12)) == WT_FFA_INVALID_PARAMETERS,
          "the delay-SRI hint from the Normal world is refused");
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
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals the still-pending id again");
    check(wt_ffa_notif_sri_pending() == 0,
          "which has no effect: no second SRI (10.5 rule 3)");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2),
                           WT_FFA_NOTIF_FLAG_PER_VCPU, BIT(13)) == 0,
          "the VM signals SP2's per-vCPU id on vCPU 0");
    check(wt_ffa_notif_sri_take() == 1, "the VM's signals latch the SRI");
    check(wt_ffa_notif_sri_take_now() == 0,
          "a Normal-world signal never asks for it at once");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), WT_FFA_NOTIF_FLAG_DELAY_SRI,
                           BIT(0)) == 0,
          "SP1 signals the VM with a delayed SRI");
    check(wt_ffa_notif_sri_take_now() == 0,
          "a delayed signal does not assert the SRI as the call completes");
    check(wt_ffa_notif_sri_pending() == 1,
          "it waits for the next Normal-world entry");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(0)) == 0,
          "SP1 signals the still-pending id again without the delay hint");
    check(wt_ffa_notif_sri_take_now() == 0,
          "which has no effect, so it asserts no SRI at once");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(1)) == 0,
          "SP1 signals a new id without the delay hint");
    check(wt_ffa_notif_sri_take_now() == 1,
          "the SRI is asserted as that call completes");
    check(wt_ffa_notif_sri_take_now() == 0, "once");
    check(wt_ffa_notif_sri_take() == 1,
          "and the earlier delayed latch is still pending");
    check(wt_ffa_notif_sri_take() == 0,
          "until the Normal-world entry takes it");
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
    check(wt_ffa_notif_get(VM0, SP2, WT_FFA_NOTIF_GET_FLAG_SP, &got) ==
          WT_FFA_DENIED, "reading another endpoint's bitmap is DENIED");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(0)) == 0,
          "SP1 signals the VM");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals SP2");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0,
          "the VM-class flag is SBZ, so ignored, at the NS physical instance");
    check((got.from_vm == 0u) && (got.from_sp == 0u),
          "and gets nothing without disturbing the pending bit");
    check((wt_ffa_notif_frame_rx_full(VM0, 1) == 0) &&
          (wt_ffa_notif_frame_rx_full(VM0, 0) == 0),
          "both framework halves pend for the VM");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_HYP |
                           WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "the Hypervisor flag is SBZ there too");
    check(got.framework == WT_FFA_NOTIF_FW_SPM_RX_FULL,
          "so only the SPM framework half comes back");
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
          "the Hypervisor framework flag drains it");
    check(got.framework == WT_FFA_NOTIF_FW_NS_RX_FULL,
          "a Normal-world sender's RX-full is bit 32");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "a second drain succeeds");
    check(got.framework == 0u, "and is empty");
    check((wt_ffa_notif_frame_rx_full(SP2, 1) == 0) &&
          (wt_ffa_notif_frame_rx_full(SP2, 0) == 0),
          "both framework halves pend for SP2");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "the SPM framework flag alone drains");
    check(got.framework == WT_FFA_NOTIF_FW_SPM_RX_FULL,
          "only the SPM half comes back");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_HYP, &got) == 0,
          "the Hypervisor framework flag alone drains");
    check(got.framework == WT_FFA_NOTIF_FW_NS_RX_FULL,
          "the Hypervisor half was left pending for it");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_SPM |
                           WT_FFA_NOTIF_GET_FLAG_HYP, &got) == 0,
          "both framework flags drain");
    check(got.framework == 0u, "and both halves are empty");
    check(wt_ffa_notif_frame_rx_full(VM0, 1) == 0,
          "a partition's message pends RX-full for the Normal world");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "the Normal world asks for the SPM framework half");
    check(got.framework == WT_FFA_NOTIF_FW_SPM_RX_FULL,
          "and reads the partition's RX-full in w6");
}

static void info_rows(void)
{
    wt_ffa_notif_info_result_t info;
    wt_ffa_notif_get_result_t got;

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
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "a list already returned is not returned again");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == WT_FFA_NO_DATA,
          "nor through the other convention");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals the still-pending id again");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "re-signaling a pending id adds no new list");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0,
          "SP2 drains");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "drained work disappears from the list");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(12)) == 0,
          "the VM signals the drained id afresh");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check((info.w2 == WT_FFA_NOTIF_INFO_COUNT(1u)) && (info.regs[0] == SP2),
          "a drain then a new signal re-arms the list");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                            BIT(13)) == 0, "SP2 binds a per-vCPU id");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP2), WT_FFA_NOTIF_FLAG_PER_VCPU,
                           BIT(13)) == 0,
          "the VM signals it while the global list is out");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check(info.w2 == (WT_FFA_NOTIF_INFO_COUNT(1u) | (1u << 12)),
          "a newly pended id re-arms the list, now with one vCPU id");
    check(info.regs[0] == SP2, "endpoint id then vCPU 0");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "and it too goes out once");
    check(wt_ffa_notif_frame_rx_full(SP2, 0) == 0,
          "a message pends RX-full for SP2");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check((info.w2 == (WT_FFA_NOTIF_INFO_COUNT(1u) | (1u << 12))) &&
          (info.regs[0] == SP2), "every message re-arms its receiver");
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_ALL, &got) == 0,
          "SP2 drains every class");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "nothing is left to report");
    check(wt_ffa_notif_bind(SP3, IDS(VM0, SP3), WT_FFA_NOTIF_FLAG_PER_VCPU,
                            BIT(0)) == 0,
          "SP3 binds per-vCPU the id RX-full shares");
    check(wt_ffa_notif_frame_rx_full(SP3, 1) == 0,
          "a Secure sender's message pends RX-full for SP3");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the scheduler asks");
    check((info.w2 == WT_FFA_NOTIF_INFO_COUNT(1u)) && (info.regs[0] == SP3),
          "a framework notification is global");
    check(wt_ffa_notif_get(SP3, SP3, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0,
          "SP3 drains it");
    check(wt_ffa_notif_bind(SP3, IDS(VM0, SP3), 0u, BIT(1)) == 0,
          "SP3 binds a global id");
    check(wt_ffa_notif_bind(SP1, IDS(VM0, SP1), 0u, BIT(2)) == 0,
          "SP1 binds a global id");
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP3), 0u, BIT(1)) == 0 &&
          wt_ffa_notif_set(VM0, IDS(VM0, SP1), 0u, BIT(2)) == 0,
          "the VM signals both");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0, "the 32-bit form asks");
    check(info.w2 == WT_FFA_NOTIF_INFO_COUNT(2u), "two all-global lists");
    check((info.regs[0] == ((uint64_t)SP3 << 16 | SP1)) &&
          (info.regs[1] == 0u), "ids pack two to a word in table order");
}

/* n partitions behind the NS endpoint, each holding one pending id from the
 * VM; returns how many were set up. */
static unsigned int pend_many(unsigned int n, uint32_t flags)
{
    unsigned int i;
    uint16_t id;

    wt_ffa_notif_reset();
    if (wt_ffa_notif_register(VM0, 0) != 0) {
        return 0u;
    }
    for (i = 0u; i < n; i++) {
        id = (uint16_t)(WT_FFA_ID_SP_FIRST + i);
        if (wt_ffa_notif_register(id, 1) != 0) {
            break;
        }
        if (wt_ffa_notif_bind(id, IDS(VM0, id), flags, BIT(0)) != 0) {
            break;
        }
        if (wt_ffa_notif_set(VM0, IDS(VM0, id), flags, BIT(0)) != 0) {
            break;
        }
    }
    return i;
}

static uint64_t pack(unsigned int first, unsigned int count)
{
    uint64_t v = 0u;
    unsigned int i;

    for (i = 0u; i < count; i++) {
        v |= (uint64_t)(WT_FFA_ID_SP_FIRST + first + i) << (16u * i);
    }
    return v;
}

static void info_page_rows(void)
{
    wt_ffa_notif_info_result_t info;
    uint64_t sizes = 0u;
    unsigned int i;

    printf("[suite] info-get pagination\n");
    check(pend_many(11u, 0u) == 11u,
          "eleven partitions each hold a global id");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0, "the 32-bit form asks");
    check(info.w2 == (WT_FFA_NOTIF_INFO_COUNT(10u) | WT_FFA_NOTIF_INFO_MORE),
          "ten lists fit and more remain");
    check((info.regs[0] == pack(0u, 2u)) && (info.regs[4] == pack(8u, 2u)),
          "the ten ids fill w3 through w7");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0,
          "the scheduler asks again");
    check((info.w2 == WT_FFA_NOTIF_INFO_COUNT(1u)) &&
          (info.regs[0] == pack(10u, 1u)),
          "the next call resumes at the eleventh list and clears more");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == WT_FFA_NO_DATA,
          "every list has gone out once");

    check(pend_many(11u, 0u) == 11u, "the same eleven afresh");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0, "the 64-bit form asks");
    check(info.w2 == WT_FFA_NOTIF_INFO_COUNT(11u), "all eleven fit");
    check((info.regs[0] == pack(0u, 4u)) && (info.regs[2] == pack(8u, 3u)),
          "ids pack four to a doubleword");

    check(pend_many(6u, WT_FFA_NOTIF_FLAG_PER_VCPU) == 6u,
          "six partitions each hold a per-vCPU id");
    for (i = 0u; i < 5u; i++) {
        sizes |= 1ull << (12u + (2u * i));
    }
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0, "the 32-bit form asks");
    check(info.w2 == (WT_FFA_NOTIF_INFO_COUNT(5u) | sizes |
                      WT_FFA_NOTIF_INFO_MORE),
          "five two-id lists fill the ten slots and more remain");
    check(wt_ffa_notif_info_get(VM0, 0, &info) == 0,
          "the scheduler asks again");
    check((info.w2 == (WT_FFA_NOTIF_INFO_COUNT(1u) | (1u << 12))) &&
          (info.regs[0] == pack(5u, 1u)), "the sixth list follows alone");
}

/* An endpoint out of service: its own bindings and pending state go, and so
 * does every binding naming it the sender; its id stays recognized, and a
 * BIND/UNBIND naming it the sender or a SET to it answers the code it was
 * retired with, ABORTED for one that aborted (Tables 16.12, 16.16, 16.20). */
static void abort_rows(void)
{
    wt_ffa_notif_get_result_t got;
    wt_ffa_notif_info_result_t info;

    printf("[suite] abort\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0 &&
          wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0)) == 0 &&
          wt_ffa_notif_bind(SP1, IDS(VM0, SP1), 0u, BIT(3)) == 0 &&
          wt_ffa_notif_bind(SP2, IDS(SP3, SP2), 0u, BIT(4)) == 0 &&
          wt_ffa_notif_set(VM0, IDS(VM0, SP1), 0u, BIT(3)) == 0,
          "SP1 binds from the VM and the VM from SP1, and the VM signals SP1");
    wt_ffa_notif_retire(SP1, WT_FFA_ABORTED);
    check(wt_ffa_notif_set(VM0, IDS(VM0, SP1), 0u, BIT(3)) == WT_FFA_ABORTED,
          "a SET to an endpoint that has aborted is ABORTED");
    check(wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(1)) == WT_FFA_ABORTED &&
          wt_ffa_notif_unbind(VM0, IDS(SP1, VM0), 0u, BIT(0)) ==
              WT_FFA_ABORTED,
          "a BIND or UNBIND naming it the sender is ABORTED");
    check(wt_ffa_notif_bind(VM0, IDS(SP2, VM0), 0u, BIT(0)) == 0,
          "the id it had bound at the VM is free for another sender");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "nothing it had pending is listed for the scheduler");
    check(wt_ffa_notif_set(SP3, IDS(SP3, SP2), 0u, BIT(4)) == 0 &&
          wt_ffa_notif_get(SP2, IDS(0u, SP2), WT_FFA_NOTIF_GET_FLAG_SP,
                           &got) == 0 && got.from_sp == BIT(4),
          "other endpoints' bindings go on");
    wt_ffa_notif_retire(SP2, WT_FFA_DENIED);
    check(wt_ffa_notif_set(SP3, IDS(SP3, SP2), 0u, BIT(4)) == WT_FFA_DENIED,
          "one that failed initialization answers DENIED instead");
}

/* What a retired sender had pended goes with the binding it rode on, in the
 * class its world pends to, so no receiver later drains an unbound id. */
static void abort_sender_rows(void)
{
    wt_ffa_notif_get_result_t got;
    wt_ffa_notif_info_result_t info;

    printf("[suite] abort (sender)\n");
    fixture();
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0 &&
          wt_ffa_notif_bind(VM0, IDS(SP1, VM0), 0u, BIT(0)) == 0 &&
          wt_ffa_notif_bind(VM0, IDS(SP2, VM0), 0u, BIT(1)) == 0 &&
          wt_ffa_notif_bind(SP3, IDS(SP1, SP3), 0u, BIT(2)) == 0 &&
          wt_ffa_notif_bind(SP3, IDS(VM0, SP3), 0u, BIT(3)) == 0,
          "the VM and SP3 bind ids from SP1, SP2, and the VM");
    check(wt_ffa_notif_set(SP1, IDS(SP1, VM0), 0u, BIT(0)) == 0 &&
          wt_ffa_notif_set(SP1, IDS(SP1, SP3), 0u, BIT(2)) == 0 &&
          wt_ffa_notif_set(VM0, IDS(VM0, SP3), 0u, BIT(3)) == 0,
          "SP1 signals the VM and SP3, and the VM signals SP3");
    wt_ffa_notif_retire(SP1, WT_FFA_ABORTED);
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SP, &got) == 0 &&
          got.from_sp == 0u,
          "the VM drains nothing SP1 pended before it aborted");
    check(wt_ffa_notif_get(SP3, SP3, WT_FFA_NOTIF_GET_FLAG_SP, &got) == 0 &&
          got.from_sp == 0u, "nor does a partition");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == 0 &&
          info.w2 == WT_FFA_NOTIF_INFO_COUNT(1u) && info.regs[0] == SP3,
          "the scheduler is sent only to SP3, for the VM's id");
    check(wt_ffa_notif_get(SP3, SP3, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0 &&
          got.from_vm == BIT(3), "which another sender's binding kept pending");
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == WT_FFA_DENIED &&
          wt_ffa_notif_unbind(VM0, IDS(SP2, VM0), 0u, BIT(1)) == 0 &&
          wt_ffa_notif_bitmap_destroy(VM0, VM0) == 0,
          "the VM's bitmap is masked and non-pending once SP2 is unbound");
    check(wt_ffa_notif_bind(SP2, IDS(VM0, SP2), 0u, BIT(5)) == 0 &&
          wt_ffa_notif_set(VM0, IDS(VM0, SP2), 0u, BIT(5)) == 0,
          "SP2 binds an id from the VM, which signals it");
    wt_ffa_notif_retire(VM0, WT_FFA_ABORTED);
    check(wt_ffa_notif_get(SP2, SP2, WT_FFA_NOTIF_GET_FLAG_VM, &got) == 0 &&
          got.from_vm == 0u, "a retired VM's signal goes with it too");
}

/* RX-full lives in the receiver's framework bitmap: a VM has one only between
 * its create and destroy (10.3), and nothing pends for it outside that. */
static void frame_rows(void)
{
    wt_ffa_notif_get_result_t got;
    wt_ffa_notif_info_result_t info;

    printf("[suite] framework bitmap\n");
    fixture();
    check(wt_ffa_notif_frame_ready(BAD_ID) == WT_FFA_INVALID_PARAMETERS,
          "an unknown receiver is refused");
    check(wt_ffa_notif_frame_ready(VM0) == WT_FFA_DENIED &&
          wt_ffa_notif_frame_rx_full(VM0, 1) == WT_FFA_DENIED,
          "a VM that never created its bitmap takes no RX-full");
    check(wt_ffa_notif_bitmap_create(VM0, VM0, 1u) == 0 &&
          wt_ffa_notif_frame_ready(VM0) == 0, "its create makes one");
    check(wt_ffa_notif_bitmap_destroy(VM0, VM0) == 0 &&
          wt_ffa_notif_frame_ready(VM0) == WT_FFA_DENIED,
          "its destroy takes it away");
    (void)wt_ffa_notif_sri_take();
    check(wt_ffa_notif_frame_rx_full(VM0, 1) == WT_FFA_DENIED,
          "so a partition's message after the destroy pends nothing");
    check(wt_ffa_notif_sri_take() == 0, "and raises no SRI");
    check(wt_ffa_notif_info_get(VM0, 1, &info) == WT_FFA_NO_DATA,
          "nor names the VM to its scheduler");
    check(wt_ffa_notif_get(VM0, VM0, WT_FFA_NOTIF_GET_FLAG_SPM, &got) == 0 &&
          got.framework == 0u, "nor comes back from a GET");
    wt_ffa_notif_retire(SP1, WT_FFA_ABORTED);
    check(wt_ffa_notif_frame_ready(SP1) == WT_FFA_DENIED &&
          wt_ffa_notif_frame_rx_full(SP1, 0) == WT_FFA_DENIED,
          "a partition out of service takes none either");
    check(wt_ffa_notif_frame_ready(SP2) == 0,
          "one in service has its bitmap from creation");
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
    info_page_rows();
    abort_rows();
    abort_sender_rows();
    frame_rows();

    printf("ffa_notif: %d checks, %d failures\n", checks, failures);
    return (failures == 0) ? 0 : 1;
}
