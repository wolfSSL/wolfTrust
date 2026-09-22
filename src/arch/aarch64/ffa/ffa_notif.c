/* ffa_notif.c
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

/* FF-A v1.2 notification state machine (DEN0077A Ch.10). Fixed storage, no
 * allocation: a bounded endpoint table seeded by the caller, a 64-bit
 * notification id space per receiver, and one pending bitmap per source
 * class. Every refusal row follows the ABI error tables of 17.5-17.12. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_notif.h"

#include <stddef.h>

typedef struct wt_notif_ep {
    uint64_t bound_mask;
    uint64_t bound_pcpu;
    uint64_t pend_sp;
    uint64_t pend_vm;
    uint64_t pend_fw;
    uint16_t bound_sender[WT_FFA_NOTIF_COUNT];
    uint16_t id;
    uint8_t secure;
    uint8_t has_bitmap;
    uint8_t used;
} wt_notif_ep_t;

static wt_notif_ep_t g_eps[WT_FFA_NOTIF_MAX_EP];
static uint8_t g_sri_pending;

static wt_notif_ep_t* ep_find(uint16_t id)
{
    unsigned int i;

    for (i = 0u; i < WT_FFA_NOTIF_MAX_EP; i++) {
        if ((g_eps[i].used != 0u) && (g_eps[i].id == id)) {
            return &g_eps[i];
        }
    }
    return NULL;
}

static uint64_t ep_pending(const wt_notif_ep_t* ep)
{
    return ep->pend_sp | ep->pend_vm | ep->pend_fw;
}

void wt_ffa_notif_reset(void)
{
    unsigned int i;
    unsigned int b;

    for (i = 0u; i < WT_FFA_NOTIF_MAX_EP; i++) {
        g_eps[i].bound_mask = 0u;
        g_eps[i].bound_pcpu = 0u;
        g_eps[i].pend_sp = 0u;
        g_eps[i].pend_vm = 0u;
        g_eps[i].pend_fw = 0u;
        for (b = 0u; b < WT_FFA_NOTIF_COUNT; b++) {
            g_eps[i].bound_sender[b] = 0u;
        }
        g_eps[i].id = 0u;
        g_eps[i].secure = 0u;
        g_eps[i].has_bitmap = 0u;
        g_eps[i].used = 0u;
    }
    g_sri_pending = 0u;
}

int wt_ffa_notif_register(uint16_t id, int secure)
{
    unsigned int i;

    if (ep_find(id) != NULL) {
        return -1;
    }
    for (i = 0u; i < WT_FFA_NOTIF_MAX_EP; i++) {
        if (g_eps[i].used == 0u) {
            g_eps[i].id = id;
            g_eps[i].secure = (secure != 0) ? 1u : 0u;
            /* Partition bitmaps exist from creation; a VM's is made by the
             * BITMAP_CREATE ABI. */
            g_eps[i].has_bitmap = (secure != 0) ? 1u : 0u;
            g_eps[i].used = 1u;
            return 0;
        }
    }
    return -1;
}

int32_t wt_ffa_notif_bitmap_create(uint16_t caller, uint32_t vm_id,
                                   uint32_t vcpu_count)
{
    wt_notif_ep_t* callerp = ep_find(caller);
    wt_notif_ep_t* vm;

    /* 17.5: a VM-only ABI; a partition is refused before anything else. */
    if ((callerp != NULL) && (callerp->secure != 0u)) {
        return WT_FFA_NOT_SUPPORTED;
    }
    if ((vm_id > 0xFFFFu) || (vcpu_count == 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    vm = ep_find((uint16_t)vm_id);
    if ((vm == NULL) || (vm->secure != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* Without a Hypervisor only the VM itself may create its bitmap. */
    if (vm->id != caller) {
        return WT_FFA_DENIED;
    }
    if (vm->has_bitmap != 0u) {
        return WT_FFA_DENIED;
    }
    vm->has_bitmap = 1u;
    return 0;
}

int32_t wt_ffa_notif_bitmap_destroy(uint16_t caller, uint32_t vm_id)
{
    wt_notif_ep_t* callerp = ep_find(caller);
    wt_notif_ep_t* vm;
    unsigned int b;

    if ((callerp != NULL) && (callerp->secure != 0u)) {
        return WT_FFA_NOT_SUPPORTED;
    }
    if (vm_id > 0xFFFFu) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    vm = ep_find((uint16_t)vm_id);
    if ((vm == NULL) || (vm->secure != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (vm->id != caller) {
        return WT_FFA_DENIED;
    }
    if (vm->has_bitmap == 0u) {
        return WT_FFA_DENIED;
    }
    /* 17.6: refused while notifications are pending in it. */
    if (ep_pending(vm) != 0u) {
        return WT_FFA_DENIED;
    }
    vm->has_bitmap = 0u;
    vm->bound_mask = 0u;
    vm->bound_pcpu = 0u;
    for (b = 0u; b < WT_FFA_NOTIF_COUNT; b++) {
        vm->bound_sender[b] = 0u;
    }
    return 0;
}

int32_t wt_ffa_notif_bind(uint16_t caller, uint32_t w1, uint32_t flags,
                          uint64_t bitmap)
{
    uint16_t sender_id = WT_FFA_NOTIF_W1_HIGH(w1);
    uint16_t receiver_id = WT_FFA_NOTIF_W1_LOW(w1);
    wt_notif_ep_t* sender = ep_find(sender_id);
    wt_notif_ep_t* receiver = ep_find(receiver_id);
    unsigned int b;

    if ((sender == NULL) || (receiver == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((flags & ~(uint32_t)WT_FFA_NOTIF_FLAG_PER_VCPU) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((bitmap == 0u) || (sender_id == receiver_id)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* A receiver binds its own ids; nothing acts on another's behalf. */
    if (receiver_id != caller) {
        return WT_FFA_DENIED;
    }
    if (receiver->has_bitmap == 0u) {
        return WT_FFA_DENIED;
    }
    if ((receiver->bound_mask & bitmap) != 0u) {
        return WT_FFA_DENIED;
    }
    for (b = 0u; b < WT_FFA_NOTIF_COUNT; b++) {
        if ((bitmap & (1ull << b)) != 0u) {
            receiver->bound_sender[b] = sender_id;
        }
    }
    receiver->bound_mask |= bitmap;
    if ((flags & WT_FFA_NOTIF_FLAG_PER_VCPU) != 0u) {
        receiver->bound_pcpu |= bitmap;
    }
    return 0;
}

int32_t wt_ffa_notif_unbind(uint16_t caller, uint32_t w1, uint32_t w2,
                            uint64_t bitmap)
{
    uint16_t sender_id = WT_FFA_NOTIF_W1_HIGH(w1);
    uint16_t receiver_id = WT_FFA_NOTIF_W1_LOW(w1);
    wt_notif_ep_t* sender = ep_find(sender_id);
    wt_notif_ep_t* receiver = ep_find(receiver_id);
    unsigned int b;

    if ((sender == NULL) || (receiver == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (w2 != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (bitmap == 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (receiver_id != caller) {
        return WT_FFA_DENIED;
    }
    /* Every named id must currently be bound to this sender. */
    if ((receiver->bound_mask & bitmap) != bitmap) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (b = 0u; b < WT_FFA_NOTIF_COUNT; b++) {
        if (((bitmap & (1ull << b)) != 0u) &&
            (receiver->bound_sender[b] != sender_id)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }
    for (b = 0u; b < WT_FFA_NOTIF_COUNT; b++) {
        if ((bitmap & (1ull << b)) != 0u) {
            receiver->bound_sender[b] = 0u;
        }
    }
    receiver->bound_mask &= ~bitmap;
    receiver->bound_pcpu &= ~bitmap;
    return 0;
}

int32_t wt_ffa_notif_set(uint16_t caller, uint32_t w1, uint32_t flags,
                         uint64_t bitmap)
{
    uint16_t sender_id = WT_FFA_NOTIF_W1_HIGH(w1);
    uint16_t receiver_id = WT_FFA_NOTIF_W1_LOW(w1);
    wt_notif_ep_t* sender = ep_find(sender_id);
    wt_notif_ep_t* receiver = ep_find(receiver_id);
    uint32_t per_vcpu = flags & WT_FFA_NOTIF_FLAG_PER_VCPU;
    uint16_t vcpu = (uint16_t)WT_FFA_NOTIF_SET_VCPU(flags);
    unsigned int b;

    if ((sender == NULL) || (receiver == NULL)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((flags & WT_FFA_NOTIF_SET_MBZ) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* One execution context: vCPU 0 is the only target, and naming one at
     * all requires the per-vCPU flag. */
    if (vcpu != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (bitmap == 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (sender_id != caller) {
        return WT_FFA_DENIED;
    }
    for (b = 0u; b < WT_FFA_NOTIF_COUNT; b++) {
        if ((bitmap & (1ull << b)) == 0u) {
            continue;
        }
        if (((receiver->bound_mask & (1ull << b)) == 0u) ||
            (receiver->bound_sender[b] != sender_id)) {
            return WT_FFA_DENIED;
        }
        if (((receiver->bound_pcpu & (1ull << b)) != 0u) != (per_vcpu != 0u)) {
            return WT_FFA_INVALID_PARAMETERS;
        }
    }
    if (sender->secure != 0u) {
        receiver->pend_sp |= bitmap;
    }
    else {
        receiver->pend_vm |= bitmap;
    }
    g_sri_pending = 1u;
    return 0;
}

int32_t wt_ffa_notif_get(uint16_t caller, uint32_t w1, uint32_t flags,
                         wt_ffa_notif_get_result_t* out)
{
    uint16_t vcpu = WT_FFA_NOTIF_W1_HIGH(w1);
    uint16_t receiver_id = WT_FFA_NOTIF_W1_LOW(w1);
    wt_notif_ep_t* receiver = ep_find(receiver_id);

    if (out == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    out->from_sp = 0u;
    out->from_vm = 0u;
    out->framework = 0u;
    if (receiver == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (vcpu != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if ((flags & ~(uint32_t)WT_FFA_NOTIF_GET_FLAG_ALL) != 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    if (receiver_id != caller) {
        return WT_FFA_DENIED;
    }
    if ((flags & WT_FFA_NOTIF_GET_FLAG_SP) != 0u) {
        out->from_sp = receiver->pend_sp;
        receiver->pend_sp = 0u;
    }
    if ((flags & WT_FFA_NOTIF_GET_FLAG_VM) != 0u) {
        out->from_vm = receiver->pend_vm;
        receiver->pend_vm = 0u;
    }
    if ((flags & WT_FFA_NOTIF_GET_FLAG_SPM) != 0u) {
        out->framework |= receiver->pend_fw & 0xFFFFFFFF00000000ull;
        receiver->pend_fw &= 0x00000000FFFFFFFFull;
    }
    if ((flags & WT_FFA_NOTIF_GET_FLAG_HYP) != 0u) {
        out->framework |= receiver->pend_fw & 0x00000000FFFFFFFFull;
        receiver->pend_fw &= 0xFFFFFFFF00000000ull;
    }
    return 0;
}

int32_t wt_ffa_notif_info_get(uint16_t caller, int is64,
                              wt_ffa_notif_info_result_t* out)
{
    wt_notif_ep_t* callerp = ep_find(caller);
    unsigned int slots_per_reg = (is64 != 0) ? 4u : 2u;
    unsigned int max_slots = WT_FFA_NOTIF_INFO_MAX_REGS * slots_per_reg;
    unsigned int slot = 0u;
    unsigned int lists = 0u;
    unsigned int more = 0u;
    unsigned int i;
    unsigned int need;
    unsigned int size;
    uint64_t sizes = 0u;

    if (out == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    /* 17.11: only the Normal-world scheduler asks. */
    if ((callerp != NULL) && (callerp->secure != 0u)) {
        return WT_FFA_NOT_SUPPORTED;
    }
    for (i = 0u; i < WT_FFA_NOTIF_INFO_MAX_REGS; i++) {
        out->regs[i] = 0u;
    }
    out->w2 = 0u;
    for (i = 0u; i < WT_FFA_NOTIF_MAX_EP; i++) {
        if ((g_eps[i].used == 0u) || (ep_pending(&g_eps[i]) == 0u)) {
            continue;
        }
        /* One list per endpoint: the id alone for global work, id plus
         * vCPU 0 when a per-vCPU notification is pending. */
        size = ((ep_pending(&g_eps[i]) & g_eps[i].bound_pcpu) != 0u) ? 1u : 0u;
        need = 1u + size;
        if ((slot + need) > max_slots) {
            more = 1u;
            break;
        }
        out->regs[slot / slots_per_reg] |=
            (uint64_t)g_eps[i].id << (16u * (slot % slots_per_reg));
        slot += need;
        sizes |= (uint64_t)(size & 0x3u) << (12u + (2u * lists));
        lists++;
    }
    if (lists == 0u) {
        return WT_FFA_NO_DATA;
    }
    out->w2 = WT_FFA_NOTIF_INFO_COUNT(lists) | sizes |
              ((more != 0u) ? WT_FFA_NOTIF_INFO_MORE : 0u);
    return 0;
}

int32_t wt_ffa_notif_frame_rx_full(uint16_t receiver_id)
{
    wt_notif_ep_t* receiver = ep_find(receiver_id);

    if (receiver == NULL) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    receiver->pend_fw |= WT_FFA_NOTIF_FW_SPM_RX_FULL;
    g_sri_pending = 1u;
    return 0;
}

int wt_ffa_notif_sri_take(void)
{
    int was = (int)g_sri_pending;

    g_sri_pending = 0u;
    return was;
}

int wt_ffa_notif_sri_pending(void)
{
    return (int)g_sri_pending;
}
