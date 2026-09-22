/* ffa_notif.h
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

#ifndef WOLFTRUST_ARCH_AARCH64_FFA_NOTIF_H
#define WOLFTRUST_ARCH_AARCH64_FFA_NOTIF_H

#include <stdint.h>

/* FF-A v1.2 notifications (DEN0077A Ch.10, ABIs 17.5-17.12): one state
 * machine shared by the SVC gate (partitions) and the forwarded Normal-world
 * instance, host-testable with no hardware. Notification ids are bits of a
 * 64-bit space per receiver; a receiver keeps one pending bitmap per signal
 * source class (partitions, VMs, framework). */

#define WT_FFA_NOTIF_MAX_EP           12u
#define WT_FFA_NOTIF_COUNT            64u

/* FFA_NOTIFICATION_BIND / FFA_NOTIFICATION_SET w2 flags. */
#define WT_FFA_NOTIF_FLAG_PER_VCPU    (1u << 0)
#define WT_FFA_NOTIF_FLAG_DELAY_SRI   (1u << 1)
#define WT_FFA_NOTIF_SET_VCPU(w2)     (((w2) >> 16) & 0xFFFFu)
#define WT_FFA_NOTIF_SET_MBZ          0x0000FFFCu

/* FFA_NOTIFICATION_GET w2 flags: which pending bitmaps to return and clear. */
#define WT_FFA_NOTIF_GET_FLAG_SP      (1u << 0)
#define WT_FFA_NOTIF_GET_FLAG_VM      (1u << 1)
#define WT_FFA_NOTIF_GET_FLAG_SPM     (1u << 2)
#define WT_FFA_NOTIF_GET_FLAG_HYP     (1u << 3)
#define WT_FFA_NOTIF_GET_FLAG_ALL     0xFu

/* The 64-bit framework bitmap: bit 0 is the RX-buffer-full the SPM pends for
 * a Secure sender's message, bit 32 the one the Normal world's relayer pends;
 * a GET returns the whole bitmap in w6/w7. */
#define WT_FFA_NOTIF_FW_SPM_RX_FULL   (1ull << 0)
#define WT_FFA_NOTIF_FW_NS_RX_FULL    (1ull << 32)

/* w1 of BIND/UNBIND/SET carries sender [31:16] and receiver [15:0]; w1 of
 * GET carries the receiver's vCPU id [31:16] and the receiver [15:0]. */
#define WT_FFA_NOTIF_W1_HIGH(w1)      ((uint16_t)(((w1) >> 16) & 0xFFFFu))
#define WT_FFA_NOTIF_W1_LOW(w1)       ((uint16_t)((w1) & 0xFFFFu))

/* FFA_NOTIFICATION_INFO_GET w2: bit 0 = more lists pending than returned,
 * bits [11:7] = count of lists, two size bits per list from bit 12 up. Each
 * list is a 16-bit endpoint id followed by that many 16-bit vCPU ids, packed
 * from x3 (or w3) upward. */
#define WT_FFA_NOTIF_INFO_MORE        (1u << 0)
#define WT_FFA_NOTIF_INFO_COUNT(n)    (((uint32_t)(n) & 0x1Fu) << 7)
#define WT_FFA_NOTIF_INFO_MAX_REGS    5u

typedef struct wt_ffa_notif_get_result {
    uint64_t from_sp;
    uint64_t from_vm;
    uint64_t framework;
} wt_ffa_notif_get_result_t;

typedef struct wt_ffa_notif_info_result {
    uint64_t regs[WT_FFA_NOTIF_INFO_MAX_REGS];
    uint64_t w2;
} wt_ffa_notif_info_result_t;

void wt_ffa_notif_reset(void);
int wt_ffa_notif_register(uint16_t id, int secure);

int32_t wt_ffa_notif_bitmap_create(uint16_t caller, uint32_t vm_id,
                                   uint32_t vcpu_count);
int32_t wt_ffa_notif_bitmap_destroy(uint16_t caller, uint32_t vm_id);
int32_t wt_ffa_notif_bind(uint16_t caller, uint32_t w1, uint32_t flags,
                          uint64_t bitmap);
int32_t wt_ffa_notif_unbind(uint16_t caller, uint32_t w1, uint32_t w2,
                            uint64_t bitmap);
int32_t wt_ffa_notif_set(uint16_t caller, uint32_t w1, uint32_t flags,
                         uint64_t bitmap);
int32_t wt_ffa_notif_get(uint16_t caller, uint32_t w1, uint32_t flags,
                         wt_ffa_notif_get_result_t* out);
int32_t wt_ffa_notif_info_get(uint16_t caller, int is64,
                              wt_ffa_notif_info_result_t* out);

/* The framework message-pending notification a message send pends for its
 * receiver, on the half of the bitmap the sender's world owns; consumed
 * through GET like any other class. */
int32_t wt_ffa_notif_frame_rx_full(uint16_t receiver, int sender_secure);

/* Schedule-receiver interrupt latch: set when a signal leaves work for the
 * Normal-world scheduler, cleared when it asks. */
int wt_ffa_notif_sri_take(void);
int wt_ffa_notif_sri_pending(void);

#endif /* WOLFTRUST_ARCH_AARCH64_FFA_NOTIF_H */
