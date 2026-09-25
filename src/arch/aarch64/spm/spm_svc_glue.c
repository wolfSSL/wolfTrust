/* spm_svc_glue.c
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

/* Lower-EL synchronous exceptions at the SPMC: the Secure virtual instance
 * (SVC from an S-EL0 partition) and partition faults. Runs on the
 * bootstrap stack underneath the wt_co_arch_enter that started the
 * partition; blocking unwinds to it through wt_co_arch_leave. */

#include "wolftrust/arch/aarch64/domain.h"
#include "wolftrust/arch/aarch64/el3.h"
#include "wolftrust/arch/aarch64/esr.h"
#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/ffa_manifest.h"
#include "wolftrust/arch/aarch64/ffa_msg.h"
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "wolftrust/arch/aarch64/ffa_notif.h"
#include "wolftrust/arch/aarch64/ffa_partinfo.h"
#include "wolftrust/arch/aarch64/ffa_runtime.h"
#include "wolftrust/arch/aarch64/gic.h"
#include "wolftrust/arch/aarch64/spm_mem.h"
#include "wolftrust/arch/aarch64/spm_svc.h"
#include "wolftrust/arch/aarch64/tables.h"
#include "wolftrust/arch.h"
#include "wolftrust/ffm_domain.h"
#include "wolftrust/platform.h"
#include "wolftrust/sched/coroutine.h"
#include "wolftrust/sched/coroutine_internal.h"
#include "wolftrust/spm_gate.h"
#include "wolftrust/spm_transport.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WT_ESR_EC_SVC64 0x15u
/* A partition's RX and TX buffers are one 4K page each. */
#define WT_SP_RXTX_PAGES 1u

wt_trap_frame_t* volatile g_wt_spm_live_frame;
struct wt_co* volatile g_wt_spm_handler_co;
static uint64_t g_yield_token;
uint64_t g_wt_ffa_direct_resp[18];
volatile uint32_t g_wt_ffa_direct_resp_ready;

uint64_t wt_spm_yield_token(void)
{
    return g_yield_token;
}

static void ffa_error(wt_trap_frame_t* frame, int32_t code)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        frame->x[i] = 0u;
    }
    frame->x[0] = WT_FFA_ERROR;
    frame->x[2] = (uint64_t)(uint32_t)code;
}

/* A partition's direct response: validate it at the Secure virtual instance,
 * keep it for the deliverer, and park the partition back in waiting. A
 * malformed response is returned to the partition as an error instead. */
static void ffa_direct_resp(wt_trap_frame_t* frame, const struct wt_co* co)
{
    unsigned int i;
    uint16_t requester = 0u;
    uint16_t self = 0u;
    int ret = wt_ffa_direct_resp_check(frame->x, WT_FFA_INSTANCE_SECURE_VIRTUAL);

    if (ret != 0) {
        ffa_error(frame, (int32_t)ret);
        return;
    }
    if (wt_spm_ffa_sp_requester(co, &requester, &self) == 0) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if ((wt_ffa_direct_sender(frame->x[1]) != self) ||
        (wt_ffa_direct_receiver(frame->x[1]) != requester)) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    /* 15.5: a REQ2 is answered with RESP2 and nothing else is. */
    if ((wt_ffa_msg_reg_count(frame->x[0]) == WT_FFA_MSG_REGS_EXT) !=
        (wt_spm_ffa_sp_req2(co) != 0)) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
        g_wt_ffa_direct_resp[i] = frame->x[i];
    }
    g_wt_ffa_direct_resp_ready = 1u;
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_RESP;
    wt_co_block();
}

/* 15.2/15.4: the callee may complete the direct request it is processing with
 * FFA_SUCCESS in place of a response, every other register MBZ; its requester
 * is handed that FFA_SUCCESS and the callee waits for the next message. */
static void ffa_direct_success(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint32_t fid = (uint32_t)frame->x[0];
    uint16_t requester = 0u;
    uint16_t self = 0u;
    unsigned int i;

    if (wt_spm_ffa_sp_requester(co, &requester, &self) == 0) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if (wt_ffa_rt_success_check(frame->x) != 0) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
        g_wt_ffa_direct_resp[i] = 0u;
    }
    g_wt_ffa_direct_resp[0] = fid;
    g_wt_ffa_direct_resp_ready = 1u;
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_RESP;
    wt_co_block();
}

static void report_partition_fault(const wt_trap_frame_t* frame)
{
    char line[80];

    (void)wt_esr_format(line, sizeof(line), 0u, frame->esr, frame->far);
    wt_el3_puts(line);
    wt_el3_puts("\r\n");
}

static void ffa_not_supported(wt_trap_frame_t* frame)
{
    ffa_error(frame, WT_FFA_NOT_SUPPORTED);
}

static void ffa_success(wt_trap_frame_t* frame, uint64_t w2, uint64_t w3)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        frame->x[i] = 0u;
    }
    frame->x[0] = WT_FFA_SUCCESS32;
    frame->x[2] = w2;
    frame->x[3] = w3;
}

/* The configured partitions as FFA_PARTITION_INFO_GET source records: each
 * manifest partition under the live id of the partition running in its
 * domain (the id its FFA_ID_GET returns), one not running omitted, with a
 * record per exported UUID. */
#define WT_SPM_PARTINFO_MAX \
    (WT_FFA_NATIVE_SP_MAX + (WT_CO_MAX * WT_FFA_MANIFEST_MAX_UUIDS))
static wt_ffa_partinfo_entry_t g_partinfo[WT_SPM_PARTINFO_MAX];

static size_t partinfo_collect(void)
{
    const wt_ffa_partition_manifest_t* parts;
    const wt_ffa_native_sp_t* natives;
    size_t native_count = 0u;
    size_t part_count = 0u;
    size_t cap = sizeof(g_partinfo) / sizeof(g_partinfo[0]);
    size_t added = 0u;
    size_t n = 0u;
    size_t i;
    unsigned int j;

    /* FF-A native endpoints lead the listing: a register-based caller sees
     * five descriptors per call and looks for message receivers first. */
    natives = wt_spm_ffa_native_list(&native_count);
    for (i = 0u; (i < native_count) && (n < cap); i++) {
        g_partinfo[n].id = wt_spm_ffa_native_id(i);
        g_partinfo[n].exec_contexts = 1u;
        g_partinfo[n].properties = natives[i].properties;
        for (j = 0u; j < 16u; j++) {
            g_partinfo[n].uuid[j] = natives[i].uuid[j];
        }
        n++;
    }
    parts = wt_generated_ffa_partitions_get(&part_count);
    if (parts == NULL) {
        return 0u;
    }
    for (i = 0u; i < part_count; i++) {
        if (wt_ffa_partinfo_from_manifest(
                &parts[i], wt_spm_sp_ffa_id_of_domain(parts[i].domain_id),
                &g_partinfo[n], cap - n, &added) != 0) {
            return 0u;
        }
        n += added;
    }
    return n;
}

/* FFA_PARTITION_INFO_GET (6.1) for either instance: x = the call's registers,
 * mb = the caller's mailbox, whose RX buffer must be mapped and free for
 * descriptors (a count needs none). */
int wt_spm_partition_info(const uint64_t* x, uint32_t caller_version,
                          wt_ffa_mailbox_t* mb, uint32_t* count, uint32_t* size)
{
    size_t n = partinfo_collect();

    return wt_ffa_partinfo_get(x, caller_version, mb, g_partinfo, n, count,
                               size);
}

/* FFA_PARTITION_INFO_GET_REGS for either instance: UUID in x1/x2, start index
 * and tag in x3 (bits 63:32 SBZ); the reply fills out18. */
int wt_spm_partition_info_regs(const uint64_t* x, uint64_t* out18)
{
    size_t n = partinfo_collect();

    return wt_ffa_partinfo_regs_call(g_partinfo, n, x, out18);
}

/* The Table 6.2 properties discovery lists for id: 0, or INVALID_PARAMETERS
 * for an id that names no listed partition. */
int wt_spm_partition_props(uint16_t id, uint32_t* props)
{
    size_t n = partinfo_collect();

    return wt_ffa_partinfo_props_of(g_partinfo, n, id, props);
}

int wt_spm_msg2_sender_allowed(uint16_t id)
{
    size_t n = partinfo_collect();

    return wt_ffa_msg2_sender_allowed(g_partinfo, n, id);
}

/* 10.7 rule 3: discovery's Table 6.2 bit 3 is whether an endpoint takes
 * notifications, and no PSA partition does. 1 listed with it, 0 listed
 * without it, -1 not listed. */
static int notif_receiver(uint16_t id)
{
    uint32_t props = 0u;

    if (wt_spm_partition_props(id, &props) != 0) {
        return -1;
    }
    return ((props & WT_FFA_PARTINFO_PROP_NOTIF) != 0u) ? 1 : 0;
}

int32_t wt_spm_notif_set(uint16_t caller, uint32_t w1, uint32_t w2,
                         uint64_t bitmap)
{
    if (notif_receiver(WT_FFA_NOTIF_W1_LOW(w1)) == 0) {
        return WT_FFA_DENIED;
    }
    return wt_ffa_notif_set(caller, w1, w2, bitmap);
}

static wt_ffa_mailbox_t* sp_mailbox(void);

static void ffa_partition_info_get_regs(wt_trap_frame_t* frame)
{
    uint64_t out[WT_FFA_MSG_REGS_EXT];
    unsigned int i;
    int ret = wt_spm_partition_info_regs(frame->x, out);

    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    for (i = 0u; i < WT_FFA_MSG_REGS_EXT; i++) {
        frame->x[i] = out[i];
    }
}

static wt_ffa_version_state_t g_sp_version[WT_CO_MAX];
/* What a partition's last FFA_FEATURES(FFA_MEM_RETRIEVE_REQ) asked about the
 * NS bit (DEN0140 1.10.4.1.1). */
static uint8_t g_sp_ns_bit[WT_CO_MAX];

/* The version a partition negotiated, which its data structures follow. */
static uint32_t sp_version(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return WT_FFA_VERSION_1_2;
    }
    return wt_ffa_version_of(&g_sp_version[co->id - 1u], WT_FFA_VERSION_1_2);
}

uint32_t wt_spm_sp_ffa_version(const struct wt_co* co)
{
    return sp_version(co);
}

int wt_spm_sp_ffa_ns_bit(const struct wt_co* co)
{
    int asked = 0;

    if ((co != NULL) && (co->id != 0u) && (co->id <= WT_CO_MAX)) {
        asked = (g_sp_ns_bit[co->id - 1u] != 0u) ? 1 : 0;
    }
    return wt_ffa_ns_bit_used(sp_version(co), asked);
}

static void ffa_partition_info_get(wt_trap_frame_t* frame,
                                   const struct wt_co* co)
{
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret = wt_spm_partition_info(frame->x, sp_version(co), sp_mailbox(),
                                    &count, &size);

    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, count, size);
}

/* FFA_RX_RELEASE (7.2.2.4): ownership of the RX buffer returns to the SPMC.
 * The VM id in w1[15:0] is MBZ at this instance (Table 13.21). */
static void ffa_rx_release(wt_trap_frame_t* frame)
{
    int ret = WT_FFA_INVALID_PARAMETERS;

    if (((uint32_t)frame->x[1] & 0xFFFFu) == 0u) {
        ret = wt_ffa_mailbox_rx_release(sp_mailbox());
    }

    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* RX/TX pairs the partitions registered with FFA_RXTX_MAP (7.2.2), indexed by
 * coroutine id; a partition that never registered has no buffer to use. */
static wt_ffa_mailbox_t g_sp_mailbox[WT_CO_MAX];

struct wt_ffa_mailbox* wt_spm_sp_mailbox_of(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return NULL;
    }
    return &g_sp_mailbox[co->id - 1u];
}

int wt_spm_mailbox_overlaps(uint64_t base, uint64_t size)
{
    unsigned int i;

    for (i = 0u; i < WT_CO_MAX; i++) {
        if (wt_ffa_mailbox_overlaps(&g_sp_mailbox[i], base, size) != 0) {
            return 1;
        }
    }
    return wt_spm_ns_mailbox_overlaps(base, size);
}

static wt_ffa_mailbox_t* sp_mailbox(void)
{
    const struct wt_co* co = (const struct wt_co*)wt_co_current();

    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return NULL;
    }
    return &g_sp_mailbox[co->id - 1u];
}

/* FFA_RXTX_MAP (13.5): x1 = TX, x2 = RX, w3 = page count. The pair must be
 * two distinct writable pages of the caller's own memory that no memory
 * transaction covers. */
static void ffa_rxtx_map(wt_trap_frame_t* frame, const struct wt_co* co)
{
    wt_ffa_mailbox_t* mb = sp_mailbox();
    uintptr_t tx = (uintptr_t)frame->x[1];
    uintptr_t rx = (uintptr_t)frame->x[2];
    uint32_t w3 = (uint32_t)frame->x[3];
    int ret;

    if (mb == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if ((mb->mapped == 0u) &&
        ((WT_FFA_RXTX_PAGE_COUNT(w3) != WT_SP_RXTX_PAGES) ||
         (wt_spm_mem_rxtx_ok(co->domain, (uint64_t)tx) == 0) ||
         (wt_spm_mem_rxtx_ok(co->domain, (uint64_t)rx) == 0))) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    ret = wt_ffa_mailbox_map(mb, (uint64_t)tx, (uint64_t)rx, w3);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* FFA_RXTX_UNMAP (13.7): the id in w1[31:16] is MBZ at this instance (Table
 * 13.30); w1[15:0] is SBZ. A descriptor the caller was still sending through
 * the TX buffer is aborted. */
static void ffa_rxtx_unmap(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    int ret;

    if ((((uint32_t)frame->x[1] >> 16) & 0xFFFFu) != 0u) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    ret = wt_ffa_mailbox_unmap(sp_mailbox());
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    if (b != NULL) {
        wt_spm_mem_frag_abort(b->id);
    }
    ffa_success(frame, 0u, 0u);
}

/* A direct request from a partition (15.2): only to another FF-A endpoint the
 * SPMC hosts that takes this kind of request (DENIED otherwise, Tables 15.8
 * and 15.16), which must be waiting, and only from a listed partition that
 * advertises sending it (7.4 relayer rule 2). The caller blocks; its callee's
 * response (or FFA_YIELD) is written into its frame before it resumes. */
static void ffa_direct_req(wt_trap_frame_t* frame, const struct wt_co* co)
{
    struct wt_co* target;
    uint16_t receiver = wt_ffa_direct_receiver(frame->x[1]);
    int ret = wt_ffa_direct_req_check(frame->x, WT_FFA_INSTANCE_SECURE_VIRTUAL);

    if ((ret == 0) &&
        (wt_ffa_direct_sender(frame->x[1]) != wt_spm_sp_ffa_id(co))) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        ret = wt_ffa_direct_req_authorize(g_partinfo, partinfo_collect(),
                                          wt_spm_sp_ffa_id(co), receiver,
                                          (uint32_t)frame->x[0]);
    }
    if (ret == 0) {
        target = wt_spm_ffa_native_by_id(receiver);
        ret = wt_spm_ffa_sp_call(co, target, frame->x);
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_CALL;
    wt_co_block();
}

/* FFA_RUN from a partition: only to resume an endpoint that yielded inside a
 * direct request this partition sent it. */
static void ffa_run(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint16_t id = 0u;
    int ret = wt_ffa_run_target((uint32_t)frame->x[1], &id);

    if (ret == 0) {
        ret = wt_spm_ffa_sp_call(co, wt_spm_ffa_native_by_id(id), NULL);
    }

    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_CALL;
    wt_co_block();
}

/* FFA_ERROR (Table 12.4: w1 MBZ here, w2 an error code) is how an initializing
 * partition reports failed initialization and enters the waiting state (8.5
 * rule 3, Figure 8.4); any other partition has no call it could be answering,
 * an invalid transition (8.1 rule 4). */
static void ffa_init_failed(wt_trap_frame_t* frame, wt_co_t* co)
{
    int32_t code = (int32_t)(uint32_t)frame->x[2];

    if (wt_spm_sp_initializing((const struct wt_co*)co) == 0) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if (wt_ffa_rt_error_check(frame->x) != 0) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    wt_spm_mem_endpoint_teardown((const struct wt_co*)co);
    wt_spm_sp_init_failed((struct wt_co*)co, code);
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_WAIT;
    wt_co_block();
}

/* FFA_YIELD (8.2): hand the CPU back to whoever entered this partition; the
 * call returns FFA_SUCCESS once FFA_RUN resumes it. An initializing partition
 * was scheduled by the SPMC and may not yield (8.5 rule 4), and a partition
 * cannot ask for a timeout (Table 14.9). */
static void ffa_yield(wt_trap_frame_t* frame, const struct wt_co* co)
{
    if ((wt_spm_sp_initializing(co) != 0) &&
        (wt_ffa_rt_init_call(WT_FFA_YIELD, 0) != 0)) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if (wt_ffa_rt_yield_check(frame->x) != 0) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    ffa_success(frame, 0u, 0u);
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_YIELD;
    wt_co_block();
}

/* A descriptor handed over in the caller's TX buffer: w1 = total length,
 * w2 = length of the fragment in TX (DEN0140 4.1.2 when shorter), w3/w4 = 0
 * (not an address). */
static int tx_descriptor(const wt_trap_frame_t* frame, uint32_t* total,
                         uint32_t* frag, const uint8_t** tx)
{
    uint64_t addr = 0u;
    int ret = 0;

    *total = (uint32_t)frame->x[1];
    *frag = (uint32_t)frame->x[2];
    if ((*frag < 1u) || (*frag > *total) || (*frag > WT_FFA_MEM_PAGE_SIZE) ||
        ((frame->x[4] >> 32) != 0u)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        ret = wt_ffa_mem_tx_buffer(sp_mailbox(), frame->x[3],
                                   (uint32_t)frame->x[4], *frag, &addr);
    }
    *tx = (const uint8_t*)(uintptr_t)addr;
    return ret;
}

/* Ask the sender for the rest of a descriptor: FFA_MEM_FRAG_RX with the
 * transaction's handle and the bytes held; w4 is MBZ at this virtual
 * instance. */
static void frag_rx_reply(wt_trap_frame_t* frame, uint64_t handle,
                          uint32_t offset)
{
    unsigned int i;

    for (i = 0u; i < 8u; i++) {
        frame->x[i] = 0u;
    }
    frame->x[0] = WT_FFA_MEM_FRAG_RX;
    frame->x[1] = handle & 0xFFFFFFFFu;
    frame->x[2] = handle >> 32;
    frame->x[3] = (uint64_t)offset;
}

/* Answer a whole retrieve request with FFA_MEM_RETRIEVE_RESP, the response
 * descriptor in the caller's RX buffer (it always fits in one fragment). */
static void retrieve_answer(wt_trap_frame_t* frame, uint16_t receiver,
                            const uint8_t* req, size_t len)
{
    wt_ffa_mailbox_t* mb = sp_mailbox();
    size_t resp_len = 0u;
    unsigned int i;
    int ret;

    ret = wt_ffa_mailbox_rx_acquire(mb);
    if (ret == 0) {
        ret = wt_spm_mem_retrieve(req, len, receiver,
                                  (uint8_t*)(uintptr_t)mb->rx,
                                  WT_FFA_MEM_PAGE_SIZE, &resp_len);
        if (ret != 0) {
            (void)wt_ffa_mailbox_rx_release(mb);
        }
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    for (i = 0u; i < 8u; i++) {
        frame->x[i] = 0u;
    }
    frame->x[0] = WT_FFA_MEM_RETRIEVE_RESP;
    frame->x[1] = (uint64_t)resp_len;
    frame->x[2] = (uint64_t)resp_len;
}

/* FFA_MEM_SHARE / LEND / DONATE from a partition: the relayer validates the
 * descriptor in its TX buffer and returns the handle in w2/w3, or asks for
 * the remaining fragments first. */
static void ffa_mem_send(wt_trap_frame_t* frame, wt_ffa_mem_op_t op)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    const uint8_t* tx = NULL;
    uint64_t handle = 0u;
    uint32_t total = 0u;
    uint32_t frag = 0u;
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = tx_descriptor(frame, &total, &frag, &tx);
    if ((ret == 0) && (frag < total)) {
        ret = wt_spm_mem_frag_begin((uint8_t)op, b->id, tx, frag, total,
                                    &handle);
        if (ret == 0) {
            frag_rx_reply(frame, handle, frag);
            return;
        }
    }
    else if (ret == 0) {
        ret = wt_spm_mem_share(tx, (size_t)total, op, b->id, &handle);
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, handle & 0xFFFFFFFFu, handle >> 32);
}

/* FFA_MEM_RETRIEVE_REQ from a partition: map the region and answer with
 * FFA_MEM_RETRIEVE_RESP, or ask for the rest of a fragmented request. */
static void ffa_mem_retrieve(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    const uint8_t* tx = NULL;
    uint64_t handle = 0u;
    uint32_t total = 0u;
    uint32_t frag = 0u;
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = tx_descriptor(frame, &total, &frag, &tx);
    if ((ret == 0) && (frag < total)) {
        ret = wt_spm_mem_frag_begin(WT_SPM_MEM_FRAG_OP_RETRIEVE, b->id, tx,
                                    frag, total, &handle);
        if (ret == 0) {
            frag_rx_reply(frame, handle, frag);
        }
        else {
            ffa_error(frame, ret);
        }
        return;
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    retrieve_answer(frame, b->id, tx, (size_t)total);
}

/* FFA_MEM_FRAG_TX (DEN0140 4.1.2.5): the next fragment, in the TX buffer the
 * first one used, which is still mapped (an unmap aborts the transfer); the
 * last completes the call that sent the first. */
static void ffa_mem_frag_tx(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    uint64_t handle = (uint64_t)(uint32_t)frame->x[1] |
                      ((uint64_t)(uint32_t)frame->x[2] << 32);
    uint32_t len = (uint32_t)frame->x[3];
    const uint8_t* frag = NULL;
    const uint8_t* desc;
    uint64_t tx = 0u;
    uint32_t offset = 0u;
    uint32_t total = 0u;
    uint8_t op = 0u;
    int done = 0;
    int ret = WT_FFA_INVALID_PARAMETERS;

    if ((b != NULL) && ((uint32_t)frame->x[4] == 0u) &&
        (len <= WT_FFA_MEM_PAGE_SIZE)) {
        if (wt_ffa_mem_tx_buffer(sp_mailbox(), 0u, 0u, len, &tx) == 0) {
            frag = (const uint8_t*)(uintptr_t)tx;
        }
        ret = wt_spm_mem_frag_next(handle, b->id, frag, len, &offset, &done);
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    if (done == 0) {
        frag_rx_reply(frame, handle, offset);
        return;
    }
    desc = wt_spm_mem_frag_desc(handle, b->id, &total, &op);
    if ((desc != NULL) && (op == WT_SPM_MEM_FRAG_OP_RETRIEVE)) {
        retrieve_answer(frame, b->id, desc, (size_t)total);
        wt_spm_mem_frag_release(handle, b->id);
        return;
    }
    ret = wt_spm_mem_frag_share(handle, b->id);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, handle & 0xFFFFFFFFu, handle >> 32);
}

/* FFA_MEM_RELINQUISH from a partition: the descriptor is in its TX buffer. */
static void ffa_mem_relinquish(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    uint64_t tx = 0u;
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = wt_ffa_mem_tx_buffer(sp_mailbox(), 0u, 0u, WT_FFA_MEM_PAGE_SIZE,
                               &tx);
    if (ret == 0) {
        ret = wt_spm_mem_relinquish((const uint8_t*)(uintptr_t)tx,
                                    WT_FFA_MEM_PAGE_SIZE, b->id);
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* FFA_MEM_RECLAIM from a partition: w1/w2 = handle, w3 = flags. */
static void ffa_mem_reclaim(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    uint64_t handle = (uint64_t)(uint32_t)frame->x[1] |
                      ((uint64_t)(uint32_t)frame->x[2] << 32);
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = wt_spm_mem_reclaim(handle, b->id, (uint32_t)frame->x[3]);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

void wt_spm_sp_ffa_reset(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return;
    }
    (void)memset(&g_sp_version[co->id - 1u], 0, sizeof(g_sp_version[0]));
    g_sp_ns_bit[co->id - 1u] = 0u;
    (void)memset(&g_sp_mailbox[co->id - 1u], 0, sizeof(g_sp_mailbox[0]));
}

/* FFA_VERSION (13.2): the result is returned in w0 alone. */
static void ffa_version(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint32_t requested = (uint32_t)frame->x[1];
    unsigned int i;

    for (i = 1u; i < 8u; i++) {
        frame->x[i] = 0u;
    }
    frame->x[0] = (uint64_t)(uint32_t)wt_ffa_version_negotiate(
        &g_sp_version[co->id - 1u], requested, WT_FFA_VERSION_1_2);
}

static int sp_implements(uint32_t fid)
{
    switch (fid) {
        case WT_FFA_ERROR:
        case WT_FFA_SUCCESS32:
        case WT_FFA_SUCCESS64:
        case WT_FFA_INTERRUPT:
        case WT_FFA_VERSION:
        case WT_FFA_FEATURES:
        case WT_FFA_RX_RELEASE:
        case WT_FFA_RXTX_MAP32:
        case WT_FFA_RXTX_MAP64:
        case WT_FFA_RXTX_UNMAP:
        case WT_FFA_PARTITION_INFO_GET:
        case WT_FFA_PARTITION_INFO_GET_REGS:
        case WT_FFA_ID_GET:
        case WT_FFA_SPM_ID_GET:
        case WT_FFA_MSG_WAIT:
        case WT_FFA_YIELD:
        case WT_FFA_RUN:
        case WT_FFA_MSG_SEND_DIRECT_REQ32:
        case WT_FFA_MSG_SEND_DIRECT_REQ64:
        case WT_FFA_MSG_SEND_DIRECT_RESP32:
        case WT_FFA_MSG_SEND_DIRECT_RESP64:
        case WT_FFA_MSG_SEND_DIRECT_REQ2:
        case WT_FFA_MSG_SEND_DIRECT_RESP2:
        case WT_FFA_MEM_SHARE32:
        case WT_FFA_MEM_SHARE64:
        case WT_FFA_MEM_LEND32:
        case WT_FFA_MEM_LEND64:
        case WT_FFA_MEM_DONATE32:
        case WT_FFA_MEM_DONATE64:
        case WT_FFA_MEM_RETRIEVE_REQ32:
        case WT_FFA_MEM_RETRIEVE_REQ64:
        case WT_FFA_MEM_RETRIEVE_RESP:
        case WT_FFA_MEM_RELINQUISH:
        case WT_FFA_MEM_RECLAIM:
        case WT_FFA_MEM_FRAG_RX:
        case WT_FFA_MEM_FRAG_TX:
        case WT_FFA_MEM_PERM_GET32:
        case WT_FFA_MEM_PERM_GET64:
        case WT_FFA_MEM_PERM_SET32:
        case WT_FFA_MEM_PERM_SET64:
        case WT_FFA_CONSOLE_LOG32:
        case WT_FFA_CONSOLE_LOG64:
        case WT_FFA_NOTIFICATION_BIND:
        case WT_FFA_NOTIFICATION_UNBIND:
        case WT_FFA_NOTIFICATION_SET:
        case WT_FFA_NOTIFICATION_GET:
        case WT_FFA_MSG_SEND2:
            return 1;
        default:
            return 0;
    }
}

/* 10.7 rules 5 and 6: a partition that does not take notifications has none
 * of the notification ABIs this instance serves partitions. */
static int sp_notif_denied(uint32_t fid, const struct wt_co* co)
{
    if ((fid != WT_FFA_NOTIFICATION_BIND) &&
        (fid != WT_FFA_NOTIFICATION_UNBIND) &&
        (fid != WT_FFA_NOTIFICATION_SET) &&
        (fid != WT_FFA_NOTIFICATION_GET)) {
        return 0;
    }
    return (notif_receiver(wt_spm_sp_ffa_id(co)) != 1) ? 1 : 0;
}

/* FFA_FEATURES (13.3): exactly the function ids this instance serves; no
 * optional feature id is implemented. FFA_RXTX_MAP reports the one-page
 * buffer limit ffa_rxtx_map enforces (7.2.2.3). */
static void ffa_features(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint32_t query = (uint32_t)frame->x[1];
    uint32_t props = (uint32_t)frame->x[2];
    int32_t ret;

    if ((query == WT_FFA_MEM_RETRIEVE_REQ32) ||
        (query == WT_FFA_MEM_RETRIEVE_REQ64)) {
        ret = wt_ffa_features_retrieve_check(sp_version(co), props);
        if (ret != 0) {
            ffa_error(frame, ret);
        }
        else {
            g_sp_ns_bit[co->id - 1u] =
                ((props & WT_FFA_FEATURES_RETRIEVE_NS_BIT) != 0u) ? 1u : 0u;
            ffa_success(frame, WT_FFA_FEATURES_RETRIEVE_NS_BIT, 0u);
        }
    }
    else if ((query == WT_FFA_RXTX_MAP32) || (query == WT_FFA_RXTX_MAP64)) {
        ffa_success(frame, WT_FFA_FEATURES_RXTX_MAX_PAGES(WT_SP_RXTX_PAGES),
                    0u);
    }
    else if (WT_FFA_FEATURES_IS_FID(query) && (sp_implements(query) != 0) &&
             wt_ffa_fid_available(query, sp_version(co)) &&
             (sp_notif_denied(query, co) == 0)) {
        ffa_success(frame, 0u, 0u);
    }
    else {
        ffa_not_supported(frame);
    }
}

/* FFA_CONSOLE_LOG (13.12): w1 = count (bits 31:8 SBZ), characters packed
 * from w2/x2 upward; 1..24 over w2-w7, 1..128 over x2-x17. */
static void ffa_console_log(wt_trap_frame_t* frame, unsigned int is64)
{
    uint32_t count = wt_ffa_console_count(frame->x[1], is64);
    unsigned int per_reg = (is64 != 0u) ? 8u : 4u;
    unsigned int i;
    uint64_t reg;

    if (count == 0u) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    for (i = 0u; i < count; i++) {
        reg = frame->x[2u + (i / per_reg)];
        wt_platform_console_putc((char)((reg >> (8u * (i % per_reg))) & 0xFFu));
    }
    ffa_success(frame, 0u, 0u);
}

/* A partition's notification calls share the Normal world's state machine;
 * the bitmap and info-get ABIs stay unhandled here so a partition caller
 * gets NOT_SUPPORTED, as the scheduler-side ABIs require. */
static void ffa_notif_bind(wt_trap_frame_t* frame, const struct wt_co* co,
                           unsigned int unbind)
{
    uint16_t caller = (uint16_t)wt_spm_sp_ffa_id(co);
    uint32_t w1 = (uint32_t)frame->x[1];
    uint32_t w2 = (uint32_t)frame->x[2];
    uint64_t bitmap = (uint64_t)(uint32_t)frame->x[3] |
                      ((uint64_t)(uint32_t)frame->x[4] << 32);
    int32_t ret;

    if (unbind != 0u) {
        ret = wt_ffa_notif_unbind(caller, w1, w2, bitmap);
    }
    else {
        ret = wt_ffa_notif_bind(caller, w1, w2, bitmap);
    }
    if (ret == 0) {
        ffa_success(frame, 0u, 0u);
    }
    else {
        ffa_error(frame, ret);
    }
}

static void ffa_notif_set(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint16_t caller = (uint16_t)wt_spm_sp_ffa_id(co);
    uint64_t bitmap = (uint64_t)(uint32_t)frame->x[3] |
                      ((uint64_t)(uint32_t)frame->x[4] << 32);
    int32_t ret = wt_spm_notif_set(caller, (uint32_t)frame->x[1],
                                   (uint32_t)frame->x[2], bitmap);

    if (ret == 0) {
        if (wt_ffa_notif_sri_take_now() != 0) {
            wt_gic->raise_ns_sgi(WT_FFA_SRI_INTID);
            wt_el3_puts("[SPM] sri sgi\r\n");
        }
        ffa_success(frame, 0u, 0u);
    }
    else {
        ffa_error(frame, ret);
    }
}

/* FFA_MSG_SEND2 from a partition: the shared delivery engine reads the
 * message from the caller's own TX buffer. */
static void ffa_msg_send2(wt_trap_frame_t* frame, const struct wt_co* co)
{
    wt_ffa_mailbox_t* mb = wt_spm_sp_mailbox_of(co);
    int ret;

    if ((mb == NULL) || (mb->mapped == 0u)) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = wt_spm_msg2_deliver((uint16_t)wt_spm_sp_ffa_id(co), sp_version(co),
                              (const uint8_t*)(uintptr_t)mb->tx,
                              mb->pages * (uint32_t)WT_TABLES_PAGE_SIZE,
                              WT_FFA_INSTANCE_SECURE_VIRTUAL,
                              (uint32_t)frame->x[1], (uint32_t)frame->x[2]);
    if (ret == 0) {
        ffa_success(frame, 0u, 0u);
    }
    else {
        ffa_error(frame, ret);
    }
}

static void ffa_notif_get(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint16_t caller = (uint16_t)wt_spm_sp_ffa_id(co);
    wt_ffa_notif_get_result_t got;
    int32_t ret = wt_ffa_notif_get(caller, (uint32_t)frame->x[1],
                                   (uint32_t)frame->x[2], &got);

    if (ret == 0) {
        wt_ffa_mailbox_rx_claim(sp_mailbox(), got.framework);
        ffa_success(frame, (uint32_t)got.from_sp,
                    (uint32_t)(got.from_sp >> 32));
        frame->x[4] = (uint32_t)got.from_vm;
        frame->x[5] = (uint32_t)(got.from_vm >> 32);
        frame->x[6] = (uint32_t)got.framework;
        frame->x[7] = (uint32_t)(got.framework >> 32);
    }
    else {
        ffa_error(frame, ret);
    }
}

/* FFA_MEM_PERM_SET (DEN0140 2.9): an S-EL0 partition re-permissions its own
 * pages, during its initialization only (DENIED otherwise, the one DENIED in
 * Table 2.41). w1 = base VA, w2 = page count, w3 = perms. */
static void ffa_mem_perm_set(wt_trap_frame_t* frame, const struct wt_co* co)
{
    int ret;

    if (wt_spm_sp_initializing(co) == 0) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = wt_spm_mem_perm_set(co->domain, wt_spm_sp_mailbox_of(co),
                              (uint64_t)frame->x[1], (uint32_t)frame->x[2],
                              (uint32_t)frame->x[3]);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* FFA_MEM_PERM_GET (DEN0140 2.8): w1 = base VA of a page; the permissions
 * return in w2. DENIED only outside initialization (Table 2.37). */
static void ffa_mem_perm_get(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint32_t perm = 0u;
    int ret;

    if (wt_spm_sp_initializing(co) == 0) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = wt_spm_mem_perm_get(co->domain, (uint64_t)frame->x[1], &perm);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, perm, 0u);
}

void wt_spm_lower_sync(wt_trap_frame_t* frame)
{
    uint32_t ec = (uint32_t)(frame->esr >> 26) & 0x3Fu;
    uint32_t fid = (uint32_t)frame->x[0];
    wt_co_t* co = wt_co_current();
    uint32_t sint;
    uint16_t requester = 0u;
    uint16_t self = 0u;
    unsigned int i;
    int busy;

    g_wt_spm_live_frame = frame;
    g_wt_spm_trap_spsr = frame->spsr;
    g_wt_spm_handler_co = co;
    g_wt_spm_handler_depth++;

    if (ec != WT_ESR_EC_SVC64) {
        report_partition_fault(frame);
        wt_spm_mem_endpoint_teardown(co);
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
        /* The Arm isolation tests fault inside a partition on purpose and
         * expect a system restart (val resumes off its NVM boot flag); the
         * quarantine below would leave the server dead for every later test. */
        wt_platform_system_reset();
#endif
        /* Route a partition fault through the core's restart policy; one
         * that is not a scheduled SP (an FF-A native, a boot self-test) is
         * retired here. */
        if (wt_spm_sp_fault(co) != WT_FFM_SUCCESS) {
            wt_spm_sp_retire((struct wt_co*)co);
        }
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        wt_sp_el0_leave();
    }

    /* 4.4: the SVC32 convention mirrors SMC32, so a 32-bit call carries w1-w7
     * only, as the monitor normalizes an SMC32 call. */
    if (wt_ffa_fid_in_range(fid)) {
        wt_ffa_regs_normalize(frame->x);
    }
    if (wt_ffa_fid_in_range(fid) && (fid != WT_FFA_VERSION) && (co != NULL) &&
        (co->id != 0u) && (co->id <= WT_CO_MAX)) {
        wt_ffa_version_lock(&g_sp_version[co->id - 1u], WT_FFA_VERSION_1_2);
    }

    if (fid == WT_SPM_SVC_FID_CALL) {
        wt_spm_call_t* call = (wt_spm_call_t*)(uintptr_t)frame->x[1];

        /* A blocking op unwinds inside the dispatch with this frame already
         * captured, so the resumed partition returns from its svc with this
         * value: SUCCESS makes the SVC transport re-issue around the block. */
        frame->x[0] = (uint64_t)WT_FFM_SUCCESS;
        wt_spm_sp_in_gate((const struct wt_co*)co, 1u);
        frame->x[0] = (uint64_t)(int64_t)wt_spm_dispatch_call(call, frame);
        wt_spm_sp_in_gate((const struct wt_co*)co, 0u);
    }
    else if (fid == WT_SPM_SVC_FID_YIELD) {
        g_yield_token = frame->x[1];
        frame->x[0] = 0u;
        wt_co_block();
    }
#if defined(WT_FFA_ACS) && (WT_FFA_ACS == 1)
    else if (fid == WT_SPM_HVC_INTERRUPT_ENABLE) {
        sint = (uint32_t)frame->x[1];
        if (wt_spm_sint_own((struct wt_co*)co, sint,
                            (frame->x[2] != 0u) ? 1u : 0u) == 0) {
            if (frame->x[2] != 0u) {
                wt_gic->set_group0(sint);
                wt_gic->set_priority(sint, 0x10u);
                wt_gic->enable(sint);
            }
            else {
                wt_gic->disable(sint);
            }
            frame->x[0] = 0u;
        }
        else {
            frame->x[0] = (uint64_t)(int64_t)-1;
        }
    }
    else if (fid == WT_SPM_HVC_INTERRUPT_GET) {
        frame->x[0] = (uint64_t)wt_spm_sint_delivered((const struct wt_co*)co);
    }
    else if (fid == WT_SPM_HVC_INTERRUPT_DEACTIVATE) {
        frame->x[0] = 0u;
    }
    else if (fid == WT_SPM_SVC_FID_TIMER_ARM) {
        frame->x[0] = (wt_spm_twdog_arm((const struct wt_co*)co,
                                        (uint32_t)frame->x[1],
                                        (uint32_t)frame->x[2]) == 0) ?
                      0u : (uint64_t)(int64_t)-1;
    }
    else if (fid == WT_SPM_SVC_FID_TIMER_STOP) {
        wt_spm_twdog_stop((const struct wt_co*)co);
        frame->x[0] = 0u;
    }
#endif
    else if (wt_ffa_fid_in_range(fid) && (co != NULL) &&
             !wt_ffa_fid_available(fid, sp_version((const struct wt_co*)co))) {
        /* 13.2.2: an ABI from after the partition's negotiated version. */
        ffa_not_supported(frame);
    }
    else if (fid == WT_FFA_MSG_WAIT) {
        /* 8.2/8.5: the partition enters the waiting state, which for one
         * still initializing signals success; the next direct request is
         * delivered as this call's return registers. A Secure interrupt
         * queued while it ran (Table 9.1) is delivered here as FFA_INTERRUPT
         * instead of blocking, w1/w2 zero (12.4.1 item 3). Either way the
         * call hands the RX buffer back (7.2.2.4.2) unless a v1.2 caller
         * keeps it with w2 bit 0 (Table 14.3). */
        busy = wt_spm_ffa_sp_requester((const struct wt_co*)co, &requester,
                                       &self);
        sint = 0u;
        if (busy == 0) {
            wt_spm_sp_init_complete((const struct wt_co*)co);
            sint = wt_spm_sint_take_pending(co);
            /* DEN0077A v1.2 REL0 Table 14.3 defines w2 bit 0 (SBZ in ALP1). */
            if (wt_ffa_rt_msg_wait_releases_rx(sp_version(co),
                                               frame->x) != 0) {
                (void)wt_ffa_mailbox_rx_release(sp_mailbox());
            }
        }
        if (busy != 0) {
            ffa_error(frame, WT_FFA_DENIED);
        }
        else if (sint != 0u) {
            for (i = 0u; i < 8u; i++) {
                frame->x[i] = 0u;
            }
            frame->x[0] = WT_FFA_INTERRUPT;
        }
        else {
            g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_WAIT;
            wt_co_block();
        }
    }
    else if ((fid == WT_FFA_MSG_SEND_DIRECT_REQ32) ||
             (fid == WT_FFA_MSG_SEND_DIRECT_REQ64) ||
             (fid == WT_FFA_MSG_SEND_DIRECT_REQ2)) {
        ffa_direct_req(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_RUN) {
        ffa_run(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_YIELD) {
        ffa_yield(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_ERROR) {
        ffa_init_failed(frame, co);
    }
    else if ((fid == WT_FFA_SUCCESS32) || (fid == WT_FFA_SUCCESS64)) {
        ffa_direct_success(frame, (const struct wt_co*)co);
    }
    else if ((fid == WT_FFA_MSG_SEND_DIRECT_RESP32) ||
             (fid == WT_FFA_MSG_SEND_DIRECT_RESP64) ||
             (fid == WT_FFA_MSG_SEND_DIRECT_RESP2)) {
        ffa_direct_resp(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_VERSION) {
        ffa_version(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_FEATURES) {
        ffa_features(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_ID_GET) {
        ffa_success(frame, wt_spm_sp_ffa_id((const struct wt_co*)co), 0u);
    }
    else if (fid == WT_FFA_SPM_ID_GET) {
        ffa_success(frame, WT_FFA_ID_SPMC, 0u);
    }
    else if ((fid == WT_FFA_CONSOLE_LOG32) || (fid == WT_FFA_CONSOLE_LOG64)) {
        ffa_console_log(frame, (fid == WT_FFA_CONSOLE_LOG64) ? 1u : 0u);
    }
    else if (sp_notif_denied(fid, (const struct wt_co*)co) != 0) {
        ffa_not_supported(frame);
    }
    else if ((fid == WT_FFA_NOTIFICATION_BIND) ||
             (fid == WT_FFA_NOTIFICATION_UNBIND)) {
        ffa_notif_bind(frame, (const struct wt_co*)co,
                       (fid == WT_FFA_NOTIFICATION_UNBIND) ? 1u : 0u);
    }
    else if (fid == WT_FFA_NOTIFICATION_SET) {
        ffa_notif_set(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_NOTIFICATION_GET) {
        ffa_notif_get(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_MSG_SEND2) {
        ffa_msg_send2(frame, (const struct wt_co*)co);
    }
    else if ((fid == WT_FFA_MEM_PERM_SET32) || (fid == WT_FFA_MEM_PERM_SET64)) {
        ffa_mem_perm_set(frame, (const struct wt_co*)co);
    }
    else if ((fid == WT_FFA_MEM_PERM_GET32) || (fid == WT_FFA_MEM_PERM_GET64)) {
        ffa_mem_perm_get(frame, (const struct wt_co*)co);
    }
    else if ((fid == WT_FFA_RXTX_MAP32) || (fid == WT_FFA_RXTX_MAP64)) {
        ffa_rxtx_map(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_RXTX_UNMAP) {
        ffa_rxtx_unmap(frame);
    }
    else if (fid == WT_FFA_PARTITION_INFO_GET) {
        ffa_partition_info_get(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_PARTITION_INFO_GET_REGS) {
        ffa_partition_info_get_regs(frame);
    }
    else if (fid == WT_FFA_RX_RELEASE) {
        ffa_rx_release(frame);
    }
    else if ((fid == WT_FFA_MEM_SHARE32) || (fid == WT_FFA_MEM_SHARE64)) {
        ffa_mem_send(frame, WT_FFA_MEM_OP_SHARE);
    }
    else if ((fid == WT_FFA_MEM_LEND32) || (fid == WT_FFA_MEM_LEND64)) {
        ffa_mem_send(frame, WT_FFA_MEM_OP_LEND);
    }
    else if ((fid == WT_FFA_MEM_DONATE32) || (fid == WT_FFA_MEM_DONATE64)) {
        ffa_mem_send(frame, WT_FFA_MEM_OP_DONATE);
    }
    else if ((fid == WT_FFA_MEM_RETRIEVE_REQ32) ||
             (fid == WT_FFA_MEM_RETRIEVE_REQ64)) {
        ffa_mem_retrieve(frame);
    }
    else if (fid == WT_FFA_MEM_RELINQUISH) {
        ffa_mem_relinquish(frame);
    }
    else if (fid == WT_FFA_MEM_RECLAIM) {
        ffa_mem_reclaim(frame);
    }
    else if (fid == WT_FFA_MEM_FRAG_TX) {
        ffa_mem_frag_tx(frame);
    }
    else if (fid == WT_FFA_MEM_FRAG_RX) {
        /* A retrieve response always fits the caller's RX buffer, so no
         * fragment is ever outstanding for it to ask for. */
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
    }
    else {
        ffa_not_supported(frame);
    }
    if (wt_ffa_fid_in_range(fid)) {
        wt_ffa_reply_clear_ext(fid, frame->x);
    }

    g_wt_spm_handler_depth--;
    g_wt_spm_live_frame = NULL;
}
