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

#define WT_ESR_EC_SVC64 0x15u

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

/* The configured partitions as FFA_PARTITION_INFO_GET source records: the FF-A
 * id follows creation order (0x8002 up), matching the ids the SPMC assigns. */
static wt_ffa_partinfo_entry_t g_partinfo[16];

static size_t partinfo_collect(void)
{
    const wt_ffa_partition_manifest_t* parts;
    const wt_ffa_native_sp_t* natives;
    size_t native_count = 0u;
    size_t part_count = 0u;
    size_t cap = sizeof(g_partinfo) / sizeof(g_partinfo[0]);
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
    for (i = 0u; (i < part_count) && (n < cap); i++) {
        g_partinfo[n].id = (uint16_t)(WT_FFA_ID_SP_FIRST + i);
        g_partinfo[n].exec_contexts = (uint16_t)parts[i].execution_contexts;
        g_partinfo[n].properties = wt_ffa_partinfo_props(parts[i].messaging);
        for (j = 0u; j < 16u; j++) {
            g_partinfo[n].uuid[j] = (parts[i].uuid_count > 0u) ?
                                    parts[i].uuids[0].bytes[j] : 0u;
        }
        n++;
    }
    return n;
}

/* FFA_PARTITION_INFO_GET (6.1) for either instance: x = the call's registers
 * (UUID in w1-w4, flags in w5), mb = the caller's mailbox (NULL for a caller
 * on the SPMC's own band), rx = where descriptors go. A UUID nothing matches
 * is INVALID_PARAMETERS; descriptors take RX ownership, a count does not. */
int wt_spm_partition_info(const uint64_t* x, wt_ffa_mailbox_t* mb, uint8_t* rx,
                          uint32_t* count, uint32_t* size)
{
    size_t n = partinfo_collect();
    uint8_t uuid[16];
    uint32_t word;
    uint32_t flags = (uint32_t)x[5];
    size_t i;
    int ret;

    if (n == 0u) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < 4u; i++) {
        word = (uint32_t)x[1u + i];
        uuid[4u * i + 0u] = (uint8_t)(word & 0xFFu);
        uuid[4u * i + 1u] = (uint8_t)((word >> 8) & 0xFFu);
        uuid[4u * i + 2u] = (uint8_t)((word >> 16) & 0xFFu);
        uuid[4u * i + 3u] = (uint8_t)((word >> 24) & 0xFFu);
    }
    /* Count first: it validates the flags and finds a UUID nothing matches
     * before the RX buffer changes hands. */
    ret = wt_ffa_partinfo_write(NULL, 0u, WT_FFA_VERSION_1_2, g_partinfo, n,
                                uuid, flags | WT_FFA_PARTINFO_FLAG_COUNT, count,
                                size);
    if ((ret == 0) && (*count == 0u)) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if ((ret != 0) || ((flags & WT_FFA_PARTINFO_FLAG_COUNT) != 0u)) {
        return ret;
    }
    if (mb != NULL) {
        ret = wt_ffa_mailbox_rx_acquire(mb);
        if (ret != 0) {
            return (ret == WT_FFA_DENIED) ? WT_FFA_BUSY : ret;
        }
    }
    ret = wt_ffa_partinfo_write(rx, (size_t)WT_FFA_MEM_PAGE_SIZE,
                                WT_FFA_VERSION_1_2, g_partinfo, n, uuid, flags,
                                count, size);
    if ((ret != 0) && (mb != NULL)) {
        (void)wt_ffa_mailbox_rx_release(mb);
    }
    return ret;
}

/* FFA_PARTITION_INFO_GET_REGS for either instance: UUID in x1/x2, start index
 * and tag in x3 (bits 63:32 SBZ); the reply fills out18. */
int wt_spm_partition_info_regs(const uint64_t* x, uint64_t* out18)
{
    size_t n = partinfo_collect();
    uint8_t uuid[16];
    unsigned int i;

    if ((n == 0u) || ((x[3] >> 32) != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    for (i = 0u; i < 16u; i++) {
        uuid[i] = (uint8_t)(x[1u + (i / 8u)] >> (8u * (i % 8u)));
    }
    return wt_ffa_partinfo_regs(g_partinfo, n, uuid, (uint16_t)(x[3] & 0xFFFFu),
                                (uint16_t)((x[3] >> 16) & 0xFFFFu), out18);
}

static wt_ffa_mailbox_t* sp_mailbox(void);
static uint8_t* sp_rx(void);

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

static void ffa_partition_info_get(wt_trap_frame_t* frame)
{
    wt_ffa_mailbox_t* mb = sp_mailbox();
    uint32_t count = 0u;
    uint32_t size = 0u;
    int ret;

    if ((mb != NULL) && (mb->mapped == 0u)) {
        mb = NULL;
    }
    ret = wt_spm_partition_info(frame->x, mb, sp_rx(), &count, &size);
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, count, size);
}

/* FFA_RX_RELEASE (7.2.2.4): ownership of the RX buffer returns to the SPMC. */
static void ffa_rx_release(wt_trap_frame_t* frame)
{
    int ret = wt_ffa_mailbox_rx_release(sp_mailbox());

    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* RX/TX pairs the partitions registered with FFA_RXTX_MAP (7.2.2), indexed by
 * coroutine id; a partition that never registered uses the SPMC's own band. */
static wt_ffa_mailbox_t g_sp_mailbox[WT_CO_MAX];

struct wt_ffa_mailbox* wt_spm_sp_mailbox_of(const struct wt_co* co)
{
    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return NULL;
    }
    return &g_sp_mailbox[co->id - 1u];
}

static wt_ffa_mailbox_t* sp_mailbox(void)
{
    const struct wt_co* co = (const struct wt_co*)wt_co_current();

    if ((co == NULL) || (co->id == 0u) || (co->id > WT_CO_MAX)) {
        return NULL;
    }
    return &g_sp_mailbox[co->id - 1u];
}

/* The calling partition's RX and TX buffers. */
static uint8_t* sp_rx(void)
{
    const wt_ffa_mailbox_t* mb = sp_mailbox();

    if ((mb != NULL) && (mb->mapped != 0u)) {
        return (uint8_t*)(uintptr_t)mb->rx;
    }
    return (uint8_t*)(uintptr_t)WT_SPM_RXTX_PA;
}

static const uint8_t* sp_tx(void)
{
    const wt_ffa_mailbox_t* mb = sp_mailbox();

    if ((mb != NULL) && (mb->mapped != 0u)) {
        return (const uint8_t*)(uintptr_t)mb->tx;
    }
    return (const uint8_t*)(uintptr_t)(WT_SPM_RXTX_PA + WT_FFA_MEM_PAGE_SIZE);
}

/* One page the caller owns and may write, per its current mapping. */
static int sp_owns_writable_page(const struct wt_co* co, uintptr_t va)
{
    uint32_t attributes = 0u;

    if ((co->domain == NULL) || ((va % WT_TABLES_PAGE_SIZE) != 0u) ||
        (wt_domain_get_permissions(co->domain->regions,
                                   co->domain->region_count, va,
                                   &attributes) != WT_TABLES_OK)) {
        return 0;
    }
    return ((attributes & WT_MEM_ATTR_WRITE) != 0u) ? 1 : 0;
}

/* FFA_RXTX_MAP (13.5): x1 = TX, x2 = RX, w3 = page count. The pair must be
 * two distinct writable pages of the caller's own memory. */
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
        ((w3 != 1u) || (sp_owns_writable_page(co, tx) == 0) ||
         (sp_owns_writable_page(co, rx) == 0))) {
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

/* FFA_RXTX_UNMAP (13.6): w1 bits 31:16 name the caller (or zero). */
static void ffa_rxtx_unmap(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint16_t id = (uint16_t)(((uint32_t)frame->x[1] >> 16) & 0xFFFFu);
    int ret;

    if ((id != 0u) && (id != wt_spm_sp_ffa_id(co))) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    ret = wt_ffa_mailbox_unmap(sp_mailbox());
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* A direct request from a partition (15.2): only to another FF-A endpoint the
 * SPMC hosts, which must be waiting. The caller blocks; its callee's response
 * (or FFA_YIELD) is written into its frame before it resumes. */
static void ffa_direct_req(wt_trap_frame_t* frame, const struct wt_co* co)
{
    struct wt_co* target;
    int ret = wt_ffa_direct_req_check(frame->x, WT_FFA_INSTANCE_SECURE_VIRTUAL);

    if ((ret == 0) &&
        (wt_ffa_direct_sender(frame->x[1]) != wt_spm_sp_ffa_id(co))) {
        ret = WT_FFA_INVALID_PARAMETERS;
    }
    if (ret == 0) {
        target = wt_spm_ffa_native_by_id(wt_ffa_direct_receiver(frame->x[1]));
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
    struct wt_co* target =
        wt_spm_ffa_native_by_id((uint16_t)((uint32_t)frame->x[1] >> 16));
    int ret = wt_spm_ffa_sp_call(co, target, NULL);

    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_CALL;
    wt_co_block();
}

/* FFA_YIELD (8.2): hand the CPU back to whoever entered this partition; the
 * call returns FFA_SUCCESS once FFA_RUN resumes it. */
static void ffa_yield(wt_trap_frame_t* frame)
{
    ffa_success(frame, 0u, 0u);
    g_wt_ffa_sp_exit = WT_FFA_SP_EXIT_YIELD;
    wt_co_block();
}

/* A descriptor handed over in the TX buffer: w1 = total length, w2 = fragment
 * length (no fragmentation, so equal), w3/w4 = 0 (not an address). */
static int tx_descriptor_length(const wt_trap_frame_t* frame, size_t* out_len)
{
    uint32_t total = (uint32_t)frame->x[1];
    uint32_t frag = (uint32_t)frame->x[2];

    if ((total != frag) || (total < 1u) || (total > WT_FFA_MEM_PAGE_SIZE) ||
        (frame->x[3] != 0u) || (frame->x[4] != 0u)) {
        return WT_FFA_INVALID_PARAMETERS;
    }
    *out_len = (size_t)total;
    return 0;
}

/* FFA_MEM_SHARE / FFA_MEM_LEND from a partition: the relayer validates the
 * descriptor in its TX buffer and returns the handle in w2/w3. */
static void ffa_mem_send(wt_trap_frame_t* frame, wt_ffa_mem_op_t op)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    uint64_t handle = 0u;
    size_t len = 0u;
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = tx_descriptor_length(frame, &len);
    if (ret == 0) {
        ret = wt_spm_mem_share(sp_tx(), len, op, b->id, &handle);
    }
    if (ret != 0) {
        ffa_error(frame, ret);
        return;
    }
    ffa_success(frame, handle & 0xFFFFFFFFu, handle >> 32);
}

/* FFA_MEM_RETRIEVE_REQ from a partition: map the region and answer with
 * FFA_MEM_RETRIEVE_RESP, the response descriptor in its RX buffer. */
static void ffa_mem_retrieve(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    wt_ffa_mailbox_t* mb = sp_mailbox();
    size_t len = 0u;
    size_t resp_len = 0u;
    unsigned int i;
    int acquired = 0;
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = tx_descriptor_length(frame, &len);
    if ((ret == 0) && (mb != NULL) && (mb->mapped != 0u)) {
        ret = wt_ffa_mailbox_rx_acquire(mb);
        acquired = (ret == 0) ? 1 : 0;
    }
    if (ret == 0) {
        ret = wt_spm_mem_retrieve(sp_tx(), len, b->id, sp_rx(),
                                  WT_FFA_MEM_PAGE_SIZE, &resp_len);
    }
    if (ret != 0) {
        if (acquired != 0) {
            (void)wt_ffa_mailbox_rx_release(mb);
        }
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

/* FFA_MEM_RELINQUISH from a partition: the descriptor is in its TX buffer. */
static void ffa_mem_relinquish(wt_trap_frame_t* frame)
{
    const wt_spm_mem_binding_t* b = wt_spm_mem_binding(wt_co_current());
    int ret;

    if (b == NULL) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    ret = wt_spm_mem_relinquish(sp_tx(), WT_FFA_MEM_PAGE_SIZE, b->id);
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

/* FFA_VERSION (13.2): the result is returned in w0 alone. */
static wt_ffa_version_state_t g_sp_version[WT_CO_MAX];

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

/* FFA_FEATURES (13.3): exactly the function ids this instance serves; no
 * optional feature id is implemented. */
static void ffa_features(wt_trap_frame_t* frame)
{
    uint32_t query = (uint32_t)frame->x[1];
    uint32_t props = (uint32_t)frame->x[2];

    if ((query == WT_FFA_MEM_RETRIEVE_REQ32) ||
        (query == WT_FFA_MEM_RETRIEVE_REQ64)) {
        /* 13.3: a v1.1+ partition must say it handles the NS bit. */
        if ((props & WT_FFA_FEATURES_RETRIEVE_NS_BIT) == 0u) {
            ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        }
        else {
            ffa_success(frame, WT_FFA_FEATURES_RETRIEVE_NS_BIT, 0u);
        }
    }
    else if (WT_FFA_FEATURES_IS_FID(query) && (sp_implements(query) != 0)) {
        ffa_success(frame, 0u, 0u);
    }
    else {
        ffa_not_supported(frame);
    }
}

/* FFA_CONSOLE_LOG (13.12): w1 = count, characters packed from w2/x2 upward;
 * 1..24 over w2-w7, 1..128 over x2-x17. */
static void ffa_console_log(wt_trap_frame_t* frame, unsigned int is64)
{
    uint32_t count = (uint32_t)frame->x[1];
    unsigned int per_reg = (is64 != 0u) ? 8u : 4u;
    unsigned int max = (is64 != 0u) ? 128u : 24u;
    unsigned int i;
    uint64_t reg;

    if (((count & 0xFFFFFF00u) != 0u) || (count < 1u) || (count > max)) {
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
    int32_t ret = wt_ffa_notif_set(caller, (uint32_t)frame->x[1],
                                   (uint32_t)frame->x[2], bitmap);

    if (ret == 0) {
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
    ret = wt_spm_msg2_deliver((uint16_t)wt_spm_sp_ffa_id(co),
                              (const uint8_t*)(uintptr_t)mb->tx,
                              mb->pages * (uint32_t)WT_TABLES_PAGE_SIZE,
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

/* FFA_MEM_PERM_GET/SET permission word: bits[1:0] data access (1 = RW,
 * 3 = RO), bit[2] set = execute-never; everything else is reserved. */
#define WT_FFA_PERM_DATA_MASK 0x3u
#define WT_FFA_PERM_DATA_RW   0x1u
#define WT_FFA_PERM_DATA_RO   0x3u
#define WT_FFA_PERM_XN        0x4u

static int perm_to_attributes(uint32_t perm, uint32_t* attributes)
{
    uint32_t data = perm & WT_FFA_PERM_DATA_MASK;

    if ((perm & ~(WT_FFA_PERM_DATA_MASK | WT_FFA_PERM_XN)) != 0u) {
        return -1;
    }
    if ((data == WT_FFA_PERM_DATA_RW) && ((perm & WT_FFA_PERM_XN) != 0u)) {
        *attributes = WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE;
        return 0;
    }
    if (data == WT_FFA_PERM_DATA_RO) {
        *attributes = WT_MEM_ATTR_READ;
        if ((perm & WT_FFA_PERM_XN) == 0u) {
            *attributes |= WT_MEM_ATTR_EXEC;
        }
        return 0;
    }
    return -1;
}

/* Code every partition maps is never one partition's to re-permission. */
static int overlaps_shared(uintptr_t va, size_t pages)
{
    wt_memory_region_t shared[4];
    uintptr_t end = va + (pages * WT_TABLES_PAGE_SIZE);
    size_t n = wt_platform_sp_shared_regions(shared, 4u);
    size_t i;

    for (i = 0u; i < n; i++) {
        if ((va < (shared[i].base + shared[i].size)) && (end > shared[i].base)) {
            return 1;
        }
    }
    return 0;
}

/* FFA_MEM_PERM_SET (18.3.2): an S-EL0 partition re-permissions its own pages,
 * during its initialization only. w1 = base VA, w2 = page count, w3 = perms. */
static void ffa_mem_perm_set(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uintptr_t va = (uintptr_t)frame->x[1];
    size_t pages = (size_t)(uint32_t)frame->x[2];
    uint32_t attributes = 0u;

    if ((co->domain == NULL) || (wt_spm_sp_initializing(co) == 0)) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if ((perm_to_attributes((uint32_t)frame->x[3], &attributes) != 0) ||
        (pages == 0u) || (pages > (WT_TABLES_VA_LIMIT / WT_TABLES_PAGE_SIZE))) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    if (overlaps_shared(va, pages) != 0) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if (wt_domain_set_permissions(co->domain->regions, co->domain->region_count,
                                  va, pages, attributes) != WT_TABLES_OK) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    ffa_success(frame, 0u, 0u);
}

/* FFA_MEM_PERM_GET (18.3.1): w1 = base VA; the permissions return in w2. */
static void ffa_mem_perm_get(wt_trap_frame_t* frame, const struct wt_co* co)
{
    uint32_t attributes = 0u;
    uint32_t perm;

    if ((co->domain == NULL) || (wt_spm_sp_initializing(co) == 0)) {
        ffa_error(frame, WT_FFA_DENIED);
        return;
    }
    if (wt_domain_get_permissions(co->domain->regions, co->domain->region_count,
                                  (uintptr_t)frame->x[1], &attributes) !=
        WT_TABLES_OK) {
        ffa_error(frame, WT_FFA_INVALID_PARAMETERS);
        return;
    }
    perm = ((attributes & WT_MEM_ATTR_WRITE) != 0u) ? WT_FFA_PERM_DATA_RW
                                                     : WT_FFA_PERM_DATA_RO;
    if ((attributes & WT_MEM_ATTR_EXEC) == 0u) {
        perm |= WT_FFA_PERM_XN;
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
#if defined(WT_CONFORMANCE) && (WT_CONFORMANCE == 1)
        /* The Arm isolation tests fault inside a partition on purpose and
         * expect a system restart (val resumes off its NVM boot flag); the
         * quarantine below would leave the server dead for every later test. */
        wt_platform_system_reset();
#endif
        /* Route a partition fault through the core's restart policy; if it is
         * not a scheduled SP (e.g. the boot self-test) quarantine it here. */
        if (wt_spm_sp_fault(co) != WT_FFM_SUCCESS) {
            wt_co_mark_faulted(co);
        }
        g_wt_spm_live_frame = NULL;
        g_wt_spm_handler_depth = 0u;
        wt_sp_el0_leave();
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
        frame->x[0] = (uint64_t)(int64_t)wt_spm_dispatch_call(call, frame);
    }
    else if (fid == WT_SPM_SVC_FID_YIELD) {
        g_yield_token = frame->x[1];
        frame->x[0] = 0u;
        wt_co_block();
    }
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
        frame->x[0] = (wt_spm_twdog_arm((uint32_t)frame->x[1],
                                        (uint32_t)frame->x[2]) == 0) ?
                      0u : (uint64_t)(int64_t)-1;
    }
    else if (fid == WT_SPM_SVC_FID_TIMER_STOP) {
        wt_spm_twdog_stop((const struct wt_co*)co);
        frame->x[0] = 0u;
    }
    else if (fid == WT_FFA_MSG_WAIT) {
        /* 8.2/8.5: the partition enters the waiting state; the next direct
         * request is delivered as this call's return registers. A Secure
         * interrupt queued while it ran (Table 9.1) is delivered here as
         * FFA_INTERRUPT instead of blocking. */
        busy = wt_spm_ffa_sp_requester((const struct wt_co*)co, &requester,
                                       &self);
        sint = (busy == 0) ? wt_spm_sint_take_pending(co) : 0u;
        if (busy != 0) {
            ffa_error(frame, WT_FFA_DENIED);
        }
        else if (sint != 0u) {
            for (i = 0u; i < 8u; i++) {
                frame->x[i] = 0u;
            }
            frame->x[0] = WT_FFA_INTERRUPT;
            frame->x[1] = (uint64_t)sint;
        }
        else {
            /* 13.8: w2 bit 0 set keeps RX ownership across the wait. */
            if (((uint32_t)frame->x[2] & 1u) == 0u) {
                (void)wt_ffa_mailbox_rx_release(sp_mailbox());
            }
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
        ffa_yield(frame);
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
        ffa_features(frame);
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
        ffa_rxtx_unmap(frame, (const struct wt_co*)co);
    }
    else if (fid == WT_FFA_PARTITION_INFO_GET) {
        ffa_partition_info_get(frame);
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
    else {
        ffa_not_supported(frame);
    }

    g_wt_spm_handler_depth--;
    g_wt_spm_live_frame = NULL;
}
