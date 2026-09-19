/* ns.c
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

/* A minimal Normal-world payload for the ns-smoke scenario: print the exception
 * level on the NS console, negotiate FF-A with an SMC to the SPMD, and report
 * the version. It proves the world switch and the SPMD NS physical instance. */

#include "wolftrust/arch/aarch64/ffa_abi.h"
#include "wolftrust/arch/aarch64/psci.h"

#if defined(WT_NS_GUEST_PSA)
#include "psa/client.h"
#include "psa/error.h"
#include "psa_manifest/sid.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"
#if defined(WT_NS_HSM_ATTACK)
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"
#endif
#include "wolftrust/hsm_psa_transport.h"
#ifndef WT_NS_GUEST_ID
#define WT_NS_GUEST_ID 0
#endif
#endif

#include <stdint.h>

#define UART_DR         0x00u
#define UART_FR         0x18u
#define UART_FR_TXFF    (1u << 5)

static volatile uint32_t* uart_reg(uint32_t offset)
{
    return (volatile uint32_t*)(uintptr_t)(WT_NS_UART + offset);
}

static void put_char(char c)
{
    while ((*uart_reg(UART_FR) & UART_FR_TXFF) != 0u) {
    }
    *uart_reg(UART_DR) = (uint32_t)(uint8_t)c;
}

static void put_str(const char* s)
{
    while (*s != '\0') {
        put_char(*s);
        s++;
    }
}

static void put_hex(uint32_t value)
{
    static const char digits[] = "0123456789abcdef";
    char buf[9];
    int i = 8;

    buf[i] = '\0';
    do {
        i--;
        buf[i] = digits[value & 0xFu];
        value >>= 4;
    } while (value != 0u && i > 0);
    put_str(&buf[i]);
}

static void put_dec(uint32_t value)
{
    char buf[11];
    int i = 10;

    buf[i] = '\0';
    do {
        i--;
        buf[i] = (char)('0' + (char)(value % 10u));
        value /= 10u;
    } while (value != 0u && i > 0);
    put_str(&buf[i]);
}

/* One FF-A SMC to the SPMD at the NS physical instance: in0/in1 in x0/x1, the
 * reply x0-x3 written back to out[0..3]. */
static void ffa_smc(uint64_t in0, uint64_t in1, uint64_t* out)
{
    register uint64_t r0 __asm__("x0") = in0;
    register uint64_t r1 __asm__("x1") = in1;
    register uint64_t r2 __asm__("x2") = 0;
    register uint64_t r3 __asm__("x3") = 0;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                       "x13", "x14", "x15", "x16", "x17", "memory");
    out[0] = r0;
    out[1] = r1;
    out[2] = r2;
    out[3] = r3;
}

/* FFA_PARTITION_INFO_GET with the count-only flag (Nil UUID lists all): the SPMD
 * forwards it to the SPMC, which replies with the partition count in x2. Returns
 * the count, or 0 on error. Passes the flag in x5, so it cannot use ffa_smc. */
static uint32_t partition_count(void)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_PARTITION_INFO_GET;
    register uint64_t r1 __asm__("x1") = 0;
    register uint64_t r2 __asm__("x2") = 0;
    register uint64_t r3 __asm__("x3") = 0;
    register uint64_t r4 __asm__("x4") = 0;
    register uint64_t r5 __asm__("x5") = WT_FFA_PARTINFO_FLAG_COUNT;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5)
                     :
                     : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                       "x15", "x16", "x17", "memory");
    if ((uint32_t)r0 != WT_FFA_SUCCESS32) {
        return 0u;
    }
    return (uint32_t)r2;
}

#if defined(WT_NS_GUEST_ECHO)
/* Send an FF-A direct request to the Secure echo partition and check it
 * complements the payload (7.4): proves the guest->SP->guest message path
 * relayed through the SPMD and the SPMC. */
static void guest_direct(void)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_MSG_SEND_DIRECT_REQ32;
    register uint64_t r1 __asm__("x1") =
        ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16) | WT_FFA_ID_ECHO;
    register uint64_t r2 __asm__("x2") = 0;
    register uint64_t r3 __asm__("x3") = WT_FFA_TEST_PAYLOAD;
    register uint64_t r4 __asm__("x4") = 0;
    register uint64_t r5 __asm__("x5") = 0;
    register uint64_t r6 __asm__("x6") = 0;
    register uint64_t r7 __asm__("x7") = 0;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4),
                       "+r"(r5), "+r"(r6), "+r"(r7)
                     :
                     : "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                       "x15", "x16", "x17", "memory");
    if (((uint32_t)r0 == WT_FFA_MSG_SEND_DIRECT_RESP32) &&
        ((uint32_t)r3 == (uint32_t)~WT_FFA_TEST_PAYLOAD)) {
        put_str("[NS] direct resp ok x3=0x");
    }
    else {
        put_str("[NS] direct resp BAD x3=0x");
    }
    put_hex((uint32_t)r3);
    put_str("\r\n");
}
#endif

#if defined(WT_NS_GUEST_PSA)
/* Reach the real Secure services over the operating-system-neutral PSA client
 * (src/client/psa_ffm_client.c, the same client an Armv8-M guest links) whose
 * WolfTrust_FFM_* entry points are the FF-A binding here: read the framework
 * and service versions, connect to SERVICE_HSM, prove an unknown service is
 * refused, close, then run the wolfHSM client over the same SPM-mediated
 * transport every Armv8-M guest uses (src/client/hsm_psa_transport.c) for one
 * echo through the relay partition and the wolfHSM server - the Secure side
 * only ever sees SPM-mediated copies of the guest's vectors. */
static const uint8_t g_hsm_echo_in[] = "wolfTrust FF-A SERVICE_HSM relay echo";
static wt_hsm_psa_transport_ctx_t g_hsm_tx;
static const wt_hsm_psa_transport_cfg_t g_hsm_tx_cfg = {
    .sid = SERVICE_HSM_SID,
    .version = 1u
};
static whCommClientConfig g_hsm_comm_cfg;
static whClientConfig g_hsm_client_cfg;
static whClientContext g_hsm_client;

static int guest_hsm_echo(void)
{
    uint8_t echo_out[sizeof(g_hsm_echo_in)];
    uint16_t echo_len = 0u;
    uint16_t want = (uint16_t)(sizeof(g_hsm_echo_in) - 1u);
    uint16_t i;
    int ok = 0;
    int rc;

    g_hsm_comm_cfg.transport_cb = &wt_hsm_psa_transport_cb;
    g_hsm_comm_cfg.transport_context = &g_hsm_tx;
    g_hsm_comm_cfg.transport_config = &g_hsm_tx_cfg;
    g_hsm_comm_cfg.client_id = 0u;
    g_hsm_client_cfg.comm = &g_hsm_comm_cfg;

    rc = wh_Client_Init(&g_hsm_client, &g_hsm_client_cfg);
    put_str("[NS] hsm client init rc=0x");
    put_hex((uint32_t)rc);
    put_str("\r\n");
    if (rc != WH_ERROR_OK) {
        return 0;
    }

    for (i = 0u; i < sizeof(echo_out); i++) {
        echo_out[i] = 0u;
    }
    rc = wh_Client_Echo(&g_hsm_client, want, g_hsm_echo_in, &echo_len,
                        echo_out);
    put_str("[NS] hsm echo rc=0x");
    put_hex((uint32_t)rc);
    put_str(" len=");
    put_dec(echo_len);
    put_str("\r\n");
    if ((rc == WH_ERROR_OK) && (echo_len == want)) {
        ok = 1;
        for (i = 0u; i < want; i++) {
            if (echo_out[i] != g_hsm_echo_in[i]) {
                ok = 0;
            }
        }
    }
    (void)wh_Client_Cleanup(&g_hsm_client);
    return ok;
}

#if defined(WT_NS_HSM_ATTACK)
/* Compromised-guest probe: a COMM_INIT forging the attestation-reserved client
 * id must not reach the committed IAK (key 0xF0), a raw NVM-group request must
 * never reach the server, and the guest's own relay namespace still works. */
#define WT_HSM_ATTACK_IAK_KEY_ID 0xF0u
#define WT_HSM_ATTACK_ROLLBACK_ID 0x0122u /* WT_HSM_ROLLBACK_TABLE_ID */

static void guest_hsm_attack(void)
{
    uint8_t label[WH_NVM_LABEL_LEN];
    uint8_t key[64];
    uint8_t nvmbuf[16];
    uint16_t keySz = (uint16_t)sizeof(key);
    uint16_t rGroup = 0u;
    uint16_t rAction = 0u;
    uint16_t rSize = (uint16_t)sizeof(nvmbuf);
    uint32_t outClientId = 0u;
    uint32_t outServerId = 0u;
    int guard = 1000;
    unsigned int i;
    int rc;

    g_hsm_comm_cfg.transport_cb = &wt_hsm_psa_transport_cb;
    g_hsm_comm_cfg.transport_context = &g_hsm_tx;
    g_hsm_comm_cfg.transport_config = &g_hsm_tx_cfg;
    g_hsm_comm_cfg.client_id = (uint8_t)WH_CLIENT_ID_MAX;
    g_hsm_client_cfg.comm = &g_hsm_comm_cfg;
    rc = wh_Client_Init(&g_hsm_client, &g_hsm_client_cfg);
    if (rc == WH_ERROR_OK) {
        rc = wh_Client_CommInit(&g_hsm_client, &outClientId, &outServerId);
    }
    put_str("[NS] hsmattack forged COMM_INIT client_id=");
    put_dec(outClientId);
    put_str(" rc=0x");
    put_hex((uint32_t)rc);
    put_str("\r\n");

    rc = wh_Client_KeyExport(&g_hsm_client, WT_HSM_ATTACK_IAK_KEY_ID, label,
                             (uint16_t)sizeof(label), key, &keySz);
    if (rc != WH_ERROR_OK) {
        put_str("[NS] hsmattack IAK read refused rc=0x");
        put_hex((uint32_t)rc);
        put_str("\r\n");
    }
    else {
        put_str("[NS] hsmattack IAK read SUCCEEDED\r\n");
    }

    for (i = 0u; i < sizeof(nvmbuf); i++) {
        nvmbuf[i] = 0u;
    }
    nvmbuf[0] = (uint8_t)(WT_HSM_ATTACK_ROLLBACK_ID & 0xFFu);
    nvmbuf[1] = (uint8_t)((WT_HSM_ATTACK_ROLLBACK_ID >> 8) & 0xFFu);
    rc = wh_Client_SendRequest(&g_hsm_client, WH_MESSAGE_GROUP_NVM,
                               WH_MESSAGE_NVM_ACTION_READ,
                               (uint16_t)sizeof(nvmbuf), nvmbuf);
    if (rc == WH_ERROR_OK) {
        do {
            rc = wh_Client_RecvResponse(&g_hsm_client, &rGroup, &rAction,
                                        &rSize, nvmbuf);
        } while ((rc == WH_ERROR_NOTREADY) && (guard-- > 0));
    }
    if (rc != WH_ERROR_OK) {
        put_str("[NS] hsmattack rollback NVM group refused rc=0x");
        put_hex((uint32_t)rc);
        put_str("\r\n");
    }
    else {
        put_str("[NS] hsmattack rollback NVM group SUCCEEDED\r\n");
    }
    (void)wh_Client_Cleanup(&g_hsm_client);

    if (guest_hsm_echo() != 0) {
        put_str("[NS] hsmattack own-namespace relay still works\r\n");
    }
    else {
        put_str("[NS] hsmattack own-namespace relay BROKEN\r\n");
    }
}
#endif

static void guest_psa(void)
{
    uint32_t fw;
    uint32_t ver;
    psa_handle_t handle;
    psa_handle_t refused;

    fw = psa_framework_version();
    put_str("[NS] psa framework 0x");
    put_hex(fw);
    put_str("\r\n");

    ver = psa_version(SERVICE_HSM_SID);
    put_str("[NS] psa version v=");
    put_dec(ver);
    put_str("\r\n");

    handle = psa_connect(SERVICE_HSM_SID, 1u);
    if (PSA_HANDLE_IS_VALID(handle)) {
        put_str("[NS] psa connect ok handle=");
        put_dec((uint32_t)handle);
        put_str("\r\n");
    }
    else {
        put_str("[NS] psa connect FAIL\r\n");
    }

    refused = psa_connect(0x9999u, 1u);
    if (!PSA_HANDLE_IS_VALID(refused)) {
        put_str("[NS] psa connect refused\r\n");
    }
    else {
        put_str("[NS] psa connect NOT refused\r\n");
        psa_close(refused);
    }

    if (PSA_HANDLE_IS_VALID(handle)) {
        psa_close(handle);
        put_str("[NS] psa close ok\r\n");
    }

    if (guest_hsm_echo() != 0) {
        put_str("[NS] psa call ok\r\n");
        put_str("[NS] hsm echo ok\r\n");
    }
    else {
        put_str("[NS] psa call BAD\r\n");
    }
#if defined(WT_NS_HSM_ATTACK)
    guest_hsm_attack();
#endif

    put_str("[NS] guest");
    put_dec((uint32_t)WT_NS_GUEST_ID);
    put_str(" ok\r\n");
}
#endif

#if defined(WT_NS_GUEST_STORAGE)
#include "psa/client.h"
#include "psa/error.h"
#include "psa/storage_common.h"
#include "psa/internal_trusted_storage.h"
#include "psa_manifest/sid.h"

/* An ITS round trip is the first Normal-world request whose service calls a
 * second partition: SERVICE_ITS fronts the VAULT partition, so every op below
 * crosses the SVC gate SP-to-SP and back before the reply reaches the guest. */
static void guest_storage(void)
{
    static const uint8_t its_in[4] = { 0x11u, 0x22u, 0x33u, 0x44u };
    uint8_t its_out[4] = { 0u, 0u, 0u, 0u };
    struct psa_storage_info_t info;
    psa_storage_uid_t uid = 0x5A5Au;
    size_t got = 0u;
    psa_status_t st_info;
    psa_status_t st_set;
    psa_status_t st_get;

    st_info = psa_its_get_info(uid, &info);
    put_str("[NS] its info st=0x");
    put_hex((uint32_t)st_info);
    put_str("\r\n");
    st_set = psa_its_set(uid, sizeof(its_in), its_in, PSA_STORAGE_FLAG_NONE);
    put_str("[NS] its set st=0x");
    put_hex((uint32_t)st_set);
    put_str("\r\n");
    st_get = psa_its_get(uid, 0u, sizeof(its_out), its_out, &got);
    put_str("[NS] its get st=0x");
    put_hex((uint32_t)st_get);
    put_str(" len=");
    put_dec((uint32_t)got);
    put_str("\r\n");
    if ((st_info == PSA_ERROR_DOES_NOT_EXIST) && (st_set == PSA_SUCCESS) &&
        (st_get == PSA_SUCCESS) && (got == sizeof(its_in)) &&
        (its_out[0] == its_in[0]) && (its_out[3] == its_in[3])) {
        put_str("[NS] its ok\r\n");
    }
    else {
        put_str("[NS] its BAD\r\n");
    }
    (void)psa_its_remove(uid);
}
#endif

#if defined(WT_NS_GUEST_CONF)
extern char _ns_vectbl[];
extern int32_t val_entry(void);

void ns_putc(char c)
{
    put_char(c);
}

/* The suite's Normal-world PROGRAMMER-ERROR checks may abort the client by
 * design; answer as the conformance monitor does on Armv8-M, with a system
 * reset that val resumes from off its NVM boot flag. */
void ns_abort_report(uint64_t esr)
{
    uint64_t o[4];

    put_str("[NS] abort esr=0x");
    put_hex((uint32_t)esr);
    put_str(" reset\r\n");
    ffa_smc(WT_PSCI_SYSTEM_RESET, 0u, o);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

/* Run the unmodified Arm psa-arch-tests val NSPE against the SPMC: every test
 * reaches the SERVER/CLIENT/DRIVER partitions through the routed PSA client. */
static void guest_conformance(void)
{
    __asm__ volatile("msr vbar_el1, %0\n\tisb" : : "r"(_ns_vectbl));
    put_str("[NS] conformance val_entry start\r\n");
    (void)val_entry();
    put_str("[NS] conformance val_entry returned\r\n");
}
#endif

#if defined(WT_NS_GUEST_MEMNEG)
#include "wolftrust/arch/aarch64/ffa_mem.h"

/* A page the guest offers to share (its content is irrelevant to descriptor
 * validation) and the descriptor buffer, both in the guest's NS window so the
 * SPMC can read the descriptor it points the relayer at. */
static uint8_t g_memneg_page[4096] __attribute__((aligned(4096)));
static uint8_t g_memneg_desc[256];

/* FFA_MEM_SHARE with the descriptor at an explicit NS address in x3 (7.3): the
 * SPMD forwards it, the SPMC reads and validates the descriptor. Returns the
 * FF-A status (x0); w2 and w3 carry the handle on success, w2 the error code. */
static uint32_t mem_share_smc(uint64_t addr, uint32_t len, uint64_t* w2,
                              uint64_t* w3)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_MEM_SHARE32;
    register uint64_t r1 __asm__("x1") = len;
    register uint64_t r2 __asm__("x2") = len;
    register uint64_t r3 __asm__("x3") = addr;
    register uint64_t r4 __asm__("x4") = 1u;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4)
                     :
                     : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
                       "x14", "x15", "x16", "x17", "memory");
    *w2 = r2;
    *w3 = r3;
    return (uint32_t)r0;
}

static uint32_t mem_reclaim_smc(uint64_t handle)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_MEM_RECLAIM;
    register uint64_t r1 __asm__("x1") = handle & 0xFFFFFFFFu;
    register uint64_t r2 __asm__("x2") = handle >> 32;
    register uint64_t r3 __asm__("x3") = 0;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                       "x13", "x14", "x15", "x16", "x17", "memory");
    return (uint32_t)r0;
}

/* Build a well-formed single-constituent share descriptor into g_memneg_desc;
 * returns its length or 0. */
static uint32_t memneg_build(void)
{
    wt_ffa_mem_constituent_t cons;
    wt_ffa_mem_build_t in;
    size_t len = 0u;

    cons.address = (uint64_t)(uintptr_t)g_memneg_page;
    cons.page_count = 1u;
    in.constituents = &cons;
    in.constituent_count = 1u;
    in.tag = 0u;
    in.handle = 0u;
    in.flags = 0u;
    in.op = WT_FFA_MEM_OP_SHARE;
    in.sender = WT_FFA_ID_NS_PRIMARY;
    in.receiver = WT_FFA_ID_SP_FIRST;
    in.attributes = (uint16_t)(WT_FFA_MEM_ATTR_TYPE_NORMAL |
                               (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT) |
                               WT_FFA_MEM_ATTR_SHARE_INNER | WT_FFA_MEM_ATTR_NS);
    in.permissions = (uint8_t)(WT_FFA_MEM_PERM_DATA_RW | WT_FFA_MEM_PERM_INSTR_NX);
    if (wt_ffa_mem_txn_build(g_memneg_desc, sizeof(g_memneg_desc), &in,
                             &len) != 0) {
        return 0u;
    }
    return (uint32_t)len;
}

static int memneg_refused(uint32_t len)
{
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;

    return mem_share_smc((uint64_t)(uintptr_t)g_memneg_desc, len, &w2, &w3) ==
           WT_FFA_ERROR;
}

/* Offer a well-formed FFA_MEM_SHARE (accepted, a handle returned), then a set of
 * malformed descriptors (each refused with no crash), reclaim the good handle,
 * and confirm a second reclaim of the now-dead handle is refused. */
static void guest_memneg(void)
{
    uint64_t handle;
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;
    uint32_t len;
    int ok = 1;

    len = memneg_build();
    if (len == 0u) {
        put_str("[NS] memneg BAD build\r\n");
        return;
    }
    if (mem_share_smc((uint64_t)(uintptr_t)g_memneg_desc, len, &w2, &w3) !=
        WT_FFA_SUCCESS32) {
        put_str("[NS] memneg BAD share\r\n");
        return;
    }
    handle = (w2 & 0xFFFFFFFFu) | (w3 << 32);

    (void)memneg_build();
    g_memneg_desc[80] = 1u;                 /* misaligned constituent base */
    ok = ok && memneg_refused(len);
    (void)memneg_build();
    g_memneg_desc[0] = 0x34u;               /* sender is not the caller */
    g_memneg_desc[1] = 0x12u;
    ok = ok && memneg_refused(len);
    (void)memneg_build();
    g_memneg_desc[50] = 0xF2u;              /* reserved permission bits */
    ok = ok && memneg_refused(len);
    (void)memneg_build();
    g_memneg_desc[64] = 9u;                 /* total page count != the sum */
    ok = ok && memneg_refused(len);

    ok = ok && (mem_reclaim_smc(handle) == WT_FFA_SUCCESS32);
    ok = ok && (mem_reclaim_smc(handle) == WT_FFA_ERROR);  /* dead handle */

    put_str(ok ? "[NS] memneg ok\r\n" : "[NS] memneg BAD\r\n");
}
#endif

#if defined(WT_NS_GUEST_FUZZ)
/* Sweep function ids the SPMD does not implement at the NS physical instance -
 * unimplemented FF-A ids, unimplemented PSCI ids, and ids outside every served
 * range - and confirm each is refused cleanly (no crash, no world change): FF-A
 * ids answer FFA_ERROR/NOT_SUPPORTED, the rest answer the SMCCC unknown value.
 * Built from macros so no raw FF-A id literal lives outside ffa_abi.h. */
static const uint32_t g_fuzz_fids[] = {
    WT_FFA_RX_RELEASE,
    WT_FFA_MSG_WAIT, WT_FFA_YIELD, WT_FFA_RUN, WT_FFA_NORMAL_WORLD_RESUME,
    WT_FFA_NOTIFICATION_BITMAP_CREATE, WT_FFA_RX_ACQUIRE, WT_FFA_MSG_SEND2,
    WT_FFA_CONSOLE_LOG32, WT_FFA_CONSOLE_LOG64, WT_FFA_PARTITION_INFO_GET_REGS,
    WT_FFA_MSG_SEND_DIRECT_REQ2, WT_FFA_FID32_LAST, WT_FFA_FID64_LAST,
    WT_PSCI_CPU_OFF, WT_PSCI_MIGRATE_INFO_TYPE, WT_PSCI_FID32_LAST,
    0x82000000u, 0x8F000000u, 0xC3000000u
};

static int fuzz_refused(uint32_t fid, const uint64_t* o)
{
    if (wt_ffa_fid_in_range(fid)) {
        return ((uint32_t)o[0] == WT_FFA_ERROR) &&
               ((int32_t)(uint32_t)o[2] == WT_FFA_NOT_SUPPORTED);
    }
    return (uint32_t)o[0] == 0xFFFFFFFFu;
}

static void guest_fuzz(void)
{
    uint64_t o[4];
    unsigned int n = (unsigned int)(sizeof(g_fuzz_fids) / sizeof(g_fuzz_fids[0]));
    unsigned int ok = 0u;
    unsigned int i;

    for (i = 0u; i < n; i++) {
        ffa_smc(g_fuzz_fids[i], 0u, o);
        if (fuzz_refused(g_fuzz_fids[i], o)) {
            ok++;
        }
        else {
            put_str("[NS] smcfuzz BAD fid=0x");
            put_hex(g_fuzz_fids[i]);
            put_str(" x0=0x");
            put_hex((uint32_t)o[0]);
            put_str("\r\n");
        }
    }
    if (ok == n) {
        put_str("[NS] smcfuzz ok swept=");
        put_dec(n);
        put_str("\r\n");
    }
    else {
        put_str("[NS] smcfuzz FAIL ok=");
        put_dec(ok);
        put_str("\r\n");
    }
}
#endif

#if defined(WT_NS_GUEST_RESET)
/* Ask the SPMD to reset the system through PSCI. On the first boot the monitor
 * re-enters the whole chain; the reset does not return to the Normal world. */
static void guest_reset(void)
{
    uint64_t o[4];

    put_str("[NS] psci system_reset\r\n");
    ffa_smc(WT_PSCI_SYSTEM_RESET, 0u, o);
}
#endif

#if defined(WT_NS_GUEST_SECRAM)
extern char _ns_vectbl[];
extern void ns_exit(int code);

/* The Normal world's own abort vector (ns.S) lands here when the Secure-RAM read
 * faults: report the refusal and end the run. A hang (no handler) or a returned
 * value (a leak) would both be failures. */
void ns_abort_report(uint64_t esr)
{
    put_str("[NS] secram refused esr=0x");
    put_hex((uint32_t)esr);
    put_str("\r\n");
    ns_exit(0);
}

/* Attempt to read Secure RAM from the Normal world: the secure physical region
 * must be unreachable from NS. The read is expected to fault into the guest's
 * own abort vector (proving the world fence); if it ever returns data the fence
 * is broken. */
static void guest_secram(void)
{
    volatile uint32_t* p = (volatile uint32_t*)(uintptr_t)WT_NS_SECURE_PROBE_PA;
    uint32_t v;

    __asm__ volatile("msr vbar_el1, %0\n\tisb" : : "r"(_ns_vectbl));
    put_str("[NS] secram read 0x");
    put_hex((uint32_t)WT_NS_SECURE_PROBE_PA);
    put_str("\r\n");
    v = *p;
    put_str("[NS] secram LEAK 0x");
    put_hex(v);
    put_str("\r\n");
}
#endif

/* Walk the NS physical instance: FEATURES(VERSION) is supported, ID_GET returns
 * the caller's own id (the primary NS endpoint, 0), SPM_ID_GET returns the SPMC
 * id (0x8000), and PARTITION_INFO_GET (forwarded to the SPMC) reports the
 * partition count. Returns non-zero when all answer as expected; *count holds
 * the reported partition count. */
static int discover(uint32_t* count)
{
    uint64_t o[4];

    ffa_smc(WT_FFA_FEATURES, WT_FFA_VERSION, o);
    if ((uint32_t)o[0] != WT_FFA_SUCCESS32) {
        return 0;
    }
    ffa_smc(WT_FFA_ID_GET, 0u, o);
    if (((uint32_t)o[0] != WT_FFA_SUCCESS32) ||
        ((uint16_t)o[2] != WT_FFA_ID_NS_PRIMARY)) {
        return 0;
    }
    ffa_smc(WT_FFA_SPM_ID_GET, 0u, o);
    if (((uint32_t)o[0] != WT_FFA_SUCCESS32) ||
        ((uint16_t)o[2] != WT_FFA_ID_SPMC)) {
        return 0;
    }
    *count = partition_count();
    if (*count == 0u) {
        return 0;
    }
    return 1;
}

#if defined(WT_NS_GUEST_PSCI)
/* Read the PSCI version from the SPMD, then power off through PSCI (WT-FFM-0067):
 * SYSTEM_OFF does not return, so the SPMD ends the run. */
static void psci_walk(void)
{
    uint64_t o[4];

    ffa_smc(WT_PSCI_VERSION, 0u, o);
    put_str("[NS] psci version ");
    put_dec((uint32_t)((o[0] >> 16) & 0xFFFFu));
    put_char('.');
    put_dec((uint32_t)(o[0] & 0xFFFFu));
    put_str("\r\n");
    ffa_smc(WT_PSCI_SYSTEM_OFF, 0u, o);
}
#endif

#if defined(WT_NS_PREEMPT)
/* Spin ~200ms of guest time so the Secure tick fires while the Normal world
 * runs; the preemption is handled at EL3 and the loop resumes to completion. */
static void ns_spin(void)
{
    uint64_t freq;
    uint64_t start;
    uint64_t now;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(start));
    put_str("[NS] spinning\r\n");
    do {
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
    } while ((now - start) < (freq / 5u));
    put_str("[NS] resumed after preempt\r\n");
}
#endif

void ns_main(void)
{
    uint64_t current_el;
    uint64_t o[4];
    uint32_t count = 0u;

    __asm__ volatile("mrs %0, CurrentEL" : "=r"(current_el));
    put_str("[NS] hello el=");
    put_char((char)('0' + (char)((current_el >> 2) & 0x3u)));
    put_str("\r\n");

    ffa_smc(WT_FFA_VERSION, WT_FFA_VERSION_1_2, o);
    if ((uint32_t)o[0] == WT_FFA_VERSION_1_2) {
        put_str("[NS] ffa version 1.2\r\n");
    }
    else {
        put_str("[NS] ffa version BAD 0x");
        put_hex((uint32_t)o[0]);
        put_str("\r\n");
    }

#if defined(WT_NS_PREEMPT)
    ns_spin();
    return;
#endif

#if defined(WT_NS_GUEST_SECRAM)
    guest_secram();
    return;
#endif

#if defined(WT_NS_GUEST_RESET)
    guest_reset();
    return;
#endif

#if defined(WT_NS_GUEST_PSCI)
    psci_walk();
#endif

    if (discover(&count)) {
        put_str("[NS] discovery ok n=");
        put_dec(count);
        put_str("\r\n");
    }
    else {
        put_str("[NS] discovery BAD\r\n");
    }

#if defined(WT_NS_GUEST_ECHO)
    guest_direct();
#endif

#if defined(WT_NS_GUEST_PSA)
    guest_psa();
#endif

#if defined(WT_NS_GUEST_FUZZ)
    guest_fuzz();
#endif

#if defined(WT_NS_GUEST_STORAGE)
    guest_storage();
#endif

#if defined(WT_NS_GUEST_MEMNEG)
    guest_memneg();
#endif

#if defined(WT_NS_GUEST_CONF)
    guest_conformance();
#endif
}
