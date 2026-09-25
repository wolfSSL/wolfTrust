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
#if defined(WT_NS_ENGINE_NATIVE)
#include "wolftrust/crypto_native_client.h"
#else
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"
#if defined(WT_NS_HSM_ATTACK)
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"
#endif
#include "wolftrust/hsm_psa_transport.h"
#endif
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

/* One SMC with x0-x4 in and x0-x4 back, for the fragment exchange, the
 * SMC32 register probe, and the notification probe. */
static void smc5(uint64_t* x)
{
    register uint64_t r0 __asm__("x0") = x[0];
    register uint64_t r1 __asm__("x1") = x[1];
    register uint64_t r2 __asm__("x2") = x[2];
    register uint64_t r3 __asm__("x3") = x[3];
    register uint64_t r4 __asm__("x4") = x[4];

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4)
                     :
                     : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
                       "x14", "x15", "x16", "x17", "memory");
    x[0] = r0;
    x[1] = r1;
    x[2] = r2;
    x[3] = r3;
    x[4] = r4;
}

/* A PSA partition takes no notifications (discovery leaves its property bit 3
 * clear), so a SET naming the first one the receiver is DENIED (DEN0077A
 * Table 16.20), not refused as an unknown id. */
static void notif_psa_denied(void)
{
    uint64_t x[5];

    x[0] = WT_FFA_NOTIFICATION_SET;
    x[1] = WT_FFA_ID_SP_FIRST;
    x[2] = 0u;
    x[3] = 1u;
    x[4] = 0u;
    smc5(x);
    if (((uint32_t)x[0] == WT_FFA_ERROR) &&
        ((int32_t)(uint32_t)x[2] == WT_FFA_DENIED)) {
        put_str("[NS] notif set to a PSA partition denied\r\n");
    }
    else {
        put_str("[NS] notif BAD x0=0x");
        put_hex((uint32_t)x[0]);
        put_str(" w2=0x");
        put_hex((uint32_t)x[2]);
        put_str("\r\n");
    }
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

/* One SMC with x0-x17 in and x0-x17 back through x[0..17]. */
static void smc18(uint64_t* x)
{
    register uint64_t* p __asm__("x19") = x;

    __asm__ volatile("ldp x0, x1, [%0, #0]\n\t"
                     "ldp x2, x3, [%0, #16]\n\t"
                     "ldp x4, x5, [%0, #32]\n\t"
                     "ldp x6, x7, [%0, #48]\n\t"
                     "ldp x8, x9, [%0, #64]\n\t"
                     "ldp x10, x11, [%0, #80]\n\t"
                     "ldp x12, x13, [%0, #96]\n\t"
                     "ldp x14, x15, [%0, #112]\n\t"
                     "ldp x16, x17, [%0, #128]\n\t"
                     "smc #0\n\t"
                     "stp x0, x1, [%0, #0]\n\t"
                     "stp x2, x3, [%0, #16]\n\t"
                     "stp x4, x5, [%0, #32]\n\t"
                     "stp x6, x7, [%0, #48]\n\t"
                     "stp x8, x9, [%0, #64]\n\t"
                     "stp x10, x11, [%0, #80]\n\t"
                     "stp x12, x13, [%0, #96]\n\t"
                     "stp x14, x15, [%0, #112]\n\t"
                     "stp x16, x17, [%0, #128]"
                     :
                     : "r"(p)
                     : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                       "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
                       "x17", "memory");
}

/* The echo partition takes no REQ2, so the SPMC refuses one with FFA_ERROR;
 * that 8-register reply to an SMC64 call returns x8-x17 zero (11.2), not the
 * request's own payload. */
static void guest_req2_refused(void)
{
    uint64_t x[18];
    uint64_t ext = 0u;
    unsigned int i;

    for (i = 0u; i < 18u; i++) {
        x[i] = 0x0101010101010101ull * (uint64_t)(i + 1u);
    }
    x[0] = WT_FFA_MSG_SEND_DIRECT_REQ2;
    x[1] = ((uint64_t)WT_FFA_ID_NS_PRIMARY << 16) | WT_FFA_ID_ECHO;
    x[2] = 0u;
    x[3] = 0u;
    smc18(x);
    for (i = 8u; i < 18u; i++) {
        ext |= x[i];
    }
    if (((uint32_t)x[0] == WT_FFA_ERROR) && (ext == 0u)) {
        put_str("[NS] req2 refused x8-x17 zero w2=0x");
    }
    else {
        put_str("[NS] req2 refused BAD x0=0x");
        put_hex((uint32_t)x[0]);
        put_str(" x8=0x");
        put_hex((uint32_t)x[8]);
        put_str(" w2=0x");
    }
    put_hex((uint32_t)x[2]);
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
#if defined(WT_NS_ENGINE_NATIVE)
/* Native engine: two random draws over the native crypto wire, each a
 * header in-vector and a data out-vector copied by the SPM. */
static int guest_native_random(void)
{
    uint8_t a[32];
    uint8_t b[32];
    uint8_t any = 0u;
    uint8_t diff = 0u;
    psa_status_t st;
    uint32_t i;

    for (i = 0u; i < sizeof(a); i++) {
        a[i] = 0u;
        b[i] = 0u;
    }
    st = wt_crypto_native_random(a, sizeof(a));
    if (st == PSA_SUCCESS) {
        st = wt_crypto_native_random(b, sizeof(b));
    }
    put_str("[NS] native random st=0x");
    put_hex((uint32_t)st);
    put_str("\r\n");
    if (st != PSA_SUCCESS) {
        return 0;
    }
    for (i = 0u; i < sizeof(a); i++) {
        any |= a[i];
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (any != 0u) && (diff != 0u);
}
#else
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
    /* wolfHSM refuses client id 0; the Secure side binds the real identity */
    g_hsm_comm_cfg.client_id = 1u;
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
#endif

#if defined(WT_NS_HSM_ATTACK) && !defined(WT_NS_ENGINE_NATIVE)
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
                                        &rSize, (uint16_t)sizeof(nvmbuf),
                                        nvmbuf);
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

#if defined(WT_NS_VAULT_SECURED)
/* SERVICE_ATTEST's IAK public-key query (WT_ATTEST_OP_PUBLIC_KEY). */
#define WT_NS_ATTEST_OP_PUBLIC_KEY 2

/* vaultrecoversec: the boot met a foreign vault under a locked lifecycle. Had
 * it reformatted the vault, a fresh IAK would answer this query; it must fail
 * closed instead. */
static void guest_vault_secured(void)
{
    uint8_t key[65];
    psa_outvec out;
    psa_handle_t handle;
    psa_status_t st;

    out.base = key;
    out.len = sizeof(key);
    handle = psa_connect(SERVICE_ATTEST_SID, SERVICE_ATTEST_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        put_str("[NS] vault attest connect FAIL\r\n");
        return;
    }
    st = psa_call(handle, WT_NS_ATTEST_OP_PUBLIC_KEY, NULL, 0u, &out, 1u);
    psa_close(handle);
    if (st == PSA_SUCCESS) {
        put_str("[NS] vault attest key ISSUED\r\n");
    }
    else {
        put_str("[NS] vault attest refused st=0x");
        put_hex((uint32_t)st);
        put_str("\r\n");
    }
}
#endif

/* SGI 15 in the boot core's GICv3 redistributor SGI frame. */
#define NS_IRQ_PROBE_SGI     15u
#define NS_GICR_SGI_BASE     (WT_NS_GICR + 0x10000u)
#define NS_GICR_ISENABLER0   (NS_GICR_SGI_BASE + 0x0100u)
#define NS_GICR_ICENABLER0   (NS_GICR_SGI_BASE + 0x0180u)
#define NS_GICR_ISPENDR0     (NS_GICR_SGI_BASE + 0x0200u)
#define NS_GICR_ICPENDR0     (NS_GICR_SGI_BASE + 0x0280u)
#define NS_GICR_IPRIORITYR   (NS_GICR_SGI_BASE + 0x0400u)

static volatile uint32_t* ns_gicr(uint32_t addr)
{
    return (volatile uint32_t*)(uintptr_t)addr;
}

/* Leave a Normal-world interrupt pending and signaled to this core, masked
 * only by PSTATE.I here; returns 0 without a GICv3 system-register interface. */
static int ns_irq_hold(void)
{
    uint64_t pfr0;
    uint64_t sre;

    __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
    if (((pfr0 >> 24) & 0xFu) == 0u) {
        return 0;
    }
    __asm__ volatile("mrs %0, icc_sre_el1" : "=r"(sre));
    if ((sre & 1u) == 0u) {
        return 0;
    }
    *(volatile uint8_t*)(uintptr_t)(NS_GICR_IPRIORITYR + NS_IRQ_PROBE_SGI) =
        0x40u;
    *ns_gicr(NS_GICR_ISENABLER0) = 1u << NS_IRQ_PROBE_SGI;
    __asm__ volatile("msr icc_pmr_el1, %0\n\t"
                     "msr icc_igrpen1_el1, %1\n\t"
                     "isb" : : "r"((uint64_t)0xFFu), "r"((uint64_t)1u));
    *ns_gicr(NS_GICR_ISPENDR0) = 1u << NS_IRQ_PROBE_SGI;
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
    return 1;
}

/* Non-zero if the interrupt was still pending; it is then withdrawn. */
static int ns_irq_release(void)
{
    uint32_t pending = (*ns_gicr(NS_GICR_ISPENDR0) >> NS_IRQ_PROBE_SGI) & 1u;

    *ns_gicr(NS_GICR_ICPENDR0) = 1u << NS_IRQ_PROBE_SGI;
    *ns_gicr(NS_GICR_ICENABLER0) = 1u << NS_IRQ_PROBE_SGI;
    __asm__ volatile("msr icc_igrpen1_el1, xzr\n\tisb" ::: "memory");
    return (int)pending;
}

/* 9.3.1.3: a data-carrying call made with a Normal-world interrupt pending
 * completes, and hands that interrupt back still pending. */
static void guest_psa_ns_irq(void)
{
    int ok;

    if (ns_irq_hold() == 0) {
        put_str("[NS] psa call with an ns irq pending skipped: no GICv3\r\n");
        return;
    }
#if defined(WT_NS_ENGINE_NATIVE)
    ok = guest_native_random();
#else
    ok = guest_hsm_echo();
#endif
    if ((ns_irq_release() != 0) && (ok != 0)) {
        put_str("[NS] psa call with an ns irq pending ok\r\n");
    }
    else {
        put_str("[NS] psa call with an ns irq pending BAD\r\n");
    }
}

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

#if defined(WT_NS_ENGINE_NATIVE)
    if (guest_native_random() != 0) {
        put_str("[NS] psa call ok\r\n");
        put_str("[NS] native random ok\r\n");
    }
#else
    if (guest_hsm_echo() != 0) {
        put_str("[NS] psa call ok\r\n");
        put_str("[NS] hsm echo ok\r\n");
    }
#endif
    else {
        put_str("[NS] psa call BAD\r\n");
    }
    guest_psa_ns_irq();
#if defined(WT_NS_HSM_ATTACK) && !defined(WT_NS_ENGINE_NATIVE)
    guest_hsm_attack();
#endif
#if defined(WT_NS_VAULT_SECURED)
    guest_vault_secured();
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
static int bytes_equal(const uint8_t* a, const uint8_t* b, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

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
        bytes_equal(its_out, its_in, sizeof(its_in))) {
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

#if defined(WT_NS_HEAP) && (WT_NS_HEAP == 1)
#include <stddef.h>

extern void* malloc(size_t n);
extern void* realloc(void* p, size_t n);
extern void free(void* p);

/* The guest heap (crypto/ns_crypto_port.c) must refuse a request that the
 * alignment rounding would wrap into a small one, through realloc too. */
static void heap_probe(void)
{
    void* p = malloc(64u);
    int ok = (p != NULL);

    ok = ok && (malloc(SIZE_MAX) == NULL);
    ok = ok && (malloc(SIZE_MAX - 8u) == NULL);
    ok = ok && (realloc(p, SIZE_MAX - 8u) == NULL);
    free(p);
    put_str(ok ? "[NS] heap bound ok\r\n" : "[NS] heap BAD\r\n");
}
#endif

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
#if defined(CRYPTO) || defined(INITIAL_ATTESTATION)
int32_t psa_crypto_init(void);
#endif

#if defined(WT_NS_ATTEST_NEG)
#include "psa/error.h"
#include <psa/initial_attestation.h>
#include "wolftrust/attestation.h"
#include "attestation_verify.h"

/* attestneg: the secure attestation service must reject invalid get_token
 * requests over the routed FF-A path, and a tampered or misattributed token
 * must fail the guest COSE_Sign1 verify. NS-side probe only; the attestation
 * service and EAT code are untouched. The guest measurement differs per image,
 * so the token's real lifecycle is discovered from a deliberately mismatched
 * verify and the measurement check runs in report-only mode. */
static void guest_attest_neg(void)
{
    uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 + 1u];
    uint8_t token[640];
    uint8_t publicKey[65];
    size_t tokenSize = 0u;
    size_t publicKeySize = 0u;
    size_t querySize = 0u;
    uint32_t lifecycle = 0u;
    psa_status_t status;
    int verify;
    unsigned int i;

    for (i = 0u; i < sizeof(challenge); i++) {
        challenge[i] = (uint8_t)(0xC0u + i);
    }

    status = psa_initial_attest_get_token_size(sizeof(challenge), &querySize);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        put_str("[NS] attestneg oversized challenge ACCEPTED st=0x");
        put_hex((uint32_t)status);
        put_str("\r\n");
        return;
    }
    put_str("[NS] attestneg oversized challenge rejected\r\n");

    status = psa_initial_attest_get_token(challenge,
        PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token, 0u, &tokenSize);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        put_str("[NS] attestneg zero token buffer ACCEPTED st=0x");
        put_hex((uint32_t)status);
        put_str("\r\n");
        return;
    }
    put_str("[NS] attestneg zero token buffer rejected\r\n");

    status = psa_initial_attest_get_token(challenge,
        PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token, sizeof(token), &tokenSize);
    if (status != PSA_SUCCESS) {
        put_str("[NS] attestneg baseline token FAIL st=0x");
        put_hex((uint32_t)status);
        put_str("\r\n");
        return;
    }
    status = wolftrust_attestation_get_iak_public_key(publicKey,
        sizeof(publicKey), &publicKeySize);
    if (status != PSA_SUCCESS) {
        put_str("[NS] attestneg public key FAIL st=0x");
        put_hex((uint32_t)status);
        put_str("\r\n");
        return;
    }

    verify = wt_attestation_verify_ex(token, tokenSize, publicKey,
        publicKeySize, challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, NULL,
        0xEEEEu, &lifecycle, NULL);
    if (verify == 0) {
        put_str("[NS] attestneg lifecycle mismatch ACCEPTED\r\n");
        return;
    }
    put_str("[NS] attestneg lifecycle mismatch rejected\r\n");

    verify = wt_attestation_verify_ex(token, tokenSize, publicKey,
        publicKeySize, challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, NULL,
        lifecycle, &lifecycle, NULL);
    if (verify != 0) {
        put_str("[NS] attestneg baseline verify FAIL\r\n");
        return;
    }
    put_str("[NS] attestneg baseline token verified\r\n");

    token[tokenSize - 1u] ^= 0x01u;
    verify = wt_attestation_verify_ex(token, tokenSize, publicKey,
        publicKeySize, challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, NULL,
        lifecycle, &lifecycle, NULL);
    token[tokenSize - 1u] ^= 0x01u;
    if (verify == 0) {
        put_str("[NS] attestneg tampered token ACCEPTED\r\n");
        return;
    }
    put_str("[NS] attestneg tampered token rejected\r\n");

    put_str("[NS] attestneg ok\r\n");
}
#endif

static void guest_conformance(void)
{
    __asm__ volatile("msr vbar_el1, %0\n\tisb" : : "r"(_ns_vectbl));
#if defined(CRYPTO) || defined(INITIAL_ATTESTATION)
    /* wolfPSA runs in this guest; nothing else brings it up on bare metal. */
    if (psa_crypto_init() != 0) {
        put_str("[NS] psa_crypto_init FAIL\r\n");
    }
#endif
#if defined(WT_NS_ATTEST_NEG)
    guest_attest_neg();
    return;
#endif
#if defined(WT_NS_HEAP) && (WT_NS_HEAP == 1)
    heap_probe();
#endif
    put_str("[NS] conformance val_entry start\r\n");
    (void)val_entry();
    put_str("[NS] conformance val_entry returned\r\n");
}
#endif

#if defined(WT_NS_GUEST_MEMNEG)
#include "wolftrust/arch/aarch64/ffa_mem.h"
#include "psa/client.h"
#include "psa/error.h"
#include "psa/internal_trusted_storage.h"
#include "psa_manifest/sid.h"

/* A page the guest offers to share (its content is irrelevant to descriptor
 * validation) and its RX/TX pair, all in the guest's NS window; every
 * descriptor is written into the TX buffer. */
static uint8_t g_memneg_page[4096] __attribute__((aligned(4096)));
static uint8_t g_memneg_desc[4096] __attribute__((aligned(4096)));
static uint8_t g_memneg_rx[4096] __attribute__((aligned(4096)));

/* FFA_MEM_SHARE naming the descriptor's buffer in x3/w4 (both zero for the TX
 * buffer, DEN0140 4.1.1.3): the SPMD forwards it, the SPMC reads and validates
 * the descriptor. Returns the FF-A status (x0); w2 and w3 carry the handle on
 * success, w2 the error code. */
static uint32_t mem_share_buf_smc(uint64_t addr, uint64_t pages, uint32_t len,
                                  uint64_t* w2, uint64_t* w3)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_MEM_SHARE32;
    register uint64_t r1 __asm__("x1") = len;
    register uint64_t r2 __asm__("x2") = len;
    register uint64_t r3 __asm__("x3") = addr;
    register uint64_t r4 __asm__("x4") = pages;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4)
                     :
                     : "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
                       "x14", "x15", "x16", "x17", "memory");
    *w2 = r2;
    *w3 = r3;
    return (uint32_t)r0;
}

static uint32_t mem_share_smc(uint32_t len, uint64_t* w2, uint64_t* w3)
{
    return mem_share_buf_smc(0u, 0u, len, w2, w3);
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

/* Build a well-formed single-constituent share, lend, or donate of page into
 * g_memneg_desc; returns its length or 0. A donate names no access, and a
 * lend to one borrower or a donate no memory type. */
static uint32_t memneg_build_op(const uint8_t* page, wt_ffa_mem_op_t op)
{
    wt_ffa_mem_constituent_t cons;
    wt_ffa_mem_build_t in;
    size_t len = 0u;
    int share = (op == WT_FFA_MEM_OP_SHARE) ? 1 : 0;

    cons.address = (uint64_t)(uintptr_t)page;
    cons.page_count = 1u;
    in.constituents = &cons;
    in.constituent_count = 1u;
    in.tag = 0u;
    in.handle = 0u;
    in.flags = 0u;
    in.op = op;
    in.sender = WT_FFA_ID_NS_PRIMARY;
    in.receiver = WT_FFA_ID_SP_FIRST;
    in.attributes = (share != 0)
                        ? (uint16_t)(WT_FFA_MEM_ATTR_TYPE_NORMAL |
                                     (0x3u << WT_FFA_MEM_ATTR_CACHE_SHIFT) |
                                     WT_FFA_MEM_ATTR_SHARE_INNER)
                        : 0u;
    in.permissions = (op != WT_FFA_MEM_OP_DONATE)
                         ? (uint8_t)WT_FFA_MEM_PERM_DATA_RW : 0u;
    in.access_desc_size = 0u;
    in.impdef = NULL;
    if (wt_ffa_mem_txn_build(g_memneg_desc, sizeof(g_memneg_desc), &in,
                             &len) != 0) {
        return 0u;
    }
    return (uint32_t)len;
}

static uint32_t memneg_build_page(const uint8_t* page)
{
    return memneg_build_op(page, WT_FFA_MEM_OP_SHARE);
}

static uint32_t memneg_build(void)
{
    return memneg_build_page(g_memneg_page);
}

/* FFA_MEM_DONATE is offered at the Normal world's instance (DEN0140 Table
 * 1.24): a donate of the guest's page is accepted, and reclaimed before any
 * partition retrieves it. */
static int memneg_donate(void)
{
    uint64_t x[5];
    uint64_t handle;
    uint32_t len = memneg_build_op(g_memneg_page, WT_FFA_MEM_OP_DONATE);
    int ok;

    x[0] = WT_FFA_FEATURES;
    x[1] = WT_FFA_MEM_DONATE32;
    x[2] = 0u;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    ok = (len != 0u) && ((uint32_t)x[0] == WT_FFA_SUCCESS32);
    x[0] = WT_FFA_MEM_DONATE32;
    x[1] = len;
    x[2] = len;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    handle = (x[2] & 0xFFFFFFFFu) | ((x[3] & 0xFFFFFFFFu) << 32);
    ok = ok && ((uint32_t)x[0] == WT_FFA_SUCCESS32);
    return ok && (mem_reclaim_smc(handle) == WT_FFA_SUCCESS32);
}

/* Send g_memneg_page with op through the TX buffer; *handle gets the handle.
 * Returns non-zero on FFA_SUCCESS. */
static int memneg_send(uint32_t fid, wt_ffa_mem_op_t op, uint64_t* handle)
{
    uint64_t x[5];
    uint32_t len = memneg_build_op(g_memneg_page, op);

    x[0] = fid;
    x[1] = len;
    x[2] = len;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    *handle = (x[2] & 0xFFFFFFFFu) | ((x[3] & 0xFFFFFFFFu) << 32);
    return (len != 0u) && ((uint32_t)x[0] == WT_FFA_SUCCESS32);
}

/* The ITS wire header psa_storage_client.c sends: GET_INFO (op 3) of uid. */
#define MEMNEG_ITS_GET_INFO 3
static const uint64_t g_memneg_uid = 0x5A5Bu;

/* One ITS GET_INFO whose request header is read from g_memneg_page, and one
 * ITS get whose data is written to it; each status in st[0] and st[1]. */
static void memneg_its_calls(psa_status_t* st)
{
    psa_handle_t handle;
    psa_invec in_vec;
    psa_outvec out_vec;
    uint32_t reply[4];
    size_t got = 0u;
    uint32_t i;

    for (i = 0u; i < 16u; i++) {
        g_memneg_page[i] = 0u;
    }
    for (i = 0u; i < 8u; i++) {
        g_memneg_page[i] = (uint8_t)(g_memneg_uid >> (8u * i));
    }
    st[0] = PSA_ERROR_GENERIC_ERROR;
    handle = psa_connect(SERVICE_ITS_SID, 1u);
    if (handle > 0) {
        in_vec.base = g_memneg_page;
        in_vec.len = 16u;
        out_vec.base = reply;
        out_vec.len = sizeof(reply);
        st[0] = psa_call(handle, MEMNEG_ITS_GET_INFO, &in_vec, 1u, &out_vec,
                         1u);
        psa_close(handle);
    }
    st[1] = psa_its_get(g_memneg_uid, 0u, 16u, &g_memneg_page[64], &got);
}

/* A PSA call reaches only memory the Normal world still has (DEN0140 Table
 * 1.3): a vector in a page it lent or donated is a PROGRAMMER_ERROR before
 * any byte is read or written; one in a page it shares, or has reclaimed, is
 * served (the object does not exist). */
static int memneg_psa_owned(void)
{
    static const uint32_t fids[3] = {
        WT_FFA_MEM_SHARE32, WT_FFA_MEM_LEND32, WT_FFA_MEM_DONATE32
    };
    static const wt_ffa_mem_op_t ops[3] = {
        WT_FFA_MEM_OP_SHARE, WT_FFA_MEM_OP_LEND, WT_FFA_MEM_OP_DONATE
    };
    psa_status_t st[2];
    psa_status_t want;
    uint64_t handle = 0u;
    uint32_t i;
    int ok = 1;

    for (i = 0u; i < 3u; i++) {
        ok = ok && memneg_send(fids[i], ops[i], &handle);
        memneg_its_calls(st);
        want = (i == 0u) ? PSA_ERROR_DOES_NOT_EXIST
                         : PSA_ERROR_PROGRAMMER_ERROR;
        ok = ok && (st[0] == want) && (st[1] == want);
        ok = ok && (mem_reclaim_smc(handle) == WT_FFA_SUCCESS32);
        memneg_its_calls(st);
        ok = ok && (st[0] == PSA_ERROR_DOES_NOT_EXIST) &&
             (st[1] == PSA_ERROR_DOES_NOT_EXIST);
    }
    return ok;
}

/* The guest's own mapped RX buffer is the SPMC's to write, never the guest's
 * to share: DENIED. */
static int memneg_rx_share_denied(void)
{
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;
    uint32_t len = memneg_build_page(g_memneg_rx);

    return (len != 0u) && (mem_share_smc(len, &w2, &w3) == WT_FFA_ERROR) &&
           ((int32_t)(uint32_t)w2 == WT_FFA_DENIED);
}

/* While a share holds g_memneg_page, an RX/TX pair naming it is refused as
 * INVALID_PARAMETERS, and the guest's own pair maps back. */
static int memneg_rxtx_over_shared(void)
{
    uint64_t x[5];
    int ok;

    x[0] = WT_FFA_RXTX_UNMAP;
    x[1] = 0u;
    x[2] = 0u;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    ok = ((uint32_t)x[0] == WT_FFA_SUCCESS32);
    x[0] = WT_FFA_RXTX_MAP64;
    x[1] = (uint64_t)(uintptr_t)g_memneg_desc;
    x[2] = (uint64_t)(uintptr_t)g_memneg_page;
    x[3] = 1u;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_ERROR) &&
         ((int32_t)(uint32_t)x[2] == WT_FFA_INVALID_PARAMETERS);
    x[0] = WT_FFA_RXTX_MAP64;
    x[1] = (uint64_t)(uintptr_t)g_memneg_desc;
    x[2] = (uint64_t)(uintptr_t)g_memneg_rx;
    x[3] = 1u;
    x[4] = 0u;
    smc5(x);
    return ok && ((uint32_t)x[0] == WT_FFA_SUCCESS32);
}

/* Send a well-formed share in two fragments through the same buffer (DEN0140
 * 4.1.2): the SPMC asks for the rest with FFA_MEM_FRAG_RX under the handle it
 * reserved, refuses a fragment for any other handle, and completes the share
 * under that same handle once the descriptor is whole. */
static int memfrag_share(void)
{
    static uint8_t full[256];
    uint64_t x[5];
    uint64_t handle;
    uint32_t len = memneg_build();
    uint32_t split = 40u;
    uint32_t i;
    int ok;

    if (len <= split) {
        return 0;
    }
    for (i = 0u; i < len; i++) {
        full[i] = g_memneg_desc[i];
    }
    x[0] = WT_FFA_MEM_SHARE32;
    x[1] = len;
    x[2] = split;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    handle = (x[1] & 0xFFFFFFFFu) | ((x[2] & 0xFFFFFFFFu) << 32);
    ok = ((uint32_t)x[0] == WT_FFA_MEM_FRAG_RX) && ((uint32_t)x[3] == split) &&
         ((uint32_t)x[4] == 0u) && (handle != 0u);

    /* A second first fragment mid-transfer is BUSY and drops nothing. */
    x[0] = WT_FFA_MEM_SHARE32;
    x[1] = len;
    x[2] = split;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_ERROR) &&
         ((int32_t)(uint32_t)x[2] == WT_FFA_BUSY);

    for (i = split; i < len; i++) {
        g_memneg_desc[i - split] = full[i];
    }
    x[0] = WT_FFA_MEM_FRAG_TX;
    x[1] = (handle + 1u) & 0xFFFFFFFFu;
    x[2] = (handle + 1u) >> 32;
    x[3] = len - split;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_ERROR) &&
         ((int32_t)(uint32_t)x[2] == WT_FFA_INVALID_PARAMETERS);

    x[0] = WT_FFA_MEM_FRAG_TX;
    x[1] = handle & 0xFFFFFFFFu;
    x[2] = handle >> 32;
    x[3] = len - split;
    x[4] = 0xFFFFu;                         /* w4[15:0] SBZ (Table 4.7) */
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_SUCCESS32) &&
         (((x[2] & 0xFFFFFFFFu) | ((x[3] & 0xFFFFFFFFu) << 32)) == handle);

    x[0] = WT_FFA_MEM_FRAG_RX;
    x[1] = handle & 0xFFFFFFFFu;
    x[2] = handle >> 32;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_ERROR) &&
         ((int32_t)(uint32_t)x[2] == WT_FFA_INVALID_PARAMETERS);

    return ok && (mem_reclaim_smc(handle) == WT_FFA_SUCCESS32);
}

/* Unmap and remap the RX/TX pair between two fragments of a share: the TX
 * buffer the first one used is gone (DEN0140 4.1.2 rule 6), so the next
 * FFA_MEM_FRAG_TX is ABORTED (rule 8), the handle names nothing after, and no
 * share was made. */
static int memfrag_unmap_aborts(void)
{
    static uint8_t full[256];
    uint64_t x[5];
    uint64_t handle;
    uint32_t len = memneg_build();
    uint32_t split = 40u;
    uint32_t i;
    int ok;

    if (len <= split) {
        return 0;
    }
    for (i = 0u; i < len; i++) {
        full[i] = g_memneg_desc[i];
    }
    x[0] = WT_FFA_MEM_SHARE32;
    x[1] = len;
    x[2] = split;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    handle = (x[1] & 0xFFFFFFFFu) | ((x[2] & 0xFFFFFFFFu) << 32);
    ok = ((uint32_t)x[0] == WT_FFA_MEM_FRAG_RX);

    x[0] = WT_FFA_RXTX_UNMAP;
    x[1] = 0u;
    x[2] = 0u;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_SUCCESS32);
    x[0] = WT_FFA_RXTX_MAP64;
    x[1] = (uint64_t)(uintptr_t)g_memneg_desc;
    x[2] = (uint64_t)(uintptr_t)g_memneg_rx;
    x[3] = 1u;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_SUCCESS32);

    for (i = split; i < len; i++) {
        g_memneg_desc[i - split] = full[i];
    }
    x[0] = WT_FFA_MEM_FRAG_TX;
    x[1] = handle & 0xFFFFFFFFu;
    x[2] = handle >> 32;
    x[3] = len - split;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_ERROR) &&
         ((int32_t)(uint32_t)x[2] == WT_FFA_ABORTED);
    x[0] = WT_FFA_MEM_FRAG_TX;
    x[1] = handle & 0xFFFFFFFFu;
    x[2] = handle >> 32;
    x[3] = len - split;
    x[4] = 0u;
    smc5(x);
    ok = ok && ((uint32_t)x[0] == WT_FFA_ERROR) &&
         ((int32_t)(uint32_t)x[2] == WT_FFA_INVALID_PARAMETERS);
    return ok && (mem_reclaim_smc(handle) == WT_FFA_ERROR);
}

/* SBZ fields set in every descriptor part (DEN0140 Tables 1.13-1.16, 1.18,
 * 1.20, 1.21) are ignored: the share is accepted and reclaimed. */
static int memneg_sbz_ignored(uint32_t len)
{
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;
    uint32_t i;

    (void)memneg_build();
    for (i = 36u; i < 48u; i++) {
        g_memneg_desc[i] = 0xA5u;           /* header reserved */
    }
    g_memneg_desc[3] |= 0x80u;              /* attributes bits[15:8] */
    g_memneg_desc[7] = 0x80u;               /* flags bit[31] */
    g_memneg_desc[50] |= 0xF0u;             /* permission bits[7:4] */
    g_memneg_desc[len - 1u] = 0xA5u;        /* constituent reserved */
    if (mem_share_smc(len, &w2, &w3) != WT_FFA_SUCCESS32) {
        return 0;
    }
    return mem_reclaim_smc((w2 & 0xFFFFFFFFu) | (w3 << 32)) ==
           WT_FFA_SUCCESS32;
}

static int memneg_refused(uint32_t len)
{
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;

    return mem_share_smc(len, &w2, &w3) == WT_FFA_ERROR;
}

/* A well-formed share the SPMC must refuse as INVALID_PARAMETERS for how it
 * names its buffer. */
static int memneg_bad_buffer(uint64_t addr, uint64_t pages, uint32_t len)
{
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;

    return (mem_share_buf_smc(addr, pages, len, &w2, &w3) == WT_FFA_ERROR) &&
           ((int32_t)(uint32_t)w2 == WT_FFA_INVALID_PARAMETERS);
}

/* Before its RX/TX pair is mapped a share is INVALID_PARAMETERS; after, offer
 * a well-formed FFA_MEM_SHARE (accepted, a handle returned), then a set of
 * malformed descriptors and dynamically allocated buffers (each refused with
 * no crash), reclaim the good handle, and confirm a second reclaim of the
 * now-dead handle is refused. */
/* FFA_RX_RELEASE(vm) at the NS physical instance: the reply's error code, or
 * 0 on FFA_SUCCESS. */
static int32_t memneg_rx_release_smc(uint32_t vm)
{
    uint64_t x[5];

    x[0] = WT_FFA_RX_RELEASE;
    x[1] = vm;
    x[2] = 0u;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    return ((uint32_t)x[0] == WT_FFA_SUCCESS32) ? 0 : (int32_t)(uint32_t)x[2];
}

static int memneg_rx_release_expect(uint32_t vm, int32_t want, const char* what)
{
    int32_t got = memneg_rx_release_smc(vm);

    if (got == want) {
        return 1;
    }
    put_str("[NS] memneg BAD rx release ");
    put_str(what);
    put_str(" x2=0x");
    put_hex((uint32_t)got);
    put_str("\r\n");
    return 0;
}

/* FFA_PARTITION_INFO_GET listing every partition into the RX buffer, which
 * the caller then owns (7.2.2.4.2). */
static int memneg_fill_rx(void)
{
    register uint64_t r0 __asm__("x0") = WT_FFA_PARTITION_INFO_GET;
    register uint64_t r1 __asm__("x1") = 0;
    register uint64_t r2 __asm__("x2") = 0;
    register uint64_t r3 __asm__("x3") = 0;
    register uint64_t r4 __asm__("x4") = 0;
    register uint64_t r5 __asm__("x5") = 0;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5)
                     :
                     : "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                       "x15", "x16", "x17", "memory");
    return ((uint32_t)r0 == WT_FFA_SUCCESS32) && (r2 != 0u);
}

/* Table 13.21: w1[15:0] names the VM whose RX buffer is released, and only
 * the primary endpoint has a pair; Table 13.22: a VM with no pair is
 * INVALID_PARAMETERS, a buffer the caller does not own is DENIED. */
static int memneg_rx_release_rows(void)
{
    int ok;

    ok = memneg_rx_release_expect(0u, WT_FFA_DENIED, "unowned");
    if (!memneg_fill_rx()) {
        put_str("[NS] memneg BAD rx release partinfo\r\n");
        return 0;
    }
    ok = ok && memneg_rx_release_expect(1u, WT_FFA_INVALID_PARAMETERS,
                                        "foreign vm");
    ok = ok && memneg_rx_release_expect(0u, 0, "owned");
    ok = ok && memneg_rx_release_expect(0u, WT_FFA_DENIED, "released");
    if (ok) {
        put_str("[NS] rx release ok\r\n");
    }
    return ok;
}

static void guest_memneg(void)
{
    uint64_t x[5];
    uint64_t handle;
    uint64_t w2 = 0u;
    uint64_t w3 = 0u;
    uint32_t len;
    int ok = 1;

    len = memneg_build();
    if ((len == 0u) || (g_memneg_desc[WT_FFA_MEM_TXN_OFF_ACC_SIZE] !=
                        WT_FFA_MEM_ACCESS_SIZE_V12)) {
        put_str("[NS] memneg BAD build\r\n");
        return;
    }
    ok = ok && memneg_bad_buffer(0u, 0u, len);  /* no RX/TX pair mapped */
    ok = ok && memneg_rx_release_expect(0u, WT_FFA_DENIED, "unmapped");
    x[0] = WT_FFA_RXTX_MAP64;
    x[1] = (uint64_t)(uintptr_t)g_memneg_desc;
    x[2] = (uint64_t)(uintptr_t)g_memneg_rx;
    x[3] = 1u;
    x[4] = 0u;
    smc5(x);
    if ((uint32_t)x[0] != WT_FFA_SUCCESS32) {
        put_str("[NS] memneg BAD rxtx map\r\n");
        return;
    }
    ok = ok && memneg_rx_release_rows();
    if (mem_share_smc(len, &w2, &w3) != WT_FFA_SUCCESS32) {
        put_str("[NS] memneg BAD share\r\n");
        return;
    }
    handle = (w2 & 0xFFFFFFFFu) | (w3 << 32);

    (void)memneg_build();
    ok = ok && memneg_bad_buffer((uint64_t)(uintptr_t)g_memneg_desc, 1u, len);
    ok = ok && memneg_bad_buffer((uint64_t)(uintptr_t)g_memneg_desc, 0u, len);
    ok = ok && memneg_bad_buffer(0u, 1u, len);
    ok = ok && memneg_rx_share_denied();
    ok = ok && memneg_rxtx_over_shared();

    (void)memneg_build();
    g_memneg_desc[len - WT_FFA_MEM_CONSTITUENT_SIZE] = 1u; /* misaligned base */
    ok = ok && memneg_refused(len);
    (void)memneg_build();
    g_memneg_desc[0] = 0x34u;               /* sender is not the caller */
    g_memneg_desc[1] = 0x12u;
    ok = ok && memneg_refused(len);
    (void)memneg_build();
    g_memneg_desc[51] = 1u;                 /* MBZ access descriptor flags */
    ok = ok && memneg_refused(len);
    (void)memneg_build();
    g_memneg_desc[len - WT_FFA_MEM_CONSTITUENT_SIZE -
                  WT_FFA_MEM_COMPOSITE_HDR_SIZE] = 9u; /* total != the sum */
    ok = ok && memneg_refused(len);

    ok = ok && (mem_reclaim_smc(handle) == WT_FFA_SUCCESS32);
    ok = ok && (mem_reclaim_smc(handle) == WT_FFA_ERROR);  /* dead handle */
    ok = ok && memneg_sbz_ignored(len);
    ok = ok && memneg_donate();
    if (memneg_psa_owned() == 0) {
        put_str("[NS] memneg psa BAD\r\n");
        ok = 0;
    }

    put_str(ok ? "[NS] memneg ok\r\n" : "[NS] memneg BAD\r\n");
    ok = memfrag_share();
    ok = ok && memfrag_unmap_aborts();
    put_str(ok ? "[NS] memfrag ok\r\n" : "[NS] memfrag BAD\r\n");
}
#endif

#if defined(WT_NS_GUEST_FUZZ)
/* Sweep function ids the SPMD does not implement at the NS physical instance -
 * unimplemented FF-A ids, unimplemented PSCI ids, and ids outside every served
 * range - and confirm each is refused cleanly (no crash, no world change): FF-A
 * ids answer FFA_ERROR/NOT_SUPPORTED, the rest answer the SMCCC unknown value.
 * Built from macros so no raw FF-A id literal lives outside ffa_abi.h. */
static const uint32_t g_fuzz_fids[] = {
    WT_FFA_YIELD, WT_FFA_NORMAL_WORLD_RESUME,
    WT_FFA_RX_ACQUIRE,
    WT_FFA_CONSOLE_LOG32, WT_FFA_CONSOLE_LOG64,
    WT_FFA_FID32_LAST, WT_FFA_FID64_LAST,
    WT_PSCI_CPU_FREEZE, WT_PSCI_SYSTEM_SUSPEND64, WT_PSCI_FID32_LAST,
    0x80000002u /* SMCCC_ARCH_SOC_ID: not offered */,
    0x82000000u, 0x8F000000u, 0xC3000000u,
    0xC3000102u /* the ACS test timer: absent outside ACS builds */
};

static int fuzz_refused(uint32_t fid, const uint64_t* o)
{
    if (wt_ffa_fid_in_range(fid)) {
        return ((uint32_t)o[0] == WT_FFA_ERROR) &&
               ((int32_t)(uint32_t)o[2] == WT_FFA_NOT_SUPPORTED);
    }
    /* SMCCC 5.2: -1 sign-extended, so an SMC64 id reads all of x0 set. */
    if ((fid & 0x40000000u) != 0u) {
        return o[0] == 0xFFFFFFFFFFFFFFFFull;
    }
    return (uint32_t)o[0] == 0xFFFFFFFFu;
}

/* An SMC32 call carries W1-W7 only (SMCCC 3.1): an RXTX_MAP32 whose buffer
 * addresses arrive with junk in the upper register halves still maps them. */
static uint8_t g_fuzz_tx[4096] __attribute__((aligned(4096)));
static uint8_t g_fuzz_rx[4096] __attribute__((aligned(4096)));

static void guest_smc32_upper(void)
{
    uint64_t x[5];
    uint32_t st;

    x[0] = WT_FFA_RXTX_MAP32;
    x[1] = 0xA5A5A5A500000000ull | (uint64_t)(uintptr_t)g_fuzz_tx;
    x[2] = 0x5A5A5A5A00000000ull | (uint64_t)(uintptr_t)g_fuzz_rx;
    x[3] = 0xFFFFFFFF00000001ull;
    x[4] = 0u;
    smc5(x);
    st = (uint32_t)x[0];
    x[0] = WT_FFA_RXTX_UNMAP;
    x[1] = 0u;
    x[2] = 0u;
    x[3] = 0u;
    x[4] = 0u;
    smc5(x);
    if ((st == WT_FFA_SUCCESS32) && ((uint32_t)x[0] == WT_FFA_SUCCESS32)) {
        put_str("[NS] smc32 upper halves ignored\r\n");
    }
    else {
        put_str("[NS] smc32 upper halves BAD map=0x");
        put_hex(st);
        put_str(" unmap=0x");
        put_hex((uint32_t)x[0]);
        put_str("\r\n");
    }
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
            put_hex((uint32_t)(o[0] >> 32));
            put_str("_");
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
    guest_smc32_upper();
}
#endif

#if defined(WT_NS_GUEST_RESET)
/* UARTIFLS: a machine reset restores it (0x12), a firmware warm re-entry
 * keeps whatever the previous boot wrote. */
#define UART_IFLS       0x34u
#define UART_IFLS_MARK  0x24u

/* Ask the SPMD to reset the system through PSCI, marking a device register
 * first so the next boot shows whether the machine was really reset. The
 * reset does not return to the Normal world. */
static void guest_reset(void)
{
    uint64_t o[4];

    put_str("[NS] uart ifls=0x");
    put_hex(*uart_reg(UART_IFLS) & 0x3Fu);
    put_str("\r\n");
    *uart_reg(UART_IFLS) = UART_IFLS_MARK;
    put_str("[NS] psci system_reset\r\n");
    ffa_smc(WT_PSCI_SYSTEM_RESET, 0u, o);
}
#endif

#if defined(WT_NS_GUEST_SECRAM)
extern char _ns_vectbl[];
extern void ns_exit(int code);
extern uint32_t ns_secram_load(uintptr_t pa);

/* The fence's refusal as the NS-EL1h guest takes it (vector slot 4): a data
 * abort without a change in Exception level (EC 0x25) that is a synchronous
 * external abort (DFSC 0x10) on a read, with FAR valid (FnV 0). */
#define WT_NS_VEC_SYNC_CUR_SPX 4u
#define WT_NS_ESR_EC_DABT_CUR  0x25u
#define WT_NS_ESR_DFSC_EXT     0x10u
#define WT_NS_ESR_WNR          (1u << 6)
#define WT_NS_ESR_FNV          (1u << 10)

/* The Normal world's own abort vector (ns.S) lands here when the Secure-RAM read
 * faults. Only the fence's abort on the probe load and address is a refusal;
 * any other exception, a hang (no handler), or a returned value (a leak) is a
 * failure. */
void ns_abort_report(uint64_t esr, uint64_t far, uint64_t elr, uint64_t slot)
{
    uint32_t ec = (uint32_t)(esr >> 26) & 0x3Fu;
    uint32_t dfsc = (uint32_t)esr & 0x3Fu;
    int ok = (slot == WT_NS_VEC_SYNC_CUR_SPX) &&
             (ec == WT_NS_ESR_EC_DABT_CUR) && (dfsc == WT_NS_ESR_DFSC_EXT) &&
             (((uint32_t)esr & (WT_NS_ESR_WNR | WT_NS_ESR_FNV)) == 0u) &&
             (far == (uint64_t)WT_NS_SECURE_PROBE_PA) &&
             (elr == (uint64_t)(uintptr_t)ns_secram_load);

    put_str((ok != 0) ? "[NS] secram refused ec=0x" : "[NS] secram BAD ec=0x");
    put_hex(ec);
    put_str(" dfsc=0x");
    put_hex(dfsc);
    put_str(" far=0x");
    put_hex((uint32_t)far);
    put_str(" esr=0x");
    put_hex((uint32_t)esr);
    put_str(" slot=");
    put_dec((uint32_t)slot);
    put_str(" elr=0x");
    put_hex((uint32_t)elr);
    put_str("\r\n");
    ns_exit((ok != 0) ? 0 : 1);
}

/* Attempt to read Secure RAM from the Normal world: the secure physical region
 * must be unreachable from NS. The read is expected to fault into the guest's
 * own abort vector (proving the world fence); if it ever returns data the fence
 * is broken. */
static void guest_secram(void)
{
    uint32_t v;

    __asm__ volatile("msr vbar_el1, %0\n\tisb" : : "r"(_ns_vectbl));
    put_str("[NS] secram read 0x");
    put_hex((uint32_t)WT_NS_SECURE_PROBE_PA);
    put_str("\r\n");
    v = ns_secram_load((uintptr_t)WT_NS_SECURE_PROBE_PA);
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
static uint64_t psci_call(uint32_t fid, uint64_t a1, uint64_t a2)
{
    register uint64_t r0 __asm__("x0") = fid;
    register uint64_t r1 __asm__("x1") = a1;
    register uint64_t r2 __asm__("x2") = a2;
    register uint64_t r3 __asm__("x3") = 0;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                       "x13", "x14", "x15", "x16", "x17", "memory");
    return r0;
}

static int psci_expect(const char* what, uint64_t got, int32_t want)
{
    if ((int32_t)(uint32_t)got == want) {
        return 1;
    }
    put_str("[NS] psci BAD ");
    put_str(what);
    put_str(" x0=0x");
    put_hex((uint32_t)got);
    put_str("\r\n");
    return 0;
}

/* An SMC64 call's int32 result must fill all of X0, sign-extended. */
static int psci_expect64(const char* what, uint64_t got, int32_t want)
{
    if (got == (uint64_t)(int64_t)want) {
        return 1;
    }
    put_str("[NS] psci BAD ");
    put_str(what);
    put_str(" x0=0x");
    put_hex((uint32_t)(got >> 32));
    put_str("_");
    put_hex((uint32_t)got);
    put_str("\r\n");
    return 0;
}

/* SMCCC 1.1 and later: a call that returns only x0, here AFFINITY_INFO64 on
 * the boot core, hands x4-x7 back unchanged. */
static int psci_preserves_x4_x7(uint64_t self)
{
    register uint64_t r0 __asm__("x0") = WT_PSCI_AFFINITY_INFO64;
    register uint64_t r1 __asm__("x1") = self;
    register uint64_t r2 __asm__("x2") = 0;
    register uint64_t r3 __asm__("x3") = 0;
    register uint64_t r4 __asm__("x4") = 0x4444444444444444ull;
    register uint64_t r5 __asm__("x5") = 0x5555555555555555ull;
    register uint64_t r6 __asm__("x6") = 0x6666666666666666ull;
    register uint64_t r7 __asm__("x7") = 0x7777777777777777ull;

    __asm__ volatile("smc #0"
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4),
                       "+r"(r5), "+r"(r6), "+r"(r7)
                     :
                     : "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                       "x15", "x16", "x17", "memory");
    if (((int32_t)(uint32_t)r0 == WT_PSCI_AFFINITY_ON) &&
        (r4 == 0x4444444444444444ull) && (r5 == 0x5555555555555555ull) &&
        (r6 == 0x6666666666666666ull) && (r7 == 0x7777777777777777ull)) {
        return 1;
    }
    put_str("[NS] psci BAD x4-x7 not preserved\r\n");
    return 0;
}

/* SMCCC_VERSION, discovered through PSCI_FEATURES (DEN0028 Appendix B), and
 * SMCCC_ARCH_FEATURES, which must know itself and SMCCC_VERSION (7.3.6). */
static int smccc_walk(uint64_t self)
{
    int ok = 1;

    ok &= psci_expect("features smccc_version",
                      psci_call(WT_PSCI_FEATURES, WT_SMCCC_VERSION, 0u),
                      WT_PSCI_SUCCESS);
    ok &= psci_expect("smccc_version", psci_call(WT_SMCCC_VERSION, 0u, 0u),
                      (int32_t)WT_SMCCC_VERSION_1_2);
    ok &= psci_expect("arch_features smccc_version",
                      psci_call(WT_SMCCC_ARCH_FEATURES, WT_SMCCC_VERSION, 0u),
                      0);
    ok &= psci_expect("arch_features arch_features",
                      psci_call(WT_SMCCC_ARCH_FEATURES, WT_SMCCC_ARCH_FEATURES,
                                0u), 0);
    ok &= psci_expect("arch_features workaround_1",
                      psci_call(WT_SMCCC_ARCH_FEATURES, 0x80008000u, 0u),
                      WT_SMCCC_NOT_SUPPORTED);
    ok &= psci_preserves_x4_x7(self);
    if (ok != 0) {
        put_str("[NS] smccc version 1.2\r\n");
    }
    return ok;
}

/* With a GIC system-register interface, NS-EL1 reaches ICC_SRE_EL1 and finds
 * SRE set: an implemented EL2 neither traps it nor forces the legacy one. */
static void gic_sre_probe(void)
{
    uint64_t pfr0;
    uint64_t sre;

    __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
    if (((pfr0 >> 24) & 0xFu) == 0u) {
        put_str("[NS] gic sysreg interface absent\r\n");
        return;
    }
    __asm__ volatile("mrs %0, icc_sre_el1" : "=r"(sre));
    if ((sre & 1u) != 0u) {
        put_str("[NS] icc_sre_el1 sre=1\r\n");
    }
    else {
        put_str("[NS] icc_sre_el1 BAD 0x");
        put_hex((uint32_t)sre);
        put_str("\r\n");
    }
}

/* Run at NS-EL2, clear HCR_EL2.RW and drop to an AArch32 EL1 stub that issues
 * one SMC with R0-R5 from regs[0..5] and returns through HVC (the vector at
 * 0x600, lower EL in AArch32); R0-R3 come back in regs[0..3]. */
void ns_a32_smc(uint64_t* regs);
__asm__(
"    .pushsection .text.ns_a32, \"ax\"\n"
"    .balign 0x800\n"
"ns_el2_vectors:\n"
"    .rept 12\n"
"    .balign 0x80\n"
"    b .\n"
"    .endr\n"
"    .balign 0x80\n"
"    b ns_a32_back\n"
"    .rept 3\n"
"    .balign 0x80\n"
"    b .\n"
"    .endr\n"
"    .globl ns_a32_smc\n"
"ns_a32_smc:\n"
"    stp x29, x30, [sp, #-112]!\n"
"    stp x19, x20, [sp, #16]\n"
"    stp x21, x22, [sp, #32]\n"
"    stp x23, x24, [sp, #48]\n"
"    stp x25, x26, [sp, #64]\n"
"    stp x27, x28, [sp, #80]\n"
"    mrs x9, hcr_el2\n"
"    stp x0, x9, [sp, #96]\n"
"    adr x10, ns_el2_vectors\n"
"    msr vbar_el2, x10\n"
"    bic x9, x9, #0x80000000\n"
"    msr hcr_el2, x9\n"
"    adr x10, ns_a32_stub\n"
"    msr elr_el2, x10\n"
"    mov x10, #0x1d3\n"
"    msr spsr_el2, x10\n"
"    ldp x4, x5, [x0, #32]\n"
"    ldp x2, x3, [x0, #16]\n"
"    ldp x0, x1, [x0]\n"
"    isb\n"
"    eret\n"
"ns_a32_back:\n"
"    ldp x9, x10, [sp, #96]\n"
"    msr hcr_el2, x10\n"
"    isb\n"
"    mov w0, w0\n"
"    mov w1, w1\n"
"    mov w2, w2\n"
"    mov w3, w3\n"
"    stp x0, x1, [x9]\n"
"    stp x2, x3, [x9, #16]\n"
"    ldp x19, x20, [sp, #16]\n"
"    ldp x21, x22, [sp, #32]\n"
"    ldp x23, x24, [sp, #48]\n"
"    ldp x25, x26, [sp, #64]\n"
"    ldp x27, x28, [sp, #80]\n"
"    ldp x29, x30, [sp], #112\n"
"    ret\n"
"    .balign 4\n"
"ns_a32_stub:\n"
"    .word 0xe1600070\n"      /* A32 smc #0 */
"    .word 0xe1400070\n"      /* A32 hvc #0 */
"    .popsection\n");

/* SMCCC 4 from an AArch32 caller: an SMC32 PSCI call and a forwarded FF-A
 * call are served and return to AArch32, and an SMC64 id is unknown (5.2). */
static int a32_walk(void)
{
    uint64_t r[6];
    uint64_t pfr0;
    unsigned int i;
    int ok = 1;

    __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
    if (((pfr0 >> 4) & 0xFu) != 2u) {
        put_str("[NS] a32 el1 absent\r\n");
        return 1;
    }
    for (i = 0u; i < 6u; i++) {
        r[i] = 0u;
    }
    r[0] = WT_PSCI_VERSION;
    ns_a32_smc(r);
    ok &= psci_expect("a32 psci_version", r[0], (int32_t)WT_PSCI_VERSION_1_1);
    r[0] = WT_PSCI_AFFINITY_INFO64;
    ns_a32_smc(r);
    ok &= psci_expect("a32 smc64 id", r[0], WT_PSCI_NOT_SUPPORTED);
    r[0] = WT_FFA_PARTITION_INFO_GET;
    r[1] = 0u;
    r[2] = 0u;
    r[3] = 0u;
    r[4] = 0u;
    r[5] = WT_FFA_PARTINFO_FLAG_COUNT;
    ns_a32_smc(r);
    if (((uint32_t)r[0] != WT_FFA_SUCCESS32) || (r[2] == 0u)) {
        put_str("[NS] psci BAD a32 partinfo x0=0x");
        put_hex((uint32_t)r[0]);
        put_str("\r\n");
        ok = 0;
    }
    if (ok != 0) {
        put_str("[NS] a32 smc ok partinfo n=");
        put_dec((uint32_t)r[2]);
        put_str("\r\n");
    }
    return ok;
}

/* A target_cpu naming the boot core but with a Must-be-zero bit set (DEN0022
 * 5.1.4: bits[31:24] and, for SMC64, bits[63:40]) names no core. */
static int psci_mbz_target(uint64_t self)
{
    static const uint32_t fids[] = {
        WT_PSCI_CPU_ON64, WT_PSCI_AFFINITY_INFO64, WT_PSCI_MIGRATE64,
        WT_PSCI_CPU_ON32, WT_PSCI_AFFINITY_INFO32, WT_PSCI_MIGRATE32
    };
    static const unsigned int bits[] = { 24u, 31u, 40u, 63u };
    uint64_t got;
    unsigned int f;
    unsigned int b;
    int smc64;
    int ok = 1;

    for (f = 0u; f < sizeof(fids) / sizeof(fids[0]); f++) {
        smc64 = ((fids[f] & 0x40000000u) != 0u) ? 1 : 0;
        for (b = 0u; b < sizeof(bits) / sizeof(bits[0]); b++) {
            if ((smc64 == 0) && (bits[b] >= 32u)) {
                continue;
            }
            got = psci_call(fids[f], self | (1ull << bits[b]), 0u);
            if (((smc64 != 0) &&
                 (got != (uint64_t)(int64_t)WT_PSCI_INVALID_PARAMS)) ||
                ((smc64 == 0) &&
                 ((int32_t)(uint32_t)got != WT_PSCI_INVALID_PARAMS))) {
                put_str("[NS] psci BAD mbz target fid=0x");
                put_hex(fids[f]);
                put_str(" bit=");
                put_dec(bits[b]);
                put_str(" x0=0x");
                put_hex((uint32_t)got);
                put_str("\r\n");
                ok = 0;
            }
        }
    }
    return ok;
}

/* The mandatory PSCI 1.1 set as a boot-core-only Normal world sees it. */
static void psci_walk(void)
{
    uint64_t o[4];
    uint64_t self;
    uint64_t parked;
    uint64_t el;
    int ok = 1;

    ffa_smc(WT_PSCI_VERSION, 0u, o);
    put_str("[NS] psci version ");
    put_dec((uint32_t)((o[0] >> 16) & 0xFFFFu));
    put_char('.');
    put_dec((uint32_t)(o[0] & 0xFFFFu));
    put_str("\r\n");

    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(self));
    self &= 0x000000FF00FFFFFFull;
    parked = self ^ 1u;
    ok &= psci_expect64("cpu_on self", psci_call(WT_PSCI_CPU_ON64, self, 0u),
                        WT_PSCI_ALREADY_ON);
    ok &= psci_expect64("cpu_on bogus",
                        psci_call(WT_PSCI_CPU_ON64, self | 0x00FF0000u, 0u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect64("affinity self",
                        psci_call(WT_PSCI_AFFINITY_INFO64, self, 0u),
                        WT_PSCI_AFFINITY_ON);
    /* The neighbour core, parked at EL3 or absent, is outside the Normal
     * world's machine view: not an MPIDR it can query or turn on. */
    ok &= psci_expect64("affinity neighbour",
                        psci_call(WT_PSCI_AFFINITY_INFO64, parked, 0u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect64("cpu_on neighbour",
                        psci_call(WT_PSCI_CPU_ON64, parked, 0u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect64("affinity level1",
                        psci_call(WT_PSCI_AFFINITY_INFO64, self, 1u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect("cpu_on32 self",
                      psci_call(WT_PSCI_CPU_ON32, self & 0xFFFFFFFFu, 0u),
                      WT_PSCI_ALREADY_ON);
    ok &= psci_expect("affinity32 neighbour",
                      psci_call(WT_PSCI_AFFINITY_INFO32,
                                parked & 0xFFFFFFFFu, 0u),
                      WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect("cpu_off", psci_call(WT_PSCI_CPU_OFF, 0u, 0u),
                      WT_PSCI_DENIED);
    ok &= psci_expect64("suspend powerdown",
                        psci_call(WT_PSCI_CPU_SUSPEND64, 0x00010000u, 0u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect64("migrate", psci_call(WT_PSCI_MIGRATE64, self, 0u),
                        WT_PSCI_DENIED);
    ok &= psci_expect64("migrate neighbour",
                        psci_call(WT_PSCI_MIGRATE64, parked, 0u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_expect64("migrate bogus",
                        psci_call(WT_PSCI_MIGRATE64, self | 0x00FF0000u, 0u),
                        WT_PSCI_INVALID_PARAMS);
    ok &= psci_mbz_target(self);
    ok &= psci_expect("migrate_info_type",
                      psci_call(WT_PSCI_MIGRATE_INFO_TYPE, 0u, 0u),
                      (int32_t)WT_PSCI_TOS_UP_NOT_MIGRATABLE);
    if (psci_call(WT_PSCI_MIGRATE_INFO_UP_CPU64, 0u, 0u) != self) {
        put_str("[NS] psci BAD migrate_info_up_cpu\r\n");
        ok = 0;
    }
    ok &= psci_expect("features cpu_suspend",
                      psci_call(WT_PSCI_FEATURES, WT_PSCI_CPU_SUSPEND64, 0u),
                      WT_PSCI_SUCCESS);
    ok &= psci_expect("features cpu_freeze",
                      psci_call(WT_PSCI_FEATURES, WT_PSCI_CPU_FREEZE, 0u),
                      WT_PSCI_NOT_SUPPORTED);
    ok &= smccc_walk(self);
    if (ok != 0) {
        put_str("[NS] psci mandatory set ok\r\n");
    }
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    if (((el >> 2) & 0x3u) == 2u) {
        (void)a32_walk();
    }
    ffa_smc(WT_PSCI_SYSTEM_OFF, 0u, o);
}
#endif

#if defined(WT_NS_PREEMPT)
/* Spin ~200ms of guest time so the Secure tick fires while the Normal world
 * runs; the preemption is handled at EL3 and the loop resumes to completion. */
static void ns_spin(void)
{
    uint64_t o[4];
    uint64_t freq;
    uint64_t start;
    uint64_t now;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(start));
    put_str("[NS] spinning\r\n");
    /* Core standby: the monitor's WFI wakes on the armed Secure tick. */
    ffa_smc(WT_PSCI_CPU_SUSPEND64, WT_PSCI_STATE_CORE_STANDBY, o);
    if ((uint32_t)o[0] == (uint32_t)WT_PSCI_SUCCESS) {
        put_str("[NS] psci standby woke\r\n");
    }
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
    gic_sre_probe();
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
    notif_psa_denied();

#if defined(WT_NS_GUEST_ECHO)
    guest_direct();
    guest_req2_refused();
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
