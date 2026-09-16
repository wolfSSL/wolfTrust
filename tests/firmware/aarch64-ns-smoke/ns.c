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
#include "wolftrust/arch/aarch64/psa_ffa.h"
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
/* Reach the Secure services over the operating-system-neutral PSA client
 * (src/client/psa_ffa_transport.c): read the framework and service versions,
 * connect to the register-only test service, prove an unknown service is
 * refused, and close the handle. This is the Normal-world guest a real OS runs
 * (B3.5); data-carrying psa_call arrives with memory sharing (B4). */
static void guest_psa(void)
{
    static const uint8_t call_in[4] = { 0x11u, 0x22u, 0x33u, 0x44u };
    uint8_t call_out[4] = { 0u, 0u, 0u, 0u };
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t status;
    uint32_t fw;
    uint32_t ver;
    psa_handle_t handle;
    psa_handle_t refused;

    fw = psa_framework_version();
    put_str("[NS] psa framework 0x");
    put_hex(fw);
    put_str("\r\n");

    ver = psa_version(WT_PSA_FFA_SID_TEST);
    put_str("[NS] psa version v=");
    put_dec(ver);
    put_str("\r\n");

    handle = psa_connect(WT_PSA_FFA_SID_TEST, WT_PSA_FFA_SID_TEST_VERSION);
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
        in_vec.base = call_in;
        in_vec.len = sizeof(call_in);
        out_vec.base = call_out;
        out_vec.len = sizeof(call_out);
        status = psa_call(handle, 0, &in_vec, 1u, &out_vec, 1u);
        if ((status == PSA_SUCCESS) && (out_vec.len == sizeof(call_in)) &&
            (call_out[0] == (uint8_t)~call_in[0]) &&
            (call_out[3] == (uint8_t)~call_in[3])) {
            put_str("[NS] psa call ok\r\n");
        }
        else {
            put_str("[NS] psa call BAD\r\n");
        }
    }

    if (PSA_HANDLE_IS_VALID(handle)) {
        psa_close(handle);
        put_str("[NS] psa close ok\r\n");
    }

    put_str("[NS] guest");
    put_dec((uint32_t)WT_NS_GUEST_ID);
    put_str(" ok\r\n");
}
#endif

#if defined(WT_NS_GUEST_FUZZ)
/* Sweep function ids the SPMD does not implement at the NS physical instance -
 * unimplemented FF-A ids, unimplemented PSCI ids, and ids outside every served
 * range - and confirm each is refused cleanly (no crash, no world change): FF-A
 * ids answer FFA_ERROR/NOT_SUPPORTED, the rest answer the SMCCC unknown value.
 * Built from macros so no raw FF-A id literal lives outside ffa_abi.h. */
static const uint32_t g_fuzz_fids[] = {
    WT_FFA_RX_RELEASE, WT_FFA_RXTX_MAP32, WT_FFA_RXTX_MAP64, WT_FFA_RXTX_UNMAP,
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
}
