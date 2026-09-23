/* guest.c — single-source NS guest for the stm32h563-vnet end-to-end test.
 *
 * One binary per guest, selected at link time by the per-guest flash/ram
 * base passed to the linker. The guest derives its identity (id, MAC, IP)
 * from _estack — which the linker sets to the top of this guest's RAM
 * window — exactly like tests/firmware/stm32h563/nonsecure/guest.c does.
 *
 * guest0 (10.0.0.1, 02:00:00:00:00:0A) sends an ICMP echo to guest1 every
 * ~500 ms and prints "ping reply ..." when the answer comes back.
 * guest1 (10.0.0.2, 02:00:00:00:00:14) just drives wolfIP_poll forever —
 * wolfIP's built-in ICMP handler auto-replies to echo requests.
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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "memory_map.h"
#include "wolftrust/vnet/vnet_abi.h"
#include "wolftrust/vnet_psa_transport.h"
#include "wolfip.h"

#ifndef WT_GUEST_CORE_CLOCK_HZ
#define WT_GUEST_CORE_CLOCK_HZ 240000000u
#endif
#ifndef WT_GUEST_UART_CLOCK_HZ
#define WT_GUEST_UART_CLOCK_HZ 120000000u
#endif

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

/* USART registers — only the small subset we need. */
#define USART2_BASE           0x40004400u
#define USART3_BASE           0x40004800u
#define USART_CR1(b)          (*(volatile uint32_t *)((b) + 0x00u))
#define USART_CR2(b)          (*(volatile uint32_t *)((b) + 0x04u))
#define USART_CR3(b)          (*(volatile uint32_t *)((b) + 0x08u))
#define USART_BRR(b)          (*(volatile uint32_t *)((b) + 0x0Cu))
#define USART_ISR(b)          (*(volatile uint32_t *)((b) + 0x1Cu))
#define USART_TDR(b)          (*(volatile uint32_t *)((b) + 0x28u))
#define USART_CR1_UE          (1u << 0)
#define USART_CR1_RE          (1u << 2)
#define USART_CR1_TE          (1u << 3)
#define USART_ISR_TXE         (1u << 7)

#define SYST_CSR     (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR     (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR     (*(volatile uint32_t *)0xE000E018u)
#define SYST_CSR_CLKSOURCE   (1u << 2)
#define SYST_CSR_TICKINT     (1u << 1)
#define SYST_CSR_ENABLE      (1u << 0)

static void default_handler(void) { for (;;) {} }

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void) __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SVC_Handler(void) __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void) __attribute__((weak, alias("default_handler")));
void SysTick_Handler(void);

__attribute__((section(".vectors")))
const uint32_t g_vectors[16] = {
    [0]  = (uint32_t)&_estack,
    [1]  = (uint32_t)&Reset_Handler,
    [2]  = (uint32_t)&NMI_Handler,
    [3]  = (uint32_t)&HardFault_Handler,
    [4]  = (uint32_t)&MemManage_Handler,
    [5]  = (uint32_t)&BusFault_Handler,
    [6]  = (uint32_t)&UsageFault_Handler,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler
};

static volatile uint32_t g_tick_ms;

void SysTick_Handler(void) { g_tick_ms++; }

static uint32_t wt_guest_id(void)
{
    return ((uintptr_t)&_estack == (WT_GUEST1_RAM_BASE + WT_GUEST_RAM_SIZE))
           ? 1u : 0u;
}

static uintptr_t wt_uart_base(void)
{
    /* The default WT_SHARED_UART=3 partition gives BOTH guests USART3 in
     * their MPU; treat the UART as shared and let the runner script
     * disambiguate by the guest tag in each line. */
    (void)wt_guest_id();
    return USART3_BASE;
}

static void wt_uart_init(void)
{
    uintptr_t b = wt_uart_base();
    uint32_t brr = WT_GUEST_UART_CLOCK_HZ / 115200u;
    USART_CR1(b) = 0u;
    USART_CR2(b) = 0u;
    USART_CR3(b) = 0u;
    USART_BRR(b) = brr;
    USART_CR1(b) = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

static void wt_uart_putc(char c)
{
    uintptr_t b = wt_uart_base();
    while ((USART_ISR(b) & USART_ISR_TXE) == 0u) { }
    USART_TDR(b) = (uint32_t)(uint8_t)c;
}

static void wt_uart_puts(const char *s)
{
    while (*s) wt_uart_putc(*s++);
}

static void wt_uart_put_u32(uint32_t v)
{
    char buf[10];
    uint32_t i = 0;
    if (v == 0) { wt_uart_putc('0'); return; }
    while (v) { buf[i++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (i) wt_uart_putc(buf[--i]);
}

static void wt_uart_put_hex2(uint8_t b)
{
    static const char hex[] = "0123456789abcdef";
    wt_uart_putc(hex[(b >> 4) & 0xFu]);
    wt_uart_putc(hex[b & 0xFu]);
}

static void wt_uart_put_ip(uint32_t ip)
{
    wt_uart_put_u32((ip >> 24) & 0xFFu); wt_uart_putc('.');
    wt_uart_put_u32((ip >> 16) & 0xFFu); wt_uart_putc('.');
    wt_uart_put_u32((ip >>  8) & 0xFFu); wt_uart_putc('.');
    wt_uart_put_u32(ip & 0xFFu);
}

static void wt_systick_init(void)
{
    SYST_CSR = 0u;
    SYST_RVR = (WT_GUEST_CORE_CLOCK_HZ / 1000u) - 1u;
    SYST_CVR = 0u;
    SYST_CSR = SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE;
}

static uint32_t now_ms(void) { return g_tick_ms; }

static void wt_copy_data(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
}

static void wt_zero_bss(void)
{
    uint32_t *dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0u;
}

/* ---------- vnet driver shim plugged into wolfIP_ll_dev -----------------
 * All switch traffic rides psa_call to SERVICE_VNET; the raw
 * WolfTrust_VNet_* veneers are retired from this guest. */

static wt_vnet_psa_ctx_t g_vnet;
static int g_tx_err_logged;
static int g_rx_err_logged;
/* SWD-readable first-failure latches: the shared UART interleaves both
 * guests' digits, so printed rc values are unreliable. */
static volatile uint32_t g_first_rx_status;
static volatile uint32_t g_first_tx_status;
static volatile uint32_t g_rx_ok_count;

static int vnet_ll_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    if (len < 14u || len > 1536u) return -1;
    int rc = wt_vnet_psa_tx(&g_vnet, buf, (uint16_t)len);
    if (rc != 0 && !g_tx_err_logged) {
        g_tx_err_logged = 1;
        g_first_tx_status = (uint32_t)rc;
        wt_uart_puts("vnet tx err rc=-");
        wt_uart_put_u32((uint32_t)(-rc));
        wt_uart_puts("\r\n");
    }
    return (rc == 0) ? (int)len : -1;
}

static int vnet_ll_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    (void)ll;
    /* Static meta: silicon CMSE range checks are the real thing, so keep
     * the outvec targets in plain guest .bss while the RX path is brought
     * up (the emulator accepts the stack address either way). */
    static vnet_rx_meta_t meta;
    int n = wt_vnet_psa_rx_fetch(&g_vnet, &meta, buf,
                                 (uint16_t)((len > 0xFFFFu) ? 0xFFFFu : len));
    if (n >= 0 || n == WT_VNET_E_EMPTY) {
        g_rx_ok_count++;
    }
    if (n < 0 && n != WT_VNET_E_EMPTY && !g_rx_err_logged) {
        g_rx_err_logged = 1;
        g_first_rx_status = (uint32_t)n;
        wt_uart_puts("vnet rx err rc=-");
        wt_uart_put_u32((uint32_t)(-n));
        wt_uart_puts("\r\n");
    }
    return (n < 0) ? 0 : n;
}

/* ---------- guest identity tables -------------------------------------- */

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;       /* host byte order */
    uint32_t mask;
    uint32_t gw;
    uint32_t peer_ip;
    const char *banner;
} guest_identity_t;

static const guest_identity_t IDENT[2] = {
    [0] = {
        .mac    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A},
        .ip     = (10u<<24) | (0u<<16) | (0u<<8) | 1u,
        .mask   = 0xFFFFFF00u,
        .gw     = 0u,
        .peer_ip= (10u<<24) | (0u<<16) | (0u<<8) | 2u,
        .banner = "vnet-guest0: alive\r\n",
    },
    [1] = {
        .mac    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x14},
        .ip     = (10u<<24) | (0u<<16) | (0u<<8) | 2u,
        .mask   = 0xFFFFFF00u,
        .gw     = 0u,
        .peer_ip= (10u<<24) | (0u<<16) | (0u<<8) | 1u,
        .banner = "vnet-guest1: alive\r\n",
    },
};

/* ICMP echo request body. wolfIP fills in csum and (for echo requests)
 * the id field at sendto time; we set type/code and seq. 8-byte
 * payload keeps the frame small enough to fit through ARP-resolution
 * latency without filling the ring. */
static uint8_t g_icmp_buf[16];

static void icmp_build_request(uint16_t seq)
{
    memset(g_icmp_buf, 0, sizeof(g_icmp_buf));
    g_icmp_buf[0] = 8;      /* ICMP_ECHO_REQUEST */
    g_icmp_buf[1] = 0;      /* code */
    /* csum at [2..3]: zero, wolfIP recomputes */
    /* id at [4..5]: zero, wolfIP overwrites on send */
    g_icmp_buf[6] = (uint8_t)(seq >> 8);
    g_icmp_buf[7] = (uint8_t)(seq & 0xFFu);
    /* payload bytes [8..15] left as a recognisable signature */
    g_icmp_buf[8]  = 'w';
    g_icmp_buf[9]  = 'o';
    g_icmp_buf[10] = 'l';
    g_icmp_buf[11] = 'f';
    g_icmp_buf[12] = 't';
    g_icmp_buf[13] = 'r';
    g_icmp_buf[14] = 'u';
    g_icmp_buf[15] = 's';
}

/* ---------- main loop -------------------------------------------------- */

static int run_guest(uint32_t guest_id)
{
    const guest_identity_t *id = &IDENT[guest_id];
    vnet_info_t info;
    struct wolfIP *ip = NULL;
    struct wolfIP_ll_dev *ll;
    struct ipconf *cfg;
    int rc;
    int sock = -1;
    int last_seq = 0;
    int next_seq = 1;
    int tries;
    volatile uint32_t spin;
    uint32_t next_ping_ms = 200;  /* first ping after a short ARP window */
    uint8_t rx_buf[64];
    uint8_t mac_ram[6];

    wt_uart_puts(id->banner);

    /* SERVICE_VNET may be mid-quarantine (a faulted partition restarting
     * under its manifest policy); a transient failure heals, so retry. */
    rc = -1;
    for (tries = 0; tries < 50 && rc != 0; tries++) {
        rc = wt_vnet_psa_open(&g_vnet, WT_VNET_SERVICE_SID,
                              WT_VNET_SERVICE_VERSION, &info);
        if (rc != 0) {
            for (spin = 0; spin < 200000u; spin++) { }
        }
    }
    if (rc != 0) { wt_uart_puts("vnet open failed\r\n"); return -1; }
    wt_uart_puts("vnet open ok, rx_irq=");
    wt_uart_put_u32((uint32_t)info.rx_irq);
    wt_uart_puts("\r\n");

    /* Stage the MAC in RAM. m33mu returns zero on secure-side reads of NS
     * flash, so passing &id->mac (which lives in .rodata) into the call
     * would feed the switch a zeroed MAC. The on-target wolfTrust build
     * works either way; this is the emulator-compatible path. */
    memcpy(mac_ram, id->mac, 6);
    rc = wt_vnet_psa_set_mac(&g_vnet, mac_ram);
    if (rc != 0) {
        wt_uart_puts("vnet set_mac failed rc=");
        wt_uart_put_u32((uint32_t)(-rc));
        wt_uart_puts("\r\n");
        return -1;
    }
    wt_uart_puts("vnet mac set\r\n");

    wolfIP_init_static(&ip);
    ll = wolfIP_getdev(ip);
    if (ll == NULL) { wt_uart_puts("wolfIP_getdev failed\r\n"); return -1; }
    memcpy(ll->mac, id->mac, 6);
    ll->mtu = info.mtu;
    ll->send = vnet_ll_send;
    ll->poll = vnet_ll_poll;

    cfg = (struct ipconf *)0;
    (void)cfg;
    wolfIP_ipconfig_set(ip, id->ip, id->mask, id->gw);
    wt_uart_puts("ip=");
    wt_uart_put_ip(id->ip);
    wt_uart_puts(" peer=");
    wt_uart_put_ip(id->peer_ip);
    wt_uart_puts("\r\n");

    if (guest_id == 0u) {
        sock = wolfIP_sock_socket(ip, AF_INET, IPSTACK_SOCK_DGRAM, 1 /*ICMP*/);
        if (sock < 0) { wt_uart_puts("icmp socket failed\r\n"); return -1; }
    }

    for (;;) {
        wolfIP_poll(ip, (uint64_t)now_ms());

        if (guest_id == 0u) {
            uint32_t t = now_ms();
            if ((int32_t)(t - next_ping_ms) >= 0) {
                struct wolfIP_sockaddr_in dst;
                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = __builtin_bswap32(id->peer_ip);
                icmp_build_request((uint16_t)next_seq);
                rc = wolfIP_sock_sendto(ip, sock, g_icmp_buf, sizeof(g_icmp_buf),
                                        0, (struct wolfIP_sockaddr *)&dst,
                                        sizeof(dst));
                if (rc >= 0) {
                    wt_uart_puts("ping seq=");
                    wt_uart_put_u32((uint32_t)next_seq);
                    wt_uart_puts(" to ");
                    wt_uart_put_ip(id->peer_ip);
                    wt_uart_puts("\r\n");
                }
                next_seq++;
                next_ping_ms = t + 500u;
            }

            /* Drain any echo replies. */
            for (;;) {
                struct wolfIP_sockaddr_in src;
                socklen_t slen = sizeof(src);
                int n = wolfIP_sock_recvfrom(ip, sock, rx_buf, sizeof(rx_buf),
                                             0, (struct wolfIP_sockaddr *)&src,
                                             &slen);
                if (n <= 0) break;
                /* First byte of the reply is the ICMP type; 0 = echo reply. */
                if (n >= 8 && rx_buf[0] == 0u) {
                    uint16_t seq = ((uint16_t)rx_buf[6] << 8) | rx_buf[7];
                    if ((int)seq != last_seq) {
                        wt_uart_puts("ping reply from ");
                        wt_uart_put_ip(__builtin_bswap32(src.sin_addr.s_addr));
                        wt_uart_puts(" seq=");
                        wt_uart_put_u32(seq);
                        wt_uart_puts("\r\n");
                        last_seq = (int)seq;
#if defined(WT_VNET_EXIT_BKPT) && (WT_VNET_EXIT_BKPT == 1)
                        /* Emulator harness end-marker; never on hardware. */
                        __asm volatile("bkpt 0x7f");
#endif
                    }
                }
            }
        }
    }
}

void Reset_Handler(void)
{
    wt_copy_data();
    wt_zero_bss();
    wt_systick_init();
    wt_uart_init();
    (void)run_guest(wt_guest_id());
    for (;;) { __asm volatile("wfi"); }
}

/* Tiny xorshift PRNG used as wolfIP_getrandom — fine for the source-port
 * and seq-number seeding that wolfIP needs; no real entropy required for
 * a closed two-guest ICMP test. */
static uint32_t g_rng_state = 0xC0FFEE01u;

uint32_t wolfIP_getrandom(void)
{
    uint32_t x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x ? x : 1u;
    return g_rng_state;
}

__attribute__((unused)) static void unused_silencer(void) { wt_uart_put_hex2(0); }
