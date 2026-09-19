/* freertos_guest1 — wolfTrust NS guest running FreeRTOS, exercising the
 * FF-M SPM through the OS-neutral PSA client core (P7-S3).
 *
 *   FreeRTOS task → psa_* (wolfPSA) / psa_connect+psa_call (neutral core)
 *                → WolfTrust_FFM_* veneers → SPM → SERVICE_CRYPTO → vault
 *
 * Every secure request is mediated by the SPM (WT-FFM-0054); the wolfCrypt
 * DRBG seeds from SERVICE_CRYPTO's vault-backed RNG over the same path.
 *
 * Cortex-M33 NTZ port: TrustZone-unaware FreeRTOS port. The secure side
 * still owns CMSE, the secure SysTick, and the per-guest MPU window.
 * FreeRTOS just sees a flat NS world driven by its own SysTick.
 *
 * Heartbeats use a busy-delay sized for the m33mu emulator pace,
 * matching the baremetal guest1.c approach — NS-SysTick paravirt under
 * the HSM scheduler is unreliable for guest-driven timing, so the
 * heartbeat doesn't trust vTaskDelay(). Crypto runs once at boot. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include <psa/crypto.h>
#include "wolfpsa/psa_engine.h"

#include "psa/client.h"

/* SERVICE_HSM (port/stm32h563/manifest.json): the single mediated door to
 * the wolfHSM server — the same path guest0 uses. */
#define WT_SERVICE_HSM_SID 4102u

/* wolfHSM client glue (module/wolfhsm-client/src/wolfhsm_client_glue.c). */
int wolfhsm_guest_init(void);
whClientContext *wolfhsm_guest_client(void);
int wolftrust_guest_rng_stub(unsigned char *output, unsigned int sz);

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;

/* USART3 — same shared UART the secure side and guest0 use. */
#define USART3_BASE          0x40004800u
#define USART_CR1(base)      (*(volatile uint32_t *)((base) + 0x00u))
#define USART_BRR(base)      (*(volatile uint32_t *)((base) + 0x0Cu))
#define USART_ISR(base)      (*(volatile uint32_t *)((base) + 0x1Cu))
#define USART_TDR(base)      (*(volatile uint32_t *)((base) + 0x28u))
#define USART_CR1_UE         (1u << 0)
#define USART_CR1_RE         (1u << 2)
#define USART_CR1_TE         (1u << 3)
#define USART_ISR_TXE        (1u << 7)

#ifndef WT_FREERTOS_HEARTBEAT_SPIN
#define WT_FREERTOS_HEARTBEAT_SPIN 27000000u
#endif

/* ---- vector table + reset path ---------------------------------------- */

static void default_handler(void)
{
    for (;;) {}
}

void Reset_Handler(void);
void NMI_Handler(void) __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void) __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void) __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void) __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));

/* FreeRTOS provides these as `vPortSVCHandler` / `xPortPendSVHandler`
 * / `xPortSysTickHandler`; FreeRTOSConfig.h aliases them onto the
 * standard CMSIS exception-vector names, so we wire them directly here. */
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);

void DebugMon_Handler(void) __attribute__((weak, alias("default_handler")));

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
    [15] = (uint32_t)&SysTick_Handler,
};

static void copy_data(void)
{
    uint32_t *src = &_sidata, *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
}

static void zero_bss(void)
{
    uint32_t *dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0u;
    }
}

/* ---- UART ------------------------------------------------------------- */

static void uart_init(void)
{
    USART_CR1(USART3_BASE) = 0u;
    /* Matches baremetal guest1's BRR pin — m33mu accepts anything nonzero. */
    USART_BRR(USART3_BASE) = 0x410u;
    USART_CR1(USART3_BASE) = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

static void uart_putc(char c)
{
    while ((USART_ISR(USART3_BASE) & USART_ISR_TXE) == 0u) {}
    USART_TDR(USART3_BASE) = (uint32_t)(uint8_t)c;
}

static void uart_puts(const char *s)
{
    while (*s != '\0') {
        uart_putc(*s++);
    }
}

static void uart_put_u32(uint32_t value)
{
    char buf[10];
    uint32_t i = 0u;

    if (value == 0u) {
        uart_putc('0');
        return;
    }
    while (value != 0u) {
        buf[i++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    while (i > 0u) {
        uart_putc(buf[--i]);
    }
}

static void uart_put_hex_byte(uint8_t b)
{
    static const char hex[] = "0123456789abcdef";
    uart_putc(hex[(b >> 4) & 0xfu]);
    uart_putc(hex[b & 0xfu]);
}

static void busy_delay(uint32_t iters)
{
    volatile uint32_t i;
    for (i = 0u; i < iters; i++) {
        __asm volatile ("nop");
    }
}

/* ---- the crypto task -------------------------------------------------- */

static void uart_put_i32(int32_t value)
{
    if (value < 0) {
        uart_putc('-');
        uart_put_u32((uint32_t)(-value));
    } else {
        uart_put_u32((uint32_t)value);
    }
}

static int buf_is_zero(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0u; i < len; i++) {
        if (buf[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/* The same KAT guest0's exercise_ffm_crypto proves: SHA-256 through
 * SERVICE_CRYPTO's mediated dispatch, now from the FreeRTOS client. */
static const uint8_t k_hash_input[] =
    "wolfTrust FF-M SERVICE_CRYPTO dispatch test";
static const uint8_t k_hash_expected[32] = {
    0x20, 0x03, 0xdf, 0x15, 0x2a, 0x52, 0x8a, 0x06,
    0xc8, 0xd3, 0x48, 0xb8, 0xfa, 0x8b, 0x2f, 0x87,
    0xf7, 0x1f, 0xae, 0xc6, 0x24, 0x6c, 0x7e, 0x72,
    0x8e, 0x27, 0xa4, 0xb5, 0x0a, 0x49, 0x84, 0x66
};

/* SHA-256 through the mediated path (wolfPSA -> wolfCrypt(WH_DEV_ID) ->
 * cryptocb -> wh_Client -> SERVICE_HSM relay). No SERVICE_CRYPTO(4097). */
static void run_ffm_sha256_kat(void)
{
    psa_status_t st;
    uint8_t digest[32];
    size_t digest_len = 0u;

    memset(digest, 0, sizeof(digest));
    st = psa_hash_compute(PSA_ALG_SHA_256, k_hash_input,
                          sizeof(k_hash_input) - 1u, digest, sizeof(digest),
                          &digest_len);
    if (st == PSA_SUCCESS && digest_len == sizeof(digest) &&
        memcmp(digest, k_hash_expected, sizeof(digest)) == 0) {
        uart_puts("freertos_guest1: ffm sha256 ok first=0x");
        uart_put_hex_byte(digest[0]);
        uart_puts("\r\n");
    } else {
        uart_puts("freertos_guest1: ffm sha256 FAILED st=");
        uart_put_i32((int32_t)st);
        uart_puts("\r\n");
    }
}

/* Randomness through the mediated path: the wolfHSM client draws entropy from
 * the secure side over SERVICE_HSM — never a raw NS-to-HSM transport. */
static void run_ffm_rng(void)
{
    uint8_t buf[32];
    int rc;

    memset(buf, 0, sizeof(buf));
    rc = wolftrust_guest_rng_stub(buf, sizeof(buf));
    if (rc == 0 && buf_is_zero(buf, sizeof(buf)) == 0) {
        uart_puts("freertos_guest1: ffm rng ok\r\n");
    } else {
        uart_puts("freertos_guest1: ffm rng FAILED\r\n");
    }
}

/* PSA Crypto API parity with guest0 (wolfPSA front-end): the DRBG behind
 * psa_generate_random seeds through the FF-M RNG hook below, so the
 * entropy crossing is SPM-mediated too. */
static void run_psa_smoke(void)
{
    psa_status_t st;
    uint8_t buf[32];
    uint8_t digest[32];
    size_t digest_len = 0u;

    st = psa_crypto_init();
    uart_puts("freertos_guest1: psa_crypto_init st=");
    uart_put_i32((int32_t)st);
    uart_puts("\r\n");
    if (st != PSA_SUCCESS) {
        return;
    }

    memset(buf, 0, sizeof(buf));
    st = psa_generate_random(buf, sizeof(buf));
    if (st == PSA_SUCCESS && buf_is_zero(buf, sizeof(buf)) == 0) {
        uart_puts("freertos_guest1: psa rng ok\r\n");
    } else {
        uart_puts("freertos_guest1: psa rng FAILED st=");
        uart_put_i32((int32_t)st);
        uart_puts("\r\n");
    }

    memset(digest, 0, sizeof(digest));
    st = psa_hash_compute(PSA_ALG_SHA_256, k_hash_input,
                          sizeof(k_hash_input) - 1u, digest, sizeof(digest),
                          &digest_len);
    if (st == PSA_SUCCESS && digest_len == sizeof(digest) &&
        memcmp(digest, k_hash_expected, sizeof(digest)) == 0) {
        uart_puts("freertos_guest1: psa hash ok\r\n");
    } else {
        uart_puts("freertos_guest1: psa hash FAILED st=");
        uart_put_i32((int32_t)st);
        uart_puts("\r\n");
    }
}

/* FF-M isolation negatives from the FreeRTOS client: the SPM must reject a
 * forged handle, an oversized input vector, and a connect to an unknown SID —
 * the same rejections guest0 proves — and none of them faults this guest. */
/* SWD-readable negative-result latch: the shared H5 console interleaves
 * guest lines char-by-char, so silicon asserts this mask by symbol instead of
 * UART markers. Bits: 1 forged handle, 2 oversized vector, 4 cross-guest
 * vector, 8 unknown SID — set only when the SPM rejected the abuse. */
volatile uint32_t g_guest1_ffm_neg;

static void run_ffm_negatives(void)
{
    psa_handle_t handle;
    psa_handle_t bad;
    psa_invec in_vec;
    psa_outvec out_vec;
    psa_status_t st;
    uint8_t digest[32];

    handle = psa_connect(WT_SERVICE_HSM_SID, 1u);
    if (handle <= 0) {
        uart_puts("freertos_guest1: ffm neg setup FAILED\r\n");
        return;
    }

    /* Forged handle: not mapped to this caller's connection. */
    in_vec.base = k_hash_input;
    in_vec.len = sizeof(k_hash_input) - 1u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    st = psa_call((psa_handle_t)(handle + 0x1000), 0, &in_vec, 1u,
                  &out_vec, 1u);
    if (st != PSA_SUCCESS) {
        g_guest1_ffm_neg |= 1u;
    }
    uart_puts(st != PSA_SUCCESS ?
              "freertos_guest1: ffm forged-handle rejected\r\n" :
              "freertos_guest1: ffm forged-handle NOT rejected\r\n");

    /* Oversized input vector: a length beyond the secure transfer bound is
     * refused on validation, before any copy. */
    in_vec.base = k_hash_input;
    in_vec.len = 2048u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    st = psa_call(handle, 0, &in_vec, 1u, &out_vec, 1u);
    if (st != PSA_SUCCESS) {
        g_guest1_ffm_neg |= 2u;
    }
    uart_puts(st != PSA_SUCCESS ?
              "freertos_guest1: ffm oversized-vector rejected\r\n" :
              "freertos_guest1: ffm oversized-vector NOT rejected\r\n");

    /* Cross-guest vector: a base inside guest0's NS RAM window must be
     * refused by the caller-banded memcheck — guests are isolated from each
     * other through the SPM, not merely NS from Secure (WT-FFM-0011). */
    in_vec.base = (const void *)0x20000000u; /* guest0 NS RAM, not ours */
    in_vec.len = 16u;
    out_vec.base = digest;
    out_vec.len = sizeof(digest);
    st = psa_call(handle, 0, &in_vec, 1u, &out_vec, 1u);
    if (st != PSA_SUCCESS) {
        g_guest1_ffm_neg |= 4u;
    }
    uart_puts(st != PSA_SUCCESS ?
              "freertos_guest1: ffm cross-guest vector rejected\r\n" :
              "freertos_guest1: ffm cross-guest vector NOT rejected\r\n");

    psa_close(handle);

    /* Connect to an unknown SID: refused, no handle handed back. */
    bad = psa_connect(0x4200u, 1u);
    if (bad <= 0) {
        g_guest1_ffm_neg |= 8u;
        uart_puts("freertos_guest1: ffm wrong-sid refused\r\n");
    } else {
        uart_puts("freertos_guest1: ffm wrong-sid NOT refused\r\n");
        psa_close(bad);
    }
}

/* Bring up the single mediated crypto path: the wolfHSM client over the
 * SPM-mediated psa_call transport registers WH_DEV_ID during client init, and
 * wolfPSA threads that devId through wolfCrypt, exactly guest0's wiring,
 * minus the Zephyr SYS_INIT hooks it does not have. */
static int guest_crypto_init(void)
{
    int rc;

    /* Boot can race a Secure Partition restart window. The shared glue
     * installs a retry callback when the first connection is refused. */
    rc = wolfhsm_guest_init();
    if (rc != WH_ERROR_OK) {
        uart_puts("freertos_guest1: hsm client init FAILED rc=");
        uart_put_i32((int32_t)rc);
        uart_puts("\r\n");
        return -1;
    }
    (void)wolfPSA_SetDefaultDevID(WH_DEV_ID);
    /* PSA requires psa_crypto_init before any other psa_* call; guest0 gets
     * this from wolfPSA's Zephyr SYS_INIT, the bare FreeRTOS guest does it
     * here so the first mediated psa_hash_compute is not BAD_STATE. */
    rc = (int)psa_crypto_init();
    if (rc != PSA_SUCCESS) {
        uart_puts("freertos_guest1: psa_crypto_init FAILED st=");
        uart_put_i32((int32_t)rc);
        uart_puts("\r\n");
        return -1;
    }
    return 0;
}

static void crypto_task(void *arg)
{
    uint32_t count = 0u;

    (void)arg;

    if (guest_crypto_init() != 0) {
        goto heartbeat;
    }

    run_ffm_sha256_kat();
    run_ffm_rng();
    run_psa_smoke();
    run_ffm_negatives();

heartbeat:
    for (;;) {
        busy_delay(WT_FREERTOS_HEARTBEAT_SPIN);
        uart_puts("freertos_guest1: heartbeat ");
        uart_put_u32(count);
        uart_puts("\r\n");
        count++;
    }
}

/* ---- entry ------------------------------------------------------------ */

__attribute__((section(".reset")))
void Reset_Handler(void)
{
    copy_data();
    zero_bss();
    uart_init();
    uart_puts("freertos_guest1: alive\r\n");

    /* 2048 stack words = 8 KiB. The first wolfCrypt DRBG init through
     * the FF-M RNG hook plus wolfPSA hash setup burns several KiB in
     * peak call depth; 4 KiB triggered a STKOF on the FreeRTOS port's
     * PSPLIM guard under the old transport, so keep the headroom. */
    if (xTaskCreate(crypto_task, "crypto", 2048, NULL,
                    tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
        uart_puts("freertos_guest1: xTaskCreate failed\r\n");
        for (;;) {}
    }

    vTaskStartScheduler();

    /* If we get here, the scheduler returned (out of heap / idle task
     * creation failed). Park forever — the secure side preempts us
     * anyway when the next timeslice fires. */
    uart_puts("freertos_guest1: scheduler exited\r\n");
    for (;;) {}
}

/* FreeRTOS hooks that the build needs symbols for even with the hook
 * Kconfig knobs disabled. Mostly stubs. */

void vAssertCalled(const char *file, int line)
{
    (void)file; (void)line;
    uart_puts("freertos_guest1: assertion failed\r\n");
    for (;;) {}
}

void vApplicationMallocFailedHook(void)
{
    uart_puts("freertos_guest1: malloc failed\r\n");
    for (;;) {}
}

void vApplicationStackOverflowHook(TaskHandle_t task, char *name)
{
    (void)task; (void)name;
    uart_puts("freertos_guest1: stack overflow\r\n");
    for (;;) {}
}

/* Entropy hook (WT-FFM-0054): wolfCrypt's random.c references wc_GenerateSeed
 * for DRBG reseed; it draws from the wolfHSM client's RNG over the SERVICE_HSM
 * relay (wolftrust_guest_rng_stub -> wh_Client_RngGenerate). This guest has no
 * raw transport to the secure side — every crossing is SPM-mediated. */
int wc_GenerateSeed(OS_Seed *os, byte *output, word32 sz)
{
    (void)os;
    return wolftrust_guest_rng_stub((unsigned char *)output,
                                    (unsigned int)sz);
}
