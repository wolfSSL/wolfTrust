/* partitions.c
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

#include "wolftrust/arch/armv8m/context.h"
#include "wolftrust/guest_verify.h"
#include "wolftrust/partition.h"
#include "memory_map.h"
#include "platform_caps.h"
#include "wolftrust/static_assert.h"
#include "wolftrust_manifest_generated.h"
#if defined(WT_HANDLER_IRQ_PROBE)
#include "wolftrust/arch.h"
#include "wolftrust/arch/armv8m/armv8m.h"
#endif

#include <string.h>

/* Pinned guest-measurement slot: the image patcher stamps the guest digests
 * by magic before wolfBoot signs the image, so the pins share its root of
 * trust; an unpatched slot advertises zero records and fails launch closed. */
#define WT_GUEST_MEAS_SLOT_MAGIC_LEN 16u
#define WT_GUEST_MEAS_SLOT_UNPATCHED 0xFFFFFFFFu

/* A writable guest window must own whole attribution blocks of the fabric
 * filter (512-byte GTZC blocks on the STM32H5, the 32-byte MPU granule
 * elsewhere), or the curtain would hand a neighbour's bytes to the guest. */
#ifndef WT_GUEST_WINDOW_GRANULE
#define WT_GUEST_WINDOW_GRANULE 32u
#endif
#if defined(__ARM_EABI__)
#define WT_GUEST_MEAS_SECTION \
    __attribute__((section(".wt_guest_meas"), used, aligned(4)))
#else
#define WT_GUEST_MEAS_SECTION
#endif

typedef struct wt_guest_meas_slot {
    uint8_t magic[WT_GUEST_MEAS_SLOT_MAGIC_LEN];
    uint32_t count;
    wt_guest_measurement_t records[WT_GUEST_MEAS_MAX_RECORDS];
} wt_guest_meas_slot_t;

static const wt_guest_meas_slot_t g_guest_meas_slot WT_GUEST_MEAS_SECTION = {
    { 0x57u, 0x54u, 0x47u, 0x4Du, 0x45u, 0x41u, 0x53u, 0x31u,
      0xA5u, 0x3Cu, 0x96u, 0xE1u, 0x78u, 0x0Fu, 0xB2u, 0x4Bu },
    WT_GUEST_MEAS_SLOT_UNPATCHED,
    { { 0u, 0u, 0u, { 0u } } }
};

static wt_guest_measurement_t g_guest_meas_copy[WT_GUEST_MEAS_MAX_RECORDS];

const wt_guest_measurement_t* wt_platform_guest_measurements(size_t* count)
{
    /* The slot is stamped into the binary after linking, so this const
     * object's initializer lies: every field is loaded through volatile, or
     * the optimizer folds the unpatched zeros into the records it returns. */
    const volatile uint32_t* slot_count = &g_guest_meas_slot.count;
    const volatile uint8_t* src =
        (const volatile uint8_t*)g_guest_meas_slot.records;
    uint8_t* dst = (uint8_t*)g_guest_meas_copy;
    uint32_t records = *slot_count;
    size_t bytes;
    size_t i;

    if (count == NULL) {
        return NULL;
    }

    if (records == WT_GUEST_MEAS_SLOT_UNPATCHED ||
            records > WT_GUEST_MEAS_MAX_RECORDS) {
        *count = 0u;
        return NULL;
    }

    bytes = (size_t)records * sizeof(wt_guest_measurement_t);
    for (i = 0u; i < bytes; i++) {
        dst[i] = src[i];
    }
    *count = (size_t)records;
    return g_guest_meas_copy;
}

#ifndef WT_TIMESLICE_MS
#define WT_TIMESLICE_MS 2U
#endif

/* Initial restore runs from a Secure exception and returns to a Non-secure
 * Thread/MSP frame; ES stays set because the exception was taken to Secure
 * state (clearing it trips INVPC on Armv8-M silicon). */
#define WT_EXC_RETURN_NS_THREAD_MSP_FROM_SECURE 0xFFFFFFB9U

/* Compile-time half of wt_partition_validate_port_binding's alias check. */
WT_STATIC_ASSERT((WT_PORT_CAPABILITIES &
                  WT_PORT_CAPABILITY_VECTOR_READ_ALIAS) == 0U ||
                 (WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE) != 0U &&
                  (WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE) & 3U) == 0U &&
                  WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE) !=
                      WT_GUEST0_FLASH_BASE),
                 "guest 0 vector read alias is invalid");
#if WT_MAX_GUESTS > 1
WT_STATIC_ASSERT((WT_PORT_CAPABILITIES &
                  WT_PORT_CAPABILITY_VECTOR_READ_ALIAS) == 0U ||
                 (WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE) != 0U &&
                  (WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE) & 3U) == 0U &&
                  WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE) !=
                      WT_GUEST1_FLASH_BASE),
                 "guest 1 vector read alias is invalid");
#endif

#if defined(WT_HANDLER_IRQ_PROBE)
#if WT_HANDLER_IRQ_PROBE < WT_ARMV8M_SECURE_IRQS || \
    WT_HANDLER_IRQ_PROBE >= WT_MAX_IRQ_WORDS * 32
#error "WT_HANDLER_IRQ_PROBE must be a spare IRQ outside the Secure range"
#endif
/* Test build: guest 0 owns one spare IRQ to wedge its handler in. */
#define WT_GUEST_PROBE_IRQ(g, w) \
    (((g) == 0 && (w) == WT_HANDLER_IRQ_PROBE / 32) ? \
     (1U << (WT_HANDLER_IRQ_PROBE % 32)) : 0U)
#else
#define WT_GUEST_PROBE_IRQ(g, w) 0U
#endif

/* One constant row per guest, built from the generated manifest. */
#define WT_GUEST_ROW(g, label, flash, console) \
    { \
        .guest_id = (g), \
        .name = label, \
        .vector_table = (flash), \
        .initial_psp_ns = 0x00000000U, \
        .initial_msp_ns = WT_GEN_GUEST##g##_MSP, \
        .irq_mask = { .words = { \
            WT_GEN_GUEST##g##_IRQ_WORD0 | WT_GUEST_PROBE_IRQ(g, 0), \
            WT_GEN_GUEST##g##_IRQ_WORD1 | WT_GUEST_PROBE_IRQ(g, 1), \
            WT_GEN_GUEST##g##_IRQ_WORD2 | WT_GUEST_PROBE_IRQ(g, 2), \
            WT_GEN_GUEST##g##_IRQ_WORD3 | WT_GUEST_PROBE_IRQ(g, 3), \
            WT_GEN_GUEST##g##_IRQ_WORD4 | WT_GUEST_PROBE_IRQ(g, 4), \
            WT_GEN_GUEST##g##_IRQ_WORD5 | WT_GUEST_PROBE_IRQ(g, 5), \
            WT_GEN_GUEST##g##_IRQ_WORD6 | WT_GUEST_PROBE_IRQ(g, 6), \
            WT_GEN_GUEST##g##_IRQ_WORD7 | WT_GUEST_PROBE_IRQ(g, 7) } }, \
        .memory_windows = { WT_GEN_GUEST##g##_WINDOWS }, \
        .memory_window_count = WT_GEN_GUEST##g##_WINDOW_COUNT, \
        .memory_regions = { WT_GEN_GUEST##g##_REGIONS, \
            { WT_NSC_BASE, WT_NSC_END - WT_NSC_BASE + 1U, \
              WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC } }, \
        .memory_region_count = WT_GEN_GUEST##g##_REGION_COUNT + 1U, \
        .restart_policy = { WT_GEN_GUEST##g##_RESTART }, \
        .timeslice_ms = WT_TIMESLICE_MS, \
        .port = { WT_PORT_CAPABILITIES, WT_PORT_CAPABILITIES, \
                  WT_FLASH_TO_S_ALIAS(flash) }, \
        .initial_state = (wt_guest_state_t)WT_GEN_GUEST##g##_LIFECYCLE, \
        .launch_required = WT_GEN_GUEST##g##_LAUNCH_REQUIRED, \
        .launch_min_version = WT_GEN_GUEST##g##_LAUNCH_MIN_VERSION \
    }

/* Guests launch privileged (CONTROL_NS = 0), restart as a domain, map only
 * their own console, and own whole attribution blocks when writable. */
#define WT_GUEST_ROW_CHECKS(g, console) \
    WT_STATIC_ASSERT(WT_GEN_GUEST##g##_PRIVILEGE == \
                     WT_PRIVILEGE_STATE_PRIVILEGED && \
                     WT_GEN_GUEST##g##_RESTART_ACTION == \
                     WT_RESTART_ACTION_DOMAIN && \
                     WT_GEN_GUEST##g##_ENTRY != 0U && \
                     WT_GEN_GUEST##g##_EXEC_SIZE != 0U && \
                     WT_GEN_GUEST##g##_REGION_COUNT < \
                     WT_MAX_MEMORY_REGIONS && \
                     WT_GEN_GUEST##g##_WINDOW_COUNT <= \
                     WT_MAX_MEMORY_WINDOWS && \
                     (WT_GEN_GUEST##g##_DEVICE_SIZE == 0U || \
                      (WT_GEN_GUEST##g##_DEVICE_BASE == (console) && \
                       WT_GEN_GUEST##g##_DEVICE_SIZE == \
                       WT_GUEST_CONSOLE_SIZE)) && \
                     ((WT_GEN_GUEST##g##_WRITE_EDGES) % \
                      WT_GUEST_WINDOW_GRANULE) == 0U, \
                     "guest " #g " manifest domain cannot bind")

WT_STATIC_ASSERT((WT_GUEST_WINDOW_GRANULE & (WT_GUEST_WINDOW_GRANULE - 1U)) ==
                 0U, "the guest window granule is a power of two");
WT_GUEST_ROW_CHECKS(0, WT_GUEST0_CONSOLE_BASE);
#if WT_MAX_GUESTS > 1
WT_GUEST_ROW_CHECKS(1, WT_GUEST1_CONSOLE_BASE);
#endif

static const wt_guest_config_t g_partition_configs[] = {
    WT_GUEST_ROW(0, "guest-a", WT_GUEST0_FLASH_BASE, WT_GUEST0_CONSOLE_BASE),
#if WT_MAX_GUESTS > 1
    WT_GUEST_ROW(1, "guest-b", WT_GUEST1_FLASH_BASE, WT_GUEST1_CONSOLE_BASE),
#endif
};

#define WT_GUEST_COUNT \
    (sizeof(g_partition_configs) / sizeof(g_partition_configs[0]))

/* The executable window the reset PC must land in. */
static const wt_memory_region_t g_guest_exec[] = {
    { WT_GEN_GUEST0_EXEC_BASE, WT_GEN_GUEST0_EXEC_SIZE, 0U },
#if WT_MAX_GUESTS > 1
    { WT_GEN_GUEST1_EXEC_BASE, WT_GEN_GUEST1_EXEC_SIZE, 0U },
#endif
};

static wt_guest_runtime_t g_partition_runtime[WT_GUEST_COUNT];
/* Port-owned concrete context storage; the neutral runtime holds pointers. */
static wt_guest_context_t g_partition_contexts[WT_GUEST_COUNT];

static const wt_profile_capabilities_t g_profile_capabilities = {
    .capabilities = WT_PLATFORM_CAPABILITIES,
    .max_domains = WT_PLATFORM_MAX_DOMAINS,
    .max_memory_resources_per_domain = WT_PLATFORM_MAX_MEMORY_RESOURCES,
    .max_interrupts_per_domain = WT_PLATFORM_MAX_INTERRUPTS,
};

static bool wt_guest_reset_handler_valid(const wt_guest_config_t* config,
                                         uintptr_t resetHandler)
{
    uintptr_t entry = resetHandler & ~(uintptr_t)1u;

    return ((resetHandler & 1u) != 0u) &&
           (entry >= config->vector_table) &&
           (entry < (config->vector_table + config->memory_windows[0].size));
}

static uintptr_t wt_guest_reset_handler(const wt_guest_config_t* config)
{
    uintptr_t resetHandler;

    resetHandler = ((const uint32_t*)config->port.vector_read_address)[1];
    if (!wt_guest_reset_handler_valid(config, resetHandler)) {
        /* Read the vector through the Secure alias first; fall back to the
         * Non-secure alias only after rejecting the value as an invalid guest
         * entry (the IDAU may return zero through the Secure alias). */
        resetHandler = ((const uint32_t*)config->vector_table)[1];
    }

    if (!wt_guest_reset_handler_valid(config, resetHandler)) {
        return 0u;
    }

    return resetHandler;
}

const wt_guest_config_t* wt_partitions_config_table(size_t* count)
{
    if (count != NULL) {
        *count = WT_GUEST_COUNT;
    }

    return g_partition_configs;
}

wt_guest_runtime_t* wt_partitions_runtime_table(size_t* count)
{
    size_t i;

    for (i = 0; i < WT_GUEST_COUNT; ++i) {
        g_partition_runtime[i].context = &g_partition_contexts[i];
    }
#if defined(WT_HANDLER_IRQ_PROBE)
    wt_arch_route_irq_to_guest((uint32_t)WT_HANDLER_IRQ_PROBE);
#endif
    if (count != NULL) {
        *count = WT_GUEST_COUNT;
    }

    return g_partition_runtime;
}

const wt_profile_capabilities_t* wt_partitions_profile_capabilities(void)
{
    return &g_profile_capabilities;
}

#if WT_MANIFEST_RUNTIME_CHECK || !defined(WT_TARGET_BUILD)
/* Re-derives each guest row from the descriptive manifest; 0 when every
 * constant row matches what the manifest declares. */
static int wt_partition_check_domain(const wt_guest_config_t* config,
                                     const wt_domain_descriptor_t* domain)
{
    wt_guest_config_t derived;
    size_t windows = 0U;
    size_t regions = 0U;
    size_t i;

    if (domain->domain_class != WT_DOMAIN_CLASS_NONSECURE_APPLICATION ||
            domain->security_state != WT_SECURITY_STATE_NONSECURE ||
            domain->privilege_state != WT_PRIVILEGE_STATE_PRIVILEGED ||
            domain->restart_policy.action != WT_RESTART_ACTION_DOMAIN ||
            domain->memory_resource_count > WT_MAX_MEMORY_REGIONS - 1U ||
            domain->stack_base > (uintptr_t)-1 - domain->stack_size) {
        return -1;
    }
    (void)memcpy(&derived, config, sizeof(derived));
    (void)memset(derived.memory_windows, 0, sizeof(derived.memory_windows));
    (void)memset(derived.memory_regions, 0, sizeof(derived.memory_regions));
    (void)memset(&derived.irq_mask, 0, sizeof(derived.irq_mask));
    for (i = 0U; i < domain->memory_resource_count; ++i) {
        const wt_memory_resource_t* resource = &domain->memory_resources[i];

        if ((resource->attributes & WT_MEM_ATTR_DEVICE) == 0U) {
            if (windows >= WT_MAX_MEMORY_WINDOWS) {
                return -1;
            }
            derived.memory_windows[windows] = *resource;
            windows++;
        }
        derived.memory_regions[regions].base = resource->base;
        derived.memory_regions[regions].size = resource->size;
        derived.memory_regions[regions].attributes = resource->attributes &
            (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_EXEC |
             WT_MEM_ATTR_DEVICE);
        regions++;
    }
    derived.memory_regions[regions] = config->memory_regions[regions];
    derived.memory_window_count = windows;
    derived.memory_region_count = regions + 1U;
    for (i = 0U; i < domain->interrupt_resource_count; ++i) {
        uint32_t irq = domain->interrupt_resources[i].interrupt;

        if (irq >= WT_MAX_IRQ_WORDS * 32U) {
            return -1;
        }
        derived.irq_mask.words[irq / 32U] |= (uint32_t)1U << (irq % 32U);
    }
#if defined(WT_HANDLER_IRQ_PROBE)
    if (config->guest_id == 0U) {
        derived.irq_mask.words[WT_HANDLER_IRQ_PROBE / 32] |=
            (uint32_t)1U << (WT_HANDLER_IRQ_PROBE % 32);
    }
#endif
    derived.restart_policy.restart_limit =
        domain->restart_policy.restart_limit;
    derived.restart_policy.restart_window_ticks =
        domain->restart_policy.restart_window_ticks;
    derived.restart_policy.initial_delay_ticks =
        domain->restart_policy.initial_delay_ticks;
    derived.initial_state = (wt_guest_state_t)domain->initial_lifecycle;
    derived.launch_required = domain->launch_required;
    derived.launch_min_version = domain->launch_min_version;
    derived.initial_msp_ns = domain->stack_base + domain->stack_size;
    if (domain->entry_point == 0U ||
            memcmp(&derived, config, sizeof(derived)) != 0) {
        return -1;
    }
    return 0;
}

int wt_partitions_check_manifest(const wt_system_manifest_t* manifest)
{
    const wt_domain_descriptor_t* domain;
    size_t i;
    size_t j;

    if (manifest == NULL || manifest->domains == NULL) {
        return -1;
    }
    for (i = 0U; i < WT_GUEST_COUNT; ++i) {
        domain = NULL;
        for (j = 0U; j < manifest->domain_count; ++j) {
            if (manifest->domains[j].id ==
                    (wt_domain_id_t)g_partition_configs[i].guest_id + 1U) {
                domain = &manifest->domains[j];
            }
        }
        if (domain == NULL ||
                wt_partition_check_domain(&g_partition_configs[i],
                                          domain) != 0 ||
                wt_partition_validate_port_binding(&g_partition_configs[i],
                                                   domain) != WT_PORT_VALID) {
            return -1;
        }
    }
    return 0;
}
#endif

void wt_partition_reset_runtime(const wt_guest_config_t* config,
                                wt_guest_runtime_t* runtime)
{
    uint32_t restart_count;
    uint32_t first_restart_tick;

    if (config == NULL || runtime == NULL) {
        return;
    }

    restart_count = runtime->restart_count;
    first_restart_tick = runtime->first_restart_tick;
    memset(runtime, 0, sizeof(*runtime));
    /* The memset wipes the port-wired context pointer; rewire by table
     * index and zero the concrete context storage instead. */
    runtime->context =
        &g_partition_contexts[(size_t)(runtime - g_partition_runtime)];
    memset(runtime->context, 0, sizeof(*runtime->context));
    runtime->restart_count = restart_count;
    runtime->first_restart_tick = first_restart_tick;
    runtime->state = config->initial_state;
    runtime->context->psp_ns = config->initial_psp_ns;
    runtime->context->msp_ns = config->initial_msp_ns;
    runtime->context->vector_table_ns = config->vector_table;
    /* Reset PC is the guest's reset-handler pointer at vector[1]; the slot
     * already carries the Thumb bit. wt_jump_to_ns strips it before BXNS.
     * Read via the Secure alias of the flash: a Secure-side read of the NS
     * alias may return zero, so vector_read_address is the Secure alias. */
    runtime->context->pc = wt_guest_reset_handler(config);
    if (config->guest_id >= WT_GUEST_COUNT ||
            runtime->context->pc < g_guest_exec[config->guest_id].base ||
            runtime->context->pc >= g_guest_exec[config->guest_id].base +
                g_guest_exec[config->guest_id].size) {
        runtime->context->pc = 0U;
        return;
    }
    runtime->context->lr = 0U;
    runtime->context->xpsr = 0x01000000U;
    runtime->context->exc_return = WT_EXC_RETURN_NS_THREAD_MSP_FROM_SECURE;
    runtime->context->frame_stacked = false;
}
