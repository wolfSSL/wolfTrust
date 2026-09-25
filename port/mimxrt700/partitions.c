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

#include <string.h>

/* Pinned guest-measurement slot. The image-assembly patcher locates it by
 * magic inside wolftrust.bin, stamps the guest digests, and only then is the
 * image signed for wolfBoot — so the pins share the image's root of trust.
 * An unpatched slot advertises zero records, which fails launch closed. */
#define WT_GUEST_MEAS_SLOT_MAGIC_LEN 16u
#define WT_GUEST_MEAS_SLOT_UNPATCHED 0xFFFFFFFFu

/* Enforcement the MIMXRT700 port provides (WT-PORT-0008). The fabric filter is
 * the per-dispatch SAU window: the RT700 reference manual (7.2.8, 11.3.3.3)
 * gives CPU0 no AHBSC master wrapper, so the SAU is the CPU's guest-isolation
 * layer, not the AHBSC SRAM rules. The silicon negative (run_rt700_hardware.sh
 * ahbscneg) is the proof this claim rides on. */
#define WT_MIMXRT700_PORT_CAPABILITIES \
    (WT_PORT_CAPABILITY_VECTOR_READ_ALIAS | \
     WT_PORT_CAPABILITY_NS_DOMAIN_PROGRAMMING | \
     WT_PORT_CAPABILITY_TZ_FILTER)
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

#ifndef WT_SHARED_UART
#define WT_SHARED_UART 0
#endif

#define WT_USART_REGION_SIZE 0x00001000U
#define WT_GUEST0_USART_BASE 0x40110000U
#define WT_GUEST1_USART_BASE 0x40110000U
/* Initial restore runs from a Secure exception and returns to a Non-secure
 * Thread/MSP frame; ES stays set because the exception was taken to Secure
 * state (clearing it trips INVPC on Armv8-M silicon). */
#define WT_EXC_RETURN_NS_THREAD_MSP_FROM_SECURE 0xFFFFFFB9U

static wt_guest_config_t g_partition_configs[] = {
    {
        .guest_id = 0U,
        .name = "guest-a",
        .vector_table = WT_GUEST0_FLASH_BASE,
        .initial_psp_ns = 0x00000000U,
        .initial_msp_ns = 0x20140000U,
        .irq_mask = {
            .words = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}
        },
        .memory_windows = {
            {WT_GUEST0_FLASH_BASE, WT_GUEST0_FLASH_SIZE,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC, WT_RESOURCE_SHARE_NONE},
            {0x20100000U, 0x00040000U,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_RESTART_CLEAR,
             WT_RESOURCE_SHARE_NONE}
        },
        .memory_window_count = 2U,
        .memory_regions = {
            {WT_GUEST0_FLASH_BASE, WT_GUEST0_FLASH_SIZE,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC},
            {0x20100000U, 0x00040000U, WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE},
            {WT_GUEST0_USART_BASE, WT_USART_REGION_SIZE,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE},
            /* NSC window: NS guests must be able to fetch the SG veneers.
             * Per ARMv8-M, NSC fetches succeed when SAU marks them NSC AND
             * the NS MPU grants execute permission. */
            {WT_NSC_BASE, (WT_NSC_END - WT_NSC_BASE + 1U),
             WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC}
        },
        .memory_region_count = 4U,
        .restart_policy = {
            .restart_limit = 3U,
            .restart_window_ticks = 64U,
            .initial_delay_ticks = 1U
        },
        .initial_state = WT_GUEST_READY,
        .timeslice_ms = WT_TIMESLICE_MS,
        .port = {
            .required_capabilities = WT_MIMXRT700_PORT_CAPABILITIES,
            .provided_capabilities = WT_MIMXRT700_PORT_CAPABILITIES,
            .vector_read_address =
                WT_FLASH_TO_S_ALIAS(WT_GUEST0_FLASH_BASE)
        }
    },
#if WT_MAX_GUESTS > 1
    {
        .guest_id = 1U,
        .name = "guest-b",
        .vector_table = WT_GUEST1_FLASH_BASE,
        .initial_psp_ns = 0x00000000U,
        .initial_msp_ns = 0x20180000U,
        .irq_mask = {
            .words = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}
        },
        .memory_windows = {
            {WT_GUEST1_FLASH_BASE, WT_GUEST1_FLASH_SIZE,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC, WT_RESOURCE_SHARE_NONE},
            {0x20140000U, 0x00040000U,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_RESTART_CLEAR,
             WT_RESOURCE_SHARE_NONE}
        },
        .memory_window_count = 2U,
        .memory_regions = {
            {WT_GUEST1_FLASH_BASE, WT_GUEST1_FLASH_SIZE,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC},
            {0x20140000U, 0x00040000U, WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE},
            {WT_GUEST1_USART_BASE, WT_USART_REGION_SIZE,
             WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_DEVICE},
            /* NSC window — see guest-a above. */
            {WT_NSC_BASE, (WT_NSC_END - WT_NSC_BASE + 1U),
             WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC}
        },
        .memory_region_count = 4U,
        .restart_policy = {
            .restart_limit = 3U,
            .restart_window_ticks = 64U,
            .initial_delay_ticks = 1U
        },
        .initial_state = WT_GUEST_READY,
        .timeslice_ms = WT_TIMESLICE_MS,
        .port = {
            .required_capabilities = WT_MIMXRT700_PORT_CAPABILITIES,
            .provided_capabilities = WT_MIMXRT700_PORT_CAPABILITIES,
            .vector_read_address =
                WT_FLASH_TO_S_ALIAS(WT_GUEST1_FLASH_BASE)
        }
    }
#endif
};

static wt_guest_runtime_t g_partition_runtime[
    sizeof(g_partition_configs) / sizeof(g_partition_configs[0])
];
/* Port-owned concrete context storage; the neutral runtime holds pointers. */
static wt_guest_context_t g_partition_contexts[
    sizeof(g_partition_configs) / sizeof(g_partition_configs[0])
];

static void wt_partitions_wire_contexts(void)
{
    size_t i;

    for (i = 0; i < sizeof(g_partition_runtime) /
            sizeof(g_partition_runtime[0]); ++i) {
        g_partition_runtime[i].context = &g_partition_contexts[i];
    }
}
static const wt_profile_capabilities_t g_profile_capabilities = {
    .capabilities = WT_CAPABILITY_SECURITY_STATE |
                    WT_CAPABILITY_PRIVILEGE_STATE |
                    WT_CAPABILITY_ROT_ISOLATION |
                    WT_CAPABILITY_DOMAIN_ISOLATION |
                    WT_CAPABILITY_MEMORY_PROTECTION |
                    WT_CAPABILITY_INTERRUPT_ISOLATION |
                    WT_CAPABILITY_RESTART,
    .max_domains = 11U,
    .max_memory_resources_per_domain = 3U,
    .max_interrupts_per_domain = 1U,
};
static uintptr_t g_bound_exec_bases[
    sizeof(g_partition_configs) / sizeof(g_partition_configs[0])
];
static size_t g_bound_exec_sizes[
    sizeof(g_partition_configs) / sizeof(g_partition_configs[0])
];

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
        *count = sizeof(g_partition_configs) / sizeof(g_partition_configs[0]);
    }

    return g_partition_configs;
}

wt_guest_runtime_t* wt_partitions_runtime_table(size_t* count)
{
    wt_partitions_wire_contexts();
    if (count != NULL) {
        *count = sizeof(g_partition_runtime) / sizeof(g_partition_runtime[0]);
    }

    return g_partition_runtime;
}

const wt_profile_capabilities_t* wt_partitions_profile_capabilities(void)
{
    return &g_profile_capabilities;
}

static const wt_domain_descriptor_t* wt_partition_manifest_domain(
    const wt_system_manifest_t* manifest, wt_domain_id_t id)
{
    size_t i;

    for (i = 0U; i < manifest->domain_count; ++i) {
        if (manifest->domains[i].id == id) {
            return &manifest->domains[i];
        }
    }

    return NULL;
}

int wt_partitions_bind_manifest(const wt_system_manifest_t* manifest)
{
    size_t count;
    size_t i;

    if (manifest == NULL || manifest->domains == NULL) {
        return -1;
    }

    count = sizeof(g_partition_configs) / sizeof(g_partition_configs[0]);
    for (i = 0U; i < count; ++i) {
        wt_guest_config_t* config = &g_partition_configs[i];
        const wt_domain_descriptor_t* domain;

        /* Domain zero is the SPM; each guest is a Non-secure application
         * domain one higher in the generated manifest. The Secure Partitions
         * (crypto, attestation) are separate secure domains above the guests
         * and are not bound to a guest here. */
        if (config->guest_id == WT_DOMAIN_ID_INVALID) {
            return -1;
        }
        domain = wt_partition_manifest_domain(manifest,
                                              (wt_domain_id_t)config->guest_id + 1U);
        if (domain == NULL ||
                domain->domain_class != WT_DOMAIN_CLASS_NONSECURE_APPLICATION ||
                domain->security_state != WT_SECURITY_STATE_NONSECURE ||
                domain->privilege_state != WT_PRIVILEGE_STATE_UNPRIVILEGED ||
                domain->restart_policy.action != WT_RESTART_ACTION_DOMAIN) {
            return -1;
        }
        if (wt_partition_validate_port_binding(config, domain) !=
                WT_PORT_VALID) {
            return -1;
        }

        /* The generated manifest's restart policy is authoritative: the SPM
         * honors the declared limits, not a compiled-in copy. */
        config->restart_policy.restart_limit =
            domain->restart_policy.restart_limit;
        config->restart_policy.restart_window_ticks =
            domain->restart_policy.restart_window_ticks;
        config->restart_policy.initial_delay_ticks =
            domain->restart_policy.initial_delay_ticks;
        /* The manifest's declared initial lifecycle drives the runtime state:
         * an NS application declared READY boots runnable; STOPPED stays out
         * of the schedule until an explicit lifecycle action. */
        config->initial_state = (wt_guest_state_t)domain->initial_lifecycle;
        config->launch_required = domain->launch_required;
        config->launch_min_version = domain->launch_min_version;

        /* Rebuild the entire NS MPU table from declared policy: memory
         * resources become caller-band windows, the declared console UART is
         * the only device grant accepted (pinned to the compiled address),
         * and unused slots are cleared so no static grant survives. */
        if (domain->memory_resource_count > WT_MAX_MEMORY_REGIONS - 1U) {
            return -1;
        }
        size_t window_count = 0U;
        size_t region_count = 0U;
        for (size_t resource = 0U;
                resource < domain->memory_resource_count; ++resource) {
            const wt_memory_resource_t* manifest_resource =
                &domain->memory_resources[resource];
            uint32_t mpu_attributes = manifest_resource->attributes &
                (WT_MEM_ATTR_READ | WT_MEM_ATTR_WRITE | WT_MEM_ATTR_EXEC |
                 WT_MEM_ATTR_DEVICE);

            if ((manifest_resource->attributes & WT_MEM_ATTR_DEVICE) != 0U) {
                uintptr_t usart_base = (config->guest_id == 0U) ?
                    WT_GUEST0_USART_BASE : WT_GUEST1_USART_BASE;

                if (manifest_resource->base != usart_base ||
                        manifest_resource->size != WT_USART_REGION_SIZE) {
                    return -1;
                }
            }
            else {
                if (window_count >= config->memory_window_count) {
                    return -1;
                }
                config->memory_windows[window_count] = *manifest_resource;
                window_count++;
            }
            config->memory_regions[region_count].base = manifest_resource->base;
            config->memory_regions[region_count].size = manifest_resource->size;
            config->memory_regions[region_count].attributes = mpu_attributes;
            region_count++;
        }
        if (window_count != config->memory_window_count) {
            return -1;
        }
        /* NSC veneer fetch window: a platform policy object every NS domain
         * needs to reach the SG gateway (SAU NSC + NS MPU execute). */
        config->memory_regions[region_count].base = WT_NSC_BASE;
        config->memory_regions[region_count].size =
            WT_NSC_END - WT_NSC_BASE + 1U;
        config->memory_regions[region_count].attributes =
            WT_MEM_ATTR_READ | WT_MEM_ATTR_EXEC;
        region_count++;
        for (size_t clear = region_count; clear < WT_MAX_MEMORY_REGIONS;
                ++clear) {
            config->memory_regions[clear].base = 0U;
            config->memory_regions[clear].size = 0U;
            config->memory_regions[clear].attributes = 0U;
        }
        config->memory_region_count = region_count;

        if (domain->entry_point == 0U ||
                domain->interrupt_resource_count > WT_MAX_IRQ_WORDS * 32U ||
                (domain->interrupt_resource_count != 0U &&
                 domain->interrupt_resources == NULL)) {
            return -1;
        }
        memset(&config->irq_mask, 0, sizeof(config->irq_mask));
        for (size_t interrupt = 0U;
                interrupt < domain->interrupt_resource_count; ++interrupt) {
            uint32_t irq = domain->interrupt_resources[interrupt].interrupt;
            size_t word = irq / 32U;
            uint32_t bit = irq % 32U;

            if (word >= WT_MAX_IRQ_WORDS) {
                return -1;
            }
            config->irq_mask.words[word] |= (uint32_t)1U << bit;
        }
        g_bound_exec_bases[i] = 0U;
        g_bound_exec_sizes[i] = 0U;
        for (size_t executable = 0U;
                executable < domain->memory_resource_count; ++executable) {
            const wt_memory_resource_t* resource =
                &domain->memory_resources[executable];

            if ((resource->attributes & WT_MEM_ATTR_EXEC) != 0U) {
                g_bound_exec_bases[i] = resource->base;
                g_bound_exec_sizes[i] = resource->size;
                break;
            }
        }
        if (g_bound_exec_sizes[i] == 0U) {
            return -1;
        }

        if (domain->stack_base > (uintptr_t)-1 - domain->stack_size) {
            return -1;
        }
        config->initial_msp_ns = domain->stack_base + domain->stack_size;
    }

    return 0;
}

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
     * Read via the Secure alias of the underlying flash bank — on m33mu
     * a Secure-side read of the 0x08... NS alias returns zero, so we
     * remap to 0x0C... (secure-MPU region 7 covers the guest images). */
    runtime->context->pc = wt_guest_reset_handler(config);
    if (config->guest_id >=
            sizeof(g_bound_exec_bases) / sizeof(g_bound_exec_bases[0]) ||
            g_bound_exec_sizes[config->guest_id] == 0U ||
            runtime->context->pc < g_bound_exec_bases[config->guest_id] ||
            runtime->context->pc >= g_bound_exec_bases[config->guest_id] +
                g_bound_exec_sizes[config->guest_id]) {
        runtime->context->pc = 0U;
        return;
    }
    runtime->context->lr = 0U;
    runtime->context->xpsr = 0x01000000U;
    runtime->context->exc_return = WT_EXC_RETURN_NS_THREAD_MSP_FROM_SECURE;
    runtime->context->frame_stacked = false;
}
