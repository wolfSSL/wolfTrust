/* pal_config_def.h
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

/* FF-A ACS target configuration for the wolfTrust QEMU machines. The machine
 * addresses and the endpoint ids come from wt_acs_machine.h, which the build
 * script writes for the selected machine. */

#ifndef _PAL_CONFIG_H_
#define _PAL_CONFIG_H_

#include "wt_acs_machine.h"

#ifndef CMAKE_BUILD
#define VERBOSITY                       3
#define PLATFORM_NS_HYPERVISOR_PRESENT  0
#define PLATFORM_SPMC_EL                1
#define PLATFORM_SP_EL                  0
#define SUITE                           all
#endif

/* The SPMC grants these S-EL0 partitions the virtual counter, so their waits
 * run in real time instead of a loop calibrated for another platform. */
#define PLATFORM_SP_EL0_COUNTER_SLEEP 1

#define PLATFORM_SP_IMAGE_OFFSET 0x4000
#define PLATFORM_VM_IMAGE_OFFSET 0x0

#define PLATFORM_PAGE_SIZE 0x1000
#define PAGE_SIZE_4K        0x1000
#define PAGE_SIZE_16K       (4 * 0x1000)
#define PAGE_SIZE_64K       (16 * 0x1000)

#define PLATFORM_MEM_RETRIEVE_USING_ADDRESS_RANGES 0

#define PLATFORM_OUTER_SHAREABLE_SUPPORT_ONLY 0
#define PLATFORM_INNER_SHAREABLE_SUPPORT_ONLY 1
#define PLATFORM_INNER_OUTER_SHAREABLE_SUPPORT 0

#define PLATFORM_NS_UART_BASE    WT_ACS_NS_UART_BASE
#define PLATFORM_NS_UART_SIZE    0x1000
#define PLATFORM_S_UART_BASE     WT_ACS_S_UART_BASE
#define PLATFORM_S_UART_SIZE     0x1000

#define PLATFORM_NVM_BASE    WT_ACS_NVM_BASE
#define PLATFORM_NVM_SIZE    0x10000

/* Neither machine models the suite's watchdogs, reference-clock timer, or
 * SMMU test engine; the ids below only keep the interrupt tests compiling. */
#define PLATFORM_WDOG_INTR           32
#define PLATFORM_TWDOG_INTID         56
#define PALTFORM_AP_REFCLK_CNTPSIRQ1 58
#define PLATFORM_NS_WD_INTR          59

#define PLATFORM_MEM_READ_ONLY_BASE  WT_ACS_RO_MEM_BASE
#define PLATFORM_MEM_READ_ONLY_SIZE  0x1000

#define PLAT_SMMU_UPSTREAM_DEVICE_MEM_REGION         0x0
#define PLAT_SMMU_UPSTREAM_DEVICE_MEM_REGION_INVALID 0x0
#define PLAT_SMMU_UPSTREAM_DEVICE_MEM_SIZE           0x10000
#define PLATFORM_SMMU_STREAM_ID           1
#define PLATFORM_SMMU_STREAM_ID_INVALID   2

#define GICD_BASE       WT_ACS_GICD_BASE
#define GICR_BASE       WT_ACS_GICR_BASE
#define GICC_BASE       WT_ACS_GICC_BASE
#define GICD_SIZE       0x10000
#define GICR_SIZE       0x100000
#define GICC_SIZE       0x2000

#define IRQ_PHY_TIMER_EL1           30
#define IRQ_VIRT_TIMER_EL1          27
#define IRQ_PHY_TIMER_EL2           26

#define PLATFORM_SP1_ID             WT_ACS_SP1_ID
#define PLATFORM_SP2_ID             WT_ACS_SP2_ID
#define PLATFORM_SP3_ID             WT_ACS_SP3_ID
#define PLATFORM_SP4_ID             WT_ACS_SP4_ID

#define PLATFORM_PRIMARY_SCHEDULER_EL  1

/* One processing element: the SPMC runs uniprocessor, secondaries stay parked. */
#define PLATFORM_NO_OF_CPUS 1

/* What this platform gives each endpoint: direct messaging (both request
 * forms), AArch64. It has no indirect messaging and no notifications, so the
 * suite skips those checks instead of demanding them. Bit values are the
 * FFA_PARTITION_INFO_GET properties (Table 6.2). */
#define WT_ACS_EP_PROPERTIES 0x70F
#define WT_ACS_EP_PROPERTIES_NO_INDIRECT 0x70B
#define PLATFORM_VM1_EP_PROPERTIES WT_ACS_EP_PROPERTIES
#define PLATFORM_SP1_EP_PROPERTIES WT_ACS_EP_PROPERTIES
#define PLATFORM_SP2_EP_PROPERTIES WT_ACS_EP_PROPERTIES
#define PLATFORM_SP3_EP_PROPERTIES WT_ACS_EP_PROPERTIES_NO_INDIRECT
#define PLATFORM_SP4_EP_PROPERTIES WT_ACS_EP_PROPERTIES_NO_INDIRECT

#endif /* _PAL_CONFIG_H_ */
