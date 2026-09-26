/* memory_map.h
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

#ifndef WOLFTRUST_FW_STM32H563_MEMORY_MAP_H
#define WOLFTRUST_FW_STM32H563_MEMORY_MAP_H

#ifndef WT_SECURE_FLASH_BASE
#define WT_SECURE_FLASH_BASE     0x0C000000u
#endif
#ifndef WT_SECURE_FLASH_SIZE
#define WT_SECURE_FLASH_SIZE     0x00020000u
#endif
#ifndef WT_SECURE_IMAGE_HEADER_SIZE
#define WT_SECURE_IMAGE_HEADER_SIZE 0u
#endif
#define WT_FLASH_S_BASE          WT_SECURE_FLASH_BASE
#define WT_FLASH_S_SIZE          WT_SECURE_FLASH_SIZE
#define WT_FLASH_IMAGE_BASE      (WT_FLASH_S_BASE + WT_SECURE_IMAGE_HEADER_SIZE)
#define WT_FLASH_NSC_BASE        (WT_FLASH_IMAGE_BASE + 0x00000400u)
#define WT_FLASH_NSC_END         (WT_FLASH_NSC_BASE + 0x000003FFu)

#define WT_FLASH_NS_BASE         0x08000000u
#define WT_FLASH_S_ALIAS_BASE    0x0C000000u
#define WT_FLASH_TO_S_ALIAS(address) \
    ((address) - WT_FLASH_NS_BASE + WT_FLASH_S_ALIAS_BASE)
#ifndef WT_GUEST0_FLASH_BASE
#define WT_GUEST0_FLASH_BASE     0x08020000u
#endif
#ifndef WT_GUEST1_FLASH_BASE
#define WT_GUEST1_FLASH_BASE     0x08040000u
#endif
#ifndef WT_GUEST_FLASH_SIZE
#define WT_GUEST_FLASH_SIZE      0x00020000u
#endif
/* Per-guest window sizes; guest0 can grow past guest1's without moving it
 * across the bank-1/bank-2 watermark boundary. */
#ifndef WT_GUEST0_FLASH_SIZE
#define WT_GUEST0_FLASH_SIZE     WT_GUEST_FLASH_SIZE
#endif
#ifndef WT_GUEST1_FLASH_SIZE
#define WT_GUEST1_FLASH_SIZE     WT_GUEST_FLASH_SIZE
#endif

/* Secure wolfHSM NVM store.
 *
 * Reserved at the end of internal flash bank 2. STM32H5 sectors are 8 KiB;
 * wolfHSM's flash backend reports one sector as the partition size, and
 * wh_nvm_flash uses two mirrored partitions, so reserve two sectors.
 */
#define WT_FLASH_SECTOR_SIZE       0x00002000u
#define WT_HSM_NVM_FLASH_BASE_NS   0x081FC000u
#define WT_HSM_NVM_FLASH_BASE_S    0x0C1FC000u
#define WT_HSM_NVM_FLASH_SIZE      0x00004000u

/* Conformance-only survive-reset NVM (P5 K2): one reserved sector directly
 * below the wolfHSM NVM store, backing the Arm DRIVER partition's NVMEM so
 * val's boot flag survives an AIRCR.SYSRESETREQ reboot. */
#define WT_CONF_NVM_FLASH_BASE_NS  0x081FA000u
#define WT_CONF_NVM_FLASH_BASE_S   0x0C1FA000u
#define WT_CONF_NVM_FLASH_SIZE     0x00002000u

#define WT_RAM_NS_BASE           0x20000000u
/* Where a guest exception frame may legitimately be stacked. */
#define WT_PLATFORM_GUEST_STACK_WINDOW_BASE WT_RAM_NS_BASE
#define WT_PLATFORM_GUEST_STACK_WINDOW_SIZE 0x00020000u
#define WT_GUEST0_RAM_BASE       0x20000000u
#define WT_GUEST1_RAM_BASE       0x20010000u
#define WT_GUEST_RAM_SIZE        0x00010000u

#define WT_RAM_S_BASE            0x30028000u
#define WT_RAM_S_SIZE            0x00080000u
/* wolfBoot writes its measured-boot record here; the scratch up to
 * WT_RAM_S_BASE is cleared once the record is consumed. */
#define WT_BOOT_HANDOFF_ADDRESS  0x30020000u

/* Secure per-partition stacks (WT-FFM-0011 Level 3 isolation). Each Secure
 * Partition runs on its own secure stack so the secure MPU can confine it to
 * its own domain. Carved from the top of the secure RAM window that the linker
 * uses (0x30028000 + 440 KiB .. 0x300A0000, the end of physical SRAM); the
 * main stack (_estack) drops to 0x30096000 to make room. Slots 2-4 host the
 * PSA-FF conformance partitions (SERVER/DRIVER/CLIENT) in the conformance
 * build. These MUST match the SPSTACKS region in
 * src/services/wolfhsm/runner/secure.ld. */
#define WT_SP_SECURE_STACK_SIZE  0x00002000u   /* 8 KiB per partition */
#define WT_SP_SECURE_STACK_COUNT 5u
#define WT_SP_SECURE_RAM_SIZE \
    (WT_SP_SECURE_STACK_SIZE * WT_SP_SECURE_STACK_COUNT)
#define WT_SP_SECURE_RAM_BASE    (WT_RAM_S_BASE + 0x0006E000u)  /* 0x30096000 */
#define WT_SP_SECURE_RAM_END \
    (WT_SP_SECURE_RAM_BASE + WT_SP_SECURE_RAM_SIZE)             /* 0x300A0000 */
#define WT_SP_CRYPTO_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 0u * WT_SP_SECURE_STACK_SIZE)      /* 0x30096000 */
#define WT_SP_ATTEST_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 1u * WT_SP_SECURE_STACK_SIZE)      /* 0x30098000 */
#define WT_SP_FF_SERVER_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 2u * WT_SP_SECURE_STACK_SIZE)      /* 0x3009A000 */
#define WT_SP_FF_DRIVER_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 3u * WT_SP_SECURE_STACK_SIZE)      /* 0x3009C000 */
#define WT_SP_FF_CLIENT_STACK_BASE \
    (WT_SP_SECURE_RAM_BASE + 4u * WT_SP_SECURE_STACK_SIZE)      /* 0x3009E000 */

/* Conformance Secure-Partition .data/.bss window (P3a). Arm's partition sources
 * keep val_api/psa_api in .data; a hosted SP reaches its own data here while
 * SPM RAM at 0x30028000 stays outside its MPU domain. Sits just below the SP
 * stacks (the linker's RAM window is shortened to make room); MUST match the
 * CONFDATA region in src/services/wolfhsm/runner/secure.ld. */
#define WT_CONF_SP_DATA_BASE     (WT_RAM_S_BASE + 0x0006B000u)  /* 0x30093000 */
#define WT_CONF_SP_DATA_SIZE     0x00003000u                    /* 12 KiB */

/* Vault partition stack (WT-FFM-0047). The vault runs as a confined,
 * unprivileged scheduled SP; this band is its execution stack and MPU-domain
 * RW resource. NVM and flash operations cross the privileged SVC gate.
 * Sits just below the conformance data window; the linker RAM window is
 * shortened to 420 KiB to make room. MUST match the VAULTSTACK region in
 * src/services/wolfhsm/runner/secure.ld. */
/* 16 KiB: ECC verify's arbitrary-point multiply (sp_256_ecc_mulmod_fast_8)
 * stacks a point table that overflows an 8 KiB coroutine stack (M33MU
 * PSPLIM STKOF proof). */
#define WT_SP_VAULT_STACK_BASE   (WT_RAM_S_BASE + 0x00067000u)  /* 0x3008F000 */
#define WT_SP_VAULT_STACK_SIZE   0x00004000u

/* ITS partition stack: a normal unprivileged scheduled SP; this band is both
 * its execution stack and its MPU-domain RW resource. Sits just below the
 * vault stack; the linker RAM window is shortened to 412 KiB to make room.
 * MUST match the ITSSTACK region in src/services/wolfhsm/runner/secure.ld. */
#define WT_SP_ITS_STACK_BASE     (WT_RAM_S_BASE + 0x00065000u)  /* 0x3008D000 */
#define WT_SP_ITS_STACK_SIZE     WT_SP_SECURE_STACK_SIZE

#define WT_SP_PS_STACK_BASE      (WT_RAM_S_BASE + 0x00063000u)  /* 0x3008B000 */
#define WT_SP_PS_STACK_SIZE      WT_SP_SECURE_STACK_SIZE

/* FWU partition stack: the PSA Firmware Update service runs as a confined,
 * unprivileged scheduled SP. This band is its execution stack and MPU-domain
 * RW resource; flash operations cross the privileged SVC gate. Sits just
 * below the PS stack; the linker RAM window is shortened to 388 KiB to make
 * room. MUST match the FWUSTACK region in secure.ld. */
#define WT_SP_FWU_STACK_BASE     (WT_RAM_S_BASE + 0x00061000u)  /* 0x30089000 */
#define WT_SP_FWU_STACK_SIZE     WT_SP_SECURE_STACK_SIZE

/* wolfHSM keystore trust band: the shared server, NVM, and lock state the
 * confined keystore partitions (attest, relay, vault) are granted while
 * running unprivileged. Mirrors the KEYSTORE region in secure.ld. */
#define WT_KEYSTORE_BASE         (WT_RAM_S_BASE + 0x0004D000u)  /* 0x30075000 */
#define WT_KEYSTORE_SIZE         0x00014000u                    /* 80 KiB */

/* VNET partition stack (CONFIG_VNET builds): SERVICE_VNET's scheduled
 * coroutine stack aliases the conformance data window - VNET and
 * WT_CONFORMANCE builds are mutually exclusive, and the window is empty
 * outside conformance builds, so the secure RAM chain needs no growth.
 * MUST match the CONFDATA origin in src/services/wolfhsm/runner/secure.ld
 * and the manifest-vnet.json domain stack. */
#define WT_SP_VNET_STACK_BASE    (WT_RAM_S_BASE + 0x0006B000u)  /* 0x30093000 */
#define WT_SP_VNET_STACK_SIZE    WT_SP_SECURE_STACK_SIZE

/* VNET data band (CONFIG_VNET builds): every RAM object the confined
 * SERVICE_VNET partition touches in-thread — the switch, its pools/rings/FDB,
 * and the relay's staging scratch — carved from the tail of general secure RAM
 * so the unprivileged coroutine reaches only its own state. MUST match the
 * VNETDATA region in src/services/wolfhsm/runner/secure.ld and the
 * manifest-vnet.json domain resource. */
#define WT_VNET_DATA_BASE        (WT_RAM_S_BASE + 0x00048000u)  /* 0x30070000 */
#define WT_VNET_DATA_SIZE        0x00005000u                    /* 20 KiB */

/* wolfBoot update partition (WOLFBOOT_PARTITION_UPDATE_ADDRESS): the secure
 * flash window SERVICE_FWU stages a candidate image into (WT-FWU-0002). Secure
 * alias, inside the writable secure-alias MPU region. */
#define WT_FWU_UPDATE_FLASH_BASE_S 0x0C100000u
#define WT_FWU_UPDATE_FLASH_SIZE   0x00040000u

/* Per-partition pseudo-MMIO holes at the top of the CONFDATA window (P4/K4).
 * Each belongs to exactly one Arm conformance partition; the scheduler grants
 * every other SP the window WITHOUT its hole, so the L3 MMIO-isolation panic
 * tests (i047/i055/i057) see a genuine out-of-domain access. MUST match
 * SERVER/DRIVER_PARTITION_MMIO_0_* in conformance/pal_config.h (guarded by an
 * #error cross-check in conformance/conf_nvm_sync.c) and stay above _econfbss
 * (link-time assert in runner/secure.ld). */
#define WT_CONF_SERVER_MMIO_BASE (WT_CONF_SP_DATA_BASE + 0x00002C00u) /* 0x30095C00 */
#define WT_CONF_SERVER_MMIO_SIZE 0x00000100u
#define WT_CONF_DRV_MMIO_BASE    (WT_CONF_SP_DATA_BASE + 0x00002E00u) /* 0x30095E00 */
#define WT_CONF_DRV_MMIO_SIZE    0x00000100u

#define WT_SHARED_STATUS_ADDR    0x20000000u

#define WT_PLATFORM_CORE_CLOCK_HZ 240000000u

#endif
