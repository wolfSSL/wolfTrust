# Architecture- and target-neutral half of the secure image build. Included
# last, after mk/target-<soc>.mk and mk/arch-<arch>.mk supply the TARGET_* and
# ARCH_* inputs; repository paths come from the Makefile.
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size

MANIFEST_DIR := $(BUILD_DIR)/manifest
MANIFEST_STAMP := $(MANIFEST_DIR)/.stamp
MANIFEST_GEN_C := $(MANIFEST_DIR)/wolftrust_manifest_generated.c
MANIFEST_GEN_H := $(MANIFEST_DIR)/wolftrust_manifest_generated.h
SECURE_ELF := $(BUILD_DIR)/wolftrust.elf
SECURE_BIN := $(BUILD_DIR)/wolftrust.bin
BUILD_MODE_STAMP := $(BUILD_DIR)/secure_build_mode.stamp
WOLFHSM_CFG_H := $(BUILD_DIR)/wolfhsm_cfg.h

WT_TIMESLICE_MS ?= 2
WT_MAX_GUESTS ?= 2
# Per-tasklet coroutine stack. 10K measured with >=2K headroom: the M33MU
# deep set (positive, devcrypto 78-test ECC, confboot 85/4) runs clean at
# 8K with no PSPLIM overflow, so peak use is under 8K. The old 24K predated
# the SP_SMALL math switch; PSPLIM_S faults any real overflow, so this floor
# is measured, not guessed.
WT_CO_STACK_SIZE ?= 10240
# Secure crypto engine. native (the default) calls wolfCrypt directly; hsm
# links the wolfHSM server as a key-management add-on. Legacy WT_ENGINE_HSM
# values map onto the selector.
WT_ENGINE_LEGACY :=
ifeq ($(WT_ENGINE_HSM),0)
WT_ENGINE_LEGACY := native
endif
ifeq ($(WT_ENGINE_HSM),1)
WT_ENGINE_LEGACY := hsm
endif
ifneq ($(WT_ENGINE_HSM),)
ifeq ($(WT_ENGINE_LEGACY),)
$(error unsupported WT_ENGINE_HSM='$(WT_ENGINE_HSM)' (want 0 or 1))
endif
endif
ifneq ($(WT_ENGINE_LEGACY),)
ifneq ($(WT_ENGINE),)
ifneq ($(WT_ENGINE),$(WT_ENGINE_LEGACY))
$(error conflicting engine selectors: WT_ENGINE=$(WT_ENGINE) but WT_ENGINE_HSM=$(WT_ENGINE_HSM) selects $(WT_ENGINE_LEGACY))
endif
endif
WT_ENGINE := $(WT_ENGINE_LEGACY)
endif
WT_ENGINE ?= native
ifneq ($(words $(WT_ENGINE))/$(filter native hsm,$(WT_ENGINE)),1/$(WT_ENGINE))
$(error unsupported WT_ENGINE='$(WT_ENGINE)' (want native or hsm))
endif
ifeq ($(WT_ENGINE),hsm)
WT_ENGINE_HSM := 1
else
WT_ENGINE_HSM := 0
endif
WT_ATTEST_COSE ?= 1
WT_FFM_NEGATIVE_PROBE ?= 0
WT_KEYSTORE_NEG_PROBE ?= 0
WT_LAUNCH_DEBUG ?= 0
WT_ROLLBACK_PROBE ?= 0
WT_SP_FAULT_PROBE ?= 0
WT_SP_FAULT_ALWAYS_PROBE ?= 0
WT_PANIC_NEG_PROBE ?= 0
WT_VNET_NEG_PROBE ?= 0
WT_MANIFEST_NEG_PROBE ?= 0
WT_REMEASURE_PROBE ?= 0
WT_BOOTUPDATE_PROBE ?= 0
WT_CONFORMANCE ?= 0

# Virtual-Ethernet (VNET) subsystem. Off until Wave 2 lands a working
# core. Host-side unit tests under tests/host/vnet/ build regardless;
# this switch only gates linking the dataplane and NSC veneers into
# the secure image.
CONFIG_VNET ?= n
WT_VNET_POOL_SLOTS ?= 8
WT_VNET_FRAME_MAX ?= 1536
WT_VNET_RX_QUEUE_DEPTH ?= 8
WT_VNET_RX_IRQ ?= 130
WT_VNET_TIMEOUT_TICKS ?= 500
WT_VNET_UNKNOWN_UCAST_FLOOD ?= 0

HSM_INCLUDES := -I$(WOLFHSM_DIR) -I$(WOLFSSL_DIR) -I$(BUILD_DIR)
HSM_INCLUDES_SECURE := $(HSM_INCLUDES) -I$(WOLFHAL_DIR) -I$(abspath $(WOLFHSM_RUNNER_DIR))
HSM_DEFS_SECURE := -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG \
    -UNO_CODING \
    -DWC_RESEED_INTERVAL=1000000 \
    $(ARCH_HSM_DEFS)
ifeq ($(WT_ENGINE),hsm)
HSM_DEFS_SECURE += -DWOLF_CRYPTO_CB -DWT_ENGINE_HSM=1
else
# Native links only the wolfHSM NVM object store; NO_CRYPTO drops the server's
# wolfCrypt dependency (and its WOLF_CRYPTO_CB requirement).
HSM_DEFS_SECURE += -DWT_ENGINE_NATIVE=1 -DWOLFHSM_CFG_NO_CRYPTO
endif

ifeq ($(WT_ATTEST_COSE),1)
SECURE_CFLAGS_COSE := -I$(WOLFCOSE_DIR)/include \
    -DWT_ATTEST_COSE=1 \
    -DWOLFCOSE_LEAN -DWOLFCOSE_ENABLE_EXT_SIGN -DWOLFCOSE_ENABLE_DEPRECATED_ALGS \
    -DWOLFCOSE_NO_SIGN1_VERIFY -DWOLFCOSE_NO_ENCRYPT0 \
    -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_KEY_ENCODE \
    -DWOLFCOSE_NO_KEY_DECODE \
    -DWOLFCOSE_ENABLE_EAT_PSA \
    -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
    -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
    -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE
endif

SECURE_CFLAGS := $(CPU_FLAGS) -std=c99 -ffreestanding -fno-builtin -nostdlib -Os -g \
    -ffunction-sections -fdata-sections -Wall -Wextra \
    -I$(ROOT)/include -I$(PORT_DIR) \
    -DWT_TIMESLICE_MS=$(WT_TIMESLICE_MS) \
    -DWT_MAX_GUESTS=$(WT_MAX_GUESTS) \
    -DWT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE) \
    $(TARGET_CFLAGS) \
    $(ARCH_CFLAGS) \
    $(HSM_INCLUDES_SECURE) $(HSM_DEFS_SECURE) $(SECURE_CFLAGS_COSE) \
    -I$(MANIFEST_DIR)
SECURE_CFLAGS += $(WT_EXTRA_CFLAGS)

ifeq ($(CONFIG_VNET),y)
SECURE_CFLAGS += -DCONFIG_VNET=1 \
    -DWT_VNET_POOL_SLOTS=$(WT_VNET_POOL_SLOTS) \
    -DWT_VNET_FRAME_MAX=$(WT_VNET_FRAME_MAX) \
    -DWT_VNET_RX_QUEUE_DEPTH=$(WT_VNET_RX_QUEUE_DEPTH) \
    -DWT_VNET_RX_IRQ=$(WT_VNET_RX_IRQ) \
    -DWT_VNET_TIMEOUT_TICKS=$(WT_VNET_TIMEOUT_TICKS) \
    -DWT_VNET_UNKNOWN_UCAST_FLOOD=$(WT_VNET_UNKNOWN_UCAST_FLOOD)
WT_VNET_DATA_LENGTH := 0x5000
else
WT_VNET_DATA_LENGTH := 0
endif

ifeq ($(WT_LAUNCH_DEBUG),1)
SECURE_CFLAGS += -DWT_LAUNCH_DEBUG=1
endif
ifeq ($(WT_ROLLBACK_PROBE),1)
SECURE_CFLAGS += -DWT_ROLLBACK_PROBE=1
endif
ifeq ($(WT_FFM_NEGATIVE_PROBE),1)
SECURE_CFLAGS += -DWT_FFM_NEGATIVE_PROBE=1
endif
ifeq ($(WT_KEYSTORE_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_KEYSTORE_NEG_PROBE=1
endif
ifeq ($(WT_SP_FAULT_PROBE),1)
SECURE_CFLAGS += -DWT_SP_FAULT_PROBE=1
endif
ifeq ($(WT_SP_FAULT_ALWAYS_PROBE),1)
SECURE_CFLAGS += -DWT_SP_FAULT_ALWAYS_PROBE=1
endif
ifeq ($(WT_PANIC_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_PANIC_NEG_PROBE=1
endif
ifeq ($(WT_VNET_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_VNET_NEG_PROBE=1
endif
ifeq ($(WT_MANIFEST_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_MANIFEST_NEG_PROBE=1
endif
ifeq ($(WT_REMEASURE_PROBE),1)
SECURE_CFLAGS += -DWT_REMEASURE_PROBE=1
endif
ifeq ($(WT_BOOTUPDATE_PROBE),1)
SECURE_CFLAGS += -DWT_BOOTUPDATE_PROBE=1
endif
# Hardware guest-flash write protection: refuse to launch a guest whose image
# sectors are not WRP-protected, so a peer Non-secure guest cannot reprogram a
# suspended guest's flash. Silicon only (the M33MU model has no flash WRP).
WT_GUEST_FLASH_WRP ?= 0
ifeq ($(WT_GUEST_FLASH_WRP),1)
SECURE_CFLAGS += -DWT_GUEST_FLASH_WRP=1
endif

# Vault recovery negative test: force the foreign-pool ACCESS at first
# provisioning so the lifecycle-gated reformat path runs. WT_VAULT_PROBE_SECURED
# additionally forces a locked lifecycle to exercise the fail-closed branch.
WT_VAULT_FOREIGN_PROBE ?= 0
ifeq ($(WT_VAULT_FOREIGN_PROBE),1)
SECURE_CFLAGS += -DWT_VAULT_FOREIGN_PROBE=1
endif
WT_VAULT_PROBE_SECURED ?= 0
ifeq ($(WT_VAULT_PROBE_SECURED),1)
SECURE_CFLAGS += -DWT_VAULT_PROBE_SECURED=1
endif

HSM_LIB_CFLAGS := $(SECURE_CFLAGS) \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter \
    -Wno-type-limits
HSM_WOLFHSM_CFLAGS := $(HSM_LIB_CFLAGS)

SECURE_SRCS := \
    $(ARCH_START_SRCS) \
    $(WOLFHSM_RUNNER_DIR)/runtime.c \
    $(TARGET_PLATFORM_SRC) \
    $(ROOT)/src/domain.c \
    $(ROOT)/src/ffm.c \
    $(ROOT)/src/ffm_boot.c \
    $(ROOT)/src/ffm_domain.c \
    $(ROOT)/src/guest_verify.c \
    $(ROOT)/src/ipc.c \
    $(ROOT)/src/restart_policy.c \
    $(ROOT)/src/rollback.c \
    $(ROOT)/src/sp_recovery.c \
    $(ROOT)/src/spm_gate.c \
    $(ROOT)/src/manifest.c \
    $(ROOT)/src/monitor.c \
    $(ROOT)/src/spm.c \
    $(ROOT)/src/boot.c \
    $(ROOT)/src/spm_partitions.c \
    $(ROOT)/src/partition.c \
    $(TARGET_PARTITIONS_SRC)

WOLFHSM_SECURE_SRCS := \
    $(WOLFHSM_DIR)/src/wh_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_crypto.c \
    $(WOLFHSM_DIR)/src/wh_message_keystore.c \
    $(WOLFHSM_DIR)/src/wh_message_nvm.c \
    $(WOLFHSM_DIR)/src/wh_message_customcb.c \
    $(WOLFHSM_DIR)/src/wh_message_counter.c \
    $(WOLFHSM_DIR)/src/wh_nvm.c \
    $(WOLFHSM_DIR)/src/wh_nvm_flash.c \
    $(WOLFHSM_DIR)/src/wh_flash_unit.c \
    $(WOLFHSM_DIR)/src/wh_server.c \
    $(WOLFHSM_DIR)/src/wh_server_crypto.c \
    $(WOLFHSM_DIR)/src/wh_server_keystore.c \
    $(WOLFHSM_DIR)/src/wh_server_nvm.c \
    $(WOLFHSM_DIR)/src/wh_server_customcb.c \
    $(WOLFHSM_DIR)/src/wh_server_counter.c \
    $(WOLFHSM_DIR)/src/wh_transport_mem.c \
    $(WOLFHSM_DIR)/src/wh_lock.c \
    $(WOLFHSM_DIR)/src/wh_utils.c \
    $(WOLFHSM_DIR)/src/wh_crypto.c \
    $(WOLFHSM_DIR)/src/wh_keyid.c

# Native engine keeps only the self-contained NVM object store (vault/ITS/PS/FWU
# ride it); the wolfHSM server, comm, and message layers are hsm-only.
ifeq ($(WT_ENGINE),native)
WOLFHSM_SECURE_SRCS := $(filter %/wh_nvm.c %/wh_nvm_flash.c %/wh_flash_unit.c \
    %/wh_lock.c %/wh_utils.c %/wh_keyid.c,$(WOLFHSM_SECURE_SRCS))
endif

WOLFCRYPT_SECURE_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/logging.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
    $(ARCH_WOLFCRYPT_SP_SRCS) \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c
WOLFCRYPT_SECURE_SRCS += $(ARCH_WOLFCRYPT_ASM_SRCS)

WT_SECURE_EXTRA_SRCS := \
    $(ARCH_SRCS) \
    $(ROOT)/src/arch/common/spm_gate_core.c \
    $(ROOT)/src/arch/common/spm_sp_api.c \
    $(ROOT)/src/arch/common/ffm_gateway.c \
    $(ROOT)/src/sched/coroutine.c \
    $(ROOT)/src/sync/mutex.c \
    $(TARGET_EXTRA_SRCS) \
    $(wildcard $(WOLFHSM_RUNNER_DIR)/libc_stubs.c) \
    $(wildcard $(ROOT)/src/services/wolfhsm/*.c) \
    $(ROOT)/src/services/nvm_store.c \
    $(ROOT)/src/services/boot_handoff.c \
    $(ROOT)/src/services/hsm_relay_service.c \
    $(ROOT)/src/services/storage_service.c \
    $(ROOT)/src/services/fwu_service.c \
    $(ROOT)/src/services/vault_service.c

# Engine split: wt_hsm.c drives the wolfHSM server (hsm engine only); the
# native engine dispatches wolfCrypt directly behind the same SERVICE_HSM
# door and keeps the server-free vault/seal/lock glue over the shared store.
ifeq ($(WT_ENGINE),native)
WT_SECURE_EXTRA_SRCS := $(filter-out %/wolfhsm/wt_hsm.c,$(WT_SECURE_EXTRA_SRCS))
WT_SECURE_EXTRA_SRCS += \
    $(ROOT)/src/services/native/crypto_native.c \
    $(ROOT)/src/services/native/native_wire.c \
    $(ROOT)/src/services/native/keyvault.c
endif

ifeq ($(WT_ATTEST_COSE),1)
WT_SECURE_EXTRA_SRCS += \
    $(ROOT)/src/services/attestation_cose.c \
    $(ROOT)/src/services/attestation_service.c \
    $(ROOT)/src/services/initial_attestation.c \
    $(WOLFCOSE_DIR)/src/wolfcose_cbor.c \
    $(WOLFCOSE_DIR)/src/wolfcose_util.c \
    $(WOLFCOSE_DIR)/src/wolfcose_alg.c \
    $(WOLFCOSE_DIR)/src/wolfcose_ecc.c \
    $(WOLFCOSE_DIR)/src/wolfcose_hdr.c \
    $(WOLFCOSE_DIR)/src/wolfcose_key.c \
    $(WOLFCOSE_DIR)/src/wolfcose_struct.c \
    $(WOLFCOSE_DIR)/src/wolfcose_recipient.c \
    $(WOLFCOSE_DIR)/src/wolfcose_sign1.c \
    $(WOLFCOSE_DIR)/src/wolfcose_sign.c \
    $(WOLFCOSE_DIR)/src/wolfcose_countersign.c \
    $(WOLFCOSE_DIR)/src/wolfcose_encrypt0.c \
    $(WOLFCOSE_DIR)/src/wolfcose_mac0.c \
    $(WOLFCOSE_DIR)/src/wolfcose_encrypt.c \
    $(WOLFCOSE_DIR)/src/wolfcose_mac.c \
    $(WOLFCOSE_DIR)/src/wolfcose_eat_psa.c
endif

ifeq ($(CONFIG_VNET),y)
WT_SECURE_EXTRA_SRCS += \
    $(ROOT)/src/vnet/vnet_mac.c    \
    $(ROOT)/src/vnet/vnet_pool.c   \
    $(ROOT)/src/vnet/vnet_ring.c   \
    $(ROOT)/src/vnet/vnet_fdb.c    \
    $(ROOT)/src/vnet/vnet_switch.c \
    $(ROOT)/src/services/vnet/vnet_service.c \
    $(ROOT)/src/services/vnet/vnet_relay_service.c
endif

HSM_SECURE_BASE_OBJS := $(patsubst %.c,$(BUILD_DIR)/sec_%.o,$(notdir $(SECURE_SRCS)))
HSM_WOLFHSM_SEC_OBJS := $(patsubst %.c,$(BUILD_DIR)/wh_sec_%.o,$(notdir $(WOLFHSM_SECURE_SRCS)))
HSM_WOLFCRYPT_SEC_OBJS := $(patsubst %.c,$(BUILD_DIR)/wc_sec_%.o,$(notdir $(WOLFCRYPT_SECURE_SRCS)))
HSM_WT_EXTRA_OBJS := $(patsubst %.c,$(BUILD_DIR)/wt_sec_%.o,$(notdir $(WT_SECURE_EXTRA_SRCS)))
MANIFEST_OBJ := $(BUILD_DIR)/wt_sec_wolftrust_manifest_generated.o
# Arch sources that live in subdirectories of src/arch/<arch>/ (C or assembly);
# each gets its own rule below because the pattern rules key on one directory.
ARCH_TREE_SRCS ?=
ARCH_ASM_SRCS ?=
ARCH_TREE_OBJS := $(foreach s,$(ARCH_TREE_SRCS) $(ARCH_ASM_SRCS),$(BUILD_DIR)/wt_sec_$(notdir $(basename $(s))).o)

ALL_SECURE_OBJS := $(strip \
    $(HSM_SECURE_BASE_OBJS) \
    $(HSM_WOLFHSM_SEC_OBJS) \
    $(HSM_WOLFCRYPT_SEC_OBJS) \
    $(HSM_WT_EXTRA_OBJS) \
    $(ARCH_TREE_OBJS) \
    $(MANIFEST_OBJ))

# Arm PSA-FF conformance partitions (P3a): the unmodified upstream server and
# client partitions plus the i001/i002 test bodies, compiled into the secure
# image and scheduled as SPs. P3c regenerates the test lists over the full run
# range; P3b adds the driver partition.
ifeq ($(WT_CONFORMANCE),1)
SECURE_CFLAGS += -DWT_CONFORMANCE=1
# WT_CONF_DIAG_TRAP=0 (hardware): the hang-probe diag trap deliberately faults
# for the emulator's register dump; on silicon that fault becomes a
# conformance-monitor reset that can eat the suite's report window.
WT_CONF_DIAG_TRAP ?= 1
SECURE_CFLAGS += -DWT_CONF_DIAG_TRAP=$(WT_CONF_DIAG_TRAP)
UPSTREAM_DIR := $(BUILD_DIR)/upstream/psa-arch-tests/api-tests
UPSTREAM_STAMP := $(BUILD_DIR)/.psa-arch-tests.stamp
CONF_GEN_STAMP := $(MANIFEST_DIR)/.conformance-gen.stamp
# VERBOSITY=9: SP-side val prints route over IPC to the DRIVER UART partition,
# which does not run until P3b; below-ALWAYS prints short-circuit instead of
# deadlocking on a service nobody serves.
CONF_CFLAGS = $(SECURE_CFLAGS) -DIPC -DVERBOSITY=9 \
    -I$(UPSTREAM_DIR)/val/common \
    -I$(UPSTREAM_DIR)/val/nspe \
    -I$(UPSTREAM_DIR)/val/spe \
    -I$(UPSTREAM_DIR)/ff/partition \
    -I$(UPSTREAM_DIR)/platform/targets/common/nspe \
    -I$(TARGET_CONF_DIR) \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter

CONF_SEC_OBJS := \
    $(BUILD_DIR)/conf_sec_server_partition.o \
    $(BUILD_DIR)/conf_sec_client_partition.o \
    $(BUILD_DIR)/conf_sec_driver_partition.o \
    $(BUILD_DIR)/conf_sec_val_driver_service_apis.o \
    $(BUILD_DIR)/conf_sec_val_log.o \
    $(BUILD_DIR)/conf_sec_pal_driver_intf.o \
    $(BUILD_DIR)/conf_sec_conf_nvm_sync.o \
    $(BUILD_DIR)/conf_sec_test_i001.o \
    $(BUILD_DIR)/conf_sec_test_supp_i001.o \
    $(BUILD_DIR)/conf_sec_test_i002.o \
    $(BUILD_DIR)/conf_sec_test_supp_i002.o \
    $(BUILD_DIR)/conf_sec_test_i003.o \
    $(BUILD_DIR)/conf_sec_test_supp_i003.o \
    $(BUILD_DIR)/conf_sec_test_i004.o \
    $(BUILD_DIR)/conf_sec_test_supp_i004.o \
    $(BUILD_DIR)/conf_sec_test_i005.o \
    $(BUILD_DIR)/conf_sec_test_supp_i005.o \
    $(BUILD_DIR)/conf_sec_test_i006.o \
    $(BUILD_DIR)/conf_sec_test_supp_i006.o \
    $(BUILD_DIR)/conf_sec_test_i007.o \
    $(BUILD_DIR)/conf_sec_test_supp_i007.o \
    $(BUILD_DIR)/conf_sec_test_i008.o \
    $(BUILD_DIR)/conf_sec_test_supp_i008.o \
    $(BUILD_DIR)/conf_sec_test_i009.o \
    $(BUILD_DIR)/conf_sec_test_supp_i009.o \
    $(BUILD_DIR)/conf_sec_test_i010.o \
    $(BUILD_DIR)/conf_sec_test_supp_i010.o \
    $(BUILD_DIR)/conf_sec_test_i011.o \
    $(BUILD_DIR)/conf_sec_test_supp_i011.o \
    $(BUILD_DIR)/conf_sec_test_i012.o \
    $(BUILD_DIR)/conf_sec_test_supp_i012.o \
    $(BUILD_DIR)/conf_sec_test_i013.o \
    $(BUILD_DIR)/conf_sec_test_supp_i013.o \
    $(BUILD_DIR)/conf_sec_test_i014.o \
    $(BUILD_DIR)/conf_sec_test_supp_i014.o \
    $(BUILD_DIR)/conf_sec_test_i015.o \
    $(BUILD_DIR)/conf_sec_test_supp_i015.o \
    $(BUILD_DIR)/conf_sec_test_i016.o \
    $(BUILD_DIR)/conf_sec_test_supp_i016.o \
    $(BUILD_DIR)/conf_sec_test_i017.o \
    $(BUILD_DIR)/conf_sec_test_supp_i017.o \
    $(BUILD_DIR)/conf_sec_test_i018.o \
    $(BUILD_DIR)/conf_sec_test_supp_i018.o \
    $(BUILD_DIR)/conf_sec_test_i019.o \
    $(BUILD_DIR)/conf_sec_test_supp_i019.o \
    $(BUILD_DIR)/conf_sec_test_i020.o \
    $(BUILD_DIR)/conf_sec_test_supp_i020.o \
    $(BUILD_DIR)/conf_sec_test_i021.o \
    $(BUILD_DIR)/conf_sec_test_supp_i021.o \
    $(BUILD_DIR)/conf_sec_test_i022.o \
    $(BUILD_DIR)/conf_sec_test_supp_i022.o \
    $(BUILD_DIR)/conf_sec_test_i023.o \
    $(BUILD_DIR)/conf_sec_test_supp_i023.o \
    $(BUILD_DIR)/conf_sec_test_i024.o \
    $(BUILD_DIR)/conf_sec_test_supp_i024.o \
    $(BUILD_DIR)/conf_sec_test_i025.o \
    $(BUILD_DIR)/conf_sec_test_supp_i025.o \
    $(BUILD_DIR)/conf_sec_test_i026.o \
    $(BUILD_DIR)/conf_sec_test_supp_i026.o \
    $(BUILD_DIR)/conf_sec_test_i027.o \
    $(BUILD_DIR)/conf_sec_test_supp_i027.o \
    $(BUILD_DIR)/conf_sec_test_i028.o \
    $(BUILD_DIR)/conf_sec_test_supp_i028.o \
    $(BUILD_DIR)/conf_sec_test_i029.o \
    $(BUILD_DIR)/conf_sec_test_supp_i029.o \
    $(BUILD_DIR)/conf_sec_test_i030.o \
    $(BUILD_DIR)/conf_sec_test_supp_i030.o \
    $(BUILD_DIR)/conf_sec_test_i031.o \
    $(BUILD_DIR)/conf_sec_test_supp_i031.o \
    $(BUILD_DIR)/conf_sec_test_i032.o \
    $(BUILD_DIR)/conf_sec_test_supp_i032.o \
    $(BUILD_DIR)/conf_sec_test_i033.o \
    $(BUILD_DIR)/conf_sec_test_supp_i033.o \
    $(BUILD_DIR)/conf_sec_test_i034.o \
    $(BUILD_DIR)/conf_sec_test_supp_i034.o \
    $(BUILD_DIR)/conf_sec_test_i035.o \
    $(BUILD_DIR)/conf_sec_test_supp_i035.o \
    $(BUILD_DIR)/conf_sec_test_i036.o \
    $(BUILD_DIR)/conf_sec_test_supp_i036.o \
    $(BUILD_DIR)/conf_sec_test_i037.o \
    $(BUILD_DIR)/conf_sec_test_supp_i037.o \
    $(BUILD_DIR)/conf_sec_test_i038.o \
    $(BUILD_DIR)/conf_sec_test_supp_i038.o \
    $(BUILD_DIR)/conf_sec_test_i039.o \
    $(BUILD_DIR)/conf_sec_test_supp_i039.o \
    $(BUILD_DIR)/conf_sec_test_i040.o \
    $(BUILD_DIR)/conf_sec_test_supp_i040.o \
    $(BUILD_DIR)/conf_sec_test_i041.o \
    $(BUILD_DIR)/conf_sec_test_supp_i041.o \
    $(BUILD_DIR)/conf_sec_test_i042.o \
    $(BUILD_DIR)/conf_sec_test_supp_i042.o \
    $(BUILD_DIR)/conf_sec_test_i043.o \
    $(BUILD_DIR)/conf_sec_test_supp_i043.o \
    $(BUILD_DIR)/conf_sec_test_i044.o \
    $(BUILD_DIR)/conf_sec_test_supp_i044.o \
    $(BUILD_DIR)/conf_sec_test_i045.o \
    $(BUILD_DIR)/conf_sec_test_supp_i045.o \
    $(BUILD_DIR)/conf_sec_test_i046.o \
    $(BUILD_DIR)/conf_sec_test_supp_i046.o \
    $(BUILD_DIR)/conf_sec_test_i047.o \
    $(BUILD_DIR)/conf_sec_test_supp_i047.o \
    $(BUILD_DIR)/conf_sec_test_i048.o \
    $(BUILD_DIR)/conf_sec_test_supp_i048.o \
    $(BUILD_DIR)/conf_sec_test_i049.o \
    $(BUILD_DIR)/conf_sec_test_supp_i049.o \
    $(BUILD_DIR)/conf_sec_test_i050.o \
    $(BUILD_DIR)/conf_sec_test_supp_i050.o \
    $(BUILD_DIR)/conf_sec_test_i051.o \
    $(BUILD_DIR)/conf_sec_test_supp_i051.o \
    $(BUILD_DIR)/conf_sec_test_i052.o \
    $(BUILD_DIR)/conf_sec_test_supp_i052.o \
    $(BUILD_DIR)/conf_sec_test_i053.o \
    $(BUILD_DIR)/conf_sec_test_supp_i053.o \
    $(BUILD_DIR)/conf_sec_test_i054.o \
    $(BUILD_DIR)/conf_sec_test_supp_i054.o \
    $(BUILD_DIR)/conf_sec_test_i055.o \
    $(BUILD_DIR)/conf_sec_test_supp_i055.o \
    $(BUILD_DIR)/conf_sec_test_i057.o \
    $(BUILD_DIR)/conf_sec_test_supp_i057.o \
    $(BUILD_DIR)/conf_sec_test_i058.o \
    $(BUILD_DIR)/conf_sec_test_supp_i058.o \
    $(BUILD_DIR)/conf_sec_test_i063.o \
    $(BUILD_DIR)/conf_sec_test_supp_i063.o \
    $(BUILD_DIR)/conf_sec_test_i064.o \
    $(BUILD_DIR)/conf_sec_test_supp_i064.o \
    $(BUILD_DIR)/conf_sec_test_i065.o \
    $(BUILD_DIR)/conf_sec_test_supp_i065.o \
    $(BUILD_DIR)/conf_sec_test_i066.o \
    $(BUILD_DIR)/conf_sec_test_supp_i066.o \
    $(BUILD_DIR)/conf_sec_test_i071.o \
    $(BUILD_DIR)/conf_sec_test_supp_i071.o \
    $(BUILD_DIR)/conf_sec_test_i056.o \
    $(BUILD_DIR)/conf_sec_test_supp_i056.o \
    $(BUILD_DIR)/conf_sec_test_i059.o \
    $(BUILD_DIR)/conf_sec_test_supp_i059.o \
    $(BUILD_DIR)/conf_sec_test_i060.o \
    $(BUILD_DIR)/conf_sec_test_supp_i060.o \
    $(BUILD_DIR)/conf_sec_test_i061.o \
    $(BUILD_DIR)/conf_sec_test_supp_i061.o \
    $(BUILD_DIR)/conf_sec_test_i062.o \
    $(BUILD_DIR)/conf_sec_test_supp_i062.o \
    $(BUILD_DIR)/conf_sec_test_i068.o \
    $(BUILD_DIR)/conf_sec_test_supp_i068.o \
    $(BUILD_DIR)/conf_sec_test_i069.o \
    $(BUILD_DIR)/conf_sec_test_supp_i069.o \
    $(BUILD_DIR)/conf_sec_test_i070.o \
    $(BUILD_DIR)/conf_sec_test_supp_i070.o \
    $(BUILD_DIR)/conf_sec_test_i072.o \
    $(BUILD_DIR)/conf_sec_test_supp_i072.o \
    $(BUILD_DIR)/conf_sec_test_i073.o \
    $(BUILD_DIR)/conf_sec_test_supp_i073.o \
    $(BUILD_DIR)/conf_sec_test_i074.o \
    $(BUILD_DIR)/conf_sec_test_supp_i074.o \
    $(BUILD_DIR)/conf_sec_test_i075.o \
    $(BUILD_DIR)/conf_sec_test_supp_i075.o \
    $(BUILD_DIR)/conf_sec_test_i076.o \
    $(BUILD_DIR)/conf_sec_test_supp_i076.o \
    $(BUILD_DIR)/conf_sec_test_i077.o \
    $(BUILD_DIR)/conf_sec_test_supp_i077.o \
    $(BUILD_DIR)/conf_sec_test_i078.o \
    $(BUILD_DIR)/conf_sec_test_supp_i078.o \
    $(BUILD_DIR)/conf_sec_test_i079.o \
    $(BUILD_DIR)/conf_sec_test_supp_i079.o \
    $(BUILD_DIR)/conf_sec_test_i080.o \
    $(BUILD_DIR)/conf_sec_test_supp_i080.o \
    $(BUILD_DIR)/conf_sec_test_i081.o \
    $(BUILD_DIR)/conf_sec_test_supp_i081.o \
    $(BUILD_DIR)/conf_sec_test_i082.o \
    $(BUILD_DIR)/conf_sec_test_supp_i082.o \
    $(BUILD_DIR)/conf_sec_test_i083.o \
    $(BUILD_DIR)/conf_sec_test_supp_i083.o \
    $(BUILD_DIR)/conf_sec_test_i084.o \
    $(BUILD_DIR)/conf_sec_test_supp_i084.o \
    $(BUILD_DIR)/conf_sec_test_i085.o \
    $(BUILD_DIR)/conf_sec_test_supp_i085.o \
    $(BUILD_DIR)/conf_sec_test_i086.o \
    $(BUILD_DIR)/conf_sec_test_supp_i086.o \
    $(BUILD_DIR)/conf_sec_test_i087.o \
    $(BUILD_DIR)/conf_sec_test_supp_i087.o \
    $(BUILD_DIR)/conf_sec_test_i089.o \
    $(BUILD_DIR)/conf_sec_test_supp_i089.o \
    $(BUILD_DIR)/conf_sec_test_i090.o \
    $(BUILD_DIR)/conf_sec_test_supp_i090.o \
    $(BUILD_DIR)/conf_sec_test_i088.o \
    $(BUILD_DIR)/conf_sec_test_supp_i088.o
ALL_SECURE_OBJS += $(CONF_SEC_OBJS)

# The upstream sources only exist after the fetch; the empty-recipe rule tells
# make the fetch stamp produces them so the conf_sec pattern rules can fire.
CONF_UPSTREAM_SRCS := \
    $(UPSTREAM_DIR)/ff/partition/server_partition.c \
    $(UPSTREAM_DIR)/ff/partition/client_partition.c \
    $(UPSTREAM_DIR)/ff/partition/driver_partition.c \
    $(UPSTREAM_DIR)/val/spe/val_driver_service_apis.c \
    $(UPSTREAM_DIR)/val/common/val_log.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i001/test_i001.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i001/test_supp_i001.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i002/test_i002.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i002/test_supp_i002.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i003/test_i003.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i003/test_supp_i003.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i004/test_i004.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i004/test_supp_i004.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i005/test_i005.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i005/test_supp_i005.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i006/test_i006.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i006/test_supp_i006.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i007/test_i007.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i007/test_supp_i007.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i008/test_i008.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i008/test_supp_i008.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i009/test_i009.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i009/test_supp_i009.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i010/test_i010.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i010/test_supp_i010.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i011/test_i011.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i011/test_supp_i011.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i012/test_i012.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i012/test_supp_i012.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i013/test_i013.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i013/test_supp_i013.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i014/test_i014.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i014/test_supp_i014.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i015/test_i015.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i015/test_supp_i015.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i016/test_i016.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i016/test_supp_i016.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i017/test_i017.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i017/test_supp_i017.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i018/test_i018.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i018/test_supp_i018.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i019/test_i019.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i019/test_supp_i019.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i020/test_i020.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i020/test_supp_i020.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i021/test_i021.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i021/test_supp_i021.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i022/test_i022.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i022/test_supp_i022.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i023/test_i023.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i023/test_supp_i023.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i024/test_i024.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i024/test_supp_i024.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i025/test_i025.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i025/test_supp_i025.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i026/test_i026.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i026/test_supp_i026.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i027/test_i027.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i027/test_supp_i027.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i028/test_i028.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i028/test_supp_i028.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i029/test_i029.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i029/test_supp_i029.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i030/test_i030.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i030/test_supp_i030.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i031/test_i031.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i031/test_supp_i031.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i032/test_i032.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i032/test_supp_i032.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i033/test_i033.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i033/test_supp_i033.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i034/test_i034.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i034/test_supp_i034.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i035/test_i035.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i035/test_supp_i035.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i036/test_i036.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i036/test_supp_i036.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i037/test_i037.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i037/test_supp_i037.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i038/test_i038.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i038/test_supp_i038.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i039/test_i039.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i039/test_supp_i039.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i040/test_i040.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i040/test_supp_i040.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i041/test_i041.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i041/test_supp_i041.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i042/test_i042.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i042/test_supp_i042.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i043/test_i043.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i043/test_supp_i043.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i044/test_i044.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i044/test_supp_i044.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i045/test_i045.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i045/test_supp_i045.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i046/test_i046.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i046/test_supp_i046.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i047/test_i047.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i047/test_supp_i047.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i048/test_i048.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i048/test_supp_i048.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i049/test_i049.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i049/test_supp_i049.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i050/test_i050.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i050/test_supp_i050.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i051/test_i051.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i051/test_supp_i051.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i052/test_i052.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i052/test_supp_i052.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i053/test_i053.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i053/test_supp_i053.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i054/test_i054.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i054/test_supp_i054.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i055/test_i055.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i055/test_supp_i055.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i057/test_i057.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i057/test_supp_i057.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i058/test_i058.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i058/test_supp_i058.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i063/test_i063.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i063/test_supp_i063.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i064/test_i064.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i064/test_supp_i064.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i065/test_i065.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i065/test_supp_i065.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i066/test_i066.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i066/test_supp_i066.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i071/test_i071.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i071/test_supp_i071.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i056/test_i056.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i056/test_supp_i056.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i059/test_i059.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i059/test_supp_i059.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i060/test_i060.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i060/test_supp_i060.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i061/test_i061.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i061/test_supp_i061.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i062/test_i062.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i062/test_supp_i062.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i068/test_i068.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i068/test_supp_i068.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i069/test_i069.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i069/test_supp_i069.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i070/test_i070.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i070/test_supp_i070.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i072/test_i072.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i072/test_supp_i072.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i073/test_i073.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i073/test_supp_i073.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i074/test_i074.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i074/test_supp_i074.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i075/test_i075.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i075/test_supp_i075.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i076/test_i076.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i076/test_supp_i076.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i077/test_i077.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i077/test_supp_i077.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i078/test_i078.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i078/test_supp_i078.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i079/test_i079.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i079/test_supp_i079.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i080/test_i080.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i080/test_supp_i080.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i081/test_i081.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i081/test_supp_i081.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i082/test_i082.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i082/test_supp_i082.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i083/test_i083.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i083/test_supp_i083.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i084/test_i084.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i084/test_supp_i084.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i085/test_i085.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i085/test_supp_i085.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i086/test_i086.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i086/test_supp_i086.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i087/test_i087.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i087/test_supp_i087.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i089/test_i089.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i089/test_supp_i089.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i090/test_i090.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i090/test_supp_i090.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i088/test_i088.c \
    $(UPSTREAM_DIR)/ff/ipc/test_i088/test_supp_i088.c

$(CONF_UPSTREAM_SRCS): $(UPSTREAM_STAMP) ;

$(UPSTREAM_STAMP): | $(BUILD_DIR)
	$(ROOT)/tests/upstream/fetch_psa_arch_tests.sh \
		$(BUILD_DIR)/upstream/psa-arch-tests
	git -C $(BUILD_DIR)/upstream/psa-arch-tests apply --reverse --check \
		$(abspath $(ROOT)/tests/upstream/psa-arch-tests-ec-overflow.patch) \
		2>/dev/null || \
	git -C $(BUILD_DIR)/upstream/psa-arch-tests apply \
		$(abspath $(ROOT)/tests/upstream/psa-arch-tests-ec-overflow.patch)
	touch $@

# Derived schedule, not a suite edit: skipped tests need a runtime capability
# the current image lacks, each tracked in task-list.md.
#   i067        -> dynamic heap the zero-allocation secure image forbids
# The panic tests run across their panic-reset reboots: the runner applies the
# M33MU-1 emulator fix (m33mu-tb-sec-chain.patch) before building the emulator.
$(CONF_GEN_STAMP): $(UPSTREAM_STAMP) $(MANIFEST_STAMP)
	sed -e 's/^test_i067$$/test_i067, skip/' \
	    -e 's/^test_i002, panic_test$$/test_i002/' \
	    -e 's/^test_i004, panic_test$$/test_i004/' \
	    -e 's/^test_i005, panic_test$$/test_i005/' \
	    -e 's/^test_i006, panic_test$$/test_i006/' \
	    -e 's/^test_i007, panic_test$$/test_i007/' \
	    -e 's/^test_i008, panic_test$$/test_i008/' \
	    -e 's/^test_i009, panic_test$$/test_i009/' \
	    -e 's/^test_i010, panic_test$$/test_i010/' \
	    -e 's/^test_i011, panic_test$$/test_i011/' \
	    -e 's/^test_i012, panic_test$$/test_i012/' \
	    -e 's/^test_i013, panic_test$$/test_i013/' \
	    -e 's/^test_i014, panic_test$$/test_i014/' \
	    -e 's/^test_i015, panic_test$$/test_i015/' \
	    -e 's/^test_i016, panic_test$$/test_i016/' \
	    -e 's/^test_i017, panic_test$$/test_i017/' \
	    -e 's/^test_i018, panic_test$$/test_i018/' \
	    -e 's/^test_i019, panic_test$$/test_i019/' \
	    -e 's/^test_i020, panic_test$$/test_i020/' \
	    -e 's/^test_i022, panic_test$$/test_i022/' \
	    -e 's/^test_i023, panic_test$$/test_i023/' \
	    -e 's/^test_i024, panic_test$$/test_i024/' \
	    -e 's/^test_i025, panic_test$$/test_i025/' \
	    -e 's/^test_i026, panic_test$$/test_i026/' \
	    -e 's/^test_i027, panic_test$$/test_i027/' \
	    -e 's/^test_i028, panic_test$$/test_i028/' \
	    -e 's/^test_i029, panic_test$$/test_i029/' \
	    -e 's/^test_i030, panic_test$$/test_i030/' \
	    -e 's/^test_i031, panic_test$$/test_i031/' \
	    -e 's/^test_i032, panic_test$$/test_i032/' \
	    -e 's/^test_i033, panic_test$$/test_i033/' \
	    -e 's/^test_i034, panic_test$$/test_i034/' \
	    -e 's/^test_i035, panic_test$$/test_i035/' \
	    -e 's/^test_i036, panic_test$$/test_i036/' \
	    -e 's/^test_i037, panic_test$$/test_i037/' \
	    -e 's/^test_i038, panic_test$$/test_i038/' \
	    -e 's/^test_i039, panic_test$$/test_i039/' \
	    -e 's/^test_i040, panic_test$$/test_i040/' \
	    -e 's/^test_i041, panic_test$$/test_i041/' \
	    -e 's/^test_i042, panic_test$$/test_i042/' \
	    -e 's/^test_i043, panic_test$$/test_i043/' \
	    -e 's/^test_i044, panic_test$$/test_i044/' \
	    -e 's/^test_i045, panic_test$$/test_i045/' \
	    -e 's/^test_i046, panic_test$$/test_i046/' \
	    -e 's/^test_i047, panic_test$$/test_i047/' \
	    -e 's/^test_i048, panic_test$$/test_i048/' \
	    -e 's/^test_i049, panic_test$$/test_i049/' \
	    -e 's/^test_i050, panic_test$$/test_i050/' \
	    -e 's/^test_i051, panic_test$$/test_i051/' \
	    -e 's/^test_i052, panic_test$$/test_i052/' \
	    -e 's/^test_i053, panic_test$$/test_i053/' \
	    -e 's/^test_i054, panic_test$$/test_i054/' \
	    -e 's/^test_i055, panic_test$$/test_i055/' \
	    -e 's/^test_i057, panic_test$$/test_i057/' \
	    -e 's/^test_i064, panic_test$$/test_i064/' \
	    -e 's/^test_i065, panic_test$$/test_i065/' \
	    -e 's/^test_i066, panic_test$$/test_i066/' \
	    -e 's/^test_i056, panic_test$$/test_i056/' \
	    -e 's/^test_i059, panic_test$$/test_i059/' \
	    -e 's/^test_i060, panic_test$$/test_i060/' \
	    -e 's/^test_i061, panic_test$$/test_i061/' \
	    -e 's/^test_i062, panic_test$$/test_i062/' \
	    -e 's/^test_i068, panic_test$$/test_i068/' \
	    -e 's/^test_i069, panic_test$$/test_i069/' \
	    -e 's/^test_i070, panic_test$$/test_i070/' \
	    -e 's/^test_i072, panic_test$$/test_i072/' \
	    -e 's/^test_i073, panic_test$$/test_i073/' \
	    -e 's/^test_i074, panic_test$$/test_i074/' \
	    -e 's/^test_i075, panic_test$$/test_i075/' \
	    -e 's/^test_i076, panic_test$$/test_i076/' \
	    -e 's/^test_i077, panic_test$$/test_i077/' \
	    -e 's/^test_i078, panic_test$$/test_i078/' \
	    -e 's/^test_i079, panic_test$$/test_i079/' \
	    -e 's/^test_i080, panic_test$$/test_i080/' \
	    -e 's/^test_i081, panic_test$$/test_i081/' \
	    -e 's/^test_i082, panic_test$$/test_i082/' \
	    -e 's/^test_i083, panic_test$$/test_i083/' \
	    -e 's/^test_i084, panic_test$$/test_i084/' \
	    -e 's/^test_i085, panic_test$$/test_i085/' \
	    -e 's/^test_i086, panic_test$$/test_i086/' \
	    -e 's/^test_i087, panic_test$$/test_i087/' \
	    -e 's/^test_i089, panic_test$$/test_i089/' \
	    -e 's/^test_i090, panic_test$$/test_i090/' \
	    $(UPSTREAM_DIR)/ff/ipc/testsuite.db \
	    > $(MANIFEST_DIR)/testsuite_sched.db
	python3 $(UPSTREAM_DIR)/tools/scripts/gen_tests_list.py ipc \
		$(MANIFEST_DIR)/testsuite_sched.db 0 ALL \
		$(MANIFEST_DIR)/testlist.txt \
		$(MANIFEST_DIR)/test_entry_list.inc \
		$(MANIFEST_DIR)/test_entry_fn_declare_list.inc \
		$(MANIFEST_DIR)/client_tests_list_declare.inc \
		$(MANIFEST_DIR)/client_tests_list.inc \
		$(MANIFEST_DIR)/server_tests_list_declare.inc \
		$(MANIFEST_DIR)/server_tests_list.inc \
		1 90
	printf '#include "server_partition.h"\n' \
		> $(MANIFEST_DIR)/psa_manifest/server_partition_psa.h
	printf '#include "client_partition.h"\n' \
		> $(MANIFEST_DIR)/psa_manifest/client_partition_psa.h
	printf '#include "driver_partition.h"\n#define DRIVER_UART_INTR_SIG DRIVER_UART_INTR_SIG_SIGNAL\n' \
		> $(MANIFEST_DIR)/psa_manifest/driver_partition_psa.h
	mkdir -p $(MANIFEST_DIR)/ns
	python3 $(UPSTREAM_DIR)/tools/scripts/gen_tests_list.py ipc \
		$(MANIFEST_DIR)/testsuite_sched.db 0 ALL \
		$(MANIFEST_DIR)/ns/testlist.txt \
		$(MANIFEST_DIR)/ns/test_entry_list.inc \
		$(MANIFEST_DIR)/ns/test_entry_fn_declare_list.inc \
		$(MANIFEST_DIR)/ns/client_tests_list_declare.inc \
		$(MANIFEST_DIR)/ns/client_tests_list.inc \
		$(MANIFEST_DIR)/ns/server_tests_list_declare.inc \
		$(MANIFEST_DIR)/ns/server_tests_list.inc \
		1 90
	mkdir -p $(MANIFEST_DIR)/storage/ns
	python3 $(UPSTREAM_DIR)/tools/scripts/gen_tests_list.py storage \
		$(UPSTREAM_DIR)/dev_apis/storage/ps_testsuite.db 0 ALL \
		$(MANIFEST_DIR)/storage/ns/testlist.txt \
		$(MANIFEST_DIR)/storage/ns/test_entry_list.inc \
		$(MANIFEST_DIR)/storage/ns/test_entry_fn_declare_list.inc \
		$(MANIFEST_DIR)/storage/ns/client_tests_list_declare.inc \
		$(MANIFEST_DIR)/storage/ns/client_tests_list.inc \
		$(MANIFEST_DIR)/storage/ns/server_tests_list_declare.inc \
		$(MANIFEST_DIR)/storage/ns/server_tests_list.inc \
		1 17
	mkdir -p $(MANIFEST_DIR)/crypto/ns
	# c047 (HMAC key + CMAC alg negative case) expects INVALID_ARGUMENT, but CMAC
	# is compiled out so wolfPSA returns spec-permitted NOT_SUPPORTED; skip it in
	# the schedule the same way the upstream db already skips c064/c065.
	sed -e 's/^test_c047$$/test_c047, skip/' \
		$(UPSTREAM_DIR)/dev_apis/crypto/testsuite.db \
		> $(MANIFEST_DIR)/crypto/ns/testsuite_sched.db
	python3 $(UPSTREAM_DIR)/tools/scripts/gen_tests_list.py crypto \
		$(MANIFEST_DIR)/crypto/ns/testsuite_sched.db 0 ALL \
		$(MANIFEST_DIR)/crypto/ns/testlist.txt \
		$(MANIFEST_DIR)/crypto/ns/test_entry_list.inc \
		$(MANIFEST_DIR)/crypto/ns/test_entry_fn_declare_list.inc \
		$(MANIFEST_DIR)/crypto/ns/client_tests_list_declare.inc \
		$(MANIFEST_DIR)/crypto/ns/client_tests_list.inc \
		$(MANIFEST_DIR)/crypto/ns/server_tests_list_declare.inc \
		$(MANIFEST_DIR)/crypto/ns/server_tests_list.inc \
		1 80
	mkdir -p $(MANIFEST_DIR)/initial_attestation/ns
	python3 $(UPSTREAM_DIR)/tools/scripts/gen_tests_list.py initial_attestation \
		$(UPSTREAM_DIR)/dev_apis/initial_attestation/testsuite.db 0 ALL \
		$(MANIFEST_DIR)/initial_attestation/ns/testlist.txt \
		$(MANIFEST_DIR)/initial_attestation/ns/test_entry_list.inc \
		$(MANIFEST_DIR)/initial_attestation/ns/test_entry_fn_declare_list.inc \
		$(MANIFEST_DIR)/initial_attestation/ns/client_tests_list_declare.inc \
		$(MANIFEST_DIR)/initial_attestation/ns/client_tests_list.inc \
		$(MANIFEST_DIR)/initial_attestation/ns/server_tests_list_declare.inc \
		$(MANIFEST_DIR)/initial_attestation/ns/server_tests_list.inc \
		1 1
	touch $@

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/partition/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i001/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i002/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i003/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i004/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i005/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i006/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i007/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i008/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i009/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i010/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i011/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i012/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i013/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i014/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i015/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i016/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i017/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i018/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i019/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i020/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i022/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i023/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i021/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i024/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i025/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i026/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i027/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i028/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i029/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i030/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i031/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i032/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i033/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i034/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i035/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i036/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i037/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i038/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i039/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i040/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i041/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i042/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i043/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i044/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i045/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i046/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i047/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i048/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i049/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i050/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i051/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i052/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i053/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i054/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i055/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i057/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i058/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i063/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i064/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i065/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i066/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i071/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i056/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i059/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i060/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i061/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i062/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i068/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i069/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i070/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i072/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i073/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i074/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i075/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i076/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i077/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i078/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i079/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i080/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i081/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i082/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i083/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i084/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i085/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i086/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i087/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i089/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i090/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/ff/ipc/test_i088/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/val/spe/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(UPSTREAM_DIR)/val/common/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/conf_sec_%.o: $(TARGET_CONF_DIR)/%.c \
		$(CONF_GEN_STAMP) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(CONF_CFLAGS) -c -o $@ $<
endif

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(MANIFEST_DIR):
	@mkdir -p $@

# The stamp records the selected variant; a mismatch regenerates even when
# mtimes tie within one second, so a stale variant can never be linked.
MANIFEST_MODE := MANIFEST_INPUT=$(MANIFEST_INPUT) CONFIG_VNET=$(CONFIG_VNET) WT_CONFORMANCE=$(WT_CONFORMANCE) GEN_OPTS=--supported-features 0x1 --supported-framework-version 0x100 --address-bits 32

$(MANIFEST_STAMP): $(ROOT)/tools/manifest/generate.py $(MANIFEST_INPUT) \
		FORCE | $(MANIFEST_DIR)
	@if test -f "$@" && test "$$(cat "$@" 2>/dev/null)" = '$(MANIFEST_MODE)' \
			&& ! test $(MANIFEST_INPUT) -nt "$@" \
			&& ! test $(ROOT)/tools/manifest/generate.py -nt "$@"; then \
		:; \
	else \
		python3 $(ROOT)/tools/manifest/generate.py $(MANIFEST_INPUT) \
			$(MANIFEST_DIR) --supported-features 0x1 \
			--supported-framework-version 0x100 --address-bits 32 \
			&& printf '%s\n' '$(MANIFEST_MODE)' > "$@"; \
	fi

$(MANIFEST_GEN_C) $(MANIFEST_GEN_H): $(MANIFEST_STAMP)

$(MANIFEST_OBJ): $(MANIFEST_GEN_C) $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $(MANIFEST_GEN_C)

$(WOLFHSM_CFG_H): | $(BUILD_DIR)
	printf '#include "%s"\n' "$(abspath $(WOLFHSM_RUNNER_DIR)/wh_settings_local.h)" > $@

.PHONY: FORCE
FORCE:

$(BUILD_MODE_STAMP): FORCE | $(BUILD_DIR)
	@tmp="$@.tmp"; \
	printf '%s\n' \
		'ARCH=$(ARCH)' \
		'TARGET=$(TARGET)' \
		'WT_SECURE_FLASH_BASE=$(WT_SECURE_FLASH_BASE)' \
		'WT_SECURE_FLASH_SIZE=$(WT_SECURE_FLASH_SIZE)' \
		'WT_SECURE_IMAGE_HEADER_SIZE=$(WT_SECURE_IMAGE_HEADER_SIZE)' \
		'WT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_BASE)' \
		'WT_GUEST1_FLASH_BASE=$(WT_GUEST1_FLASH_BASE)' \
		'WT_GUEST0_FLASH_SIZE=$(WT_GUEST0_FLASH_SIZE)' \
		'WT_GUEST1_FLASH_SIZE=$(WT_GUEST1_FLASH_SIZE)' \
		'WT_ENGINE_HSM=$(WT_ENGINE_HSM)' \
		'WT_ATTEST_COSE=$(WT_ATTEST_COSE)' \
		'WT_CONFORMANCE=$(WT_CONFORMANCE)' \
		'CONFIG_VNET=$(CONFIG_VNET)' \
		'WT_FFM_NEGATIVE_PROBE=$(WT_FFM_NEGATIVE_PROBE)' \
		'WT_KEYSTORE_NEG_PROBE=$(WT_KEYSTORE_NEG_PROBE)' \
		'WT_LAUNCH_DEBUG=$(WT_LAUNCH_DEBUG)' \
		'WT_ROLLBACK_PROBE=$(WT_ROLLBACK_PROBE)' \
		'WT_SP_FAULT_PROBE=$(WT_SP_FAULT_PROBE)' \
		'WT_SP_FAULT_ALWAYS_PROBE=$(WT_SP_FAULT_ALWAYS_PROBE)' \
		'WT_PANIC_NEG_PROBE=$(WT_PANIC_NEG_PROBE)' \
		'WT_VNET_NEG_PROBE=$(WT_VNET_NEG_PROBE)' \
		'WT_MANIFEST_NEG_PROBE=$(WT_MANIFEST_NEG_PROBE)' \
		'WT_REMEASURE_PROBE=$(WT_REMEASURE_PROBE)' \
		'WT_BOOTUPDATE_PROBE=$(WT_BOOTUPDATE_PROBE)' \
		'WT_MAX_GUESTS=$(WT_MAX_GUESTS)' \
		'WT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE)' \
		'WT_WOLFCRYPT_SP_ASM=$(WT_WOLFCRYPT_SP_ASM)' \
		'WT_WOLFCRYPT_ARMASM=$(WT_WOLFCRYPT_ARMASM)' \
		'WT_WOLFCRYPT_STM32_HASH=$(WT_WOLFCRYPT_STM32_HASH)' \
		'WT_SHARED_UART=$(WT_SHARED_UART)' \
		'WT_TIMESLICE_MS=$(WT_TIMESLICE_MS)' \
		'WT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ)' \
		'WT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ)' \
		'WT_EXTRA_CFLAGS=$(WT_EXTRA_CFLAGS)' \
		'WT_EXTRA_LDFLAGS=$(WT_EXTRA_LDFLAGS)' > "$$tmp"; \
	if test -f "$@" && cmp -s "$$tmp" "$@"; then \
		rm -f "$$tmp"; \
	else \
		mv "$$tmp" "$@"; \
	fi

$(BUILD_DIR)/wh_sec_%.o: $(WOLFHSM_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_WOLFHSM_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/st/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/arch/$(ARCH)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/arch/common/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/sched/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/sync/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHSM_RUNNER_DIR)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(PORT_DIR)/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHAL_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHAL_DIR)/src/rng/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/wolfhsm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/native/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/vnet/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/vnet/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFCOSE_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

define wt_arch_tree_rule
$(BUILD_DIR)/wt_sec_$(notdir $(basename $(1))).o: $(1) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$$(CC) $$(SECURE_CFLAGS) -c -o $$@ $$<
endef
$(foreach s,$(ARCH_TREE_SRCS) $(ARCH_ASM_SRCS),$(eval $(call wt_arch_tree_rule,$(s))))

$(BUILD_DIR)/sec_monitor.o: $(ROOT)/src/monitor.c $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_ffm_boot.o: $(ROOT)/src/ffm_boot.c $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_$(notdir $(TARGET_PLATFORM_SRC:.c=.o)): $(TARGET_PLATFORM_SRC) \
		$(PORT_HEADERS) $(MANIFEST_GEN_H) $(WOLFHSM_CFG_H) \
		$(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(WOLFHSM_RUNNER_DIR)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(PORT_DIR)/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(ROOT)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(SECURE_ELF) $(ARCH_LINK_OUTPUTS) &: $(ALL_SECURE_OBJS) $(SECURE_LD) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) \
		$(TARGET_LDFLAGS) \
		-Wl,--defsym=WT_VNET_DATA_LENGTH=$(WT_VNET_DATA_LENGTH) \
		-Wl,-T$(SECURE_LD) \
		-Wl,--gc-sections $(WT_EXTRA_LDFLAGS) \
		$(ARCH_LDFLAGS) \
		-o $(SECURE_ELF) $(ALL_SECURE_OBJS) -lgcc
	$(arch_image_checks)

$(SECURE_BIN): $(SECURE_ELF)
	$(OBJCOPY) -O binary $< $@

# What `make` builds by default; an arch fragment overrides it while its full
# secure image cannot link yet (an EL3-only monitor image, for example).
ARCH_DEFAULT_GOALS ?= secure-image
secure-image: $(SECURE_BIN) $(SECURE_ELF)
	@$(SIZE) $(SECURE_ELF)

# Footprint evidence for size tracking: totals plus the section and largest
# .bss breakdown of the secure image.
size-report: $(SECURE_ELF)
	@$(SIZE) $(SECURE_ELF)
	@$(SIZE) -A -d $(SECURE_ELF) | grep -vE '^(Total|section| *$$)' | sort -k2 -nr | head -12
	@$(TOOLPREFIX)nm --print-size --size-sort --radix=d $(SECURE_ELF) | \
		awk '$$3 ~ /^[bB]$$/' | tail -10
