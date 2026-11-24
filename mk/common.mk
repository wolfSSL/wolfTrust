# Architecture- and target-neutral half of the secure image build. Included
# last, after mk/target-<soc>.mk and mk/arch-<arch>.mk supply the TARGET_* and
# ARCH_* inputs; repository paths come from the Makefile.
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
NM := $(TOOLPREFIX)nm
SIZE := $(TOOLPREFIX)size

# A linked image that fails any post-link security check must not remain a
# reusable Make target. This also removes every output of the grouped link
# rule, including the CMSE import library and link map.
.DELETE_ON_ERROR:

MANIFEST_DIR := $(BUILD_DIR)/manifest
MANIFEST_STAMP := $(MANIFEST_DIR)/.stamp
MANIFEST_GEN_C := $(MANIFEST_DIR)/wolftrust_manifest_generated.c
MANIFEST_GEN_H := $(MANIFEST_DIR)/wolftrust_manifest_generated.h
SECURE_ELF := $(BUILD_DIR)/wolftrust.elf
SECURE_BIN := $(BUILD_DIR)/wolftrust.bin
SECURE_MAP := $(BUILD_DIR)/wolftrust.map
BUILD_MODE_STAMP := $(BUILD_DIR)/secure_build_mode.stamp
WOLFHSM_CFG_H := $(BUILD_DIR)/wolfhsm_cfg.h

WT_TIMESLICE_MS ?= 2
WT_MAX_GUESTS ?= 1
ifneq ($(words $(WT_MAX_GUESTS))/$(filter 1 2,$(WT_MAX_GUESTS)),1/$(WT_MAX_GUESTS))
$(error unsupported WT_MAX_GUESTS='$(WT_MAX_GUESTS)' (want 1 or 2))
endif
# Per-tasklet coroutine stack. 10K measured with >=2K headroom: the M33MU
# deep set (positive, devcrypto 78-test ECC, confboot 85/4) runs clean at
# 8K with no PSPLIM overflow, so peak use is under 8K. The old 24K predated
# the SP_SMALL math switch; PSPLIM_S faults any real overflow, so this floor
# is measured, not guessed.
WT_CO_STACK_SIZE ?= 10240
# Secure main (SPM) stack, sized at link and limited by MSPLIM_S at reset.
WT_SPM_STACK_SIZE ?= 0x1000
WT_LTO ?= 1
ifneq ($(WT_LTO),0)
ifneq ($(WT_LTO),1)
$(error unsupported WT_LTO='$(WT_LTO)' (want 0 or 1))
endif
endif
WT_LTO_CFLAGS :=
WT_LTO_LDFLAGS :=
ifeq ($(WT_LTO),1)
WT_LTO_CFLAGS := -flto=auto
WT_LTO_LDFLAGS := -flto=auto -Wl,-u,wt_platform_panic
endif
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
WT_PERIPH_SP_NEG_PROBE ?= 0
WT_BAND_NEG_PROBE ?= 0
WT_RESTART_NEG_PROBE ?= 0
WT_DEPUTY_NEG_PROBE ?= 0
WT_HSM_PIN_NEG_PROBE ?= 0
WT_LAUNCH_DEBUG ?= 0
WT_ROLLBACK_PROBE ?= 0
WT_SP_FAULT_PROBE ?= 0
WT_HSM_FAULT_PROBE ?= 0
WT_SP_FAULT_ALWAYS_PROBE ?= 0
WT_PANIC_NEG_PROBE ?= 0
WT_BUSFAULT_NEG_PROBE ?= 0
WT_SVC_NEG_PROBE ?= 0
WT_VNET_NEG_PROBE ?= 0
WT_TPM_NEG_PROBE ?= 0
WT_PKCS11_NEG_PROBE ?= 0
WT_MANIFEST_NEG_PROBE ?= 0
# The generator refuses at build time every manifest the boot-time validator
# would; 1 also re-runs that validator and the port binding checks at boot.
WT_MANIFEST_RUNTIME_CHECK ?= 0
# Manifest negatives 1 and 2 corrupt the manifest at boot, after the build.
ifneq ($(filter 1 2,$(WT_MANIFEST_NEG_PROBE)),)
override WT_MANIFEST_RUNTIME_CHECK := 1
endif
ifneq ($(words $(WT_MANIFEST_RUNTIME_CHECK))/$(filter 0 1,$(WT_MANIFEST_RUNTIME_CHECK)),1/$(WT_MANIFEST_RUNTIME_CHECK))
$(error unsupported WT_MANIFEST_RUNTIME_CHECK='$(WT_MANIFEST_RUNTIME_CHECK)' (want 0 or 1))
endif
WT_HANDLER_IRQ_PROBE ?= 0
WT_REMEASURE_PROBE ?= 0
WT_BOOTUPDATE_PROBE ?= 0
WT_CONFORMANCE ?= 0
# PSA Firmware Update partition (SERVICE_FWU) and its 4 KiB stack.
WT_FWU ?= 0
ifneq ($(words $(WT_FWU))/$(filter 0 1,$(WT_FWU)),1/$(WT_FWU))
$(error unsupported WT_FWU='$(WT_FWU)' (want 0 or 1))
endif
ifeq ($(WT_BOOTUPDATE_PROBE)/$(WT_FWU),1/0)
$(error WT_BOOTUPDATE_PROBE=1 drives the update service; build it with WT_FWU=1)
endif

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

# Firmware-TPM (fwTPM) subsystem. Off by default; when on, links the
# SERVICE_TPM mediated relay into the secure image so a Non-secure wolfTPM
# client reaches the isolated fwTPM partition. Host unit tests under
# tests/host/tpm_relay/ build regardless of this switch.
CONFIG_TPM ?= n

# PKCS#11 clients call SERVICE_PKCS11 in a managed Secure partition. Its
# implementation uses native wolfCrypt or the mediated wolfHSM engine.
CONFIG_PKCS11 ?= n
WT_INTERFACE_LOCAL_PROVIDER ?= 0

HSM_INCLUDES := -I$(WOLFHSM_DIR) -I$(WOLFSSL_DIR) \
    $(if $(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),-I$(WOLFTPM_DIR) -I$(WOLFPKCS11_DIR)) \
    -I$(BUILD_DIR)
HSM_INCLUDES_SECURE := $(HSM_INCLUDES) -I$(WOLFHAL_DIR) -I$(abspath $(WOLFHSM_RUNNER_DIR))
HSM_DEFS_SECURE := -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG \
    -DWC_RESEED_INTERVAL=1000000 \
    $(ARCH_HSM_DEFS)
ifeq ($(WT_ENGINE),hsm)
HSM_DEFS_SECURE += -DWOLF_CRYPTO_CB -DWC_NO_DEFAULT_DEVID -DWT_ENGINE_HSM=1
else
# Native links only the wolfHSM NVM object store; NO_CRYPTO drops the server's
# wolfCrypt dependency (and its WOLF_CRYPTO_CB requirement).
HSM_DEFS_SECURE += -DWT_ENGINE_NATIVE=1 -DWOLFHSM_CFG_NO_CRYPTO
endif

ifeq ($(WT_ATTEST_COSE),1)
SECURE_CFLAGS_COSE := -I$(WOLFCOSE_DIR)/include \
    -DWT_ATTEST_COSE=1 \
    -DWOLFCOSE_LEAN -DWOLFCOSE_ENABLE_EXT_SIGN -DWOLFCOSE_NO_LOCAL_SIGN \
    -DWOLFCOSE_ENABLE_DEPRECATED_ALGS \
    -DWOLFCOSE_NO_SIGN1_VERIFY -DWOLFCOSE_NO_ENCRYPT0 \
    -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_KEY_ENCODE \
    -DWOLFCOSE_NO_KEY_DECODE \
    -DWOLFCOSE_ENABLE_EAT_PSA \
    -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
    -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
    -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE
endif

WOLFPKCS11_COMMON_DEFS := -DWOLFPKCS11_USER_SETTINGS \
    -DWOLFPKCS11_NO_STORE -DWOLFPKCS11_NO_TIME -DWOLFPKCS11_NO_ENV
ifeq ($(WT_ENGINE),hsm)
WOLFPKCS11_COMMON_DEFS += -DWOLFPKCS11_DEFAULT_DEVID=0x5748534D
endif

SECURE_CFLAGS := $(CPU_FLAGS) -std=c99 -ffreestanding -fno-builtin -nostdlib -Os -g \
    -ffunction-sections -fdata-sections -Wall -Wextra \
    $(WT_LAYOUT_CFLAGS) \
    -DWT_TIMESLICE_MS=$(WT_TIMESLICE_MS) \
    -DWT_MAX_GUESTS=$(WT_MAX_GUESTS) \
    -DWT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE) \
    $(TARGET_CFLAGS) \
    $(ARCH_CFLAGS) \
    $(HSM_INCLUDES_SECURE) $(HSM_DEFS_SECURE) $(SECURE_CFLAGS_COSE) \
    -I$(MANIFEST_DIR) $(WT_LTO_CFLAGS)
SECURE_CFLAGS += $(WT_EXTRA_CFLAGS)

ifeq ($(CONFIG_VNET),y)
ifneq ($(WT_MAX_GUESTS),2)
$(error CONFIG_VNET=y needs both guests; build with WT_MAX_GUESTS=2)
endif
endif
ifeq ($(CONFIG_VNET),y)
SECURE_CFLAGS += -DCONFIG_VNET=1 \
    -DWT_VNET_POOL_SLOTS=$(WT_VNET_POOL_SLOTS) \
    -DWT_VNET_FRAME_MAX=$(WT_VNET_FRAME_MAX) \
    -DWT_VNET_RX_QUEUE_DEPTH=$(WT_VNET_RX_QUEUE_DEPTH) \
    -DWT_VNET_RX_IRQ=$(WT_VNET_RX_IRQ) \
    -DWT_VNET_TIMEOUT_TICKS=$(WT_VNET_TIMEOUT_TICKS) \
    -DWT_VNET_UNKNOWN_UCAST_FLOOD=$(WT_VNET_UNKNOWN_UCAST_FLOOD)
endif

ifeq ($(CONFIG_PKCS11),y)
SECURE_CFLAGS += -DCONFIG_PKCS11=1
ifeq ($(WT_INTERFACE_LOCAL_PROVIDER),1)
SECURE_CFLAGS += $(WOLFPKCS11_COMMON_DEFS)
ifneq ($(WT_PKCS11_PIN_MAX_FAILURES),)
ifneq ($(shell printf '%s' '$(WT_PKCS11_PIN_MAX_FAILURES)' | grep -Ex '[1-9][0-9]*'),$(WT_PKCS11_PIN_MAX_FAILURES))
$(error WT_PKCS11_PIN_MAX_FAILURES must be > 0)
endif
SECURE_CFLAGS += -DWT_PKCS11_PIN_MAX_FAILURES=$(WT_PKCS11_PIN_MAX_FAILURES)U
endif
# Production keeps wolfPKCS11's 600,000-round PIN PBKDF2; only the M33MU
# emulator gate lowers it, explicitly, because emulated SHA-256 is too slow.
ifneq ($(WT_PKCS11_TEST_PBKDF2_ITERATIONS),)
$(warning NOTE: emulator-only PIN PBKDF2 iterations=$(WT_PKCS11_TEST_PBKDF2_ITERATIONS))
SECURE_CFLAGS += -DPBKDF2_ITERATIONS=$(WT_PKCS11_TEST_PBKDF2_ITERATIONS)
endif
endif
endif

ifeq ($(CONFIG_TPM),y)
SECURE_CFLAGS += -DCONFIG_TPM=1
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
ifeq ($(WT_PERIPH_SP_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_PERIPH_SP_NEG_PROBE=1
endif
ifneq ($(filter 1 2 3 4 5 6,$(WT_BAND_NEG_PROBE)),)
SECURE_CFLAGS += -DWT_BAND_NEG_PROBE=$(WT_BAND_NEG_PROBE)
endif
ifneq ($(filter 1 2 3,$(WT_RESTART_NEG_PROBE)),)
SECURE_CFLAGS += -DWT_RESTART_NEG_PROBE=$(WT_RESTART_NEG_PROBE)
endif
ifeq ($(WT_DEPUTY_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_DEPUTY_NEG_PROBE=1
endif
# The vault's AES AEAD, and the one PSA AEAD of small and tiny (ccm there)
WT_AEAD ?=
ifneq ($(filter-out gcm ccm,$(WT_AEAD))$(word 2,$(WT_AEAD)),)
$(error unsupported WT_AEAD='$(WT_AEAD)' (want gcm or ccm))
endif
WT_AEAD_ONE := $(if $(filter 1,$(WT_SECURE_PSA)),$(filter small tiny,$(WT_SECURE_PSA_PROFILE)))
WT_AEAD_USED := $(or $(WT_AEAD),$(if $(WT_AEAD_ONE),ccm,gcm))
SECURE_CFLAGS += -DWT_AEAD_$(if $(filter ccm,$(WT_AEAD_USED)),CCM,GCM)
ifeq ($(WT_HSM_PIN_NEG_PROBE),1)
# Probe lives in the hsm-only wt_hsm.c; defining it for a native build would
# leave the spm_partitions.c call undefined at link. Native has no tasklet, so
# the flag is a no-op there.
ifeq ($(WT_ENGINE_HSM),1)
SECURE_CFLAGS += -DWT_HSM_PIN_NEG_PROBE=1
endif
endif
ifeq ($(WT_SP_FAULT_PROBE),1)
SECURE_CFLAGS += -DWT_SP_FAULT_PROBE=1
endif
ifeq ($(WT_HSM_FAULT_PROBE),1)
SECURE_CFLAGS += -DWT_HSM_FAULT_PROBE=1
endif
ifeq ($(WT_SP_FAULT_ALWAYS_PROBE),1)
SECURE_CFLAGS += -DWT_SP_FAULT_ALWAYS_PROBE=1
endif
ifeq ($(WT_PANIC_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_PANIC_NEG_PROBE=1
endif
ifeq ($(WT_BUSFAULT_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_BUSFAULT_NEG_PROBE=1
endif
ifeq ($(WT_SVC_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_SVC_NEG_PROBE=1
endif
ifeq ($(WT_VNET_NEG_PROBE),1)
SECURE_CFLAGS += -DWT_VNET_NEG_PROBE=1
endif
ifeq ($(WT_TPM_NEG_PROBE),1)
ifneq ($(CONFIG_TPM),y)
$(error WT_TPM_NEG_PROBE=1 requires CONFIG_TPM=y)
endif
SECURE_CFLAGS += -DWT_INTERFACE_NEG_PROBE=1
endif
ifeq ($(WT_PKCS11_NEG_PROBE),1)
ifneq ($(CONFIG_PKCS11),y)
$(error WT_PKCS11_NEG_PROBE=1 requires CONFIG_PKCS11=y)
endif
SECURE_CFLAGS += -DWT_INTERFACE_NEG_PROBE=1
endif
ifneq ($(filter 1 2 3,$(WT_MANIFEST_NEG_PROBE)),)
SECURE_CFLAGS += -DWT_MANIFEST_NEG_PROBE=$(WT_MANIFEST_NEG_PROBE)
endif
ifeq ($(WT_MANIFEST_RUNTIME_CHECK),1)
SECURE_CFLAGS += -DWT_MANIFEST_RUNTIME_CHECK=1
endif
ifneq ($(filter-out 0,$(WT_HANDLER_IRQ_PROBE)),)
SECURE_CFLAGS += -DWT_HANDLER_IRQ_PROBE=$(WT_HANDLER_IRQ_PROBE)
endif
ifeq ($(WT_REMEASURE_PROBE),1)
SECURE_CFLAGS += -DWT_REMEASURE_PROBE=1
endif
ifeq ($(WT_BOOTUPDATE_PROBE),1)
SECURE_CFLAGS += -DWT_BOOTUPDATE_PROBE=1
endif
# A probe that faults a partition on its first entry keeps that entry lazy
# (src/ffm_boot.c), so the fault lands on a client's in-flight request. Only
# the values that emit a probe macro above count.
ifneq ($(strip \
    $(filter 1,$(WT_SP_FAULT_PROBE) $(WT_SP_FAULT_ALWAYS_PROBE) \
        $(WT_BUSFAULT_NEG_PROBE) $(WT_PANIC_NEG_PROBE) $(WT_SVC_NEG_PROBE) \
        $(WT_FFM_NEGATIVE_PROBE) $(WT_KEYSTORE_NEG_PROBE) \
        $(WT_PERIPH_SP_NEG_PROBE) $(WT_VNET_NEG_PROBE) $(WT_XN_NEG_PROBE) \
        $(WT_FP_NEG_PROBE) $(WT_TPM_NEG_PROBE) $(WT_PKCS11_NEG_PROBE)) \
    $(filter 1 2 3 4,$(WT_SEAL_NEG_PROBE))),)
SECURE_CFLAGS += -DWT_SP_LAZY_FIRST_ENTRY=1
endif
ifeq ($(WT_FWU),1)
SECURE_CFLAGS += -DWT_FWU=1
MANIFEST_EXCLUDE :=
else
# The conformance manifest never carries the update partition.
MANIFEST_EXCLUDE := $(if $(filter 1,$(WT_CONFORMANCE)),,--exclude-partition PARTITION_FWU)
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
    $(ROOT)/src/fabric_windows.c \
    $(ROOT)/src/periph.c \
    $(ROOT)/src/irq_claim.c \
    $(ROOT)/src/spm.c \
    $(ROOT)/src/boot.c \
    $(ROOT)/src/spm_partitions.c \
    $(ROOT)/src/partition.c \
    $(TARGET_PARTITIONS_SRC)

# The flash and entropy backends every port shares, over its flash_port.h
# and rng_port.h drivers.
PORT_SHARED_SRCS := \
    $(PORT_NEUTRAL_DIR)/hsm_flash.c \
    $(PORT_NEUTRAL_DIR)/hsm_flash_ctx.c \
    $(PORT_NEUTRAL_DIR)/rng_entropy.c \
    $(PORT_DIR)/flash_drv.c \
    $(PORT_DIR)/rng_drv.c
TARGET_EXTRA_SRCS += $(PORT_SHARED_SRCS)
PORT_HEADERS += $(wildcard $(PORT_NEUTRAL_DIR)/*.h)

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
ifeq ($(WT_ENGINE)/$(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),native/)
WOLFCRYPT_SECURE_SRCS := $(filter-out %/asn.c,$(WOLFCRYPT_SECURE_SRCS))
endif

# TPM 2.0 and PKCS#11 build one provider the same way; only one is ever linked.
WT_IF := $(if $(filter y,$(CONFIG_TPM)),tpm,$(if $(filter y,$(CONFIG_PKCS11)),p11))
WT_IF_LIB_SRCS :=
WT_IF_WOLFCRYPT_SRCS :=
WT_IF_WOLFHSM_SRCS :=
WOLFTPM_SECURE_CFLAGS := -DWOLFTPM_USER_SETTINGS -DWOLFTPM_FWTPM \
    -DFWTPM_NO_NV -include wolftrust/tpm/tpm_abi.h \
    -DFWTPM_MAX_COMMAND_SIZE=WT_TPM_FRAME_MAX \
    -DFWTPM_MAX_PERSISTENT=2 -DFWTPM_MAX_SESSIONS=2 \
    -DFWTPM_NO_POLICY -DFWTPM_NO_CREDENTIAL \
    -DFWTPM_NO_PARAM_ENC -DFWTPM_NO_KEY_MIGRATION \
    -DFWTPM_NO_CONTEXT -DFWTPM_NO_SYM_ENCRYPT -DFWTPM_NO_CLOCK
WT_TPM_DA ?= 1
ifeq ($(WT_TPM_DA),0)
WOLFTPM_SECURE_CFLAGS += -DFWTPM_NO_DA
else ifneq ($(WT_TPM_DA),1)
$(error WT_TPM_DA must be 0 or 1)
endif
TPM_CRYPTO_DEVICE_CFLAGS := $(if $(filter hsm,$(WT_ENGINE)),-DWOLF_CRYPTO_CB_FIND)
WOLFTPM_SECURE_CFLAGS += $(TPM_CRYPTO_DEVICE_CFLAGS)
WOLFPKCS11_SECURE_CFLAGS := $(WOLFPKCS11_COMMON_DEFS) -DWOLFSSL_PUBLIC_MP \
    -DWT_PKCS11_PROVIDER_HEAP=1 -include time.h
WT_PROVIDER_ECC_FALLBACK ?= 0
ifeq ($(WT_ENGINE)/$(WT_PROVIDER_ECC_FALLBACK),hsm/0)
TPM_CRYPTO_DEVICE_CFLAGS += -DWT_TPM_HSM_CALLBACK_ECC
WOLFTPM_SECURE_CFLAGS += -DWT_TPM_HSM_CALLBACK_ECC
WOLFPKCS11_SECURE_CFLAGS += -DWOLF_CRYPTO_CB_ONLY_ECC
else ifeq ($(WT_ENGINE),hsm)
ifneq ($(WT_PROVIDER_ECC_FALLBACK),1)
$(error WT_PROVIDER_ECC_FALLBACK must be 0 or 1)
endif
endif

$(BUILD_DIR)/wt_sec_tpm_local_provider.o: SECURE_CFLAGS += $(WOLFTPM_SECURE_CFLAGS)

ifeq ($(WT_IF),tpm)
WT_IF_NAMESPACE := wt_tpm_
WT_IF_CLIENT_CFLAGS = -UWC_NO_DEFAULT_DEVID $(WOLFTPM_SECURE_CFLAGS)
WT_IF_WOLFCRYPT_CFLAGS = -UWC_NO_DEFAULT_DEVID $(TPM_CRYPTO_DEVICE_CFLAGS)
WT_IF_WOLFHSM_CFLAGS = -UWC_NO_DEFAULT_DEVID
else
WT_IF_NAMESPACE := wt_p11_
WT_IF_CLIENT_CFLAGS = $(WOLFPKCS11_SECURE_CFLAGS)
WT_IF_WOLFCRYPT_CFLAGS = $(WOLFPKCS11_SECURE_CFLAGS)
WT_IF_WOLFHSM_CFLAGS = $(WOLFPKCS11_SECURE_CFLAGS)
endif

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
    $(ROOT)/src/services/nvm_boot.c \
    $(ROOT)/src/services/boot_handoff.c \
    $(ROOT)/src/services/hsm_relay_service.c \
    $(ROOT)/src/services/nvm_client.c \
    $(ROOT)/src/services/storage_service.c \
    $(ROOT)/src/services/vault_service.c

ifeq ($(WT_FWU),1)
WT_SECURE_EXTRA_SRCS += $(ROOT)/src/services/fwu_service.c
endif

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

WT_PSA_SIZE_VARS := WT_PSA_POOL_BYTES WT_PSA_KEY_SLOTS WT_PSA_OP_SLOTS
$(foreach v,$(WT_PSA_SIZE_VARS),$(if $(filter-out 0 1 2 3 4 5 6 7 8 9,$(subst 0,0 ,$(subst 1,1 ,$(subst 2,2 ,$(subst 3,3 ,$(subst 4,4 ,$(subst 5,5 ,$(subst 6,6 ,$(subst 7,7 ,$(subst 8,8 ,$(subst 9,9 ,$($(v)))))))))))))$(word 2,$($(v))),$(error unsupported $(v)='$($(v))' (want a decimal count))))
WOLFPSA_DIR := $(ROOT)/lib/wolfPSA
WOLFPSA_SECURE_SRCS :=
ifneq ($(filter-out 0 1,$(WT_SECURE_PSA))$(words $(WT_SECURE_PSA)),1)
$(error unsupported WT_SECURE_PSA='$(WT_SECURE_PSA)' (want 0 or 1))
endif
ifeq ($(WT_SECURE_PSA),1)
ifneq ($(WT_ENGINE),native)
$(error WT_SECURE_PSA=1 requires WT_ENGINE=native)
endif
ifneq ($(filter-out extended default small tiny,$(WT_SECURE_PSA_PROFILE))$(words $(WT_SECURE_PSA_PROFILE)),1)
$(error unsupported WT_SECURE_PSA_PROFILE='$(WT_SECURE_PSA_PROFILE)' (want extended, default, small or tiny))
endif
ifeq ($(WT_WOLFCRYPT_ARMASM),1)
$(error WT_SECURE_PSA=1 needs constant-time AES, and WT_WOLFCRYPT_ARMASM=1 builds the T-table Thumb-2 AES)
endif
WT_SECURE_PSA_CFLAGS := -DWT_SECURE_PSA=1 -DWT_SECURE_PSA_$(WT_SECURE_PSA_PROFILE)=1 \
    -DWOLFSSL_PSA_ENGINE -DWOLFPSA_CUSTOM_STORE -DWOLFPSA_NO_TRACE -DWOLFPSA_AEAD_BORROW \
    -DWOLFPSA_AEAD_STREAM_AAD \
    -I$(WOLFPSA_DIR) -I$(WOLFPSA_DIR)/wolfpsa -I$(BUILD_DIR)/wolfpsa_cfg \
    $(foreach v,$(WT_PSA_SIZE_VARS),$(if $($(v)),-D$(v)=$($(v))U))
WT_PSA_CONFIG_H := $(BUILD_DIR)/wolfpsa_cfg/crypto_config_generated.h
SECURE_CFLAGS += $(WT_SECURE_PSA_CFLAGS)
HSM_LIB_CFLAGS += $(WT_SECURE_PSA_CFLAGS)
HSM_WOLFHSM_CFLAGS += $(WT_SECURE_PSA_CFLAGS)
WOLFPSA_SECURE_SRCS := $(filter-out %/psa_store_posix.c %/psa_attestation.c \
    %/psa_ffm.c %/psa_its.c %/psa_store_zephyr.c %/psa_tf_psa.c,$(wildcard $(WOLFPSA_DIR)/src/*.c))
WT_SECURE_EXTRA_SRCS += $(ROOT)/src/services/native/psa_crypto_service.c
ifeq ($(WT_SECURE_PSA_PROFILE),extended)
WOLFCRYPT_SECURE_SRCS += $(WOLFSSL_DIR)/wolfcrypt/src/kdf.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/pwdbased.c
endif
ifneq ($(WT_AEAD_ONE),)
ifeq ($(WT_AEAD_USED),ccm)
WT_PSA_WANT_WITHOUT := --without PSA_WANT_ALG_GCM
endif
endif
ifneq ($(WT_SECURE_PSA_PROFILE),extended)
WT_PSA_WANT_WITHOUT += --without PSA_WANT_ALG_SP800_108_COUNTER_HMAC \
    --without PSA_WANT_ALG_SP800_108_COUNTER_CMAC \
    --without PSA_WANT_ALG_CCM_STAR_NO_TAG
endif
endif

ifeq ($(WT_ATTEST_COSE),1)
WT_SECURE_EXTRA_SRCS += \
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

ifeq ($(WT_INTERFACE_LOCAL_PROVIDER),1)
ifneq ($(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
include $(ROOT)/mk/crypto-profile.mk
SECURE_CFLAGS += $(WT_INTERFACE_PROFILE_FLAGS)
HSM_LIB_CFLAGS += $(WT_INTERFACE_PROFILE_FLAGS)
HSM_WOLFHSM_CFLAGS += $(WT_INTERFACE_PROFILE_FLAGS)
endif
endif

# TPM 2.0 and PKCS#11 are instances of one message relay; each links only its transfer mode.
ifneq ($(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
WT_SECURE_EXTRA_SRCS += $(ROOT)/src/services/msg_relay.c
$(BUILD_DIR)/wt_sec_msg_relay.o: SECURE_CFLAGS += \
    $(if $(filter y,$(CONFIG_TPM)),-DWT_MSG_RELAY_ONESHOT=1,-DWT_MSG_RELAY_CHUNKED=1)
endif

ifeq ($(CONFIG_TPM),y)
WT_SECURE_EXTRA_SRCS += \
    $(ROOT)/src/services/tpm/tpm_relay_service.c
ifeq ($(WT_INTERFACE_LOCAL_PROVIDER),1)
WT_IF_LIB_SRCS += \
    $(WOLFTPM_DIR)/src/fwtpm/fwtpm.c \
    $(WOLFTPM_DIR)/src/fwtpm/fwtpm_command.c \
    $(WOLFTPM_DIR)/src/fwtpm/fwtpm_crypto.c \
    $(WOLFTPM_DIR)/src/fwtpm/fwtpm_nv.c \
    $(WOLFTPM_DIR)/src/tpm2_util.c \
    $(WOLFTPM_DIR)/src/tpm2_packet.c \
    $(WOLFTPM_DIR)/src/tpm2_param_enc.c \
    $(WOLFTPM_DIR)/src/tpm2_crypto.c
WT_SECURE_EXTRA_SRCS += $(ROOT)/src/services/tpm/tpm_local_provider.c
endif
endif

ifeq ($(CONFIG_PKCS11),y)
WT_SECURE_EXTRA_SRCS += \
    $(ROOT)/src/services/pkcs11/pkcs11_relay_service.c
ifeq ($(WT_INTERFACE_LOCAL_PROVIDER),1)
WT_IF_LIB_SRCS += \
    $(WOLFPKCS11_DIR)/src/wolfpkcs11.c \
    $(WOLFPKCS11_DIR)/src/internal.c \
    $(WOLFPKCS11_DIR)/src/slot.c \
    $(WOLFPKCS11_DIR)/src/crypto.c
WOLFCRYPT_SECURE_SRCS += $(filter-out $(WOLFCRYPT_SECURE_SRCS), \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha512.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/kdf.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/pwdbased.c)
WT_SECURE_EXTRA_SRCS += \
    $(ROOT)/src/pkcs11/pkcs11_wire.c \
    $(ROOT)/src/pkcs11/pkcs11_provider.c \
    $(ROOT)/src/pkcs11/pkcs11_secure_heap.c
endif
endif

# The provider owns private copies of wolfCrypt and the wolfHSM client.
ifeq ($(if $(WT_IF),$(WT_INTERFACE_LOCAL_PROVIDER)),1)
WT_IF_LIB_SRCS += $(ROOT)/src/client/provider_crypto.c
ifeq ($(WT_ENGINE),hsm)
WT_IF_LIB_SRCS += $(ROOT)/src/client/hsm_psa_transport.c
WT_IF_WOLFHSM_SRCS := \
    $(WOLFHSM_DIR)/src/wh_client.c \
    $(WOLFHSM_DIR)/src/wh_client_crypto.c \
    $(WOLFHSM_DIR)/src/wh_client_cryptocb.c
endif
WT_IF_WOLFCRYPT_SRCS := $(WOLFCRYPT_SECURE_SRCS)
endif

# Shared code has no writable state; working contexts stay in the caller domain.
ifneq ($(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
HSM_LIB_CFLAGS += -DWOLFSSL_PUBLIC_MP
WT_INTERFACE_SHARED_CRYPTO := $(ARCH_WOLFCRYPT_ASM_SRCS) \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c
ifeq ($(WT_ENGINE),native)
WT_INTERFACE_SHARED_CRYPTO := $(filter-out \
    %/wc_port.c %/cryptocb.c %/random.c %/pwdbased.c,$(WOLFCRYPT_SECURE_SRCS))
endif
WT_IF_WOLFCRYPT_SRCS := $(filter-out $(WT_INTERFACE_SHARED_CRYPTO),$(WT_IF_WOLFCRYPT_SRCS))
endif

HSM_SECURE_BASE_OBJS := $(patsubst %.c,$(BUILD_DIR)/sec_%.o,$(notdir $(SECURE_SRCS)))
HSM_WOLFHSM_SEC_OBJS := $(patsubst %.c,$(BUILD_DIR)/wh_sec_%.o,$(notdir $(WOLFHSM_SECURE_SRCS)))
HSM_WOLFCRYPT_SEC_OBJS := $(patsubst %.c,$(BUILD_DIR)/wc_sec_%.o,$(notdir $(WOLFCRYPT_SECURE_SRCS)))
HSM_WT_EXTRA_OBJS := $(patsubst %.c,$(BUILD_DIR)/wt_sec_%.o,$(notdir $(WT_SECURE_EXTRA_SRCS)))
WOLFPSA_SEC_OBJS := $(patsubst %.c,$(BUILD_DIR)/wp_sec_%.o,$(notdir $(WOLFPSA_SECURE_SRCS)))
WT_IF_LIB_OBJS := $(patsubst %.c,$(BUILD_DIR)/$(WT_IF)_sec_%.o,$(notdir $(WT_IF_LIB_SRCS)))
WT_IF_WOLFCRYPT_RAW_OBJS := $(patsubst %.c,$(BUILD_DIR)/$(WT_IF)_wc_raw_%.o,$(notdir $(WT_IF_WOLFCRYPT_SRCS)))
WT_IF_WOLFCRYPT_OBJS := $(patsubst %.c,$(BUILD_DIR)/$(WT_IF)_wc_%.o,$(notdir $(WT_IF_WOLFCRYPT_SRCS)))
WT_IF_WOLFHSM_RAW_OBJS := $(patsubst %.c,$(BUILD_DIR)/$(WT_IF)_wh_raw_%.o,$(notdir $(WT_IF_WOLFHSM_SRCS)))
WT_IF_WOLFHSM_OBJS := $(patsubst %.c,$(BUILD_DIR)/$(WT_IF)_wh_%.o,$(notdir $(WT_IF_WOLFHSM_SRCS)))
WT_IF_NAMESPACE_MAP := $(BUILD_DIR)/$(WT_IF)_wc_symbols.map
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
    $(WOLFPSA_SEC_OBJS) \
    $(WT_IF_LIB_OBJS) \
    $(WT_IF_WOLFCRYPT_OBJS) \
    $(WT_IF_WOLFHSM_OBJS) \
    $(ARCH_TREE_OBJS) \
    $(MANIFEST_OBJ))

ifneq ($(WT_INTERFACE_PROFILE_HEADER),)
# Namespaced objects also have raw compile prerequisites; a dependency on
# only the final object does not order those compilations after generation.
WT_PROFILE_RAW_OBJS := $(WT_IF_WOLFCRYPT_RAW_OBJS) $(WT_IF_WOLFHSM_RAW_OBJS) \
    $(patsubst $(BUILD_DIR)/$(WT_IF)_sec_%.o,$(BUILD_DIR)/$(WT_IF)_sec_raw_%.o,$(WT_IF_LIB_OBJS))
$(ALL_SECURE_OBJS) $(WT_PROFILE_RAW_OBJS): $(WT_INTERFACE_PROFILE_HEADER)
# Rebuild namespace maps when makefile edits change private source membership.
$(ALL_SECURE_OBJS) $(WT_PROFILE_RAW_OBJS): $(MAKEFILE_LIST)
endif

# LTO cannot safely rewrite objects whose symbols are consumed by inline
# assembly or synthesized by the CMSE linker. Objects that own a
# filename-selected isolation band retain their object identity.
ifeq ($(WT_LTO),1)
WT_LTO_WOLFCRYPT_EXCLUDED_OBJS := \
    $(BUILD_DIR)/wc_sec_cryptocb.o \
    $(BUILD_DIR)/wc_sec_sp_cortexm.o \
    $(BUILD_DIR)/wc_sec_thumb2-aes-asm_c.o \
    $(BUILD_DIR)/wc_sec_thumb2-sha256-asm_c.o
WT_LTO_SECURE_EXCLUDED_OBJS := \
    $(BUILD_DIR)/sec_ivt.o \
    $(BUILD_DIR)/wt_sec_start_armv8m.o \
    $(BUILD_DIR)/sec_runtime.o \
    $(BUILD_DIR)/wt_sec_coroutine_armv8m.o \
    $(BUILD_DIR)/wt_sec_ffm_nsc.o \
    $(BUILD_DIR)/wt_sec_guest_context_armv8m.o \
    $(BUILD_DIR)/wt_sec_sp_fault_armv8m.o \
    $(BUILD_DIR)/wt_sec_spm_svc.o
# Every object the owner map gives to a partition or marks shared keeps its
# identity, so tools/check_secure_layout.py can check where its state lands.
WT_HASH := \#
WT_LTO_OWNED_NAMES := $(shell awk '{sub(/$(WT_HASH).*/, "")} \
    NF == 2 && $$2 != "spm" {sub(/\*$$/, "%", $$1); print $$1}' \
    $(ROOT)/tools/secure_owners.txt $(wildcard $(PORT_DIR)/secure_owners.txt))
WT_LTO_OWNED_OBJS := $(filter \
    $(addprefix $(BUILD_DIR)/,$(WT_LTO_OWNED_NAMES)),$(ALL_SECURE_OBJS))
$(WT_LTO_WOLFCRYPT_EXCLUDED_OBJS): HSM_LIB_CFLAGS += -fno-lto
$(WT_LTO_SECURE_EXCLUDED_OBJS): SECURE_CFLAGS += -fno-lto
$(WT_LTO_OWNED_OBJS): SECURE_CFLAGS += -fno-lto
$(WT_LTO_OWNED_OBJS): HSM_LIB_CFLAGS += -fno-lto
$(WT_LTO_OWNED_OBJS): HSM_WOLFHSM_CFLAGS += -fno-lto
# objcopy --redefine-syms renames native objects only, never LTO bytecode.
WT_LTO_NAMESPACE_RAW_OBJS := $(WT_IF_WOLFCRYPT_RAW_OBJS) $(WT_IF_WOLFHSM_RAW_OBJS) \
    $(patsubst $(BUILD_DIR)/$(WT_IF)_sec_%.o,$(BUILD_DIR)/$(WT_IF)_sec_raw_%.o,$(WT_IF_LIB_OBJS))
$(WT_LTO_NAMESPACE_RAW_OBJS): HSM_LIB_CFLAGS += -fno-lto
$(WT_LTO_NAMESPACE_RAW_OBJS): HSM_WOLFHSM_CFLAGS += -fno-lto
endif

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
# One PAL for every port; its addresses come from the port's memory_map.h.
TARGET_CONF_DIR := $(ROOT)/tests/conformance/pal
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
ifeq ($(WT_LTO),1)
$(CONF_SEC_OBJS): SECURE_CFLAGS += -fno-lto
endif

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
# The panic tests run across their panic-reset reboots, which the pinned M33MU
# supports.
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

# The manifest is rendered from the shared template under this build's layout
# configuration; WT_CONFORMANCE=1, CONFIG_VNET=y, CONFIG_TPM=y and
# CONFIG_PKCS11=y add their overlay, and
# a port registers the variants it supports in port/<soc>/port.json.
ifneq ($(filter y,$(CONFIG_TPM) $(CONFIG_PKCS11)),)
ifeq ($(WT_CONFORMANCE),1)
$(error CONFIG_TPM/CONFIG_PKCS11 conflicts with WT_CONFORMANCE=1; the manifests are mutually exclusive)
endif
ifeq ($(CONFIG_VNET),y)
$(error CONFIG_TPM/CONFIG_PKCS11 conflicts with CONFIG_VNET=y; the manifests are mutually exclusive)
endif
ifeq ($(WT_SECURE_PSA),1)
$(error CONFIG_TPM/CONFIG_PKCS11 conflicts with WT_SECURE_PSA=1; their guests do not use PSA Crypto)
endif
endif
ifeq ($(CONFIG_TPM)$(CONFIG_PKCS11),yy)
$(error CONFIG_TPM=y conflicts with CONFIG_PKCS11=y; select one application API)
endif
MANIFEST_VARIANT := base
MANIFEST_OVERLAY :=
ifeq ($(WT_CONFORMANCE),1)
MANIFEST_VARIANT := conformance
else ifeq ($(CONFIG_VNET),y)
MANIFEST_VARIANT := vnet
else ifeq ($(CONFIG_TPM),y)
MANIFEST_VARIANT := tpm
else ifeq ($(CONFIG_PKCS11),y)
MANIFEST_VARIANT := pkcs11
endif
ifneq ($(MANIFEST_VARIANT),base)
MANIFEST_OVERLAY := $(ROOT)/manifest/$(MANIFEST_VARIANT).json
WT_PORT_VARIANTS := $(shell python3 $(ROOT)/tests/target/lib/scenario_matrix.py \
    --port $(TARGET) --get build.variants)
ifeq ($(filter $(MANIFEST_VARIANT),$(WT_PORT_VARIANTS)),)
$(error TARGET=$(TARGET) registers no $(MANIFEST_VARIANT) manifest variant (port/$(TARGET)/port.json build.variants))
endif
endif
MANIFEST_INPUT := $(MANIFEST_DIR)/manifest.json

# FORCE: the renderer writes only on change, so a variant switch within one
# mtime tick still re-renders on a make that compares whole seconds.
$(MANIFEST_INPUT): $(MANIFEST_OVERLAY) $(WT_MANIFEST_RENDER_DEPS) \
		$(BUILD_MODE_STAMP) FORCE | $(MANIFEST_DIR)
	$(WT_MANIFEST_RENDER) $(addprefix --overlay ,$(MANIFEST_OVERLAY)) \
		--output $@ $(WT_MANIFEST_TEMPLATE)

# The generator checks the manifest against the port's platform limits and the
# FF-M runtime's compiled limits, read from the headers that size it.
wt_header_value = $(strip $(shell sed -n -E 's/^.define $(1)[[:space:]]+(0x[0-9A-Fa-f]+|[0-9]+)U.*/\1/p' $(2)))
WT_FFM_MAX_PARTITIONS_VALUE := $(call wt_header_value,WT_FFM_MAX_PARTITIONS,$(ROOT)/include/wolftrust/ffm.h)
WT_FFM_MAX_SERVICES_VALUE := $(call wt_header_value,WT_FFM_MAX_SERVICES,$(ROOT)/include/wolftrust/ffm.h)
WT_PSA_FRAMEWORK_VERSION_VALUE := $(call wt_header_value,PSA_FRAMEWORK_VERSION,$(ROOT)/include/psa/client.h)
ifeq ($(words $(WT_FFM_MAX_PARTITIONS_VALUE) $(WT_FFM_MAX_SERVICES_VALUE) $(WT_PSA_FRAMEWORK_VERSION_VALUE)),3)
else
$(error cannot read the FF-M runtime limits for the manifest generator)
endif
ifeq ($(words $(WT_PLATFORM_CAPABILITIES) $(WT_PLATFORM_MAX_DOMAINS) $(WT_PLATFORM_MAX_MEMORY_RESOURCES) $(WT_PLATFORM_MAX_INTERRUPTS) $(WT_PLATFORM_PORT_CAPABILITIES)),5)
else
$(error the WT_PLATFORM_* capabilities are unset (mk/arch-$(ARCH).mk))
endif
MANIFEST_GEN_ARGS := --supported-features 0x1 \
    --supported-framework-version $(WT_PSA_FRAMEWORK_VERSION_VALUE) \
    --address-bits 32 \
    --platform-capabilities $(WT_PLATFORM_CAPABILITIES) \
    --platform-max-domains $(WT_PLATFORM_MAX_DOMAINS) \
    --platform-max-memory-resources $(WT_PLATFORM_MAX_MEMORY_RESOURCES) \
    --platform-max-interrupts $(WT_PLATFORM_MAX_INTERRUPTS) \
    --port-capabilities $(WT_PLATFORM_PORT_CAPABILITIES) \
    --platform-header platform_caps.h \
    --ffm-max-partitions $(WT_FFM_MAX_PARTITIONS_VALUE) \
    --ffm-max-services $(WT_FFM_MAX_SERVICES_VALUE) --ffm-ipc-only

# The stamp records the selected variant; a mismatch regenerates even when
# mtimes tie within one second, so a stale variant can never be linked.
MANIFEST_MODE = MANIFEST_VARIANT=$(MANIFEST_VARIANT) CONFIG_VNET=$(CONFIG_VNET) CONFIG_TPM=$(CONFIG_TPM) CONFIG_PKCS11=$(CONFIG_PKCS11) WT_CONFORMANCE=$(WT_CONFORMANCE) WT_FWU=$(WT_FWU) GEN_OPTS=$(strip $(MANIFEST_GEN_ARGS) $(MANIFEST_EXCLUDE) $(WT_L3_MANIFEST_ARGS))

$(MANIFEST_STAMP): $(ROOT)/tools/manifest/generate.py $(MANIFEST_INPUT) \
		FORCE | $(MANIFEST_DIR)
	@if test -f "$@" && test "$$(cat "$@" 2>/dev/null)" = '$(MANIFEST_MODE)' \
			&& ! test $(MANIFEST_INPUT) -nt "$@" \
			&& ! test $(ROOT)/tools/manifest/generate.py -nt "$@"; then \
		:; \
	else \
		python3 $(ROOT)/tools/manifest/generate.py $(MANIFEST_INPUT) \
			$(MANIFEST_DIR) $(MANIFEST_GEN_ARGS) $(MANIFEST_EXCLUDE) \
			$(WT_L3_MANIFEST_ARGS) && printf '%s\n' '$(MANIFEST_MODE)' > "$@"; \
	fi

$(MANIFEST_GEN_C) $(MANIFEST_GEN_H): $(MANIFEST_STAMP)

# tests/host/manifest_ports generates every port manifest with these arguments.
.PHONY: print-manifest-gen-args
print-manifest-gen-args:
	@echo $(MANIFEST_GEN_ARGS) $(MANIFEST_EXCLUDE) $(WT_L3_MANIFEST_ARGS)

$(MANIFEST_OBJ): $(MANIFEST_GEN_C) $(MANIFEST_GEN_H) $(PORT_HEADERS) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $(MANIFEST_GEN_C)

$(WOLFHSM_CFG_H): | $(BUILD_DIR)
	printf '#include "%s"\n' "$(abspath $(WOLFHSM_RUNNER_DIR)/wh_settings_local.h)" > $@

.PHONY: FORCE
FORCE:

# The stamp is the build's configuration fingerprint: every define and flag
# the secure objects, the linker script and the link are produced with, so a
# changed input regenerates every output even when mtimes tie.
BUILD_MODE_LINES = \
		'ARCH=$(ARCH)' \
		'TARGET=$(TARGET)' \
		'WT_LAYOUT_CFLAGS=$(WT_LAYOUT_CFLAGS)' \
		'SECURE_CFLAGS=$(SECURE_CFLAGS)' \
		'SECURE_LD_DEFS=$(SECURE_LD_DEFS)' \
		'TARGET_LDFLAGS=$(TARGET_LDFLAGS)' \
		'WT_LAYOUT_LDFLAGS=$(WT_LAYOUT_LDFLAGS)' \
		'WT_ENGINE_HSM=$(WT_ENGINE_HSM)' \
		'WT_LTO=$(WT_LTO)' \
		'WT_PROVIDER_ECC_FALLBACK=$(WT_PROVIDER_ECC_FALLBACK)' \
		'WT_TPM_DA=$(WT_TPM_DA)' \
		'WT_ATTEST_COSE=$(WT_ATTEST_COSE)' \
		'WT_SECURE_PSA=$(WT_SECURE_PSA)' \
		'WT_SECURE_PSA_PROFILE=$(if $(filter 1,$(WT_SECURE_PSA)),$(WT_SECURE_PSA_PROFILE))' \
		'WT_PSA_SIZES=$(if $(filter 1,$(WT_SECURE_PSA)),$(subst / ,/,$(foreach v,$(WT_PSA_SIZE_VARS),$($(v))/)))' \
		'WT_CONFORMANCE=$(WT_CONFORMANCE)' \
		'CONFIG_VNET=$(CONFIG_VNET)' \
		'WT_VNET_TIMEOUT_TICKS=$(WT_VNET_TIMEOUT_TICKS)' \
		'CONFIG_TPM=$(CONFIG_TPM)' \
		'TPM_CRYPTO_DEVICE_CFLAGS=$(TPM_CRYPTO_DEVICE_CFLAGS)' \
		'CONFIG_PKCS11=$(CONFIG_PKCS11)' \
		'WT_FFM_NEGATIVE_PROBE=$(WT_FFM_NEGATIVE_PROBE)' \
		'WT_KEYSTORE_NEG_PROBE=$(WT_KEYSTORE_NEG_PROBE)' \
		'WT_PERIPH_SP_NEG_PROBE=$(WT_PERIPH_SP_NEG_PROBE)' \
		'WT_BAND_NEG_PROBE=$(WT_BAND_NEG_PROBE)' \
		'WT_RESTART_NEG_PROBE=$(WT_RESTART_NEG_PROBE)' \
		'WT_DEPUTY_NEG_PROBE=$(WT_DEPUTY_NEG_PROBE)' \
		'WT_HSM_PIN_NEG_PROBE=$(WT_HSM_PIN_NEG_PROBE)' \
		'WT_LAUNCH_DEBUG=$(WT_LAUNCH_DEBUG)' \
		'WT_ROLLBACK_PROBE=$(WT_ROLLBACK_PROBE)' \
		'WT_SP_FAULT_PROBE=$(WT_SP_FAULT_PROBE)' \
		'WT_HSM_FAULT_PROBE=$(WT_HSM_FAULT_PROBE)' \
		'WT_SP_FAULT_ALWAYS_PROBE=$(WT_SP_FAULT_ALWAYS_PROBE)' \
		'WT_PANIC_NEG_PROBE=$(WT_PANIC_NEG_PROBE)' \
		'WT_VNET_NEG_PROBE=$(WT_VNET_NEG_PROBE)' \
		'WT_TPM_NEG_PROBE=$(WT_TPM_NEG_PROBE)' \
		'WT_PKCS11_NEG_PROBE=$(WT_PKCS11_NEG_PROBE)' \
		'WT_MANIFEST_NEG_PROBE=$(WT_MANIFEST_NEG_PROBE)' \
		'WT_MANIFEST_RUNTIME_CHECK=$(WT_MANIFEST_RUNTIME_CHECK)' \
		'WT_HANDLER_IRQ_PROBE=$(WT_HANDLER_IRQ_PROBE)' \
		'WT_FP_NEG_PROBE=$(WT_FP_NEG_PROBE)' \
		'WT_SEAL_NEG_PROBE=$(WT_SEAL_NEG_PROBE)' \
		'WT_MSP_OVF_PROBE=$(WT_MSP_OVF_PROBE)' \
		'WT_BUSFAULT_NEG_PROBE=$(WT_BUSFAULT_NEG_PROBE)' \
		'WT_XN_NEG_PROBE=$(WT_XN_NEG_PROBE)' \
		'WT_SVC_NEG_PROBE=$(WT_SVC_NEG_PROBE)' \
		'WT_REMEASURE_PROBE=$(WT_REMEASURE_PROBE)' \
		'WT_BOOTUPDATE_PROBE=$(WT_BOOTUPDATE_PROBE)' \
		'WT_FWU=$(WT_FWU)' \
		'WT_MAX_GUESTS=$(WT_MAX_GUESTS)' \
		'WT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE)' \
		'WT_SPM_STACK_SIZE=$(WT_SPM_STACK_SIZE)' \
		'WT_WOLFCRYPT_SP_ASM=$(WT_WOLFCRYPT_SP_ASM)' \
		'WT_AEAD=$(WT_AEAD_USED)' \
		'WT_WOLFCRYPT_ARMASM=$(WT_WOLFCRYPT_ARMASM)' \
		'WT_SHA256_FAST=$(WT_SHA256_FAST)' \
		'WT_WOLFCRYPT_STM32_HASH=$(WT_WOLFCRYPT_STM32_HASH)' \
		'WT_TIMESLICE_MS=$(WT_TIMESLICE_MS)' \
		'WT_EXTRA_CFLAGS=$(WT_EXTRA_CFLAGS)' \
		'WT_INTERFACE_SHARED_CRYPTO=$(WT_INTERFACE_SHARED_CRYPTO)' \
		'WT_PKCS11_PIN_MAX_FAILURES=$(WT_PKCS11_PIN_MAX_FAILURES)' \
		'WT_PKCS11_TEST_PBKDF2_ITERATIONS=$(WT_PKCS11_TEST_PBKDF2_ITERATIONS)' \
		'WT_EXTRA_LDFLAGS=$(WT_EXTRA_LDFLAGS)'

$(BUILD_MODE_STAMP): FORCE | $(BUILD_DIR)
	@tmp="$@.tmp"; \
	printf '%s\n' $(BUILD_MODE_LINES) > "$$tmp"; \
	if test -f "$@" && cmp -s "$$tmp" "$@"; then \
		rm -f "$$tmp"; \
	else \
		mv "$$tmp" "$@"; \
	fi

# The resolved configuration for tools and tests outside this directory.
.PHONY: print-layout-cflags print-build-mode print-profile
print-profile:
	@echo $(foreach v,WT_PROFILE WT_SECURE_PSA_PROFILE WT_INTERFACE_PROFILE \
	    WT_MAX_GUESTS WT_MANIFEST_RUNTIME_CHECK WT_FWU WT_SHA256_FAST,$(v)=$($(v)))
print-layout-cflags:
	@echo '$(WT_LAYOUT_CFLAGS_ABS)'
print-build-mode:
	@printf '%s\n' $(BUILD_MODE_LINES)

$(BUILD_DIR)/wh_sec_%.o: $(WOLFHSM_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_WOLFHSM_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wp_sec_%.o: $(WOLFPSA_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) $(WT_PSA_CONFIG_H) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -DWT_PSA_POOL_TU -I$(WOLFPSA_DIR)/src -c -o $@ $<

ifeq ($(WT_SECURE_PSA),1)
# wolfPSA's PSA_WANT_* surface comes from the Secure image's own wolfCrypt set.
# FORCE: the generator rewrites the header only when the surface changes.
$(WT_PSA_CONFIG_H): $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) FORCE | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	python3 $(WOLFPSA_DIR)/tools/gen-crypto-config.py $(WT_PSA_WANT_WITHOUT) $@ "$(CC)" \
	    $(WOLFPSA_DIR)/tools/psa_want_probe.c $(HSM_LIB_CFLAGS) -I$(WOLFPSA_DIR)/src \
	    -DWT_PSA_WANT_PROBE
$(BUILD_DIR)/wt_sec_psa_crypto_service.o: $(WT_PSA_CONFIG_H)
endif

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/st/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

ifeq ($(if $(WT_IF),$(WT_INTERFACE_LOCAL_PROVIDER)),1)
ifeq ($(WT_IF),tpm)
$(BUILD_DIR)/tpm_sec_raw_fwtpm_command.o: $(WT_INTERFACE_PROFILE_DIR)/fwtpm_command.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFTPM_SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tpm_sec_raw_%.o: $(WOLFTPM_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFTPM_SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tpm_sec_raw_%.o: $(WOLFTPM_DIR)/src/fwtpm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFTPM_SECURE_CFLAGS) -c -o $@ $<
else
$(BUILD_DIR)/p11_sec_raw_crypto.o: $(WT_INTERFACE_PROFILE_DIR)/pkcs11_crypto.c \
        $(WOLFPKCS11_DIR)/src/crypto.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFPKCS11_SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/p11_sec_raw_%.o: $(WOLFPKCS11_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFPKCS11_SECURE_CFLAGS) -c -o $@ $<
endif

$(BUILD_DIR)/$(WT_IF)_sec_raw_%.o: $(ROOT)/src/client/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WT_IF_CLIENT_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/$(WT_IF)_wh_raw_%.o: $(WOLFHSM_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_WOLFHSM_CFLAGS) $(WT_IF_WOLFHSM_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/$(WT_IF)_wh_raw_wh_client_cryptocb.o: $(WT_INTERFACE_PROFILE_DIR)/hsm_callback.c \
        $(WOLFHSM_DIR)/src/wh_client_cryptocb.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP)
	$(CC) $(HSM_WOLFHSM_CFLAGS) $(WT_IF_WOLFHSM_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/$(WT_IF)_wc_raw_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WT_IF_WOLFCRYPT_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/$(WT_IF)_wc_raw_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WT_IF_WOLFCRYPT_CFLAGS) -c -o $@ $<

$(WT_IF_NAMESPACE_MAP): $(WT_IF_WOLFCRYPT_RAW_OBJS) | $(BUILD_DIR)
	@$(NM) -g --defined-only $^ | awk 'NF >= 2 && $$(NF - 1) ~ /^[A-ZTWV]$$/ { print $$NF, "$(WT_IF_NAMESPACE)" $$NF }' | LC_ALL=C sort -u > $@.tmp
	@mv $@.tmp $@

$(BUILD_DIR)/$(WT_IF)_wc_%.o: $(BUILD_DIR)/$(WT_IF)_wc_raw_%.o $(WT_IF_NAMESPACE_MAP)
	$(OBJCOPY) --redefine-syms=$(WT_IF_NAMESPACE_MAP) $< $@

$(BUILD_DIR)/$(WT_IF)_sec_%.o: $(BUILD_DIR)/$(WT_IF)_sec_raw_%.o $(WT_IF_NAMESPACE_MAP)
	$(OBJCOPY) --redefine-syms=$(WT_IF_NAMESPACE_MAP) $< $@

$(BUILD_DIR)/$(WT_IF)_wh_%.o: $(BUILD_DIR)/$(WT_IF)_wh_raw_%.o $(WT_IF_NAMESPACE_MAP)
	$(OBJCOPY) --redefine-syms=$(WT_IF_NAMESPACE_MAP) $< $@
else ifeq ($(WT_IF),tpm)
$(BUILD_DIR)/tpm_sec_%.o: $(WOLFTPM_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFTPM_SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tpm_sec_%.o: $(WOLFTPM_DIR)/src/fwtpm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFTPM_SECURE_CFLAGS) -c -o $@ $<
else ifeq ($(WT_IF),p11)
$(BUILD_DIR)/p11_sec_%.o: $(WOLFPKCS11_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) $(WOLFPKCS11_SECURE_CFLAGS) -c -o $@ $<
endif

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/arch/$(ARCH)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/arch/common/%.c $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/sched/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/sync/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHSM_RUNNER_DIR)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(PORT_DIR)/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

ifneq ($(PORT_COMMON_DIR),)
$(BUILD_DIR)/wt_sec_%.o: $(PORT_COMMON_DIR)/%.c $(PORT_HEADERS) $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(PORT_NEUTRAL_DIR)/%.c $(PORT_HEADERS) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<
endif

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

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/tpm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/pkcs11/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/pkcs11/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFCOSE_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

define wt_arch_tree_rule
$(BUILD_DIR)/wt_sec_$(notdir $(basename $(1))).o: $(1) $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
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

$(BUILD_DIR)/sec_%.o: $(PORT_COMMON_DIR)/%.c $(PORT_HEADERS) $(MANIFEST_GEN_H) \
		$(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(PORT_DIR)/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(ROOT)/src/%.c $(MANIFEST_GEN_H) $(WOLFHSM_CFG_H) \
		$(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

ifneq ($(SECURE_LD_IN),)
$(SECURE_LD): $(SECURE_LD_IN) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) -E -P -x c $(SECURE_LD_DEFS) -o $@ $<
endif

# The link reads the band placement from the port headers, so they are link
# inputs even when no object changed.
$(SECURE_ELF) $(SECURE_MAP) $(ARCH_LINK_OUTPUTS) &: $(ALL_SECURE_OBJS) $(SECURE_LD) \
		$(PORT_HEADERS) $(ROOT)/tools/check_secure_layout.py \
		$(ROOT)/tools/secure_owners.txt $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(RM) $(SECURE_BIN)
	$(if $(WT_SECURE_LINK_REFUSE),@$(RM) $(SECURE_ELF) $(SECURE_MAP) $(ARCH_LINK_OUTPUTS); \
		printf 'error: %s\n' '$(WT_SECURE_LINK_REFUSE)' >&2; exit 1)
	$(CC) $(SECURE_CFLAGS) \
		$(TARGET_LDFLAGS) \
		-Wl,--defsym=WT_SPM_STACK_SIZE=$(WT_SPM_STACK_SIZE) \
		-Wl,-T$(SECURE_LD) \
		-Wl,--gc-sections -Wl,-Map=$(SECURE_MAP),--cref \
		$(WT_LTO_LDFLAGS) $(WT_EXTRA_LDFLAGS) \
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
size-report: $(SECURE_ELF) $(SECURE_MAP)
	@$(SIZE) $(SECURE_ELF)
	@python3 $(ROOT)/tools/secure_ram.py $(SECURE_MAP)
	@$(SIZE) -A -d $(SECURE_ELF) | grep -vE '^(Total|section| *$$)' | sort -k2 -nr | head -12
	@$(TOOLPREFIX)nm --print-size --size-sort --radix=d $(SECURE_ELF) | \
		awk '$$3 ~ /^[bB]$$/' | tail -10
