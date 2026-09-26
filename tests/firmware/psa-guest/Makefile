# Portable bare-metal PSA test guest. Builds the wolfTrust Secure image's
# CMSE import library through the top-level Makefile, then links the same
# lifecycle into both Non-secure windows of the selected target with the
# STM32H563 FreeRTOS guest's freestanding recipe: wolfCrypt + wolfPSA for the
# PSA Crypto API, wolfCOSE for the attestation token verify, the OS-neutral
# FF-M, storage, and attestation clients, and (hsm engine) the wolfHSM client
# over the SPM-mediated transport.
TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size
NM := $(TOOLPREFIX)nm

ROOT := ../../..
TARGET ?= mimxrt700
ARCH ?= armv8m
WT_ENGINE ?= native
BUILD ?= build

include boards/$(TARGET)/board.mk

TOP_BUILD_DIR := $(ROOT)/build
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o

WOLFSSL_DIR := $(ROOT)/lib/wolfSSL
WOLFPSA_DIR := $(ROOT)/lib/wolfPSA
WOLFHSM_DIR := $(ROOT)/lib/wolfHSM
WOLFCOSE_DIR := $(ROOT)/lib/wolfCOSE
ZEPHYR_GUEST_DIR := $(ROOT)/tests/firmware/zephyr-stm32h5/apps/guest0_psa/src
TEE_MODULE_DIR := $(ROOT)/tests/firmware/zephyr-stm32h5/module/wolftrust-tee
WOLFHSM_MODULE_DIR := $(ROOT)/tests/firmware/zephyr-stm32h5/module/wolfhsm-client
NS_SETTINGS_DIR := $(ROOT)/tests/firmware/stm32h563/nonsecure

# Guest probes (each its own build): the restart fault, the attestation
# negatives, the compromised-guest wolfHSM probe (hsm engine only), and the
# firmware-update staging probe.
WT_GUEST_FAULT_PROBE ?= 0
WT_ATTEST_NEG_PROBE ?= 0
WT_HSM_ATTACK_PROBE ?= 0
WT_FWU_PROBE ?= 0
# Bytes of candidate body the FWU probe streams past the header, so a runner
# can push the staging across every data sector of its update partition.
WT_FWU_PROBE_STREAM_BYTES ?=
# The backend under test refuses a write that skips ahead of the staged extent.
WT_FWU_PROBE_SEQUENTIAL ?= 0
# The attestation verify pins the token measurement to wolfBoot's measurement
# of the signed Secure image and the lifecycle the Secure side reports.
WT_EXPECTED_MEASUREMENT_HEX ?=
WT_EXPECTED_LIFECYCLE ?= 0x3000u
WT_ATTEST_CBOR ?= wolfcose
# WT_M33MU_EXPECT_BKPT=1 ends the run on bkpt #0x7f once the lifecycle is done.
WT_M33MU_EXPECT_BKPT ?= 0

WOLFCRYPT_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha512.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/kdf.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/pwdbased.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c

# The whole wolfPSA front-end, as the Zephyr guest links it; the POSIX store
# is replaced by the volatile-only custom store, attestation by the FF-M client.
WOLFPSA_SRCS := $(filter-out %/psa_store_posix.c %/psa_attestation.c, \
    $(wildcard $(WOLFPSA_DIR)/src/*.c))

WOLFCOSE_SRCS := \
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

CLIENT_SRCS := \
    $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/client/psa_storage_client.c \
    $(TEE_MODULE_DIR)/src/wolftrust_attestation_client.c

ifeq ($(WT_ENGINE),native)
ENGINE_SRCS := $(ROOT)/src/client/crypto_native_client.c
ENGINE_DEFS := -DWT_ENGINE_NATIVE=1
GUEST_ENGINE_SRCS :=
else
ENGINE_SRCS := \
    $(WOLFHSM_DIR)/src/wh_client.c \
    $(WOLFHSM_DIR)/src/wh_client_crypto.c \
    $(WOLFHSM_DIR)/src/wh_client_cryptocb.c \
    $(WOLFHSM_DIR)/src/wh_comm.c \
    $(WOLFHSM_DIR)/src/wh_crypto.c \
    $(WOLFHSM_DIR)/src/wh_keyid.c \
    $(WOLFHSM_DIR)/src/wh_message_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_crypto.c \
    $(WOLFHSM_DIR)/src/wh_message_keystore.c \
    $(WOLFHSM_DIR)/src/wh_message_nvm.c \
    $(WOLFHSM_DIR)/src/wh_message_customcb.c \
    $(WOLFHSM_DIR)/src/wh_message_counter.c \
    $(WOLFHSM_DIR)/src/wh_utils.c \
    $(ROOT)/src/client/hsm_psa_transport.c
ENGINE_DEFS := -DWOLFHSM_CFG -DWOLF_CRYPTO_CB -DWT_ENGINE_HSM=1
GUEST_ENGINE_SRCS := $(WOLFHSM_MODULE_DIR)/src/wolfhsm_client_glue.c
endif


SHARED_SRCS := guest_libc.c $(WOLFCRYPT_SRCS) $(WOLFPSA_SRCS) $(WOLFCOSE_SRCS) \
    $(CLIENT_SRCS) $(ENGINE_SRCS)
# Per-guest objects: the verifier pins the guest's own PSA client id, the
# wolfHSM glue its client id.
GUEST_SRCS := main.c $(ZEPHYR_GUEST_DIR)/attestation_verify.c $(GUEST_ENGINE_SRCS)
GUEST0_SRCS := $(GUEST_SRCS)

WH_CFG_DIR := $(BUILD)/wh_include

CFLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only \
    -ffreestanding -fno-builtin -nostdlib -Os -g \
    -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
    -Wno-unused-parameter -Wno-type-limits \
    -ffunction-sections -fdata-sections -mno-unaligned-access \
    -I. -Imanifest -Iboards/$(TARGET) \
    -I$(ROOT)/include \
    -I$(WOLFSSL_DIR) \
    -I$(WOLFHSM_DIR) \
    -I$(WOLFPSA_DIR) \
    -I$(WOLFPSA_DIR)/wolfpsa \
    -I$(WOLFPSA_DIR)/src \
    -I$(WOLFCOSE_DIR)/include \
    -I$(TEE_MODULE_DIR)/include \
    -I$(ZEPHYR_GUEST_DIR) \
    -I$(NS_SETTINGS_DIR) \
    -I$(WH_CFG_DIR) \
    -DWOLFSSL_USER_SETTINGS \
    -DWOLFSSL_PSA_ENGINE \
    -DWOLFPSA_CUSTOM_STORE \
    -DWOLFPSA_NO_TRACE \
    -include $(ROOT)/tests/firmware/zephyr-stm32h5/module/wolfpsa/wolfpsa_no_trace.h \
    -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM -DWOLFSSL_ARM_ARCH=8 \
    -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_ARMASM_INLINE \
    -DWOLFSSL_ARMASM_NO_NEON -DWOLFSSL_ARMASM_THUMB2 \
    -DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT \
    -DWC_RESEED_INTERVAL=1000000 \
    -DWOLFCOSE_LEAN -DWOLFCOSE_ENABLE_DEPRECATED_ALGS -DWOLFCOSE_NO_SIGN1_SIGN \
    -DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_KEY_ENCODE \
    -DWOLFCOSE_NO_KEY_DECODE \
    -DWT_EXPECTED_LIFECYCLE=$(WT_EXPECTED_LIFECYCLE) \
    $(ENGINE_DEFS) \
    -include user_settings.h

ifeq ($(WT_M33MU_EXPECT_BKPT),1)
CFLAGS += -DWT_M33MU_EXPECT_BKPT
endif

ifneq ($(WT_EXPECTED_MEASUREMENT_HEX),)
CFLAGS += -DWT_EXPECTED_MEASUREMENT_HEX=\"$(WT_EXPECTED_MEASUREMENT_HEX)\"
endif

PROBE_CFLAGS :=
ifeq ($(WT_GUEST_FAULT_PROBE),1)
PROBE_CFLAGS += -DWT_GUEST_FAULT_PROBE
endif
ifeq ($(WT_ATTEST_NEG_PROBE),1)
PROBE_CFLAGS += -DWT_ATTEST_NEG_PROBE
endif
ifeq ($(WT_HSM_ATTACK_PROBE),1)
PROBE_CFLAGS += -DWT_HSM_ATTACK_PROBE
endif
ifeq ($(WT_FWU_PROBE),1)
PROBE_CFLAGS += -DWT_FWU_PROBE
endif
ifneq ($(WT_FWU_PROBE_STREAM_BYTES),)
PROBE_CFLAGS += -DWT_FWU_PROBE_STREAM_BYTES=$(WT_FWU_PROBE_STREAM_BYTES)
endif
ifeq ($(WT_FWU_PROBE_SEQUENTIAL),1)
PROBE_CFLAGS += -DWT_FWU_PROBE_SEQUENTIAL
endif

# guest0 carries the probes; guest1 is the peer that must keep running.
GUEST0_CFLAGS := -DGUEST_NAME=\"guest0\" -DWT_WOLFHSM_CLIENT_ID=1u \
    -DGUEST_PEER_RAM=$(GUEST1_RAM_ORIGIN)u $(PROBE_CFLAGS)
GUEST1_CFLAGS := -DGUEST_NAME=\"guest1\" -DWT_WOLFHSM_CLIENT_ID=2u \
    -DGUEST_PEER_RAM=$(GUEST0_RAM_ORIGIN)u -DWT_ATTEST_EXPECTED_CLIENT_ID=-2

SHARED_OBJS := $(patsubst %.c,$(BUILD)/shared_%.o,$(notdir $(SHARED_SRCS)))
GUEST0_OBJS := $(patsubst %.c,$(BUILD)/g0_%.o,$(notdir $(GUEST0_SRCS)))
GUEST1_OBJS := $(patsubst %.c,$(BUILD)/g1_%.o,$(notdir $(GUEST_SRCS)))

vpath %.c $(sort $(dir $(SHARED_SRCS) $(GUEST0_SRCS)))

all: $(BUILD)/guest0.bin $(BUILD)/guest1.bin

$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) ARCH=$(ARCH) TARGET=$(TARGET) TOOLPREFIX=$(TOOLPREFIX) \
	    WT_ENGINE=$(WT_ENGINE) build/secure_cmse_implib.o

# wh_settings.h finds its configuration through these trampolines.
$(WH_CFG_DIR)/wolfhsm_cfg.h: | $(BUILD)
	mkdir -p $(WH_CFG_DIR)
	printf '#include "%s"\n' "wh_settings_guest.h" > $@
	printf '#include "%s"\n' "wh_settings_guest.h" > $(WH_CFG_DIR)/wolfhsm_guest_cfg.h

$(BUILD)/shared_%.o: %.c $(WH_CFG_DIR)/wolfhsm_cfg.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/g0_%.o: %.c $(WH_CFG_DIR)/wolfhsm_cfg.h | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST0_CFLAGS) -c -o $@ $<

$(BUILD)/g1_%.o: %.c $(WH_CFG_DIR)/wolfhsm_cfg.h | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST1_CFLAGS) -c -o $@ $<

define link_guest
	$(CC) $(CFLAGS) \
	    -Wl,-Tguest.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(1) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(2) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(3) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(4) \
	    -Wl,--gc-sections \
	    -o $@ $(5) $(SHARED_OBJS) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $@
endef

$(BUILD)/guest0.elf: $(GUEST0_OBJS) $(SHARED_OBJS) $(SECURE_CMSE_IMPLIB) guest.ld
	$(call link_guest,$(GUEST0_FLASH_ORIGIN),$(GUEST0_FLASH_LENGTH),$(GUEST0_RAM_ORIGIN),$(GUEST0_RAM_LENGTH),$(GUEST0_OBJS))

$(BUILD)/guest1.elf: $(GUEST1_OBJS) $(SHARED_OBJS) $(SECURE_CMSE_IMPLIB) guest.ld
	$(call link_guest,$(GUEST1_FLASH_ORIGIN),$(GUEST1_FLASH_LENGTH),$(GUEST1_RAM_ORIGIN),$(GUEST1_RAM_LENGTH),$(GUEST1_OBJS))

# Every Secure crossing is SPM-mediated: the retired direct veneers must be
# absent, and the engine's client must be the one linked.
$(BUILD)/%.bin: $(BUILD)/%.elf
	@if $(NM) $< | grep -Eq 'WolfTrust_HSM_(Submit|Poll|Cancel)|WolfTrust_Attest_'; then \
	    echo "FAIL: retired direct veneers linked into $<" >&2; exit 1; fi
	@if [ "$(WT_ENGINE)" = "native" ]; then \
	    $(NM) $< | grep -q wt_crypto_native_call || { echo "FAIL: $< is not wired to the native crypto wire client" >&2; exit 1; }; \
	    ! $(NM) $< | grep -q wh_Client || { echo "FAIL: wolfHSM client linked into a native-engine guest" >&2; exit 1; }; \
	else \
	    $(NM) $< | grep -q wt_hsm_psa_transport_cb || { echo "FAIL: $< is not wired to the SPM-mediated wolfHSM transport" >&2; exit 1; }; \
	fi
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean FORCE
FORCE:
