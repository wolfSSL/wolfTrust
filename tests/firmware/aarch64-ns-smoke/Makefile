.DEFAULT_GOAL := all

# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# Normal-world payload for tests/target/run_qemu_a_scenario.sh (ns-smoke).
# MACHINE picks the NS console; the run address is NS DRAM (WT_NS_BASE): the
# loaded image first, then the RAM the payload copies .data into at every entry.
ROOT ?= ../../..
TOOLPREFIX ?= aarch64-none-elf-
MACHINE ?= virt
WT_NS_BASE ?= 0x40000000
WT_CONF_SUITE ?= ipc
# Run the board-neutral TPM 2.0 or PKCS#11 application (tests/firmware/interface-guest).
WT_NS_GUEST_INTERFACE ?=
ifneq ($(WT_NS_GUEST_INTERFACE),)
WT_NS_IMG_SIZE ?= 0x100000
WT_NS_RAM_SIZE ?= 0x100000
WT_NS_STACK_SIZE ?= 0x40000
endif
# The crypto and attestation suites link wolfPSA, wolfCrypt, and a heap.
ifneq ($(filter crypto attestation,$(WT_CONF_SUITE)),)
WT_NS_IMG_SIZE ?= 0x100000
WT_NS_RAM_SIZE ?= 0x100000
WT_NS_STACK_SIZE ?= 0x40000
endif
WT_NS_IMG_SIZE ?= 0x60000
WT_NS_RAM_SIZE ?= 0x20000
WT_RUN_CONFORMANCE ?= 0
ifeq ($(WT_RUN_CONFORMANCE),1)
WT_NS_STACK_SIZE ?= 0x10000
endif
WT_NS_STACK_SIZE ?= 0x4000
BUILD_DIR ?= build/$(MACHINE)

CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
NM := $(TOOLPREFIX)nm

# GICR: the boot core's GICv3 redistributor, probed only under a GICv3.
ifeq ($(MACHINE),virt)
UART := 0x09000000
GICR := 0x080A0000
WT_NS_CONFDATA_PA ?= 0x0E2C0000
else ifeq ($(MACHINE),versal-virt)
UART := 0xFF000000
GICR := 0xF9080000
WT_NS_CONFDATA_PA ?= 0x7F2C0000
else
$(error unsupported MACHINE=$(MACHINE) (virt or versal-virt))
endif

# Send a direct request to the Secure echo partition (ffa-guest-direct proof).
WT_NS_GUEST_ECHO ?= 0
CFLAGS := -mcpu=generic -mgeneral-regs-only -mstrict-align -ffreestanding \
    -fno-builtin -fno-pic -fno-stack-protector -ffunction-sections \
    -fdata-sections -nostdlib -O2 -g \
    -Wall -Wextra -Werror -I$(ROOT)/include -DWT_NS_UART=$(UART)u \
    -DWT_NS_GICR=$(GICR)u
ifeq ($(WT_NS_GUEST_ECHO),1)
CFLAGS += -DWT_NS_GUEST_ECHO=1
endif
# Power off through PSCI at the end of the run (the psci proof).
WT_NS_GUEST_PSCI ?= 0
ifeq ($(WT_NS_GUEST_PSCI),1)
CFLAGS += -DWT_NS_GUEST_PSCI=1
endif
# Spin long enough to be preempted by a Secure tick (the ffa-preempt proof).
WT_NS_PREEMPT ?= 0
ifeq ($(WT_NS_PREEMPT),1)
CFLAGS += -DWT_NS_PREEMPT=1
endif
# Reach the Secure services over the PSA FF-A transport (the positive/guest1
# proofs); WT_NS_GUEST_ID stamps the guest marker.
WT_NS_GUEST_PSA ?= 0
WT_NS_GUEST_ID ?= 0
WT_NS_VAULT_SECURED ?= 0
ifeq ($(WT_NS_VAULT_SECURED),1)
CFLAGS += -DWT_NS_VAULT_SECURED=1
endif
# Forge a client id and an NVM-group request at the relay (the hsmattackneg proof).
WT_NS_HSM_ATTACK ?= 0
ifeq ($(WT_NS_HSM_ATTACK),1)
CFLAGS += -DWT_NS_HSM_ATTACK=1
endif
# Sweep unimplemented function ids and confirm each is refused (the smcfuzz proof).
WT_NS_GUEST_FUZZ ?= 0
ifeq ($(WT_NS_GUEST_FUZZ),1)
CFLAGS += -DWT_NS_GUEST_FUZZ=1
endif
# Attempt to read Secure RAM from the Normal world (the secramneg proof).
WT_NS_GUEST_SECRAM ?= 0
WT_NS_SECURE_PROBE_PA ?= 0x0E300000
ifeq ($(WT_NS_GUEST_SECRAM),1)
CFLAGS += -DWT_NS_GUEST_SECRAM=1 -DWT_NS_SECURE_PROBE_PA=$(WT_NS_SECURE_PROBE_PA)u
endif
# Request a PSCI system reset that re-enters the boot chain (the resetneg proof).
WT_NS_GUEST_RESET ?= 0
ifeq ($(WT_NS_GUEST_RESET),1)
CFLAGS += -DWT_NS_GUEST_RESET=1
endif
# Offer malformed FFA_MEM_SHARE descriptors, each refused (the ffa-memneg proof).
WT_NS_GUEST_MEMNEG ?= 0
# Round-trip an ITS object through SERVICE_ITS and the VAULT partition behind
# it (the storage proof: the first SP-to-SP message driven from the Normal
# world).
WT_NS_GUEST_STORAGE ?= 0
LDFLAGS := -nostartfiles -Wl,--build-id=none -Wl,--gc-sections -T ns.ld \
    -Wl,--defsym=WT_NS_BASE=$(WT_NS_BASE) \
    -Wl,--defsym=WT_NS_IMG_SIZE=$(WT_NS_IMG_SIZE) \
    -Wl,--defsym=WT_NS_RAM_SIZE=$(WT_NS_RAM_SIZE) \
    -Wl,--defsym=WT_NS_STACK_SIZE=$(WT_NS_STACK_SIZE)

SRCS := ns.S ns.c
# The PSA, storage and conformance guests link the same OS-neutral PSA client
# every Armv8-M guest does plus the FF-A binding of its WolfTrust_FFM_* entry
# points; the service ids come from the generated manifest header of the
# matching secure build (WT_NS_MANIFEST_INC).
WT_NS_MANIFEST_INC ?=
WOLFHSM_DIR ?= $(ROOT)/lib/wolfHSM
WOLFSSL_DIR ?= $(ROOT)/lib/wolfSSL
ifneq ($(filter 1,$(WT_NS_GUEST_PSA) $(WT_NS_GUEST_STORAGE) $(WT_NS_GUEST_MEMNEG) $(WT_RUN_CONFORMANCE))$(WT_NS_GUEST_INTERFACE),)
ifneq ($(WT_NS_MANIFEST_INC),)
CFLAGS += -I$(WT_NS_MANIFEST_INC)
endif
SRCS += $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/arch/aarch64/ffa/psa_ffa_transport_arch.c \
    $(ROOT)/src/arch/aarch64/common/libc_min.c
endif
# The crypto engine of the matching secure build picks the guest's client.
WT_ENGINE ?= native
ifneq ($(words $(WT_ENGINE))/$(filter native hsm,$(WT_ENGINE)),1/$(WT_ENGINE))
$(error unsupported WT_ENGINE='$(WT_ENGINE)' (want native or hsm))
endif
ifeq ($(WT_NS_HSM_ATTACK)/$(WT_ENGINE),1/native)
$(error WT_NS_HSM_ATTACK=1 drives the wolfHSM wire and needs WT_ENGINE=hsm)
endif
ifeq ($(WT_NS_GUEST_PSA)/$(WT_ENGINE),1/native)
CFLAGS += -DWT_NS_GUEST_PSA=1 -DWT_NS_GUEST_ID=$(WT_NS_GUEST_ID) \
    -DWT_NS_ENGINE_NATIVE=1
SRCS += $(ROOT)/src/client/crypto_native_client.c
endif
ifeq ($(WT_NS_GUEST_PSA)/$(WT_ENGINE),1/hsm)
CFLAGS += -DWT_NS_GUEST_PSA=1 -DWT_NS_GUEST_ID=$(WT_NS_GUEST_ID) \
    -DWOLFHSM_CFG -I. -I$(WOLFHSM_DIR)
SRCS += $(ROOT)/src/client/hsm_psa_transport.c \
    $(WOLFHSM_DIR)/src/wh_client.c \
    $(WOLFHSM_DIR)/src/wh_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_keystore.c \
    $(WOLFHSM_DIR)/src/wh_message_counter.c \
    $(WOLFHSM_DIR)/src/wh_message_customcb.c \
    $(WOLFHSM_DIR)/src/wh_message_nvm.c \
    $(WOLFHSM_DIR)/src/wh_utils.c
endif
ifeq ($(WT_NS_GUEST_MEMNEG),1)
CFLAGS += -DWT_NS_GUEST_MEMNEG=1
SRCS += $(ROOT)/src/arch/aarch64/ffa/ffa_mem.c
endif
ifeq ($(WT_NS_GUEST_STORAGE),1)
CFLAGS += -DWT_NS_GUEST_STORAGE=1
endif
# The same sources and settings as the Armv8-M interface guest, on 64-bit SP math.
IF_GUEST_DIR := $(ROOT)/tests/firmware/interface-guest
WOLFTPM_DIR ?= $(ROOT)/lib/wolfTPM
WOLFPKCS11_DIR ?= $(ROOT)/lib/wolfPKCS11
IF_WIRED :=
IF_ABSENT :=
ifneq ($(WT_NS_GUEST_INTERFACE),)
ifeq ($(filter tpm pkcs11,$(WT_NS_GUEST_INTERFACE)),)
$(error WT_NS_GUEST_INTERFACE must be tpm or pkcs11)
endif
CONFIG_PKCS11 := $(if $(filter pkcs11,$(WT_NS_GUEST_INTERFACE)),y,n)
include $(ROOT)/mk/crypto-profile.mk
WT_PKCS11_FULL_SUITE ?= all
WT_PKCS11_SUITE ?= $(if $(filter default,$(WT_INTERFACE_PROFILE)),profile,$(WT_PKCS11_FULL_SUITE))
WT_TPM_DA ?= 1
CFLAGS += -I$(IF_GUEST_DIR) -I$(WOLFSSL_DIR) -DWOLFSSL_USER_SETTINGS \
    $(WT_INTERFACE_PROFILE_FLAGS) \
    -DSP_WORD_SIZE=64 -DHAVE___UINT128_T=1 -DWOLFSSL_USE_ALIGN \
    -DWT_NS_GUEST_INTERFACE=1 -DWT_TPM_DA=$(WT_TPM_DA) \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter \
    -Wno-type-limits
SRCS += $(ROOT)/src/client/msg_client.c
ifeq ($(WT_NS_GUEST_INTERFACE),tpm)
CFLAGS += -I$(WOLFTPM_DIR) -DWOLFTPM_USER_SETTINGS -DWT_TPM_ROLE_APP \
    -DWOLFTPM_SWTPM -DWOLF_CRYPTO_CB -DWOLFTPM_SMALL_STACK \
    '-DXSLEEP_MS(ms)=((void)(ms))' \
    -DWT_INTERFACE_TPM -DWT_TPM_APP_NAME=\"tpm-guest0\" \
    -DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT \
    -DWC_RESEED_INTERVAL=1000000 -DWT_WOLFHSM_CLIENT_ID=1u \
    -DWT_MSG_RELAY_ONESHOT=1
SRCS += $(IF_GUEST_DIR)/tpm_tests.c $(ROOT)/src/client/tpm_psa_transport.c \
    crypto/ns_crypto_port.c \
    $(addprefix $(WOLFTPM_DIR)/src/, tpm2.c tpm2_util.c tpm2_packet.c \
        tpm2_wrap.c tpm2_asn.c tpm2_crypto.c tpm2_param_enc.c tpm2_cryptocb.c) \
    $(addprefix $(WOLFSSL_DIR)/wolfcrypt/src/, aes.c cryptocb.c ecc.c \
        random.c sha256.c asn.c coding.c error.c hash.c hmac.c memory.c sha.c \
        sp_c64.c sp_int.c wolfmath.c wc_port.c sha512.c kdf.c pwdbased.c)
ifeq ($(WT_ENGINE),native)
CFLAGS += -DWT_ENGINE_NATIVE=1
SRCS += $(ROOT)/src/client/crypto_native_client.c
else
IF_WH_CFG_DIR := $(BUILD_DIR)/wh_include
CFLAGS += -DWT_ENGINE_HSM=1 -DWOLFHSM_CFG -I$(WOLFHSM_DIR) \
    -I$(ROOT)/tests/firmware/stm32h563/nonsecure -I$(IF_WH_CFG_DIR)
SRCS += $(ROOT)/src/client/hsm_psa_transport.c \
    $(ROOT)/tests/firmware/zephyr-stm32h5/module/wolfhsm-client/src/wolfhsm_client_glue.c \
    $(addprefix $(WOLFHSM_DIR)/src/, wh_client.c wh_client_crypto.c \
        wh_client_cryptocb.c wh_comm.c wh_crypto.c wh_keyid.c \
        wh_message_comm.c wh_message_crypto.c wh_message_keystore.c \
        wh_message_nvm.c wh_message_customcb.c wh_message_counter.c \
        wh_utils.c)
endif
IF_WIRED := wt_tpm_psa_transact TPM2_SWTPM_SendCommand
LDFLAGS += -Wl,-u,wt_tpm_psa_transact,-u,TPM2_SWTPM_SendCommand
IF_ABSENT := 'fwTPM|FWTPM_|WP11_'
else
SUITE_DEF := $(strip \
    $(if $(filter profile,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_PROFILE) \
    $(if $(filter core,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_CORE) \
    $(if $(filter all,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_ALL))
ifeq ($(SUITE_DEF),)
$(error WT_PKCS11_SUITE must be profile, core, or all)
endif
CFLAGS += -I$(WOLFPKCS11_DIR) -DWOLFPKCS11_USER_SETTINGS -DWOLFPKCS11_NO_ENV \
    -DWT_INTERFACE_PKCS11 -D$(SUITE_DEF)=1 \
    -DWT_PKCS11_APP_NAME=\"pkcs11-guest0\" -DWT_MSG_RELAY_CHUNKED=1
SRCS += $(IF_GUEST_DIR)/pkcs11_tests.c $(ROOT)/src/client/pkcs11_proxy.c \
    $(ROOT)/src/pkcs11/pkcs11_wire.c $(ROOT)/src/client/pkcs11_psa_transport.c \
    crypto/ns_crypto_port.c
IF_WIRED := C_GetFunctionList wt_pkcs11_psa_call
LDFLAGS += -Wl,-u,C_GetFunctionList,-u,wt_pkcs11_psa_call
IF_ABSENT := 'WP11_|wolfTPM|TPM2_|wc_'
endif
endif
# The memneg guest names memory it lent away in ITS calls.
ifneq ($(filter 1,$(WT_NS_GUEST_STORAGE) $(WT_NS_GUEST_MEMNEG)),)
SRCS += $(ROOT)/src/client/psa_storage_client.c
endif
# Run the unmodified Arm psa-arch-tests val NSPE from this payload: the FF-M
# IPC suite (confboot, WT_CONF_SUITE=ipc) or the dev_apis storage suite
# (devstorage, WT_CONF_SUITE=storage). val and the scheduled tests come from
# the secure build's fetched upstream tree and generated test lists;
# wolfTrust's psa/*.h stay first on the include path, the NS test list before
# the SPE one.
CONF_OBJS :=
ifeq ($(WT_RUN_CONFORMANCE),1)
WT_NS_CONF_UPSTREAM ?= $(ROOT)/build/upstream/psa-arch-tests/api-tests
ifeq ($(WT_CONF_SUITE),storage)
CONF_LIST_DIR := $(WT_NS_MANIFEST_INC)/storage/ns
CONF_SUITE_DIR := $(WT_NS_CONF_UPSTREAM)/dev_apis/storage
CONF_SUITE_DEFS := -DSTORAGE
CONF_SUITE_SRCS := $(CONF_SUITE_DIR)/common/test_storage_common.c
CONF_SUITE_INCS := -I$(CONF_SUITE_DIR)/common
else ifeq ($(WT_CONF_SUITE),crypto)
CONF_LIST_DIR := $(WT_NS_MANIFEST_INC)/crypto/ns
CONF_SUITE_DIR := $(WT_NS_CONF_UPSTREAM)/dev_apis/crypto
CONF_PAL_DIR := $(WT_NS_CONF_UPSTREAM)/platform/targets/common/nspe/crypto
CONF_SUITE_DEFS := -DCRYPTO
CONF_SUITE_SRCS := $(CONF_SUITE_DIR)/common/test_crypto_common.c \
    $(CONF_PAL_DIR)/pal_crypto_intf.c
CONF_SUITE_INCS := -I$(CONF_SUITE_DIR)/common -I$(CONF_PAL_DIR)
CONF_PSA := 1
else ifeq ($(WT_CONF_SUITE),attestation)
# The token parses with the wolfCOSE shim by default; WT_ATTEST_CBOR=qcbor
# swaps in the reference QCBOR library (test-only, fetch_qcbor.sh).
WT_ATTEST_CBOR ?= shim
ifeq ($(WT_ATTEST_CBOR),qcbor)
WT_QCBOR_DIR ?= $(ROOT)/build/upstream/qcbor
ATTEST_CBOR_SRCS := $(WT_QCBOR_DIR)/src/UsefulBuf.c \
    $(WT_QCBOR_DIR)/src/qcbor_encode.c $(WT_QCBOR_DIR)/src/qcbor_decode.c \
    $(WT_QCBOR_DIR)/src/ieee754.c
# QCBOR carries double types, so its objects use FP and the payload enables it.
ATTEST_CBOR_INCS := -I$(WT_QCBOR_DIR)/inc -I$(WT_QCBOR_DIR)/inc/qcbor \
    -DWT_NS_ENABLE_FP=1
else
ATTEST_CBOR_SRCS := $(ROOT)/tests/conformance/qcbor-shim/qcbor_shim.c
ATTEST_CBOR_INCS := -I$(ROOT)/tests/conformance/qcbor-shim
endif
CONF_LIST_DIR := $(WT_NS_MANIFEST_INC)/initial_attestation/ns
CONF_SUITE_DIR := $(WT_NS_CONF_UPSTREAM)/dev_apis/initial_attestation
CONF_PAL_DIR := $(WT_NS_CONF_UPSTREAM)/platform/targets/common/nspe/initial_attestation
CONF_SUITE_DEFS := -DINITIAL_ATTESTATION -DPSA_ATTESTATION_PROFILE_2 \
    -DPSA_INITIAL_ATTEST_MAX_TOKEN_SIZE=640
CONF_SUITE_SRCS := $(CONF_PAL_DIR)/pal_attestation_intf.c \
    $(CONF_PAL_DIR)/pal_attestation_crypto.c \
    $(ROOT)/tests/firmware/zephyr-stm32h5/module/wolftrust-tee/src/wolftrust_attestation_client.c \
    $(ATTEST_CBOR_SRCS)
CONF_SUITE_INCS := -I$(CONF_PAL_DIR) $(ATTEST_CBOR_INCS) \
    -I$(ROOT)/tests/firmware/zephyr-stm32h5/module/wolftrust-tee/include
# attestneg runs a Normal-world negative probe instead of val, reusing this
# build's attestation client and COSE stack plus the guest's own token verify.
WT_NS_ATTEST_NEG ?= 0
ifeq ($(WT_NS_ATTEST_NEG),1)
CONF_SUITE_DEFS += -DWT_NS_ATTEST_NEG=1
CONF_SUITE_SRCS += $(ROOT)/tests/firmware/zephyr-stm32h5/apps/guest0_psa/src/attestation_verify.c \
    $(ROOT)/lib/wolfCOSE/src/wolfcose_recipient.c
CONF_SUITE_INCS += -I$(ROOT)/tests/firmware/zephyr-stm32h5/apps/guest0_psa/src
endif
CONF_PSA := 1
else
CONF_LIST_DIR := $(WT_NS_MANIFEST_INC)/ns
CONF_SUITE_DIR := $(WT_NS_CONF_UPSTREAM)/ff/ipc
CONF_SUITE_DEFS := -DIPC
CONF_SUITE_SRCS :=
CONF_SUITE_INCS :=
endif
CONF_TESTS := $(shell cat $(CONF_LIST_DIR)/testlist.txt 2>/dev/null)
ifeq ($(CONF_TESTS),)
$(error WT_RUN_CONFORMANCE=1 needs the secure build's generated test list at $(CONF_LIST_DIR)/testlist.txt)
endif
CFLAGS := -I$(CONF_LIST_DIR) $(CFLAGS) \
    -DWT_NS_GUEST_CONF=1 $(CONF_SUITE_DEFS) -DVAL_NSPE_BUILD \
    -DNONSECURE_TEST_BUILD -DVERBOSITY=3 \
    -DWT_SPM_CONFDATA_PA=$(WT_NS_CONFDATA_PA)u \
    -ffunction-sections -fdata-sections \
    -I$(WT_NS_CONF_UPSTREAM)/val/common \
    -I$(WT_NS_CONF_UPSTREAM)/val/nspe \
    -I$(WT_NS_CONF_UPSTREAM)/val/spe \
    -I$(WT_NS_CONF_UPSTREAM)/platform/targets/common/nspe \
    -I$(ROOT)/port/common/aarch64/conformance \
    $(CONF_SUITE_INCS) \
    $(foreach t,$(CONF_TESTS),-I$(CONF_SUITE_DIR)/$(t))
LDFLAGS += -Wl,--gc-sections
SRCS += conformance_pal.c $(ROOT)/src/client/psa_storage_client.c
CONF_CFLAGS := $(filter-out -Werror,$(CFLAGS)) -Wno-unused-function \
    -Wno-unused-variable -Wno-unused-parameter -Wno-type-limits
CONF_SRCS := $(WT_NS_CONF_UPSTREAM)/val/common/val_log.c \
    $(addprefix $(WT_NS_CONF_UPSTREAM)/val/nspe/,val_entry.c val_dispatcher.c \
        val_framework.c val_interfaces.c val_peripherals.c val_platform.c \
        val_crypto.c val_storage.c val_attestation.c) \
    $(CONF_SUITE_SRCS) \
    $(foreach t,$(CONF_TESTS),$(CONF_SUITE_DIR)/$(t)/$(t).c \
        $(CONF_SUITE_DIR)/$(t)/test_entry_$(t:test_%=%).c)
ifeq ($(CONF_PSA),1)
# wolfPSA over wolfCrypt runs in the guest itself; persistent keys ride the
# ITS client through wolfPSA's secure-storage backend.
WOLFSSL_DIR ?= $(ROOT)/lib/wolfSSL
WOLFPSA_DIR ?= $(ROOT)/lib/wolfPSA
WOLFCOSE_DIR ?= $(ROOT)/lib/wolfCOSE
CFLAGS += -DWOLFSSL_USER_SETTINGS -DWT_NS_HEAP=1 -Icrypto \
    -I$(WOLFSSL_DIR) -I$(WOLFPSA_DIR) -I$(WOLFPSA_DIR)/wolfpsa \
    -I$(WOLFPSA_DIR)/src -I$(WOLFCOSE_DIR)/include \
    -DWOLFCOSE_LEAN -DWOLFCOSE_ENABLE_DEPRECATED_ALGS -DWOLFCOSE_NO_SIGN1_SIGN \
    -DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_KEY_ENCODE \
    -DWOLFCOSE_NO_KEY_DECODE
# <psa/crypto.h> takes its PSA_WANT_* surface from this guest's wolfCrypt set.
PSA_CFG_H := $(BUILD_DIR)/wolfpsa_cfg/crypto_config_generated.h
CFLAGS += -I$(BUILD_DIR)/wolfpsa_cfg
CONF_CFLAGS := $(filter-out -Werror,$(CFLAGS)) -Wno-unused-function \
    -Wno-unused-variable -Wno-unused-parameter -Wno-type-limits
CONF_SRCS += crypto/ns_crypto_port.c crypto/psa_store_ns.c \
    $(filter-out %/psa_store_posix.c %/psa_store_zephyr.c %/psa_attestation.c,$(wildcard $(WOLFPSA_DIR)/src/*.c)) \
    $(addprefix $(WOLFSSL_DIR)/wolfcrypt/src/,aes.c asn.c chacha.c \
        chacha20_poly1305.c cmac.c coding.c cryptocb.c des3.c ecc.c error.c \
        hash.c hmac.c kdf.c logging.c md5.c memory.c poly1305.c pwdbased.c \
        random.c ripemd.c rsa.c sha.c sha256.c sha3.c sha512.c signature.c \
        sp_c64.c sp_int.c wc_encrypt.c wc_port.c wolfmath.c) \
    $(addprefix $(WOLFCOSE_DIR)/src/,wolfcose_cbor.c wolfcose_util.c \
        wolfcose_alg.c wolfcose_ecc.c wolfcose_hdr.c wolfcose_key.c \
        wolfcose_struct.c wolfcose_sign1.c)
endif
CONF_OBJS := $(addprefix $(BUILD_DIR)/conf/,$(notdir $(CONF_SRCS:.c=.o)))
vpath %.c $(sort $(dir $(CONF_SRCS)))
endif
ELF := $(BUILD_DIR)/ns.elf
BIN := $(BUILD_DIR)/ns.bin

.PHONY: all clean FORCE

FORCE:

all: $(ELF) $(BIN)

$(BUILD_DIR) $(BUILD_DIR)/conf:
	mkdir -p $@

ifneq ($(PSA_CFG_H),)
# FORCE: the generator rewrites the header only when the surface changes.
$(PSA_CFG_H): FORCE
	mkdir -p $(dir $@)
	python3 $(WOLFPSA_DIR)/tools/gen-crypto-config.py $@ "$(CC)" \
	    $(WOLFPSA_DIR)/tools/psa_want_probe.c $(CONF_CFLAGS)
$(CONF_OBJS) $(ELF): $(PSA_CFG_H)
endif

$(BUILD_DIR)/conf/%.o: %.c | $(BUILD_DIR)/conf
	$(CC) $(CONF_CFLAGS) -c -o $@ $<

ifeq ($(WT_ATTEST_CBOR),qcbor)
$(addprefix $(BUILD_DIR)/conf/,UsefulBuf.o qcbor_encode.o qcbor_decode.o ieee754.o): \
    CONF_CFLAGS := $(filter-out -mgeneral-regs-only,$(CONF_CFLAGS))
endif

ifneq ($(WT_NS_GUEST_INTERFACE),)
$(ELF): $(WT_INTERFACE_PROFILE_HEADER)
ifeq ($(WT_NS_GUEST_INTERFACE)/$(WT_ENGINE),tpm/hsm)
$(IF_WH_CFG_DIR)/wolfhsm_cfg.h:
	mkdir -p $(IF_WH_CFG_DIR)
	printf '#include "%s"\n' "wh_settings_guest.h" > $@
	printf '#include "%s"\n' "wh_settings_guest.h" > $(IF_WH_CFG_DIR)/wolfhsm_guest_cfg.h
$(ELF): $(IF_WH_CFG_DIR)/wolfhsm_cfg.h
endif
endif

$(ELF): $(SRCS) $(CONF_OBJS) ns.ld | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(CONF_OBJS) -lgcc
ifneq ($(WT_NS_GUEST_INTERFACE),)
	@for sym in $(IF_WIRED); do \
	    $(NM) --defined-only $@ | grep -q " $$sym$$" || \
	    { echo "FAIL: $@ lacks $$sym" >&2; rm -f $@; exit 1; }; done
	@if $(NM) --defined-only $@ | grep -Eq $(IF_ABSENT); then \
	    echo "FAIL: provider code linked into $@" >&2; rm -f $@; exit 1; fi
endif

$(BIN): $(ELF)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -rf build
