# interface.mk
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
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# The TPM 2.0 or PKCS#11 application build every architecture's guest shares.
# Set ROOT, WT_INTERFACE, WT_ENGINE, IF_SP_MATH and IF_ITS_CFLAGS, and include
# mk/crypto-profile.mk, first; the guest adds its own CPU, console and libc.
IF_GUEST_DIR ?= $(ROOT)/tests/firmware/interface-guest
IF_PRE_INCLUDE ?=
IF_SP_MATH_CFLAGS ?=
IF_WOLFSSL_DIR := $(ROOT)/lib/wolfSSL
IF_WOLFTPM_DIR := $(ROOT)/lib/wolfTPM
IF_WOLFPKCS11_DIR := $(ROOT)/lib/wolfPKCS11

ifeq ($(filter tpm pkcs11,$(WT_INTERFACE)),)
$(error WT_INTERFACE must be tpm or pkcs11)
endif
ifeq ($(filter native hsm,$(WT_ENGINE)),)
$(error WT_ENGINE must be native or hsm)
endif

# The default profile trims the token, so only the profile suite fits it.
WT_PKCS11_FULL_SUITE ?= all
WT_PKCS11_SUITE ?= $(if $(filter default,$(WT_INTERFACE_PROFILE)),profile,$(WT_PKCS11_FULL_SUITE))
WT_TPM_DA ?= 1
WT_TPM_RESET_PROBE ?= 0
WT_PKCS11_RESET_PROBE ?= 0

IF_CFLAGS := -I$(IF_GUEST_DIR) -I$(ROOT)/include -I$(IF_WOLFSSL_DIR) \
    -DWOLFSSL_USER_SETTINGS $(IF_PRE_INCLUDE) $(WT_INTERFACE_PROFILE_FLAGS) \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter \
    -Wno-type-limits -DWT_TPM_DA=$(WT_TPM_DA) \
    -DWT_TPM_RESET_PROBE=$(WT_TPM_RESET_PROBE) \
    -DWT_PKCS11_RESET_PROBE=$(WT_PKCS11_RESET_PROBE)

ifeq ($(WT_INTERFACE),tpm)
IF_APP_NAME := tpm-guest0
IF_CFLAGS += -I$(IF_WOLFTPM_DIR) -DWOLFTPM_USER_SETTINGS -DWT_TPM_ROLE_APP \
    -DWOLFTPM_SWTPM -DWOLF_CRYPTO_CB -DWOLFTPM_SMALL_STACK \
    -DWT_INTERFACE_TPM -DWT_TPM_APP_NAME=\"$(IF_APP_NAME)\" \
    $(IF_SP_MATH_CFLAGS) -DNO_ERROR_STRINGS -DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT \
    -DWC_RESEED_INTERVAL=1000000 -DWT_WOLFHSM_CLIENT_ID=1u \
    -DWT_MSG_RELAY_ONESHOT=1
IF_SRCS := $(IF_GUEST_DIR)/tpm_tests.c $(ROOT)/src/client/tpm_psa_transport.c \
    $(ROOT)/src/client/msg_client.c \
    $(addprefix $(IF_WOLFTPM_DIR)/src/, tpm2.c tpm2_util.c tpm2_packet.c \
        tpm2_wrap.c tpm2_asn.c tpm2_crypto.c tpm2_param_enc.c tpm2_cryptocb.c) \
    $(addprefix $(IF_WOLFSSL_DIR)/wolfcrypt/src/, aes.c cryptocb.c ecc.c \
        random.c sha256.c asn.c coding.c error.c hash.c hmac.c memory.c sha.c \
        $(IF_SP_MATH) sp_int.c wolfmath.c wc_port.c sha512.c kdf.c pwdbased.c)
IF_WIRED := wt_tpm_psa_transact TPM2_SWTPM_SendCommand wt_tpm_psa_random
IF_ABSENT := 'fwTPM|FWTPM_|WP11_|wh_Client|wt_crypto_native'
IF_RESET_PROBE := $(WT_TPM_RESET_PROBE)
else
IF_APP_NAME := pkcs11-guest0
IF_SUITE_DEF := $(strip \
    $(if $(filter profile,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_PROFILE) \
    $(if $(filter core,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_CORE) \
    $(if $(filter objects,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_OBJECTS) \
    $(if $(filter crypto,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_CRYPTO) \
    $(if $(filter negative,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_NEGATIVE) \
    $(if $(filter all,$(WT_PKCS11_SUITE)),WT_PKCS11_SUITE_ALL))
ifeq ($(IF_SUITE_DEF),)
$(error WT_PKCS11_SUITE must be profile, core, objects, crypto, negative, or all)
endif
IF_CFLAGS += -I$(IF_WOLFPKCS11_DIR) -DWOLFPKCS11_USER_SETTINGS -DWOLFPKCS11_NO_ENV \
    -DWT_INTERFACE_PKCS11 -D$(IF_SUITE_DEF)=1 -DWT_PKCS11_APP_NAME=\"$(IF_APP_NAME)\" \
    -DWT_MSG_RELAY_CHUNKED=1
IF_SRCS := $(IF_GUEST_DIR)/pkcs11_tests.c $(ROOT)/src/client/pkcs11_proxy.c \
    $(ROOT)/src/client/msg_client.c $(ROOT)/src/pkcs11/pkcs11_wire.c \
    $(ROOT)/src/client/pkcs11_psa_transport.c
IF_WIRED := C_GetFunctionList wt_pkcs11_psa_call
IF_ABSENT := 'WP11_|wolfTPM|TPM2_|wc_'
IF_RESET_PROBE := $(WT_PKCS11_RESET_PROBE)
endif
# A reset probe marks its first launch in ITS, which outlives the guest.
ifeq ($(IF_RESET_PROBE),1)
IF_CFLAGS += $(IF_ITS_CFLAGS)
IF_SRCS += $(ROOT)/src/client/psa_storage_client.c
endif
IF_KEEP := $(foreach sym,$(IF_WIRED),-Wl,-u,$(sym))

# The application reaches its provider only through the SPM-mediated service.
define wt_interface_link_check
	@for sym in $(IF_WIRED); do \
	    $(NM) --defined-only $(1) | grep -q " $$sym$$" || \
	    { echo "FAIL: $(1) lacks $$sym" >&2; rm -f $(1); exit 1; }; done
	@if $(NM) --defined-only $(1) | grep -Eq $(IF_ABSENT); then \
	    echo "FAIL: provider code linked into $(1)" >&2; rm -f $(1); exit 1; fi
	@if $(NM) --defined-only $(1) | grep -Eq ' psa_(crypto_init|generate_|hash_|cipher_|aead_|mac_|sign_|verify_)'; then \
	    echo "FAIL: PSA Crypto linked into the $(WT_INTERFACE) application" >&2; rm -f $(1); exit 1; fi
endef
