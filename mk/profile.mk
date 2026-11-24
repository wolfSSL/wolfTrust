# Build profile: tiny, small, default or extended. It picks the add-on
# defaults and the Secure PSA algorithm set; a flag set explicitly still wins.
WT_PROFILE ?= default
ifneq ($(filter-out tiny small default extended,$(WT_PROFILE))$(words $(WT_PROFILE)),1)
$(error unsupported WT_PROFILE='$(WT_PROFILE)' (want tiny, small, default or extended))
endif
ifeq ($(WT_PROFILE),extended)
WT_MAX_GUESTS ?= 2
WT_MANIFEST_RUNTIME_CHECK ?= 1
WT_FWU ?= 1
WT_SHA256_FAST ?= 1
endif
# tiny carries no ECC: an HMAC attestation key and no vault P-256 key
# operations. The wolfHSM engine keeps both, its server signs with ECC.
ifeq ($(WT_PROFILE)/$(filter hsm,$(WT_ENGINE))$(filter 1,$(WT_ENGINE_HSM)),tiny/)
WT_ATTEST_KEY ?= hmac
WT_VAULT_ECC ?= 0
endif
WT_ATTEST_KEY ?= ecc
WT_VAULT_ECC ?= 1
WT_SECURE_PSA_PROFILE ?= $(WT_PROFILE)
WT_PROFILE_RESOLVED := $(WT_PROFILE)
