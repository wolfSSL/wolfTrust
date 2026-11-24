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
WT_SECURE_PSA_PROFILE ?= $(WT_PROFILE)
WT_PROFILE_RESOLVED := $(WT_PROFILE)
