# crypto-profile.mk
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

# Generate one operation selection shared by the provider and its clients.
WT_INTERFACE_PROFILE ?= $(if $(filter extended,$(WT_PROFILE)),extended,default)
WT_INTERFACE_PROFILE_DIR := $(abspath $(BUILD_DIR)/crypto-profile)
WT_INTERFACE_PROFILE_HEADER := $(WT_INTERFACE_PROFILE_DIR)/selected_profile.h
WT_INTERFACE_PROFILE_FLAGS := -include $(WT_INTERFACE_PROFILE_HEADER)
export WT_INTERFACE_PROFILE WT_INTERFACE_CONFIG WT_INTERFACE_ENABLE WT_INTERFACE_DISABLE

.PHONY: crypto-profile-force
crypto-profile-force:

$(WT_INTERFACE_PROFILE_HEADER): crypto-profile-force
	@python3 $(ROOT)/tools/crypto_profile.py --root $(abspath $(ROOT)) \
		--output $(WT_INTERFACE_PROFILE_DIR) --profile $(WT_INTERFACE_PROFILE) \
		--interface $(if $(filter y,$(CONFIG_PKCS11)),pkcs11,tpm)

$(WT_INTERFACE_PROFILE_DIR)/fwtpm_command.c: $(WT_INTERFACE_PROFILE_HEADER)
	@test -f $@

$(WT_INTERFACE_PROFILE_DIR)/pkcs11_crypto.c: $(WT_INTERFACE_PROFILE_HEADER)
	@test -f $@

$(WT_INTERFACE_PROFILE_DIR)/hsm_callback.c: $(WT_INTERFACE_PROFILE_HEADER)
	@test -f $@
