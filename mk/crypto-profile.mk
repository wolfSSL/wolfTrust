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
WT_CRYPTO_PROFILE ?= default
WT_CRYPTO_PROFILE_DIR := $(abspath $(BUILD_DIR)/crypto-profile)
WT_CRYPTO_PROFILE_HEADER := $(WT_CRYPTO_PROFILE_DIR)/selected_profile.h
WT_CRYPTO_PROFILE_FLAGS := -include $(WT_CRYPTO_PROFILE_HEADER)
export WT_CRYPTO_PROFILE WT_CRYPTO_CONFIG WT_CRYPTO_ENABLE WT_CRYPTO_DISABLE

.PHONY: crypto-profile-force
crypto-profile-force:

$(WT_CRYPTO_PROFILE_HEADER): crypto-profile-force
	@python3 $(ROOT)/tools/crypto_profile.py --root $(abspath $(ROOT)) \
		--output $(WT_CRYPTO_PROFILE_DIR) --profile $(WT_CRYPTO_PROFILE)

$(WT_CRYPTO_PROFILE_DIR)/fwtpm_command.c: $(WT_CRYPTO_PROFILE_HEADER)
	@test -f $@

$(WT_CRYPTO_PROFILE_DIR)/pkcs11_crypto.c: $(WT_CRYPTO_PROFILE_HEADER)
	@test -f $@
