# shellcheck shell=sh
# profile.sh
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

# Build profiles every target runner puts ahead of its scenario's probe flags:
# tiny, small, default (the image `make` builds with no options) or extended
# (every add-on). mk/profile.mk holds the same table for the build itself.
# POSIX sh; source it, do not execute it.

# The variables a profile owns, cleared before a profile is applied so the
# caller's environment never leaks into a run.
SCENARIO_PROFILE_VARS="WT_PROFILE WT_SECURE_PSA_PROFILE WT_MAX_GUESTS \
WT_MANIFEST_RUNTIME_CHECK WT_FWU WT_SHA256_FAST WT_ATTEST_KEY WT_VAULT_ECC"

scenario_profile_flags() {
    case "$1" in
        tiny|small|default) echo "WT_PROFILE=$1" ;;
        extended) echo "WT_PROFILE=extended WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1 WT_SHA256_FAST=1" ;;
        *)
            echo "unknown build profile '$1' (want tiny, small, default or extended)" >&2
            return 1
            ;;
    esac
}

# Guests the profile's Secure image schedules.
scenario_profile_guests() {
    case "$1" in
        extended) echo 2 ;;
        *)        echo 1 ;;
    esac
}

scenario_profile_reset() {
    # shellcheck disable=SC2086
    unset $SCENARIO_PROFILE_VARS
}
