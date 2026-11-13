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

# Build profiles every target runner puts ahead of its scenario's probe flags.
# "default" is the lean image `make` builds with no options; "full" turns
# every add-on back on. POSIX sh; source it, do not execute it.

# The add-on variables a profile owns, cleared before a profile is applied so
# the caller's environment never leaks into a run.
SCENARIO_PROFILE_VARS="WT_MAX_GUESTS WT_MANIFEST_RUNTIME_CHECK WT_FWU"

scenario_profile_flags() {
    case "$1" in
        default) echo "" ;;
        full)    echo "WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1" ;;
        *)
            echo "unknown build profile '$1' (want default or full)" >&2
            return 1
            ;;
    esac
}

# Guests the profile's Secure image schedules.
scenario_profile_guests() {
    case "$1" in
        full) echo 2 ;;
        *)    echo 1 ;;
    esac
}

scenario_profile_reset() {
    # shellcheck disable=SC2086
    unset $SCENARIO_PROFILE_VARS
}
