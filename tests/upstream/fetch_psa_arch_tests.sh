#!/bin/sh
# fetch_psa_arch_tests.sh
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

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
revision=$(sed -n '1p' "$script_dir/psa-arch-tests.rev")
destination=${1:-"$script_dir/../../build/upstream/psa-arch-tests"}
repository=https://github.com/ARM-software/psa-arch-tests.git

case "$revision" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *)
        echo "invalid PSA architecture test revision" >&2
        exit 1
        ;;
esac

if [ ! -d "$destination/.git" ]; then
    git clone --no-checkout "$repository" "$destination"
fi
git -C "$destination" fetch --depth 1 origin "$revision"
git -C "$destination" checkout --detach "$revision"
actual=$(git -C "$destination" rev-parse HEAD)
if [ "$actual" != "$revision" ]; then
    echo "PSA architecture test revision mismatch" >&2
    exit 1
fi

# Arm psa-arch-tests issue #125: get_info reports the applied protections.
storage_patch="$script_dir/psa-arch-tests-storage-flags.patch"
if ! git -C "$destination" apply --reverse --check "$storage_patch" \
        2>/dev/null; then
    git -C "$destination" apply "$storage_patch"
fi
printf '%s\n' "$destination"
