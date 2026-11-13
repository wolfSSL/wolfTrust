#!/bin/sh
# run.sh
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

root=$1
build=$2
make=${MAKE:-make}
count=0

# shellcheck source=../../target/lib/profile.sh disable=SC1091
. "$root/tests/target/lib/profile.sh"

mkdir -p "$build"
for manifest in "$root"/port/*/manifest*.json; do
    port_dir=$(dirname "$manifest")
    port=$(basename "$port_dir")
    variant=$(basename "$manifest" .json)
    case "$variant" in
        manifest-conformance) profiles="conformance" ;;
        *) profiles="default full" ;;
    esac
    for profile in $profiles; do
        out="$build/$port-$variant-$profile"
        if [ "$profile" = conformance ]; then
            flags="WT_CONFORMANCE=1"
            guests=1
        else
            flags=$(scenario_profile_flags "$profile")
            guests=$(scenario_profile_guests "$profile")
        fi
        # shellcheck disable=SC2086
        args=$("$make" -s --no-print-directory -C "$root" TARGET="$port" \
            $flags print-manifest-gen-args)

        rm -rf "$out"
        # shellcheck disable=SC2086
        python3 "$root/tools/manifest/generate.py" "$manifest" "$out" $args
        # shellcheck disable=SC2086
        ${CC:-cc} $CFLAGS -DWT_MAX_GUESTS="$guests" -I"$out" -I"$port_dir" \
            -DWT_TEST_MANIFEST="\"$port/$variant.json ($profile)\"" $LDFLAGS \
            -o "$out/test_manifest_port" \
            "$root/src/domain.c" "$root/src/manifest.c" "$root/src/spm.c" \
            "$root/src/partition.c" "$root/src/ffm.c" "$root/src/ipc.c" \
            "$root/src/ffm_domain.c" "$port_dir/partitions.c" \
            "$out/wolftrust_manifest_generated.c" main.c
        ${RUNNER:-} "$out/test_manifest_port"
        count=$((count + 1))
    done
done

if [ "$count" -eq 0 ]; then
    echo "FAIL: no port manifests found"
    exit 1
fi
echo "PASS: WT-PORT-0009 $count port manifest builds (default, full and conformance) pass the boot-time validator and port binding"
