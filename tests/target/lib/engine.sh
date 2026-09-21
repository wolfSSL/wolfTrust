# engine.sh
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

# Resolve the crypto engine exactly as mk/common.mk does, so the Secure image
# and every guest always agree. POSIX sh; source it, do not execute it.
# Legacy WT_ENGINE_HSM=0/1 maps onto WT_ENGINE; a conflict or an unsupported
# value stops the build instead of producing a hybrid image.

wt_engine_legacy=""
case "${WT_ENGINE_HSM:-}" in
    1) wt_engine_legacy="hsm" ;;
    0) wt_engine_legacy="native" ;;
    "") ;;
    *)
        echo "unsupported WT_ENGINE_HSM='${WT_ENGINE_HSM}' (want 0 or 1)" >&2
        exit 2
        ;;
esac

if [ -n "${WT_ENGINE:-}" ] && [ -n "$wt_engine_legacy" ] && \
        [ "$WT_ENGINE" != "$wt_engine_legacy" ]; then
    echo "conflicting engine selectors: WT_ENGINE=$WT_ENGINE but" \
         "WT_ENGINE_HSM=$WT_ENGINE_HSM selects $wt_engine_legacy" >&2
    exit 2
fi

WT_ENGINE="${WT_ENGINE:-${wt_engine_legacy:-native}}"
case "$WT_ENGINE" in
    native|hsm) ;;
    *)
        echo "unsupported WT_ENGINE='$WT_ENGINE' (want native or hsm)" >&2
        exit 2
        ;;
esac
export WT_ENGINE
unset wt_engine_legacy
