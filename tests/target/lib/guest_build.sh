# guest_build.sh
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

# Keep the guest optimization policy consistent with the Secure image.
case "${WT_LTO:-1}" in
    0) WT_GUEST_LTO_FLAGS= ;;
    1) WT_GUEST_LTO_FLAGS=-flto=auto ;;
    *) echo "unsupported WT_LTO=${WT_LTO}" >&2; exit 1 ;;
esac
# LTO can emit memory calls after its global dead-code pass.
WT_GUEST_KEEP_FLAGS=-Wl,-u,memcpy,-u,memset,-u,memmove,-u,memcmp


# Keep RTOS assembly and cross-world calls opaque to whole-program analysis.
wt_guest_compile_platform()
{
    WT_GUEST_PLATFORM_OBJECTS=
    wt_platform_index=0
    for wt_platform_source do
        wt_platform_object="$BUILD_DIR/platform_$wt_platform_index.o"
        # CFLAGS is the same intentional word list used by the final link.
        # shellcheck disable=SC2086
        "$GUEST_CC" $CFLAGS -fno-lto -c "$wt_platform_source" \
            -o "$wt_platform_object"
        WT_GUEST_PLATFORM_OBJECTS="$WT_GUEST_PLATFORM_OBJECTS $wt_platform_object"
        wt_platform_index=$((wt_platform_index + 1))
    done
}


wt_guest_prepare_profile()
{
    WT_GUEST_PROFILE_DIR="$BUILD_DIR/crypto-profile"
    python3 "$ROOT/tools/crypto_profile.py" --root "$ROOT" \
        --output "$WT_GUEST_PROFILE_DIR" --profile "${WT_CRYPTO_PROFILE:-default}"
    WT_GUEST_PROFILE_FLAGS="-include $WT_GUEST_PROFILE_DIR/selected_profile.h"
}

# Interface providers use FF-M IPC but must not pull in PSA Crypto.
wt_guest_reject_psa_crypto()
{
    if printf '%s\n' "$1" | grep -Eq '[[:space:]](wt_profile_real_)?psa_(crypto_init|generate_|hash_|cipher_|aead_|mac_|sign_|verify_|key_derivation_)'; then
        echo "FAIL: PSA Crypto linked into an independent TPM/PKCS11 image" >&2
        exit 1
    fi
}

# A selected HSM engine need not retain a second software ECC implementation.
wt_guest_hsm_ecc_flags()
{
    WT_GUEST_HSM_ECC_FLAGS=
    case "${WT_PROVIDER_ECC_FALLBACK:-0}" in
        0)
            if [ "$WT_ENGINE" = hsm ]; then
                WT_GUEST_HSM_ECC_FLAGS=-DWOLF_CRYPTO_CB_ONLY_ECC
            fi
            ;;
        1) ;;
        *) echo "WT_PROVIDER_ECC_FALLBACK must be 0 or 1" >&2; exit 2 ;;
    esac
}

wt_guest_profile_enabled()
{
    python3 - "$WT_GUEST_PROFILE_DIR/selection.json" "$1" "$2" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as selection:
    names = json.load(selection)[sys.argv[2]]
raise SystemExit(0 if sys.argv[3] in names else 1)
PYTHON
}
