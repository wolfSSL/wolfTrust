# shellcheck shell=sh
# The pinned MCXN947 wolfBoot first stage the MCXN947 runner boots: the
# secure-application handoff branch (wolfSSL/wolfBoot#948, pinned at its
# fork ref until it merges; bump MCXN947_WOLFBOOT_REPO/REF to upstream then),
# built from the mcxn-tz-wolftrust config. Sourced; needs $here (tests/target).
MCXN947_WOLFBOOT_REPO=https://github.com/aidangarske/wolfBoot.git
MCXN947_WOLFBOOT_REF=1d47fa7b622b654a8e6a53cf53e7811c42618505
MCXN947_WOLFBOOT_CONFIG=config/examples/mcxn-tz-wolftrust.config

# What a cached tree must match: the ref, the config, the carried life cycle
# patch (the MCXN HAL at the pin reports a fixed SECURED life cycle; the
# patch reads the part's), and the make overrides.
mcxn947_wolfboot_stamp() {
    # shellcheck disable=SC2154  # $here is set by the sourcing runner
    printf '%s %s %s [%s]' "$MCXN947_WOLFBOOT_REF" "$MCXN947_WOLFBOOT_CONFIG" \
        "$(cksum "$here/wolfboot-mcxn947-lifecycle.patch" | cut -d' ' -f1)" "$*"
}

mcxn947_wolfboot_current() {
    [ -s "$1/wolfboot.bin" ] && [ -x "$1/tools/keytools/sign" ] &&
        [ -s "$1/wolfboot_signing_private_key.der" ] &&
        [ "$(cat "$1/.wt_first_stage" 2>/dev/null)" = "$2" ]
}

# The MCUXpresso SDK the wolfBoot MCXN HAL compiles against: the environment
# (as the CI stages it), else the sibling checkout wolfBoot's config expects.
mcxn947_wolfboot_sdk() {
    if [ -z "${MCUXPRESSO:-}" ] && [ -d "$HOME/NXP/mcuxpresso-sdk/mcuxsdk" ]; then
        MCUXPRESSO="$HOME/NXP/mcuxpresso-sdk/mcuxsdk"
        export MCUXPRESSO
    fi
    if [ -z "${MCUXPRESSO_CMSIS:-}" ] && [ -d "$HOME/NXP/CMSIS_5/CMSIS" ]; then
        MCUXPRESSO_CMSIS="$HOME/NXP/CMSIS_5/CMSIS"
        export MCUXPRESSO_CMSIS
    fi
    [ -n "${MCUXPRESSO:-}" ] && [ -d "$MCUXPRESSO" ] &&
        [ -n "${MCUXPRESSO_CMSIS:-}" ] && [ -d "$MCUXPRESSO_CMSIS" ]
}

# mcxn947_wolfboot_build <dir> [make VAR=value...]: builds <dir>/wolfboot.bin
# at the pin unless the tree there already matches; nonzero on any failure.
mcxn947_wolfboot_build() {
    mcxn947_dir="$1"
    shift
    mcxn947_stamp=$(mcxn947_wolfboot_stamp "$@")
    if mcxn947_wolfboot_current "$mcxn947_dir" "$mcxn947_stamp"; then
        return 0
    fi
    mcxn947_wolfboot_sdk || {
        echo "MCXN947 wolfBoot needs the MCUXpresso SDK: set MCUXPRESSO and MCUXPRESSO_CMSIS" >&2
        return 1
    }
    rm -rf "$mcxn947_dir" &&
    git clone --no-checkout "$MCXN947_WOLFBOOT_REPO" "$mcxn947_dir" &&
    git -C "$mcxn947_dir" fetch --depth 1 origin "$MCXN947_WOLFBOOT_REF" &&
    git -C "$mcxn947_dir" checkout --detach "$MCXN947_WOLFBOOT_REF" &&
    git -C "$mcxn947_dir" apply "$here/wolfboot-mcxn947-lifecycle.patch" &&
    git -C "$mcxn947_dir" submodule update --init --single-branch --depth 1 &&
    cp "$mcxn947_dir/$MCXN947_WOLFBOOT_CONFIG" "$mcxn947_dir/.config" &&
    # keygen writes src/keystore.c, which the loader links, so the key and the
    # tools that locate it from the working directory come first. wolfBoot's
    # TARGET comes from its .config, never from a calling make.
    (
        unset TARGET MAKEFLAGS MFLAGS
        cd "$mcxn947_dir" &&
        make keytools &&
        make -j1 wolfboot_signing_private_key.der &&
        make -j1 "$@" wolfboot.bin
    ) &&
    printf '%s\n' "$mcxn947_stamp" > "$mcxn947_dir/.wt_first_stage"
}
