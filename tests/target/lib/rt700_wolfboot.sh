# shellcheck shell=sh
# The pinned MIMXRT700 wolfBoot first stage both RT700 runners boot: upstream
# at RT700_WOLFBOOT_REF plus the two carried patches, built from the
# imx-rt700-tz config. Sourced; needs $here (tests/target).
RT700_WOLFBOOT_REF=e6d169c7218d82e33bd04e2c086146ed37ec0cca

# What a cached tree must match: the ref, both patches, and the make overrides.
rt700_wolfboot_stamp() {
    # shellcheck disable=SC2154  # $here is set by the sourcing runner
    printf '%s %s %s [%s]' "$RT700_WOLFBOOT_REF" \
        "$(cksum "$here/wolfboot-imxrt700-lifecycle.patch" | cut -d' ' -f1)" \
        "$(cksum "$here/wolfboot-imxrt700-guest-fence.patch" | cut -d' ' -f1)" \
        "$*"
}

rt700_wolfboot_current() {
    [ -s "$1/wolfboot.bin" ] && [ -x "$1/tools/keytools/sign" ] &&
        [ -s "$1/wolfboot_signing_private_key.der" ] &&
        [ "$(cat "$1/.wt_first_stage" 2>/dev/null)" = "$2" ]
}

# rt700_wolfboot_build <dir> [make VAR=value...]: builds <dir>/wolfboot.bin at
# the pin unless the tree there already matches; nonzero on any failure.
rt700_wolfboot_build() {
    rt700_dir="$1"
    shift
    rt700_stamp=$(rt700_wolfboot_stamp "$@")
    if rt700_wolfboot_current "$rt700_dir" "$rt700_stamp"; then
        return 0
    fi
    rm -rf "$rt700_dir" &&
    git clone --no-checkout https://github.com/wolfSSL/wolfBoot.git \
        "$rt700_dir" &&
    git -C "$rt700_dir" fetch --depth 1 origin "$RT700_WOLFBOOT_REF" &&
    git -C "$rt700_dir" checkout --detach "$RT700_WOLFBOOT_REF" &&
    git -C "$rt700_dir" apply "$here/wolfboot-imxrt700-lifecycle.patch" &&
    git -C "$rt700_dir" apply "$here/wolfboot-imxrt700-guest-fence.patch" &&
    git -C "$rt700_dir" submodule update --init --single-branch --depth 1 &&
    cp "$rt700_dir/config/examples/imx-rt700-tz.config" "$rt700_dir/.config" &&
    # keygen writes src/keystore.c, which the loader links, so the key and the
    # tools that locate it from the working directory come first. wolfBoot's
    # TARGET comes from its .config, never from a calling make.
    (
        unset TARGET MAKEFLAGS MFLAGS
        cd "$rt700_dir" &&
        make keytools &&
        make -j1 wolfboot_signing_private_key.der &&
        make -j1 "$@" wolfboot.bin
    ) &&
    printf '%s\n' "$rt700_stamp" > "$rt700_dir/.wt_first_stage"
}
