# shellcheck shell=sh
# The pinned STM32L562 wolfBoot first stage the STM32L562 runner boots:
# upstream wolfBoot at the merge of the STM32L5 secure-application handoff,
# built from the stm32l5-tz-wolftrust config. Sourced; needs $here
# (tests/target).
STM32L562_WOLFBOOT_REPO=https://github.com/wolfSSL/wolfBoot.git
STM32L562_WOLFBOOT_REF=8c1f19e71d67b3762b4e735b3decc60d1264951c
STM32L562_WOLFBOOT_CONFIG=config/examples/stm32l5-tz-wolftrust.config

# What a cached tree must match: the ref, the config and the make overrides
# (the conformance layout rebuilds with a larger slot).
stm32l562_wolfboot_stamp() {
    printf '%s %s [%s]' "$STM32L562_WOLFBOOT_REF" "$STM32L562_WOLFBOOT_CONFIG" "$*"
}

# A cached tree (often under /tmp) is reused only when this user owns it and
# nobody else can write it, so another account cannot plant the signer.
stm32l562_owned_dir() {
    # shellcheck disable=SC3067  # bash and dash both have -O
    [ -d "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] || return 1
    case "$(ls -ld "$1")" in
        ?????w*|????????w*) return 1 ;;
    esac
}

stm32l562_wolfboot_current() {
    stm32l562_owned_dir "$1" &&
    [ -s "$1/wolfboot.bin" ] && [ -x "$1/tools/keytools/sign" ] &&
        [ -s "$1/wolfboot_signing_private_key.der" ] &&
        [ "$(cat "$1/.wt_first_stage" 2>/dev/null)" = "$2" ]
}

# stm32l562_wolfboot_build <dir> [make VAR=value...]: builds <dir>/wolfboot.bin
# at the pin unless the tree there already matches; nonzero on any failure.
stm32l562_wolfboot_build() {
    stm32l562_dir="$1"
    shift
    stm32l562_stamp=$(stm32l562_wolfboot_stamp "$@")
    if stm32l562_wolfboot_current "$stm32l562_dir" "$stm32l562_stamp"; then
        return 0
    fi
    rm -rf "$stm32l562_dir" &&
    git clone --no-checkout "$STM32L562_WOLFBOOT_REPO" "$stm32l562_dir" &&
    git -C "$stm32l562_dir" fetch --depth 1 origin "$STM32L562_WOLFBOOT_REF" &&
    git -C "$stm32l562_dir" checkout --detach "$STM32L562_WOLFBOOT_REF" &&
    git -C "$stm32l562_dir" submodule update --init --single-branch --depth 1 \
        lib/wolfssl &&
    cp "$stm32l562_dir/$STM32L562_WOLFBOOT_CONFIG" "$stm32l562_dir/.config" &&
    # keygen writes src/keystore.c, which the loader links, so the key and the
    # tools that locate it from the working directory come first. wolfBoot's
    # TARGET comes from its .config, never from a calling make.
    (
        unset TARGET MAKEFLAGS MFLAGS
        cd "$stm32l562_dir" &&
        make keytools &&
        make -j1 wolfboot_signing_private_key.der &&
        make -j1 "$@" wolfboot.bin
    ) &&
    printf '%s\n' "$stm32l562_stamp" > "$stm32l562_dir/.wt_first_stage"
}
