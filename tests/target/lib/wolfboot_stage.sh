# shellcheck shell=bash
# The wolfBoot first stage for one port: the pinned repository and ref, the
# port's config and carried patches, built once per (ref, patches, config,
# make arguments) into a directory the runners sign with. Sourced by
# run_target.sh after the port profile set WOLFBOOT_REPO, WOLFBOOT_REF,
# WOLFBOOT_CONFIG and WOLFBOOT_PATCHES.

wolfboot_stamp() {
    local patch sums=""
    for patch in ${WOLFBOOT_PATCHES:-}; do
        sums="$sums $(cksum "$patch" | cut -d' ' -f1)"
    done
    printf '%s %s%s [%s]' "$WOLFBOOT_REF" "$WOLFBOOT_CONFIG" "$sums" "$*"
}

wolfboot_current() {
    [ -s "$1/wolfboot.bin" ] && [ -x "$1/tools/keytools/sign" ] &&
        [ -s "$1/wolfboot_signing_private_key.der" ] &&
        [ "$(cat "$1/.wt_first_stage" 2>/dev/null)" = "$2" ]
}

# A first stage that needs the MCUXpresso SDK (WOLFBOOT_NEEDS_SDK=1 in the
# port profile) finds it under ~/NXP or in MCUXPRESSO and MCUXPRESSO_CMSIS.
wolfboot_sdk_env() {
    [ "${WOLFBOOT_NEEDS_SDK:-0}" = "1" ] || return 0
    if [ -z "${MCUXPRESSO:-}" ] && [ -d "$HOME/NXP/mcuxpresso-sdk/mcuxsdk" ]; then
        export MCUXPRESSO="$HOME/NXP/mcuxpresso-sdk/mcuxsdk"
    fi
    if [ -z "${MCUXPRESSO_CMSIS:-}" ] && [ -d "$HOME/NXP/CMSIS_5/CMSIS" ]; then
        export MCUXPRESSO_CMSIS="$HOME/NXP/CMSIS_5/CMSIS"
    fi
    [ -d "${MCUXPRESSO:-/nonexistent}" ] && [ -d "${MCUXPRESSO_CMSIS:-/nonexistent}" ]
}

# wolfboot_build <dir> [make args...]: the directory holds wolfboot.bin,
# tools/keytools/sign and wolfboot_signing_private_key.der afterwards.
wolfboot_build() {
    local dir="$1" stamp patch
    shift
    stamp="$(wolfboot_stamp "$@")"
    if wolfboot_current "$dir" "$stamp"; then
        log "Reusing wolfBoot first stage in $dir"
        return 0
    fi
    # A tree the user named (WOLFBOOT_DIR_OVERRIDE) is never replaced.
    if [ -n "${WOLFBOOT_DIR_OVERRIDE:-}" ] && [ "$dir" = "$WOLFBOOT_DIR_OVERRIDE" ]; then
        log "wolfBoot: $dir was not built by lib/wolfboot_stage.sh from this pin, patches and make arguments; rebuild it or unset the override"
        return 1
    fi
    wolfboot_sdk_env || {
        log "wolfBoot needs the MCUXpresso SDK to build: set MCUXPRESSO and MCUXPRESSO_CMSIS"
        return 1
    }
    stage "wolfBoot $WOLFBOOT_REF ($WOLFBOOT_CONFIG)"
    rm -rf "$dir" &&
    git clone --no-checkout "$WOLFBOOT_REPO" "$dir" &&
    git -C "$dir" -c protocol.version=2 fetch --depth 1 origin "$WOLFBOOT_REF" &&
    git -C "$dir" checkout --detach "$WOLFBOOT_REF" || return 1
    for patch in ${WOLFBOOT_PATCHES:-}; do
        git -C "$dir" apply "$patch" || return 1
    done
    git -C "$dir" submodule update --init --single-branch --depth 1 &&
    cp "$dir/$WOLFBOOT_CONFIG" "$dir/.config" || return 1
    # keygen writes src/keystore.c, which the loader links, so the key and the
    # tools that locate it from the working directory come first; keytools
    # link serially (a parallel link races on the shared sp_* objects) and
    # wolfboot.bin at -j1 (include/target.h is regenerated in place). wolfBoot's
    # TARGET comes from its .config, never from a calling make.
    (
        unset TARGET MAKEFLAGS MFLAGS
        cd "$dir" &&
        make keytools &&
        make -j1 wolfboot_signing_private_key.der &&
        make -j1 "$@" wolfboot.bin
    ) || return 1
    printf '%s\n' "$stamp" > "$dir/.wt_first_stage"
}
