# shellcheck shell=bash
# The pinned M33MU emulator for one port: a caller-supplied binary, a build
# from a prior scenario with the same pin and patch, or a fresh build under
# /tmp. Sourced by run_target.sh after the port profile set M33MU_REF,
# M33MU_PATCH (may be empty) and M33MU_CMAKE_EXTRA.

m33mu_stamp() {
    if [ -n "${M33MU_PATCH:-}" ]; then
        printf '%s %s' "$M33MU_REF" "$(cksum "$M33MU_PATCH" | cut -d' ' -f1)"
    else
        printf '%s' "$M33MU_REF"
    fi
}

# Sets M33MU to a usable emulator binary.
m33mu_prepare() {
    local src="/tmp/m33mu_${1}_src" stamp
    stamp="$(m33mu_stamp)"
    if [ -n "${M33MU:-}" ] && [ -x "$M33MU" ]; then
        log "Using prebuilt M33MU: $M33MU"
        return 0
    fi
    if [ -x "$src/build/m33mu" ] &&
       [ "$(cat "$src/.wt_m33mu" 2>/dev/null)" = "$stamp" ]; then
        M33MU="$src/build/m33mu"
        log "Reusing M33MU from a prior scenario: $M33MU"
        return 0
    fi
    stage "build M33MU $M33MU_REF"
    rm -rf "$src"
    git clone --no-checkout https://github.com/danielinux/m33mu.git "$src"
    git -C "$src" fetch --depth 1 origin "$M33MU_REF"
    git -C "$src" checkout --detach "$M33MU_REF"
    if [ -n "${M33MU_PATCH:-}" ]; then
        git -C "$src" apply "$M33MU_PATCH"
    fi
    # shellcheck disable=SC2086
    cmake -S "$src" -B "$src/build" -DM33MU_ENABLE_WOLFSSL=OFF ${M33MU_CMAKE_EXTRA:-}
    cmake --build "$src/build" --target m33mu -j"$(nproc)"
    printf '%s\n' "$stamp" > "$src/.wt_m33mu"
    M33MU="$src/build/m33mu"
}
