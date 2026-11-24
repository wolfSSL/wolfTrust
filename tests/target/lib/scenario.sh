# shellcheck shell=bash
# Shell helpers the target runners share: logging, the pass/fail check line
# format the suites grep for, and the port's isolation level 3 layout. The
# scenario table and every assertion live in lib/scenarios.py.

log()   { printf '%s\n' "$*"; }
stage() { log "== $*"; }
fail()  { log "FAIL: $*"; exit 1; }
check() { if [ "$1" -eq 0 ]; then log "  [check] PASS  $2"; \
          else log "  [check] FAIL  $2"; exit 1; fi; }
# shellcheck disable=SC2154  # $log is the sourcing runner's boot log path
count()     { grep -c -F -- "$1" "$log" || true; }
count_re()  { grep -c -E -- "$1" "$log" || true; }
expect()    { check "$([ "$(count "$2")" -ge 1 ]; echo $?)" "$1"; }
expect_re() { check "$([ "$(count_re "$2")" -ge 1 ]; echo $?)" "$1"; }
refute_re() { check "$([ "$(count_re "$2")" -eq 0 ]; echo $?)" "$1"; }
expect_n()  { local n; n="$(count "$3")"; \
              check "$([ "$n" -eq "$2" ]; echo $?)" "$1 ($n)"; }
expect_n_re() { local n; n="$(count_re "$3")"; \
                check "$([ "$n" -eq "$2" ]; echo $?)" "$1 ($n)"; }

# shellcheck source=profile.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/profile.sh"

# The profile scenario $2 of port $1 builds with: WT_PROFILE when the matrix
# registers it there, otherwise extended when it runs there, otherwise its only
# profile.
scenario_profile() {
    python3 "$(dirname "${BASH_SOURCE[0]}")/scenario_matrix.py" \
        --port "$1" --profile-of "$2"
}

# Isolation level 3 addresses of port/$2 (band, partition stack and SPM
# peripheral), read from its memory_map.h under the build's own layout
# configuration so no runner copies them.
l3_layout_load() {
    local vars cflags
    cflags="$(make -s --no-print-directory -C "$1" TARGET="$2" \
        print-layout-cflags)" ||
        fail "could not read the layout configuration of port/$2"
    vars="$(python3 "$1/tools/l3_layout_args.py" --shell \
        --cc "${L3_CPP:-arm-none-eabi-gcc}" --cflags "$cflags" \
        "$1/port/$2/memory_map.h")" ||
        fail "could not read the level 3 layout of port/$2"
    eval "$vars"
}
