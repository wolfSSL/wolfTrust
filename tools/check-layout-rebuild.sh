#!/bin/sh
# Proves the secure build regenerates every layout consumer when one input
# changes and nothing when none does. Needs the cross toolchain.
# Usage: [TOOLPREFIX=arm-none-eabi-] tools/check-layout-rebuild.sh [<target>] [<build dir>]
set -eu
target=${1:-}
build=${2:-build-layout-rebuild}
: "${TOOLPREFIX:=arm-none-eabi-}"
log=$build/rebuild.log
fail() { echo "FAIL: $*" >&2; exit 1; }
mk() {
    make BUILD_DIR="$build" ${target:+TARGET="$target"} TOOLPREFIX="$TOOLPREFIX" \
        "$@" secure-image
}
rebuilt() { grep -qE ' -c -o | -E -P -x c ' "$log"; }
value() {
    printf '#include "memory_map.h"\n0=%s\n' "$1" |
        "$TOOLPREFIX"gcc -E -P -x c $cflags - | sed -n 's/^0=//p' | tr -d 'uUlL'
}

mk > /dev/null
mk > "$log" 2>&1
rebuilt && fail "an unchanged configuration rebuilt"

cflags=$(make -s --no-print-directory ${target:+TARGET="$target"} print-layout-cflags)
port=$(printf '%s\n' $cflags | sed -n 's#^-I.*/port/\([^/]*\)$#\1#p')
# One line below the port's own keeps the vector inside every port's table.
irq=$(( $(value WT_CONF_IRQ) - 1 ))
mk WT_CONF_IRQ=$irq > "$log" 2>&1
grep -q ' -E -P -x c ' "$log" || fail "a changed WT_CONF_IRQ did not regenerate the linker script"
grep -q 'sec_platform_' "$log" || fail "a changed WT_CONF_IRQ did not recompile the port objects"
grep -q -- "-DWT_CONF_IRQ=${irq}u" "$build/secure_build_mode.stamp" ||
    fail "the build-mode stamp does not record WT_CONF_IRQ"
mk WT_CONF_IRQ=$irq > "$log" 2>&1
rebuilt && fail "a repeated configuration rebuilt"

ram=$(( $(value WT_RAM_S_BASE) ))
spm=$(( $(value WT_L3_SPM_RAM_SIZE) - 0x1000 ))
mk WT_L3_SPM_RAM_SIZE=$(printf '0x%X' "$spm") > "$log" 2>&1
grep -q -- '-Wl,-T' "$log" || fail "a changed WT_L3_SPM_RAM_SIZE did not relink"
origin=$("$TOOLPREFIX"nm "$build/wolftrust.elf" | awk '$3 == "WT_L3_VAULT_ORIGIN" { print $1 }')
[ -n "$origin" ] || fail "the link carries no WT_L3_VAULT_ORIGIN"
[ $((0x$origin)) -eq $((ram + spm)) ] ||
    fail "linked keystore origin 0x$origin, want $(printf '0x%08x' $((ram + spm)))"

if mk WT_EXTRA_CFLAGS=-DWT_L3_SPM_RAM_SIZE=0x4C000 > "$log" 2>&1; then
    fail "a layout define in WT_EXTRA_CFLAGS was accepted"
fi
grep -q 'make variable' "$log" || fail "the WT_EXTRA_CFLAGS refusal names no make variable"
echo "PASS: layout rebuild ($port)"
