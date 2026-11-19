# shellcheck shell=bash
# pyOCD helpers for the hardware runner. Every call carries the bound probe
# (HW_PROBE) so another probe on the host is never touched; observation uses
# the generic Cortex-M attach because a device-pack target resets the chip on
# connect, which would land a read in a fresh boot instead of the one under
# test.

pyocd_bin() {
    if command -v "${HW_PYOCD:-pyocd}" >/dev/null 2>&1; then
        printf '%s' "${HW_PYOCD:-pyocd}"
    elif [ -x "${HW_SPSDK_VENV:-$HOME/spsdk-venv}/bin/pyocd" ]; then
        printf '%s' "${HW_SPSDK_VENV:-$HOME/spsdk-venv}/bin/pyocd"
    else
        return 1
    fi
}

# pyocd_observe <cmd args...>: a read-only session on the running target.
pyocd_observe() {
    timeout 60 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t cortex_m "$@" 2>&1 |
        grep -viE "rom table|APB-AP|coresight|cidr"
}

# One 32-bit word as eight lowercase hex digits (empty when unreadable).
pyocd_read32() {
    pyocd_observe -c "read32 $1" | grep -oiE '[0-9a-f]{8}' | tail -1 | tr 'A-F' 'a-f'
}

pyocd_readback() {
    timeout 120 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t cortex_m \
        -c "savemem $1 $2 $3" >/dev/null 2>&1
}

# The current IPSR as 1 when the core sits in a fault handler, else 0.
pyocd_ipsr_fault() {
    local ipsr
    ipsr="$(pyocd_observe -c halt -c 'reg xpsr' -c go | sed -n 's/^xpsr = 0x\([0-9a-fA-F]*\).*/\1/p')"
    ipsr=$((0x${ipsr:-3} & 0x1ff))
    if [ "$ipsr" -ge 2 ] && [ "$ipsr" -le 7 ]; then printf '00000001'; else printf '00000000'; fi
}

# pyocd_session <target> <cmd args...>: one programming session on the pack
# target with the core parked first; the commander exits 0 whatever a command
# did, so its output is checked for errors too.
pyocd_session() {
    local target="$1" out rc=0
    shift
    out="$(timeout 900 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t "$target" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE000ED94 0" "$@" 2>&1)" || rc=$?
    printf '%s\n' "$out" >> "$evidence/program.log"
    if [ "$rc" -ne 0 ]; then
        printf '%s\n' "$out" | tail -6
        fail "programming the board failed (pyocd exit $rc)"
    fi
    if grep -qiE 'error|exception|not halted|failure|not within|not in flash' <<<"$out"; then
        printf '%s\n' "$out" | grep -iE 'error|exception|not halted|failure|not within|not in flash' | tail -6
        fail "programming the board failed"
    fi
}

# Erase a sector and read its head and tail back blank; pyOCD's erase can die
# silently ("flash init timed out"), so retry on a non-blank readback.
pyocd_erase_verified() {
    local target="$1" addr="$2" size="$3" tail attempt out wh wt
    tail=$(printf '0x%08X' $(( addr + size - 4 )))
    for attempt in 1 2 3; do
        timeout 120 "$(pyocd_bin)" erase -u "$HW_PROBE" -t "$target" -s "$addr" >> "$evidence/program.log" 2>&1 || true
        out="$(timeout 60 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t "$target" -c halt \
            -c "read32 $addr 4" -c "read32 $tail 4" 2>/dev/null)"
        wh="$(printf '%s\n' "$out" | awk -v a="$(printf '%08x' $((addr)))" 'tolower($1)==a":"{print $2}')"
        wt="$(printf '%s\n' "$out" | awk -v a="$(printf '%08x' $((tail)))" 'tolower($1)==a":"{print $2}')"
        [ "$wh" = "ffffffff" ] && [ "$wt" = "ffffffff" ] && return 0
    done
    fail "sector $addr did not erase (head=${wh:-none} tail=${wt:-none})"
}
