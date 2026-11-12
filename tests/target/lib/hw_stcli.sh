# shellcheck shell=bash
# STM32CubeProgrammer helpers for the hardware runner. Every call names the
# bound ST-Link (sn=HW_PROBE). The runner reads option bytes to check the
# fixture; it never writes one (provisioning_ctrl.sh owns option bytes).

stcli_bin() {
    printf '%s' "${STM32_CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}"
}

stcli_strip() {
    sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g'
}

# The serial numbers of the attached ST-Links, one per line.
stcli_probes() {
    "$(stcli_bin)" -l st 2>/dev/null | stcli_strip | grep -oiE 'SN[[:space:]]*:[[:space:]]*[0-9A-Z]+' |
        grep -oE '[0-9A-Z]+$'
}

# The option-byte dump, read-only (HotPlug leaves the target running).
stcli_option_bytes() {
    "$(stcli_bin)" -c port=SWD sn="$HW_PROBE" mode=HotPlug -ob displ 2>&1 | stcli_strip
}

stcli_ob_field() {
    printf '%s\n' "$2" | grep -oiE "$1[[:space:]]*:[[:space:]]*0x[0-9A-Fa-f]+" | head -1 |
        grep -oE "0x[0-9A-Fa-f]+"
}

# stcli_program <image addr>...: flash with verify, then a hard reset. The
# CLI exits nonzero after -hardRst even on success, so the verify text gates.
stcli_program() {
    local args=() out
    while [ $# -ge 2 ]; do
        args+=(-d "$1" "$2")
        shift 2
    done
    out="$("$(stcli_bin)" -c port=SWD sn="$HW_PROBE" mode=UR "${args[@]}" --verify -hardRst 2>&1 | stcli_strip)" || true
    printf '%s\n' "$out" >> "$evidence/program.log"
    grep -aq "verified successfully" <<<"$out" || fail "flash verify did not complete"
}
