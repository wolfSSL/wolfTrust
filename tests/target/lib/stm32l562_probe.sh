# shellcheck shell=bash
# stm32l562_probe.sh
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

# The STM32L562E-DK's on-board ST-LINK behind one interface for
# run_stm32l562_hardware.sh, detect_stm32l562.sh and the provisioning port:
# STM32CubeProgrammer where it is installed, else OpenOCD through the
# ST-LINK's DAP (an arm64 host has no CubeProgrammer). STM32L562_PROBE_TOOL
# (cubeprog or openocd) picks one. Every call is bound to one ST-LINK serial.
# Sourced; set L5_TOOL from l5_tool first.

l5_lib_dir="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
L5_CLI="${STM32_CLI:-${STM32_CP:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin}/STM32_Programmer_CLI}"
L5_OPENOCD="${STM32L562_OPENOCD:-openocd}"
L5_UID_BASE=0x0BFA0590
L5_TOOL="${L5_TOOL:-}"

l5_strip() { sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g'; }
# The board host has coreutils timeout; an offline test host may not.
l5_timeout() {
    if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi
}
l5_have() { [ -x "$1" ] || command -v "$1" >/dev/null 2>&1; }

# cubeprog or openocd; nonzero when neither is usable or the choice is unknown.
l5_tool() {
    case "${STM32L562_PROBE_TOOL:-}" in
        cubeprog) l5_have "$L5_CLI" && echo cubeprog ;;
        openocd) l5_have "$L5_OPENOCD" && echo openocd ;;
        "")
            if l5_have "$L5_CLI"; then
                echo cubeprog
            elif l5_have "$L5_OPENOCD"; then
                echo openocd
            else
                return 1
            fi ;;
        *) return 2 ;;
    esac
}

l5_tool_missing() {
    case "${STM32L562_PROBE_TOOL:-}" in
        cubeprog) echo "STM32CubeProgrammer CLI not installed (set STM32_CLI or STM32_CP)" ;;
        openocd) echo "OpenOCD not installed (set STM32L562_OPENOCD)" ;;
        "") echo "neither STM32CubeProgrammer CLI nor OpenOCD installed (set STM32_CLI or STM32L562_OPENOCD)" ;;
        *) echo "STM32L562_PROBE_TOOL must be cubeprog or openocd, not '$STM32L562_PROBE_TOOL'" ;;
    esac
}

l5_pyocd() {
    if [ -n "${STM32L562_PYOCD:-}" ]; then
        echo "$STM32L562_PYOCD"
    elif command -v pyocd >/dev/null 2>&1; then
        command -v pyocd
    elif [ -x "$HOME/spsdk-venv/bin/pyocd" ]; then
        echo "$HOME/spsdk-venv/bin/pyocd"
    fi
}

# The serials of the attached ST-LINKs whose board is an STM32L562E-DK:
# CubeProgrammer's board name, else pyOCD's board or target for the probe, or
# the ST-LINK's mass-storage label (DIS_L562QE).
l5_dk_serials() {
    local py
    case "$L5_TOOL" in
        cubeprog)
            l5_timeout 60 "$L5_CLI" -l st 2>/dev/null | l5_strip |
                awk -F': *' '/ST-LINK SN/ { s = $2 } /Board Name/ && $2 ~ /STM32L562E-DK/ { print s }' |
                tr -d ' \r' ;;
        openocd)
            py="$(l5_pyocd)"
            {
                [ -z "$py" ] || l5_timeout 60 "$py" list 2>/dev/null | awk '
                    $1 ~ /^[0-9]+$/ {
                        sn = ""
                        for (i = 2; i <= NF; i++)
                            if ($i ~ /^[0-9A-Fa-f]+$/ && length($i) >= 12) sn = $i
                        if (sn != "" && tolower($0) ~ /stm32l562/) print sn
                        next
                    }
                    sn != "" && /STM32L562E-DK/ { print sn }
                    { sn = "" }'
                lsblk -dno SERIAL,LABEL 2>/dev/null | awk '$2 ~ /^DIS_L562/ { print $1 }'
            } | tr -d ' \r' | sort -u ;;
    esac | grep -E '^[0-9A-Za-z]+$' || true
}

# Serials reach OpenOCD's Tcl and CubeProgrammer's argument parser, so only
# letters and digits are ever accepted.
l5_sn_ok() { case "$1" in ""|*[!0-9A-Za-z]*) return 1 ;; esac; }
l5_is_dk() { l5_sn_ok "$1" && l5_dk_serials | grep -Fxq "$1"; }

# CubeProgrammer bound to one ST-LINK: <sn> <mode> <args...>; HotPlug attaches
# without a reset.
l5_cube() {
    local sn="$1" mode="$2"
    shift 2
    l5_sn_ok "$sn" || { echo "L5ERR serial"; return 1; }
    l5_timeout 300 "$L5_CLI" -c port=SWD "sn=$sn" "mode=$mode" "$@" 2>&1 | l5_strip
}

# OpenOCD bound to one ST-LINK: <sn> hot|halt|reset <-c command...>. hot
# attaches without a reset; halt holds the core from the reset vector (under
# SRST, so a running chain cannot stop it); reset only arms the reset pin.
l5_ocd() {
    local sn="$1" mode="$2"
    local -a pre=()
    shift 2
    l5_sn_ok "$sn" || { echo "L5ERR serial"; return 1; }
    case "$mode" in
        halt) pre=(-c "reset_config srst_only srst_nogate connect_assert_srst" -c init
                   -c "reset halt" -c "reset_config none") ;;
        reset) pre=(-c "reset_config srst_only srst_nogate" -c init) ;;
        *) pre=(-c "reset_config none" -c init) ;;
    esac
    l5_timeout "${STM32L562_OCD_TIMEOUT:-300}" "$L5_OPENOCD" -c "gdb_port disabled" \
        -c "tcl_port disabled" -c "telnet_port disabled" -f interface/stlink-dap.cfg \
        -c "adapter serial $sn" -c "transport select dapdirect_swd" -f target/stm32l5x.cfg \
        -c "adapter speed ${STM32L562_SWD_KHZ:-4000}" -f "$l5_lib_dir/stm32l562_openocd.tcl" \
        "${pre[@]}" "$@" -c shutdown 2>&1
}

# The 12 option registers OPTR..WRP2BR as CubeProgrammer names their fields.
l5_ob_fields() {
    local optr=$((0x$1)) sba=$((0x$4)) w1=$((0x$5)) a1=$((0x$7)) b1=$((0x$8))
    local w2=$((0x$9)) a2=$((0x${11})) b2=$((0x${12}))
    printf '     %-12s : 0x%X\n' RDP $((optr & 0xFF)) TZEN $(((optr >> 31) & 1)) \
        DBANK $(((optr >> 22) & 1)) SWAP_BANK $(((optr >> 20) & 1)) \
        SECBOOTADD0 $(((sba >> 7) & 0x1FFFFFF)) BOOT_LOCK $((sba & 1)) \
        SECWM1_PSTRT $((w1 & 0x7F)) SECWM1_PEND $(((w1 >> 16) & 0x7F)) \
        SECWM2_PSTRT $((w2 & 0x7F)) SECWM2_PEND $(((w2 >> 16) & 0x7F)) \
        WRP1A_PSTRT $((a1 & 0x7F)) WRP1A_PEND $(((a1 >> 16) & 0x7F)) \
        WRP1B_PSTRT $((b1 & 0x7F)) WRP1B_PEND $(((b1 >> 16) & 0x7F)) \
        WRP2A_PSTRT $((a2 & 0x7F)) WRP2A_PEND $(((a2 >> 16) & 0x7F)) \
        WRP2B_PSTRT $((b2 & 0x7F)) WRP2B_PEND $(((b2 >> 16) & 0x7F))
}

# One option byte's register offset, field mask and shift (RM0438 FLASH).
l5_ob_field() {
    case "$1" in
        RDP) echo "0x40 0xFF 0" ;;
        TZEN) echo "0x40 0x80000000 31" ;;
        DBANK) echo "0x40 0x00400000 22" ;;
        SWAP_BANK) echo "0x40 0x00100000 20" ;;
        SECBOOTADD0) echo "0x4C 0xFFFFFF80 7" ;;
        BOOT_LOCK) echo "0x4C 0x1 0" ;;
        SECWM1_PSTRT) echo "0x50 0x7F 0" ;;
        SECWM1_PEND) echo "0x50 0x007F0000 16" ;;
        WRP1A_PSTRT) echo "0x58 0x7F 0" ;;
        WRP1A_PEND) echo "0x58 0x007F0000 16" ;;
        WRP1B_PSTRT) echo "0x5C 0x7F 0" ;;
        WRP1B_PEND) echo "0x5C 0x007F0000 16" ;;
        SECWM2_PSTRT) echo "0x60 0x7F 0" ;;
        SECWM2_PEND) echo "0x60 0x007F0000 16" ;;
        WRP2A_PSTRT) echo "0x68 0x7F 0" ;;
        WRP2A_PEND) echo "0x68 0x007F0000 16" ;;
        WRP2B_PSTRT) echo "0x6C 0x7F 0" ;;
        WRP2B_PEND) echo "0x6C 0x007F0000 16" ;;
        *) return 1 ;;
    esac
}

# The option bytes as "     NAME : value" lines.
l5_ob_displ() {
    local out
    case "$L5_TOOL" in
        cubeprog) l5_cube "$1" HotPlug -ob displ ;;
        openocd)
            out="$(l5_ocd "$1" hot -c l5_ob | awk '$1 == "L5OB" { $1 = ""; $2 = ""; print; exit }')"
            # shellcheck disable=SC2086
            [ "$(wc -w <<<"$out")" -eq 12 ] && l5_ob_fields $out ;;
    esac
}

# l5_read <sn> <address> <bytes>: "0xADDRESS : word..." lines, four words each.
l5_read() {
    local w
    case "$L5_TOOL" in
        cubeprog) l5_cube "$1" HotPlug -r32 "$2" "$3" ;;
        openocd)
            w="$(l5_ocd "$1" hot -c "l5_mem $(($2)) $((($3 + 3) / 4))" |
                awk '$1 == "L5MEM" { $1 = ""; $2 = ""; print; exit }')"
            [ -n "$w" ] || return 1
            # shellcheck disable=SC2086
            printf '%s\n' $w | awk -v a="$(($2))" '{ w[n++] = toupper($1) }
                END { for (i = 0; i < n; i += 4) {
                    printf "0x%08X :", a + i * 4
                    for (j = i; j < i + 4 && j < n; j++) printf " %s", w[j]
                    printf "\n" } }' ;;
    esac
}

# The 96-bit device UID as 24 lowercase hex digits.
l5_uid() {
    local u
    case "$L5_TOOL" in
        cubeprog)
            u="$(l5_cube "$1" HotPlug -r32 "$L5_UID_BASE" 12 |
                awk -v a="$(printf '0x%08x' "$L5_UID_BASE")" 'tolower($1) == a && $2 == ":" { print tolower($3 $4 $5) }')" ;;
        openocd)
            u="$(l5_ocd "$1" hot -c l5_uid | awk '$1 == "L5UID" { print tolower($3 $4 $5); exit }')" ;;
    esac
    case "$u" in
        ""|000000000000000000000000|ffffffffffffffffffffffff) return 1 ;;
    esac
    echo "$u"
}

# l5_upload <sn> <address> <bytes> <file>: read flash or RAM into <file>.
l5_upload() {
    case "$L5_TOOL" in
        cubeprog) l5_cube "$1" HotPlug -u "$2" "$3" "$4" >/dev/null ;;
        openocd)
            rm -f "$4"
            l5_ocd "$1" hot -c "l5_dump {$4} $(($2)) $(($3))" | grep -q '^L5DUMP ' && [ -s "$4" ] ;;
    esac
}

# l5_ob_write <sn> UR|HotPlug NAME=value...: program option bytes; the caller
# reads them back. Only RDP level 0 is ever written here.
l5_ob_write() {
    local sn="$1" mode="$2" kv f off mask shift out
    local -a fields=()
    shift 2
    for kv in "$@"; do
        f="$(l5_ob_field "${kv%%=*}")" || { echo "unknown option byte ${kv%%=*}"; return 1; }
        if [ "${kv%%=*}" = RDP ] && [ "$(( ${kv#*=} ))" -ne $((0xAA)) ]; then
            echo "refusing an RDP write other than level 0 (0xAA)"
            return 1
        fi
        read -r off mask shift <<<"$f"
        fields+=("$off" "$mask" "$(( (${kv#*=} << shift) & mask ))")
    done
    case "$L5_TOOL" in
        cubeprog) l5_cube "$sn" "$mode" -ob "$@" ;;
        openocd)
            [ "$mode" = UR ] && mode=halt || mode=hot
            out="$(l5_ocd "$sn" "$mode" -c "l5_obw ${fields[*]}")"
            printf '%s\n' "$out" | grep -E '^L5(OBW|ERR)' || true
            # OBL_LAUNCH resets the part; the next session waits for its boot.
            sleep 2
            grep -q '^L5OBW ' <<<"$out" && ! grep -q '^L5ERR' <<<"$out" ;;
    esac
}

l5_hard_reset() {
    case "$L5_TOOL" in
        cubeprog) l5_cube "$1" HotPlug -hardRst ;;
        openocd) l5_ocd "$1" reset -c "reset run" ;;
    esac
}

# l5_program <sn> <file>@<address>...: erase the whole flash (wolfBoot,
# wolfTrust, the vault and conformance NVM, swap, update slot, guests), then
# program only each image's bytes. Programmed 0xFF double-words are not
# erased ones, so the vault's first write would fail over them.
l5_program() {
    local sn="$1" spec out n=0
    local -a args=()
    shift
    case "$L5_TOOL" in
        cubeprog)
            for spec in "$@"; do args+=(-d "${spec%@*}" "${spec##*@}" -v); n=$((n + 1)); done
            out="$(l5_cube "$sn" UR -e all "${args[@]}")" || { printf '%s\n' "$out"; return 1; }
            printf '%s\n' "$out"
            ! grep -qiE 'error|failed' <<<"$out" &&
                [ "$(grep -ci 'verified successfully' <<<"$out")" -ge "$n" ] ;;
        openocd)
            for spec in "$@"; do args+=("{${spec%@*}}" "$((${spec##*@}))"); n=$((n + 1)); done
            out="$(l5_ocd "$sn" halt -c "l5_program $((0x0C000000)) $((0x80000)) ${args[*]}")"
            printf '%s\n' "$out"
            grep -qx "L5PROG $n" <<<"$out" && ! grep -q '^L5ERR' <<<"$out" ;;
    esac
}

# l5_boot <sn> <address>...: clear the words with the core held, then one
# hardware reset boots the chain.
l5_boot() {
    local sn="$1" a out
    local -a args=()
    shift
    case "$L5_TOOL" in
        cubeprog)
            for a in "$@"; do args+=(-w32 "$a" 0x0); done
            l5_cube "$sn" UR "${args[@]}" -hardRst ;;
        openocd)
            for a in "$@"; do args+=("$((a))"); done
            out="$(l5_ocd "$sn" halt -c "l5_boot ${args[*]}")"
            printf '%s\n' "$out"
            grep -qx "L5BOOT $#" <<<"$out" ;;
    esac
}

# l5_erase_try <sn> <address> <bytes>: attempt an erase with the core held at
# reset; prints L5ERASE refused|done. 2 when the backend has no such probe.
l5_erase_try() {
    case "$L5_TOOL" in
        openocd) l5_ocd "$1" halt -c "l5_erase_try $(($2)) $(($3))" ;;
        *) return 2 ;;
    esac
}

# l5_trim <in> <out>: the image without its trailing erased bytes, padded to
# the 8-byte flash double-word.
l5_trim() {
    python3 - "$1" "$2" <<'PYEOF'
import sys
data = open(sys.argv[1], "rb").read().rstrip(b"\xff")
data += b"\xff" * (-len(data) % 8)
open(sys.argv[2], "wb").write(data)
PYEOF
}

# l5_framed_digest <address> <file>...: the provisioning controller's image
# digest, each address and length ahead of its bytes.
l5_framed_digest() {
    local i
    for ((i = 2; i <= $#; i += 2)); do [ -s "${!i}" ] || return 1; done
    while [ "$#" -ge 2 ]; do
        printf '%s %s\n' "$1" "$(wc -c < "$2" | tr -d ' ')"
        cat "$2"
        shift 2
    done | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -c1-64
}
