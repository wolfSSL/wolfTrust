# shellcheck shell=bash disable=SC2034,SC2154
# STM32L562E-DK hardware profile for tests/target/run_hardware.sh: probe.sh
# erases, programs and reads over the bound ST-LINK; the USART1 VCP is the
# console. Option bytes are read for the fixture check, never written here.

HW_WOLFBOOT_ADDR=0x0C000000
HW_SECURE_ADDR=0x0C00C000
HW_GUEST0_ADDR=0x0802C000
HW_GUEST1_ADDR=0x08040000
HW_GUEST0_RAM=0x20028000
HW_GUEST1_RAM=0x20034000
HW_SIGN_EXTRA=""
HW_CONSOLE="${WT_HW_CONSOLE:-${STM32L562_CONSOLE:-}}"
# TZEN at RDP level 0, which wolfBoot hands over as PSA_ROT_PROVISIONING.
HW_EXPECTED_LIFECYCLE=0x2000u
# The production split the fixture carries (provisioning_ctrl_stm32l562.sh).
HW_SECWM1="0x0 0x57"
HW_SECWM2="0x20 0x7F"

# shellcheck source=probe.sh disable=SC1091
. "$here/ports/stm32l562/probe.sh"
L5_TOOL="$(l5_tool || true)"

hw_detect() {
    [ -n "$L5_TOOL" ] || { l5_tool_missing; return 1; }
    [ -n "$(l5_dk_serials)" ] || { echo "no STM32L562E-DK ST-LINK attached"; return 1; }
    return 0
}

hw_probe_bind() {
    local listed tty
    if [ -n "${WT_HW_PROBE:-}" ]; then
        l5_is_dk "$WT_HW_PROBE" ||
            fail "WT_HW_PROBE=$WT_HW_PROBE is not an attached STM32L562E-DK"
        HW_PROBE="$WT_HW_PROBE"
    else
        listed="$(l5_dk_serials)"
        [ "$(printf '%s\n' "$listed" | grep -c .)" -eq 1 ] ||
            fail "expected exactly one STM32L562E-DK (set WT_HW_PROBE to its serial)"
        HW_PROBE="$listed"
    fi
    if [ -z "$HW_CONSOLE" ]; then
        for tty in /dev/serial/by-id/*STLINK*"$HW_PROBE"*-if0[0-9]; do
            [ -c "$tty" ] && HW_CONSOLE="$tty" && break
        done
    fi
    [ -n "$HW_CONSOLE" ] && [ -c "$HW_CONSOLE" ] || fail "board console not found (set WT_HW_CONSOLE)"
}

l5_ob_pair() {
    printf '%s %s' "$(stcli_ob_field "${1}_PSTRT" "$2")" "$(stcli_ob_field "${1}_PEND" "$2")"
}

# The fixture the runner needs, read only: TrustZone on, RDP level 0, both
# banks unswapped, the production watermarks and every WRP area disabled.
# Anything else names the gated provisioning command that puts it back.
hw_preflight() {
    local ob area wstart wend prov="TARGET=stm32l562 WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh"
    ob="$(l5_ob_displ "$HW_PROBE")"
    printf '%s\n' "$ob" > "$evidence/option-bytes.txt" 2>/dev/null || true
    case "$(stcli_ob_field TZEN "$ob")" in 0x1) ;; *) fail "fixture: TZEN is not set; run $prov set-perimeter" ;; esac
    case "$(stcli_ob_field RDP "$ob")" in 0xAA|0xaa) ;; *) fail "fixture: RDP is not level 0; run $prov regress (a mass-erasing, typed RDP regression), then $prov set-perimeter" ;; esac
    case "$(stcli_ob_field DBANK "$ob")/$(stcli_ob_field SWAP_BANK "$ob")" in 0x1/0x0) ;; *)
        fail "fixture: want DBANK=1 SWAP_BANK=0, which set-perimeter will not change; a person sets those option bytes in STM32CubeProgrammer (see the STM32L562 Guide)" ;;
    esac
    [ "$(l5_ob_pair SECWM1 "$ob")" = "$HW_SECWM1" ] && [ "$(l5_ob_pair SECWM2 "$ob")" = "$HW_SECWM2" ] ||
        fail "fixture: SECWM1 $(l5_ob_pair SECWM1 "$ob"), SECWM2 $(l5_ob_pair SECWM2 "$ob") is not the production split; run $prov set-perimeter"
    for area in WRP1A WRP1B WRP2A WRP2B; do
        read -r wstart wend <<<"$(l5_ob_pair "$area" "$ob")"
        [ -n "$wend" ] && (( wstart > wend )) ||
            fail "fixture: $area protects pages $wstart-$wend the reflash erases; run $prov clear-wrp"
    done
    log "  [fixture] TZEN RDP0 DBANK SECWM1 $HW_SECWM1 SECWM2 $HW_SECWM2 no WRP"
}

hw_capture_seconds() {
    case "$1" in
        restart) echo 32 ;;
        authneg) echo 30 ;;
        *) echo 25 ;;
    esac
}

# hw_program <wolfboot> <secure> <guest0> <guest1>: erase the whole flash and
# program only each image's bytes, so the stores, swap and update slot start
# erased rather than 0xFF-programmed; the core stays parked for hw_boot.
hw_program() {
    local specs=() spec name out rc=0
    for spec in "wolfboot:$1:$HW_WOLFBOOT_ADDR" "wolftrust:$2:$HW_SECURE_ADDR" \
            "guest0:$3:$HW_GUEST0_ADDR" "guest1:$4:$HW_GUEST1_ADDR"; do
        name="${spec%%:*}"
        l5_trim "$(printf '%s' "$spec" | cut -d: -f2)" "$evidence/flash-$name.bin" ||
            fail "could not trim the $name image"
        specs+=("$evidence/flash-$name.bin@${spec##*:}")
    done
    out="$(l5_program "$HW_PROBE" "${specs[@]}")" || rc=$?
    printf '%s\n' "$out" >> "$evidence/program.log"
    [ "$rc" -eq 0 ] || fail "programming the board failed (see $evidence/program.log)"
}

# SRAM survives a reset: the guest mailboxes, the probe word and the launch
# masks are cleared with the core held, then one hardware reset boots the run.
hw_boot() {
    local seconds="$1" clear=() a i cap
    for a in "$HW_GUEST0_RAM" "$HW_GUEST1_RAM"; do
        for i in 0 1 2 3 4 5 6 7 8 9 10 11; do
            clear+=("$(printf '0x%08x' $((a + i * 4)))")
        done
    done
    clear+=("$probe_addr")
    for a in g_wt_launch_verified_mask g_wt_launch_refused_mask; do
        a="$(elf_sym "$a" build/wolftrust-signed.elf)"
        [ -z "$a" ] || clear+=("$a")
    done
    stty -F "$HW_CONSOLE" 115200 raw -echo -crtscts -ixon 2>/dev/null || true
    : > "$evidence/console.log"
    timeout "$seconds" cat "$HW_CONSOLE" >> "$evidence/console.log" 2>/dev/null &
    cap=$!
    sleep 1
    l5_boot "$HW_PROBE" "${clear[@]}" >> "$evidence/boot.log" 2>&1 ||
        fail "could not clear the mailboxes and reset the board"
    wait "$cap" 2>/dev/null || true
}

hw_read32() {
    local addr
    addr="$(printf '0x%08x' $(($1)))"
    l5_read "$HW_PROBE" "$addr" 4 |
        awk -v a="$addr" 'tolower($1) == a && $2 == ":" { print tolower($3); exit }'
}

hw_readback() {
    rm -f "$3"
    l5_upload "$HW_PROBE" "$1" "$2" "$3" && [ -s "$3" ]
}
