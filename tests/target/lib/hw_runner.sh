# shellcheck shell=bash disable=SC2154
# Shared machinery of the hardware runner: the board lock, the evidence
# directory, the chain build the emulator runner also uses, the SWD word
# collection every port's judge reads, and the hook contract a port profile
# (tests/target/ports/<port>/hw.sh) must satisfy. Sourced by run_hardware.sh.

HW_REQUIRED_HOOKS="hw_detect hw_probe_bind hw_preflight hw_program hw_boot hw_read32 hw_readback"

hw_require_hooks() {
    local hook
    for hook in $HW_REQUIRED_HOOKS; do
        declare -F "$hook" >/dev/null || fail "ports/$port/hw.sh does not define $hook"
    done
}

# One run at a time owns the board; a suite batch takes the same lock once
# for all of its scenarios and says so (WT_HW_LOCKED=1).
hw_take_lock() {
    local lock="$1"
    if [ -z "${WT_HW_LOCKED:-}" ] && command -v flock >/dev/null 2>&1; then
        mkdir -p "$(dirname "$lock")"
        exec 9>"$lock"
        if ! flock -n 9; then
            log "WAIT: another $port hardware run holds $lock"
            flock 9
        fi
    fi
}

# A wolfTrust global's address from the image this run built and flashed.
elf_sym() {
    "${ARM_NM:-arm-none-eabi-nm}" "$2" 2>/dev/null |
        awk -v s="$1" '$3 == s && !f { print "0x" $1; f = 1 }'
}

# One word of evidence: key=hex8 in swd.txt (a missing read is recorded as
# such, never invented).
emit_word() {
    local key="$1" value="$2"
    [ -n "$value" ] || value="missing"
    printf '%s=%s\n' "$key" "$value" >> "$evidence/swd.txt"
}

read_word() {
    hw_read32 "$(printf '0x%x' $(($1 + ${2:-0})))" | tr 'A-F' 'a-f'
}

emit_sym_word() {
    local name="$1" elf="$2" prefix="$3" offset="${4:-0}" addr
    addr="$(elf_sym "$name" "$elf")"
    if [ -n "$addr" ]; then
        emit_word "$prefix.$name" "$(read_word "$addr" "$offset")"
    else
        printf '%s.%s=absent\n' "$prefix" "$name" >> "$evidence/swd.txt"
    fi
}

# The word itself for the value checks, then two readings a second apart
# for the judge's "advancing" checks.
emit_beat() {
    local key="$1" addr="$2" offset="${3:-0}" first
    first="$(read_word "$addr" "$offset")"
    emit_word "$key" "$first"
    emit_word "$key@0" "$first"
    sleep 1
    emit_word "$key@1" "$(read_word "$addr" "$offset")"
}

# The mailbox a guest kind keeps at the base of its RAM window.
emit_guest_words() {
    local i="$1" kind="$2" base="$3"
    case "$kind" in
        baremetal)
            emit_word "g$i.sig" "$(read_word "$base" 0)"
            emit_word "g$i.fw" "$(read_word "$base" 8)"
            emit_word "g$i.status" "$(read_word "$base" 20)"
            emit_word "g$i.console" "$(read_word "$base" 24)"
            emit_word "g$i.probe" "$(read_word "$base" 28)"
            emit_word "g$i.probe_read" "$(read_word "$base" 32)"
            emit_beat "g$i.beat" "$base" 36 ;;
        psa)
            emit_word "g$i.sig" "$(read_word "$base" 0)"
            emit_word "g$i.lc" "$(read_word "$base" 4)"
            emit_word "g$i.neg" "$(read_word "$base" 8)" ;;
    esac
}

# The words every judge block may read: the Secure image's counters and
# latches, both guests' mailboxes or latches, and the isolation probe target.
hw_collect_words() {
    local sym
    : > "$evidence/swd.txt"
    printf 'scenario=%s\nengine=%s\nimage=%s\n' "$scenario" "$WT_ENGINE" \
        "$(sha256sum build/wolftrust_v1_signed.bin | cut -c1-16)" >> "$evidence/swd.txt"
    for sym in g_wt_launch_verified_mask g_wt_launch_refused_mask g_wt_restart_events \
               g_wt_quarantine_events g_last_fault_address g_tasklet_fault_count \
               g_tasklet_fault_cfsr g_wt_boot_zeroed_bytes g_wt_xn_denied \
               g_wt_seal_violation g_vault_reformatted g_wt_attest_degraded \
               g_wt_spm_fault_cfsr g_wt_spm_fault_pc g_wt_rom_flash_last_status \
               g_wt_flash_last_error g_wt_els_errors; do
        emit_sym_word "$sym" build/wolftrust-signed.elf sym
    done
    emit_guest_words 0 "$SC_GUEST0" "$HW_GUEST0_RAM"
    emit_guest_words 1 "$SC_GUEST1" "$HW_GUEST1_RAM"
    if [ "$SC_GUEST0" = "zephyr" ]; then
        for sym in g_guest0_lifecycle g_guest0_periph_probe g_guest0_gtzc_probe \
                   g_hsm_attack_probe g_wt_ns_mask_state; do
            emit_sym_word "$sym" "$G0_ELF" g0sym
        done
    fi
    if [ "$SC_GUEST1" = "freertos" ]; then
        emit_sym_word g_guest1_ffm_neg "$G1_ELF" g1sym
    fi
    emit_word "peer.word" "$(read_word "$probe_addr" 0)"
    if declare -F hw_collect >/dev/null; then
        hw_collect
    fi
}

hw_verify_image() {
    local addr="$1" image="$2" size back
    size="$(wc -c < "$image" | tr -d ' ')"
    back="$evidence/readback-$(basename "$image")"
    hw_readback "$addr" "$size" "$back" || fail "readback of $addr failed"
    cmp -s "$back" "$image" || fail "flash verify mismatch at $addr ($(basename "$image"))"
    log "  [flash] verified $(basename "$image") @ $addr"
}

# result.json: what ran and how it was judged, for a reader without the board.
hw_write_result() {
    local status="$1"
    python3 - "$evidence/result.json" "$port" "$scenario" "$WT_ENGINE" "$status" "$HW_PROBE" <<'PYEOF'
import json, sys, time
path, port, scenario, engine, status, probe = sys.argv[1:7]
json.dump({"port": port, "scenario": scenario, "engine": engine, "status": status,
           "probe": probe, "env": "hardware",
           "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
          open(path, "w"), indent=2)
PYEOF
}
