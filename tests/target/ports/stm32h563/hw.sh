# shellcheck shell=bash disable=SC2034,SC2154
# STM32H563 (NUCLEO-H563ZI) hardware profile for tests/target/run_hardware.sh:
# STM32CubeProgrammer flashes through the bound ST-Link, pyOCD parks the core,
# erases the sectors a run must start blank and reads the latches, and the
# board's VCP is the console. Option bytes are read for the fixture check and
# never written here.

HW_WOLFBOOT_ADDR=0x0C000000
HW_SECURE_ADDR=0x0C060000
HW_GUEST0_ADDR=0x080A0000
HW_GUEST1_ADDR=0x080E0000
HW_UPDATE_ADDR=0x0C100000
HW_GUEST0_RAM=0x20000000
HW_GUEST1_RAM=0x20010000
HW_PYOCD_TARGET="${PYOCD_TARGET:-stm32h563zitx}"
HW_SIGN_EXTRA=""
HW_CONSOLE="${WT_HW_CONSOLE:-${H5_SERIAL:-/dev/ttyACM0}}"
# wolfBoot's BOOT and UPDATE trailers and the SWAP sector keep a previous
# run's update trigger; the vault and the conformance boot flag keep its state.
HW_TRAILER_SECTORS="0x0C09E000 0x0C13E000 0x0C140000"
HW_VAULT_SECTORS="0x0C1FC000 0x0C1FE000"
HW_BOOTFLAG_SECTOR=0x0C1FA000
HW_SECTOR_SIZE=0x2000
# The running chain hides guest flash from the debugger; programming verifies.
HW_VERIFY_AFTER_BOOT=0

hw_detect() {
    H5_SERIAL="$HW_CONSOLE" "$repo/tests/target/detect_h5.sh"
}

hw_probe_bind() {
    local listed
    if [ -n "${WT_HW_PROBE:-}" ]; then
        HW_PROBE="$WT_HW_PROBE"
        return 0
    fi
    listed="$(stcli_probes)"
    [ "$(printf '%s\n' "$listed" | grep -c .)" -eq 1 ] ||
        fail "expected exactly one ST-Link (set WT_HW_PROBE to its serial): $(printf '%s' "$listed" | tr '\n' ' ')"
    HW_PROBE="$listed"
}

# The fixture the runner needs, read only: TrustZone on, product state Open,
# and no WRP on the guest sectors (a protected sector keeps its contents
# through a program and fails every verify). Anything else names the gated
# provisioning command that puts the board back.
hw_preflight() {
    local ob tzen state wrp
    ob="$(stcli_option_bytes)"
    printf '%s\n' "$ob" > "$evidence/option-bytes.txt" 2>/dev/null || true
    tzen="$(stcli_ob_field TZEN "$ob")"
    state="$(stcli_ob_field PRODUCT_STATE "$ob")"
    wrp="$(stcli_ob_field WRPSGn1 "$ob")"
    case "${tzen:-}" in 0xB4|0xb4) ;; *) fail "fixture: TZEN=${tzen:-none}, want 0xB4 (TrustZone on)" ;; esac
    case "${state:-}" in 0xED|0xed) ;; *)
        fail "fixture: PRODUCT_STATE=${state:-none}, want 0xED (Open); run TARGET=stm32h563 WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh restore" ;;
    esac
    case "${wrp:-}" in 0xFFFFFFFF|0xffffffff) ;; *)
        fail "fixture: WRPSGn1=${wrp:-none} protects guest flash; run TARGET=stm32h563 WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh clear-wrp" ;;
    esac
    log "  [fixture] TZEN=$tzen PRODUCT_STATE=$state WRPSGn1=$wrp"
}

hw_capture_seconds() {
    case "$1" in
        restart|nsbusfaultneg) echo 32 ;;
        confboot) echo 900 ;;
        devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec) echo 600 ;;
        bootupdate) echo 45 ;;
        authneg) echo 30 ;;
        writeonce) echo 40 ;;
        *) echo 25 ;;
    esac
}

pyocd_h5() {
    timeout 120 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t "$HW_PYOCD_TARGET" "$@"
}

# A previous run's armed update trigger would swap its candidate over the
# image flashed next: every flow blanks the trailers before it programs.
h5_blank_trailers() {
    local sector
    pyocd_h5 -c "reset halt" >> "$evidence/program.log" 2>&1 || true
    for sector in $HW_TRAILER_SECTORS; do
        pyocd_erase_verified "$HW_PYOCD_TARGET" "$sector" "$HW_SECTOR_SIZE"
    done
}

# hw_program <wolfboot> <secure> <guest0> <guest1> [update]: flash with
# verify, then park the core and blank the sectors a run must start from.
hw_program() {
    local wolfboot="$1" secure="$2" g0="$3" g1="$4" update="${5:-}" sector
    local images=("$wolfboot" "$HW_WOLFBOOT_ADDR" "$secure" "$HW_SECURE_ADDR"
                  "$g0" "$HW_GUEST0_ADDR" "$g1" "$HW_GUEST1_ADDR")
    [ -n "$update" ] && images+=("$update" "$HW_UPDATE_ADDR")
    h5_blank_trailers
    stcli_program "${images[@]}"
    # Park at the reset vector and erase while halted: erasing a running
    # target lets the old firmware's cached wolfHSM state rewrite the pool
    # before the reset, and a reset landing mid vault-format tears a write.
    pyocd_h5 -c "reset halt" >> "$evidence/program.log" 2>&1 || true
    for sector in $HW_VAULT_SECTORS; do
        pyocd_erase_verified "$HW_PYOCD_TARGET" "$sector" "$HW_SECTOR_SIZE"
    done
    case "$SC_ROLE" in
        conformance) pyocd_erase_verified "$HW_PYOCD_TARGET" "$HW_BOOTFLAG_SECTOR" "$HW_SECTOR_SIZE" ;;
    esac
}

# Boot exactly once from the parked state while the console is captured.
hw_boot() {
    local seconds="$1" waited=0 cap
    stty -F "$HW_CONSOLE" 115200 raw -echo -echoe -echok -onlcr 2>/dev/null || true
    : > "$evidence/console.log"
    timeout "$seconds" cat "$HW_CONSOLE" >> "$evidence/console.log" 2>/dev/null &
    cap=$!
    sleep 1
    pyocd_h5 -c reset >/dev/null 2>&1 || true
    case "$SC_ROLE" in
        conformance)
            # The suite prints its report once; stop early on it.
            while [ "$waited" -lt "$seconds" ]; do
                grep -aq "TOTAL FAILED" "$evidence/console.log" && break
                sleep 5; waited=$((waited + 5))
            done ;;
        *) sleep "$seconds" ;;
    esac
    kill "$cap" 2>/dev/null || true
    wait "$cap" 2>/dev/null || true
}

# A word at a Non-secure RAM address is read through both aliases: the GTZC
# curtain marks the idle guest's blocks Secure, so exactly one view holds the
# live word; Secure addresses are read as they are.
hw_read32() {
    local addr="$1" alias out ns_val s_val
    case "$addr" in
        0x2*|0X2*)
            alias="$(printf '0x%08x' $((addr + 0x10000000)))"
            out="$(pyocd_h5 -c halt -c "read32 $addr 4" -c "read32 $alias 4" 2>/dev/null)"
            ns_val="$(printf '%s\n' "$out" | awk -v a="$(printf '%08x' $((addr)))" 'tolower($1)==a":"{print $2}')"
            s_val="$(printf '%s\n' "$out" | awk -v a="$(printf '%08x' $((alias)))" 'tolower($1)==a":"{print $2}')"
            if [ -n "$ns_val" ] && [ $((0x$ns_val)) -ne 0 ]; then printf '%s' "$ns_val"
            elif [ -n "$s_val" ]; then printf '%s' "$s_val"
            else printf '%s' "$ns_val"; fi ;;
        *)
            pyocd_h5 -c halt -c "read32 $addr 4" 2>/dev/null |
                awk -v a="$(printf '%08x' $((addr)))" 'tolower($1)==a":"{print $2}' ;;
    esac
}

hw_readback() {
    pyocd_h5 -c halt -c "savemem $1 $2 $3" >/dev/null 2>&1
}

# The Secure alias of a guest symbol, read until it moves off zero: a read
# while the guest's RAM is fenced for its peer returns 0.
h5_poll_word() {
    local addr="$1" v="" n
    for n in 1 2 3 4 5; do
        v="$(hw_read32 "$addr")"
        [ -n "$v" ] && [ $((0x$v)) -ne 0 ] && break
    done
    printf '%s' "$v"
}

hw_collect() {
    local hdr addr
    case "$scenario" in
        bootupdate)
            hdr="$evidence/boot-header.bin"
            hw_readback "$HW_SECURE_ADDR" 0x400 "$hdr" || true
            emit_word "bootslot.measurement" \
                "$(python3 tests/scripts/read_wolfboot_measurement.py "$hdr" 2>/dev/null)" ;;
        nsmaskneg)
            addr="$(elf_sym g_guest1_heartbeats "$G1_ELF")"
            emit_word "g1sym.g_guest1_heartbeats@0" "$(h5_poll_word "$addr")"
            addr="$(elf_sym g_wt_ns_mask_spins "$G0_ELF")"
            emit_word "g0sym.g_wt_ns_mask_spins@0" "$(hw_read32 "$addr")"
            sleep 30
            emit_word "g1sym.g_guest1_heartbeats@1" "$(h5_poll_word "$(elf_sym g_guest1_heartbeats "$G1_ELF")")"
            emit_word "g0sym.g_wt_ns_mask_spins@1" "$(hw_read32 "$addr")" ;;
    esac
}

# Two boots: the first seals a WRITE_ONCE object on a blank vault, the second
# finds it immutable. The halt, erase and release share one pyOCD session so
# the running firmware cannot rewrite the pool between them.
hw_scenario_writeonce() {
    local addr waited=0 st=""
    h5_blank_trailers
    stcli_program "$HW_WOLFBOOT_BIN" "$HW_WOLFBOOT_ADDR" build/wolftrust_v1_signed.bin "$HW_SECURE_ADDR" \
        "$G0_IMG" "$HW_GUEST0_ADDR" "$G1_IMG" "$HW_GUEST1_ADDR"
    : > "$evidence/console.log"
    ( timeout "$capture_s" cat "$HW_CONSOLE" >> "$evidence/console.log" 2>/dev/null ) &
    pyocd_h5 -c "reset halt" -c "erase 0x0C1FC000" -c "erase 0x0C1FE000" -c reset >> "$evidence/program.log" 2>&1 || true
    sleep "$capture_s"
    wait
    addr="$(elf_sym g_write_once_stage "$G0_ELF")"
    hw_collect_words
    emit_word "g0sym.g_write_once_stage@boot1" "$(hw_read32 "$addr")"
    pyocd_h5 -c reset >/dev/null 2>&1 || true
    while [ "$waited" -lt 20 ]; do
        st="$(hw_read32 "$addr")"
        [ -n "$st" ] && [ $((0x$st)) -ne 0 ] && break
        sleep 2; waited=$((waited + 2))
    done
    emit_word "g0sym.g_write_once_stage@boot2" "$st"
}
