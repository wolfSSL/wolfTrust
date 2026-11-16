# shellcheck shell=bash disable=SC2034,SC2154
# FRDM-MCXN947 hardware profile for tests/target/run_hardware.sh: the chain is
# programmed in one pyOCD session through the board's bound MCU-Link (the pack
# resets the chip on every connect, so the park and every step that depends
# on it share the session), the MCU-Link VCOM is the console, and the Secure
# side's latches, the vault's first phrase and the handoff are read over SWD.

HW_WOLFBOOT_ADDR=0x00000000
HW_SECURE_ADDR=0x00040000
HW_GUEST0_ADDR=0x00080000
HW_GUEST1_ADDR=0x00100000
HW_GUEST0_RAM=0x20000000
HW_GUEST1_RAM=0x20018000
# 8 KiB sectors: update and swap 0x180000-0x1C2000, NVM 0x1E0000-0x1E6000.
HW_UPDATE_ERASE="0x00180000 33"
HW_NVM_ERASE="0x001E0000 3"
HW_HSM_NVM_ADDR=0x001E0000
HW_FLASH_SECTOR=0x2000
HW_HANDOFF_ADDR=0x30030000
HW_SYSCON_LC_STATE=0x50000980
HW_PACK_TARGET="${MCXN947_TARGET:-mcxn947vdf}"
HW_SPSDK_VENV="${MCXN947_SPSDK_VENV:-$HOME/spsdk-venv}"
HW_SIGN_EXTRA="--sha256"
HW_CONSOLE="${WT_HW_CONSOLE:-${MCXN947_CONSOLE:-}}"

hw_detect() {
    if [ -d "$HW_SPSDK_VENV/bin" ]; then
        PATH="$HW_SPSDK_VENV/bin:$PATH"
        export PATH
    fi
    MCXN947_CONSOLE="$HW_CONSOLE" "$repo/tests/target/detect_mcxn947.sh"
}

# The board's own MCU-Link, unless the caller named a probe; other probes on
# the host belong to other boards and are never touched.
hw_probe_bind() {
    local listed tty
    if [ -n "${WT_HW_PROBE:-${MCXN947_PROBE_UID:-}}" ]; then
        HW_PROBE="${WT_HW_PROBE:-$MCXN947_PROBE_UID}"
    else
        listed="$("$(pyocd_bin)" list 2>/dev/null | grep -F "MCU-LINK FRDM-MCXN947" || true)"
        [ "$(printf '%s\n' "$listed" | grep -c .)" -eq 1 ] ||
            fail "expected one MCU-Link FRDM-MCXN947 probe (set WT_HW_PROBE)"
        HW_PROBE="$(printf '%s\n' "$listed" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[A-Z0-9]{8,}$/) { print $i; exit } }')"
        [ -n "$HW_PROBE" ] || fail "could not read the probe's unique id"
    fi
    if [ -z "$HW_CONSOLE" ]; then
        for tty in /dev/serial/by-id/*FRDM-MCXN947*-if02; do
            [ -c "$tty" ] && HW_CONSOLE="$tty" && break
        done
    fi
    [ -n "$HW_CONSOLE" ] && [ -c "$HW_CONSOLE" ] || fail "board console not found (set WT_HW_CONSOLE)"
}

hw_preflight() {
    :
}

hw_capture_seconds() {
    echo "${MCXN947_CONSOLE_SECONDS:-25}"
}

hw_first_stage() {
    WOLFBOOT_DIR="${MCXN947_WOLFBOOT_DIR:-$HOME/.cache/wolftrust/wolfboot-mcxn947}"
    mkdir -p "$(dirname "$WOLFBOOT_DIR")"
}

# Flash the chain, erase the update, swap and NVM sectors so the run starts
# from a blank vault, and clear the SRAM a warm reset keeps, all in one
# parked session.
hw_program() {
    local wolfboot="$1" secure="$2" g0="$3" g1="$4" verified refused image
    for image in "$wolfboot" "$secure" "$g0" "$g1"; do
        [ -s "$image" ] || fail "flash image missing: $image"
    done
    verified="$(elf_sym g_wt_launch_verified_mask build/wolftrust.elf)"
    refused="$(elf_sym g_wt_launch_refused_mask build/wolftrust.elf)"
    [ -n "$refused" ] || fail "launch masks not found in wolftrust.elf"
    # A WT_GUEST_FLASH_WRP=1 image verifies no guest, so the linker drops the
    # verified mask; every other image must carry it.
    [ -n "$verified" ] || [ "${WT_GUEST_FLASH_WRP:-0}" = "1" ] || fail "launch masks not found in wolftrust.elf"
    pyocd_session "$HW_PACK_TARGET" \
        -c "load $wolfboot $HW_WOLFBOOT_ADDR" -c "load $secure $HW_SECURE_ADDR" \
        -c "load $g0 $HW_GUEST0_ADDR" -c "load $g1 $HW_GUEST1_ADDR" \
        -c "erase $HW_UPDATE_ERASE" -c "erase $HW_NVM_ERASE" \
        -c "write32 $HW_GUEST0_RAM 0 0 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $HW_GUEST1_RAM 0 0 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $probe_addr 0" -c "write32 $refused 0" \
        ${verified:+-c "write32 $verified 0"}
}

# Boot from the parked state: the pack's halt leaves a DWT comparator and the
# debug fault status armed, which would stop the chain again, so both are
# cleared before the core is released. The MCU-Link forwards early-boot UART
# only while the debug link stays active, so the capture is kept company by
# spaced reads.
hw_boot() {
    local seconds="$1" n
    stty -F "$HW_CONSOLE" 115200 raw -echo -crtscts -ixon 2>/dev/null || true
    : > "$evidence/console.log"
    ( timeout "$seconds" cat "$HW_CONSOLE" > "$evidence/console.log" 2>/dev/null ) &
    sleep 0.5
    timeout 60 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t "$HW_PACK_TARGET" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE0001028 0" \
        -c "write32 0xE0001038 0" -c "write32 0xE000ED30 0x1F" -c "go" \
        >/dev/null 2>&1 || fail "could not release the core"
    for n in 1 2 3 4 5 6; do
        sleep 1.5
        pyocd_observe -c "read32 $HW_GUEST0_RAM" >/dev/null 2>&1 || true
    done
    wait
}

hw_read32() {
    pyocd_read32 "$1"
}

hw_readback() {
    pyocd_readback "$1" "$2" "$3"
}

hw_collect() {
    local lc
    hw_verify_image "$HW_WOLFBOOT_ADDR" "$HW_WOLFBOOT_BIN"
    emit_word "nvm.phrase" "$(pyocd_read32 "$(printf '0x%x' $((HW_HSM_NVM_ADDR + 4)))")"
    emit_word "nvm.blank" "$(pyocd_read32 "$(printf '0x%x' $((HW_HSM_NVM_ADDR + HW_FLASH_SECTOR)))")"
    emit_word "mem.handoff" "$(pyocd_read32 "$HW_HANDOFF_ADDR")"
    emit_word "cpu.ipsr_fault" "$(pyocd_ipsr_fault)"
    lc="$(pyocd_read32 "$HW_SYSCON_LC_STATE")"
    emit_word "syscon.lc_state" "$lc"
    emit_sym_word g_wt_boot_handoff build/wolftrust-signed.elf handoff 12
    sed -i 's/^handoff\.g_wt_boot_handoff=/handoff.lifecycle=/' "$evidence/swd.txt"
    emit_sym_word g_wt_els_last_status build/wolftrust-signed.elf sym
    emit_sym_word g_wt_els_last_err build/wolftrust-signed.elf sym
}
