# shellcheck shell=bash disable=SC2034,SC2154
# MIMXRT700-EVK hardware profile for tests/target/run_hardware.sh: wolfBoot is
# wrapped with the EVK FCB and a plain MBI (nxpimage), every image is flashed
# with pyOCD through the bound MCU-Link with the core parked, the board is
# reset through the pi4 line, and the evidence is read over SWD (the EVK
# runner captures no console).

HW_XSPI0_BASE=0x28000000
HW_MBI_OFFSET=0x4000
HW_WOLFBOOT_ADDR=0x28000000
HW_SECURE_ADDR=0x28040000
HW_GUEST0_ADDR=0x28080000
HW_GUEST1_ADDR=0x28100000
HW_GUEST0_RAM=0x20100000
HW_GUEST1_RAM=0x20140000
HW_HSM_NVM_ADDR=0x281E0000
HW_HSM_NVM_SIZE=0x2000
HW_PACK_TARGET="${RT700_TARGET:-mimxrt798sgfob}"
HW_FCB="${RT700_FCB:-$HOME/rt700-boot/fcb.bin}"
HW_SPSDK_VENV="${RT700_SPSDK_VENV:-$HOME/spsdk-venv}"
HW_SIGN_EXTRA=""
HW_PST_MAILBOX=0x20180080
HW_SMOKE_MAILBOX=0x20180000
export WT_ATTEST_COSE=0

hw_detect() {
    if [ -d "$HW_SPSDK_VENV/bin" ]; then
        PATH="$HW_SPSDK_VENV/bin:$PATH"
        export PATH
    fi
    "$repo/tests/target/detect_rt700.sh"
}

hw_probe_bind() {
    local listed
    if [ -n "${WT_HW_PROBE:-}" ]; then
        HW_PROBE="$WT_HW_PROBE"
        return 0
    fi
    listed="$("$(pyocd_bin)" list 2>/dev/null | grep -F "MCU-LINK" | grep -vF "MCXN947" || true)"
    [ "$(printf '%s\n' "$listed" | grep -c .)" -eq 1 ] ||
        fail "expected exactly one EVK MCU-Link (set WT_HW_PROBE to its unique id)"
    HW_PROBE="$(printf '%s\n' "$listed" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[A-Z0-9]{8,}$/) { print $i; exit } }')"
    [ -n "$HW_PROBE" ] || fail "could not read the probe's unique id"
}

hw_preflight() {
    [ -s "$HW_FCB" ] || fail "fixture: FCB binary missing at $HW_FCB (RT700_FCB)"
    "$here/ports/mimxrt700/reset.sh" status >/dev/null 2>&1 || fail "fixture: the pi4 reset line is not reachable"
}

hw_capture_seconds() {
    echo 5
}

# The first stage is cached per fence setting under ~/.cache/wolftrust; the
# emulator profile already chose the make arguments for this scenario.
hw_first_stage() {
    local dir="$HOME/.cache/wolftrust/wolfboot-rt700"
    case "$WOLFBOOT_DIR" in
        *_fence_selftest) dir="$dir-fence-selftest" ;;
        *_fence) dir="$dir-fence" ;;
    esac
    WOLFBOOT_DIR="${RT700_WOLFBOOT_DIR:-$dir}"
    mkdir -p "$(dirname "$WOLFBOOT_DIR")"
    # The ROM executes the MBI at its configured address: no emulator link
    # override here, only the scenario's fence flags.
    WOLFBOOT_MAKE_ARGS=("CFLAGS_EXTRA=$WOLFBOOT_FENCE_CFLAGS")
}

wrap_xip() {
    local app="$1" out="$2" exec_addr="$3"
    cat > "$evidence/mbi.yaml" <<YAML
family: mimxrt798s
revision: latest
outputImageExecutionTarget: xip
outputImageAuthenticationType: plain
masterBootOutputFile: $evidence/mbi.bin
inputImageFile: $app
outputImageExecutionAddress: $exec_addr
imageVersion: 0
YAML
    nxpimage mbi export -c "$evidence/mbi.yaml" >/dev/null
    cat > "$evidence/bootimg.yaml" <<YAML
family: mimxrt798s
revision: latest
memory_type: xspi_nor
output: $out
output_format: bin
init_offset: 0
fcb: $HW_FCB
mbi: $evidence/mbi.bin
YAML
    nxpimage bootable-image export -c "$evidence/bootimg.yaml" >/dev/null
}

# pyOCD's flash algorithm runs in RAM and faults under wolfTrust's Secure MPU
# whitelist, so the core is parked (hardware reset, MPU off) before each image.
park_core() {
    timeout 60 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t "$HW_PACK_TARGET" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE000ED94 0" >/dev/null 2>&1 || fail "could not park the core"
}

flash_at() {
    local addr="$1" image="$2" out
    [ -s "$image" ] || fail "flash image missing: $image"
    park_core
    if ! out="$(timeout 300 "$(pyocd_bin)" flash -u "$HW_PROBE" -t "$HW_PACK_TARGET" -O resume_on_disconnect=false \
            --no-reset -a "$addr" -e sector "$image" 2>&1)"; then
        printf '%s\n' "$out" | grep -vE "AP#3 IDR" | tail -6
        fail "flash of $(basename "$image") at $addr failed"
    fi
    printf '%s\n' "$out" >> "$evidence/program.log"
}

hw_program() {
    local wolfboot="$1" secure="$2" g0="$3" g1="$4" verified refused
    wrap_xip "$wolfboot" "$evidence/flash_wolfboot.bin" "$(printf '0x%08x' $((HW_XSPI0_BASE + HW_MBI_OFFSET)))"
    flash_at "$HW_XSPI0_BASE" "$evidence/flash_wolfboot.bin"
    flash_at "$HW_SECURE_ADDR" "$secure"
    flash_at "$HW_GUEST0_ADDR" "$g0"
    flash_at "$HW_GUEST1_ADDR" "$g1"
    park_core
    timeout 120 "$(pyocd_bin)" erase -u "$HW_PROBE" -t "$HW_PACK_TARGET" -O resume_on_disconnect=false \
        -s "$(printf '0x%08x-0x%08x' "$HW_HSM_NVM_ADDR" $((HW_HSM_NVM_ADDR + HW_HSM_NVM_SIZE)))" >/dev/null 2>&1 ||
        fail "erase of the wolfHSM NVM store failed"
    # SRAM survives a warm reset: the last run's mailboxes, sentinel and launch
    # masks would otherwise read back as this run's result.
    verified="$(elf_sym g_wt_launch_verified_mask build/wolftrust.elf)"
    refused="$(elf_sym g_wt_launch_refused_mask build/wolftrust.elf)"
    [ -n "$refused" ] || fail "launch masks not found in wolftrust.elf"
    park_core
    timeout 60 "$(pyocd_bin)" cmd -u "$HW_PROBE" -t "$HW_PACK_TARGET" -O resume_on_disconnect=false \
        -c "write32 $HW_GUEST0_RAM 0 0 0 0 0 0 0 0 0 0" -c "write32 $HW_GUEST1_RAM 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $probe_addr 0" -c "write32 $HW_PST_MAILBOX 0 0 0 0 0 0 0 0 0 0 0 0" \
        ${verified:+-c "write32 $verified 0"} -c "write32 $refused 0" >/dev/null 2>&1 ||
        fail "could not clear the guest mailboxes"
}

# Parking leaves the reset vector catch armed; a resuming reset clears it so
# the hard reset through the pi4 line boots the chain instead of halting.
hw_boot() {
    timeout 60 "$(pyocd_bin)" reset -u "$HW_PROBE" -t "$HW_PACK_TARGET" -m hw >/dev/null 2>&1 || fail "could not release the core"
    "$here/ports/mimxrt700/reset.sh" reset
    sleep "$1"
    : > "$evidence/console.log"
}

hw_read32() {
    pyocd_read32 "$1"
}

hw_readback() {
    pyocd_readback "$1" "$2" "$3"
}

# All eight XSPI0 FRADs as "start end acp word3" lines; only words 0-3 of
# each 0x20 stride are readable.
frad_dump() {
    local -a cmds=()
    local n
    for n in 0 1 2 3 4 5 6 7; do
        cmds+=(-c "read32 $(printf '0x%x' $((0x50184800 + n * 0x20))) 16")
    done
    pyocd_observe "${cmds[@]}" | awk '/^50184[89]/ { print $2, $3, $4, $5 }'
}

sfp_sealed() {
    local mgc mdad
    mgc=$((0x$(pyocd_read32 0x50184920)))
    mdad=$((0x$(pyocd_read32 0x50184900)))
    [ $((mgc & 0xA8000000)) -eq $((0xA8000000)) ] && [ $((mgc & 0xC00)) -ne 0 ] &&
        [ $((mdad & 0xA0000000)) -eq $((0xA0000000)) ]
}

# One valid, hard-reset-locked (EAL clear), write-denying FRAD spans the
# guest windows.
fence_armed() {
    local w0 w1 w2 w3 lock
    rt700_fence_bounds || fail "guest fence bounds"
    while read -r w0 w1 w2 w3; do
        lock=$((0x$w3 & 0x63000000))
        if [ $((0x$w0 & 0xFFFF0000)) -le $((RT700_GUEST_FENCE_START)) ] &&
           [ $(((0x$w1 & 0xFFFF0000) | 0xFFFF)) -ge $((RT700_GUEST_FENCE_END - 1)) ] &&
           [ $((0x$w3 & 0x80000000)) -ne 0 ] && [ $((0x$w2 & 0x3F)) -eq 0 ] &&
           { [ "$lock" -eq $((0x20000000)) ] || [ "$lock" -eq $((0x60000000)) ]; }; then
            return 0
        fi
    done < <(frad_dump)
    return 1
}

hw_collect() {
    local n
    hw_verify_image "$HW_XSPI0_BASE" "$evidence/flash_wolfboot.bin"
    emit_word "cpu.ipsr_fault" "$(pyocd_ipsr_fault)"
    emit_word "cpu.iabr2" "$(pyocd_read32 0xE000E308)"
    case "$scenario" in
        wrpfence|wrpoff|wrpneg)
            emit_word "fence.sfp_sealed" "$(sfp_sealed && printf '00000001' || printf '00000000')"
            emit_word "fence.armed" "$(fence_armed && printf '00000001' || printf '00000000')"
            for n in 0 1 3 4 7 8 9 10 11; do
                emit_word "pst.$n" "$(pyocd_read32 "$(printf '0x%x' $((HW_PST_MAILBOX + 4 * n)))")"
            done
            printf 'pst_4=%s\n' "$(pyocd_read32 "$(printf '0x%x' $((HW_PST_MAILBOX + 16)))")" >> "$evidence/vars.txt" ;;
    esac
}

# The BootROM boots our own XIP image from XSPI0: a marker and a moving
# counter in SRAM, with the PC inside the image.
hw_scenario_romsmoke() {
    local pc
    make -s -C "$repo/tests/firmware/mimxrt700-smoke" BUILD="$evidence/smoke" all
    wrap_xip "$evidence/smoke/smoke.bin" "$evidence/flash_smoke.bin" "$(printf '0x%08x' $((HW_XSPI0_BASE + HW_MBI_OFFSET)))"
    flash_at "$HW_XSPI0_BASE" "$evidence/flash_smoke.bin"
    hw_boot 2
    hw_verify_image "$HW_XSPI0_BASE" "$evidence/flash_smoke.bin"
    : > "$evidence/swd.txt"
    emit_word "smoke.marker" "$(pyocd_read32 "$HW_SMOKE_MAILBOX")"
    emit_beat "smoke.counter" "$HW_SMOKE_MAILBOX" 4
    pc="$(pyocd_observe -c halt -c 'reg pc' -c go | sed -n 's/^pc = 0x//p')"
    emit_word "cpu.pc" "$(printf '%08x' $((0x${pc:-0})))"
}
