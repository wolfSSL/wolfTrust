#!/usr/bin/env bash
# FRDM-MCXN947 hardware runner (sibling of run_rt700_hardware.sh and
# run_mcxn947_m33mu.sh; one CLI shape). Runs on the host that owns the probe.
#
#   run_mcxn947_hardware.sh <scenario>
#
# Scenarios:
#   positive  the full chain: wolfBoot (TrustZone loader) authenticates the
#             wolfTrust Secure image, which launches both Non-secure guests.
#             Builds wolfTrust + the guests, pins the guest measurements,
#             wolfBoot-signs the Secure image, flashes the chain, erases the
#             update, swap and NVM sectors so the run starts from a fresh
#             vault, resets, verifies every image by readback, and asserts the
#             guest mailboxes, the launch masks, the ROM flash status and the
#             vault's first phrase over SWD.
#   sauneg    positive plus the guest isolation negative: guest0 stores into
#             guest1's RAM, which the per-dispatch SAU window keeps Secure; the
#             store must fault on every launch until guest0 is quarantined,
#             guest1's RAM never holds the sentinel, and guest1 keeps running.
#   periphneg guest0, its MPU off, reads the SPM's ELS through the Non-secure
#             alias on every launch; the SAU must refuse it (no leak) until
#             guest0 is quarantined, and guest1 keeps running.
#   restart   guest0 reads Secure RAM on every launch: the monitor spends its
#             restart budget and quarantines it; guest1 is untouched.
#   psa       both Non-secure windows run the portable PSA client
#             (tests/firmware/psa-guest): every lifecycle stage must complete
#             in both mailboxes, with the ELS behind psa_generate_random.
#
# The probe is the board's MCU-Link, the one pyOCD lists as
# "MCU-LINK FRDM-MCXN947" (MCXN947_PROBE_UID picks one of several); the
# console is its VCOM (MCXN947_CONSOLE). The wolfBoot first stage is
# MCXN947_WOLFBOOT_REF plus the carried patch (lib/mcxn947_wolfboot.sh)
# unless MCXN947_WOLFBOOT_DIR names a tree that library built.
set -euo pipefail

scenario="${1:-}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="${MCXN947_WORK:-$repo/build/mcxn947-hw}"
target="${MCXN947_TARGET:-mcxn947vdf}"
probe_uid="${MCXN947_PROBE_UID:-}"
console="${MCXN947_CONSOLE:-}"
wolfboot_dir="${MCXN947_WOLFBOOT_DIR:-}"
spsdk_venv="${MCXN947_SPSDK_VENV:-$HOME/spsdk-venv}"
console_seconds="${MCXN947_CONSOLE_SECONDS:-25}"
# Physical flash offsets (port/mcxn947/memory_map.h, wolfBoot's
# mcxn-tz-wolftrust config): the debugger and the ROM see the array at 0.
wolfboot_flash_addr=0x00000000
secure_flash_addr=0x00040000
guest0_flash_addr=0x00080000
guest1_flash_addr=0x00100000
update_erase=0x00180000-0x001C2000
nvm_erase=0x001E0000-0x001E6000
hsm_nvm_addr=0x001E0000
flash_sector=0x2000
guest0_ram=0x20000000
guest1_ram=0x20018000
probe_addr=0x20028000
handoff_addr=0x30030000
syscon_lc_state=0x50000980
# The guests' manifest restart budget (port/mcxn947/partitions.c).
restart_limit=3
baremetal_dir="$repo/tests/firmware/mcxn947-baremetal"
psa_dir="$repo/tests/firmware/psa-guest"

# shellcheck source=lib/mcxn947_wolfboot.sh disable=SC1091
. "$here/lib/mcxn947_wolfboot.sh"

log() { printf '%s\n' "$*"; }
stage() { printf '  ... %s\n' "$*"; }
fail() { log "FAIL: $*"; exit 1; }
check() {
    if [ "$1" -eq 0 ]; then log "  [check] PASS  $2"; else log "  [check] FAIL  $2"; fail "$2"; fi
}

ensure_spsdk() {
    if ! command -v pyocd >/dev/null 2>&1; then
        [ -x "$spsdk_venv/bin/pyocd" ] || fail "pyocd not found (set MCXN947_SPSDK_VENV)"
        PATH="$spsdk_venv/bin:$PATH"
        export PATH
    fi
}

# The board's own MCU-Link, unless the caller named a probe; other probes on
# the host belong to other boards and are never touched.
ensure_probe() {
    local listed
    if [ -z "$probe_uid" ]; then
        listed="$(pyocd list 2>/dev/null | grep -F "MCU-LINK FRDM-MCXN947" || true)"
        [ "$(printf '%s\n' "$listed" | grep -c .)" -eq 1 ] || \
            fail "expected one MCU-Link FRDM-MCXN947 probe (set MCXN947_PROBE_UID)"
        probe_uid="$(printf '%s\n' "$listed" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[A-Z0-9]{8,}$/) { print $i; exit } }')"
        [ -n "$probe_uid" ] || fail "could not read the probe's unique id"
    fi
    if [ -z "$console" ]; then
        for tty in /dev/serial/by-id/*FRDM-MCXN947*-if02; do
            [ -c "$tty" ] && console="$tty" && break
        done
    fi
    [ -n "$console" ] && [ -c "$console" ] || fail "board console not found (set MCXN947_CONSOLE)"
}

# Observation uses the generic Cortex-M attach: the device-pack target resets
# the chip on connect, so a read would land in a fresh boot, not the one under
# test.
dap() {
    timeout 60 pyocd cmd -u "$probe_uid" -t cortex_m "$@" 2>&1 |
        grep -viE "rom table|APB-AP|coresight|cidr"
}

# Park the core before wolfTrust owns it: pyOCD's flash algorithm runs in RAM
# and faults under wolfTrust's Secure MPU whitelist, so the halt is followed
# by disabling the MPU explicitly.
park_core() {
    timeout 60 pyocd cmd -u "$probe_uid" -t "$target" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE000ED94 0" \
        >/dev/null 2>&1 || fail "could not park the core"
}

# A failed or partial flash must stop the run: a stale image either boots old
# code or fails its pinned measurement and looks like a port bug.
flash_at() {
    local addr="$1" image="$2" out
    [ -s "$image" ] || fail "flash image missing: $image"
    park_core
    if ! out="$(timeout 300 pyocd flash -u "$probe_uid" -t "$target" \
            -O resume_on_disconnect=false --no-reset -a "$addr" -e sector "$image" 2>&1)"; then
        printf '%s\n' "$out" | tail -6
        fail "flash of $(basename "$image") at $addr failed"
    fi
}

# The board keeps the update, swap and NVM sectors across runs where the
# emulator starts fresh; erasing them puts every run on a blank vault.
erase_ranges() {
    park_core
    timeout 180 pyocd erase -u "$probe_uid" -t "$target" -O resume_on_disconnect=false \
        -s "$@" >/dev/null 2>&1 || fail "erase of $* failed"
}

# SRAM survives a warm reset, so the last run's mailboxes, sentinel and launch
# masks would otherwise read back as this run's result.
clear_mailboxes() {
    local verified refused
    verified="$(elf_sym g_wt_launch_verified_mask)"
    refused="$(elf_sym g_wt_launch_refused_mask)"
    [ -n "$verified" ] && [ -n "$refused" ] || fail "launch masks not found in wolftrust.elf"
    park_core
    timeout 60 pyocd cmd -u "$probe_uid" -t "$target" -O resume_on_disconnect=false \
        -c "write32 $guest0_ram 0 0 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $guest1_ram 0 0 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $probe_addr 0" \
        -c "write32 $verified 0" -c "write32 $refused 0" >/dev/null 2>&1 || \
        fail "could not clear the guest mailboxes"
}

# Boot from the parked state: the pack's halt leaves a DWT comparator and the
# debug fault status armed, which would stop the chain again, so both are
# cleared before the core is released. The console is read for the whole boot;
# the MCU-Link forwards early-boot UART only while the debug link stays active,
# so the capture is kept company by spaced reads.
release_core() {
    local n
    stty -F "$console" 115200 raw -echo -crtscts -ixon 2>/dev/null || true
    ( timeout "$console_seconds" cat "$console" > "$work/console.log" 2>/dev/null ) &
    sleep 0.5
    timeout 60 pyocd cmd -u "$probe_uid" -t "$target" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE0001028 0" \
        -c "write32 0xE0001038 0" -c "write32 0xE000ED30 0x1F" -c "go" \
        >/dev/null 2>&1 || fail "could not release the core"
    for n in 1 2 3 4 5 6; do
        sleep 1.5
        dap -c "read32 $guest0_ram" >/dev/null 2>&1 || true
    done
    wait
}

# Read an image back over the debug port once the chain has booted and
# compare it.
verify_at() {
    local addr="$1" image="$2" size
    size="$(wc -c < "$image" | tr -d ' ')"
    timeout 120 pyocd cmd -u "$probe_uid" -t cortex_m \
        -c "savemem $addr $size $work/readback.bin" >/dev/null 2>&1 || \
        fail "readback of $addr failed"
    cmp -s "$work/readback.bin" "$image" || \
        fail "flash verify mismatch at $addr ($(basename "$image"))"
    log "  [flash] verified $(basename "$image") @ $addr"
}

ensure_wolfboot() {
    if [ -n "$wolfboot_dir" ]; then
        mcxn947_wolfboot_current "$wolfboot_dir" "$(mcxn947_wolfboot_stamp)" || \
            fail "MCXN947_WOLFBOOT_DIR=$wolfboot_dir was not built by lib/mcxn947_wolfboot.sh at $MCXN947_WOLFBOOT_REF"
    else
        wolfboot_dir="$HOME/.cache/wolftrust/wolfboot-mcxn947"
        mkdir -p "$(dirname "$wolfboot_dir")"
        stage "wolfBoot $MCXN947_WOLFBOOT_REF (mcxn-tz-wolftrust)"
        mcxn947_wolfboot_build "$wolfboot_dir" > "$work/wolfboot-build.log" 2>&1 || {
            tail -20 "$work/wolfboot-build.log"
            fail "wolfBoot build failed"
        }
    fi
    [ -s "$wolfboot_dir/wolfboot.bin" ] || \
        fail "wolfBoot image missing at $wolfboot_dir/wolfboot.bin (MCXN947_WOLFBOOT_DIR)"
}

# Build wolfTrust and both guests, pin the guest measurements, sign, flash the
# whole chain, boot it from a fresh vault, and verify every image by readback.
run_chain() {
    local guest_dir="$1" guest_flags="$2" guest_build

    ensure_spsdk
    ensure_probe
    mkdir -p "$work"
    ensure_wolfboot

    # MCXN wolfBoot uses a 1024-byte image header, so wolfTrust links at the
    # boot base + 0x400 and is signed with a matching header. Exported so the
    # secure image and the guest CMSE import library agree.
    export WT_SECURE_IMAGE_HEADER_SIZE=0x400
    rm -rf "$repo/build"
    mkdir -p "$work"

    stage "build wolfTrust secure image + CMSE import library (${WT_ENGINE:-native})"
    make -s -C "$repo" TARGET=mcxn947 secure-image TOOLPREFIX=arm-none-eabi-

    stage "build the Non-secure guests from ${guest_dir#"$repo/"} ${guest_flags:-(no probes)}"
    make -s -C "$guest_dir" clean
    # The board is OEM_OPEN, the ASSEMBLY_AND_TEST life cycle the attestation
    # token reports; the PSA guest's verify pins it.
    # shellcheck disable=SC2086
    make -s -C "$guest_dir" TARGET=mcxn947 WT_EXPECTED_LIFECYCLE=0x1000u $guest_flags
    guest_build="$guest_dir/build"

    stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
    python3 "$repo/tools/measure/patch_guest_digests.py" "$repo/build/wolftrust.bin" \
        "0:1:$guest_build/guest0.bin" "1:1:$guest_build/guest1.bin"
    IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=$flash_sector \
        "$wolfboot_dir/tools/keytools/sign" --ecc256 --sha256 \
        "$repo/build/wolftrust.bin" \
        "$wolfboot_dir/wolfboot_signing_private_key.der" 1

    stage "flash the chain"
    flash_at "$wolfboot_flash_addr" "$wolfboot_dir/wolfboot.bin"
    flash_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
    flash_at "$guest0_flash_addr" "$guest_build/guest0.bin"
    flash_at "$guest1_flash_addr" "$guest_build/guest1.bin"
    stage "erase the update, swap and NVM sectors so the run starts from a fresh vault"
    erase_ranges "$update_erase" "$nvm_erase"
    clear_mailboxes

    stage "boot the chain, reading the console for ${console_seconds}s"
    release_core
    verify_at "$wolfboot_flash_addr" "$wolfboot_dir/wolfboot.bin"
    verify_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
    verify_at "$guest0_flash_addr" "$guest_build/guest0.bin"
    verify_at "$guest1_flash_addr" "$guest_build/guest1.bin"
    log "  [console] $work/console.log"
}

# One 32-bit word at base+offset over SWD, as eight lowercase hex digits.
word_at() {
    dap -c "read32 $(printf '0x%x' $(($1 + $2)))" | grep -oiE '[0-9a-f]{8}' | tail -1 |
        tr 'A-F' 'a-f'
}

# A wolfTrust global's address, from the image this run built and flashed.
elf_sym() {
    arm-none-eabi-nm "$repo/build/wolftrust.elf" |
        awk -v s="$1" '$3 == s && !f { print "0x" $1; f = 1 }'
}

sym_word() { word_at "$(elf_sym "$1")" 0; }

# Each bare-metal guest records its progress at the base of its own RAM
# window (tests/firmware/mcxn947-baremetal/guest0.c).
check_guest() {
    local id="$1" base="$2" sig fw st uart
    sig="$(word_at "$base" 0)"
    fw="$(word_at "$base" 8)"
    st="$(word_at "$base" 20)"
    uart="$(word_at "$base" 24)"
    check "$([ "$sig" = "47543030" ]; echo $?)" "guest$id launched: signature 0x47543030 ($sig)"
    check "$([ "$fw" = "00000100" ]; echo $?)" "guest$id psa_framework_version 0x0100 ($fw)"
    check "$([ "$st" = "600d600d" ]; echo $?)" \
        "guest$id done: FF-M connect verified, status 0x600D600D ($st)"
    check "$([ -n "$uart" ] && [ "$uart" != "00000000" ]; echo $?)" \
        "guest$id reaches its Non-secure console (LPUART4 VERID 0x$uart)"
}

# The peer keeps running: its idle beat advances between two reads.
check_beating() {
    local id="$1" base="$2" b1 b2
    b1="$(word_at "$base" 36)"
    sleep 1
    b2="$(word_at "$base" 36)"
    check "$([ -n "$b1" ] && [ "$b1" != "$b2" ]; echo $?)" \
        "guest$id still running (beat 0x$b1 -> 0x$b2)"
}

check_launch_masks() {
    local want_verified="$1" want_refused="$2" verified refused
    verified="$(sym_word g_wt_launch_verified_mask)"
    refused="$(sym_word g_wt_launch_refused_mask)"
    check "$([ "$verified" = "$want_verified" ]; echo $?)" \
        "launch-verified guest mask 0x$verified (want 0x$want_verified)"
    check "$([ "$refused" = "$want_refused" ]; echo $?)" \
        "launch-refused guest mask 0x$refused (want 0x$want_refused)"
}

# The Secure side of every run: the ROM flash API answered from the SVC gate,
# the vault was created in the ROM-programmed NVM, an erased phrase reads as
# 0xFF, wolfBoot's handoff was consumed, and the scheduler is not in a fault
# handler.
check_secure_side() {
    local rom err els phrase blank handoff ipsr lc handed
    rom="$(sym_word g_wt_rom_flash_last_status)"
    err="$(sym_word g_wt_flash_last_error)"
    check "$([ "$rom" = "00000000" ]; echo $?)" \
        "ROM flash API reached from the SVC gate, last status 0x$rom"
    check "$([ "$err" = "00000000" ]; echo $?)" "wolfHSM flash backend last error 0x$err"
    els="$(sym_word g_wt_els_errors)"
    check "$([ "$els" = "00000000" ]; echo $?)" \
        "the ELS served every RND_REQ (refusals 0x$els, last status 0x$(sym_word g_wt_els_last_status), error 0x$(sym_word g_wt_els_last_err))"
    phrase="$(word_at "$hsm_nvm_addr" 4)"
    check "$([ -n "$phrase" ] && [ "$phrase" != "ffffffff" ]; echo $?)" \
        "the vault's first state phrase is programmed (0x$phrase)"
    blank="$(word_at "$hsm_nvm_addr" "$flash_sector")"
    check "$([ "$blank" = "ffffffff" ]; echo $?)" \
        "an erased phrase reads as 0xFF through the bus (0x$blank)"
    handoff="$(word_at "$handoff_addr" 0)"
    check "$([ "$handoff" = "00000000" ]; echo $?)" \
        "wolfBoot's handoff record was consumed and cleared (0x$handoff)"
    ipsr="$(dap -c halt -c 'reg xpsr' -c go | sed -n 's/^xpsr = 0x\([0-9a-fA-F]*\).*/\1/p')"
    ipsr=$((0x${ipsr:-3} & 0x1ff))
    check "$([ "$ipsr" -lt 2 ] || [ "$ipsr" -gt 7 ]; echo $?)" \
        "system still scheduling (IPSR $ipsr, not a fault handler)"
    lc="$(word_at "$syscon_lc_state" 0)"
    log "  [lifecycle] ELS_OTP_LC_STATE 0x$lc"
    handed="$(word_at "$(elf_sym g_wt_boot_handoff)" 12)"
    if [ "$lc" = "00000003" ]; then
        check "$([ "$handed" = "00001000" ]; echo $?)" \
            "wolfBoot handed OEM_OPEN as PSA ASSEMBLY_AND_TEST (lifecycle 0x$handed)"
    else
        log "  [lifecycle] handoff lifecycle 0x$handed"
    fi
    check "$(grep -q "Verifying signature...done" "$work/console.log"; echo $?)" \
        "wolfBoot verified the wolfTrust image signature (console)"
}

# guest0 faulted on every launch: the monitor spent its restart budget and
# quarantined it, while guest1 ran untouched.
check_guest0_quarantined() {
    local restarts quarantines st beat
    restarts="$(sym_word g_wt_restart_events)"
    quarantines="$(sym_word g_wt_quarantine_events)"
    check "$([ "$((0x$restarts))" -eq "$restart_limit" ]; echo $?)" \
        "guest0 relaunched through its restart budget ($((0x$restarts)) of $restart_limit)"
    check "$([ "$((0x$quarantines))" -eq 1 ]; echo $?)" \
        "guest0 quarantined once ($((0x$quarantines)))"
    st="$(word_at "$guest0_ram" 20)"
    beat="$(word_at "$guest0_ram" 36)"
    check "$([ "$st" != "600d600d" ]; echo $?)" "guest0 never reported done (status 0x$st)"
    check "$([ "$beat" = "00000000" ]; echo $?)" "guest0 never reached its idle loop (beat 0x$beat)"
    check_launch_masks 00000003 00000000
    check_guest 1 "$guest1_ram"
    check_beating 1 "$guest1_ram"
}

# The PSA guest's mailbox (tests/firmware/psa-guest/main.c): a signature and
# the lifecycle stages it completed.
check_psa_guest() {
    local id="$1" base="$2" sig lc neg
    sig="$(word_at "$base" 0)"
    lc="$(word_at "$base" 4)"
    neg="$(word_at "$base" 8)"
    check "$([ "$sig" = "50534147" ]; echo $?)" "guest$id launched: signature PSAG ($sig)"
    check "$([ $((0x$lc & 0xBF)) -eq $((0xBF)) ]; echo $?)" \
        "guest$id completed the TEE, crypto, ITS, PS, key-ops, SHA KAT and done stages (0x$lc)"
    check "$([ $((0x$lc & 0x40)) -ne 0 ]; echo $?)" \
        "guest$id completed the attestation COSE stage (0x$lc)"
    check "$([ "$neg" = "0000000f" ]; echo $?)" \
        "guest$id FF-M negatives all rejected: forged handle, oversized vector, cross-guest vector, unknown SID (0x$neg)"
}

case "$scenario" in
positive)
    run_chain "$baremetal_dir" ""
    check_guest 0 "$guest0_ram"
    check_guest 1 "$guest1_ram"
    check_launch_masks 00000003 00000000
    check "$([ "$(sym_word g_wt_restart_events)" = "00000000" ]; echo $?)" "no guest restarted"
    check_secure_side
    log "PASS: hardware/mcxn947/$scenario"
    ;;
sauneg)
    run_chain "$baremetal_dir" "WT_SAU_PROBE=1"
    check_guest0_quarantined
    peer="$(word_at "$probe_addr" 0)"
    check "$([ "$peer" != "deadbeef" ]; echo $?)" \
        "guest1 RAM never received guest0's sentinel (0x$peer)"
    check_secure_side
    log "PASS: hardware/mcxn947/$scenario"
    ;;
periphneg)
    run_chain "$baremetal_dir" "WT_PERIPH_NEG_PROBE=1"
    check_guest0_quarantined
    check "$(! grep -q "periph probe LEAKED" "$work/console.log"; echo $?)" \
        "no NS read of the SPM's ELS ever returned (console)"
    check_secure_side
    log "PASS: hardware/mcxn947/$scenario"
    ;;
restart)
    run_chain "$baremetal_dir" "WT_GUEST_FAULT_PROBE=1"
    check_guest0_quarantined
    check_secure_side
    log "PASS: hardware/mcxn947/$scenario"
    ;;
psa)
    run_chain "$psa_dir" ""
    check_psa_guest 0 "$guest0_ram"
    check_psa_guest 1 "$guest1_ram"
    check_launch_masks 00000003 00000000
    check "$([ "$(sym_word g_wt_restart_events)" = "00000000" ]; echo $?)" "no guest restarted"
    check_secure_side
    log "PASS: hardware/mcxn947/$scenario"
    ;;
*)
    log "usage: $0 positive|sauneg|periphneg|restart|psa"
    exit 2
    ;;
esac
