#!/usr/bin/env bash
# run_stm32l562_hardware.sh
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

# One wolfTrust scenario on a real STM32L562E-DK: build wolfTrust (native
# engine) and two Non-secure guests, sign wolfTrust for the pinned wolfBoot
# stm32l5-tz-wolftrust first stage, flash the chain through the on-board
# ST-LINK (lib/stm32l562_probe.sh: STM32CubeProgrammer, or OpenOCD where it is
# not installed), boot it and judge it from the console and SWD reads of the
# guests' mailboxes and wolfTrust's globals.
#
#   positive  both bare-metal guests launch verified, complete the FF-M
#             handshake through the SG veneers, and keep running.
#   gtzcneg   guest0, its MPU off, stores into guest1's RAM; the GTZC MPCBB
#             curtain must stop it (fault and quarantine, or RAZ/WI), the
#             sentinel never lands, and guest1 keeps running.
#   periphneg guest0, its MPU off, reads the SPM's RNG through the Non-secure
#             alias on every launch; the SAU must refuse it until guest0 is
#             quarantined, and guest1 keeps running.
#   restart   guest0 reads Secure RAM on every launch: the monitor spends its
#             restart budget and quarantines it; guest1 is untouched.
#   psa       both Non-secure windows run the portable PSA client
#             (tests/firmware/psa-guest): every lifecycle stage must complete
#             in both mailboxes.
#   wrpoff    wolfTrust built with WT_GUEST_FLASH_WRP=1 on a part whose guest
#             WRP fence is not armed must refuse both guests (launch refused
#             mask 0x3, no mailbox written).
#   wrpfence  the same wolfTrust with WRP2A armed over both guest windows
#             (a reversible option byte write at RDP level 0) must launch both
#             guests, and the silicon must refuse a debugger erase inside the
#             fence (OpenOCD backend); the fence is released on every exit.
#
# The part must carry the production perimeter at RDP level 0
# (provisioning_ctrl.sh set-perimeter: TZEN, the watermarks, SECBOOTADD0 at
# wolfBoot) and no guest WRP fence, which would keep the guests from being
# reflashed (clear-wrp). BOOT_LOCK is not required: a passing positive run is
# the evidence boot-lock asks for, so it records one for the provisioning
# controller. The probe is the DK's ST-LINK (STM32L562_STLINK_SN picks one of
# several, and must still be an STM32L562E-DK's); the console is its virtual
# COM port (STM32L562_CONSOLE). The wolfBoot first stage is the pinned
# STM32L562_WOLFBOOT_REF (lib/stm32l562_wolfboot.sh) unless
# STM32L562_WOLFBOOT_DIR names a tree that library built.
set -euo pipefail

scenario="${1:-}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# Retained evidence (console, readback, wolfBoot build log) lives outside
# build/, which every run cleans before it builds.
work="${STM32L562_WORK:-$repo/logs/stm32l562-hw}"
lock="${STM32L562_HW_LOCK:-$repo/logs/stm32l562-hw.lock}"
engine="${WT_ENGINE:-native}"
case "$scenario" in
    positive|gtzcneg|periphneg|restart|psa|wrpoff|wrpfence) ;;
    *) echo "usage: $0 positive|gtzcneg|periphneg|restart|psa|wrpoff|wrpfence" >&2; exit 2 ;;
esac
if [ "$engine" != "native" ]; then
    echo "TARGET=stm32l562 builds the native engine only" >&2
    exit 2
fi
case "$scenario" in
    wrpoff|wrpfence) export WT_GUEST_FLASH_WRP=1 ;;
esac
# Each run's console, readbacks and SWD dump, kept per scenario and engine.
evidence="$work/$scenario-$engine"
stlink_sn="${STM32L562_STLINK_SN:-}"
console="${STM32L562_CONSOLE:-}"
wolfboot_dir="${STM32L562_WOLFBOOT_DIR:-}"
console_seconds="${STM32L562_CONSOLE_SECONDS:-25}"
byid="${STM32L562_BYID_DIR:-/dev/serial/by-id}"
# The record boot-lock requires, in the provisioning controller's state.
hwrun_record="${WT_PROVISION_STATE:-$HOME/.cache/wolftrust}/stm32l562/hwrun"
# The production layout (port/stm32l562/memory_map.h, wolfBoot's
# stm32l5-tz-wolftrust config): bank 1 and the update slot through the
# Secure alias, the guest windows through the Non-secure one.
wolfboot_flash_addr=0x0C000000
secure_flash_addr=0x0C00C000
guest0_flash_addr=0x08060000
guest1_flash_addr=0x08070000
hsm_nvm_addr=0x0C038000
flash_sector=0x2000
part_size=0x20000
guest0_ram=0x20028000
guest1_ram=0x20034000
# What guest0's probes touch (tests/firmware/stm32l562-baremetal/Makefile):
# guest1's RAM, the SPM's RNG through its NS alias, and Secure RAM.
probe_addr=0x20034100
periph_probe_addr=0x420C0800
restart_probe_addr=0x30001000
handoff_addr=0x30000000
# The guests' manifest restart budget (port/stm32l562/partitions.c).
restart_limit=3
baremetal_dir="$repo/tests/firmware/stm32l562-baremetal"
psa_dir="$repo/tests/firmware/psa-guest"

# shellcheck source=lib/stm32l562_wolfboot.sh disable=SC1091
. "$here/lib/stm32l562_wolfboot.sh"
# shellcheck source=lib/stm32l562_probe.sh disable=SC1091
. "$here/lib/stm32l562_probe.sh"

# One run at a time owns the board; a suite batch takes the same lock once
# for all of its scenarios and says so.
if [ -z "${STM32L562_HW_LOCKED:-}" ]; then
    mkdir -p "$(dirname "$lock")"
    exec 9>"$lock"
    flock 9
fi

log() { printf '%s\n' "$*"; }
stage() { printf '  ... %s\n' "$*"; }
fail() { log "FAIL: $*"; exit 1; }
check() {
    if [ "$1" -eq 0 ]; then log "  [check] PASS  $2"; else log "  [check] FAIL  $2"; fail "$2"; fi
}
# The DK's own ST-LINK; a serial the caller names must still belong to an
# STM32L562E-DK. Other probes on the host belong to other boards and are never
# touched.
ensure_probe() {
    local listed
    L5_TOOL="$(l5_tool)" || fail "$(l5_tool_missing)"
    if [ -z "$stlink_sn" ]; then
        listed="$(l5_dk_serials)"
        [ "$(printf '%s\n' "$listed" | grep -c .)" -eq 1 ] || \
            fail "expected one STM32L562E-DK ST-LINK (set STM32L562_STLINK_SN)"
        stlink_sn="$listed"
    else
        l5_is_dk "$stlink_sn" || \
            fail "ST-LINK $stlink_sn is not an attached STM32L562E-DK's (STM32L562_STLINK_SN)"
    fi
    if [ -z "$console" ]; then
        for tty in "$byid"/*STLINK*"$stlink_sn"*-if0[0-9]; do
            [ -c "$tty" ] && console="$tty" && break
        done
    fi
    [ -n "$console" ] && [ -c "$console" ] || fail "board console not found (set STM32L562_CONSOLE)"
    log "  [probe] ST-LINK $stlink_sn through $L5_TOOL, console $console"
}

# The port's layout needs TrustZone, the production watermarks, the Secure
# boot address at wolfBoot, both banks unswapped, RDP level 0 and no guest WRP
# fence over the windows it flashes. BOOT_LOCK may be either value.
ensure_perimeter() {
    local ob name want got s e boot_lock
    ob="$(l5_ob_displ "$stlink_sn")"
    for want in RDP=0xAA TZEN=0x1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
            SECWM2_PSTRT=0x0 SECWM2_PEND=0x3F SECBOOTADD0=0x180000 \
            DBANK=0x1 SWAP_BANK=0x0; do
        name="${want%%=*}"
        got="$(awk -v n="$name" '$1 == n && $2 == ":" { print $3; exit }' <<<"$ob")"
        [ -n "$got" ] && [ "$((got))" -eq "$((${want#*=}))" ] || \
            fail "option byte $name is ${got:-unreadable}, want ${want#*=} (TARGET=stm32l562 tests/target/provisioning/provisioning_ctrl.sh set-perimeter)"
    done
    boot_lock="$(awk '$1 == "BOOT_LOCK" && $2 == ":" { print $3; exit }' <<<"$ob")"
    for name in WRP2A WRP2B; do
        s="$(awk -v n="${name}_PSTRT" '$1 == n && $2 == ":" { print $3; exit }' <<<"$ob")"
        e="$(awk -v n="${name}_PEND" '$1 == n && $2 == ":" { print $3; exit }' <<<"$ob")"
        if [ -n "$s" ] && [ -n "$e" ] && [ $((s)) -le $((e)) ] && [ $((e)) -ge $((0x40)) ]; then
            fail "$name protects bank 2 pages $s-$e, so the guests cannot be reflashed (provisioning_ctrl.sh clear-wrp)"
        fi
    done
    log "  [perimeter] RDP 0xAA, TZEN, SECWM1 0-0x7F, SECWM2 0-0x3F, SECBOOTADD0 0x0C000000 (BOOT_LOCK ${boot_lock:-?}), no guest WRP"
}

ensure_wolfboot() {
    if [ -n "$wolfboot_dir" ]; then
        stm32l562_wolfboot_current "$wolfboot_dir" \
            "$(stm32l562_wolfboot_stamp WOLFBOOT_PARTITION_SIZE=$part_size)" || \
            fail "STM32L562_WOLFBOOT_DIR=$wolfboot_dir was not built by lib/stm32l562_wolfboot.sh at $STM32L562_WOLFBOOT_REF for the production layout"
    else
        wolfboot_dir="$HOME/.cache/wolftrust/wolfboot-stm32l562"
        mkdir -p "$(dirname "$wolfboot_dir")"
        stage "wolfBoot $STM32L562_WOLFBOOT_REF (stm32l5-tz-wolftrust, production layout)"
        stm32l562_wolfboot_build "$wolfboot_dir" WOLFBOOT_PARTITION_SIZE=$part_size \
            > "$work/wolfboot-build.log" 2>&1 || {
            tail -20 "$work/wolfboot-build.log"
            fail "wolfBoot build failed"
        }
    fi
    [ -s "$wolfboot_dir/wolfboot.bin" ] || \
        fail "wolfBoot image missing at $wolfboot_dir/wolfboot.bin (STM32L562_WOLFBOOT_DIR)"
    cmp -s "$wolfboot_dir/hal/stm32l5_lifecycle.h" \
        "$repo/tests/host/stm32l562_lifecycle/stm32l5_lifecycle.h" || \
        fail "wolfBoot's hal/stm32l5_lifecycle.h differs from the copy the host suite tests"
}

# Each image trimmed of its trailing erased bytes, after a check that it fits
# its window: the programmer erases the whole flash and writes only these
# bytes, so the vault, swap and update slot start erased, never 0xFF-written.
make_flash_images() {
    local spec name src window addr
    flash_specs=()
    for spec in "wolfboot:$wolfboot_dir/wolfboot.bin:0xC000:$wolfboot_flash_addr" \
            "wolftrust:$repo/build/wolftrust_v1_signed.bin:$part_size:$secure_flash_addr" \
            "guest0:$1/guest0.bin:0x10000:$guest0_flash_addr" \
            "guest1:$1/guest1.bin:0x10000:$guest1_flash_addr"; do
        IFS=: read -r name src window addr <<<"$spec"
        [ -s "$src" ] || fail "flash image missing: $src"
        [ "$(wc -c < "$src" | tr -d ' ')" -le $((window)) ] || \
            fail "$src does not fit its $window window at $addr"
        l5_trim "$src" "$evidence/flash-$name.bin" || fail "could not trim $src"
        flash_specs+=("$evidence/flash-$name.bin@$addr")
    done
}

# A failed or unverified programming run stops before the boot: a stale image
# either boots old code or fails its pinned measurement and looks like a port
# bug.
program_board() {
    local out rc=0
    out="$(l5_program "$stlink_sn" "${flash_specs[@]}")" || rc=$?
    printf '%s\n' "$out" > "$evidence/program.log"
    if [ "$rc" -ne 0 ]; then
        printf '%s\n' "$out" | grep -iE 'error|failed|L5ERR' | tail -6
        fail "programming the board failed"
    fi
}

# SRAM survives a reset, so the mailboxes, the probe word and the launch
# masks are cleared with the core held, then one hardware reset boots the run
# the console captures.
boot_board() {
    local -a clear=()
    local a i
    for a in "$guest0_ram" "$guest1_ram"; do
        for i in 0 1 2 3 4 5 6 7 8 9 10 11; do
            clear+=("$(printf '0x%08x' $((a + i * 4)))")
        done
    done
    clear+=("$probe_addr")
    for a in g_wt_launch_verified_mask g_wt_launch_refused_mask; do
        a="$(elf_sym "$a")"
        [ -z "$a" ] || clear+=("$a")
    done
    [ -n "$(elf_sym g_wt_launch_refused_mask)" ] || fail "launch masks not found in wolftrust.elf"
    stty -F "$console" 115200 raw -echo -crtscts -ixon 2>/dev/null || true
    console_start
    sleep 0.5
    l5_boot "$stlink_sn" "${clear[@]}" > "$evidence/boot.log" || {
        tail -5 "$evidence/boot.log"
        fail "could not clear SRAM and reset the board"
    }
    console_finish
}

# The console is read for the whole budget: only timeout's own expiry (124)
# is a complete capture; an early EOF or a reader error fails the run.
console_start() {
    ( timeout "$console_seconds" cat "$console" > "$evidence/console.log" 2>/dev/null ) &
    console_pid=$!
}

console_finish() {
    local rc=0
    wait "$console_pid" || rc=$?
    [ "$rc" -eq 124 ] || \
        fail "the console capture on $console ended early (status $rc)"
}

# Read an image back over the debug port once the chain has booted and
# compare it.
verify_at() {
    local addr="$1" image="$2" size back
    size="$(wc -c < "$image" | tr -d ' ')"
    back="$evidence/readback-$(basename "$image")"
    rm -f "$back"
    l5_upload "$stlink_sn" "$addr" "$size" "$back" || fail "readback of $addr failed"
    cmp -s "$back" "$image" || fail "flash verify mismatch at $addr ($(basename "$image"))"
    log "  [flash] verified $(basename "$image") @ $addr"
}

# A wolfTrust global's address, from the image this run built and flashed.
elf_sym() {
    arm-none-eabi-nm "$repo/build/wolftrust.elf" |
        awk -v s="$1" '$3 == s && !f { print "0x" $1; f = 1 }'
}

# One 32-bit word at base+offset over SWD, as eight lowercase hex digits.
word_at() {
    local a
    a="$(printf '0x%08x' $(($1 + $2)))"
    l5_read "$stlink_sn" "$a" 4 |
        awk -v a="$a" 'tolower($1) == a && $2 == ":" { print tolower($3) }'
}

sym_word() { word_at "$(elf_sym "$1")" 0; }

# The words every check reads, kept as text beside the console so a verdict
# can be re-read without the board.
dump_evidence() {
    local s
    {
        echo "scenario=$scenario engine=$engine image=$(sha256sum "$repo/build/wolftrust_v1_signed.bin" | cut -c1-16)"
        for s in "$guest0_ram:48" "$guest1_ram:48" "$probe_addr:4" "$hsm_nvm_addr:32" \
                "$(printf '0x%08x' $((hsm_nvm_addr + flash_sector))):16" "$handoff_addr:16"; do
            l5_read "$stlink_sn" "${s%%:*}" "${s##*:}"
        done
        for s in g_wt_launch_verified_mask g_wt_launch_refused_mask g_wt_restart_events \
                g_wt_quarantine_events g_wt_flash_first_err g_wt_flash_gate_aborts \
                g_last_fault_address; do
            echo "$s=$(sym_word "$s" || true)"
        done
        echo "uid=$(l5_uid "$stlink_sn" || echo unreadable) probe=$stlink_sn tool=$L5_TOOL"
        l5_ob_displ "$stlink_sn"
    } > "$evidence/swd.txt" 2>&1 || true
}

# Build wolfTrust and both guests, pin the guest measurements, sign, flash the
# whole chain over an erased vault, boot it, and verify every image by
# readback.
run_chain() {
    local guest_dir="$1" guest_flags="$2" guest_build

    ensure_probe
    mkdir -p "$work"
    ensure_perimeter
    ensure_wolfboot

    # The wolfBoot config uses a 1024-byte image header, so wolfTrust links at
    # the slot base + 0x400 and is signed with a matching header. Exported so
    # the secure image and the guest CMSE import library agree.
    export WT_SECURE_IMAGE_HEADER_SIZE=0x400
    rm -rf "$repo/build" "$evidence"
    mkdir -p "$evidence"

    stage "build wolfTrust secure image + CMSE import library ($engine)"
    make -s -C "$repo" TARGET=stm32l562 secure-image TOOLPREFIX=arm-none-eabi-

    stage "build the Non-secure guests from ${guest_dir#"$repo/"} ${guest_flags:-(no probes)}"
    make -s -C "$guest_dir" clean
    # TZEN=1 at RDP level 0 is the PSA_ROT_PROVISIONING life cycle wolfBoot
    # reports; the PSA guest's verify pins it.
    # shellcheck disable=SC2086
    make -s -C "$guest_dir" TARGET=stm32l562 WT_EXPECTED_LIFECYCLE=0x2000u $guest_flags
    guest_build="$guest_dir/build"

    stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
    python3 "$repo/tools/measure/patch_guest_digests.py" "$repo/build/wolftrust.bin" \
        "0:1:$guest_build/guest0.bin" "1:1:$guest_build/guest1.bin"
    IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=$part_size WOLFBOOT_SECTOR_SIZE=0x800 \
        "$wolfboot_dir/tools/keytools/sign" --ecc256 --sha256 \
        "$repo/build/wolftrust.bin" \
        "$wolfboot_dir/wolfboot_signing_private_key.der" 1

    stage "erase the flash, then program only the images (vault, swap and update slot left erased)"
    make_flash_images "$guest_build"
    program_board

    [ "$scenario" != wrpfence ] || arm_fence
    stage "boot the chain, reading the console for ${console_seconds}s"
    boot_board
    verify_at "$wolfboot_flash_addr" "$wolfboot_dir/wolfboot.bin"
    verify_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
    verify_at "$guest0_flash_addr" "$guest_build/guest0.bin"
    verify_at "$guest1_flash_addr" "$guest_build/guest1.bin"
    dump_evidence
    log "  [evidence] $evidence (console.log, readback-*.bin, swd.txt)"
}

# WRP2A over bank 2 pages 0x40-0x7F, both guest windows; the option byte
# load resets the part. Released again by the EXIT trap whatever happens.
fence_armed=0
arm_fence() {
    stage "arm the guest WRP fence (WRP2A pages 0x40-0x7F)"
    trap release_fence EXIT
    trap 'exit 130' INT HUP
    trap 'exit 143' TERM
    fence_armed=1
    l5_ob_write "$stlink_sn" UR WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F > "$evidence/fence-on.log" 2>&1 || true
    fence_reads 0x40 0x7F || fail "the guest WRP fence did not read back armed"
    log "  [fence] WRP2A pages 0x40-0x7F armed"
}

release_fence() {
    [ "$fence_armed" = 1 ] || return 0
    fence_armed=0
    l5_ob_write "$stlink_sn" UR WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 > "$evidence/fence-off.log" 2>&1 || true
    if fence_reads 0x7F 0x0; then
        log "  [fence] WRP2A released"
    else
        log "FAIL: the guest WRP fence is still armed (provisioning_ctrl.sh clear-wrp)"
        exit 1
    fi
}

fence_reads() {
    local ob
    ob="$(l5_ob_displ "$stlink_sn")"
    [ "$(awk '$1 == "WRP2A_PSTRT" { print $3 }' <<<"$ob")" = "$1" ] &&
        [ "$(awk '$1 == "WRP2A_PEND" { print $3 }' <<<"$ob")" = "$2" ]
}

# Each bare-metal guest records its progress at the base of its own RAM
# window (tests/firmware/stm32l562-baremetal/guest0.c).
check_guest() {
    local id="$1" base="$2" sig fw st
    sig="$(word_at "$base" 0)"
    fw="$(word_at "$base" 8)"
    st="$(word_at "$base" 20)"
    check "$([ "$sig" = "47543030" ]; echo $?)" "guest$id launched: signature 0x47543030 ($sig)"
    check "$([ "$fw" = "00000100" ]; echo $?)" "guest$id psa_framework_version 0x0100 ($fw)"
    check "$([ "$st" = "600d600d" ]; echo $?)" \
        "guest$id done: FF-M connect verified, status 0x600D600D ($st)"
    # Both guests share USART1 and are preempted mid-line, so their text
    # interleaves; the mailbox is the verdict, the console only shows life.
    check "$(grep -aq "wolfTrust STM32L562 gues" "$evidence/console.log"; echo $?)" \
        "the guests wrote to the Non-secure console (USART1)"
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

# The Secure side of every run: the flash driver reached the controller from
# the SVC gate without an error, the vault was created in its Secure pages, an
# erased double-word reads as 0xFF, wolfBoot's handoff was consumed, and it
# carried the level-0 life cycle.
check_secure_side() {
    local err aborts vault blank handoff handed
    err="$(sym_word g_wt_flash_first_err)"
    aborts="$(sym_word g_wt_flash_gate_aborts)"
    check "$([ "$err" = "00000000" ]; echo $?)" "flash driver first error 0x$err"
    check "$([ "$aborts" = "00000000" ]; echo $?)" "flash SVC gate aborts 0x$aborts"
    vault="$(word_at "$hsm_nvm_addr" 0)"
    check "$([ -n "$vault" ] && [ "$vault" != "ffffffff" ]; echo $?)" \
        "the vault's first partition is programmed (0x$vault)"
    blank="$(word_at "$hsm_nvm_addr" "$flash_sector")"
    check "$([ "$blank" = "ffffffff" ]; echo $?)" \
        "an erased double-word reads as 0xFF through the bus (0x$blank)"
    handoff="$(word_at "$handoff_addr" 0)"
    check "$([ "$handoff" = "00000000" ]; echo $?)" \
        "wolfBoot's handoff record was consumed and cleared (0x$handoff)"
    handed="$(word_at "$(elf_sym g_wt_boot_handoff)" 12)"
    check "$([ "$handed" = "00002000" ]; echo $?)" \
        "wolfBoot handed RDP level 0 under TZEN as PSA_ROT_PROVISIONING (0x$handed)"
}

# guest0 faulted at $1 on every launch (the Secure fault handler records the
# address), so a fault anywhere else fails the scenario; the monitor spent its
# restart budget and quarantined guest0, while guest1 ran untouched.
check_guest0_quarantined() {
    local want="$1" restarts quarantines st beat fault
    restarts="$(sym_word g_wt_restart_events)"
    quarantines="$(sym_word g_wt_quarantine_events)"
    fault="$(sym_word g_last_fault_address)"
    check "$([ "$((0x$fault))" -eq "$((want))" ]; echo $?)" \
        "guest0's last fault was its probe's access to $want (0x$fault)"
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

# The production chain booted from SECBOOTADD0 on this part: the evidence
# provisioning_ctrl.sh boot-lock requires before the permanent BOOT_LOCK,
# bound to the device UID, the ST-LINK and the flashed images.
record_hwrun() {
    local uid digest
    uid="$(l5_uid "$stlink_sn")" || fail "cannot read the device UID for the hardware-run record"
    digest="$(l5_framed_digest "$wolfboot_flash_addr" "$wolfboot_dir/wolfboot.bin" \
        "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin" \
        "$guest0_flash_addr" "$baremetal_dir/build/guest0.bin" \
        "$guest1_flash_addr" "$baremetal_dir/build/guest1.bin")" || fail "cannot digest the flashed images"
    mkdir -p "$(dirname "$hwrun_record")"
    echo "scenario=$scenario id=$uid image=$digest probe=$stlink_sn secbootadd0=0x180000 handoff=00002000 completed=$(date +%s)" \
        > "$hwrun_record"
    cp "$hwrun_record" "$evidence/hwrun.txt"
    log "  [record] $hwrun_record (device $uid, images ${digest:0:16})"
}

case "$scenario" in
positive)
    rm -f "$hwrun_record"
    run_chain "$baremetal_dir" ""
    check_guest 0 "$guest0_ram"
    check_guest 1 "$guest1_ram"
    check_launch_masks 00000003 00000000
    check "$([ "$(sym_word g_wt_restart_events)" = "00000000" ]; echo $?)" "no guest restarted"
    check_beating 1 "$guest1_ram"
    check_secure_side
    record_hwrun
    log "PASS: hardware/stm32l562/$scenario"
    ;;
gtzcneg)
    run_chain "$baremetal_dir" "WT_SAU_PROBE=1"
    peer="$(word_at "$probe_addr" 0)"
    check "$([ "$peer" != "deadbeef" ]; echo $?)" \
        "guest1 RAM never received guest0's sentinel (0x$peer)"
    latch="$(word_at "$guest0_ram" 28)"
    check "$([ -n "$latch" ] && [ "$latch" != "00000003" ]; echo $?)" \
        "guest0 never read its sentinel back (probe latch 0x$latch)"
    check "$(! grep -aq "LEAKED" "$evidence/console.log"; echo $?)" \
        "no leak reported on the console"
    # The curtain either faults the store (guest0 quarantined, latch 1) or
    # discards it (latch 2).
    if [ "$latch" = "00000002" ]; then
        log "  [gtzc] the store was discarded (RAZ/WI)"
        check_launch_masks 00000003 00000000
        check_guest 1 "$guest1_ram"
        check_beating 1 "$guest1_ram"
    else
        check_guest0_quarantined "$probe_addr"
    fi
    check_secure_side
    log "PASS: hardware/stm32l562/$scenario"
    ;;
periphneg)
    run_chain "$baremetal_dir" "WT_PERIPH_NEG_PROBE=1"
    check_guest0_quarantined "$periph_probe_addr"
    # The quarantine scrubs guest0's RAM, so its latch reads 0 or 1; 3 leaked.
    latch="$(word_at "$guest0_ram" 28)"
    check "$([ -n "$latch" ] && [ "$latch" != "00000003" ]; echo $?)" \
        "guest0's NS read of the SPM's RNG never returned (probe latch 0x$latch)"
    check "$(! grep -aq "LEAKED" "$evidence/console.log"; echo $?)" \
        "no leak reported on the console"
    check_secure_side
    log "PASS: hardware/stm32l562/$scenario"
    ;;
restart)
    run_chain "$baremetal_dir" "WT_GUEST_FAULT_PROBE=1"
    check_guest0_quarantined "$restart_probe_addr"
    check_secure_side
    log "PASS: hardware/stm32l562/$scenario"
    ;;
psa)
    run_chain "$psa_dir" ""
    check_psa_guest 0 "$guest0_ram"
    check_psa_guest 1 "$guest1_ram"
    check_launch_masks 00000003 00000000
    check "$([ "$(sym_word g_wt_restart_events)" = "00000000" ]; echo $?)" "no guest restarted"
    check_secure_side
    log "PASS: hardware/stm32l562/$scenario"
    ;;
wrpoff)
    run_chain "$baremetal_dir" ""
    check "$([ -z "$(elf_sym g_wt_launch_verified_mask)" ] ||
        [ "$(sym_word g_wt_launch_verified_mask)" = "00000000" ]; echo $?)" \
        "no guest was launch-verified"
    check "$([ "$(sym_word g_wt_launch_refused_mask)" = "00000003" ]; echo $?)" \
        "launch-refused guest mask 0x$(sym_word g_wt_launch_refused_mask) (want 0x00000003)"
    for g in "0:$guest0_ram" "1:$guest1_ram"; do
        sig="$(word_at "${g##*:}" 0)"
        check "$([ "$sig" = "00000000" ] || [ "$sig" = "ffffffff" ]; echo $?)" \
            "guest${g%%:*} never entered its domain (mailbox 0x$sig)"
    done
    check "$(! grep -aq "wolfTrust STM32L562 gues" "$evidence/console.log"; echo $?)" \
        "no guest wrote to the console"
    check_secure_side
    log "PASS: hardware/stm32l562/$scenario"
    ;;
wrpfence)
    run_chain "$baremetal_dir" ""
    check_guest 0 "$guest0_ram"
    check_guest 1 "$guest1_ram"
    check_launch_masks 00000003 00000000
    check_beating 1 "$guest1_ram"
    check_secure_side
    erased=0
    l5_erase_try "$stlink_sn" "$guest0_flash_addr" 0x800 > "$evidence/erase.log" 2>&1 || erased=$?
    check "$([ "$erased" -ne 2 ]; echo $?)" \
        "the backend can probe an erase inside the fence (OpenOCD)"
    # Only WRPERR ("device protected") proves the fence, not any erase error.
    check "$(grep -q '^L5ERASE refused' "$evidence/erase.log" &&
             grep -q 'device protected' "$evidence/erase.log"; echo $?)" \
        "the silicon refused a debugger erase of guest0's first page with WRPERR"
    l5_hard_reset "$stlink_sn" >/dev/null 2>&1 || true
    verify_at "$guest0_flash_addr" "$baremetal_dir/build/guest0.bin"
    release_fence
    log "PASS: hardware/stm32l562/$scenario"
    ;;
esac
