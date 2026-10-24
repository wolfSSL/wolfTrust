#!/usr/bin/env bash
# MIMXRT700-EVK hardware runner (sibling of run_h5_hardware.sh and
# run_m33mu_scenario.sh; one CLI shape, assertions via lib/expect.sh once it
# lands on main). Runs on the host that owns the probe (pi5).
#
#   run_rt700_hardware.sh <scenario>
#
# Scenarios:
#   romsmoke  the BootROM boots our own XIP image from XSPI0: build
#             tests/firmware/mimxrt700-smoke, wrap it (EVK FCB + plain MBI at
#             flash+0x4000), flash with pyOCD, hard-reset through the pi4 line,
#             then assert the SRAM marker and a moving counter over SWD.
#   positive  the full chain: wolfBoot (TrustZone loader) authenticates the
#             wolfTrust Secure image, which launches both Non-secure guests.
#             Builds wolfTrust + the guests, pins the guest measurements,
#             wolfBoot-signs the Secure image, flashes the chain at its XSPI0
#             offsets, resets from a fresh vault, verifies every image by
#             readback, and asserts both guest mailboxes over SWD.
#   ahbscneg  positive plus the guest isolation negative: guest0 stores into
#             guest1's RAM, which the per-dispatch SAU window keeps Secure; the
#             store must be blocked, guest1's RAM must not hold the sentinel,
#             and guest1 must keep running.
#   wrpfence  a WT_GUEST_FLASH_WRP=1 wolfTrust behind a wolfBoot that arms the
#             XSPI guest fence: the fence reads back sealed over SWD and both
#             guests launch.
#   wrpoff    the same wolfTrust behind an unfenced wolfBoot: wolfTrust must
#             refuse both guests (launch refused mask 0x3, no mailbox written).
#   wrpneg    wrpfence with wolfBoot's flash-protect selftest: the silicon must
#             refuse an erase inside the guest fence and leave the block as is.
#
# The wolfBoot first stage is RT700_WOLFBOOT_REF plus the carried patches
# (lib/rt700_wolfboot.sh), cached under ~/.cache/wolftrust, unless
# RT700_WOLFBOOT_DIR names a prebuilt tree.
set -euo pipefail

scenario="${1:-}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="${RT700_WORK:-$repo/build/rt700}"
target="${RT700_TARGET:-mimxrt798sgfob}"
fcb="${RT700_FCB:-$HOME/rt700-boot/fcb.bin}"
wolfboot_dir="${RT700_WOLFBOOT_DIR:-}"
spsdk_venv="${RT700_SPSDK_VENV:-$HOME/spsdk-venv}"
xspi0_base=0x28000000
mbi_offset=0x4000
secure_flash_addr=0x28040000
guest0_flash_addr=0x28080000
guest1_flash_addr=0x28100000
hsm_nvm_addr=0x281E0000
hsm_nvm_size=0x2000
guest_build="$repo/tests/firmware/mimxrt700-baremetal/build"

# shellcheck source=lib/rt700_fence.sh disable=SC1091
. "$here/lib/rt700_fence.sh"
# shellcheck source=lib/rt700_wolfboot.sh disable=SC1091
. "$here/lib/rt700_wolfboot.sh"
case "$scenario" in
    wrpfence|wrpneg) guest_fence=1; export WT_GUEST_FLASH_WRP=1 ;;
    wrpoff)   guest_fence=0; export WT_GUEST_FLASH_WRP=1 ;;
    *)        guest_fence="${WT_XSPI_GUEST_FENCE:-${WT_GUEST_FLASH_WRP:-0}}" ;;
esac

log() { printf '%s\n' "$*"; }
stage() { printf '  ... %s\n' "$*"; }
fail() { log "FAIL: $*"; exit 1; }
check() {
    if [ "$1" -eq 0 ]; then log "  [check] PASS  $2"; else log "  [check] FAIL  $2"; fail "$2"; fi
}

# SPSDK (nxpimage) and pyOCD live in a virtualenv; put it on PATH when the bare
# tools are not already resolvable.
ensure_spsdk() {
    if ! command -v pyocd >/dev/null 2>&1 || ! command -v nxpimage >/dev/null 2>&1; then
        [ -x "$spsdk_venv/bin/pyocd" ] || fail "pyocd/nxpimage not found (set RT700_SPSDK_VENV)"
        PATH="$spsdk_venv/bin:$PATH"
        export PATH
    fi
}

# Observation uses the generic Cortex-M attach: the device-pack target resets
# the chip on connect, so a read would land in a fresh boot, not the one under
# test.
dap() {
    timeout 60 pyocd cmd -t cortex_m "$@" 2>&1 |
        grep -viE "rom table|APB-AP|coresight|cidr"
}

wrap_xip() {
    local app="$1" out="$2" exec_addr="$3"
    [ -s "$fcb" ] || fail "FCB binary missing at $fcb (RT700_FCB)"
    cat > "$work/mbi.yaml" <<YAML
family: mimxrt798s
revision: latest
outputImageExecutionTarget: xip
outputImageAuthenticationType: plain
masterBootOutputFile: $work/mbi.bin
inputImageFile: $app
outputImageExecutionAddress: $exec_addr
imageVersion: 0
YAML
    nxpimage mbi export -c "$work/mbi.yaml" >/dev/null
    cat > "$work/bootimg.yaml" <<YAML
family: mimxrt798s
revision: latest
memory_type: xspi_nor
output: $out
output_format: bin
init_offset: 0
fcb: $fcb
mbi: $work/mbi.bin
YAML
    nxpimage bootable-image export -c "$work/bootimg.yaml" >/dev/null
}

# Read an image back through XIP once the chain has booted and compare it.
verify_at() {
    local addr="$1" image="$2" size
    size="$(wc -c < "$image" | tr -d ' ')"
    timeout 120 pyocd cmd -t cortex_m -c "savemem $addr $size $work/readback.bin" \
        >/dev/null 2>&1 || fail "readback of $addr failed"
    cmp -s "$work/readback.bin" "$image" || \
        fail "flash verify mismatch at $addr ($(basename "$image"))"
    log "  [flash] verified $(basename "$image") @ $addr"
}

# Park the core before wolfTrust owns it: pyOCD's flash algorithm runs in RAM
# and faults under wolfTrust's Secure MPU whitelist. A running wolfTrust sets
# AIRCR.SYSRESETREQS, so only the probe's hardware reset is honoured; the halt
# can still land after boot code starts, so the MPU is disabled explicitly.
park_core() {
    timeout 60 pyocd cmd -t "$target" -O resume_on_disconnect=false \
        -O reset_type=hw -c "reset halt" -c "write32 0xE000ED94 0" \
        >/dev/null 2>&1 || fail "could not park the core"
}

# A failed or partial flash must stop the run: a stale image either boots old
# code or fails its pinned measurement and looks like a port bug.
flash_at() {
    local addr="$1" image="$2" out
    [ -s "$image" ] || fail "flash image missing: $image"
    park_core
    if ! out="$(timeout 300 pyocd flash -t "$target" -O resume_on_disconnect=false \
            --no-reset -a "$addr" -e sector "$image" 2>&1)"; then
        printf '%s\n' "$out" | grep -vE "AP#3 IDR" | tail -6
        fail "flash of $(basename "$image") at $addr failed"
    fi
}

# Erase a sector range with the core parked; the board keeps NVM state across
# runs where the emulator starts fresh (mirrors the H5 runner's vault erase).
erase_range() {
    local range="$1"
    park_core
    timeout 120 pyocd erase -t "$target" -O resume_on_disconnect=false \
        -s "$range" >/dev/null 2>&1 || fail "erase of $range failed"
}

# SRAM survives a warm reset, so the last run's mailboxes, sentinel, and launch
# masks would otherwise read back as this run's result.
clear_mailboxes() {
    local verified refused
    verified="$(elf_sym g_wt_launch_verified_mask)"
    refused="$(elf_sym g_wt_launch_refused_mask)"
    [ -n "$verified" ] && [ -n "$refused" ] || fail "launch masks not found in wolftrust.elf"
    park_core
    timeout 60 pyocd cmd -t "$target" -O resume_on_disconnect=false \
        -c "write32 0x20100000 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 0x20140000 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 0x20170000 0" \
        -c "write32 0x20180080 0 0 0 0 0 0 0 0 0 0 0 0" \
        -c "write32 $verified 0" -c "write32 $refused 0" >/dev/null 2>&1 || \
        fail "could not clear the guest mailboxes"
}

# Parking leaves the reset vector catch armed; a resuming reset clears it so
# the warm reset below boots the chain instead of halting in the BootROM.
reset_board() {
    timeout 60 pyocd reset -t "$target" -m hw >/dev/null 2>&1 || \
        fail "could not release the core"
    "$here/lib/rt700_reset.sh" reset
}


# The first stage to flash: a prebuilt RT700_WOLFBOOT_DIR as-is (a fence run
# must still match the pin), otherwise the pinned build for this fence setting.
ensure_wolfboot() {
    local fence_cflags=""

    if [ "$guest_fence" = "1" ]; then
        fence_cflags="$(rt700_fence_cflags)" || fail "guest fence bounds"
    fi
    if [ "$scenario" = "wrpneg" ]; then
        fence_cflags="$fence_cflags -DXSPI_FLASH_PROTECT_SELFTEST"
    fi
    if [ -n "$wolfboot_dir" ]; then
        if [ -n "${WT_GUEST_FLASH_WRP:-}" ]; then
            rt700_wolfboot_current "$wolfboot_dir" \
                "$(rt700_wolfboot_stamp "CFLAGS_EXTRA=$fence_cflags")" || \
                fail "RT700_WOLFBOOT_DIR=$wolfboot_dir was not built by lib/rt700_wolfboot.sh with this guest fence"
        fi
    else
        wolfboot_dir="$HOME/.cache/wolftrust/wolfboot-rt700"
        [ "$guest_fence" = "1" ] && wolfboot_dir="$wolfboot_dir-fence"
        [ "$scenario" = "wrpneg" ] && wolfboot_dir="$wolfboot_dir-selftest"
        mkdir -p "$(dirname "$wolfboot_dir")"
        stage "wolfBoot $RT700_WOLFBOOT_REF (imx-rt700-tz${fence_cflags:+, guest fence})"
        rt700_wolfboot_build "$wolfboot_dir" "CFLAGS_EXTRA=$fence_cflags" \
            > "$work/wolfboot-build.log" 2>&1 || {
            tail -20 "$work/wolfboot-build.log"
            fail "wolfBoot build failed"
        }
    fi
    [ -s "$wolfboot_dir/wolfboot.bin" ] || \
        fail "wolfBoot TZ image missing at $wolfboot_dir/wolfboot.bin (RT700_WOLFBOOT_DIR)"
}

# Build wolfTrust and both guests, pin the guest measurements, sign, flash the
# whole chain, boot it from a fresh vault, and verify every image by readback.
run_chain() {
    local guest_flags="$1"

    ensure_spsdk
    mkdir -p "$work"
    ensure_wolfboot

    # RT700 wolfBoot uses a 1024-byte image header, so wolfTrust links at the
    # boot base + 0x400 and is signed with a matching header. Exported so the
    # secure image and the guest CMSE import library agree (mirrors the H5 runner).
    export WT_SECURE_IMAGE_HEADER_SIZE=0x400
    export WT_ATTEST_COSE=0
    rm -rf "$repo/build"
    mkdir -p "$work"

    stage "build wolfTrust secure image + CMSE import library"
    make -s -C "$repo" TARGET=mimxrt700 secure-image TOOLPREFIX=arm-none-eabi-

    stage "build the Non-secure guests ${guest_flags:-(no probes)}"
    make -s -C "$repo/tests/firmware/mimxrt700-baremetal" clean
    # shellcheck disable=SC2086
    make -s -C "$repo/tests/firmware/mimxrt700-baremetal" TARGET=mimxrt700 $guest_flags

    stage "pin both guest measurements, then wolfBoot-sign wolfTrust"
    python3 "$repo/tools/measure/patch_guest_digests.py" "$repo/build/wolftrust.bin" \
        "0:1:$guest_build/guest0.bin" "1:1:$guest_build/guest1.bin"
    IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x1000 \
        "$wolfboot_dir/tools/keytools/sign" --ecc256 \
        "$repo/build/wolftrust.bin" \
        "$wolfboot_dir/wolfboot_signing_private_key.der" 1

    stage "wrap wolfBoot (FCB + MBI) and flash the chain"
    wrap_xip "$wolfboot_dir/wolfboot.bin" "$work/flash_wolfboot.bin" \
        "$(printf '0x%08x' $((xspi0_base + mbi_offset)))"
    flash_at "$xspi0_base" "$work/flash_wolfboot.bin"
    flash_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
    flash_at "$guest0_flash_addr" "$guest_build/guest0.bin"
    flash_at "$guest1_flash_addr" "$guest_build/guest1.bin"
    stage "erase the wolfHSM NVM store so the run starts from a fresh vault"
    erase_range "$(printf '0x%08x-0x%08x' "$hsm_nvm_addr" $((hsm_nvm_addr + hsm_nvm_size)))"
    clear_mailboxes

    reset_board
    sleep 2
    verify_at "$xspi0_base" "$work/flash_wolfboot.bin"
    verify_at "$secure_flash_addr" "$repo/build/wolftrust_v1_signed.bin"
    verify_at "$guest0_flash_addr" "$guest_build/guest0.bin"
    verify_at "$guest1_flash_addr" "$guest_build/guest1.bin"
}

# One 32-bit word at base+offset over SWD, as eight lowercase hex digits.
mailbox_word() {
    dap -c "read32 $(printf '0x%x' $(($1 + $2)))" | grep -oiE '[0-9a-f]{8}' | tail -1 |
        tr 'A-F' 'a-f'
}

# Each guest records its progress at the base of its own RAM window.
check_guest() {
    local id="$1" base="$2" sig fw st uart
    sig="$(mailbox_word "$base" 0)"
    fw="$(mailbox_word "$base" 8)"
    st="$(mailbox_word "$base" 20)"
    uart="$(mailbox_word "$base" 24)"
    check "$([ "$sig" = "47543030" ]; echo $?)" "guest$id launched: signature 0x47543030 ($sig)"
    check "$([ "$fw" = "00000100" ]; echo $?)" "guest$id psa_framework_version 0x0100 ($fw)"
    check "$([ "$st" = "600d600d" ]; echo $?)" \
        "guest$id done: FF-M connect verified, status 0x600D600D ($st)"
    check "$([ -n "$uart" ] && [ "$uart" != "00000000" ]; echo $?)" \
        "guest$id reaches its Non-secure console (LPUART0 VERID 0x$uart)"
}

# A wolfTrust global's address, from the image this run built and flashed.
elf_sym() {
    arm-none-eabi-nm "$repo/build/wolftrust.elf" |
        awk -v s="$1" '$3 == s && !f { print "0x" $1; f = 1 }'
}

# All eight XSPI0 FRADs as "start end acp word3" lines, in one debugger
# session; only words 0-3 of each 0x20 stride are readable.
frad_dump() {
    local -a cmds=()
    local n
    for n in 0 1 2 3 4 5 6 7; do
        cmds+=(-c "read32 $(printf '0x%x' $((0x50184800 + n * 0x20))) 16")
    done
    dap "${cmds[@]}" | awk '/^50184[89]/ { print $2, $3, $4, $5 }'
}

# wolfBoot sealed the SFP configuration until the next reset.
sfp_sealed() {
    local mgc mdad
    mgc=$((0x$(mailbox_word 0x50184920 0)))
    mdad=$((0x$(mailbox_word 0x50184900 0)))
    [ $((mgc & 0xA8000000)) -eq $((0xA8000000)) ] && [ $((mgc & 0xC00)) -ne 0 ] &&
        [ $((mdad & 0xA0000000)) -eq $((0xA0000000)) ]
}

# One valid, hard-reset-locked (EAL clear), write-denying FRAD spans the guest
# windows; the Secure-side predicate is the authority, this is the evidence.
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

check_launch_masks() {
    local want_verified="$1" want_refused="$2" verified refused
    verified="$(mailbox_word "$(elf_sym g_wt_launch_verified_mask)" 0)"
    refused="$(mailbox_word "$(elf_sym g_wt_launch_refused_mask)" 0)"
    check "$([ "$verified" = "$want_verified" ]; echo $?)" \
        "launch-verified guest mask 0x$verified (want 0x$want_verified)"
    check "$([ "$refused" = "$want_refused" ]; echo $?)" \
        "launch-refused guest mask 0x$refused (want 0x$want_refused)"
}

case "$scenario" in
romsmoke)
    mkdir -p "$work"
    ensure_spsdk
    make -s -C "$repo/tests/firmware/mimxrt700-smoke" BUILD="$work/smoke" all
    wrap_xip "$work/smoke/smoke.bin" "$work/flash_smoke.bin" \
        "$(printf '0x%08x' $((xspi0_base + mbi_offset)))"
    flash_at "$xspi0_base" "$work/flash_smoke.bin"
    reset_board
    verify_at "$xspi0_base" "$work/flash_smoke.bin"
    s1="$(dap -c 'read32 0x20180000 8' | tail -1)"
    sleep 1
    s2="$(dap -c 'read32 0x20180000 8' | tail -1)"
    m1="$(printf '%s' "$s1" | awk '{print $2}')"
    c1="$(printf '%s' "$s1" | awk '{print $3}')"
    c2="$(printf '%s' "$s2" | awk '{print $3}')"
    check "$([ "$m1" = "52543030" ]; echo $?)" "ROM booted the XIP image: marker RT00 at 0x20180000 ($m1)"
    check "$([ "$c1" != "$c2" ]; echo $?)" "smoke loop alive: counter $c1 -> $c2"
    pc="$(dap -c halt -c 'reg pc' -c go | sed -n 's/^pc = //p')"
    check "$(case "$pc" in 0x2800[4-9]*|0x2800[a-f]*) echo 0;; *) echo 1;; esac)" "PC inside the XIP image ($pc)"
    log "PASS: hardware/romsmoke"
    ;;
positive|ahbscneg)
    guest_flags=""
    [ "$scenario" = "ahbscneg" ] && guest_flags="WT_AHBSC_PROBE=1"
    run_chain "$guest_flags"

    for g in 0:0x20100000 1:0x20140000; do
        check_guest "${g%%:*}" "${g##*:}"
    done

    if [ "$scenario" = "ahbscneg" ]; then
        # guest0 stores a sentinel into guest1's RAM, which the per-dispatch SAU
        # window keeps Secure while guest0 runs.
        probe="$(mailbox_word 0x20100000 28)"
        seen="$(mailbox_word 0x20100000 32)"
        check "$(case "$probe" in 00000001|00000002) echo 0;; *) echo 1;; esac)" \
            "guest0 store into guest1 RAM blocked (latch $probe, read 0x$seen)"
        peer="$(mailbox_word 0x20170000 0)"
        check "$([ "$peer" != "deadbeef" ]; echo $?)" \
            "guest1 RAM never received guest0's sentinel (0x$peer)"
        # Containment means the peer keeps running, not only that the mailboxes
        # were written before the probes: an all-guests-faulted monitor also
        # idles in thread mode.
        beat1="$(mailbox_word 0x20140000 36)"
        sleep 1
        beat2="$(mailbox_word 0x20140000 36)"
        check "$([ -n "$beat1" ] && [ "$beat1" != "$beat2" ]; echo $?)" \
            "guest1 still running after guest0's faults (beat 0x$beat1 -> 0x$beat2)"
        g0beat="$(mailbox_word 0x20100000 36)"
        check "$([ "$g0beat" = "00000000" ]; echo $?)" \
            "guest0 never got past its probe store (beat 0x$g0beat)"
        ipsr="$(dap -c halt -c 'reg xpsr' -c go | sed -n 's/^xpsr = 0x\([0-9a-fA-F]*\).*/\1/p')"
        ipsr=$((0x${ipsr:-3} & 0x1ff))
        check "$([ "$ipsr" -lt 2 ] || [ "$ipsr" -gt 7 ]; echo $?)" \
            "system still scheduling after the probes (IPSR $ipsr, not a fault handler)"
        valid="$(mailbox_word 0x5017CF00 0)"
        log "  [fabric] AHBSC0 violation latches valid 0x$valid"
        for port in $(seq 0 28); do
            [ $(((0x$valid >> port) & 1)) -eq 1 ] || continue
            log "  [fabric]   port $port addr 0x$(mailbox_word 0x5017CE00 $((4 * port)))" \
                "info 0x$(mailbox_word 0x5017CE80 $((4 * port)))"
        done
    fi
    log "PASS: hardware/$scenario"
    ;;
wrpfence)
    run_chain ""
    rt700_fence_bounds || fail "guest fence bounds"
    check "$(sfp_sealed; echo $?)" "XSPI SFP configuration valid and sealed until reset"
    check "$(fence_armed; echo $?)" \
        "a locked, write-denying FRAD spans the guest windows ($RT700_GUEST_FENCE_START-$RT700_GUEST_FENCE_END)"
    check_launch_masks 00000003 00000000
    for g in 0:0x20100000 1:0x20140000; do
        check_guest "${g%%:*}" "${g##*:}"
    done
    log "PASS: hardware/$scenario"
    ;;
wrpoff)
    run_chain ""
    rt700_fence_bounds || fail "guest fence bounds"
    check "$(sfp_sealed; echo $?)" "XSPI SFP configuration valid and sealed until reset"
    check "$(fence_armed && echo 1 || echo 0)" \
        "no FRAD fences the guest windows (unfenced wolfBoot)"
    check_launch_masks 00000000 00000003
    for g in 0:0x20100000 1:0x20140000; do
        sig="$(mailbox_word "${g##*:}" 0)"
        check "$([ "$sig" = "00000000" ]; echo $?)" \
            "guest${g%%:*} never entered its domain (mailbox 0x$sig)"
    done
    log "PASS: hardware/$scenario"
    ;;
wrpneg)
    run_chain ""
    rt700_fence_bounds || fail "guest fence bounds"
    check "$(fence_armed; echo $?)" \
        "a locked, write-denying FRAD spans the guest windows ($RT700_GUEST_FENCE_START-$RT700_GUEST_FENCE_END)"
    # wolfBoot's selftest verdicts (hal/imx_rt7xx.c PST mailbox).
    pst() { mailbox_word 0x20180080 $((4 * $1)); }
    check "$([ "$(pst 0)" = "50510002" ]; echo $?)" "wolfBoot's flash-protect selftest ran to completion"
    # Only the refusal: the block's contents depend on what the board held.
    check "$([ "$(pst 3)" = "$(pst 4)" ]; echo $?)" \
        "the boot-root erase at 0x$(pst 1) returned the FRAD check error ($(pst 3))"
    check "$([ "$(pst 9)" = "$(pst 4)" ]; echo $?)" \
        "the erase at 0x$(pst 7) in the guest fence returned the FRAD check error ($(pst 9))"
    check "$([ "$(pst 11)" = "505150aa" ]; echo $?)" \
        "the guest-fence block is unchanged (0x$(pst 8) -> 0x$(pst 10))"
    check_launch_masks 00000003 00000000
    for g in 0:0x20100000 1:0x20140000; do
        check_guest "${g%%:*}" "${g##*:}"
    done
    log "PASS: hardware/$scenario"
    ;;
*)
    log "usage: $0 romsmoke|positive|ahbscneg|wrpfence|wrpoff|wrpneg"
    exit 2
    ;;
esac
