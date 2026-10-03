#!/usr/bin/env bash
# wolfTrust STM32H563 provisioning + lock control. One flag-driven entry point
# for the whole silicon lifecycle: set the OEM-iRoT option-byte perimeter, flash
# the wolfTrust chain, advance/regress product state for the reversible lock, and
# restore. It supersedes wolfBoot's set-stm32-tz-option-bytes.sh (which computes
# the wrong SECWM for wolfTrust's secure-alias layout and never sets BOOT_UBE)
# with the exact values captured from a known-good wolfTrust board, and folds in
# ST's tested DA provisioning/regression command order (ROT_Provisioning/DA).
#
# BRICK SAFETY (non-negotiable):
#   * board-writing commands refuse to run without WT_LOCK_CONFIRM=1
#   * the permanent Locked product state (0x5C) is refused outright
#   * regression returns to Open (fully debuggable, reflashable) — never a brick
#   * DA uses the certificate OBK that matches TZEN-enabled (ST AN6008 pairing)
#   * restore reproduces the captured-verified perimeter, so recovery is proven
#     on the Open board BEFORE any state advance is ever attempted
#
# Commands:
#   status                 read product state + option bytes (read-only)
#   set-perimeter          set the wolfTrust OEM-iRoT option bytes (restore pt 1)
#   flash                  flash wolfBoot + wolfTrust + guests (restore pt 2)
#   verify                 reset + capture UART, assert the wolfTrust chain boots
#   restore                set-perimeter + flash + verify (full recovery)
#   provision-da           -sdp the DA OBK (only valid in Provisioning state)
#   discover               prove the DA credential authenticates (non-destructive)
#   advance <hexstate>     set PRODUCT_STATE (GATED; Locked refused)
#   regress                DA-authenticate + full regression back to Open (GATED)
set -euo pipefail

CP="${STM32_CP:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin}"
CLI="${STM32_CLI:-$CP/STM32_Programmer_CLI}"
SERIAL="${H5_SERIAL:-/dev/ttyACM0}"
repo="$(cd "$(dirname "$0")/../.." && pwd)"

# ST DA credential from the pinned NUCLEO-H563ZI ROT_Provisioning/DA folder.
# wolfTrust runs with TrustZone ENABLED, so DA is CERTIFICATE-based: AN6008
# requires the certificate method when TZEN=0xB4, and a password OBK provisioned
# here cannot authenticate and blocks regression (verified on board
# 2026-08-19). Use DA_Config.obk with the leaf key and certificate chain, not
# DA_ConfigWithPassword.obk. Override once a wolfTrust-owned certificate chain
# replaces ST's sample.
DA_DIR="${WT_DA_DIR:-$HOME/st-rot-h5/Projects/NUCLEO-H563ZI/ROT_Provisioning/DA}"
DA_OBK="${WT_DA_OBK:-$DA_DIR/Binary/DA_Config.obk}"
DA_PWD="${WT_DA_PWD:-$DA_DIR/Binary/password.bin}"
DA_KEY="${WT_DA_KEY:-$DA_DIR/Keys/key_3_leaf.pem}"
DA_CERT="${WT_DA_CERT:-$DA_DIR/Certificates/cert_leaf_chain.b64}"
# ST ROT_Provisioning/DA connect strings (regression is sensitive to these).
DA_CONN="-c port=SWD speed=fast ap=1 mode=Hotplug"
DA_CONN_RST="-c port=SWD speed=fast ap=1 mode=Hotplug -hardRst"

# wolfTrust OEM-iRoT perimeter — the EXACT option bytes read from a known-good
# wolfTrust STM32H563 board. BOOT_UBE
# selects the OEM-iRoT boot path (so SECBOOTADD is unused); SECWM1 covers the
# secure wolfBoot+wolfTrust region, SECWM2 the secure bank-2 window.
# SECWM1_END must span the WHOLE boot partition (through 0x0809FFFF): with the
# earlier 0x3F, flash writes past 0x08080000 were silently dropped and wolfBoot
# integrity-rejected any secure image over 128K (found by MP5 confboot).
WT_OB=(TZEN=0xB4 BOOT_UBE=0xB4 SWAP_BANK=0x0
       SECWM1_STRT=0x0 SECWM1_END=0x4F SECWM2_STRT=0x0 SECWM2_END=0x7F)

# Guest-flash write protection (WRPSGn1, 0 = protected, 4 sectors per bit).
# 0x000FFFFF clears bits 20-31 -> bank-1 sectors 0x50-0x7F protected, the guest
# region; 0xFFFFFFFF leaves all sectors writable (factory default).
WRP_GUEST=0x000FFFFF; WRP_OPEN=0xFFFFFFFF

# Product-state codes (RM0481).
PS_OPEN=0xED; PS_PROVISIONING=0x17; PS_TZCLOSED=0xC6; PS_CLOSED=0x72; PS_LOCKED=0x5C

# Flash layout (matches run_h5_hardware.sh).
WOLFBOOT=0x0C000000; WOLFTRUST=0x0C060000; GUEST0=0x080A0000; GUEST1=0x080E0000
wb="$repo/wolfBoot/wolfboot.bin"
wt="$repo/build/wolftrust_v1_signed.bin"
g0="$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
g1="$repo/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"

strip() { sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g'; }
pass()  { printf '  [check] PASS  %s\n' "$1"; }
fail()  { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }
confirm() { [ "${WT_LOCK_CONFIRM:-0}" = "1" ] || {
    echo "REFUSED: '$cmd' writes to the board. Re-run with WT_LOCK_CONFIRM=1." >&2; exit 2; }; }
product_state() {
  "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
    | grep -iE "PRODUCT_STATE" | grep -oE "0x[0-9A-Fa-f]+" | head -1
}

cmd="${1:-status}"
case "$cmd" in
  status)
    "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
      | grep -iE "PRODUCT_STATE|TZEN|BOOT_UBE|SECWM|SECBOOT" | head -20
    ;;

  set-perimeter)
    confirm
    echo "Setting wolfTrust OEM-iRoT perimeter: ${WT_OB[*]}"
    # TZEN first (an off->on flip mass-erases); then the rest. Setting the same
    # values on an already-provisioned board is a safe no-op.
    "$CLI" -c port=SWD mode=UR -ob TZEN=0xB4 2>&1 | strip | tail -3
    "$CLI" -c port=SWD mode=UR -ob "${WT_OB[@]}" 2>&1 | strip | tail -4
    ;;

  set-wrp)
    # Write-protect the guest flash region so a privileged Non-secure guest
    # cannot reprogram a peer guest's image (WT-SYS-0002 hardware root fix).
    # WRPSGn1 groups four 8 KiB sectors per bit and 0 means protected, so
    # 0x000FFFFF protects bank-1 sectors 0x50-0x7F (0x080A0000-0x080FFFFF),
    # the whole guest region, and leaves the secure/FWU region writable. WRP is
    # mutable only in Open; run this AFTER flashing the guests (a protected
    # sector rejects the image write) and before advancing product state.
    confirm
    [ "$(product_state)" = "$PS_OPEN" ] || \
      fail "set-wrp" "WRP is settable only in Open ($PS_OPEN); state=$(product_state)"
    echo "Write-protecting guest flash (bank1 sectors 0x50-0x7F): WRPSGn1=$WRP_GUEST"
    "$CLI" -c port=SWD mode=UR -ob WRPSGn1="$WRP_GUEST" 2>&1 | strip | tail -4
    "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip | grep -iE "WRPSGn1"
    ;;

  clear-wrp)
    # Remove guest-flash write protection so the images can be reflashed.
    confirm
    echo "Clearing guest-flash write protection: WRPSGn1=$WRP_OPEN"
    "$CLI" -c port=SWD mode=UR -ob WRPSGn1="$WRP_OPEN" 2>&1 | strip | tail -4
    ;;

  flash)
    confirm
    for f in "$wb" "$wt" "$g0" "$g1"; do
      [ -s "$f" ] || fail "flash" "missing image: $f (build first)"; done
    "$CLI" -c port=SWD mode=UR \
      -d "$wb" "$WOLFBOOT" -d "$wt" "$WOLFTRUST" \
      -d "$g0" "$GUEST0" -d "$g1" "$GUEST1" --verify -hardRst 2>&1 | strip \
      | grep -iE "verified successfully|error|download" | tail -4
    ;;

  verify)
    stty -F "$SERIAL" 115200 raw -echo 2>/dev/null || true
    ( timeout 8 cat "$SERIAL" > /tmp/wt-verify.log 2>/dev/null & )
    "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
    sleep 7
    if strip < /tmp/wt-verify.log | grep -aqE "guest0_psa|heartbeat|TEE client"; then
      pass "wolfTrust chain boots on silicon"
    else
      fail "verify" "no wolfTrust boot markers on $SERIAL"
    fi
    ;;

  restore)
    confirm
    WT_LOCK_CONFIRM=1 "$0" set-perimeter
    WT_LOCK_CONFIRM=1 "$0" clear-wrp
    WT_LOCK_CONFIRM=1 "$0" flash
    WT_LOCK_CONFIRM=1 "$0" set-wrp
    "$0" verify
    echo "PASS: wolfTrust restored and booting"
    ;;

  provision-da)
    confirm
    [ -s "$DA_OBK" ] || fail "provision-da" "DA OBK not found: $DA_OBK"
    [ "$(product_state)" = "$PS_PROVISIONING" ] || \
      fail "provision-da" "must be in Provisioning ($PS_PROVISIONING); state=$(product_state)"
    echo "Provisioning DA OBK (ST obk_provisioning.sh order): $DA_OBK"
    "$CLI" $DA_CONN_RST >/dev/null 2>&1 || true
    "$CLI" $DA_CONN -sdp "$DA_OBK" 2>&1 | strip | tail -5
    "$CLI" $DA_CONN_RST >/dev/null 2>&1 || true
    ;;

  discover)
    echo "DA discovery (non-destructive) with $DA_PWD:"
    "$CLI" $DA_CONN pwd="$DA_PWD" debugauth=2 2>&1 | strip \
      | grep -iE "permission|regression|discovery|not supported|error|auth" | head
    ;;

  advance)
    confirm
    state="${2:-}"
    case "$state" in
      "$PS_LOCKED"|0x5c) echo "REFUSED: Locked (0x5C) is permanent — never on a dev board." >&2; exit 2 ;;
      "$PS_PROVISIONING"|"$PS_TZCLOSED"|"$PS_CLOSED"|0x17|0xc6|0x72) ;;
      *) echo "REFUSED: advance needs a reversible state (0x17/0xC6/0x72), got '${state:-none}'." >&2; exit 2 ;;
    esac
    echo "ADVANCING product state $(product_state) -> $state (regress is the only way back)"
    "$CLI" -c port=SWD mode=HotPlug -ob PRODUCT_STATE="$state" 2>&1 | strip | tail -4
    echo "now: $(product_state)"
    ;;

  regress)
    confirm
    # Certificate DA Full Regression -> Open. VERIFIED on board 2026-08-19.
    # wolfTrust runs TZEN enabled, so the credential is the certificate (per=a).
    # Do NOT send debugauth=3 first: it locks the debug session and then blocks
    # AP access for the handshake. Reset to clear any stale lock, then
    # authenticate on a bare "-c port=SWD" (default NORMAL/under-reset so the RSS
    # answers) with the key+cert; CubeProgrammer selects the certificate because
    # TZEN is enabled and the RSS mass-erases the device back to Open.
    echo "DA certificate Full Regression -> Open (mass-erase):"
    "$CLI" -c port=SWD mode=HotPlug -rst 2>&1 | strip | tail -1 || true
    "$CLI" -c port=SWD per=a key="$DA_KEY" cert="$DA_CERT" pwd="$DA_PWD" \
      debugauth=1 </dev/null 2>&1 | strip | tail -14
    echo "state after regression: $(product_state)"
    ;;

  *) echo "usage: $0 status|set-perimeter|flash|verify|restore|provision-da|discover|advance <hexstate>|regress" >&2; exit 2 ;;
esac
