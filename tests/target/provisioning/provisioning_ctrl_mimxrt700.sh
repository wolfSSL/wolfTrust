# shellcheck shell=bash
# provisioning_ctrl_mimxrt700.sh
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

# MIMXRT700 (MIMXRT700-EVK) port for provisioning_ctrl.sh: the OTP life cycle,
# rehearsed in the OTP shadow registers that every reset reloads, burned over
# the BootROM's ISP. Sourced, never run. See docs/MIMXRT700-Guide.md.
# shellcheck disable=SC2034,SC2154  # PORT_* are read, and $cur/$PENDING set, by the main script

# A port file only works inside provisioning_ctrl.sh, which holds the gates.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "REFUSED: run TARGET=mimxrt700 tests/target/provisioning/provisioning_ctrl.sh, not this port file." >&2
  exit 2
fi

PORT_NAME="MIMXRT700"
target_dir="$here/.."
pyocd_target="${RT700_TARGET:-mimxrt798sgfob}"
spsdk_venv="${RT700_SPSDK_VENV:-$HOME/spsdk-venv}"
# Set here, not in a helper: the controller runs many port calls in subshells.
[ ! -d "$spsdk_venv/bin" ] || PATH="$spsdk_venv/bin:$PATH"
# The Python that runs SPSDK: the venv's, else the one behind pyocd on PATH.
if [ -x "$spsdk_venv/bin/python" ]; then
  spsdk_py="$spsdk_venv/bin/python"
else
  spsdk_py="$(sed -n '1s/^#! *\([^ ]*python[^ ]*\).*/\1/p' "$(command -v pyocd 2>/dev/null || echo /dev/null)" 2>/dev/null)"
  spsdk_py="${spsdk_py:-python3}"
fi
guest_mask="${RT700_GUEST_MASK:-0x3}"
case "$guest_mask" in
  0x1|0x2|0x3|1|2|3) ;;
  *) refuse "RT700_GUEST_MASK must be 0x1, 0x2, or 0x3 (both guests), not '$guest_mask'." ;;
esac
elf="$repo/build/wolftrust.elf"

# OTP shadow words (fuse index * 4 from 0x50018000, both silicon revisions).
LC_STATE=0x5001823C
LC_STATE_RED=0x50018094
LOCK_CFG3=0x5001800C
DAUTHSTATUS=0xE000EFB8
XSPI_MGC=0x50184920
XSPI_TG0MDAD=0x50184900
LC_DEVELOP=0x03
# OTP fuse word indexes blhost addresses (not shadow addresses).
FUSE_LC_RED=0x25
FUSE_LC=0x8F

# shellcheck source=../lib/rt700_fence.sh disable=SC1091
. "$target_dir/lib/rt700_fence.sh"

port_ladder() {
  cat <<'EOF'
0x03 develop          no  no  permanent -
0x07 develop2         yes yes permanent 0x03
0x0F in-field         yes yes permanent 0x07
0xCF in-field-locked  yes yes permanent 0x0F
0x1F in-field-return  yes yes permanent 0x0F
EOF
}
port_usage_extra() {
  cat <<'EOF'
  verify-wrp          check the running chain's XSPI guest fence (read-only)
EOF
}

lc_hex() { printf '0x%02X' $(( $1 & 0xFF )); }
ensure_spsdk() {
  if ! command -v pyocd >/dev/null 2>&1; then
    [ -x "$spsdk_venv/bin/pyocd" ] || fail "tools" "pyocd not found (set RT700_SPSDK_VENV)"
    PATH="$spsdk_venv/bin:$PATH"
    export PATH
  fi
}
# Words over SWD with the generic attach, which never resets the chip.
read_words() {
  local -a cmds=()
  local a
  for a in "$@"; do cmds+=(-c "read32 $a"); done
  timeout 60 pyocd cmd -t cortex_m "${cmds[@]}" 2>&1 | awk '/^[0-9a-f]+:/ { print $2 }'
}
psa_name() {
  case "$1" in
    00001000) echo "ASSEMBLY_AND_TEST" ;; 00002000) echo "PSA_ROT_PROVISIONING" ;;
    00003000) echo "SECURED" ;; 00004000) echo "NON_PSA_ROT_DEBUG" ;;
    00005000) echo "RECOVERABLE_PSA_ROT_DEBUG" ;; 00006000) echo "DECOMMISSIONED" ;;
    *) echo "UNKNOWN" ;;
  esac
}
# The PSA life cycles wolfTrust may report while the life cycle is $1.
expect_psa() {
  case "$1" in
    0x03) echo "00001000" ;; 0x07) echo "00002000" ;;
    0x0F|0xCF) echo "00003000 00004000 00005000" ;; 0x1F) echo "00006000" ;;
  esac
}
# The life cycle fused when discover ran (the shadow can differ until a reset).
fused_lc() {
  local w
  w="$(sed -n 's/^LC=\(0x[0-9A-Fa-f]*\) .*/\1/p' "$state_dir/discovery" 2>/dev/null)"
  [ -n "$w" ] && lc_hex "$w"
}
elf_sym() { arm-none-eabi-nm "$elf" | awk -v s="$1" '$3 == s && !f { print "0x" $1; f = 1 }'; }
# The life cycle wolfBoot handed wolfTrust: the raw handoff record while it is
# intact, else wolfTrust's consumed copy.
handoff_lifecycle() {
  local magic inv lc sym
  read -r magic inv lc < <(read_words 0x30180000 0x30180004 0x3018000C | tr '\n' ' '; echo)
  if [ "${magic:-}" = "5742484f" ] && [ $((0x$magic ^ 0x${inv:-0})) -eq $((0xFFFFFFFF)) ]; then
    echo "$lc"
    return 0
  fi
  [ -s "$elf" ] || return 1
  sym="$(elf_sym g_boot_lifecycle)"
  [ -n "$sym" ] || return 1
  read_words "$sym"
}
# The same predicate as wt_platform_guest_flash_wrp_ok: SFP sealed, every valid
# descriptor touching the guest windows locked and write-denying, no gap.
fence_line() {
  local -a cmds=(-c "read32 0x50184900 4" -c "read32 0x50184920 4") st=() en=() deny=() desc=()
  local addr w0 w1 w2 w3 n mgc="" mdad="" lock last cur found out=""
  rt700_fence_bounds || return 1
  for n in 0 1 2 3 4 5 6 7; do
    cmds+=(-c "read32 $(printf '0x%x' $((0x50184800 + n * 0x20))) 16")
  done
  while read -r addr w0 w1 w2 w3; do
    case "$addr" in
      50184900:) mdad="$w0" ;;
      50184920:) mgc="$w0" ;;
      *)
        [ $((0x${w3:-0} & 0x80000000)) -ne 0 ] || continue
        lock=$((0x$w3 & 0x60000000))
        st+=("$((0x$w0 & 0xFFFF0000))")
        en+=("$(((0x$w1 & 0xFFFF0000) | 0xFFFF))")
        desc+=("FRAD$(( (0x${addr%:} - 0x50184800) / 0x20 )) acp=0x$w2 word3=0x$w3")
        if [ $((0x$w2 & 0x3F)) -eq 0 ] && [ $((0x$w3 & 0x03000000)) -eq 0 ] &&
           { [ "$lock" -eq $((0x20000000)) ] || [ "$lock" -eq $((0x60000000)) ]; }; then
          deny+=(1)
        else
          deny+=(0)
        fi ;;
    esac
  done < <(timeout 60 pyocd cmd -t cortex_m "${cmds[@]}" 2>&1 | awk '/^50184/ { print $1, $2, $3, $4, $5 }')
  if [ -z "$mgc" ] || [ -z "$mdad" ] ||
     [ $((0x$mgc & 0xA8000000)) -ne $((0xA8000000)) ] || [ $((0x$mgc & 0xC00)) -eq 0 ] ||
     [ $((0x$mdad & 0xA0000000)) -ne $((0xA0000000)) ]; then
    echo "open SFP not sealed (MGC=0x${mgc:-?} TG0MDAD=0x${mdad:-?})"
    return 1
  fi
  last=$((RT700_GUEST_FENCE_END - 1))
  for n in "${!st[@]}"; do
    if [ "${st[$n]}" -le "$last" ] && [ "${en[$n]}" -ge $((RT700_GUEST_FENCE_START)) ] && [ "${deny[$n]}" = 0 ]; then
      echo "open ${desc[$n]} touches the guest windows without a locked write deny"
      return 1
    fi
  done
  cur=$((RT700_GUEST_FENCE_START))
  while [ "$cur" -le "$last" ]; do
    found=""
    for n in "${!st[@]}"; do
      if [ "${deny[$n]}" = 1 ] && [ "${st[$n]}" -le "$cur" ] && [ "${en[$n]}" -ge "$cur" ]; then
        found="$n"
        break
      fi
    done
    if [ -z "$found" ]; then
      echo "open no locked write deny covers $(printf '0x%08X' "$cur")"
      return 1
    fi
    out="${out:+$out, }${desc[$found]}"
    cur=$((en[found] + 1))
  done
  echo "armed $out"
}
# The four images run_rt700_hardware.sh flashes, as "address file" lines.
flashed_images() {
  printf '%s %s\n' \
    0x28000000 "${RT700_WORK:-$repo/build/rt700}/flash_wolfboot.bin" \
    0x28040000 "$repo/build/wolftrust_v1_signed.bin" \
    0x28080000 "$repo/tests/firmware/mimxrt700-baremetal/build/guest0.bin" \
    0x28100000 "$repo/tests/firmware/mimxrt700-baremetal/build/guest1.bin"
}
port_image_digest() { framed_digest; }
images_on_device() {
  local a f
  while read -r a f; do
    timeout 120 pyocd cmd -t cortex_m \
      -c "savemem $a $(wc -c < "$f" | tr -d ' ') $state_dir/readback.bin" \
      >/dev/null 2>&1 && cmp -s "$state_dir/readback.bin" "$f" || return 1
  done < <(flashed_images)
}
# The one attached debug probe; the EVK's MCU-Link is soldered to the board.
probe_uid() {
  local ids
  ids="$(timeout 30 pyocd list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ { print $(NF-1) }')"
  [ "$(printf '%s\n' "$ids" | grep -c .)" = "1" ] && echo "$ids"
}
# fuse_word <index>: the burned OTP word over the ISP connection, not the shadow.
fuse_word() {
  # shellcheck disable=SC2086  # RT700_ISP is a blhost option list
  blhost $RT700_ISP -j efuse-read-once "$1" 2>/dev/null |
    "$spsdk_py" -c '
import json, sys
r = json.load(sys.stdin)
if r.get("status", {}).get("value") != 0 or len(r.get("response", [])) != 2:
    sys.exit(1)
print("0x%08X" % r["response"][1])' 2>/dev/null
}

port_status() {
  local lc lcr lock dauth mgc mdad hl vm rf
  ensure_spsdk
  read -r lc lcr lock dauth mgc mdad < <(read_words "$LC_STATE" "$LC_STATE_RED" \
    "$LOCK_CFG3" "$DAUTHSTATUS" "$XSPI_MGC" "$XSPI_TG0MDAD" | tr '\n' ' '; echo)
  echo "OTP life cycle   LC_STATE=0x${lc: -2} ($(state_name "$(lc_hex "0x$lc")" || true))  LC_STATE_RED=0x${lcr: -2}"
  echo "LOCK_CFG3        0x$lock (LIFE_CYCLE_LOCK=$((0x$lock & 7)): 0 = shadow override and fuse burn both open)"
  echo "DAUTHSTATUS      0x$dauth"
  echo "XSPI SFP         MGC=0x$mgc TG0MDAD=0x$mdad"
  echo "guest fence      $(fence_line || true)"
  if hl="$(handoff_lifecycle)"; then echo "wolfTrust saw    0x$hl ($(psa_name "$hl"))"; fi
  if [ -s "$elf" ]; then
    read -r vm rf < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
      "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
    echo "guest launches   verified=0x${vm:-?} refused=0x${rf:-?}"
  fi
}
port_discover() {
  local lc lcr lock dauth hl
  ensure_spsdk
  mkdir -p "$state_dir"
  rm -f "$state_dir/discovery" "$state_dir/regress-ok"
  command -v shadowregs >/dev/null 2>&1 || PATH="$spsdk_venv/bin:$PATH"
  shadowregs get-families 2>/dev/null | grep -qi mimxrt798s ||
    fail "discover" "SPSDK shadowregs has no mimxrt798s support"
  pass "SPSDK shadowregs supports mimxrt798s"
  read -r lc lcr lock dauth < <(read_words "$LC_STATE" "$LC_STATE_RED" "$LOCK_CFG3" "$DAUTHSTATUS" | tr '\n' ' '; echo)
  [ "$(lc_hex "0x$lc")" = "$(lc_hex "0x$lcr")" ] || fail "discover" "life cycle copies disagree (LC 0x$lc, RED 0x$lcr)"
  [ $((0x$lc & 0xFFFFFF00)) -eq 0 ] && [ $((0x$lcr & 0xFFFFFF00)) -eq 0 ] ||
    fail "discover" "life cycle words 0x$lc/0x$lcr carry bits above the state byte (A0/A1 bit-protection copies); only the B0 encoding is validated"
  case "$(lc_hex "0x$lc")" in
    0x03|0x07|0x0F) ;;
    *) fail "discover" "fused life cycle $(lc_hex "0x$lc") has no further rehearsal step" ;;
  esac
  pass "fused life cycle is $(label "$(lc_hex "0x$lc")") and its redundant copy agrees"
  [ $((0x$lock & 2)) -eq 0 ] || fail "discover" "LIFE_CYCLE_LOCK over-ride protect is set (0x$lock)"
  pass "life cycle shadow over-ride is open (LOCK_CFG3 0x$lock)"
  hl="$(handoff_lifecycle)" || fail "discover" "no readable boot handoff: run tests/target/run_rt700_hardware.sh first"
  pass "the boot handoff life cycle is readable (0x$hl, $(psa_name "$hl"))"
  printf 'LC=0x%s RED=0x%s LOCK_CFG3=0x%s DAUTH=0x%s\n' "$lc" "$lcr" "$lock" "$dauth" > "$state_dir/discovery"
  echo "PASS: discovery stamped ($state_dir/discovery)"
}
port_restore() { "$target_dir/run_rt700_hardware.sh" wrpfence; }
port_extra() {
  local line
  case "$1" in
    verify-wrp)
      ensure_spsdk
      line="$(fence_line)" || fail "verify-wrp" "$line"
      pass "guest fence $line" ;;
    provision-da|burn)
      refuse "'$1' programs OTP fuses: 'lock' burns only the life cycle, one rehearsed step at a time. Burning the root key hash and debug root waits for a chip identity that binds the rehearsed part to the ISP target; see the MIMXRT700 Guide." ;;
    set-perimeter|set-wrp|clear-wrp)
      refuse "'$1' has no MIMXRT700 form: wolfBoot and wolfTrust program the TrustZone perimeter and the XSPI guest fence on every boot, and every reset clears them. Use 'restore' and 'verify-wrp'." ;;
    *) return 1 ;;
  esac
}

port_advance_check() {
  [ -s "$state_dir/discovery" ] || refuse "run 'discover' first."
  [ "$1" = "0x07" ] || [ -s "$state_dir/regress-ok" ] ||
    refuse "prove 'regress' from Develop2 before advancing to $1."
}
# Halt inside wolfBoot, after the ROM loaded the shadows and before wolfBoot
# reads them, write both life cycle copies, and resume.
port_advance() {
  local entry vm rf
  ensure_spsdk
  vm="$(elf_sym g_wt_launch_verified_mask)"; rf="$(elf_sym g_wt_launch_refused_mask)"
  [ -n "$vm" ] && [ -n "$rf" ] || fail "advance" "launch masks not found in $elf"
  entry="$(read_words 0x28004004)"
  [ -n "$entry" ] && [ "$entry" != "00000000" ] && [ "$entry" != "ffffffff" ] ||
    fail "advance" "no wolfBoot reset vector at 0x28004004 (flash the chain first)"
  echo "ADVANCING the life cycle shadow to $1 ($(state_name "$1")); regress or any reset undoes it"
  "$spsdk_py" - "0x$entry" "$1" "$LC_STATE" "$LC_STATE_RED" "$pyocd_target" \
    "$vm" "$rf" 0x30180000 <<'PYEOF'
import sys
import time
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target

WOLFBOOT_TEXT = (0x28004000, 0x28040000)
entry, value, lc, lc_red = (int(a, 0) for a in sys.argv[1:5])
with ConnectHelper.session_with_chosen_probe(
        options={"target_override": sys.argv[5], "resume_on_disconnect": True,
                 "reset_type": "hw"}) as s:
    t = s.target
    t.reset_and_halt()
    pc = t.read_core_register("pc")
    if pc < WOLFBOOT_TEXT[0]:
        t.set_breakpoint(entry & ~1)
        t.resume()
        deadline = time.time() + 10
        while t.get_state() != Target.State.HALTED or \
                t.read_core_register("pc") != (entry & ~1):
            if time.time() > deadline:
                sys.exit("wolfBoot entry breakpoint not reached")
            time.sleep(0.02)
        t.remove_breakpoint(entry & ~1)
        pc = t.read_core_register("pc")
    if not WOLFBOOT_TEXT[0] <= pc < WOLFBOOT_TEXT[1]:
        sys.exit("halted at 0x%08x, outside wolfBoot: too late to move the life cycle" % pc)
    t.write32(lc, value)
    t.write32(lc_red, value)
    got = (t.read32(lc) & 0xFF, t.read32(lc_red) & 0xFF)
    # SRAM survives the reset: clear the launch masks and the handoff magic so
    # only this boot's wolfBoot and wolfTrust can set them.
    for a in sys.argv[6:9]:
        t.write32(int(a, 0), 0)
        if t.read32(int(a, 0)) != 0:
            sys.exit("could not clear the boot evidence at %s" % a)
    t.resume()
print("halted in wolfBoot at 0x%08x; shadow LC_STATE=0x%02x LC_STATE_RED=0x%02x"
      % (pc, got[0], got[1]))
sys.exit(0 if got == (value, value) else 3)
PYEOF
  sleep 3
}
# The rehearsal evidence: the life cycle wolfTrust saw, every guest launched
# verified, the fence, the images read back, and the one attached probe.
port_booted() {
  local hl want vm rf fence digest probe
  # advance cleared the handoff and the launch masks, so both are this boot's.
  hl="$(handoff_lifecycle)" || { echo "no boot handoff written after the advance"; return 1; }
  echo "wolfTrust saw 0x$hl ($(psa_name "$hl"))"
  case " $(expect_psa "$1") " in
    *" $hl "*) pass "wolfTrust booted with the $(state_name "$1") life cycle" ;;
    *) echo "wolfTrust saw 0x$hl, not the life cycle of $1"; return 1 ;;
  esac
  # In Field Return is decommissioned: wolfTrust need not launch guests there.
  if [ "$1" != "0x1F" ]; then
    want=$((guest_mask))
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      read -r vm rf < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
        "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
      [ -n "${vm:-}" ] && [ $(((0x$vm | 0x${rf:-0}) & want)) -eq "$want" ] && break
      sleep 1
    done
    [ -n "${vm:-}" ] && [ $((0x$vm)) -eq "$want" ] && [ $((0x${rf:-1})) -eq 0 ] || {
      echo "guests did not all launch (verified=0x${vm:-?} refused=0x${rf:-?}, want $guest_mask)"
      return 1
    }
    pass "guests launched (verified=0x$vm refused=0x$rf)"
  fi
  fence="open"
  if fence_line >/dev/null; then fence="armed"; fi
  digest="$(port_image_digest)" || { echo "missing a flashed image"; return 1; }
  images_on_device || { echo "the images on the part differ from the host build: run 'restore'"; return 1; }
  pass "the images on the part match the host build (${digest:0:16})"
  probe="$(probe_uid)" || { echo "attach exactly one debug probe"; return 1; }
  EVIDENCE="id=$probe image=$digest fused=$(fused_lc) fence=$fence"
}
port_regress() {
  local fused lc lcr hl
  ensure_spsdk
  timeout 60 pyocd reset -t "$pyocd_target" -m hw >/dev/null 2>&1 || true
  "$target_dir/lib/rt700_reset.sh" reset
  sleep 3
  fused="$(fused_lc || echo "$LC_DEVELOP")"
  read -r lc lcr < <(read_words "$LC_STATE" "$LC_STATE_RED" | tr '\n' ' '; echo)
  [ "$(lc_hex "0x$lc")" = "$fused" ] && [ "$(lc_hex "0x$lcr")" = "$fused" ] ||
    fail "regress" "life cycle after reset is 0x$lc/0x$lcr, not the fused $fused (run discover)"
  pass "hardware reset reloaded the fused $(state_name "$fused") life cycle"
  hl="$(handoff_lifecycle)" || fail "regress" "cannot read the life cycle wolfTrust saw after the reset"
  case " $(expect_psa "$fused") " in
    *" $hl "*) pass "wolfTrust booted $(psa_name "$hl") again" ;;
    *) fail "regress" "wolfTrust saw 0x$hl after regress" ;;
  esac
  # Only a regress out of a recorded mock proves the way back for later steps.
  if [ -n "$PENDING" ]; then
    mkdir -p "$state_dir"
    date -u +%FT%TZ > "$state_dir/regress-ok"
  fi
}

port_cred_fp() { echo none; }
port_lock_current() {
  local lc lcr
  [ -n "${RT700_ISP:-}" ] || refuse "set RT700_ISP to the blhost ISP connection (for example '-u 0x1fc9,0x014f')."
  ensure_spsdk
  command -v blhost >/dev/null 2>&1 || PATH="$spsdk_venv/bin:$PATH"
  if ! lc="$(fuse_word "$FUSE_LC")" || ! lcr="$(fuse_word "$FUSE_LC_RED")"; then
    refuse "cannot read the life cycle fuses over RT700_ISP ($RT700_ISP)."
  fi
  [ "$(lc_hex "$lc")" = "$(lc_hex "$lcr")" ] || refuse "the life cycle fuses disagree (LC $lc, RED $lcr)."
  [ $((lc & 0xFFFFFF00)) -eq 0 ] && [ $((lcr & 0xFFFFFF00)) -eq 0 ] ||
    refuse "the life cycle fuses $lc/$lcr carry bits above the state byte (A0/A1 bit-protection copies); only the B0 burn encoding is validated."
  lc_hex "$lc"
}
# The burn runs over ISP USB, and no chip identity is documented that both the
# SWD rehearsal and ISP can read, so the main script requires a bound fixture.
port_lock_identity() { :; }
port_rehearsal_for() { echo "$1"; }
port_record_ok() {
  local rfused
  rfused="$(field fused "$1")"
  [ -n "$rfused" ] && [ $((rfused & ~cur & 0xFF)) -eq 0 ] &&
    [ "$(field fence "$1")" = "armed" ] &&
    [ "$(probe_uid || true)" = "$(field id "$1")" ]
}
port_ready() {
  case "$1" in
    0x0F|0xCF|0x1F)
      refuse "$(label "$1") needs the BootROM to authenticate wolfBoot (a signed image under the fused root key hash), which this port does not build yet; see the MIMXRT700 Guide." ;;
  esac
  CHECKED="$CHECKED, same debug probe $(probe_uid)"
}
burn_script() {
  printf 'efuse-program-once %s %08X --no-verify\nefuse-program-once %s %08X --no-verify\n' \
    "$FUSE_LC_RED" "$(($1))" "$FUSE_LC" "$(($1))"
}
port_lock_plan() { burn_script "$1" | sed "s|^|blhost $RT700_ISP |"; }
port_consequence() { echo "fuses cannot be unburned, and the part never returns to $(label "$cur")."; }
port_lock_write() {
  LC0="$(fuse_word "$FUSE_LC")"
  LCR0="$(fuse_word "$FUSE_LC_RED")"
  mkdir -p "$state_dir"
  burn_script "$1" > "$state_dir/burn-$1.bls"
  # shellcheck disable=SC2086  # RT700_ISP is a blhost option list
  blhost $RT700_ISP batch "$state_dir/burn-$1.bls" ||
    echo "blhost batch failed part way; reading both life cycle words back"
}
port_lock_verify() {
  local lc lcr
  if ! lc="$(fuse_word "$FUSE_LC")" || ! lcr="$(fuse_word "$FUSE_LC_RED")"; then
    fail "lock" "cannot read the life cycle fuses back"
  fi
  [ "$(lc_hex "$lc")" = "$1" ] && [ "$(lc_hex "$lcr")" = "$1" ] &&
    [ $((lc >> 8)) -eq $((LC0 >> 8)) ] && [ $((lcr >> 8)) -eq $((LCR0 >> 8)) ] ||
    fail "lock" "fuses read LC $lc, RED $lcr after the burn (before: $LC0, $LCR0), expected $1"
  echo "reset the part, then run: TARGET=mimxrt700 $0 status"
}
