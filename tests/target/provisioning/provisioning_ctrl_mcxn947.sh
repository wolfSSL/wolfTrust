# shellcheck shell=bash
# provisioning_ctrl_mcxn947.sh
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

# MCXN947 (FRDM-MCXN947) port for provisioning_ctrl.sh: the OTP life cycle
# the ROM reflects into SYSCON, rehearsed by handing wolfTrust the target
# state's PSA life cycle in the boot handoff record (a reset undoes it).
# No permanent write is implemented: every lock is refused. Sourced, never
# run. See docs/MCXN947-Guide.md.
# shellcheck disable=SC2034,SC2154  # PORT_* are read, and $cur/$PENDING set, by the main script

# A port file only works inside provisioning_ctrl.sh, which holds the gates.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "REFUSED: run TARGET=mcxn947 tests/target/provisioning/provisioning_ctrl.sh, not this port file." >&2
  exit 2
fi

PORT_NAME="MCXN947"
target_dir="$here/.."
pyocd_target="${MCXN947_TARGET:-mcxn947}"
spsdk_venv="${MCXN947_SPSDK_VENV:-$HOME/spsdk-venv}"
# Set here, not in a helper: the controller runs many port calls in subshells.
[ ! -d "$spsdk_venv/bin" ] || PATH="$spsdk_venv/bin:$PATH"
# The Python that runs pyOCD: the venv's, else the one behind pyocd on PATH.
if [ -x "$spsdk_venv/bin/python" ]; then
  spsdk_py="$spsdk_venv/bin/python"
else
  spsdk_py="$(sed -n '1s/^#! *\([^ ]*python[^ ]*\).*/\1/p' "$(command -v pyocd 2>/dev/null || echo /dev/null)" 2>/dev/null)"
  spsdk_py="${spsdk_py:-python3}"
fi
guest_mask="${MCXN947_GUEST_MASK:-0x3}"
case "$guest_mask" in
  0x1|0x2|0x3|1|2|3) ;;
  *) refuse "MCXN947_GUEST_MASK must be 0x1, 0x2, or 0x3 (both guests), not '$guest_mask'." ;;
esac
elf="$repo/build/wolftrust.elf"

# SYSCON life cycle state the ROM reflects from OTP (read-only), its
# duplicate, the debug authentication status, the device UUID (IPC1), the
# BOOT partition's reset vector, and the handoff record.
LC_STATE=0x50000980
LC_STATE_DP=0x50000984
DAUTHSTATUS=0xE000EFB8
UUID_BASE=0x01100000
WOLFTRUST_RESET_VECTOR=0x10040404
HANDOFF=0x30030000
LC_OEM_OPEN=0x03

port_ladder() {
  cat <<'EOF'
0x03 oem-open         no  no  permanent -
0x07 oem-secure-world yes no  permanent 0x03
0x0F oem-closed       yes no  permanent 0x07
0xCF oem-locked       yes no  permanent 0x0F
0x1F oem-field-return yes no  permanent 0x0F
EOF
}
port_usage_extra() {
  cat <<'EOF'
  verify-wrp          report the guest flash fence (none on this port yet)
EOF
}

lc_hex() { printf '0x%02X' $(( $1 & 0xFF )); }
ensure_pyocd() {
  if ! command -v pyocd >/dev/null 2>&1; then
    [ -x "$spsdk_venv/bin/pyocd" ] || fail "tools" "pyocd not found (set MCXN947_SPSDK_VENV)"
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
# The PSA life cycle the mock hands wolfTrust for state $1: the production
# value, with debug closed, which only a fused part can show on its own.
mock_psa() {
  case "$1" in
    0x07) echo 0x2000 ;; 0x0F|0xCF) echo 0x3000 ;; 0x1F) echo 0x6000 ;;
  esac
}
# The life cycle fused when discover ran.
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
  read -r magic inv lc < <(read_words "$HANDOFF" $((HANDOFF + 4)) $((HANDOFF + 12)) | tr '\n' ' '; echo)
  if [ "${magic:-}" = "5742484f" ] && [ $((0x$magic ^ 0x${inv:-0})) -eq $((0xFFFFFFFF)) ]; then
    echo "$lc"
    return 0
  fi
  [ -s "$elf" ] || return 1
  sym="$(elf_sym g_boot_lifecycle)"
  [ -n "$sym" ] || return 1
  read_words "$sym"
}
# The four images the chain flashes, as "address file" lines (physical
# offsets; wolfBoot at 0, the BOOT partition and both guest windows).
flashed_images() {
  printf '%s %s\n' \
    0x00000000 "${MCXN947_WORK:-$repo/build/mcxn947}/flash_wolfboot.bin" \
    0x00040000 "$repo/build/wolftrust_v1_signed.bin" \
    0x00080000 "$repo/tests/firmware/mcxn947-baremetal/build/guest0.bin" \
    0x00100000 "$repo/tests/firmware/mcxn947-baremetal/build/guest1.bin"
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
# The device UUID, readable over SWD in every state short of closed debug.
chip_uuid() {
  local w
  w="$(read_words "$UUID_BASE" $((UUID_BASE + 4)) $((UUID_BASE + 8)) $((UUID_BASE + 12)) | tr -d '\n')"
  [ ${#w} -eq 32 ] && [ "$w" != "00000000000000000000000000000000" ] &&
    [ "$w" != "ffffffffffffffffffffffffffffffff" ] && echo "$w"
}
# The one attached debug probe; the FRDM board's MCU-Link is soldered on.
probe_uid() {
  local ids
  ids="$(timeout 30 pyocd list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ { print $(NF-1) }')"
  [ "$(printf '%s\n' "$ids" | grep -c .)" = "1" ] && echo "$ids"
}
# The MCXN947 has no guest flash fence yet: the array is written only through
# the ROM API from the Secure side, and no hardware write fence is claimed.
fence_line() {
  echo "none (no guest flash fence on this port; a WT_GUEST_FLASH_WRP=1 image refuses every guest)"
  return 1
}

port_status() {
  local lc lcd dauth hl vm rf uuid
  ensure_pyocd
  read -r lc lcd dauth < <(read_words "$LC_STATE" "$LC_STATE_DP" "$DAUTHSTATUS" | tr '\n' ' '; echo)
  echo "OTP life cycle   LC_STATE=0x${lc: -2} ($(state_name "$(lc_hex "0x$lc")" || true))  LC_STATE_DP=0x${lcd: -2}"
  echo "DAUTHSTATUS      0x$dauth"
  echo "device UUID      $(chip_uuid || echo unreadable)"
  echo "guest fence      $(fence_line || true)"
  if hl="$(handoff_lifecycle)"; then echo "wolfTrust saw    0x$hl ($(psa_name "$hl"))"; fi
  if [ -s "$elf" ]; then
    read -r vm rf < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
      "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
    echo "guest launches   verified=0x${vm:-?} refused=0x${rf:-?}"
  fi
}
port_discover() {
  local lc lcd dauth hl uuid
  ensure_pyocd
  mkdir -p "$state_dir"
  rm -f "$state_dir/discovery" "$state_dir/regress-ok"
  read -r lc lcd dauth < <(read_words "$LC_STATE" "$LC_STATE_DP" "$DAUTHSTATUS" | tr '\n' ' '; echo)
  [ -n "${lc:-}" ] && [ -n "${lcd:-}" ] || fail "discover" "cannot read the life cycle over SWD"
  [ "$(lc_hex "0x$lc")" = "$(lc_hex "0x$lcd")" ] || fail "discover" "life cycle copies disagree (LC 0x$lc, DP 0x$lcd)"
  [ $((0x$lc & 0xFFFFFF00)) -eq 0 ] && [ $((0x$lcd & 0xFFFFFF00)) -eq 0 ] ||
    fail "discover" "life cycle words 0x$lc/0x$lcd carry bits above the state byte"
  case "$(lc_hex "0x$lc")" in
    0x03|0x07|0x0F) ;;
    *) fail "discover" "life cycle $(lc_hex "0x$lc") has no further rehearsal step" ;;
  esac
  pass "life cycle is $(label "$(lc_hex "0x$lc")") and its duplicate agrees"
  uuid="$(chip_uuid)" || fail "discover" "cannot read the device UUID at $UUID_BASE"
  pass "device UUID $uuid"
  hl="$(handoff_lifecycle)" || fail "discover" "no readable boot handoff: boot the wolfTrust chain first"
  pass "the boot handoff life cycle is readable (0x$hl, $(psa_name "$hl"))"
  printf 'LC=0x%s DP=0x%s DAUTH=0x%s UUID=%s\n' "$lc" "$lcd" "$dauth" "$uuid" > "$state_dir/discovery"
  echo "PASS: discovery stamped ($state_dir/discovery)"
}
port_restore() {
  fail "restore" "no MCXN947 hardware runner yet: flash wolfBoot, the signed wolfTrust image and both guests by hand (see the MCXN947 Guide), then run 'discover'"
}
port_extra() {
  local line
  case "$1" in
    verify-wrp)
      line="$(fence_line)" || fail "verify-wrp" "$line"
      pass "guest fence $line" ;;
    provision-da|burn)
      refuse "'$1' would program OTP: this port rehearses life cycles only and writes none of them; see the MCXN947 Guide." ;;
    set-perimeter|set-wrp|clear-wrp)
      refuse "'$1' has no MCXN947 form: wolfTrust programs the TrustZone perimeter on every boot, every reset clears it, and the port has no guest flash fence yet." ;;
    *) return 1 ;;
  esac
}

port_advance_check() {
  [ -s "$state_dir/discovery" ] || refuse "run 'discover' first."
  [ "$1" = "0x07" ] || [ -s "$state_dir/regress-ok" ] ||
    refuse "prove 'regress' from oem-secure-world before advancing to $1."
}
# Halt at wolfTrust's reset vector, after wolfBoot wrote the handoff record
# and before wolfTrust consumes it, replace the record's PSA life cycle with
# the target state's, and resume. The fuses and SYSCON are untouched.
port_advance() {
  local entry vm rf psa
  ensure_pyocd
  vm="$(elf_sym g_wt_launch_verified_mask)"; rf="$(elf_sym g_wt_launch_refused_mask)"
  [ -n "$vm" ] && [ -n "$rf" ] || fail "advance" "launch masks not found in $elf"
  entry="$(read_words "$WOLFTRUST_RESET_VECTOR")"
  [ -n "$entry" ] && [ "$entry" != "00000000" ] && [ "$entry" != "ffffffff" ] ||
    fail "advance" "no wolfTrust reset vector at $WOLFTRUST_RESET_VECTOR (flash the chain first)"
  psa="$(mock_psa "$1")"
  echo "ADVANCING the boot handoff life cycle to $psa for $1 ($(state_name "$1")); regress or any reset undoes it"
  "$spsdk_py" - "0x$entry" "$psa" "$HANDOFF" "$pyocd_target" "$vm" "$rf" <<'PYEOF'
import sys
import time
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target

HANDOFF_MAGIC = 0x5742484F
entry, psa, handoff = (int(a, 0) for a in sys.argv[1:4])
with ConnectHelper.session_with_chosen_probe(
        options={"target_override": sys.argv[4], "resume_on_disconnect": True,
                 "reset_type": "hw"}) as s:
    t = s.target
    t.reset_and_halt()
    t.set_breakpoint(entry & ~1)
    t.resume()
    deadline = time.time() + 10
    while t.get_state() != Target.State.HALTED or \
            t.read_core_register("pc") != (entry & ~1):
        if time.time() > deadline:
            sys.exit("wolfTrust entry breakpoint not reached")
        time.sleep(0.02)
    t.remove_breakpoint(entry & ~1)
    if t.read32(handoff) != HANDOFF_MAGIC or \
            t.read32(handoff + 4) != (HANDOFF_MAGIC ^ 0xFFFFFFFF):
        sys.exit("no intact handoff record at 0x%08x" % handoff)
    t.write32(handoff + 12, psa)
    got = t.read32(handoff + 12)
    # SRAM survives the reset: clear the launch masks so only this boot's
    # wolfTrust can set them.
    for a in sys.argv[5:7]:
        t.write32(int(a, 0), 0)
        if t.read32(int(a, 0)) != 0:
            sys.exit("could not clear the boot evidence at %s" % a)
    t.resume()
print("halted at wolfTrust's entry 0x%08x; handoff life cycle=0x%04x" % (entry & ~1, got))
sys.exit(0 if got == psa else 3)
PYEOF
  sleep 3
}
# The rehearsal evidence: the life cycle wolfTrust saw, every guest launched
# verified, the images read back, and the device UUID.
port_booted() {
  local hl want vm rf digest uuid
  # advance cleared the launch masks, so both are this boot's.
  hl="$(handoff_lifecycle)" || { echo "no boot handoff life cycle readable after the advance"; return 1; }
  echo "wolfTrust saw 0x$hl ($(psa_name "$hl"))"
  case " $(expect_psa "$1") " in
    *" $hl "*) pass "wolfTrust booted with the $(state_name "$1") life cycle" ;;
    *) echo "wolfTrust saw 0x$hl, not the life cycle of $1"; return 1 ;;
  esac
  # Field Return is decommissioned: wolfTrust need not launch guests there.
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
  digest="$(port_image_digest)" || { echo "missing a flashed image"; return 1; }
  images_on_device || { echo "the images on the part differ from the host build: flash the chain again"; return 1; }
  pass "the images on the part match the host build (${digest:0:16})"
  uuid="$(chip_uuid)" || { echo "cannot read the device UUID"; return 1; }
  EVIDENCE="id=$uuid image=$digest fused=$(fused_lc) fence=none"
}
port_regress() {
  local fused lc lcd hl
  ensure_pyocd
  timeout 60 pyocd reset -t "$pyocd_target" -m hw >/dev/null 2>&1 ||
    fail "regress" "hardware reset through pyocd failed"
  sleep 3
  fused="$(fused_lc || echo "$LC_OEM_OPEN")"
  read -r lc lcd < <(read_words "$LC_STATE" "$LC_STATE_DP" | tr '\n' ' '; echo)
  [ "$(lc_hex "0x$lc")" = "$fused" ] && [ "$(lc_hex "0x$lcd")" = "$fused" ] ||
    fail "regress" "life cycle after reset is 0x$lc/0x$lcd, not the fused $fused (run discover)"
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
  local lc lcd
  ensure_pyocd
  read -r lc lcd < <(read_words "$LC_STATE" "$LC_STATE_DP" | tr '\n' ' '; echo)
  [ -n "${lc:-}" ] && [ -n "${lcd:-}" ] || refuse "cannot read the life cycle over SWD."
  [ "$(lc_hex "0x$lc")" = "$(lc_hex "0x$lcd")" ] || refuse "the life cycle copies disagree (LC 0x$lc, DP 0x$lcd)."
  lc_hex "0x$lc"
}
port_lock_identity() { chip_uuid || true; }
port_rehearsal_for() { echo "$1"; }
port_record_ok() {
  local rfused
  rfused="$(field fused "$1")"
  [ -n "$rfused" ] && [ $((rfused & ~cur & 0xFF)) -eq 0 ] &&
    [ "$(field fence "$1")" = "none" ] &&
    [ "$(chip_uuid || true)" = "$(field id "$1")" ]
}
# No life cycle write is implemented for this part: the ladder marks every
# state unlockable, and these refuse again should the ladder ever change.
port_ready() {
  refuse "$(label "$1") cannot be locked by this port: the MCXN947 life cycle write (ROM ISP, OTP) is not validated here, so only rehearsals run; see the MCXN947 Guide."
}
port_lock_plan() { refuse "no MCXN947 life cycle write is implemented."; }
port_consequence() { echo "the OTP life cycle cannot be unburned, and the part never returns to $(label "$cur")."; }
port_lock_write() { refuse "no MCXN947 life cycle write is implemented."; }
port_lock_verify() { refuse "no MCXN947 life cycle write is implemented."; }
