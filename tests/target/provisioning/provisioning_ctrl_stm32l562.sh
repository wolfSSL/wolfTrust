# shellcheck shell=bash
# provisioning_ctrl_stm32l562.sh
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

# STM32L562 (STM32L562E-DK) port for provisioning_ctrl.sh: the RDP level in
# FLASH_OPTR under TZEN, which wolfBoot maps to the PSA life cycle, rehearsed
# in the boot handoff record; the TrustZone perimeter (TZEN, SECWM1/2,
# SECBOOTADD0, BOOT_LOCK) and the guest WRP fence are option bytes written
# over the on-board ST-LINK through STM32CubeProgrammer, or OpenOCD where it
# is not installed (tests/target/ports/stm32l562/probe.sh). The RDP lock is
# previewed and refused, hard-wired off. Sourced, never run.
# See docs/STM32L562-Guide.md.
# shellcheck disable=SC2034,SC2154  # PORT_* are read, and $cur/$PENDING set, by the main script

# A port file only works inside provisioning_ctrl.sh, which holds the gates.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "REFUSED: run TARGET=stm32l562 tests/target/provisioning/provisioning_ctrl.sh, not this port file." >&2
  exit 2
fi

PORT_NAME="STM32L562"
target_dir="$repo/tests/target"
# The hardware profile (sourced by provisioning_ctrl.sh) loaded probe.sh.
bind_probe STM32L562_STLINK_SN
pyocd_target="${STM32L562_PYOCD_TARGET:-cortex_m}"
pyocd_venv="${STM32L562_PYOCD_VENV:-$HOME/pyocd-venv}"
# Set here, not in a helper: the controller runs many port calls in subshells.
[ ! -d "$pyocd_venv/bin" ] || PATH="$pyocd_venv/bin:$PATH"
if [ -x "$pyocd_venv/bin/python" ]; then
  pyocd_py="$pyocd_venv/bin/python"
else
  pyocd_py="$(sed -n '1s/^#! *\([^ ]*python[^ ]*\).*/\1/p' "$(command -v pyocd 2>/dev/null || echo /dev/null)" 2>/dev/null)"
  pyocd_py="${pyocd_py:-python3}"
fi
guest_mask="${STM32L562_GUEST_MASK:-0x3}"
case "$guest_mask" in
  0x1|0x2|0x3|1|2|3) ;;
  *) refuse "STM32L562_GUEST_MASK must be 0x1, 0x2, or 0x3 (both guests), not '$guest_mask'." ;;
esac
elf="$repo/build/wolftrust-signed.elf"
# The RDP write stays hard-wired off: the lock previews the exact option byte
# write and refuses it whatever the caller supplies.
STM32L562_LOCK_WRITE_ENABLED=0

# The boot handoff record wolfBoot writes, wolfTrust's reset vector in the
# production slot (0x0C00C000 plus the 0x400 image header), and the 96-bit
# device UID (RM0438 UID_BASE).
HANDOFF=0x30000000
WOLFTRUST_RESET_VECTOR=0x0C00C404
UID_BASE=0x0BFA0590
RDP_LEVEL_0=0xAA

# The production perimeter of tests/target/ports/stm32l562/hw.sh: guest 0 at
# the top of bank 1 and guest 1 at the bottom of bank 2 Non-secure, wolfBoot,
# wolfTrust, the update slot, swap and stores Secure, boot pinned to wolfBoot.
WT_OB=(TZEN=0x1 SECWM1_PSTRT=${HW_SECWM1% *} SECWM1_PEND=${HW_SECWM1#* }
       SECWM2_PSTRT=${HW_SECWM2% *} SECWM2_PEND=${HW_SECWM2#* } SECBOOTADD0=0x180000)
WT_OB_BANKS=(DBANK=0x1 SWAP_BANK=0x0)
BOOT_LOCK_ON=(BOOT_LOCK=0x1)
# The guest pages per bank (SWAP_BANK=0): guest 0 is bank 1 pages 0x58-0x7F
# under WRP1A, guest 1 bank 2 pages 0x00-0x1F under WRP2A. Start above end
# disables an area; the bank's B area may cover the guest pages too.
WRP_GUEST=(WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F)
WRP_GUEST_PAGES="1:0x58:0x7F 2:0x0:0x1F"
OB_NAMES="RDP|TZEN|SECWM1_PSTRT|SECWM1_PEND|SECWM2_PSTRT|SECWM2_PEND|SECBOOTADD0|BOOT_LOCK|DBANK|SWAP_BANK|WRP1A_PSTRT|WRP1A_PEND|WRP1B_PSTRT|WRP1B_PEND|WRP2A_PSTRT|WRP2A_PEND|WRP2B_PSTRT|WRP2B_PEND"
OB_COUNT=18

port_ladder() {
  cat <<'EOF'
0xAA level-0          no  no  reversible -
0x55 level-0.5        yes yes reversible 0xAA
0xBB level-1          yes yes reversible 0x55
0xCC level-2          no  no  permanent  0xBB
EOF
}
port_commands() {
  cat <<'EOF'
set-perimeter write set TZEN, the watermarks and SECBOOTADD0 (level 0 only)
boot-lock write set BOOT_LOCK, which is permanent (production gates, level 0 only)
set-wrp write arm the guest flash WRP fence (level 0 only)
clear-wrp write release the guest flash WRP fence (level 0 only)
verify-wrp read report the guest flash fence
rdp2 refused RDP level 2 is permanent and never written by this tool
EOF
}

# Any RDP byte that is not level 0, 0.5 or 2 is level 1 (RM0438).
rdp_code() {
  case "$(printf '0x%02X' $(( $1 & 0xFF )))" in
    0xAA) echo 0xAA ;; 0x55) echo 0x55 ;; 0xCC) echo 0xCC ;; *) echo 0xBB ;;
  esac
}
# The ST-LINK serial this host names, else the one attached STM32L562E-DK's;
# a named serial must belong to an attached STM32L562E-DK too. Resolved once,
# outside any subshell, so a missing serial refuses loudly.
stlink_sn() {
  local sns
  if [ -n "${STM32L562_STLINK_SN:-}" ]; then
    l5_is_dk "$STM32L562_STLINK_SN" || return 2
    echo "$STM32L562_STLINK_SN"
    return 0
  fi
  sns="$(l5_dk_serials)"
  [ "$(printf '%s\n' "$sns" | grep -c .)" = "1" ] && echo "$sns"
}
ensure_probe() {
  local rc=0
  [ -n "${PROBE:-}" ] && return 0
  [ -n "$L5_TOOL" ] || fail "tools" "$(l5_tool_missing)"
  PROBE="$(stlink_sn)" || rc=$?
  [ "$rc" != 2 ] ||
    refuse "ST-LINK $STM32L562_STLINK_SN is not an attached STM32L562E-DK's (STM32L562_STLINK_SN names the DK's ST-LINK)."
  [ "$rc" = 0 ] ||
    refuse "this host does not have exactly one STM32L562E-DK ST-LINK: set STM32L562_STLINK_SN to the STM32L562E-DK's ST-LINK serial."
}
ob_values() {
  [ -n "${PROBE:-}" ] || refuse "no ST-LINK bound (ensure_probe was not called)."
  l5_ob_displ "$PROBE" 2>&1 |
    awk -v re="^($OB_NAMES)\$" '$1 ~ re && $2 == ":" { print $1 "=" $3 }' | sort || true
}
ob_get() { sed -n "s/^$1=//p" <<<"$2" | head -1; }
# A read near a reset can be transient, so two reads in a row must agree.
ob_snapshot() {
  local a b
  a="$(ob_values)"
  for _ in 1 2 3; do
    sleep 1
    b="$(ob_values)"
    if [ "$(grep -c . <<<"$b")" -eq "$OB_COUNT" ] && [ "$a" = "$b" ]; then
      sha256 <<<"$b" | cut -c1-64
      return 0
    fi
    a="$b"
  done
  return 1
}
# ob_match <values> NAME=want...: every named option byte has its value.
ob_match() {
  local v="$1" kv got
  shift
  for kv in "$@"; do
    got="$(ob_get "${kv%%=*}" "$v")"
    [ -n "$got" ] && [ "$(( got ))" = "$(( ${kv#*=} ))" ] 2>/dev/null || return 1
  done
}
live_rdp() {
  local r
  r="$(ob_get RDP "$(ob_values)")"
  [ -n "$r" ] && rdp_code "$r"
}
# Words over SWD at each address, as eight lowercase hex digits.
read_words() {
  local a
  [ -n "${PROBE:-}" ] || refuse "no ST-LINK bound (ensure_probe was not called)."
  for a in "$@"; do
    l5_read "$PROBE" "$a" 4 2>&1 |
      awk -v a="$(printf '0x%08x' "$a")" 'tolower($1) == a && $2 == ":" { print tolower($3) }'
  done
}
# The PSA life cycle wolfBoot reports for RDP code $1 under TZEN
# (hal/stm32l5_lifecycle.h, pinned in tests/host/stm32l562_lifecycle).
expect_psa() {
  case "$1" in
    0xAA) echo "00002000" ;; 0x55) echo "00004000" ;;
    0xBB) echo "00004000" ;; 0xCC) echo "00003000" ;;
  esac
}
mock_psa() {
  case "$1" in
    0x55) echo 0x4000 ;; 0xBB) echo 0x4000 ;;
  esac
}
# The images run_hardware.sh last built and flashed (build/hw).
port_image_files() {
  printf '%s\n' "$repo/build/hw/wolfboot.bin" "$repo/build/wolftrust_v1_signed.bin" \
    "$repo/build/hw/guest0.bin" "$repo/build/hw/guest1.bin"
}
port_image_digest() { framed_digest; }
images_on_device() {
  local a f n=0
  [ -n "${PROBE:-}" ] || refuse "no ST-LINK bound (ensure_probe was not called)."
  while read -r a f; do
    [ -s "$f" ] || return 1
    l5_upload "$PROBE" "$a" "$(wc -c < "$f" | tr -d ' ')" "$wt_tmp/readback.$n.bin" >/dev/null 2>&1 || return 1
    cmp -s "$wt_tmp/readback.$n.bin" "$f" || return 1
    n=$((n + 1))
  done < <(flashed_images)
}
# The UID answers only a Non-secure access; the OpenOCD backend claims its page
# Non-secure for the read (lib/stm32l562_openocd.tcl).
device_uid() {
  [ -n "${PROBE:-}" ] || refuse "no ST-LINK bound (ensure_probe was not called)."
  l5_uid "$PROBE"
}
# A WRP area NAME (WRP1A ...) when it is active (start <= end) and covers page
# $3 of its bank.
wrp_area_has() {
  local s e
  s="$(ob_get "${2}_PSTRT" "$1")"; e="$(ob_get "${2}_PEND" "$1")"
  [ -n "$s" ] && [ -n "$e" ] && [ $((s)) -le $((e)) ] &&
    [ $((s)) -le $(($3)) ] && [ $((e)) -ge $(($3)) ]
}
# Every guest page of every bank covered by that bank's A or B area.
wrp_guests_covered() {
  local spec bank first last p
  for spec in $WRP_GUEST_PAGES; do
    IFS=: read -r bank first last <<<"$spec"
    for ((p = first; p <= last; p++)); do
      wrp_area_has "$1" "WRP${bank}A" "$p" || wrp_area_has "$1" "WRP${bank}B" "$p" || return 1
    done
  done
}
# The active areas that protect any guest page, which a reflash must release.
wrp_guest_areas() {
  local spec bank first last a s e
  for spec in $WRP_GUEST_PAGES; do
    IFS=: read -r bank first last <<<"$spec"
    for a in "WRP${bank}A" "WRP${bank}B"; do
      s="$(ob_get "${a}_PSTRT" "$1")"; e="$(ob_get "${a}_PEND" "$1")"
      [ -n "$s" ] && [ -n "$e" ] && [ $((s)) -le $((e)) ] &&
        [ $((s)) -le $((last)) ] && [ $((e)) -ge $((first)) ] && echo "$a"
    done
  done
}
# An active area that also protects a page of its bank outside the guest pages.
wrp_area_wider() {
  local spec bank first last s e
  for spec in $WRP_GUEST_PAGES; do
    IFS=: read -r bank first last <<<"$spec"
    [ "WRP${bank}" = "${2%?}" ] || continue
    s="$(ob_get "${2}_PSTRT" "$1")"; e="$(ob_get "${2}_PEND" "$1")"
    [ -n "$s" ] && [ -n "$e" ] && [ $((s)) -le $((e)) ] &&
      { [ $((s)) -lt $((first)) ] || [ $((e)) -gt $((last)) ]; }
    return
  done
  return 1
}
fence_line() {
  local v a areas=""
  v="$(ob_values)"
  [ -n "$(ob_get SWAP_BANK "$v")" ] && [ "$(( $(ob_get SWAP_BANK "$v") ))" = 0 ] 2>/dev/null || {
    echo "unknown (SWAP_BANK is set or unreadable; the fence check assumes the unswapped bank map)"
    return 1
  }
  for a in $(wrp_guest_areas "$v"); do
    areas="${areas:+$areas, }$a pages $(ob_get "${a}_PSTRT" "$v")-$(ob_get "${a}_PEND" "$v")"
  done
  if wrp_guests_covered "$v"; then
    echo "armed: $areas cover both guest windows"
    return 0
  fi
  echo "none (bank 1 pages 0x58-0x7F and bank 2 pages 0x00-0x1F are not all covered; 'set-wrp' arms them)${areas:+; partial: $areas}"
  return 1
}
# Option byte arguments that release ($2 = open) or restore ($2 = keep) every
# area wrp_guest_areas names.
wrp_guest_args() {
  local a
  for a in $(wrp_guest_areas "$1"); do
    if [ "$2" = open ]; then
      printf '%s\n' "${a}_PSTRT=0x7F" "${a}_PEND=0x0"
    else
      printf '%s\n' "${a}_PSTRT=$(ob_get "${a}_PSTRT" "$1")" "${a}_PEND=$(ob_get "${a}_PEND" "$1")"
    fi
  done
}

port_status() {
  local v hl vm rf
  ensure_probe
  v="$(ob_values)"
  [ -n "$(ob_get RDP "$v")" ] || fail "status" "cannot read the option bytes over SWD through ST-LINK $PROBE"
  echo "ST-LINK          $PROBE ($L5_TOOL)"
  echo "RDP              $(ob_get RDP "$v") ($(state_name "$(rdp_code "$(ob_get RDP "$v")")" || true))"
  echo "TZEN             $(ob_get TZEN "$v")"
  echo "SECWM1           $(ob_get SECWM1_PSTRT "$v")-$(ob_get SECWM1_PEND "$v")  SECWM2 $(ob_get SECWM2_PSTRT "$v")-$(ob_get SECWM2_PEND "$v")"
  echo "SECBOOTADD0      $(ob_get SECBOOTADD0 "$v")  BOOT_LOCK $(ob_get BOOT_LOCK "$v")"
  echo "banks            DBANK $(ob_get DBANK "$v")  SWAP_BANK $(ob_get SWAP_BANK "$v")"
  echo "device UID       $(device_uid || echo unreadable)"
  echo "guest fence      $(fence_line || true)"
  echo "lock write       hard-wired off (STM32L562_LOCK_WRITE_ENABLED=$STM32L562_LOCK_WRITE_ENABLED): lock previews only"
  if hl="$(handoff_lifecycle)"; then echo "wolfTrust saw    0x$hl ($(psa_name "$hl"))"; fi
  if [ -s "$elf" ]; then
    read -r vm rf < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
      "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
    echo "guest launches   verified=0x${vm:-?} refused=0x${rf:-?}"
  fi
}
port_discover() {
  local v rdp code uid hl
  ensure_probe
  mkdir -p "$state_dir"
  rm -f "$state_dir/discovery" "$state_dir/regress-ok"
  v="$(ob_values)"
  rdp="$(ob_get RDP "$v")"
  [ -n "$rdp" ] || fail "discover" "cannot read the option bytes over SWD through ST-LINK $PROBE"
  code="$(rdp_code "$rdp")"
  case "$code" in
    0xAA|0x55) ;;
    *) fail "discover" "RDP $rdp is $(label "$code"), which has no further rehearsal step" ;;
  esac
  ob_match "$v" TZEN=0x1 ||
    fail "discover" "TrustZone is off (TZEN $(ob_get TZEN "$v")): run 'set-perimeter' at level 0 first"
  pass "RDP $rdp is $(label "$code") with TrustZone on (ST-LINK $PROBE)"
  uid="$(device_uid)" || fail "discover" "cannot read the device UID at $UID_BASE"
  pass "device UID $uid"
  hl="$(handoff_lifecycle)" || fail "discover" "no readable boot handoff: boot the wolfTrust chain first"
  pass "the boot handoff life cycle is readable (0x$hl, $(psa_name "$hl"))"
  printf 'RDP=%s TZEN=%s UID=%s PROBE=%s\n' "$rdp" "$(ob_get TZEN "$v")" "$uid" "$PROBE" > "$state_dir/discovery"
  echo "PASS: discovery stamped ($state_dir/discovery)"
}
# Put back the WRP2 areas restore released after stopping the runner; the
# saved values stay until the write reads back, so the EXIT trap retries once.
wrp_put_back() {
  local -a keep=()
  if [ -n "${RUNNER_PID:-}" ]; then
    kill "$RUNNER_PID" 2>/dev/null || true
    wait "$RUNNER_PID" 2>/dev/null || true
    RUNNER_PID=""
  fi
  [ "${#WRP_KEEP[@]}" != 0 ] || return 0
  keep=("${WRP_KEEP[@]}")
  if (ob_write restore "${keep[@]}"); then
    WRP_KEEP=()
    return 0
  fi
  echo "UNSAFE: the guest fence is still released (wanted ${keep[*]}); run 'verify-wrp' and 'set-wrp' before this part leaves the bench" >&2
  return 1
}
# The production images, through the hardware runner bound to this ST-LINK
# (a passing run is also the record boot-lock requires). Every WRP2 area over
# the guests is released for the reflash and put back exactly as it was,
# whether the runner passed, failed, or the controller was interrupted.
# The watermarks and the guest page map assume DBANK=1 SWAP_BANK=0.
require_bank_map() {
  ob_match "$1" "${WT_OB_BANKS[@]}" ||
    refuse "the part is not in dual-bank mode without bank swap (DBANK=1 SWAP_BANK=0), which the port's layout needs; nothing was written."
}
port_restore() {
  local rc=0 v a
  local -a open=()
  ensure_probe
  v="$(ob_values)"
  require_bank_map "$v"
  for a in $(wrp_guest_areas "$v"); do
    ! wrp_area_wider "$v" "$a" ||
      refuse "$a also protects pages outside the guest windows; restore would drop it while it erases the flash. Nothing was written."
  done
  mapfile -t open < <(wrp_guest_args "$v" open)
  mapfile -t WRP_KEEP < <(wrp_guest_args "$v" keep)
  RUNNER_PID=""
  trap 'wrp_put_back; rm -rf "$wt_tmp"' EXIT
  trap 'exit 130' INT HUP
  trap 'exit 143' TERM
  [ "${#open[@]}" = 0 ] || ob_write restore "${open[@]}"
  WT_HW_PROBE="$PROBE" STM32L562_PROBE_TOOL="$L5_TOOL" \
    "$target_dir/run_hardware.sh" stm32l562 positive &
  RUNNER_PID=$!
  wait "$RUNNER_PID" || rc=$?
  RUNNER_PID=""
  wrp_put_back || fail "restore" "the guest fence could not be put back"
  [ "$rc" = 0 ] || fail "restore" "the hardware runner did not pass; see its output"
  record_hwrun
}
# The production chain booted from SECBOOTADD0 on this part: the evidence
# boot-lock requires before the permanent BOOT_LOCK, bound to the device UID,
# the ST-LINK and the flashed images.
record_hwrun() {
  local uid digest hl
  uid="$(device_uid)" || fail "restore" "cannot read the device UID for the hardware-run record"
  digest="$(port_image_digest)" || fail "restore" "cannot digest the flashed images"
  hl="$(handoff_lifecycle)" || fail "restore" "no boot handoff life cycle readable after the run"
  put hwrun "scenario=positive id=$uid image=$digest probe=$PROBE secbootadd0=0x180000 handoff=$hl completed=$(date +%s)"
  pass "hardware-run record kept for part $uid (images ${digest:0:16})"
}
# Option byte writes: level 0 only, read back before they count.
ob_write() {
  local what="$1"
  shift
  [ "$(live_rdp || true)" = "$RDP_LEVEL_0" ] ||
    fail "$what" "option bytes are written by this tool only at level-0 (0xAA)"
  echo "Writing option bytes: $*"
  l5_ob_write "$PROBE" UR "$@" 2>&1 | tail -3 || true
  ob_match "$(ob_values)" "$@" || fail "$what" "the option bytes did not read back as $*"
  pass "option bytes read back as $*"
}
# BOOT_LOCK freezes SECBOOTADD0 for good, so it needs proof that this part
# boots the production chain from there: a recent passing hardware run
# (run_hardware.sh stm32l562 positive, which 'restore' runs) of these images.
hwrun_ok() {
  local rec uid
  rec="$(cat "$state_dir/hwrun" 2>/dev/null || true)"
  [ -n "$rec" ] ||
    refuse "no passing hardware run is recorded for this part: run 'restore' (run_hardware.sh stm32l562 positive) first."
  [ "$(field scenario "$rec")" = positive ] && [ "$(field secbootadd0 "$rec")" = 0x180000 ] &&
    [ "$(field handoff "$rec")" = 00002000 ] ||
    refuse "the hardware-run record is not a positive boot from SECBOOTADD0 0x180000: run 'restore' first."
  fresh "$(field completed "$rec")" ||
    refuse "the hardware run is older than ${rehearsal_max_age}s or from the future: run 'restore' again."
  [ "$(field image "$rec")" = "$(port_image_digest || true)" ] ||
    refuse "the hardware run booted other images than the ones built here: run 'restore' again."
  [ "$(field probe "$rec")" = "$PROBE" ] ||
    refuse "the hardware run went through ST-LINK $(field probe "$rec"), not $PROBE."
  uid="$(device_uid || true)"
  [ -n "$uid" ] && [ "$uid" = "$(field id "$rec")" ] ||
    refuse "this part (${uid:-UID unreadable}) is not the one the hardware run booted ($(field id "$rec"))."
  images_on_device ||
    refuse "the images on this part differ from the ones the hardware run booted: run 'restore' again."
  pass "a passing hardware run booted these images from SECBOOTADD0 on part $uid $(age_of "$(field completed "$rec")")s ago"
}
port_extra() {
  local line v a
  local -a open=()
  case "$1" in
    verify-wrp)
      ensure_probe
      line="$(fence_line)" || fail "verify-wrp" "$line"
      pass "guest fence $line" ;;
    set-perimeter)
      ensure_probe
      v="$(ob_values)"
      require_bank_map "$v"
      # RM0438: enabling TZEN resets the watermarks, so it is a write of its own.
      ob_match "$v" TZEN=0x1 || ob_write set-perimeter TZEN=0x1
      ob_write set-perimeter "${WT_OB[@]}" ;;
    boot-lock)
      # BOOT_LOCK is permanent (AN5347) and freezes SECBOOTADD0, so it takes
      # the production gates, checked again after the typed acceptance.
      ensure_probe
      ob_match "$(ob_values)" "${WT_OB[@]}" "${WT_OB_BANKS[@]}" ||
        refuse "set the perimeter first ('set-perimeter'): BOOT_LOCK freezes SECBOOTADD0."
      hwrun_ok
      lock_confirm "I ACCEPT BOOT_LOCK" "Setting BOOT_LOCK on this STM32L562" \
        "BOOT_LOCK pins the boot to SECBOOTADD0 (wolfBoot) and is permanent."
      ob_match "$(ob_values)" "${WT_OB[@]}" "${WT_OB_BANKS[@]}" ||
        refuse "the option bytes changed during the confirmation; nothing was written."
      hwrun_ok
      ob_write boot-lock "${BOOT_LOCK_ON[@]}" ;;
    set-wrp)
      ensure_probe
      v="$(ob_values)"
      require_bank_map "$v"
      for a in WRP1A WRP2A; do
        ! wrp_area_wider "$v" "$a" ||
          refuse "$a already protects pages outside the guest windows; arming the fence would drop them. Nothing was written."
      done
      ob_write set-wrp "${WRP_GUEST[@]}" ;;
    clear-wrp)
      ensure_probe
      v="$(ob_values)"
      require_bank_map "$v"
      for a in $(wrp_guest_areas "$v"); do
        ! wrp_area_wider "$v" "$a" ||
          refuse "$a also protects pages outside the guest windows; clearing it would drop them. Nothing was written."
      done
      mapfile -t open < <(wrp_guest_args "$v" open)
      if [ "${#open[@]}" = 0 ]; then
        pass "no WRP area protects a guest page"
      else
        ob_write clear-wrp "${open[@]}"
      fi ;;
    rdp2)
      refuse "'$1' has no STM32L562 form here: RDP level 2 is permanent and is never written by this tool; see the STM32L562 Guide." ;;
    *) return 1 ;;
  esac
}

port_advance_check() {
  local live
  [ -s "$state_dir/discovery" ] || refuse "run 'discover' first."
  [ "$1" = "0x55" ] || [ -s "$state_dir/regress-ok" ] ||
    refuse "prove 'regress' from level-0.5 before advancing to $1."
  ensure_probe
  live="$(live_rdp || true)"
  case "$1:$live" in
    0x55:0xAA|0xBB:0xAA|0xBB:0x55) ;;
    *) refuse "the part is ${live:-unreadable}: the mock of $(label "$1") runs only from a lower RDP level." ;;
  esac
}
# Halt at wolfTrust's reset vector, after wolfBoot wrote the handoff record
# and before wolfTrust consumes it, replace the record's PSA life cycle with
# the target state's, and resume. The option bytes are untouched.
port_advance() {
  local entry vm rf psa out got
  ensure_probe
  [ "$L5_TOOL" = openocd ] || command -v pyocd >/dev/null 2>&1 ||
    fail "advance" "pyocd not found (set STM32L562_PYOCD_VENV)"
  vm="$(elf_sym g_wt_launch_verified_mask)"; rf="$(elf_sym g_wt_launch_refused_mask)"
  [ -n "$vm" ] && [ -n "$rf" ] || fail "advance" "launch masks not found in $elf"
  entry="$(read_words "$WOLFTRUST_RESET_VECTOR")"
  [ -n "$entry" ] && [ "$entry" != "00000000" ] && [ "$entry" != "ffffffff" ] ||
    fail "advance" "no wolfTrust reset vector at $WOLFTRUST_RESET_VECTOR (flash the chain first)"
  psa="$(mock_psa "$1")"
  echo "ADVANCING the boot handoff life cycle to $psa for $1 ($(state_name "$1")) through ST-LINK $PROBE; regress or any reset undoes it"
  if [ "$L5_TOOL" = openocd ]; then
    out="$(l5_ocd "$PROBE" halt -c "l5_advance $((0x$entry & ~1)) $((psa)) $((HANDOFF)) $((vm)) $((rf))")"
    got="$(awk '$1 == "L5ADV" { print $3; exit }' <<<"$out")"
    [ -n "$got" ] && [ $((got)) -eq $((psa)) ] ||
      fail "advance" "$(grep -m1 '^L5ERR' <<<"$out" || echo "no L5ADV"): the handoff was not rewritten"
    echo "halted at wolfTrust's entry 0x$(printf '%08x' $((0x$entry & ~1))); handoff life cycle=$got"
    sleep 3
    return 0
  fi
  "$pyocd_py" - "0x$entry" "$psa" "$HANDOFF" "$pyocd_target" "$vm" "$rf" "$PROBE" <<'PYEOF'
import sys
import time
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target

HANDOFF_MAGIC = 0x5742484F
entry, psa, handoff = (int(a, 0) for a in sys.argv[1:4])
with ConnectHelper.session_with_chosen_probe(
        unique_id=sys.argv[7],
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
# verified, the images read back, the option bytes, the UID and the ST-LINK.
port_booted() {
  local hl want vm rf digest uid ob
  ensure_probe
  hl="$(handoff_lifecycle)" || { echo "no boot handoff life cycle readable after the advance"; return 1; }
  echo "wolfTrust saw 0x$hl ($(psa_name "$hl"))"
  [ "$hl" = "$(expect_psa "$1")" ] || { echo "wolfTrust saw 0x$hl, not the life cycle of $1"; return 1; }
  pass "wolfTrust booted with the $(state_name "$1") life cycle"
  want=$((guest_mask))
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    read -r vm rf < <(read_words "$(elf_sym g_wt_launch_verified_mask)" \
      "$(elf_sym g_wt_launch_refused_mask)" | tr '\n' ' '; echo)
    [ -n "${vm:-}" ] && [ $(((0x$vm | 0x${rf:-0}) & want)) -eq "$want" ] && break
    sleep 1
  done
  # Only the selected guests count: each verified and none refused.
  [ -n "${vm:-}" ] && [ -n "${rf:-}" ] && [ $((0x$vm & want)) -eq "$want" ] &&
    [ $((0x$rf & want)) -eq 0 ] || {
    echo "guests did not all launch (verified=0x${vm:-?} refused=0x${rf:-?}, want $guest_mask)"
    return 1
  }
  pass "guests launched (verified=0x$vm refused=0x$rf)"
  digest="$(port_image_digest)" || { echo "missing a flashed image"; return 1; }
  images_on_device || { echo "the images on the part differ from the host build: flash the chain again"; return 1; }
  pass "the images on the part match the host build (${digest:0:16})"
  uid="$(device_uid)" || { echo "cannot read the device UID"; return 1; }
  ob="$(ob_snapshot)" || { echo "the option bytes did not read back steadily"; return 1; }
  EVIDENCE="id=$uid image=$digest rdp=$(live_rdp) ob=$ob probe=$PROBE"
}
# A real regression from 0.5 or 1 to level 0 mass-erases the whole flash, so
# it is previewed and needs the same typed acceptance as a lock.
rdp_regress() {
  local answer now
  echo "Regression: $(label "$1") -> $(label "$RDP_LEVEL_0")"
  # Above level 0 the debugger can only attach hot (AN5347), not under reset
  echo "  will run: $(rdp_command "$RDP_LEVEL_0")"
  echo "  this MASS-ERASES the whole flash: wolfBoot, wolfTrust, both guests, the vault NVM and the update slot; 'restore' reflashes the chain"
  [ -t 0 ] || refuse "an RDP regression mass-erases the part: it needs an interactive terminal and the typed acceptance, not a pipe or script."
  printf '\n!!! Regressing this %s to %s\n!!! This MASS-ERASES the whole flash.\n!!! Are you sure? Type "I ACCEPT %s" to continue: ' \
    "$PORT_NAME" "$(label "$RDP_LEVEL_0")" "$RDP_LEVEL_0" >&2
  read -r answer || answer=""
  [ "$answer" = "I ACCEPT $RDP_LEVEL_0" ] || refuse "confirmation did not match; nothing was changed."
  l5_ob_write "$PROBE" HotPlug RDP="$RDP_LEVEL_0" 2>&1 | tail -3 || true
  now="$(live_rdp || true)"
  [ "$now" = "$RDP_LEVEL_0" ] || fail "regress" "RDP reads ${now:-unreadable} after the regression, expected $RDP_LEVEL_0"
  pass "the part is $(label "$RDP_LEVEL_0") and its flash was mass-erased: run 'restore'"
}
port_regress() {
  local live hl
  ensure_probe
  live="$(live_rdp || true)"
  case "$live" in
    0xAA) ;;
    0x55|0xBB) rdp_regress "$live"; return 0 ;;
    *) refuse "the part is ${live:-unreadable}: level-2 (0xCC) is permanent and no regression exists." ;;
  esac
  l5_hard_reset "$PROBE" >/dev/null 2>&1 || true
  sleep 3
  hl="$(handoff_lifecycle)" || fail "regress" "cannot read the life cycle wolfTrust saw after the reset"
  [ "$hl" = "$(expect_psa "$RDP_LEVEL_0")" ] || fail "regress" "wolfTrust saw 0x$hl after regress"
  pass "a hardware reset brought back the level-0 life cycle ($(psa_name "$hl"))"
  # Only a regress out of a recorded mock proves the way back for later steps.
  if [ -n "$PENDING" ]; then
    mkdir -p "$state_dir"
    date -u +%FT%TZ > "$state_dir/regress-ok"
  fi
}

port_cred_fp() { echo none; }
port_lock_current() {
  local r
  ensure_probe
  r="$(ob_get RDP "$(ob_values)")"
  [ -n "$r" ] || refuse "cannot read the RDP option byte over SWD (level 2 closes the debug port)."
  rdp_code "$r"
}
port_lock_identity() { device_uid || true; }
port_rehearsal_for() { echo "$1"; }
port_record_ok() {
  ensure_probe
  [ "$(field rdp "$1")" = "$cur" ] &&
    [ "$(field probe "$1")" = "$PROBE" ] &&
    [ "$(field ob "$1")" = "$(ob_snapshot || true)" ] &&
    [ "$(device_uid || true)" = "$(field id "$1")" ]
}
port_ready() {
  local v d
  ensure_probe
  images_on_device || refuse "the images on this part differ from the rehearsed build: 'restore' it first."
  v="$(ob_values)"
  ob_match "$v" "${WT_OB[@]}" "${WT_OB_BANKS[@]}" "${BOOT_LOCK_ON[@]}" ||
    refuse "the TrustZone perimeter option bytes are not wolfTrust's: run 'set-perimeter' and 'boot-lock' at level 0."
  fence_line >/dev/null || refuse "the guest flash WRP fence is not armed: run 'set-wrp' at level 0."
  d="$state_dir/lock-$1"
  mkdir -p "$d"
  printf '%s\n' "$v" > "$d/option-bytes.txt"
  port_lock_plan "$1" > "$d/plan.txt"
  CHECKED="$CHECKED, same ST-LINK $PROBE, images read back, perimeter and BOOT_LOCK values, guest WRP fence, option bytes and plan kept in $d"
}
# The RDP write as this host's probe tool would issue it, over a hot attach.
rdp_command() {
  if [ "$L5_TOOL" = openocd ]; then
    echo "$L5_OPENOCD (ST-LINK $PROBE, hot attach): l5_obw RDP=$1, OPTSTRT, OBL_LAUNCH"
  else
    echo "$L5_CLI -c port=SWD sn=$PROBE mode=HotPlug -ob RDP=$1"
  fi
}
port_lock_plan() {
  rdp_command "$1"
  echo "the way back: an RDP regression to level-0 (-ob RDP=0xAA) MASS-ERASES the whole flash"
  echo "REFUSED at the write: STM32L562_LOCK_WRITE_ENABLED=$STM32L562_LOCK_WRITE_ENABLED, hard-wired off in this port"
}
port_consequence() {
  case "$1" in
    0x55) echo "the debugger loses Secure memory, and only an RDP regression to level 0, which MASS-ERASES the whole flash, returns the part to $(label "$cur")." ;;
    *) echo "the debugger loses the flash and SRAM2, and only an RDP regression to level 0, which MASS-ERASES the whole flash, undoes it." ;;
  esac
}
port_lock_write() {
  [ "$STM32L562_LOCK_WRITE_ENABLED" = "1" ] ||
    refuse "the STM32L562 RDP write is hard-wired off in this port (STM32L562_LOCK_WRITE_ENABLED=0): the preview is the whole of what this phase does, and nothing was written."
  refuse "no STM32L562 RDP write path is implemented even when enabled."
}
port_lock_verify() { refuse "no STM32L562 RDP write is implemented."; }
