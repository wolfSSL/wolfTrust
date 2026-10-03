# shellcheck shell=bash
# provisioning_ctrl_stm32h563.sh
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

# STM32H563 (NUCLEO-H563ZI) port for provisioning_ctrl.sh: product states set
# by option bytes through STM32CubeProgrammer, rehearsed by a Debug
# Authentication (DA) regression. Sourced, never run. See docs/STM32H5-Guide.md.
# shellcheck disable=SC2034,SC2154  # PORT_* are read, and $cmd/$PENDING set, by the main script

# A port file only works inside provisioning_ctrl.sh, which holds the gates.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "REFUSED: run TARGET=stm32h563 tests/target/provisioning/provisioning_ctrl.sh, not this port file." >&2
  exit 2
fi

PORT_NAME="STM32H563"
CP="${STM32_CP:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin}"
CLI="${STM32_CLI:-$CP/STM32_Programmer_CLI}"
SERIAL="${H5_SERIAL:-/dev/ttyACM0}"

# ST's NUCLEO-H563ZI ROT_Provisioning/DA sample. wolfTrust runs TZEN enabled,
# so DA is certificate based (AN6008); a password OBK cannot regress the part.
DA_SAMPLE_DIR="$HOME/st-rot-h5/Projects/NUCLEO-H563ZI/ROT_Provisioning/DA"
# SHA-256 of every file in that public sample (Binary, Keys, Certificates), so
# a renamed copy is caught even where the sample tree is not installed.
DA_SAMPLE_SHA256="
2cafcf533300aebe1ebaaa2b6bd6e99c3502ef88acd668b2d41f910515527862
f4d40b1b669a635e15719eaf0f6fd9f7b5494e3616a6337d2c350eca7f2d4547
774e73f4c0ec7f9617da41405b0eb02d560ea498af8717de91b411203d1af499
32227fc98010224ab39dd8fb5bb3b917820047fb52a1be91551e9c7e6e424590
ef86c2ea01df5fdf526fb7a68fb4876436131f575093b3bc90f7428e677e72b2
b00d6ad78f9d8a5b1a9299bc618fd651b7637ed0873fb9104a674edd5a19569b
d21811a12f5533f474901f2bec27ae4c85c76a4968394e221edc55f4c291ac0a
1c343faca2e1c81c913afe520aa0de26b8b01a71c0ab2d7796a356cd4d127a59
67ba2294171501a8df9864da5d18ecee386b69f1f197138cb3452ed4aed8d854
d4ac966902c0129bd311a23794d5430d4e4ecb75071195135adfd64373c56d19
10ef8afae7bad8608cb01d803347dfc396210c65eaa2f808ce1b52b757a3ea3d
9c6c7589abc052671f107a5b3cc7e9437865b342ed5909d8fef73c3f5771b560
d8617a54b88c6061f310d75b66d6319e9b87212a8f53401f039067f9aa520894
9a77fd6ab8533715976bc83dc72182c3c1cb568f30fc3630e911eb1c64a33e59
"
DA_DIR="${WT_DA_DIR:-$DA_SAMPLE_DIR}"
DA_OBK="${WT_DA_OBK:-$DA_DIR/Binary/DA_Config.obk}"
DA_PWD="${WT_DA_PWD:-$DA_DIR/Binary/password.bin}"
DA_KEY="${WT_DA_KEY:-$DA_DIR/Keys/key_3_leaf.pem}"
DA_CERT="${WT_DA_CERT:-$DA_DIR/Certificates/cert_leaf_chain.b64}"
DA_CONN="-c port=SWD speed=fast ap=1 mode=Hotplug"
DA_CONN_RST="-c port=SWD speed=fast ap=1 mode=Hotplug -hardRst"

# The OEM-iRoT perimeter read from a known-good wolfTrust board. SECWM1_END
# must span the whole boot partition, or writes past 0x08080000 are dropped.
WT_OB=(TZEN=0xB4 BOOT_UBE=0xB4 SWAP_BANK=0x0
       SECWM1_STRT=0x0 SECWM1_END=0x4F SECWM2_STRT=0x0 SECWM2_END=0x7F)
# WRPSGn1: 0 protects four sectors per bit; 0x000FFFFF covers the guests.
WRP_GUEST=0x000FFFFF; WRP_OPEN=0xFFFFFFFF
PS_OPEN=0xED; PS_PROVISIONING=0x17

WOLFBOOT=0x0C000000; WOLFTRUST=0x0C060000; GUEST0=0x080A0000; GUEST1=0x080E0000
wb="$repo/wolfBoot/wolfboot.bin"
wt="$repo/build/wolftrust_v1_signed.bin"
g0="$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
g1="$repo/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"

port_ladder() {
  cat <<'EOF'
0xED open         no  no  reversible -
0x17 provisioning yes yes reversible 0xED
0xC6 tz-closed    yes yes reversible 0x17
0x72 closed       yes yes reversible 0x17
0x5C locked       no  yes permanent  0x17
EOF
}

port_usage_extra() {
  cat <<'EOF'
  set-perimeter       set the wolfTrust TrustZone option bytes (writes)
  set-wrp, clear-wrp  protect or release the guest flash (writes, Open only)
  flash, verify       flash the images; reset and check the boot
  provision-da        provision the DA OBK (writes, Provisioning only)
EOF
}

strip() { sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g'; }

# A read right after a reset can return garbage, so only a known code counts.
product_state() {
  local v
  for _ in 1 2 3; do
    v="$("$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
      | grep -iE "PRODUCT_STATE" | grep -oE "0x[0-9A-Fa-f]+" | head -1 || true)"
    case "$(printf '0x%02X' "$(( ${v:-0x100} ))")" in
      0xED|0x17|0x2E|0xC6|0x72|0x5C) hexstate "$v"; return 0 ;;
    esac
    sleep 2
  done
  return 1
}
st_lifecycle() {
  case "$1" in
    0x17) echo "ST_LIFECYCLE_PROVISIONING" ;; 0xC6) echo "ST_LIFECYCLE_TZ_CLOSED" ;;
    0x72) echo "ST_LIFECYCLE_CLOSED" ;; 0x5C) echo "ST_LIFECYCLE_LOCKED" ;;
  esac
}
# shellcheck disable=SC2086  # DA_CONN is an option list
da_discovery() { "$CLI" $DA_CONN pwd="$DA_PWD" debugauth=2 2>&1 | strip; }
da_ready() {
  local disc
  disc="$(da_discovery)"
  grep -q "0xeaeaeaea" <<<"$disc" && grep -q "Full Regression" <<<"$disc"
}
# A closed part drops the debug link, so its state is read by DA discovery.
da_lifecycle() { da_discovery | grep -oE "ST_LIFECYCLE_[A-Z_]+" | head -1; }
# Only output that arrives after the capture starts counts as a boot: a tty is
# drained first, and a file (a replay or test) is read from its current end.
uart_capture() {
  rm -f "$2.from"
  if [ -c "$SERIAL" ]; then
    stty -F "$SERIAL" 115200 raw -echo 2>/dev/null || true
    timeout 1 cat "$SERIAL" >/dev/null 2>&1 || true
    ( timeout "$1" cat "$SERIAL" > "$2" 2>/dev/null & )
  else
    : > "$2"
    wc -c < "$SERIAL" | tr -d ' ' > "$2.from"
  fi
}
booted() {
  if [ -s "$1.from" ]; then tail -c +$(( $(cat "$1.from") + 1 )) "$SERIAL"; else cat "$1"; fi |
    strip | grep -aqE "guest0_psa|heartbeat|TEE client"
}

flashed_images() {
  printf '%s %s\n' "$WOLFBOOT" "$wb" "$WOLFTRUST" "$wt" "$GUEST0" "$g0" "$GUEST1" "$g1"
}
port_image_digest() { framed_digest; }
# The running chain hides guest flash from the debugger, so read under reset.
images_on_device() {
  local a f n=0 rc=0
  local -a reads=()
  while read -r a f; do
    reads+=(-u "$a" "$(wc -c < "$f" | tr -d ' ')" "$wt_tmp/readback.$n.bin")
    n=$((n + 1))
  done < <(flashed_images)
  "$CLI" -c port=SWD mode=UR "${reads[@]}" >/dev/null 2>&1 || rc=1
  "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
  n=0
  while read -r a f; do
    [ "$rc" = 0 ] && cmp -s "$wt_tmp/readback.$n.bin" "$f" || rc=1
    n=$((n + 1))
  done < <(flashed_images)
  return "$rc"
}
# The 96-bit device UID (RM0481 UID_BASE): readable under reset in Open only.
device_uid() {
  local u
  u="$("$CLI" -c port=SWD mode=UR -r32 0x08FFF800 12 2>&1 | strip \
    | awk '$1 == "0x08FFF800" { print $3 $4 $5 }')"
  "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
  case "$u" in
    ""|000000000000000000000000|ffffffffffffffffffffffff|FFFFFFFFFFFFFFFFFFFFFFFF) return 1 ;;
  esac
  echo "$u"
}
# The perimeter and guest WRP option bytes this port sets, as NAME=value.
ob_values() {
  "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
    | awk '$1 ~ /^(TZEN|BOOT_UBE|SWAP_BANK|SECWM[12]_(STRT|END)|WRPSGn1)$/ && $2 == ":" { print $1 "=" $3 }' \
    | sort || true
}
# A read near a reset can be transient, so two reads in a row must agree.
ob_snapshot() {
  local a b
  a="$(ob_values)"
  for _ in 1 2 3; do
    sleep 1
    b="$(ob_values)"
    if [ "$(grep -c . <<<"$b")" -eq 8 ] && [ "$a" = "$b" ]; then
      sha256 <<<"$b" | cut -c1-64
      return 0
    fi
    a="$b"
  done
  return 1
}
# ob_safe [wrp]: the live option bytes are wolfTrust's perimeter (and guest WRP).
ob_safe() {
  local v kv name want
  v="$(ob_values)"
  for kv in "${WT_OB[@]}" ${1:+WRPSGn1=$WRP_GUEST}; do
    name="${kv%%=*}"; want="${kv#*=}"
    [ "$(( $(sed -n "s/^$name=//p" <<<"$v" | head -1) ))" = "$(( want ))" ] 2>/dev/null || return 1
  done
}

# Every DA input a regression used: key, certificate chain, OBK, and password.
port_cred_fp() {
  local f
  for f in "$DA_KEY" "$DA_CERT" "$DA_OBK" "$DA_PWD"; do
    [ -s "$f" ] || { echo none; return 0; }
  done
  for f in "$DA_KEY" "$DA_CERT" "$DA_OBK" "$DA_PWD"; do sha256 < "$f"; done | sha256 | cut -c1-64
}
da_is_sample() {
  local h s
  h="$(sha256 < "$1" | cut -c1-64)"
  case "$DA_SAMPLE_SHA256" in *"$h"*) return 0 ;; esac
  if [ -d "$DA_SAMPLE_DIR" ]; then
    while IFS= read -r s; do
      [ "$(sha256 < "$s" | cut -c1-64)" != "$h" ] || return 0
    done < <(find "$DA_SAMPLE_DIR" -type f)
  fi
  return 1
}
# A production part must carry its own DA credential, never ST's sample.
da_production_ready() {
  local f
  [ -n "${WT_DA_OBK:-}" ] && [ -n "${WT_DA_KEY:-}" ] && [ -n "${WT_DA_CERT:-}" ] &&
    [ -n "${WT_DA_PWD:-}" ] || return 1
  for f in "$DA_OBK" "$DA_KEY" "$DA_CERT" "$DA_PWD"; do
    [ -s "$f" ] || return 1
    ! da_is_sample "$f" || return 1
  done
}
da_refuse_sample() {
  refuse "a production part needs its own DA credential: set WT_DA_OBK, WT_DA_KEY, WT_DA_CERT, and WT_DA_PWD, not ST's sample."
}

set_perimeter() {
  echo "Setting wolfTrust OEM-iRoT perimeter: ${WT_OB[*]}"
  # TZEN first: an off-to-on flip mass-erases.
  "$CLI" -c port=SWD mode=UR -ob TZEN=0xB4 2>&1 | strip | tail -3
  "$CLI" -c port=SWD mode=UR -ob "${WT_OB[@]}" 2>&1 | strip | tail -4
}
set_wrp() {
  [ "$(product_state || true)" = "$PS_OPEN" ] || fail "set-wrp" "WRP is settable only in Open"
  echo "Write-protecting guest flash (bank1 sectors 0x50-0x7F): WRPSGn1=$WRP_GUEST"
  "$CLI" -c port=SWD mode=UR -ob WRPSGn1="$WRP_GUEST" 2>&1 | strip | tail -4
}
clear_wrp() {
  echo "Clearing guest-flash write protection: WRPSGn1=$WRP_OPEN"
  "$CLI" -c port=SWD mode=UR -ob WRPSGn1="$WRP_OPEN" 2>&1 | strip | tail -4
}
flash_images() {
  local f
  rm -f "$state_dir/readback"
  for f in "$wb" "$wt" "$g0" "$g1"; do [ -s "$f" ] || fail "flash" "missing image: $f"; done
  "$CLI" -c port=SWD mode=UR -d "$wb" "$WOLFBOOT" -d "$wt" "$WOLFTRUST" \
    -d "$g0" "$GUEST0" -d "$g1" "$GUEST1" --verify -hardRst 2>&1 | strip \
    | grep -iE "verified successfully|error|download" | tail -4
}
verify_boot() {
  uart_capture 8 "$wt_tmp/verify.log"
  "$CLI" -c port=SWD mode=UR -rst >/dev/null 2>&1 || true
  sleep 7
  booted "$wt_tmp/verify.log" || fail "verify" "no wolfTrust boot markers on $SERIAL"
  pass "wolfTrust chain boots on silicon"
}
provision_da() {
  [ -s "$DA_OBK" ] || fail "provision-da" "DA OBK not found: $DA_OBK"
  [ "${WT_PRODUCTION_LOCK:-0}" != "1" ] || da_production_ready || da_refuse_sample
  [ "$(product_state || true)" = "$PS_PROVISIONING" ] || fail "provision-da" "only in Provisioning"
  echo "Provisioning DA OBK: $DA_OBK"
  # shellcheck disable=SC2086
  "$CLI" $DA_CONN_RST >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  "$CLI" $DA_CONN -sdp "$DA_OBK" 2>&1 | strip | tail -2
  # shellcheck disable=SC2086
  "$CLI" $DA_CONN_RST >/dev/null 2>&1 || true
  da_ready || fail "provision-da" "discovery does not show an intact OBK offering Full Regression"
  put da-provisioned "cred=$(port_cred_fp) time=$(date +%s)"
  pass "DA provisioned and recorded for this credential set"
}

port_status() {
  "$CLI" -c port=SWD mode=HotPlug -ob displ 2>&1 | strip \
    | grep -iE "PRODUCT_STATE|TZEN|BOOT_UBE|SECWM|SECBOOT|WRPSGn1" | head -20
}
port_discover() {
  echo "DA discovery (non-destructive):"
  da_discovery | grep -iE "PSA lifecycle|integrity|permission|Discovery Success|not supported|error" || true
}
port_restore() { set_perimeter; clear_wrp; flash_images; set_wrp; verify_boot; }
port_extra() {
  case "$1" in
    set-perimeter) confirm; set_perimeter ;;
    set-wrp) confirm; set_wrp ;;
    clear-wrp) confirm; clear_wrp ;;
    flash) confirm; flash_images ;;
    verify) verify_boot ;;
    provision-da) confirm; provision_da ;;
    *) return 1 ;;
  esac
}

# Closed states are written from Provisioning: from TrustZone Closed the debug
# link cannot write the next state (seen 2026-08-19).
port_advance_check() {
  local cur rb
  cur="$(product_state || true)"
  if [ "$1" = "$PS_PROVISIONING" ]; then
    [ "$cur" = "$PS_OPEN" ] || refuse "advance to Provisioning runs from Open; state=${cur:-unreadable}."
    return 0
  fi
  [ "$cur" = "$PS_PROVISIONING" ] ||
    refuse "advance to $(label "$1") runs only from Provisioning (0x17); state=${cur:-unreadable}."
  da_ready || refuse "Debug Authentication is not provisioned (no intact OBK offering Full Regression): without it $(label "$1") cannot be regressed. Run 'provision-da' and 'discover'."
  rb="$(cat "$state_dir/readback" 2>/dev/null || true)"
  if [ "$(field image "$rb")" != "$(port_image_digest)" ] || ! fresh "$(field time "$rb")"; then
    refuse "no recent read-back of these images: 'restore', then 'advance 0x17' from Open reads them back."
  fi
}
# Provisioning closes Secure debug, so the part is read back while still Open.
port_advance() {
  local uid ob
  if [ "$1" = "$PS_PROVISIONING" ]; then
    rm -f "$state_dir/readback"
    ob="$(ob_snapshot || true)"
    uid="$(device_uid || true)"
    if [ -n "$uid" ] && [ -n "$ob" ] && images_on_device; then
      put readback "image=$(port_image_digest) id=$uid ob=$ob time=$(date +%s)"
      pass "the images on device $uid match the host build ($(port_image_digest | cut -c1-16))"
    else
      refuse "could not read back the images, device UID, and option bytes; nothing was written. Run 'restore' first."
    fi
  fi
  echo "ADVANCING product state $(product_state || echo '?') -> $1 (regress is the only way back)"
  uart_capture 12 "$wt_tmp/advance.log"
  # The CLI fails its post-write reconnect once debug closes; the read-back decides.
  "$CLI" -c port=SWD mode=HotPlug -ob PRODUCT_STATE="$1" 2>&1 | strip | tail -4 || true
  sleep 10
  echo "now: $(product_state || da_lifecycle || true)"
}
# The read-back resets the part, so only a closed state's capture proves the boot.
port_booted() {
  local rb
  rb="$(cat "$state_dir/readback" 2>/dev/null || true)"
  [ -n "$rb" ] || return 1
  if [ "$(product_state || true)" != "$1" ] &&
     [ "$(da_lifecycle || true)" != "$(st_lifecycle "$1")" ]; then
    echo "the part does not read back as $(label "$1") after the write"
    return 1
  fi
  pass "the part reads back as $(label "$1")"
  if [ "$1" != "$PS_PROVISIONING" ]; then
    booted "$wt_tmp/advance.log" || { echo "no wolfTrust boot markers on $SERIAL after the write"; return 1; }
    pass "wolfTrust chain boots in $(label "$1")"
  fi
  EVIDENCE="id=$(field id "$rb") image=$(field image "$rb") ob=$(field ob "$rb")"
}
port_regress() {
  local after uid
  rm -f "$state_dir/readback" "$state_dir/da-provisioned"
  echo "DA certificate Full Regression -> Open (mass-erase):"
  "$CLI" -c port=SWD mode=HotPlug -rst 2>&1 | strip | tail -1 || true
  "$CLI" -c port=SWD per=a key="$DA_KEY" cert="$DA_CERT" pwd="$DA_PWD" \
    debugauth=1 </dev/null 2>&1 | strip | tail -4
  after="$(product_state || true)"
  echo "state after regression: ${after:-unreadable}"
  [ "$after" = "$PS_OPEN" ] || return 1
  [ -n "$PENDING" ] || return 0
  uid="$(device_uid || true)"
  [ -n "$uid" ] && [ "$uid" = "$(field id "$PENDING")" ] || {
    echo "device UID ${uid:-unreadable} is not the rehearsed one; not recorded"
    return 1
  }
}

port_lock_current() {
  product_state || refuse "cannot read the product state over SWD (a closed part drops the link)."
}
port_lock_identity() {
  [ "$(product_state || true)" = "$PS_OPEN" ] || return 0
  device_uid || refuse "cannot read the device UID over SWD."
}
# Provisioning runs no wolfTrust chain, so its step is covered by any closing
# rehearsal; Locked cannot be rehearsed, so Closed stands in for it.
port_rehearsal_for() {
  case "$1" in
    0x17) echo "0x17 0xC6 0x72" ;; 0x5C) echo "0x72" ;; *) echo "$1" ;;
  esac
}
port_record_ok() { [ "$(ob_snapshot || true)" = "$(field ob "$1")" ]; }
port_ready() {
  local dp dt rt
  if [ "$cur" = "$PS_OPEN" ]; then
    images_on_device || refuse "the images on this part differ from the rehearsed build: 'restore' it first."
    CHECKED="$CHECKED, images read back"
  else
    CHECKED="$CHECKED, images not readable in Provisioning"
  fi
  if [ "$1" = "$PS_PROVISIONING" ]; then
    ob_safe || refuse "the TrustZone perimeter option bytes are not wolfTrust's: run 'set-perimeter' in Open."
    CHECKED="$CHECKED, perimeter values"
    return 0
  fi
  ob_safe wrp || refuse "the perimeter or guest WRP option bytes are not wolfTrust's: run 'set-perimeter' and 'set-wrp' in Open."
  CHECKED="$CHECKED, perimeter and guest WRP values"
  # Locked too: the read-back after every closing write needs DA discovery.
  if da_production_ready; then
    CHECKED="$CHECKED, production DA credential"
  else
    [ "${WT_PRODUCTION_LOCK:-0}" != "1" ] || da_refuse_sample
    CHECKED="$CHECKED, DA credential is ST's sample or unset (a production lock refuses it)"
  fi
  da_ready || refuse "Debug Authentication is not provisioned (no intact OBK offering Full Regression): run 'provision-da' and 'discover'."
  # Regression wipes the DA, so the one on the part must be this tool's install
  # of the rehearsed credentials since that rehearsal; discovery cannot tell.
  dp="$(cat "$state_dir/da-provisioned" 2>/dev/null || true)"
  dt="$(field time "$dp")"; rt="$(field completed "$rec")"
  if [ "$(field cred "$dp")" != "$(port_cred_fp)" ] || [ "${dt:-0}" -lt "${rt:-0}" ]; then
    refuse "the DA on this part was not installed by 'provision-da' with these credentials since the rehearsal: run 'provision-da'."
  fi
  CHECKED="$CHECKED, DA provisioned with the rehearsed credentials"
}
port_lock_plan() { echo "$CLI -c port=SWD mode=HotPlug -ob PRODUCT_STATE=$1"; }
port_consequence() {
  case "$1" in
    0x5C) echo "debug closes for good, no regression or mass erase, and only a wolfBoot-signed update can change the firmware." ;;
    *) echo "Only a DA regression, which mass-erases the part, returns it to Open." ;;
  esac
}
port_lock_write() {
  uart_capture 12 "$wt_tmp/lock.log"
  "$CLI" -c port=SWD mode=HotPlug -ob PRODUCT_STATE="$1" 2>&1 | strip | tail -4 || true
  sleep 10
}
port_lock_verify() {
  local now
  if [ "$1" = "$PS_PROVISIONING" ]; then
    now="$(product_state || true)"
    [ "$now" = "$1" ] || fail "lock" "product state reads ${now:-unreadable} after the write, expected $1"
    return 0
  fi
  now="$(da_lifecycle || true)"
  [ "$now" = "$(st_lifecycle "$1")" ] ||
    fail "lock" "DA discovery reports ${now:-nothing} after the write, expected $(st_lifecycle "$1"); the write may still have landed, so do not repeat it"
  booted "$wt_tmp/lock.log" ||
    fail "lock" "the part is $(label "$1") but wolfTrust did not boot on $SERIAL; do not ship it"
  pass "wolfTrust chain boots in $(label "$1")"
}
