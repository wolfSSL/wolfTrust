#!/usr/bin/env bash
# test_provisioning_gates.sh
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

# Offline tests of the production lock gates in provisioning_ctrl.sh (STM32H5)
# and provisioning_ctrl_rt700.sh (MIMXRT700). Every vendor tool is a stub that
# records writes to a file; nothing here touches a board.
# shellcheck disable=SC2015  # result lines are "cond && pass || fail" on purpose
set -u
SRC="$(cd "$(dirname "$0")/../../.." && pwd)"
T="$(mktemp -d)" && [ -n "$T" ] && [ -d "$T" ] || { echo "cannot create a temporary directory" >&2; exit 1; }
trap 'rm -rf "$T"' EXIT
R="$T/repo"
mkdir -p "$R/build" "$R/wolfBoot" "$R/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr" \
    "$R/tests/firmware/zephyr-stm32h5/build/freertos_guest1" "$T/st" "$T/bin" "$T/venv/bin"
cp -R "$SRC/tests/target" "$R/tests/"
mkdir -p "$R/mk"; cp "$SRC/mk/target-mimxrt700.mk" "$R/mk/"
echo wb > "$R/wolfBoot/wolfboot.bin"; echo wt > "$R/build/wolftrust_v1_signed.bin"
echo g0 > "$R/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
echo g1 > "$R/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"
echo elf > "$R/build/wolftrust.elf"
mkdir -p "$R/build/rt700" "$R/tests/firmware/mimxrt700-baremetal/build"
echo rwb > "$R/build/rt700/flash_wolfboot.bin"
echo rg0 > "$R/tests/firmware/mimxrt700-baremetal/build/guest0.bin"
echo rg1 > "$R/tests/firmware/mimxrt700-baremetal/build/guest1.bin"
SD="$T/home/st-rot-h5/Projects/NUCLEO-H563ZI/ROT_Provisioning/DA"
mkdir -p "$SD/Binary" "$SD/Keys" "$SD/Certificates" "$T/prodda"
echo sobk > "$SD/Binary/DA_Config.obk"; echo spwd > "$SD/Binary/password.bin"
echo skey > "$SD/Keys/key_3_leaf.pem"; echo scert > "$SD/Certificates/cert_leaf_chain.b64"
echo pobk > "$T/prodda/obk"; echo pkey > "$T/prodda/key"; echo pcert > "$T/prodda/cert"; echo ppwd > "$T/prodda/pwd"
echo pkey2 > "$T/prodda/key2"
mkdir -p "$T/flash"

# STM32 CLI stub: state in $T/ps, $T/wrp; logs writes to $T/writes.
cat > "$T/bin/stcli" <<EOF
#!/usr/bin/env bash
ps=\$(cat $T/ps)
args=("\$@")
for i in "\${!args[@]}"; do
  if [ "\${args[\$i]}" = "-u" ]; then cp "$T/flash/\${args[\$((i+1))]}" "\${args[\$((i+3))]}"; read_done=1; fi
  if [ "\${args[\$i]}" = "-r32" ]; then
    if [ "\$ps" = 0xED ] && [[ " \$* " == *" mode=UR "* ]]; then echo "0x08FFF800 : \$(cat $T/uid)"; else echo "0x08FFF800 : 00000000 00000000 00000000"; fi; exit 0; fi
done
[ -z "\${read_done:-}" ] || exit 0
for a in "\$@"; do
  case "\$a" in
    displ) case "\$ps" in 0x72|0xC6|0x5C) echo "Error: Cannot connect to access port 1!"; exit 1 ;; esac
           echo "     PRODUCT_STATE: \$ps"; echo "     TZEN         : \$(cat $T/tzen) (Trust zone)"
           echo "     BOOT_UBE     : 0xB4 (OEM-iRoT)"; echo "     SWAP_BANK    : 0x0 (0x0)"
           echo "     SECBOOTADD   : 0x\$RANDOM (0x0)"
           echo "     SECWM1_STRT  : 0x0 (0x8000000)"; echo "     SECWM1_END   : 0x4F  (0x809E000)"
           echo "     SECWM2_STRT  : 0x0 (0x8100000)"; echo "     SECWM2_END   : 0x7F  (0x81FE000)"
           echo "     WRPSGn1      : \$(cat $T/wrp) (0x\$RANDOM)" ;;
    debugauth=2) case "\$ps" in 0xED) l=OPEN ;; 0x17) l=PROVISIONING ;; 0xC6) l=TZ_CLOSED ;; 0x72) l=CLOSED ;; 0x5C) l=LOCKED ;; *) exit 1 ;; esac
           echo "discovery: PSA lifecycle...................:ST_LIFECYCLE_\$l"
           echo "discovery: ST provisioning integrity status:\$(cat $T/da)"
           [ "\$(cat $T/da)" = 0xeaeaeaea ] && echo "discovery: permission if authorized........:(a/14) ==> Full Regression"; true ;;
    debugauth=1) [ -e $T/noregress ] || echo 0xED > $T/ps; echo "Debug Authentication Success" ;;
    -sdp) echo 0xeaeaeaea > $T/da; echo "OBKey Provisioned successfully" ;;
    PRODUCT_STATE=*) echo "\$a" >> $T/writes; [ -e $T/stuck ] || echo "\${a#PRODUCT_STATE=}" > $T/ps; [ ! -e $T/boots ] || echo "guest0_psa heartbeat" >> $T/uart; echo "Error: failed to reconnect after reset !"; exit 1 ;;
  esac
done
EOF
printf '#!/bin/sh\nshift\nexec "$@"\n' > "$T/bin/timeout"; chmod +x "$T/bin/timeout"
echo "guest0_psa heartbeat" > "$T/uart"; touch "$T/boots"; echo 0xf5f5f5f5 > "$T/da"
# blhost stub: fuses in $T/fuse.<index-decimal>; batch logs to $T/writes.
cat > "$T/venv/bin/blhost" <<EOF
#!/usr/bin/env bash
while [ "\${1:-}" != "efuse-read-once" ] && [ "\${1:-}" != "batch" ] && [ \$# -gt 0 ]; do shift; done
case "\$1" in
  efuse-read-once) i=\$((\$2)); v=\$(cat $T/fuse.\$i 2>/dev/null || echo 0)
    printf '{"command":"efuse-read-once","response":[4,%d],"status":{"value":0}}\n' \$((v)) ;;
  batch) cat "\$2" >> $T/writes
    while read -r c a d _; do i=\$((a)); o=\$(cat $T/fuse.\$i 2>/dev/null || echo 0)
      echo \$(( o | 0x\$d )) > $T/fuse.\$i; [ ! -e $T/batchfail ] || exit 1; done < "\$2" ;;
esac
EOF
cat > "$T/venv/bin/pyocd" <<EOF
#!/bin/sh
if [ "\$1" = cmd ]; then cat "$T/sfp" 2>/dev/null; exit 0; fi
[ "\$1" = list ] || exit 0
echo "  #   Probe/Board   Unique ID   Target"
echo "-----------------------------------"
n=0; for u in \$(cat $T/probe 2>/dev/null); do echo "  \$n   NXP MCU-LINK on-board   \$u   n/a"; n=\$((n+1)); done
EOF
echo PROBEA > "$T/probe"
cp "$T/bin/timeout" "$T/venv/bin/timeout"
printf '#!/bin/sh\nexec %s "$@"\n' "$(command -v python3)" > "$T/venv/bin/python"; chmod +x "$T/venv/bin/python"
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
subst() { sed "s/$1/$2/" "$3" > "$3.tmp" && mv "$3.tmp" "$3"; }
have_expect=0; command -v expect >/dev/null 2>&1 && have_expect=1
chmod +x "$T/bin/stcli" "$T/venv/bin/blhost" "$T/venv/bin/pyocd"

pass=0; failn=0
check() { # check <name> <expected-rc> <grep-in-output> -- cmd...
  local name="$1" want="$2" pat="$3"; shift 4
  out="$("$@" 2>&1 </dev/null)"; rc=$?
  if [ "$rc" = "$want" ] && grep -q -- "$pat" <<<"$out"; then pass=$((pass+1)); echo "ok   $name"
  else failn=$((failn+1)); echo "FAIL $name (rc=$rc want=$want)"; echo "$out" | sed 's/^/     /' | tail -6; fi
}
field_of() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" "$2"; }
nowrite() { if [ -s "$T/writes" ]; then failn=$((failn+1)); echo "FAIL a refusal wrote: $(cat "$T/writes")"; : > "$T/writes"; fi; }

P="$R/tests/target/provisioning/provisioning_ctrl.sh"
H5=(env TARGET=stm32h563 HOME="$T/home" PATH="$T/bin:$PATH" STM32_CLI="$T/bin/stcli" H5_SERIAL="$T/uart" WT_PROVISION_STATE="$T/st" "$P")
HS="$T/st/stm32h563"
dafp() { for f in "$@"; do sha < "$f"; done | sha | cut -c1-64; }
SFP="$(dafp "$SD/Keys/key_3_leaf.pem" "$SD/Certificates/cert_leaf_chain.b64" "$SD/Binary/DA_Config.obk" "$SD/Binary/password.bin")"
PFP="$(dafp "$T/prodda/key" "$T/prodda/cert" "$T/prodda/obk" "$T/prodda/pwd")"
MFP="$(dafp "$T/prodda/key" "$T/prodda/cert" "$T/prodda/obk" "$SD/Binary/password.bin")"
flashsync() { cp "$R/wolfBoot/wolfboot.bin" "$T/flash/0x0C000000"; cp "$R/build/wolftrust_v1_signed.bin" "$T/flash/0x0C060000"
  cp "$R/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin" "$T/flash/0x080A0000"
  cp "$R/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin" "$T/flash/0x080E0000"; }
flashsync
PROD=(WT_DA_OBK="$T/prodda/obk" WT_DA_KEY="$T/prodda/key" WT_DA_CERT="$T/prodda/cert" WT_DA_PWD="$T/prodda/pwd")
: > "$T/writes"; echo 0xED > "$T/ps"; echo 0x000FFFFF > "$T/wrp"; echo 0xB4 > "$T/tzen"; echo "00210045 33325112 38363236" > "$T/uid"
UID1=002100453332511238363236

echo "== shared"
check "help lists the port's states" 0 "0x72   closed" -- "${H5[@]}" help
check "a port file refuses to run alone" 2 "not this port file" -- bash "$R/tests/target/provisioning/provisioning_ctrl_stm32h563.sh" lock 0x72
check "the other port file too" 2 "not this port file" -- bash "$R/tests/target/provisioning/provisioning_ctrl_mimxrt700.sh" lock 0x07
check "unknown port"         2 "no provisioning port for TARGET=nope" -- env TARGET=nope "$P" help
check "unknown state"        2 "unknown state '0x99'" -- "${H5[@]}" lock 0x99
check "no state"             2 "unknown state ''" -- "${H5[@]}" lock
check "start state is not a lock target" 2 "open (0xED) is not a lock target" -- "${H5[@]}" lock open
check "permanent state has no mock" 2 "locked (0x5C) has no mock" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance locked
check "writes need WT_LOCK_CONFIRM" 2 "writes to the board" -- "${H5[@]}" advance 0x17
nowrite

echo "== STM32H563"
check "lock skipping a state" 2 "runs only from provisioning (0x17)" -- "${H5[@]}" lock closed
check "lock unrehearsed"     2 "no rehearsal for provisioning (0x17)" -- "${H5[@]}" lock provisioning
check "advance Closed from Open" 2 "runs only from Provisioning" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
nowrite
echo x >> "$R/build/wolftrust_v1_signed.bin"
check "advance with host images not on the part" 2 "could not read back" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x17
[ "$(cat "$T/ps")" = 0xED ] && { pass=$((pass+1)); echo "ok   a failed read-back leaves the part in Open"; } || { failn=$((failn+1)); echo "FAIL part left in $(cat "$T/ps")"; }
nowrite
echo 0xeaeaeaea > "$T/da"; echo 0x17 > "$T/ps"
check "closing advance without a read-back" 2 "no recent read-back" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
echo 0xf5f5f5f5 > "$T/da"
echo wt > "$R/build/wolftrust_v1_signed.bin"; echo 0xED > "$T/ps"; : > "$T/writes"
check "advance by name reads the part back in Open" 0 "the images on device $UID1 match" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance provisioning
check "closed advance without DA" 2 "cannot be regressed" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
echo 0xeaeaeaea > "$T/da"
rm -f "$T/boots"
check "advance without a boot records nothing" 1 "no rehearsal recorded" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance 0x72
echo 0x17 > "$T/ps"; touch "$T/boots"
touch "$T/stuck"
check "a write that did not land records nothing" 1 "does not read back as closed (0x72)" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance closed
[ ! -e "$HS/pending" ] && { pass=$((pass+1)); echo "ok   no pending rehearsal for an unconfirmed state"; } || { failn=$((failn+1)); echo "FAIL pending after a stuck write"; }
rm -f "$T/stuck"
check "advance Closed, boot captured" 0 "rehearsal of closed (0x72) recorded" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" advance closed
: > "$T/writes"
check "lock while Closed (link down)" 2 "cannot read the product state" -- "${H5[@]}" lock 0x5C
touch "$T/noregress"; cp "$HS/pending" "$T/pending.keep"
check "a failed regression exits nonzero" 1 "nothing was recorded" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" regress
[ ! -e "$HS/rehearsal-0x72" ] && { pass=$((pass+1)); echo "ok   a failed regression records no rehearsal"; } || { failn=$((failn+1)); echo "FAIL rehearsal after failed regress"; }
rm -f "$T/noregress"; cp "$T/pending.keep" "$HS/pending"
check "regress completes the rehearsal" 0 "rehearsal of closed (0x72) complete" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" regress
grep -q " id=$UID1 .* cred=$SFP " "$HS/rehearsal-0x72" && { pass=$((pass+1)); echo "ok   rehearsal binds UID and every DA input"; } || { failn=$((failn+1)); echo "FAIL record: $(cat "$HS/rehearsal-0x72")"; }
check "a second regress records nothing stale" 0 "state after regression" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" regress
[ "$(grep -c . "$HS/rehearsal-0x72")" = 1 ] && [ ! -e "$HS/pending" ] && { pass=$((pass+1)); echo "ok   no pending rehearsal survives a regress"; } || { failn=$((failn+1)); echo "FAIL stale pending"; }
check "lock 0x17 preview on the rehearsed part" 2 "same part $UID1, images read back, perimeter values" -- "${H5[@]}" lock 0x17
echo "11111111 22222222 33333333" > "$T/uid"
check "lock on another part" 2 "is not the one rehearsed" -- "${H5[@]}" lock 0x17
echo "00210045 33325112 38363236" > "$T/uid"
echo bad > "$T/flash/0x080A0000"
check "lock with different flash" 2 "differ from the rehearsed build" -- "${H5[@]}" lock 0x17
flashsync
echo 0xC3 > "$T/tzen"
check "option bytes changed since the rehearsal" 2 "no rehearsal for" -- "${H5[@]}" lock 0x17
cp "$HS/rehearsal-0x72" "$T/keep"
obnow="$(env PATH="$T/bin:$PATH" "$T/bin/stcli" -ob displ | awk '$1 ~ /^(TZEN|BOOT_UBE|SWAP_BANK|SECWM[12]_(STRT|END)|WRPSGn1)$/ && $2 == ":" { print $1 "=" $3 }' | sort | sha | cut -c1-64)"
subst "ob=[0-9a-f]*" "ob=$obnow" "$HS/rehearsal-0x72"
check "consistent but unsafe perimeter" 2 "perimeter option bytes are not wolfTrust's" -- "${H5[@]}" lock 0x17
cp "$T/keep" "$HS/rehearsal-0x72"; echo 0xB4 > "$T/tzen"
subst "completed=[0-9]*" "completed=$(( $(date +%s) - 7200 ))" "$HS/rehearsal-0x72"
check "expired rehearsal"    2 "in the last 3600s" -- "${H5[@]}" lock 0x17
cp "$T/keep" "$HS/rehearsal-0x72"
nowrite
echo 0x17 > "$T/ps"
check "closing preview before provision-da" 2 "not installed by 'provision-da'" -- "${H5[@]}" lock 0x72
check "provision-da records the install" 0 "DA provisioned and recorded" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" provision-da
check "closing preview: identity unreadable, sample DA noted" 2 "identity not readable here (needs WT_FIXTURE_BOUND=1)" -- "${H5[@]}" lock 0x72
check "closing preview lists DA checks" 2 "DA credential is ST's sample or unset" -- "${H5[@]}" lock closed
check "Locked preview"       2 "provisioning (0x17) -> locked (0x5C)" -- "${H5[@]}" lock locked
echo 0xf5f5f5f5 > "$T/da"
check "Locked without DA"    2 "Debug Authentication is not provisioned" -- "${H5[@]}" lock locked
echo 0xeaeaeaea > "$T/da"
check "closing lock without a bound fixture" 2 "set WT_FIXTURE_BOUND=1 there" -- env WT_LOCK_CONFIRM=1 "${H5[@]}" lock 0x72
check "no production opt-in" 2 "Only a production station" -- env WT_FIXTURE_BOUND=1 WT_LOCK_CONFIRM=1 "${H5[@]}" lock 0x72
check "production lock with ST sample DA" 2 "needs its own DA credential" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
check "production DA set to sample copies" 2 "needs its own DA credential" -- env WT_DA_OBK="$SD/Binary/DA_Config.obk" WT_DA_KEY="$SD/Keys/key_3_leaf.pem" WT_DA_CERT="$SD/Certificates/cert_leaf_chain.b64" WT_DA_PWD="$SD/Binary/password.bin" WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
check "production provision-da with sample" 2 "needs its own DA credential" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" provision-da
check "rehearsed with sample, locking with production DA" 2 "no rehearsal for" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
subst "cred=$SFP" "cred=$MFP" "$HS/rehearsal-0x72"
check "production DA without WT_DA_PWD" 2 "needs its own DA credential" -- env WT_DA_OBK="$T/prodda/obk" WT_DA_KEY="$T/prodda/key" WT_DA_CERT="$T/prodda/cert" WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
subst "cred=$MFP" "cred=$PFP" "$HS/rehearsal-0x72"
check "DA key swapped after the rehearsal" 2 "no rehearsal for" -- env "${PROD[@]}" WT_DA_KEY="$T/prodda/key2" "${H5[@]}" lock 0x72
check "DA installed with other credentials" 2 "not installed by 'provision-da'" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
env WT_LOCK_CONFIRM=1 "${PROD[@]}" "${H5[@]}" provision-da >/dev/null
subst "time=[0-9]*" "time=$(( $(field_of completed "$HS/rehearsal-0x72") - 10 ))" "$HS/da-provisioned"
check "DA provisioned before the rehearsal" 2 "not installed by 'provision-da'" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
env WT_LOCK_CONFIRM=1 "${PROD[@]}" "${H5[@]}" provision-da >/dev/null
check "production DA preview" 2 "production DA credential" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
check "piped confirmation"   2 "interactive terminal" -- env "${PROD[@]}" WT_FIXTURE_BOUND=1 WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${H5[@]}" lock 0x72
check "TZ-Closed unrehearsed" 2 "no rehearsal for tz-closed" -- env "${PROD[@]}" "${H5[@]}" lock 0xC6
echo x >> "$R/build/wolftrust_v1_signed.bin"
check "rebuilt images"       2 "no rehearsal for" -- env "${PROD[@]}" "${H5[@]}" lock 0x72
echo wt > "$R/build/wolftrust_v1_signed.bin"
nowrite
if [ "$have_expect" = 1 ]; then
H5X="env TARGET=stm32h563 HOME=$T/home WT_DA_OBK=$T/prodda/obk WT_DA_KEY=$T/prodda/key WT_DA_CERT=$T/prodda/cert WT_DA_PWD=$T/prodda/pwd PATH=$T/bin:$PATH STM32_CLI=$T/bin/stcli H5_SERIAL=$T/uart WT_PROVISION_STATE=$T/st WT_FIXTURE_BOUND=1 WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
for phrase in "yes" "LOCK 0x72" "I ACCEPT 0x5C" "i accept 0x72"; do
  expect -c "set timeout 300; spawn $H5X lock 0x72; expect \"to continue: \"; send \"$phrase\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
  rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   wrong phrase '$phrase' refused"; } || { failn=$((failn+1)); echo "FAIL phrase '$phrase' rc=$rc"; }
done
rm -f "$T/boots"
out="$(expect -c "set timeout 300; spawn $H5X lock 0x72; expect \"to continue: \"; send \"I ACCEPT 0x72\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 1 ] && grep -q "wolfTrust did not boot" <<<"$out" && [ -e "$HS/rehearsal-0x72" ] && { pass=$((pass+1)); echo "ok   stale UART markers without a post-write boot fail the lock and keep the rehearsal"; } || { failn=$((failn+1)); echo "FAIL no-boot lock rc=$rc"; echo "$out" | tail -4; }
touch "$T/boots"; : > "$T/writes"; echo 0x17 > "$T/ps"; cp "$HS/rehearsal-0x72" "$T/keep72"
echo 0xED > "$T/ps"
out="$(expect -c "set timeout 300; spawn $H5X lock 0x17; expect \"to continue: \"; exec sh -c {echo 11111111 22222222 33333333 > $T/uid}; send \"I ACCEPT 0x17\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && grep -q "different part is attached" <<<"$out" && { pass=$((pass+1)); echo "ok   a part swapped during the prompt is not written"; } || { failn=$((failn+1)); echo "FAIL swap during prompt rc=$rc writes=$(cat "$T/writes")"; echo "$out" | tail -4; }
echo "00210045 33325112 38363236" > "$T/uid"; : > "$T/writes"
out="$(expect -c "set timeout 300; spawn $H5X lock 0x17; expect \"to continue: \"; exec sh -c {echo x >> $R/build/wolftrust_v1_signed.bin}; send \"I ACCEPT 0x17\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && grep -q "no longer matches" <<<"$out" && { pass=$((pass+1)); echo "ok   images changed during the prompt are not written"; } || { failn=$((failn+1)); echo "FAIL image change rc=$rc"; echo "$out" | tail -3; }
echo wt > "$R/build/wolftrust_v1_signed.bin"
out="$(expect -c "set timeout 300; spawn $H5X lock 0x17; expect \"to continue: \"; exec sh -c {sed -i.bak s/completed=.*/completed=1/ $HS/rehearsal-0x72}; send \"I ACCEPT 0x17\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && grep -q "no longer matches" <<<"$out" && { pass=$((pass+1)); echo "ok   a rehearsal that expires during the prompt is not used"; } || { failn=$((failn+1)); echo "FAIL expiry rc=$rc"; echo "$out" | tail -3; }
cp "$T/keep72" "$HS/rehearsal-0x72"; rm -f "$HS/rehearsal-0x72.bak"; echo 0x17 > "$T/ps"; : > "$T/writes"
out="$(expect -c "set timeout 300; spawn $H5X lock 0x72; expect \"to continue: \"; send \"I ACCEPT 0x72\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/writes")" = "PRODUCT_STATE=0x72" ] && grep -q "STM32H563 is closed (0x72)" <<<"$out" && [ ! -e "$HS/rehearsal-0x72" ] && { pass=$((pass+1)); echo "ok   exact phrase writes Closed (stub) and consumes the rehearsal"; } || { failn=$((failn+1)); echo "FAIL exact phrase rc=$rc writes=$(cat "$T/writes")"; echo "$out" | tail -5; }
: > "$T/writes"; echo 0x17 > "$T/ps"; cp "$T/keep72" "$HS/rehearsal-0x72"
out="$(expect -c "set timeout 300; spawn $H5X lock 0x5C; expect \"to continue: \"; send \"I ACCEPT 0x5C\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/writes")" = "PRODUCT_STATE=0x5C" ] && grep -q "STM32H563 is locked (0x5C)" <<<"$out" && [ ! -e "$HS/rehearsal-0x72" ] && { pass=$((pass+1)); echo "ok   Locked (stub) consumes the Closed rehearsal it used"; } || { failn=$((failn+1)); echo "FAIL Locked consume rc=$rc writes=$(cat "$T/writes")"; echo "$out" | tail -5; }
: > "$T/writes"; echo 0x17 > "$T/ps"
else
  echo "skip typed confirmation tests (no expect)"
  rm -f "$HS"/rehearsal-*
fi
check "a consumed rehearsal cannot lock again" 2 "no rehearsal for" -- env "${PROD[@]}" "${H5[@]}" lock 0x5C
nowrite

echo "== MIMXRT700"
RT=(env TARGET=mimxrt700 RT700_SPSDK_VENV="$T/venv" WT_PROVISION_STATE="$T/st" PATH="$T/venv/bin:$PATH" "$P")
RS="$T/st/mimxrt700"
ISP=(RT700_ISP="-u 0x1fc9,0x014f")
fuse() { echo "$2" > "$T/fuse.$(($1))"; }
edig() {
  local a f
  for a in 0x28000000:build/rt700/flash_wolfboot.bin 0x28040000:build/wolftrust_v1_signed.bin \
           0x28080000:tests/firmware/mimxrt700-baremetal/build/guest0.bin \
           0x28100000:tests/firmware/mimxrt700-baremetal/build/guest1.bin; do
    f="$R/${a#*:}"; printf '%s %s\n' "${a%%:*}" "$(wc -c < "$f" | tr -d ' ')"; cat "$f"
  done | sha | cut -c1-64
}
# rec <state> <fused> <image> <fence> <completed> [probe]
rec() { mkdir -p "$RS"; echo "state=$1 run=r id=${6:-PROBEA} image=$3 fused=$2 fence=$4 time=$5 cred=none completed=$5" > "$RS/rehearsal-$1"; }
now() { date +%s; }
rm -f "$T"/fuse.*; fuse 0x8F 0x03; fuse 0x25 0x03
check "help lists the port's states" 0 "in-field-locked" -- "${RT[@]}" help
for m in 0 0x0 0x4 0x7 junk; do
  check "RT700_GUEST_MASK=$m refused" 2 "RT700_GUEST_MASK must be" -- env RT700_GUEST_MASK="$m" WT_LOCK_CONFIRM=1 "${RT[@]}" advance 0x07
done
# sfp <MGC> <FRAD2 last> <FRAD2 word3> [extra descriptor line]
sfp() {
  printf '50184900:  a000c000\n50184920:  %s\n' "$1"
  printf '50184800:  28000000 2803ffff 00000000 a0000000\n50184820:  28040000 2807ffff 00000007 a0000000\n'
  printf '50184840:  28080000 %s 00000000 %s\n50184860:  28140000 2bffffff 00000007 a0000000\n' "$2" "$3"
  printf '%s\n' "${4:-50184880:  00000000 00000000 00000000 20000000}"
}
sfp a8000400 2813ffff a0000000 > "$T/sfp"
check "verify-wrp: wolfBoot's fence" 0 "armed FRAD2" -- "${RT[@]}" verify-wrp
sfp 28000400 2813ffff a0000000 > "$T/sfp"
check "verify-wrp: SFP not valid" 1 "SFP not sealed" -- "${RT[@]}" verify-wrp
sfp a8000000 2813ffff a0000000 > "$T/sfp"
check "verify-wrp: SFP not locked" 1 "SFP not sealed" -- "${RT[@]}" verify-wrp
sfp a8000400 2813ffff 80000000 > "$T/sfp"
check "verify-wrp: fence descriptor unlocked" 1 "FRAD2 .* touches the guest windows" -- "${RT[@]}" verify-wrp
sfp a8000400 2813ffff a0000000 "50184880:  28100000 2810ffff 00000007 a0000000" > "$T/sfp"
check "verify-wrp: writable overlap" 1 "FRAD4 .* touches the guest windows" -- "${RT[@]}" verify-wrp
sfp a8000400 280fffff a0000000 > "$T/sfp"
check "verify-wrp: gap in the fence" 1 "covers 0x28100000" -- "${RT[@]}" verify-wrp
rm -f "$T/sfp"
check "no ISP"               2 "set RT700_ISP" -- "${RT[@]}" lock 0x07
check "skip ahead"           2 "runs only from develop2 (0x07)" -- env "${ISP[@]}" "${RT[@]}" lock in-field
fuse 0x25 0x07
check "copies disagree"      2 "disagree" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
fuse 0x8F 0x00030003; fuse 0x25 0x00030003
check "A0/A1 protection copies"  2 "only the B0 burn encoding" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
fuse 0x8F 0x03; fuse 0x25 0x03
check "unrehearsed"          2 "no rehearsal for develop2" -- env "${ISP[@]}" "${RT[@]}" lock develop2
rec 0x07 0x03 0000 armed "$(now)"
check "rehearsed other images" 2 "no rehearsal for" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
G="$R/tests/firmware/mimxrt700-baremetal/build"
rec 0x07 0x03 "$(edig)" armed "$(now)"
printf 'rg0\nr' > "$G/guest0.bin"; printf 'g1\n' > "$G/guest1.bin"
check "bytes moved between images" 2 "no rehearsal for" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
echo rg0 > "$G/guest0.bin"; echo rg1 > "$G/guest1.bin"
rec 0x07 0x03 "$(edig)" armed $(( $(now) - 7200 ))
check "stale rehearsal"      2 "in the last 3600s" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x07 0x03 "$(edig)" armed $(( $(now) + 600 ))
check "future-dated rehearsal" 2 "in the last 3600s" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x07 0x03 "$(edig)" open "$(now)"
check "rehearsed without the guest fence" 2 "no rehearsal for" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x07 0x03 "$(edig)" armed "$(now)" PROBEB
check "rehearsed through another probe" 2 "no rehearsal for" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
rec 0x07 0x03 "$(edig)" armed "$(now)"
: > "$T/probe"
check "no probe attached"    2 "no rehearsal for" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
echo PROBEA > "$T/probe"
check "Develop2 preview"     2 "efuse-program-once 0x8F 00000007" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
check "SPSDK venv off PATH"  2 "efuse-program-once 0x8F 00000007" -- env "${ISP[@]}" TARGET=mimxrt700 RT700_SPSDK_VENV="$T/venv" WT_PROVISION_STATE="$T/st" PATH="$T/bin:/usr/bin:/bin" "$P" lock 0x07
check "SPSDK installed system-wide" 2 "efuse-program-once 0x8F 00000007" -- env "${ISP[@]}" TARGET=mimxrt700 RT700_SPSDK_VENV="$T/no-venv" WT_PROVISION_STATE="$T/st" PATH="$T/venv/bin:$T/bin:/usr/bin:/bin" "$P" lock 0x07
check "preview names the probe" 2 "same debug probe PROBEA" -- env "${ISP[@]}" "${RT[@]}" lock 0x07
check "burn without a bound fixture" 2 "set WT_FIXTURE_BOUND=1 there" -- env WT_LOCK_CONFIRM=1 "${ISP[@]}" "${RT[@]}" lock 0x07
check "no production opt-in" 2 "Only a production station" -- env WT_FIXTURE_BOUND=1 WT_LOCK_CONFIRM=1 "${ISP[@]}" "${RT[@]}" lock 0x07
check "piped confirmation"   2 "interactive terminal" -- env WT_FIXTURE_BOUND=1 WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${ISP[@]}" "${RT[@]}" lock 0x07
check "lock takes one state" 2 "lock takes one state" -- env "${ISP[@]}" "${RT[@]}" lock 0x07 fuses.yaml
check "fuse burn commands refused" 2 "programs OTP fuses" -- "${RT[@]}" burn
nowrite
if [ "$have_expect" = 1 ]; then
RTX="env WT_FIXTURE_BOUND=1 TARGET=mimxrt700 RT700_SPSDK_VENV=$T/venv WT_PROVISION_STATE=$T/st PATH=$T/venv/bin:$PATH RT700_ISP=-u0x1fc9,0x014f WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
expect -c "set timeout 300; spawn $RTX lock 0x07; expect \"to continue: \"; send \"BURN 0x07\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   old phrase refused"; } || { failn=$((failn+1)); echo "FAIL old phrase rc=$rc"; }
out="$(expect -c "set timeout 300; spawn $RTX lock 0x07; expect \"to continue: \"; exec sh -c {echo PROBEB > $T/probe}; send \"I ACCEPT 0x07\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && grep -q "no longer matches" <<<"$out" && { pass=$((pass+1)); echo "ok   a probe swapped during the prompt is not burned"; } || { failn=$((failn+1)); echo "FAIL probe swap rc=$rc"; echo "$out" | tail -3; }
echo PROBEA > "$T/probe"
expect -c "set timeout 300; spawn $RTX lock 0x07; expect \"to continue: \"; send \"I ACCEPT 0x07\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/fuse.143")" = 7 ] && [ "$(cat "$T/fuse.37")" = 7 ] && [ ! -e "$RS/rehearsal-0x07" ] && { pass=$((pass+1)); echo "ok   exact phrase burns Develop2 (stub) and consumes the rehearsal"; } || { failn=$((failn+1)); echo "FAIL exact phrase rc=$rc"; }
[ "$(head -1 "$T/writes" | cut -d' ' -f2)" = 0x25 ] && { pass=$((pass+1)); echo "ok   life cycle words burn RED then LC"; } || { failn=$((failn+1)); echo "FAIL order"; }
: > "$T/writes"; fuse 0x8F 0x03; fuse 0x25 0x03; touch "$T/batchfail"
rec 0x07 0x03 "$(edig)" armed "$(now)"
out="$(expect -c "set timeout 300; spawn $RTX lock 0x07; expect \"to continue: \"; send \"I ACCEPT 0x07\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 1 ] && grep -q "batch failed part way" <<<"$out" && grep -q "fuses read LC 0x00000003, RED 0x00000007" <<<"$out" && { pass=$((pass+1)); echo "ok   a burn that fails part way still reads both words back"; } || { failn=$((failn+1)); echo "FAIL partial burn rc=$rc"; echo "$out" | tail -4; }
rm -f "$T/batchfail" "$RS/rehearsal-0x07"; fuse 0x8F 0x07; fuse 0x25 0x07; : > "$T/writes"
else
  echo "skip typed burn tests (no expect)"; fuse 0x8F 0x07; fuse 0x25 0x07
fi
check "the next step after the burn" 2 "runs only from in-field (0x0F)" -- env "${ISP[@]}" "${RT[@]}" lock in-field-locked
rec 0x0F 0x07 "$(edig)" armed "$(now)"
check "In Field refused until ROM authentication" 2 "needs the BootROM to authenticate wolfBoot" -- env "${ISP[@]}" "${RT[@]}" lock in-field
nowrite
echo "provisioning gates: $pass passed, $failn failed"
[ "$failn" = 0 ]
