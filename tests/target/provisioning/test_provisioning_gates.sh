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

# Offline tests of the production lock gates in provisioning_ctrl.sh and its
# STM32H563, MIMXRT700, MCXN947 and STM32L562 port files. Every vendor tool is
# a stub that records writes to a file; nothing here touches a board.
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
echo "\$*" >> $T/pyocd_calls
if [ "\$1" = cmd ]; then
  # With a register file (MCXN947), answer each read32 from it and give a
  # savemem a blank page; else the RT700 SFP dump.
  if [ -s "$T/mcxn_regs" ]; then
    for a in "\$@"; do
      case "\$a" in
        "read32 "*) k=\$(printf '%08x' "\${a#read32 }" 2>/dev/null || echo 0)
          v=\$(awk -v k="\$k" '\$1 == k { print \$2 }' "$T/mcxn_regs")
          echo "\$k:  \${v:-00000000}" ;;
        "savemem "*) set -- \$a
          head -c "\$3" /dev/zero | tr '\\000' '\\377' > "\$4"
          # A failed read: the file is written but the commander reports an
          # error, ahead of a long log, and still exits 0.
          if [ -e "$T/savemem_err" ]; then echo "Error: memory transfer fault"
            printf '%02000000d\\n' 0; fi ;;
      esac
    done
    exit 0
  fi
  cat "$T/sfp" 2>/dev/null; exit 0
fi
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
# SPSDK stubs for the MCXN947 lock preview: pfr parses a page into a YAML
# that names its source and exports that source back (a byte-true round
# trip); nxpfuses writes the fuse script for the named life cycle; every
# write-class command of pfr, nxpfuses and nxpdebugmbox is logged and fails.
cat > "$T/venv/bin/pfr" <<EOF
#!/usr/bin/env bash
sub="\$1"; shift
case "\$sub" in
  parse) while [ \$# -gt 0 ]; do case "\$1" in -b) b="\$2"; shift;; -o) o="\$2"; shift;; esac; shift; done
    printf 'family: mcxn947\\nsource: %s\\nsha: %s\\n' "\$b" "\$(sha256sum "\$b" | cut -c1-16)" > "\$o" ;;
  export) while [ \$# -gt 0 ]; do case "\$1" in -c) c="\$2"; shift;; -o) o="\$2"; shift;; esac; shift; done
    cp "\$(sed -n 's/^source: //p' "\$c")" "\$o" ;;
  get-template) while [ \$# -gt 0 ]; do case "\$1" in -o) o="\$2"; shift;; esac; shift; done
    printf 'family: mcxn947\\n' > "\$o" ;;
  *) echo "pfr \$sub \$*" >> $T/writes; exit 1 ;;
esac
EOF
cat > "$T/venv/bin/nxpfuses" <<EOF
#!/usr/bin/env bash
sub="\$1"; shift
case "\$sub" in
  fuses-script) while [ \$# -gt 0 ]; do case "\$1" in -c) c="\$2"; shift;; -o) o="\$2"; shift;; esac; shift; done
    case "\$(sed -n 's/.*"LIFECYCLE\\[7:0\\]": //p' "\$c")" in
      DEVELOP2) v=7 ;; IN_FIELD) v=F ;; *) exit 1 ;;
    esac
    printf '# Fuse LIFE_CYCLE, index 1 and value: 0x%s00000%s.\\nefuse-program-once 1 0x%s00000%s --no-verify\\n' "\$v" "\$v" "\$v" "\$v" > "\$o" ;;
  *) echo "nxpfuses \$sub \$*" >> $T/writes; exit 1 ;;
esac
EOF
cat > "$T/venv/bin/nxpdebugmbox" <<EOF
#!/usr/bin/env bash
case "\$*" in
  *"tool get-uuid"*) echo "The device UUID is: 11111111222222223333333344444444" ;;
  *) echo "nxpdebugmbox \$*" >> $T/writes; exit 1 ;;
esac
EOF
chmod +x "$T/bin/stcli" "$T/venv/bin/blhost" "$T/venv/bin/pyocd" "$T/venv/bin/pfr" "$T/venv/bin/nxpfuses" "$T/venv/bin/nxpdebugmbox"

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

echo "== MCXN947"
MX=(env TARGET=mcxn947 MCXN947_SPSDK_VENV="$T/venv" MCXN947_PROBE_UID=PROBEA MCXN947_WOLFBOOT_DIR="$R/wolfBoot" WT_PROVISION_STATE="$T/st" PATH="$T/venv/bin:$PATH" "$P")
MS="$T/st/mcxn947"
mkdir -p "$R/tests/firmware/mcxn947-baremetal/build"
echo mg0 > "$R/tests/firmware/mcxn947-baremetal/build/guest0.bin"
echo mg1 > "$R/tests/firmware/mcxn947-baremetal/build/guest1.bin"
# restore runs the hardware runner; here a stub that reports the probe it got.
printf '#!/bin/sh\necho "stub runner $1 probe=${MCXN947_PROBE_UID:-none}"\n' > "$R/tests/target/run_mcxn947_hardware.sh"
chmod +x "$R/tests/target/run_mcxn947_hardware.sh"
mdig() {
  local a f
  for a in 0x00000000:wolfBoot/wolfboot.bin 0x00040000:build/wolftrust_v1_signed.bin \
           0x00080000:tests/firmware/mcxn947-baremetal/build/guest0.bin \
           0x00100000:tests/firmware/mcxn947-baremetal/build/guest1.bin; do
    f="$R/${a#*:}"; printf '%s %s\n' "${a%%:*}" "$(wc -c < "$f" | tr -d ' ')"; cat "$f"
  done | sha | cut -c1-64
}
# mrec <state> <fused> <completed> [probe]: a rehearsal record of this part
mrec() { mkdir -p "$MS"; echo "state=$1 run=r id=11111111222222223333333344444444 image=$(mdig) fused=$2 fence=none probe=${4:-PROBEA} time=$3 cred=none completed=$3" > "$MS/rehearsal-$1"; }
# regs <LC_STATE> <LC_STATE_DP> [DAUTHSTATUS]: the words the pyocd stub answers
# (SYSCON life cycle, debug status, UUID, an intact handoff, the reset vector).
regs() {
  printf '50000980 %08x\n50000984 %08x\ne000efb8 %08x\n' $(($1)) $(($2)) $((${3:-0xAA})) > "$T/mcxn_regs"
  printf '01100000 11111111\n01100004 22222222\n01100008 33333333\n0110000c 44444444\n' >> "$T/mcxn_regs"
  printf '30030000 5742484f\n30030004 a8bdb7b0\n3003000c 00001000\n10040404 10040801\n' >> "$T/mcxn_regs"
}
regs 0x03 0x03
check "help lists the port's states" 0 "oem-secure-world" -- "${MX[@]}" help
check "the MCXN947 port file refuses to run alone" 2 "not this port file" -- bash "$R/tests/target/provisioning/provisioning_ctrl_mcxn947.sh" lock 0x07
for m in 0 0x4 junk; do
  check "MCXN947_GUEST_MASK=$m refused" 2 "MCXN947_GUEST_MASK must be" -- env MCXN947_GUEST_MASK="$m" WT_LOCK_CONFIRM=1 "${MX[@]}" advance 0x07
done
check "no guest flash fence is reported" 1 "no guest flash fence" -- "${MX[@]}" verify-wrp
check "lock refused: oem-closed by name" 2 "oem-closed (0x0F) is not a lock target" -- "${MX[@]}" lock oem-closed
check "lock refused: oem-locked" 2 "is not a lock target" -- "${MX[@]}" lock 0xCF
check "lock refused: oem-field-return" 2 "is not a lock target" -- "${MX[@]}" lock 0x1F
check "advance needs discover" 2 "run 'discover' first" -- env WT_LOCK_CONFIRM=1 "${MX[@]}" advance 0x07
check "status reads the life cycle and the UUID" 0 "device UUID      11111111222222223333333344444444" -- "${MX[@]}" status
regs 0x03 0x07
check "discover: copies disagree" 1 "life cycle copies disagree" -- "${MX[@]}" discover
regs 0x103 0x103
check "discover: bits above the state byte" 1 "above the state byte" -- "${MX[@]}" discover
regs 0xCF 0xCF
check "discover: no further rehearsal step" 1 "has no further rehearsal step" -- "${MX[@]}" discover
regs 0x03 0x03
check "discover stamps the life cycle and UUID" 0 "discovery stamped" -- "${MX[@]}" discover
check "advance past oem-secure-world needs a regress" 2 "prove 'regress' from oem-secure-world" -- env WT_LOCK_CONFIRM=1 "${MX[@]}" advance 0x0F
check "OTP writes refused" 2 "would program OTP" -- "${MX[@]}" burn
check "perimeter commands refused" 2 "has no MCXN947 form" -- "${MX[@]}" set-wrp
check "restore runs the hardware runner bound to the probe" 0 "stub runner positive probe=PROBEA" -- env WT_LOCK_CONFIRM=1 "${MX[@]}" restore
# Three probes and no id: every device command refuses loudly, never a
# silent empty read.
printf 'PROBEA\nPROBEB\nPROBEC\n' > "$T/probe"
check "status with three probes and no id refuses" 2 "set MCXN947_PROBE_UID" -- env -u MCXN947_PROBE_UID TARGET=mcxn947 MCXN947_SPSDK_VENV="$T/venv" WT_PROVISION_STATE="$T/st" PATH="$T/venv/bin:$PATH" "$P" status
check "status names the bound probe" 0 "debug probe      PROBEA" -- "${MX[@]}" status
check "discover stamps the probe" 0 "probe PROBEA" -- "${MX[@]}" discover
grep -q "PROBE=PROBEA" "$MS/discovery" && { pass=$((pass+1)); echo "ok   discovery records the probe"; } || { failn=$((failn+1)); echo "FAIL discovery lacks the probe"; }
: > "$T/pyocd_calls"
# The lock: previews the vendor write from the live pages and refuses it,
# with every confirmation supplied, on the hard-wired port constant.
check "lock needs a rehearsal" 2 "no rehearsal for oem-secure-world" -- "${MX[@]}" lock 0x07
mrec 0x07 0x03 "$(now)"
out="$("${MX[@]}" lock 0x07 2>&1)"; rc=$?
[ $rc = 2 ] && grep -q "preview only" <<<"$out" && grep -q "efuse-program-once 1 0x7000007 --no-verify" <<<"$out" && grep -q "pfr write: nothing" <<<"$out" && grep -q "hard-wired off" <<<"$out" && grep -q "CMPA/CFPA read and parsed" <<<"$out" && { pass=$((pass+1)); echo "ok   lock previews the fuse script and the pages, then stops"; } || { failn=$((failn+1)); echo "FAIL lock preview rc=$rc"; echo "$out" | tail -8; }
[ -s "$MS/lock-0x07/burn-0x07.bls" ] && [ -s "$MS/lock-0x07/cmpa.yaml" ] && [ -s "$MS/lock-0x07/pages.sha256" ] && { pass=$((pass+1)); echo "ok   the preview keeps the script, the parsed pages and their digests"; } || { failn=$((failn+1)); echo "FAIL preview artifacts missing"; }
if grep -q . "$T/pyocd_calls" && ! grep -v -- "-u PROBEA" "$T/pyocd_calls" | grep -q .; then pass=$((pass+1)); echo "ok   every pyocd call of the preview carried the probe id"; else failn=$((failn+1)); echo "FAIL a pyocd call ran without -u PROBEA: $(grep -v -- '-u PROBEA' "$T/pyocd_calls" | head -2)"; fi
mrec 0x07 0x03 "$(now)" PROBEB
check "a rehearsal on another probe is refused" 2 "no rehearsal for oem-secure-world" -- "${MX[@]}" lock 0x07
mrec 0x07 0x03 "$(now)"
check "lock refused with the production opt-in but no terminal" 2 "needs an interactive terminal" -- env WT_FIXTURE_BOUND=1 WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${MX[@]}" lock 0x07
if [ "$have_expect" = 1 ]; then
MXX="env TARGET=mcxn947 MCXN947_SPSDK_VENV=$T/venv MCXN947_PROBE_UID=PROBEA MCXN947_WOLFBOOT_DIR=$R/wolfBoot WT_PROVISION_STATE=$T/st PATH=$T/venv/bin:$PATH WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
out="$(expect -c "set timeout 300; spawn $MXX lock 0x07; expect \"to continue: \"; send \"I ACCEPT 0x07\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 2 ] && grep -q "hard-wired off in this port (MCXN947_LOCK_WRITE_ENABLED=0)" <<<"$out" && [ -e "$MS/rehearsal-0x07" ] && { pass=$((pass+1)); echo "ok   the exact phrase with every confirmation is still refused at the write"; } || { failn=$((failn+1)); echo "FAIL typed acceptance rc=$rc"; echo "$out" | tail -5; }
else
  echo "skip typed lock refusal (no expect)"
fi
nowrite
check "verify-pages: unchanged since the preview" 0 "cfpa-pong unchanged since the preview" -- "${MX[@]}" verify-pages
# A savemem that fails while the commander exits 0 must not let the previous
# readback stand in for the page.
touch "$T/savemem_err"
check "verify-pages: a failed read is never the earlier readback" 1 "cannot read cmpa over SWD" -- "${MX[@]}" verify-pages
rm -f "$T/savemem_err"
# From a part fused one step further, the closed states are still no lock
# target: the ladder stops them before any preview.
regs 0x07 0x07; mrec 0x0F 0x07 "$(now)"
check "lock refused: oem-closed from oem-secure-world" 2 "oem-closed (0x0F) is not a lock target" -- "${MX[@]}" lock 0x0F
regs 0x0F 0x0F; mrec 0xCF 0x0F "$(now)"
check "lock refused: oem-locked from oem-closed" 2 "oem-locked (0xCF) is not a lock target" -- "${MX[@]}" lock 0xCF
nowrite
rm -f "$T/mcxn_regs"

echo "== STM32L562"
# CubeProgrammer stub for the L5: option bytes in $T/l5/ob ("NAME VALUE"),
# memory words in $T/l5/mem, flash images in $T/l5flash/<address>; every
# option byte write and download is logged to $T/writes, every call to
# $T/l5/calls.
mkdir -p "$T/l5" "$T/l5flash"
cat > "$T/bin/l5cli" <<EOF
#!/usr/bin/env bash
[ -n "\${L5_NOLOG:-}" ] || echo "\$*" >> $T/l5/calls
rdp=\$(awk '\$1 == "RDP" { print \$2 }' $T/l5/ob)
args=("\$@")
if [ "\${1:-}" = -l ]; then
  n=0; for s in \$(cat $T/l5/sns 2>/dev/null); do
    printf 'ST-Link Probe %d :\n   ST-LINK SN  : %s\n   Board Name  : %s\n' \$n "\$s" "\$(cat $T/l5/board 2>/dev/null || echo STM32L562E-DK)"; n=\$((n+1)); done
  exit 0
fi
[ "\$rdp" != 0xCC ] || { echo "Error: No STM32 target found!"; exit 1; }
case "\$rdp:\$*" in 0x55:*mode=UR*|0xBB:*mode=UR*) echo "UR \$*" >> $T/l5/ur_above0; echo "Error: unable to connect under reset"; exit 1 ;; esac
for i in "\${!args[@]}"; do
  case "\${args[\$i]}" in
    -u) cp "$T/l5flash/\${args[\$((i+1))]}" "\${args[\$((i+3))]}" 2>/dev/null || exit 1; up=1 ;;
    -r32) a=\$(printf '%08x' "\${args[\$((i+1))]}")
      if [ "\$a" = 0bfa0590 ]; then echo "0x0BFA0590 : \$(cat $T/l5/uid)"
      else echo "0x\$(tr a-f A-F <<<"\$a") : \$(awk -v k="\$a" '\$1 == k { print \$2 }' $T/l5/mem)"; fi; exit 0 ;;
    -ob) if [ "\${args[\$((i+1))]}" = displ ]; then
        awk '{ printf "     %-12s : %s (x)\n", \$1, \$2 }' $T/l5/ob; exit 0; fi
      echo "OB \${args[*]:\$((i+1))}" >> $T/writes
      [ -e $T/l5/obstuck ] || for kv in "\${args[@]:\$((i+1))}"; do
        awk -v k="\${kv%%=*}" -v v="\${kv#*=}" '\$1 == k { \$2 = v } { print }' $T/l5/ob > $T/l5/ob.new && mv $T/l5/ob.new $T/l5/ob; done
      echo "Option Bytes successfully programmed"; exit 0 ;;
    -d|-e) echo "WRITE \${args[*]}" >> $T/writes; exit 0 ;;
  esac
done
[ -z "\${up:-}" ] || exit 0
echo "ok"
EOF
chmod +x "$T/bin/l5cli"
l5ob() {
  printf '%s\n' "RDP ${1:-0xAA}" "TZEN ${2:-0x1}" SECWM1_PSTRT\ 0x0 SECWM1_PEND\ 0x7F \
    SECWM2_PSTRT\ 0x0 "SECWM2_PEND ${3:-0x3F}" SECBOOTADD0\ 0x180000 "BOOT_LOCK ${4:-0x1}" \
    DBANK\ 0x1 SWAP_BANK\ 0x0 WRP1A_PSTRT\ 0x7F WRP1A_PEND\ 0x0 WRP1B_PSTRT\ 0x7F WRP1B_PEND\ 0x0 \
    "WRP2A_PSTRT ${5:-0x40}" "WRP2A_PEND ${6:-0x7F}" "WRP2B_PSTRT ${7:-0x7F}" "WRP2B_PEND ${8:-0x0}" > "$T/l5/ob"
}
printf '30000000 5742484f\n30000004 a8bdb7b0\n3000000c 00002000\n0c00c404 0c00c4c1\n' > "$T/l5/mem"
echo "00380041 31365102 38393437" > "$T/l5/uid"; UIDL5=003800413136510238393437
echo PROBEL5 > "$T/l5/sns"
mkdir -p "$R/tests/firmware/stm32l562-baremetal/build" "$T/l5wb"
echo lwb > "$T/l5wb/wolfboot.bin"
echo lg0 > "$R/tests/firmware/stm32l562-baremetal/build/guest0.bin"
echo lg1 > "$R/tests/firmware/stm32l562-baremetal/build/guest1.bin"
l5sync() { cp "$T/l5wb/wolfboot.bin" "$T/l5flash/0x0C000000"; cp "$R/build/wolftrust_v1_signed.bin" "$T/l5flash/0x0C00C000"
  cp "$R/tests/firmware/stm32l562-baremetal/build/guest0.bin" "$T/l5flash/0x08060000"
  cp "$R/tests/firmware/stm32l562-baremetal/build/guest1.bin" "$T/l5flash/0x08070000"; }
l5sync
printf '#!/bin/sh\necho "stub runner $1 sn=${STM32L562_STLINK_SN:-none} tool=${STM32L562_PROBE_TOOL:-none}"\n[ -z "${L5_RUNNER_SIG:-}" ] || { kill -TERM $PPID; sleep 30; }\n[ -z "${L5_RUNNER_STICK:-}" ] || touch "%s/l5/obstuck"\n[ -z "${L5_RUNNER_FAIL:-}" ]\n' "$T" > "$R/tests/target/run_stm32l562_hardware.sh"
chmod +x "$R/tests/target/run_stm32l562_hardware.sh"
L5=(env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI="$T/bin/l5cli" STM32L562_WOLFBOOT_DIR="$T/l5wb" STM32L562_PYOCD_VENV="$T/no-venv" WT_PROVISION_STATE="$T/st" PATH="$T/bin:$PATH" "$P")
LS="$T/st/stm32l562"
l5snap() { L5_NOLOG=1 "$T/bin/l5cli" -ob displ | awk '$2 == ":" { print $1 "=" $3 }' | sort | sha | cut -c1-64; }
l5dig() {
  local a f
  for a in 0x0C000000:$T/l5wb/wolfboot.bin 0x0C00C000:$R/build/wolftrust_v1_signed.bin \
           0x08060000:$R/tests/firmware/stm32l562-baremetal/build/guest0.bin \
           0x08070000:$R/tests/firmware/stm32l562-baremetal/build/guest1.bin; do
    f="${a#*:}"; printf '%s %s\n' "${a%%:*}" "$(wc -c < "$f" | tr -d ' ')"; cat "$f"
  done | sha | cut -c1-64
}
# lrec <state> <rdp> <completed> [probe]: a rehearsal record of this part
lrec() { mkdir -p "$LS"; echo "state=$1 run=r id=$UIDL5 image=$(l5dig) rdp=$2 ob=$(l5snap) probe=${4:-PROBEL5} time=$3 cred=none completed=$3" > "$LS/rehearsal-$1"; }
# l5hw [completed] [id] [probe] [image]: the hardware runner's passing positive record
l5hw() { mkdir -p "$LS"; echo "scenario=positive id=${2:-$UIDL5} image=${4:-$(l5dig)} probe=${3:-PROBEL5} secbootadd0=0x180000 handoff=00002000 completed=${1:-$(now)}" > "$LS/hwrun"; }
l5ob; : > "$T/writes"; : > "$T/l5/calls"
check "help lists the port's states" 0 "level-0.5" -- "${L5[@]}" help
check "the STM32L562 port file refuses to run alone" 2 "not this port file" -- bash "$R/tests/target/provisioning/provisioning_ctrl_stm32l562.sh" lock 0x55
check "STM32L562_GUEST_MASK=junk refused" 2 "STM32L562_GUEST_MASK must be" -- env STM32L562_GUEST_MASK=junk WT_LOCK_CONFIRM=1 "${L5[@]}" advance 0x55
check "level 2 is no lock target" 2 "level-2 (0xCC) is not a lock target" -- "${L5[@]}" lock level-2
check "level 2 has no mock" 2 "level-2 (0xCC) has no mock" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" advance 0xCC
check "level 0 is no lock target" 2 "level-0 (0xAA) is not a lock target" -- "${L5[@]}" lock 0xAA
check "RDP 2 writes refused" 2 "RDP level 2 is permanent" -- "${L5[@]}" rdp2
check "advance needs discover" 2 "run 'discover' first" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" advance 0x55
: > "$T/l5/sns"
check "no ST-LINK attached" 2 "set STM32L562_STLINK_SN" -- "${L5[@]}" status
printf 'PROBEL5\nPROBEX\n' > "$T/l5/sns"
check "two ST-LINKs and no serial" 2 "set STM32L562_STLINK_SN" -- "${L5[@]}" status
check "a named ST-LINK among two" 0 "ST-LINK          PROBEX" -- env STM32L562_STLINK_SN=PROBEX "${L5[@]}" status
echo PROBEL5 > "$T/l5/sns"
echo NUCLEO-L552ZE-Q > "$T/l5/board"
check "a sole ST-LINK on another board is not picked" 2 "exactly one STM32L562E-DK ST-LINK" -- "${L5[@]}" status
check "a named ST-LINK on another board is refused" 2 "is not an attached STM32L562E-DK's" -- env STM32L562_STLINK_SN=PROBEL5 "${L5[@]}" status
rm -f "$T/l5/board"
check "status reads RDP, the UID and the fence" 0 "device UID       $UIDL5" -- "${L5[@]}" status
check "status reports the hard-wired lock write" 0 "STM32L562_LOCK_WRITE_ENABLED=0" -- "${L5[@]}" status
check "status reports the handoff life cycle" 0 "PSA_ROT_PROVISIONING" -- "${L5[@]}" status
l5ob 0xAA 0x0
check "discover: TrustZone off" 1 "TrustZone is off" -- "${L5[@]}" discover
l5ob 0xBB
check "discover: level 1 has no further rehearsal" 1 "has no further rehearsal step" -- "${L5[@]}" discover
l5ob 0xCC
check "discover: level 2 closes the debug port" 1 "cannot read the option bytes" -- "${L5[@]}" discover
l5ob
check "discover stamps RDP, the UID and the ST-LINK" 0 "discovery stamped" -- "${L5[@]}" discover
grep -q "RDP=0xAA TZEN=0x1 UID=$UIDL5 PROBE=PROBEL5" "$LS/discovery" && { pass=$((pass+1)); echo "ok   discovery records the part and the ST-LINK"; } || { failn=$((failn+1)); echo "FAIL discovery: $(cat "$LS/discovery")"; }
check "advance to level 1 needs a regress first" 2 "prove 'regress' from level-0.5" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" advance 0xBB
nowrite
check "set-perimeter needs WT_LOCK_CONFIRM" 2 "writes to the board" -- "${L5[@]}" set-perimeter
nowrite
l5ob 0xAA 0x0 0x7F 0x0
check "set-perimeter writes TZEN, the watermarks and SECBOOTADD0" 0 "read back as TZEN=0x1" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-perimeter
[ "$(cat "$T/writes")" = "OB TZEN=0x1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F SECWM2_PSTRT=0x0 SECWM2_PEND=0x3F SECBOOTADD0=0x180000" ] &&
  { pass=$((pass+1)); echo "ok   set-perimeter never writes the permanent BOOT_LOCK"; } || { failn=$((failn+1)); echo "FAIL perimeter writes: $(cat "$T/writes")"; }
: > "$T/writes"
check "boot-lock needs WT_LOCK_CONFIRM" 2 "writes to the board" -- "${L5[@]}" boot-lock
rm -f "$LS/hwrun"
check "boot-lock without a hardware run" 2 "no passing hardware run is recorded" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5hw "$(( $(now) - 7200 ))"
check "boot-lock with an expired hardware run" 2 "older than 3600s" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5hw "" "" "" 0000000000000000000000000000000000000000000000000000000000000000
check "boot-lock after a run of other images" 2 "booted other images" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5hw "" 111111112222222233333333
check "boot-lock on a part other than the one booted" 2 "is not the one the hardware run booted" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5hw "" "" PROBEX
check "boot-lock through another ST-LINK" 2 "went through ST-LINK PROBEX" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5hw; sed 's/secbootadd0=0x180000/secbootadd0=0x1801C0/' "$LS/hwrun" > "$LS/hwrun.t" && mv "$LS/hwrun.t" "$LS/hwrun"
check "boot-lock after a run that did not boot from wolfBoot" 2 "not a positive boot from SECBOOTADD0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5hw; echo bad > "$T/l5flash/0x08070000"
check "boot-lock with other images on the part" 2 "differ from the ones the hardware run booted" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5sync
nowrite
check "boot-lock without a production opt-in" 2 "Only a production station" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
check "boot-lock with the opt-in but no terminal" 2 "needs an interactive terminal" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5[@]}" boot-lock
l5ob 0xAA 0x0 0x7F 0x0
check "boot-lock before the perimeter is refused" 2 "set the perimeter first" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5[@]}" boot-lock
nowrite
if [ "$have_expect" = 1 ]; then
l5ob 0xAA 0x1 0x3F 0x0; l5hw
L5B="env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI=$T/bin/l5cli STM32L562_WOLFBOOT_DIR=$T/l5wb STM32L562_PYOCD_VENV=$T/no-venv WT_PROVISION_STATE=$T/st PATH=$T/bin:$PATH WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
expect -c "set timeout 60; spawn $L5B boot-lock; expect \"to continue: \"; send \"yes\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   boot-lock refuses a wrong phrase"; } || { failn=$((failn+1)); echo "FAIL boot-lock wrong phrase rc=$rc"; }
expect -c "set timeout 60; spawn $L5B boot-lock; expect \"to continue: \"; send \"I ACCEPT BOOT_LOCK\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/writes")" = "OB BOOT_LOCK=0x1" ] && { pass=$((pass+1)); echo "ok   boot-lock writes BOOT_LOCK after the typed acceptance"; } || { failn=$((failn+1)); echo "FAIL boot-lock rc=$rc writes: $(cat "$T/writes")"; }
: > "$T/writes"
else
  echo "skip typed boot-lock (no expect)"
fi
l5ob 0xAA 0x0; sed 's/^SWAP_BANK 0x0/SWAP_BANK 0x1/' "$T/l5/ob" > "$T/l5/ob.t" && mv "$T/l5/ob.t" "$T/l5/ob"
check "set-perimeter on a swapped bank map is refused" 2 "DBANK=1 SWAP_BANK=0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-perimeter
nowrite
touch "$T/l5/obstuck"; l5ob 0xAA 0x0
check "a perimeter write that does not read back fails" 1 "did not read back" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-perimeter
rm -f "$T/l5/obstuck"; : > "$T/writes"
l5ob 0x55
check "option bytes are written only at level 0" 1 "only at level-0 (0xAA)" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
nowrite
l5ob 0xAA 0x1 0x3F 0x1 0x7F 0x0
check "verify-wrp: no fence" 1 "no WRP2 area covers" -- "${L5[@]}" verify-wrp
check "set-wrp arms WRP2A over the guests" 0 "read back as WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
check "verify-wrp: the armed fence" 0 "armed: WRP2A pages 0x40-0x7F" -- "${L5[@]}" verify-wrp
check "clear-wrp releases it" 0 "read back as WRP2A_PSTRT=0x7F WRP2A_PEND=0x0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" clear-wrp
: > "$T/writes"
check "restore runs the hardware runner bound to the ST-LINK" 0 "stub runner positive sn=PROBEL5" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
nowrite
l5ob
check "restore with the fence armed" 0 "stub runner positive" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F')" ] &&
  { pass=$((pass+1)); echo "ok   restore releases the fence for the reflash and arms it again"; } || { failn=$((failn+1)); echo "FAIL restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
# The fence may be WRP2B alone, split across A and B, or partial: restore and
# clear-wrp release every area over a guest page and put each back as it was.
l5ob 0xAA 0x1 0x3F 0x1 0x7F 0x0 0x40 0x7F
check "verify-wrp: a WRP2B-only fence" 0 "armed: WRP2B pages 0x40-0x7F" -- "${L5[@]}" verify-wrp
check "clear-wrp releases WRP2B" 0 "read back as WRP2B_PSTRT=0x7F WRP2B_PEND=0x0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" clear-wrp
: > "$T/writes"
l5ob 0xAA 0x1 0x3F 0x1 0x40 0x5F 0x60 0x7F
check "verify-wrp: a fence split across A and B" 0 "armed: WRP2A pages 0x40-0x5F, WRP2B pages 0x60-0x7F" -- "${L5[@]}" verify-wrp
check "restore with a split fence" 0 "stub runner positive" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0\nOB WRP2A_PSTRT=0x40 WRP2A_PEND=0x5F WRP2B_PSTRT=0x60 WRP2B_PEND=0x7F')" ] &&
  { pass=$((pass+1)); echo "ok   restore releases both areas and puts each back as it was"; } || { failn=$((failn+1)); echo "FAIL split restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
l5ob 0xAA 0x1 0x3F 0x1 0x50 0x5F
check "verify-wrp: a partial fence is not armed" 1 "partial: WRP2A pages 0x50-0x5F" -- "${L5[@]}" verify-wrp
check "restore with a partial fence" 0 "stub runner positive" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP2A_PSTRT=0x50 WRP2A_PEND=0x5F')" ] &&
  { pass=$((pass+1)); echo "ok   restore releases a partial fence too and restores it"; } || { failn=$((failn+1)); echo "FAIL partial restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
# A WRP2 area that also covers non-guest pages is never narrowed or dropped.
l5ob 0xAA 0x1 0x3F 0x1 0x0 0x20
check "set-wrp keeps an unrelated WRP2A range" 2 "outside 0x40-0x7F; arming the fence would drop them" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
l5ob 0xAA 0x1 0x3F 0x1 0x7F 0x0 0x20 0x7F
check "clear-wrp keeps a range spanning guest and other pages" 2 "WRP2B also protects bank 2 pages outside 0x40-0x7F" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" clear-wrp
[ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   refused WRP changes write nothing"; } || { failn=$((failn+1)); echo "FAIL refused WRP writes: $(cat "$T/writes")"; }
l5ob 0xAA 0x1 0x3F 0x1 0x50 0x5F
check "set-wrp widens a guest-only WRP2A range" 0 "read back as WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
: > "$T/writes"
l5ob
check "restore hands the runner its probe tool" 0 "tool=cubeprog" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
: > "$T/writes"
check "restore interrupted by SIGTERM" 143 "Writing option bytes: WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F" -- env L5_RUNNER_SIG=1 WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F')" ] && [ "$(awk '$1 == "WRP2A_PSTRT" { print $2 }' "$T/l5/ob")" = 0x40 ] &&
  { pass=$((pass+1)); echo "ok   an interrupted restore arms the fence again"; } || { failn=$((failn+1)); echo "FAIL interrupted restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
check "restore with a failing runner" 1 "the hardware runner did not pass" -- env L5_RUNNER_FAIL=1 WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F')" ] &&
  { pass=$((pass+1)); echo "ok   a failed restore still arms the fence again"; } || { failn=$((failn+1)); echo "FAIL failed restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
# The re-arm write does not read back: restore retries once and says the fence is still open.
check "restore whose re-arm write fails" 1 "UNSAFE: the guest fence is still released" -- env L5_RUNNER_STICK=1 WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(grep -c '^OB WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F' "$T/writes")" = 2 ] && [ "$(awk '$1 == "WRP2A_PSTRT" { print $2 }' "$T/l5/ob")" = 0x7F ] &&
  { pass=$((pass+1)); echo "ok   a failed re-arm is retried once and the released fence is reported"; } || { failn=$((failn+1)); echo "FAIL failed re-arm writes: $(cat "$T/writes")"; }
rm -f "$T/l5/obstuck"; : > "$T/writes"
l5ob
check "lock needs a rehearsal" 2 "no rehearsal for level-0.5" -- "${L5[@]}" lock 0x55
check "lock skipping a level" 2 "runs only from level-0.5 (0x55)" -- "${L5[@]}" lock level-1
lrec 0x55 0xAA "$(now)"
out="$("${L5[@]}" lock 0x55 2>&1)"; rc=$?
[ $rc = 2 ] && grep -q "preview only" <<<"$out" && grep -q "mode=HotPlug -ob RDP=0x55" <<<"$out" && grep -q "MASS-ERASES" <<<"$out" &&
  grep -q "hard-wired off" <<<"$out" && grep -q "same part $UIDL5" <<<"$out" && grep -q "perimeter and BOOT_LOCK values, guest WRP fence" <<<"$out" &&
  { pass=$((pass+1)); echo "ok   lock previews the RDP write and the mass-erase way back, then stops"; } || { failn=$((failn+1)); echo "FAIL lock preview rc=$rc"; echo "$out" | tail -8; }
grep -qx "BOOT_LOCK=0x1" "$LS/lock-0x55/option-bytes.txt" && grep -qx "RDP=0xAA" "$LS/lock-0x55/option-bytes.txt" &&
  grep -q "mode=HotPlug -ob RDP=0x55" "$LS/lock-0x55/plan.txt" && grep -q "kept in $LS/lock-0x55" <<<"$out" &&
  { pass=$((pass+1)); echo "ok   the preview keeps the option bytes it checked and the plan"; } || { failn=$((failn+1)); echo "FAIL L5 preview artifacts missing"; ls -la "$LS/lock-0x55" 2>&1; }
lrec 0x55 0xAA "$(now)" PROBEX
check "a rehearsal through another ST-LINK is refused" 2 "no rehearsal for level-0.5" -- "${L5[@]}" lock 0x55
lrec 0x55 0xAA "$(( $(now) - 7200 ))"
check "an expired rehearsal is refused" 2 "in the last 3600s" -- "${L5[@]}" lock 0x55
echo "11111111 22222222 33333333" > "$T/l5/uid"; lrec 0x55 0xAA "$(now)"
echo "00380041 31365102 38393437" > "$T/l5/uid"
subst "id=[0-9a-f]*" "id=111111112222222233333333" "$LS/rehearsal-0x55"
check "a rehearsal of another part is refused" 2 "no rehearsal for level-0.5" -- "${L5[@]}" lock 0x55
l5ob 0xAA 0x1 0x7F; lrec 0x55 0xAA "$(now)"
check "an unsafe watermark is refused" 2 "perimeter option bytes are not wolfTrust's" -- "${L5[@]}" lock 0x55
l5ob 0xAA 0x1 0x3F 0x0; lrec 0x55 0xAA "$(now)"
check "BOOT_LOCK off is refused" 2 "perimeter option bytes are not wolfTrust's" -- "${L5[@]}" lock 0x55
l5ob 0xAA 0x1 0x3F 0x1 0x7F 0x0; lrec 0x55 0xAA "$(now)"
check "a lock without the guest fence is refused" 2 "WRP fence is not armed" -- "${L5[@]}" lock 0x55
l5ob; lrec 0x55 0xAA "$(now)"
echo bad > "$T/l5flash/0x08060000"
check "different flash on the part is refused" 2 "differ from the rehearsed build" -- "${L5[@]}" lock 0x55
l5sync
check "lock without a production opt-in" 2 "Only a production station" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" lock 0x55
check "lock with the opt-in but no terminal" 2 "needs an interactive terminal" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5[@]}" lock 0x55
nowrite
if [ "$have_expect" = 1 ]; then
L5X="env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI=$T/bin/l5cli STM32L562_WOLFBOOT_DIR=$T/l5wb STM32L562_PYOCD_VENV=$T/no-venv WT_PROVISION_STATE=$T/st PATH=$T/bin:$PATH WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
expect -c "set timeout 300; spawn $L5X lock 0x55; expect \"to continue: \"; send \"I ACCEPT 0xBB\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   a wrong phrase is refused"; } || { failn=$((failn+1)); echo "FAIL wrong phrase rc=$rc"; }
out="$(expect -c "set timeout 300; spawn $L5X lock 0x55; expect \"to continue: \"; send \"I ACCEPT 0x55\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 2 ] && grep -q "hard-wired off in this port (STM32L562_LOCK_WRITE_ENABLED=0)" <<<"$out" && grep -q "MASS-ERASES" <<<"$out" && [ ! -s "$T/writes" ] && [ -e "$LS/rehearsal-0x55" ] && { pass=$((pass+1)); echo "ok   the exact phrase with every confirmation is still refused at the write"; } || { failn=$((failn+1)); echo "FAIL typed acceptance rc=$rc"; echo "$out" | tail -5; }
else
  echo "skip typed lock refusal (no expect)"
fi
nowrite
check "regress at level 0 is a reset" 0 "brought back the level-0 life cycle" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" regress
nowrite
l5ob 0x55
check "an RDP regression from level 0.5 is previewed" 2 "MASS-ERASES the whole flash" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" regress
check "and needs a terminal" 2 "needs an interactive terminal and the typed acceptance" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" regress
nowrite
if [ "$have_expect" = 1 ]; then
L5R="env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI=$T/bin/l5cli STM32L562_WOLFBOOT_DIR=$T/l5wb STM32L562_PYOCD_VENV=$T/no-venv WT_PROVISION_STATE=$T/st PATH=$T/bin:$PATH WT_LOCK_CONFIRM=1 $P"
l5ob 0xBB
expect -c "set timeout 300; spawn $L5R regress; expect \"to continue: \"; send \"yes\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]" >/dev/null
rc=$?; [ $rc = 2 ] && [ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   a regression with the wrong phrase writes nothing"; } || { failn=$((failn+1)); echo "FAIL regression phrase rc=$rc"; }
out="$(expect -c "set timeout 300; spawn $L5R regress; expect \"to continue: \"; send \"I ACCEPT 0xAA\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/writes")" = "OB RDP=0xAA" ] && grep -q "mass-erased" <<<"$out" && grep -q "mode=HotPlug -ob RDP=0xAA" "$T/l5/calls" && grep -q "will run: .*mode=HotPlug -ob RDP=0xAA" <<<"$out" && { pass=$((pass+1)); echo "ok   the typed acceptance regresses level 1 to level 0 over a hot-plug connection (stub)"; } || { failn=$((failn+1)); echo "FAIL regression rc=$rc writes=$(cat "$T/writes")"; echo "$out" | tail -4; }
: > "$T/writes"
else
  echo "skip typed regression (no expect)"
fi
l5ob 0xCC
check "level 2 has no regression" 2 "level-2 (0xCC) is permanent" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" regress
nowrite
if grep -q . "$T/l5/calls" && ! grep -v -- "^-l st" "$T/l5/calls" | grep -v "sn=PROBE" | grep -q .; then pass=$((pass+1)); echo "ok   every CubeProgrammer call carried the ST-LINK serial"; else failn=$((failn+1)); echo "FAIL a call ran unbound: $(grep -v -- '^-l st' "$T/l5/calls" | grep -v 'sn=PROBE' | head -2)"; fi
echo "== STM32L562 through OpenOCD"
# An OpenOCD stub that runs the l5_* operations of lib/stm32l562_openocd.tcl
# against the same option bytes, memory and flash files as the CubeProgrammer
# stub, composing and splitting the option registers as the silicon does.
mkdir -p "$T/ocd"
cat > "$T/ocd/openocd" <<EOF
#!/usr/bin/env python3
import os, sys, shutil
T = "$T"
FIELDS = [("RDP",0x40,0xFF,0),("TZEN",0x40,0x80000000,31),("DBANK",0x40,0x400000,22),
  ("SWAP_BANK",0x40,0x100000,20),("SECBOOTADD0",0x4C,0xFFFFFF80,7),("BOOT_LOCK",0x4C,1,0)]
for n, o in (("SECWM1",0x50),("WRP1A",0x58),("WRP1B",0x5C),("SECWM2",0x60),("WRP2A",0x68),("WRP2B",0x6C)):
    FIELDS += [(n + "_PSTRT", o, 0x7F, 0), (n + "_PEND", o, 0x7F0000, 16)]
def ob():
    return dict(l.split() for l in open(T + "/l5/ob") if l.strip())
def mem():
    return dict(l.split() for l in open(T + "/l5/mem") if l.strip())
def savemem(m):
    open(T + "/l5/mem", "w").write("".join("%s %s\n" % kv for kv in m.items()))
cmds = [sys.argv[i + 1] for i, a in enumerate(sys.argv[:-1]) if a == "-c"]
sn = next((c.split()[2] for c in cmds if c.startswith("adapter serial ")), "")
open(T + "/l5/ocdcalls", "a").write("sn=%s %s\n" % (sn, " | ".join(c for c in cmds if c.startswith("l5_") or c.startswith("reset "))))
o = ob()
if o["RDP"] == "0xCC":
    print("Error: init mode failed (unable to connect to the target)"); sys.exit(1)
if "reset halt" in cmds and o["RDP"] != "0xAA":
    open(T + "/l5/ur_above0", "a").write("halt\n"); print("Error: timed out while waiting for target halted"); sys.exit(1)
for c in cmds:
    w = c.split()
    if w[0] == "l5_ob":
        regs = {}
        for name, off, mask, sh in FIELDS:
            regs[off] = regs.get(off, 0) | ((int(o[name], 16) << sh) & mask)
        print("L5OB 0x50022040 " + " ".join("%08x" % regs.get(0x40 + 4 * i, 0) for i in range(12)))
    elif w[0] == "l5_mem":
        a, n, m = int(w[1]), int(w[2]), mem()
        print("L5MEM 0x%08X " % a + " ".join(m.get("%08x" % (a + 4 * i), "00000000") for i in range(n)))
    elif w[0] == "l5_uid":
        print("L5UID 0x0BFA0590 " + open(T + "/l5/uid").read().strip())
    elif w[0] == "l5_dump":
        f, a = w[1].strip("{}"), int(w[2])
        src = T + "/l5flash/0x%08X" % a
        if not os.path.exists(src):
            print("L5ERR dump"); continue
        shutil.copy(src, f); print("L5DUMP 0x%08X %s" % (a, w[3]))
    elif w[0] == "l5_obw":
        t, out = w[1:], []
        for i in range(0, len(t), 3):
            off, mask, val = int(t[i], 16), int(t[i + 1], 16), int(t[i + 2])
            for name, fo, fm, sh in FIELDS:
                if fo == off and fm & mask == fm:
                    out.append("%s=0x%X" % (name, (val & fm) >> sh))
        open(T + "/writes", "a").write("OB " + " ".join(out) + "\n")
        if not os.path.exists(T + "/l5/obstuck"):
            for kv in out:
                o[kv.split("=")[0]] = kv.split("=")[1]
            open(T + "/l5/ob", "w").write("".join("%s %s\n" % kv for kv in o.items()))
        print("L5OBW 0x00000000")
    elif w[0] == "l5_advance":
        m = mem()
        m["3000000c"] = "%08x" % int(w[2])
        m["%08x" % int(w[4])] = os.environ.get("OCD_ADV_VM", "00000003")
        m["%08x" % int(w[5])] = os.environ.get("OCD_ADV_RF", "00000000")
        savemem(m); open(T + "/writes", "a").write("ADVANCE 0x%04x\n" % int(w[2]))
        print("L5ADV 0x%08X 0x%04X" % (int(w[1]), int(w[2])))
    elif c == "reset run":
        m = mem(); m["3000000c"] = "00002000"; savemem(m)
        open(T + "/l5/ocdcalls", "a").write("RESET\n")
EOF
printf '#!/bin/sh\n[ "$1" = list ] || exit 1\nfor s in $(cat %s/l5/sns); do echo "  0   STLINK-V3   $s   x n/a"; echo "      $(cat %s/l5/board 2>/dev/null || echo STM32L562E-DK)"; done\n' "$T" "$T" > "$T/ocd/pyocd"
printf '#!/bin/sh\nexit 0\n' > "$T/ocd/lsblk"
printf '#!/bin/sh\necho "30000100 B g_wt_launch_verified_mask"\necho "30000104 B g_wt_launch_refused_mask"\necho "30000108 B g_boot_lifecycle"\n' > "$T/ocd/arm-none-eabi-nm"
chmod +x "$T/ocd/"*
L5O=(env TARGET=stm32l562 STM32L562_PROBE_TOOL=openocd STM32L562_OPENOCD="$T/ocd/openocd" STM32L562_PYOCD="$T/ocd/pyocd" STM32_CLI="$T/no-cli" STM32L562_WOLFBOOT_DIR="$T/l5wb" WT_PROVISION_STATE="$T/sto" PATH="$T/ocd:$T/bin:$PATH" "$P")
LO="$T/sto/stm32l562"
# pyOCD lists ST-LINK serials as hex digits.
L5OSN=0021004A3137
: > "$T/l5/ocdcalls"; : > "$T/writes"; l5ob; l5sync
printf '30000000 5742484f\n30000004 a8bdb7b0\n3000000c 00002000\n0c00c404 0c00c4c1\n' > "$T/l5/mem"
echo "$L5OSN" > "$T/l5/sns"
check "openocd: status names the tool" 0 "ST-LINK          $L5OSN (openocd)" -- "${L5O[@]}" status
check "openocd: status decodes the option registers" 0 "SECBOOTADD0      0x180000  BOOT_LOCK 0x1" -- "${L5O[@]}" status
check "openocd: status reads the UID" 0 "device UID       $UIDL5" -- "${L5O[@]}" status
echo NUCLEO-L552ZE-Q > "$T/l5/board"
check "openocd: a sole ST-LINK on another board is not picked" 2 "exactly one STM32L562E-DK ST-LINK" -- "${L5O[@]}" status
check "openocd: a named ST-LINK on another board is refused" 2 "is not an attached STM32L562E-DK's" -- env STM32L562_STLINK_SN=$L5OSN "${L5O[@]}" status
rm -f "$T/l5/board"
check "openocd: discover stamps the part" 0 "discovery stamped" -- "${L5O[@]}" discover
l5ob 0xAA 0x1 0x3F 0x1 0x7F 0x0
check "openocd: set-wrp merges WRP2A into its register" 0 "read back as WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" set-wrp
[ "$(cat "$T/writes")" = "OB WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F" ] && { pass=$((pass+1)); echo "ok   openocd: set-wrp writes only the WRP2A fields"; } || { failn=$((failn+1)); echo "FAIL openocd set-wrp writes: $(cat "$T/writes")"; }
: > "$T/writes"
check "openocd: verify-wrp sees the fence" 0 "armed: WRP2A pages 0x40-0x7F" -- "${L5O[@]}" verify-wrp
check "openocd: restore interrupted by SIGTERM" 143 "stub runner positive sn=$L5OSN tool=openocd" -- env L5_RUNNER_SIG=1 WT_LOCK_CONFIRM=1 "${L5O[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F')" ] &&
  { pass=$((pass+1)); echo "ok   openocd: an interrupted restore arms the fence again"; } || { failn=$((failn+1)); echo "FAIL openocd interrupted restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
l5ob 0xAA 0x1 0x3F 0x0
check "openocd: set-perimeter never touches BOOT_LOCK" 0 "read back as TZEN=0x1" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" set-perimeter
[ "$(cat "$T/writes")" = "OB TZEN=0x1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F SECWM2_PSTRT=0x0 SECWM2_PEND=0x3F SECBOOTADD0=0x180000" ] &&
  [ "$(awk '$1 == "BOOT_LOCK" { print $2 }' "$T/l5/ob")" = 0x0 ] && { pass=$((pass+1)); echo "ok   openocd: the perimeter write leaves BOOT_LOCK off"; } || { failn=$((failn+1)); echo "FAIL openocd perimeter writes: $(cat "$T/writes")"; }
: > "$T/writes"
rm -f "$LO/hwrun"
check "openocd: boot-lock without a hardware run" 2 "no passing hardware run is recorded" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5O[@]}" boot-lock
mkdir -p "$LO"; echo "scenario=positive id=$UIDL5 image=$(l5dig) probe=$L5OSN secbootadd0=0x180000 handoff=00002000 completed=$(now)" > "$LO/hwrun"
check "openocd: boot-lock with a run reaches the typed acceptance" 2 "needs an interactive terminal" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5O[@]}" boot-lock
nowrite
l5ob
check "openocd: the rehearsal advances the handoff life cycle" 0 "rehearsal of level-0.5 (0x55) recorded" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" advance 0x55
grep -q "ADVANCE 0x4000" "$T/writes" && grep -q "l5_advance 201376960" "$T/l5/ocdcalls" && { pass=$((pass+1)); echo "ok   openocd: advance stops at wolfTrust's entry from reset"; } || { failn=$((failn+1)); echo "FAIL openocd advance: $(grep l5_advance "$T/l5/ocdcalls")"; }
: > "$T/writes"
check "openocd: regress at level 0 is a pin reset" 0 "rehearsal of level-0.5 (0x55) complete" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" regress
grep -q "^RESET" "$T/l5/ocdcalls" && { pass=$((pass+1)); echo "ok   openocd: regress reset the part"; } || { failn=$((failn+1)); echo "FAIL openocd regress did not reset"; }
# STM32L562_GUEST_MASK selects the guests that must launch; the other guest is not judged.
check "openocd: guest mask 0x1 passes on a two-guest boot" 0 "guests launched (verified=0x00000003" -- env STM32L562_GUEST_MASK=0x1 WT_LOCK_CONFIRM=1 "${L5O[@]}" advance 0x55
check "openocd: regress after the 0x1 rehearsal" 0 "complete" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" regress
check "openocd: guest mask 0x2 ignores a refused guest0" 0 "guests launched (verified=0x00000002 refused=0x00000001)" -- env STM32L562_GUEST_MASK=0x2 OCD_ADV_VM=00000002 OCD_ADV_RF=00000001 WT_LOCK_CONFIRM=1 "${L5O[@]}" advance 0x55
check "openocd: regress after the 0x2 rehearsal" 0 "complete" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" regress
check "openocd: guest mask 0x2 fails when guest1 is refused" 1 "guests did not all launch" -- env STM32L562_GUEST_MASK=0x2 OCD_ADV_VM=00000001 OCD_ADV_RF=00000002 WT_LOCK_CONFIRM=1 "${L5O[@]}" advance 0x55
check "openocd: the default mask still needs both guests" 1 "guests did not all launch" -- env OCD_ADV_VM=00000001 WT_LOCK_CONFIRM=1 "${L5O[@]}" advance 0x55
: > "$T/writes"
out="$("${L5O[@]}" lock 0x55 2>&1)"; rc=$?
[ $rc = 2 ] && grep -q "preview only" <<<"$out" && grep -q "will run: .*openocd (ST-LINK $L5OSN, hot attach): l5_obw RDP=0x55" <<<"$out" && grep -q "same part $UIDL5" <<<"$out" &&
  { pass=$((pass+1)); echo "ok   openocd: the lock previews the hot RDP write and stops"; } || { failn=$((failn+1)); echo "FAIL openocd lock preview rc=$rc"; echo "$out" | tail -6; }
nowrite
l5ob 0x55
check "openocd: an RDP regression from level 0.5 is previewed" 2 "l5_obw RDP=0xAA" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" regress
nowrite
if ! grep -v '^RESET' "$T/l5/ocdcalls" | grep -v "^sn=$L5OSN " | grep -q .; then pass=$((pass+1)); echo "ok   every OpenOCD session was bound to the ST-LINK serial"; else failn=$((failn+1)); echo "FAIL an OpenOCD session ran unbound: $(grep -v "^sn=$L5OSN " "$T/l5/ocdcalls" | head -2)"; fi
echo "provisioning gates: $pass passed, $failn failed"
[ "$failn" = 0 ]
