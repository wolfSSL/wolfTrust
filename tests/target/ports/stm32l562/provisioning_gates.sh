# shellcheck shell=bash disable=SC2015,SC2016,SC2034,SC2154
# STM32L562 provisioning gates, sourced by
# tests/target/provisioning/test_provisioning_gates.sh with its helpers and stubs.
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
      tz0=\$(awk '\$1 == "TZEN" { print \$2 }' $T/l5/ob)
      [ -e $T/l5/obstuck ] || for kv in "\${args[@]:\$((i+1))}"; do
        awk -v k="\${kv%%=*}" -v v="\${kv#*=}" '\$1 == k { \$2 = v } { print }' $T/l5/ob > $T/l5/ob.new && mv $T/l5/ob.new $T/l5/ob; done
      # RM0438: enabling TZEN resets the watermarks to all Secure.
      if [ "\$tz0" = 0x0 ] && [ "\$(awk '\$1 == "TZEN" { print \$2 }' $T/l5/ob)" = 0x1 ]; then
        awk '\$1 ~ /^SECWM[12]_PSTRT\$/ { \$2 = "0x0" } \$1 ~ /^SECWM[12]_PEND\$/ { \$2 = "0x7F" } { print }' $T/l5/ob > $T/l5/ob.new && mv $T/l5/ob.new $T/l5/ob; fi
      echo "Option Bytes successfully programmed"; exit 0 ;;
    -d|-e) echo "WRITE \${args[*]}" >> $T/writes; exit 0 ;;
  esac
done
[ -z "\${up:-}" ] || exit 0
echo "ok"
EOF
chmod +x "$T/bin/l5cli"
# l5ob [rdp tzen secwm2-start boot-lock wrp1a wrp2a wrp2b], each WRP area as
# "start end": the production perimeter and the armed guest fence by default.
l5ob() {
  printf '%s\n' "RDP ${1:-0xAA}" "TZEN ${2:-0x1}" SECWM1_PSTRT\ 0x0 SECWM1_PEND\ 0x57 \
    "SECWM2_PSTRT ${3:-0x20}" SECWM2_PEND\ 0x7F SECBOOTADD0\ 0x180000 "BOOT_LOCK ${4:-0x1}" \
    DBANK\ 0x1 SWAP_BANK\ 0x0 "WRP1A_PSTRT ${5:-0x58}" "WRP1A_PEND ${6:-0x7F}" WRP1B_PSTRT\ 0x7F WRP1B_PEND\ 0x0 \
    "WRP2A_PSTRT ${7:-0x0}" "WRP2A_PEND ${8:-0x1F}" "WRP2B_PSTRT ${9:-0x7F}" "WRP2B_PEND ${10:-0x0}" > "$T/l5/ob"
}
printf '30000000 5742484f\n30000004 a8bdb7b0\n3000000c 00002000\n0c00c404 0c00c4c1\n' > "$T/l5/mem"
echo "00380041 31365102 38393437" > "$T/l5/uid"; UIDL5=003800413136510238393437
echo PROBEL5 > "$T/l5/sns"
mkdir -p "$R/build/hw"
echo elf > "$R/build/wolftrust-signed.elf"
echo lwb > "$R/build/hw/wolfboot.bin"
echo lg0 > "$R/build/hw/guest0.bin"
echo lg1 > "$R/build/hw/guest1.bin"
l5sync() { cp "$R/build/hw/wolfboot.bin" "$T/l5flash/0x0C000000"; cp "$R/build/wolftrust_v1_signed.bin" "$T/l5flash/0x0C00C000"
  cp "$R/build/hw/guest0.bin" "$T/l5flash/0x0802C000"
  cp "$R/build/hw/guest1.bin" "$T/l5flash/0x08040000"; }
l5sync
printf '#!/bin/sh\necho "stub runner $1 $2 sn=${WT_HW_PROBE:-none} tool=${STM32L562_PROBE_TOOL:-none}"\n[ -z "${L5_RUNNER_SIG:-}" ] || { kill -TERM $PPID; sleep 30; }\n[ -z "${L5_RUNNER_STICK:-}" ] || touch "%s/l5/obstuck"\n[ -z "${L5_RUNNER_FAIL:-}" ]\n' "$T" > "$R/tests/target/run_hardware.sh"
chmod +x "$R/tests/target/run_hardware.sh"
L5=(env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI="$T/bin/l5cli" STM32L562_PYOCD_VENV="$T/no-venv" WT_PROVISION_STATE="$T/st" PATH="$T/bin:$PATH" "$P")
LS="$T/st/stm32l562"
l5snap() { L5_NOLOG=1 "$T/bin/l5cli" -ob displ | awk '$2 == ":" { print $1 "=" $3 }' | sort | sha | cut -c1-64; }
l5dig() {
  local a f
  for a in 0x0C000000:$R/build/hw/wolfboot.bin 0x0C00C000:$R/build/wolftrust_v1_signed.bin \
           0x0802C000:$R/build/hw/guest0.bin \
           0x08040000:$R/build/hw/guest1.bin; do
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
l5ob 0xAA 0x0 0x0 0x0
check "set-perimeter writes TZEN, the watermarks and SECBOOTADD0" 0 "read back as TZEN=0x1" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-perimeter
[ "$(cat "$T/writes")" = "$(printf 'OB TZEN=0x1\nOB TZEN=0x1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x57 SECWM2_PSTRT=0x20 SECWM2_PEND=0x7F SECBOOTADD0=0x180000')" ] &&
  { pass=$((pass+1)); echo "ok   set-perimeter enables TZEN alone first and never writes the permanent BOOT_LOCK"; } || { failn=$((failn+1)); echo "FAIL perimeter writes: $(cat "$T/writes")"; }
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
l5hw; echo bad > "$T/l5flash/0x08040000"
check "boot-lock with other images on the part" 2 "differ from the ones the hardware run booted" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
l5sync
nowrite
check "boot-lock without a production opt-in" 2 "Only a production station" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" boot-lock
check "boot-lock with the opt-in but no terminal" 2 "needs an interactive terminal" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5[@]}" boot-lock
l5ob 0xAA 0x0 0x0 0x0
check "boot-lock before the perimeter is refused" 2 "set the perimeter first" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5[@]}" boot-lock
nowrite
if [ "$have_expect" = 1 ]; then
l5ob 0xAA 0x1 0x20 0x0; l5hw
L5B="env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI=$T/bin/l5cli STM32L562_PYOCD_VENV=$T/no-venv WT_PROVISION_STATE=$T/st PATH=$T/bin:$PATH WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
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
# A swapped or single-bank map moves the guest pages, so no WRP mutator runs on it.
for cmd in set-wrp clear-wrp restore; do
  for bm in "SWAP_BANK 0x1" "DBANK 0x0"; do
    l5ob; awk -v k="${bm% *}" -v v="${bm#* }" '$1 == k { $2 = v } { print }' "$T/l5/ob" > "$T/l5/ob.t" && mv "$T/l5/ob.t" "$T/l5/ob"
    check "$cmd refused with ${bm% *}=${bm#* }" 2 "DBANK=1 SWAP_BANK=0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" $cmd
    nowrite
  done
done
touch "$T/l5/obstuck"; l5ob 0xAA 0x0
check "a perimeter write that does not read back fails" 1 "did not read back" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-perimeter
rm -f "$T/l5/obstuck"; : > "$T/writes"
l5ob 0x55
check "option bytes are written only at level 0" 1 "only at level-0 (0xAA)" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
nowrite
l5ob 0xAA 0x1 0x20 0x1 0x7F 0x0 0x7F 0x0
check "verify-wrp: no fence" 1 "are not all covered" -- "${L5[@]}" verify-wrp
check "set-wrp arms WRP1A and WRP2A over the guests" 0 "read back as WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
check "verify-wrp: the armed fence" 0 "armed: WRP1A pages 0x58-0x7F, WRP2A pages 0x0-0x1F" -- "${L5[@]}" verify-wrp
check "clear-wrp releases it" 0 "read back as WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" clear-wrp
: > "$T/writes"
check "restore runs the hardware runner bound to the ST-LINK" 0 "stub runner stm32l562 positive sn=PROBEL5" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
nowrite
l5ob
check "restore with the fence armed" 0 "stub runner stm32l562 positive" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F')" ] &&
  { pass=$((pass+1)); echo "ok   restore releases the fence for the reflash and arms it again"; } || { failn=$((failn+1)); echo "FAIL restore writes: $(cat "$T/writes")"; }
grep -q "scenario=positive id=$UIDL5 image=$(l5dig) probe=PROBEL5 secbootadd0=0x180000 handoff=00002000" "$LS/hwrun" &&
  { pass=$((pass+1)); echo "ok   a passing restore records the hardware run boot-lock needs"; } || { failn=$((failn+1)); echo "FAIL hwrun record: $(cat "$LS/hwrun" 2>&1)"; }
: > "$T/writes"
# The fence may use either area of a bank, split across both, or be partial:
# restore and clear-wrp release every area over a guest page and put each back.
l5ob 0xAA 0x1 0x20 0x1 0x58 0x7F 0x7F 0x0 0x0 0x1F
check "verify-wrp: guest 1 behind WRP2B" 0 "armed: WRP1A pages 0x58-0x7F, WRP2B pages 0x0-0x1F" -- "${L5[@]}" verify-wrp
check "clear-wrp releases WRP1A and WRP2B" 0 "read back as WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" clear-wrp
: > "$T/writes"
l5ob 0xAA 0x1 0x20 0x1 0x58 0x7F 0x0 0x0F 0x10 0x1F
check "verify-wrp: guest 1 split across A and B" 0 "armed: WRP1A pages 0x58-0x7F, WRP2A pages 0x0-0x0F, WRP2B pages 0x10-0x1F" -- "${L5[@]}" verify-wrp
check "restore with a split fence" 0 "stub runner stm32l562 positive" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0\nOB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x0F WRP2B_PSTRT=0x10 WRP2B_PEND=0x1F')" ] &&
  { pass=$((pass+1)); echo "ok   restore releases all three areas and puts each back as it was"; } || { failn=$((failn+1)); echo "FAIL split restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
l5ob 0xAA 0x1 0x20 0x1 0x60 0x7F 0x7F 0x0
check "verify-wrp: a partial fence is not armed" 1 "partial: WRP1A pages 0x60-0x7F" -- "${L5[@]}" verify-wrp
check "restore with a partial fence" 0 "stub runner stm32l562 positive" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP1A_PSTRT=0x7F WRP1A_PEND=0x0\nOB WRP1A_PSTRT=0x60 WRP1A_PEND=0x7F')" ] &&
  { pass=$((pass+1)); echo "ok   restore releases a partial fence too and restores it"; } || { failn=$((failn+1)); echo "FAIL partial restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
# An area that also covers non-guest pages is never narrowed or dropped.
l5ob 0xAA 0x1 0x20 0x1 0x7F 0x0 0x20 0x30
check "set-wrp keeps an unrelated WRP2A range" 2 "WRP2A already protects pages outside the guest windows" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
l5ob 0xAA 0x1 0x20 0x1 0x7F 0x0 0x7F 0x0 0x10 0x40
check "clear-wrp keeps a range spanning guest and other pages" 2 "WRP2B also protects pages outside the guest windows" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" clear-wrp
check "restore keeps a range spanning guest and other pages" 2 "WRP2B also protects pages outside the guest windows" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ ! -s "$T/writes" ] && { pass=$((pass+1)); echo "ok   refused WRP changes write nothing"; } || { failn=$((failn+1)); echo "FAIL refused WRP writes: $(cat "$T/writes")"; }
l5ob 0xAA 0x1 0x20 0x1 0x60 0x7F 0x7F 0x0
check "set-wrp widens a guest-only WRP1A range" 0 "read back as WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" set-wrp
: > "$T/writes"
l5ob
check "restore hands the runner its probe tool" 0 "tool=cubeprog" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" restore
: > "$T/writes"
check "restore interrupted by SIGTERM" 143 "Writing option bytes: WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F" -- env L5_RUNNER_SIG=1 WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F')" ] && [ "$(awk '$1 == "WRP1A_PSTRT" { print $2 }' "$T/l5/ob")" = 0x58 ] &&
  { pass=$((pass+1)); echo "ok   an interrupted restore arms the fence again"; } || { failn=$((failn+1)); echo "FAIL interrupted restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
check "restore with a failing runner" 1 "the hardware runner did not pass" -- env L5_RUNNER_FAIL=1 WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F')" ] &&
  { pass=$((pass+1)); echo "ok   a failed restore still arms the fence again"; } || { failn=$((failn+1)); echo "FAIL failed restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
# The re-arm write does not read back: restore retries once and says the fence is still open.
check "restore whose re-arm write fails" 1 "UNSAFE: the guest fence is still released" -- env L5_RUNNER_STICK=1 WT_LOCK_CONFIRM=1 "${L5[@]}" restore
[ "$(grep -c '^OB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F' "$T/writes")" = 2 ] && [ "$(awk '$1 == "WRP1A_PSTRT" { print $2 }' "$T/l5/ob")" = 0x7F ] &&
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
l5ob 0xAA 0x1 0x0; lrec 0x55 0xAA "$(now)"
check "an unsafe watermark is refused" 2 "perimeter option bytes are not wolfTrust's" -- "${L5[@]}" lock 0x55
l5ob 0xAA 0x1 0x20 0x0; lrec 0x55 0xAA "$(now)"
check "BOOT_LOCK off is refused" 2 "perimeter option bytes are not wolfTrust's" -- "${L5[@]}" lock 0x55
l5ob 0xAA 0x1 0x20 0x1 0x7F 0x0 0x7F 0x0; lrec 0x55 0xAA "$(now)"
check "a lock without the guest fence is refused" 2 "WRP fence is not armed" -- "${L5[@]}" lock 0x55
l5ob; lrec 0x55 0xAA "$(now)"
echo bad > "$T/l5flash/0x0802C000"
check "different flash on the part is refused" 2 "differ from the rehearsed build" -- "${L5[@]}" lock 0x55
l5sync
check "lock without a production opt-in" 2 "Only a production station" -- env WT_LOCK_CONFIRM=1 "${L5[@]}" lock 0x55
check "lock with the opt-in but no terminal" 2 "needs an interactive terminal" -- env WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 "${L5[@]}" lock 0x55
nowrite
if [ "$have_expect" = 1 ]; then
L5X="env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI=$T/bin/l5cli STM32L562_PYOCD_VENV=$T/no-venv WT_PROVISION_STATE=$T/st PATH=$T/bin:$PATH WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 $P"
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
L5R="env TARGET=stm32l562 STM32L562_PROBE_TOOL=cubeprog STM32_CLI=$T/bin/l5cli STM32L562_PYOCD_VENV=$T/no-venv WT_PROVISION_STATE=$T/st PATH=$T/bin:$PATH WT_LOCK_CONFIRM=1 $P"
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
# Without pipefail, l5_cube still returns CubeProgrammer's status, not sed's.
if bash -c '. "$1/tests/target/ports/stm32l562/probe.sh"; L5_CLI=false; l5_cube SN1 UR -r32 0x0 1' _ "$R" >/dev/null 2>&1; then
  failn=$((failn+1)); echo "FAIL l5_cube hid a failing CubeProgrammer behind its output filter"
else
  pass=$((pass+1)); echo "ok   l5_cube returns CubeProgrammer's failure without pipefail"
fi
echo "== STM32L562 through OpenOCD"
# l5_open must put exactly the SECBB registers over the production guest
# pages under SECBB, beside the two MPCBB SRWILADIS words, and restore them.
if command -v tclsh >/dev/null 2>&1; then
  out="$(tclsh <<TCL 2>&1
proc mrw {r} { return 0 }
proc mww {r v} { lappend ::w [format 0x%08X \$r] }
set ::w {}
source $R/tests/target/ports/stm32l562/openocd.tcl
l5_open
puts "open [lsort \$::w]"
set ::w {}
l5_close
puts "close [lsort \$::w]"
TCL
)"
  want="0x50022088 0x5002208C 0x500220A0 0x50032C00 0x50033000"
  grep -qx "open $want" <<<"$out" && grep -qx "close $want" <<<"$out" &&
    { pass=$((pass+1)); echo "ok   openocd: l5_open opens SECBB over both guest windows and l5_close restores it"; } ||
    { failn=$((failn+1)); echo "FAIL openocd SECBB attribution: $out"; }
  # l5_ob and l5_uid issue each read with the AP security the part answers:
  # a Secure read of a Secure alias only with TZEN set at RDP level 0.
  l5tcl() {
    tclsh <<TCL 2>&1
proc echo {s} { puts \$s }
set ::optr $1
set ::st running
set ::csw ns
set ::log {}
proc stm32l5x.cpu {args} { return \$::st }
proc halt {args} { if {(\$::optr & 0xFF) != 0xAA} { error "secure debug off" }; set ::st halted }
proc resume {args} { set ::st running }
proc stm32l5x.dap {op v m} { set ::csw [expr {(\$v & \$m) != 0 ? "ns" : "s"}] }
proc mrw {a} { return 0 }
proc mww {a v} {}
proc read_memory {a w n} {
  lappend ::log [format "%s-0x%08X" \$::csw \$a]
  if {\$a == 0x40022040 && \$n == 1} { return [list \$::optr] }
  if {\$a == 0x50022040 && (\$::csw ne "s" || (\$::optr & 0x80000000) == 0)} { return [lrepeat \$n 0] }
  if {\$a == 0x0BFA0590 && \$::csw ne "ns"} { error "secure read of the UID" }
  return [lrepeat \$n 7]
}
source $R/tests/target/ports/stm32l562/openocd.tcl
$2
puts "log \$::log csw=\$::csw \$::st"
TCL
  }
  for c in "0x800000AA|log ns-0x40022040 s-0x50022040 csw=s running" \
           "0x000000AA|log ns-0x40022040 ns-0x40022040 csw=s running" \
           "0x80000055|log ns-0x40022040 ns-0x40022040 csw=s running"; do
    out="$(l5tcl "${c%%|*}" l5_ob)"
    grep -qx "${c#*|}" <<<"$out" && grep -q "^L5OB" <<<"$out" &&
      { pass=$((pass+1)); echo "ok   openocd: l5_ob at OPTR ${c%%|*} reads through the view the part answers"; } ||
      { failn=$((failn+1)); echo "FAIL openocd l5_ob at ${c%%|*}: $out"; }
  done
  out="$(l5tcl 0x800000AA l5_uid)"
  grep -q "^L5UID" <<<"$out" && grep -q "ns-0x0BFA0590 csw=s running" <<<"$out" &&
    { pass=$((pass+1)); echo "ok   openocd: l5_uid reads the UID with HNONSEC and puts the AP back to Secure"; } ||
    { failn=$((failn+1)); echo "FAIL openocd l5_uid: $out"; }
  # A failed mailbox clear inside l5_boot still restores the attribution.
  out="$(tclsh <<TCL 2>&1
proc echo {s} { puts \$s }
proc mrw {r} { return 0 }
proc mww {r v} { if {\$r == 0x30028000} { error "bus fault" }; lappend ::w [format 0x%08X \$r] }
set ::w {}
source $R/tests/target/ports/stm32l562/openocd.tcl
l5_boot 0x20028000
puts "writes [lsort \$::w]"
TCL
)"
  grep -q "L5ERR zero .*bus fault" <<<"$out" && ! grep -q "L5BOOT" <<<"$out" &&
    grep -qx "writes $(for r in $want; do printf '%s %s ' "$r" "$r"; done | sed 's/ $//')" <<<"$out" &&
    { pass=$((pass+1)); echo "ok   openocd: a failed clear in l5_boot reports L5ERR and restores the attribution"; } ||
    { failn=$((failn+1)); echo "FAIL openocd l5_boot cleanup: $out"; }
else
  echo "skip openocd SECBB attribution (no tclsh)"
fi
# An OpenOCD stub that runs the l5_* operations of ports/stm32l562/openocd.tcl
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
        alias, t, out = int(w[1], 16), w[2:], []
        # Above level 0 the debug port is Non-secure only (AN5347).
        if o["RDP"] != "0xAA" and alias != 0x40022000:
            print("Error: Secure FLASH alias 0x%08X refused above RDP level 0" % alias); sys.exit(1)
        for i in range(0, len(t), 3):
            off, mask, val = int(t[i], 16), int(t[i + 1], 16), int(t[i + 2])
            for name, fo, fm, sh in FIELDS:
                if fo == off and fm & mask == fm:
                    out.append("%s=0x%X" % (name, (val & fm) >> sh))
        open(T + "/writes", "a").write("OB " + " ".join(out) + "\n")
        if not os.path.exists(T + "/l5/obstuck"):
            tz0 = o.get("TZEN")
            for kv in out:
                o[kv.split("=")[0]] = kv.split("=")[1]
            # RM0438: enabling TZEN resets the watermarks to all Secure.
            if tz0 == "0x0" and o.get("TZEN") == "0x1":
                o.update(SECWM1_PSTRT="0x0", SECWM1_PEND="0x7F", SECWM2_PSTRT="0x0", SECWM2_PEND="0x7F")
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
L5O=(env TARGET=stm32l562 STM32L562_PROBE_TOOL=openocd STM32L562_OPENOCD="$T/ocd/openocd" STM32L562_PYOCD="$T/ocd/pyocd" STM32_CLI="$T/no-cli" WT_PROVISION_STATE="$T/sto" PATH="$T/ocd:$T/bin:$PATH" "$P")
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
l5ob 0xAA 0x1 0x20 0x1 0x7F 0x0 0x7F 0x0
check "openocd: set-wrp merges both areas into their registers" 0 "read back as WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" set-wrp
[ "$(cat "$T/writes")" = "OB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F" ] && { pass=$((pass+1)); echo "ok   openocd: set-wrp writes only the WRP1A and WRP2A fields"; } || { failn=$((failn+1)); echo "FAIL openocd set-wrp writes: $(cat "$T/writes")"; }
: > "$T/writes"
check "openocd: verify-wrp sees the fence" 0 "armed: WRP1A pages 0x58-0x7F, WRP2A pages 0x0-0x1F" -- "${L5O[@]}" verify-wrp
check "openocd: restore interrupted by SIGTERM" 143 "stub runner stm32l562 positive sn=$L5OSN tool=openocd" -- env L5_RUNNER_SIG=1 WT_LOCK_CONFIRM=1 "${L5O[@]}" restore
[ "$(cat "$T/writes")" = "$(printf 'OB WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0\nOB WRP1A_PSTRT=0x58 WRP1A_PEND=0x7F WRP2A_PSTRT=0x0 WRP2A_PEND=0x1F')" ] &&
  { pass=$((pass+1)); echo "ok   openocd: an interrupted restore arms the fence again"; } || { failn=$((failn+1)); echo "FAIL openocd interrupted restore writes: $(cat "$T/writes")"; }
: > "$T/writes"
l5ob 0xAA 0x1 0x20 0x0
check "openocd: set-perimeter never touches BOOT_LOCK" 0 "read back as TZEN=0x1" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" set-perimeter
[ "$(cat "$T/writes")" = "OB TZEN=0x1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x57 SECWM2_PSTRT=0x20 SECWM2_PEND=0x7F SECBOOTADD0=0x180000" ] &&
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
l5ob 0xAA 0x1 0x20 0x1 0x7F 0x0 0x7F 0x0 0x10 0x40
check "openocd: restore keeps a range spanning guest and other pages" 2 "WRP2B also protects pages outside the guest windows" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" restore
nowrite
l5ob 0x55
check "openocd: an RDP regression from level 0.5 is previewed" 2 "l5_obw RDP=0xAA" -- env WT_LOCK_CONFIRM=1 "${L5O[@]}" regress
nowrite
if [ "$have_expect" = 1 ]; then
L5OR="env TARGET=stm32l562 STM32L562_PROBE_TOOL=openocd STM32L562_OPENOCD=$T/ocd/openocd STM32L562_PYOCD=$T/ocd/pyocd STM32_CLI=$T/no-cli WT_PROVISION_STATE=$T/sto PATH=$T/ocd:$T/bin:$PATH WT_LOCK_CONFIRM=1 $P"
out="$(expect -c "set timeout 300; spawn $L5OR regress; expect \"to continue: \"; send \"I ACCEPT 0xAA\r\"; expect eof; catch close; catch wait r; exit [lindex \$r 3]")"
rc=$?; [ $rc = 0 ] && [ "$(cat "$T/writes")" = "OB RDP=0xAA" ] && [ "$(awk '$1 == "RDP" { print $2 }' "$T/l5/ob")" = 0xAA ] &&
  { pass=$((pass+1)); echo "ok   openocd: the typed regression from level 0.5 writes RDP through the Non-secure alias"; } ||
  { failn=$((failn+1)); echo "FAIL openocd typed regression rc=$rc writes=$(cat "$T/writes")"; echo "$out" | tail -4; }
: > "$T/writes"
else
  typed_skip "openocd typed regression"
fi
if ! grep -v '^RESET' "$T/l5/ocdcalls" | grep -v "^sn=$L5OSN " | grep -q .; then pass=$((pass+1)); echo "ok   every OpenOCD session was bound to the ST-LINK serial"; else failn=$((failn+1)); echo "FAIL an OpenOCD session ran unbound: $(grep -v "^sn=$L5OSN " "$T/l5/ocdcalls" | head -2)"; fi
