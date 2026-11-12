#!/usr/bin/env bash
# Regression check for the STM32L562 hardware suite: with no board it SKIPs
# and passes, its logs and the runner's retained evidence never live under
# build/, a batch serializes on the board lock the runner shares, the runner
# stops before booting on a failed or unverified flash or a part outside the
# production perimeter, and both probe backends (STM32CubeProgrammer and
# OpenOCD, lib/stm32l562_probe.sh) erase the flash and program only image
# bytes. Runs without a board: every tool is a stub.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
suite="$repo/tests/target/run_stm32l562_suite.sh"
runner="$repo/tests/target/run_stm32l562_hardware.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
check() {
    if [ "$1" -eq 0 ]; then echo "PASS: $2"; else echo "FAIL: $2"; fails=$((fails + 1)); fi
}

# The defaults, read from the scripts: nothing retained lands under build/.
check "$(grep -qE '^logs="\$\{STM32L562_SUITE_LOGS:-\$repo/logs/' "$suite"; echo $?)" \
    "the suite's logs default to logs/, not build/"
check "$(grep -qE '^work="\$\{STM32L562_WORK:-\$repo/logs/' "$runner"; echo $?)" \
    "the runner's retained evidence defaults to logs/, not build/"
check "$(! grep -qE '(logs|work|lock)="\$\{[A-Z0-9_]+:-\$repo/build' "$suite" "$runner"; echo $?)" \
    "no evidence path defaults to build/"
check "$(grep -q 'flock' "$suite" && grep -q 'flock' "$runner"; echo $?)" \
    "the suite and the runner both take the board lock"
check "$(grep -qE '^evidence="\$work/\$scenario-\$engine"' "$runner"; echo $?)" \
    "the runner keeps each run's console and dumps by scenario and engine"
check "$(grep -qE '^scenarios="\$\{WT_STM32L562_SCENARIOS:-positive gtzcneg periphneg restart psa wrpoff wrpfence\}"' "$suite"; echo $?)" \
    "the suite's default scenarios are the seven board scenarios"

# No board: the detector says why, the suite SKIPs and passes.
printf '#!/bin/sh\necho "STM32L562E-DK ST-LINK not attached"\nexit 1\n' > "$tmp/nodetect.sh"
chmod +x "$tmp/nodetect.sh"
set +e
out="$(STM32L562_SUITE_DETECT="$tmp/nodetect.sh" STM32L562_SUITE_RUNNER=/bin/false \
    STM32L562_SUITE_LOGS="$tmp/skiplogs" "$suite" 2>&1)"; rc=$?
set -e
check "$([ "$rc" -eq 0 ] && grep -q "^SKIP: STM32L562 hardware suite (STM32L562E-DK ST-LINK not attached)" <<<"$out"; echo $?)" \
    "without a board the suite SKIPs with the detector's reason and passes"
check "$([ ! -e "$tmp/skiplogs" ]; echo $?)" "a skipped suite ran nothing"

# The default list on CubeProgrammer skips wrpfence (its verdict needs OpenOCD).
if command -v flock >/dev/null 2>&1; then
printf '#!/bin/sh\nexit 0\n' > "$tmp/okdetect.sh"
printf '#!/bin/sh\necho "ran $1" >> "%s/ran.txt"\n' "$tmp" > "$tmp/okrunner.sh"
chmod +x "$tmp/okdetect.sh" "$tmp/okrunner.sh"
set +e
out="$(env -u WT_STM32L562_SCENARIOS STM32L562_PROBE_TOOL=cubeprog STM32_CLI=/bin/echo \
    STM32L562_SUITE_DETECT="$tmp/okdetect.sh" STM32L562_SUITE_RUNNER="$tmp/okrunner.sh" \
    STM32L562_SUITE_LOGS="$tmp/cplogs" STM32L562_HW_LOCK="$tmp/cp.lock" "$suite" 2>&1)"; rc=$?
set -e
check "$([ "$rc" -eq 0 ] && grep -q "^SKIP: hardware/wrpfence (needs the OpenOCD backend" <<<"$out" &&
    ! grep -q "ran wrpfence" "$tmp/ran.txt" && grep -q "ran wrpoff" "$tmp/ran.txt"; echo $?)" \
    "on CubeProgrammer the default suite skips wrpfence and runs the rest"
else
  echo "SKIP: default-suite backend check (the suite's flock is the board host's, not this host's)"
fi
set +e
out="$(env STM32L562_PROBE_TOOL=cubeprog STM32_CLI="$tmp/no-cli" "$repo/tests/target/detect_stm32l562.sh" 2>&1)"; rc=$?
set -e
check "$([ "$rc" -eq 1 ] && grep -q "STM32CubeProgrammer CLI not installed" <<<"$out"; echo $?)" \
    "the detector names a missing CubeProgrammer"
set +e
out="$(env STM32L562_PROBE_TOOL=openocd STM32L562_OPENOCD="$tmp/no-ocd" "$repo/tests/target/detect_stm32l562.sh" 2>&1)"; rc=$?
set -e
check "$([ "$rc" -eq 1 ] && grep -q "OpenOCD not installed" <<<"$out"; echo $?)" \
    "the detector names a missing OpenOCD"
set +e
out="$(env STM32_CLI="$tmp/no-cli" STM32L562_OPENOCD="$tmp/no-ocd" "$repo/tests/target/detect_stm32l562.sh" 2>&1)"; rc=$?
set -e
check "$([ "$rc" -eq 1 ] && grep -q "neither STM32CubeProgrammer CLI nor OpenOCD" <<<"$out"; echo $?)" \
    "with neither probe tool the detector says so"

# A host without one of the runner's build tools is a SKIP with its name.
mkdir -p "$tmp/toolbin"
for t in STM32_Programmer_CLI arm-none-eabi-gcc arm-none-eabi-gcc-nm \
        arm-none-eabi-nm arm-none-eabi-objcopy arm-none-eabi-objdump \
        arm-none-eabi-size make python3 stty sha256sum flock timeout; do
    printf '#!/bin/sh\nexit 0\n' > "$tmp/toolbin/$t"
    chmod +x "$tmp/toolbin/$t"
done
detect_without() {
    mv "$tmp/toolbin/$1" "$tmp/toolbin/$1.off"
    set +e
    out="$(env PATH="$tmp/toolbin" STM32_CLI="$tmp/toolbin/STM32_Programmer_CLI" \
        "$BASH" "$repo/tests/target/detect_stm32l562.sh" 2>&1)"; rc=$?
    set -e
    mv "$tmp/toolbin/$1.off" "$tmp/toolbin/$1"
    [ "$rc" -eq 1 ] && grep -q "^$1 not installed" <<<"$out"
}
for t in arm-none-eabi-objcopy arm-none-eabi-size make sha256sum stty; do
    check "$(detect_without "$t"; echo $?)" "the detector names a missing $t"
done

# The OpenOCD backend finds the DK by pyOCD's board name or the ST-LINK's
# mass-storage label, and a named serial must be an attached DK's too.
mkdir -p "$tmp/ocdbin"
cat > "$tmp/ocdbin/pyocd" <<'EOF2'
#!/bin/sh
[ "$1" = list ] || exit 1
echo "  #   Probe/Board        Unique ID                  Target"
echo "  0   STLINK-V3          ${PY_SN:-002100243137511533333639}   x stm32l562qeixq"
echo "      ${PY_BOARD:-STM32L562E-DK}"
echo "  1   STLINK-V3          004400000000000000000001   n/a"
echo "      NUCLEO-H563ZI"
EOF2
printf '#!/bin/sh
exit 0
' > "$tmp/ocdbin/openocd"
printf '#!/bin/sh
exit 0
' > "$tmp/ocdbin/lsblk"
chmod +x "$tmp/ocdbin/"*
for t in arm-none-eabi-gcc arm-none-eabi-gcc-nm arm-none-eabi-nm arm-none-eabi-objcopy \
        arm-none-eabi-objdump arm-none-eabi-size make python3 stty sha256sum flock timeout; do
    command -v "$t" >/dev/null 2>&1 || cp "$tmp/toolbin/$t" "$tmp/ocdbin/$t"
done
printf '#!/bin/sh\nshift\nexec "$@"\n' > "$tmp/ocdbin/timeout"
chmod +x "$tmp/ocdbin/timeout"
ocd_detect() {
    set +e
    out="$(env PATH="$tmp/ocdbin:$PATH" STM32_CLI="$tmp/no-cli" STM32L562_PYOCD="$tmp/ocdbin/pyocd" \
        STM32L562_OPENOCD="$tmp/ocdbin/openocd" STM32L562_CONSOLE=/dev/null "$@" \
        "$repo/tests/target/detect_stm32l562.sh" 2>&1)"; rc=$?
    set -e
}
ocd_detect
check "$([ "$rc" -eq 0 ]; echo $?)" "OpenOCD: the DK pyOCD names is found ($out)"
ocd_detect PY_BOARD=NUCLEO-L552ZE-Q PY_SN=002100243137511533333639x
check "$([ "$rc" -eq 1 ] && grep -q "STM32L562E-DK ST-LINK not attached" <<<"$out"; echo $?)" \
    "OpenOCD: an ST-LINK on another board is never picked"
ocd_detect STM32L562_STLINK_SN=004400000000000000000001
check "$([ "$rc" -eq 1 ] && grep -q "not attached" <<<"$out"; echo $?)" \
    "OpenOCD: a named serial that is not a DK's is refused"
printf '#!/bin/sh
echo "002100243137511533333639 DIS_L562QE"
echo "004400000000000000000001 NOD_H563ZI"
' > "$tmp/ocdbin/lsblk"
ocd_detect STM32L562_PYOCD="$tmp/no-pyocd"
check "$([ "$rc" -eq 0 ]; echo $?)" "OpenOCD: without pyOCD the mass-storage label finds the DK"
printf '#!/bin/sh\necho "abc[shutdown] DIS_L562QE"\n' > "$tmp/ocdbin/lsblk"
ocd_detect STM32L562_PYOCD="$tmp/no-pyocd"
check "$([ "$rc" -eq 1 ] && grep -q "not attached" <<<"$out"; echo $?)" \
    "OpenOCD: a device serial that is not letters and digits is never used"
check "$(bash -c '. "$1/tests/target/lib/stm32l562_probe.sh"; L5_TOOL=openocd; L5_OPENOCD=/bin/echo
    l5_ocd "x;shutdown" hot; true' _ "$repo" | grep -qx "L5ERR serial"; echo $?)" \
    "OpenOCD: a session refuses a serial OpenOCD would evaluate as Tcl"

# A stub runner that cleans build/ the way a real run does, then reports; its
# log must survive in the suite's log dir, and a second batch waits its turn.
lock_checks() {
local stub out rc holder waited wrc
stub="$tmp/runner.sh"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
rm -rf "${STUB_REPO}/build/stm32l562-suite"
echo "  [check] PASS  stub $1 ran with lock=${STM32L562_HW_LOCKED:-unset}"
echo "PASS: hardware/stm32l562/$1"
EOF
chmod +x "$stub"
export STUB_REPO="$repo" STM32L562_SUITE_RUNNER="$stub" STM32L562_SUITE_DETECT=/bin/true
export STM32L562_SUITE_LOGS="$tmp/logs" STM32L562_HW_LOCK="$tmp/hw.lock"
export WT_STM32L562_SCENARIOS="alpha beta"
set +e
out="$("$suite" 2>&1)"; rc=$?
set -e
check "$([ "$rc" -eq 0 ]; echo $?)" "the stub batch passes (rc $rc)"
check "$(grep -q "PASS: hardware/alpha" <<<"$out" && grep -q "PASS: hardware/beta" <<<"$out"; echo $?)" \
    "both scenarios reported"
check "$([ -s "$tmp/logs/alpha.log" ] && [ -s "$tmp/logs/beta.log" ]; echo $?)" \
    "every scenario's log survived the runner cleaning build/"
check "$(grep -q "lock=1" "$tmp/logs/beta.log"; echo $?)" \
    "the runner saw the batch's lock and did not take its own"
check "$(grep -q "^LOGS: $tmp/logs" <<<"$out"; echo $?)" "the suite names its log dir"

# Serialization: while another batch holds the lock, a new batch waits.
( flock "$tmp/hw.lock" sleep 4 ) &
holder=$!
sleep 0.5
rm -rf "$tmp/logs"
set +e
waited="$(timeout 2 "$suite" 2>&1)"; wrc=$?
set -e
check "$([ "$wrc" -eq 124 ]; echo $?)" "a batch waits for the lock holder (rc $wrc)"
check "$(grep -q "^WAIT:" <<<"$waited"; echo $?)" "the waiting batch says so"
check "$([ ! -e "$tmp/logs/alpha.log" ]; echo $?)" "the waiting batch ran no scenario"
wait "$holder"
"$suite" >/dev/null 2>&1
check "$([ -s "$tmp/logs/beta.log" ]; echo $?)" "the batch runs once the lock is released"
}
if command -v flock >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    lock_checks
else
    echo "SKIP: board lock serialization (flock and timeout are the board host's, not this host's)"
fi

# l5_program: both backends erase the whole flash, then program only the
# images; a failed, erroring or unverified run reports failure.
cat > "$tmp/cubecli" <<'EOF2'
#!/bin/sh
echo "$*" > "$PB_ARGS"
case "$PB_MODE" in
    silent) exit 1 ;; error) echo "Error: failed to download Segment[0]"; exit 0 ;;
    oneverify) echo "Download verified successfully"; exit 0 ;;
esac
for _ in 1 2 3 4; do echo "File download complete"; echo "Download verified successfully"; done
EOF2
cat > "$tmp/ocd" <<'EOF2'
#!/bin/sh
printf '%s\n' "$@" > "$PB_ARGS"
case "$PB_MODE" in
    silent) exit 1 ;; error) echo "L5ERR write x"; echo "L5PROG 4"; exit 0 ;;
    oneverify) echo "L5PROG 1"; exit 0 ;;
esac
echo "L5PROG 4"
EOF2
chmod +x "$tmp/cubecli" "$tmp/ocd"
program_case() {
    bash -c '
. "$1/tests/target/lib/stm32l562_probe.sh"
L5_TOOL="$2"
l5_program SN /w.bin@0x0C000000 /t.bin@0x0C00C000 /g0.bin@0x08060000 /g1.bin@0x08070000 >/dev/null &&
    echo RELEASED' _ "$repo" "$1" 2>&1
}
for tool in cubeprog openocd; do
    export STM32_CLI="$tmp/cubecli" STM32L562_OPENOCD="$tmp/ocd" PB_ARGS="$tmp/pb.args"
    check "$(! PB_MODE=silent program_case "$tool" | grep -q RELEASED; echo $?)" \
        "$tool: a failed programming run stops before the boot"
    check "$(! PB_MODE=error program_case "$tool" | grep -q RELEASED; echo $?)" \
        "$tool: a failed step reported with exit 0 stops before the boot"
    check "$(! PB_MODE=oneverify program_case "$tool" | grep -q RELEASED; echo $?)" \
        "$tool: a run that programmed or verified only one image stops before the boot"
    check "$(PB_MODE=ok program_case "$tool" | grep -q RELEASED; echo $?)" \
        "$tool: a complete programming run proceeds to the boot"
    unset STM32_CLI STM32L562_OPENOCD
done
export STM32_CLI="$tmp/cubecli" STM32L562_OPENOCD="$tmp/ocd" PB_ARGS="$tmp/pb.args"
PB_MODE=ok program_case cubeprog >/dev/null || true
check "$(grep -q -- "sn=SN mode=UR -e all -d /w.bin 0x0C000000 -v -d /t.bin 0x0C00C000 -v -d /g0.bin 0x08060000 -v -d /g1.bin 0x08070000 -v" "$tmp/pb.args"; echo $?)" \
    "cubeprog: a mass erase, then each image downloaded and verified on its own"
PB_MODE=ok program_case openocd >/dev/null || true
check "$(grep -qx "adapter serial SN" "$tmp/pb.args" && grep -qx "reset halt" "$tmp/pb.args" &&
    grep -qx "l5_program 201326592 524288 {/w.bin} 201326592 {/t.bin} 201375744 {/g0.bin} 134610944 {/g1.bin} 134676480" "$tmp/pb.args"; echo $?)" \
    "openocd: bound to the ST-LINK, the core held at reset, the whole flash erased, then each image"
unset STM32_CLI STM32L562_OPENOCD PB_ARGS
# The OpenOCD operation verifies every image before it reports L5PROG.
sed -n '/^proc l5_program /,/^}/p' "$repo/tests/target/lib/stm32l562_openocd.tcl" > "$tmp/l5_program.tcl"
check "$(awk '/flash write_image/ { w = NR } /verify_image/ { v = NR } /echo "L5PROG/ { p = NR }
    END { exit !(w && v > w && p > v) }' "$tmp/l5_program.tcl"; echo $?)" \
    "openocd: every image is verified after it is written and before L5PROG"
check "$(grep -q 'L5ERR verify' "$tmp/l5_program.tcl"; echo $?)" \
    "openocd: a verify mismatch is reported as a failure"

# The console capture passes only when it ran for the whole budget.
sed -n '/^console_start() {/,/^}/p;/^console_finish() {/,/^}/p' "$runner" > "$tmp/console.sh"
console_case() {
    bash -c '
set -euo pipefail
fail() { echo "FAIL: $*"; exit 1; }
timeout() { case "$TO_MODE" in full) return 124 ;; eof) return 0 ;; *) return 1 ;; esac; }
evidence="$1"; console=/dev/null; console_seconds=1
. "$2"
console_start
console_finish && echo CAPTURED' _ "$tmp" "$tmp/console.sh" 2>&1
}
check "$(TO_MODE=full console_case | grep -q CAPTURED; echo $?)" \
    "a capture that ran the whole budget is accepted"
check "$(! TO_MODE=eof console_case | grep -q CAPTURED; echo $?)" \
    "a console that hit EOF early fails the run"
check "$(! TO_MODE=err console_case | grep -q CAPTURED; echo $?)" \
    "a console reader error fails the run"

# ensure_perimeter must refuse a part off the production layout or with the
# guest fence armed, before anything is built or flashed.
sed -n '/^ensure_perimeter() {/,/^}/p' "$runner" > "$tmp/ensure_perimeter.sh"
perimeter_case() {
    bash -c '
set -euo pipefail
fail() { echo "FAIL: $*"; exit 1; }
log() { echo "$*"; }
l5_ob_displ() { printf "     %-12s : %s (x)\n" RDP "${OB_RDP:-0xAA}" TZEN 0x1 SECWM1_PSTRT 0x0 \
    SECWM1_PEND 0x7F SECWM2_PSTRT 0x0 SECWM2_PEND "${OB_WM2:-0x3F}" \
    SECBOOTADD0 "${OB_BOOT:-0x180000}" BOOT_LOCK "${OB_LOCK:-0x1}" DBANK 0x1 SWAP_BANK 0x0 \
    WRP2A_PSTRT "${OB_WRP_S:-0x7F}" WRP2A_PEND "${OB_WRP_E:-0x0}" WRP2B_PSTRT 0x7F WRP2B_PEND 0x0; }
. "$1"
stlink_sn=SN
ensure_perimeter && echo READY' _ "$tmp/ensure_perimeter.sh" 2>&1
}
check "$(perimeter_case | grep -q READY; echo $?)" "the production perimeter at level 0 is accepted"
check "$(! OB_RDP=0x55 perimeter_case | grep -q READY; echo $?)" "a part above RDP level 0 is refused"
check "$(! OB_WM2=0x7F perimeter_case | grep -q READY; echo $?)" \
    "a watermark that makes the guest windows Secure is refused"
check "$(! OB_WRP_S=0x40 OB_WRP_E=0x7F perimeter_case | grep -q READY; echo $?)" \
    "an armed guest WRP fence is refused before the reflash"
check "$(! OB_BOOT=0x1801C0 perimeter_case | grep -q READY; echo $?)" \
    "a Secure boot address other than wolfBoot's is refused"
check "$(OB_LOCK=0x0 perimeter_case | grep -q READY; echo $?)" \
    "BOOT_LOCK is not required: the run is the evidence boot-lock asks for"

# make_flash_images trims every image of its erased tail (never programming
# 0xFF over the vault, swap or update slot) and refuses an image larger than
# its window.
sed -n '/^make_flash_images() {/,/^}/p' "$runner" > "$tmp/images.sh"
mkdir -p "$tmp/img/g" "$tmp/img/build"
head -c 4096 /dev/zero | tr '\0' 'W' > "$tmp/img/wolfboot.bin"
{ head -c 8190 /dev/zero | tr '\0' 'T'; head -c 4096 /dev/zero | LC_ALL=C tr '\0' '\377'; } > "$tmp/img/build/wolftrust_v1_signed.bin"
images_case() {
    bash -c '
set -euo pipefail
fail() { echo "FAIL: $*"; exit 1; }
. "$2/tests/target/lib/stm32l562_probe.sh"
evidence="$1"; wolfboot_dir="$1"; repo="$1"; part_size=0x20000
wolfboot_flash_addr=0x0C000000; secure_flash_addr=0x0C00C000
guest0_flash_addr=0x08060000; guest1_flash_addr=0x08070000
. "$3"
make_flash_images "$1/g" && printf "%s\n" "${flash_specs[@]}" && echo PACKED' _ "$tmp/img" "$repo" "$tmp/images.sh" 2>&1
}
head -c 65536 /dev/zero | tr '\0' 'A' > "$tmp/img/g/guest0.bin"
head -c 1024 /dev/zero | tr '\0' 'B' > "$tmp/img/g/guest1.bin"
images_out="$(images_case || true)"
check "$(grep -q PACKED <<<"$images_out" &&
    grep -qx "$tmp/img/flash-wolfboot.bin@0x0C000000" <<<"$images_out" &&
    grep -qx "$tmp/img/flash-wolftrust.bin@0x0C00C000" <<<"$images_out" &&
    grep -qx "$tmp/img/flash-guest0.bin@0x08060000" <<<"$images_out" &&
    grep -qx "$tmp/img/flash-guest1.bin@0x08070000" <<<"$images_out"; echo $?)" \
    "each image is programmed at its own window"
check "$([ "$(wc -c < "$tmp/img/flash-wolftrust.bin")" -eq 8192 ] &&
    [ "$(dd if="$tmp/img/flash-wolftrust.bin" bs=1 skip=8189 count=1 2>/dev/null)" = T ] &&
    [ "$(wc -c < "$tmp/img/flash-guest0.bin")" -eq 65536 ]; echo $?)" \
    "a trailing erased run is dropped, padded only to the 8-byte double-word"
head -c 65537 /dev/zero | tr '\0' 'B' > "$tmp/img/g/guest1.bin"
check "$(! images_case | grep -q PACKED; echo $?)" "a guest 1 larger than its window is refused"
head -c 65537 /dev/zero | tr '\0' 'A' > "$tmp/img/g/guest0.bin"
head -c 1024 /dev/zero | tr '\0' 'B' > "$tmp/img/g/guest1.bin"
check "$(! images_case | grep -q PACKED; echo $?)" "a guest 0 larger than its window is refused"

# The OpenOCD backend decodes the option registers as CubeProgrammer names
# them (words read from the DK at TZEN=1, SECWM2 0-0x3F) and encodes writes
# into register fields, never an RDP other than level 0.
ob_out="$(bash -c '. "$1/tests/target/lib/stm32l562_probe.sh"
l5_ob_fields ffeff8aa 0800007f 0bf9007f 0c00007c ffffff80 7f807f80 ff80ffff ff80ffff \
    ffbfff80 7f807f80 ff80ffff ff80ffff' _ "$repo" | awk '{ print $1 "=" $3 }' | tr '\n' ' ')"
check "$([ "$ob_out" = "RDP=0xAA TZEN=0x1 DBANK=0x1 SWAP_BANK=0x0 SECBOOTADD0=0x180000 BOOT_LOCK=0x0 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F SECWM2_PSTRT=0x0 SECWM2_PEND=0x3F WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP1B_PSTRT=0x7F WRP1B_PEND=0x0 WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0 " ]; echo $?)" \
    "openocd: the DK's option registers decode to the production perimeter ($ob_out)"
obw_case() {
    bash -c '. "$1/tests/target/lib/stm32l562_probe.sh"
L5_TOOL=openocd; L5_OPENOCD="$2"; shift 2
l5_ob_write SN UR "$@"' _ "$repo" "$tmp/obwocd" "$@" 2>&1
}
printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s"\necho "L5OBW 0x00000000"\n' "$tmp/obw.args" > "$tmp/obwocd"
chmod +x "$tmp/obwocd"
obw_case WRP2A_PSTRT=0x40 WRP2A_PEND=0x7F SECBOOTADD0=0x180000 >/dev/null || true
check "$(grep -qx "l5_obw 0x68 0x7F 64 0x68 0x007F0000 8323072 0x4C 0xFFFFFF80 201326592" "$tmp/obw.args" &&
    grep -qx "reset halt" "$tmp/obw.args"; echo $?)" \
    "openocd: option bytes are merged into their register fields with the core held"
rm -f "$tmp/obw.args"
check "$(! obw_case RDP=0x55 >/dev/null && [ ! -e "$tmp/obw.args" ]; echo $?)" \
    "openocd: an RDP write other than level 0 is refused before any session"

# The OpenOCD procs against a stub target: a register that will not take its
# saved value back leaves the core halted instead of resuming the firmware.
if command -v tclsh >/dev/null 2>&1; then
cat > "$tmp/tclstub.tcl" <<'TCL'
set stuck [lindex $argv 0]
array set regs {}
set resumed 0
proc stm32l5x.cpu {op} { return running }
proc halt {t} {}
proc resume {} { global resumed; set resumed 1 }
proc stm32l5x.dap {args} {}
proc echo {s} { puts $s }
proc mrw {a} {
    global regs
    set a [expr {$a}]
    if {$a == 0xE000EE08} { return [expr {[info exists regs($a)] ? ($regs($a) | 0x10000) : 0x10000}] }
    if {$a == 0xE000EDD4} { return 8 }
    return [expr {[info exists regs($a)] ? $regs($a) : 0}]
}
proc mww {a v} {
    global regs stuck
    set a [expr {$a}]
    if {$stuck ne "" && $a == $stuck && [info exists regs($a)]} { return }
    set regs($a) [expr {$v & 0xFFFFFFFF}]
}
proc read_memory {a w n} { return [lrepeat $n 0x11] }
source [lindex $argv 1]
eval [lindex $argv 2]
puts "resumed=$resumed"
TCL
tcl="$repo/tests/target/lib/stm32l562_openocd.tcl"
tcl_case() { tclsh "$tmp/tclstub.tcl" "$1" "$tcl" "$2" 2>&1; }
out="$(tcl_case "" "l5_mem 0x20040000 1")"
check "$(grep -q '^L5MEM 0x20040000' <<<"$out" && grep -q 'resumed=1' <<<"$out"; echo $?)" \
    "openocd: a held read restores the attribution and resumes the core"
out="$(tcl_case 0x50033000 "l5_mem 0x20040000 1")"
check "$(grep -q '^L5ERR read .*not restored: 0x50033000; the core stays halted' <<<"$out" && grep -q 'resumed=0' <<<"$out"; echo $?)" \
    "openocd: an MPCBB that is not restored leaves the core halted"
out="$(tcl_case 0x500220AC "l5_dump $tmp/d.bin 0x08060000 4")"
check "$(grep -q '^L5ERR dump .*not restored: 0x500220AC' <<<"$out" && grep -q 'resumed=0' <<<"$out"; echo $?)" \
    "openocd: a SECBB that is not restored leaves the core halted"
out="$(tcl_case "" "l5_uid")"
check "$(grep -q '^L5UID 0x0BFA0590' <<<"$out" && grep -q 'resumed=1' <<<"$out"; echo $?)" \
    "openocd: the UID read restores the SAU and resumes the core"
out="$(tcl_case 0xE000EDE0 "l5_uid")"
check "$(grep -q '^L5ERR uid: the SAU could not be restored; the core stays halted' <<<"$out" && grep -q 'resumed=0' <<<"$out"; echo $?)" \
    "openocd: a SAU region that is not restored leaves the core halted"
else
  echo "SKIP: OpenOCD proc checks (no tclsh)"
fi

echo "stm32l562 suite evidence: $fails failures"
[ "$fails" -eq 0 ]
