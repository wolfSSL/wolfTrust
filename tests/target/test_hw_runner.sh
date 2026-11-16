#!/usr/bin/env bash
# Self-tests of the hardware runner that need no board: every port profile
# satisfies the hook contract and keeps option bytes, fuses and life-cycle
# state out of the runner; the suite keeps its evidence under logs/, holds the
# board lock for a batch and waits for another holder; a pyOCD session that
# died silently or reported an error with exit 0 stops programming.
# shellcheck disable=SC2016,SC2319
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
lib="$repo/tests/target/lib"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
check() {
    if [ "$1" -eq 0 ]; then echo "PASS: $2"; else echo "FAIL: $2"; fails=$((fails + 1)); fi
}

for port in $(python3 "$lib/scenario_matrix.py" --list-ports); do
    profile="$repo/tests/target/ports/$port/hw.sh"
    check "$([ -f "$profile" ]; echo $?)" "$port has a hardware profile"
    out="$(bash -c '
        set -u; port="$1"; here="$2"; repo="$3"; evidence="$4"
        . "$here/lib/scenario.sh"; . "$here/lib/hw_runner.sh"; . "$here/lib/hw_pyocd.sh"; . "$here/lib/hw_stcli.sh"
        . "$here/ports/$port/hw.sh"
        hw_require_hooks && echo HOOKS-OK
        hw_capture_seconds positive | grep -qE "^[0-9]+$" && echo CAPTURE-OK
        [ -n "${HW_GUEST0_RAM:-}" ] && [ -n "${HW_GUEST1_RAM:-}" ] && [ -n "${HW_SECURE_ADDR:-}" ] && echo FACTS-OK
    ' _ "$port" "$repo/tests/target" "$repo" "$tmp" 2>&1 || true)"
    check "$(grep -q HOOKS-OK <<<"$out"; echo $?)" "$port profile defines every required hook"
    check "$(grep -q CAPTURE-OK <<<"$out"; echo $?)" "$port profile gives a numeric console window"
    check "$(grep -q FACTS-OK <<<"$out"; echo $?)" "$port profile names the image and RAM addresses"
    # No option-byte, fuse or life-cycle write anywhere in the runner code.
    check "$(! grep -nE -- '-ob [A-Za-z0-9_]+=|-psrss [^d]|blhost .*(efuse|fuse-program|set-property)|-sdp |debugauth=1' \
        "$profile" "$repo/tests/target/run_hardware.sh" "$lib/hw_runner.sh" "$lib/hw_pyocd.sh" "$lib/hw_stcli.sh"; echo $?)" \
        "$port: no option-byte, fuse or life-cycle write in the runner"
    check "$(grep -q 'HW_PROBE' "$profile"; echo $?)" "$port profile binds the probe"
done
check "$(! grep -q "safe.directory '\*'" "$repo/tests/target/run_hardware.sh"; echo $?)" \
    "the runner does not blanket-trust every directory"

# The build half sees each profile's build configuration before any hook runs.
cose="$(bash -c '. "$1/ports/mimxrt700/hw.sh"; echo "${WT_ATTEST_COSE:-unset}"' _ "$repo/tests/target" 2>/dev/null || true)"
check "$([ "$cose" = 0 ]; echo $?)" "the RT700 chain is built without COSE attestation, as the EVK runner built it"
after="$(bash -c '. "$1/ports/stm32h563/hw.sh"; echo "${HW_VERIFY_AFTER_BOOT:-1}"' _ "$repo/tests/target" 2>/dev/null || true)"
check "$([ "$after" = 0 ]; echo $?)" "the H5 run reads no guest flash from the running chain"
# The VNET guests' exit breakpoint ends an emulator run; on silicon it would fault.
# shellcheck disable=SC1091,SC2329
vnet_make() {
    (
        cd "$tmp" || exit 1
        make() { printf '%s\n' "$@" > "$tmp/vnet_make"; }
        . "$repo/tests/target/ports/stm32h563/m33mu.sh"
        port_build_vnet_guests "$1"
    ) >/dev/null 2>&1
    cat "$tmp/vnet_make" 2>/dev/null
}
check "$(! vnet_make hardware | grep -q WT_VNET_EXIT_BKPT && vnet_make emulator | grep -q WT_VNET_EXIT_BKPT &&
         grep -q 'port_build_vnet_guests hardware' "$repo/tests/target/run_hardware.sh"; echo $?)" \
    "the hardware VNET guests carry no emulator exit breakpoint"
# A stamped wolfBoot tree is reused without the SDK it was built with.
wb="$(bash -c '
    set -u; T="$2"; log() { echo "$*"; }; stage() { :; }
    . "$1/lib/wolfboot_stage.sh"
    WOLFBOOT_REF=r WOLFBOOT_CONFIG=c WOLFBOOT_PATCHES="" WOLFBOOT_NEEDS_SDK=1 WOLFBOOT_REPO=/nonexistent
    unset MCUXPRESSO MCUXPRESSO_CMSIS; HOME="$T/nohome"
    mkdir -p "$T/wb/tools/keytools"; echo x > "$T/wb/wolfboot.bin"; echo k > "$T/wb/wolfboot_signing_private_key.der"
    printf "#!/bin/sh\n" > "$T/wb/tools/keytools/sign"; chmod +x "$T/wb/tools/keytools/sign"
    wolfboot_stamp > "$T/wb/.wt_first_stage"
    wolfboot_build "$T/wb" && echo REUSED
    wolfboot_build "$T/wb-new" || echo REFUSED
' _ "$repo/tests/target" "$tmp" 2>&1 || true)"
check "$(grep -q '^REUSED' <<<"$wb" && grep -q '^REFUSED' <<<"$wb" && grep -q 'MCUXpresso SDK' <<<"$wb" &&
         ! grep -q wolfboot_sdk_env "$repo/tests/target/run_target.sh" "$repo/tests/target/run_hardware.sh"; echo $?)" \
    "a stamped wolfBoot tree is reused without the SDK; only a build needs it"

# The shared collector and the judge agree on the words: every sym., g0., g1.,
# g0sym., g1sym. and peer. key a minimum scenario's checks read is one the
# collector writes (a port's own hw_collect words are outside this contract).
# shellcheck disable=SC1090,SC1091,SC2034,SC2329
collect_keys() {
    local port="$1" scenario="$2" g0="$3" g1="$4"
    (
        cd "$tmp" || exit 1
        mkdir -p build "$tmp/ev"; echo x > build/wolftrust_v1_signed.bin; : > "$tmp/ev/swd.txt"
        set -u; here="$repo/tests/target"; evidence="$tmp/ev"; WT_ENGINE=native
        . "$here/lib/scenario.sh"; . "$here/lib/hw_runner.sh"; . "$here/lib/hw_pyocd.sh"; . "$here/lib/hw_stcli.sh"
        . "$here/ports/$port/hw.sh"
        unset -f hw_collect
        read_word() { echo 00000001; }
        elf_sym() { echo 0x20000000; }
        sha256sum() { echo 0000; }
        sleep() { :; }
        SC_GUEST0="$g0"; SC_GUEST1="$g1"; probe_addr=0x20000000
        G0_ELF=/dev/null; G1_ELF=/dev/null
        hw_collect_words
        cut -d= -f1 "$tmp/ev/swd.txt"
    ) 2>/dev/null
}
for port in $(python3 "$lib/scenario_matrix.py" --list-ports); do
    for scenario in $(python3 "$lib/scenarios.py" --hardware-minimum); do
        eval "$(python3 "$lib/scenarios.py" --port "$port" --scenario "$scenario" --env hardware --shell | sed -n 's/^SC_GUEST\([01]\)=/PLAN_GUEST\1=/p')"
        have="$(collect_keys "$port" "$scenario" "$PLAN_GUEST0" "$PLAN_GUEST1")"
        missing=""
        while IFS= read -r line; do
            key="${line##*\[}"; key="${key%]}"
            case "$key" in sym.*|g0.*|g1.*|g0sym.*|g1sym.*|peer.*) ;; *) continue ;; esac
            case "$line" in
                *advancing:*) for k in "$key@0" "$key@1"; do grep -qxF "$k" <<<"$have" || missing="$missing $k"; done ;;
                *) grep -qxF "$key" <<<"$have" || missing="$missing $key" ;;
            esac
        done < <(python3 "$lib/scenarios.py" --port "$port" --scenario "$scenario" --env hardware --asserts | grep -E '^  (word|advancing): .*\[.*\]$')
        check "$([ -z "$missing" ]; echo $?)" "$port $scenario: the collector writes every word the judge reads${missing:+ (missing:$missing)}"
    done
done

# The suite: evidence under logs/, one lock per batch, a waiting batch says so.
suite="$repo/tests/target/run_hardware_suite.sh"
check "$(grep -qE 'logs="\$\{WT_HW_SUITE_LOGS:-\$repo/logs/' "$suite"; echo $?)" "the suite's logs default to logs/, not build/"
check "$(grep -qE 'work="\$repo/logs/\$port-hw"' "$repo/tests/target/run_hardware.sh"; echo $?)" \
    "the runner's retained evidence defaults to logs/, not build/"
stub="$tmp/runner.sh"
cat > "$stub" <<'EOF'
#!/bin/bash
echo "  [check] PASS  stub $2 ran with lock=${WT_HW_LOCKED:-unset}"
echo "PASS: hardware/$1/$2"
EOF
chmod +x "$stub"
export WT_HW_SUITE_RUNNER="$stub" WT_HW_SUITE_DETECT="$(command -v true)" WT_HW_SUITE_LOGS="$tmp/logs" WT_HW_SUITE_LOCK="$tmp/hw.lock"
out="$("$suite" mcxn947 alpha beta 2>&1)"; rc=$?
check "$([ "$rc" -eq 0 ]; echo $?)" "a stub batch passes (rc $rc)"
check "$(grep -q "PASS: hardware/alpha" <<<"$out" && grep -q "PASS: hardware/beta" <<<"$out"; echo $?)" "both scenarios reported"
check "$([ -s "$tmp/logs/alpha.log" ] && [ -s "$tmp/logs/beta.log" ]; echo $?)" "every scenario's log is kept"
check "$(grep -q "lock=1" "$tmp/logs/beta.log"; echo $?)" "the runner saw the batch's lock and did not take its own"
check "$(grep -q "^LOGS: $tmp/logs" <<<"$out"; echo $?)" "the suite names its log dir"
skipper="$tmp/skipper.sh"
printf '#!/bin/bash\necho "SKIP: $1 hardware (board gone)"\nexit 0\n' > "$skipper"
chmod +x "$skipper"
out="$(WT_HW_SUITE_RUNNER="$skipper" "$suite" mcxn947 alpha 2>&1)" && src=0 || src=$?
check "$([ "$src" -ne 0 ] && grep -q "^SKIP: hardware/alpha" <<<"$out" && ! grep -q "PASS: hardware/" <<<"$out"; echo $?)" \
    "a scenario the runner skipped mid-batch is neither a pass nor a passing batch"
if command -v flock >/dev/null 2>&1; then
    ( flock "$tmp/hw.lock" sleep 4 ) &
    holder=$!
    sleep 0.5
    rm -rf "$tmp/logs"
    set +e
    waited="$(timeout 2 "$suite" mcxn947 alpha 2>&1)"; wrc=$?
    set -e
    check "$([ "$wrc" -eq 124 ]; echo $?)" "a batch waits for the lock holder (rc $wrc)"
    check "$(grep -q "^WAIT:" <<<"$waited"; echo $?)" "the waiting batch says so"
    check "$([ ! -e "$tmp/logs/alpha.log" ]; echo $?)" "the waiting batch ran no scenario"
    wait "$holder"
    "$suite" mcxn947 alpha >/dev/null 2>&1
    check "$([ -s "$tmp/logs/alpha.log" ]; echo $?)" "the batch runs once the lock is released"
else
    echo "SKIP: board lock cases (no flock on this host)"
fi
smoke="$("$suite" mcxn947 smoke 2>&1 | grep -c '^RUN: hardware/')"
check "$([ "$smoke" -eq "$(python3 "$lib/scenarios.py" --hardware-minimum | wc -w | tr -d ' ')" ]; echo $?)" \
    "the smoke tier is the eight-scenario minimum ($smoke)"

# The conformance capture stops at the suite report, not at the window's end.
# shellcheck disable=SC2329
boot_case() {
    bash -c '
set -u; here="$1"; repo="$2"; evidence="$3"; port=stm32h563; mkdir -p "$evidence"
. "$here/lib/scenario.sh"; . "$here/lib/hw_runner.sh"; . "$here/lib/hw_pyocd.sh"; . "$here/lib/hw_stcli.sh"
. "$here/ports/stm32h563/hw.sh"
stty() { :; }; pyocd_h5() { :; }; timeout() { shift; "$@"; }
cat() { echo "TOTAL FAILED : 0"; command sleep 20; }
SC_ROLE=conformance; HW_CONSOLE=/dev/null
start=$SECONDS; hw_boot 20; echo "took $((SECONDS - start))"' _ "$repo/tests/target" "$repo" "$tmp/boot" 2>&1
}
took="$(boot_case | sed -n 's/^took //p')"
check "$([ -n "$took" ] && [ "$took" -lt 10 ]; echo $?)" "the conformance capture stops at the suite report (${took:-?}s)"

# A pyOCD session that died silently or reported an error with exit 0.
program_case() {
    bash -c '
set -euo pipefail
. "$1"
log() { printf "%s\n" "$*"; }
fail() { echo "FAIL: $*"; exit 1; }
timeout() { shift; "$@"; }
pyocd() { case "$PB_MODE" in
    silent) return 124 ;; error) echo "Error: transfer failed"; return 0 ;;
    longerror) echo "Error: transfer failed"; printf "%02000000d\n" 0; return 0 ;;
    *) echo "loaded"; return 0 ;; esac; }
pyocd_bin() { printf pyocd; }
HW_PROBE=X; evidence="$2"
pyocd_session mcxn947vdf -c "load a.bin 0x0" && echo RELEASED' _ "$lib/hw_pyocd.sh" "$tmp" 2>&1
}
check "$(! PB_MODE=silent program_case | grep -q RELEASED; echo $?)" "a silent pyOCD timeout stops programming"
check "$(! PB_MODE=error program_case | grep -q RELEASED; echo $?)" "a command error reported with exit 0 stops programming"
check "$(! PB_MODE=longerror program_case | grep -q RELEASED; echo $?)" "a command error ahead of a long log stops programming"
check "$(PB_MODE=ok program_case | grep -q RELEASED; echo $?)" "a clean session releases the core"

# A multi-image CubeProgrammer flash passes only when every image verified.
stcli_case() {
    bash -c '
set -euo pipefail
. "$1"
fail() { echo "FAIL: $*"; exit 1; }
stcli_bin() { printf stcli_fake; }
stcli_fake() { echo "File download complete"; echo "Download verified successfully"
    case "$PB_MODE" in
    laterfail) echo "Error: failed to download Segment[0]" ;;
    resetonly) echo "File download complete"; echo "Download verified successfully"; echo "Error: hard reset failed" ;;
    *) echo "File download complete"; echo "Download verified successfully" ;; esac
    return 1; }
HW_PROBE=X; evidence="$2"
stcli_program a.bin 0x08000000 b.bin 0x08040000 && echo FLASHED' _ "$lib/hw_stcli.sh" "$tmp" 2>&1
}
check "$(! PB_MODE=laterfail stcli_case | grep -q FLASHED; echo $?)" "a later image's download error fails the flash"
check "$(PB_MODE=resetonly stcli_case | grep -q FLASHED; echo $?)" "an error about the hard reset alone does not fail the flash"
check "$(PB_MODE=ok stcli_case | grep -q FLASHED; echo $?)" "every image verified passes the flash"

echo "hardware runner self-tests: $fails failures"
[ "$fails" -eq 0 ]
