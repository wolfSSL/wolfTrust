#!/usr/bin/env bash
# Regression check for the MCXN947 hardware suite: its logs and the runner's
# retained evidence never live under build/ (every run cleans build/ before
# it builds, so a batch would lose the previous scenario's log there), and a
# batch serializes on the board lock the runner shares. Runs without a board:
# the suite is driven with a stub runner and a stub detector.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
suite="$repo/tests/target/run_mcxn947_suite.sh"
runner="$repo/tests/target/run_mcxn947_hardware.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
check() {
    if [ "$1" -eq 0 ]; then echo "PASS: $2"; else echo "FAIL: $2"; fails=$((fails + 1)); fi
}

# The defaults, read from the scripts: nothing retained lands under build/.
check "$(grep -qE '^logs="\$\{MCXN947_SUITE_LOGS:-\$repo/logs/' "$suite"; echo $?)" \
    "the suite's logs default to logs/, not build/"
check "$(grep -qE '^work="\$\{MCXN947_WORK:-\$repo/logs/' "$runner"; echo $?)" \
    "the runner's retained evidence defaults to logs/, not build/"
check "$(! grep -qE '(logs|work|lock)="\$\{[A-Z0-9_]+:-\$repo/build' "$suite" "$runner"; echo $?)" \
    "no evidence path defaults to build/"
check "$(grep -q 'flock' "$suite" && grep -q 'flock' "$runner"; echo $?)" \
    "the suite and the runner both take the board lock"
check "$(grep -qE '^evidence="\$work/\$scenario-\$engine"' "$runner"; echo $?)" \
    "the runner keeps each run's console and dumps by scenario and engine"

# A stub runner that cleans build/ the way a real run does (the suite's old
# log home), then reports; its log must survive in the suite's log dir.
stub="$tmp/runner.sh"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
rm -rf "${STUB_REPO}/build/mcxn947-suite"
echo "  [check] PASS  stub $1 ran with lock=${MCXN947_HW_LOCKED:-unset}"
echo "PASS: hardware/mcxn947/$1"
EOF
chmod +x "$stub"
export STUB_REPO="$repo" MCXN947_SUITE_RUNNER="$stub" MCXN947_SUITE_DETECT=/bin/true
export MCXN947_SUITE_LOGS="$tmp/logs" MCXN947_HW_LOCK="$tmp/hw.lock"
export WT_MCXN947_SCENARIOS="alpha beta"
out="$("$suite" 2>&1)"; rc=$?
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

# program_board must stop before the core is released when pyOCD exits nonzero
# without saying why (a timeout) or exits 0 reporting a failed command.
sed -n '/^program_board() {/,/^}/p' "$runner" > "$tmp/program_board.sh"
program_case() {
    bash -c '
fail() { echo "FAIL: $*"; exit 1; }
timeout() { shift; "$@"; }
pyocd() { case "$PB_MODE" in
    silent) return 124 ;; error) echo "Error: transfer failed"; return 0 ;;
    *) echo "loaded"; return 0 ;; esac; }
probe_uid=X; target=mcxn947vdf
park_cmds=(-c "reset halt"); board_cmds=(-c "load a.bin 0x0")
. "$1"
program_board && echo RELEASED' _ "$tmp/program_board.sh" 2>&1
}
check "$(! PB_MODE=silent program_case | grep -q RELEASED; echo $?)" \
    "a silent pyOCD timeout stops programming"
check "$(! PB_MODE=error program_case | grep -q RELEASED; echo $?)" \
    "a command error reported with exit 0 stops programming"
check "$(PB_MODE=ok program_case | grep -q RELEASED; echo $?)" \
    "a clean session releases the core"

echo "mcxn947 suite evidence: $fails failures"
[ "$fails" -eq 0 ]
