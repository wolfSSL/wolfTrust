#!/bin/sh
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

set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
target_dir="$root/tests/firmware/stm32h563-tpm"
checks=0
failures=0

check_recipe() {
    target=$1
    needle=$2
    description=$3
    output=$(make -n -C "$target_dir" MAKE=true "$target")
    checks=$((checks + 1))
    if printf '%s\n' "$output" | grep -Fq "$needle"; then
        echo "  [check] PASS  $description"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  $description"
    fi
}

check_recipe run-tpm "run_suite.sh m33mu tpm" \
    "TPM uses the authenticated single-application runner"
check_recipe run-pkcs11 "run_suite.sh m33mu pkcs11" \
    "PKCS11 uses the authenticated single-application runner"
check_recipe secure "WT_MAX_GUESTS=1" \
    "interface Secure images default to one guest context"
for retired in tpm-provider pkcs11-provider; do
    checks=$((checks + 1))
    if make -n -C "$target_dir" "$retired" >/dev/null 2>&1; then
        failures=$((failures + 1))
        echo "  [check] FAIL  retired $retired target still exists"
    else
        echo "  [check] PASS  no extra $retired image can be built"
    fi
done
check_recipe pkcs11-freertos-app "freertos-workspace" \
    "PKCS11 application provisions FreeRTOS"
check_recipe tpm-freertos-app "freertos-workspace" \
    "TPM application provisions FreeRTOS"

# Required API rows must distinguish a real pass from a successful skip.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/tests/target"
cp "$root/tests/target/run_suite.sh" "$work/tests/target/run_suite.sh"
cat > "$work/tests/target/run_qemu_a_scenario.sh" <<'EOF'
#!/bin/sh
case "$WT_FAKE_RESULT" in
    skip) echo 'SKIP: qemu-a/tpm: unavailable' ;;
    missing) echo 'no terminal verdict' ;;
    pass) echo 'PASS: qemu-a/tpm (fixture)' ;;
    fail) exit 1 ;;
esac
EOF
chmod +x "$work/tests/target/run_qemu_a_scenario.sh"
check_verdict() {
    checks=$((checks + 1))
    if WT_FAKE_RESULT="$1" WT_REQUIRE_SCENARIO_PASS="$2" \
            bash "$work/tests/target/run_suite.sh" qemu-a tpm \
            > "$work/out" 2>&1; then actual=0; else actual=1; fi
    if [ "$actual" -eq "$3" ]; then
        echo "  [check] PASS  verdict=$1 required=$2 (WT-FFM-0054)"
    else
        failures=$((failures + 1))
        echo "  [check] FAIL  verdict=$1 required=$2"
    fi
}
check_verdict skip 0 0
check_verdict skip 1 1
check_verdict missing 1 1
check_verdict pass 1 0
check_verdict fail 1 1

echo "Interface runner guard tests: $checks checks, $failures failures"
if [ "$failures" -eq 0 ]; then
    echo "PASS: interface_runner_guard"
    exit 0
fi
echo "FAIL: interface_runner_guard"
exit 1
