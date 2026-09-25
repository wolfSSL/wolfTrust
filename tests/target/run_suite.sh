#!/usr/bin/env bash
# Run target scenarios through one emulator runner and report them the way
# `make test-target` always has: RUN/PASS/FAIL per scenario, the tagged
# "  [check] " lines, the log path, and PASS/FAIL: target/all at the end.
#
#   tests/target/run_suite.sh m33mu       <scenario>...   -> run_m33mu_scenario.sh
#   tests/target/run_suite.sh qemu-a      <scenario>...   -> run_qemu_a_scenario.sh
#   tests/target/run_suite.sh rt700-m33mu <scenario>...   -> run_rt700_m33mu.sh
#   WT_SUITE_LOG_DIR   where target-<scenario>.log lands (default logs)
set -u

usage() { echo "usage: $0 m33mu|qemu-a|rt700-m33mu <scenario>..." >&2; exit 2; }

model="${1:-}"
case "$model" in
  m33mu)       runner=run_m33mu_scenario.sh ;;
  qemu-a)      runner=run_qemu_a_scenario.sh ;;
  rt700-m33mu) runner=run_rt700_m33mu.sh ;;
  *) usage ;;
esac
shift
[ $# -ge 1 ] || usage

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo" || exit 2
logdir="${WT_SUITE_LOG_DIR:-logs}"
mkdir -p "$logdir"

rc=0
for s in "$@"; do
  echo "RUN: target/$s"
  if "tests/target/$runner" "$s" > "$logdir/target-$s.log" 2>&1; then
    grep -F '  [check] ' "$logdir/target-$s.log" || true
    echo "PASS: target/$s"
  else
    grep -F '  [check] ' "$logdir/target-$s.log" || true
    echo "FAIL: target/$s (tail of $logdir/target-$s.log):"
    tail -20 "$logdir/target-$s.log"
    rc=1
  fi
  echo "LOG: $logdir/target-$s.log"
done
if [ "$rc" -eq 0 ]; then
  echo "PASS: target/all"
else
  echo "FAIL: target/all"
fi
exit "$rc"
