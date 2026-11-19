#!/usr/bin/env bash
# Run target scenarios for one port through the shared emulator runner and
# report them the way `make test-target` always has: RUN/PASS/FAIL per
# scenario, the tagged "  [check] " lines, the log path, and PASS/FAIL:
# target/all at the end.
#
#   tests/target/run_suite.sh <port> <scenario>...
#   tests/target/run_suite.sh qemu-a <scenario>...   -> run_qemu_a_scenario.sh
#   WT_SUITE_LOG_DIR   where target-<scenario>.log lands (default logs)
#   WT_REQUIRE_SCENARIO_PASS=1 requires a real terminal PASS, including API CI.
#
# A port's former runner arm (port.json m33mu.arm) still selects it.
set -u

repo="$(cd "$(dirname "$0")/../.." && pwd)"
matrix="$repo/tests/target/lib/scenario_matrix.py"
ports="$(python3 "$matrix" --list-ports)"
usage() { echo "usage: $0 <$(echo "$ports" | tr ' ' '|')|qemu-a> <scenario>..." >&2; exit 2; }

port="${1:-}"
if [ "$port" = qemu-a ]; then
  runner=(tests/target/run_qemu_a_scenario.sh)
else
  for p in $ports; do
    if [ "$(python3 "$matrix" --port "$p" --arm)" = "$port" ]; then
      port="$p"
    fi
  done
  case " $ports " in
    *" $port "*) ;;
    *) usage ;;
  esac
  runner=(tests/target/run_target.sh "$port")
fi
shift
[ $# -ge 1 ] || usage

cd "$repo" || exit 2
logdir="${WT_SUITE_LOG_DIR:-logs}"
mkdir -p "$logdir"

rc=0
for s in "$@"; do
  echo "RUN: target/$s"
  if "${runner[@]}" "$s" > "$logdir/target-$s.log" 2>&1; then
    grep -F '  [check] ' "$logdir/target-$s.log" || true
    if [ "${WT_REQUIRE_SCENARIO_PASS:-0}" = 1 ] &&
        ! grep -Eq "^PASS: (target|qemu-a)/([^/ ]+/)?$s( |$)" "$logdir/target-$s.log"; then
      echo "FAIL: target/$s (required scenario did not report a real pass)"
      tail -5 "$logdir/target-$s.log"
      rc=1
    elif grep -q '^SKIP:' "$logdir/target-$s.log"; then
      echo "SKIP: target/$s ($(grep -m1 '^SKIP:' "$logdir/target-$s.log" | sed -E 's/^SKIP: [^:]*: //'))"
    else
      echo "PASS: target/$s"
    fi
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
