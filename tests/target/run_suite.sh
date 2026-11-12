#!/usr/bin/env bash
# Run target scenarios for one port through the shared emulator runner and
# report them the way `make test-target` always has: RUN/PASS/FAIL per
# scenario, the tagged "  [check] " lines, the log path, and PASS/FAIL:
# target/all at the end.
#
#   tests/target/run_suite.sh <port> <scenario>...
#   WT_SUITE_LOG_DIR   where target-<scenario>.log lands (default logs)
#
# A port's former runner arm (port.json m33mu.arm) still selects it.
set -u

repo="$(cd "$(dirname "$0")/../.." && pwd)"
matrix="$repo/tests/target/lib/scenario_matrix.py"
ports="$(python3 "$matrix" --list-ports)"
usage() { echo "usage: $0 <$(echo "$ports" | tr ' ' '|')> <scenario>..." >&2; exit 2; }

port="${1:-}"
for p in $ports; do
  if [ "$(python3 "$matrix" --port "$p" --arm)" = "$port" ]; then
    port="$p"
  fi
done
case " $ports " in
  *" $port "*) ;;
  *) usage ;;
esac
shift
[ $# -ge 1 ] || usage

cd "$repo" || exit 2
logdir="${WT_SUITE_LOG_DIR:-logs}"
mkdir -p "$logdir"

rc=0
for s in "$@"; do
  echo "RUN: target/$s"
  if tests/target/run_target.sh "$port" "$s" > "$logdir/target-$s.log" 2>&1; then
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
