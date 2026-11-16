#!/usr/bin/env bash
# Shared build, CI and test-harness files must not name a registered port:
# a port is known to them only through port/<soc>/port.json. The baseline
# (tools/port-names-baseline.txt, "count path" per line) records what still
# does today; a count must match it (a shrink is recorded with --update), and
# a shared file absent from the baseline may not name a port at all.
#
#   tools/check-no-port-names.sh            audit against the baseline
#   tools/check-no-port-names.sh --update   rewrite the baseline from the tree
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
baseline=tools/port-names-baseline.txt

ports="$(python3 tests/target/lib/scenario_matrix.py --list-ports)" || exit 2
re="\\b($(printf '%s' "$ports" | tr ' ' '|'))\\b"

shared_files() {
  git ls-files Makefile mk/common.mk mk/layout.mk 'mk/arch-*.mk' 'tools/*.sh' \
    'tools/*.py' '.github/workflows/*.yml' 'tests/target/lib/*' \
    tests/target/run_suite.sh tests/host/layout.mk \
    tests/host/Makefile tests/target/provisioning/provisioning_ctrl.sh \
    | grep -v -e '^tools/check-no-port-names.sh$' -e "^$baseline\$"
}

count_in() { # file
  grep -c -E "$re" "$1" 2> /dev/null || true
}

if [ "${1:-}" = "--update" ]; then
  : > "$baseline"
  while IFS= read -r f; do
    n="$(count_in "$f")"
    [ "$n" -gt 0 ] && printf '%s %s\n' "$n" "$f" >> "$baseline"
  done < <(shared_files)
  echo "baseline rewritten: $(wc -l < "$baseline" | tr -d ' ') file(s) still name a port"
  exit 0
fi

[ -f "$baseline" ] || { echo "FAIL: $baseline is missing" >&2; exit 2; }
rc=0
while IFS= read -r f; do
  n="$(count_in "$f")"
  allowed="$(awk -v f="$f" '$2 == f { print $1 }' "$baseline")"
  : "${allowed:=0}"
  if [ "$n" -gt "$allowed" ]; then
    echo "FAIL: $f names a port $n time(s), baseline allows $allowed"
    grep -n -E "$re" "$f" | head -5
    rc=1
  elif [ "$n" -lt "$allowed" ]; then
    echo "FAIL: $f names a port $n time(s), below the baseline's $allowed; run --update to keep the shrink"
    rc=1
  fi
done < <(shared_files)
while IFS=' ' read -r n f; do
  [ -z "$f" ] && continue
  if [ ! -f "$f" ]; then
    echo "FAIL: baseline names $f, which no longer exists; run --update"
    rc=1
  fi
done < "$baseline"
[ "$rc" -eq 0 ] && echo "OK: no shared file names a port beyond the baseline"
exit "$rc"
