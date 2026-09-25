#!/usr/bin/env bash
# Docs guard. docs/ is published to the wiki, so the public tree must never
# point at the internal ledger or at a developer's home directory.
#
#   tools/check-docs-no-internal-links.sh [path...]
#       default paths: docs README.md .github/workflows/README.md
#   tools/check-docs-no-internal-links.sh --selftest
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
PATTERN='wolfTrust-internal-docs|internal-docs|/Users/[A-Za-z]|/home/[A-Za-z]|~/wolfTrust-internal'

selftest() {
  local dir fails=0
  dir="$(mktemp -d)" || { echo "SELFTEST FAIL: mktemp failed"; exit 1; }
  printf 'See ~/wolfTrust-internal-docs/task-list.md for the rows.\n' > "$dir/bad1.md"
  printf 'Logs live in /home/aidangarske/wolfTrust-l3-work.\n' > "$dir/bad2.md"
  printf 'Run `tools/check-core-port-split.sh --selftest` first.\n' > "$dir/ok.md"
  if grep -qE "$PATTERN" "$dir/ok.md"; then
    echo "SELFTEST FAIL: clean doc flagged"; fails=$((fails + 1)); fi
  if ! grep -qE "$PATTERN" "$dir/bad1.md"; then
    echo "SELFTEST FAIL: internal ledger link missed"; fails=$((fails + 1)); fi
  if ! grep -qE "$PATTERN" "$dir/bad2.md"; then
    echo "SELFTEST FAIL: home directory path missed"; fails=$((fails + 1)); fi
  rm -rf "$dir"
  if [ "$fails" -ne 0 ]; then echo "SELFTEST: $fails failure(s)"; exit 1; fi
  echo "SELFTEST: ok"
  exit 0
}

[ "${1:-}" = "--selftest" ] && selftest

cd "$root" || exit 2
if [ $# -gt 0 ]; then paths=("$@"); else paths=(docs README.md .github/workflows/README.md); fi

echo "docs guard: no internal-ledger or home-directory references in: ${paths[*]}"
hits="$(grep -rnE "$PATTERN" "${paths[@]}")"
rc=$?
if [ "$rc" -eq 1 ]; then
  echo "OK: no internal references."
  exit 0
fi
if [ "$rc" -ne 0 ]; then
  echo "FAIL: grep error $rc (missing path?)"
  exit 2
fi
printf '%s\n' "$hits"
echo "FAIL: $(printf '%s\n' "$hits" | wc -l | tr -d ' ') reference(s) to internal material in the public tree."
exit 1
