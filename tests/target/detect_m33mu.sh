#!/usr/bin/env bash
# Single source of truth for "can the full FF-M target suite run here?".
# Exit 0 when an M33MU emulator is reachable (or the user forced a target run),
# non-zero otherwise. On non-zero, print a one-line reason to stdout so the
# caller can fold it into its SKIP or WARNING. Shared by the Makefile's
# test-conformance and test-target so the two can never drift.
set -u

if [ "${WT_TARGET_SCENARIOS:-0}" = "1" ]; then
    exit 0
fi
# A port whose emulator carries a model patch builds its pinned M33MU itself.
if [ -n "${1:-}" ] &&
   grep -qE '^M33MU_PATCH="[^"]+"' "$(dirname "$0")/ports/$1/m33mu.sh" 2>/dev/null; then
    exit 0
fi
if [ -n "${M33MU:-}" ] && [ -x "${M33MU:-}" ]; then
    exit 0
fi
if command -v m33mu >/dev/null 2>&1; then
    exit 0
fi

echo "M33MU not detected — set WT_TARGET_SCENARIOS=1 or provide M33MU=/path/to/m33mu"
exit 1
