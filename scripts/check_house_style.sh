#!/bin/sh
# wolfTrust checks for the required wolfSSL C coding conventions.

status=0
tab=$(printf '\t')

report() {
    matches=$2
    if [ -n "$matches" ]; then
        printf '\nFAIL: %s\n' "$1"
        printf '%s\n' "$matches"
        status=1
    fi
}

# Structured control flow only. Cleanup uses status-gated fallthrough.
matches=$(git grep -nw goto -- '*.c' '*.h' || true)
report "goto is banned; use structured fallthrough cleanup" "$matches"

# C source uses C comments. The scanner ignores strings and block comments.
scan_status=0
matches=$(python3 scripts/check-c-comments.py) || scan_status=$?
if [ "$scan_status" -gt 1 ]; then
    exit "$scan_status"
fi
report "C++ // comments are banned; use /* ... */" "$matches"

# Core library and port code use spaces; integration fixtures retain upstream
# formatting where required.
matches=$(git grep -nE "$tab" -- \
    ':(glob)src/**/*.[ch]' \
    ':(glob)include/**/*.[ch]' \
    ':(glob)port/**/*.[ch]' || true)
report "tabs are banned in core C sources; use spaces" "$matches"

matches=$(git grep -nE ' +$' -- '*.c' '*.h' || true)
report "trailing whitespace" "$matches"

if [ "$status" -ne 0 ]; then
    printf '\nHouse-style check failed.\n'
    exit 1
fi
printf 'House-style check passed.\n'
