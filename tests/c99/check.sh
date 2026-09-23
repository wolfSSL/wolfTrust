#!/bin/sh
# Confirm the compiler gate accepts ISO C99 and rejects C11 syntax and VLAs.
set -eu

compiler=${CC:-cc}
flags='-std=c99 -pedantic-errors -Werror=vla -Wall -Wextra -Werror -fsyntax-only'

"$compiler" $flags -Iinclude tests/c99/valid.c
if "$compiler" $flags tests/c99/invalid_c11.c >/dev/null 2>&1; then
    printf '%s\n' 'C99 gate accepted C11-only syntax' >&2
    exit 1
fi
if "$compiler" $flags tests/c99/invalid_vla.c >/dev/null 2>&1; then
    printf '%s\n' 'C99 gate accepted a variable-length array' >&2
    exit 1
fi
printf '%s\n' 'C99 compiler gate passed.'
