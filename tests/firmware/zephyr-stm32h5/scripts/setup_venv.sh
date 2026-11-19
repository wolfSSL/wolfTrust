#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUBTREE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV_DIR="$SUBTREE_DIR/.venv"
PYTHON_BIN="${WEST_PYTHON:-$VENV_DIR/bin/python3}"

if [ ! -x "$PYTHON_BIN" ]; then
    python3 -m venv "$VENV_DIR"
fi

if ! "$PYTHON_BIN" -m west --version >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install west
fi

if ! "$PYTHON_BIN" -c 'import elftools' >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install pyelftools
fi
