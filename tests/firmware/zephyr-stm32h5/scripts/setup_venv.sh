#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUBTREE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV_DIR="$SUBTREE_DIR/.venv"
PYTHON_BIN="${WEST_PYTHON:-$VENV_DIR/bin/python3}"
WEST_BIN_PATH="${WEST_BIN:-$VENV_DIR/bin/west}"

if [ ! -x "$PYTHON_BIN" ]; then
    python3 -m venv "$VENV_DIR"
fi

if ! "$WEST_BIN_PATH" --version >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install --force-reinstall west
fi

if ! "$PYTHON_BIN" -c 'import elftools' >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install pyelftools
fi
