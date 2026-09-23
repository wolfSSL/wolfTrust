#!/usr/bin/env python3
"""Find C++ comments in tracked C files without mistaking URLs for comments."""

import subprocess
import sys
from pathlib import Path


def scan_line(line, in_block, quote):
    index = 0
    while index < len(line):
        if in_block:
            end = line.find("*/", index)
            if end < 0:
                return False, True, quote
            in_block = False
            index = end + 2
        elif quote:
            if line[index] == "\\":
                index += 2
            elif line[index] == quote:
                quote = None
                index += 1
            else:
                index += 1
        elif line.startswith("/*", index):
            in_block = True
            index += 2
        elif line.startswith("//", index):
            return True, in_block, quote
        elif line[index] in ('"', "'"):
            quote = line[index]
            index += 1
        else:
            index += 1

    if quote and not line.endswith("\\"):
        quote = None
    return False, in_block, quote


def main():
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "*.c", "*.h"]
    ).split(b"\0")
    found = False
    for raw_path in filter(None, paths):
        path = Path(raw_path.decode(sys.getfilesystemencoding()))
        in_block = False
        quote = None
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            comment, in_block, quote = scan_line(line, in_block, quote)
            if comment:
                print(f"{path}:{number}: C++ comment")
                found = True
    return 1 if found else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
