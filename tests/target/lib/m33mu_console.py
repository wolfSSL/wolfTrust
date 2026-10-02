#!/usr/bin/env python3
# m33mu_console.py
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Remove complete console interjections for guest0 marker checks.

Both H5 guests write USART3. Guest1 can disable/re-enable it and print while
guest0 has a line in progress. Remove the attach banner and tagged guest1
records with their line endings, retaining every other byte and line ending.
The original log remains the evidence for guest1 and fault checks. Arbitrary
interleaving, including an incomplete interjection, must still fail to match.
"""

import argparse
from pathlib import Path
import re
import sys


UART_ATTACH = re.compile(
    rb"\[UART\] [0-9a-fA-F]{8} attached to (?:stdio|/dev/pts/[0-9]+)\r?\n"
)
GUEST1_RECORD = re.compile(rb"freertos_guest1:[^\r\n]*\r?\n")


def guest0_console(log: bytes) -> bytes:
    # Remove banners first: a reopen can also split a guest1 record.
    return GUEST1_RECORD.sub(b"", UART_ATTACH.sub(b"", log))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    sys.stdout.buffer.write(guest0_console(args.log.read_bytes()))


if __name__ == "__main__":
    main()
