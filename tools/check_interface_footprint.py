#!/usr/bin/env python3
# check_interface_footprint.py
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Check complete, matched Secure + application flash measurements."""

import argparse
import csv
from pathlib import Path
import sys


def compare(rows, max_overhead):
    expected = {(api, engine, role) for api in ("psa", "pkcs11", "tpm")
                for engine in ("native", "hsm") for role in ("secure", "app")}
    measured = {}
    for row in rows:
        key = (row["api"], row["engine"], row["role"])
        if key not in expected or key in measured:
            raise ValueError("unexpected or duplicate measurement: " + str(key))
        sizes = [int(row[field]) for field in ("text", "data", "bss", "flash")]
        text, data, bss, flash = sizes
        if min(sizes) < 0 or text == 0 or flash != text + data:
            raise ValueError("invalid section sizes: " + str(key))
        measured[key] = flash
    if set(measured) != expected:
        raise ValueError("missing measurements: " + str(sorted(expected - set(measured))))
    summary = []
    exceeded = False
    for engine in ("native", "hsm"):
        baseline = sum(measured["psa", engine, role] for role in ("secure", "app"))
        for api in ("psa", "pkcs11", "tpm"):
            secure, app = (measured[api, engine, role] for role in ("secure", "app"))
            total = secure + app
            overhead = total - baseline
            summary.append("%s %s: secure=%d app=%d total=%d delta=%+d (%+.2f%%)" %
                           (engine, api, secure, app, total, overhead,
                            100.0 * overhead / baseline))
            exceeded |= overhead > max_overhead
    return summary, exceeded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--max-overhead", type=int, required=True,
                        help="maximum total flash bytes above same-engine PSA")
    args = parser.parse_args()
    if args.max_overhead < 0:
        parser.error("--max-overhead must be nonnegative")
    try:
        with args.csv.open(newline="", encoding="utf-8") as source:
            summary, exceeded = compare(csv.DictReader(source), args.max_overhead)
    except (OSError, ValueError, KeyError, csv.Error) as error:
        print("FAIL: interface footprint: " + str(error), file=sys.stderr)
        return 1
    print("\n".join(summary))
    print("%s: interface flash overhead <= %d bytes" %
          ("FAIL" if exceeded else "PASS", args.max_overhead))
    return int(exceeded)


if __name__ == "__main__":
    sys.exit(main())
