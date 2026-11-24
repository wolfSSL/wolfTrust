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

"""Check complete, matched Secure + application flash measurements: every
port and engine measured has a Secure image and an application for PSA, TPM
2.0 and PKCS#11, and each interface's total is reported against PSA's."""

import argparse
import csv
from pathlib import Path
import sys

APIS = ("psa", "pkcs11", "tpm")
ROLES = ("secure", "app")


def compare(rows, max_overhead=None):
    measured = {}
    for row in rows:
        key = (row["port"], row["api"], row["engine"], row["role"])
        if row["api"] not in APIS or row["role"] not in ROLES or key in measured:
            raise ValueError("unexpected or duplicate measurement: " + str(key))
        flash = int(row["flash"])
        if flash <= 0:
            raise ValueError("invalid flash size: " + str(key))
        if row["role"] == "secure" and int(row["ram"] or "0") <= 0:
            raise ValueError("invalid Secure RAM: " + str(key))
        measured[key] = flash
    cells = sorted({(port, engine) for port, _, engine, _ in measured})
    if not cells:
        raise ValueError("no measurements")
    expected = {(port, api, engine, role) for port, engine in cells
                for api in APIS for role in ROLES}
    if set(measured) != expected:
        raise ValueError("missing measurements: " + str(sorted(expected - set(measured))))
    summary = []
    exceeded = False
    for port, engine in cells:
        baseline = sum(measured[port, "psa", engine, role] for role in ROLES)
        for api in APIS:
            secure, app = (measured[port, api, engine, role] for role in ROLES)
            total = secure + app
            overhead = total - baseline
            summary.append("%s %s %s: secure=%d app=%d total=%d delta=%+d (%+.2f%%)" %
                           (port, engine, api, secure, app, total, overhead,
                            100.0 * overhead / baseline))
            exceeded |= max_overhead is not None and overhead > max_overhead
    return summary, exceeded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--max-overhead", type=int,
                        help="fail above this many total flash bytes over same-engine PSA")
    args = parser.parse_args()
    if args.max_overhead is not None and args.max_overhead < 0:
        parser.error("--max-overhead must be nonnegative")
    try:
        with args.csv.open(newline="", encoding="utf-8") as source:
            summary, exceeded = compare(csv.DictReader(source), args.max_overhead)
    except (OSError, ValueError, KeyError, csv.Error) as error:
        print("FAIL: interface footprint: " + str(error), file=sys.stderr)
        return 1
    print("\n".join(summary))
    if args.max_overhead is not None:
        print("%s: interface flash overhead <= %d bytes" %
              ("FAIL" if exceeded else "PASS", args.max_overhead))
    return int(exceeded)


if __name__ == "__main__":
    sys.exit(main())
