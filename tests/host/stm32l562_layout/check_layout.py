#!/usr/bin/env python3
# check_layout.py
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
"""Compare the STM32L562 manifests' guest windows with memory_map.h."""

import argparse
import json
import os
import re
import subprocess
import sys

LAYOUTS = (("manifest.json", 0), ("manifest-conformance.json", 1))
ATTR_EXEC_FLASH = 5
ATTR_RAM = 19


def macros(cc, root, conformance):
    port = os.path.join(root, "port", "stm32l562")
    out = subprocess.run(
        cc.split() + ["-E", "-dM", "-DWT_CONFORMANCE=%d" % conformance,
                      "-I", os.path.join(root, "include"), "-I", port,
                      "-I", os.path.join(root, "port", "common", "armv8m"),
                      os.path.join(port, "memory_map.h")],
        check=True, capture_output=True, text=True).stdout
    found = {}
    for name, value in re.findall(
            r"^#define (WT_GUEST[01]_(?:FLASH|RAM)_(?:BASE|SIZE)) "
            r"(0x[0-9A-Fa-f]+)u?$", out, re.M):
        found[name] = int(value, 16)
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--root", default="../../..")
    args = parser.parse_args()
    checks = 0
    failures = 0
    for manifest, conformance in LAYOUTS:
        want = macros(args.cc, args.root, conformance)
        path = os.path.join(args.root, "port", "stm32l562", manifest)
        domains = json.load(open(path))["domains"]
        for guest in (0, 1):
            base = want["WT_GUEST%d_FLASH_BASE" % guest]
            doms = [d for d in domains if d.get("entry_point") == base]
            checks += 1
            if len(doms) != 1:
                print("FAIL: %s has no single guest %d entering at %#x"
                      % (manifest, guest, base))
                failures += 1
                continue
            res = {(r["attributes"], r["base"]): r["size"]
                   for r in doms[0]["memory_resources"]}
            for kind, attr in (("FLASH", ATTR_EXEC_FLASH), ("RAM", ATTR_RAM)):
                b = want["WT_GUEST%d_%s_BASE" % (guest, kind)]
                s = want["WT_GUEST%d_%s_SIZE" % (guest, kind)]
                checks += 1
                if res.get((attr, b)) != s:
                    print("FAIL: %s guest %d %s grants %s at %#x, memory_map.h "
                          "says %#x" % (manifest, guest, kind,
                                        res.get((attr, b)), b, s))
                    failures += 1
    print("stm32l562 layout: %d checks, %d failures" % (checks, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
