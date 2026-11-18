#!/usr/bin/env python3
"""Report the Secure RAM a linked level 3 image reserves, from its map.

arm-none-eabi-size counts sections only, and the level 3 partition stacks and
bands are linker regions with no section, so it leaves them out. This counts
the SPM's .data and .bss, the SPM main stack, every partition band and stack
at its full length, and a port's RAM code band: RAM no other code can use. With --max, the report
fails when the total exceeds that many bytes; --base-max allows the linked
RAM code band on top of that many bytes."""

import argparse
import re
import sys

# A port's RAM code band (the MIMXRT700 NSC gateway and NOR driver), if any.
PORT_REGIONS = ("RAMFUNC",)
BANDS = ("VNETDATA", "CRYPTOSTACK", "HSMDATA", "VAULTDATA", "ATTESTDATA", "PSSTACK",
         "ITSSTACK", "VAULTSTACK", "SPSTACKS", "CONFDATA", "FWUSTACK")


def read_map(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    regions = {}
    for match in re.finditer(r"^(\w+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)"
                             r"\s+\w+\s*$", text, re.M):
        regions[match.group(1)] = (int(match.group(2), 16),
                                   int(match.group(3), 16))
    symbols = {}
    for name in ("_ebss", "WT_SPM_STACK_SIZE"):
        match = re.search(r"0x([0-9a-fA-F]+)\s+" + name + r" = ", text)
        if match:
            symbols[name] = int(match.group(1), 16)
    missing = [name for name in ("RAM",) + BANDS if name not in regions]
    missing += [name for name in ("_ebss", "WT_SPM_STACK_SIZE")
                if name not in symbols]
    if missing:
        raise SystemExit("FAIL: %s has no %s" % (path, ", ".join(missing)))
    return regions, symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("map")
    limits = parser.add_mutually_exclusive_group()
    limits.add_argument("--max", type=lambda value: int(value, 0))
    limits.add_argument("--base-max", type=lambda value: int(value, 0))
    args = parser.parse_args()
    regions, symbols = read_map(args.map)
    rows = [("SPM .data + .bss", symbols["_ebss"] - regions["RAM"][0]),
            ("SPM main stack", symbols["WT_SPM_STACK_SIZE"])]
    rows += [(name, regions[name][1]) for name in BANDS if regions[name][1]]
    rows += [(name, regions[name][1]) for name in PORT_REGIONS
             if regions.get(name, (0, 0))[1]]
    total = sum(size for _, size in rows)
    for name, size in rows:
        print("  %-18s %7d" % (name, size))
    print("Reserved Secure RAM: %d bytes" % total)
    limit = args.max
    if args.base_max is not None:
        limit = args.base_max + sum(regions.get(name, (0, 0))[1]
                                    for name in PORT_REGIONS)
    if limit is not None and total > limit:
        print("FAIL: reserved Secure RAM %d exceeds %d" % (total, limit))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
