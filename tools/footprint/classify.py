#!/usr/bin/env python3
"""Split a linked Secure image's flash and RAM by category, from its GNU ld map.

Every byte of a flash-resident output section is attributed: input sections
to the object that supplied them, *fill* to "fill", and whatever the linker
script emitted itself to "linker". The flash total matches what
arm-none-eabi-size reports as text + data, so moving code between categories
cannot hide bytes. Objects are classified by the first rule whose regex
matches the object path; an object no rule matches fails the run.

Use a non-LTO map for the split: an LTO image folds objects into ltrans
units, which the rules cannot attribute."""

import argparse
import json
import re
import subprocess
import sys

NOBITS_NAMES = re.compile(r"(^|[._])(bss|noinit|stack|stacks|heap)($|[._])")
OUT_RE = re.compile(r"^(\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)"
                    r"(?:\s+load address 0x([0-9a-fA-F]+))?\s*$")
OUT_NAME_RE = re.compile(r"^(\S+)\s*$")
OUT_REST_RE = re.compile(r"^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)"
                         r"(?:\s+load address 0x([0-9a-fA-F]+))?\s*$")
IN_RE = re.compile(r"^ (\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S.*?)\s*$")
IN_NAME_RE = re.compile(r"^ (\S+)\s*$")
IN_REST_RE = re.compile(r"^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S.*?)\s*$")
FILL_RE = re.compile(r"^ \*fill\*\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)")
DATA_CMD_RE = re.compile(r"^(BYTE|SHORT|LONG|QUAD|SQUAD|FILL)\b")
REGION_RE = re.compile(r"^(\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)(?:\s+(\S+))?\s*$")


def read_rules(path):
    rules = []
    for number, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise SystemExit("FAIL: %s:%d: want '<category> <regex>'" % (path, number))
        rules.append((parts[0], re.compile(parts[1])))
    return rules


def read_regions(lines):
    regions = []
    inside = False
    for line in lines:
        if line.startswith("Memory Configuration"):
            inside = True
            continue
        if line.startswith("Linker script and memory map"):
            break
        match = REGION_RE.match(line) if inside else None
        if match and match.group(1) not in ("Name", "*default*"):
            attrs = match.group(4) or ""
            regions.append((match.group(1), int(match.group(2), 16),
                            int(match.group(3), 16), attrs))
    return regions


def region_of(regions, addr):
    for name, origin, length, attrs in regions:
        if origin <= addr < origin + length:
            return name, attrs
    return None, ""


def is_flash(regions, addr):
    name = region_of(regions, addr)[0]
    return name is not None and ("FLASH" in name.upper() or "ROM" in name.upper())


def nobits_sections(elf, readelf):
    if elf is None:
        return None
    out = subprocess.run([readelf, "-SW", elf], check=True,
                         capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        match = re.match(r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)", line)
        if match and match.group(2) == "NOBITS":
            names.add(match.group(1))
    return names


def parse_map(path):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    regions = read_regions(lines)
    start = next(i for i, line in enumerate(lines)
                 if line.startswith("Linker script and memory map"))
    sections = []
    current = None
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if line and not line[0].isspace():
            match = OUT_RE.match(line)
            name = addr = size = lma = None
            if match:
                name, addr, size, lma = match.groups()
            else:
                name_match = OUT_NAME_RE.match(line)
                rest = OUT_REST_RE.match(lines[i + 1]) if i + 1 < len(lines) else None
                if name_match and rest and name_match.group(1).startswith("."):
                    name = name_match.group(1)
                    addr, size, lma = rest.groups()
                    i += 1
            if name is not None and name.startswith(".") and name != "/DISCARD/":
                current = {"name": name, "addr": int(addr, 16),
                           "size": int(size, 16),
                           "lma": int(lma, 16) if lma else int(addr, 16),
                           "entries": []}
                sections.append(current)
            else:
                current = None
            i += 1
            continue
        if current is None:
            i += 1
            continue
        fill = FILL_RE.match(line)
        if fill:
            current["entries"].append(("*fill*", "", int(fill.group(2), 16)))
            i += 1
            continue
        match = IN_RE.match(line)
        if (match and not match.group(4).startswith("0x")
                and not DATA_CMD_RE.match(match.group(4))):
            sec, addr, size, obj = match.groups()
        else:
            name_match = IN_NAME_RE.match(line)
            rest = IN_REST_RE.match(lines[i + 1]) if i + 1 < len(lines) else None
            if (name_match and rest and not rest.group(3).startswith("0x")
                    and not DATA_CMD_RE.match(rest.group(3))):
                sec = name_match.group(1)
                addr, size, obj = rest.groups()
                i += 1
            else:
                i += 1
                continue
        size = int(size, 16)
        if size and int(addr, 16):
            current["entries"].append((obj.strip(), sec, size))
        i += 1
    return regions, sections


def classify(rules, obj):
    for category, regex in rules:
        if regex.search(obj):
            return category
    return None


def measure(path, rules, nobits):
    regions, sections = parse_map(path)
    flash = {}
    ram = {}
    objects = {}
    unclassified = set()
    flash_total = 0
    ram_total = 0
    for section in sections:
        if section["size"] == 0:
            continue
        if nobits is not None:
            loads = section["name"] not in nobits
        else:
            loads = not NOBITS_NAMES.search(section["name"])
        in_flash = is_flash(regions, section["addr"])
        counts_flash = loads and (in_flash or is_flash(regions, section["lma"]))
        counts_ram = not in_flash and region_of(regions, section["addr"])[0] is not None
        if not counts_flash and not counts_ram:
            continue
        accounted = 0
        for obj, _sec, size in section["entries"]:
            accounted += size
            if obj == "*fill*":
                category = "fill"
            else:
                category = classify(rules, obj)
                if category is None:
                    unclassified.add(obj)
                    category = "unclassified"
            key = (category, obj)
            if counts_flash:
                flash[category] = flash.get(category, 0) + size
                objects.setdefault(key, [0, 0])[0] += size
            if counts_ram:
                ram[category] = ram.get(category, 0) + size
                objects.setdefault(key, [0, 0])[1] += size
        residual = section["size"] - accounted
        if residual:
            if counts_flash:
                flash["linker"] = flash.get("linker", 0) + residual
            if counts_ram:
                ram["linker"] = ram.get("linker", 0) + residual
        if counts_flash:
            flash_total += section["size"]
        if counts_ram:
            ram_total += section["size"]
    return {"flash": flash, "ram": ram, "flash_total": flash_total,
            "ram_total": ram_total, "objects": objects,
            "unclassified": sorted(unclassified)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("map")
    parser.add_argument("--rules", required=True)
    parser.add_argument("--elf", help="read NOBITS sections from this ELF")
    parser.add_argument("--readelf", default="arm-none-eabi-readelf")
    parser.add_argument("--exclude", default="crypto",
                        help="category left out of the gated total")
    parser.add_argument("--max", type=lambda value: int(value, 0),
                        help="fail when flash outside --exclude exceeds this")
    parser.add_argument("--objects", action="store_true",
                        help="list every object with its category")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    rules = read_rules(args.rules)
    result = measure(args.map, rules, nobits_sections(args.elf, args.readelf))
    gated = result["flash_total"] - result["flash"].get(args.exclude, 0)
    if args.json:
        out = dict(result)
        out["objects"] = [{"category": c, "object": o, "flash": f, "ram": r}
                          for (c, o), (f, r) in sorted(result["objects"].items())]
        out["gated"] = gated
        print(json.dumps(out, indent=1, sort_keys=True))
    else:
        for category in sorted(result["flash"], key=lambda c: -result["flash"][c]):
            print("  %-14s %7d" % (category, result["flash"][category]))
        print("Flash total: %d bytes; without %s: %d bytes"
              % (result["flash_total"], args.exclude, gated))
        if args.objects:
            for (category, obj), (fl, rm) in sorted(
                    result["objects"].items(), key=lambda item: (item[0][0], -item[1][0])):
                print("  %-12s %7d %7d %s" % (category, fl, rm, obj))
    if result["unclassified"]:
        for obj in result["unclassified"]:
            print("FAIL: no rule classifies %s" % obj, file=sys.stderr)
        return 2
    if args.max is not None and gated > args.max:
        print("FAIL: flash without %s %d exceeds %d" % (args.exclude, gated, args.max),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
