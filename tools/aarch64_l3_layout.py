#!/usr/bin/env python3
"""Read the AArch64 isolation level 3 layout from a port's memory_map.h.

The Secure bands come from port/common/aarch64/l3_layout.h. --cflags and
--ldflags print them for the compiler and the linker, --shell for the target
runner, and --check-manifest proves a manifest grants the keystore bands the
linker places, so no address list is copied anywhere else."""

import argparse
import json
import os
import re
import subprocess
import sys


MACROS = (
    "WT_SPM_BOOT_INFO_PA", "WT_SPM_TABLE_POOL_PA",
    "WT_SPM_IMAGE_PA", "WT_SPM_IMAGE_SIZE",
    "WT_SPM_RAM_PA", "WT_SPM_RAM_SIZE",
    "WT_SPM_CONFDATA_PA", "WT_SPM_CONFDATA_SIZE",
    "WT_SPM_KEYSTORE_PA", "WT_SPM_KEYSTORE_SIZE",
    "WT_SPM_VAULT_PA", "WT_SPM_VAULT_SIZE",
    "WT_SPM_ATTEST_PA", "WT_SPM_ATTEST_SIZE",
    "WT_SPM_HSMDATA_PA", "WT_SPM_HSMDATA_SIZE",
    "WT_SPM_RXTX_PA", "WT_SPM_RXTX_SIZE",
    "WT_SPM_SHARE_PA", "WT_SPM_SHARE_SIZE",
    "WT_L3_BAND_BASE", "WT_L3_HANDOFF_PA", "WT_L3_FFA_ACS_PA",
    "WT_L3_SPM_PERIPHERAL_BASE",
)
# The C code reads these from -D flags; the rest only through memory_map.h.
CFLAGS_MACROS = MACROS[:20]
LDFLAGS_MACROS = (
    "WT_SPM_IMAGE_PA", "WT_SPM_IMAGE_SIZE", "WT_SPM_RAM_PA", "WT_SPM_RAM_SIZE",
    "WT_SPM_KEYSTORE_PA", "WT_SPM_KEYSTORE_SIZE",
    "WT_SPM_VAULT_PA", "WT_SPM_VAULT_SIZE", "WT_SPM_ATTEST_PA",
    "WT_SPM_ATTEST_SIZE", "WT_SPM_HSMDATA_PA", "WT_SPM_HSMDATA_SIZE",
    "WT_SPM_CONFDATA_PA", "WT_SPM_CONFDATA_SIZE",
)
# Each band and the partition whose data wolftrust.ld links into it.
KEYSTORE_BANDS = (("WT_SPM_VAULT_PA", "WT_SPM_VAULT_SIZE", "PARTITION_VAULT"),
                  ("WT_SPM_ATTEST_PA", "WT_SPM_ATTEST_SIZE",
                   "PARTITION_ATTEST"),
                  ("WT_SPM_HSMDATA_PA", "WT_SPM_HSMDATA_SIZE",
                   "PARTITION_HSM"))
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b")
EXPRESSION = re.compile(r"^[0-9a-fA-FxX+\-*() ]+$")


def evaluate(cc, header, defines, includes):
    probe = '#include "%s"\n' % os.path.abspath(header)
    probe += '#include "%s"\n' % os.path.join(
        os.path.dirname(os.path.abspath(header)), "l3_port.h")
    probe += "".join("%d=%s\n" % (index, name)
                     for index, name in enumerate(MACROS))
    command = [cc, "-E", "-P", "-x", "c"]
    command += ["-D%s" % define for define in defines]
    command += ["-I%s" % path for path in includes]
    result = subprocess.run(command + ["-"], input=probe, text=True,
                            capture_output=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("FAIL: preprocessing %s failed" % header)
    values = {}
    for line in result.stdout.splitlines():
        index, separator, text = line.partition("=")
        if not separator or not index.isdigit() or int(index) >= len(MACROS):
            continue
        name = MACROS[int(index)]
        text = INTEGER.sub(r"\1", text).strip()
        if name == text or not EXPRESSION.match(text):
            raise SystemExit("FAIL: %s does not reduce to a constant: %s" %
                             (name, text))
        values[name] = eval(text, {"__builtins__": {}})
    missing = [name for name in MACROS if name not in values]
    if missing:
        raise SystemExit("FAIL: %s does not define %s" %
                         (header, ", ".join(missing)))
    return values


def check_manifest(path, values):
    """Each keystore band is granted exactly once, to the domain of the
    partition linked into it, and nothing else is granted inside the
    keystore window."""
    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    window = (values["WT_SPM_KEYSTORE_PA"],
              values["WT_SPM_KEYSTORE_PA"] + values["WT_SPM_KEYSTORE_SIZE"])
    owners = {partition["name"]: partition["domain_id"]
              for partition in manifest.get("partitions", ())}
    bands = [(values[base], values[size], owners.get(name))
             for base, size, name in KEYSTORE_BANDS]
    granted = []
    for domain in manifest.get("domains", ()):
        for resource in domain.get("memory_resources", ()):
            base, size = resource["base"], resource["size"]
            if base < window[1] and base + size > window[0]:
                granted.append((base, size, domain["id"]))
    errors = []
    for band in bands:
        if granted.count(band) != 1:
            errors.append("band 0x%X+0x%X is granted %d times to domain %s" %
                          (band[0], band[1], granted.count(band), band[2]))
    for grant in granted:
        if grant not in bands:
            errors.append("grant 0x%X+0x%X to domain %s is not its keystore "
                          "band" % grant)
    if errors:
        raise SystemExit("FAIL: %s: %s" % (path, "; ".join(errors)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("header", help="the port's memory_map.h")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("-I", dest="includes", action="append", default=[])
    parser.add_argument("-D", dest="defines", action="append", default=[])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cflags", action="store_true")
    mode.add_argument("--ldflags", action="store_true")
    mode.add_argument("--shell", action="store_true")
    mode.add_argument("--check-manifest", metavar="JSON")
    args = parser.parse_args()
    values = evaluate(args.cc, args.header, args.defines, args.includes)
    if args.cflags:
        print(" ".join("-D%s=0x%Xu" % (name, values[name])
                       for name in CFLAGS_MACROS))
    elif args.ldflags:
        print(" ".join("-Wl,--defsym=%s=0x%X" % (name, values[name])
                       for name in LDFLAGS_MACROS))
    elif args.shell:
        for name in MACROS:
            print("%s=0x%X" % (name, values[name]))
    else:
        check_manifest(args.check_manifest, values)
    return 0


if __name__ == "__main__":
    sys.exit(main())
