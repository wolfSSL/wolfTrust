#!/usr/bin/env python3
"""Read the isolation level 3 layout from a port's memory_map.h.

The keystore bands, partition stacks and conformance data window come from
the shared Armv8-M layout. The default output is the post-link band check's
arguments; --shell prints the addresses the target scenario checks match
fault logs against. Both read the macros the C code and the linker fragments
are placed by instead of a copied address list."""

import argparse
import os
import re
import subprocess
import sys


BAND_MACROS = (
    "WT_SP_VAULT_DATA_BASE", "WT_SP_VAULT_DATA_SIZE",
    "WT_SP_ATTEST_DATA_BASE", "WT_SP_ATTEST_DATA_SIZE",
    "WT_SP_HSM_DATA_BASE", "WT_SP_HSM_DATA_SIZE",
    "WT_CONF_SP_DATA_BASE", "WT_CONF_SERVER_MMIO_BASE",
)
SHELL_MACROS = BAND_MACROS + (
    "WT_RAM_S_BASE", "WT_SP_SECURE_STACK_SIZE",
    "WT_SP_CRYPTO_STACK_BASE", "WT_SP_ATTEST_STACK_BASE",
    "WT_SP_VAULT_STACK_BASE", "WT_SP_VAULT_STACK_SIZE",
    "WT_L3_SPM_PERIPHERAL_BASE",
)
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b")
EXPRESSION = re.compile(r"^[0-9a-fA-FxX+\-*() ]+$")


def evaluate(cc, header, macros, includes):
    probe = '#include "%s"\n' % header
    port_header = os.path.join(os.path.dirname(header), "l3_port.h")
    if "WT_L3_SPM_PERIPHERAL_BASE" in macros:
        probe += '#include "%s"\n' % port_header
    probe += "".join("%d=%s\n" % (index, name)
                     for index, name in enumerate(macros))
    command = [cc, "-E", "-P", "-x", "c"]
    command += ["-I%s" % path for path in includes]
    result = subprocess.run(command + ["-"], input=probe, text=True,
                            capture_output=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("FAIL: preprocessing %s failed" % header)
    values = {}
    for line in result.stdout.splitlines():
        index, separator, text = line.partition("=")
        if not separator or not index.isdigit() or int(index) >= len(macros):
            continue
        name = macros[int(index)]
        if name == text.strip():
            continue
        text = INTEGER.sub(r"\1", text).strip()
        if not EXPRESSION.match(text):
            raise SystemExit("FAIL: %s does not reduce to a constant: %s" %
                             (name, text))
        values[name] = eval(text, {"__builtins__": {}})
    missing = [name for name in macros if name not in values]
    if missing:
        raise SystemExit("FAIL: %s defines no %s" %
                         (header, ", ".join(missing)))
    return values


def band_args(v):
    out = []
    for band, prefix in (("vault", "WT_SP_VAULT_DATA"),
                         ("attest", "WT_SP_ATTEST_DATA"),
                         ("hsm", "WT_SP_HSM_DATA")):
        base = v[prefix + "_BASE"]
        out.append("--band %s=0x%08X:0x%08X" %
                   (band, base, base + v[prefix + "_SIZE"]))
    out.append("--confdata 0x%08X:0x%08X" %
               (v["WT_CONF_SP_DATA_BASE"], v["WT_CONF_SERVER_MMIO_BASE"]))
    return " ".join(out)


def shell_vars(v):
    stack = v["WT_SP_SECURE_STACK_SIZE"]
    pairs = (
        ("L3_SPM_RAM", v["WT_RAM_S_BASE"]),
        ("L3_VAULT_BAND", v["WT_SP_VAULT_DATA_BASE"]),
        ("L3_ATTEST_BAND", v["WT_SP_ATTEST_DATA_BASE"]),
        ("L3_HSM_BAND", v["WT_SP_HSM_DATA_BASE"]),
        ("L3_CRYPTO_STACK_LO", v["WT_SP_CRYPTO_STACK_BASE"]),
        ("L3_CRYPTO_STACK_HI", v["WT_SP_CRYPTO_STACK_BASE"] + stack),
        ("L3_ATTEST_STACK_LO", v["WT_SP_ATTEST_STACK_BASE"]),
        ("L3_ATTEST_STACK_HI", v["WT_SP_ATTEST_STACK_BASE"] + stack),
        ("L3_VAULT_STACK_LO", v["WT_SP_VAULT_STACK_BASE"]),
        ("L3_VAULT_STACK_HI",
         v["WT_SP_VAULT_STACK_BASE"] + v["WT_SP_VAULT_STACK_SIZE"]),
        ("L3_SPM_PERIPHERAL", v["WT_L3_SPM_PERIPHERAL_BASE"]),
    )
    return "\n".join("%s=0x%08x" % pair for pair in pairs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="arm-none-eabi-gcc")
    parser.add_argument("-I", dest="includes", action="append", default=[])
    parser.add_argument("--shell", action="store_true",
                        help="print the scenario checks' layout variables")
    parser.add_argument("memory_map")
    args = parser.parse_args()

    if args.shell:
        print(shell_vars(evaluate(args.cc, args.memory_map, SHELL_MACROS,
                                  args.includes)))
    else:
        print(band_args(evaluate(args.cc, args.memory_map, BAND_MACROS,
                                 args.includes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
