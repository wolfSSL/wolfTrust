#!/usr/bin/env python3
"""Configuration authority (WT-PORT layout): every consumer of a port's
layout reads the one resolved configuration of mk/layout.mk, and any input
change changes the build fingerprint.

For every registered port, at the defaults and under each permitted
override: the configuration is host-compilable; the firmware's view
(memory_map.h preprocessed with WT_LAYOUT_CFLAGS), the layout tool's link,
band and guest outputs, the guest Makefiles' link symbols and the make
variables agree; the build-mode stamp differs for every input change and is
stable without one; a layout define smuggled through WT_EXTRA_CFLAGS is
refused; every secure object that includes a generated manifest header is
ordered after its generation, so a parallel build cannot compile it first."""

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "../../..").resolve()
CC = os.environ.get("CC", "cc")
TOOL = ROOT / "tools" / "l3_layout_args.py"
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b")
FIRMWARE_MACROS = (
    "WT_RAM_S_BASE", "WT_L3_SPM_RAM_SIZE", "WT_SP_HSM_DATA_SIZE",
    "WT_KEYSTORE_BASE", "WT_SP_FWU_STACK_BASE",
    "WT_SP_VAULT_DATA_BASE", "WT_SP_VAULT_DATA_SIZE",
    "WT_SP_ATTEST_DATA_BASE", "WT_SP_ATTEST_DATA_SIZE",
    "WT_SP_HSM_DATA_BASE", "WT_CONF_SP_DATA_BASE", "WT_CONF_SERVER_MMIO_BASE",
    "WT_SECURE_FLASH_BASE", "WT_SECURE_FLASH_SIZE",
    "WT_SECURE_IMAGE_HEADER_SIZE", "WT_CONF_IRQ",
    "WT_GUEST0_FLASH_BASE", "WT_GUEST0_FLASH_SIZE",
    "WT_GUEST1_FLASH_BASE", "WT_GUEST1_FLASH_SIZE",
    "WT_GUEST0_RAM_BASE", "WT_GUEST1_RAM_BASE", "WT_GUEST_RAM_SIZE",
)
checks = 0


def fail(message):
    raise SystemExit("FAIL: layout_config: " + message)


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        fail(message)


# The harness's own make flags (its BUILD_DIR, -s, jobserver) must not leak
# into the builds this test drives.
ENV = {name: value for name, value in os.environ.items()
       if name not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "BUILD_DIR")}


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, env=ENV,
                          **kwargs)


def make(target, goal, *settings, directory=ROOT):
    return run(["make", "-s", "--no-print-directory", "-C", str(directory),
                "TARGET=" + target, "WT_LAYOUT_CPP=" + CC, *settings, goal])


def cflags(target, *settings):
    result = make(target, "print-layout-cflags", *settings)
    if result.returncode != 0:
        fail("%s print-layout-cflags %s: %s" %
             (target, " ".join(settings), result.stderr.strip()))
    return result.stdout.strip()


def stamp(target, *settings):
    result = make(target, "print-build-mode", *settings)
    if result.returncode != 0:
        fail("%s print-build-mode %s: %s" %
             (target, " ".join(settings), result.stderr.strip()))
    return result.stdout


def firmware_view(target, flags, macros=FIRMWARE_MACROS):
    """memory_map.h as the firmware compiles it under this configuration."""
    header = ROOT / "port" / target / "memory_map.h"
    probe = '#include "%s"\n' % header
    probe += "".join("%d=%s\n" % pair for pair in enumerate(macros))
    result = run([CC, "-E", "-P", "-x", "c", *shlex.split(flags), "-"],
                 input=probe)
    if result.returncode != 0:
        fail("%s: host preprocessing with the layout configuration failed: %s"
             % (target, result.stderr.strip()))
    values = {}
    for line in result.stdout.splitlines():
        index, separator, text = line.partition("=")
        if separator and index.isdigit() and int(index) < len(macros):
            if text.strip() != macros[int(index)]:
                values[macros[int(index)]] = eval(
                    INTEGER.sub(r"\1", text), {"__builtins__": {}})
    missing = [name for name in macros if name not in values]
    if missing:
        fail("%s: memory_map.h defines no %s" % (target, ", ".join(missing)))
    return values


def tool(target, flags, *mode):
    result = run([sys.executable, str(TOOL), *mode, "--cc", CC,
                  "--cflags", flags,
                  str(ROOT / "port" / target / "memory_map.h")])
    if result.returncode != 0:
        fail("%s: l3_layout_args.py %s: %s" %
             (target, " ".join(mode), result.stderr.strip()))
    return result.stdout


def defsyms(text):
    return {name: int(value, 16) for name, value in
            re.findall(r"--defsym=(\w+)=(0x[0-9A-Fa-f]+)", text)}


def pairs(text):
    return {name: int(value, 16) for name, value in
            re.findall(r"^(\w+)=(0x[0-9A-Fa-f]+)$", text, re.M)}


def bands(text):
    out = {}
    for name, low, high in re.findall(
            r"--band (\w+)=(0x[0-9A-Fa-f]+):(0x[0-9A-Fa-f]+)", text):
        out[name] = (int(low, 16), int(high, 16))
    low, high = re.search(r"--confdata (0x[0-9A-Fa-f]+):(0x[0-9A-Fa-f]+)",
                          text).groups()
    out["confdata"] = (int(low, 16), int(high, 16))
    return out


def defines(flags):
    out = {}
    for token in shlex.split(flags):
        if token.startswith("-D"):
            name, _, value = token[2:].partition("=")
            out[name] = value
    return out


def agree(target, flags, label):
    """Every consumer sees the values the firmware sees."""
    view = firmware_view(target, flags)
    link = defsyms(tool(target, flags, "--link"))
    for symbol, macro in (("WT_L3_KEYSTORE_ORIGIN", "WT_KEYSTORE_BASE"),
                          ("WT_L3_HSM_DATA_LENGTH", "WT_SP_HSM_DATA_SIZE"),
                          ("WT_L3_STACKS_ORIGIN", "WT_SP_FWU_STACK_BASE")):
        check(link.get(symbol) == view[macro],
              "%s %s: linker %s=%s, firmware %s=%#x" %
              (target, label, symbol, link.get(symbol), macro, view[macro]))
    band = bands(tool(target, flags))
    for name, prefix in (("vault", "WT_SP_VAULT_DATA"),
                         ("attest", "WT_SP_ATTEST_DATA"),
                         ("hsm", "WT_SP_HSM_DATA")):
        want = (view[prefix + "_BASE"],
                view[prefix + "_BASE"] + view[prefix + "_SIZE"])
        check(band.get(name) == want,
              "%s %s: layout check %s band %s, firmware %s" %
              (target, label, name, band.get(name), want))
    want = (view["WT_CONF_SP_DATA_BASE"], view["WT_CONF_SERVER_MMIO_BASE"])
    check(band["confdata"] == want,
          "%s %s: layout check confdata %s, firmware %s" %
          (target, label, band["confdata"], want))
    guest = pairs(tool(target, flags, "--guest"))
    for index in (0, 1):
        for suffix, macro in (("FLASH_ORIGIN", "WT_GUEST%d_FLASH_BASE"),
                              ("FLASH_LENGTH", "WT_GUEST%d_FLASH_SIZE"),
                              ("RAM_ORIGIN", "WT_GUEST%d_RAM_BASE")):
            name = "GUEST%d_%s" % (index, suffix)
            check(guest.get(name) == view[macro % index],
                  "%s %s: guest window %s=%s, firmware %s=%#x" %
                  (target, label, name, guest.get(name), macro % index,
                   view[macro % index]))
        check(guest.get("GUEST%d_RAM_LENGTH" % index) == view["WT_GUEST_RAM_SIZE"],
              "%s %s: guest %d RAM length disagrees" % (target, label, index))
    made = defines(flags)
    for name in ("WT_SECURE_FLASH_BASE", "WT_SECURE_FLASH_SIZE",
                 "WT_SECURE_IMAGE_HEADER_SIZE", "WT_GUEST0_FLASH_BASE",
                 "WT_GUEST1_FLASH_BASE", "WT_GUEST0_FLASH_SIZE",
                 "WT_GUEST1_FLASH_SIZE"):
        check(int(made[name], 0) == view[name],
              "%s %s: make %s=%s, firmware %#x" %
              (target, label, name, made[name], view[name]))
    check(int(made["WT_CONF_IRQ"].rstrip("u"), 0) == view["WT_CONF_IRQ"],
          "%s %s: make and firmware disagree on WT_CONF_IRQ" % (target, label))
    return view, guest


def guest_makefiles_agree(target, flags, guest):
    """A guest build links into the windows the firmware guards."""
    for makefile in sorted((ROOT / "tests" / "firmware").glob(
            "%s-baremetal/Makefile" % target)):
        directory = makefile.parent
        # -o keeps the dry run from recursing into the Secure image build.
        result = run(["make", "-n", "-s", "--no-print-directory",
                      "-C", str(directory), "TARGET=" + target,
                      "WT_LAYOUT_CPP=" + CC,
                      "-o", os.path.relpath(ROOT / "build" / "secure_cmse_implib.o", directory),
                      "all"])
        check(result.returncode == 0, "%s: dry run of %s failed: %s" %
              (target, directory, result.stderr.strip()))
        linked = defsyms(result.stdout)
        for name in ("GUEST_FLASH_ORIGIN", "GUEST_FLASH_LENGTH",
                     "GUEST_RAM_ORIGIN", "GUEST_RAM_LENGTH"):
            check(name in linked, "%s: %s links no %s" % (target, directory, name))
        for index in (0, 1):
            for suffix in ("FLASH_ORIGIN", "FLASH_LENGTH",
                           "RAM_ORIGIN", "RAM_LENGTH"):
                wanted = "--defsym=GUEST_%s=0x%08X" % (
                    suffix, guest["GUEST%d_%s" % (index, suffix)])
                check(wanted in result.stdout,
                      "%s: %s does not link guest %d with %s" %
                      (target, directory, index, wanted))


GENERATED_INCLUDE = re.compile(
    r'^\s*#\s*include\s+"(psa_manifest/[^"]+|wolftrust_manifest_generated\.h)"',
    re.M)
LOCAL_INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)


def includes_generated(source):
    pending, seen = [source], set()
    while pending:
        path = pending.pop()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        text = path.read_text(errors="replace")
        if GENERATED_INCLUDE.search(text):
            return True
        for name in LOCAL_INCLUDE.findall(text):
            pending.extend((path.parent / name, ROOT / "include" / name))
    return False


def generated_headers_ordered(target, *settings):
    result = run(["make", "-np", "--no-print-directory", "-C", str(ROOT),
                  "TARGET=" + target, "WT_LAYOUT_CPP=" + CC, *settings,
                  "secure-image"])
    if result.returncode != 0:
        fail("%s make -np secure-image %s: %s" %
             (target, " ".join(settings), result.stderr.strip()[-400:]))
    names = dict(re.findall(r"^(MANIFEST_GEN_H|MANIFEST_STAMP|CONF_GEN_STAMP) :?= (\S+)$",
                            result.stdout, re.M))
    check("MANIFEST_GEN_H" in names and "MANIFEST_STAMP" in names,
          "%s: the make database lacks the manifest outputs" % target)
    generated = set(names.values())
    consumers = 0
    for obj, prereqs in re.findall(r"^(\S+\.o): ([^\n|%]*)", result.stdout, re.M):
        listed = prereqs.split()
        if not listed or not listed[0].endswith(".c"):
            continue
        source = Path(listed[0])
        source = source if source.is_absolute() else ROOT / source
        if not includes_generated(source):
            continue
        consumers += 1
        check(generated & set(listed[1:]),
              "%s %s: %s includes a generated manifest header but its rule "
              "does not depend on the manifest, so make -j can compile it "
              "first" % (target, " ".join(settings), obj))
    check(consumers > 0, "%s %s: no secure object includes a generated "
          "manifest header" % (target, " ".join(settings)))


def main():
    ports = sorted(path.parent.name
                   for path in (ROOT / "port").glob("*/port.json"))
    check(len(ports) >= 1, "no registered port")
    stamps = {}
    for target in ports:
        base = cflags(target)
        tokens = shlex.split(base)
        check(all(token.startswith(("-D", "-I")) for token in tokens),
              "%s: WT_LAYOUT_CFLAGS carries more than defines and include "
              "paths: %s" % (target, base))
        check("-DWT_CONF_IRQ=" in base and "-DWT_ISOLATION_LEVEL=" in base,
              "%s: WT_LAYOUT_CFLAGS lacks the conformance IRQ or the "
              "isolation level" % target)
        view, guest = agree(target, base, "defaults")
        guest_makefiles_agree(target, base, guest)
        base_stamp = stamp(target)
        check(base_stamp == stamp(target),
              "%s: the build-mode stamp is not stable" % target)
        check(("WT_LAYOUT_CFLAGS=" + base.split(" -I")[0]) in base_stamp,
              "%s: the build-mode stamp does not record WT_LAYOUT_CFLAGS" %
              target)
        stamps[target] = base_stamp
        for variant in ((), ("WT_CONFORMANCE=1",), ("WT_ENGINE=hsm",)):
            generated_headers_ordered(target, *variant)

        # Each case keeps the port's windows inside their regions (the
        # headers refuse an overlap), so a moved secure image also shrinks.
        overrides = (
            (("WT_L3_SPM_RAM_SIZE", view["WT_L3_SPM_RAM_SIZE"] - 0x1000),),
            (("WT_SP_HSM_DATA_SIZE", view["WT_SP_HSM_DATA_SIZE"] - 0x800),),
            (("WT_SECURE_FLASH_BASE", view["WT_SECURE_FLASH_BASE"] + 0x1000),
             ("WT_SECURE_FLASH_SIZE", view["WT_SECURE_FLASH_SIZE"] - 0x1000)),
            (("WT_SECURE_IMAGE_HEADER_SIZE",
              view["WT_SECURE_IMAGE_HEADER_SIZE"] + 0x400),),
            (("WT_GUEST0_FLASH_SIZE", view["WT_GUEST0_FLASH_SIZE"] // 2),),
            (("WT_GUEST1_FLASH_SIZE", view["WT_GUEST1_FLASH_SIZE"] // 2),),
            (("WT_CONF_IRQ", view["WT_CONF_IRQ"] + 1),),
        )
        for case in overrides:
            settings = ["%s=%#x" % pair for pair in case]
            flags = cflags(target, *settings)
            seen = firmware_view(target, flags, tuple(name for name, _ in case))
            for name, value in case:
                check(seen[name] == value,
                      "%s: %s leaves the firmware at %#x" %
                      (target, " ".join(settings), seen[name]))
            agree(target, flags, " ".join(settings))
            check(stamp(target, *settings) != base_stamp,
                  "%s: %s leaves the build-mode stamp unchanged" %
                  (target, " ".join(settings)))
        shape = re.search(r"-DWT_LD_RAM_CODE_BAND=([01])", base_stamp)
        check(shape is not None,
              "%s: the build-mode stamp does not record the linker shape" % target)
        for setting in ("WT_LD_RAM_CODE_BAND=%d" % (1 - int(shape.group(1))),
                        "WT_CONFORMANCE=1", "WT_ENGINE=hsm",
                        "WT_EXTRA_CFLAGS=-DWT_LAYOUT_CONFIG_TEST=1"):
            check(stamp(target, setting) != base_stamp,
                  "%s: %s leaves the build-mode stamp unchanged" % (target, setting))
        for smuggled in ("-DWT_CONF_IRQ=5", "-DWT_L3_SPM_RAM_SIZE=0x4C000",
                         "-DWT_GUEST0_FLASH_BASE"):
            result = make(target, "print-layout-cflags",
                          "WT_EXTRA_CFLAGS=" + smuggled)
            check(result.returncode != 0 and "make variable" in result.stderr,
                  "%s: WT_EXTRA_CFLAGS=%s was not refused" % (target, smuggled))
    for first in ports:
        for second in ports:
            if first < second:
                check(stamps[first] != stamps[second],
                      "%s and %s share a build-mode stamp" % (first, second))
    print("PASS: layout configuration authority (%d ports, %d checks)" %
          (len(ports), checks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
