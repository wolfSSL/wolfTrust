#!/usr/bin/env python3
"""Validate security-critical placement in a linked wolfTrust image."""

import argparse
import io
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# STM32H563 bands; other ports pass their own with --keystore/--confdata.
KEYSTORE_ORIGIN = 0x30075000
KEYSTORE_LIMIT = 0x30089000
CONFDATA_ORIGIN = 0x30093000
CONFDATA_DATA_LIMIT = 0x30095C00

REQUIRED_ENTRIES = (
    "Reset_Handler",
    "SVC_Handler",
    "PendSV_Handler",
    "MemManage_Handler",
    "UsageFault_Handler",
    "SecureFault_Handler",
    "wt_platform_panic",
)

KEYSTORE_STATE = tuple(
    re.compile(pattern)
    for pattern in (
        r"^g_attest_",
        r"^g_vault_",
        r"^g_relay_",
        r"^g_nvm_",
        r"^g_seal_",
        r"^g_flash_ecc_",
        r"^g_fwu_",
        r"^g_wt_flash_",
        r"^g_hsm_flash_ctx(?:\.|$)",
        r"^g_conf_nvm_",
        r"^g_hsm_fault_notify(?:\.|$)",
        r"^g_active_image_version(?:\.|$)",
        r"^g_foreign_probe_fired(?:\.|$)",
        r"^g_boot_lifecycle(?:\.|$)",
        r"^g_boot_seed(?:\.|$)",
        r"^g_boot_handoff(?:\.|$)",
        r"^g_handoff_ready(?:\.|$)",
        r"^g_implementation_id(?:\.|$)",
        r"^g_signer_id(?:\.|$)",
        r"^g_ueid(?:\.|$)",
        r"^g_guests(?:\.|$)",
        r"^g_co_stack_slots(?:\.|$)",
        r"^gCryptoDev(?:\.|$)",
        r"^sha256DrbgDisabled(?:\.|$)",
        r"^initRefCount(?:\.|$)",
    )
)

VNET_STATE = tuple(
    re.compile(pattern)
    for pattern in (
        r"^g_vnet_",
        r"^g_wt_vnet_",
        r"^g_vnics(?:\.|$)",
        r"^g_frames(?:\.|$)",
        r"^g_fdb(?:\.|$)",
        r"^g_ring_storage(?:\.|$)",
        r"^g_switch(?:\.|$)",
    )
)

HEAP_SYMBOL_NAMES = (
    "malloc", "free", "calloc", "realloc", "_sbrk", "_malloc_r", "_free_r",
    "_calloc_r", "_realloc_r", "_sbrk_r",
)
HEAP_SYMBOLS = re.compile(
    r"^(?:%s)(?:\.|$)" % "|".join(
        re.escape(name) for name in HEAP_SYMBOL_NAMES
    )
)
WRITABLE_TYPES = frozenset("bBcCdDgGsS")
EXECUTABLE_TYPES = frozenset("T")


@dataclass(frozen=True)
class Symbol:
    address: int
    size: int
    kind: str
    name: str


@dataclass(frozen=True)
class Layout:
    keystore_origin: int = KEYSTORE_ORIGIN
    keystore_limit: int = KEYSTORE_LIMIT
    confdata_origin: int = CONFDATA_ORIGIN
    confdata_data_limit: int = CONFDATA_DATA_LIMIT
    wolfhal: bool = True


DEFAULT_LAYOUT = Layout()


def parse_nm(text):
    symbols = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 3:
            address, kind, name = fields
            size = "0"
        elif len(fields) == 4:
            address, size, kind, name = fields
        else:
            continue
        try:
            symbols.append(Symbol(int(address, 16), int(size, 16), kind, name))
        except ValueError:
            continue
    return symbols


def symbol_table(symbols):
    table = {}
    for symbol in symbols:
        table.setdefault(symbol.name, []).append(symbol)
    return table


def validate(symbols, layout=DEFAULT_LAYOUT):
    errors = []
    table = symbol_table(symbols)

    def address(name):
        matches = table.get(name, ())
        if len(matches) != 1:
            errors.append("expected one %s symbol, found %d" %
                          (name, len(matches)))
            return None
        return matches[0].address

    bounds = {
        name: address(name)
        for name in (
            "_sdata", "_edata", "_sbss", "_ebss",
            "_s_vnet", "_e_vnet",
            "_s_keystore", "_e_keystore_data",
            "_s_keystore_bss", "_e_keystore",
            "_sconfdata", "_econfdata", "_sconfbss", "_econfbss",
        )
    }
    text_start = address("_s_secure_text")
    text_end = address("_e_secure_text")

    if all(value is not None for value in bounds.values()):
        if not (bounds["_sdata"] <= bounds["_edata"] <=
                bounds["_sbss"] <= bounds["_ebss"] <=
                bounds["_s_vnet"] <= bounds["_e_vnet"] <=
                bounds["_s_keystore"]):
            errors.append("general, VNET, and keystore RAM ranges overlap")
        if bounds["_s_keystore"] != layout.keystore_origin:
            errors.append("keystore origin is not 0x%08x" %
                          layout.keystore_origin)
        if not (bounds["_s_keystore"] <= bounds["_e_keystore_data"] <=
                bounds["_s_keystore_bss"] <= bounds["_e_keystore"] <=
                layout.keystore_limit):
            errors.append("keystore state escapes its isolation band")
        if bounds["_sconfdata"] != layout.confdata_origin:
            errors.append("conformance data origin is not 0x%08x" %
                          layout.confdata_origin)
        if not (bounds["_sconfdata"] <= bounds["_econfdata"] <=
                bounds["_sconfbss"] <= bounds["_econfbss"] <=
                layout.confdata_data_limit):
            errors.append("conformance state escapes its isolation band")

    if (text_start is not None and text_end is not None and
            text_start >= text_end):
        errors.append("secure text range is empty or reversed")

    entries = {}
    for name in REQUIRED_ENTRIES:
        matches = table.get(name, ())
        if len(matches) != 1:
            errors.append("expected one %s symbol, found %d" %
                          (name, len(matches)))
            continue
        entry = matches[0]
        entries[name] = entry
        if entry.kind not in EXECUTABLE_TYPES:
            errors.append("required entry is not strong text: %s" % name)
        if (text_start is not None and text_end is not None and
                not (text_start <= entry.address < text_end)):
            errors.append("required entry outside secure text: %s" % name)

    default_addresses = {
        symbol.address for symbol in table.get("default_handler", ())
    }
    for name, entry in entries.items():
        if entry.address in default_addresses:
            errors.append("required entry aliases default_handler: %s" % name)

    keystore_start = bounds.get("_s_keystore")
    keystore_end = bounds.get("_e_keystore")
    vnet_start = bounds.get("_s_vnet")
    vnet_end = bounds.get("_e_vnet")

    for symbol in symbols:
        if HEAP_SYMBOLS.match(symbol.name):
            errors.append("heap symbol linked into secure image: %s" %
                          symbol.name)
        if symbol.kind not in WRITABLE_TYPES:
            continue
        end = symbol.address + max(symbol.size, 1)
        if any(pattern.match(symbol.name) for pattern in KEYSTORE_STATE):
            if (keystore_start is None or keystore_end is None or
                    symbol.address < keystore_start or end > keystore_end):
                errors.append("keystore state outside its band: %s" %
                              symbol.name)
        if any(pattern.match(symbol.name) for pattern in VNET_STATE):
            if (vnet_start is None or vnet_end is None or
                    symbol.address < vnet_start or end > vnet_end):
                errors.append("VNET state outside its band: %s" % symbol.name)

    timeout = table.get("g_whalTimeout", ())
    if not layout.wolfhal:
        if timeout:
            errors.append("g_whalTimeout linked into a port without wolfHAL")
    elif len(timeout) != 1:
        errors.append("expected one g_whalTimeout symbol, found %d" %
                      len(timeout))
    elif (bounds.get("_sdata") is not None and
          bounds.get("_s_vnet") is not None and
          not (bounds["_sdata"] <= timeout[0].address < bounds["_s_vnet"])):
        errors.append("g_whalTimeout is outside privileged SPM RAM")

    return errors


def check_elf(nm, elf, runner=None, output=None, error=None,
              layout=DEFAULT_LAYOUT):
    if runner is None:
        runner = subprocess.run
    if output is None:
        output = sys.stdout
    if error is None:
        error = sys.stderr

    result = runner(
        [nm, "-n", "-S", "--defined-only", str(elf)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, end="", file=error)
        return result.returncode

    errors = validate(parse_nm(result.stdout), layout)
    if errors:
        for message in errors:
            print("FAIL: %s" % message, file=error)
        return 1

    print("PASS: secure layout (WT-FFM-0010/0011)", file=output)
    return 0


def self_test():
    lines = [
        "0c000800 ? _s_secure_text",
        "0c010000 ? _e_secure_text",
        "30028000 D _sdata",
        "30028020 D _edata",
        "30028020 B _sbss",
        "30028100 B _ebss",
        "30070000 ? _s_vnet",
        "30070100 ? _e_vnet",
        "30075000 ? _s_keystore",
        "30075020 ? _e_keystore_data",
        "30075020 ? _s_keystore_bss",
        "30075200 ? _e_keystore",
        "30093000 ? _sconfdata",
        "30093020 ? _econfdata",
        "30093020 ? _sconfbss",
        "30093040 ? _econfbss",
        "30028004 0000000c D g_whalTimeout",
        "30075040 00000100 B g_guests.lto_priv.0",
        "30075140 00000020 B g_conf_nvm_ctx.lto_priv.0",
        "30070020 00000020 B g_vnet_tx_scratch",
        "0c000900 00000004 t default_handler",
    ]
    lines.extend("0c001%03x 00000004 T %s" % (index * 4, name)
                 for index, name in enumerate(REQUIRED_ENTRIES, 1))
    good = parse_nm("\n".join(lines))

    def changed(symbols, name, address=None, size=None, kind=None):
        result = []
        found = False
        for symbol in symbols:
            if symbol.name == name and not found:
                result.append(Symbol(
                    symbol.address if address is None else address,
                    symbol.size if size is None else size,
                    symbol.kind if kind is None else kind,
                    symbol.name,
                ))
                found = True
            else:
                result.append(symbol)
        if not found:
            raise ValueError("missing self-test symbol: %s" % name)
        return result

    def removed(symbols, name):
        return [symbol for symbol in symbols if symbol.name != name]

    def duplicate(symbols, name):
        match = next(symbol for symbol in symbols if symbol.name == name)
        return list(symbols) + [match]

    def rendered(symbols):
        return "\n".join(
            "%08x %08x %s %s" %
            (symbol.address, symbol.size, symbol.kind, symbol.name)
            for symbol in symbols
        )

    errors = validate(good)
    if errors:
        print("self-test valid table rejected: %s" % ", ".join(errors),
              file=sys.stderr)
        return False

    default_handler = next(
        symbol for symbol in good if symbol.name == "default_handler"
    )
    heap_cases = tuple(
        ("heap symbol %s" % name,
         list(good) + [Symbol(0x0C001800, 16, "T", name)],
         "heap symbol linked into secure image: %s" % name)
        for name in HEAP_SYMBOL_NAMES
    )
    rejection_cases = (
        ("missing bound", removed(good, "_sdata"),
         "expected one _sdata symbol, found 0"),
        ("duplicate bound", duplicate(good, "_sdata"),
         "expected one _sdata symbol, found 2"),
        ("overlapping bands", changed(good, "_e_vnet", 0x30076000),
         "general, VNET, and keystore RAM ranges overlap"),
        ("keystore origin", changed(good, "_s_keystore", 0x30075020),
         "keystore origin is not"),
        ("keystore limit", changed(good, "_e_keystore", 0x30089004),
         "keystore state escapes its isolation band"),
        ("conformance origin", changed(good, "_sconfdata", 0x30093004),
         "conformance data origin is not"),
        ("conformance limit", changed(good, "_econfbss", 0x30095C04),
         "conformance state escapes its isolation band"),
        ("empty text", changed(good, "_e_secure_text", 0x0C000800),
         "secure text range is empty or reversed"),
        ("missing entry", removed(good, "SVC_Handler"),
         "expected one SVC_Handler symbol, found 0"),
        ("duplicate entry", duplicate(good, "SVC_Handler"),
         "expected one SVC_Handler symbol, found 2"),
        ("weak entry", changed(good, "SVC_Handler", kind="W"),
         "required entry is not strong text: SVC_Handler"),
        ("default entry", changed(
            good, "SVC_Handler", address=default_handler.address),
         "required entry aliases default_handler: SVC_Handler"),
        ("entry outside text", changed(
            good, "SVC_Handler", address=0x0C010000),
         "required entry outside secure text: SVC_Handler"),
        ("keystore symbol", changed(
            good, "g_guests.lto_priv.0", address=0x30028200),
         "keystore state outside its band"),
        ("conformance NVM symbol", changed(
            good, "g_conf_nvm_ctx.lto_priv.0", address=0x30028200),
         "keystore state outside its band"),
        ("keystore size overrun", changed(
            good, "g_guests.lto_priv.0", address=0x300751FC, size=8),
         "keystore state outside its band"),
        ("keystore zero-size boundary", list(good) + [
            Symbol(0x30075200, 0, "B", "g_vault_zero")
         ], "keystore state outside its band"),
        ("VNET symbol", changed(
            good, "g_vnet_tx_scratch", address=0x30028200),
         "VNET state outside its band"),
        ("VNET size overrun", changed(
            good, "g_vnet_tx_scratch", address=0x300700FC, size=8),
         "VNET state outside its band"),
        ("VNET zero-size boundary", list(good) + [
            Symbol(0x30070100, 0, "B", "g_vnet_zero")
         ], "VNET state outside its band"),
    ) + heap_cases + (
        ("missing timeout", removed(good, "g_whalTimeout"),
         "expected one g_whalTimeout symbol, found 0"),
        ("duplicate timeout", duplicate(good, "g_whalTimeout"),
         "expected one g_whalTimeout symbol, found 2"),
        ("misplaced timeout", changed(
            good, "g_whalTimeout", address=0x30070000),
         "g_whalTimeout is outside privileged SPM RAM"),
    )
    for label, symbols, expected in rejection_cases:
        errors = validate(symbols)
        if not any(expected in message for message in errors):
            print("self-test did not reject %s: %s" %
                  (label, ", ".join(errors)), file=sys.stderr)
            return False

    moved = Layout(keystore_origin=0x301D5000, keystore_limit=0x301E9000,
                   confdata_origin=0x301F3000,
                   confdata_data_limit=0x301F5C00, wolfhal=False)
    port_cases = (
        ("port keystore band", good, moved,
         "keystore origin is not 0x301d5000"),
        ("port conformance band", good, moved,
         "conformance data origin is not 0x301f3000"),
        ("timeout without wolfHAL", good, moved,
         "g_whalTimeout linked into a port without wolfHAL"),
    )
    for label, symbols, layout, expected in port_cases:
        errors = validate(symbols, layout)
        if not any(expected in message for message in errors):
            print("self-test did not reject %s: %s" %
                  (label, ", ".join(errors)), file=sys.stderr)
            return False
    if validate(removed(good, "g_whalTimeout"), Layout(wolfhal=False)):
        print("self-test rejected a port without wolfHAL", file=sys.stderr)
        return False
    for text in ("0x2000", "0x3000:0x2000", "base:0x3000"):
        try:
            band(text)
        except argparse.ArgumentTypeError:
            continue
        print("self-test accepted band %s" % text, file=sys.stderr)
        return False
    if band("0x301D5000:0x301E9000") != (0x301D5000, 0x301E9000):
        print("self-test misparsed a band", file=sys.stderr)
        return False

    def completed(returncode, stdout="", stderr=""):
        def run(args, **_kwargs):
            return subprocess.CompletedProcess(
                args, returncode, stdout=stdout, stderr=stderr
            )
        return run

    output = io.StringIO()
    error = io.StringIO()
    if check_elf("fake-nm", Path("valid.elf"),
                 runner=completed(0, rendered(good)),
                 output=output, error=error) != 0:
        print("self-test valid CLI path failed", file=sys.stderr)
        return False

    bad_keystore = changed(
        good, "g_guests.lto_priv.0", address=0x30028200
    )
    error = io.StringIO()
    if (check_elf("fake-nm", Path("invalid.elf"),
                  runner=completed(0, rendered(bad_keystore)),
                  output=io.StringIO(), error=error) != 1 or
            "keystore state outside" not in error.getvalue()):
        print("self-test invalid CLI path did not fail", file=sys.stderr)
        return False

    error = io.StringIO()
    if (check_elf("fake-nm", Path("missing.elf"),
                  runner=completed(7, stderr="nm failed\n"),
                  output=io.StringIO(), error=error) != 7 or
            error.getvalue() != "nm failed\n"):
        print("self-test nm failure was not propagated", file=sys.stderr)
        return False

    print("WT-FFM-0010 PASS executable entry and zero-heap checks")
    print("WT-FFM-0011 PASS secure writable-state placement checks")
    print("PASS: secure_layout")
    return True


def band(text):
    origin, separator, limit = text.partition(":")
    try:
        if not separator:
            raise ValueError
        low = int(origin, 0)
        high = int(limit, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "expected ORIGIN:LIMIT, got %r" % text) from None
    if low >= high:
        raise argparse.ArgumentTypeError(
            "band %r is empty or reversed" % text)
    return low, high


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", nargs="?", type=Path)
    parser.add_argument("--nm", default="arm-none-eabi-nm")
    parser.add_argument("--keystore", type=band, metavar="ORIGIN:LIMIT",
                        default=(KEYSTORE_ORIGIN, KEYSTORE_LIMIT))
    parser.add_argument("--confdata", type=band, metavar="ORIGIN:DATA_LIMIT",
                        default=(CONFDATA_ORIGIN, CONFDATA_DATA_LIMIT))
    parser.add_argument("--no-wolfhal", action="store_true",
                        help="the port links no wolfHAL, so no g_whalTimeout")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return 0 if self_test() else 1
    if args.elf is None:
        parser.error("ELF is required unless --self-test is used")

    layout = Layout(keystore_origin=args.keystore[0],
                    keystore_limit=args.keystore[1],
                    confdata_origin=args.confdata[0],
                    confdata_data_limit=args.confdata[1],
                    wolfhal=not args.no_wolfhal)
    return check_elf(args.nm, args.elf, layout=layout)


if __name__ == "__main__":
    sys.exit(main())
