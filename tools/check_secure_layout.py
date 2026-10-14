#!/usr/bin/env python3
"""Validate security-critical placement in a linked wolfTrust image."""

import argparse
import io
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


# Per-partition keystore data bands: the vault, attestation, and crypto
# partitions each own exactly one (isolation level 3). STM32H563 defaults;
# other ports pass their own with --band/--confdata.
VAULT_ORIGIN = 0x30075000
VAULT_LIMIT = 0x30077000
ATTEST_ORIGIN = 0x30077000
ATTEST_LIMIT = 0x30077800
HSM_ORIGIN = 0x30077800
HSM_LIMIT = 0x30089000
CONFDATA_ORIGIN = 0x30093000
CONFDATA_DATA_LIMIT = 0x30095C00
# SERVICE_TPM mailbox band (CONFIG_TPM builds only). STM32H563 default; other
# ports pass their own with --tpm-band.
TPM_ORIGIN = 0x30095000
TPM_LIMIT = 0x30095800
PKCS11_ORIGIN = 0x30070000
PKCS11_LIMIT = 0x30075000

REQUIRED_ENTRIES = (
    "Reset_Handler",
    "SVC_Handler",
    "PendSV_Handler",
    "MemManage_Handler",
    "UsageFault_Handler",
    "SecureFault_Handler",
    "wt_platform_panic",
)

# wolfCrypt globals every partition's crypto reads and none writes: they must
# link read-only (shared constants), never into a partition band or SPM RAM.
READONLY_STATE = tuple(
    re.compile(pattern)
    for pattern in (
        r"^always_prefetch(?:\.|$)",
        r"^sha256DrbgDisabled(?:\.|$)",
    )
)
READONLY_TYPES = frozenset("rR")

# Public wolfCrypt setters that write READONLY_STATE: linking or referencing
# one would store to the read-only image, so the build fails instead.
READONLY_SETTERS = ("wc_Sha256Drbg_Enable", "wc_Sha256Drbg_Disable")
READONLY_SETTER_SYMBOLS = re.compile(
    r"^(?:%s)(?:\.|$)" % "|".join(
        re.escape(name) for name in READONLY_SETTERS
    )
)
UNDEFINED_TYPES = frozenset("Uwv")

BANDS = (
    ("vault", VAULT_ORIGIN, VAULT_LIMIT),
    ("attest", ATTEST_ORIGIN, ATTEST_LIMIT),
    ("hsm", HSM_ORIGIN, HSM_LIMIT),
)
BAND_NAMES = tuple(name for name, _, _ in BANDS)


@dataclass(frozen=True)
class Layout:
    bands: tuple = BANDS
    confdata_origin: int = CONFDATA_ORIGIN
    confdata_data_limit: int = CONFDATA_DATA_LIMIT
    tpm_origin: int = TPM_ORIGIN
    tpm_limit: int = TPM_LIMIT
    pkcs11_origin: int = PKCS11_ORIGIN
    pkcs11_limit: int = PKCS11_LIMIT
    wolfhal: bool = True


DEFAULT_LAYOUT = Layout()

# Owners (tools/secure_owners.txt) and the linker symbols bounding the region
# each may place writable state in. "shared" objects may place none.
OWNER_REGIONS = {
    "spm": ("_sdata", "_ebss"),
    "vault": ("_s_vault", "_e_vault"),
    "attest": ("_s_attest", "_e_attest"),
    "hsm": ("_s_hsm", "_e_hsm"),
    "vnet": ("_s_vnet", "_e_vnet"),
    "tpm": ("_s_tpm", "_e_tpm"),
    "pkcs11": ("_s_pkcs11", "_e_pkcs11"),
    "conf": ("_sconfdata", "_econfbss"),
    "conf-server": ("_s_conf_server_data", "_e_conf_server_data"),
    "conf-driver": ("_s_conf_driver_data", "_e_conf_driver_data"),
}
# AArch64 keeps the optional direct-application provider in one shared
# interface band. TPM and PKCS#11 are mutually exclusive build modes, so both
# owner classes intentionally resolve to the same linker bounds. The other
# partition bands retain their per-owner bounds while S-EL1 state stays in the
# private SPM RAM window.
AARCH64_OWNER_REGIONS = dict(OWNER_REGIONS, **{
    "spm": ("__data_start", "__spm_ram_end"),
    "tpm": ("_s_interface", "_e_interface"),
    "pkcs11": ("_s_interface", "_e_interface"),
    "conf": ("_s_conf_data", "_e_conf_data"),
})
OWNER_PROFILES = {
    "armv8m": OWNER_REGIONS,
    "aarch64": AARCH64_OWNER_REGIONS,
}
SHARED_OWNER = "shared"
SPM_OWNER = "spm"
# The SPM also owns the secure stacks the linker script places by section.
SPM_STACK_SECTIONS = (".sp_stacks",)
# An LTO link unit carries no object identity; no band claims it by name, so
# its writable state can only land in SPM-private RAM.
LTO_UNIT = re.compile(r"\.ltrans\d*(?:\.ltrans)?\.o$")

# Conformance-only entry points and state: a production image links none.
CONFORMANCE_SYMBOLS = re.compile(
    r"^(?:wt_platform_conf_|wt_conf_|wt_spm_conf_|g_spm_conf_|g_conf_)"
)
CONFORMANCE_OBJECT = re.compile(r"^conf_sec_")

HEAP_SYMBOL_NAMES = (
    "malloc", "free", "calloc", "realloc", "_sbrk", "_malloc_r", "_free_r",
    "_calloc_r", "_realloc_r", "_sbrk_r",
)
HEAP_SYMBOLS = re.compile(
    r"^(?:%s)(?:\.|$)" % "|".join(
        re.escape(name) for name in HEAP_SYMBOL_NAMES
    )
)
EXECUTABLE_TYPES = frozenset("T")

MAP_MEMORY = re.compile(
    r"^(\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)(?:\s+(\S+))?\s*$"
)
MAP_OUTPUT = re.compile(r"^(\.\S+)")
MAP_INPUT = re.compile(r"^ (\S+)(?:\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)"
                       r"\s+(\S.*?))?\s*$")
MAP_PLACED = re.compile(r"^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)"
                        r"\s+(\S.*?)\s*$")


@dataclass(frozen=True)
class Symbol:
    address: int
    size: int
    kind: str
    name: str


@dataclass(frozen=True)
class Region:
    name: str
    origin: int
    length: int
    writable: bool


@dataclass(frozen=True)
class Section:
    output: str
    name: str
    address: int
    size: int
    origin: str


@dataclass(frozen=True)
class Owners:
    exact: dict
    families: tuple

    def owner(self, name):
        if name in self.exact:
            return self.exact[name]
        for prefix, owner in self.families:
            if name.startswith(prefix):
                return owner
        return None


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


def parse_owners(text):
    exact = {}
    families = []
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2:
            errors.append("owner map line %d is not 'object owner'" % number)
            continue
        name, owner = fields
        if owner != SHARED_OWNER and owner not in OWNER_REGIONS:
            errors.append("owner map line %d names unknown owner %s" %
                          (number, owner))
            continue
        if name.endswith("*"):
            families.append((name[:-1], owner))
        elif name in exact:
            errors.append("owner map lists %s twice" % name)
        else:
            exact[name] = owner
    # Longest prefix first, so a narrower family wins over a wider one.
    families.sort(key=lambda entry: len(entry[0]), reverse=True)
    return Owners(exact, tuple(families)), errors


def object_name(origin):
    """The owner-map key for a linker map origin: an object's basename, or
    the archive's basename for an archive member."""
    origin = origin.strip()
    if origin.endswith(")") and "(" in origin:
        origin = origin[:origin.rindex("(")]
    return origin.replace("\\", "/").rsplit("/", 1)[-1]


def parse_map(text):
    regions = []
    sections = []
    state = "head"
    output = None
    pending = None

    for line in text.splitlines():
        if state == "head":
            if line.startswith("Memory Configuration"):
                state = "memory"
            continue
        if state == "memory":
            if line.startswith("Linker script and memory map"):
                state = "map"
                continue
            match = MAP_MEMORY.match(line)
            if match and match.group(1) not in ("Name", "*default*"):
                regions.append(Region(
                    match.group(1), int(match.group(2), 16),
                    int(match.group(3), 16),
                    "w" in (match.group(4) or "")))
            continue

        if pending is not None:
            match = MAP_PLACED.match(line)
            name = pending
            pending = None
            if match and not match.group(3).startswith("0x"):
                sections.append(Section(
                    output, name, int(match.group(1), 16),
                    int(match.group(2), 16), match.group(3)))
                continue
        if line.startswith("."):
            match = MAP_OUTPUT.match(line)
            if match:
                output = match.group(1)
            continue
        if not line.startswith(" ") or line.startswith("  "):
            continue
        match = MAP_INPUT.match(line)
        if not match:
            continue
        name = match.group(1)
        if name.startswith("*") or output is None:
            continue
        if match.group(2) is None:
            pending = name
        else:
            sections.append(Section(
                output, name, int(match.group(2), 16),
                int(match.group(3), 16), match.group(4)))
    return regions, sections


def validate(symbols, production=False, layout=DEFAULT_LAYOUT,
             require_tpm=False, require_pkcs11=False):
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
            "_s_vault", "_e_vault_data", "_s_vault_bss", "_e_vault",
            "_s_attest", "_e_attest_data", "_s_attest_bss", "_e_attest",
            "_s_hsm", "_e_hsm_data", "_s_hsm_bss", "_e_hsm",
            "_sconfdata", "_econfdata", "_sconfbss", "_econfbss",
        )
    }
    text_start = address("_s_secure_text")
    text_end = address("_e_secure_text")

    if all(value is not None for value in bounds.values()):
        if not (bounds["_sdata"] <= bounds["_edata"] <=
                bounds["_sbss"] <= bounds["_ebss"] <=
                bounds["_s_vnet"] <= bounds["_e_vnet"] <=
                bounds["_s_vault"]):
            errors.append("general, VNET, and keystore RAM ranges overlap")
        for band, origin, limit in layout.bands:
            if bounds["_s_%s" % band] != origin:
                errors.append("%s band origin is not 0x%08x" % (band, origin))
            if not (bounds["_s_%s" % band] <=
                    bounds["_e_%s_data" % band] <=
                    bounds["_s_%s_bss" % band] <=
                    bounds["_e_%s" % band] <= limit):
                errors.append("%s state escapes its isolation band" % band)
        if bounds["_sconfdata"] != layout.confdata_origin:
            errors.append("conformance data origin is not 0x%08x" %
                          layout.confdata_origin)
        if not (bounds["_sconfdata"] <= bounds["_econfdata"] <=
                bounds["_sconfbss"] <= bounds["_econfbss"] <=
                layout.confdata_data_limit):
            errors.append("conformance state escapes its isolation band")
        if production and bounds["_sconfdata"] != bounds["_econfbss"]:
            errors.append("production image carries conformance data")

    # SERVICE_TPM mailbox band (CONFIG_TPM builds only): when it carries state,
    # hold it to the same fixed origin and containment the keystore bands get.
    # Empty outside CONFIG_TPM; a linked relay object makes emptiness an error.
    tpm_edges = {
        name: table.get(name, ())
        for name in ("_s_tpm", "_e_tpm_data", "_s_tpm_bss", "_e_tpm")
    }
    if all(len(matches) == 1 for matches in tpm_edges.values()):
        s_tpm = tpm_edges["_s_tpm"][0].address
        e_tpm_data = tpm_edges["_e_tpm_data"][0].address
        s_tpm_bss = tpm_edges["_s_tpm_bss"][0].address
        e_tpm = tpm_edges["_e_tpm"][0].address
        if require_tpm and e_tpm <= s_tpm:
            errors.append("required tpm band is empty")
        if e_tpm > s_tpm:
            if s_tpm != layout.tpm_origin:
                errors.append("tpm band origin is not 0x%08x" %
                              layout.tpm_origin)
            if not (s_tpm <= e_tpm_data <= s_tpm_bss <= e_tpm <=
                    layout.tpm_limit):
                errors.append("tpm state escapes its isolation band")
    elif require_tpm:
        errors.append("required tpm band markers are missing or duplicated")

    pkcs11_edges = {
        name: table.get(name, ())
        for name in ("_s_pkcs11", "_e_pkcs11_data", "_s_pkcs11_bss",
                     "_e_pkcs11")
    }
    if all(len(matches) == 1 for matches in pkcs11_edges.values()):
        s_pkcs11 = pkcs11_edges["_s_pkcs11"][0].address
        e_pkcs11_data = pkcs11_edges["_e_pkcs11_data"][0].address
        s_pkcs11_bss = pkcs11_edges["_s_pkcs11_bss"][0].address
        e_pkcs11 = pkcs11_edges["_e_pkcs11"][0].address
        if require_pkcs11 and e_pkcs11 <= s_pkcs11:
            errors.append("required pkcs11 band is empty")
        if e_pkcs11 > s_pkcs11:
            if s_pkcs11 != layout.pkcs11_origin:
                errors.append("pkcs11 band origin is not 0x%08x" %
                              layout.pkcs11_origin)
            if not (s_pkcs11 <= e_pkcs11_data <= s_pkcs11_bss <=
                    e_pkcs11 <= layout.pkcs11_limit):
                errors.append("pkcs11 state escapes its isolation band")
    elif require_pkcs11:
        errors.append("required pkcs11 band markers are missing or duplicated")

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

    for symbol in symbols:
        if HEAP_SYMBOLS.match(symbol.name):
            errors.append("heap symbol linked into secure image: %s" %
                          symbol.name)
        if (any(pattern.match(symbol.name) for pattern in READONLY_STATE) and
                symbol.kind not in READONLY_TYPES):
            errors.append("shared library state is not read-only: %s" %
                          symbol.name)
        if production and CONFORMANCE_SYMBOLS.match(symbol.name):
            errors.append("conformance symbol in a production image: %s" %
                          symbol.name)

    # The privileged tasklet stacks and their registry sit below every band.
    band_starts = [bounds.get("_s_%s" % band) for band, _, _ in layout.bands]
    band_starts.append(bounds.get("_s_vnet"))
    priv_end = None if None in band_starts else min(band_starts)
    for name, matches in table.items():
        if name.startswith("g_co_stack_slots"):
            label = "privileged tasklet stack"
        elif name.startswith("g_wt_taskreg"):
            label = "privileged tasklet registry"
        else:
            continue
        for symbol in matches:
            end = symbol.address + max(symbol.size, 1)
            if (bounds.get("_sdata") is None or priv_end is None or
                    symbol.address < bounds["_sdata"] or end > priv_end):
                errors.append(
                    "%s outside SPM-private RAM: %s" % (label, name))

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


def validate_ownership(symbols, regions, sections, owners, objects=(),
                       production=False, owner_regions=OWNER_REGIONS):
    """Every writable input section must lie in its object's owner region."""
    errors = []
    table = symbol_table(symbols)
    reported = set()

    def bound(name):
        matches = table.get(name, ())
        return matches[0].address if len(matches) == 1 else None

    def owner_of(name):
        if LTO_UNIT.search(name):
            return SPM_OWNER
        return owners.owner(name)

    def report(kind, name):
        if (kind, name) not in reported:
            reported.add((kind, name))
            errors.append("%s: %s" % (kind, name))

    writable = [region for region in regions
                if region.writable and region.length != 0]
    if not writable:
        errors.append("linker map names no writable memory region")

    for path in objects:
        name = object_name(str(path))
        if owner_of(name) is None:
            report("object has no owner entry", name)
        if production and CONFORMANCE_OBJECT.match(name):
            report("conformance object in a production image", name)

    for section in sections:
        name = object_name(section.origin)
        if production and CONFORMANCE_OBJECT.match(name):
            report("conformance object in a production image", name)
        if section.size == 0:
            continue
        end = section.address + section.size
        if not any(region.origin <= section.address and
                   end <= region.origin + region.length
                   for region in writable):
            # Straddling a writable region's edge is as wrong as leaving it.
            if any(section.address < region.origin + region.length and
                   end > region.origin for region in writable):
                errors.append("writable section crosses a memory region: "
                              "%s (%s)" % (section.name, name))
            continue
        owner = owner_of(name)
        if owner is None:
            report("object has no owner entry", name)
            continue
        if owner == SHARED_OWNER:
            errors.append("shared object holds writable state: %s (%s)" %
                          (section.name, name))
            continue
        if owner == SPM_OWNER and section.output in SPM_STACK_SECTIONS:
            continue
        low, high = owner_regions[owner]
        start = bound(low)
        stop = bound(high)
        if (start is None or stop is None or
                section.address < start or end > stop):
            errors.append("%s object places writable state outside its "
                          "region: %s (%s)" % (owner, section.name, name))
    return errors


def validate_references(text):
    # LTO can inline a setter out of the ELF; the caller's object still
    # carries the undefined reference.
    errors = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[-2] not in UNDEFINED_TYPES:
            continue
        if READONLY_SETTER_SYMBOLS.match(fields[-1]):
            errors.append("read-only library state setter referenced: %s" %
                          line.strip())
    return errors


def check_objects(nm, objects, runner=None, error=None):
    if runner is None:
        runner = subprocess.run
    if error is None:
        error = sys.stderr

    result = runner(
        [nm, "-A", "-u"] + [str(obj) for obj in objects],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or "plugin needed" in result.stderr:
        print(result.stderr, end="", file=error)
        return result.returncode if result.returncode != 0 else 1

    errors = validate_references(result.stdout)
    for message in errors:
        print("FAIL: %s" % message, file=error)
    return 1 if errors else 0


def is_lto_object(path):
    try:
        return b".gnu.lto_" in Path(path).read_bytes()
    except OSError:
        return False


def validate_lto_provenance(objects, owners, is_lto):
    """An LTO unit links as SPM and loses its source object's owner, so every
    object owned by a partition or marked shared must be compiled without
    LTO for its placement to be checkable."""
    errors = []
    for path in objects:
        owner = owners.owner(Path(path).name)
        if owner is None or owner == SPM_OWNER:
            continue
        if is_lto(path):
            errors.append("object owned by %s was compiled with LTO: %s" %
                          (owner, path))
    return errors


def check_lto_provenance(objects, owners_text, error=None,
                         is_lto=is_lto_object):
    if error is None:
        error = sys.stderr

    owners, errors = parse_owners(owners_text)
    if not errors:
        errors = validate_lto_provenance(objects, owners, is_lto)
    for message in errors:
        print("FAIL: %s" % message, file=error)
    return 1 if errors else 0


def check_elf(nm, elf, map_text=None, owners_text=None, objects=(),
              production=False, runner=None, output=None, error=None,
              layout=DEFAULT_LAYOUT, ownership_only=False,
              owner_regions=OWNER_REGIONS):
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

    symbols = parse_nm(result.stdout)
    require_tpm = any(
        Path(path).name.endswith("tpm_relay_service.o") for path in objects
    )
    require_pkcs11 = any(
        Path(path).name.endswith("pkcs11_relay_service.o") for path in objects
    )
    errors = []
    if not ownership_only:
        errors = validate(symbols, production, layout, require_tpm=require_tpm,
                          require_pkcs11=require_pkcs11)
    if map_text is not None:
        owners, owner_errors = parse_owners(owners_text or "")
        regions, sections = parse_map(map_text)
        errors.extend(owner_errors)
        errors.extend(validate_ownership(
            symbols, regions, sections, owners, objects, production,
            owner_regions))
    if errors:
        for message in errors:
            print("FAIL: %s" % message, file=error)
        return 1

    if ownership_only:
        print("PASS: secure ownership (WT-FFM-0011)", file=output)
    else:
        print("PASS: secure layout (WT-FFM-0010/0011)", file=output)
    return 0


SELF_TEST_OWNERS = """
# object owner
sec_monitor.o            spm
wt_sec_wt_hsm_priv.o     spm
wt_sec_nvm_store.o       vault
wt_sec_initial_attestation.o attest
wt_sec_wt_hsm.o          hsm
wt_sec_vnet_switch.o     vnet
wc_sec_aes.o             shared
conf_sec_driver_partition.o conf-driver
conf_sec_test_supp_i*    conf-server
conf_sec_*               conf
libgcc.a                 shared
"""


def render_map(sections):
    lines = [
        "Memory Configuration",
        "",
        "Name             Origin             Length             Attributes",
        "FLASH            0x0c000400         0x0003fc00         xr",
        "RAM              0x30028000         0x00048000         xrw",
        "VNETDATA         0x30070000         0x00005000         rw",
        "VAULTDATA        0x30075000         0x00002000         rw",
        "ATTESTDATA       0x30077000         0x00000800         rw",
        "HSMDATA          0x30077800         0x00011800         rw",
        "CONFDATA         0x30093000         0x00003000         rw",
        "SPSTACKS         0x30096000         0x0000a000         rw",
        "*default*        0x00000000         0xffffffff",
        "",
        "Linker script and memory map",
        "",
        "LOAD build/sec_monitor.o",
    ]
    output = None
    for section in sections:
        if section.output != output:
            output = section.output
            lines.append("%s  0x%08x  0x%x" % (output, section.address, 0))
            lines.append(" *(%s*)" % output)
        if len(section.name) > 14:
            lines.append(" %s" % section.name)
            lines.append("                0x%08x  0x%x %s" %
                         (section.address, section.size, section.origin))
        else:
            lines.append(" %-14s 0x%08x  0x%x %s" %
                         (section.name, section.address, section.size,
                          section.origin))
        lines.append("                0x%08x                %s" %
                     (section.address, section.name.rsplit(".", 1)[-1]))
    lines.append(" *fill*         0x30028003        0x1 ")
    return "\n".join(lines) + "\n"


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
        "30075000 ? _s_vault",
        "30075020 ? _e_vault_data",
        "30075020 ? _s_vault_bss",
        "30075200 ? _e_vault",
        "30077000 ? _s_attest",
        "30077020 ? _e_attest_data",
        "30077020 ? _s_attest_bss",
        "30077100 ? _e_attest",
        "30077800 ? _s_hsm",
        "30077820 ? _e_hsm_data",
        "30077820 ? _s_hsm_bss",
        "30078000 ? _e_hsm",
        "30093000 ? _sconfdata",
        "30093020 ? _s_conf_server_data",
        "30093040 ? _e_conf_server_data",
        "30093040 ? _s_conf_driver_data",
        "30093060 ? _e_conf_driver_data",
        "30093060 ? _econfdata",
        "30093060 ? _sconfbss",
        "30093080 ? _econfbss",
        "30095000 ? _s_tpm",
        "30095004 ? _e_tpm_data",
        "30095004 ? _s_tpm_bss",
        "30095420 ? _e_tpm",
        "30028004 0000000c D g_whalTimeout",
        "30077840 00000100 B g_guests",
        "30028020 00000080 B g_co_stack_slots",
        "300280a0 00000008 B g_wt_taskreg",
        "30075160 00000018 B g_wt_nvm_ctx",
        "30077040 00000021 b g_ueid",
        "0c00f000 00000004 r always_prefetch",
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

    empty_tpm = good
    for name in ("_e_tpm_data", "_s_tpm_bss", "_e_tpm"):
        empty_tpm = changed(empty_tpm, name, 0x30095000)
    errors = validate(empty_tpm, require_tpm=True)
    if not any("required tpm band is empty" in message for message in errors):
        print("self-test accepted a required empty TPM band", file=sys.stderr)
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
        ("vault origin", changed(good, "_s_vault", 0x30075020),
         "vault band origin is not"),
        ("vault limit", changed(good, "_e_vault", 0x30077004),
         "vault state escapes its isolation band"),
        ("attest origin", changed(good, "_s_attest", 0x30077020),
         "attest band origin is not"),
        ("attest limit", changed(good, "_e_attest", 0x30077804),
         "attest state escapes its isolation band"),
        ("hsm origin", changed(good, "_s_hsm", 0x30077820),
         "hsm band origin is not"),
        ("hsm limit", changed(good, "_e_hsm", 0x30089004),
         "hsm state escapes its isolation band"),
        ("conformance origin", changed(good, "_sconfdata", 0x30093004),
         "conformance data origin is not"),
        ("conformance limit", changed(good, "_econfbss", 0x30095C04),
         "conformance state escapes its isolation band"),
        ("tpm origin", changed(good, "_s_tpm", 0x30095100),
         "tpm band origin is not"),
        ("tpm limit", changed(good, "_e_tpm", 0x30096000),
         "tpm state escapes its isolation band"),
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
        ("privileged stack in the vault band", changed(
            good, "g_co_stack_slots", address=0x30075100),
         "privileged tasklet stack outside SPM-private RAM"),
        ("privileged stack in the attest band", changed(
            good, "g_co_stack_slots", address=0x30077040),
         "privileged tasklet stack outside SPM-private RAM"),
        ("privileged stack in the hsm band", changed(
            good, "g_co_stack_slots", address=0x30077900),
         "privileged tasklet stack outside SPM-private RAM"),
        ("privileged stack in the VNET band", changed(
            good, "g_co_stack_slots", address=0x30070020),
         "privileged tasklet stack outside SPM-private RAM"),
        ("privileged stack across the first band", changed(
            good, "g_co_stack_slots", address=0x3006FFC0),
         "privileged tasklet stack outside SPM-private RAM"),
        ("registry in the vault band", changed(
            good, "g_wt_taskreg", address=0x30075100),
         "privileged tasklet registry outside SPM-private RAM"),
        ("registry in the hsm band", changed(
            good, "g_wt_taskreg", address=0x30077900),
         "privileged tasklet registry outside SPM-private RAM"),
        ("writable prefetch anchor", changed(
            good, "always_prefetch", address=0x30077900, kind="b"),
         "shared library state is not read-only"),
        ("prefetch anchor in .data", changed(
            good, "always_prefetch", kind="D"),
         "shared library state is not read-only"),
        ("writable DRBG flag", list(good) + [
            Symbol(0x30028200, 4, "b", "sha256DrbgDisabled")
         ], "shared library state is not read-only"),
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

    # A VNET build moves the lowest band down; the stack rule follows it.
    if not any("privileged tasklet stack" in message for message in validate(
            changed(changed(good, "_s_vnet", 0x30028080),
                    "_e_vnet", 0x30028080))):
        print("self-test stack rule ignored the lowest band",
              file=sys.stderr)
        return False

    production = changed(changed(changed(changed(changed(changed(changed(
        good, "_s_conf_server_data", 0x30093000),
        "_e_conf_server_data", 0x30093000),
        "_s_conf_driver_data", 0x30093000),
        "_e_conf_driver_data", 0x30093000),
        "_econfdata", 0x30093000),
        "_sconfbss", 0x30093000), "_econfbss", 0x30093000)
    errors = validate(production, production=True)
    if errors:
        print("self-test production table rejected: %s" % ", ".join(errors),
              file=sys.stderr)
        return False
    production_cases = (
        ("conformance data", good, "production image carries conformance"),
        ("conformance grants", list(production) + [
            Symbol(0x0C001900, 8, "T", "wt_platform_conf_sp_grants")
         ], "conformance symbol in a production image"),
        ("conformance NVM sync", list(production) + [
            Symbol(0x0C001900, 8, "t", "wt_conf_nvm_flash_sync.lto_priv.0")
         ], "conformance symbol in a production image"),
        ("conformance interrupt source", list(production) + [
            Symbol(0x0C001900, 8, "T", "wt_conf_uart_irq_set")
         ], "conformance symbol in a production image"),
        ("conformance state", list(production) + [
            Symbol(0x30028200, 4, "b", "g_spm_conf_activity")
         ], "conformance symbol in a production image"),
    )
    for label, symbols, expected in production_cases:
        errors = validate(symbols, production=True)
        if not any(expected in message for message in errors):
            print("self-test did not reject production %s: %s" %
                  (label, ", ".join(errors)), file=sys.stderr)
            return False

    moved = port_layout((("vault", 0x301D5000, 0x301D7000),
                         ("attest", 0x301D7000, 0x301D7800),
                         ("hsm", 0x301D7800, 0x301E9000)),
                        (0x301F3000, 0x301F5C00), False)
    port_cases = (
        ("port vault band", good, moved, "vault band origin is not 0x301d5000"),
        ("port conformance band", good, moved,
         "conformance data origin is not 0x301f3000"),
        ("timeout without wolfHAL", good, moved,
         "g_whalTimeout linked into a port without wolfHAL"),
    )
    for label, symbols, layout, expected in port_cases:
        errors = validate(symbols, layout=layout)
        if not any(expected in message for message in errors):
            print("self-test did not reject %s: %s" %
                  (label, ", ".join(errors)), file=sys.stderr)
            return False
    if validate(removed(good, "g_whalTimeout"), layout=Layout(wolfhal=False)):
        print("self-test rejected a port without wolfHAL", file=sys.stderr)
        return False
    for text in ("0x2000", "0x3000:0x2000", "base:0x3000"):
        try:
            band(text)
        except argparse.ArgumentTypeError:
            continue
        print("self-test accepted band %s" % text, file=sys.stderr)
        return False
    for text in ("vault0x1000:0x2000", "keystore=0x1000:0x2000"):
        try:
            named_band(text)
        except argparse.ArgumentTypeError:
            continue
        print("self-test accepted band %s" % text, file=sys.stderr)
        return False
    try:
        port_layout((("vault", 0x1000, 0x2000),), (0x3000, 0x4000), True)
    except argparse.ArgumentTypeError:
        pass
    else:
        print("self-test accepted a partial band set", file=sys.stderr)
        return False

    owners, owner_errors = parse_owners(SELF_TEST_OWNERS)
    if owner_errors:
        print("self-test owner map rejected: %s" % ", ".join(owner_errors),
              file=sys.stderr)
        return False
    for text, expected in (
        ("a.o spm\na.o vault\n", "lists a.o twice"),
        ("a.o nobody\n", "unknown owner"),
        ("a.o\n", "is not 'object owner'"),
    ):
        _, owner_errors = parse_owners(text)
        if not any(expected in message for message in owner_errors):
            print("self-test accepted a bad owner map: %s" % text.strip(),
                  file=sys.stderr)
            return False

    placed = [
        Section(".data", ".data.g_whalTimeout", 0x30028004, 0xC,
                "/tmp/ccAbCdEf.ltrans0.ltrans.o"),
        Section(".bss", ".bss.g_co_stack_slots", 0x30028020, 0x80,
                "build/wt_sec_wt_hsm_priv.o"),
        Section(".bss", "COMMON", 0x300280A0, 0x10, "build/sec_monitor.o"),
        Section(".bss", ".bss.empty", 0x300280B0, 0x0,
                "build/sec_monitor.o"),
        Section(".vnet_bss", ".bss.g_vnet_tx_scratch", 0x30070020, 0x20,
                "build/wt_sec_vnet_switch.o"),
        Section(".vault_bss", ".bss.g_wt_nvm_ctx", 0x30075160, 0x18,
                "build/wt_sec_nvm_store.o"),
        Section(".attest_bss", ".bss.g_ueid", 0x30077040, 0x21,
                "build/wt_sec_initial_attestation.o"),
        Section(".hsm_bss", ".bss.g_guests", 0x30077840, 0x100,
                "build/wt_sec_wt_hsm.o"),
        Section(".conf_data", ".data.client", 0x30093000, 0x20,
                "build/conf_sec_client_partition.o"),
        Section(".conf_data", ".data.supp", 0x30093020, 0x20,
                "build/conf_sec_test_supp_i001.o"),
        Section(".conf_data", ".data.driver", 0x30093040, 0x20,
                "build/conf_sec_driver_partition.o"),
        Section(".sp_stacks", ".sp_stacks.its", 0x30096000, 0x2000,
                "build/sec_monitor.o"),
        Section(".text", ".text.aes", 0x0C001000, 0x100,
                "build/wc_sec_aes.o"),
        Section(".text", ".text.div", 0x0C001100, 0x40,
                "/opt/gcc/lib/libgcc.a(_udivmoddi4.o)"),
    ]
    regions, sections = parse_map(render_map(placed))
    if sections != placed:
        print("self-test linker map did not round-trip", file=sys.stderr)
        return False
    if len([region for region in regions if region.writable]) != 7:
        print("self-test linker map regions misparsed", file=sys.stderr)
        return False
    errors = validate_ownership(good, regions, sections, owners,
                                [Path("build/wt_sec_wt_hsm.o")])
    if errors:
        print("self-test valid ownership rejected: %s" % ", ".join(errors),
              file=sys.stderr)
        return False

    def moved(name, address=None, origin=None, size=None, output=None):
        result = []
        for section in placed:
            if section.name == name:
                section = Section(
                    section.output if output is None else output,
                    section.name,
                    section.address if address is None else address,
                    section.size if size is None else size,
                    section.origin if origin is None else origin)
            result.append(section)
        return result

    ownership_cases = (
        ("vault global in the hsm band",
         moved(".bss.g_wt_nvm_ctx", address=0x30077900), (),
         "vault object places writable state outside its region"),
        ("hsm global in the vault band",
         moved(".bss.g_guests", address=0x30075040), (),
         "hsm object places writable state outside its region"),
        ("attest global in the vault band",
         moved(".bss.g_ueid", address=0x30075100), (),
         "attest object places writable state outside its region"),
        ("partition global in SPM RAM",
         moved(".bss.g_guests", address=0x30028040), (),
         "hsm object places writable state outside its region"),
        ("SPM global in a partition band",
         moved(".bss.g_co_stack_slots", address=0x30077900), (),
         "spm object places writable state outside its region"),
        ("link-time-optimized state in a partition band",
         moved(".data.g_whalTimeout", address=0x30075040), (),
         "spm object places writable state outside its region"),
        ("SPM global above the general sections",
         moved(".bss.g_co_stack_slots", address=0x30028100), (),
         "spm object places writable state outside its region"),
        ("partition global past its band end",
         moved(".bss.g_guests", address=0x30077FFC, size=8), (),
         "hsm object places writable state outside its region"),
        ("partition global on a partition stack",
         moved(".bss.g_guests", address=0x30096000, output=".sp_stacks"), (),
         "hsm object places writable state outside its region"),
        ("VNET global in SPM RAM",
         moved(".bss.g_vnet_tx_scratch", address=0x30028040), (),
         "vnet object places writable state outside its region"),
        ("server test data in the shared conformance window",
         moved(".data.supp", address=0x30093000), (),
         "conf-server object places writable state outside its region"),
        ("driver data in the server band",
         moved(".data.driver", address=0x30093020), (),
         "conf-driver object places writable state outside its region"),
        ("shared library with a static",
         list(placed) + [Section(".bss", ".bss.aes_state", 0x300280C0, 4,
                                 "build/wc_sec_aes.o")], (),
         "shared object holds writable state"),
        ("archive member with a static",
         list(placed) + [Section(".bss", ".bss.div", 0x300280C0, 4,
                                 "/opt/gcc/lib/libgcc.a(_udivmoddi4.o)")],
         (), "shared object holds writable state"),
        ("unowned object with state",
         list(placed) + [Section(".bss", ".bss.new", 0x300280C0, 4,
                                 "build/wt_sec_new_service.o")], (),
         "object has no owner entry: wt_sec_new_service.o"),
        ("unowned object without state", placed,
         (Path("build/wt_sec_new_service.o"),),
         "object has no owner entry: wt_sec_new_service.o"),
        ("state across a memory region edge",
         moved(".bss.g_guests", address=0x30088FFC, size=8), (),
         "writable section crosses a memory region"),
    )
    for label, layout, objects, expected in ownership_cases:
        regions, sections = parse_map(render_map(layout))
        errors = validate_ownership(good, regions, sections, owners, objects)
        if not any(expected in message for message in errors):
            print("self-test did not reject %s: %s" %
                  (label, ", ".join(errors)), file=sys.stderr)
            return False

    aarch_symbols = list(good) + parse_nm("\n".join((
        "40000000 ? __data_start",
        "40008000 ? __spm_ram_end",
        "40010000 ? _s_interface",
        "40011000 ? _e_interface",
        "40020000 ? _s_conf_data",
        "40021000 ? _e_conf_data",
    )))
    aarch_regions = [
        Region("RAM", 0x40000000, 0x8000, True),
        Region("INTERFACEDATA", 0x40010000, 0x1000, True),
        Region("CONFDATA", 0x40020000, 0x1000, True),
    ]
    aarch_sections = [
        Section(".data", ".data.spm", 0x40000000, 4,
                "build/sec_monitor.o"),
        Section(".interface_bss", ".bss.tpm", 0x40010000, 4,
                "build/wt_sec_tpm_local_provider.o"),
    ]
    aarch_owners_text = (SELF_TEST_OWNERS +
                         "wt_sec_tpm_local_provider.o tpm\n")
    aarch_owners, owner_errors = parse_owners(aarch_owners_text)
    errors = validate_ownership(
        aarch_symbols, aarch_regions, aarch_sections, aarch_owners,
        owner_regions=AARCH64_OWNER_REGIONS)
    if owner_errors or errors:
        print("self-test valid AArch64 ownership rejected: %s" %
              ", ".join(owner_errors + errors), file=sys.stderr)
        return False
    misplaced = [aarch_sections[0], Section(
        ".bss", ".bss.tpm", 0x40000004, 4,
        "build/wt_sec_tpm_local_provider.o")]
    errors = validate_ownership(
        aarch_symbols, aarch_regions, misplaced, aarch_owners,
        owner_regions=AARCH64_OWNER_REGIONS)
    if not any("tpm object places writable state outside its region" in error
               for error in errors):
        print("self-test accepted AArch64 TPM state in SPM RAM",
              file=sys.stderr)
        return False

    regions, sections = parse_map(render_map(placed))
    errors = validate_ownership(
        good, regions, sections, owners,
        [Path("build/conf_sec_test_i001.o")], production=True)
    if len([message for message in errors
            if "conformance object in a production image" in message]) != 4:
        print("self-test production image accepted conformance objects: %s"
              % ", ".join(errors), file=sys.stderr)
        return False
    errors = validate_ownership(good, [], sections, owners)
    if not any("names no writable memory region" in message
               for message in errors):
        print("self-test accepted a map without memory regions",
              file=sys.stderr)
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
                 map_text=render_map(placed), owners_text=SELF_TEST_OWNERS,
                 runner=completed(0, rendered(good)),
                 output=output, error=error) != 0:
        print("self-test valid CLI path failed", file=sys.stderr)
        return False

    error = io.StringIO()
    if (check_elf("fake-nm", Path("invalid.elf"),
                  map_text=render_map(
                      moved(".bss.g_guests", address=0x30028040)),
                  owners_text=SELF_TEST_OWNERS,
                  runner=completed(0, rendered(good)),
                  output=io.StringIO(), error=error) != 1 or
            "hsm object places writable state outside" not in
            error.getvalue()):
        print("self-test invalid CLI path did not fail", file=sys.stderr)
        return False

    error = io.StringIO()
    if (check_elf(
            "fake-nm", Path("empty-tpm.elf"),
            objects=[Path("build/wt_sec_tpm_relay_service.o")],
            runner=completed(0, rendered(empty_tpm)),
            output=io.StringIO(), error=error) != 1 or
            "required tpm band is empty" not in error.getvalue()):
        print("self-test required TPM object did not reject an empty band",
              file=sys.stderr)
        return False

    error = io.StringIO()
    if (check_elf("fake-nm", Path("invalid.elf"),
                  map_text=render_map(placed), owners_text="a.o nobody\n",
                  runner=completed(0, rendered(good)),
                  output=io.StringIO(), error=error) != 1 or
            "unknown owner" not in error.getvalue()):
        print("self-test bad owner map did not fail", file=sys.stderr)
        return False

    error = io.StringIO()
    if (check_elf("fake-nm", Path("missing.elf"),
                  runner=completed(7, stderr="nm failed\n"),
                  output=io.StringIO(), error=error) != 7 or
            error.getvalue() != "nm failed\n"):
        print("self-test nm failure was not propagated", file=sys.stderr)
        return False

    references = (
        "build/wt_sec_a.o:         U wc_Sha256Drbg_IsDisabled\n"
        "build/wc_sec_random.o:         U wc_InitRng\n"
    )
    error = io.StringIO()
    if check_objects("fake-nm", [Path("a.o")],
                     runner=completed(0, references), error=error) != 0:
        print("self-test clean object references rejected", file=sys.stderr)
        return False
    for setter in READONLY_SETTERS:
        error = io.StringIO()
        if (check_objects("fake-nm", [Path("a.o")],
                          runner=completed(
                              0, references +
                              "build/wt_sec_a.o:         U %s\n" % setter),
                          error=error) != 1 or
                "setter referenced" not in error.getvalue()):
            print("self-test did not reject a reference to %s" % setter,
                  file=sys.stderr)
            return False
    error = io.StringIO()
    if check_objects("fake-nm", [Path("a.o")],
                     runner=completed(
                         0, stderr="a.o: plugin needed to handle lto object\n"),
                     error=error) == 0:
        print("self-test LTO object without a plugin was accepted",
              file=sys.stderr)
        return False
    error = io.StringIO()
    if check_objects("fake-nm", [Path("a.o")],
                     runner=completed(3, stderr="nm failed\n"),
                     error=error) != 3:
        print("self-test object nm failure was not propagated",
              file=sys.stderr)
        return False

    lto_objects = [Path("build/wt_sec_vault_service.o"),
                   Path("build/wt_sec_ffm.o")]
    lto_owners = ("wt_sec_vault_service.o vault\n"
                  "wt_sec_ffm.o spm\n")
    for lto_paths, expected in ((("build/wt_sec_vault_service.o",), 1),
                                (("build/wt_sec_ffm.o",), 0)):
        status = check_lto_provenance(
            lto_objects, lto_owners, error=io.StringIO(),
            is_lto=lambda path, lto=lto_paths: str(path) in lto)
        if status != expected:
            print("self-test LTO provenance: %s gave %d, want %d" %
                  (lto_paths, status, expected), file=sys.stderr)
            return False

    print("WT-FFM-0010 PASS executable entry and zero-heap checks")
    print("WT-FFM-0011 PASS per-partition writable-state ownership checks")
    print("WT-FFM-CONF-001 PASS production image conformance exclusion checks")
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


def named_band(text):
    name, separator, rest = text.partition("=")
    if not separator or name not in BAND_NAMES:
        raise argparse.ArgumentTypeError(
            "expected NAME=ORIGIN:LIMIT with NAME in %s, got %r" %
            ("/".join(BAND_NAMES), text))
    low, high = band(rest)
    return name, low, high


def port_layout(bands, confdata, wolfhal, tpm_band=None, pkcs11_band=None):
    """Every port declares all three bands or none (the STM32H563 default)."""
    if bands and sorted(name for name, _, _ in bands) != sorted(BAND_NAMES):
        raise argparse.ArgumentTypeError(
            "--band must name each of %s exactly once" % "/".join(BAND_NAMES))
    ordered = tuple(sorted(bands, key=lambda b: BAND_NAMES.index(b[0]))) if bands else BANDS
    tpm_origin = tpm_band[0] if tpm_band else TPM_ORIGIN
    tpm_limit = tpm_band[1] if tpm_band else TPM_LIMIT
    pkcs11_origin = pkcs11_band[0] if pkcs11_band else PKCS11_ORIGIN
    pkcs11_limit = pkcs11_band[1] if pkcs11_band else PKCS11_LIMIT
    return Layout(bands=ordered, confdata_origin=confdata[0],
                  confdata_data_limit=confdata[1], tpm_origin=tpm_origin,
                  tpm_limit=tpm_limit, pkcs11_origin=pkcs11_origin,
                  pkcs11_limit=pkcs11_limit, wolfhal=wolfhal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", nargs="?", type=Path)
    parser.add_argument("--nm", default="arm-none-eabi-nm")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--objects-nm", default="arm-none-eabi-gcc-nm")
    parser.add_argument("--objects", nargs="*", type=Path, default=[])
    parser.add_argument("--map", type=Path)
    parser.add_argument("--owners", type=Path)
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--ownership-only", action="store_true",
                        help="check object ownership without Armv8-M symbols")
    parser.add_argument("--owner-profile", choices=OWNER_PROFILES,
                        default="armv8m",
                        help="linker bounds used for writable-state owners")
    parser.add_argument("--band", type=named_band, action="append", default=[],
                        metavar="NAME=ORIGIN:LIMIT")
    parser.add_argument("--confdata", type=band, metavar="ORIGIN:DATA_LIMIT",
                        default=(CONFDATA_ORIGIN, CONFDATA_DATA_LIMIT))
    parser.add_argument("--tpm-band", type=band, metavar="ORIGIN:LIMIT",
                        default=None, dest="tpm_band",
                        help="SERVICE_TPM mailbox band bounds for this port")
    parser.add_argument("--pkcs11-band", type=band, metavar="ORIGIN:LIMIT",
                        default=None, dest="pkcs11_band",
                        help="SERVICE_PKCS11 relay band bounds for this port")
    parser.add_argument("--no-wolfhal", action="store_true",
                        help="the port links no wolfHAL, so no g_whalTimeout")
    args = parser.parse_args()

    if args.self_test:
        return 0 if self_test() else 1
    if args.elf is None:
        parser.error("ELF is required unless --self-test is used")
    if args.map is None or args.owners is None:
        parser.error("--map and --owners are required to check an ELF")
    try:
        layout = port_layout(args.band, args.confdata, not args.no_wolfhal,
                             args.tpm_band, args.pkcs11_band)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    if args.objects:
        status = check_objects(args.objects_nm, args.objects)
        if status == 0:
            status = check_lto_provenance(
                args.objects, args.owners.read_text(encoding="utf-8"))
        if status != 0:
            return status
    return check_elf(
        args.nm, args.elf,
        map_text=args.map.read_text(encoding="utf-8", errors="replace"),
        owners_text=args.owners.read_text(encoding="utf-8"),
        objects=args.objects, production=args.production,
        layout=layout, ownership_only=args.ownership_only,
        owner_regions=OWNER_PROFILES[args.owner_profile])


if __name__ == "__main__":
    sys.exit(main())
