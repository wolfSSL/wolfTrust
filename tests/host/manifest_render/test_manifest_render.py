#!/usr/bin/env python3
"""Generated manifests (WT-FFM-0010/0011, WT-PORT layout): the shared template
rendered under each port's layout configuration is the manifest the secure
build compiles.

For every registered port and each variant it registers: the rendered
manifest is pinned by SHA-256 (a layout or template change is a reviewed
change), the generator accepts it, every window in
it equals the port's memory_map.h (the guests' flash, RAM and console, the
SPM stack, the partition stacks and keystore bands, the conformance IRQ),
no two partitions share a writable byte and none reaches SPM RAM, and a
changed layout input moves exactly the windows that depend on it."""

import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "../../..").resolve()
CC = os.environ.get("CC", "cc")
RENDER = ROOT / "tools" / "manifest" / "render.py"
GENERATE = ROOT / "tools" / "manifest" / "generate.py"
TEMPLATE = ROOT / "manifest" / "base.json"
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b")

# The STM32H563 emulator layout (tests/target/ports/stm32h563/m33mu.sh), under
# which the H5 manifests were committed with the guests relocated behind
# wolfBoot; the Secure image itself now renders at its real link base too.
H5_RUNNER = ("WT_SECURE_FLASH_BASE=0x0C060000", "WT_SECURE_FLASH_SIZE=0x00040000",
             "WT_SECURE_IMAGE_HEADER_SIZE=0x400", "WT_GUEST0_FLASH_BASE=0x080A0000",
             "WT_GUEST1_FLASH_BASE=0x080E0000", "WT_GUEST0_FLASH_SIZE=0x00040000")
H5_COMMITTED = ("WT_GUEST0_FLASH_BASE=0x080A0000", "WT_GUEST1_FLASH_BASE=0x080E0000",
                "WT_GUEST0_FLASH_SIZE=0x00040000")
# SHA-256 of each port's rendered manifest under the shared level 3 layout,
# pinned so a layout or template change is a reviewed change.
COMMITTED = {
    ("mimxrt700", "base", ()):
        "a29087bd0d88b219b57d242aba5118e60aa84d347cf995ad18eb02a686c890d6",
    ("mimxrt700", "conformance", ()):
        "47aa6cf705f92301aeb94d1c59aa15502e31c3246aef921fadaf2d65ba5b9c96",
    ("mcxn947", "base", ()):
        "058de906b0d66891eaa81911626acced63b69c8e07e6108170ec08f4a1fbdce4",
    ("mcxn947", "conformance", ()):
        "6c31e082b00cf5a659dd60ecb4e28d30e7f059867470e70e6cd8aa1892729fa8",
    ("stm32h563", "base", H5_COMMITTED):
        "ba52a4776e93a42e59f927485cbda8dfd8f7b0359e113e52f74eb93c496c210f",
    ("stm32h563", "conformance", H5_COMMITTED):
        "1ace9388c4c4d26ca254719fb873cbe393b59938c32803e6d4357114c8168f84",
    ("stm32h563", "vnet", H5_COMMITTED):
        "f3c6c1b87037517c71834c2c3dacacb3a9fa5fe699d5555406be0e079abee397",
}
WINDOW_MACROS = (
    "WT_SECURE_FLASH_BASE", "WT_RAM_S_BASE", "WT_SP_CODE_BASE",
    "WT_SP_CODE_SLOT_SIZE", "WT_CONF_IRQ",
    "WT_GUEST0_FLASH_BASE", "WT_GUEST0_FLASH_SIZE", "WT_GUEST0_RAM_BASE",
    "WT_GUEST0_RAM_SIZE", "WT_GUEST1_FLASH_BASE", "WT_GUEST1_FLASH_SIZE",
    "WT_GUEST1_RAM_BASE", "WT_GUEST1_RAM_SIZE", "WT_GUEST0_CONSOLE_BASE",
    "WT_GUEST1_CONSOLE_BASE", "WT_GUEST_CONSOLE_SIZE",
    "WT_SP_ATTEST_STACK_BASE", "WT_SP_CRYPTO_STACK_BASE",
    "WT_SP_VAULT_STACK_BASE", "WT_SP_VAULT_STACK_SIZE", "WT_SP_ITS_STACK_BASE",
    "WT_SP_PS_STACK_BASE", "WT_SP_FWU_STACK_BASE", "WT_SP_SECURE_STACK_SIZE",
    "WT_SP_ATTEST_STACK_SIZE", "WT_SP_CRYPTO_STACK_SIZE", "WT_SP_ITS_STACK_SIZE",
    "WT_SP_PS_STACK_SIZE", "WT_SP_FWU_STACK_SIZE",
    "WT_SP_FF_SERVER_STACK_BASE", "WT_SP_FF_DRIVER_STACK_BASE",
    "WT_SP_FF_CLIENT_STACK_BASE", "WT_SP_VNET_STACK_BASE", "WT_SP_VNET_STACK_SIZE",
    "WT_SP_VAULT_DATA_BASE", "WT_SP_VAULT_DATA_SIZE", "WT_SP_ATTEST_DATA_BASE",
    "WT_SP_ATTEST_DATA_SIZE", "WT_SP_HSM_DATA_BASE", "WT_SP_HSM_DATA_SIZE",
    "WT_VNET_DATA_BASE", "WT_VNET_DATA_SIZE", "WT_CONF_SP_DATA_BASE",
    "WT_CONF_SP_DATA_SIZE", "WT_L3_BANDS_BASE",
    "WT_SP_INTERFACE_STACK_BASE", "WT_SP_INTERFACE_STACK_SIZE",
    "WT_INTERFACE_DATA_BASE", "WT_INTERFACE_DATA_SIZE",
)
STACKS = {
    "PARTITION_ATTEST": ("WT_SP_ATTEST_STACK_BASE", "WT_SP_ATTEST_STACK_SIZE"),
    "PARTITION_HSM": ("WT_SP_CRYPTO_STACK_BASE", "WT_SP_CRYPTO_STACK_SIZE"),
    "PARTITION_VAULT": ("WT_SP_VAULT_STACK_BASE", "WT_SP_VAULT_STACK_SIZE"),
    "PARTITION_ITS": ("WT_SP_ITS_STACK_BASE", "WT_SP_ITS_STACK_SIZE"),
    "PARTITION_PS": ("WT_SP_PS_STACK_BASE", "WT_SP_PS_STACK_SIZE"),
    "PARTITION_FWU": ("WT_SP_FWU_STACK_BASE", "WT_SP_FWU_STACK_SIZE"),
    "PARTITION_VNET": ("WT_SP_VNET_STACK_BASE", "WT_SP_VNET_STACK_SIZE"),
    "PARTITION_TPM": ("WT_SP_INTERFACE_STACK_BASE", "WT_SP_INTERFACE_STACK_SIZE"),
    "PARTITION_PKCS11": ("WT_SP_INTERFACE_STACK_BASE", "WT_SP_INTERFACE_STACK_SIZE"),
    "SERVER_PARTITION": ("WT_SP_FF_SERVER_STACK_BASE", "WT_SP_SECURE_STACK_SIZE"),
    "DRIVER_PARTITION": ("WT_SP_FF_DRIVER_STACK_BASE", "WT_SP_SECURE_STACK_SIZE"),
    "CLIENT_PARTITION": ("WT_SP_FF_CLIENT_STACK_BASE", "WT_SP_SECURE_STACK_SIZE"),
}
BANDS = {
    "PARTITION_ATTEST": ("WT_SP_ATTEST_DATA_BASE", "WT_SP_ATTEST_DATA_SIZE"),
    "PARTITION_HSM": ("WT_SP_HSM_DATA_BASE", "WT_SP_HSM_DATA_SIZE"),
    "PARTITION_VAULT": ("WT_SP_VAULT_DATA_BASE", "WT_SP_VAULT_DATA_SIZE"),
    "PARTITION_VNET": ("WT_VNET_DATA_BASE", "WT_VNET_DATA_SIZE"),
    "PARTITION_TPM": ("WT_INTERFACE_DATA_BASE", "WT_INTERFACE_DATA_SIZE"),
    "PARTITION_PKCS11": ("WT_INTERFACE_DATA_BASE", "WT_INTERFACE_DATA_SIZE"),
}
SLOTS = {"PARTITION_ATTEST": 0, "PARTITION_HSM": 1, "SERVER_PARTITION": 2,
         "DRIVER_PARTITION": 3, "CLIENT_PARTITION": 4, "PARTITION_VAULT": 5,
         "PARTITION_ITS": 6, "PARTITION_PS": 7, "PARTITION_FWU": 8,
         "PARTITION_VNET": 9, "PARTITION_TPM": 9, "PARTITION_PKCS11": 9}
WRITABLE = 0x02
checks = 0


def fail(message):
    raise SystemExit("FAIL: manifest_render: " + message)


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        fail(message)


ENV = {name: value for name, value in os.environ.items()
       if name not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "BUILD_DIR")}


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, env=ENV,
                          **kwargs)


def registry(target):
    result = run([sys.executable, str(ROOT / "tests/target/lib/scenario_matrix.py"),
                  "--port", target, "--get", "build.variants"])
    check(result.returncode == 0, "%s: no build.variants in port.json" % target)
    return ["base"] + result.stdout.split()


def cflags(target, *settings):
    result = run(["make", "-s", "--no-print-directory", "-C", str(ROOT),
                  "TARGET=" + target, "WT_LAYOUT_CPP=" + CC, *settings,
                  "print-layout-cflags"])
    check(result.returncode == 0, "%s: print-layout-cflags failed: %s" %
          (target, result.stderr.strip()))
    return result.stdout.strip()


def layout(flags):
    probe = '#include "memory_map.h"\n'
    probe += "".join("%d=%s\n" % pair for pair in enumerate(WINDOW_MACROS))
    result = run([CC, "-E", "-P", "-x", "c", *shlex.split(flags), "-"],
                 input=probe)
    check(result.returncode == 0, "preprocessing memory_map.h failed: %s" %
          result.stderr.strip())
    values = {}
    for line in result.stdout.splitlines():
        index, separator, text = line.partition("=")
        if separator and index.isdigit() and int(index) < len(WINDOW_MACROS):
            values[WINDOW_MACROS[int(index)]] = eval(
                INTEGER.sub(r"\1", text), {"__builtins__": {}})
    missing = [name for name in WINDOW_MACROS if name not in values]
    check(not missing, "memory_map.h defines no " + ", ".join(missing))
    return values


# The build mode a variant renders under: the layout reserves the update
# stack, the conformance window and the VNET band only in the modes that use
# them, and the base template carries the update partition.
MODE = {"base": ("WT_FWU=1",), "conformance": ("WT_CONFORMANCE=1",),
        "vnet": ("CONFIG_VNET=y", "WT_MAX_GUESTS=2", "WT_FWU=1"),
        "tpm": ("CONFIG_TPM=y", "WT_FWU=1"),
        "pkcs11": ("CONFIG_PKCS11=y", "WT_FWU=1")}


def render(flags, variant):
    command = [sys.executable, str(RENDER), "--cc", CC, "--cflags", flags]
    if variant != "base":
        command += ["--overlay", str(ROOT / "manifest" / (variant + ".json"))]
    result = run(command + [str(TEMPLATE)])
    check(result.returncode == 0, "render %s failed: %s" %
          (variant, result.stderr.strip()))
    return result.stdout


def mode(target, variant):
    """A variant a port limits to the default profile builds without FWU."""
    result = run([sys.executable, str(ROOT / "tests/target/lib/scenario_matrix.py"),
                  "--port", target, "--get", "build.variant_profiles." + variant])
    if result.returncode == 0 and "full" not in result.stdout.split():
        return tuple(f for f in MODE[variant] if f != "WT_FWU=1"), True
    return MODE[variant], False


def generator_accepts(text, label, no_fwu=False):
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "manifest.json"
        source.write_text(text, encoding="utf-8")
        result = run([sys.executable, str(GENERATE), str(source),
                      str(Path(directory) / "out"), "--supported-features",
                      "0x1", "--supported-framework-version", "0x100",
                      "--address-bits", "32", "--unchecked"] +
                     (["--exclude-partition", "PARTITION_FWU"] if no_fwu else []))
        check(result.returncode == 0, "%s: the generator rejects the rendered "
              "manifest: %s" % (label, result.stderr.strip()))


def windows(manifest, values, label, variant):
    domains = {domain["id"]: domain for domain in manifest["domains"]}
    spm = domains[0]
    check(spm["entry_point"] == values["WT_SECURE_FLASH_BASE"] and
          spm["stack_base"] == values["WT_RAM_S_BASE"],
          "%s: the SPM domain is not at the Secure image and SPM RAM" % label)
    for index in (0, 1):
        guest = domains[1 + index]
        mems = {(m["base"], m["size"]) for m in guest["memory_resources"]}
        want = {(values["WT_GUEST%d_FLASH_BASE" % index],
                 values["WT_GUEST%d_FLASH_SIZE" % index]),
                (values["WT_GUEST%d_RAM_BASE" % index],
                 values["WT_GUEST%d_RAM_SIZE" % index]),
                (values["WT_GUEST%d_CONSOLE_BASE" % index],
                 values["WT_GUEST_CONSOLE_SIZE"])}
        check(mems == want and guest["entry_point"] ==
              values["WT_GUEST%d_FLASH_BASE" % index],
              "%s: guest %d windows %s, memory_map.h %s" %
              (label, index, sorted(mems), sorted(want)))
    # SPM RAM ends at the lowest partition band: the VNET band, then the
    # crypto partition's stack and data band below the keystore.
    spm_end = values["WT_L3_BANDS_BASE"]
    writable = []
    for part in manifest["partitions"]:
        domain = domains[part["domain_id"]]
        name = part["name"]
        stack_base, stack_size = STACKS[name]
        check(domain["stack_base"] == values[stack_base] and
              domain["stack_size"] == values[stack_size],
              "%s: %s stack is not %s" % (label, name, stack_base))
        slot = values["WT_SP_CODE_BASE"] + SLOTS[name] * values["WT_SP_CODE_SLOT_SIZE"]
        check(domain["entry_point"] == slot,
              "%s: %s code slot %#x, want %#x" %
              (label, name, domain["entry_point"], slot))
        mems = {(m["base"], m["size"]) for m in domain["memory_resources"]
                if m["attributes"] & WRITABLE}
        want = {(values[stack_base], values[stack_size])}
        if name in BANDS:
            want.add((values[BANDS[name][0]], values[BANDS[name][1]]))
        check(mems == want, "%s: %s writable windows %s, want %s" %
              (label, name, sorted(mems), sorted(want)))
        for base, size in mems:
            check(base >= spm_end, "%s: %s reaches SPM RAM" % (label, name))
            for other, obase, osize in writable:
                check(base + size <= obase or obase + osize <= base,
                      "%s: %s and %s share a writable byte" % (label, name, other))
            writable.append((name, base, size))
        for irq in domain["interrupt_resources"]:
            check(irq["interrupt"] == values["WT_CONF_IRQ"],
                  "%s: %s interrupt %d is not WT_CONF_IRQ" %
                  (label, name, irq["interrupt"]))
        for irq in part["interrupts"]:
            check(irq["interrupt"] == values["WT_CONF_IRQ"],
                  "%s: %s signal interrupt is not WT_CONF_IRQ" % (label, name))
    names = {part["name"] for part in manifest["partitions"]}
    expect = {"PARTITION_ATTEST", "PARTITION_HSM", "PARTITION_VAULT",
              "PARTITION_ITS", "PARTITION_PS"}
    if variant == "conformance":
        expect |= {"SERVER_PARTITION", "DRIVER_PARTITION", "CLIENT_PARTITION"}
    else:
        expect.add("PARTITION_FWU")
    if variant in ("vnet", "tpm", "pkcs11"):
        expect.add("PARTITION_" + variant.upper())
    check(names == expect, "%s: partitions %s, want %s" %
          (label, sorted(names), sorted(expect)))
    caps = manifest["profile_capabilities"]
    check(caps["max_domains"] == len(manifest["domains"]) and
          manifest["limits"]["max_partitions"] == len(manifest["partitions"]),
          "%s: the counters do not match the content" % label)


# The AArch64 ports render the same interface overlays onto their literal port
# manifest (render.py --arch aarch64): one S-EL0 domain and its FF-A partition.
AARCH64_PORTS = ("qemuvirt", "versal")
AARCH64_UUIDS = {"tpm": "14a60fe3-05ca-583d-a88a-1e9d0a47d74d",
                 "pkcs11": "ab4f39e1-d12d-5b91-a21c-57d66f7f04ae"}
L3_LAYOUT = ROOT / "tools" / "aarch64_l3_layout.py"


def aarch64_layout(target, mode):
    result = run([sys.executable, str(L3_LAYOUT), "--cc", CC, "-I",
                  str(ROOT / "port" / "common" / "aarch64"), "-D",
                  "WT_ISOLATION_LEVEL=3", "--" + mode,
                  str(ROOT / "port" / target / "memory_map.h")])
    check(result.returncode == 0, "%s: aarch64_l3_layout --%s failed: %s" %
          (target, mode, result.stderr.strip()))
    return result.stdout


def aarch64_render(target, overlay, template=None):
    flags = "-I%s -I%s %s" % (ROOT / "include", ROOT / "port" / target,
                              aarch64_layout(target, "cflags").strip())
    return run([sys.executable, str(RENDER), "--arch", "aarch64", "--cc", CC,
                "--cflags", flags, "--overlay", str(overlay),
                str(template or ROOT / "port" / target / "manifest.json")])


def aarch64_check_manifest(target, text):
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "manifest.json"
        source.write_text(text, encoding="utf-8")
        return run([sys.executable, str(L3_LAYOUT), "--cc", CC, "-I",
                    str(ROOT / "port" / "common" / "aarch64"), "-D",
                    "WT_ISOLATION_LEVEL=3", "--check-manifest", str(source),
                    str(ROOT / "port" / target / "memory_map.h")])


def aarch64_checks():
    for target in AARCH64_PORTS:
        values = {}
        for line in aarch64_layout(target, "shell").splitlines():
            name, separator, text = line.partition("=")
            if separator:
                values[name] = int(text, 0)
        literal = json.loads((ROOT / "port" / target / "manifest.json").read_text())
        for variant, uuid in AARCH64_UUIDS.items():
            label = "%s/%s" % (target, variant)
            result = aarch64_render(target, ROOT / "manifest" / (variant + ".json"))
            check(result.returncode == 0, "%s: render failed: %s" %
                  (label, result.stderr.strip()))
            manifest = json.loads(result.stdout)
            name = "PARTITION_" + variant.upper()
            added = [d for d in manifest["domains"]
                     if d not in literal["domains"]]
            check(manifest["domains"][:len(literal["domains"])] ==
                  literal["domains"] and len(added) == 1,
                  "%s: the port's own domains changed" % label)
            resources = [(r["base"], r["size"], r["attributes"])
                         for r in added[0]["memory_resources"]]
            want = [(values["WT_SPM_IMAGE_PA"], values["WT_SPM_IMAGE_SIZE"], 37),
                    (values["WT_SP_INTERFACE_STACK_BASE"],
                     values["WT_SP_INTERFACE_STACK_SIZE"], 19),
                    (values["WT_INTERFACE_DATA_BASE"],
                     values["WT_INTERFACE_DATA_SIZE"], 19)]
            check(resources == want, "%s: domain resources %s, want %s" %
                  (label, resources, want))
            check(added[0]["entry_point"] == values["WT_SPM_IMAGE_PA"],
                  "%s: the partition does not enter at the SPMC image" % label)
            parts = [p["name"] for p in manifest["partitions"]]
            check(parts == [p["name"] for p in literal["partitions"]] + [name],
                  "%s: partitions %s" % (label, parts))
            ffa = manifest["ffa"]["partitions"]
            check(ffa[:-1] == literal["ffa"]["partitions"] and
                  ffa[-1]["uuids"] == [uuid] and
                  ffa[-1]["domain_id"] == added[0]["id"] and
                  ffa[-1]["runtime_el"] == "S-EL0",
                  "%s: FF-A partition %s" % (label, ffa[-1]))
            check(manifest["profile_capabilities"]["max_domains"] ==
                  len(manifest["domains"]) and
                  manifest["limits"]["max_partitions"] ==
                  len(manifest["partitions"]),
                  "%s: the counters do not match the content" % label)
            ok = aarch64_check_manifest(target, result.stdout)
            check(ok.returncode == 0, "%s: --check-manifest rejects it: %s" %
                  (label, (ok.stdout + ok.stderr).strip()))
            # A second domain granted the interface band is refused.
            shared = json.loads(result.stdout)
            shared["domains"][1]["memory_resources"].append(
                dict(added[0]["memory_resources"][2]))
            bad = aarch64_check_manifest(target, json.dumps(shared))
            check(bad.returncode != 0, "%s: a shared interface band passed "
                  "--check-manifest" % label)
            # Without the overlay, a stray interface grant is refused too.
            stray = copy.deepcopy(literal)
            stray["domains"][1]["memory_resources"].append(
                dict(added[0]["memory_resources"][2]))
            bad = aarch64_check_manifest(target, json.dumps(stray))
            check(bad.returncode != 0, "%s: an interface band with no "
                  "interface partition passed --check-manifest" % label)
        with tempfile.TemporaryDirectory() as directory:
            plain = Path(directory) / "plain.json"
            overlay = json.loads((ROOT / "manifest" / "tpm.json").read_text())
            overlay.pop("aarch64")
            plain.write_text(json.dumps(overlay), encoding="utf-8")
            result = aarch64_render(target, plain)
            check(result.returncode != 0 and "no aarch64 block" in result.stderr,
                  "%s: an overlay without an aarch64 block rendered" % target)
            overlay = json.loads((ROOT / "manifest" / "tpm.json").read_text())
            overlay["aarch64"]["domains"] = overlay["domains"]
            plain.write_text(json.dumps(overlay), encoding="utf-8")
            result = aarch64_render(target, plain)
            check(result.returncode != 0 and "unknown key" in result.stderr,
                  "%s: an aarch64 block replacing the domains rendered" % target)
        result = aarch64_render(target, ROOT / "manifest" / "tpm.json", TEMPLATE)
        check(result.returncode != 0 and "no ffa section" in result.stderr,
              "%s: --arch aarch64 rendered onto a template without ffa" % target)


def main():
    ports = sorted(path.parent.name
                   for path in (ROOT / "port").glob("*/port.json"))
    check(len(ports) >= 1, "no registered port")
    seen = set()
    for target in ports:
        variants = registry(target)
        for variant in variants:
            settings, no_fwu = mode(target, variant)
            flags = cflags(target, *settings)
            text = render(flags, variant)
            label = "%s/%s" % (target, variant)
            generator_accepts(text, label, no_fwu)
            windows(json.loads(text), layout(flags), label, variant)
            for key, digest in COMMITTED.items():
                port, committed_variant, settings = key
                if (port, committed_variant) != (target, variant):
                    continue
                pinned = render(cflags(target, *(settings + mode(target, variant)[0])),
                                variant)
                check(hashlib.sha256(pinned.encode()).hexdigest() == digest,
                      "%s: rendered under %s differs from the committed "
                      "manifest" % (label, " ".join(settings) or "the defaults"))
                seen.add(key)
        # Each guest's console follows the console selection, as the bind check does.
        for uart in range(4):
            flags = cflags(target, "WT_SHARED_UART=%d" % uart, *MODE["base"])
            windows(json.loads(render(flags, "base")), layout(flags),
                    "%s/WT_SHARED_UART=%d" % (target, uart), "base")
        # A moved guest window moves only the guest's windows.
        values = layout(cflags(target))
        moved = "WT_GUEST1_FLASH_SIZE=%#x" % (values["WT_GUEST1_FLASH_SIZE"] // 2)
        before = json.loads(render(cflags(target, *MODE["base"]), "base"))
        after = json.loads(render(cflags(target, moved, *MODE["base"]), "base"))
        check(before != after and
              after["domains"][2]["memory_resources"][0]["size"] ==
              values["WT_GUEST1_FLASH_SIZE"] // 2 and
              before["domains"][1] == after["domains"][1] and
              before["domains"][3:] == after["domains"][3:],
              "%s: %s did not move exactly guest 1's window" % (target, moved))
        if "conformance" in variants:
            irq = "WT_CONF_IRQ=%d" % (values["WT_CONF_IRQ"] + 1)
            conf = json.loads(render(cflags(target, irq, *MODE["conformance"]),
                                     "conformance"))
            driver = [d for d in conf["domains"] if d["interrupt_resources"]]
            check(len(driver) == 1 and
                  driver[0]["interrupt_resources"][0]["interrupt"] ==
                  values["WT_CONF_IRQ"] + 1,
                  "%s: %s did not reach the conformance driver" % (target, irq))
    aarch64_checks()
    missing = set(COMMITTED) - seen
    check(not missing, "committed manifests not reproduced: %s" %
          sorted("%s/%s" % key[:2] for key in missing))
    print("PASS: manifest render (%d ports, %d checks)" % (len(ports), checks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
