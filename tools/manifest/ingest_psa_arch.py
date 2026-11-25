#!/usr/bin/env python3
"""Ingest Arm PSA-FF partition manifests into wolfTrust manifest artifacts.

Reads the upstream psa-arch-tests `*_psa.json` partition manifests and either
emits the `psa_manifest/pid.h`, `sid.h`, and per-partition signal headers the
upstream `val`/PAL sources `#include`, or (with --base/--emit-overlay) turns
the Arm test partitions into the conformance overlay (manifest/conformance.json)
that tools/manifest/render.py applies to the shared template: every address
is a memory_map.h expression, so one overlay serves every port. Reuses the
production generator's header emitters so the output matches
wolftrust_manifest_generated.
"""
import argparse
import copy
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate  # noqa: E402  (reuse validated header emitters)

MODEL_IPC = 0
SIGNAL_FIRST = 0x10
SIGNAL_MAX = 0x80000000
FRAMEWORK_VERSION_1_0 = 0x0100

PRIORITY = {
    "LOW": 0,
    "NORMAL": 1,
    "HIGH": 2,
}

VERSION_POLICY = {
    "STRICT": 0,
    "RELAXED": 1,
}

# The conformance partitions take the code slots and stacks the shared level 3
# layout reserves for them (port/common/armv8m/l3_layout.h), by index.
SP_CODE_SIZE = "WT_SP_CODE_SLOT_SIZE"
SP_STACK_SIZE = "WT_SP_SECURE_STACK_SIZE"
# The fixed slot in l3_layout.h. The ingest test checks it against the layout.
SP_STACK_CAPACITY = 0x2000
CONFORMANCE_SLOTS = (
    ("WT_SP_CODE_BASE + 2 * WT_SP_CODE_SLOT_SIZE", "WT_SP_FF_SERVER_STACK_BASE"),
    ("WT_SP_CODE_BASE + 3 * WT_SP_CODE_SLOT_SIZE", "WT_SP_FF_DRIVER_STACK_BASE"),
    ("WT_SP_CODE_BASE + 4 * WT_SP_CODE_SLOT_SIZE", "WT_SP_FF_CLIENT_STACK_BASE"),
)
MEM_ATTR_CODE = 5     # READ | EXEC
MEM_ATTR_STACK = 19   # READ | WRITE | RESTART_CLEAR
DOMAIN_CLASS_SP = 1
ROT_ROLE = {
    "PSA-ROT": 2,
    "APPLICATION-ROT": 3,
}
SP_REQUIRED_CAPS = 80
SP_RESTART_POLICY = {
    "action": 1,
    "restart_limit": 3,
    "restart_window_ticks": 8000,
    "initial_delay_ticks": 1,
}

# The upstream FF-test manifest names an IRQ only by a symbolic source; the
# port's layout configuration decides the NVIC line (WT_CONF_IRQ), so the
# overlay carries the macro and stays reproducible from upstream.
PLATFORM_IRQ_LINES = {
    "FF_TEST_UART_IRQ": "WT_CONF_IRQ",
}


class IngestError(Exception):
    pass


def parse_sid(value):
    try:
        return int(str(value), 0)
    except ValueError:
        raise IngestError("service sid is not an integer: {}".format(value))


def next_signal(bit):
    if bit >= SIGNAL_MAX:
        raise IngestError("partition exhausts the 31-bit signal space")
    return bit << 1


def normalize_partition(source, domain_id):
    if "name" not in source or "services" not in source:
        raise IngestError("manifest missing name or services")
    if "heap_size" in source:
        raise IngestError("partition {} requests heap_size, but private heaps "
                          "are unsupported".format(source["name"]))
    framework = source.get("psa_framework_version")
    if type(framework) not in (int, float) or framework != 1.0:
        raise IngestError("psa_framework_version must be 1.0")
    priority = source.get("priority")
    if not isinstance(priority, str) or priority not in PRIORITY:
        raise IngestError("priority must be LOW, NORMAL, or HIGH")
    stack_size = source.get("stack_size")
    if isinstance(stack_size, str) and re.fullmatch(r"0[xX][0-9a-fA-F]+",
                                                   stack_size):
        stack_size = int(stack_size, 16)
    if type(stack_size) is not int or not 0 < stack_size <= SP_STACK_CAPACITY:
        raise IngestError("stack_size must be a positive integer or "
                          "hexadecimal string up to {:#x}".format(
                              SP_STACK_CAPACITY))

    services = []
    signal = SIGNAL_FIRST
    for entry in source["services"]:
        if "name" not in entry or "sid" not in entry:
            raise IngestError("service missing name or sid")
        policy = entry.get("version_policy", "STRICT")
        if policy not in VERSION_POLICY:
            raise IngestError("unknown version_policy: {}".format(policy))
        services.append({
            "name": entry["name"],
            "sid": parse_sid(entry["sid"]),
            "version": int(entry.get("version", 1)),
            "version_policy": VERSION_POLICY[policy],
            "non_secure_clients": bool(entry.get("non_secure_clients", False)),
            "signal": signal,
        })
        signal = next_signal(signal)

    interrupts = []
    for entry in source.get("irqs", []):
        if "signal" not in entry:
            raise IngestError("irq missing signal name")
        line = PLATFORM_IRQ_LINES.get(entry.get("source"))
        if line is None:
            raise IngestError("no platform IRQ line for source: {}".format(
                entry.get("source")))
        interrupts.append({
            "signal_name": entry["signal"],
            "interrupt": line,
            "signal": signal,
        })
        signal = next_signal(signal)

    return {
        "name": source["name"],
        "domain_id": domain_id,
        "framework_version": FRAMEWORK_VERSION_1_0,
        "model": MODEL_IPC,
        "priority": PRIORITY[priority],
        "services": services,
        "interrupts": interrupts,
    }


def ingest(paths, pid_base):
    partitions = []
    domain_id = pid_base
    for path in paths:
        source = json.loads(Path(path).read_text(encoding="utf-8"))
        partitions.append(normalize_partition(source, domain_id))
        domain_id += 1
    return {"partitions": partitions}


def partition_rot_role(source):
    partition_type = source.get("type")
    role = None
    if isinstance(partition_type, str):
        role = ROT_ROLE.get(partition_type)
    if role is None:
        raise IngestError("unknown partition type: {!r}".format(partition_type))
    return role


def sp_domain(domain_id, index, rot_role):
    if index >= len(CONFORMANCE_SLOTS):
        raise IngestError("the level 3 layout reserves {} conformance "
                          "partition slots".format(len(CONFORMANCE_SLOTS)))
    code, stack = CONFORMANCE_SLOTS[index]
    return {
        "id": domain_id,
        "domain_class": DOMAIN_CLASS_SP,
        "rot_role": rot_role,
        "security_state": 0,
        "privilege_state": 1,
        "initial_lifecycle": 0,
        "entry_point": code,
        "stack_base": stack,
        "stack_size": SP_STACK_SIZE,
        "memory_resources": [
            {"base": code, "size": SP_CODE_SIZE,
             "attributes": MEM_ATTR_CODE, "share_id": 0},
            {"base": stack, "size": SP_STACK_SIZE,
             "attributes": MEM_ATTR_STACK, "share_id": 0},
        ],
        "interrupt_resources": [],
        "restart_policy": copy.deepcopy(SP_RESTART_POLICY),
        "required_capabilities": SP_REQUIRED_CAPS,
        "launch_required": 0,
        "launch_min_version": 0,
    }


def full_service(entry):
    return {
        "name": entry["name"],
        "sid": entry["sid"],
        "version": entry["version"],
        "version_policy": entry["version_policy"],
        "signal": entry["signal"],
        "stateless_handle_index": 0,
        "nonsecure_clients": entry["non_secure_clients"],
        "connection_based": True,
    }


# Production-only Secure Partitions the Arm FF-M conformance image does not
# exercise. SERVICE_FWU stages the wolfBoot update partition and has no place
# in the conformance suite, so it is dropped here to keep the conformance
# domain layout independent of production-only services.
CONFORMANCE_EXCLUDE = {"PARTITION_FWU"}


def emit_overlay(base_path, arm_paths):
    """The conformance overlay: drop the production-only partitions, then add
    the Arm partitions in the domain ids the drop frees."""
    manifest = json.loads(Path(base_path).read_text(encoding="utf-8"))
    excluded_domain_ids = {
        part["domain_id"] for part in manifest["partitions"]
        if part["name"] in CONFORMANCE_EXCLUDE}
    kept = [domain["id"] for domain in manifest["domains"]
            if domain["id"] not in excluded_domain_ids]
    next_id = max(kept) + 1

    sid_by_name = {}
    normalized = []
    for index, path in enumerate(arm_paths):
        source = json.loads(Path(path).read_text(encoding="utf-8"))
        part = normalize_partition(source, next_id + index)
        part["_source"] = source
        normalized.append(part)
        for service in part["services"]:
            sid_by_name[service["name"]] = service["sid"]

    overlay = {"drop_partitions": sorted(CONFORMANCE_EXCLUDE),
               "domains": [], "partitions": []}
    for index, part in enumerate(normalized):
        domain_id = next_id + index
        domain = sp_domain(domain_id, index,
                           partition_rot_role(part["_source"]))
        domain["interrupt_resources"] = [
            {"interrupt": irq["interrupt"], "attributes": 0, "share_id": 0}
            for irq in part["interrupts"]
        ]
        overlay["domains"].append(domain)
        dependencies = []
        for name in part["_source"].get("dependencies", []):
            if name not in sid_by_name:
                raise IngestError("unresolved dependency: {}".format(name))
            dependencies.append(sid_by_name[name])
        overlay["partitions"].append({
            "name": part["name"],
            "domain_id": domain_id,
            "framework_version": part["framework_version"],
            "model": MODEL_IPC,
            "priority": part["priority"],
            "services": [full_service(s) for s in part["services"]],
            "dependencies": dependencies,
            "interrupts": part["interrupts"],
        })
    return overlay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pid-base", type=lambda value: int(value, 0),
                        default=1)
    parser.add_argument("--base", type=Path,
                        help="the shared template, manifest/base.json")
    parser.add_argument("--emit-overlay", type=Path,
                        help="write the conformance overlay for the template")
    args = parser.parse_args()

    if args.output is None and args.emit_overlay is None:
        print("nothing to do: pass --output and/or --emit-overlay",
              file=sys.stderr)
        return 2
    if args.emit_overlay is not None and args.base is None:
        print("--emit-overlay requires --base", file=sys.stderr)
        return 2

    try:
        if args.output is not None:
            manifest = ingest(args.manifests, args.pid_base)
            psa_manifest = args.output / "psa_manifest"
            psa_manifest.mkdir(parents=True, exist_ok=True)
            (psa_manifest / "pid.h").write_text(
                generate.generate_pid_header(manifest), encoding="utf-8")
            (psa_manifest / "sid.h").write_text(
                generate.generate_sid_header(manifest), encoding="utf-8")
            for partition in manifest["partitions"]:
                file_name, content = generate.generate_partition_header(
                    partition)
                (psa_manifest / file_name).write_text(content, encoding="utf-8")
        if args.emit_overlay is not None:
            overlay = emit_overlay(args.base, args.manifests)
            args.emit_overlay.write_text(
                json.dumps(overlay, indent=2) + "\n", encoding="utf-8")
    except (IngestError, OSError, json.JSONDecodeError) as error:
        print("manifest ingestion failed: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
