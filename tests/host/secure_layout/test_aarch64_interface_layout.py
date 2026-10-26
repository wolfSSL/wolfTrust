#!/usr/bin/env python3
"""Reject invalid AArch64 interface bands and manifest grants."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "tools/aarch64_l3_layout.py"
HEADER = ROOT / "port/qemuvirt/memory_map.h"
INCLUDE = ROOT / "port/common/aarch64"


def load_layout_tool():
    spec = importlib.util.spec_from_file_location("aarch64_l3_layout", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_manifest(layout, manifest, values):
    path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as handle:
            json.dump(manifest, handle)
            path = handle.name
        layout.check_manifest(path, values)
    finally:
        if path is not None:
            os.unlink(path)


def require_manifest_rejected(layout, name, manifest, values):
    try:
        check_manifest(layout, manifest, values)
    except SystemExit as error:
        if "interface band" not in str(error):
            raise SystemExit("FAIL: %s failed for the wrong reason: %s" %
                             (name, error))
        return
    raise SystemExit("FAIL: interface %s grant was accepted" % name)


def require_rejected(name, address, size="0x1000u"):
    command = [
        sys.executable,
        str(TOOL),
        "--cc",
        os.environ.get("CC", "cc"),
        "-I",
        str(INCLUDE),
        "-D",
        "WT_ISOLATION_LEVEL=3",
        "-D",
        "WT_SPM_TABLE_POOL_PAGES=128u",
        "-D",
        "WT_SPM_INTERFACE_PA=%s" % address,
        "-D",
        "WT_SPM_INTERFACE_SIZE=%s" % size,
        "--shell",
        str(HEADER),
    ]
    result = subprocess.run(command, capture_output=True, text=True,
                            check=False)
    if result.returncode == 0:
        raise SystemExit("FAIL: interface overlap with %s was accepted" % name)
    if "application-interface band overlaps" not in result.stderr:
        raise SystemExit("FAIL: %s collision failed for the wrong reason: %s" %
                         (name, result.stderr.strip()))


require_rejected("boot information", "0x0E040000u")
require_rejected("translation table pool", "0x0E080000u")

layout = load_layout_tool()
values = {
    "WT_SPM_KEYSTORE_PA": 0x1000,
    "WT_SPM_KEYSTORE_SIZE": 0x3000,
    "WT_SPM_VAULT_PA": 0x1000,
    "WT_SPM_VAULT_SIZE": 0x1000,
    "WT_SPM_ATTEST_PA": 0x2000,
    "WT_SPM_ATTEST_SIZE": 0x1000,
    "WT_SPM_HSMDATA_PA": 0x3000,
    "WT_SPM_HSMDATA_SIZE": 0x1000,
    "WT_SPM_INTERFACE_PA": 0x8000,
    "WT_SPM_INTERFACE_SIZE": 0x1000,
}
manifest = {
    "partitions": [
        {"name": "PARTITION_VAULT", "domain_id": 1},
        {"name": "PARTITION_ATTEST", "domain_id": 2},
        {"name": "PARTITION_HSM", "domain_id": 3},
        {"name": "PARTITION_TPM", "domain_id": 4},
    ],
    "domains": [
        {"id": 1, "memory_resources": [
            {"base": 0x1000, "size": 0x1000}]},
        {"id": 2, "memory_resources": [
            {"base": 0x2000, "size": 0x1000}]},
        {"id": 3, "memory_resources": [
            {"base": 0x3000, "size": 0x1000}]},
        {"id": 4, "memory_resources": [
            {"base": 0x8000, "size": 0x1000}]},
    ],
}
check_manifest(layout, manifest, values)
for overlap_name, overlap in (
        ("subset", {"base": 0x8100, "size": 0x200}),
        ("superset", {"base": 0x7F00, "size": 0x1200}),
        ("partial-overlap", {"base": 0x7F00, "size": 0x200})):
    invalid = copy.deepcopy(manifest)
    invalid["domains"][0]["memory_resources"].append(overlap)
    require_manifest_rejected(layout, overlap_name, invalid, values)

invalid = copy.deepcopy(manifest)
invalid["partitions"].append(
    {"name": "PARTITION_PKCS11", "domain_id": 5})
invalid["domains"].append(
    {"id": 5, "memory_resources": [
        {"base": 0x8000, "size": 0x1000}]})
require_manifest_rejected(layout, "multiple-owner", invalid, values)

invalid = copy.deepcopy(manifest)
invalid["domains"][3]["memory_resources"].append(
    {"base": 0x8000, "size": 0x1000})
require_manifest_rejected(layout, "duplicate-exact", invalid, values)

invalid = copy.deepcopy(manifest)
invalid["partitions"] = [partition for partition in invalid["partitions"]
                         if partition["name"] != "PARTITION_TPM"]
require_manifest_rejected(layout, "ownerless-overlap", invalid, values)

print("PASS: AArch64 interface layout and single-owner grants are enforced")
