#!/usr/bin/env python3
"""Assert the Arm PSA-FF manifest ingester emits the expected psa_manifest
identity headers from the real upstream server/driver/client manifests."""
import json
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
INGESTER = REPO / "tools" / "manifest" / "ingest_psa_arch.py"

sys.path.insert(0, str(INGESTER.parent))
import ingest_psa_arch  # noqa: E402
import render  # noqa: E402

WT_SERVICE_VERSION_STRICT = 0
WT_SERVICE_VERSION_RELAXED = 1

EXPECT_PID = {
    "SERVER_PARTITION_ID",
    "DRIVER_PARTITION_ID",
    "CLIENT_PARTITION_ID",
}

EXPECT_SID = {
    "SERVER_TEST_DISPATCHER_SID": 0x0000FB01,
    "SERVER_SECURE_CONNECT_ONLY_SID": 0x0000FB02,
    "SERVER_STRICT_VERSION_SID": 0x0000FB03,
    "SERVER_UNSPECIFIED_VERSION_SID": 0x0000FB04,
    "SERVER_CONNECTION_DROP_SID": 0x0000FB07,
    "DRIVER_UART_SID": 0x0000FC01,
    "DRIVER_NVMEM_SID": 0x0000FC03,
    "CLIENT_TEST_DISPATCHER_SID": 0x0000FA01,
}

EXPECT_VERSION = {
    "SERVER_STRICT_VERSION_VERSION": 2,
    "SERVER_UNSPECIFIED_VERSION_VERSION": 1,
    "DRIVER_UART_VERSION": 1,
}

EXPECT_ROT_ROLE = {
    "SERVER_PARTITION": 3,
    "DRIVER_PARTITION": 2,
    "CLIENT_PARTITION": 3,
}

EXPECT_DRIVER_SIGNAL = {
    "DRIVER_UART_SIGNAL": 0x10,
    "DRIVER_NVMEM_SIGNAL": 0x40,
    "DRIVER_UART_INTR_SIG_SIGNAL": 0x100,
}

ACS_UNUSED_HEAPS = {
    "server_partition_psa.json": "0x100",
    "driver_partition_psa.json": "0x100",
}

DEFINE = re.compile(r"#define\s+(\S+)\s+(\S+?)U?$", re.MULTILINE)


def defines(path):
    values = {}
    for name, value in DEFINE.findall(path.read_text(encoding="utf-8")):
        try:
            values[name] = int(value, 0)
        except ValueError:
            values[name] = value
    return values


def main():
    if len(sys.argv) < 2:
        print("usage: run.py <psa-arch-tests-dir>", file=sys.stderr)
        return 2
    manifests = Path(sys.argv[1]) / "api-tests" / "platform" / "manifests"
    inputs = [
        manifests / "server_partition_psa.json",
        manifests / "driver_partition_psa.json",
        manifests / "client_partition_psa.json",
    ]
    for path in inputs:
        if not path.is_file():
            print("missing upstream manifest: {}".format(path), file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory() as directory:
        adapted = []
        for path in inputs:
            source = json.loads(path.read_text(encoding="utf-8"))
            if path.name not in ACS_UNUSED_HEAPS:
                adapted.append(path)
                continue
            if source.get("heap_size") != ACS_UNUSED_HEAPS[path.name]:
                print("unexpected ACS heap request in {}".format(path),
                      file=sys.stderr)
                return 1
            # These pinned ACS fixtures declare private heaps but do not use
            # them. Adapt temporary manifest copies for the fixed-slot port.
            del source["heap_size"]
            fixture = Path(directory) / path.name
            fixture.write_text(json.dumps(source), encoding="utf-8")
            adapted.append(fixture)

        rejected = subprocess.run(
            [sys.executable, str(INGESTER), str(inputs[0]),
             "--output", directory,
             "--base", str(REPO / "manifest" / "base.json"),
             "--emit-overlay", str(Path(directory) / "conformance.json")],
            capture_output=True, text=True)
        if rejected.returncode != 1 or "requests heap_size" not in \
                rejected.stderr or (Path(directory) / "psa_manifest").exists() \
                or (Path(directory) / "conformance.json").exists():
            print("heap request was not refused: {}".format(rejected.stderr),
                  file=sys.stderr)
            return 1

        return check_ingest(adapted)


def check_ingest(inputs):
    failures = 0

    server = ingest_psa_arch.normalize_partition(
        json.loads(inputs[0].read_text(encoding="utf-8")), 1)
    policies = {s["name"]: s["version_policy"] for s in server["services"]}
    for name, expect in (
            ("SERVER_STRICT_VERSION", WT_SERVICE_VERSION_STRICT),
            ("SERVER_UNSPECIFIED_VERSION", WT_SERVICE_VERSION_STRICT),
            ("SERVER_RELAX_VERSION", WT_SERVICE_VERSION_RELAXED)):
        if policies.get(name) != expect:
            print("version_policy {}: expected {}, got {}".format(
                name, expect, policies.get(name)), file=sys.stderr)
            failures += 1

    with tempfile.TemporaryDirectory() as out:
        result = subprocess.run(
            [sys.executable, str(INGESTER), *[str(p) for p in inputs],
             "--output", out],
            capture_output=True, text=True)
        if result.returncode != 0:
            print("ingester failed: {}".format(result.stderr), file=sys.stderr)
            return 1

        psa = Path(out) / "psa_manifest"
        pid = defines(psa / "pid.h")
        sid = defines(psa / "sid.h")
        driver = defines(psa / "driver_partition.h")

        for name in EXPECT_PID:
            if name not in pid:
                print("pid.h missing {}".format(name), file=sys.stderr)
                failures += 1
        for name, value in EXPECT_SID.items():
            if sid.get(name) != value:
                print("sid.h {}: expected {:#x}, got {}".format(
                    name, value, sid.get(name)), file=sys.stderr)
                failures += 1
        for name, value in EXPECT_VERSION.items():
            if sid.get(name) != value:
                print("sid.h {}: expected {}, got {}".format(
                    name, value, sid.get(name)), file=sys.stderr)
                failures += 1
        for name, value in EXPECT_DRIVER_SIGNAL.items():
            if driver.get(name) != value:
                print("driver_partition.h {}: expected {:#x}, got {}".format(
                    name, value, driver.get(name)), file=sys.stderr)
                failures += 1

    overlay = REPO / "manifest" / "conformance.json"
    base = REPO / "manifest" / "base.json"
    generator = REPO / "tools" / "manifest" / "generate.py"
    renderer = REPO / "tools" / "manifest" / "render.py"

    with tempfile.TemporaryDirectory() as emit_dir:
        emitted = Path(emit_dir) / "conformance.json"
        emit = subprocess.run(
            [sys.executable, str(INGESTER), *[str(p) for p in inputs],
             "--base", str(base), "--emit-overlay", str(emitted)],
            capture_output=True, text=True)
        if emit.returncode != 0:
            print("emit-overlay failed: {}".format(emit.stderr),
                  file=sys.stderr)
            failures += 1
        elif json.loads(emitted.read_text()) != json.loads(overlay.read_text()):
            print("committed manifest/conformance.json is not reproducible "
                  "from the upstream manifests", file=sys.stderr)
            failures += 1
        if emit.returncode == 0:
            merged = json.loads(emitted.read_text())
            roles = {d["id"]: d["rot_role"] for d in merged["domains"]}
            got = {p["name"]: roles.get(p["domain_id"])
                   for p in merged["partitions"]}
            for name, expect in EXPECT_ROT_ROLE.items():
                if got.get(name) != expect:
                    print("rot_role {}: expected {}, got {}".format(
                        name, expect, got.get(name)), file=sys.stderr)
                    failures += 1
    for bad_type in (None, "NS-AGENT", []):
        with tempfile.TemporaryDirectory() as bad_dir:
            source = json.loads(inputs[0].read_text(encoding="utf-8"))
            if bad_type is None:
                del source["type"]
            else:
                source["type"] = bad_type
            bad_input = Path(bad_dir) / "server_partition_psa.json"
            bad_input.write_text(json.dumps(source), encoding="utf-8")
            bad_emit = Path(bad_dir) / "conformance.json"
            refused = subprocess.run(
                [sys.executable, str(INGESTER), str(bad_input),
                 *[str(p) for p in inputs[1:]], "--base", str(base),
                 "--emit-overlay", str(bad_emit)],
                capture_output=True, text=True)
            if refused.returncode != 1 or \
                    "unknown partition type" not in refused.stderr or \
                    bad_emit.exists():
                print("partition type {!r} was not refused: {}".format(
                    bad_type, refused.stderr.strip()), file=sys.stderr)
                failures += 1

    # The conformance manifest the secure build compiles: the overlay rendered
    # under the default port's layout configuration.
    cflags = subprocess.run(
        ["make", "-s", "--no-print-directory", "-C", str(REPO),
         "print-layout-cflags"], capture_output=True, text=True)
    if cflags.returncode != 0:
        print("reading the layout flags failed: {}".format(cflags.stderr),
              file=sys.stderr)
        return 1
    layout = render.evaluate("cc", shlex.split(cflags.stdout),
                             [ingest_psa_arch.SP_STACK_SIZE])
    capacity = layout[ingest_psa_arch.SP_STACK_SIZE]
    client = json.loads(inputs[2].read_text(encoding="utf-8"))
    for key, value in (("psa_framework_version", 1.1),
                       ("psa_framework_version", True),
                       ("priority", "URGENT"),
                       ("stack_size", 0),
                       ("stack_size", hex(capacity + 1))):
        try:
            ingest_psa_arch.normalize_partition(dict(client, **{key: value}),
                                               1)
        except ingest_psa_arch.IngestError as error:
            if key in str(error):
                continue
        print("{}={!r} was not refused".format(key, value), file=sys.stderr)
        failures += 1
    for priority, expected in (("LOW", 0), ("HIGH", 2)):
        part = ingest_psa_arch.normalize_partition(
            dict(client, stack_size=capacity, priority=priority), 1)
        if part["priority"] != expected:
            print("priority {} was not preserved".format(priority),
                  file=sys.stderr)
            failures += 1
    with tempfile.TemporaryDirectory() as ingest_out, \
            tempfile.TemporaryDirectory() as conf_out:
        conf = Path(conf_out) / "manifest-conformance.json"
        rendered = subprocess.run(
            [sys.executable, str(renderer), "--cc", "cc",
             "--cflags", cflags.stdout.strip(), "--overlay", str(overlay),
             "--output", str(conf), str(base)],
            capture_output=True, text=True)
        if rendered.returncode != 0:
            print("rendering the conformance manifest failed: {}".format(
                rendered.stderr), file=sys.stderr)
            return 1
        result = subprocess.run(
            [sys.executable, str(INGESTER), *[str(p) for p in inputs],
             "--output", ingest_out],
            capture_output=True, text=True)
        conf_result = subprocess.run(
            [sys.executable, str(generator), str(conf), conf_out,
             "--supported-features", "1", "--unchecked"],
            capture_output=True, text=True)
        if result.returncode != 0 or conf_result.returncode != 0:
            print("conformance manifest generation failed: {}{}".format(
                result.stderr, conf_result.stderr), file=sys.stderr)
            failures += 1
        else:
            ingested = defines(Path(ingest_out) / "psa_manifest" / "sid.h")
            generated = defines(Path(conf_out) / "psa_manifest" / "sid.h")
            for name, value in ingested.items():
                if generated.get(name) != value:
                    print("conformance manifest drift on {}: {} != {}".format(
                        name, value, generated.get(name)), file=sys.stderr)
                    failures += 1

    if failures != 0:
        print("manifest ingest checks failed: {}".format(failures),
              file=sys.stderr)
        return 1
    print("PASS: manifest ingest (Arm PSA-FF -> psa_manifest headers)")
    print("PASS: conformance manifest validates and matches upstream SIDs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
