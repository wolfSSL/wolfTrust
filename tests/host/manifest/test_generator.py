#!/usr/bin/env python3
# test_generator.py
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[2]
GENERATOR = ROOT / "tools" / "manifest" / "generate.py"
FIXTURE = TEST_DIR / "fixtures" / "level3.json"
H5_MANIFEST = ROOT / "port" / "stm32h563" / "manifest.json"


class GeneratorTest(unittest.TestCase):
    def run_generator(self, source, output, supported_features="0x5"):
        return subprocess.run(
            [sys.executable, str(GENERATOR), str(source), str(output),
             "--supported-features", supported_features,
             "--address-bits", "32"],
            check=False, capture_output=True, text=True)

    def compile_generated(self, output, executable):
        command = shlex.split(os.environ.get("CC", "cc"))
        command.extend([
            "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-I" + str(ROOT / "include"), "-I" + str(output),
            str(ROOT / "src" / "domain.c"),
            str(ROOT / "src" / "manifest.c"),
            str(output / "wolftrust_manifest_generated.c"),
            str(TEST_DIR / "generated_main.c"), "-o", str(executable),
        ])
        return subprocess.run(command, check=False, capture_output=True,
                              text=True)

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"

            self.assertEqual(self.run_generator(FIXTURE, first).returncode, 0)
            self.assertEqual(self.run_generator(FIXTURE, second).returncode, 0)
            for name in ("wolftrust_manifest_generated.c",
                         "wolftrust_manifest_generated.h"):
                self.assertEqual((first / name).read_bytes(),
                                 (second / name).read_bytes())
            for name in ("pid.h", "sid.h", "partition_alpha.h",
                         "partition_beta.h"):
                self.assertEqual((first / "psa_manifest" / name).read_bytes(),
                                 (second / "psa_manifest" / name).read_bytes())

    def test_duplicate_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "duplicate.json"
            source.write_text('{"format_version":1,"format_version":1}',
                              encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate JSON key", result.stderr)

    def test_missing_required_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "missing.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            del manifest["domains"][0]["restart_policy"]
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("restart_policy is required", result.stderr)

    def test_unknown_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "unknown.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][0]["priviledged"] = True
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown field priviledged", result.stderr)

    def test_policy_failure_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "overlap.json"
            output = root / "output"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][1]["memory_resources"][0]["base"] = 4096
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlap", result.stderr)
            self.assertFalse(output.exists())

    def test_level3_refuses_writable_sharing_between_partitions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "shared.json"
            output = root / "output"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["profile_capabilities"][
                "max_memory_resources_per_domain"] = 3
            for domain in manifest["domains"][1:]:
                domain["memory_resources"].append({
                    "base": 0xD000, "size": 0x1000,
                    "attributes": 0x23, "share_id": 7})
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("isolation level 3 forbids a writable memory "
                          "resource shared between partitions",
                          result.stderr)
            self.assertFalse(output.exists())

            for domain in manifest["domains"][1:]:
                domain["memory_resources"][-1]["attributes"] = 0x21
            source.write_text(json.dumps(manifest), encoding="utf-8")
            result = self.run_generator(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_address_width_is_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "wide.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][0]["entry_point"] = 0x100000000
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("supported range", result.stderr)

    def test_header_binds_manifest_symbols(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            self.assertEqual(self.run_generator(FIXTURE, output).returncode, 0)
            header = (output / "wolftrust_manifest_generated.h").read_text(
                encoding="utf-8")
            self.assertIn("WT_GENERATED_PARTITION_ALPHA_DOMAIN_ID 1U", header)
            self.assertIn("WT_GENERATED_SERVICE_ALPHA_SID 4096U", header)
            self.assertIn("WT_GENERATED_SERVICE_BETA_HANDLE 1U", header)

    def test_standard_psa_manifest_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            self.assertEqual(self.run_generator(FIXTURE, output).returncode, 0)
            include_dir = output / "psa_manifest"
            pid = (include_dir / "pid.h").read_text(encoding="utf-8")
            sid = (include_dir / "sid.h").read_text(encoding="utf-8")
            alpha = (include_dir / "partition_alpha.h").read_text(
                encoding="utf-8")
            beta = (include_dir / "partition_beta.h").read_text(
                encoding="utf-8")

            self.assertIn("#define PARTITION_ALPHA_ID 1", pid)
            self.assertIn("#define PARTITION_BETA_ID 2", pid)
            self.assertIn("#define SERVICE_ALPHA_SID 4096U", sid)
            self.assertIn("#define SERVICE_BETA_VERSION 2U", sid)
            self.assertIn("#define SERVICE_ALPHA_SIGNAL 16U", alpha)
            self.assertIn("#define ALPHA_IRQ_SIGNAL 32U", alpha)
            self.assertIn("#define SERVICE_BETA_SIGNAL 16U", beta)
            self.assertIn("#define BETA_IRQ_SIGNAL 32U", beta)
            print("PASS: WT-FFM-0004 generated PSA headers")

    def test_sfn_zero_signal_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sfn.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["features"] = 7
            manifest["partitions"][0]["model"] = 1
            manifest["partitions"][0]["framework_version"] = 0x101
            manifest["partitions"][0]["services"][0]["signal"] = 0
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output", "0x7")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unspecified_version_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "policy.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["partitions"][0]["services"][0]["version_policy"] = 2
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("version policy", result.stderr)

    def test_framework_above_build_contract_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "framework.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["partitions"][0]["framework_version"] = 0x101
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(source),
                 str(root / "output"),
                 "--supported-features", "0x5",
                 "--supported-framework-version", "0x100",
                 "--address-bits", "32"],
                check=False, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build contract", result.stderr)

    def test_unaligned_memory_resource_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "unaligned.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][1]["memory_resources"][0]["size"] += 8
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("granule", result.stderr)

    def test_dependency_cycle_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cycle.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["partitions"][1]["dependencies"] = [0x1000]
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cycle", result.stderr)
            self.assertFalse((root / "output").exists())

    def test_domain_enum_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "domain.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][1]["domain_class"] = 99
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("domain class", result.stderr)

    def test_service_policy_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "service.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["partitions"][0]["services"][0]["connection_based"] = False
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("connection based", result.stderr)

    def test_entry_point_policy_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "entry.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][1]["entry_point"] = \
                manifest["domains"][1]["stack_base"]
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("entry point", result.stderr)

    def test_interrupt_ownership_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "interrupt.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["partitions"][0]["interrupts"][0]["interrupt"] += 1
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("partition interrupt", result.stderr)

    def assert_rejected(self, manifest, message):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "manifest.json"
            source.write_text(json.dumps(manifest), encoding="utf-8")
            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
            self.assertFalse((root / "output").exists())

    def test_partition_peripheral_is_rejected(self):
        # WT-FFM-0068: with or without DEVICE, shared or not.
        for attributes, share_id, message in (
                (0x03, 0, "does not assign"),
                (0x0B, 0, "does not assign"),
                (0x2B, 5, "cannot be shared")):
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["profile_capabilities"][
                "max_memory_resources_per_domain"] = 3
            manifest["domains"][1]["memory_resources"].append({
                "base": 0x40004800, "size": 0x400,
                "attributes": attributes, "share_id": share_id})
            self.assert_rejected(manifest, message)

    def test_overlapping_partition_memory_is_rejected(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        manifest["profile_capabilities"]["max_memory_resources_per_domain"] = 3
        manifest["domains"][2]["memory_resources"].append({
            "base": 0x7000, "size": 0x400, "attributes": 0x03,
            "share_id": 0})
        self.assert_rejected(manifest, "overlap")

    def test_duplicate_partition_interrupt_is_rejected(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        manifest["domains"][2]["interrupt_resources"][0]["interrupt"] = 21
        manifest["partitions"][1]["interrupts"][0]["interrupt"] = 21
        self.assert_rejected(manifest, "multiply owned")

    def test_partition_interrupt_beyond_vector_table_is_rejected(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        manifest["domains"][1]["interrupt_resources"][0]["interrupt"] = 64
        manifest["partitions"][0]["interrupts"][0]["interrupt"] = 64
        self.assert_rejected(manifest, "beyond the Secure vector table")

    def test_isolation_levels_1_and_2_are_rejected(self):
        for level in (1, 2):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "level.json"
                manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
                manifest["isolation_profile"] = level
                source.write_text(json.dumps(manifest), encoding="utf-8")

                result = self.run_generator(source, root / "output")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("isolation levels 1 and 2 are not implemented",
                              result.stderr)
                self.assertFalse((root / "output").exists())

    def test_privileged_secure_partition_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "privileged.json"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["domains"][1]["privilege_state"] = 0
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Secure Partitions must be unprivileged",
                          result.stderr)
            self.assertFalse((root / "output").exists())


# Runs the boot-time checks this build-time generator replaces, on a manifest
# the generator itself would refuse to emit.
RUNTIME_HARNESS = r"""
#include "wolftrust_manifest_generated.h"
#include "wolftrust/ffm.h"
#include "wolftrust/partition.h"

#include <stdio.h>
#include <string.h>

static int check_read(void* context, psa_client_id_t caller,
                      const void* address, size_t size)
{
    (void)context; (void)caller; (void)address; (void)size;
    return 0;
}

static int check_write(void* context, psa_client_id_t caller, void* address,
                       size_t size)
{
    (void)context; (void)caller; (void)address; (void)size;
    return 0;
}

static int dispatch(void* context, wt_ffm_runtime_t* runtime,
                    int32_t partition_id)
{
    (void)context; (void)runtime; (void)partition_id;
    return WT_FFM_ERROR_STATE;
}

static void panic(void* context, int32_t partition_id)
{
    (void)context; (void)partition_id;
}

static const wt_ffm_port_ops_t ops = { check_read, check_write, dispatch,
                                       panic };
static wt_ffm_runtime_t runtime;

int main(void)
{
    const wt_system_manifest_t* manifest = wt_generated_manifest_get();
    wt_profile_capabilities_t platform = { TP_CAPS, TP_DOMAINS, TP_MEMORY,
                                           TP_IRQS };
    wt_guest_config_t config;
    size_t i;
    int binding = 0;

    (void)memset(&config, 0, sizeof(config));
    config.vector_table = 0x1000U;
    config.memory_region_count = 1U;
    config.port.required_capabilities = TP_PORT;
    config.port.provided_capabilities = TP_PORT;
    config.port.vector_read_address = 0x2000U;
    for (i = 0U; i < manifest->domain_count; i++) {
        if (manifest->domains[i].domain_class ==
                WT_DOMAIN_CLASS_NONSECURE_APPLICATION &&
                binding == 0) {
            binding = wt_partition_validate_port_binding(&config,
                &manifest->domains[i]);
        }
    }
    (void)printf("%d %d %d %d\n",
                 wt_manifest_validate(manifest, TP_FEATURES, &platform),
                 wt_ffm_init(&runtime, manifest, &ops, NULL),
                 wt_partition_validate_profile(&platform, TP_PORT), binding);
    return 0;
}
"""


def load_generator():
    spec = importlib.util.spec_from_file_location("wt_generate", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def h5_platform():
    return {"capabilities": 0x7F, "max_domains": 11,
            "max_memory_resources_per_domain": 3,
            "max_interrupts_per_domain": 1, "port_capabilities": 0x7}


def fixture_platform():
    return {"capabilities": 0x7F, "max_domains": 3,
            "max_memory_resources_per_domain": 2,
            "max_interrupts_per_domain": 1, "port_capabilities": 0x7}


def ffm_fixture():
    """level3.json reduced to what the FF-M 1.0 runtime activates."""
    manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
    manifest["partitions"][1]["framework_version"] = 0x100
    manifest["partitions"][1]["services"][0]["connection_based"] = True
    manifest["partitions"][1]["services"][0]["stateless_handle_index"] = 0
    return manifest


class BuildTimeParityTest(unittest.TestCase):
    """Every manifest the boot-time checks reject must fail the build."""

    @classmethod
    def setUpClass(cls):
        cls.generator = load_generator()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.objects = []
        work = Path(cls.temporary.name)
        command = shlex.split(os.environ.get("CC", "cc"))
        for name in ("domain.c", "manifest.c", "partition.c", "ffm.c",
                     "ipc.c", "ffm_domain.c"):
            obj = work / (name + ".o")
            subprocess.run(command + ["-std=c99", "-c",
                                      "-DWT_MANIFEST_RUNTIME_CHECK=1",
                                      "-I" + str(ROOT / "include"),
                                      str(ROOT / "src" / name), "-o", str(obj)],
                           check=True)
            cls.objects.append(str(obj))
        (work / "harness.c").write_text(RUNTIME_HARNESS, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def generator_args(self, platform, features, framework, ffm):
        args = ["--supported-features", hex(features),
                "--supported-framework-version", hex(framework),
                "--address-bits", "32",
                "--platform-capabilities", hex(platform["capabilities"]),
                "--platform-max-domains", str(platform["max_domains"]),
                "--platform-max-memory-resources",
                str(platform["max_memory_resources_per_domain"]),
                "--platform-max-interrupts",
                str(platform["max_interrupts_per_domain"]),
                "--port-capabilities", hex(platform["port_capabilities"])]
        if ffm:
            args += ["--ffm-max-partitions", "9", "--ffm-max-services", "20",
                     "--ffm-ipc-only"]
        return args

    def build_time(self, manifest, platform, features, framework=0x100,
                   ffm=True, extra=()):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "manifest.json"
            source.write_text(json.dumps(manifest), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(GENERATOR), str(source),
                 str(Path(temporary) / "output")] +
                self.generator_args(platform, features, framework, ffm) +
                list(extra), check=False, capture_output=True, text=True)

    def boot_time(self, manifest, platform, features):
        """Return the boot-time verdicts: validator, FF-M, profile, binding."""
        work = Path(self.temporary.name) / "case"
        work.mkdir(exist_ok=True)
        digest = hashlib.sha256(json.dumps(manifest).encode()).digest()
        (work / "wolftrust_manifest_generated.c").write_text(
            self.generator.generate_source(manifest, digest), encoding="utf-8")
        (work / "wolftrust_manifest_generated.h").write_text(
            self.generator.generate_header(manifest), encoding="utf-8")
        executable = work / "boot_time"
        command = shlex.split(os.environ.get("CC", "cc"))
        command += ["-std=c99", "-DWT_MANIFEST_RUNTIME_CHECK=1",
                    "-DTP_CAPS={}U".format(platform["capabilities"]),
                    "-DTP_DOMAINS={}U".format(platform["max_domains"]),
                    "-DTP_MEMORY={}U".format(
                        platform["max_memory_resources_per_domain"]),
                    "-DTP_IRQS={}U".format(
                        platform["max_interrupts_per_domain"]),
                    "-DTP_PORT={}U".format(platform["port_capabilities"]),
                    "-DTP_FEATURES={}U".format(features),
                    "-I" + str(ROOT / "include"), "-I" + str(work),
                    str(work / "wolftrust_manifest_generated.c"),
                    str(Path(self.temporary.name) / "harness.c"),
                    "-o", str(executable)] + self.objects
        subprocess.run(command, check=True)
        result = subprocess.run([str(executable)], check=True,
                                capture_output=True, text=True)
        return [int(value) for value in result.stdout.split()]

    def assert_parity(self, manifest, platform, features, message,
                      framework=0x100):
        verdicts = self.boot_time(manifest, platform, features)
        self.assertTrue(any(verdicts), "boot time accepted: " + message)
        result = self.build_time(manifest, platform, features, framework)
        self.assertNotEqual(result.returncode, 0, message)
        self.assertIn(message, result.stderr)

    def test_baselines_pass_both(self):
        for manifest, platform, features in (
                (ffm_fixture(), fixture_platform(), 0x5),
                (json.loads(H5_MANIFEST.read_text(encoding="utf-8")),
                 h5_platform(), 0x1)):
            self.assertEqual(self.boot_time(manifest, platform, features),
                             [0, 0, 0, 0])
            result = self.build_time(manifest, platform, features)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_build_without_ipc_feature_is_rejected(self):
        manifest = ffm_fixture()
        manifest["features"] = 1
        self.assert_parity(manifest, fixture_platform(), 0x4,
                           "must support the IPC feature")

    def test_profile_beyond_platform_is_rejected(self):
        for field, value in (("capabilities", 0x3F), ("max_domains", 2),
                             ("max_memory_resources_per_domain", 1),
                             ("max_interrupts_per_domain", 0)):
            platform = fixture_platform()
            platform[field] = value
            # A narrower platform must still pass the domain set itself.
            manifest = ffm_fixture()
            if field == "max_domains":
                manifest["domains"] = manifest["domains"][:2]
                manifest["partitions"] = manifest["partitions"][:1]
            if field == "max_memory_resources_per_domain":
                for domain in manifest["domains"]:
                    del domain["memory_resources"][1]
                    domain["stack_base"] = domain["memory_resources"][0][
                        "base"]
            if field == "max_interrupts_per_domain":
                for domain in manifest["domains"]:
                    domain["interrupt_resources"] = []
                for partition in manifest["partitions"]:
                    partition["interrupts"] = []
            self.assert_parity(manifest, platform, 0x5,
                               "profile capabilities exceed the platform")

    def test_platform_capability_mask_is_rejected(self):
        platform = fixture_platform()
        platform["capabilities"] = 0xFF
        self.assert_parity(ffm_fixture(), platform, 0x5,
                           "platform capability mask is invalid")

    def test_nonsecure_application_interrupt_is_rejected(self):
        manifest = json.loads(H5_MANIFEST.read_text(encoding="utf-8"))
        manifest["profile_capabilities"]["max_interrupts_per_domain"] = 1
        manifest["domains"][1]["interrupt_resources"] = [
            {"interrupt": 40, "attributes": 0, "share_id": 0}]
        self.assert_parity(manifest, h5_platform(), 0x1,
                           "Non-secure application cannot own interrupts")

    def test_interrupt_signal_named_after_partition_is_rejected(self):
        manifest = ffm_fixture()
        manifest["partitions"][0]["interrupts"][0]["signal_name"] = \
            "PARTITION_BETA"
        self.assert_parity(manifest, fixture_platform(), 0x5,
                           "interrupt signal name is a partition name")

    def test_sfn_partition_is_rejected_for_the_ffm_runtime(self):
        manifest = ffm_fixture()
        manifest["features"] = 7
        manifest["partitions"][1]["framework_version"] = 0x101
        manifest["partitions"][1]["model"] = 1
        manifest["partitions"][1]["services"][0]["signal"] = 0
        self.assert_parity(manifest, fixture_platform(), 0x7,
                           "schedules IPC partitions only", framework=0x101)

    def test_framework_above_runtime_is_rejected(self):
        manifest = ffm_fixture()
        manifest["partitions"][1]["framework_version"] = 0x101
        self.assert_parity(manifest, fixture_platform(), 0x5,
                           "exceeds the build contract")

    def test_ffm_runtime_counts_are_enforced(self):
        for option, message in (
                ("--ffm-max-partitions", "partition count exceeds"),
                ("--ffm-max-services", "service count exceeds")):
            result = self.build_time(ffm_fixture(), fixture_platform(), 0x5,
                                     extra=(option, "1"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)

    def test_port_capabilities_bind_at_build_time(self):
        for port, message in (
                (0x1, "memory protection needs"),
                (0x3, "domain isolation needs a TrustZone filter"),
                (0x5, "guest MPU regions need"),
                (0xF, "port capability mask is invalid")):
            platform = h5_platform()
            platform["port_capabilities"] = port
            self.assert_parity(
                json.loads(H5_MANIFEST.read_text(encoding="utf-8")),
                platform, 0x1, message)

    def test_range_ending_at_the_address_space_top_is_rejected(self):
        # A 32-bit wt_range_end refuses size > UINTPTR_MAX - base; a 64-bit
        # host cannot show it, so only the generator side runs here.
        manifest = ffm_fixture()
        manifest["profile_capabilities"]["max_memory_resources_per_domain"] = 3
        manifest["domains"][0]["memory_resources"].append({
            "base": 0xFFFFF000, "size": 0x1000, "attributes": 1,
            "share_id": 0})
        platform = fixture_platform()
        platform["max_memory_resources_per_domain"] = 3
        result = self.build_time(manifest, platform, 0x5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside target address space", result.stderr)

    def test_platform_drift_fails_the_compile(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            base = self.generator_args(h5_platform(), 0x1, 0x100, True)
            for drift, accepted in ((None, True), ("12", False)):
                args = list(base)
                if drift is not None:
                    args[args.index("--platform-max-domains") + 1] = drift
                result = subprocess.run(
                    [sys.executable, str(GENERATOR), str(H5_MANIFEST),
                     str(output)] + args +
                    ["--platform-header", "platform_caps.h"],
                    check=False, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                command = shlex.split(os.environ.get("CC", "cc"))
                command += ["-std=c99", "-Wall", "-Wextra", "-Werror",
                            "-pedantic", "-fsyntax-only",
                            "-I" + str(ROOT / "include"), "-I" + str(output),
                            "-I" + str(ROOT / "port" / "stm32h563"),
                            str(output / "wolftrust_manifest_generated.c")]
                compiled = subprocess.run(command, check=False,
                                          capture_output=True, text=True)
                self.assertEqual(compiled.returncode == 0, accepted,
                                 compiled.stderr)


if __name__ == "__main__":
    unittest.main()
