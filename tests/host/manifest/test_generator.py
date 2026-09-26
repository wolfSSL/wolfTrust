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


class GeneratorTest(unittest.TestCase):
    def run_generator(self, source, output, supported_features="0x5"):
        return subprocess.run(
            [sys.executable, str(GENERATOR), str(source), str(output),
             "--supported-features", supported_features,
             "--address-bits", "32"],
            check=False, capture_output=True, text=True)

    def compile_generated(self, output, executable, defines=(),
                          main=TEST_DIR / "generated_main.c"):
        command = shlex.split(os.environ.get("CC", "cc"))
        command.extend(defines)
        command.extend([
            "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-I" + str(ROOT / "include"), "-I" + str(output),
            str(ROOT / "src" / "domain.c"),
            str(ROOT / "src" / "manifest.c"),
            str(output / "wolftrust_manifest_generated.c"),
            str(main), "-o", str(executable),
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

    def run_generator_64(self, source, output, extra=()):
        return subprocess.run(
            [sys.executable, str(GENERATOR), str(source), str(output),
             "--supported-features", "0x5", "--address-bits", "64", *extra],
            check=False, capture_output=True, text=True)

    def test_64_bit_header_sizes_the_table_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pool.json"
            output = root / "output"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            domain = manifest["domains"][2]
            domain["memory_resources"][1].update(base=0x1FF000, size=0x2000)
            domain["stack_base"] = 0x1FF800
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator_64(source, output,
                                           ("--spm-table-pages", "4"))
            self.assertEqual(result.returncode, 0, result.stderr)
            header = (output / "wolftrust_manifest_generated.h").read_text(
                encoding="utf-8")
            self.assertIn("#define WT_GENERATED_TABLE_POOL_PAGES 14U", header)

    def test_64_bit_source_refuses_a_table_pool_below_the_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pool.json"
            output = root / "output"
            source.write_text(json.dumps(self.ffa_manifest()), encoding="utf-8")

            result = self.run_generator_64(source, output,
                                           ("--spm-table-pages", "4"))
            self.assertEqual(result.returncode, 0, result.stderr)
            header = (output / "wolftrust_manifest_generated.h").read_text(
                encoding="utf-8")
            need = int(header.split("WT_GENERATED_TABLE_POOL_PAGES ")[1]
                       .split("U")[0])
            for defines, ok in ((("-DWT_SPM_TABLE_POOL_PAGES={}U".format(need),),
                                 True),
                                (("-DWT_SPM_TABLE_POOL_PAGES={}U".format(
                                    need - 1),), False),
                                ((), False)):
                compiled = self.compile_generated(output, root / "generated",
                                                  defines)
                if ok:
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                else:
                    self.assertNotEqual(compiled.returncode, 0, defines)
                    self.assertIn("WT_GENERATED_TABLE_POOL_PAGES",
                                  compiled.stderr, defines)

    def test_32_bit_header_has_no_table_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            self.assertEqual(self.run_generator(FIXTURE, output).returncode, 0)
            header = (output / "wolftrust_manifest_generated.h").read_text(
                encoding="utf-8")
            self.assertNotIn("TABLE_POOL", header)

    def ffa_manifest(self):
        manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
        manifest["ffa"] = {"partitions": [{
            "domain_id": manifest["partitions"][0]["domain_id"],
            "ffa_version": "1.2",
            "uuids": ["b4b5671e-4a90-4fe1-b81f-fb13dae1dacb",
                      "01234567-0123-4567-89ab-0123456789ab"],
            "execution_contexts": 1,
            "runtime_el": "S-EL0",
            "messaging": "none",
            "ns_interrupt_action": "signaled",
            "boot_info_register": "none",
        }]}
        return manifest

    def test_ffa_section_emits_a_separate_partition_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "ffa.json"
            output = root / "output"
            source.write_text(json.dumps(self.ffa_manifest()), encoding="utf-8")

            result = self.run_generator_64(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = (output / "wolftrust_manifest_generated.c").read_text(
                encoding="utf-8")
            self.assertIn('#include "wolftrust/arch/aarch64/ffa_manifest.h"',
                          generated)
            self.assertIn("wt_generated_ffa_partitions[1]", generated)
            self.assertIn(".uuid_count = 2U", generated)
            self.assertIn("0xb4U, 0xb5U, 0x67U, 0x1eU", generated)
            self.assertIn(".messaging = 0U", generated)
            self.assertIn(".ffa_version = 65538U", generated)
            self.assertIn(".boot_info_register = 4294967295U", generated)
            self.assertIn("wt_generated_ffa_partitions_get(size_t* count)",
                          generated)
            compiled = self.compile_generated(
                output, root / "generated", ("-DWT_SPM_TABLE_POOL_PAGES=4096U",))
            self.assertEqual(compiled.returncode, 0, compiled.stderr)

    def test_64_bit_manifest_without_ffa_links_an_empty_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            main = root / "ffa_main.c"
            main.write_text(
                "#include \"wolftrust_manifest_generated.h\"\n"
                "#include \"wolftrust/arch/aarch64/ffa_manifest.h\"\n"
                "int main(void)\n"
                "{\n"
                "    size_t count = 1U;\n"
                "    const wt_ffa_partition_manifest_t* parts =\n"
                "        wt_generated_ffa_partitions_get(&count);\n"
                "    return ((parts != NULL) && (count == 0U)) ? 0 : 1;\n"
                "}\n", encoding="utf-8")
            self.assertEqual(self.run_generator_64(FIXTURE, output).returncode, 0)
            generated = (output / "wolftrust_manifest_generated.c").read_text(
                encoding="utf-8")
            self.assertIn("wt_generated_ffa_partitions_get(size_t* count)",
                          generated)
            compiled = self.compile_generated(
                output, root / "ffa_empty", ("-DWT_SPM_TABLE_POOL_PAGES=4096U",),
                main)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(root / "ffa_empty")], check=False)
            self.assertEqual(ran.returncode, 0)

    def test_32_bit_manifest_emits_no_ffa_symbols(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            self.assertEqual(self.run_generator(FIXTURE, output).returncode, 0)
            generated = (output / "wolftrust_manifest_generated.c").read_text(
                encoding="utf-8")
            self.assertNotIn("ffa", generated)

    def test_ffa_section_needs_a_64_bit_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "ffa32.json"
            source.write_text(json.dumps(self.ffa_manifest()), encoding="utf-8")

            result = self.run_generator(source, root / "output")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--address-bits 64", result.stderr)

    def test_ffa_null_section_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "null.json"
            output = root / "output"
            manifest = json.loads(FIXTURE.read_text(encoding="utf-8"))
            manifest["ffa"] = None
            source.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_generator_64(source, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest.ffa", result.stderr)
            self.assertFalse(output.exists())

    def test_ffa_policy_is_rejected_before_output(self):
        cases = (
            ("uuids", ["B4B5671E-4A90-4FE1-B81F-FB13DAE1DACB"], "canonical"),
            ("uuids", [], "1 to 4 UUIDs"),
            ("domain_id", 250, "unknown domain"),
            ("execution_contexts", 2, "one execution context"),
            ("ffa_version", "1.1", "ffa_version must be 1.2"),
            ("ffa_version", 0x10002, "ffa_version must be"),
            ("runtime_el", "EL2", "runtime_el"),
            ("runtime_el", "S-EL1", "runtime_el must be S-EL0"),
            ("messaging", "smoke", "messaging"),
            ("messaging", "indirect", "messaging must be none"),
            ("messaging", "direct", "messaging must be none"),
            ("ns_interrupt_action", "drop", "ns_interrupt_action"),
            ("ns_interrupt_action", "queued", "must be signaled"),
            ("boot_info_register", 4, "boot_info_register"),
            ("boot_info_register", "x0", "boot_info_register must be none"),
        )
        for field, value, message in cases:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "bad.json"
                output = root / "output"
                manifest = self.ffa_manifest()
                manifest["ffa"]["partitions"][0][field] = value
                source.write_text(json.dumps(manifest), encoding="utf-8")

                result = self.run_generator_64(source, output)
                self.assertNotEqual(result.returncode, 0, field)
                self.assertIn(message, result.stderr, field)
                self.assertFalse(output.exists(), field)


if __name__ == "__main__":
    unittest.main()
