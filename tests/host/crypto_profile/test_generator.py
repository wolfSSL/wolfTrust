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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Operation selection regressions against the pinned dependency sources."""

import argparse
import importlib.util
import json
import os
import shlex
import subprocess
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("crypto_profile", ROOT / "tools/crypto_profile.py")
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog, cls.signatures, cls.sources, cls.commands = profile.discover(ROOT)
        cls.defaults = json.loads((ROOT / "config/crypto-profiles.json").read_text())["default"]

    def test_default_and_overrides(self):
        selected, mechanisms = profile.select(self.catalog, self.defaults,
            "default", {}, ["tpm:PCR_Read", "pkcs11:C_CopyObject"],
            ["psa:psa_sign_hash"])
        self.assertIn("PCR_Read", selected["tpm"])
        self.assertIn("C_CopyObject", selected["pkcs11"])
        self.assertNotIn("psa_sign_hash", selected["psa"])
        self.assertEqual(mechanisms, self.defaults["mechanisms"])

    def test_full_means_implemented_proxy_operations(self):
        selected, mechanisms = profile.select(self.catalog, self.defaults,
            "full", {}, [], [])
        self.assertIn("C_DeriveKey", selected["pkcs11"])
        self.assertNotIn("C_WrapKey", selected["pkcs11"])
        self.assertIsNone(mechanisms)

    def test_reject_unknown_operations(self):
        for value in ("tpm:NotACommand", "psa:psa_connect", "pkcs11:C_WrapKey", "bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                profile.select(self.catalog, self.defaults, "default", {}, [value], [])

    def test_reject_invalid_configuration(self):
        for custom in ([], {"psa": "psa_sign_hash"}, {"tpm": [1]}, {"bogus": []},
                       {"mechanisms": ["CKM_SHA256; invalid"]}):
            with self.subTest(custom=custom), self.assertRaises(ValueError):
                profile.select(self.catalog, self.defaults, "default", custom, [], [])

    def test_tpm_table_filters_handlers_and_keeps_auth_metadata(self):
        selected = profile.selected_tpm(self.commands, {"Sign"})
        start, end, rows = profile.tpm_table(selected)
        self.assertEqual([m.group(1) for m in rows], ["Sign"])
        self.assertIn("FwCmd_Sign,                 1, 1, 0, FW_CMD_FLAG_ENC", selected[start:end])
        self.assertIn("== 1U", selected[end:])
        # Parser and handlers are untouched; only dispatcher roots disappear.
        original_start, original_end, _ = profile.tpm_table(self.commands)
        self.assertEqual(selected[:start], self.commands[:original_start])
        self.assertTrue(selected.endswith(self.commands[original_end + 3:]))

    def test_fail_closed_on_dependency_table_change(self):
        with self.assertRaises(ValueError):
            profile.tpm_table(self.commands.replace(profile.TPM_TABLE, "changed table"))

    def test_internal_psa_dependencies_keep_private_names(self):
        with tempfile.TemporaryDirectory(dir=BUILD_DIR) as temporary:
            output = Path(temporary)
            profile.generate(ROOT, output, "default", {}, [], [])
            api = (output / "psa/profile_api.c").read_text()
            private = (output / "private_psa.h").read_text()
            self.assertIn("return wt_profile_real_psa_generate_key", api)
            self.assertIn("#define psa_hash_setup wt_profile_real_psa_hash_setup", private)
            disabled = api[api.index("psa_status_t psa_cipher_encrypt("):]
            disabled = disabled[:disabled.index("\n}")]
            self.assertIn("PSA_ERROR_NOT_SUPPORTED", disabled)
            self.assertNotIn("wt_profile_real_psa_cipher_encrypt", disabled)

    def test_repeated_generation_preserves_file_times(self):
        with tempfile.TemporaryDirectory(dir=BUILD_DIR) as temporary:
            output = Path(temporary)
            profile.generate(ROOT, output, "default", {}, [], [])
            before = {p: p.stat().st_mtime_ns for p in output.rglob("*") if p.is_file()}
            profile.generate(ROOT, output, "default", {}, [], [])
            self.assertEqual(before, {p: p.stat().st_mtime_ns for p in before})

    def test_multipart_actions_and_mechanism_aliases(self):
        header = profile.pkcs11_header(self.signatures,
            {"C_DigestInit", "C_DigestUpdate", "C_DigestFinal"},
            ["CKM_EC_KEY_PAIR_GEN", "CKM_ECDSA_KEY_PAIR_GEN"])
        self.assertNotIn("flags &= ~(CK_FLAGS)CKF_DIGEST;", header)
        self.assertIn("flags &= ~(CK_FLAGS)CKF_SIGN;", header)
        self.assertNotIn("case CKM_EC", header)

    def test_raw_provider_objects_wait_for_generated_header(self):
        cases = (("p11_wc_raw_random.o", "PKCS11", "native"),
                 ("p11_sec_raw_internal.o", "PKCS11", "native"),
                 ("p11_sec_raw_crypto.o", "PKCS11", "native"),
                 ("p11_wh_raw_wh_client.o", "PKCS11", "hsm"),
                 ("tpm_wc_raw_random.o", "TPM", "native"),
                 ("tpm_sec_raw_fwtpm_crypto.o", "TPM", "native"),
                 ("tpm_wh_raw_wh_client.o", "TPM", "hsm"))
        for object_name, api, engine in cases:
            with self.subTest(object=object_name), tempfile.TemporaryDirectory(dir=BUILD_DIR) as temporary:
                output = Path(temporary)
                compiler = output / "compiler.py"
                compiler.write_text("#!/usr/bin/env python3\n"
                    "import pathlib, sys\n"
                    "args = sys.argv[1:]\n"
                    "if '-o' not in args: raise SystemExit(0)\n"
                    "seen = False\n"
                    "for i, arg in enumerate(args):\n"
                    "    if arg == '-include' and pathlib.Path(args[i+1]).name == 'selected_profile.h':\n"
                    "        assert pathlib.Path(args[i+1]).is_file(), args[i+1]\n"
                    "        seen = True\n"
                    "assert seen, 'profile header not passed to compiler'\n"
                    "pathlib.Path(args[args.index('-o')+1]).touch()\n")
                compiler.chmod(0o755)
                build = output / "objects"
                # This independent make has its own parallel job pool; Python
                # does not pass through the parent make's jobserver descriptors.
                environment = os.environ.copy()
                environment.pop("MAKEFLAGS", None)
                environment.pop("MFLAGS", None)
                result = subprocess.run(["make", "--no-print-directory", "-j8",
                    "-C", str(ROOT), "ARCH=aarch64", "TARGET=qemuvirt", "TOOLPREFIX=",
                    "CONFIG_" + api + "=y", "WT_ENGINE=" + engine,
                    "BUILD_DIR=" + str(build), "CC=" + str(compiler),
                    str(build / object_name)], text=True, capture_output=True,
                    env=environment)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((build / "crypto-profile/selected_profile.h").is_file())
                self.assertTrue((build / object_name).is_file())

    def test_empty_pkcs11_selection_compiles(self):
        with tempfile.TemporaryDirectory(dir=BUILD_DIR) as temporary:
            output = Path(temporary)
            profile.generate(ROOT, output, "default",
                {"pkcs11": [], "mechanisms": []}, [], [])
            compiler = shlex.split(os.environ.get("CC", "cc"))
            subprocess.run(compiler + ["-std=c99", "-Wall", "-Wextra", "-Werror",
                "-fsyntax-only", "-x", "c", "-DWOLFPKCS11_USER_SETTINGS",
                "-I" + str(ROOT / "tests/host/pkcs11_provider"),
                "-I" + str(ROOT / "include"), "-I" + str(ROOT / "lib/wolfPKCS11"),
                "-include", str(output / "selected_profile.h"), "-"],
                input='#include "wolftrust/crypto_profile.h"\nint main(void) { return wt_profile_pkcs11_operation(0); }\n',
                text=True, capture_output=True, check=True)

    def test_public_mechanisms_do_not_remove_internal_pin_crypto(self):
        for mechanisms, aes, hmac in (
            (self.defaults["mechanisms"], False, False),
            (["CKM_SHA256_HMAC"], False, True),
            (["CKM_AES_GCM"], True, False),
            (None, True, True),
        ):
            with self.subTest(mechanisms=mechanisms):
                source = profile.pkcs11_mechanism_source(ROOT, mechanisms)
                self.assertEqual("#define NO_AES" in source, not aes)
                self.assertEqual("#define NO_HMAC" in source, not hmac)
                for macro in ("#define NO_AES", "#define NO_HMAC"):
                    if macro in source:
                        self.assertLess(source.index("<wolfpkcs11/internal.h>"),
                                        source.index(macro))

    def test_tpm_full_point_dependency_restores_software_ecc(self):
        for enabled in ([], ["tpm:ZGen_2Phase"]):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory(dir=BUILD_DIR) as temporary:
                output = Path(temporary)
                profile.generate(ROOT, output, "default", {}, enabled, [])
                compiler = shlex.split(os.environ.get("CC", "cc"))
                result = subprocess.run(compiler + ["-E", "-dM", "-x", "c",
                    "-DWT_TPM_HSM_CALLBACK_ECC", "-include",
                    str(output / "selected_profile.h"), "-"], input="",
                    text=True, capture_output=True, check=True)
                self.assertEqual("#define WOLF_CRYPTO_CB_ONLY_ECC 1" in result.stdout,
                                 not enabled)

    def test_ci_matrix_keeps_every_profile_engine_api_cell(self):
        matrix_spec = importlib.util.spec_from_file_location("scenario_matrix",
            ROOT / "tests/target/lib/scenario_matrix.py")
        matrix = importlib.util.module_from_spec(matrix_spec)
        matrix_spec.loader.exec_module(matrix)
        workflow = (ROOT / ".github/workflows/m33mu.yml").read_text()
        aarch = (ROOT / ".github/workflows/aarch64-cross-compile.yml").read_text()
        self.assertIsNone(matrix.interface_matrices_error(workflow, aarch))
        for original, replacement in (
            ("engine: [native, hsm]", "engine: [native]"),
            ("profile: [default, full]", "profile: [full]"),
            ("api: [psa, pkcs11, tpm]", "api: [psa, tpm]"),
            ("WT_ENGINE: ${{ matrix.engine }}", "WT_ENGINE: native"),
            ("WT_INTERFACE_OS: ${{ matrix.os }}", "WT_INTERFACE_OS: zephyr"),
            ("WT_CRYPTO_PROFILE: ${{ matrix.profile }}", "WT_CRYPTO_PROFILE: full"),
        ):
            with self.subTest(replacement=replacement):
                self.assertIsNotNone(matrix.interface_matrices_error(
                    workflow.replace(original, replacement, 1), aarch))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    BUILD_DIR = args.build_dir.resolve()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    unittest.main(argv=["test_generator.py"], verbosity=1)
