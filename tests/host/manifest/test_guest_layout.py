#!/usr/bin/env python3
"""Tests for the build-time guest manifest layout check."""

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CHECKER_PATH = ROOT / "tools" / "manifest" / "check_guest_layout.py"
SPEC = importlib.util.spec_from_file_location("check_guest_layout", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def guest(domain_id, base, size):
    return {
        "id": domain_id,
        "domain_class": 2,
        "entry_point": base,
        "memory_resources": [
            {"base": base, "size": size, "attributes": 5},
            {"base": 0x20000000, "size": 0x1000, "attributes": 19},
        ],
    }


class GuestLayoutTests(unittest.TestCase):
    def setUp(self):
        self.expected = {1: (0x080A0000, 0x40000),
                         2: (0x080E0000, 0x20000)}
        self.manifest = {"domains": [
            {"id": 0, "domain_class": 0},
            guest(1, *self.expected[1]),
            guest(2, *self.expected[2]),
        ]}

    def test_matching_layout_passes(self):
        self.assertEqual(CHECKER.check_layout(self.manifest, self.expected), [])

    def test_wrong_base_fails(self):
        self.manifest["domains"][1]["memory_resources"][0]["base"] += 0x1000
        self.assertTrue(CHECKER.check_layout(self.manifest, self.expected))

    def test_wrong_size_fails(self):
        self.manifest["domains"][1]["memory_resources"][0]["size"] //= 2
        self.assertTrue(CHECKER.check_layout(self.manifest, self.expected))

    def test_entry_point_must_be_vector_base(self):
        self.manifest["domains"][1]["entry_point"] += 4
        self.assertTrue(CHECKER.check_layout(self.manifest, self.expected))

    def test_multiple_executable_regions_fail(self):
        self.manifest["domains"][1]["memory_resources"].append(
            {"base": 0x08100000, "size": 0x1000, "attributes": 5})
        self.assertTrue(CHECKER.check_layout(self.manifest, self.expected))

    def test_unexpected_guest_fails(self):
        self.manifest["domains"].append(guest(3, 0x08100000, 0x10000))
        self.assertTrue(CHECKER.check_layout(self.manifest, self.expected))

    def test_missing_region_fields_fail_cleanly(self):
        resource = self.manifest["domains"][1]["memory_resources"][0]
        for field in ("base", "size", "attributes"):
            with self.subTest(field=field):
                saved = resource.pop(field)
                self.assertTrue(
                    CHECKER.check_layout(self.manifest, self.expected))
                resource[field] = saved

    def test_non_integer_region_fields_fail_cleanly(self):
        resource = self.manifest["domains"][1]["memory_resources"][0]
        for field in ("base", "size", "attributes"):
            with self.subTest(field=field):
                saved = resource[field]
                resource[field] = "invalid"
                self.assertTrue(
                    CHECKER.check_layout(self.manifest, self.expected))
                resource[field] = saved

    def test_invalid_entry_point_fails_cleanly(self):
        domain = self.manifest["domains"][1]
        for entry_point in (None, "invalid"):
            with self.subTest(entry_point=entry_point):
                domain["entry_point"] = entry_point
                self.assertTrue(
                    CHECKER.check_layout(self.manifest, self.expected))

    def test_non_integer_domain_id_fails_cleanly(self):
        self.manifest["domains"][1]["id"] = []
        self.assertTrue(CHECKER.check_layout(self.manifest, self.expected))


if __name__ == "__main__":
    unittest.main()
