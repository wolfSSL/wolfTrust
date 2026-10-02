#!/usr/bin/env python3
# test_m33mu_console.py
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

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "target/lib/m33mu_console.py"
SPEC = importlib.util.spec_from_file_location("m33mu_console", HELPER)
CONSOLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSOLE)

PREFIX = (b"[00:00:00.063,000] \x1b[0m<inf> guest0_psa: "
          b"wolfTrust FF-M oversized-vector call rejecte")
TAIL = b"d st=-135\x1b[0m\r\n"
MARKER = b"wolfTrust FF-M oversized-vector call rejected st=-135"
BANNER = b"[UART] 40004800 attached to stdio\n"
# PR #52, run 36894209966, job 110477452533. The tail arrived after guest1.
INTERJECTION = (
    BANNER
    + b"freertos_guest1: alive\r\n"
    + b"freertos_guest1: ffm sha256 ok first=0x20\r\n"
    + b"freertos_guest1: ffm rng ok\r\n"
    + b"freertos_guest1: psa_crypto_init st=0\r\n"
    + b"freertos_guest1: psa rng ok\r\n"
    + b"freertos_guest1: psa hash ok\r\n"
    + b"freertos_guest1: ffm forged-handle rejected\r\n"
    + b"freertos_guest1: ffm oversized-vector rejected\r\n"
    + b"freertos_guest1: ffm cross-guest vector rejected\r\n"
    + b"freertos_guest1: ffm wrong-sid refused\r\n"
)


class ConsoleTests(unittest.TestCase):
    def test_ci_split_rejoins_exactly_without_modifying_the_raw_log(self):
        raw = PREFIX + INTERJECTION + TAIL
        self.assertNotIn(MARKER, raw)
        self.assertEqual(CONSOLE.guest0_console(raw), PREFIX + TAIL)
        self.assertIn(b"freertos_guest1: ffm oversized-vector rejected", raw)

    def test_missing_marker_bytes_still_fail(self):
        for index in range(len(MARKER)):
            with self.subTest(index=index):
                damaged = MARKER[:index] + MARKER[index + 1:]
                split = len(damaged) // 2
                raw = damaged[:split] + INTERJECTION + damaged[split:] + b"\n"
                self.assertNotIn(MARKER, CONSOLE.guest0_console(raw))
        self.assertNotIn(MARKER, CONSOLE.guest0_console(PREFIX + INTERJECTION))

    def test_unrelated_lines_do_not_form_a_marker(self):
        for ending in (b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                raw = PREFIX + ending + INTERJECTION + TAIL
                self.assertNotIn(MARKER, CONSOLE.guest0_console(raw))

    def test_complete_interjections_at_every_marker_position(self):
        for index in range(len(MARKER) + 1):
            for injection in (BANNER, INTERJECTION,
                              b"freertos_guest1: heartbeat 0\n"):
                with self.subTest(index=index, injection=injection):
                    raw = MARKER[:index] + injection + MARKER[index:] + b"\n"
                    self.assertEqual(CONSOLE.guest0_console(raw), MARKER + b"\n")

    def test_banner_inside_guest1_record(self):
        raw = PREFIX + b"freertos_guest1: heart" + BANNER + b"beat 0\n" + TAIL
        self.assertEqual(CONSOLE.guest0_console(raw), PREFIX + TAIL)

    def test_conformance_totals_keep_their_line_boundaries(self):
        raw = (b"TOTAL PASSED    : 85\r\nTOTAL SK" + INTERJECTION
               + b"IPPED   : 4\r\nTOTAL FAILED    : 0\r\n")
        expected = (b"TOTAL PASSED    : 85\r\nTOTAL SKIPPED   : 4\r\n"
                    b"TOTAL FAILED    : 0\r\n")
        self.assertEqual(CONSOLE.guest0_console(raw), expected)

    def test_confboot_pipeline_reads_reconstructed_per_test_results(self):
        target = HELPER.parent.parent
        expected = b"".join(
            line + b"\n" for line in
            (target / "ffm_ipc_results.txt").read_bytes().splitlines()
            if line and not line.startswith(b"#")
        )
        raw = b""
        for line in expected.splitlines():
            num, result = line.split()
            raw += (b"Num=" + num[:1] + INTERJECTION + num[1:]
                    + b" Result=" + result[:3] + BANNER + result[3:]
                    + b"\r\n")
        # Exercise the runner's actual extraction pipeline without booting.
        runner = (target / "run_m33mu_scenario.sh").read_text()
        pipeline = runner.split('\n    conf_got=', 1)[1]
        pipeline = 'conf_got=' + pipeline.split('\n    if grep -v', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "build").mkdir()
            (repo / "raw.log").write_bytes(raw)
            (repo / "guest0.log").write_bytes(CONSOLE.guest0_console(raw))
            script = ('set -euo pipefail\nrepo=$1\nlog="$repo/raw.log"\n'
                      'guest0_log="$repo/guest0.log"\n' + pipeline)
            completed = subprocess.run(
                ["bash", "-c", script, "confboot-test", str(repo)],
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((repo / "build/ffm-ipc-results.txt").read_bytes(),
                             expected)

    def test_pty_and_crlf_banner(self):
        banner = b"[UART] 44002400 attached to /dev/pts/17\r\n"
        self.assertEqual(CONSOLE.guest0_console(PREFIX + banner + TAIL), PREFIX + TAIL)

    def test_incomplete_or_unrecognized_records_are_preserved(self):
        for raw in (BANNER[:-1], b"freertos_guest1: alive",
                    b"[UART] 40004800 attached to stdio EXTRA\n",
                    b"[UART] 4000480 attached to stdio\n",
                    b"freertos_guest0: alive\n"):
            with self.subTest(raw=raw):
                self.assertEqual(CONSOLE.guest0_console(raw), raw)

    def test_fault_and_unrelated_bytes_are_preserved(self):
        raw = b"prefix\xff\r\n[MEMFAULT] addr=0x30028000\n[HARDFLT]\nHardFault\n"
        self.assertEqual(CONSOLE.guest0_console(raw), raw)

    def test_guest1_alone_cannot_supply_guest0_marker(self):
        raw = b"freertos_guest1: " + MARKER + b"\n"
        self.assertNotIn(MARKER, CONSOLE.guest0_console(raw))

    def test_cli_keeps_raw_file_and_exits_nonzero_for_missing_input(self):
        raw = PREFIX + INTERJECTION + TAIL
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.log"
            path.write_bytes(raw)
            result = subprocess.run([sys.executable, str(HELPER), str(path)],
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, PREFIX + TAIL)
            self.assertEqual(path.read_bytes(), raw)
            missing = subprocess.run([sys.executable, str(HELPER), str(path) + ".missing"],
                                     capture_output=True)
            self.assertNotEqual(missing.returncode, 0)


if __name__ == "__main__":
    unittest.main()
