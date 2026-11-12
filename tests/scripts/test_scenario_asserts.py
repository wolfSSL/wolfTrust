#!/usr/bin/env python3
# test_scenario_asserts.py
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

"""Every assertion the target judge declares is load-bearing.

For each port, each scenario it runs and each engine, the applicable checks
are turned into the smallest evidence that satisfies them (a boot log, a
trace log, a symbol file and the variables the runner would pass), which the
judge must accept. Then every check is mutated in turn (a required marker
removed or duplicated, a forbidden line injected, a fault address or stacked
SP moved, the SAU attribution dropped, a suite total or recorded result
changed, the exit status or the symbol taken away) and the judge must
refuse each mutation. A check that cannot be made to fail proves nothing,
and this test refuses it.
"""

import os
import re
import sys

try:
    import sre_parse
except ImportError:  # Python 3.13
    from re import _parser as sre_parse

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.normpath(os.path.join(HERE, "..", "target", "lib"))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, LIB)
import scenario_matrix  # noqa: E402
import scenarios  # noqa: E402

VARS = {"expected_measurement": "deadbeef00112233", "v2_measurement": "feedface44556677",
        "probe_addr": "0x20170000", "fault_addr": "0x30188000",
        "periph_ns": "0x40187000", "L3_SPM_RAM": "0x30188000",
        "L3_VAULT_BAND": "0x301d5000", "L3_ATTEST_BAND": "0x301d7000",
        "L3_HSM_BAND": "0x301d7800", "L3_CRYPTO_STACK_LO": "0x301f6000",
        "L3_CRYPTO_STACK_HI": "0x301f8000", "L3_ATTEST_STACK_LO": "0x301f8000",
        "L3_ATTEST_STACK_HI": "0x301fa000", "L3_VAULT_STACK_LO": "0x301ef000",
        "L3_VAULT_STACK_HI": "0x301f3000", "L3_SPM_PERIPHERAL": "0x50187000",
        "conf_want": os.path.join(REPO, "tests", "target", "ffm_ipc_results.txt"),
        "board": "RT700"}
with open(os.path.join(REPO, "tests", "upstream", "psa-arch-tests.rev")) as handle:
    VARS["conf_rev"] = handle.read().strip()


def example(pattern):
    """One string the regular expression matches, from its parse tree."""
    def walk(items):
        out = []
        for op, arg in items:
            name = str(op).split(".")[-1]
            if name == "LITERAL":
                out.append(chr(arg))
            elif name == "ANY":
                out.append("x")
            elif name == "AT":
                continue
            elif name == "IN":
                out.append(first_in(arg))
            elif name == "BRANCH":
                out.append(walk(arg[1][0]))
            elif name == "SUBPATTERN":
                out.append(walk(arg[-1]))
            elif name in ("MAX_REPEAT", "MIN_REPEAT"):
                lo, _, sub = arg
                out.append(walk(sub) * max(lo, 1))
            elif name == "NOT_LITERAL":
                out.append("x")
            else:
                raise SystemExit("unsupported regex construct %s in %r" % (name, pattern))
        return "".join(out)

    def first_in(arg):
        for op, val in arg:
            name = str(op).split(".")[-1]
            if name == "LITERAL":
                return chr(val)
            if name == "RANGE":
                return chr(val[0])
            if name == "CATEGORY":
                return "7"
            if name == "NEGATE":
                continue
        return "x"
    text = walk(sre_parse.parse(pattern))
    assert re.search(pattern, text, re.M), (pattern, text)
    return text


def substitute(text):
    return scenarios.substitute(text, VARS)


class Evidence(object):
    def __init__(self):
        self.lines = {"log": [], "trace": [], "guest0": []}
        self.syms = []
        self.var = dict(VARS)

    def add(self, where, line, n=1):
        where = "log" if where == "faults" else where
        self.lines[where].extend([line] * n)

    def logs(self, guest0_separate):
        logs = {"log": "\n".join(self.lines["log"]) + "\n",
                "trace": "\n".join(self.lines["trace"]) + "\n",
                "syms": "\n".join(self.syms) + "\n"}
        if guest0_separate:
            logs["guest0"] = "\n".join(self.lines["guest0"]) + "\n"
        else:
            logs["guest0"] = logs["log"] + "\n".join(self.lines["guest0"]) + "\n"
        return logs


def satisfy(ev, check):
    op = check["op"]
    if op == "info":
        return
    if op == "either":
        for c in check["options"][0]:
            satisfy(ev, c)
        return
    if op == "status":
        ev.var[check["var"]] = str(check["accept"][0])
        return
    if op == "symbol":
        ev.syms.append("20001000 T " + check["name"])
        return
    if op == "totals":
        passed = check["passed"] if check["passed"] is not None else (check["scheduled"] or 0)
        skipped = check["skipped"] if check["skipped"] is not None else 0
        ev.add("guest0", "TOTAL PASSED    : %d" % passed)
        ev.add("guest0", "TOTAL SKIPPED   : %d" % skipped)
        ev.add("guest0", "TOTAL FAILED    : %d" % check["failed"])
        return
    if op == "ledger":
        with open(ev.var["conf_want"]) as handle:
            for line in handle:
                if line.startswith("#") or not line.strip():
                    continue
                num, result = line.split()
                ev.add("guest0", "Num=%s Result=%s" % (num, result))
        return
    where = check["where"]
    key = "log" if where == "faults" else where
    if op in ("expect", "expect_re"):
        # At least one: a line another check already put there serves.
        line = substitute(check["text"]) if op == "expect" else example(substitute(check["re"]))
        if line not in ev.lines[key]:
            ev.add(where, line)
    elif op == "expect_n":
        ev.add(where, substitute(check["text"]), check["n"])
    elif op == "expect_n_re":
        ev.add(where, example(substitute(check["re"])), check["n"])
    elif op == "refute_re":
        return
    elif op == "faults_at":
        fault = "[MEMFAULT] pc=0x08001000 addr=%s" % check["addr"].lower()
        lines = ev.lines[key]
        present = [i for i, line in enumerate(lines) if line == fault]
        if check["lo"]:
            # Every existing fault at this address gets the prober's SP.
            for i in reversed(present):
                sp = "[MEMFAULT] sp=%s" % check["lo"]
                if i + 1 < len(lines) and lines[i + 1].startswith("[MEMFAULT] sp="):
                    lines[i + 1] = sp
                else:
                    lines.insert(i + 1, sp)
        for _ in range(check["n"] - len(present)):
            ev.add(where, fault)
            if check["lo"]:
                ev.add(where, "[MEMFAULT] sp=%s" % check["lo"])
    elif op == "sau_refusal":
        # The attribution follows the fault line the trace checks already
        # expect; a second copy would double their count.
        line = example(substitute(check["re"]))
        lines = ev.lines["log" if where == "faults" else where]
        if line in lines:
            lines.insert(lines.index(line) + 1, "  src=SAU")
        else:
            ev.add(where, line)
            ev.add(where, "  src=SAU")
    else:
        raise SystemExit("unknown check %s" % op)


def mutations(ev, check, guest0_separate):
    """Evidence variants that must each fail this check."""
    op = check["op"]
    base = ev.logs(guest0_separate)
    out = []

    def without(where, line, count=1):
        logs = dict(base)
        key = "log" if where == "faults" else where
        text = logs[key]
        for _ in range(count):
            text = text.replace(line + "\n", "", 1)
        logs[key] = text
        if key == "log" and not guest0_separate:
            logs["guest0"] = text + "\n".join(ev.lines["guest0"]) + "\n"
        return logs

    def with_extra(where, line):
        logs = dict(base)
        key = "log" if where == "faults" else where
        logs[key] = logs[key] + line + "\n"
        if key == "log" and not guest0_separate:
            logs["guest0"] = logs["log"] + "\n".join(ev.lines["guest0"]) + "\n"
        return logs

    if op in ("info",):
        return out
    if op == "either":
        logs = dict(base)
        for option in check["options"]:
            for c in option:
                if c["op"] in ("expect", "expect_n"):
                    line = substitute(c["text"])
                    key = "log" if c["where"] == "faults" else c["where"]
                    logs[key] = logs[key].replace(line + "\n", "")
                    if key == "log" and not guest0_separate:
                        logs["guest0"] = logs["log"] + "\n".join(ev.lines["guest0"]) + "\n"
        return [("every option broken", logs, ev.var)]
    if op == "status":
        refused = []
        for code in ("0", "1", "127", "99"):
            if int(code) not in check["accept"]:
                var = dict(ev.var)
                var[check["var"]] = code
                refused.append(("exit status " + code, base, var))
        return refused
    if op == "symbol":
        logs = dict(base)
        logs["syms"] = "20001000 T other_symbol\n"
        return [("symbol absent", logs, ev.var)]
    if op == "totals":
        logs = dict(base)
        logs["guest0"] = logs["guest0"].replace("TOTAL FAILED    : %d" % check["failed"],
                                                "TOTAL FAILED    : %d" % (check["failed"] + 1))
        out.append(("one test failed", logs, ev.var))
        if check["passed"] is not None or check["scheduled"] is not None:
            logs = dict(base)
            logs["guest0"] = re.sub(r"TOTAL PASSED    : (\d+)",
                                    lambda m: "TOTAL PASSED    : %d" % (int(m.group(1)) - 1),
                                    logs["guest0"])
            out.append(("one test missing", logs, ev.var))
        return out
    if op == "ledger":
        logs = dict(base)
        logs["guest0"] = re.sub(r"Result=([A-Za-z]+)", r"Result=\1X", logs["guest0"], count=1)
        out.append(("a recorded result reported differently", logs, ev.var))
        var = dict(ev.var)
        var["conf_rev"] = "0000000"
        out.append(("results recorded for another suite revision", base, var))
        return out
    where = check["where"]
    if op == "expect":
        out.append(("marker removed", without(where, substitute(check["text"])), ev.var))
    elif op == "expect_n":
        line = substitute(check["text"])
        out.append(("one occurrence removed", without(where, line), ev.var))
        out.append(("one occurrence added", with_extra(where, line), ev.var))
    elif op == "expect_re":
        out.append(("marker removed", without(where, example(substitute(check["re"]))), ev.var))
    elif op == "expect_n_re":
        line = example(substitute(check["re"]))
        out.append(("one occurrence removed", without(where, line), ev.var))
        out.append(("one occurrence added", with_extra(where, line), ev.var))
    elif op == "refute_re":
        out.append(("forbidden line injected", with_extra(where, example(substitute(check["re"]))), ev.var))
    elif op == "faults_at":
        line = "[MEMFAULT] pc=0x08001000 addr=%s" % check["addr"].lower()
        logs = dict(base)
        key = "log" if where == "faults" else where
        logs[key] = logs[key].replace(line, "[MEMFAULT] pc=0x08001000 addr=0x00000004", 1)
        out.append(("fault address moved", logs, ev.var))
        if check["lo"]:
            logs = dict(base)
            logs[key] = logs[key].replace("[MEMFAULT] sp=%s" % check["lo"], "[MEMFAULT] sp=0x00000000", 1)
            out.append(("stacked SP outside the prober's stack", logs, ev.var))
    elif op == "sau_refusal":
        logs = dict(base)
        logs["trace"] = logs["trace"].replace("  src=SAU\n", "", 1)
        out.append(("SAU attribution dropped", logs, ev.var))
    return out


def run_judge(port, scenario, engine, logs, var):
    result = scenarios.judge(port, scenario, "emulator", dict(logs), dict(var), engine)
    return result.failures == 0, result.lines


def main():
    checked = 0
    mutated = 0
    problems = []
    for port in sorted(scenario_matrix.PORTS):
        display = scenario_matrix.PORTS[port]["def"]["display"]
        for scenario in scenario_matrix.flat(port, "full", None):
            row = scenarios.SCENARIOS[scenario]
            for engine in row["engines"]:
                p = scenarios.plan(port, scenario, engine)
                guest0_separate = p["guests"][0] == "zephyr"
                var = dict(VARS)
                var["board"] = display
                var["trace_kind"] = p["trace"]
                ctx = scenarios.Ctx(port, scenario, "emulator", p["guests"], var)
                ev = Evidence()
                ev.var["board"] = display
                checks = []
                for block in p["applicable"]:
                    for check in scenarios.block_checks(ctx, block, p["end"]):
                        checks.append(check)
                        satisfy(ev, check)
                ok, lines = run_judge(port, scenario, engine, ev.logs(guest0_separate), ev.var)
                if not ok:
                    problems.append("%s/%s/%s: the satisfying evidence was refused:\n%s" %
                                    (port, scenario, engine,
                                     "\n".join(l for l in lines if "FAIL" in l)))
                    continue
                checked += len(checks)
                for check in checks:
                    for what, logs, var in mutations(ev, check, guest0_separate):
                        mutated += 1
                        ok, lines = run_judge(port, scenario, engine, logs, var)
                        if ok:
                            problems.append("%s/%s/%s: %r still passed with %s" %
                                            (port, scenario, engine, check["desc"], what))
    if problems:
        print("FAIL: scenario asserts\n" + "\n".join(problems))
        return 1
    print("PASS: scenario asserts (%d checks, %d mutations refused)" % (checked, mutated))
    return 0


if __name__ == "__main__":
    sys.exit(main())
