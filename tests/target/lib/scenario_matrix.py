#!/usr/bin/env python3
# scenario_matrix.py
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

"""The M33MU scenario matrix per port and tier.

Each port's scenario groups live here once. The M33MU workflow's plan job
reads the whole run with --ci-plan (the event, the PR labels, and the dispatch
input pick each port's tier), and `make test-target` reads one port's
scenario list with --flat, so a scenario is registered in exactly one place.

    GITHUB_EVENT_NAME=pull_request PR_LABELS="ci:rt700" scenario_matrix.py --ci-plan
    scenario_matrix.py --port mimxrt700 --tier smoke --json
    scenario_matrix.py --port stm32h563 --tier full --engine native --flat
"""

import argparse
import json
import os
import sys

ENGINES = ("native", "hsm")

# Scenarios whose Secure-image probe or client wire lives only in the wolfHSM
# engine: the native engine does not link it, so the behaviour under test does
# not exist there.
HSM_ONLY = frozenset(("hsmattackneg", "hsmpinneg", "hsmfaultneg"))

# The isolation level 3 bar: every port's full tier runs each of these, or
# names it in its "l3_exempt" map with the reason (an open issue) it cannot.
L3_REQUIRED = frozenset((
    "crossdomain", "keystoreneg", "deputyneg", "hsmpinneg", "hsmfaultneg",
    "bandneg1", "bandneg2", "bandneg3", "bandneg4", "bandneg5", "bandneg6",
    "restartneg1", "restartneg2", "restartneg3",
    "manifestneg2", "manifestneg3", "periphspneg",
    "fpneg", "sealneg", "sealhaltneg", "sealbootneg", "sealpivotneg",
    "mspovfneg", "xnneg", "svcneg",
))

# smoke: the per-PR set (one job per scenario and engine). groups: the full
# tier, packed so each job builds the emulator and wolfBoot once.
PORTS = {
    "stm32h563": {
        "label": "ci:h5",
        "arm": "m33mu",
        "image": "ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.15",
        "smoke": ("positive", "gtzcneg", "crossdomain", "bothpsa", "confboot",
                  "devcrypto"),
        "groups": (
            ("positive", "Positive lifecycle"),
            ("bothpsa", "Both-OS PSA parity (Zephyr + FreeRTOS)"),
            ("bothiso", "Both-OS FF-M isolation negatives"),
            ("restart", "Guest restart recovery"),
            ("crossdomain", "Cross-domain isolation (L3)"),
            ("keystoreneg", "Keystore-band isolation (L3)"),
            ("deputyneg", "Keystore-flash privileged-deputy refused (L3)"),
            ("hsmpinneg", "wolfHSM server pointers pinned before the pump (L3)"),
            ("bandneg1 bandneg2 bandneg3 bandneg4 bandneg5 bandneg6",
             "Partition band-to-band isolation negatives (L3)"),
            ("restartneg1 restartneg2 restartneg3",
             "Partitions restart on a reset band (L3)"),
            ("spfaultneg", "Graceful SP fault recovery"),
            ("hsmfaultneg", "HSM tasklet fault containment"),
            ("panicneg", "Secure-caller misuse panic"),
            ("confboot", "FF-M IPC conformance (85/4)"),
            ("devstorage", "dev_apis Storage (s001-s017)"),
            ("devcrypto", "dev_apis Crypto (c001-c080)"),
            ("devattest", "dev_apis Initial Attestation (a001, shim)"),
            ("devattestqcbor", "dev_apis Initial Attestation (a001, QCBOR)"),
            ("attestneg", "Attestation negatives (IPC + tamper)"),
            ("hsmattackneg", "wolfHSM cross-namespace + NVM relay negatives"),
            ("authneg", "Authenticated launch fail-closed"),
            ("rollbackneg", "Anti-rollback downgrade refused"),
            ("vaultrecover", "Vault recovery self-heal"),
            ("vaultrecoversec", "Vault recovery fail-closed"),
            ("fwustage", "PSA Firmware Update staging"),
            ("remeasureneg", "Runtime re-measurement quarantine"),
            ("bootupdate", "Full boot-and-update swap gate"),
            ("vnet", "wolfIP virtual network (mediated ping)"),
            ("vnetneg", "Confined VNET isolation negatives"),
            ("manifestneg", "Corrupted-manifest activation refused"),
            ("manifestneg2", "Level 2 manifest refused at boot"),
            ("manifestneg3", "Overlapping partition tables refused at boot"),
            ("gtzcneg", "NS MPU bypass cannot reach peer guest RAM"),
            ("periphneg", "NS peripheral and DMA access to Secure resources"),
            ("periphspneg", "Partition read of an SPM peripheral faults (L3)"),
            ("spbudgetneg", "SP restart-budget exhaustion escalates"),
            ("revneg", "Engineering-sample silicon refused"),
            ("fpneg", "FP isolation (partition FP faults, contained)"),
            ("sealneg", "Stack seal damage faults only its partition"),
            ("sealhaltneg", "Stack seal damage at dispatch halts"),
            ("sealbootneg", "Damaged main-stack seal refuses to boot"),
            ("sealpivotneg", "Blocking wait stacked on the seal stays contained"),
            ("mspovfneg", "SPM main-stack overflow halts fail-closed"),
            ("xnneg", "Privileged execution from SPM RAM denied"),
            ("svcneg", "Partition guest-return SVC panics only that partition"),
        ),
        "l3_exempt": {},
    },
    "mimxrt700": {
        "label": "ci:rt700",
        "arm": "rt700-m33mu",
        "image": "ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25",
        "smoke": ("positive", "ahbscneg", "crossdomain", "bothpsa", "confboot",
                  "devcrypto"),
        "groups": (
            ("positive", "RT700 positive lifecycle (SAU guest windows)"),
            ("ahbscneg", "RT700 cross-guest store faults and is contained"),
            ("restart authneg", "RT700 guest restart budget and launch refusal"),
            ("rollbackneg remeasureneg manifestneg spbudgetneg",
             "RT700 secure verdict negatives"),
            ("crossdomain keystoreneg", "RT700 SP domain isolation negatives"),
            ("spfaultneg panicneg", "RT700 SP fault and panic recovery"),
            ("fpneg", "RT700 FP isolation (partition FP faults, contained)"),
            ("sealbootneg", "RT700 damaged main-stack seal refuses to boot"),
            ("bothpsa bothiso", "RT700 both-guest PSA lifecycle and isolation"),
            ("attestneg fwustage",
             "RT700 attestation negatives and FWU staging"),
            ("hsmattackneg",
             "RT700 wolfHSM cross-namespace + NVM relay negatives"),
            ("confboot", "RT700 FF-M IPC conformance (85/4)"),
            ("devstorage devattest devattestqcbor",
             "RT700 dev_apis storage and attestation conformance"),
            ("devcrypto vaultrecover vaultrecoversec",
             "RT700 dev_apis crypto conformance and vault recovery"),
            ("periphneg", "RT700 NS read of the SPM's TRNG refused by the SAU"),
            ("deputyneg", "RT700 keystore-flash privileged deputy refused (L3)"),
            ("hsmpinneg hsmfaultneg",
             "RT700 wolfHSM pointer pin and tasklet fault containment (L3)"),
            ("bandneg1 bandneg2 bandneg3 bandneg4 bandneg5 bandneg6",
             "RT700 partition band-to-band isolation negatives (L3)"),
            ("restartneg1 restartneg2 restartneg3",
             "RT700 partitions restart on a reset band (L3)"),
            ("periphspneg manifestneg2 manifestneg3",
             "RT700 SPM peripheral and manifest level negatives (L3)"),
            ("sealneg sealhaltneg sealpivotneg",
             "RT700 stack seal containment and halt (L3)"),
            ("mspovfneg xnneg svcneg",
             "RT700 SPM stack, execute-never and SVC misuse (L3)"),
        ),
        "l3_exempt": {},
    },
}


def group_name(port, scenario):
    for key, name in PORTS[port]["groups"]:
        if key.split() == [scenario]:
            return name
    return scenario


def engines_for(scenarios, engine):
    engines = ("hsm",) if all(s in HSM_ONLY for s in scenarios) else ENGINES
    return [e for e in engines if engine is None or e == engine]


def entry(port, tier, engine, key, name):
    port_def = PORTS[port]
    # Check names follow wolfBoot's <device>_<test> slugs.
    job = "_".join([port] + key.split() + [engine])
    return {"port": port, "tier": tier, "engine": engine, "key": key,
            "name": name, "job": job, "image": port_def["image"],
            "arm": port_def["arm"]}


def entries(port, tier, engine):
    port_def = PORTS[port]
    out = []
    if tier == "smoke":
        for scenario in port_def["smoke"]:
            for eng in engines_for([scenario], engine):
                out.append(entry(port, tier, eng, scenario,
                                 group_name(port, scenario)))
    else:
        for key, name in port_def["groups"]:
            for eng in engines_for(key.split(), engine):
                out.append(entry(port, tier, eng, key, name))
    return out


def ci_plan(event, labels, port_input):
    """Every job of one workflow run: a pull request gets each port's smoke
    tier unless its label (or ci:all) asks for the full one; a push, the
    schedule, or a dispatch gets the full tier of the selected ports."""
    out = []
    for port in sorted(PORTS):
        label = PORTS[port]["label"]
        if event == "pull_request":
            full = ("ci:all" in labels or "ci:m33mu" in labels or
                    label in labels)
        elif event == "workflow_dispatch":
            full = port_input in ("", "all", port)
            if not full:
                continue
        else:
            full = True
        out.extend(entries(port, "full" if full else "smoke", None))
    return out


SELFTEST = (
    ("pull_request", "", "", "mimxrt700:smoke stm32h563:smoke"),
    ("pull_request", "ci:rt700", "", "mimxrt700:full stm32h563:smoke"),
    ("pull_request", "ci:h5", "", "mimxrt700:smoke stm32h563:full"),
    ("pull_request", "ci:all", "", "mimxrt700:full stm32h563:full"),
    ("pull_request", "ci:m33mu", "", "mimxrt700:full stm32h563:full"),
    ("pull_request", "ci:h5 ci:rt700", "", "mimxrt700:full stm32h563:full"),
    ("push", "", "", "mimxrt700:full stm32h563:full"),
    ("schedule", "", "", "mimxrt700:full stm32h563:full"),
    ("workflow_dispatch", "", "", "mimxrt700:full stm32h563:full"),
    ("workflow_dispatch", "", "all", "mimxrt700:full stm32h563:full"),
    ("workflow_dispatch", "", "mimxrt700", "mimxrt700:full"),
    ("workflow_dispatch", "", "stm32h563", "stm32h563:full"),
)


def l3_gaps(port):
    """Problems with a port's level 3 bar: a required scenario neither run
    nor exempted, an exemption with no reason, or a stale exemption."""
    port_def = PORTS[port]
    exempt = port_def.get("l3_exempt", {})
    run = set(flat(port, "full", None))
    gaps = []
    for scenario in sorted(L3_REQUIRED):
        if scenario not in run and not exempt.get(scenario, "").strip():
            gaps.append("%s does not run level 3 scenario %s" %
                        (port, scenario))
    for scenario in sorted(exempt):
        if scenario not in L3_REQUIRED:
            gaps.append("%s exempts %s, which is not a level 3 scenario" %
                        (port, scenario))
        elif scenario in run:
            gaps.append("%s runs %s but still exempts it" % (port, scenario))
    return gaps


def selftest():
    """The routing table above, the engine rule and the level 3 bar, run by
    the select job."""
    for event, labels, port_input, expect in SELFTEST:
        got = " ".join(sorted(set(e["port"] + ":" + e["tier"] for e in
                                  ci_plan(event, labels.split(), port_input))))
        if got != expect:
            return "ci_plan(%s, %r, %r) = %s, expected %s" % (
                event, labels, port_input, got, expect)
    for port in sorted(PORTS):
        for tier in ("smoke", "full"):
            for e in entries(port, tier, None):
                if e["engine"] == "native" and all(
                        s in HSM_ONLY for s in e["key"].split()):
                    return "native job for the hsm-only %s" % e["key"]
                if e["engine"] not in ENGINES or e["image"] == "":
                    return "bad entry %r" % e
        gaps = l3_gaps(port)
        if gaps:
            return "; ".join(gaps)
    return None


def flat(port, tier, engine):
    seen = []
    for entry in entries(port, tier, engine):
        for scenario in entry["key"].split():
            if scenario in HSM_ONLY and engine == "native":
                continue
            if scenario not in seen:
                seen.append(scenario)
    return seen


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", choices=sorted(PORTS))
    parser.add_argument("--tier", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--engine", choices=ENGINES)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true",
                      help="matrix include list for the workflow")
    mode.add_argument("--flat", action="store_true",
                      help="space-separated scenario list for run_suite.sh")
    mode.add_argument("--image", action="store_true",
                      help="the port's CI container image")
    mode.add_argument("--arm", action="store_true",
                      help="the port's run_suite.sh arm")
    mode.add_argument("--list-ports", action="store_true")
    mode.add_argument("--ci-plan", action="store_true",
                      help="the whole run's include list from GITHUB_EVENT_NAME, "
                           "PR_LABELS, and PORT_INPUT")
    mode.add_argument("--selftest", action="store_true",
                      help="check the event/label routing table")
    args = parser.parse_args()

    if args.list_ports:
        print(" ".join(sorted(PORTS)))
        return 0
    if args.selftest:
        failure = selftest()
        if failure is not None:
            print("scenario_matrix selftest: " + failure, file=sys.stderr)
            return 1
        print("scenario_matrix selftest ok")
        return 0
    if args.ci_plan:
        print(json.dumps(ci_plan(os.environ.get("GITHUB_EVENT_NAME", ""),
                                 os.environ.get("PR_LABELS", "").split(),
                                 os.environ.get("PORT_INPUT", ""))))
        return 0
    if args.port is None:
        parser.error("--port is required")
    if args.image:
        print(PORTS[args.port]["image"])
    elif args.arm:
        print(PORTS[args.port]["arm"])
    elif args.flat:
        print(" ".join(flat(args.port, args.tier, args.engine)))
    else:
        print(json.dumps(entries(args.port, args.tier, args.engine)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
