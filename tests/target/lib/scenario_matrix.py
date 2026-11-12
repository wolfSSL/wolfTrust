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

Each port registers itself in port/<soc>/port.json and this module is the one
reader of that registry. The M33MU workflow's plan job reads the whole run
with --ci-plan (the event, the PR labels, and the dispatch input pick each
port's tier), `make test-target` reads one port's scenario list with --flat,
and the cross-build jobs read --build-plan, so a port is registered in
exactly one place.

    GITHUB_EVENT_NAME=pull_request PR_LABELS="ci:<port>" scenario_matrix.py --ci-plan
    scenario_matrix.py --port <port> --tier smoke --json
    scenario_matrix.py --port <port> --tier full --engine native --flat
    scenario_matrix.py --port <port> --get ci.mcuxsdk_board
    scenario_matrix.py --build-plan
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

PORT_ROOT = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "port"))
REPO_ROOT = os.path.dirname(PORT_ROOT)
REQUIRED_KEYS = ("name", "display", "board", "arch", "guide", "ci", "build",
                 "m33mu")


def load_ports(root=PORT_ROOT):
    """Every port/<soc>/port.json, keyed by port name; a port directory with
    no registry entry is an error, so nothing exists unregistered.
    smoke: the per-PR set (one job per scenario and engine). groups: the full
    tier, packed so each job builds the emulator and wolfBoot once.
    label_only: an unlabeled pull request runs none of this port."""
    ports = {}
    for name in sorted(os.listdir(root)):
        if name == "common" or not os.path.isdir(os.path.join(root, name)):
            continue
        path = os.path.join(root, name, "port.json")
        if not os.path.isfile(path):
            raise SystemExit("port/%s has no port.json" % name)
        with open(path) as handle:
            data = json.load(handle)
        missing = [key for key in REQUIRED_KEYS if key not in data]
        if missing or data["name"] != name:
            raise SystemExit("port/%s/port.json: name mismatch or missing %s" %
                             (name, " ".join(missing)))
        m33mu = data["m33mu"]
        ports[name] = {
            "label": data["ci"]["label"],
            "label_only": bool(data["ci"].get("label_only", False)),
            "image": data["ci"]["image"],
            "arm": m33mu["arm"],
            "smoke": tuple(m33mu["smoke"]),
            "groups": tuple((key, text) for key, text in m33mu["groups"]),
            "l3_exempt": dict(m33mu.get("l3_exempt", {})),
            "def": data,
        }
    return ports


PORTS = load_ports()


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
    tier unless its label (or ci:all) asks for the full one, and a label_only
    port runs only when labelled; a push, the schedule, or a dispatch gets the
    full tier of the selected ports."""
    out = []
    if (event == "workflow_dispatch" and port_input not in ("", "all") and
            port_input not in PORTS):
        raise SystemExit("unknown port %r; registered: %s" %
                         (port_input, " ".join(sorted(PORTS))))
    for port in sorted(PORTS):
        label = PORTS[port]["label"]
        if event == "pull_request":
            full = ("ci:all" in labels or "ci:m33mu" in labels or
                    label in labels)
            if not full and PORTS[port].get("label_only"):
                continue
        elif event == "workflow_dispatch":
            full = port_input in ("", "all", port)
            if not full:
                continue
        else:
            full = True
        out.extend(entries(port, "full" if full else "smoke", None))
    return out


def build_plan():
    """Every secure-image cross-build: the port, the engine, the attestation
    setting its default build uses, the variants it also builds, and the
    .vectors address its default layout must keep ("" when unchecked)."""
    out = []
    for port in sorted(PORTS):
        build = PORTS[port]["def"]["build"]
        for engine in build["engines"]:
            out.append({"port": port, "engine": engine,
                        "attest_cose": build["attest_cose"],
                        "variants": list(build.get("variants", [])),
                        "vectors": build.get("vectors", "")})
    return out


def get_field(port, dotted):
    """One registry value by dotted path, for shell consumers."""
    value = PORTS[port]["def"]
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            raise SystemExit("%s has no field %s" % (port, dotted))
        value = value[key]
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value)


def plan_tiers(event, labels, port_input):
    tiers = {}
    for e in ci_plan(event, labels, port_input):
        tiers.setdefault(e["port"], set()).add(e["tier"])
    for port, seen in tiers.items():
        if len(seen) != 1:
            raise SystemExit("%s runs two tiers in one plan" % port)
    return dict((p, next(iter(s))) for p, s in tiers.items())


def routing_gaps():
    """The routing rule as properties over the registry: an unlabeled pull
    request runs every always-on port at smoke; a port's label runs that port
    full and the rest as unlabeled; ci:all, ci:m33mu, a push, the schedule and
    a dispatch with no port run every port full; a dispatch names one port;
    an unknown dispatch port is refused."""
    ports = sorted(PORTS)
    always = dict((p, "smoke") for p in ports if not PORTS[p]["label_only"])
    everything = dict((p, "full") for p in ports)
    checks = [("pull_request", [], "", always)]
    for port in ports:
        want = dict(always)
        want[port] = "full"
        checks.append(("pull_request", [PORTS[port]["label"]], "", want))
    if len(ports) > 1:
        want = dict(always)
        want[ports[0]] = "full"
        want[ports[1]] = "full"
        checks.append(("pull_request",
                       [PORTS[ports[0]]["label"], PORTS[ports[1]]["label"]],
                       "", want))
    for labels in (["ci:all"], ["ci:m33mu"]):
        checks.append(("pull_request", labels, "", everything))
    for event in ("push", "schedule"):
        checks.append((event, [], "", everything))
    for port_input in ("", "all"):
        checks.append(("workflow_dispatch", [], port_input, everything))
    for port in ports:
        checks.append(("workflow_dispatch", [], port, {port: "full"}))
    gaps = []
    for event, labels, port_input, want in checks:
        got = plan_tiers(event, labels, port_input)
        if got != want:
            gaps.append("ci_plan(%s, %r, %r) = %r, expected %r" %
                        (event, labels, port_input, got, want))
    try:
        ci_plan("workflow_dispatch", [], "__no_such_port__")
        gaps.append("an unknown dispatch port was accepted")
    except SystemExit:
        pass
    return gaps


# Sources every port takes from port/common/<arch>/ and may not carry itself.
SHARED_PORT_SOURCES = ("partitions.c", "l3_port.h", "secure.ld", "hsm_flash.c",
                       "hsm_flash.h", "hsm_flash_ctx.c", "rng_entropy.c")


def registry_gaps():
    """A registered port has its build fragment, its guide and its shared
    architecture layer, no copy of a shared source, a unique CI label and
    runner arm, a usable image, known engines, and a smoke set drawn from its
    full tier."""
    gaps = []
    labels = {}
    arms = {}
    for port in sorted(PORTS):
        data = PORTS[port]["def"]
        needed = (("mk/target-%s.mk" % port, "build fragment"),
                  (data["guide"], "guide"),
                  ("port/common/%s" % data["arch"], "shared architecture layer"))
        for rel, what in needed:
            if not os.path.exists(os.path.join(REPO_ROOT, rel)):
                gaps.append("%s: missing %s %s" % (port, what, rel))
        # The build compiles a port's own copy of a shared source before the
        # shared one, so a leftover copy would silently replace it.
        for shared in SHARED_PORT_SOURCES:
            if os.path.exists(os.path.join(REPO_ROOT, "port", port, shared)):
                gaps.append("%s: port/%s/%s shadows port/common/%s/%s" %
                            (port, port, shared, data["arch"], shared))
        for field, table in (("label", labels), ("arm", arms)):
            value = PORTS[port][field]
            if not value:
                gaps.append("%s: empty %s" % (port, field))
            elif value in table:
                gaps.append("%s and %s share %s %s" %
                            (table[value], port, field, value))
            table[value] = port
        if not PORTS[port]["image"]:
            gaps.append("%s: empty image" % port)
        full = set(flat(port, "full", None))
        for scenario in PORTS[port]["smoke"]:
            if scenario not in full:
                gaps.append("%s: smoke scenario %s is not in the full tier" %
                            (port, scenario))
        engines = data["build"].get("engines", [])
        if not engines or any(e not in ENGINES for e in engines):
            gaps.append("%s: bad engines %r" % (port, engines))
    return gaps


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
    """The registry, the routing properties, the engine rule and the level 3
    bar, run by the select job and by make test."""
    gaps = registry_gaps() + routing_gaps()
    for port in sorted(PORTS):
        for tier in ("smoke", "full"):
            for e in entries(port, tier, None):
                if e["engine"] == "native" and all(
                        s in HSM_ONLY for s in e["key"].split()):
                    gaps.append("native job for the hsm-only %s" % e["key"])
                if e["engine"] not in ENGINES or e["image"] == "":
                    gaps.append("bad entry %r" % e)
        gaps.extend(l3_gaps(port))
    return "; ".join(gaps) if gaps else None


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
    mode.add_argument("--build-plan", action="store_true",
                      help="every port's secure-image cross-builds")
    mode.add_argument("--get", metavar="FIELD",
                      help="one registry value of --port by dotted path")
    mode.add_argument("--selftest", action="store_true",
                      help="check the registry and the event/label routing")
    args = parser.parse_args()

    if args.list_ports:
        print(" ".join(sorted(PORTS)))
        return 0
    if args.build_plan:
        print(json.dumps(build_plan()))
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
    elif args.get:
        print(get_field(args.port, args.get))
    elif args.arm:
        print(PORTS[args.port]["arm"])
    elif args.flat:
        print(" ".join(flat(args.port, args.tier, args.engine)))
    else:
        print(json.dumps(entries(args.port, args.tier, args.engine)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
