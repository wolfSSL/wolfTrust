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
    WT_PROFILE=default scenario_matrix.py --port <port> --profile-of positive

Every group also names the build profile its Secure image is built with:
"full" turns every add-on on (tests/target/lib/profile.sh holds the flags),
"default" is the lean image the Makefile builds with no options. A port's
m33mu "smoke" and "groups" are its full profile; m33mu "default" holds the
same two lists for the lean image. A runner asks --profile-of which profile a
scenario runs on.
"""

import argparse
import json
import os
import sys

ENGINES = ("native", "hsm")
PROFILES = ("default", "full")

# Scenarios that need a second guest or an add-on the lean default leaves
# out; they never run on the default profile.
NEEDS_FULL = frozenset((
    "restart", "sauneg", "ahbscneg", "gtzcneg", "guestisoneg", "bothpsa",
    "bothiso", "fwustage", "bootupdate", "confboot", "devstorage",
    "devcrypto", "devattest", "devattestqcbor", "vaultrecover",
    "vaultrecoversec", "vnet", "vnetneg", "hsmfaultneg",
))

# Scenarios whose Secure-image probe or client wire lives only in the wolfHSM
# engine: the native engine does not link it, so the behaviour under test does
# not exist there.
HSM_ONLY = frozenset(("hsmattackneg", "hsmpinneg", "hsmfaultneg"))
NATIVE_ONLY = frozenset(("nativewire", "nativewireasm", "devcryptolocal"))
ENGINE_ONLY = {"hsm": HSM_ONLY, "native": NATIVE_ONLY}

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

# The AArch64 QEMU lane. Each cell is one qemu-system-aarch64 job; a job runs
# the suite scenarios or the FF-A ACS groups on one crypto engine. family gates
# the ci:qemu-virt and ci:qemu-versal labels; ci:aarch64 and ci:all run every
# cell. The runner self-skips a scenario a cell or engine does not support, so
# one list serves every cell.
QEMU_A_IMAGE = "ghcr.io/wolfssl/wolfboot-ci-aarch64:v1.15"

QEMU_A_FAMILIES = {"qemu-virt": "ci:qemu-virt", "qemu-versal": "ci:qemu-versal"}

QEMU_A_CELLS = (
    {"name": "virt-gicv2-a35", "slug": "virt_gicv2_a35", "machine": "virt",
     "target": "qemuvirt", "gic": 2, "cpu": "cortex-a35", "smp": 2,
     "family": "qemu-virt"},
    {"name": "virt-gicv3-a72", "slug": "virt_gicv3_a72", "machine": "virt",
     "target": "qemuvirt", "gic": 3, "cpu": "cortex-a72", "smp": 2,
     "family": "qemu-virt"},
    {"name": "versal-virt", "slug": "versal_virt", "machine": "versal-virt",
     "target": "versal", "gic": 3, "cpu": "cortex-a72", "smp": 4,
     "family": "qemu-versal",
     "l3_exempt": {
         "secramneg": "xlnx-versal-virt models no XMPU to fence Secure RAM "
                      "from the Normal world (#45)",
         "periphneg": "xlnx-versal-virt models no XPPU to fence the SPM's "
                      "devices from the Normal world (#45)"}},
)

# Isolation level 3 scenarios every AArch64 port runs in its full tier; a cell
# that cannot names it in its "l3_exempt" map with the reason (an open issue).
QEMU_A_L3_REQUIRED = frozenset((
    "crossdomain", "spfaultneg", "manifestneg", "manifestneg2",
    "manifestneg3", "keystoreneg", "bandneg1", "bandneg2", "bandneg3",
    "bandneg4", "bandneg5", "bandneg6", "periphspneg", "restartneg1",
    "restartneg2", "restartneg3", "spbudgetneg", "panicneg", "svcneg",
    "fpneg", "mspovfneg", "xnneg", "secramneg", "periphneg", "hsmpinneg",
))

QEMU_A_SUITE = (
    "smoke", "boot", "boot-smp2", "positive-secure", "crossdomain",
    "spfaultneg", "tablesneg", "proofneg", "manifestneg", "manifestneg2",
    "manifestneg3", "keystoreneg", "bandneg1", "bandneg2", "bandneg3",
    "bandneg4", "bandneg5", "bandneg6", "restartneg1", "restartneg2",
    "restartneg3", "spbudgetneg", "panicneg", "svcneg", "fpneg",
    "mspovfneg", "xnneg", "ffa-direct", "ffa-sint", "ns-smoke",
    "ffa-discovery", "ffa-guest-direct", "psci", "psci-el2", "parkneg",
    "rdistneg", "tickneg", "el2dirtyneg", "ffa-preempt", "positive",
    "guest1", "smcfuzz", "secramneg", "periphneg", "periphspneg",
    "resetneg", "ffa-memneg", "hsmattackneg", "hsmpinneg", "attestneg",
    "vaultrecover", "vaultrecoversec", "confboot", "storage", "devstorage",
    "devattest", "devattestqcbor", "devcrypto",
)
QEMU_A_ACS = (
    "ffaacs-discovery", "ffaacs-direct", "ffaacs-memory", "ffaacs-notify",
    "ffaacs-indirect", "ffaacs-interrupts",
)

# smoke: the catch-most subset, mirroring the M33MU smoke sets, on the
# representative GICv3 virt cell (both engines) and the versal cell (native).
# boot-smp2 and the ACS stay in the full tier.
QEMU_A_SMOKE = ("smoke", "boot", "positive", "crossdomain", "ffa-direct",
                "confboot", "devcrypto")
QEMU_A_SMOKE_CELLS = {"virt-gicv3-a72": ENGINES, "versal-virt": ("native",)}
# The Armv8-M registry below does not describe the QEMU lane's targets yet.
QEMU_A_TARGETS = frozenset(cell["target"] for cell in QEMU_A_CELLS)


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
        if name == "common" or name in QEMU_A_TARGETS or \
                not os.path.isdir(os.path.join(root, name)):
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
        lean = m33mu.get("default", {})
        ports[name] = {
            "label": data["ci"]["label"],
            "label_only": bool(data["ci"].get("label_only", False)),
            "image": data["ci"]["image"],
            "arm": m33mu["arm"],
            "smoke": {"full": tuple(m33mu["smoke"]),
                      "default": tuple(lean.get("smoke", []))},
            "groups": {"full": tuple((key, text)
                                     for key, text in m33mu["groups"]),
                       "default": tuple((key, text) for key, text in
                                        lean.get("groups", []))},
            "l3_exempt": {"full": dict(m33mu.get("l3_exempt", {})),
                          "default": dict(lean.get("l3_exempt", {}))},
            "def": data,
        }
    return ports


PORTS = load_ports()


def qemu_a_entry(cell, engine, kind, tier, scenarios):
    job = "%s_%s_%s" % ("el3" if kind == "suite" else "ffa_acs",
                        cell["slug"], engine)
    return {"kind": kind, "tier": tier, "cell": cell["name"],
            "slug": cell["slug"], "machine": cell["machine"],
            "target": cell["target"], "gic": cell["gic"], "cpu": cell["cpu"],
            "smp": cell["smp"], "engine": engine, "image": QEMU_A_IMAGE,
            "scenarios": " ".join(scenarios), "job": job}


def qemu_a_cell_suite(cell):
    exempt = cell.get("l3_exempt", {})
    return tuple(s for s in QEMU_A_SUITE if s not in exempt)


def qemu_a_full(cell):
    out = []
    for engine in ENGINES:
        out.append(qemu_a_entry(cell, engine, "suite", "full",
                                qemu_a_cell_suite(cell)))
        out.append(qemu_a_entry(cell, engine, "acs", "full", QEMU_A_ACS))
    return out


def qemu_a_smoke(cell):
    return [qemu_a_entry(cell, engine, "suite", "smoke", QEMU_A_SMOKE)
            for engine in QEMU_A_SMOKE_CELLS.get(cell["name"], ())]


def qemu_a_plan(event, labels, cell_input):
    """Every AArch64 job of one workflow run: a pull request gets the smoke
    subset unless ci:all, ci:aarch64, or the cell's family label asks for the
    full suite and ACS; a push, the schedule, or a dispatch gets the full tier
    of the selected cells."""
    out = []
    for cell in QEMU_A_CELLS:
        fam = QEMU_A_FAMILIES[cell["family"]]
        if event == "pull_request":
            full = ("ci:all" in labels or "ci:aarch64" in labels or
                    fam in labels)
        elif event == "workflow_dispatch":
            full = cell_input in ("", "all", cell["name"], cell["family"])
            if not full:
                continue
        else:
            full = True
        out.extend(qemu_a_full(cell) if full else qemu_a_smoke(cell))
    return out


def qemu_a_flat(tier):
    return list(QEMU_A_SUITE if tier == "full" else QEMU_A_SMOKE)


def group_name(port, profile, scenario):
    for key, name in PORTS[port]["groups"][profile]:
        if key.split() == [scenario]:
            return name
    return scenario


def engines_for(scenarios, engine, port_engines=ENGINES):
    engines = ENGINES
    for only, names in ENGINE_ONLY.items():
        if all(s in names for s in scenarios):
            engines = (only,)
    return [e for e in engines
            if e in port_engines and (engine is None or e == engine)]


def entry(port, tier, engine, profile, key, name):
    port_def = PORTS[port]
    # Check names follow wolfBoot's <device>_<test> slugs; the lean profile's
    # jobs carry "default" so a scenario's two runs never share a name.
    words = [port] + key.split()
    if profile == "default":
        words.append("default")
    job = "_".join(words + [engine])
    return {"port": port, "tier": tier, "engine": engine, "profile": profile,
            "key": key, "name": name, "job": job, "image": port_def["image"],
            "arm": port_def["arm"],
            "mcuxsdk_board": port_def["def"]["ci"].get("mcuxsdk_board", "")}


def entries(port, tier, engine, profile=None):
    port_def = PORTS[port]
    port_engines = port_def["def"]["build"]["engines"]
    out = []
    for prof in PROFILES:
        if profile is not None and prof != profile:
            continue
        if tier == "smoke":
            for scenario in port_def["smoke"][prof]:
                for eng in engines_for([scenario], engine, port_engines):
                    out.append(entry(port, tier, eng, prof, scenario,
                                     group_name(port, prof, scenario)))
        else:
            for key, name in port_def["groups"][prof]:
                for eng in engines_for(key.split(), engine, port_engines):
                    out.append(entry(port, tier, eng, prof, key, name))
    return out


def ci_plan(event, labels, port_input):
    """Every job of one workflow run: a pull request gets each port's smoke
    tier unless its label (or ci:all) asks for the full one, and a label_only
    port runs only when labelled; a push, the schedule, or a dispatch gets the
    full tier of the selected ports. Each tier runs on both profiles."""
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
                       "hsm_flash.h", "hsm_flash_ctx.c", "rng_entropy.c",
                       "platform_armv8m.c", "platform_port.h", "fabric_sau.c",
                       "fabric_sau.h")


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
        for prof in PROFILES:
            full = set(flat(port, "full", None, prof))
            for scenario in PORTS[port]["smoke"][prof]:
                if scenario not in full:
                    gaps.append("%s: %s smoke scenario %s is not in its "
                                "full tier" % (port, prof, scenario))
            if not PORTS[port]["groups"][prof]:
                gaps.append("%s: no %s profile scenarios" % (port, prof))
        for scenario in flat(port, "full", None, "default"):
            if scenario in NEEDS_FULL:
                gaps.append("%s runs %s on the default profile" %
                            (port, scenario))
        engines = data["build"].get("engines", [])
        if not engines or any(e not in ENGINES for e in engines):
            gaps.append("%s: bad engines %r" % (port, engines))
    return gaps


def profiles_of(port, scenario):
    """The profiles whose full tier registers scenario."""
    return [prof for prof in PROFILES
            if scenario in flat(port, "full", None, prof)]


def profile_of(port, scenario, requested):
    """The profile a runner builds scenario with: the requested one when the
    scenario is registered there, else full when it runs there, else its only
    profile. None when the scenario cannot run as asked."""
    found = profiles_of(port, scenario)
    if requested:
        return requested if requested in found else None
    if not found:
        return None
    return "full" if "full" in found else found[0]


def l3_gaps(port):
    """Problems with a port's level 3 bar on each profile: a required
    scenario neither run nor exempted, an exemption with no reason, or a
    stale exemption."""
    port_def = PORTS[port]
    gaps = []
    for prof in PROFILES:
        exempt = port_def["l3_exempt"][prof]
        run = set(flat(port, "full", None, prof))
        for scenario in sorted(L3_REQUIRED):
            if scenario not in run and not exempt.get(scenario, "").strip():
                gaps.append("%s does not run level 3 scenario %s on %s" %
                            (port, scenario, prof))
        for scenario in sorted(exempt):
            if scenario not in L3_REQUIRED:
                gaps.append("%s exempts %s on %s, which is not a level 3 "
                            "scenario" % (port, scenario, prof))
            elif scenario in run:
                gaps.append("%s runs %s on %s but still exempts it" %
                            (port, scenario, prof))
    return gaps


def profile_gaps():
    """Every plan runs both profiles with unique job names, and a runner
    resolves a scenario to the profile it is registered on."""
    gaps = []
    for event in ("pull_request", "push"):
        plan = ci_plan(event, [], "")
        jobs = [e["job"] for e in plan]
        if len(jobs) != len(set(jobs)):
            gaps.append("ci_plan(%s) repeats a job name" % event)
        for port in sorted(set(e["port"] for e in plan)):
            got = sorted(set(e["profile"] for e in plan if e["port"] == port))
            if got != sorted(PROFILES):
                gaps.append("ci_plan(%s) runs %s on %s only" %
                            (event, port, " ".join(got)))
    for port in sorted(PORTS):
        for scenario in flat(port, "full", None, "default"):
            if profile_of(port, scenario, "default") != "default":
                gaps.append("%s: %s does not resolve to default" %
                            (port, scenario))
        for scenario in NEEDS_FULL:
            if profile_of(port, scenario, "default") is not None:
                gaps.append("%s: %s resolves to the default profile" %
                            (port, scenario))
        if profile_of(port, "__no_such_scenario__", "") is not None:
            gaps.append("%s: an unknown scenario resolved" % port)
    return gaps


QEMU_A_SELFTEST = (
    ("pull_request", "", "", "versal-virt:smoke virt-gicv3-a72:smoke"),
    ("pull_request", "ci:qemu-virt", "",
     "versal-virt:smoke virt-gicv2-a35:full virt-gicv3-a72:full"),
    ("pull_request", "ci:qemu-versal", "",
     "versal-virt:full virt-gicv3-a72:smoke"),
    ("pull_request", "ci:aarch64", "",
     "versal-virt:full virt-gicv2-a35:full virt-gicv3-a72:full"),
    ("pull_request", "ci:all", "",
     "versal-virt:full virt-gicv2-a35:full virt-gicv3-a72:full"),
    ("push", "", "",
     "versal-virt:full virt-gicv2-a35:full virt-gicv3-a72:full"),
    ("schedule", "", "",
     "versal-virt:full virt-gicv2-a35:full virt-gicv3-a72:full"),
    ("workflow_dispatch", "", "",
     "versal-virt:full virt-gicv2-a35:full virt-gicv3-a72:full"),
    ("workflow_dispatch", "", "versal-virt", "versal-virt:full"),
    ("workflow_dispatch", "", "qemu-virt",
     "virt-gicv2-a35:full virt-gicv3-a72:full"),
)


def qemu_a_l3_gaps():
    """A level 3 scenario the AArch64 suite does not run, or a cell exemption
    that names no level 3 scenario or gives no reason."""
    gaps = ["the QEMU AArch64 suite does not run level 3 scenario %s" % s
            for s in sorted(QEMU_A_L3_REQUIRED - set(QEMU_A_SUITE))]
    for cell in QEMU_A_CELLS:
        planned = set(qemu_a_full(cell)[0]["scenarios"].split())
        for scenario in sorted(QEMU_A_L3_REQUIRED - planned):
            if not cell.get("l3_exempt", {}).get(scenario, "").strip():
                gaps.append("%s does not plan level 3 scenario %s" %
                            (cell["name"], scenario))
        for scenario, reason in sorted(cell.get("l3_exempt", {}).items()):
            if scenario not in QEMU_A_L3_REQUIRED:
                gaps.append("%s exempts %s, which is not a level 3 scenario" %
                            (cell["name"], scenario))
            elif not reason.strip():
                gaps.append("%s exempts %s without a reason" %
                            (cell["name"], scenario))
    return gaps


def qemu_a_gaps():
    """The AArch64 QEMU lane's level 3 bar and event/label routing."""
    gaps = qemu_a_l3_gaps()
    for event, labels, cell_input, expect in QEMU_A_SELFTEST:
        got = " ".join(sorted(set(e["cell"] + ":" + e["tier"] for e in
                                  qemu_a_plan(event, labels.split(),
                                              cell_input))))
        if got != expect:
            gaps.append("qemu_a_plan(%s, %r, %r) = %s, expected %s" % (
                event, labels, cell_input, got, expect))
    return gaps


def selftest():
    """The registry, the routing properties, the engine rule and the level 3
    bar, run by the select job and by make test."""
    gaps = (registry_gaps() + routing_gaps() + profile_gaps() +
            qemu_a_gaps())
    for port in sorted(PORTS):
        for tier in ("smoke", "full"):
            for e in entries(port, tier, None):
                names = e["key"].split()
                for only, restricted in ENGINE_ONLY.items():
                    if e["engine"] != only and any(s in restricted for s in names):
                        gaps.append("%s job for the %s-only %s" %
                                    (e["engine"], only, e["key"]))
                if e["engine"] not in ENGINES or e["image"] == "":
                    gaps.append("bad entry %r" % e)
        gaps.extend(l3_gaps(port))
    return "; ".join(gaps) if gaps else None


def flat(port, tier, engine, profile=None):
    seen = []
    for entry in entries(port, tier, engine, profile):
        for scenario in entry["key"].split():
            if any(scenario in names for only, names in ENGINE_ONLY.items()
                   if engine is not None and engine != only):
                continue
            if scenario not in seen:
                seen.append(scenario)
    return seen


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", choices=sorted(PORTS))
    parser.add_argument("--tier", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--engine", choices=ENGINES)
    parser.add_argument("--profile", choices=PROFILES,
                        help="only this build profile's scenarios")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true",
                      help="matrix include list for the workflow")
    mode.add_argument("--flat", action="store_true",
                      help="space-separated scenario list for run_suite.sh")
    mode.add_argument("--image", action="store_true",
                      help="the port's CI container image")
    mode.add_argument("--arm", action="store_true",
                      help="the port's run_suite.sh arm")
    mode.add_argument("--profile-of", metavar="SCENARIO",
                      help="the build profile SCENARIO runs on (WT_PROFILE "
                           "asks for one)")
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
    mode.add_argument("--aarch64-plan", action="store_true",
                      help="the AArch64 run's include list from "
                           "GITHUB_EVENT_NAME, PR_LABELS, and CELL_INPUT")
    mode.add_argument("--aarch64-flat", action="store_true",
                      help="space-separated AArch64 scenario list for "
                           "run_suite.sh qemu-a (with --tier)")
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
    if args.aarch64_plan:
        print(json.dumps(qemu_a_plan(os.environ.get("GITHUB_EVENT_NAME", ""),
                                     os.environ.get("PR_LABELS", "").split(),
                                     os.environ.get("CELL_INPUT", ""))))
        return 0
    if args.aarch64_flat:
        print(" ".join(qemu_a_flat(args.tier)))
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
    elif args.profile_of:
        profile = profile_of(args.port, args.profile_of,
                             os.environ.get("WT_PROFILE", ""))
        if profile is None:
            print("%s does not run %s on profile %r" %
                  (args.port, args.profile_of,
                   os.environ.get("WT_PROFILE", "")), file=sys.stderr)
            return 1
        print(profile)
    elif args.flat:
        print(" ".join(flat(args.port, args.tier, args.engine, args.profile)))
    else:
        print(json.dumps(entries(args.port, args.tier, args.engine,
                                 args.profile)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
