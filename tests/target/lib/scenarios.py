#!/usr/bin/env python3
# scenarios.py
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

"""The target scenario table and the one judge of its evidence.

Every scenario is one row of SCENARIOS: the Secure-image probe flags, the
guest role (which guest pair a port boots), the guest build flags, how a
passing run ends, its wall-clock budget, whether a delivered fault may end
the run, whether a protection-unit trace boot follows, and the assertion
blocks that judge it. A block is data, never shell: a list of checks over
the boot log, the guest 0 console view, the trace log or a symbol file, each
naming the property it proves. Which blocks apply is decided here from the
port's guest kinds and the capabilities its registry entry declares absent,
so a port cannot weaken a check by leaving it out: a block that does not
apply is listed as N/A with the port's reason, and a block that applies must
pass.

    scenarios.py --port <port> --scenario <s> --shell      resolved plan
    scenarios.py --port <port> --scenario <s> --asserts    applicable blocks
    scenarios.py --port <port> --scenario <s> judge --log <boot.log> ...
    scenarios.py --list                                   every scenario
    scenarios.py --selftest                               table invariants
"""

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scenario_matrix  # noqa: E402

PORTS = scenario_matrix.PORTS

FAULT_MARKERS = r'^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
ESCALATION = r'(\[HARDFLT\]|HardFault|SecureFault)'
PSA_STEP_FAILED = (r'guest[01]: .*(FAILED|failed|NOT re|SUCCEEDED|accepted|'
                   r'unavailable|wrong data|not refused|not rejected)')

# Port-private names every port accepted before the table was shared.
ALIASES = {"gtzcneg": "guestisoneg", "ahbscneg": "guestisoneg",
           "sauneg": "guestisoneg"}

GUEST_KINDS = ("baremetal", "psa", "zephyr", "freertos", "vnet")
ROLES = ("lifecycle", "psa", "conformance", "vnet")
CAPABILITIES = {
    "boot_console": "wolfBoot prints its HAL and signature lines on the console",
    "prot_trace": "the emulator's protection-unit trace names the unit behind a refusal",
    "dma_probe": "the guest can aim a Non-secure DMA at Secure memory",
    "guest_fence": "the first stage arms a guest flash fence wolfTrust requires",
    "idcode": "the emulator reports the silicon revision through DBGMCU",
    "bootupdate": "wolfBoot swaps a pre-staged candidate on the armed reboot",
    "vnet": "the port builds the wolfIP network guests",
    "busfault": "the emulator vectors a precise data BusFault",
    "idle_scheduler": "the port runs the single-guest idle recovery scenario",
    "handler_overrun": "the port runs the Non-secure handler overrun scenario",
}


def S(secure="", role="lifecycle", guest_flags="", end="guest", timeout=None,
      quit_on_faults=True, trace=None, blocks=(), engines=("native", "hsm"),
      requires=(), level3=False, hw=False, prebuild="", update=False,
      tamper=False, note=""):
    return {"secure": secure, "role": role, "guest_flags": guest_flags,
            "end": end, "timeout": timeout, "quit_on_faults": quit_on_faults,
            "trace": trace, "blocks": tuple(blocks), "engines": tuple(engines),
            "requires": tuple(requires), "level3": level3, "hw": hw,
            "prebuild": prebuild, "update": update, "tamper": tamper,
            "note": note}


SP_PROBE_FLAGS = "WT_M33MU_EXPECT_BKPT=1"
CONF = "WT_RUN_CONFORMANCE=1"

SCENARIOS = {
    "positive": S(blocks=("no_faults", "lifecycle", "storage_served"),
                  hw=True),
    "restart": S(guest_flags="WT_GUEST_FAULT_PROBE=1", end="timeout",
                 timeout=40, quit_on_faults=False, trace="restart",
                 blocks=("restart",), hw=True),
    "restartidle": S(guest_flags="WT_GUEST_FAULT_PROBE=1", end="bkpt:0x7d",
                     timeout=40, quit_on_faults=False,
                     blocks=("restart", "restartidle_verdict"),
                     requires=("idle_scheduler",)),
    "guestisoneg": S(guest_flags="WT_ISO_PROBE=1", end="timeout", timeout=40,
                     quit_on_faults=False, trace="guestisoneg",
                     blocks=("guestisoneg",), hw=True),
    "periphneg": S(guest_flags="WT_PERIPH_NEG_PROBE=1", trace="periphneg",
                   blocks=("periphneg",), hw=True),
    "crossdomain": S(secure="WT_FFM_NEGATIVE_PROBE=1", trace="band_read",
                     blocks=("sp_probe_lifecycle", "sp_probe_denied", "l3"),
                     level3=True, hw=True),
    "keystoreneg": S(secure="WT_KEYSTORE_NEG_PROBE=1", trace="band_read",
                     blocks=("sp_probe_lifecycle", "sp_probe_denied", "l3"),
                     level3=True),
    "periphspneg": S(secure="WT_PERIPH_SP_NEG_PROBE=1", role="psa",
                     guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                     blocks=("sp_probe_lifecycle", "l3", "periphspneg"),
                     level3=True),
    "deputyneg": S(secure="WT_DEPUTY_NEG_PROBE=1", role="psa",
                   guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                   blocks=("psa_probe_lifecycle", "probe_linked",
                           "no_faults", "psa_served"),
                   level3=True),
    "hsmpinneg": S(secure="WT_HSM_PIN_NEG_PROBE=1", role="psa",
                   guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                   blocks=("psa_probe_lifecycle", "probe_linked",
                           "no_faults", "psa_served"),
                   engines=("hsm",), level3=True),
    "hsmfaultneg": S(secure="WT_HSM_FAULT_PROBE=1", role="psa",
                     guest_flags=SP_PROBE_FLAGS + " WT_M33MU_BKPT_GUEST=1",
                     end="bkpt:0x7f", timeout=40, quit_on_faults=False,
                     blocks=("psa_probe_lifecycle", "l3", "hsmfaultneg"),
                     engines=("hsm",), level3=True),
    "bandneg1": S(secure="WT_BAND_NEG_PROBE=1", role="psa",
                  guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                  quit_on_faults=False,
                  blocks=("psa_probe_lifecycle", "l3", "psa_served"),
                  level3=True),
    "spfaultneg": S(secure="WT_SP_FAULT_PROBE=1", quit_on_faults=False,
                    trace="sp_fault",
                    blocks=("sp_fault", "lifecycle", "storage_served",
                            "sp_recovered"), level3=False),
    "panicneg": S(secure="WT_PANIC_NEG_PROBE=1", quit_on_faults=False,
                  trace="sp_fault",
                  blocks=("sp_fault", "lifecycle", "panic_unblocked",
                          "storage_served")),
    "confboot": S(secure="WT_CONFORMANCE=1", role="conformance",
                  guest_flags=CONF + " " + SP_PROBE_FLAGS, end="bkpt:0x7f",
                  timeout=1200, quit_on_faults=False,
                  blocks=("conformance_boot", "confboot")),
    "devstorage": S(secure="WT_CONFORMANCE=1", role="conformance",
                    guest_flags=CONF + " WT_CONF_SUITE=storage " + SP_PROBE_FLAGS,
                    end="bkpt:0x7f", timeout=900, quit_on_faults=False,
                    blocks=("conformance_boot", "devstorage")),
    "devcrypto": S(secure="WT_CONFORMANCE=1", role="conformance",
                   guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                   end="bkpt:0x7f", timeout=7200, quit_on_faults=False,
                   blocks=("conformance_boot", "devcrypto")),
    "devattest": S(secure="WT_CONFORMANCE=1", role="conformance",
                   guest_flags=CONF + " WT_CONF_SUITE=attestation " + SP_PROBE_FLAGS,
                   end="bkpt:0x7f", timeout=900,
                   blocks=("conformance_boot", "devattest")),
    "devattestqcbor": S(secure="WT_CONFORMANCE=1", role="conformance",
                        guest_flags=CONF + " WT_CONF_SUITE=attestation WT_ATTEST_CBOR=qcbor " + SP_PROBE_FLAGS,
                        end="bkpt:0x7f", timeout=900,
                        blocks=("conformance_boot", "devattest"),
                        prebuild="tests/upstream/fetch_qcbor.sh"),
    "attestneg": S(role="psa", guest_flags="WT_ATTEST_NEG_PROBE=1",
                   blocks=("psa_lifecycle", "attestneg")),
    "hsmattackneg": S(role="psa", guest_flags="WT_HSM_ATTACK_PROBE=1",
                      blocks=("no_faults", "psa_lifecycle", "hsmattackneg"),
                      engines=("hsm",)),
    "authneg": S(end="timeout", timeout=40, blocks=("no_faults", "authneg"),
                 tamper=True, hw=True),
    "rollbackneg": S(secure="WT_ROLLBACK_PROBE=1", end="bkpt:0x7d",
                     blocks=("verdict_rollbackneg",)),
    "vaultrecover": S(secure="WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1",
                      role="conformance",
                      guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                      end="bkpt:0x7f", timeout=7200,
                      blocks=("conformance_start", "vaultrecover")),
    "vaultrecoversec": S(secure="WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1 WT_VAULT_PROBE_SECURED=1",
                         role="conformance",
                         guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                         end="timeout", timeout=900,
                         blocks=("vaultrecoversec",)),
    "fwustage": S(role="psa", guest_flags="WT_FWU_PROBE=1",
                  blocks=("no_faults", "psa_lifecycle", "fwustage")),
    "remeasureneg": S(secure="WT_REMEASURE_PROBE=1", end="bkpt:0x6c",
                      blocks=("verdict_remeasureneg",)),
    "bootupdate": S(secure="WT_BOOTUPDATE_PROBE=1", timeout=150,
                    blocks=("bootupdate",), requires=("bootupdate",),
                    update=True),
    "vnet": S(secure="CONFIG_VNET=y", role="vnet", timeout=180,
              blocks=("no_faults", "vnet"), requires=("vnet",)),
    "vnetneg": S(secure="CONFIG_VNET=y WT_VNET_NEG_PROBE=1", role="vnet",
                 timeout=180, quit_on_faults=False, blocks=("vnetneg",),
                 requires=("vnet",)),
    "manifestneg": S(secure="WT_MANIFEST_NEG_PROBE=1", end="bkpt:0x7e",
                     blocks=("verdict_manifestneg",)),
    "manifestneg2": S(secure="WT_MANIFEST_NEG_PROBE=2", end="bkpt:0x7e",
                      blocks=("verdict_manifestneg",), level3=True),
    "manifestneg3": S(secure="WT_MANIFEST_NEG_PROBE=3", end="bkpt:0x7e",
                      blocks=("verdict_manifestneg",), level3=True),
    "spbudgetneg": S(secure="WT_SP_FAULT_ALWAYS_PROBE=1", end="bkpt:0x7d",
                     timeout=40, quit_on_faults=False,
                     blocks=("verdict_spbudgetneg",)),
    "revneg": S(end="bkpt:0x7e", timeout=40, blocks=("revneg",), requires=("idcode",)),
    "fpneg": S(secure="WT_SP_FAULT_PROBE=1 WT_FP_NEG_PROBE=1", end="fault",
               timeout=40, blocks=("fpneg",),
               level3=True),
    "sealneg": S(secure="WT_SEAL_NEG_PROBE=1", role="psa",
                 guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                 quit_on_faults=False,
                 blocks=("psa_probe_lifecycle", "l3", "peer_alive"),
                 level3=True),
    "sealhaltneg": S(secure="WT_SEAL_NEG_PROBE=2", end="bkpt:0x6e",
                     timeout=40, blocks=("verdict_sealhaltneg",),
                     level3=True),
    "sealbootneg": S(secure="WT_SEAL_NEG_PROBE=3", end="bkpt:0x7e",
                     timeout=40, blocks=("verdict_sealbootneg",),
                     level3=True),
    "sealpivotneg": S(secure="WT_SEAL_NEG_PROBE=4", role="psa",
                      guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                      quit_on_faults=False,
                      blocks=("psa_probe_lifecycle", "l3", "peer_alive"),
                      level3=True),
    "mspovfneg": S(secure="WT_MSP_OVF_PROBE=1", end="fault", timeout=40,
                   blocks=("verdict_mspovfneg",),
                   level3=True),
    "busfaultneg": S(secure="WT_BUSFAULT_NEG_PROBE=1", quit_on_faults=False,
                     blocks=("busfaultneg", "sp_recovered"),
                     requires=("busfault",)),
    "xnneg": S(secure="WT_XN_NEG_PROBE=1", end="fault", timeout=40,
               blocks=("verdict_xnneg",), level3=True),
    "svcneg": S(secure="WT_SVC_NEG_PROBE=1", role="psa",
                guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                quit_on_faults=False,
                blocks=("psa_probe_lifecycle", "l3", "svcneg", "peer_alive"),
                level3=True),
    "bothpsa": S(role="psa", blocks=("no_faults", "psa_lifecycle", "bothpsa")),
    "bothiso": S(role="psa", blocks=("no_faults", "psa_lifecycle", "bothiso")),
    "handlerneg": S(guest_flags="WT_HANDLER_OVERRUN_PROBE=1", end="timeout",
                    quit_on_faults=False, blocks=("handlerneg",),
                    requires=("handler_overrun",)),
    "wrpfence": S(secure="WT_GUEST_FLASH_WRP=1", blocks=("no_faults", "fenced"),
                  requires=("guest_fence",)),
    "wrpneg": S(secure="WT_GUEST_FLASH_WRP=1",
                blocks=("no_faults", "fence_selftest", "fenced"),
                requires=("guest_fence",)),
    "wrpoff": S(secure="WT_GUEST_FLASH_WRP=1", end="timeout",
                blocks=("wrpoff",), hw=True,
                note="a fence-required image behind a first stage that arms none"),
}
for _n in range(2, 7):
    SCENARIOS["bandneg%d" % _n] = dict(SCENARIOS["bandneg1"],
                                        secure="WT_BAND_NEG_PROBE=%d" % _n)
for _n in range(1, 4):
    SCENARIOS["restartneg%d" % _n] = S(
        secure="WT_RESTART_NEG_PROBE=%d" % _n, role="psa",
        guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f", quit_on_faults=False,
        blocks=("psa_probe_lifecycle", "l3", "psa_served"), level3=True)

# The eight every board runs on silicon (docs/Porting.md).
HARDWARE_MINIMUM = ("positive", "guestisoneg", "periphneg", "restart", "psa",
                    "wrpoff", "crossdomain", "authneg")


def canonical(name):
    return ALIASES.get(name, name)


def family(name):
    for prefix in ("bandneg", "restartneg"):
        if name.startswith(prefix) and name[len(prefix):].isdigit():
            return prefix
    return name


def port_m33mu(port):
    return PORTS[port]["def"]["m33mu"]


def guest_pair(port, role):
    guests = port_m33mu(port).get("guests", {})
    pair = guests.get(role)
    if not pair or len(pair) != 2 or any(k not in GUEST_KINDS for k in pair):
        raise SystemExit("port/%s/port.json m33mu.guests.%s must name two guest kinds" %
                         (port, role))
    return tuple(pair)


def caps_absent(port):
    return dict(port_m33mu(port).get("caps_absent", {}))


def faults_by_design(port):
    return dict(port_m33mu(port).get("faults_by_design", {}))


def resolve(port, scenario, engine="native"):
    """The scenario as this port runs it: the guest pair, the end mode, the
    wall-clock budget and the flags, with the port's declared quirks applied."""
    name = canonical(scenario)
    if name not in SCENARIOS:
        raise SystemExit("unknown scenario %s" % scenario)
    row = SCENARIOS[name]
    m33mu = port_m33mu(port)
    pair = guest_pair(port, row["role"])
    end = row["end"]
    guest_flags = row["guest_flags"]
    # The port's own flags for a scenario (the PSA guest's FWU stream probe
    # sizes follow the port's update partition and program unit).
    extra = m33mu.get("guest_flags", {}).get(name, "")
    if extra:
        guest_flags = (guest_flags + " " + extra).strip()
    if end == "guest":
        # A guest that can end the run on its clean breakpoint does; a guest
        # that idles forever leaves the run to the wall clock.
        if m33mu.get("guest_end", {}).get(pair[0], "idle") == "bkpt":
            end = "bkpt:0x7f"
            if "WT_M33MU_EXPECT_BKPT=1" not in guest_flags:
                guest_flags = (guest_flags + " WT_M33MU_EXPECT_BKPT=1").strip()
        else:
            end = "idle"
    # The port's own end for a scenario: an OS guest pair stops at the
    # partition's deliberate fault where a bare-metal pair runs on to idle.
    end = m33mu.get("ends", {}).get(name, end)
    timeout = row["timeout"]
    if timeout is None:
        timeout = int(m33mu.get("timeouts", {}).get(row["role"], 60))
    quit_on_faults = row["quit_on_faults"]
    if name in faults_by_design(port):
        quit_on_faults = False
    missing = [c for c in row["requires"] if c in caps_absent(port)]
    return {"scenario": name, "alias": scenario if scenario != name else "",
            "secure": row["secure"], "role": row["role"], "guests": pair,
            "guest_flags": guest_flags, "end": end, "timeout": timeout,
            "quit_on_faults": quit_on_faults, "trace": row["trace"] or "",
            "engines": row["engines"], "engine": engine,
            "level3": row["level3"], "missing": missing,
            "blocks": row["blocks"], "prebuild": row["prebuild"],
            "update": row["update"], "tamper": row["tamper"],
            "guest0_end": m33mu.get("guest_end", {}).get(pair[0], "idle"),
            "note": row["note"]}


# ---------------------------------------------------------------- markers --

def markers(kind, guest, board):
    """Console markers a guest of this kind prints, by role in the story."""
    if kind == "baremetal":
        tag = "wolfTrust %s %s" % (board, guest)
        return {"started": tag + ": start",
                "done": tag + ": FF-M connect ok, done",
                "connect": tag + ": FF-M connect ok",
                "storage": tag + ": storage connect ok",
                "failed": tag + ": FAIL",
                "periph_leaked": tag + ": periph probe LEAKED",
                "periph_blocked": tag + ": periph probe blocked",
                "periph_inconclusive": tag + ": periph probe INCONCLUSIVE",
                "entry_mask_ok": tag + ": NS entry mask ok"}
    if kind == "psa":
        return {"started": guest + ": alive", "done": guest + ": done"}
    if kind == "zephyr":
        return {"started": "guest0_psa alive", "done": "guest0_psa done",
                "iso_attempt": "wolfTrust GTZC bypass probe: attempting peer write",
                "iso_blocked": "wolfTrust GTZC peer write blocked",
                "iso_leaked": "wolfTrust GTZC peer write LEAKED",
                "periph_blocked": "wolfTrust periph probe blocked",
                "periph_bad": "wolfTrust periph probe (LEAKED|INCONCLUSIVE)"}
    if kind == "freertos":
        return {"started": "freertos_guest1: alive",
                "heartbeat": "freertos_guest1: heartbeat",
                "sha": "freertos_guest1: ffm sha256 ok"}
    if kind == "vnet":
        return {"started": "vnet-%s: alive" % guest}
    raise SystemExit("unknown guest kind %s" % kind)


ZEPHYR_LIFECYCLE = (
    ("TEE client initialized", "wolfTrust TEE client initialized"),
    ("FF-M psa_framework_version=0x0100",
     "wolfTrust FF-M psa_framework_version=0x0100"),
    ("mediated crypto dispatch verified",
     "wolfTrust FF-M mediated crypto dispatch verified"),
    ("ITS set/get verified", "wolfTrust ITS set/get verified"),
    ("PS sealed set/get verified", "wolfTrust PS sealed set/get verified"),
    ("key-ops sign/verify verified", "wolfTrust key-ops sign/verify verified"),
    ("key negatives verified", "wolfTrust key negatives verified"),
    ("forged-handle call rejected", "wolfTrust FF-M forged-handle call rejected"),
    ("oversized-vector call rejected",
     "wolfTrust FF-M oversized-vector call rejected"),
    ("psa_initial_attestation short-buffer rejected",
     "psa_initial_attestation short-buffer rejected correctly"),
    ("psa_hash_compute(SHA-256) KAT verified",
     "psa_hash_compute(SHA-256) KAT verified"),
    ("psa_cipher_encrypt(AES-CTR) through a volatile key",
     "psa_cipher_encrypt(AES-CTR) st=0"),
    ("psa_initial_attestation st=0", "psa_initial_attestation st=0"),
    ("attestation COSE_Sign1 signed through the engine",
     "wolfTrust attestation: wolfCOSE COSE_Sign1 signed by wolfHSM"),
    ("attestation COSE_Sign1 verified",
     "wolfTrust attestation: COSE_Sign1 verified"),
    ("token measurement equals wolfBoot measurement of the signed image",
     "wolfTrust attestation: token measurement={expected_measurement}"),
    ("attestation fields verify=0 lifecycle=0x1000 measurement=ok cose=ES256",
     "attestation verify=0 challenge=ok identity=ok lifecycle=0x1000 measurement=ok cose=ES256"),
    ("secured lifecycle policy rejected the development token",
     "secured lifecycle policy rejected development token"),
)
FREERTOS_LIFECYCLE = (
    ("guest1 FF-M SHA-256 KAT through SERVICE_CRYPTO", "freertos_guest1: ffm sha256 ok"),
    ("guest1 vault-backed RNG through the SPM (WT-FFM-0054)", "freertos_guest1: ffm rng ok"),
    ("guest1 wolfPSA front-end initialized", "freertos_guest1: psa_crypto_init st=0"),
    ("guest1 psa_generate_random seeded through the FF-M RNG hook", "freertos_guest1: psa rng ok"),
    ("guest1 psa_hash_compute KAT (PSA API parity)", "freertos_guest1: psa hash ok"),
)
PSA_GUEST_CHECKS = (
    ("mediated SERVICE_CRYPTO SHA-256 KAT", "{g}: wolfTrust FF-M mediated crypto dispatch verified"),
    ("PSA psa_generate_random", "{g}: psa_generate_random st=0"),
    ("PSA psa_hash_compute(SHA-256) KAT", "{g}: psa_hash_compute(SHA-256) KAT verified"),
    ("PSA AES-CTR through a volatile key", "{g}: psa_cipher_encrypt(AES-CTR) st=0"),
    ("ITS set/get through SERVICE_ITS", "{g}: wolfTrust ITS set/get verified"),
    ("PS sealed set/get through SERVICE_PS", "{g}: wolfTrust PS sealed set/get verified"),
    ("key-ops sign/verify through the mediated path", "{g}: wolfTrust key-ops sign/verify verified"),
    ("cross-key verify refused", "{g}: wolfTrust key negatives verified"),
    ("initial attestation token issued", "{g}: psa_initial_attestation st=0"),
    ("COSE_Sign1 token verified against the IAK", "{g}: wolfTrust attestation: COSE_Sign1 verified"),
    ("token measurement equals wolfBoot's measurement of the signed image",
     "{g}: wolfTrust attestation: token measurement={expected_measurement}"),
)
PSA_SERVED = (
    ("mediated crypto dispatch verified", "guest0: wolfTrust FF-M mediated crypto dispatch verified"),
    ("ITS set/get verified", "guest0: wolfTrust ITS set/get verified"),
    ("PS sealed set/get verified", "guest0: wolfTrust PS sealed set/get verified"),
    ("key-ops sign/verify verified", "guest0: wolfTrust key-ops sign/verify verified"),
    ("attestation COSE_Sign1 verified", "guest0: wolfTrust attestation: COSE_Sign1 verified"),
)


# ----------------------------------------------------------------- checks --

def expect(desc, text, where="log"):
    return {"op": "expect", "desc": desc, "text": text, "where": where}


def expect_n(desc, n, text, where="log"):
    return {"op": "expect_n", "desc": desc, "text": text, "n": n, "where": where}


def expect_re(desc, pattern, where="log"):
    return {"op": "expect_re", "desc": desc, "re": pattern, "where": where}


def expect_n_re(desc, n, pattern, where="log"):
    return {"op": "expect_n_re", "desc": desc, "re": pattern, "n": n, "where": where}


def refute_re(desc, pattern, where="log"):
    return {"op": "refute_re", "desc": desc, "re": pattern, "where": where}


def faults_at(desc, n, addr, lo=None, hi=None, where="log", op="eq"):
    return {"op": "faults_at", "desc": desc, "n": n, "addr": addr, "lo": lo,
            "hi": hi, "where": where, "cmp": op}


def sau_refusal(desc, pattern, where="trace"):
    return {"op": "sau_refusal", "desc": desc, "re": pattern, "where": where}


def symbol(desc, name):
    return {"op": "symbol", "desc": desc, "name": name}


def totals(desc, passed=None, skipped=None, failed=0, scheduled=None):
    return {"op": "totals", "desc": desc, "passed": passed, "skipped": skipped,
            "failed": failed, "scheduled": scheduled}


def ledger(desc):
    return {"op": "ledger", "desc": desc}


def status(desc, accept, var="emu_status"):
    return {"op": "status", "desc": desc, "accept": accept, "var": var}


def either(desc, options):
    """Passes when any option's checks all pass; the report names the one."""
    return {"op": "either", "desc": desc, "options": options}


def info(desc):
    return {"op": "info", "desc": desc}


class Ctx(object):
    def __init__(self, port, scenario, env, guests, var):
        self.port = port
        self.name = scenario
        self.env = env
        self.guests = guests
        self.var = var
        self.board = var.get("board", PORTS[port]["def"].get("display", port))
        self.g0 = markers(guests[0], "guest0", self.board)
        self.g1 = markers(guests[1], "guest1", self.board)
        self.m33mu = port_m33mu(port)

    def restart_limit(self):
        return int(self.var.get("restart_limit", "3"))

    def kind(self, i):
        return self.guests[i]


# The scenarios that take down the partition serving guest0's ITS test (a
# pinned client unblocked with an error, a seal broken on purpose): the
# lifecycle holds every marker but the ITS one.
ITS_SKIPPED = ("panicneg", "svcneg", "sealneg", "sealpivotneg")


def _lifecycle_checks(ctx, guest, kind, m):
    if kind == "baremetal":
        return [expect_n("%s launched exactly once (no fault, no relaunch)" % guest, 1, m["started"]),
                expect_n("%s reached the SPM through the SG veneers and finished" % guest, 1, m["done"])]
    if kind == "psa":
        return [expect_n("%s launched exactly once (no fault, no relaunch)" % guest, 1, m["started"]),
                expect_n("%s ran its whole PSA lifecycle" % guest, 1, m["done"])]
    if kind == "zephyr":
        skip = ("ITS set/get verified",) if ctx.name in ITS_SKIPPED else ()
        return [expect(desc, text, where="guest0") for desc, text in ZEPHYR_LIFECYCLE if desc not in skip]
    if kind == "freertos":
        return [expect(desc, text) for desc, text in FREERTOS_LIFECYCLE]
    if kind == "vnet":
        return [expect("%s alive" % guest, m["started"])]
    return []


def _end_checks(ctx, end):
    if end == "idle":
        return [status("M33MU exited on the wall-clock budget (status 127)", (127,)),
                refute_re("wolfTrust never panicked (bkpt 0x7e)", r'\[BKPT\] imm=0x7e'),
                refute_re("the monitor never lost every guest (bkpt 0x7d)", r'\[BKPT\] imm=0x7d'),
                refute_re("no HardFault escalation", r'\[HARDFLT\]'),
                refute_re("no guest reported a failed FF-M handshake", r'guest[01]: FAIL'),
                refute_re("no PSA guest lifecycle step failed", PSA_STEP_FAILED),
                expect("the run ended on the wall-clock budget, not a trap", "wall-clock limit")]
    if end == "timeout":
        # Exit 0 is a guest's clean breakpoint, which only a guest the port
        # declares in m33mu.guest_end may reach; any other pair runs out the clock.
        if ctx.m33mu.get("guest_end", {}).get(ctx.kind(0), "idle") == "bkpt":
            return [status("M33MU exited on the wall-clock budget or guest0's clean breakpoint", (127, 0))]
        return [status("M33MU exited on the wall-clock budget (status 127)", (127,))]
    if end == "fault":
        return [status("M33MU exited at the delivered fault (status 0 or 1)", (0, 1)),
                expect("the run stopped at the first delivered fault", "Execution stopped")]
    if end.startswith("bkpt:"):
        return [status("M33MU exited on the expected breakpoint (status 0)", (0,)),
                expect("the emulator stopped on the expected breakpoint %s" % end[5:],
                       "[EXPECT BKPT] Success")]
    raise SystemExit("unknown end %s" % end)


def _verdict(ctx, name):
    started = ctx.g0["started"]
    peers = "|".join(re.escape(s) for s in (ctx.g0["started"], ctx.g1["started"]))
    if name == "rollbackneg":
        return [refute_re("no fault markers in the boot log", FAULT_MARKERS),
                expect("downgraded boot refused fail-closed (all guests quarantined)", "[BKPT] imm=0x7d"),
                refute_re("no guest entered a domain after the floor armed", peers)]
    if name == "remeasureneg":
        return [refute_re("no fault markers in the boot log", FAULT_MARKERS),
                expect("clean re-measure passed, then the in-flash tamper was caught before dispatch", "[BKPT] imm=0x6c")]
    if name == "manifestneg":
        return [expect("boot halted on the production manifest-validation panic", "[BKPT] imm=0x7e"),
                refute_re("no guest scheduled off the corrupted manifest", peers),
                info("refused variant built with %s" % SCENARIOS[ctx.name]["secure"])]
    if name == "sealhaltneg":
        return [expect("damaged seal halted the platform at dispatch", "[BKPT] imm=0x6e"),
                refute_re("partition with the damaged seal was never resumed", r'\[USGFLT\]'),
                refute_re("run did not reach a clean success exit", r'\[BKPT\] imm=0x7f')]
    if name == "sealbootneg":
        return [expect("boot halted on the damaged main-stack seal", "[BKPT] imm=0x7e"),
                refute_re("no guest scheduled after the refused boot", peers)]
    if name == "spbudgetneg":
        return [expect("restart budget exhaustion escalated to platform recovery", "[BKPT] imm=0x7d"),
                refute_re("the mandatory service never completed a guest lifecycle",
                          re.escape(ctx.g0.get("done", started))),
                refute_re("no clean lifecycle exit after the mandatory service died", r'\[BKPT\] imm=0x7f')]
    if name == "xnneg":
        return [expect_re("privileged execution from SPM RAM faulted (IACCVIOL)",
                          r'\[MEMFAULT\] pc=0x30[0-9a-f]{6} addr=0x30[0-9a-f]{6}'),
                refute_re("the thunk never returned into the gate", r'\[USGFLT\]'),
                refute_re("no clean lifecycle after the SPM fault", r'\[BKPT\] imm=0x7f'),
                info("the production halt is not executed by the emulator (synchronous fault pended past the SVC); asserted on silicon")]
    if name == "mspovfneg":
        return [expect_re("main-stack overflow raised STKOF against MSPLIM_S",
                          r'\[(USGFLT|HARDFLT)\].*CFSR=0x00[1-9a-f][0-9a-f]0000'),
                expect("the emulator ended the run at the SPM fault", "Execution stopped"),
                refute_re("run did not reach the wall-clock budget", "wall-clock"),
                refute_re("no partition or guest ran after the fault", peers + r'|\[BKPT\] imm=0x7f'),
                info("the production halt is not executed by the emulator; asserted on silicon")]
    raise SystemExit("no verdict table for %s" % name)


def _l3(ctx):
    name = ctx.name
    fam = family(name)
    v = ctx.var
    if name == "crossdomain":
        return [faults_at("cross-domain read of SPM RAM %s denied (MEMFAULT)" % v.get("L3_SPM_RAM", "?"),
                          1, v.get("L3_SPM_RAM"), op="ge")]
    if name == "keystoreneg":
        return [faults_at("vault band read %s denied to a non-keystore SP (MEMFAULT)" % v.get("L3_VAULT_BAND", "?"),
                          1, v.get("L3_VAULT_BAND"), op="ge")]
    if name == "periphspneg":
        return [faults_at("SP read of the SPM's peripheral at %s denied (MEMFAULT)" % v.get("L3_SPM_PERIPHERAL", "?"),
                          1, v.get("L3_SPM_PERIPHERAL"), op="ge")]
    if fam == "bandneg":
        probe = int(name[len("bandneg"):])
        bands = {1: ("L3_VAULT_BAND", "L3_CRYPTO_STACK", "crypto partition denied the vault's band"),
                 2: ("L3_ATTEST_BAND", "L3_CRYPTO_STACK", "crypto partition denied the attestation band"),
                 3: ("L3_VAULT_BAND", "L3_ATTEST_STACK", "attestation partition denied the vault's band"),
                 4: ("L3_HSM_BAND", "L3_ATTEST_STACK", "attestation partition denied the crypto band"),
                 5: ("L3_ATTEST_BAND", "L3_VAULT_STACK", "vault denied the attestation band"),
                 6: ("L3_HSM_BAND", "L3_VAULT_STACK", "vault denied the crypto band")}
        band, stack, what = bands[probe]
        addr = v.get(band)
        return [faults_at("%s, read then write (2 MEMFAULTs at %s)" % (what, addr), 2, addr),
                faults_at("both faults taken on the prober's own stack", 2, addr,
                          v.get(stack + "_LO"), v.get(stack + "_HI")),
                refute_re("no access ran past its fault, no keystore pin was open", r'^\[USGFLT\]'),
                refute_re("faults were contained, not escalated", r'^(\[HARDFLT\]|HardFault|SecureFault)')]
    if fam == "restartneg":
        return [expect_n_re("partition faulted once and restarted on a reset band", 1,
                            r'^\[USGFLT\] CFSR=0x00010000'),
                refute_re("the fault was the planted one", r'^\[USGFLT\] mem16\[[^]]*\]=0xde02'),
                refute_re("fault was contained, not escalated",
                          r'^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)')]
    if name in ("sealneg", "sealpivotneg", "svcneg"):
        return [expect_re("the partition was panicked on the panic trap (Secure-Thread UNDEFINSTR)",
                          r'^\[USGFLT\] mem16\[0x[0-9a-f]+\]=0xde50'),
                expect_re("the panic trap was an undefined instruction", r'\[USGFLT\].*CFSR=0x00010000'),
                refute_re("partition fault was contained, not escalated", ESCALATION),
                refute_re("platform did not halt on the partition's fault", r'\[BKPT\] imm=0x(6e|7e|7d)')]
    if name == "hsmfaultneg":
        return [expect("the guest's HSM tasklet faulted", "[USGFLT]"),
                refute_re("HSM fault stayed contained", r'(\[HARDFLT\]|HardFault|SecureFault|\[BKPT\] imm=0x7e)')]
    raise SystemExit("no level 3 checks for %s" % name)


def _restart_checks(ctx):
    faults = ctx.restart_limit() + 1
    k0, k1 = ctx.kind(0), ctx.kind(1)
    out = [expect_n("guest0 relaunched through its restart budget, then quarantined", faults, ctx.g0["started"])]
    if k0 == "baremetal":
        out.append(refute_re("guest0 never got past its launch-time fault", re.escape(ctx.g0["connect"])))
    if k1 == "baremetal":
        out += [expect_n("guest1 launched once, untouched by guest0's faults", 1, ctx.g1["started"]),
                expect_n("guest1 completed the FF-M handshake", 1, ctx.g1["done"])]
    return out


def _trace_sau(ctx, desc, pattern, who):
    return [expect("the traced run stopped at a delivered fault", "Execution stopped", where="trace"),
            expect_n_re(desc, 1, pattern, where="trace"),
            sau_refusal("the refusal came from the SAU%s" % who, pattern)]


def _trace_kind(ctx, v):
    kind = v.get("trace_kind", "")
    if kind == "restart":
        pat = r"\[MEMFAULT_CAUSE\] sec=NS type=READ addr=%s reason=secure-attr" % v.get("fault_addr", "?")
        return _trace_sau(ctx, "the fault was guest0's read of Secure RAM, refused as Secure", pat, "")
    if kind == "guestisoneg":
        pat = r"\[MEMFAULT_CAUSE\] sec=NS type=WRITE addr=%s reason=secure-attr" % v.get("probe_addr", "?")
        return _trace_sau(ctx, "the fault was guest0's store into guest1's RAM, refused as Secure", pat,
                          ": the peer window was Secure at dispatch")
    if kind == "periphneg":
        pat = r"\[MEMFAULT_CAUSE\] sec=NS type=READ addr=%s reason=secure-attr" % v.get("periph_ns", "?")
        return _trace_sau(ctx, "the fault was guest0's NS read of the SPM's peripheral, refused as Secure", pat, "")
    if kind == "band_read":
        addr = v.get("L3_SPM_RAM") if ctx.name == "crossdomain" else v.get("L3_VAULT_BAND")
        return [expect("the traced run stopped at a delivered fault", "Execution stopped", where="trace"),
                expect_re("the fault was the SP's out-of-domain read at the band address",
                          r"\[MEMFAULT_CAUSE\] sec=S type=READ addr=%s reason=mpu-ap" % addr, where="trace")]
    if kind == "sp_fault":
        return [expect("the traced run stopped at a delivered fault", "Execution stopped", where="trace"),
                expect_n_re("the probed SP took a Secure-Thread UsageFault", 1, r'\[USGFLT\] enter sec=1 mode=0', where="trace"),
                expect("the fault was the undefined instruction", "[USGFLT] CFSR=0x00010000", where="trace")]
    raise SystemExit("no trace checks for %s" % kind)


def block_checks(ctx, block, end):
    """The checks of one block for this port, guest pair and variables."""
    v = ctx.var
    k0, k1 = ctx.kind(0), ctx.kind(1)
    if block == "end":
        return _end_checks(ctx, end)
    if block == "boot_console":
        out = []
        if ctx.m33mu.get("boot_marker"):
            out.append(expect("wolfBoot brought up the SoC", ctx.m33mu["boot_marker"]))
        out.append(expect("wolfBoot verified the wolfTrust image signature", "Verifying signature...done"))
        return out
    if block == "no_faults":
        return [refute_re("no fault markers in boot log", FAULT_MARKERS)]
    if block == "lifecycle":
        return _lifecycle_checks(ctx, "guest0", k0, ctx.g0) + _lifecycle_checks(ctx, "guest1", k1, ctx.g1)
    if block == "storage_served":
        if k0 != "baremetal":
            return []
        if ctx.name == "panicneg":
            return [expect_n("the restarted storage SP served the guest after the panic", 1, ": storage connect ok")]
        return [expect_n("both guests reached the storage service", 2, ": storage connect ok")]
    if block == "sp_probe_denied":
        if k0 != "baremetal":
            return []
        return [refute_re("the probed storage SP never served a guest connect", ": storage connect ok")]
    if block == "sp_probe_lifecycle":
        # The run may end at the partition's fault on an OS guest, so only
        # its launch is held; a bare-metal pair finishes its lifecycle.
        if k0 == "zephyr":
            return [expect("guest0 launched", ctx.g0["started"])]
        if k0 == "psa":
            return [expect_n("guest0 launched exactly once", 1, ctx.g0["started"]),
                    expect("guest0 ran its whole PSA lifecycle to the end breakpoint", ctx.g0["done"]),
                    expect("guest1 ran beside the partition under test", ctx.g1["started"])]
        return _lifecycle_checks(ctx, "guest0", k0, ctx.g0) + _lifecycle_checks(ctx, "guest1", k1, ctx.g1)
    if block == "l3":
        return _l3(ctx)
    if block == "probe_linked":
        sym = {"deputyneg": "wt_platform_deputy_flash_probe",
               "hsmpinneg": "wt_platform_hsm_pin_probe"}[ctx.name]
        return [symbol("%s linked into the secure image" % sym, sym)]
    if block == "psa_probe_lifecycle":
        if k0 == "zephyr":
            if ctx.name == "hsmfaultneg":
                # guest0's HSM tasklet faults by design; its peer finishes.
                return [expect("guest0 launched", ctx.g0["started"])] + _lifecycle_checks(ctx, "guest1", k1, ctx.g1)
            return _lifecycle_checks(ctx, "guest0", k0, ctx.g0) + _lifecycle_checks(ctx, "guest1", k1, ctx.g1)
        out = [expect_n("guest0 launched exactly once", 1, ctx.g0["started"])]
        if ctx.name == "hsmfaultneg":
            out.append(expect("guest1 ran its whole PSA lifecycle to the end breakpoint", ctx.g1["done"]))
        else:
            out += [expect("guest0 ran its whole PSA lifecycle to the end breakpoint", ctx.g0["done"]),
                    expect("guest1 ran beside the partition under test", ctx.g1["started"])]
        return out
    if block == "psa_served":
        if k0 == "zephyr":
            return []
        return [expect(d, t) for d, t in PSA_SERVED]
    if block == "peer_alive":
        if k1 == "freertos":
            return [expect("unrelated guest kept running", ctx.g1["started"])]
        return []
    if block == "periphspneg":
        if k0 == "zephyr":
            return []
        return [refute_re("the probed storage SP never served ITS", r'guest[01]: wolfTrust ITS set/get verified')]
    if block == "hsmfaultneg":
        if k1 == "freertos":
            return [expect("other guest remains functional", ctx.g1["sha"])]
        return [expect("the other guest kept being served", "guest1: psa_hash_compute(SHA-256) KAT verified")]
    if block == "sp_fault":
        return [expect_re("the probed SP faulted once (Secure-Thread UNDEFINSTR UsageFault)",
                          r'\[USGFLT\].*CFSR=0x00010000', where="faults"),
                refute_re("fault was contained, not escalated", ESCALATION, where="faults")]
    if block == "sp_recovered":
        if k0 == "zephyr":
            return [expect("restarted relay serves mediated key-ops", "wolfTrust key-ops sign/verify verified", where="guest0"),
                    expect("unrelated storage partitions unaffected", "wolfTrust ITS set/get verified", where="guest0"),
                    expect("restarted relay serves the mediated SHA KAT", "psa_hash_compute(SHA-256) KAT verified", where="guest0"),
                    expect("unrelated guest booted and ran through the SP fault", ctx.g1["started"]),
                    expect("restarted relay serves the other-OS client too", ctx.g1["sha"])]
        return []
    if block == "panic_unblocked":
        if k0 == "zephyr":
            return [expect("pinned client unblocked with COMMUNICATION_FAILURE",
                           "psa_connect(SERVICE_ITS) failed rc=0 handle=-145", where="guest0"),
                    expect("sealed storage path unaffected", "wolfTrust PS sealed set/get verified", where="guest0"),
                    expect("unrelated guest booted and ran through the panic", ctx.g1["started"])]
        return []
    if block == "svcneg":
        if k0 == "zephyr":
            return [expect("pinned client unblocked with COMMUNICATION_FAILURE",
                           "psa_connect(SERVICE_ITS) failed rc=0 handle=-145", where="guest0"),
                    expect("sealed storage path unaffected", "wolfTrust PS sealed set/get verified", where="guest0")]
        return [expect_re("the pinned ITS client was unblocked with an error", r'guest[01]: psa_its_set failed st=-1(32|45)'),
                expect("the restarted ITS partition served the other guest", "wolfTrust ITS set/get verified"),
                expect("sealed storage path unaffected", "guest0: wolfTrust PS sealed set/get verified")]
    if block == "restart":
        return _restart_checks(ctx)
    if block == "restartidle_verdict":
        return [expect("terminal recovery verdict", "[EXPECT BKPT] Success")]
    if block == "guestisoneg":
        if k0 == "zephyr":
            return [refute_re("peer RAM never receives the sentinel", re.escape(ctx.g0["iso_leaked"])),
                    either("NS MPU bypass cannot reach peer guest RAM (WT-FFM-0011)", [
                        [expect("peer store blocked without a fault (RAZ/WI)", ctx.g0["iso_blocked"])],
                        [expect("peer store attempted", ctx.g0["iso_attempt"]),
                         refute_re("peer store faults the initiating guest, contained",
                                   re.escape(ctx.g0["done"]))]]),
                    expect("peer guest keeps running through the containment", ctx.g1["heartbeat"])]
        faults = ctx.restart_limit() + 1
        return [expect_n("guest0 relaunched through its restart budget", faults, ctx.g0["started"]),
                expect_n("every guest0 launch completed the FF-M handshake before probing", faults, ctx.g0["done"]),
                expect_n("guest1 launched once, untouched by guest0's faults", 1, ctx.g1["started"]),
                expect_n("guest1 completed the FF-M handshake", 1, ctx.g1["done"])]
    if block == "periphneg":
        mode = ctx.m33mu.get("periph_probe", "faults")
        if k0 == "zephyr" or mode == "verdict":
            m = ctx.g0
            bad = m.get("periph_bad") or "(%s|%s)" % (re.escape(m["periph_leaked"]), re.escape(m["periph_inconclusive"]))
            out = [refute_re("Secure peripheral and memory stay out of NS reach", bad),
                   expect("NS RNG poke and NS DMA copies blocked", m["periph_blocked"])]
            if k0 == "zephyr":
                out += _lifecycle_checks(ctx, "guest0", k0, ctx.g0) + _lifecycle_checks(ctx, "guest1", k1, ctx.g1)
            else:
                out += [expect_n("guest0 launched exactly once", 1, m["started"]),
                        expect_n("guest1 launched once", 1, ctx.g1["started"])]
            return out
        faults = ctx.restart_limit() + 1
        return [expect_n("guest0 relaunched through its restart budget", faults, ctx.g0["started"]),
                refute_re("no NS read of the SPM's peripheral ever returned", "periph probe LEAKED"),
                expect_n("guest1 launched once, untouched by guest0's faults", 1, ctx.g1["started"]),
                expect_n("guest1 completed the FF-M handshake", 1, ctx.g1["done"])]
    if block == "trace":
        return [status("the trace boot ended at its fault (status 0)", (0,), var="trace_status")] + \
            _trace_kind(ctx, v)
    if block == "conformance_boot":
        if k0 == "zephyr":
            return [expect("TEE client initialized", "wolfTrust TEE client initialized"),
                    expect("FF-M psa_framework_version=0x0100", "wolfTrust FF-M psa_framework_version=0x0100"),
                    expect("conformance val_entry start", "wolfTrust FF-M conformance: val_entry start")]
        return [expect("guest0 booted the PSA client", "guest0: wolfTrust FF-M psa_framework_version=0x0100"),
                expect("conformance val_entry start", "guest0: wolfTrust FF-M conformance: val_entry start")]
    if block == "conformance_start":
        return [expect("conformance val_entry start", "wolfTrust FF-M conformance: val_entry start")]
    if block == "confboot":
        out = [totals("Arm FF-M IPC suite (want 85/4/0)", passed=85, skipped=4, failed=0)]
        if k0 == "zephyr":
            out.insert(0, expect("mediated crypto dispatch verified", "wolfTrust FF-M mediated crypto dispatch verified"))
        out.append(ledger("every test matches its recorded result (89 tests)"))
        return out
    if block == "devstorage":
        return [totals("dev_apis storage (17 total)", failed=0, scheduled=17)]
    if block == "devcrypto":
        return [totals("dev_apis crypto (77 scheduled; c047 CMAC config-skipped)", failed=0, scheduled=77)]
    if block == "devattest":
        return [totals("dev_apis initial_attestation (1 passed)", passed=1, failed=0)]
    if block == "vaultrecover":
        return [totals("crypto suite green after self-heal (77 scheduled)", failed=0, scheduled=77)]
    if block == "vaultrecoversec":
        return [refute_re("no fault (fail closed, not a brick)", r'(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'),
                expect("guest starts under fail-closed attestation", "wolfTrust FF-M conformance: val_entry start")]
    if block == "psa_lifecycle":
        if k0 == "zephyr":
            return []
        return _lifecycle_checks(ctx, "guest0", k0, ctx.g0) + _lifecycle_checks(ctx, "guest1", k1, ctx.g1)
    if block == "attestneg":
        pre = "guest0: " if k0 == "psa" else ""
        return [expect("attestation baseline token verified", pre + "wolfTrust attestation: COSE_Sign1 verified"),
                expect("oversized challenge rejected st=-135", pre + "attestneg oversized challenge rejected st=-135"),
                expect("zero token buffer rejected st=-135", pre + "attestneg zero token buffer rejected st=-135"),
                expect("tampered token fails the guest verify", pre + "attestneg tampered token rejected"),
                expect("misattributed lifecycle fails the guest verify", pre + "attestneg lifecycle mismatch rejected"),
                expect("attestation negatives verified", pre + "wolfTrust attestation negatives verified")]
    if block == "hsmattackneg":
        pre = "guest0: " if k0 == "psa" else ""
        return [expect("forged COMM_INIT attempted", pre + "hsmattackneg forged COMM_INIT"),
                expect("IAK sign refused", pre + "hsmattackneg IAK sign refused"),
                expect("rollback NVM group refused", pre + "hsmattackneg rollback NVM group refused"),
                expect("own-namespace crypto still works", pre + "hsmattackneg own-namespace crypto still works"),
                refute_re("IAK sign never succeeded", "hsmattackneg IAK sign SUCCEEDED"),
                refute_re("NVM group never succeeded", "hsmattackneg rollback NVM group SUCCEEDED")]
    if block == "fwustage":
        pre = "guest0: " if k0 == "psa" else ""
        where = "guest0" if k0 == "zephyr" else "log"
        out = [expect("guest booted and reached the FWU probe", ctx.g0["started"]),
               expect("write before start refused on target (WT-FWU-0003)", pre + "wolfTrust FWU write-before-start refused", where=where),
               expect("candidate staged to the update partition and armed (WT-FWU-0002)",
                      pre + "wolfTrust FWU staged signed-header candidate to update partition, armed, verified", where=where),
               expect("reject disarms and clean restores READY (WT-FWU-0003)", pre + "wolfTrust FWU reject disarmed and clean restored READY", where=where),
               expect("unrelated storage partitions unaffected", pre + "wolfTrust ITS set/get verified", where=where)]
        if k0 == "psa":
            out[2:2] = [expect("candidate body streamed across the update partition's data sectors",
                               pre + "wolfTrust FWU streamed candidate body across the update partition"),
                        expect("a write that skips ahead is refused and the session cleans",
                               pre + "wolfTrust FWU out-of-order write refused and cleaned")]
        return out
    if block == "authneg":
        out = [refute_re("the tampered guest0 never entered its domain", re.escape(ctx.g0["started"]))]
        if k1 == "freertos":
            out += [expect("guest1 (unrelated domain) still runs", ctx.g1["heartbeat"]),
                    expect("guest1 mediated SERVICE_CRYPTO still live", ctx.g1["sha"])]
        else:
            out += [expect_n("guest1 launched once after guest0's refusal", 1, ctx.g1["started"]),
                    expect_n("guest1 completed the FF-M handshake", 1, ctx.g1["done"]),
                    expect_n("guest1 reached the storage service", 1, ctx.g1["storage"])]
        return out
    if block.startswith("verdict_"):
        return _verdict(ctx, block[len("verdict_"):])
    if block == "bootupdate":
        return [refute_re("no fault markers across the update reboot", FAULT_MARKERS),
                expect("swapped image runs a clean FF-M lifecycle", "wolfTrust FF-M mediated crypto dispatch verified", where="guest0"),
                expect("token measurement equals the v2 (swapped-in) image measurement",
                       "wolfTrust attestation: token measurement={v2_measurement}", where="guest0"),
                refute_re("the pre-update v1 image is no longer the one attested", "token measurement={expected_measurement}")]
    if block == "vnet":
        return [expect("guest0 alive", "vnet-guest0: alive"), expect("guest1 alive", "vnet-guest1: alive"),
                expect("guest0 sends the first mediated ping", "ping seq=1 to 10.0.0.2"),
                expect("guest0 receives guest1's mediated echo reply", "ping reply from 10.0.0.2 seq=1")]
    if block == "vnetneg":
        return [expect("SPM-RAM read denied to the confined vnet SP (MEMFAULT)", "addr=%s" % v.get("L3_SPM_RAM", "?")),
                expect("execute from the XN vnet data band denied", v.get("vnet_data_band", "0x30070000")),
                refute_re("no HardFault escalation", r'(\[HARDFLT\]|HardFault)'),
                expect("guest0 alive through the quarantine", "vnet-guest0: alive"),
                expect("guest1 alive through the quarantine", "vnet-guest1: alive"),
                expect("mediated ping still completes after both restarts", "ping reply from 10.0.0.2")]
    if block == "revneg":
        peers = "|".join(re.escape(s) for s in (ctx.g0["started"], ctx.g1["started"]))
        return [expect("revision Z refused with the ES0565 2.2.9 console line",
                       "wolfTrust: halt, STM32H563 engineering sample (ES0565 2.2.9) IDCODE 0x10016484"),
                expect("boot halted on the production panic", "[BKPT] imm=0x7e"),
                refute_re("no partition or guest started on refused silicon", r'(Booting Zephyr|' + peers + r'|\[BKPT\] imm=0x7f)')]
    if block == "fpneg":
        return [expect_n_re("the relay took a Secure-Thread UsageFault", 1, r'\[USGFLT\] enter sec=1 mode=0'),
                expect("the fault was the NOCP trap (Secure FP disabled)", "[USGFLT] CFSR=0x00080000"),
                refute_re("FP fault did not escalate (containment only)", ESCALATION),
                refute_re("run did not reach the wall-clock budget", "wall-clock"),
                info("partition restart and guest survival are asserted on silicon, not the emulator")]
    if block == "busfaultneg":
        return [expect_re("relay SP took a precise BusFault at the bus-error window", r'\[BUSFLT\] pc=0x[0-9a-f]+ addr=0x300a0000'),
                refute_re("fault was contained, not escalated", ESCALATION),
                refute_re("platform did not halt on the partition's fault", r'\[BKPT\] imm=0x(6e|7e|7d)')]
    if block == "bothpsa":
        out = []
        if k0 == "zephyr":
            return [expect("Zephyr: mediated SERVICE_CRYPTO SHA-256 KAT", "wolfTrust FF-M mediated crypto dispatch verified", where="guest0"),
                    expect("FreeRTOS: mediated SERVICE_CRYPTO SHA-256 KAT", ctx.g1["sha"]),
                    expect("Zephyr: PSA psa_generate_random", "psa_generate_random st=0", where="guest0"),
                    expect("FreeRTOS: PSA psa_generate_random", "freertos_guest1: psa rng ok"),
                    expect("Zephyr: PSA psa_hash_compute(SHA-256) KAT", "psa_hash_compute(SHA-256) KAT verified", where="guest0"),
                    expect("FreeRTOS: PSA psa_hash_compute(SHA-256) KAT", "freertos_guest1: psa hash ok")]
        for g in ("guest0", "guest1"):
            out += [expect("%s: %s" % (g, d), t.replace("{g}", g)) for d, t in PSA_GUEST_CHECKS]
        return out
    if block == "bothiso":
        if k0 == "zephyr":
            return [expect("Zephyr: forged-handle call rejected", "wolfTrust FF-M forged-handle call rejected", where="guest0"),
                    expect("Zephyr: oversized-vector call rejected", "wolfTrust FF-M oversized-vector call rejected", where="guest0"),
                    expect("FreeRTOS: forged-handle call rejected", "freertos_guest1: ffm forged-handle rejected"),
                    expect("FreeRTOS: oversized-vector call rejected", "freertos_guest1: ffm oversized-vector rejected"),
                    expect("FreeRTOS: cross-guest vector refused (caller-banded memcheck)", "freertos_guest1: ffm cross-guest vector rejected"),
                    expect("FreeRTOS: unknown-SID connect refused", "freertos_guest1: ffm wrong-sid refused"),
                    expect("FreeRTOS survived: still serves mediated SERVICE_CRYPTO", ctx.g1["sha"])]
        out = []
        for g in ("guest0", "guest1"):
            out += [expect("%s: forged-handle call rejected" % g, "%s: wolfTrust FF-M forged-handle call rejected" % g),
                    expect("%s: oversized-vector call rejected" % g, "%s: wolfTrust FF-M oversized-vector call rejected" % g),
                    expect("%s: cross-guest vector refused (caller-banded memcheck)" % g, "%s: wolfTrust FF-M cross-guest vector rejected" % g),
                    expect("%s: unknown-SID connect refused" % g, "%s: wolfTrust FF-M unknown-SID connect refused" % g),
                    expect("%s: still served after the negatives" % g, "%s: psa_hash_compute(SHA-256) KAT verified" % g)]
        return out
    if block == "handlerneg":
        faults = ctx.restart_limit() + 1
        return [expect_n("guest0 relaunched through its restart budget, then quarantined", faults, ctx.g0["started"]),
                refute_re("guest0 never got past its handler", re.escape(ctx.g0["connect"])),
                expect_n("guest1 launched once, untouched by guest0's overruns", 1, ctx.g1["started"]),
                expect_n("guest1 completed the FF-M handshake", 1, ctx.g1["done"])]
    if block == "fence_selftest":
        return [expect("the boot-root erase was refused", "xspi protect selftest PASS"),
                expect("an erase inside the guest fence was refused, block unchanged", "xspi guest fence selftest PASS")]
    if block == "fenced":
        return [expect_n("guest0 launched behind the armed guest fence", 1, ctx.g0["started"]),
                expect_n("guest0 reached the SPM and finished", 1, ctx.g0["done"]),
                expect_n("guest1 launched behind the armed guest fence", 1, ctx.g1["started"]),
                expect_n("guest1 reached the SPM and finished", 1, ctx.g1["done"]),
                expect_n("both guests reached the storage service", 2, ": storage connect ok")]
    if block == "wrpoff":
        peers = "|".join(re.escape(s) for s in (ctx.g0["started"], ctx.g1["started"]))
        return [refute_re("no guest entered its domain without the guest fence", peers)]
    raise SystemExit("unknown block %s" % block)


BLOCK_CAPS = {"boot_console": ("boot_console",), "trace": ("prot_trace",)}


def plan(port, scenario, engine="native"):
    r = resolve(port, scenario, engine)
    blocks = ["end", "boot_console"] + list(r["blocks"])
    if r["trace"]:
        blocks.append("trace")
    absent = caps_absent(port)
    applicable = []
    na = []
    for b in blocks:
        need = [c for c in BLOCK_CAPS.get(b, ()) if c in absent]
        if need:
            na.append((b, "; ".join("%s: %s" % (c, absent[c]) for c in need)))
        else:
            applicable.append(b)
    r["applicable"] = applicable
    r["na"] = na
    return r


# ------------------------------------------------------------------ judge --

def read(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")


PLACEHOLDER = re.compile(r"\{([a-z][a-z_0-9]*)\}")


def substitute(text, var):
    """{name} placeholders from the runner's variables; a regex quantifier
    such as {6} is not a name and stays."""
    return PLACEHOLDER.sub(lambda m: var.get(m.group(1), m.group(0)), text)


def count_text(text, needle):
    return text.count(needle)


def count_re(text, pattern):
    return len(re.findall(pattern, text, re.M))


def faults_at_count(text, addr, lo=None, hi=None):
    """MemManage faults at exactly addr; with lo/hi only those whose stacked
    SP, printed on the dump's next line, lies in [lo, hi)."""
    want = addr.lower()
    n = 0
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("[MEMFAULT] pc="):
            continue
        if ("addr=" + want) not in line.lower().split():
            continue
        if lo is None:
            n += 1
            continue
        if i + 1 < len(lines) and lines[i + 1].startswith("[MEMFAULT] sp="):
            sp = int(lines[i + 1].split()[1].split("=")[1], 16)
            if int(lo, 16) <= sp < int(hi, 16):
                n += 1
    return n


def conf_totals(text):
    flat = re.sub(r"guest1:.*$", "", text, flags=re.M).replace("\r", "").replace("\n", "")
    out = {}
    for key in ("PASSED", "SKIPPED", "FAILED"):
        found = re.findall(r"TOTAL %s[ \t]*:[ \t]*([0-9]+)" % key, flat)
        out[key] = int(found[-1]) if found else -1
    return out


class Judge(object):
    def __init__(self, ctx, logs):
        self.ctx = ctx
        self.logs = logs
        self.failures = 0
        self.lines = []

    def text(self, where):
        if where == "faults":
            where = "log"
        if where not in self.logs:
            raise SystemExit("no %s evidence was given" % where)
        return self.logs[where]

    def sub(self, s):
        return substitute(s, self.ctx.var)

    def report(self, ok, desc, why=""):
        if ok:
            self.lines.append("  [check] PASS  %s" % desc)
        else:
            self.failures += 1
            self.lines.append("  [check] FAIL  %s  (%s)" % (desc, why))
        return ok

    def run(self, check):
        op = check["op"]
        if op == "info":
            self.lines.append("  [check] INFO  %s" % check["desc"])
            return True
        if op == "either":
            for option in check["options"]:
                sub = Judge(self.ctx, self.logs)
                if all(sub.run(c) for c in option):
                    self.lines.append("  [check] PASS  %s (%s)" % (check["desc"], option[0]["desc"]))
                    return True
            return self.report(False, check["desc"], "no option held")
        if op == "status":
            got = int(self.ctx.var.get(check["var"], "-1"))
            return self.report(got in check["accept"], check["desc"], "got status %d" % got)
        if op == "symbol":
            syms = self.text("syms")
            return self.report(re.search(r" %s$" % re.escape(check["name"]), syms, re.M) is not None,
                               check["desc"], "symbol absent")
        if op == "totals":
            t = conf_totals(self.text("guest0" if "guest0" in self.logs else "log"))
            ok = t["FAILED"] == check["failed"]
            if check["passed"] is not None:
                ok = ok and t["PASSED"] == check["passed"]
            if check["skipped"] is not None:
                ok = ok and t["SKIPPED"] == check["skipped"]
            if check["scheduled"] is not None:
                ok = ok and t["PASSED"] + t["SKIPPED"] == check["scheduled"]
            return self.report(ok, "%s: %d passed, %d skipped, %d failed" %
                               (check["desc"], t["PASSED"], t["SKIPPED"], t["FAILED"]), "totals")
        if op == "ledger":
            want = self.ctx.var.get("conf_want")
            rev = self.ctx.var.get("conf_rev", "")
            if not want or not os.path.isfile(want):
                return self.report(False, check["desc"], "no recorded results file")
            recorded = read(want)
            if rev not in recorded:
                return self.report(False, check["desc"], "%s was not recorded for psa-arch-tests %s" % (want, rev))
            got = []
            num = None
            for m in re.finditer(r"Num=([0-9]+)|Result=([A-Za-z]+)", self.text("guest0" if "guest0" in self.logs else "log")):
                if m.group(1) is not None:
                    num = m.group(1)
                elif num is not None:
                    got.append((int(num), m.group(2)))
                    num = None
            got = sorted(set(got))
            wanted = []
            for line in recorded.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                wanted.append((int(parts[0]), parts[1]))
            return self.report(got == wanted, check["desc"],
                               "per-test results differ from %s" % want)
        text = self.text(check["where"])
        if op == "expect":
            needle = self.sub(check["text"])
            return self.report(needle in text, check["desc"], "missing: %s" % needle)
        if op == "expect_n":
            needle = self.sub(check["text"])
            n = count_text(text, needle)
            return self.report(n == check["n"], "%s (%d)" % (check["desc"], n), "want %d of: %s" % (check["n"], needle))
        if op == "expect_re":
            pat = self.sub(check["re"])
            return self.report(count_re(text, pat) >= 1, check["desc"], "missing: %s" % pat)
        if op == "expect_n_re":
            pat = self.sub(check["re"])
            n = count_re(text, pat)
            return self.report(n == check["n"], "%s (%d)" % (check["desc"], n), "want %d of: %s" % (check["n"], pat))
        if op == "refute_re":
            pat = self.sub(check["re"])
            return self.report(count_re(text, pat) == 0, check["desc"], "unexpected: %s" % pat)
        if op == "faults_at":
            if not check["addr"]:
                return self.report(False, check["desc"], "no layout address")
            n = faults_at_count(text, check["addr"], check["lo"], check["hi"])
            ok = n >= check["n"] if check["cmp"] == "ge" else n == check["n"]
            return self.report(ok, "%s (saw %d)" % (check["desc"], n), "want %s %d" % (check["cmp"], check["n"]))
        if op == "sau_refusal":
            pat = self.sub(check["re"])
            lines = text.splitlines()
            n = 0
            for i, line in enumerate(lines):
                if re.search(pat, line) and i + 1 < len(lines) and "src=SAU" in lines[i + 1]:
                    n += 1
            return self.report(n == 1, check["desc"], "saw %d SAU refusals" % n)
        raise SystemExit("unknown check %s" % op)


def judge(port, scenario, env, logs, var, engine="native"):
    p = plan(port, scenario, engine)
    ctx = Ctx(port, p["scenario"], env, p["guests"], var)
    j = Judge(ctx, logs)
    for block, why in p["na"]:
        j.lines.append("  [check] N/A   %s: %s" % (block, why))
    for block in p["applicable"]:
        if block == "trace":
            var["trace_kind"] = p["trace"]
        for check in block_checks(ctx, block, p["end"]):
            j.run(check)
    return j


# --------------------------------------------------------------- selftest --

PROFILE_LABEL = re.compile(r"^\s*[a-z0-9|\[\]-]+\)")


def profile_gaps():
    """A port profile may name a scenario only as a case label inside one of
    its hooks, so no port-private verdict or flag hides in a profile."""
    gaps = []
    names = set(SCENARIOS) | set(ALIASES)
    root = os.path.join(scenario_matrix.REPO_ROOT, "tests", "target", "ports")
    for port in sorted(PORTS):
        path = os.path.join(root, port, "m33mu.sh")
        if not os.path.isfile(path):
            gaps.append("%s has no tests/target/ports/%s/m33mu.sh" % (port, port))
            continue
        with open(path) as handle:
            for number, line in enumerate(handle, 1):
                code = line.split("#", 1)[0]
                tokens = set(re.findall(r"(?<![A-Za-z0-9_-])[a-z0-9]+(?![A-Za-z0-9_-])", code))
                if tokens & names and not PROFILE_LABEL.match(code):
                    gaps.append("%s/m33mu.sh:%d names a scenario outside a case label" %
                                (port, number))
    return gaps


def selftest():
    gaps = profile_gaps()
    for name, row in SCENARIOS.items():
        if canonical(name) != name:
            gaps.append("%s is an alias" % name)
        if row["role"] not in ROLES:
            gaps.append("%s: bad role" % name)
        for cap in row["requires"]:
            if cap not in CAPABILITIES:
                gaps.append("%s requires unknown capability %s" % (name, cap))
    for port in sorted(PORTS):
        m33mu = port_m33mu(port)
        for role in ROLES:
            try:
                guest_pair(port, role)
            except SystemExit as exc:
                gaps.append(str(exc))
        for cap, reason in caps_absent(port).items():
            if cap not in CAPABILITIES:
                gaps.append("%s declares unknown capability %s absent" % (port, cap))
            if not str(reason).strip():
                gaps.append("%s: caps_absent.%s has no reason" % (port, cap))
        for name, reason in faults_by_design(port).items():
            if canonical(name) not in SCENARIOS or not str(reason).strip():
                gaps.append("%s: faults_by_design.%s is unknown or has no reason" % (port, name))
        for name, flags in m33mu.get("guest_flags", {}).items():
            if name not in SCENARIOS or not str(flags).strip():
                gaps.append("%s: guest_flags.%s is unknown or empty" % (port, name))
        for name, end in m33mu.get("ends", {}).items():
            if name not in SCENARIOS or not (end in ("fault", "idle", "timeout") or re.match(r"^bkpt:0x[0-9a-f]+$", str(end))):
                gaps.append("%s: ends.%s is unknown or not an end mode" % (port, name))
        run = set(scenario_matrix.flat(port, "full", None))
        # A run that should hit the wall clock passes on exit 0 only where
        # guest0 ends it on its own clean breakpoint.
        for name in sorted(n for n in run if n in SCENARIOS):
            r = resolve(port, name, "native")
            if r["end"] == "timeout":
                accept = _end_checks(Ctx(port, name, "emulator", r["guests"], {"board": "X"}), "timeout")[0]["accept"]
                if tuple(accept) != ((127, 0) if r["guest0_end"] == "bkpt" else (127,)):
                    gaps.append("%s %s: a timeout run accepts exit status %s" % (port, name, accept))
        for name in run:
            if name in ALIASES:
                gaps.append("%s lists the port-private name %s (use %s)" % (port, name, ALIASES[name]))
            elif name not in SCENARIOS:
                gaps.append("%s lists unknown scenario %s" % (port, name))
        exempt = dict(m33mu.get("exempt", {}))
        for name in sorted(SCENARIOS):
            if name in run:
                if name in exempt:
                    gaps.append("%s runs %s but still exempts it" % (port, name))
                missing = [c for c in SCENARIOS[name]["requires"] if c in caps_absent(port)]
                if missing:
                    gaps.append("%s runs %s without %s" % (port, name, " ".join(missing)))
            elif name not in exempt or not str(exempt[name]).strip():
                missing = [c for c in SCENARIOS[name]["requires"] if c in caps_absent(port)]
                if not missing:
                    gaps.append("%s neither runs nor exempts %s" % (port, name))
        for name in exempt:
            if name not in SCENARIOS:
                gaps.append("%s exempts unknown scenario %s" % (port, name))
        for name in run:
            for engine in ("native", "hsm"):
                if engine in SCENARIOS[name]["engines"]:
                    try:
                        p = plan(port, name, engine)
                        ctx = Ctx(port, name, "emulator", p["guests"], {"board": "X"})
                        for block in p["applicable"]:
                            ctx.var["trace_kind"] = p["trace"]
                            block_checks(ctx, block, p["end"])
                    except SystemExit as exc:
                        gaps.append("%s/%s: %s" % (port, name, exc))
    return gaps


def shell_plan(p):
    out = []
    for key, value in (("SC_SCENARIO", p["scenario"]), ("SC_SECURE", p["secure"]),
                       ("SC_ROLE", p["role"]), ("SC_GUEST0", p["guests"][0]),
                       ("SC_GUEST1", p["guests"][1]), ("SC_GUEST_FLAGS", p["guest_flags"]),
                       ("SC_END", p["end"]), ("SC_TIMEOUT", str(p["timeout"])),
                       ("SC_QUIT_ON_FAULTS", "1" if p["quit_on_faults"] else "0"),
                       ("SC_TRACE", p["trace"] if "trace" in p["applicable"] else ""),
                       ("SC_MISSING", " ".join(p["missing"])),
                       ("SC_ENGINES", " ".join(p["engines"])),
                       ("SC_PREBUILD", p["prebuild"]),
                       ("SC_UPDATE", "1" if p["update"] else "0"),
                       ("SC_TAMPER", "1" if p["tamper"] else "0"),
                       ("SC_GUEST0_END", p["guest0_end"]),
                       ("SC_BLOCKS", " ".join(p["applicable"]))):
        out.append("%s=%s" % (key, shell_quote(value)))
    return "\n".join(out)


def shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", choices=sorted(PORTS))
    parser.add_argument("--scenario")
    parser.add_argument("--engine", choices=("native", "hsm"), default="native")
    parser.add_argument("--env", choices=("emulator", "hardware"), default="emulator")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--shell", action="store_true", help="the resolved plan as SC_* assignments")
    mode.add_argument("--asserts", action="store_true", help="the applicable blocks and their checks")
    mode.add_argument("--list", action="store_true", help="every scenario")
    mode.add_argument("--hardware-minimum", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--canonical", action="store_true", help="the canonical name of --scenario")
    sub = parser.add_subparsers(dest="cmd")
    j = sub.add_parser("judge")
    j.add_argument("--log", required=True)
    j.add_argument("--trace-log")
    j.add_argument("--guest0-log")
    j.add_argument("--syms")
    j.add_argument("--var", action="append", default=[])
    args = parser.parse_args()

    if args.list:
        print(" ".join(sorted(SCENARIOS)))
        return 0
    if args.hardware_minimum:
        print(" ".join(HARDWARE_MINIMUM))
        return 0
    if args.selftest:
        gaps = selftest()
        if gaps:
            print("scenarios selftest: " + "; ".join(gaps), file=sys.stderr)
            return 1
        print("scenarios selftest ok")
        return 0
    if args.scenario and args.canonical:
        print(canonical(args.scenario))
        return 0
    if args.port is None or args.scenario is None:
        parser.error("--port and --scenario are required")
    p = plan(args.port, args.scenario, args.engine)
    if args.shell:
        print(shell_plan(p))
        return 0
    if args.asserts:
        ctx = Ctx(args.port, p["scenario"], args.env, p["guests"], {"board": PORTS[args.port]["def"]["display"]})
        for block, why in p["na"]:
            print("N/A %s: %s" % (block, why))
        for block in p["applicable"]:
            ctx.var["trace_kind"] = p["trace"]
            print("block %s" % block)
            for check in block_checks(ctx, block, p["end"]):
                print("  %s: %s" % (check["op"], check["desc"]))
        return 0
    if args.cmd == "judge":
        var = {}
        for item in args.var:
            key, _, value = item.partition("=")
            var[key] = value
        logs = {"log": read(args.log)}
        if args.trace_log:
            logs["trace"] = read(args.trace_log)
        if args.guest0_log:
            logs["guest0"] = read(args.guest0_log)
        elif p["guests"][0] != "zephyr":
            logs["guest0"] = logs["log"]
        if args.syms:
            logs["syms"] = read(args.syms)
        result = judge(args.port, args.scenario, args.env, logs, var, args.engine)
        print("\n".join(result.lines))
        return 1 if result.failures else 0
    parser.error("nothing to do")
    return 2


if __name__ == "__main__":
    sys.exit(main())
