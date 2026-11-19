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
import collections
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

GUEST_KINDS = ("baremetal", "psa", "zephyr", "freertos", "vnet", "interface")
ROLES = ("lifecycle", "psa", "conformance", "vnet", "hwpsa", "tpm", "pkcs11")
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
    "hw_console": "the board's console is captured during a hardware run",
    "hw_secure_swd": "the debugger reads Secure RAM on the fixture (an open board)",
    "rom_xip": "the BootROM boots an XIP image the port's smoke firmware proves",
    "ns_handler_probes": "the bare-metal guest's NS entry-mask and parked-IRQ probes",
    "pris": "AIRCR.PRIS holds the Secure tick above every Non-secure mask",
    "ns_bus_hole": "an unmapped Non-secure peripheral hole raises a precise BusFault",
    "write_once": "the PSA guest seals a WRITE_ONCE object across a reset",
    "boot_header_swd": "the boot slot's wolfBoot header is read back over SWD",
}


def S(secure="", role="lifecycle", guest_flags="", end="guest", timeout=None,
      quit_on_faults=True, trace=None, blocks=(), engines=("native", "hsm"),
      requires=(), level3=False, hw=False, prebuild="", update=False,
      tamper=False, note="", envs=("emulator", "hardware"), hw_blocks=(),
      hw_requires=(), hw_secure=""):
    return {"secure": secure, "role": role, "guest_flags": guest_flags,
            "end": end, "timeout": timeout, "quit_on_faults": quit_on_faults,
            "trace": trace, "blocks": tuple(blocks), "engines": tuple(engines),
            "requires": tuple(requires), "level3": level3, "hw": hw,
            "prebuild": prebuild, "update": update, "tamper": tamper,
            "note": note, "envs": tuple(envs), "hw_blocks": tuple(hw_blocks),
            "hw_requires": tuple(hw_requires), "hw_secure": hw_secure}


SP_PROBE_FLAGS = "WT_M33MU_EXPECT_BKPT=1"
TPM_APP = "WT_INTERFACE=tpm " + SP_PROBE_FLAGS
PKCS11_APP = "WT_INTERFACE=pkcs11 " + SP_PROBE_FLAGS
# Emulator-only: the PIN KDF at its production cost outlasts the budget.
PKCS11_KDF = "WT_PKCS11_TEST_PBKDF2_ITERATIONS=25"
CONF = "WT_RUN_CONFORMANCE=1"

SCENARIOS = {
    "positive": S(blocks=("no_faults", "lifecycle", "storage_served"),
                  hw=True,
                hw_blocks=("hw_no_faults", "hw_lifecycle", "hw_launched_all", "hw_no_restarts", "hw_positive_extras")),
    "restart": S(guest_flags="WT_GUEST_FAULT_PROBE=1", end="timeout",
                 timeout=40, quit_on_faults=False, trace="restart",
                 blocks=("restart",), hw=True,
                hw_blocks=("hw_no_escalation", "hw_quarantined", "hw_peer_alive")),
    "restartidle": S(guest_flags="WT_GUEST_FAULT_PROBE=1", end="bkpt:0x7d",
                     timeout=40, quit_on_faults=False,
                     blocks=("restart", "restartidle_verdict"),
                     requires=("idle_scheduler",)),
    # The peer's first heartbeat follows its wolfHSM crypto, which the portable
    # C wolfCrypt serves past 40 s while guest0's restarts share the server.
    "guestisoneg": S(guest_flags="WT_ISO_PROBE=1", end="timeout", timeout=90,
                     quit_on_faults=False, trace="guestisoneg",
                     blocks=("guestisoneg",), hw=True,
                hw_blocks=("hw_no_escalation", "hw_guestisoneg", "hw_peer_alive")),
    "periphneg": S(guest_flags="WT_PERIPH_NEG_PROBE=1", trace="periphneg",
                   blocks=("periphneg",), hw=True,
                hw_blocks=("hw_periphneg", "hw_peer_alive")),
    "crossdomain": S(secure="WT_FFM_NEGATIVE_PROBE=1", trace="band_read",
                     blocks=("sp_probe_lifecycle", "sp_probe_denied", "l3"),
                     level3=True, hw=True,
                hw_blocks=("hw_no_escalation", "hw_sp_fault", "hw_sp_guests", "hw_peer_alive")),
    "keystoreneg": S(secure="WT_KEYSTORE_NEG_PROBE=1", trace="band_read",
                     blocks=("sp_probe_lifecycle", "sp_probe_denied", "l3"),
                     level3=True,
                hw_blocks=("hw_no_escalation", "hw_sp_fault", "hw_sp_guests", "hw_peer_alive")),
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
                          "storage_served"),
                hw_blocks=("hw_no_escalation", "hw_panic", "hw_peer_alive")),
    # The wolfHSM engine's portable C crypto takes about 20 minutes on a CI
    # runner; the budget stays inside the job's 45-minute limit.
    "confboot": S(secure="WT_CONFORMANCE=1", role="conformance",
                  guest_flags=CONF + " " + SP_PROBE_FLAGS, end="bkpt:0x7f",
                  timeout=2100, quit_on_faults=False,
                  blocks=("conformance_boot", "confboot"),
                hw_blocks=("hw_confboot",), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "devstorage": S(secure="WT_CONFORMANCE=1", role="conformance",
                    guest_flags=CONF + " WT_CONF_SUITE=storage " + SP_PROBE_FLAGS,
                    end="bkpt:0x7f", timeout=900, quit_on_faults=False,
                    blocks=("conformance_boot", "devstorage"),
                hw_blocks=("hw_no_escalation", "hw_devsuite"), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "devcrypto": S(secure="WT_CONFORMANCE=1", role="conformance",
                   guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                   end="bkpt:0x7f", timeout=7200, quit_on_faults=False,
                   blocks=("conformance_boot", "devcrypto"),
                hw_blocks=("hw_no_escalation", "hw_devsuite"), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "devcryptolocal": S(secure="WT_CONFORMANCE=1 WT_SECURE_PSA=0", role="conformance",
                       guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                       end="bkpt:0x7f", timeout=7200, quit_on_faults=False,
                       blocks=("conformance_boot", "devcrypto"),
                       engines=("native",), envs=("emulator",)),
    "devattest": S(secure="WT_CONFORMANCE=1", role="conformance",
                   guest_flags=CONF + " WT_CONF_SUITE=attestation " + SP_PROBE_FLAGS,
                   end="bkpt:0x7f", timeout=900,
                   blocks=("conformance_boot", "devattest"),
                hw_blocks=("hw_no_escalation", "hw_devattest"), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "devattestqcbor": S(secure="WT_CONFORMANCE=1", role="conformance",
                        guest_flags=CONF + " WT_CONF_SUITE=attestation WT_ATTEST_CBOR=qcbor " + SP_PROBE_FLAGS,
                        end="bkpt:0x7f", timeout=900,
                        blocks=("conformance_boot", "devattest"),
                        prebuild="tests/upstream/fetch_qcbor.sh",
                hw_blocks=("hw_no_escalation", "hw_devattest"), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "attestneg": S(role="psa", guest_flags="WT_ATTEST_NEG_PROBE=1",
                   blocks=("psa_lifecycle", "attestneg")),
    "nativewire": S(role="hwpsa", guest_flags="WT_NATIVE_WIRE_PROBE=1 " + SP_PROBE_FLAGS,
                    end="bkpt:0x7f", engines=("native",),
                    blocks=("no_faults", "psa_lifecycle", "nativewire")),
    "nativewireasm": S(secure="WT_SECURE_PSA=0 WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1",
                       role="hwpsa", guest_flags="WT_NATIVE_WIRE_PROBE=1 " + SP_PROBE_FLAGS,
                       end="bkpt:0x7f", engines=("native",),
                       blocks=("no_faults", "psa_lifecycle", "nativewire")),
    "hsmattackneg": S(role="psa", guest_flags="WT_HSM_ATTACK_PROBE=1",
                      blocks=("no_faults", "psa_lifecycle", "hsmattackneg"),
                      engines=("hsm",),
                hw_blocks=("hw_no_faults", "hw_hsmattack")),
    "authneg": S(end="timeout", timeout=40, blocks=("no_faults", "authneg"),
                 tamper=True, hw=True,
                hw_blocks=("hw_no_faults", "hw_authneg", "hw_peer_alive")),
    "rollbackneg": S(secure="WT_ROLLBACK_PROBE=1", end="bkpt:0x7d",
                     blocks=("verdict_rollbackneg",)),
    "vaultrecover": S(secure="WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1",
                      role="conformance",
                      guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                      end="bkpt:0x7f", timeout=7200,
                      blocks=("conformance_start", "vaultrecover"),
                hw_blocks=("hw_no_escalation", "hw_vaultrecover"), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "vaultrecoversec": S(secure="WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1 WT_VAULT_PROBE_SECURED=1",
                         role="conformance",
                         guest_flags=CONF + " WT_CONF_SUITE=crypto " + SP_PROBE_FLAGS,
                         end="timeout", timeout=900,
                         blocks=("vaultrecoversec",),
                hw_blocks=("hw_no_escalation", "hw_vaultrecoversec"), hw_secure="WT_CONF_DIAG_TRAP=0"),
    "fwustage": S(role="psa", guest_flags="WT_FWU_PROBE=1",
                  blocks=("no_faults", "psa_lifecycle", "fwustage")),
    "remeasureneg": S(secure="WT_REMEASURE_PROBE=1", end="bkpt:0x6c",
                      blocks=("verdict_remeasureneg",)),
    "bootupdate": S(secure="WT_BOOTUPDATE_PROBE=1", timeout=150,
                    blocks=("bootupdate",), requires=("bootupdate",),
                    update=True,
                hw_blocks=("hw_bootupdate",), hw_requires=("boot_header_swd",)),
    "vnet": S(secure="CONFIG_VNET=y", role="vnet", timeout=180,
              blocks=("no_faults", "vnet"), requires=("vnet",),
                hw_blocks=("hw_no_faults", "vnet")),
    "vnetneg": S(secure="CONFIG_VNET=y WT_VNET_NEG_PROBE=1", role="vnet",
                 timeout=180, quit_on_faults=False, blocks=("vnetneg",),
                 requires=("vnet",),
                hw_blocks=("hw_no_escalation", "hw_vnetneg")),
    "tpm": S(secure="CONFIG_TPM=y", role="tpm", guest_flags=TPM_APP,
             end="bkpt:0x7f", timeout=360, blocks=("no_faults", "tpm"),
             envs=("emulator",)),
    "tpmneg": S(secure="CONFIG_TPM=y WT_TPM_NEG_PROBE=1", role="tpm",
                guest_flags=TPM_APP, end="bkpt:0x7f", timeout=360,
                quit_on_faults=False, blocks=("tpmneg",), level3=True,
                envs=("emulator",)),
    "pkcs11": S(secure="CONFIG_PKCS11=y " + PKCS11_KDF, role="pkcs11",
                guest_flags=PKCS11_APP, end="bkpt:0x7f", timeout=1200,
                blocks=("no_faults", "pkcs11"), envs=("emulator",)),
    "pkcs11neg": S(secure="CONFIG_PKCS11=y WT_PKCS11_NEG_PROBE=1 " + PKCS11_KDF,
                   role="pkcs11", guest_flags=PKCS11_APP + " WT_PKCS11_FULL_SUITE=core",
                   end="bkpt:0x7f", timeout=360, quit_on_faults=False,
                   blocks=("pkcs11neg",), level3=True, envs=("emulator",)),
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
               level3=True,
                hw_blocks=("hw_no_escalation", "hw_fpneg", "hw_lifecycle", "hw_peer_alive")),
    "sealneg": S(secure="WT_SEAL_NEG_PROBE=1", role="psa",
                 guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                 quit_on_faults=False,
                 blocks=("psa_probe_lifecycle", "l3", "peer_alive"),
                 level3=True,
                hw_blocks=("hw_no_escalation", "hw_seal", "hw_lifecycle", "hw_peer_alive")),
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
                      level3=True,
                hw_blocks=("hw_no_escalation", "hw_seal", "hw_lifecycle", "hw_peer_alive")),
    "mspovfneg": S(secure="WT_MSP_OVF_PROBE=1", end="fault", timeout=40,
                   blocks=("verdict_mspovfneg",),
                   level3=True,
                hw_blocks=("hw_mspovf",)),
    "busfaultneg": S(secure="WT_BUSFAULT_NEG_PROBE=1", quit_on_faults=False,
                     blocks=("busfaultneg", "sp_recovered"),
                     requires=("busfault",),
                hw_blocks=("hw_no_escalation", "hw_busfault", "hw_lifecycle", "hw_peer_alive")),
    "xnneg": S(secure="WT_XN_NEG_PROBE=1", end="fault", timeout=40,
               blocks=("verdict_xnneg",), level3=True,
                hw_blocks=("hw_xnneg",)),
    "svcneg": S(secure="WT_SVC_NEG_PROBE=1", role="psa",
                guest_flags=SP_PROBE_FLAGS, end="bkpt:0x7f",
                quit_on_faults=False,
                blocks=("psa_probe_lifecycle", "l3", "svcneg", "peer_alive"),
                level3=True,
                hw_blocks=("hw_no_escalation", "hw_panic", "hw_peer_alive")),
    "bothpsa": S(role="psa", blocks=("no_faults", "psa_lifecycle", "bothpsa")),
    "bothiso": S(role="psa", blocks=("no_faults", "psa_lifecycle", "bothiso")),
    "handlerneg": S(guest_flags="WT_HANDLER_OVERRUN_PROBE=1", end="timeout",
                    quit_on_faults=False, blocks=("handlerneg",),
                    requires=("handler_overrun",)),
    "wrpfence": S(secure="WT_GUEST_FLASH_WRP=1", blocks=("no_faults", "fenced"),
                  requires=("guest_fence",),
                hw_blocks=("hw_fenced",)),
    "wrpneg": S(secure="WT_GUEST_FLASH_WRP=1",
                blocks=("no_faults", "fence_selftest", "fenced"),
                requires=("guest_fence",),
                hw_blocks=("hw_fenced", "hw_fence_selftest")),
    "wrpoff": S(secure="WT_GUEST_FLASH_WRP=1", end="timeout",
                blocks=("wrpoff",), hw=True,
                note="a fence-required image behind a first stage that arms none",
                hw_blocks=("hw_wrpoff", "hw_wrpoff_fence")),
}
SCENARIOS.update({
    "psa": S(role="hwpsa", envs=("hardware",), hw=True,
             hw_blocks=("hw_no_faults", "hw_lifecycle", "hw_launched_all", "hw_no_restarts")),
    "nsentrymask": S(guest_flags="WT_NS_ENTRY_MASK_PROBE=1", envs=("hardware",),
                     hw_requires=("ns_handler_probes",),
                     hw_blocks=("hw_lifecycle", "hw_entry_mask")),
    "handlerirqneg": S(guest_flags="WT_HANDLER_IRQ_PROBE=64", envs=("hardware",),
                       hw_requires=("ns_handler_probes",),
                       hw_blocks=("hw_handler_irq",)),
    "romsmoke": S(envs=("hardware",), hw_requires=("rom_xip",),
                  hw_blocks=("hw_romsmoke",)),
    "nsmaskneg": S(guest_flags="WT_NS_MASK_PROBE=1", envs=("hardware",),
                   hw_requires=("pris",), hw_blocks=("hw_nsmask",)),
    "nsbusfaultneg": S(guest_flags="WT_NS_BUSFAULT_PROBE=1", envs=("hardware",),
                       hw_requires=("ns_bus_hole",),
                       hw_blocks=("hw_no_escalation", "hw_nsbusfault", "hw_peer_alive")),
    "writeonce": S(guest_flags="WT_WRITE_ONCE_RESET_PROBE=1", envs=("hardware",),
                   hw_requires=("write_once",),
                   hw_blocks=("hw_no_faults", "hw_writeonce")),
})
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

# What an absent guest "prints": a one-guest image never schedules guest1,
# so every expectation of it can only be met by a guest that is there.
NO_GUEST_MARKER = "@no_guest1@"


def markers(kind, guest, board):
    """Console markers a guest of this kind prints, by role in the story."""
    if kind == "none":
        return collections.defaultdict(lambda: NO_GUEST_MARKER)
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
    if kind == "interface":
        return {"started": "-%s: alive" % guest}
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


def sau_refusal(desc, pattern, where="trace", src="SAU"):
    return {"op": "sau_refusal", "desc": desc, "re": pattern, "where": where, "src": src}


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


def word(desc, key, eq=None, ne=None, mask=None, ge=None, lo=None, hi=None,
         in_=None, absent_ok=False):
    """One SWD word of the hardware evidence (key=hex in swd.txt). With mask,
    the masked value must equal eq; lo/hi bound it half-open. absent_ok
    accepts a symbol the collector recorded as absent (link-eliminated)."""
    return {"op": "word", "desc": desc, "key": key, "eq": eq, "ne": ne,
            "mask": mask, "ge": ge, "lo": lo, "hi": hi, "in": in_,
            "absent_ok": absent_ok}


def advancing(desc, key):
    """The word was read twice (key@0, key@1) and moved: the guest is alive."""
    return {"op": "advancing", "desc": desc, "key": key}


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
        self.hw = dict(PORTS[port]["def"].get("hardware", {}))

    def restart_limit(self):
        return int(self.var.get("restart_limit", "3"))

    def kind(self, i):
        return self.guests[i]

    def live_guests(self):
        return sum(1 for kind in self.guests if kind != "none")


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


PKCS11_PASSED = {"core": 10, "objects": 8, "crypto": 10, "negative": 12,
                 "all": 40, "profile": 9}


def _interface_neg(v, what):
    band, spm = v.get("L3_INTERFACE_BAND"), v.get("L3_SPM_RAM")
    lo, hi = v.get("L3_INTERFACE_STACK_LO"), v.get("L3_INTERFACE_STACK_HI")
    return [faults_at("%s band %s read then written by the crypto partition (2 MEMFAULTs)" % (what, band),
                      2, band, v.get("L3_CRYPTO_STACK_LO"), v.get("L3_CRYPTO_STACK_HI")),
            faults_at("%s relay denied SPM private RAM %s on its own stack" % (what, spm), 1, spm, lo, hi),
            expect_re("%s relay denied execution from its XN data band" % what,
                      r'^\[MEMFAULT\] pc=%s addr=%s' % (band, band)),
            refute_re("isolation faults did not escalate", ESCALATION)]


def _interface_checks(ctx, block):
    v = ctx.var
    full = v.get("interface_profile", "default") != "default"
    if block.startswith("tpm"):
        app = "tpm-guest0"
        out = _interface_neg(v, "TPM") if block == "tpmneg" else []
        out += [expect("TPM application guest alive", app + ": alive"),
                expect("fwTPM capabilities match the relay frame limit", app + ": tpm frame caps ok"),
                expect("valid TPM command reaches the advertised frame limit", app + ": tpm max frame ok")]
        if not full and block == "tpm":
            out += [expect("TPM capabilities match the selected commands",
                           app + ": tpm command capabilities match profile"),
                    expect("disabled TPM command refused by the provider", app + ": tpm disabled command rejected")]
        return out + [expect("repeated bad authorization reaches DA lockout", app + ": tpm lockout ok"),
                      expect("wolfTPM round trip through the isolated fwTPM", app + ": tpm round trip ok")]
    app = "pkcs11-guest0"
    suite = ("core" if block == "pkcs11neg" else "all") if full else "profile"
    out = _interface_neg(v, "PKCS#11") if block == "pkcs11neg" else []
    return out + [expect("PKCS#11 application guest alive", app + ": alive"),
                  expect("the %s PKCS#11 suite completed" % suite, "%s: suite %s complete" % (app, suite)),
                  expect("the PKCS#11 suite reported zero failures", app + ": TOTAL FAILED: 0"),
                  expect("the PKCS#11 suite ran every planned case",
                         "%s: TOTAL PASSED: %d" % (app, PKCS11_PASSED[suite]))]


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


def _trace_sau(ctx, desc, pattern, who, src="SAU"):
    return [expect("the traced run stopped at a delivered fault", "Execution stopped", where="trace"),
            expect_n_re(desc, 1, pattern, where="trace"),
            sau_refusal("the refusal came from the %s%s" % (src, who), pattern, src=src)]


def _trace_kind(ctx, v):
    kind = v.get("trace_kind", "")
    if kind == "restart":
        pat = r"\[MEMFAULT_CAUSE\] sec=NS type=READ addr=%s reason=secure-attr" % v.get("fault_addr", "?")
        return _trace_sau(ctx, "the fault was guest0's read of Secure RAM, refused as Secure", pat, "")
    if kind == "guestisoneg":
        pat = r"\[MEMFAULT_CAUSE\] sec=NS type=WRITE addr=%s reason=secure-attr" % v.get("probe_addr", "?")
        return _trace_sau(ctx, "the fault was guest0's store into guest1's RAM, refused as Secure", pat,
                          ": the peer window was Secure at dispatch",
                          ctx.m33mu.get("iso_refusal_src", "SAU"))
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
        if ctx.name == "panicneg" and k1 == "none":
            return [expect("the pinned client was unblocked with COMMUNICATION_FAILURE",
                           ": storage connect unblocked rc=-145")]
        if ctx.name == "panicneg":
            return [expect_n("the restarted storage SP served the guest after the panic", 1, ": storage connect ok")]
        return [expect_n("every guest reached the storage service", ctx.live_guests(), ": storage connect ok")]
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
        out = [expect_re("the pinned ITS client was unblocked with an error", r'guest[01]: psa_its_set failed st=-1(32|45)')]
        if k1 != "none":
            out.append(expect("the restarted ITS partition served the other guest", "wolfTrust ITS set/get verified"))
        return out + [expect("sealed storage path unaffected", "guest0: wolfTrust PS sealed set/get verified")]
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
    if block == "nativewire":
        return [expect("every native wire key op served by the crypto partition",
                       "guest0: nativewire every key op verified"),
                refute_re("no native wire op failed", r'nativewire .*(failed st=|bad |mismatch)'),
                refute_re("no Secure stack overflow or usage fault", r'\[USGFLT\]')]
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
        if k1 == "none":
            out += [expect("the only guest refused fail-closed (all guests quarantined)",
                           "[BKPT] imm=0x7d")]
        elif k1 == "freertos":
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
                expect("execute from the XN vnet data band denied", v.get("L3_VNET_BAND", "<L3_VNET_BAND unset>")),
                refute_re("no HardFault escalation", r'(\[HARDFLT\]|HardFault)'),
                expect("guest0 alive through the quarantine", "vnet-guest0: alive"),
                expect("guest1 alive through the quarantine", "vnet-guest1: alive"),
                expect("mediated ping still completes after both restarts", "ping reply from 10.0.0.2")]
    if block in ("tpm", "tpmneg", "pkcs11", "pkcs11neg"):
        return _interface_checks(ctx, block)
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
                expect_n("every guest reached the storage service", ctx.live_guests(), ": storage connect ok")]
    if block == "wrpoff":
        peers = "|".join(re.escape(s) for s in (ctx.g0["started"], ctx.g1["started"]))
        return [refute_re("no guest entered its domain without the guest fence", peers)]
    raise SystemExit("unknown block %s" % block)


# --------------------------------------------------------------- hardware --

GUEST_SIG = "47543030"
PSA_SIG = "50534147"


def _hw_guest_lifecycle(ctx, i):
    g = "guest%d" % i
    kind = ctx.kind(i)
    if kind == "baremetal":
        return [word("%s launched: signature 0x47543030" % g, "g%d.sig" % i, eq=GUEST_SIG),
                word("%s psa_framework_version 0x0100" % g, "g%d.fw" % i, eq="00000100"),
                word("%s done: FF-M connect verified, status 0x600D600D" % g, "g%d.status" % i, eq="600d600d"),
                word("%s reaches its Non-secure console" % g, "g%d.console" % i, ne="00000000")]
    if kind == "psa":
        return [word("%s launched: signature PSAG" % g, "g%d.sig" % i, eq=PSA_SIG),
                word("%s completed the TEE, crypto, ITS, PS, key-ops, SHA KAT and done stages" % g,
                     "g%d.lc" % i, mask="000000bf", eq="000000bf"),
                word("%s completed the attestation COSE stage" % g, "g%d.lc" % i, mask="00000040", eq="00000040"),
                word("%s FF-M negatives all rejected: forged handle, oversized vector, cross-guest vector, unknown SID" % g,
                     "g%d.neg" % i, eq="0000000f")]
    if kind == "zephyr":
        return [word("guest0 full PSA/FF-M lifecycle latched (every milestone)", "g0sym.g_guest0_lifecycle",
                     mask="000000ff", eq="000000ff")]
    if kind == "freertos":
        return [expect("guest1 (FreeRTOS) runs its mediated SHA KAT", ctx.g1["sha"])]
    if kind == "vnet":
        return [expect("%s alive" % g, "vnet-%s: alive" % g)]
    return []


def _hw_masks(verified, refused):
    return [word("launch-verified guest mask 0x%s" % verified, "sym.g_wt_launch_verified_mask", eq=verified),
            word("launch-refused guest mask 0x%s" % refused, "sym.g_wt_launch_refused_mask", eq=refused)]


def _hw_peer_alive(ctx):
    if ctx.kind(1) == "freertos":
        return [expect("guest1 (unrelated domain) still runs", ctx.g1["heartbeat"])]
    return [advancing("guest1 still running (idle beat advances)", "g1.beat")]


def _hw_quarantined(ctx, want_key):
    """guest0 faulted at the probe's address on every launch, spent its
    restart budget and was quarantined; guest1 ran untouched."""
    limit = "%08x" % ctx.restart_limit()
    out = []
    if want_key:
        out.append(word("guest0's last fault was its probe's access", "sym.g_last_fault_address",
                        eq="{%s}" % want_key))
    out += [word("guest0 relaunched through its restart budget", "sym.g_wt_restart_events", eq=limit),
            word("guest0 quarantined once", "sym.g_wt_quarantine_events", eq="00000001")]
    if ctx.kind(0) == "baremetal":
        out += [word("guest0 never reported done", "g0.status", ne="600d600d"),
                word("guest0 never reached its idle loop", "g0.beat", eq="00000000")]
        out += _hw_masks("00000003", "00000000")
    if ctx.kind(1) == "baremetal":
        out += _hw_guest_lifecycle(ctx, 1)
    return out


def hw_block_checks(ctx, block):
    v = ctx.var
    hw = ctx.hw
    k0, k1 = ctx.kind(0), ctx.kind(1)
    if block == "hw_chain":
        return [expect("wolfBoot verified the wolfTrust image signature (console)", "Verifying signature...done")]
    if block == "hw_no_faults":
        return [refute_re("no fault markers on the console",
                          r'^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault|BusFault|UsageFault)')]
    if block == "hw_no_escalation":
        return [refute_re("no HardFault escalation on the console", r'^(\[HARDFLT\]|HardFault|SecureFault)')]
    if block == "hw_lifecycle":
        return _hw_guest_lifecycle(ctx, 0) + _hw_guest_lifecycle(ctx, 1)
    if block == "hw_launched_all":
        return _hw_masks("00000003", "00000000")
    if block == "hw_no_restarts":
        return [word("no guest restarted", "sym.g_wt_restart_events", eq="00000000")]
    if block == "hw_positive_extras":
        if k0 != "zephyr":
            return []
        return [word("partition stacks and bands zeroed at boot", "sym.g_wt_boot_zeroed_bytes", ge="00000001"),
                word("cross-guest vector refused on silicon (guest1 negative mask bit 0x4)", "g1sym.g_guest1_ffm_neg",
                     mask="00000004", eq="00000004"),
                word("SPM RAM execute-never cover present on every dispatch", "sym.g_wt_xn_denied", eq="00000000"),
                info("the attestation measurement is gated by the lifecycle latch; the interleaved console is not asserted")]
    if block == "hw_peer_alive":
        return _hw_peer_alive(ctx)
    if block == "hw_quarantined":
        return _hw_quarantined(ctx, "fault_addr")
    if block == "hw_guestisoneg":
        if k0 == "zephyr":
            return [word("NS MPU bypass blocked (2) or faulted and contained (1)", "g0sym.g_guest0_gtzc_probe",
                         in_=("00000001", "00000002"))]
        out = [word("guest1 RAM never received guest0's sentinel", "peer.word", ne="deadbeef")]
        mode = hw.get("iso_probe", "faults")
        if mode == "faults":
            out += _hw_quarantined(ctx, "probe_addr")
        elif mode == "silent":
            # The fabric drops the store without a fault, so guest 0 runs on.
            out += [word("guest0 store into guest1 RAM silently blocked (latch 2)", "g0.probe", eq="00000002"),
                    word("guest0 kept running past its probe store", "g0.beat", ne="00000000"),
                    word("system still scheduling after the probes (IPSR not a fault handler)", "cpu.ipsr_fault", eq="00000000")]
            out += _hw_guest_lifecycle(ctx, 1)
        else:
            out += [word("guest0 store into guest1 RAM blocked (latch 1 faulted or 2 blocked)", "g0.probe",
                         in_=("00000001", "00000002")),
                    word("guest0 never got past its probe store", "g0.beat", eq="00000000"),
                    word("system still scheduling after the probes (IPSR not a fault handler)", "cpu.ipsr_fault", eq="00000000")]
            out += _hw_guest_lifecycle(ctx, 1)
        return out
    if block == "hw_periphneg":
        if k0 == "zephyr" or ctx.m33mu.get("periph_probe", "faults") == "verdict":
            out = [word("NS peripheral and DMA access blocked (latch 2)", "g0sym.g_guest0_periph_probe" if k0 == "zephyr" else "g0.probe",
                        eq="00000002")]
            if k0 == "zephyr":
                out += [refute_re("no fault markers on the console",
                                  r'^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault|BusFault|UsageFault)')]
            out += _hw_guest_lifecycle(ctx, 0)
            return out
        out = _hw_quarantined(ctx, "periph_addr")
        if "hw_console" not in caps_absent(ctx.port):
            out.append(refute_re("no NS read of the SPM's peripheral ever returned (console)", "periph probe LEAKED"))
        return out
    if block == "hw_sp_fault":
        addr = "{L3_SPM_RAM}" if ctx.name == "crossdomain" else "{L3_VAULT_BAND}"
        return [word("the partition faulted on the out-of-domain read", "sym.g_tasklet_fault_count", ge="00000001"),
                word("the denied read targeted the band under test", "sym.g_last_fault_address", eq=addr)]
    if block == "hw_sp_guests":
        if k0 == "baremetal":
            return _hw_guest_lifecycle(ctx, 0) + _hw_guest_lifecycle(ctx, 1)
        return []
    if block == "hw_authneg":
        out = [word("the monitor quarantined the tampered guest", "sym.g_wt_quarantine_events", ge="00000001")]
        if k0 == "baremetal":
            out += [word("the tampered guest0 never wrote its mailbox", "g0.sig", eq="00000000")]
            out += _hw_masks("00000002", "00000001") + _hw_guest_lifecycle(ctx, 1)
        else:
            out += [refute_re("the tampered guest0 never entered its domain", re.escape(ctx.g0["started"])),
                    expect("guest1 mediated crypto still live", ctx.g1["sha"])]
        return out
    if block == "hw_wrpoff":
        # An image that verifies no guest may have the verified mask dropped by the linker.
        out = [word("launch-refused guest mask 0x3", "sym.g_wt_launch_refused_mask", eq="00000003"),
               word("no guest was launch-verified", "sym.g_wt_launch_verified_mask", eq="00000000",
                    absent_ok=True)]
        if k0 == "baremetal":
            out += [word("guest0 never entered its domain (mailbox blank)", "g0.sig", eq="00000000"),
                    word("guest1 never entered its domain (mailbox blank)", "g1.sig", eq="00000000")]
        else:
            out += [refute_re("no guest entered its domain", "|".join(re.escape(x) for x in (ctx.g0["started"], ctx.g1["started"])))]
        return out
    if block == "hw_wrpoff_fence":
        return [word("XSPI SFP configuration valid and sealed until reset", "fence.sfp_sealed", eq="00000001"),
                word("no FRAD fences the guest windows (unfenced first stage)", "fence.armed", eq="00000000")]
    if block == "hw_confboot":
        return [expect("Arm suite TOTAL TESTS : 89", "TOTAL TESTS     : 89"),
                expect("Arm suite TOTAL PASSED : 85", "TOTAL PASSED    : 85"),
                expect("Arm suite TOTAL SKIPPED : 4", "TOTAL SKIPPED   : 4"),
                expect("Arm suite TOTAL FAILED : 0", "TOTAL FAILED    : 0"),
                expect("ACS run completed", "END OF ACS")]
    if block == "hw_devsuite":
        if ctx.name == "devcrypto":
            return [totals("dev_apis crypto (77 scheduled; c047 CMAC config-skipped)", failed=0, scheduled=77)]
        return [totals("dev_apis storage (17 scheduled)", failed=0, scheduled=17)]
    if block == "hw_devattest":
        return [totals("dev_apis initial_attestation (1 passed)", passed=1, failed=0)]
    if block == "hw_vaultrecover":
        # The crypto schedule as recorded on the Nucleo: 64 pass, none fail.
        return [totals("crypto suite green after self-heal", passed=64, failed=0),
                word("unlocked lifecycle: vault self-healed", "sym.g_vault_reformatted", eq="00000001")]
    if block == "hw_vaultrecoversec":
        return [word("SECURED lifecycle: failed closed, no trap", "sym.g_wt_attest_degraded", eq="00000001"),
                word("SECURED lifecycle: vault not reformatted", "sym.g_vault_reformatted", eq="00000000")]
    if block == "hw_panic":
        out = [word("the partition panicked on its first entry", "sym.g_tasklet_fault_count", ge="00000001"),
               word("the panic took the UNDEFINSTR trap", "sym.g_tasklet_fault_cfsr", mask="00010000", eq="00010000")]
        if k0 == "zephyr":
            out.append(word("client unblocked; lifecycle completed minus the panicked leg (0xFB)",
                            "g0sym.g_guest0_lifecycle", mask="000000ff", eq="000000fb"))
        return out
    if block == "hw_hsmattack":
        return [word("IAK sign and NVM read refused, own namespace works", "g0sym.g_hsm_attack_probe",
                     mask="00000007", eq="00000007")]
    if block == "hw_bootupdate":
        return [word("boot slot holds v2 after the swap", "bootslot.measurement", eq="{v2_measurement}"),
                word("the pre-update v1 image was swapped out of the boot slot", "bootslot.measurement", ne="{expected_measurement}")]
    if block == "hw_vnetneg":
        return [word("the vnet partition faulted on both probes", "sym.g_tasklet_fault_count", ge="00000002"),
                expect("guest0 alive through the quarantine", "vnet-guest0: alive"),
                expect("guest1 alive through the quarantine", "vnet-guest1: alive"),
                expect("mediated ping completes after both restarts", "ping reply from 10.0.0.2")]
    if block == "hw_fpneg":
        return [word("the relay faulted on the FP instruction", "sym.g_tasklet_fault_count", ge="00000001"),
                word("the fault took the NOCP trap on silicon", "sym.g_tasklet_fault_cfsr", mask="00080000", eq="00080000")]
    if block == "hw_busfault":
        return [word("the relay took the contained fault", "sym.g_tasklet_fault_count", ge="00000001"),
                word("the fault was a precise BusFault with BFAR", "sym.g_tasklet_fault_cfsr", mask="00008200", eq="00008200"),
                word("BFAR names the probe's bus-error window", "sym.g_last_fault_address", eq="300a0000")]
    if block == "hw_xnneg":
        return [word("privileged execution from SPM RAM faulted (IACCVIOL)", "sym.g_wt_spm_fault_cfsr", mask="00000001", eq="00000001"),
                word("the faulting fetch was inside SPM RAM", "sym.g_wt_spm_fault_pc", lo="{L3_SPM_RAM}", hi="{L3_VAULT_BAND}"),
                refute_re("no guest ran after the halt", "|".join(re.escape(x) for x in (ctx.g0["started"], ctx.g1.get("heartbeat", ctx.g1["started"]))))]
    if block == "hw_mspovf":
        return [word("main-stack overflow raised STKOF against MSPLIM_S", "sym.g_wt_spm_fault_cfsr", mask="00100000", eq="00100000"),
                refute_re("no guest ran after the halt", "|".join(re.escape(x) for x in (ctx.g0["started"], ctx.g1.get("heartbeat", ctx.g1["started"]))))]
    if block == "hw_seal":
        return [word("the switch-time seal check detected the tamper", "sym.g_wt_seal_violation", eq="fef5eda5"),
                word("the offending partition took the contained fault", "sym.g_tasklet_fault_count", ge="00000001")]
    if block == "hw_fenced":
        return [word("XSPI SFP configuration valid and sealed until reset", "fence.sfp_sealed", eq="00000001"),
                word("a locked, write-denying FRAD spans the guest windows", "fence.armed", eq="00000001")] +                _hw_masks("00000003", "00000000") + _hw_guest_lifecycle(ctx, 0) + _hw_guest_lifecycle(ctx, 1)
    if block == "hw_fence_selftest":
        return [word("wolfBoot's flash-protect selftest ran to completion", "pst.0", eq="50510002"),
                word("the boot-root erase returned the FRAD check error", "pst.3", eq="{pst_4}"),
                word("the erase in the guest fence returned the FRAD check error", "pst.9", eq="{pst_4}"),
                word("the guest-fence block is unchanged", "pst.11", eq="505150aa")]
    if block == "hw_entry_mask":
        return [word("each due tick was held to the FF-M entry's exit, none nested", "g0.probe", eq="4d41534b")]
    if block == "hw_handler_irq":
        return _hw_guest_lifecycle(ctx, 1) + [
            word("guest0 never got past its IRQ handler", "g0.status", ne="600d600d"),
            word("guest0 spent its restart budget and was quarantined", "sym.g_wt_quarantine_events", ne="00000000"),
            word("guest0's abandoned IRQ is no longer active (IABR2 bit 0 clear)", "cpu.iabr2", mask="00000001", eq="00000000"),
            advancing("guest1 keeps taking its PendSV after guest0's overruns", "g1.beat")]
    if block == "hw_romsmoke":
        return [word("ROM booted the XIP image: marker RT00", "smoke.marker", eq="52543030"),
                advancing("smoke loop alive: counter advances", "smoke.counter"),
                word("PC inside the XIP image", "cpu.pc", lo="28004000", hi="28100000")]
    if block == "hw_nsmask":
        return [word("guest0 holds PRIMASK, FAULTMASK and BASEPRI 0x10", "g0sym.g_wt_ns_mask_state", eq="00001003"),
                advancing("guest1 keeps running beside the masked guest0", "g1sym.g_guest1_heartbeats"),
                advancing("guest0 still gets its own slices", "g0sym.g_wt_ns_mask_spins"),
                word("the masked guest0 was never restarted", "sym.g_wt_restart_events", eq="00000000")]
    if block == "hw_nsbusfault":
        return [word("BusFault BFAR names the Non-secure hole", "sym.g_last_fault_address", eq="4c000000")] +                _hw_quarantined(ctx, "")
    if block == "hw_writeonce":
        return [word("the first boot sealed the WRITE_ONCE object (stage 1)", "g0sym.g_write_once_stage@boot1", eq="00000001"),
                word("the object survived the reset and refused set/remove (stage 2)", "g0sym.g_write_once_stage@boot2", eq="00000002")]
    if block == "mcxn_secure_side":
        return [word("ROM flash API reached from the SVC gate, last status 0", "sym.g_wt_rom_flash_last_status", eq="00000000"),
                word("wolfHSM flash backend last error 0", "sym.g_wt_flash_last_error", eq="00000000"),
                word("the ELS served every RND_REQ", "sym.g_wt_els_errors", eq="00000000"),
                word("the vault's first state phrase is programmed", "nvm.phrase", ne="ffffffff"),
                word("an erased phrase reads as 0xFF through the bus", "nvm.blank", eq="ffffffff"),
                word("wolfBoot's handoff record was consumed and cleared", "mem.handoff", eq="00000000"),
                word("system still scheduling (IPSR not a fault handler)", "cpu.ipsr_fault", eq="00000000"),
                word("wolfBoot handed OEM_OPEN as PSA ASSEMBLY_AND_TEST", "handoff.lifecycle", eq="00001000")]
    return block_checks(ctx, block, "idle")


BLOCK_CAPS = {"boot_console": ("boot_console",), "trace": ("prot_trace",),
              "hw_wrpoff_fence": ("guest_fence",),
              "hw_chain": ("hw_console", "boot_console"), "hw_no_faults": ("hw_console",),
              "hw_no_escalation": ("hw_console",), "hw_confboot": ("hw_console",),
              "hw_devsuite": ("hw_console",), "hw_devattest": ("hw_console",),
              "hw_vnetneg": ("hw_console",), "vnet": ("hw_console",)}


def hardware_caps_absent(port):
    out = dict(caps_absent(port))
    out.update(PORTS[port]["def"].get("hardware", {}).get("caps_absent", {}))
    return out


def plan(port, scenario, engine="native", env="emulator", guests=2):
    r = resolve(port, scenario, engine)
    row = SCENARIOS[r["scenario"]]
    if guests == 1 and row["tamper"]:
        # Refusing the only guest quarantines every guest: the monitor stops
        # on the platform recovery breakpoint, not on a guest's clean end.
        r["end"] = "bkpt:0x7d"
    if env == "hardware":
        # A bare-metal breakpoint with no debugger would fault on silicon.
        r["guest_flags"] = " ".join(f for f in r["guest_flags"].split()
                                    if f != "WT_M33MU_EXPECT_BKPT=1")
        r["secure"] = (r["secure"] + " " + row["hw_secure"]).strip()
        extra = list(PORTS[port]["def"].get("hardware", {}).get("extra_blocks", []))
        blocks = ["hw_chain"] + list(row["hw_blocks"]) + extra
        absent = hardware_caps_absent(port)
        r["missing"] = [c for c in row["hw_requires"] if c in absent]
        r["trace"] = ""
    else:
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
    r["env"] = env
    return r


# ------------------------------------------------------------------ judge --

def read(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")


PLACEHOLDER = re.compile(r"\{([A-Za-z][A-Za-z_0-9]*)\}")
HEX8 = re.compile(r"^[0-9a-f]{8}([0-9a-f]{56})?$")


def describe_word(check, judge):
    parts = []
    for key in ("eq", "ne", "ge", "lo", "hi"):
        if check[key] is not None:
            parts.append("%s 0x%s" % (key, judge.sub(check[key])))
    if check["mask"]:
        parts.append("mask 0x%s" % judge.sub(check["mask"]))
    if check["in"] is not None:
        parts.append("one of %s" % " ".join(check["in"]))
    return ", ".join(parts)


def substitute(text, var):
    """{name} placeholders from the runner's variables; a regex quantifier
    such as {6} starts with a digit, is not a name and stays."""
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


def interleaved(text, needle):
    """Guests sharing a board UART can splice a burst into a marker, so a
    hardware console accepts its words with bounded fragments between them."""
    return re.search(".{0,160}".join(re.escape(w) for w in needle.split(" ")), text, re.S) is not None


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

    def words(self):
        if "swd" not in self.logs:
            raise SystemExit("no SWD evidence was given")
        out = {}
        for line in self.logs["swd"].splitlines():
            key, sep, value = line.partition("=")
            if sep:
                out[key.strip()] = value.strip().lower()
        return out

    def run_word(self, check):
        words = self.words()
        desc = check["desc"]
        if check["op"] == "advancing":
            a = words.get(check["key"] + "@0")
            b = words.get(check["key"] + "@1")
            if a is None or b is None or not HEX8.match(a) or not HEX8.match(b):
                return self.report(False, desc, "no two readings of %s" % check["key"])
            return self.report(a != b, "%s (0x%s -> 0x%s)" % (desc, a, b), "did not move")
        value = words.get(check["key"])
        if value is None:
            return self.report(False, desc, "no SWD word %s" % check["key"])
        if value == "absent" and check.get("absent_ok"):
            return self.report(True, "%s (symbol absent from this image)" % desc)
        if not HEX8.match(value):
            return self.report(False, desc, "malformed SWD word %s=%s" % (check["key"], value))
        n = int(value, 16)
        if check["mask"]:
            n &= int(self.sub(check["mask"]), 16)
        ok = True
        if check["eq"] is not None:
            ok = ok and n == int(self.sub(check["eq"]), 16)
        if check["ne"] is not None:
            ok = ok and n != int(self.sub(check["ne"]), 16)
        if check["ge"] is not None:
            ok = ok and n >= int(self.sub(check["ge"]), 16)
        if check["lo"] is not None:
            ok = ok and int(self.sub(check["lo"]), 16) <= n < int(self.sub(check["hi"]), 16)
        if check["in"] is not None:
            ok = ok and n in [int(x, 16) for x in check["in"]]
        return self.report(ok, "%s (0x%s)" % (desc, value), "want %s" % describe_word(check, self))

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
        if op in ("word", "advancing"):
            return self.run_word(check)
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
            # On a shared UART another guest's lines can land inside a Result= token
            conf = re.sub(r"wolfTrust [^\n]*guest[1-9][0-9]*: [^\n]*\n", "",
                          self.text("guest0" if "guest0" in self.logs else "log"))
            for m in re.finditer(r"Num=([0-9]+)|Result=([A-Za-z]+)", conf):
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
            ok = needle in text or (self.ctx.env == "hardware" and interleaved(text, needle))
            return self.report(ok, check["desc"], "missing: %s" % needle)
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
                if re.search(pat, line) and i + 1 < len(lines) and "src=%s" % check["src"] in lines[i + 1]:
                    n += 1
            return self.report(n == 1, check["desc"], "saw %d %s refusals" % (n, check["src"]))
        raise SystemExit("unknown check %s" % op)


def needs_absent_guest(check):
    """An expectation only the absent guest could meet: a one-guest image
    drops it, and keeps every refute (the absent guest prints nothing)."""
    if check["op"] in ("expect", "expect_n"):
        return NO_GUEST_MARKER in check["text"] and check.get("n", 1) != 0
    if check["op"] in ("expect_re", "expect_n_re"):
        return NO_GUEST_MARKER in check["re"] and check.get("n", 1) != 0
    return False


def without_absent_guest(checks):
    out = []
    for check in checks:
        if check["op"] == "either":
            options = [without_absent_guest(option) for option in check["options"]
                       if not any(needs_absent_guest(c) for c in option)]
            if options:
                out.append(dict(check, options=options))
        elif not needs_absent_guest(check):
            out.append(check)
    return out


def one_guest(pair, guests):
    """The guest pair a build that schedules `guests` guests runs."""
    return (pair[0], "none") if guests == 1 else pair


def judge(port, scenario, env, logs, var, engine="native", guests=2):
    p = plan(port, scenario, engine, env, guests)
    ctx = Ctx(port, p["scenario"], env, one_guest(p["guests"], guests), var)
    j = Judge(ctx, logs)
    for block, why in p["na"]:
        j.lines.append("  [check] N/A   %s: %s" % (block, why))
    for block in p["applicable"]:
        if block == "trace":
            var["trace_kind"] = p["trace"]
        if env == "hardware":
            checks = hw_block_checks(ctx, block)
        else:
            checks = block_checks(ctx, block, p["end"])
        if guests == 1:
            checks = without_absent_guest(checks)
        for check in checks:
            j.run(check)
    if guests == 1:
        absent = markers(p["guests"][1], "guest1", ctx.board)["started"]
        j.run(refute_re("the one-guest image never started guest1",
                        re.escape(absent)))
    return j


def hardware_tiers(port):
    """The hardware scenarios a port runs: the minimum every board runs, the
    qualification extras that gate a merge, and the opt-in board-only set."""
    hw = PORTS[port]["def"].get("hardware", {})
    absent = hardware_caps_absent(port)
    minimum = [s for s in HARDWARE_MINIMUM
               if not any(c in absent for c in SCENARIOS[s]["hw_requires"])]
    return {"smoke": minimum,
            "qualification": minimum + list(hw.get("qualification", [])),
            "optin": list(hw.get("optin", []))}


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


def one_guest_gaps():
    """No assertion a lean (one-guest) run applies can only be met by the
    guest that image never schedules."""
    gaps = []
    for port in sorted(PORTS):
        for name in scenario_matrix.flat(port, "full", None, "default"):
            p = plan(port, name, "native", "emulator")
            ctx = Ctx(port, p["scenario"], "emulator",
                      one_guest(p["guests"], 1), {"board": "X"})
            ctx.var["trace_kind"] = p["trace"]
            for block in p["applicable"]:
                checks = without_absent_guest(block_checks(ctx, block, p["end"]))
                pending = list(checks)
                while pending:
                    check = pending.pop()
                    if check["op"] == "either":
                        pending.extend(c for option in check["options"]
                                       for c in option)
                    elif needs_absent_guest(check):
                        gaps.append("%s %s: %s still expects guest1" %
                                    (port, name, block))
    return gaps


def selftest():
    gaps = profile_gaps() + one_guest_gaps()
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
            if "emulator" not in SCENARIOS[name]["envs"]:
                continue
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
        hw = PORTS[port]["def"].get("hardware", {})
        absent_hw = hardware_caps_absent(port)
        for cap in hw.get("caps_absent", {}):
            if cap not in CAPABILITIES:
                gaps.append("%s declares unknown hardware capability %s absent" % (port, cap))
        for name in HARDWARE_MINIMUM:
            if any(c in absent_hw for c in SCENARIOS[name]["hw_requires"]):
                gaps.append("%s cannot run the minimum hardware scenario %s" % (port, name))
        # The minimum is the contract; extras are the port's qualification
        # and opt-in sets, never required of another port.
        hw_run = set(hardware_tiers(port)["qualification"]) | set(hardware_tiers(port)["optin"])
        for name in hw_run:
            if name not in SCENARIOS or "hardware" not in SCENARIOS[name]["envs"]:
                gaps.append("%s lists the unknown hardware scenario %s" % (port, name))
            else:
                try:
                    p = plan(port, name, "native", "hardware")
                    ctx = Ctx(port, name, "hardware", p["guests"], {"board": "X"})
                    for block in p["applicable"]:
                        hw_block_checks(ctx, block)
                except SystemExit as exc:
                    gaps.append("%s/%s (hardware): %s" % (port, name, exc))
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
    parser.add_argument("--guests", type=int, choices=(1, 2), default=2,
                        help="guests the Secure image schedules (1: the lean default)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--shell", action="store_true", help="the resolved plan as SC_* assignments")
    mode.add_argument("--asserts", action="store_true", help="the applicable blocks and their checks")
    mode.add_argument("--list", action="store_true", help="every scenario")
    mode.add_argument("--hardware-minimum", action="store_true")
    mode.add_argument("--hardware-tier", choices=("smoke", "qualification", "optin"),
                      help="the port's hardware scenarios of that tier")
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--canonical", action="store_true", help="the canonical name of --scenario")
    sub = parser.add_subparsers(dest="cmd")
    j = sub.add_parser("judge")
    j.add_argument("--log", required=True)
    j.add_argument("--trace-log")
    j.add_argument("--guest0-log")
    j.add_argument("--syms")
    j.add_argument("--swd")
    j.add_argument("--var", action="append", default=[])
    args = parser.parse_args()

    if args.list:
        print(" ".join(sorted(SCENARIOS)))
        return 0
    if args.hardware_minimum:
        print(" ".join(HARDWARE_MINIMUM))
        return 0
    if args.hardware_tier:
        if args.port is None:
            parser.error("--port is required")
        print(" ".join(hardware_tiers(args.port)[args.hardware_tier]))
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
    p = plan(args.port, args.scenario, args.engine, args.env, args.guests)
    if args.shell:
        print(shell_plan(p))
        return 0
    if args.asserts:
        ctx = Ctx(args.port, p["scenario"], args.env,
                  one_guest(p["guests"], args.guests),
                  {"board": PORTS[args.port]["def"]["display"]})
        for block, why in p["na"]:
            print("N/A %s: %s" % (block, why))
        for block in p["applicable"]:
            ctx.var["trace_kind"] = p["trace"]
            print("block %s" % block)
            checks = hw_block_checks(ctx, block) if args.env == "hardware" else block_checks(ctx, block, p["end"])
            if args.guests == 1:
                checks = without_absent_guest(checks)
            for check in checks:
                key = " [%s]" % check["key"] if check["op"] in ("word", "advancing") else ""
                print("  %s: %s%s" % (check["op"], check["desc"], key))
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
        if args.swd:
            logs["swd"] = read(args.swd)
        result = judge(args.port, args.scenario, args.env, logs, var,
                       args.engine, args.guests)
        print("\n".join(result.lines))
        return 1 if result.failures else 0
    parser.error("nothing to do")
    return 2


if __name__ == "__main__":
    sys.exit(main())
