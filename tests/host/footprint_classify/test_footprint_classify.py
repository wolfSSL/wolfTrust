#!/usr/bin/env python3
"""tools/footprint/classify.py attributes every flash byte of a linked map:
input sections to their object's category, *fill* and linker-emitted bytes to
their own buckets, .data once to flash at its load address, and .bss never.
An object no rule matches fails the run, and so does a gated total over
--max. Both shipped rule files classify the objects each project links."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "../../..").resolve()
CLASSIFY = ROOT / "tools" / "footprint" / "classify.py"
RULES = ROOT / "tools" / "footprint"

MAP = """\
Archive member included to satisfy reference by file (symbol)

Discarded input sections

 .text.dead     0x00000000       0x40 build/wt_sec_dead.o

Memory Configuration

Name             Origin             Length             Attributes
FLASH            0x0c000000         0x00020000         xr
RAM              0x30000000         0x00010000         xrw
RAMFUNC          0x10000000         0x00001000         xr
*default*        0x00000000         0xffffffff

Linker script and memory map

.vectors        0x0c000000       0x20
 *(.vectors)
 .vectors       0x0c000000       0x20 build/sec_ivt.o

.gnu.sgstubs    0x0c000020       0x20
 .gnu.sgstubs   0x0c000020       0x20 linker stubs

.text           0x0c000040      0x110
 .text.wt_ffm_call_begin
                0x0c000040       0x80 build/sec_ffm.o
                0x0c000040                wt_ffm_call_begin
 *fill*         0x0c0000c0        0x4
 .text.wc_AesGcmEncrypt
                0x0c0000c4       0x7c build/wc_sec_aes.o
 .text.empty    0x00000000        0x0 build/sec_ffm.o
                0x0c000140        0x8 LONG 0x0 _end_marker
                0x0c000150                . = ALIGN (0x10)

.data           0x30000000       0x10 load address 0x0c000150
 .data.g_state  0x30000000       0x10 build/wt_sec_wt_hsm_vault.o

.nsc            0x10000000       0x40 load address 0x0c000160
 .nsc           0x10000000       0x40 build/wt_sec_ffm_nsc.o

.ramfunc        0x10000040       0x20 load address 0x0c000160
 .ramfunc       0x10000040       0x20 build/wt_sec_xspi_nor.o

.bss            0x30000010      0x100 load address 0x0c000180
 .bss.g_table   0x30000010      0x100 build/sec_ffm.o

.debug_info     0x00000000     0x1000
 .debug_info    0x00000000     0x1000 build/sec_ffm.o
"""

RULES_TEXT = """\
crypto   /wc_sec_
storage  /wt_sec_(wt_hsm_vault|xspi_nor)\\.o$
spm      sec_(ffm|ivt|ffm_nsc)\\.o$
spm      ^linker stubs$
"""

WOLFTRUST_OBJECTS = {
    "build/wc_sec_aes.o": "crypto",
    "build/wp_sec_psa_aead.o": "crypto",
    "build/wt_sec_psa_crypto_service.o": "crypto",
    "build/wt_sec_keyvault.o": "crypto",
    "build/wt_sec_wolfcose_eat_psa.o": "attestation",
    "build/wt_sec_initial_attestation.o": "attestation",
    "build/wt_sec_wt_hsm_vault.o": "storage",
    "build/wh_sec_wh_nvm.o": "storage",
    "build/wt_sec_nvm_native.o": "storage",
    "build/sec_monitor.o": "guest",
    "build/wt_sec_guest_context_armv8m.o": "guest",
    "build/sec_platform_stm32h563.o": "platform",
    "build/wt_sec_gtzc.o": "platform",
    "build/wt_sec_mpu_armv8m.o": "platform",
    "build/sec_ffm.o": "spm",
    "build/wt_sec_spm_gate_core.o": "spm",
    "build/wt_sec_service_ipc.o": "spm",
    "build/sec_runtime.o": "runtime",
    "/opt/lib/gcc/libgcc.a(cmse.o)": "runtime",
    "linker stubs": "spm",
}

TFM_OBJECTS = {
    "lib/libtfpsacrypto.a(aes.o)": "crypto",
    "partitions/libtfm_psa_rot_partition_crypto.a(crypto_init.o)": "crypto",
    "partitions/lib/runtime/libtfm_sprt.a(tfm_crypto_api.o)": "crypto",
    "lib/ext/qcbor-build/libqcbor.a(qcbor_encode.o)": "attestation",
    "partitions/libtfm_psa_rot_partition_attestation.a(attest_core.o)": "attestation",
    "partitions/libtfm_psa_rot_partition_its.a(its_flash_fs.o)": "storage",
    "platform/libplatform_s.a(nv_counters.o)": "storage",
    "spm/libtfm_spm.a(ns_agent_tz_v80m.o)": "guest",
    "platform/libplatform_s.a(stm32l5xx_hal_uart.o)": "platform",
    "spm/libtfm_spm.a(backend_ipc.o)": "spm",
    "partitions/lib/runtime/libtfm_sprt.a(crt_memcpy.o)": "runtime",
    "linker stubs": "spm",
}

checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise SystemExit("FAIL: footprint_classify: " + message)


def classify(map_path, rules_path, *extra):
    return subprocess.run([sys.executable, str(CLASSIFY), str(map_path),
                           "--rules", str(rules_path)] + list(extra),
                          capture_output=True, text=True)


def rule_categories(rules_name, objects, workdir):
    lines = ["Memory Configuration", "",
             "Name             Origin             Length             Attributes",
             "FLASH            0x00000000         0x00100000         xr", "",
             "Linker script and memory map", "",
             ".text           0x00000100     0x%x" % (0x10 * len(objects))]
    for index, obj in enumerate(objects):
        lines.append(" .text.f%d       0x%08x       0x10 %s"
                     % (index, 0x100 + 0x10 * index, obj))
    path = Path(workdir) / (rules_name + ".map")
    path.write_text("\n".join(lines) + "\n")
    result = classify(path, RULES / (rules_name + ".rules"), "--json")
    check(result.returncode == 0,
          "%s.rules leaves objects unclassified: %s" % (rules_name, result.stderr))
    out = json.loads(result.stdout)
    return {row["object"]: row["category"] for row in out["objects"]}


def main():
    with tempfile.TemporaryDirectory() as workdir:
        map_path = Path(workdir) / "image.map"
        map_path.write_text(MAP)
        rules_path = Path(workdir) / "test.rules"
        rules_path.write_text(RULES_TEXT)

        readelf = Path(workdir) / "readelf"
        readelf.write_text("#!/bin/sh\necho '  [ 6] .nsc NOBITS 10000000 0 40 00 WA 0 0 1'\n"
                           "echo '  [ 9] .bss NOBITS 30000010 0 100 00 WA 0 0 4'\n")
        readelf.chmod(0o755)
        elf = ["--elf", str(map_path), "--readelf", str(readelf)]
        result = classify(map_path, rules_path, "--json", *elf)
        check(result.returncode == 0, "fixture map failed: " + result.stderr)
        out = json.loads(result.stdout)
        check(out["flash_total"] == 0x20 + 0x20 + 0x110 + 0x10 + 0x20,
              "flash total %d is not vectors + stubs + text + data + ramfunc"
              % out["flash_total"])
        check(out["flash"]["spm"] == 0x20 + 0x20 + 0x80, "spm flash %d" % out["flash"]["spm"])
        check(out["flash"]["crypto"] == 0x7c, "crypto flash %d" % out["flash"]["crypto"])
        check(out["flash"]["fill"] == 0x4, "fill %d" % out["flash"]["fill"])
        check(out["flash"]["linker"] == 0x110 - 0x80 - 0x4 - 0x7c,
              "linker-emitted bytes %d" % out["flash"]["linker"])
        check(out["flash"]["storage"] == 0x10 + 0x20, ".data and RAM code count once in flash")
        check(out["ram"]["storage"] == 0x10 + 0x20, ".data and RAM code count in RAM")
        check(out["ram"]["spm"] == 0x100 + 0x40, "NOBITS sections count in RAM only")
        check(out["gated"] == out["flash_total"] - 0x7c, "gated total leaves out crypto")
        check(sum(out["flash"].values()) == out["flash_total"],
              "categories do not add up to the flash total")
        check(not any(row["object"].endswith("wt_sec_dead.o") for row in out["objects"]),
              "a discarded input section was counted")

        limit = out["gated"]
        check(classify(map_path, rules_path, "--max", str(limit), *elf).returncode == 0,
              "a total equal to --max failed")
        check(classify(map_path, rules_path, "--max", str(limit - 1), *elf).returncode == 1,
              "a total one byte over --max passed")

        rules_path.write_text(RULES_TEXT.replace("crypto   /wc_sec_\n", ""))
        result = classify(map_path, rules_path)
        check(result.returncode == 2 and "wc_sec_aes.o" in result.stderr,
              "an unclassified object did not fail the run")

        for name, objects in (("wolftrust", WOLFTRUST_OBJECTS), ("tfm", TFM_OBJECTS)):
            got = rule_categories(name, list(objects), workdir)
            for obj, want in objects.items():
                check(got.get(obj) == want,
                      "%s.rules puts %s in %s, want %s" % (name, obj, got.get(obj), want))

    print("PASS: footprint classify (%d checks)" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
