#!/usr/bin/env python3
"""Check Armv8-M initialization of the TPM and PKCS11 data bands."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
START = ROOT / "src/arch/armv8m/start_armv8m.c"
LINKERS = (
    ROOT / "src/services/wolfhsm/runner/secure.ld",
    ROOT / "port/mimxrt700/secure.ld",
)


def require(text, needle, source):
    if needle not in text:
        raise SystemExit("FAIL: %s lacks %s" % (source, needle))


start = START.read_text(encoding="utf-8")
for symbol in (
    "_si_tpm", "_s_tpm", "_e_tpm_data", "_s_tpm_bss", "_e_tpm",
    "_wt_band_tpm_base", "_wt_band_tpm_limit",
    "_wt_tpm_stack_base", "_wt_tpm_stack_limit",
):
    require(start, "extern uint32_t %s;" % symbol, START)

for symbol in (
    "_si_pkcs11", "_s_pkcs11", "_e_pkcs11_data", "_s_pkcs11_bss",
    "_e_pkcs11", "_wt_band_pkcs11_base", "_wt_band_pkcs11_limit",
    "_wt_pkcs11_stack_base", "_wt_pkcs11_stack_limit",
):
    require(start, "extern uint32_t %s;" % symbol, START)

require(
    start,
    "{ &_si_tpm, &_s_tpm, &_e_tpm_data, &_s_tpm_bss, &_e_tpm,\n"
    "      &_wt_band_tpm_base, &_wt_band_tpm_limit },",
    START,
)

require(
    start,
    "{ &_si_pkcs11, &_s_pkcs11, &_e_pkcs11_data, &_s_pkcs11_bss,\n"
    "      &_e_pkcs11, &_wt_band_pkcs11_base, &_wt_band_pkcs11_limit },",
    START,
)

for linker in LINKERS:
    text = linker.read_text(encoding="utf-8")
    for api, prefix in (("tpm", "tpm"), ("pkcs11", "p11")):
        require(text, "_wt_band_%s_base = ORIGIN(VNETDATA);" % api,
                linker)
        require(text, "_wt_band_%s_limit = ORIGIN(VNETDATA) +\n"
                "    ((SIZEOF(.%s_data) + SIZEOF(.%s_bss)) != 0 ? 48K : 0);"
                % (api, api, api), linker)
        for edge, amount in (("base", "48K"), ("limit", "64K")):
            require(text, "_wt_%s_stack_%s = ORIGIN(VNETDATA) +\n"
                    "    ((SIZEOF(.%s_data) + SIZEOF(.%s_bss)) != 0 ? %s : 0);"
                    % (api, edge, api, api, amount), linker)
        for pattern in ("wt_sec_%s*.o" % api, "%s_sec_*.o" % prefix,
                        "%s_wc_*.o" % prefix, "%s_wh_*.o" % prefix):
            require(text, "*%s(.data .data.*)" % pattern, linker)
            require(text, "*%s(.bss .bss.* COMMON)" % pattern, linker)

require(
    start,
    "for (dst = &_wt_tpm_stack_base; dst < &_wt_tpm_stack_limit; ++dst)",
    START,
)

require(
    start,
    "for (dst = &_wt_pkcs11_stack_base;\n"
    "         dst < &_wt_pkcs11_stack_limit; ++dst)",
    START,
)

print("PASS: Armv8-M TPM and PKCS11 band initialization contract")
