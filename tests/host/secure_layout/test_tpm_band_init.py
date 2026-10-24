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
    require(text, "_wt_band_tpm_base = ORIGIN(TPMDATA);", linker)
    require(
        text,
        "_wt_band_tpm_limit = ORIGIN(TPMDATA) + LENGTH(TPMDATA);",
        linker,
    )
    require(text, "_wt_tpm_stack_base = ORIGIN(CONFDATA);", linker)
    require(text, "_wt_tpm_stack_limit = ORIGIN(TPMDATA);", linker)
    require(
        text,
        "*wt_sec_tpm_relay_service.o(.data .data.*)",
        linker,
    )
    require(
        text,
        "*wt_sec_tpm_relay_service.o(.bss .bss.* COMMON)",
        linker,
    )
    require(text, "_wt_band_pkcs11_base = ORIGIN(VNETDATA);", linker)
    require(
        text,
        "_wt_band_pkcs11_limit = ORIGIN(VNETDATA) + LENGTH(VNETDATA);",
        linker,
    )
    require(text, "_wt_pkcs11_stack_base = ORIGIN(CONFDATA);", linker)
    require(text, "_wt_pkcs11_stack_limit = ORIGIN(TPMDATA);", linker)
    require(
        text,
        "*wt_sec_pkcs11_relay_service.o(.data .data.*)",
        linker,
    )
    require(
        text,
        "*wt_sec_pkcs11_relay_service.o(.bss .bss.* COMMON)",
        linker,
    )

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
