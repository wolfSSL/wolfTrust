#!/usr/bin/env python3
# crypto_profile.py
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Generate build-only operation selections against the pinned dependencies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


KINDS = ("psa", "pkcs11", "tpm")
TPM_TABLE = "static const FWTPM_CMD_ENTRY fwCmdTable[] = {"


def write_file(path, text):
    if not path.exists() or path.read_text() != text:
        path.write_text(text)


def masked_c(source):
    """Keep offsets while hiding braces in comments and string literals."""
    token = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(token, lambda m: re.sub(r"[^\n]", " ", m.group()),
                  source, flags=re.S)


def definitions(source, pattern):
    masked = masked_c(source)
    for match in re.finditer(pattern, masked):
        depth = 1
        end = match.end()
        while end < len(masked) and depth:
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        if depth:
            raise ValueError("unbalanced function definition")
        yield match, end


def tpm_table(source):
    if source.count(TPM_TABLE) != 1:
        raise ValueError("pinned fwTPM command-table format changed")
    start = source.index(TPM_TABLE) + len(TPM_TABLE)
    end = source.index("\n};", start)
    body = source[start:end]
    rows = list(re.finditer(
        r"(?m)^[ \t]*\{\s*TPM_CC_(\w+)\s*,[^\n]*\},[ \t]*$", body))
    if len(rows) != len(re.findall(r"\{\s*TPM_CC_", masked_c(body))):
        raise ValueError("unrecognized fwTPM command descriptor")
    if not rows:
        raise ValueError("empty fwTPM command catalog")
    return start, end, rows


def discover(root):
    proxy = (root / "src/client/pkcs11_proxy.c").read_text()
    signatures = {}
    supported = set()
    for match, end in definitions(proxy,
            r"static\s+CK_RV\s+proxy_(C_\w+)\s*\(([^;{}]*?)\)\s*\{"):
        signatures[match.group(1)] = proxy[match.start(2):match.end(2)]
        if "proxy_unsupported(" not in proxy[match.end():end]:
            supported.add(match.group(1))
    if not signatures:
        raise ValueError("PKCS11 proxy catalog is empty")
    psa = root / "lib/wolfPSA"
    headers = "\n".join(p.read_text() for p in
                        (psa / "wolfpsa/psa").rglob("*.h"))
    public = set(re.findall(r"\bpsa_status_t\s+(psa_\w+)\s*\(", headers))
    sources = {p.name: p.read_text() for p in (psa / "src").glob("*.c")
               if p.name not in ("psa_store_posix.c", "psa_attestation.c")}
    implemented = set()
    for source in sources.values():
        implemented.update(m.group(1) for m, _ in definitions(source,
            r"\bpsa_status_t\s+(psa_\w+)\s*\([^;{}]*?\)\s*\{"))
    commands = (root / "lib/wolfTPM/src/fwtpm/fwtpm_command.c").read_text()
    _, _, rows = tpm_table(commands)
    return ({"psa": public & implemented, "pkcs11": supported,
             "tpm": {m.group(1) for m in rows}}, signatures, sources, commands)


def select(catalog, defaults, profile, custom, enable, disable):
    if not isinstance(custom, dict):
        raise ValueError("profile configuration must be a JSON object")
    for kind, names in custom.items():
        if not isinstance(names, list) or any(not isinstance(n, str) for n in names):
            raise ValueError("profile field %s must be a list of names" % kind)
    selected = {kind: set(catalog[kind] if profile == "full" else
                          defaults[kind]) for kind in KINDS}
    mechanisms = None if profile == "full" else defaults["mechanisms"]
    for kind, names in custom.items():
        if kind == "mechanisms":
            mechanisms = names
        elif kind in KINDS:
            selected[kind] = set(names)
        else:
            raise ValueError("unknown profile field: " + kind)
    for values, enabled in ((enable, True), (disable, False)):
        for value in values:
            kind, separator, name = value.partition(":")
            if not separator or kind not in KINDS or name not in catalog[kind]:
                raise ValueError("unknown operation: " + value)
            if enabled:
                selected[kind].add(name)
            else:
                selected[kind].discard(name)
    for kind in KINDS:
        unknown = selected[kind] - catalog[kind]
        if unknown:
            raise ValueError("unknown %s operations: %s" %
                             (kind, ", ".join(sorted(unknown))))
    if not selected["tpm"]:
        raise ValueError("a TPM profile requires at least one command")
    if mechanisms is not None and any(not re.fullmatch(r"CKM_[A-Z0-9_]+", n)
                                      for n in mechanisms):
        raise ValueError("invalid PKCS11 mechanism name")
    return selected, mechanisms


def psa_wrappers(root, output, sources, enabled, public):
    signatures = {}
    pattern = r"\bpsa_status_t\s+(psa_\w+)\s*\(([^;{}]*?)\)\s*\{"
    for source in sources.values():
        for match, _ in definitions(source, pattern):
            if match.group(1) in public:
                signatures.setdefault(match.group(1),
                    source[match.start(2):match.end(2)])
    renames = ["/* Private implementation names preserve internal dependencies. */"]
    renames.extend("#define %s wt_profile_real_%s" % (name, name)
                   for name in sorted(public))
    write_file(output / "private_psa.h", "\n".join(renames) + "\n")
    psa_output = output / "psa"
    psa_output.mkdir(exist_ok=True)
    for name in sources:
        original = (root / "lib/wolfPSA/src" / name).resolve()
        write_file(psa_output / name,
            '#include "../private_psa.h"\n#include %s\n' %
            json.dumps(str(original)))
    adapters = ['/* Generated public entry points for the selected profile. */',
                '#include <psa/crypto.h>', '#include <psa/crypto-pqc.h>']
    for name, parameters in sorted(signatures.items()):
        args = arguments(masked_c(parameters))
        if name in enabled:
            adapters.append("extern psa_status_t wt_profile_real_%s(%s);" %
                            (name, parameters))
        adapters.append("psa_status_t %s(%s)\n{" % (name, parameters))
        if name in enabled:
            adapters.append("    return wt_profile_real_%s(%s);" %
                            (name, ", ".join(args)))
        else:
            adapters.extend("    (void)%s;" % arg for arg in args)
            adapters.append("    return PSA_ERROR_NOT_SUPPORTED;")
        adapters.append("}")
    write_file(psa_output / "profile_api.c", "\n".join(adapters) + "\n")


def selected_tpm(source, enabled, full=False):
    start, end, rows = tpm_table(source)
    body = source[start:end]
    for row in reversed(rows):
        if row.group(1) not in enabled:
            body = body[:row.start()] + body[row.end():]
    result = source[:start] + body + source[end:]
    if not full:
        # A selected command hidden by dependency guards must fail the build.
        check = ("\ntypedef char wt_selected_tpm_commands_available[\n"
                 "    (sizeof(fwCmdTable) / sizeof(fwCmdTable[0]) == %dU) ? 1 : -1];\n"
                 % len(enabled))
        result = result[:start + len(body) + 3] + check + result[start + len(body) + 3:]
    return result


def opcode(name):
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name[2:])
    return "WT_P11_" + re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).upper()


def arguments(parameters):
    if parameters.strip() == "void":
        return []
    result = []
    for parameter in parameters.split(","):
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$", parameter)
        if match is None:
            raise ValueError("unrecognized PKCS11 parameter: " + parameter)
        result.append(match.group(1))
    return result


def pkcs11_header(signatures, enabled, mechanisms):
    lines = ["/* Generated operation selection. */", "#ifndef WT_PKCS11_PROFILE_H",
             "#define WT_PKCS11_PROFILE_H",
             "static inline int wt_profile_pkcs11_mechanism(CK_MECHANISM_TYPE mechanism)", "{"]
    if mechanisms is None:
        lines.extend(["    (void)mechanism;", "    return 1;"])
    elif mechanisms:
        # Equality tests accept numeric aliases without duplicate case labels.
        expression = " || ".join("mechanism == %s" % name
                                  for name in sorted(mechanisms))
        lines.append("    return " + expression + ";")
    else:
        lines.extend(["    (void)mechanism;", "    return 0;"])
    lines.append("}")
    for name, parameters in sorted(signatures.items()):
        args = arguments(parameters)
        if name in enabled:
            lines.append("#define WT_P11_EXPORT_%s proxy_%s" % (name, name))
            if re.search(r"CK_MECHANISM_PTR\s+mechanism\b", parameters):
                lines.extend(["#ifdef WT_PKCS11_PROVIDER_BUILD",
                    "static inline CK_RV wt_filtered_%s(%s)" % (name, parameters),
                    "{", "    if (mechanism != NULL &&",
                    "            !wt_profile_pkcs11_mechanism(mechanism->mechanism)) {",
                    "        return CKR_MECHANISM_INVALID;", "    }",
                    "    return %s(%s);" % (name, ", ".join(args)), "}",
                    "#undef %s" % name,
                    "#define %s wt_filtered_%s" % (name, name), "#endif"])
        else:
            lines.append("static inline CK_RV wt_disabled_%s(%s)\n{" % (name, parameters))
            lines.extend("    (void)%s;" % arg for arg in args)
            lines.append("    return CKR_FUNCTION_NOT_SUPPORTED;\n}")
            lines.append("#define WT_P11_EXPORT_%s wt_disabled_%s" % (name, name))
            lines.append("#ifdef WT_PKCS11_PROVIDER_BUILD\n#undef %s\n#define %s wt_disabled_%s\n#endif" %
                         (name, name, name))
    lines.extend(["#define WT_P11_EXPORT(name) WT_P11_EXPORT_ ## name",
                  "static inline int wt_profile_pkcs11_operation(uint32_t operation)", "{"])
    if enabled:
        lines.append("    switch (operation) {")
        lines.extend("        case %s:" % opcode(name) for name in sorted(enabled))
        lines.extend(["            return 1;", "        default: return 0;", "    }"])
    else:
        lines.extend(["    (void)operation;", "    return 0;"])
    lines.extend(["}", "static inline CK_FLAGS wt_profile_pkcs11_flags(CK_FLAGS flags)", "{"])
    actions = {
        "CKF_ENCRYPT": (("C_EncryptInit", "C_Encrypt"), ("C_EncryptInit", "C_EncryptUpdate", "C_EncryptFinal")),
        "CKF_DECRYPT": (("C_DecryptInit", "C_Decrypt"), ("C_DecryptInit", "C_DecryptUpdate", "C_DecryptFinal")),
        "CKF_DIGEST": (("C_DigestInit", "C_Digest"), ("C_DigestInit", "C_DigestUpdate", "C_DigestFinal")),
        "CKF_SIGN": (("C_SignInit", "C_Sign"), ("C_SignInit", "C_SignUpdate", "C_SignFinal")),
        "CKF_VERIFY": (("C_VerifyInit", "C_Verify"), ("C_VerifyInit", "C_VerifyUpdate", "C_VerifyFinal")),
        "CKF_SIGN_RECOVER": (("C_SignRecoverInit", "C_SignRecover"),),
        "CKF_VERIFY_RECOVER": (("C_VerifyRecoverInit", "C_VerifyRecover"),),
        "CKF_GENERATE": (("C_GenerateKey",),),
        "CKF_GENERATE_KEY_PAIR": (("C_GenerateKeyPair",),),
        "CKF_DERIVE": (("C_DeriveKey",),),
        "CKF_WRAP": (("C_WrapKey",),),
        "CKF_UNWRAP": (("C_UnwrapKey",),),
    }
    for flag, alternatives in actions.items():
        if not any(set(names) <= enabled for names in alternatives):
            lines.append("    flags &= ~(CK_FLAGS)%s;" % flag)
    lines.extend(["    return flags;", "}", "#endif", ""])
    return "\n".join(lines)


def generate(root, output, profile, custom, enable, disable):
    catalog, signatures, sources, commands = discover(root)
    defaults = json.loads((root / "config/crypto-profiles.json").read_text())["default"]
    selected, mechanisms = select(catalog, defaults, profile, custom, enable, disable)
    output.mkdir(parents=True, exist_ok=True)
    write_file(output / "pkcs11_profile.h",
        pkcs11_header(signatures, selected["pkcs11"], mechanisms))
    write_file(output / "fwtpm_command.c", selected_tpm(commands, selected["tpm"], profile == "full"))
    psa_wrappers(root, output, sources, selected["psa"], catalog["psa"])
    flags = ["/* Generated build configuration. */",
             "#ifndef WT_SELECTED_CRYPTO_PROFILE_H",
             "#define WT_SELECTED_CRYPTO_PROFILE_H",
             "#define WT_PROFILE_FULL %d" % (profile == "full"),
             "#define WT_PROFILE_TPM_COMMAND_COUNT %dU" % len(selected["tpm"]),
             "#define WT_PKCS11_PROFILE_HEADER %s" %
             json.dumps(str((output / "pkcs11_profile.h").resolve()))]
    for kind in KINDS:
        for name in sorted(catalog[kind]):
            flags.append("#define WT_PROFILE_%s_%s %d" %
                         (kind.upper(), name, name in selected[kind]))
    flags.extend([
        "/* TPM ZGen_2Phase needs a full point, not the ECDH callback's x output. */",
        "#if defined(WT_TPM_HSM_CALLBACK_ECC) && !WT_PROFILE_TPM_ZGen_2Phase",
        "#define WOLF_CRYPTO_CB_ONLY_ECC 1",
        "#endif",
    ])
    flags.extend(["#endif", ""])
    write_file(output / "selected_profile.h", "\n".join(flags))
    manifest = {kind: sorted(names) for kind, names in selected.items()}
    manifest.update(profile=profile, mechanisms=mechanisms,
                    tpm_commands="requested; dependency feature guards still apply; default-derived builds check availability",
                    fwtpm_source_sha256=hashlib.sha256(commands.encode()).hexdigest())
    write_file(output / "selection.json", json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile", choices=("default", "full"), default="default")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--enable", action="append", default=[])
    parser.add_argument("--disable", action="append", default=[])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    try:
        if args.list:
            print(json.dumps({k: sorted(v) for k, v in discover(args.root)[0].items()}, indent=2))
        elif args.output is None:
            parser.error("--output is required")
        else:
            config = args.config or (Path(os.environ["WT_CRYPTO_CONFIG"])
                                     if os.environ.get("WT_CRYPTO_CONFIG") else None)
            custom = json.loads(config.read_text()) if config else {}
            enable = args.enable + os.environ.get("WT_CRYPTO_ENABLE", "").split()
            disable = args.disable + os.environ.get("WT_CRYPTO_DISABLE", "").split()
            generate(args.root, args.output, args.profile, custom, enable, disable)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
