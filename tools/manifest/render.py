#!/usr/bin/env python3
"""Render the system manifest for one build from the shared template.

manifest/base.json describes the production partitions with every address
and size written as a memory_map.h expression; a variant overlay
(manifest/conformance.json, manifest/vnet.json) drops partitions and adds
its own domains and partitions in the same form. The renderer applies the
overlays, evaluates every expression in one preprocessor pass under the
build's layout configuration (--cflags, the WT_LAYOUT_CFLAGS of
mk/layout.mk), derives the capability and limit counters from the content
and writes the canonical JSON the generator and its digest consume. The
output is written only when it changed and never on a failure."""

import argparse
import copy
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

EXPRESSION_KEYS = ("base", "size", "entry_point", "stack_base", "stack_size",
                   "interrupt")
INTEGER = re.compile(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b")
CONSTANT = re.compile(r"^[0-9a-fA-FxX+\-*() ]+$")


class RenderError(Exception):
    pass


def apply_overlay(manifest, overlay):
    dropped = set(overlay.get("drop_partitions", []))
    unknown = dropped - {part["name"] for part in manifest["partitions"]}
    if unknown:
        raise RenderError("overlay drops unknown partition(s): %s" %
                          ", ".join(sorted(unknown)))
    domain_ids = {part["domain_id"] for part in manifest["partitions"]
                  if part["name"] in dropped}
    manifest["partitions"] = [part for part in manifest["partitions"]
                              if part["name"] not in dropped]
    manifest["domains"] = [domain for domain in manifest["domains"]
                           if domain["id"] not in domain_ids]
    manifest["domains"] += copy.deepcopy(overlay.get("domains", []))
    manifest["partitions"] += copy.deepcopy(overlay.get("partitions", []))


def expressions(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in EXPRESSION_KEYS and isinstance(value, str):
                found.append(value)
            else:
                expressions(value, found)
    elif isinstance(node, list):
        for value in node:
            expressions(value, found)


def substitute(node, values):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in EXPRESSION_KEYS and isinstance(value, str):
                node[key] = values[value]
            else:
                substitute(value, values)
    elif isinstance(node, list):
        for value in node:
            substitute(value, values)


def evaluate(cc, cflags, names):
    names = sorted(set(names))
    if not names:
        return {}
    probe = '#include "memory_map.h"\n'
    probe += "".join("%d=%s\n" % pair for pair in enumerate(names))
    command = [cc, "-E", "-P", "-x", "c"] + list(cflags) + ["-"]
    result = subprocess.run(command, input=probe, text=True,
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise RenderError("preprocessing the layout failed:\n" +
                          result.stderr.strip())
    values = {}
    for line in result.stdout.splitlines():
        index, separator, text = line.partition("=")
        if not separator or not index.isdigit() or int(index) >= len(names):
            continue
        name = names[int(index)]
        text = INTEGER.sub(r"\1", text).strip()
        if not CONSTANT.match(text):
            raise RenderError("%s does not reduce to a constant: %s" %
                              (name, text))
        values[name] = eval(text, {"__builtins__": {}})
    missing = [name for name in names if name not in values]
    if missing:
        raise RenderError("the layout defines no " + ", ".join(missing))
    return values


def derive_counters(manifest):
    domains = manifest["domains"]
    partitions = manifest["partitions"]
    if not domains or not partitions:
        raise RenderError("the manifest has no domains or no partitions")
    capabilities = manifest["profile_capabilities"]
    capabilities["max_domains"] = len(domains)
    capabilities["max_memory_resources_per_domain"] = max(
        len(domain["memory_resources"]) for domain in domains)
    capabilities["max_interrupts_per_domain"] = max(
        len(domain["interrupt_resources"]) for domain in domains)
    limits = manifest["limits"]
    limits["max_partitions"] = len(partitions)
    limits["max_services_per_partition"] = max(
        len(part["services"]) for part in partitions)
    limits["max_dependencies_per_partition"] = max(
        [len(part["dependencies"]) for part in partitions] + [1])


def render(template, overlays, cc, cflags):
    manifest = json.loads(Path(template).read_text(encoding="utf-8"))
    for overlay in overlays:
        apply_overlay(manifest,
                      json.loads(Path(overlay).read_text(encoding="utf-8")))
    found = []
    expressions(manifest, found)
    substitute(manifest, evaluate(cc, cflags, found))
    derive_counters(manifest)
    return json.dumps(manifest, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--overlay", action="append", default=[], type=Path)
    parser.add_argument("--cc", default="arm-none-eabi-gcc")
    parser.add_argument("--cflags", default="",
                        help="the build's layout defines and include paths")
    parser.add_argument("--output", type=Path,
                        help="written only when the content changes")
    args = parser.parse_args()
    try:
        text = render(args.template, args.overlay, args.cc,
                      shlex.split(args.cflags))
    except (RenderError, OSError, json.JSONDecodeError, KeyError) as error:
        print("manifest render failed: %s" % error, file=sys.stderr)
        return 1
    if args.output is None:
        sys.stdout.write(text)
        return 0
    current = None
    if args.output.exists():
        current = args.output.read_text(encoding="utf-8")
    if current != text:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
