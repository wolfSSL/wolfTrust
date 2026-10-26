#!/usr/bin/env python3
"""Check that compiled guest image layouts match an Armv8-M manifest."""

import argparse
import json
import sys
from pathlib import Path


DOMAIN_CLASS_NONSECURE = 2
MEMORY_ATTR_EXECUTE = 1 << 2


def is_integer(value):
    """Return whether value is an integer, excluding JSON booleans."""
    return isinstance(value, int) and not isinstance(value, bool)


def display(value):
    """Format valid addresses as hex and malformed values safely."""
    return f"{value:#x}" if is_integer(value) else repr(value)


def parse_guest(value):
    """Parse ID=BASE:SIZE into an integer tuple."""
    try:
        domain_id_text, layout = value.split("=", 1)
        base_text, size_text = layout.split(":", 1)
        domain_id = int(domain_id_text, 0)
        base = int(base_text, 0)
        size = int(size_text, 0)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError(
            "guest layout must be ID=BASE:SIZE") from error

    if domain_id < 0 or base < 0 or size <= 0:
        raise argparse.ArgumentTypeError(
            "guest ID and base must be non-negative and size must be positive")
    return domain_id, base, size


def check_layout(manifest, expected):
    """Return layout errors for the expected Non-secure guest domains."""
    errors = []
    if not isinstance(manifest, dict):
        return ["manifest root must be an object"]

    domains = manifest.get("domains")
    if not isinstance(domains, list):
        return ["manifest domains must be an array"]

    guests = [domain for domain in domains if isinstance(domain, dict) and
              domain.get("domain_class") == DOMAIN_CLASS_NONSECURE]
    actual_ids = []
    for domain in guests:
        domain_id = domain.get("id")
        if is_integer(domain_id):
            actual_ids.append(domain_id)
        else:
            errors.append(
                f"Non-secure domain has invalid ID {display(domain_id)}")

    if len(actual_ids) != len(set(actual_ids)):
        errors.append("manifest contains duplicate Non-secure domain IDs")

    expected_ids = set(expected)
    actual_id_set = set(actual_ids)
    if actual_id_set != expected_ids:
        errors.append(
            "Non-secure domain IDs do not match: expected "
            f"{sorted(expected_ids)}, found {sorted(actual_id_set)}")

    for domain in guests:
        domain_id = domain.get("id")
        if not is_integer(domain_id) or domain_id not in expected:
            continue

        base, size = expected[domain_id]
        resources = domain.get("memory_resources")
        if not isinstance(resources, list):
            errors.append(f"domain {domain_id} memory resources must be an array")
            continue

        executable = []
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                errors.append(
                    f"domain {domain_id} resource {index} must be an object")
                continue
            attributes = resource.get("attributes")
            if not is_integer(attributes):
                errors.append(
                    f"domain {domain_id} resource {index} has invalid "
                    f"attributes {display(attributes)}")
                continue
            if attributes & MEMORY_ATTR_EXECUTE:
                executable.append(resource)
        if len(executable) != 1:
            errors.append(
                f"domain {domain_id} must have exactly one executable region")
            continue

        resource = executable[0]
        actual_base = resource.get("base")
        actual_size = resource.get("size")
        if (not is_integer(actual_base) or not is_integer(actual_size) or
                actual_base != base or actual_size != size):
            errors.append(
                f"domain {domain_id} executable region is "
                f"{display(actual_base)}:{display(actual_size)}, expected "
                f"{base:#x}:{size:#x}")
        entry_point = domain.get("entry_point")
        if not is_integer(entry_point) or entry_point != base:
            errors.append(
                f"domain {domain_id} entry point is "
                f"{display(entry_point)}, expected vector base {base:#x}")

    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--guest", action="append", default=[], type=parse_guest,
        help="expected Non-secure guest layout as ID=BASE:SIZE")
    args = parser.parse_args()

    expected = {}
    for domain_id, base, size in args.guest:
        if domain_id in expected:
            parser.error(f"duplicate guest domain ID {domain_id}")
        expected[domain_id] = (base, size)
    if not expected:
        parser.error("at least one --guest layout is required")

    try:
        with args.manifest.open("r", encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
    except (OSError, json.JSONDecodeError) as error:
        parser.error(str(error))

    errors = check_layout(manifest, expected)
    if errors:
        for error in errors:
            print(f"guest layout error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
