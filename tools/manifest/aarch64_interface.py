#!/usr/bin/env python3
"""Add one optional application-interface partition to an AArch64 manifest."""

import argparse
import copy
import json
import sys
from pathlib import Path


INTERFACES = {
    "tpm": {
        "partition": "PARTITION_TPM",
        "service": "SERVICE_TPM",
        "sid": 4104,
        "uuid": "14a60fe3-05ca-583d-a88a-1e9d0a47d74d",
        "dependencies": [4102],
    },
    "pkcs11": {
        "partition": "PARTITION_PKCS11",
        "service": "SERVICE_PKCS11",
        "sid": 4105,
        "uuid": "ab4f39e1-d12d-5b91-a21c-57d66f7f04ae",
        "dependencies": [4102],
    },
}


def parse_int(value):
    return int(value, 0)


def add_interface(manifest, kind, stack_base, data_base, data_size):
    interface = INTERFACES[kind]
    secure_domains = [domain for domain in manifest["domains"]
                      if domain["domain_class"] == 1]
    if not secure_domains:
        raise ValueError("base manifest has no Secure Partition domain")
    if any(partition["name"] == interface["partition"]
           for partition in manifest["partitions"]):
        raise ValueError("interface partition already exists")

    domain_id = max(domain["id"] for domain in manifest["domains"]) + 1
    template = copy.deepcopy(secure_domains[-1])
    image = copy.deepcopy(template["memory_resources"][0])
    template["id"] = domain_id
    template["stack_base"] = stack_base
    template["stack_size"] = 0x4000
    template["memory_resources"] = [
        image,
        {
            "base": stack_base,
            "size": 0x4000,
            "attributes": 19,
            "share_id": 0,
        },
        {
            "base": data_base,
            "size": data_size,
            "attributes": 19,
            "share_id": 0,
        },
    ]
    manifest["domains"].append(template)

    partition = {
        "name": interface["partition"],
        "domain_id": domain_id,
        "framework_version": 256,
        "model": 0,
        "priority": 1,
        "services": [{
            "name": interface["service"],
            "sid": interface["sid"],
            "version": 1,
            "version_policy": 0,
            "signal": 16,
            "stateless_handle_index": 0,
            "nonsecure_clients": True,
            "connection_based": True,
        }],
        "dependencies": interface["dependencies"],
        "interrupts": [],
    }
    manifest["partitions"].append(partition)
    manifest["profile_capabilities"]["max_domains"] = len(
        manifest["domains"])
    manifest["limits"]["max_partitions"] = len(manifest["partitions"])

    ffa_template = copy.deepcopy(manifest["ffa"]["partitions"][-1])
    ffa_template["domain_id"] = domain_id
    ffa_template["uuids"] = [interface["uuid"]]
    manifest["ffa"]["partitions"].append(ffa_template)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--interface", choices=sorted(INTERFACES),
                        required=True)
    parser.add_argument("--stack-base", type=parse_int, required=True)
    parser.add_argument("--data-base", type=parse_int, required=True)
    parser.add_argument("--data-size", type=parse_int, required=True)
    args = parser.parse_args()

    try:
        manifest = json.loads(args.input.read_text(encoding="utf-8"))
        manifest = add_interface(manifest, args.interface, args.stack_base,
                                 args.data_base, args.data_size)
        args.output.write_text(json.dumps(manifest, indent=2) + "\n",
                               encoding="utf-8")
    except (KeyError, TypeError, ValueError, OSError,
            json.JSONDecodeError) as error:
        print("interface manifest generation failed: {}".format(error),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
