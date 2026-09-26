#!/usr/bin/env python3
# generate.py
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

"""Generate C from the normalized wolfTrust manifest representation."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


UINT = "uint"
WORD = "word"
BOOL = "bool"
STRING = "string"

MEMORY_SCHEMA = {
    "base": WORD,
    "size": WORD,
    "attributes": UINT,
    "share_id": UINT,
}

INTERRUPT_RESOURCE_SCHEMA = {
    "interrupt": UINT,
    "attributes": UINT,
    "share_id": UINT,
}

RESTART_SCHEMA = {
    "action": UINT,
    "restart_limit": UINT,
    "restart_window_ticks": UINT,
    "initial_delay_ticks": UINT,
}

DOMAIN_SCHEMA = {
    "id": UINT,
    "domain_class": UINT,
    "rot_role": UINT,
    "security_state": UINT,
    "privilege_state": UINT,
    "initial_lifecycle": UINT,
    "entry_point": WORD,
    "stack_base": WORD,
    "stack_size": WORD,
    "memory_resources": [MEMORY_SCHEMA],
    "interrupt_resources": [INTERRUPT_RESOURCE_SCHEMA],
    "restart_policy": RESTART_SCHEMA,
    "required_capabilities": UINT,
    "launch_required": UINT,
    "launch_min_version": UINT,
}

SERVICE_SCHEMA = {
    "name": STRING,
    "sid": UINT,
    "version": UINT,
    "version_policy": UINT,
    "signal": UINT,
    "stateless_handle_index": UINT,
    "nonsecure_clients": BOOL,
    "connection_based": BOOL,
}

MANIFEST_INTERRUPT_SCHEMA = {
    "signal_name": STRING,
    "interrupt": UINT,
    "signal": UINT,
}

PARTITION_SCHEMA = {
    "name": STRING,
    "domain_id": UINT,
    "framework_version": UINT,
    "model": UINT,
    "priority": UINT,
    "services": [SERVICE_SCHEMA],
    "dependencies": [UINT],
    "interrupts": [MANIFEST_INTERRUPT_SCHEMA],
}

CAPABILITIES_SCHEMA = {
    "capabilities": UINT,
    "max_domains": UINT,
    "max_memory_resources_per_domain": UINT,
    "max_interrupts_per_domain": UINT,
}

LIMITS_SCHEMA = {
    "max_partitions": UINT,
    "max_services_per_partition": UINT,
    "max_dependencies_per_partition": UINT,
    "max_stateless_handles": UINT,
}

MANIFEST_SCHEMA = {
    "format_version": UINT,
    "generator_version": STRING,
    "features": UINT,
    "isolation_profile": UINT,
    "profile_capabilities": CAPABILITIES_SCHEMA,
    "domains": [DOMAIN_SCHEMA],
    "partitions": [PARTITION_SCHEMA],
    "limits": LIMITS_SCHEMA,
}
# Optional top-level "ffa" section (AArch64 targets): FF-A partition
# properties per DEN0077A 1.2 Table 5.1, emitted as a separate table so the
# wolfTrust domain and partition structures are untouched.
FFA_PARTITION_SCHEMA = {
    "domain_id": UINT,
    "ffa_version": STRING,
    "uuids": [STRING],
    "execution_contexts": UINT,
    "runtime_el": STRING,
    "messaging": STRING,
    "ns_interrupt_action": STRING,
    "boot_info_register": STRING,
}
FFA_SCHEMA = {
    "partitions": [FFA_PARTITION_SCHEMA],
}
# Only the values the SPMC honours: every manifest partition expects FF-A 1.2,
# the version the SPMC holds a partition to until it negotiates, runs at S-EL0,
# takes no FF-A messages (its services are reached through the SPMC's PSA
# endpoint, so discovery lists neither messaging method), has its Non-secure
# interrupts signaled, and is handed no FF-A boot information (its entry
# register carries the partition id, not a blob address).
FFA_VERSIONS = {"1.2": 0x00010002}
FFA_RUNTIME_EL = {"S-EL0": 0}
FFA_MESSAGING = {"none": 0}
FFA_NS_INTERRUPT_ACTION = {"signaled": 0}
FFA_BOOT_INFO_REGISTER = {"none": 0xffffffff}
FFA_MAX_UUIDS = 4
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

FILE_HEADER = """/* {name}
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
"""


class ManifestError(ValueError):
    """Raised for malformed normalized manifest input."""


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("duplicate JSON key: " + key)
        result[key] = value
    return result


def validate(value, schema, path, word_max):
    if schema in (UINT, WORD):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ManifestError(path + " must be an unsigned integer")
        maximum = 0xffffffff if schema == UINT else word_max
        if value < 0 or value > maximum:
            raise ManifestError(path + " is outside the supported range")
        return

    if schema == BOOL:
        if not isinstance(value, bool):
            raise ManifestError(path + " must be a boolean")
        return

    if schema == STRING:
        if not isinstance(value, str) or not value:
            raise ManifestError(path + " must be a nonempty string")
        if any(ord(char) < 0x20 or ord(char) > 0x7e for char in value):
            raise ManifestError(path + " must contain printable ASCII")
        return

    if isinstance(schema, list):
        if not isinstance(value, list):
            raise ManifestError(path + " must be an array")
        for index, item in enumerate(value):
            validate(item, schema[0], "{}[{}]".format(path, index), word_max)
        return

    if not isinstance(value, dict):
        raise ManifestError(path + " must be an object")

    unknown = set(value) - set(schema)
    missing = set(schema) - set(value)
    if unknown:
        raise ManifestError(path + " has unknown field " + sorted(unknown)[0])
    if missing:
        raise ManifestError(path + "." + sorted(missing)[0] + " is required")
    for name, child_schema in schema.items():
        validate(value[name], child_schema, path + "." + name, word_max)


def policy_error(message):
    raise ManifestError("policy: " + message)


def name_valid(value):
    return re.fullmatch(r"[A-Z_][A-Z0-9_]*", value) is not None


def ranges_overlap(first_base, first_size, second_base, second_size):
    return (first_base < second_base + second_size and
            second_base < first_base + first_size)


MEMORY_ATTR_MASK = 0x3F
INTERRUPT_ATTR_SHARED = 0x01
CAPABILITY_MASK = 0x7F
FEATURE_MASK = 0x0F
RESERVED_SIGNALS = 0x0F
MAX_PARTITIONS = 32
MAX_SERVICES = 28
MAX_DEPENDENCIES = 32
MAX_SIGNALS = 28
MAX_NAME = 63
TABLE_L2_SHIFT = 30
TABLE_L3_SHIFT = 21
TABLE_SPARE_PAGES = 3
# The count is a lower bound (the SPMC's shared fill is not counted per
# table), so a pool below it fails the build rather than the boot.
TABLE_POOL_CHECK = (
    "#if !defined(WT_SPM_TABLE_POOL_PAGES) || \\",
    "    (WT_SPM_TABLE_POOL_PAGES < WT_GENERATED_TABLE_POOL_PAGES)",
    "#error \"WT_SPM_TABLE_POOL_PAGES is below this manifest's "
    "WT_GENERATED_TABLE_POOL_PAGES\"",
    "#endif",
    "",
)


def policy_range_end(base, size, word_max, description):
    if size == 0 or base + size > word_max + 1:
        policy_error(description + " is outside target address space")
    return base + size


def policy_signal_valid(signal):
    return (signal != 0 and (signal & RESERVED_SIGNALS) == 0 and
            (signal & (signal - 1)) == 0)


def policy_name_valid(name):
    return (len(name) <= MAX_NAME and name_valid(name))


def policy_generated_symbols(manifest):
    symbols = set()
    reserved = []
    raw_names = set()

    def add(symbol):
        if symbol in symbols:
            policy_error("generated symbol is duplicated: " + symbol)
        symbols.add(symbol)

    def reserve(symbol):
        if symbol in reserved:
            policy_error("generated symbol is duplicated: " + symbol)
        reserved.append(symbol)

    for partition in manifest["partitions"]:
        prefix = "WT_GENERATED_" + partition["name"]
        raw_names.add(partition["name"])
        for suffix in ("_DOMAIN_ID", "_FRAMEWORK_VERSION", "_MODEL"):
            add(prefix + suffix)
        if partition["framework_version"] == 0x101:
            reserve(partition["name"] + "_MODEL_IPC")
            reserve(partition["name"] + "_MODEL_SFN")
        for service in partition["services"]:
            service_prefix = "WT_GENERATED_" + service["name"]
            for suffix in ("_SID", "_VERSION"):
                add(service_prefix + suffix)
                reserve(service["name"] + suffix)
            if partition["model"] == 0:
                add(service_prefix + "_SIGNAL")
                reserve(service["name"] + "_SIGNAL")
            if not service["connection_based"]:
                add(service_prefix + "_HANDLE")
                reserve(service["name"] + "_HANDLE")
        for interrupt in partition["interrupts"]:
            raw_names.add(interrupt["signal_name"])
            add("WT_GENERATED_" + interrupt["signal_name"] + "_SIGNAL")

    if set(reserved) & raw_names:
        policy_error("generated symbol is duplicated")


def validate_policy(manifest, supported_features, word_max,
                    supported_framework=0x101, mpu_granule=32):
    features = manifest["features"]
    if features & ~FEATURE_MASK or features & 1 == 0:
        policy_error("invalid required feature set")
    if supported_features & ~FEATURE_MASK or features & ~supported_features:
        policy_error("manifest requests unsupported features")
    if manifest["format_version"] != 1:
        policy_error("unsupported manifest format")
    if not policy_name_valid(manifest["generator_version"]):
        policy_error("generator version is not a generated identifier")

    limits = manifest["limits"]
    if (limits["max_partitions"] == 0 or
            limits["max_partitions"] > MAX_PARTITIONS or
            limits["max_services_per_partition"] == 0 or
            limits["max_services_per_partition"] > MAX_SERVICES or
            limits["max_dependencies_per_partition"] == 0 or
            limits["max_dependencies_per_partition"] > MAX_DEPENDENCIES or
            limits["max_stateless_handles"] < 32):
        policy_error("manifest limits are invalid")

    capabilities = manifest["profile_capabilities"]
    if capabilities["capabilities"] & ~CAPABILITY_MASK:
        policy_error("profile capability mask is invalid")
    required_by_profile = {
        0: 0,
        1: 0x01 | 0x10,
        2: 0x01 | 0x04 | 0x10,
        3: 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20,
    }
    profile = manifest["isolation_profile"]
    if profile not in required_by_profile:
        policy_error("isolation profile is invalid")
    if capabilities["capabilities"] & required_by_profile[profile] != \
            required_by_profile[profile]:
        policy_error("profile capabilities are insufficient")

    domains = manifest["domains"]
    partitions = manifest["partitions"]
    if not partitions or len(partitions) > limits["max_partitions"]:
        policy_error("partition count exceeds limits")
    if not domains or len(domains) > capabilities["max_domains"]:
        policy_error("domain count exceeds profile capability")

    domain_ids = set()
    spm_count = 0
    all_memory = []
    all_interrupts = []
    for domain in domains:
        domain_id = domain["id"]
        if domain_id == 0xFFFFFFFF or domain_id in domain_ids:
            policy_error("domain identity is invalid or duplicated")
        domain_ids.add(domain_id)
        domain_class = domain["domain_class"]
        if domain_class not in (0, 1, 2):
            policy_error("domain class is invalid")
        if domain["rot_role"] not in (0, 1, 2, 3):
            policy_error("domain root-of-trust role is invalid")
        if domain["security_state"] not in (0, 1):
            policy_error("domain security state is invalid")
        if domain["privilege_state"] not in (0, 1):
            policy_error("domain privilege state is invalid")
        if domain["initial_lifecycle"] not in (0, 1):
            policy_error("domain lifecycle is invalid")
        if domain_class == 0:
            spm_count += 1
            if (domain["rot_role"], domain["security_state"],
                    domain["privilege_state"]) != (1, 0, 0):
                policy_error("SPM identity is invalid")
        elif domain_class == 1:
            if domain["rot_role"] not in (2, 3) or domain["security_state"] != 0:
                policy_error("Secure Partition identity is invalid")
        elif domain["rot_role"] != 0 or domain["security_state"] != 1:
            policy_error("Non-secure identity is invalid")

        if domain["launch_required"] not in (0, 1):
            policy_error("domain launch_required must be 0 or 1")
        if domain["launch_required"] == 1 and domain_class != 2:
            policy_error("authenticated launch applies to Non-secure domains")

        restart = domain["restart_policy"]
        if restart["action"] not in (0, 1, 2):
            policy_error("restart action is invalid")
        if restart["action"] == 1:
            if restart["restart_limit"] == 0 or restart["restart_window_ticks"] == 0:
                policy_error("domain restart policy is incomplete")
        elif (restart["restart_limit"] != 0 or
              restart["restart_window_ticks"] != 0 or
              restart["initial_delay_ticks"] != 0):
            policy_error("restart fields are invalid for this action")
        required = domain["required_capabilities"]
        if (required & ~CAPABILITY_MASK or
                capabilities["capabilities"] & required != required):
            policy_error("domain capabilities are unsupported")
        if (restart["action"] == 1 and
                not capabilities["capabilities"] & 0x40):
            policy_error("restart capability is unavailable")

        memories = domain["memory_resources"]
        interrupts = domain["interrupt_resources"]
        if not memories or len(memories) > capabilities["max_memory_resources_per_domain"]:
            policy_error("domain memory count is invalid")
        if len(interrupts) > capabilities["max_interrupts_per_domain"]:
            policy_error("domain interrupt count is invalid")
        if memories and not capabilities["capabilities"] & 0x10:
            policy_error("memory protection capability is unavailable")
        if interrupts and not capabilities["capabilities"] & 0x20:
            policy_error("interrupt isolation capability is unavailable")

        for memory in memories:
            policy_range_end(memory["base"], memory["size"], word_max,
                             "memory resource")
            attributes = memory["attributes"]
            if mpu_granule > 1 and (memory["base"] % mpu_granule != 0 or
                                    memory["size"] % mpu_granule != 0):
                policy_error("memory resource is not MPU-granule aligned")
            if attributes & ~MEMORY_ATTR_MASK:
                policy_error("memory attributes are invalid")
            if not attributes & 0x07:
                policy_error("memory resource has no access permission")
            if attributes & 0x08 and attributes & 0x04:
                policy_error("device memory is executable")
            if attributes & 0x10 and not attributes & 0x02:
                policy_error("restart-clear memory is not writable")
            if attributes & 0x06 == 0x06:
                policy_error("memory resource is writable and executable")
            if attributes & 0x20:
                if memory["share_id"] == 0:
                    policy_error("shared memory has no share identifier")
            elif memory["share_id"] != 0:
                policy_error("private memory has a share identifier")
            if domain_class == 1 and attributes & 0x08 and attributes & 0x20:
                policy_error("Secure Partition device memory cannot be shared")
            for owner, other in all_memory:
                if ranges_overlap(memory["base"], memory["size"],
                                  other["base"], other["size"]):
                    exact_shared = (
                        attributes & 0x20 and other["attributes"] & 0x20 and
                        memory["share_id"] != 0 and
                        memory["share_id"] == other["share_id"] and
                        memory["base"] == other["base"] and
                        memory["size"] == other["size"] and
                        attributes == other["attributes"])
                    if owner == domain_id or not exact_shared:
                        policy_error("memory resources overlap incompatibly")
            all_memory.append((domain_id, memory))
        for index, interrupt in enumerate(interrupts):
            number = interrupt["interrupt"]
            attributes = interrupt["attributes"]
            if number == 0xFFFFFFFF or attributes & ~INTERRUPT_ATTR_SHARED:
                policy_error("interrupt resource is invalid")
            if attributes & INTERRUPT_ATTR_SHARED:
                if interrupt["share_id"] == 0:
                    policy_error("shared interrupt has no share identifier")
            elif interrupt["share_id"] != 0:
                policy_error("private interrupt has a share identifier")
            if domain_class == 1 and attributes & INTERRUPT_ATTR_SHARED:
                policy_error("Secure Partition interrupts cannot be shared")
            if any(number == prior[1]["interrupt"]
                   for prior in all_interrupts if prior[0] == domain_id):
                policy_error("domain interrupt is multiply owned")
            all_interrupts.append((domain_id, interrupt))

        stack_end = policy_range_end(domain["stack_base"], domain["stack_size"],
                                     word_max, "domain stack")
        entry_found = False
        stack_found = False
        for memory in memories:
            end = memory["base"] + memory["size"]
            if memory["attributes"] & 0x04 and memory["base"] <= domain["entry_point"] < end:
                entry_found = True
            stack_attrs = memory["attributes"]
            if (stack_attrs & 0x03) == 0x03 and not stack_attrs & (0x04 | 0x08 | 0x20) and \
                    memory["base"] <= domain["stack_base"] and stack_end <= end:
                stack_found = True
        if not entry_found:
            policy_error("domain entry point is outside executable memory")
        if not stack_found:
            policy_error("domain stack is outside private writable memory")

    for index, (owner, first) in enumerate(all_memory):
        for other_owner, second in all_memory[index + 1:]:
            if owner == other_owner or not ranges_overlap(
                    first["base"], first["size"], second["base"], second["size"]):
                continue
            exact_shared = (
                first["attributes"] & 0x20 and second["attributes"] & 0x20 and
                first["share_id"] != 0 and first["share_id"] == second["share_id"] and
                first["base"] == second["base"] and first["size"] == second["size"] and
                first["attributes"] == second["attributes"])
            if not exact_shared:
                policy_error("memory resources overlap incompatibly")
    for index, (owner, first) in enumerate(all_interrupts):
        for other_owner, second in all_interrupts[index + 1:]:
            if owner == other_owner or first["interrupt"] != second["interrupt"]:
                continue
            shared = (first["attributes"] & INTERRUPT_ATTR_SHARED and
                      second["attributes"] & INTERRUPT_ATTR_SHARED and
                      first["share_id"] != 0 and
                      first["share_id"] == second["share_id"])
            if not shared:
                policy_error("interrupt resource is multiply owned")

    if profile != 0 and spm_count != 1:
        policy_error("exactly one SPM is required")

    service_names = set()
    service_ids = set()
    stateless_handles = set()
    service_owner = {}
    partition_names = set()
    partition_domains = set()
    for partition_index, partition in enumerate(partitions):
        name = partition["name"]
        if not policy_name_valid(name):
            policy_error("partition name is not a generated identifier")
        if name in partition_names or partition["domain_id"] in partition_domains:
            policy_error("partition identity is duplicated")
        partition_names.add(name)
        partition_domains.add(partition["domain_id"])
        domain = next((item for item in domains
                       if item["id"] == partition["domain_id"]), None)
        if (domain is None or partition["domain_id"] == 0 or
                partition["domain_id"] > 0x7FFFFFFF or
                domain["domain_class"] != 1):
            policy_error("partition is not bound to a Secure Partition domain")
        framework = partition["framework_version"]
        model = partition["model"]
        if framework not in (0x100, 0x101):
            policy_error("unsupported framework version")
        if framework > supported_framework:
            policy_error("framework version exceeds the build contract")
        if model not in (0, 1) or (framework == 0x100 and model != 0):
            policy_error("partition model is invalid")
        if (model == 0 and not features & 1) or (model == 1 and not features & 2):
            policy_error("partition model feature is unavailable")
        if partition["priority"] not in (0, 1, 2):
            policy_error("partition priority is invalid")
        if not partition["services"] and not partition["interrupts"]:
            policy_error("partition has no service or interrupt")
        if len(partition["services"]) > limits["max_services_per_partition"]:
            policy_error("service count exceeds limits")
        if len(partition["dependencies"]) > limits["max_dependencies_per_partition"]:
            policy_error("dependency count exceeds limits")
        if len(partition["interrupts"]) != len(domain["interrupt_resources"]):
            policy_error("partition interrupt count does not match domain")
        signal_count = len(partition["interrupts"])
        if model == 0:
            signal_count += len(partition["services"])
        if signal_count > MAX_SIGNALS:
            policy_error("partition signal count exceeds limits")
        used_signals = set()
        for service in partition["services"]:
            service_name = service["name"]
            if not policy_name_valid(service_name):
                policy_error("service name is not a generated identifier")
            if service_name in service_names or service["sid"] in service_ids:
                policy_error("service identity is duplicated")
            if service["sid"] == 0 or service["version"] == 0:
                policy_error("service identity or version is invalid")
            # FF-M defines exactly STRICT (0) and RELAXED (1); the IR's
            # UNSPECIFIED (2) accept-any policy is not generatable.
            if service["version_policy"] not in (0, 1):
                policy_error("service version policy is invalid")
            if framework == 0x100 and not service["connection_based"]:
                policy_error("FF-M 1.0 service must be connection based")
            if service["connection_based"]:
                if service["stateless_handle_index"] != 0:
                    policy_error("connection service has a stateless handle")
            else:
                if not features & 4 or not (1 <= service["stateless_handle_index"] <= limits["max_stateless_handles"]):
                    policy_error("stateless service handle is invalid")
                handle = service["stateless_handle_index"]
                if handle in stateless_handles:
                    policy_error("stateless service handle is duplicated")
                stateless_handles.add(handle)
            if model == 0:
                if not policy_signal_valid(service["signal"]):
                    policy_error("IPC service signal is invalid")
            elif service["signal"] != 0:
                policy_error("SFN service signal must be zero")
            if service["signal"] and service["signal"] in used_signals:
                policy_error("partition signal is duplicated")
            if service["signal"]:
                used_signals.add(service["signal"])
            service_names.add(service_name)
            service_ids.add(service["sid"])
            service_owner[service["sid"]] = partition_index
        for interrupt_index, interrupt in enumerate(partition["interrupts"]):
            if not policy_name_valid(interrupt["signal_name"]) or not policy_signal_valid(interrupt["signal"]):
                policy_error("partition interrupt signal is invalid")
            if interrupt["signal"] in used_signals:
                policy_error("partition signal is duplicated")
            if not any(interrupt["interrupt"] == item["interrupt"]
                       for item in domain["interrupt_resources"]):
                policy_error("partition interrupt is not owned by its domain")
            if any(interrupt["interrupt"] == item["interrupt"] or
                   interrupt["signal_name"] == item["signal_name"]
                   for item in partition["interrupts"][:interrupt_index]):
                policy_error("partition interrupt is duplicated")
            used_signals.add(interrupt["signal"])

    if not service_ids:
        policy_error("no services are defined")
    if any(domain["domain_class"] == 1 and
           domain["id"] not in partition_domains for domain in domains):
        policy_error("Secure Partition domain has no manifest partition")
    for partition_index, partition in enumerate(partitions):
        dependencies = partition["dependencies"]
        if len(dependencies) != len(set(dependencies)) or any(value == 0 for value in dependencies):
            policy_error("partition dependencies are duplicated or invalid")
        for dependency in dependencies:
            if dependency not in service_ids:
                policy_error("partition dependency is unresolved")
            if service_owner[dependency] == partition_index:
                policy_error("partition depends on its own service")

    edges = {index: set() for index in range(len(partitions))}
    for index, partition in enumerate(partitions):
        for dependency in partition["dependencies"]:
            edges[index].add(service_owner[dependency])
    removed = set()
    while True:
        ready = {index for index, targets in edges.items()
                 if index not in removed and not (targets - removed)}
        if not ready:
            break
        removed.update(ready)
    if len(removed) != len(partitions):
        policy_error("partition dependency cycle")
    policy_generated_symbols(manifest)


def c_uint(value):
    return "{}U".format(value)


def c_word(value):
    return "{}ULL".format(value)


def c_bool(value):
    return c_uint(int(value))


def c_string(value):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"{}"'.format(escaped)


def c_struct(fields):
    lines = ["{"]
    for name, value in fields:
        value_lines = value.splitlines()
        lines.append("    .{} = {}".format(name, value_lines[0]))
        lines.extend("    " + line for line in value_lines[1:])
        lines[-1] += ","
    lines.append("}")
    return "\n".join(lines)


def emit_array(lines, declaration, values):
    if not values:
        return "NULL"
    lines.append("static const {} = {{".format(declaration))
    for value in values:
        value_lines = value.splitlines()
        lines.extend("    " + line for line in value_lines)
        lines[-1] += ","
    lines.extend(("};", ""))
    return declaration.split("[")[0].split()[-1]


def c_scalar(value, schema):
    if schema == BOOL:
        return c_bool(value)
    if schema == STRING:
        return c_string(value)
    if schema == WORD:
        return c_word(value)
    return c_uint(value)


def scalar_struct(value, schema):
    return c_struct(tuple(
        (name, c_scalar(item, schema[name]))
        for name, item in value.items()))


def emit_domain(lines, domain, index):
    memory = emit_array(lines,
        "wt_memory_resource_t wt_generated_memory_{}[{}]".format(
            index, len(domain["memory_resources"])),
        [scalar_struct(item, MEMORY_SCHEMA)
         for item in domain["memory_resources"]])
    interrupts = emit_array(lines,
        "wt_interrupt_resource_t wt_generated_irqs_{}[{}]".format(
            index, len(domain["interrupt_resources"])),
        [scalar_struct(item, INTERRUPT_RESOURCE_SCHEMA)
         for item in domain["interrupt_resources"]])
    fields = []
    for name, value in domain.items():
        if name == "memory_resources":
            fields.extend(((name, memory),
                           ("memory_resource_count",
                            c_uint(len(domain[name])))))
        elif name == "interrupt_resources":
            fields.extend(((name, interrupts),
                           ("interrupt_resource_count",
                            c_uint(len(domain[name])))))
        elif name == "restart_policy":
            fields.append((name, scalar_struct(value, RESTART_SCHEMA)))
        else:
            fields.append((name, c_scalar(value, DOMAIN_SCHEMA[name])))
    return c_struct(fields)


def emit_partition(lines, partition, index):
    service_values = [scalar_struct(service, SERVICE_SCHEMA)
                      for service in partition["services"]]
    services = emit_array(lines,
        "wt_service_descriptor_t wt_generated_services_{}[{}]".format(
            index, len(service_values)), service_values)
    dependencies = emit_array(lines,
        "uint32_t wt_generated_dependencies_{}[{}]".format(
            index, len(partition["dependencies"])),
        [c_uint(value) for value in partition["dependencies"]])
    interrupt_values = [scalar_struct(interrupt, MANIFEST_INTERRUPT_SCHEMA)
                        for interrupt in partition["interrupts"]]
    interrupts = emit_array(lines,
        "wt_manifest_interrupt_t wt_generated_partition_irqs_{}[{}]".format(
            index, len(interrupt_values)), interrupt_values)
    fields = []
    for name, value in partition.items():
        if name == "name":
            fields.append((name, c_string(value)))
        elif name == "services":
            fields.extend(((name, services),
                           ("service_count", c_uint(len(value)))))
        elif name == "dependencies":
            fields.extend(((name, dependencies),
                           ("dependency_count", c_uint(len(value)))))
        elif name == "interrupts":
            fields.extend(((name, interrupts),
                           ("interrupt_count", c_uint(len(value)))))
        else:
            fields.append((name, c_scalar(value, PARTITION_SCHEMA[name])))
    return c_struct(fields)


def validate_ffa(ffa, manifest):
    domain_ids = {domain["id"] for domain in manifest["domains"]}
    partition_domains = {partition["domain_id"]
                         for partition in manifest["partitions"]}
    seen = set()
    for index, entry in enumerate(ffa["partitions"]):
        path = "manifest.ffa.partitions[{}]".format(index)
        if entry["domain_id"] not in domain_ids:
            policy_error(path + " names an unknown domain")
        if entry["domain_id"] not in partition_domains:
            policy_error(path + " names a domain without a partition")
        if entry["domain_id"] in seen:
            policy_error(path + " repeats a domain")
        seen.add(entry["domain_id"])
        if not entry["uuids"] or len(entry["uuids"]) > FFA_MAX_UUIDS:
            policy_error(path + " needs 1 to {} UUIDs".format(FFA_MAX_UUIDS))
        for uuid in entry["uuids"]:
            if not UUID_RE.match(uuid):
                policy_error(path + " UUID is not canonical lowercase")
        if entry["ffa_version"] not in FFA_VERSIONS:
            policy_error(path + " ffa_version must be 1.2")
        if entry["execution_contexts"] != 1:
            policy_error(path + " supports one execution context only")
        if entry["runtime_el"] not in FFA_RUNTIME_EL:
            policy_error(path + " runtime_el must be S-EL0")
        if entry["messaging"] not in FFA_MESSAGING:
            policy_error(path + " messaging must be none")
        if entry["ns_interrupt_action"] not in FFA_NS_INTERRUPT_ACTION:
            policy_error(path + " ns_interrupt_action must be signaled")
        if entry["boot_info_register"] not in FFA_BOOT_INFO_REGISTER:
            policy_error(path + " boot_info_register must be none")


def uuid_bytes(uuid):
    return bytes.fromhex(uuid.replace("-", ""))


def emit_ffa(lines, ffa):
    entries = []
    for index, entry in enumerate(ffa["partitions"]):
        uuids = emit_array(lines,
            "wt_ffa_uuid_t wt_generated_ffa_uuids_{}[{}]".format(
                index, len(entry["uuids"])),
            ["{ { " + ", ".join("0x{:02x}U".format(byte)
                                 for byte in uuid_bytes(uuid)) + " } }"
             for uuid in entry["uuids"]])
        entries.append(c_struct((
            ("uuids", uuids),
            ("domain_id", c_uint(entry["domain_id"])),
            ("uuid_count", c_uint(len(entry["uuids"]))),
            ("execution_contexts", c_uint(entry["execution_contexts"])),
            ("runtime_el", c_uint(FFA_RUNTIME_EL[entry["runtime_el"]])),
            ("messaging", c_uint(FFA_MESSAGING[entry["messaging"]])),
            ("ns_interrupt_action",
             c_uint(FFA_NS_INTERRUPT_ACTION[entry["ns_interrupt_action"]])),
            ("boot_info_register",
             c_uint(FFA_BOOT_INFO_REGISTER[entry["boot_info_register"]])),
            ("ffa_version", c_uint(FFA_VERSIONS[entry["ffa_version"]])),
        )))
    count = len(entries)
    if count == 0:
        # The SPMC always calls the accessor: hand it a real, empty table.
        entries.append(c_struct(
            (("uuids", "NULL"),) +
            tuple((name, c_uint(0)) for name in (
                "domain_id", "uuid_count", "execution_contexts", "runtime_el",
                "messaging", "ns_interrupt_action", "boot_info_register",
                "ffa_version"))))
    table = emit_array(lines,
        "wt_ffa_partition_manifest_t wt_generated_ffa_partitions[{}]".format(
            len(entries)), entries)
    lines.extend((
        "const wt_ffa_partition_manifest_t* wt_generated_ffa_partitions_get("
        "size_t* count)",
        "{", "    *count = {}U;".format(count),
        "    return {};".format(table), "}", ""))


def generate_source(manifest, digest, ffa=None, pool_pages=None):
    lines = [FILE_HEADER.format(name="wolftrust_manifest_generated.c"),
             "/* Normalized manifest SHA-256: {} */".format(digest.hex()),
             "#include \"wolftrust_manifest_generated.h\"", ""]
    if ffa is not None:
        lines[-2:] = ["#include \"wolftrust_manifest_generated.h\"",
                      "#include \"wolftrust/arch/aarch64/ffa_manifest.h\"", ""]
    if pool_pages is not None:
        lines.extend(TABLE_POOL_CHECK)
    digest_values = ["0x{:02x}U".format(value) for value in digest]
    emit_array(lines, "uint8_t wt_generated_digest[32]", digest_values)
    domain_values = [emit_domain(lines, domain, index)
                     for index, domain in enumerate(manifest["domains"])]
    domains = emit_array(lines,
        "wt_domain_descriptor_t wt_generated_domains[{}]".format(
            len(domain_values)), domain_values)
    partition_values = [emit_partition(lines, partition, index)
                        for index, partition in enumerate(manifest["partitions"])]
    partitions = emit_array(lines,
        "wt_partition_manifest_t wt_generated_partitions[{}]".format(
            len(partition_values)), partition_values)
    capabilities = scalar_struct(manifest["profile_capabilities"],
                                 CAPABILITIES_SCHEMA)
    limits = scalar_struct(manifest["limits"], LIMITS_SCHEMA)
    system = c_struct((
        ("format_version", c_uint(manifest["format_version"])),
        ("generator_version", c_string(manifest["generator_version"])),
        ("input_digest", "wt_generated_digest"),
        ("input_digest_size", "sizeof(wt_generated_digest)"),
        ("features", c_uint(manifest["features"])),
        ("isolation_profile", c_uint(manifest["isolation_profile"])),
        ("profile_capabilities", "&wt_generated_capabilities"),
        ("domains", domains),
        ("domain_count", c_uint(len(domain_values))),
        ("partitions", partitions),
        ("partition_count", c_uint(len(partition_values))),
        ("limits", limits),
    ))
    lines.extend((
        "static const wt_profile_capabilities_t wt_generated_capabilities =",
        capabilities + ";", "",
        "static const wt_system_manifest_t wt_generated_manifest =",
        system + ";", "",
        "const wt_system_manifest_t* wt_generated_manifest_get(void)",
        "{", "    return &wt_generated_manifest;", "}", ""))
    if ffa is not None:
        emit_ffa(lines, ffa)
    return "\n".join(lines)


def count_blocks(regions, shift):
    intervals = sorted((base >> shift, (base + size - 1) >> shift)
                       for base, size in regions if size > 0)
    total = 0
    end = -1
    for first, last in intervals:
        if first > end:
            total += last - first + 1
        elif last > end:
            total += last - end
        end = max(end, last)
    return total


def table_pool_pages(manifest, spm_table_pages):
    """Pages for one 4 KB-granule stage-1 table per partition (L1 + one L2 per
    GB + one L3 per 2 MB of its regions), the SPMC's own table, and a spare set."""
    domains = {domain["id"]: domain for domain in manifest["domains"]}
    pages = spm_table_pages + TABLE_SPARE_PAGES
    for partition in manifest["partitions"]:
        domain = domains[partition["domain_id"]]
        regions = [(memory["base"], memory["size"])
                   for memory in domain["memory_resources"]]
        regions.append((domain["stack_base"], domain["stack_size"]))
        pages += (1 + count_blocks(regions, TABLE_L2_SHIFT)
                  + count_blocks(regions, TABLE_L3_SHIFT))
    return pages


def generate_header(manifest, pool_pages=None):
    lines = [FILE_HEADER.format(name="wolftrust_manifest_generated.h"),
             "#ifndef WOLFTRUST_MANIFEST_GENERATED_H",
             "#define WOLFTRUST_MANIFEST_GENERATED_H", "",
             "#include \"wolftrust/manifest.h\"", ""]
    symbols = set()

    def add_symbol(name):
        if name in symbols:
            policy_error("generated symbol is duplicated: " + name)
        symbols.add(name)

    for partition in manifest["partitions"]:
        prefix = "WT_GENERATED_" + partition["name"]
        add_symbol(prefix + "_DOMAIN_ID")
        add_symbol(prefix + "_FRAMEWORK_VERSION")
        add_symbol(prefix + "_MODEL")
        lines.extend((
            "#define {}_DOMAIN_ID {}U".format(prefix, partition["domain_id"]),
            "#define {}_FRAMEWORK_VERSION {}U".format(
                prefix, partition["framework_version"]),
            "#define {}_MODEL {}U".format(prefix, partition["model"]),
        ))
        for service in partition["services"]:
            service_prefix = "WT_GENERATED_" + service["name"]
            add_symbol(service_prefix + "_SID")
            add_symbol(service_prefix + "_VERSION")
            lines.extend((
                "#define {}_SID {}U".format(service_prefix, service["sid"]),
                "#define {}_VERSION {}U".format(
                    service_prefix, service["version"]),
            ))
            if partition["model"] == 0:
                add_symbol(service_prefix + "_SIGNAL")
                lines.append("#define {}_SIGNAL {}U".format(
                    service_prefix, service["signal"]))
            if not service["connection_based"]:
                add_symbol(service_prefix + "_HANDLE")
                lines.append("#define {}_HANDLE {}U".format(
                    service_prefix, service["stateless_handle_index"]))
        for interrupt in partition["interrupts"]:
            interrupt_prefix = "WT_GENERATED_" + interrupt["signal_name"]
            add_symbol(interrupt_prefix + "_SIGNAL")
            lines.append("#define {}_SIGNAL {}U".format(
                interrupt_prefix, interrupt["signal"]))
        lines.append("")
    if pool_pages is not None:
        add_symbol("WT_GENERATED_TABLE_POOL_PAGES")
        lines.extend(("#define WT_GENERATED_TABLE_POOL_PAGES {}U".format(
            pool_pages), ""))
    lines.extend((
        "const wt_system_manifest_t* wt_generated_manifest_get(void);", "",
        "#endif", ""))
    return "\n".join(lines)


def generated_guard(name):
    return "PSA_MANIFEST_{}_H".format(
        re.sub(r"[^A-Z0-9]", "_", name.upper()))


def generate_pid_header(manifest):
    lines = [FILE_HEADER.format(name="pid.h"),
             "#ifndef PSA_MANIFEST_PID_H",
             "#define PSA_MANIFEST_PID_H", ""]
    for partition in manifest["partitions"]:
        lines.append("#define {}_ID {}".format(
            partition["name"], partition["domain_id"]))
    lines.append("")
    for partition in manifest["partitions"]:
        lines.append("#define {} {}_ID".format(
            partition["name"], partition["name"]))
    lines.extend(("", "#endif", ""))
    return "\n".join(lines)


def generate_sid_header(manifest):
    lines = [FILE_HEADER.format(name="sid.h"),
             "#ifndef PSA_MANIFEST_SID_H",
             "#define PSA_MANIFEST_SID_H", ""]
    for partition in manifest["partitions"]:
        for service in partition["services"]:
            lines.extend((
                "#define {}_SID {}U".format(service["name"],
                                             service["sid"]),
                "#define {}_VERSION {}U".format(service["name"],
                                                 service["version"]),
            ))
    lines.extend(("", "#endif", ""))
    return "\n".join(lines)


def generate_partition_header(partition):
    file_name = partition["name"].lower() + ".h"
    guard = generated_guard(partition["name"])
    lines = [FILE_HEADER.format(name=file_name),
             "#ifndef {}".format(guard),
             "#define {}".format(guard), ""]
    for service in partition["services"]:
        if partition["model"] == 0:
            lines.append("#define {}_SIGNAL {}U".format(
                service["name"], service["signal"]))
    for interrupt in partition["interrupts"]:
        lines.append("#define {}_SIGNAL {}U".format(
            interrupt["signal_name"], interrupt["signal"]))
    lines.extend(("", "#endif", ""))
    return file_name, "\n".join(lines)


# Marks an absent "ffa" key, so a present null value still meets FFA_SCHEMA.
NO_FFA = object()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--supported-features", required=True,
                        type=lambda value: int(value, 0))
    parser.add_argument("--supported-framework-version", default="0x101",
                        type=lambda value: int(value, 0))
    parser.add_argument("--mpu-granule", default="32",
                        type=lambda value: int(value, 0))
    parser.add_argument("--address-bits", choices=("32", "64"), default="32")
    parser.add_argument("--spm-table-pages", default="0",
                        type=lambda value: int(value, 0))
    args = parser.parse_args()
    pool_pages = None

    try:
        input_bytes = args.input.read_bytes()
        manifest = json.loads(input_bytes.decode("utf-8"),
                              object_pairs_hook=reject_duplicate_keys)
        word_max = (1 << int(args.address_bits)) - 1
        ffa = manifest.pop("ffa", NO_FFA) if isinstance(manifest, dict) else NO_FFA
        validate(manifest, MANIFEST_SCHEMA, "manifest", word_max)
        validate_policy(manifest, args.supported_features, word_max,
                        args.supported_framework_version, args.mpu_granule)
        if ffa is not NO_FFA:
            if args.address_bits != "64":
                raise ManifestError("manifest.ffa needs --address-bits 64")
            validate(ffa, FFA_SCHEMA, "manifest.ffa", word_max)
            validate_ffa(ffa, manifest)
        if args.address_bits == "64":
            pool_pages = table_pool_pages(manifest, args.spm_table_pages)
            if ffa is NO_FFA:
                ffa = {"partitions": []}
        if ffa is NO_FFA:
            ffa = None
        source = generate_source(manifest, hashlib.sha256(input_bytes).digest(),
                                 ffa, pool_pages)
        args.output.mkdir(parents=True, exist_ok=True)
        psa_manifest = args.output / "psa_manifest"
        psa_manifest.mkdir(parents=True, exist_ok=True)
        (args.output / "wolftrust_manifest_generated.c").write_text(
            source, encoding="utf-8")
        (args.output / "wolftrust_manifest_generated.h").write_text(
            generate_header(manifest, pool_pages), encoding="utf-8")
        (psa_manifest / "pid.h").write_text(
            generate_pid_header(manifest), encoding="utf-8")
        (psa_manifest / "sid.h").write_text(
            generate_sid_header(manifest), encoding="utf-8")
        for file_name, content in (generate_partition_header(partition)
                                   for partition in manifest["partitions"]):
            (psa_manifest / file_name).write_text(content, encoding="utf-8")
    except (ManifestError, UnicodeDecodeError, json.JSONDecodeError,
            OSError) as error:
        print("manifest generation failed: {}".format(error), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
