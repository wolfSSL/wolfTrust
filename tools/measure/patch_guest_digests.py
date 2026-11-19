#!/usr/bin/env python3
# patch_guest_digests.py
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

"""Stamp pinned guest measurements into wolftrust.bin before signing.

Usage:
  patch_guest_digests.py <wolftrust.bin> <guest_id>:<version>:<guest.bin> ...

Locates the guest-measurement slot by magic (see port/common/armv8m/partitions.c
wt_guest_meas_slot_t), writes one record per argument (guest_id, version,
image_size, SHA-256), and rewrites the image in place. Must run BEFORE the
wolfBoot signing step so the pins are covered by the image signature.
"""

import hashlib
import struct
import sys

MAGIC = bytes([0x57, 0x54, 0x47, 0x4D, 0x45, 0x41, 0x53, 0x31,
               0xA5, 0x3C, 0x96, 0xE1, 0x78, 0x0F, 0xB2, 0x4B])
MAX_RECORDS = 4
RECORD_SIZE = 4 + 4 + 4 + 32


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    image_path = sys.argv[1]
    with open(image_path, "rb") as f:
        image = bytearray(f.read())

    offset = image.find(MAGIC)
    if offset < 0:
        print("measurement slot magic not found in {}".format(image_path),
              file=sys.stderr)
        return 1
    if image.find(MAGIC, offset + 1) >= 0:
        print("measurement slot magic is not unique in {}".format(image_path),
              file=sys.stderr)
        return 1

    records = []
    for arg in sys.argv[2:]:
        guest_id, version, guest_path = arg.split(":", 2)
        with open(guest_path, "rb") as f:
            guest = f.read()
        if len(guest) == 0:
            print("empty guest image {}".format(guest_path), file=sys.stderr)
            return 1
        digest = hashlib.sha256(guest).digest()
        records.append(struct.pack("<III32s", int(guest_id, 0),
                                   int(version, 0), len(guest), digest))
        print("guest {} v{} size {} sha256 {}".format(
            guest_id, version, len(guest), digest.hex()))

    if len(records) > MAX_RECORDS:
        print("too many guest records ({} > {})".format(
            len(records), MAX_RECORDS), file=sys.stderr)
        return 1

    slot = struct.pack("<I", len(records)) + b"".join(records)
    slot += b"\x00" * ((MAX_RECORDS - len(records)) * RECORD_SIZE)

    start = offset + len(MAGIC)
    end = start + len(slot)
    if end > len(image):
        print("slot extends past image end", file=sys.stderr)
        return 1
    image[start:end] = slot

    with open(image_path, "wb") as f:
        f.write(image)
    print("patched {} records into {} at 0x{:x}".format(
        len(records), image_path, offset))
    return 0


if __name__ == "__main__":
    sys.exit(main())
