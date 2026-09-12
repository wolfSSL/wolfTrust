#!/usr/bin/env bash
# Single source of truth for "can the AArch64 QEMU scenarios run here?", the
# twin of detect_m33mu.sh. Exit 0 when qemu-system-aarch64 and the
# aarch64-none-elf toolchain are reachable (or the user forced a target run),
# non-zero with a one-line reason on stdout otherwise.
set -u

if [ "${WT_TARGET_SCENARIOS:-0}" = "1" ]; then
    exit 0
fi
if command -v "${QEMU:-qemu-system-aarch64}" >/dev/null 2>&1 && \
   command -v "${TOOLPREFIX:-aarch64-none-elf-}gcc" >/dev/null 2>&1; then
    exit 0
fi

echo "qemu-system-aarch64 + aarch64-none-elf-gcc not detected — run inside ghcr.io/wolfssl/wolfboot-ci-aarch64 or set WT_TARGET_SCENARIOS=1"
exit 1
