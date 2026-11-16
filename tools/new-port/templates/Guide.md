# <SOC> Guide

Write each section from what this board showed, then delete its stub line.
Record emulator, cross-build, and board evidence separately.

## Status

NEW_PORT_STUB <soc>: what is validated on the board, in emulation, or only cross-built, and what is not ported yet.

## What the port comprises

NEW_PORT_STUB <soc>: the first-stage loader additions (HAL, configuration, carried patches) and one line per file under `port/<soc>/`.

## Reference flash and RAM layout

NEW_PORT_STUB <soc>: the first stage, Secure image, guests, update and swap, stores and boot handoff, with their Secure and Non-secure addresses.

## TrustZone and fabric perimeter

NEW_PORT_STUB <soc>: the SAU and Secure MPU tables, the fabric filter, the SPM-only peripheral, and what the board's `guestisoneg` run proved.

## Silicon constraints

NEW_PORT_STUB <soc>: errata, cache maintenance, IDAU overrides, and the flash program and erase rules the drivers follow.

## Required tools

NEW_PORT_STUB <soc>: the probe and its software, the console device, and the first-stage build inputs.

## Read-only preflight

NEW_PORT_STUB <soc>: the commands that read the board's state before anything is written, and the state the runner requires.

## Emulator

NEW_PORT_STUB <soc>: the pinned M33MU and wolfBoot, each carried patch and what it models, and where the model differs from the board.

## Build, flash, and verify

NEW_PORT_STUB <soc>: what `make test-hardware TARGET=<soc>` flashes where, its qualification extras, and the guest mailbox addresses and console.

## Guest flash write protection

NEW_PORT_STUB <soc>: how the guest flash fence is armed and read back, or that the port has none and `wrpoff` proves the refusal.

## Provisioning and life cycle

NEW_PORT_STUB <soc>: the states with their PSA life cycles, the port variables, the mock lock, and the one permanent write.

## Recovery rules

NEW_PORT_STUB <soc>: how a board comes back, and which states have no way back.

## Open items

NEW_PORT_STUB <soc>: what is not done yet, each with what closes it.
