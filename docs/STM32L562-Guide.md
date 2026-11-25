# STM32L562 Guide

This guide covers the ST STM32L562E-DK (STM32L562QE: a Cortex-M33 with
TrustZone-M, 512 KiB of dual-bank internal flash and 256 KiB of SRAM). Like
the STM32H563, it executes from internal flash behind wolfBoot and isolates
its guests with the GTZC. Unlike the other ports it builds the native crypto
engine only, because 256 KiB of SRAM cannot hold the wolfHSM engine's
level 3 bands beside two guests. RDP level 2 is permanent and closes the
debug port for good. This port rehearses the RDP ladder and never raises
RDP. The only RDP write is a typed regression back to level 0.

## Status

- **Cross-build:** `make TARGET=stm32l562 secure-image` links both manifests
  on the native engine, and the layout check passes for each. Production is
  96,804 bytes of flash (96,096 text, 708 data). Conformance is 150,456 bytes.
  `WT_ENGINE=hsm` stops at `port/stm32l562/memory_map.h` with an `#error`.
- **Host:** `make test` runs the shared `port_flash` suite over
  `tests/host/port_flash/models/stm32l562.c`, plus the port's own suites:
  - `stm32l562_flash`: program, page erase, ECC, bounded waits and the tamper
    check, run over the same model;
  - `stm32l562_rng`: the RNG driver over an RCC and RNG model;
  - `stm32l562_gtzc`: the boot attribution and its read-back;
  - `stm32l562_wrp`: the guest fence coverage check over both banks;
  - `stm32l562_lifecycle`: the RDP to PSA life cycle map. It tests a copy of
    wolfBoot's `hal/stm32l5_lifecycle.h`, and the emulator profile checks the
    copy matches the pinned wolfBoot before every boot.
- **Emulator:** on this layout, under m33mu 268fbef3 with the carried patch, the
  smoke tier passes 6 of 6. Across two `all`-tier runs every one of the 46
  scenarios has passed. The patch's FLASH TrustZone model also has its own unit
  test, which the profile runs before each boot.
- **Board:** none for this layout. An earlier layout ran on a DK, with the
  guests at the top of bank 2: the hardware minimum, a fence erase check and
  the level 0 provisioning flow. The current layout needs the new watermarks
  first (see [Provisioning and life cycle](#provisioning-and-life-cycle)), so
  that run is not evidence for this one.

M33MU's STM32L552 model gives emulator evidence and the DK gives silicon
evidence. Neither substitutes for the other.

## What the port comprises

The first stage is upstream wolfBoot pinned at `8c1f19e7`, built from
`config/examples/stm32l5-tz-wolftrust.config`. That config gives TrustZone
with the Secure-application handoff (`WOLFBOOT_SECURE_APP`), 2 KiB sectors, a
1024-byte image header and no debug UART. wolfBoot verifies and measures the
Secure image, writes the handoff record to `0x30000000` and jumps to it
without leaving the Secure state. `hal/stm32l5_lifecycle.h` maps `FLASH_OPTR`
to the PSA life cycle in that record. The emulator and hardware profiles
rebuild it per layout with the partition addresses below.

| File under `port/stm32l562/` | Responsibility |
| --- | --- |
| `port.json` | Registry entry: native engine only, emulator scenarios, hardware tiers and capabilities |
| `memory_map.h` | Both flash layouts, Secure and guest RAM, the stores, the update partition, the level 3 band sizes and the native-only guard |
| `stm32l562_regs.h` | RCC, GPIOA, USART1, RNG, GTZC, DMA, flash controller and instruction cache registers |
| `platform_stm32l562.c` | The `platform_port.h` hooks: SAU and Secure MPU tables, the GTZC curtain and the USART1 console |
| `gtzc.c`, `gtzc.h` | Boot GTZC attribution with a full read-back, and the per-dispatch MPCBB range writes |
| `guest_wrp.c` | Guest flash WRP coverage over both banks' areas and `SWAP_BANK` |
| `flash_drv.c` | The `flash_port.h` contract: Secure flash registers, double-word program, page erase, ECC containment |
| `rng_drv.c` | The `rng_port.h` contract: the RNG on HSI48 under the shared entropy callback |
| `secure_owners.txt` | The port's objects in the post-link owner map |

The partitions, manifests, linker script, NVM backend and entropy callback
are the shared ones under `port/common/`.

`mk/target-stm32l562.mk` holds the CPU, both flash layouts, the console and
conformance interrupt, and the source list. It also maps the emulator
runner's development life cycle to the `0x2000` an L5 reports under TZEN.

## Reference flash and RAM layout

Flash is `0x08000000` (Non-secure) and `0x0C000000` (Secure). SRAM is
`0x20000000` and `0x30000000`. The part runs in dual-bank mode (`DBANK=1`):
two 256 KiB banks of 128 pages of 2 KiB, programmed one 64-bit double-word
at a time. `WT_CONFORMANCE`, `CONFIG_TPM=y` or `CONFIG_PKCS11=y` picks the
conformance layout, whose larger Secure slot holds those images.

| Region | Production | Conformance |
| --- | ---: | ---: |
| wolfBoot (48 KiB) | `0x0C000000` | `0x0C000000` |
| wolfTrust Secure slot | `0x0C00C000` (128 KiB) | `0x0C00C000` (160 KiB) |
| Guest 0 | `0x0802C000` (80 KiB, bank 1) | `0x08034000` (240 KiB, both banks) |
| Guest 1 | `0x08040000` (64 KiB, bank 2) | `0x08070000` (16 KiB) |
| wolfBoot update partition | `0x0C050000` (128 KiB) | none: FWU is not in the conformance manifest, and TPM 2.0 or PKCS#11 builds refuse `WT_FWU=1` |
| wolfBoot swap | `0x0C070000` | `0x0C074000` |
| wolfHSM store | `0x0C07A000` (16 KiB) | `0x0C07A000` |
| Conformance NVM | `0x0C07E000` (8 KiB) | `0x0C07E000` |

The conformance wolfBoot is built with `WOLFBOOT_PARTITION_SIZE=0x28000` and
`WOLFBOOT_PARTITION_UPDATE_ADDRESS=0x0C04C000`, so the partition ends at the
swap. It falls in the guest windows, with its trailer page at the top of
guest 1's window, which a small guest leaves erased. Nothing stages an
update there.

| RAM region | Production | Conformance |
| --- | ---: | ---: |
| Boot handoff record | `0x30000000` | `0x30000000` |
| Secure runtime RAM (`0x27000`) | `0x30001000` | `0x30001000` |
| Guest 0 RAM | `0x20028000` (48 KiB) | `0x20028000` (80 KiB) |
| Guest 1 RAM | `0x20034000` (48 KiB) | `0x2003C000` (16 KiB) |

The SPM band is 46 KiB (`WT_L3_SPM_RAM_SIZE=0xB800`). Arm's crypto
conformance guest overruns its stack in 48 KiB, so the conformance layout
gives guest 0 80 KiB.

## TrustZone and fabric perimeter

The option bytes are set once on a part at RDP level 0 by `set-perimeter`:

| Option byte | Production value | Why |
| --- | --- | --- |
| `TZEN` | `1` | TrustZone on |
| `DBANK`, `SWAP_BANK` | `1`, `0` | The bank map the layout and flash driver assume |
| `SECWM1_PSTRT`/`PEND` | `0x0`/`0x57` | Bank 1 pages 0 to 87 Secure: wolfBoot and the Secure slot. Guest 0 above is Non-secure |
| `SECWM2_PSTRT`/`PEND` | `0x20`/`0x7F` | Bank 2 pages 32 to 127 Secure: update, swap and stores. Guest 1 below is Non-secure |
| `SECBOOTADD0` | `0x180000` | Boot at `0x0C000000` |
| `BOOT_LOCK` | `1` | Permanent, so `boot-lock` sets it last behind the production gates |

The emulator runs the conformance layout with `--secwm1=0:103 --secwm2=104:127`.

`platform_stm32l562.c` programs the rest on every boot:

- **SAU:** Non-secure windows over the guest flash, the guest RAM extent and
  the peripherals except the RNG page, plus the veneer window. Leaving out
  the RNG page turns a guest's access to the SPM's RNG into a precise
  SecureFault instead of a read-as-zero.
- **GTZC:** boot marks all SRAM Secure except the guest extent. It keeps AES,
  HASH, RNG, PKA, SDMMC1 and the DMA channels Secure, makes USART1 Non-secure
  and reads all of it back. On every dispatch the MPCBB curtain marks the
  whole guest extent Secure, then reopens only the arriving guest's windows.
- **Secure MPU:** eight regions with the default map off.

Guests run privileged, so the curtain is the boundary between them. No
board run of `guestisoneg` exists for this layout yet.

## Silicon constraints

- **Double-word program unit.** The flash keeps ECC per double-word and
  refuses to reprogram one that is not erased. The driver programs one
  aligned double-word per `PG` operation.
- **Secure registers.** Unlock is `SECKEYR`, operations are `SECCR` and
  status is `SECSR`, whose flags are write-1-to-clear. A page number is
  relative to its bank (`PNB` plus `BKER`), and the driver follows
  `SWAP_BANK` for erase and for the ECC bank check.
- **A wolfHSM sector is four pages.** An 8 KiB sector erases as four 2 KiB
  page erases.
- **ECC double error is an NMI.** A checked read arms the window it is about
  to read. The NMI handler claims a double error inside it, and anything
  else halts. An aborted read returns no flash bytes.
- **RNG on HSI48.** The driver uses AN4230's 48 MHz NIST setting
  (`RNG_CR` `0x00F00D00`, `RNG_HTCR` `0xA2B3`) and discards the first word.
  A seed or clock error fails the request, and the shared entropy layer
  retries init on the next one.
- **wolfBoot prints nothing on the DK's console.** Its L5 debug UART is
  LPUART1, not the ST-LINK virtual COM port, and the config builds it off.

## Required tools

- `arm-none-eabi-gcc` and binutils, Python 3, CMake for the emulator build.
- For a board: the STM32L562E-DK's on-board ST-LINK, with either
  STM32CubeProgrammer (`STM32_CLI`) or OpenOCD 0.12 (`STM32L562_OPENOCD`).
  `STM32L562_PROBE_TOOL=cubeprog|openocd` forces one. With OpenOCD, pyOCD or
  the ST-LINK's `DIS_L562QE` mass-storage label identifies the DK.

## Read-only preflight

```sh
TARGET=stm32l562 tests/target/provisioning/provisioning_ctrl.sh status
TARGET=stm32l562 tests/target/provisioning/provisioning_ctrl.sh verify-wrp
```

The hardware runner's `hw_preflight` wants TZEN set, RDP `0xAA`,
`DBANK=1 SWAP_BANK=0`, the production watermarks and all four WRP areas
disabled. Each refusal names the provisioning command that fixes it.

## Emulator

`make test-target TARGET=stm32l562` runs inside
`ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25`. The profile
`tests/target/ports/stm32l562/m33mu.sh` pins M33MU at `268fbef3` and applies
`m33mu-stm32l562.patch`. The patch adds the STM32L552 TrustZone model: GTZC
MPCBB and TZSC enforcement, the flash watermarks (`--secwm1`, `--secwm2`),
power-up with TZEN at RDP level 0, and write-1-to-clear flash status. The
L552 lacks the L562's AES, HASH, PKA and OTFDEC blocks, which the port leaves
Secure and never uses. The model's life cycle is `0x2000`, the same as the
part at level 0.

## Build, flash, and verify

```sh
make test-hardware TARGET=stm32l562
```

`run_hardware.sh stm32l562` sources the port's `hw.sh`, which drives the
ST-LINK through `ports/stm32l562/probe.sh`. Each run erases the whole flash
and programs four images:

- `build/hw/wolfboot.bin` at `0x0C000000`
- the signed Secure image at `0x0C00C000`
- guest 0 at `0x0802C000`
- guest 1 at `0x08040000`

It then clears the mailboxes and launch masks, boots with a pin reset and
reads every image back. The bare-metal guests keep their mailboxes at
`0x20028000` and `0x20034000` and print on USART1 (`STM32L562_CONSOLE`).
The two guests preempt each other mid-line on the console, so the mailboxes
are the verdict. The port lists no qualification extras.

## Guest flash write protection

The fence is `WRP1A` over bank 1 pages `0x58` to `0x7F` (guest 0) plus
`WRP2A` over bank 2 pages `0x00` to `0x1F` (guest 1). `set-wrp` arms both
areas and `clear-wrp` releases them. `verify-wrp` reports any area that
covers a guest page, including one split across an A and B area or only
partly covering it. An area that also protects non-guest pages is never
narrowed or dropped. A Secure image built with `WT_GUEST_FLASH_WRP=1` refuses
both guests while the fence is open, and that refusal is the `wrpoff`
evidence.

## Provisioning and life cycle

The life cycle is the RDP option byte under TZEN, which wolfBoot hands
wolfTrust:

| `FLASH_OPTR` | RDP level | PSA life cycle |
| --- | --- | --- |
| `TZEN=1`, RDP `0xAA` | 0 | `0x2000` PSA_ROT_PROVISIONING |
| `TZEN=1`, RDP `0x55` | 0.5 | `0x4000` NON_PSA_ROT_DEBUG |
| `TZEN=1`, any other | 1 | `0x4000` NON_PSA_ROT_DEBUG |
| `TZEN=1`, RDP `0xCC` | 2 | `0x3000` SECURED |
| `TZEN=0` | any | `0x0000` UNKNOWN |

The ladder runs level 0, then 0.5, then 1. Level 2 is no lock target, and
`rdp2` is refused outright.

```sh
export TARGET=stm32l562
tests/target/provisioning/provisioning_ctrl.sh status
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh set-perimeter
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh set-wrp
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh restore
tests/target/provisioning/provisioning_ctrl.sh discover
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh advance 0x55
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh regress
tests/target/provisioning/provisioning_ctrl.sh lock 0x55
```

- **A part from the earlier layout needs `set-perimeter`.** That layout
  used `SECWM1 0x0-0x7F` and `SECWM2 0x0-0x3F`, which leave guest 0 Secure
  and guest 1 behind the old fence. `set-perimeter` is an option byte write
  at level 0, so a person runs it.
- **Every command is bound to one ST-LINK.** `STM32L562_STLINK_SN` or
  `WT_HW_PROBE` must name an attached STM32L562E-DK. With more than one DK and
  no serial, every command refuses.
- **`restore` is the hardware runner.** It releases an armed fence and runs
  `run_hardware.sh stm32l562 positive` on that ST-LINK. It then arms the fence
  again, even if the runner fails or the command gets `INT`, `HUP` or
  `TERM`. A passing run records `hwrun` (device UID, image digest, ST-LINK,
  `SECBOOTADD0`, handoff life cycle). `boot-lock` refuses without a fresh one.
- **The mock is in the handoff record.** `advance` halts at wolfTrust's
  reset vector and replaces the record's life cycle with `0x4000`. The option
  bytes are untouched, and `regress` at level 0 is a pin reset.
- **`lock` previews and refuses.** It checks the images, the perimeter,
  `BOOT_LOCK` and the fence, then prints the exact RDP write and the
  mass-erase way back. It refuses the write because
  `STM32L562_LOCK_WRITE_ENABLED=0`, even with every confirmation supplied.

`make test-provisioning` runs these gates against stub CubeProgrammer and
OpenOCD tools.

## Recovery rules

- Clear the WRP fence (`clear-wrp`) before reflashing; the hardware runner
  refuses a part with any WRP area enabled.
- An RDP regression from level 0.5 or 1 to level 0 mass-erases the whole
  flash. `regress` previews it and runs only after the typed `I ACCEPT 0xAA`.
- `BOOT_LOCK` is permanent. Only `boot-lock` writes it, after a fresh
  `hwrun` record, `WT_PRODUCTION_LOCK=1` and the typed `I ACCEPT BOOT_LOCK`.
  RDP level 2 is permanent too, and nothing here writes it.
- A part left with `SWAP_BANK=1` maps the banks the wrong way for this
  layout. `set-perimeter` refuses it rather than guess.

## Open items

- **Silicon run of this layout.** It needs the new watermarks
  (`set-perimeter`, run by a person), then the hardware minimum.
- **Hardware isolation probe verdict.** On silicon the GTZC drops a
  Non-secure store into Secure SRAM without faulting, so the probe latches 2
  and guest 0 keeps beating. `port.json` declares `iso_probe` as `silent`,
  the judge mode for that result. No silicon run of this layout has been
  judged against it yet.
- **`wrpfence` does not apply.** The shared scenario expects the first stage
  to arm the fence. Here the fence is an option byte (`set-wrp`), so
  `guest_fence` is absent and `wrpoff` carries the refusal evidence.
- **Native engine only.** `hsmpinneg`, `hsmfaultneg` and `hsmattackneg` need
  the wolfHSM engine and are exempt in `port.json`.
- **Emulator patch.** Carried until M33MU's STM32L552 model merges
  upstream.

See [Porting](Porting.md) for the port contract and [Testing](Testing.md)
for scenario selection.
