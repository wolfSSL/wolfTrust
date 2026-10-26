# MCXN947 Guide

This guide covers the NXP FRDM-MCXN947 (MCXN947, Cortex-M33 CPU0 with
TrustZone-M) as the third Armv8-M port. Unlike the MIMXRT700 it executes from
2 MiB of internal ECC flash, programmed through the boot ROM's flash API, and
its entropy comes from the EdgeLock (ELS) block. CPU1 is Non-secure only and
out of scope. Changing the OTP life cycle or the CMPA can permanently lock
the part; this port rehearses life cycles and writes none of them.

## Status

- **Validated on silicon:** the wolfBoot first stage for this part
  (wolfSSL/wolfBoot#948: signed boot with ECC256/SHA-256, update swap and
  rollback over the write-once trailer, and the measured Secure-application
  handoff to `0x30030000`), and the wolfTrust chain behind it on the
  FRDM-MCXN947 (`tests/target/run_mcxn947_hardware.sh`, see
  [Build and verify on the board](#build-and-verify-on-the-frdm-mcxn947)):
  wolfBoot verifies the Secure image, the SPM consumes the handoff, creates
  the wolfHSM vault in the ROM-programmed NVM, and launches both guests on
  both crypto engines (`positive`); the SAU refuses a guest's store into its
  peer's RAM (`sauneg`) and its read of the SPM's ELS (`periphneg`), and a
  guest faulting at launch spends its restart budget and is quarantined
  (`restart`), the peer running on throughout; the portable PSA client runs
  its crypto, ITS, sealed PS, key-ops, FF-M negative and SHA-256 KAT stages
  from both windows with the ELS behind `psa_generate_random`, and verifies
  the attestation token it is issued against the IAK the vault provisioned at
  first boot (`psa`).
- **Validated in cross-build:** the wolfTrust Secure image
  (`make TARGET=mcxn947 secure-image`) on both crypto engines and both
  manifests, with the port split, veneer, owner map, and layout checks green.
- **Validated in emulation:** the chain under M33MU's MCXN947 model
  (`tests/target/run_mcxn947_m33mu.sh`, see Testing): wolfBoot verifies the
  Secure image, both bare-metal guests launch and complete their PSA calls
  through the veneers (`positive`, both engines), the isolation negative
  (`sauneg`) shows a guest's store into the other guest's RAM refused by the
  SAU, contained by the monitor, and the offender quarantined after its
  restart budget while the peer keeps running, and every other scenario the
  matrix lists for this port (`tests/target/lib/scenario_matrix.py`: the
  whole MIMXRT700 set, every isolation level 3 scenario included) passes on
  the model on both crypto engines. The one MIMXRT700 scenario not listed is
  `confboot`: on the M33MU commit this port pins (the one with the MCXN947
  RAM attribution fix), the Arm FF-M IPC suite stops in test i002 check 5,
  the Non-secure val guest parked in its HardFault handler with an
  undefined-instruction UsageFault right after `psa_connect` returns, and
  the MIMXRT700 chain does the same on that emulator commit while it passes
  on the older one its runner pins; the dev_apis storage, crypto and
  attestation suites and the vault recovery runs complete on both. It is an
  emulator regression to bisect upstream, not a port claim.
- **Not validated:** any guest flash fence and any life cycle write. The
  TRDC and the AHB secure controller are left as the first loader leaves
  them. See [Open items](#open-items).

Record emulator, cross-build, and physical-board evidence separately: M33MU's
MCXN947 model gives emulator evidence, the FRDM board gives silicon evidence,
and neither substitutes for the other.

## What an MCXN947 port comprises

### First-stage loader (wolfBoot)

| Addition | Purpose |
| --- | --- |
| `hal/mcxn.{c,ld}` | LPUART4 debug console and the internal flash through the ROM flash API (`FLASH_Init`, `FLASH_Program`, `FLASH_Erase`, `FLASH_VerifyErase`); the flash path runs from RAM. |
| `config/examples/mcxn-tz-wolftrust.config` | TrustZone enabled with the generic Secure-application handoff (`WOLFBOOT_SECURE_APP`): wolfBoot writes the measured-boot record to Secure SRAM and stays in Secure state across the jump; 8 KiB sectors, a 1024-byte image header, `NVM_FLASH_WRITEONCE`. |
| `tests/target/wolfboot-mcxn947-lifecycle.patch` (carried here) | reads the OTP life cycle the ROM reflects into `SYSCON.ELS_OTP_LC_STATE` and its duplicate, with `DAUTHSTATUS`, and hands wolfTrust the matching PSA life cycle; the HAL at the pin reports a fixed SECURED value. |

The loader satisfies the [Porting](Porting.md) bootloader contract: it
authenticates the Secure image, provides `wt_boot_handoff_t` (SHA-256
measurement, life cycle, image version) at `0x30030000`, reserves the
1024-byte image header, and provides an update partition compatible with the
firmware-update backend.

### Secure runtime (wolfTrust)

The port reuses `src/arch/armv8m/`, `src/arch/common/`, and the shared
Armv8-M isolation level 3 layer in `port/common/armv8m/` unchanged, and adds
`port/mcxn947/` and one build fragment:

| File | Responsibility |
| --- | --- |
| `memory_map.h` | The bit-28 Secure-alias map: flash windows, Secure and guest RAM, the boot-handoff address, and the port-sized level 3 bands (`WT_L3_SPM_RAM_SIZE`, `WT_SP_HSM_DATA_SIZE`) from `port/common/armv8m/l3_layout.h`. |
| `l3_port.h` | The level 3 layer's one board input: the ELS as the Secure peripheral only the SPM drives. |
| `mcxn947_regs.h` | Register bases for SYSCON, the FMU, the ELS, LPUART4, the TRDC and the AHBSC, the boot ROM and its API tree, and the ELS command interface. |
| `platform_mcxn947.c` | Every `wt_platform_*` operation: the SAU table, the Secure MPU whitelist (eight regions, one of them the boot ROM for the flash API), the boot-handoff region, fault logging, panic, and reset. |
| `partitions.c` | The guest and capability tables, the profile capability bitmap (the fabric filter is claimed on the per-dispatch SAU window, as on the MIMXRT700), and the pinned guest-measurement slot. |
| `rom_flash.c/.h` | Internal flash program and erase through the boot ROM's API tree, called directly with a local definition of the driver interface layout (no vendor SDK): one 16-byte phrase is programmed at most once per erase, each program is issued from its 128-byte page base behind all-ones padding as the ROM requires, every erase is verified by the ROM, and the code-bus cache is cleared after each change. |
| `hsm_flash.c/.h`, `hsm_flash_ctx.c` | The `port_nvm.h` backend for the wolfHSM store and the FWU staging backend: reads through the Secure alias, program and erase through `rom_flash.c`. |
| `rng_entropy.c` | The `CUSTOM_RAND_GENERATE_BLOCK` entropy source over the ELS `RND_REQ` command, preserving the unprivileged-to-privileged trap. |
| `secure.ld` | The port's Secure linker script, which INCLUDEs the shared level 3 regions, band sections, and layout ASSERTs; the SG veneers sit in the image's second 1 KiB, as on the STM32H5. |
| `secure_owners.txt` | The port's objects in the post-link owner map, appended to `tools/secure_owners.txt` by the link. |
| `manifest.json`, `manifest-conformance.json`, `conformance/` | The service partitions and their resources; the conformance manifest and PAL bindings host Arm's test partitions. |
| `mk/target-mcxn947.mk` | `WT_CPU`, the flash and RAM defaults, the linker `--defsym` set, and the source lists. |

## Reference flash and RAM layout

Flash is `0x00000000` (Non-secure) / `0x10000000` (Secure); RAMA-H SRAM is
`0x20000000` / `0x30000000`; peripherals `0x40000000` / `0x50000000`. Bit 28
selects the Secure alias. Flash is two 1 MiB banks (read-while-write across
banks) of 8 KiB sectors and 16-byte ECC phrases.

| Image or region | Non-secure | Secure alias |
| --- | ---: | ---: |
| wolfBoot (bank 0) | `0x00000000` | `0x10000000` |
| wolfTrust Secure image, BOOT partition (`0x40000`) | `0x00040000` | `0x10040000` |
| Guest 0 (`0x80000`) | `0x00080000` | `0x10080000` |
| Guest 1 (`0x40000`, bank 1) | `0x00100000` | `0x10100000` |
| wolfBoot update partition (`0x40000`) | `0x00180000` | `0x10180000` |
| wolfBoot swap sector (`0x2000`) | `0x001C0000` | `0x101C0000` |
| wolfHSM NVM store (two mirrored sectors) | `0x001E0000` | `0x101E0000` |
| Conformance NVM store (one sector) | `0x001E4000` | `0x101E4000` |

| RAM region | Address |
| --- | ---: |
| Guest 0 RAM (`0x18000`) | `0x20000000` |
| Guest 1 RAM (`0x18000`) | `0x20018000` |
| Boot-handoff record (4 KiB page, the record is 56 bytes) | `0x30030000` |
| Secure runtime RAM (`0x37000`: 86 KiB SPM, 42 KiB keystore bands, 102 KiB stacks and conformance data) | `0x30031000` |

The guest windows alias wolfBoot's own RAM (`0x30000000` to `0x3001E000`),
dead after the jump; `wt_platform_init` zeroes both windows before any guest
runs. Every store below the Secure image is in bank 1, so the image keeps
executing from bank 0 while the ROM API programs the NVM and update
partitions: no RAM code band is needed, and the port has none.

These constants come from `port/mcxn947/memory_map.h` and
`mk/target-mcxn947.mk`; the emulator runner assembles the flash image from
them so the build and flash offsets stay paired.

## TrustZone perimeter

The MCXN947 has no option-byte Secure watermark. The Secure boundary is set at
run time by what the port programs before any guest launches:

- **IDAU/SAU:** the bit-28 alias makes each address inherently Secure or
  Non-secure; the SAU table in `platform_mcxn947.c` opens the static
  Non-secure windows (the guest flash, the LPUART4 console) and the
  Non-secure-callable veneer window in the Secure image, and leaves
  everything else Secure. The guest RAM windows are not static: each dispatch
  programs a dynamic SAU region over the arriving guest's window only, so the
  peer's window stays Secure while it runs, exactly as on the MIMXRT700.
- **Secure MPU:** a per-partition whitelist confines each Secure Partition to
  its own RAM band. The SPM's eight regions are the Secure image, the Secure
  alias of everything above it (guest images, update and swap partitions, the
  stores: read-only, execute-never), Secure RAM from the handoff record up,
  the guest RAM alias, the flash Non-secure alias, the peripheral aperture,
  the private peripheral bus, and the boot ROM (privileged read-execute, for
  the flash API).
- **TRDC and AHBSC:** not programmed. At reset the flash MBC leaves every
  block Non-secure-accessible and the AHB secure controller rules are open,
  as the first loader leaves them. The port claims the fabric filter on the
  per-dispatch SAU window alone (`partitions.c`): it isolates CPU0's guests
  from each other and says nothing about CPU1, DMA, or any other bus master.
  No capability is claimed for fencing those.

As on the other ports, the manifest declares the guests unprivileged but the
runtime launches them with `CONTROL_NS.nPRIV` clear; a guest's Non-secure MPU
is scheduling policy, not a boundary. The SAU window is the boundary, and
`sauneg` shows it under M33MU.

## Silicon constraints for this port

- **A phrase is written once.** The flash has ECC per 16-byte phrase; a
  programmed phrase cannot be reprogrammed until its sector is erased. The
  wolfHSM store runs with `WOLFHSM_CFG_FLASH_UNIT_SIZE` 16 (the wolfTrust
  runner setting all ports share), so every journal unit is one phrase and
  no unit shares a phrase with another written at a different time;
  `rom_flash.c` refuses to program a non-blank phrase and `hsm_flash.c`
  refuses any program that is not phrase-aligned. `tests/host/mcxn947_flash`
  runs the real driver and the wolfHSM store over a model of this flash and
  its ROM and proves it: 643 page-based ROM programs across three partition
  compactions and a reopen, zero double programs with 16-byte units (even
  through a backend with no phrase guard), 281 double programs with
  wolfHSM's 8-byte default, which the port backend refuses outright.
- **The ROM programs from a page base.** On silicon (ROM `K` 3.2.0) the
  flash driver's `FLASH_Program` returns `kStatus_FLASH_AlignmentError` (101)
  for any start that is not 128-byte page aligned, whatever the length, and
  leaves an all-ones phrase exactly as it was (programming only clears bits,
  and the erased phrase is a valid ECC word). `rom_flash.c` therefore
  programs each phrase from its page base behind all-ones padding, one page
  per ROM call; the padding never counts as a program of the phrases it
  covers, which the host model checks. The ROM also stores each phrase
  through the flash's Non-secure alias for the FMU to capture, so the SPM's
  MPU keeps that alias writable (a store outside a ROM program sequence does
  not alter flash).
- **Flash is programmed through the ROM.** There is no SDK in the build; the
  port calls the ROM API tree at `0x1303FC00` through a local definition of
  its layout, checks the geometry the ROM reports (8 KiB sectors, 2 MiB)
  before the first program, masks interrupts around each call, and clears
  the LPCAC afterwards. Reads, verifies, and blank checks go through the
  Secure alias, as wolfBoot's own flash path does on silicon; an erased
  phrase reads as `0xFF` without a fault.
- **Entropy is the ELS.** `RND_REQ` (command 24) fills a buffer by DMA; the
  port requests whole pages, serves only what a request uses, wipes the rest,
  and fails closed on `ELS_ERR` or a locked ELS, counting every refusal in
  `g_wt_els_errors` for the hardware runner. The ROM leaves the ELS clocked
  (`AHBCLKCTRL2`/`PRESETCTRL2` bit 18); the port enables it and never resets
  it.
- **The first loader's image header sets the Secure link address.** wolfBoot
  on this part uses a 1024-byte image header, so wolfTrust links at the boot
  base plus `0x400` (`WT_SECURE_IMAGE_HEADER_SIZE=0x400`) and is signed with
  `IMAGE_HEADER_SIZE=1024` and 8 KiB sectors.
- **NSC in flash works.** The flash is in the Code region, where the IDAU
  honours an SAU Non-secure-callable window, so the veneers stay in the
  image, as on the STM32H5 (the MIMXRT700's RAM code band is not needed).

## Required tools

- `arm-none-eabi-gcc` with newlib headers, and `arm-none-eabi-{nm,objcopy,size}`
- Python 3, CMake (for the emulator build)
- wolfBoot's MCXN HAL builds against the MCUXpresso SDK (`MCUXPRESSO`,
  `MCUXPRESSO_CMSIS`, or `~/NXP` as wolfBoot's config expects)
- for a board: the FRDM-MCXN947 with its MCU-Link (CMSIS-DAP and VCOM),
  pyOCD with the MCXN947 pack (`pyocd pack install MCXN947`), and SPSDK's
  `blhost` for the life cycle rehearsal (`tests/target/detect_mcxn947.sh`
  reports what is missing)

## Build and verify under M33MU

```sh
make TARGET=mcxn947 secure-image
make test-target TARGET=mcxn947
tests/target/run_mcxn947_m33mu.sh positive
tests/target/run_mcxn947_m33mu.sh sauneg
```

The runner builds its pinned emulator (upstream M33MU plus
`tests/target/m33mu-mcxn947.patch`, which adds the ELS `RND_REQ` register
model behind its `AHBCLKCTRL2` gate, programs flash from a page base by
clearing bits as the ROM does, makes the ROM executable so an API call leaves
no stale `IACCVIOL` in `CFSR`, and reflects the OEM_OPEN life cycle into
SYSCON) and its pinned
wolfBoot (`tests/target/lib/mcxn947_wolfboot.sh`: the wolfSSL/wolfBoot#948
branch at its fork ref until it merges, built from
`config/examples/mcxn-tz-wolftrust.config` with the carried life cycle
patch), then:

1. builds the wolfTrust Secure image and its CMSE import library with the
   port's default `WT_SECURE_IMAGE_HEADER_SIZE=0x400`;
2. builds the bare-metal guest for both guest windows, linked against the
   Secure image's CMSE import library;
3. patches both guest measurement records into the unsigned `wolftrust.bin`
   (`tools/measure/patch_guest_digests.py`);
4. signs `wolftrust.bin` with the wolfBoot key tools (`IMAGE_HEADER_SIZE=1024`,
   `WOLFBOOT_SECTOR_SIZE=0x2000`);
5. boots `m33mu --cpu mcxn947` with wolfBoot at flash offset 0, the signed
   Secure image at `0x40000`, and the guests at `0x80000` and `0x100000`.

`MCXN947_WOLFBOOT_DIR` reuses a wolfBoot tree the library built; `M33MU` a
prebuilt emulator carrying the patch.

### Bring-up markers

Each guest records progress in a mailbox at the base of its own Non-secure RAM
window (`0x20000000` for guest 0, `0x20018000` for guest 1) and echoes it on
LPUART4 (`0x400B4000`):

| Mailbox word | Offset | Pass value |
| --- | ---: | ---: |
| signature | `+0x00` | `0x47543030` |
| step | `+0x04` | `0x00000005` |
| `psa_framework_version()` | `+0x08` | `0x00000100` |
| `psa_connect(SERVICE_HSM)` handle | `+0x10` | > 0, distinct per guest |
| status | `+0x14` | `0x600D600D` |
| LPUART4 `VERID` as the guest reads it | `+0x18` | non-zero |
| isolation probe latch (`sauneg`) | `+0x1C` | `1` faulted or `2` blocked; `3` leaked |
| isolation probe read-back (`sauneg`) | `+0x20` | not the stored sentinel |

A `status` of `0x600D600D` in both mailboxes proves the wolfBoot to wolfTrust
to Non-secure-guest chain booted and that the Secure runtime serviced both
Non-secure PSA clients through the veneers. In `sauneg`, guest 0 disables its
own Non-secure MPU and stores a sentinel into guest 1's RAM; the runner
asserts from M33MU's protection-unit trace that the store faulted, refused by
the SAU with the peer window Secure at dispatch.

## Build and verify on the FRDM-MCXN947

```sh
make test-hardware TARGET=mcxn947            # positive sauneg periphneg restart psa
tests/target/run_mcxn947_hardware.sh positive
WT_ENGINE=hsm tests/target/run_mcxn947_hardware.sh positive
```

`tests/target/run_mcxn947_hardware.sh` runs on the host that owns the
board's MCU-Link (`MCXN947_PROBE_UID` picks one of several probes; the
console is the MCU-Link VCOM, `MCXN947_CONSOLE`). For each scenario it
takes the board lock (`logs/mcxn947-hw.lock`, shared with the suite), then
builds the Secure image and the guests, pins the guest measurements, signs
the image with the pinned wolfBoot's key, flashes wolfBoot, the signed image
and both guests at their physical offsets with pyOCD, erases the update,
swap and NVM sectors so every run starts from a blank vault, clears the
mailboxes and launch masks in SRAM, boots, reads every image back and
compares it, and asserts the result over SWD:

- the bare-metal mailboxes (signature, framework version, `0x600D600D`,
  the LPUART4 `VERID` the guest read) and, for the negatives, the monitor's
  `g_wt_restart_events` and `g_wt_quarantine_events` counters, the launch
  masks, the peer's advancing idle beat, and that the sentinel never landed;
- the Secure side of every run: `g_wt_rom_flash_last_status` 0 (the ROM
  flash API answered from the SVC gate), the wolfHSM backend's last error,
  the vault's first state phrase programmed, an erased phrase reading as
  `0xFF`, the handoff record consumed, IPSR outside the fault handlers, and
  wolfBoot's `Verifying signature...done` on the console;
- for `psa`, each PSA guest's mailbox stage bits (TEE, crypto, ITS, PS,
  key-ops, SHA-256 KAT, COSE attestation, done).

Each run's console capture, image readbacks and an SWD dump of every word
the checks read are kept under `logs/mcxn947-hw/<scenario>-<engine>/`
(`console.log`, `readback-*.bin`, `swd.txt`), the suite's per-scenario logs
under `logs/mcxn947-suite/`: outside `build/`, which every run cleans before
it builds, and never overwritten by another scenario or engine.

Two board facts the runner encodes: the pack's `reset halt` leaves a DWT
comparator and the debug fault status armed, so the core is released only
after both are cleared; and the MCU-Link forwards early-boot UART only while
the debug link stays active, so the console capture runs alongside spaced
reads. The two guests share LPUART4, so their console lines interleave on
silicon; the assertions are the mailboxes and counters, the console is
evidence.

## Provisioning and life cycle

This section is the MCXN947 part of [Provisioning](Provisioning.md). The
life cycle lives in OTP; the ROM reflects it into `SYSCON.ELS_OTP_LC_STATE`
(`0x50000980`) and its duplicate (`0x50000984`), eight bits each, which the
carried wolfBoot patch reads and maps to the PSA life cycle it hands
wolfTrust (`tests/host/mcxn947_lifecycle` tests that mapping):

| `LC_STATE` | NXP state | PSA life cycle wolfBoot hands wolfTrust |
| --- | --- | --- |
| `0x03` | OEM Open (as the FRDM board ships) | `0x1000` ASSEMBLY_AND_TEST |
| `0x07` | OEM Secure World Closed | `0x2000` PSA_ROT_PROVISIONING |
| `0x0F` | OEM Closed | `0x3000` SECURED with every `DAUTHSTATUS` field disabled; `0x5000`/`0x4000` while debug is open; `0x0000` for a malformed `DAUTHSTATUS` |
| `0xCF` | OEM Locked | as OEM Closed |
| `0x1F` | OEM Field Return | `0x6000` DECOMMISSIONED |
| other, or the copies disagree | NXP Blank, Fab, Dev, Provisioned, Field Return, Shredded, or corrupt | `0x0000` UNKNOWN |

All commands use the single entry point with `TARGET=mcxn947`:

```sh
export TARGET=mcxn947
tests/target/provisioning/provisioning_ctrl.sh status
tests/target/provisioning/provisioning_ctrl.sh discover
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh advance 0x07
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh regress
```

What differs from the MIMXRT700:

- **The mock lock is in the handoff record.** The MCXN947 has no life cycle
  shadow register (`ELS_OTP_LC_STATE` is read-only), so `advance` halts the
  core at wolfTrust's reset vector, after wolfBoot wrote the handoff record
  and before wolfTrust consumed it, and replaces the record's PSA life cycle
  with the target state's production value (`0x2000`, `0x3000`, or
  `0x6000`). Fuses and SYSCON are untouched; `regress` is a hardware reset.
  The rehearsal records what wolfTrust saw, the guests launched verified,
  the images read back, and the device UUID (`0x01100000`).
- **No state can be locked.** The port implements no OTP write: every
  `lock`, `burn`, and `provision-da` is refused, and `verify-wrp` reports
  that there is no guest flash fence. The real life cycle advance on this
  part (the ROM's ISP path) is not validated here.
- **`restore` has no runner yet.** Flash wolfBoot, the signed Secure image,
  and both guests by hand, then `discover`.

`make test-provisioning` runs the MCXN947 gates against stub tools with the
other ports' gates.

## Open items

- **Life cycle in the handoff.** wolfBoot's HAL at the pin reports no life
  cycle (`hal_attestation_get_lifecycle` is the weak default), so the
  carried patch supplies it; the hardware runner checks the handed value
  against `ELS_OTP_LC_STATE` on every run because an `UNKNOWN` life cycle
  silently fails attestation closed (the vault may not provision an IAK
  under it).
- **Guest flash fence.** No hardware write protection of the guest windows is
  claimed: `wt_platform_guest_flash_wrp_ok` reports every window unprotected,
  so a `WT_GUEST_FLASH_WRP=1` image refuses every guest. The TRDC MBC gates
  bus accesses to the flash, not the FMU's program and erase commands, so it
  is not the fence; the candidate is a flash page lock the ROM's
  `kStatus_FLASH_ModifyProtectedAreaDisallowed` status names, which needs the
  reference manual and a silicon negative before it can be claimed.
- **Other bus masters.** CPU1, DMA, and the ELS DMA are not fenced from
  Secure RAM; programming the TRDC and the AHB secure controller for them is
  silicon work that M33MU does not model.
- **wolfBoot's own flash writes.** The MCXN HAL at the pin programs 4-byte
  words at any word-aligned address, which this ROM refuses off a page base
  (`kStatus_FLASH_AlignmentError`, checked on the board with a direct ROM
  call); wolfTrust's own stores never go through it, the hardware runner
  never asks wolfBoot to write, and an update swap on silicon is not claimed
  until the HAL programs from page bases.
- **Life cycle write.** A validated life cycle advance on the part does not
  exist; the hardware runner rehearses only.
- **Upstream pins.** The wolfBoot pin moves to wolfSSL/wolfBoot once
  wolfSSL/wolfBoot#948 merges; the emulator patch goes once M33MU models the
  ELS command interface, the ROM's page-based bit-clearing program, an
  executable ROM, and seeds the life cycle itself.

See [Porting](Porting.md) for the generic port contract, [Testing](Testing.md)
for scenario selection, and [Security Model](Security-Model.md) for the policy
enforced after boot.
