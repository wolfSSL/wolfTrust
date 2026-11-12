# STM32L562 Guide

This guide covers the ST STM32L562E-DK (STM32L562QE, Cortex-M33 with
TrustZone-M, 512 KiB of dual-bank internal flash, 256 KiB of SRAM) as the
fourth Armv8-M port. Like the STM32H563 it executes from internal flash
behind wolfBoot and isolates its guests with the GTZC; unlike the other
ports it builds the native crypto engine only, because 256 KiB of SRAM does
not hold the wolfHSM engine's level 3 bands beside two guests. RDP level 2
is permanent and closes the debug port for good; this port rehearses the RDP
ladder and writes none of it.

## Status

- **Validated in cross-build:** the wolfTrust Secure image
  (`make TARGET=stm32l562 secure-image`) for both manifests on the native
  engine: production 94,404 bytes of flash (93,696 text, 708 data),
  conformance 147,896, with `.vectors` at `0x0C00C400` in both, and the port
  split, veneer, owner map, and layout checks green. `WT_ENGINE=hsm` stops
  the build with an error.
- **Validated in emulation:** the chain under M33MU's STM32L552 model
  (`tests/target/run_stm32l562_m33mu.sh`, see
  [Build and verify under M33MU](#build-and-verify-under-m33mu)): wolfBoot
  verifies the Secure image and hands off, both bare-metal guests launch and
  complete their PSA calls through the veneers (`positive`), the GTZC curtain
  stops a guest's store into its peer's RAM (`gtzcneg`), an SP's read of
  another band faults (`crossdomain`), the PSA client runs its whole
  lifecycle from both windows and the attestation token's measurement equals
  wolfBoot's (`bothpsa`), Arm's unmodified FF-M IPC suite passes 85 with 4
  skipped (`confboot`), and the dev_apis crypto suite passes with none failed
  (`devcrypto`). Every scenario the matrix lists for this port
  (`tests/target/lib/scenario_matrix.py`: the MCXN947 set with `gtzcneg` in
  place of `sauneg` and without the wolfHSM-only scenarios, 46 in all, every
  isolation level 3 scenario included) passes on the model.
- **Validated on the host:** the flash driver over a model of the L5 flash
  controller with the wolfHSM store on top (`tests/host/stm32l562_flash`),
  the RNG driver over an RCC and RNG model (`tests/host/stm32l562_rng`), and
  the RDP to PSA life cycle mapping from the pinned wolfBoot header
  (`tests/host/stm32l562_lifecycle`).
- **Validated on silicon:** the chain on an STM32L562E-DK at RDP level 0
  with TZEN set (`tests/target/run_stm32l562_hardware.sh` through OpenOCD on
  an arm64 board host, see
  [Build and verify on the STM32L562E-DK](#build-and-verify-on-the-stm32l562e-dk)):
  wolfBoot verifies the Secure image and hands off the level 0 life cycle,
  the SPM creates the vault in its Secure pages, and both guests complete
  their FF-M handshake (`positive`); the GTZC curtain discards a guest's
  store into its peer's RAM (`gtzcneg`), the SAU faults a guest's read of the
  SPM's RNG and of Secure RAM until the monitor quarantines it (`periphneg`,
  `restart`), the PSA client runs every lifecycle stage from both windows
  (`psa`), and a `WT_GUEST_FLASH_WRP=1` image refuses both guests without
  the `WRP2A` fence (`wrpoff`) and launches both with it armed, while the
  flash refuses a debugger erase inside the fence (`wrpfence`). The
  provisioning port ran its level 0 flow on the same part: status,
  discovery, the perimeter and fence writes, `restore`, the level 0.5
  rehearsal, `regress`, and the refused `lock` and `boot-lock` previews. See
  [Open items](#open-items) for what has not run on the part.

Record emulator, cross-build, and physical-board evidence separately: M33MU's
STM32L552 model gives emulator evidence, the DK gives silicon evidence, and
neither substitutes for the other.

## What an STM32L562 port comprises

### First-stage loader (wolfBoot)

The port pins `aidangarske/wolfBoot` branch `stm32l5-wolftrust-handoff`
(`tests/target/lib/stm32l562_wolfboot.sh`) until it merges upstream:

| Addition | Purpose |
| --- | --- |
| `config/examples/stm32l5-tz-wolftrust.config` | TrustZone with the generic Secure-application handoff (`WOLFBOOT_SECURE_APP`): wolfBoot verifies and measures the Secure image, writes the measured-boot record to `0x30000000`, and jumps to it without leaving the Secure state. 2 KiB sectors, a 1024-byte image header, `NVM_FLASH_WRITEONCE`, `ARMORED`, no debug UART. |
| `hal/stm32l5_lifecycle.h` | Maps `FLASH_OPTR` (RDP and TZEN) to the PSA life cycle in the handoff record. |
| `hal/stm32l5.c`, `hal/stm32l5-secure-app.ld` | Erases through the Secure flash alias for a Secure application, and links wolfBoot's own RAM at `0x30030000` so the record and wolfTrust's RAM below it are left alone. |

The loader satisfies the [Porting](Porting.md) bootloader contract: it
authenticates the Secure image, provides `wt_boot_handoff_t` (SHA-256
measurement, life cycle, image version) at `0x30000000`, reserves the
1024-byte image header, and provides an update partition compatible with the
firmware-update backend in the production layout.

### Secure runtime (wolfTrust)

The port reuses `src/arch/armv8m/`, `src/arch/common/`, and the shared
Armv8-M isolation level 3 layer in `port/common/armv8m/` unchanged, and adds
`port/stm32l562/` and one build fragment:

| File | Responsibility |
| --- | --- |
| `memory_map.h` | The two flash layouts, Secure and guest RAM, the boot-handoff address, and the port-sized level 3 bands (`WT_L3_SPM_RAM_SIZE`, `WT_SP_HSM_DATA_SIZE`) from `port/common/armv8m/l3_layout.h`. |
| `l3_port.h` | The level 3 layer's one board input: the RNG as the Secure peripheral only the SPM drives. |
| `stm32l562_regs.h` | Register bases for RCC, PWR, GPIOA, USART1, the RNG, the GTZC (TZSC and both MPCBBs), the flash controller, and the instruction cache. |
| `platform_stm32l562.c` | Every `wt_platform_*` operation: the SAU table, the Secure MPU whitelist, the per-dispatch GTZC curtain, the USART1 console, fault logging, panic, and reset. |
| `gtzc.c` | The boot GTZC attribution (SPM SRAM and peripherals Secure, guest RAM and USART1 Non-secure) and its full read-back, tested by `tests/host/stm32l562_gtzc`. |
| `guest_wrp.c` | The guest flash WRP coverage check over both banks' WRP areas and `SWAP_BANK`, tested by `tests/host/stm32l562_wrp`. |
| `partitions.c` | The guest and capability tables, the profile capability bitmap (the fabric filter is the GTZC MPCBB curtain; guests get no DMA), and the pinned guest-measurement slot. |
| `hsm_flash.c/.h`, `hsm_flash_ctx.c` | The `port_nvm.h` backend for the wolfHSM store, the FWU staging backend, and the conformance NVM: reads through the Secure alias with the ECC double-error check, programs and erases through the Secure flash registers. |
| `rng_entropy.c` | The `CUSTOM_RAND_GENERATE_BLOCK` entropy source over the RNG, clocked from HSI48, preserving the unprivileged-to-privileged trap. |
| `secure.ld` | The port's Secure linker script, which INCLUDEs the shared level 3 regions, band sections, and layout ASSERTs; the SG veneers sit in the image's second 1 KiB. |
| `secure_owners.txt` | The port's objects in the post-link owner map, appended to `tools/secure_owners.txt` by the link. |
| `manifest.json`, `manifest-conformance.json`, `conformance/` | The service partitions and their resources; the conformance manifest and PAL bindings host Arm's test partitions. |
| `mk/target-stm32l562.mk` | `WT_CPU`, both flash layouts, the console and conformance interrupt, the linker `--defsym` set, the source lists, and the native-engine guard. |

## Reference flash and RAM layout

Flash is `0x08000000` (Non-secure) / `0x0C000000` (Secure); SRAM is
`0x20000000` / `0x30000000` (SRAM1 192 KiB, then SRAM2 64 KiB at
`+0x30000`); peripherals `0x40000000` / `0x50000000`. The port runs the part
in dual-bank mode (`DBANK=1`): two 256 KiB banks of 128 pages of 2 KiB, with a
64-bit ECC double-word as the program unit.

`WT_CONFORMANCE` picks one of two flash layouts. The production layout keeps
a 128 KiB Secure slot and a matching update slot; the conformance image and
Arm's test guest need a 160 KiB slot and a 240 KiB guest 0 window, which
leaves no room for an update slot (FWU is not in that manifest).

| Image or region | Production | Conformance |
| --- | ---: | ---: |
| wolfBoot (48 KiB, its empty NSC at `0x0C00B000`) | `0x0C000000` | `0x0C000000` |
| wolfTrust Secure slot | `0x0C00C000` (128 KiB) | `0x0C00C000` (160 KiB) |
| wolfHSM NVM store (two mirrored 8 KiB sectors) | `0x0C038000` | `0x0C038000` |
| Conformance NVM store (one sector) | `0x0C03C000` | `0x0C03C000` |
| wolfBoot swap page | `0x0C03E000` | `0x0C03E000` |
| wolfBoot update partition (bank 2) | `0x0C040000` (128 KiB) | none |
| Guest 0 | `0x08060000` (64 KiB) | `0x08040000` (240 KiB) |
| Guest 1 | `0x08070000` (64 KiB) | `0x0807C000` (14 KiB) |

The conformance layout rebuilds wolfBoot with `WOLFBOOT_PARTITION_SIZE=0x28000`
and `WOLFBOOT_PARTITION_UPDATE_ADDRESS=0x0C058000`; that update address falls
in the guest windows. Guest 1's window ends at the slot's last page
(`0x0807F800`), wolfBoot's update trailer, which stays erased; the runner
refuses any image that touches it, and nothing stages an update there.

| RAM region | Production | Conformance |
| --- | ---: | ---: |
| Boot-handoff record (4 KiB page, the record is 56 bytes) | `0x30000000` | `0x30000000` |
| Secure runtime RAM (`0x27000`: the SPM, the keystore bands, and the level 3 stacks) | `0x30001000` | `0x30001000` |
| Guest 0 RAM | `0x20028000` (48 KiB) | `0x20028000` (80 KiB) |
| Guest 1 RAM | `0x20034000` (48 KiB) | `0x2003C000` (16 KiB) |

The guest windows are the top 96 KiB of SRAM (the last 32 KiB of SRAM1 and
all of SRAM2). Their Secure alias holds wolfBoot's own RAM from `0x30030000`,
dead after the jump; `wt_platform_init` zeroes both windows before any guest
runs. The conformance layout splits the same 96 KiB as 80 KiB and 16 KiB
because Arm's crypto conformance guest overruns its stack in 48 KiB
(wolfCrypt's ECC key generation, seen as `PSA_ERROR_BAD_STATE` failures).
Every store the Secure image writes is in a bank or page the image does not
execute from, so no RAM code band is needed and the port has none.

These constants come from `port/stm32l562/memory_map.h` and
`mk/target-stm32l562.mk`; the emulator and hardware runners assemble their
flash images from them so the build and flash offsets stay paired.

## TrustZone perimeter

Part of the perimeter is option bytes, set once on a part at RDP level 0, and
part is programmed by wolfTrust on every boot.

**Option bytes** (`provisioning_ctrl.sh set-perimeter` and `boot-lock`, or by hand with
STM32CubeProgrammer):

| Option byte | Value | Why |
| --- | --- | --- |
| `TZEN` | `1` | TrustZone on; without it wolfBoot reports no life cycle |
| `DBANK`, `SWAP_BANK` | `1`, `0` | the dual-bank map the layout and the flash driver assume |
| `SECWM1_PSTRT`, `SECWM1_PEND` | `0x0`, `0x7F` | all of bank 1 Secure: wolfBoot, wolfTrust, the stores, the swap page |
| `SECWM2_PSTRT`, `SECWM2_PEND` | `0x0`, `0x3F` | production: bank 2 pages 0-63, the update slot, Secure; the guests above Non-secure |
| `SECBOOTADD0` | `0x180000` | boot at `0x0C000000`, wolfBoot |
| `BOOT_LOCK` | `1` | pins the boot to `SECBOOTADD0`; permanent, so `boot-lock` sets it last behind the production gates |
| `WRP2A_PSTRT`, `WRP2A_PEND` | `0x40`, `0x7F` | optional guest flash fence over both guest windows (`set-wrp`) |

The conformance layout puts guest 0 at the start of bank 2, so it needs bank
2 Non-secure (`SECWM2_PSTRT` above `SECWM2_PEND`); the emulator runner passes
the production watermark only to production scenarios.

**Programmed at boot** by `platform_stm32l562.c`:

- **SAU:** static Non-secure windows over the guest flash, the whole guest
  RAM extent, and the peripherals except the RNG page, plus the
  Non-secure-callable veneer window in the Secure image. Leaving the RNG page
  out makes a guest's touch of the SPM's RNG a precise SecureFault rather
  than a TZSC read-as-zero (`periphneg`).
- **GTZC:** both MPCBBs mark all of SRAM Secure except the guest RAM extent,
  and the TZSC keeps AES, HASH, RNG, PKA, and SDMMC1 (a bus master through
  its internal DMA) Secure while USART1 goes Non-secure for the guests'
  console. Boot reads the attribution back and panics on a mismatch. On
  every dispatch the curtain marks the whole guest
  extent Secure at the fabric and reopens only the arriving guest's
  declared windows, so the peer's RAM is Secure to every Non-secure master
  while that guest runs. A DMA transfer a guest armed could still complete
  after the switch, so boot holds every DMA1/DMA2 channel disabled, Secure
  (SECM) and privileged, reads that back, and guests get no DMA.
- **Secure MPU:** a whitelist of eight regions with the default map off: the
  Secure image (read-only, executable), the stores, update and swap
  partitions (read-write, never executed, non-cacheable so a verify reads
  the array), Secure RAM from the handoff record up, the guest RAM alias, the
  flash Non-secure alias (read-only), the peripheral aperture, the private
  peripheral bus, and the Secure alias of the guest images (read-only, for
  the vector and measurement reads).

As on the other ports, the guests run with `CONTROL_NS.nPRIV` clear, so a
guest's own Non-secure MPU is scheduling policy, not a boundary. The GTZC
curtain is the boundary between guests, and `gtzcneg` shows it under M33MU.

## Silicon constraints for this port

- **The program unit is a 64-bit double-word.** The flash keeps ECC per
  double-word and refuses (`PROGERR`) to program one that is not erased,
  unless the new value is all zeros (RM0438), which the driver never writes. The
  driver programs one double-word per `PG` operation and refuses any program
  off the 8-byte unit; wolfHSM's default `WOLFHSM_CFG_FLASH_UNIT_SIZE` (8)
  matches it, so no journal unit shares a double-word with another written at
  a different time. `tests/host/stm32l562_flash` runs the real driver and the
  wolfHSM store over a model of the controller and proves it: thousands of
  double-word programs across partition compactions and a reopen with no
  `PROGERR`, sequence error or all-zero reprogram.
- **Secure pages go through the Secure registers.** Unlock is `SECKEYR`
  (`KEY1`, `KEY2`), operations are `SECCR`, status is `SECSR`, whose error
  and `EOP` flags are write-1-to-clear: the driver clears them by writing
  ones, and a model that stored the write instead set every flag (the
  carried M33MU patch fixes its own). A page number is relative to its bank
  (`PNB`, with `BKER` for bank 2), and `SWAP_BANK` exchanges the banks, which
  the driver follows for both erase and the ECC bank check.
- **A wolfHSM sector is four pages.** wolfHSM's 8 KiB partitions erase as
  four 2 KiB page erases; the update slot uses the same 8 KiB sectors, and
  the FWU trigger is the last 16 bytes (two program units) of the slot.
- **An ECC double error is an NMI.** A checked read masks interrupts, arms
  the bank and address window it is about to read, and reads; the NMI handler
  claims a double error inside that window and anything else halts the core.
  The driver also re-checks `ECCR` after the read, and an aborted read
  returns no flash bytes.
- **Entropy is the RNG on HSI48.** The driver turns HSI48 on, selects it with
  `CLK48MSEL`, runs one conditioning reset that programs AN4230's NIST
  setting for a 48 MHz clock (`RNG_CR` `0x00F00D00`, `RNG_HTCR` `0xA2B3`),
  and discards the first word, as RM0438 advises. A seed or clock error,
  current (`SECS`, `CECS`) or latched (`SEIS`, `CEIS`, which stay set after
  the fault recovers), seen before or after a word is read, or a `DRDY` that
  never comes, fails the request and latches the source shut until reset.
- **The first loader's image header sets the Secure link address.** wolfBoot
  uses a 1024-byte image header, so wolfTrust links at the slot base plus
  `0x400` (`WT_SECURE_IMAGE_HEADER_SIZE=0x400`) and is signed with
  `IMAGE_HEADER_SIZE=1024`, `WOLFBOOT_SECTOR_SIZE=0x800`, and the layout's
  partition size.
- **NSC in flash works.** The flash is in the Code region, where the IDAU
  honours an SAU Non-secure-callable window, so the veneers stay in the image.
- **Native engine only.** `mk/target-stm32l562.mk` stops a `WT_ENGINE=hsm`
  build: the wolfHSM server's per-guest bands and stacks do not fit 256 KiB
  of SRAM beside the guests.
- **wolfBoot prints nothing on the DK's console.** wolfBoot's L5 debug UART
  is LPUART1, not the ST-LINK virtual COM port (USART1), and the config
  builds it off; the console markers are the guests'.

## Required tools

- `arm-none-eabi-gcc` with newlib headers, and `arm-none-eabi-{nm,objcopy,objdump,size}`
- Python 3, CMake (for the emulator build)
- for a board: the STM32L562E-DK with its on-board ST-LINK, and either
  STM32CubeProgrammer's `STM32_Programmer_CLI` (`STM32_CLI` or `STM32_CP`) or
  OpenOCD 0.12 (`STM32L562_OPENOCD`, used when CubeProgrammer is absent, as
  on an arm64 host; `STM32L562_PROBE_TOOL=cubeprog|openocd` forces one),
  `flock` and `timeout`. With OpenOCD, pyOCD (`pyocd list`) or the ST-LINK's
  mass-storage label (`DIS_L562QE`, from `lsblk`) identifies the DK; with
  CubeProgrammer, pyOCD drives the provisioning rehearsal
  (`tests/target/detect_stm32l562.sh` reports what is missing)

## Build and verify under M33MU

```sh
make TARGET=stm32l562 secure-image
make test-target TARGET=stm32l562
tests/target/run_stm32l562_m33mu.sh positive
tests/target/run_stm32l562_m33mu.sh gtzcneg
```

The runner builds its pinned emulator (M33MU with the STM32L552 TrustZone
model, pinned on the fork until it merges upstream, which enforces the GTZC
MPCBBs, the flash watermarks and the TZSC, powers it up with
`TZEN=1` and RDP level 0 (`M33MU_STM32L5_OPTR` overrides that), and makes
the flash status registers write-1-to-clear) and its pinned wolfBoot
(`tests/target/lib/stm32l562_wolfboot.sh`, from
`config/examples/stm32l5-tz-wolftrust.config`, rebuilt with the larger slot
for the conformance scenarios), checks that wolfBoot's
`hal/stm32l5_lifecycle.h` is the copy the host suite tests, then:

1. builds the wolfTrust Secure image and its CMSE import library with
   `WT_SECURE_IMAGE_HEADER_SIZE=0x400`;
2. builds the guests for the scenario (the bare-metal guest, the portable PSA
   guest, or the PSA guest hosting Arm's val client), linked against the
   Secure image's CMSE import library;
3. patches both guest measurement records into the unsigned `wolftrust.bin`
   (`tools/measure/patch_guest_digests.py`);
4. signs `wolftrust.bin` with the wolfBoot key tools;
5. boots `m33mu --cpu stm32l552` on one 512 KiB factory image (wolfBoot at
   0, the signed Secure image at `0xC000`, the guests at the layout's
   offsets), with `--secwm2=0:63` for the production layout.

The L552 model stands in for the L562, which adds the AES, HASH, PKA and
OTFDEC blocks; the port leaves those Secure and does not use them.
`STM32L562_WOLFBOOT_DIR` reuses a wolfBoot tree the library built; `M33MU` a
prebuilt emulator carrying the patch.

### Bring-up markers

Each bare-metal guest records progress in a mailbox at the base of its own
Non-secure RAM window (`0x20028000` for guest 0, `0x20034000` for guest 1 in
the production layout) and echoes it on USART1 (`0x40013800`):

| Mailbox word | Offset | Pass value |
| --- | ---: | ---: |
| signature | `+0x00` | `0x47543030` |
| step | `+0x04` | `0x00000005` |
| `psa_framework_version()` | `+0x08` | `0x00000100` |
| `psa_connect(SERVICE_HSM)` handle | `+0x10` | > 0, distinct per guest |
| status | `+0x14` | `0x600D600D` |
| USART1 `CR1` as the guest found it | `+0x18` | informational (`0` for the first guest to run) |
| isolation probe latch (`gtzcneg`) | `+0x1C` | `1` faulted or `2` blocked; `3` leaked |
| isolation probe read-back (`gtzcneg`) | `+0x20` | not the stored sentinel |
| idle beat | `+0x24` | advancing once done |

A `status` of `0x600D600D` in both mailboxes, and
`wolfTrust STM32L562 guest<n>: FF-M connect ok, done` on the console, prove
the wolfBoot to wolfTrust to Non-secure-guest chain booted and that the
Secure runtime serviced both Non-secure PSA clients through the veneers. In
`gtzcneg`, guest 0 disables its own Non-secure MPU and stores a sentinel
into guest 1's RAM; the curtain either faults the store, and the monitor
quarantines guest 0 after its restart budget, or discards it, and guest 0
reads it back absent. Either way the peer never sees the sentinel.

## Build and verify on the STM32L562E-DK

```sh
make test-hardware TARGET=stm32l562   # positive gtzcneg periphneg restart psa wrpoff wrpfence
tests/target/run_stm32l562_hardware.sh positive
```

`tests/target/run_stm32l562_hardware.sh` runs on the host that owns the DK's
ST-LINK. Every board operation goes through `tests/target/lib/stm32l562_probe.sh`:
STM32CubeProgrammer where it is installed, else OpenOCD through the ST-LINK's
DAP (`interface/stlink-dap.cfg`, `dapdirect_swd`, `target/stm32l5x.cfg`) with
the operations in `tests/target/lib/stm32l562_openocd.tcl`. The lab rig is an
arm64 Raspberry Pi 5 with OpenOCD 0.12, where CubeProgrammer does not exist.
Every call is bound to one ST-LINK serial: the one attached STM32L562E-DK
(CubeProgrammer's board name, pyOCD's board or target, or the mass-storage
label), or `STM32L562_STLINK_SN`, which must still name an attached DK. The
console is the ST-LINK's virtual COM port (USART1, `STM32L562_CONSOLE`). The
runner builds the native engine only.

For each scenario it takes the board lock (`logs/stm32l562-hw.lock`, shared
with the suite) and refuses a part that is not at RDP level 0 with TZEN, the
production watermarks, `SECBOOTADD0` at wolfBoot and both banks unswapped, or
that has the guest WRP fence armed (the fence would keep the guests from being
reflashed). `BOOT_LOCK` may be either value: a passing `positive` run is the
evidence `boot-lock` requires, so the runner records one (below). It then
builds the Secure image and the guests, pins the guest measurements, signs
the image with the pinned wolfBoot's key, erases the whole flash and programs
only each image's bytes (wolfBoot, the signed image, both guests), so the
vault, conformance NVM, swap page and update slot start erased rather than
programmed with `0xFF`. It clears the mailboxes, the probe word and the launch
masks with the core held at reset, boots once with a pin reset while
capturing the console, reads every image back and compares it, and asserts:

- the bare-metal mailboxes (signature, framework version, `0x600D600D`), the
  probe latch for the negatives, the monitor's `g_wt_restart_events` and
  `g_wt_quarantine_events` counters, the last fault address, the launch
  masks, the peer's advancing idle beat, and that the sentinel never landed;
- the Secure side of every run: the flash driver's first error and the SVC
  gate's abort count both 0, the vault's first partition programmed, an
  erased double-word reading as `0xFF`, the handoff record consumed, and the
  life cycle wolfBoot handed over (`0x2000` at RDP level 0 under TZEN);
- for `psa`, each PSA guest's mailbox stage bits (TEE, crypto, ITS, PS,
  key-ops, SHA-256 KAT, COSE attestation, done) and its FF-M negatives;
- for `wrpoff`, a Secure image built with `WT_GUEST_FLASH_WRP=1` on a part
  without the fence refusing both guests (launch refused mask `0x3`, no
  mailbox written, nothing on the console);
- for `wrpfence`, the same image with `WRP2A` armed over pages `0x40`-`0x7F`
  (a reversible option byte write at level 0) launching both guests, and the
  flash refusing an OpenOCD erase of guest 0's first page, which then reads
  back unchanged. An `EXIT`, `INT`, `HUP` and `TERM` trap releases the fence.

Both guests print on USART1 and are preempted mid-line, so on silicon their
console text interleaves; the mailboxes are the verdict and the console only
shows that the guests ran.

A passing `positive` writes the hardware-run record
`$WT_PROVISION_STATE/stm32l562/hwrun` (default `~/.cache/wolftrust`): the
device UID, the framed digest of the four images, the ST-LINK, the Secure
boot address and the handed-over life cycle. `boot-lock` refuses without a
fresh one for this part and these images.

Each run's console capture, image readbacks, the trimmed images it
programmed, the programming and boot logs and an SWD dump of every word the
checks read (with the UID and the option bytes) are kept under
`logs/stm32l562-hw/<scenario>-native/`, the suite's per-scenario logs under
`logs/stm32l562-suite/`: outside `build/`, which every run cleans before it
builds. Without a probe tool, the ST-LINK, its console, the Arm toolchain,
or `flock`, `tests/target/detect_stm32l562.sh` reports why and the suite
skips. Hardware test commands write flash and reset the board.

### Board evidence

All seven scenarios pass on an STM32L562E-DK (`TZEN=1`, RDP `0xAA`, `SECWM1`
`0x0`-`0x7F`, `SECWM2` `0x0`-`0x3F`, `SECBOOTADD0` `0x180000`, `BOOT_LOCK`
`0`), driven through OpenOCD 0.12 from a Raspberry Pi 5 with wolfBoot at the
pin in `tests/target/lib/stm32l562_wolfboot.sh`. On silicon the GTZC curtain
discards guest 0's store into guest 1's RAM (probe latch 2, RAZ/WI) rather
than faulting it, one of the two outcomes `gtzcneg` accepts. A quarantine
scrubs the guest's RAM, so the `periphneg` latch reads 0 after it.

### What the silicon taught the runner

- **Never program `0xFF` over the stores.** A programmed all-ones
  double-word is not an erased one: the flash refuses (`PROGERR`) to program
  it again, so the vault's first write failed and wolfTrust panicked in
  `wt_boot_run`. Both backends now erase the whole flash and program only
  the images, trimmed of their erased tail and padded to the double-word.
- **With TZEN set the debugger is Secure, and OpenOCD changes that.** OpenOCD
  tags its memory accesses Non-secure (`CSW.HNONSEC`) while the halted core
  is in Non-secure state, so every OpenOCD operation forces Secure accesses
  after its halt. A Secure access to a Non-secure SRAM block is illegal under
  the GTZC unless `MPCBBx_CR.SRWILADIS`, and a Non-secure flash page reads
  through the Secure alias only under `SECBB`, so a read opens both with the
  core held and puts them back before it resumes.
- **The UID answers only a Non-secure access.** `0x0BFA0590` (and the rest
  of the engineering area) reads as zero to every Secure access, debugger or
  core. The OpenOCD backend halts, claims that page Non-secure with the last
  SAU region (selecting the Secure SAU bank through `DSCSR`), reads it, and
  restores the SAU exactly. OpenOCD's flash probe cannot read the flash size
  there either and assumes 512 KiB, which is right for this part.
- **OpenOCD's `option_write` does not persist with TZEN set.** The backend
  unlocks `NSKEYR` and `OPTKEYR`, merges each field into its Secure option
  register (`0x50022040`-`0x5002206C`), sets `OPTSTRT`, waits on `BSY`, checks
  the error flags, and launches the load with `OBL_LAUNCH`, which resets the
  part; the caller reads the option bytes back before a write counts.
- **Connect under reset, then release it.** Holding the core needs
  `connect_assert_srst` and `reset halt`; flash and option operations then
  run with `reset_config none`, or the reset line fires mid-operation.

## Provisioning and life cycle

This section is the STM32L562 part of [Provisioning](Provisioning.md). The
life cycle is the RDP option byte in `FLASH_OPTR` under TZEN, which wolfBoot
maps to the PSA life cycle it hands wolfTrust (`hal/stm32l5_lifecycle.h`;
`tests/host/stm32l562_lifecycle` tests the pinned copy):

| `FLASH_OPTR` | RDP level | PSA life cycle wolfBoot hands wolfTrust |
| --- | --- | --- |
| `TZEN=1`, RDP `0xAA` | 0 (as the DK ships, once TZEN is set) | `0x2000` PSA_ROT_PROVISIONING |
| `TZEN=1`, RDP `0x55` | 0.5: Secure memory closed to the debugger | `0x4000` NON_PSA_ROT_DEBUG |
| `TZEN=1`, any other RDP | 1: flash and SRAM2 closed to the debugger | `0x4000` NON_PSA_ROT_DEBUG |
| `TZEN=1`, RDP `0xCC` | 2: debug closed for good | `0x3000` SECURED |
| `TZEN=0` | any | `0x0000` UNKNOWN: with no Secure world there is nothing to attest |

The ladder in the provisioning port is the perimeter at level 0, then level
0.5, then level 1:

| Code | State | Mock | Lock | Permanence | From |
| --- | --- | --- | --- | --- | --- |
| `0xAA` | level-0 | no | no | reversible | - |
| `0x55` | level-0.5 | yes | yes | reversible | `0xAA` |
| `0xBB` | level-1 (any RDP byte not listed) | yes | yes | reversible | `0x55` |
| `0xCC` | level-2 | no | no | permanent | `0xBB` |

All commands use the single entry point with `TARGET=stm32l562`:

```sh
export TARGET=stm32l562
tests/target/provisioning/provisioning_ctrl.sh status
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh set-perimeter
WT_LOCK_CONFIRM=1 WT_PRODUCTION_LOCK=1 tests/target/provisioning/provisioning_ctrl.sh boot-lock
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh restore
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh set-wrp
tests/target/provisioning/provisioning_ctrl.sh discover
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh advance 0x55
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh regress
tests/target/provisioning/provisioning_ctrl.sh lock 0x55
```

What differs from the other ports:

- **The perimeter is option bytes this tool writes.** `set-perimeter` writes
  `TZEN`, the watermarks and `SECBOOTADD0`. `BOOT_LOCK` is permanent and
  freezes `SECBOOTADD0`, so `boot-lock` first requires a passing hardware run
  of this part booting these images from `SECBOOTADD0` (the runner's `hwrun`
  record: same device UID, same image digest, same ST-LINK, the images still
  on the part, no older than `WT_REHEARSAL_MAX_AGE`), then
  `WT_PRODUCTION_LOCK=1` and a typed `I ACCEPT BOOT_LOCK` at a terminal, and
  re-checks the perimeter and the record after the acceptance. The hardware
  suite does not require `BOOT_LOCK`; `lock` does. `set-wrp` and
  `clear-wrp` arm and release `WRP2A` over the guest windows; `verify-wrp`
  reports the fence. Each runs only at RDP level 0 and counts only once the
  option bytes read back as written.
- **Every device command is bound to one ST-LINK.** `STM32L562_STLINK_SN`
  names the DK's ST-LINK, and is refused unless it is an attached
  STM32L562E-DK's (CubeProgrammer's board name, pyOCD's board or target, or
  the mass-storage label); with more than one DK attached and no serial
  every command refuses instead of reading nothing. The probe tool is
  CubeProgrammer or OpenOCD, as for the runner.
  `status` prints it, `discover` stamps it, the rehearsal record carries it,
  and `lock` accepts only a rehearsal made through the same ST-LINK.
- **`restore` is the hardware runner.** It releases an armed guest fence,
  runs `tests/target/run_stm32l562_hardware.sh positive` on that ST-LINK, and
  arms the fence again, so the images a rehearsal binds are the ones the
  runner built, flashed and read back. The fence goes back on whether the
  runner passes or fails and on `INT`, `HUP` or `TERM`, which also stop the
  runner first.
- **The mock is in the handoff record.** `advance` halts the core (OpenOCD,
  or pyOCD with CubeProgrammer) at wolfTrust's reset vector (`0x0C00C404`), after wolfBoot wrote the
  handoff record and before wolfTrust consumed it, and replaces the record's
  PSA life cycle with `0x4000` NON_PSA_ROT_DEBUG, the value at levels 0.5
  and 1. The option bytes are untouched; `regress` at level 0 is a hardware
  reset. The rehearsal records what wolfTrust saw, the guests launched
  verified, the images read back, the option bytes, the device UID
  (`0x0BFA0590`), and the ST-LINK.
- **`lock` previews the RDP write and refuses it.** `lock level-0.5` checks
  the images on the part, the perimeter and `BOOT_LOCK`, and the guest fence,
  prints the exact write (CubeProgrammer `-ob RDP=0x55`, or the OpenOCD
  option sequence over a hot attach) and the way back (an
  RDP regression to level 0, which mass-erases the whole flash), keeps the
  option bytes it checked and that plan under the port's state folder
  (`lock-0x55/`), and then
  refuses the write on `STM32L562_LOCK_WRITE_ENABLED=0`, a port constant
  hard-wired off in this phase. That refusal holds with `WT_LOCK_CONFIRM=1`,
  `WT_PRODUCTION_LOCK=1` and the typed acceptance all supplied. Level 2 is no
  lock target at all, and `rdp2` is refused outright.
- **A real regression mass-erases, so it asks first.** On a part found at
  level 0.5 or 1, `regress` is an RDP regression to level 0 (`-ob RDP=0xAA`):
  it previews that the whole flash will be erased and runs only from an
  interactive terminal after the typed `I ACCEPT 0xAA`. At level 2 it
  refuses; there is no way back.

`make test-provisioning` runs the STM32L562 gates against a stub
`STM32_Programmer_CLI` and a stub OpenOCD with the other ports' gates.

On the DK (OpenOCD backend, RDP level 0, `BOOT_LOCK` 0) the port ran
`status`, `discover`, `set-perimeter`, `set-wrp`, `verify-wrp`, `restore` with
the fence armed (released, the runner passed, armed again), the `advance
0x55` rehearsal (wolfTrust saw `0x4000` NON_PSA_ROT_DEBUG and launched both
guests), `regress` (a pin reset back to `0x2000`), `lock 0x55` (refused before
any write: `BOOT_LOCK` is off), `boot-lock` without the production opt-in
(the hardware-run record passed, then refused before any write),
`clear-wrp`, and a `restore` stopped by `SIGTERM` with the fence armed, which
put the fence back. No RDP level and no `BOOT_LOCK` were written.

## Open items

- **Not on the board yet.** The CubeProgrammer backend (no arm64 build, so
  the rig uses OpenOCD; its calls are checked against a stub), `BOOT_LOCK`
  and any RDP change (permanent or mass-erasing, so never written here), the
  ECC NMI path, `confboot` and the other emulator-only scenarios (the other
  ports' hardware suites do not run them either).
- **Native engine only.** The wolfHSM engine's bands do not fit 256 KiB of
  SRAM beside two guests; the level 3 scenarios `hsmpinneg` and `hsmfaultneg`
  are exempt for that reason in `tests/target/lib/scenario_matrix.py`, and the
  wolfHSM-only `hsmattackneg` does not run.
- **No in-flash update slot in the conformance layout.** The 160 KiB slot and
  240 KiB guest window leave no room; FWU is not in the conformance manifest.
- **RDP write.** A validated RDP advance on the part does not exist; the
  lock flow rehearses and previews only.
- **Upstream pins.** The wolfBoot pin moves to wolfSSL/wolfBoot once the
  `stm32l5-wolftrust-handoff` branch merges; the emulator patch goes once
  M33MU's STM32L552 model enforces the GTZC, the watermarks and the TZSC,
  powers up with TZEN set, and clears its flash status write-1-to-clear.

See [Porting](Porting.md) for the generic port contract, [Testing](Testing.md)
for scenario selection, and [Security Model](Security-Model.md) for the policy
enforced after boot.
