# MIMXRT700 Guide

This guide covers the NXP MIMXRT700-EVK (MIMXRT798S, compute Cortex-M33) as a
second Armv8-M reference port. Unlike the STM32H563, this part has no internal
program flash: it executes in place from an external octal SPI NOR on XSPI0, and
the boot chain, Secure image, and guests all live in that NOR. Changing the OTP,
debug-authentication policy, or product lifecycle can permanently lock the part.
Read the current state first and keep a development board recoverable.

## Status

- **Validated:** the wolfBoot first-stage loader on this silicon (signed boot
  with ECC256 and ML-DSA-87, update swap and rollback, boot-region protection,
  and the TrustZone measured handoff into a Secure payload), and the wolfTrust
  Secure image cross-build (`make TARGET=mimxrt700 secure-image`) with the port
  split, veneer, and manifest checks green.
- **Validated in emulation:** the wolfTrust chain under M33MU's RT700 model
  (`tests/target/run_rt700_m33mu.sh`, see Testing). wolfBoot verifies the
  Secure image and both bare-metal guests launch and complete their PSA calls
  through the veneers (`positive`); the isolation negative (`ahbscneg`) shows a
  guest's store into the other guest's RAM refused by the SAU, contained by the
  monitor, and the offender quarantined after its restart budget while the peer
  keeps running.
- **Validated on the EVK:** the same two scenarios on both crypto engines
  (`tests/target/run_rt700_hardware.sh`). In `ahbscneg`, guest0 disables its
  Non-secure MPU and stores into guest1's RAM; the store faults, guest1's RAM
  never holds the sentinel, and guest1 keeps running. The port isolates guest
  RAM with a per-dispatch SAU window, because the AHB secure controller's SRAM
  rules do not gate CPU0 on this silicon (an earlier fabric-filter attempt let
  a guest with its Non-secure MPU disabled write the other guest's RAM).
- **Not yet ported:** firmware update, conformance, and `SERVICE_VNET`.
  `SERVICE_FWU` is in the manifest, but its begin, write, arm, disarm, and
  verify operations return `WH_ERROR_NOTIMPL` until arming the wolfBoot update
  trailer is ported. The target has no conformance or VNET manifest, so
  `WT_CONFORMANCE=1` and `CONFIG_VNET=y` stop the build with an error. The
  NOR guest-window write-protect check is not ported either, so a
  `WT_GUEST_FLASH_WRP=1` build refuses to launch any guest.

Record emulator, cross-build, and physical-board evidence separately: M33MU's
RT700 model gives emulator evidence, the EVK gives silicon evidence, and
neither substitutes for the other.

## What a MIMXRT700 port comprises

A full port spans two repositories. The first-stage loader changes live in
wolfBoot; the Secure runtime changes live in wolfTrust.

### First-stage loader (wolfBoot)

| Addition | Purpose |
| --- | --- |
| `hal/imx_rt7xx.{c,h,ld}` | LPUART0 debug console, and an XSPI0 octal-NOR driver (program, erase, read-modify-write). The part has no ROM flash API, so the flash path runs from RAM (`RAM_CODE`) through a deadline-bounded transaction layer, invalidating the XSPI cache after every write. |
| `config/examples/imx-rt700.config` | ECC256, TrustZone disabled: the plain-boot smoke configuration. |
| `config/examples/imx-rt700-tz.config` | TrustZone enabled with the generic Secure-application handoff (`WOLFBOOT_SECURE_APP`): wolfBoot writes the measured-boot record to Secure SRAM and stays in Secure state across the jump to the Secure runtime. |
| `config/examples/imx-rt700-mldsa.config` | ML-DSA-87 image signatures for a CNSA 2.0 boot chain. |
| Boot-region protection | Before handoff, wolfBoot programs and locks the XSPI Secure Flash Protection descriptors so the bootloader region is read-only to the application, and refuses to continue if the protection cannot be read back. |

The loader satisfies the [Porting](Porting.md) bootloader contract: it
authenticates the Secure image, provides `wt_boot_handoff_t` (SHA-256
measurement, lifecycle, image version) at the agreed Secure-RAM address,
reserves the Secure image header, and provides an update partition compatible
with the firmware-update backend.

### Secure runtime (wolfTrust)

The port reuses `src/arch/armv8m/` and `src/arch/common/` unchanged and adds
only `port/mimxrt700/` and one build fragment:

| File | Responsibility |
| --- | --- |
| `memory_map.h` | The bit-28 Secure-alias map: XSPI0 NOR windows, Secure and guest RAM, the boot-handoff address, and the per-partition RAM bands. |
| `mimxrt798_regs.h` | Register bases for CLKCTL, SYSCON, IOPCTL, LPUART0, XSPI0, TRNG, the AHBSC fabric controllers, and their GLIKEY unlock state machines. |
| `platform_mimxrt700.c` | Every `wt_platform_*` operation: clocks, the SAU table, the Secure MPU whitelist, enabling AHBSC secure checking behind its GLIKEY unlock, staging of the RAM code band, the boot-handoff region, fault logging, panic, and reset. |
| `partitions.c` | The guest and capability tables, the profile capability bitmap (the fabric filter is claimed on the per-dispatch SAU window, not on the AHBSC SRAM rules), and the pinned guest-measurement slot. |
| `xspi_nor.c/.h` | The XSPI0 octal-DTR NOR program and erase driver: bounded target-group IP commands on its own LUT sequences, run from the RAM code band with interrupts masked, flushing the XSPI read cache afterwards. |
| `hsm_flash.c/.h` | The `port_nvm.h` backend for the wolfHSM store: reads through the Secure XIP alias, program and erase through `xspi_nor.c`. |
| `rng_entropy.c` | The `CUSTOM_RAND_GENERATE_BLOCK` entropy source over the on-die TRNG, preserving the unprivileged-to-privileged trap. |
| `secure.ld` | The port's own Secure linker script, including the RAM code band: the SG veneers, the `cmse_nonsecure_entry` bodies, and the NOR driver, loaded from flash and executed from SRAM. |
| `manifest.json` | The service partitions (attestation, HSM, vault, ITS, PS, FWU) and their resources. |
| `mk/target-mimxrt700.mk` | `WT_CPU`, the flash and RAM defaults, the linker `--defsym` set, and the source lists. |

The only edit outside the port allow-list is a neutral seam: an `#ifndef` guard
around `WOLFHSM_CFG_FLASH_UNIT_SIZE` so the port can set the NOR write unit.

## Reference flash and RAM layout

XSPI0 octal NOR is aliased at `0x28000000` (Non-secure) and `0x38000000`
(Secure); compute-domain SRAM is `0x20000000` / `0x30000000`; peripherals are
`0x40000000` / `0x50000000`. Bit 28 selects the Secure alias.

| Image or region | Non-secure | Secure alias |
| --- | ---: | ---: |
| wolfBoot (FCB at flash + 0, boot header at + `0x4000`) | `0x28000000` | `0x38000000` |
| wolfTrust Secure image (`0x40000`) | `0x28040000` | `0x38040000` |
| Guest 0 (`0x80000`) | `0x28080000` | `0x38080000` |
| Guest 1 (`0x40000`) | `0x28100000` | `0x38100000` |
| wolfBoot update partition (`0x40000`) | `0x28180000` | `0x38180000` |
| wolfHSM NVM store | `0x281E0000` | `0x381E0000` |
| Conformance NVM store | `0x281E8000` | `0x381E8000` |

| RAM region | Address |
| --- | ---: |
| Guest 0 RAM (`0x40000`) | `0x20100000` |
| Guest 1 RAM (`0x40000`) | `0x20140000` |
| Boot-handoff record | `0x30180000` |
| Secure runtime RAM | `0x30188000` |
| RAM code band (`0x4000`, NSC gateway and NOR driver) | executes at `0x10200000`, staged through `0x30200000` |

SRAM appears at four aliases with the same offset: `0x0` Non-secure code,
`0x1` Secure code, `0x2` Non-secure data, `0x3` Secure data.

These constants come from `port/mimxrt700/memory_map.h` and
`mk/target-mimxrt700.mk`. Use the hardware runner for image assembly so the
build and flash addresses stay paired.

## TrustZone and fabric perimeter

The MIMXRT700 has no option-byte Secure watermark. The Secure boundary is set at
run time by three mechanisms the port programs before any guest launches:

- **IDAU/SAU:** the bit-28 alias makes each address inherently Secure or
  Non-secure; the SAU table in `platform_mimxrt700.c` opens the static
  Non-secure windows (the guest flash, the shared console) and leaves
  everything else Secure. The guest RAM windows are not static: each dispatch
  programs a dynamic SAU region over the arriving guest's window only, so the
  peer's window stays Secure while it runs. The shared `fabric_windows` helper
  drives those regions the way it drives GTZC blocks on the STM32H5.
- **Secure MPU:** a per-partition whitelist confines each Secure Partition to
  its own RAM band. The core implements eight Secure regions; the port merges
  the Secure alias of the guest images, the update partition, and the NVM
  stores into one read-only region (the NOR is only written through XSPI IP
  commands) to leave one region for the executable RAM code band.
- **AHBSC fabric:** reset leaves AHBSC0 secure checking off. The port turns it
  on (MISC_CTRL and its duplicate, behind GLIKEY0) and opens only the LPUART0
  console to the Non-secure side. With checking on, a guest's write to the
  AHBSC rule registers through their Non-secure alias is blocked. The port also
  marks the Secure runtime partition and the RAM code band Secure-only, as
  NXP's TrustZone setup does, without claiming isolation from those rules.

A port declares what it actually enforces through the capability bitmap in
`partitions.c`, and the manifest validator refuses a domain that requires a
capability the port does not provide: a writable Non-secure guest window is
refused unless the port claims the fabric filter. This port claims it on the
strength of the per-dispatch SAU window. The AHBSC SRAM rules do not gate CPU0
on this silicon (a Non-secure store into a closed guest window landed with them
on), so the CPU's own attribution is the barrier: with the peer window Secure,
a guest's store into it faults even after the guest disables its own
Non-secure MPU, and the monitor contains the fault. `ahbscneg` shows exactly
that on the EVK and under M33MU.
As on the STM32H563 (see [TF-M Compatibility](TF-M-Compatibility.md)), the
manifest declares the guests unprivileged but the runtime launches them with
`CONTROL_NS.nPRIV` clear. A guest's Non-secure MPU is therefore scheduling
policy, not a boundary; the SAU window is the boundary. Fencing other bus masters (the sense M33, the DSPs, the NPU, and DMA) per
master is not implemented.

## Silicon constraints for this port

These properties of the MIMXRT700 shaped the port and apply to any port on a
similar bit-28 IDAU part:

- **NSC is honoured only in the Code region.** An SAU Non-secure-callable
  region over the XSPI0 Secure alias (`0x38000000`) is overridden to Secure by
  the IDAU, so a Non-secure call faults with INVEP even though the SG
  instruction is present. XSPI0 has no Code-region alias, so the gateway (the
  SG veneers and the entry bodies they branch to) runs from SRAM through the
  Secure Code alias, as NXP's own TrustZone examples do.
- **SRAM partitions are not uniform.** AHBSC0 partitions range from 32 KiB to
  1 MiB; each carries 32 rule fields, so the rule granularity is the partition
  size divided by 32 (16 KiB for the 512 KiB partition holding both guest
  windows).
- **The fabric does not check at reset, and its rules are not a guest
  filter.** AHBSC secure checking is off until MISC_CTRL bits 11:2 are
  rewritten behind GLIKEY0 write index 1. Even with checking on, the SRAM
  partition rules did not stop a Non-secure CPU store into a closed guest
  window on the EVK, so they cannot back the fabric-filter capability; CPU-side
  guest isolation is the SAU.
- **There is no ROM flash API and the code runs from the same NOR.** A program
  or erase leaves the NOR unable to serve instruction fetches, so the driver
  and everything it calls execute from the RAM code band with interrupts
  masked, and the XSPI read cache is flushed before returning.
- **The first loader's image header sets the Secure link address.** wolfBoot
  on this part uses a 1024-byte image header, so wolfTrust links at the boot
  base plus `0x400` (`WT_SECURE_IMAGE_HEADER_SIZE=0x400`) and is signed with
  `IMAGE_HEADER_SIZE=1024`.

## Required tools

- MIMXRT700-EVK with its on-board MCU-Link (CMSIS-DAP) and USB serial
- `arm-none-eabi-gcc` with newlib headers, and `arm-none-eabi-{nm,objcopy,size}`
- NXP SPSDK (`nxpimage` for FCB and bootable-image assembly)
- pyOCD with MIMXRT798S pack support (flash and SWD inspection)
- Python 3
- wolfBoot key tools and a signing key for the Secure payload
- a hardware runner host that owns the probe, with a controllable reset line to
  the EVK, and a serial console (default `/dev/ttyACM0`)

## Build, flash, and verify

The hardware runner (`tests/target/run_rt700_hardware.sh`) drives image
assembly and flashing so the addresses stay paired; its emulator sibling
(`tests/target/run_rt700_m33mu.sh`) runs the same chain and scenario names
under M33MU. The `romsmoke` scenario proves the BootROM XIP path; the
`positive` scenario is the wolfTrust chain; `ahbscneg` adds the guest
isolation negative.

The full chain build and flash performs:

1. wrap the wolfBoot TrustZone image (`imx-rt700-tz.config`) with the EVK FCB
   and a boot header (`nxpimage`);
2. build the wolfTrust Secure image and its CMSE import library with the
   target's default `WT_SECURE_IMAGE_HEADER_SIZE=0x400`;
3. build the bare-metal guest for both guest windows, linked against the
   Secure image's CMSE import library so the `WolfTrust_FFM_*` veneers resolve;
4. patch both guest measurement records into the unsigned `wolftrust.bin`
   (`tools/measure/patch_guest_digests.py`);
5. sign `wolftrust.bin` with the wolfBoot key tools (`IMAGE_HEADER_SIZE=1024`);
6. flash wolfBoot at `0x28000000`, the signed Secure image at `0x28040000`, and
   the guests at `0x28080000` and `0x28100000`, each with the core parked by a
   hardware reset;
7. erase the wolfHSM NVM store so the run starts from a fresh vault;
8. reset the board, read every image back through XIP, and check both guests'
   markers.

Because the Secure image pins each guest's SHA-256 before it is signed, an
unpatched or corrupted guest fails launch closed: the wolfBoot signature covers
the pinned digests, and the Secure port refuses a guest whose image does not
match its record.

### Bring-up markers

Each guest records progress in an SWD-readable mailbox at the base of its own
Non-secure RAM window (`0x20100000` for guest 0, `0x20140000` for guest 1) and
echoes it on LPUART0:

| Mailbox word | Offset | Pass value |
| --- | ---: | ---: |
| signature | `+0x00` | `0x47543030` |
| step | `+0x04` | `0x00000005` |
| `psa_framework_version()` | `+0x08` | `0x00000100` |
| `psa_connect(SERVICE_HSM)` handle | `+0x10` | > 0, distinct per guest |
| status | `+0x14` | `0x600D600D` |
| LPUART0 `VERID` as the guest reads it | `+0x18` | non-zero |
| isolation probe latch (`ahbscneg`) | `+0x1C` | `1` faulted or `2` blocked; `3` leaked |
| isolation probe read-back (`ahbscneg`) | `+0x20` | not the stored sentinel |

A `status` of `0x600D600D` in both mailboxes proves the wolfBoot to wolfTrust to
Non-secure-guest chain booted and that the Secure runtime serviced both
Non-secure PSA clients through the veneers. `0xBAD00000` records a failed check
at the `step` reached. In `ahbscneg`, guest 0 disables its own Non-secure MPU
and stores a sentinel into guest 1's RAM; guest 1 carries no probe of its own
and keeps running untouched. The M33MU runner asserts the store faulted,
refused by the SAU with the peer window Secure at dispatch; the hardware
runner also reads guest 1's RAM over SWD to confirm the sentinel never landed
and that the core is not parked in a fault handler, and logs the AHBSC0
violation latches for reference.

## Recovery rules

- If the BootROM does not run the image, confirm the FCB is present and the
  boot header offset matches the runner (`0x4000`).
- If wolfBoot rejects wolfTrust, confirm the guest measurement records were
  patched before signing and that the signing key matches the configured
  keystore.
- If wolfTrust refuses a guest, compare the built guest address and size with
  the manifest and inspect the signed measurement record.
- If the guest mailbox never leaves `0x00000000`, halt over SWD and sample the
  program counter: an identical value each time is a spin, not progress. Confirm
  the Secure image launched the Non-secure guest before assuming a veneer fault.
- If a guest is quarantined before it ever runs while its image and pinned
  digest match, suspect persisted vault state such as a guest rollback floor:
  erase the wolfHSM NVM store and boot again.
- A running wolfTrust sets `AIRCR.SYSRESETREQS`, so a debugger's software reset
  is ignored and a "reset halt" can leave the core running under the Secure MPU,
  where the flash algorithm faults. Park the core with the probe's hardware
  reset before flashing.
- The device-pack debug target resets the chip on connect; read live state with
  a plain Cortex-M attach, or the read lands in a fresh boot. SRAM survives a
  warm reset, so a stale mailbox can look like a result.
- An aborted attach can leave the reset vector catch armed, so every warm reset
  halts in the BootROM with no UART output; a resuming hardware reset clears
  it. A persistent `WAIT ACK` on attach is a wedged bus: `pyocd reset -m hw`.
- An isolation probe must disable the guest's Non-secure MPU before the store,
  or that MPU stops it and the test says nothing about the fabric. Debugger
  accesses are no substitute: they are checked against the SAU and IDAU, so
  they cannot show what the fabric does to a guest store.
- A guest fault the guest does not handle itself escalates to the Secure
  HardFault, which currently stops the whole system rather than the one guest.
- Never reuse another NXP part's FCB, clock, or pin table without checking its
  reference manual and NOR geometry.

See [Porting](Porting.md) for the generic port contract, [Testing](Testing.md)
for scenario selection, and [Security Model](Security-Model.md) for the policy
enforced after boot.
