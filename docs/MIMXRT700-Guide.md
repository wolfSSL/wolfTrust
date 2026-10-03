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
- **Validated on the EVK and in emulation:** the XSPI guest flash fence
  (`wrpfence`, `wrpoff`, `wrpneg`) and the mock lock of every life cycle
  state, described under Guest flash write protection and Provisioning and
  life cycle below. The real fuse burn is gated and has never been run.
- **Not yet ported:** `SERVICE_VNET`. The target has no VNET manifest, so
  `CONFIG_VNET=y` stops the build with an error. `SERVICE_FWU` stages a
  candidate into the wolfBoot update partition
  (`0x38180000`, the `imx-rt700-tz.config` update address) and arms the swap
  trigger in its trailer, as the STM32H563 port does; staging must be
  contiguous from offset 0, so a finished candidate has no unwritten gap. `WT_CONFORMANCE=1`
  selects `port/mimxrt700/manifest-conformance.json`, which hosts Arm's
  server, driver, and client partitions for the conformance suites.

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
| Guest flash fence | Carried as `tests/target/wolfboot-imxrt700-guest-fence.patch`: with `XSPI_GUEST_FENCE_START`/`END` defined, a further locked descriptor makes both guest windows read-only to every initiator until the next reset. |
| Life cycle | Carried as `tests/target/wolfboot-imxrt700-lifecycle.patch`: `hal_attestation_get_lifecycle()` reads the OTP `LC_STATE` shadow, its redundant copy, the A0/A1 bit-protection copies when present, and `DAUTHSTATUS`, and maps them to the PSA life cycle in the handoff. In Field reports SECURED only when every `DAUTHSTATUS` field reads implemented and disabled (`0xAA`); an enabled field lowers it to `0x5000` or `0x4000`, and any other encoding reports UNKNOWN. |

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
- NXP SPSDK (`nxpimage` for FCB and bootable-image assembly; `shadowregs`
  support for `mimxrt798s`, checked by the life cycle preflight)
- pyOCD with MIMXRT798S pack support (flash and SWD inspection)
- Python 3
- wolfBoot key tools and a signing key for the Secure payload
- a hardware runner host that owns the probe, with a controllable reset line to
  the EVK, and a serial console (default `/dev/ttyACM0`)

## Read-only preflight

Before any command that writes to the board, read the life cycle, debug, and
fence state, then run the preflight that gates `advance`:

```sh
TARGET=mimxrt700 tests/target/provisioning/provisioning_ctrl.sh status
TARGET=mimxrt700 tests/target/provisioning/provisioning_ctrl.sh discover
```

Both only read over SWD, with the generic Cortex-M attach that never resets the
chip. A factory EVK running the fenced chain (after `restore`) reads:

```text
OTP life cycle   LC_STATE=0x03 (Develop)  LC_STATE_RED=0x03
LOCK_CFG3        0x00000000 (LIFE_CYCLE_LOCK=0: 0 = shadow override and fuse burn both open)
DAUTHSTATUS      0x000000ff
XSPI SFP         MGC=0xa8000400 TG0MDAD=0xa000c000
guest fence      armed FRAD2 acp=0x00000000 word3=0xa0000000
wolfTrust saw    0x00001000 (ASSEMBLY_AND_TEST)
guest launches   verified=0x00000003 refused=0x00000000
```

| Line | Meaning |
| --- | --- |
| `OTP life cycle` | the `LC_STATE` shadow and its redundant copy; they must agree |
| `LOCK_CFG3` | `LIFE_CYCLE_LOCK` bits: bit 0 blocks burning, bit 1 blocks shadow over-ride, bit 2 blocks reads |
| `DAUTHSTATUS` | Cortex-M debug authentication; `0xff` means Secure and Non-secure debug are open |
| `XSPI SFP` | global flash-protection configuration and the initiator domain; `0xa8000400` and `0xa000c000` mean valid and sealed |
| `guest fence` | the descriptor spanning the guest windows; `armed` needs write access `0` and a hard-reset lock |
| `wolfTrust saw` | the life cycle wolfBoot handed wolfTrust at `0x30180000` |
| `guest launches` | wolfTrust's launch-verified and launch-refused guest masks |

On an unfenced chain the fence line instead reads
`open FRAD1 acp=0x00000007 word3=0xa0000000`: FRAD1 grants write access over the
guest windows. `discover` then checks the preflight:

```text
  [check] PASS  SPSDK shadowregs supports mimxrt798s
  [check] PASS  fused life cycle is Develop and its redundant copy agrees
  [check] PASS  life cycle shadow over-ride is open (LOCK_CFG3 0x00000000)
  [check] PASS  the boot handoff life cycle is readable (0x00001000, ASSEMBLY_AND_TEST)
PASS: discovery stamped (/home/<user>/.cache/wolftrust/mimxrt700/discovery)
```

The stamp lives under `WT_PROVISION_STATE/mimxrt700` (default `~/.cache/wolftrust/mimxrt700`).
Running `discover` again clears both it and any earlier `regress` stamp.

## Build, flash, and verify

The hardware runner (`tests/target/run_rt700_hardware.sh`) drives image
assembly and flashing so the addresses stay paired; its emulator sibling
(`tests/target/run_rt700_m33mu.sh`) runs the same chain and scenario names
under M33MU. The `romsmoke` scenario proves the BootROM XIP path; the
`positive` scenario is the wolfTrust chain; `ahbscneg` adds the guest
isolation negative; `wrpfence`, `wrpoff`, and `wrpneg` cover the guest flash
fence. `make test-hardware TARGET=mimxrt700` runs that set through
`tests/target/run_rt700_suite.sh` on the probe host and skips without a board.
Both runners build the wolfBoot first stage from one pinned upstream commit
plus the carried patches (`tests/target/lib/rt700_wolfboot.sh`) unless
`RT700_WOLFBOOT_DIR` names a prebuilt tree. The emulator runner then carries the STM32H563 scenario
matrix (restart and launch refusal, SP fault recovery, the Secure-verdict
negatives, the PSA guest's lifecycle and negatives, and Arm's conformance
suites), listed in [Testing](Testing.md).

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

## Guest flash write protection

The STM32H563 protects guest flash with persistent WRP option bytes. This part
has none; the equivalent is the XSPI Secure Flash Protection fabric, whose
region descriptors (FRADs) are programmed by wolfBoot on every boot and locked
until the next hard reset. With the guest fence armed, wolfBoot's descriptor
layout is:

| FRAD | Range | Writable |
| --- | --- | --- |
| 0 | boot root, `0x28000000`-`0x2803FFFF` | no |
| 1 | Secure image, `0x28040000`-`0x2807FFFF` | yes |
| 2 | guest windows, `0x28080000`-`0x2813FFFF` | no (the guest fence) |
| 3 | update, swap, and storage, `0x28140000`-end of NOR | yes |
| 4-7 | unused | locked invalid |

The fence refuses writes from every initiator, the Secure runtime included, so
guest images are installed before wolfBoot arms it and a scenario that
deliberately rewrites guest flash (`remeasureneg`) runs unfenced. The fence
bounds come from the same `WT_GUEST*_FLASH_*` values the wolfTrust build uses
(`tests/target/lib/rt700_fence.sh`), and the build refuses a layout whose guest
windows are not contiguous and 64 KiB aligned.

Build wolfTrust with `WT_GUEST_FLASH_WRP=1` and every required launch checks,
from the registers alone, that the SFP configuration is valid and sealed, the
initiator domain descriptor is valid and locked, and valid, hard-reset-locked,
write-denying descriptors cover the whole guest window with no write-granting
or unlocked descriptor overlapping it. Anything less refuses the launch. The
runners set this up per scenario:

```sh
tests/target/run_rt700_hardware.sh wrpfence   # fence armed: both guests run
tests/target/run_rt700_hardware.sh wrpoff     # no fence: both guests refused
tests/target/run_rt700_hardware.sh wrpneg     # the silicon refuses a fenced erase
TARGET=mimxrt700 tests/target/provisioning/provisioning_ctrl.sh verify-wrp
```

Because the fence is rebuilt on every boot and cleared by every reset, there is
no `set-wrp` or `clear-wrp` step: the probe always flashes a parked core with
the controller unfenced, and which wolfBoot is flashed decides the posture.

## Provisioning and life cycle

This section is the MIMXRT700 part of [Provisioning](Provisioning.md). That
page covers the shared flow (rehearse, validate, then lock), the command
table, the gates, and what a production lock does to the firmware. Here are
the MIMXRT700 states, the mock lock on the EVK, and the real lock, with output.

The life cycle lives in OTP fuses (`LC_STATE` and its redundant copy
`LC_STATE_RED`). Programming a fuse is permanent, and on this EVK
`LOCK_CFG3.LIFE_CYCLE_LOCK` is open, so nothing in silicon would stop it. Each
state therefore has two commands:

- **`advance <state>`** is the mock lock. It moves the life cycle only in the
  OTP shadow registers, which every hardware reset reloads from the fuses.
  `regress` resets the part back.
- **`lock <state>`** is the real lock. It burns the fuses.

| `LC_STATE` | NXP state | Nearest STM32H5 state | PSA life cycle wolfBoot hands wolfTrust |
| --- | --- | --- | --- |
| `0x03` | Develop (as the EVK ships) | Open | `0x1000` ASSEMBLY_AND_TEST |
| `0x07` | Develop2 | Provisioning | `0x2000` PSA_ROT_PROVISIONING |
| `0x0F` | In Field | Closed | `0x3000` SECURED with `DAUTHSTATUS` `0xAA`; `0x5000`/`0x4000` while debug is open; `0x0000` for any other encoding |
| `0xCF` | In Field Locked | Locked | as In Field |
| `0x1F` | In Field Return | none | `0x6000` DECOMMISSIONED |
| other, or copies disagree | NXP Blank, Fab, FA, Dev, Bricked, or corrupt | none | `0x0000` UNKNOWN |

The state names are NXP's, as SPSDK's life cycle check uses them. The STM32H5
column is only an orientation, because the two machines differ:
- The STM32H5 has a TrustZone Closed state and returns Closed parts to Open by
  regression.
- The MIMXRT700 has no TrustZone Closed. The life cycle is a thermometer code:
  each step only adds fuse bits.
- In Field Return is a one-way failure-analysis state, not a return to Develop.

All commands below use the single entry point with `TARGET=mimxrt700`:

```sh
export TARGET=mimxrt700
```

### Stage 1: prepare the production chain

Flash the production posture (the fenced wolfBoot and a `WT_GUEST_FLASH_WRP=1`
wolfTrust, verified by the `wrpfence` checks), then run the read-only
preflight:

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh restore
tests/target/provisioning/provisioning_ctrl.sh verify-wrp
tests/target/provisioning/provisioning_ctrl.sh discover
```

Output on the EVK:

```text
  [check] PASS  XSPI SFP configuration valid and sealed until reset
  [check] PASS  a locked, write-denying FRAD spans the guest windows (0x28080000-0x28140000)
  [check] PASS  launch-verified guest mask 0x00000003 (want 0x00000003)
  [check] PASS  launch-refused guest mask 0x00000000 (want 0x00000000)
  [check] PASS  guest0 done: FF-M connect verified, status 0x600D600D (600d600d)
  [check] PASS  guest1 done: FF-M connect verified, status 0x600D600D (600d600d)
PASS: hardware/wrpfence
  [check] PASS  guest fence armed FRAD2 acp=0x00000000 word3=0xa0000000
  [check] PASS  SPSDK shadowregs supports mimxrt798s
  [check] PASS  fused life cycle is Develop and its redundant copy agrees
  [check] PASS  life cycle shadow over-ride is open (LOCK_CFG3 0x00000000)
  [check] PASS  the boot handoff life cycle is readable (0x00001000, ASSEMBLY_AND_TEST)
PASS: discovery stamped (~/.cache/wolftrust/mimxrt700/discovery)
```

`discover` gates `advance`. It requires the fused life cycle copies to agree,
and the shadow override to be open.

### Stage 2: rehearse a state (mock lock)

`advance` puts the part in the target state until the next reset, and
`regress`, after the validation in stage 3, brings it back. Together they are
the rehearsal that the real `lock` for that state requires. Nothing here is
permanent. Rehearse one state at a time: `advance 0x07`, stage 3, then the
same for `0x0F` and `0xCF`.

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh advance 0x07
```

Output on the EVK for Develop2:

```text
ADVANCING the life cycle shadow to 0x07 (develop2); regress or any reset undoes it
halted in wolfBoot at 0x28005910; shadow LC_STATE=0x07 LC_STATE_RED=0x07
wolfTrust saw 0x00002000 (PSA_ROT_PROVISIONING)
  [check] PASS  wolfTrust booted with the develop2 life cycle
  [check] PASS  guests launched (verified=0x00000003 refused=0x00000000)
  [check] PASS  the images on the part match the host build (8841d566395ee97b)
rehearsal of develop2 (0x07) recorded; 'regress' completes it
```

How `advance` works:
1. It halts the core inside wolfBoot, after the ROM has loaded the shadows and
   before wolfBoot reads them.
2. It writes both copies and resumes.
3. It checks that wolfTrust received the matching PSA life cycle. It then
   waits until every guest in `RT700_GUEST_MASK` (default `0x3`, both guests)
   has launched verified with none refused. In Field Return (`0x1F`) only
   needs the life cycle.
4. It reads the four flashed images back over SWD and compares them with the
   host build: the wrapped wolfBoot, the signed wolfTrust image, and both
   guests.
5. Only then does it record the rehearsal. The record holds the fused state,
   the SHA-256 of those four images, whether the guest fence was armed, and
   the time. `lock` accepts only a rehearsal with the fence armed, so rehearse
   the fenced chain that `restore` flashes.

Past Develop2, `advance` also requires a proven `regress`. That is a hardware
reset through the board's reset line, which the debug port cannot block.

### Stage 3: validate the rehearsed state, then regress

While the part is still in the mock state, check that it behaves like the
product you intend to ship, then `regress` to complete the rehearsal. Output
on the EVK after `advance 0xCF`, the mock locked state:

```text
$ tests/target/provisioning/provisioning_ctrl.sh status
OTP life cycle   LC_STATE=0xcf (in-field-locked)  LC_STATE_RED=0xcf
LOCK_CFG3        0x00000000 (LIFE_CYCLE_LOCK=0: 0 = shadow override and fuse burn both open)
DAUTHSTATUS      0x000000ff
XSPI SFP         MGC=0xa8000400 TG0MDAD=0xa000c000
guest fence      armed FRAD2 acp=0x00000000 word3=0xa0000000
wolfTrust saw    0x00005000 (RECOVERABLE_PSA_ROT_DEBUG)
guest launches   verified=0x00000003 refused=0x00000000

$ WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh regress
  [check] PASS  hardware reset reloaded the fused develop life cycle
  [check] PASS  wolfTrust booted ASSEMBLY_AND_TEST again
  [check] PASS  rehearsal of in-field-locked (0xCF) complete
```

Check four things:
- the life cycle copies agree;
- the guest fence is armed;
- both guests launched verified;
- wolfTrust received the life cycle you expect.

A shadow-only advance cannot close debug, because debug enablement is decided
from the fuses at boot. That is why this EVK attests `0x5000` rather than
`0x3000`. SECURED proper needs a part whose fuse configuration closes debug.

A refused command changes nothing and exits with status 2:

```text
$ WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh advance 0x0F
REFUSED: prove 'regress' from Develop2 before advancing to 0x0F.
$ tests/target/provisioning/provisioning_ctrl.sh burn
REFUSED: 'burn' programs OTP fuses, which is permanent on the MIMXRT700
```

### Stage 4: production lock

> **Production only. IRREVERSIBLE.** `lock` burns OTP fuses. A burned fuse can
> never be cleared, so a locked part never returns to an earlier life cycle
> state, and the software on it stays bound to the keys you locked it with.
> Never run `lock` on a development EVK: `LOCK_CFG3` is open on it, so nothing
> in silicon would stop the burn.

**What each state does to the part:**

- **Develop2 (`0x07`)** is the first production state. The part keeps
  development behaviour and can still move on, but never returns to Develop.
- **In Field (`0x0F`)** is the shipping state. From here on the BootROM
  applies the policy burned in the fuses:
  - debug access follows the fused debug configuration;
  - the root key table hash (RKTH) decides which signed first-stage images
    the ROM accepts.

  wolfTrust enforces guest rollback floors, never reformats the vault, and
  attests the new life cycle. See
  [what a production lock does to the firmware](Provisioning.md#what-a-production-lock-does-to-the-firmware).
- **In Field Locked (`0xCF`)** is final. No further life cycle step exists,
  including the field-return path.
- **In Field Return (`0x1F`)**, reached only from In Field, is also final. It is
  for failure analysis.

**How it binds the software.** After the lock, the software can only change
through wolfBoot's signed update path. It is held in place by:
- the fused RKTH;
- the wolfBoot signing key;
- the guest measurement records.

See [how a production lock binds the software](Provisioning.md#how-a-production-lock-binds-the-software).

> **Prerequisites not yet in the port, and enforced.** The reference chain boots
> wolfBoot as a plain XIP image that the BootROM does not authenticate. Locking
> the life cycle to In Field without ROM authentication would leave the first
> stage replaceable. So `lock` refuses In Field, In Field Locked, and In Field
> Return until the port builds wolfBoot as a ROM-signed image under a fused
> RKTH. Develop2 is the only burnable step today.

`lock` burns one step at a time, and only the next one:

| Command | Runs only when the fuses read | Burns | Also needs |
| --- | --- | --- | --- |
| `lock develop2` (`0x07`) | develop `0x03` | Develop2 | a fresh rehearsal of `0x07` with the current images and the guest fence armed; `WT_FIXTURE_BOUND=1` |
| `lock in-field` (`0x0F`) | develop2 `0x07` | In Field | **refused until ROM authentication** |
| `lock in-field-locked` (`0xCF`) | in-field `0x0F` | In Field Locked (final) | **refused until ROM authentication** |
| `lock in-field-return` (`0x1F`) | in-field `0x0F` | In Field Return (final) | **refused until ROM authentication** |

The burn runs over the ISP USB link, and no chip identity is documented that
both the SWD rehearsal and ISP can read. So every RT700 burn needs
`WT_FIXTURE_BOUND=1`, set only on a fixture that wires the debug probe and ISP
USB to one socket. On top of [the shared gates](Provisioning.md#the-lock-gates),
`lock` checks these on this port:
- It reads the life cycle from the burned fuses over the ISP connection, not
  from the shadows that `advance` changes.
- The life cycle words must hold nothing above the state byte, which is the B0
  layout. A0/A1 silicon keeps a bit-protection copy of each byte in bits
  16-23; that burn encoding is not validated, so `discover` and `lock` refuse
  those parts.
- It needs a rehearsal of that exact state, with the SHA-256 of the four
  images the runner flashes, from a fused state earlier in the ladder. The
  rehearsal read those images back from the part; the burn runs over ISP and
  does not read them again. Develop2 leaves the flash writable after the burn,
  so this binds nothing that a later reflash could not change. A burn into
  In Field or later will need a live read-back at burn time.
- The rehearsal must have run through the same debug probe that is attached
  now, and that probe must be the only one attached. The EVK's MCU-Link is
  soldered to the board, so this binds the record to the board; on a
  production fixture with its own probe, it binds the record to the station.
- The rehearsal must be recent: at most `WT_REHEARSAL_MAX_AGE` seconds old,
  one hour by default, and not dated in the future. No silicon UID is
  documented to bind a record to the part itself. On a fixture, the probe plus
  a fresh, single-use rehearsal stands in for that binding: rehearse the part
  in the fixture right before its own burn.
- Each burn uses its rehearsal up.

The steps below mix three kinds of output:
- The rehearsal output above was captured on the EVK.
- The preview and prompt come from the same script run offline against a
  stubbed `blhost`.
- The burn has never been run on a wolfTrust board, so its output is marked
  as expected.

1. **Rehearse and validate the step on this part**, as in stages 2 and 3,
   right before the burn.

2. **Preview the burn.** Put the part in ISP mode. Without `WT_LOCK_CONFIRM=1`,
   `lock` runs every check, prints the exact blhost script, and writes nothing:

   ```sh
   RT700_ISP='-u 0x1fc9,0x014f' tests/target/provisioning/provisioning_ctrl.sh lock develop2
   ```

   ```text
   Lock step: develop (0x03) -> develop2 (0x07)
     checked: next state, rehearsal of develop2 (0x07) with images 8841d566395ee97b (240s ago), part identity not readable here (needs WT_FIXTURE_BOUND=1), same debug probe 2GMGHYXZEONQS
     will run: blhost -u 0x1fc9,0x014f efuse-program-once 0x25 00000007 --no-verify
     will run: blhost -u 0x1fc9,0x014f efuse-program-once 0x8F 00000007 --no-verify
   REFUSED: preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1.
   ```

   Each line is a permanent fuse write. `lock` burns only the two life cycle
   words, the redundant copy first, each exactly the requested state. After
   the burn it requires the low byte of both words to be the new state, with
   the upper bits unchanged.

   > **Not yet burnable: the root key hash and debug root.** `lock` refuses a
   > fuse configuration file. The burn runs over the ISP USB link, and no chip
   > identity is documented that both the SWD rehearsal and ISP can read, so
   > nothing would stop such a file being burned into a different part than the
   > one rehearsed.

   > **Fixture required for the burn.** The same gap applies to the life
   > cycle step: the rehearsal is bound to the debug probe, but the burn goes
   > over ISP USB. `lock` therefore burns only with `WT_FIXTURE_BOUND=1`,
   > which a station sets only on a fixture whose single socket wires both the
   > probe and ISP USB to the part. Without it, `lock` stops after the preview.

3. **Burn it**, on the production station only:

   > **Warning:** this step is permanent. After it, the part can never return
   > to Develop.

   ```sh
   export WT_PRODUCTION_LOCK=1 WT_FIXTURE_BOUND=1 RT700_ISP='-u 0x1fc9,0x014f'
   WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh lock develop2
   ```

   After the same preview it asks, and only a person at a terminal typing the
   acceptance exactly continues:

   ```text
   !!! Burning life cycle Develop2 (0x07) into this MIMXRT700's fuses
   !!! This is IRREVERSIBLE: fuses cannot be unburned, and the part never returns to Develop.
   !!! Are you sure? Type "I ACCEPT 0x07" to continue: I ACCEPT 0x07
   ```

   Expected output: blhost prints one status per fuse. `lock` then reads both
   life cycle fuses back, and fails unless they carry the new state.

   ```text
   Response status = 0 (0x0) Success.
   Response status = 0 (0x0) Success.
     [check] PASS  life cycle fuses are Develop2 (0x07); reset the part, then run: tests/target/provisioning/provisioning_ctrl.sh status
   ```

   The two life cycle copies are separate fuse words. A burn interrupted
   between them leaves them disagreeing, which wolfBoot reports as UNKNOWN, so
   keep the station powered and the ISP link stable.

4. **Verify.** Reset the part and run `status`. Expected: both life cycle
   copies at the burned value, the guest fence armed, both guests verified,
   and wolfTrust receiving `0x2000`:

   ```text
   OTP life cycle   LC_STATE=0x07 (develop2)  LC_STATE_RED=0x07
   guest fence      armed FRAD2 acp=0x00000000 word3=0xa0000000
   wolfTrust saw    0x00002000 (PSA_ROT_PROVISIONING)
   guest launches   verified=0x00000003 refused=0x00000000
   ```

   Then run the production image's hardware scenarios.

A refused `lock` exits with status 2 and burns nothing. Refusals seen on the
EVK:

```text
$ tests/target/provisioning/provisioning_ctrl.sh lock 0x0F
REFUSED: In Field (0x0F) needs the BootROM to authenticate wolfBoot (a signed image under the fused root key hash), which this port does not build yet; see the MIMXRT700 Guide.
$ tests/target/provisioning/provisioning_ctrl.sh lock 0x07
REFUSED: set RT700_ISP to the blhost ISP connection (for example '-u 0x1fc9,0x014f').
$ RT700_ISP='-u 0x1fc9,0x014f' tests/target/provisioning/provisioning_ctrl.sh lock 0x07
REFUSED: cannot read the life cycle fuses over RT700_ISP (-u 0x1fc9,0x014f).
```

Refusals from the offline gate tests:

```text
REFUSED: the life cycle fuses disagree (LC 0x00000003, RED 0x00000007).
REFUSED: no rehearsal for develop2 (0x07) on this part with these images and credentials in the last 3600s: run 'advance 0x07' and 'regress' first.
REFUSED: confirmation did not match; nothing was changed.
```

Field returns go to In Field Return through NXP's debug credential flow. That
needs the debug credential root fused and a validated credential chain.
wolfTrust attests In Field Return as DECOMMISSIONED.

### Verified on the EVK

Every command was run on a MIMXRT700-EVK (fused Develop, `LOCK_CFG3` `0x0`)
on 2026-09-30, from an empty provisioning state directory, 31 steps in one
session. Commands that refuse exit with status 2 and change nothing:

| Command | Result |
| --- | --- |
| `set-perimeter`, `set-wrp`, `clear-wrp` | explains there is no persistent RT700 form, points at `restore` and `verify-wrp` |
| `provision-da`, `burn` | refused: fuse programming is permanent |
| `restore`, `regress`, `advance` without `WT_LOCK_CONFIRM=1` | refused before touching the board |
| `advance 0x5C`, `advance 0xFF`, `advance junk` | refused: only `0x07`, `0x0F`, `0xCF`, `0x1F` |
| `advance 0x07` before `discover` | refused: run `discover` first |
| `advance 0x0F` before a proven `regress` | refused |
| `restore` | fenced chain built, flashed, read back; both guests complete |
| `verify-wrp` | `armed FRAD2 acp=0x00000000 word3=0xa0000000` |
| `discover` | four checks pass; stamps the preflight |

`status` in each state (`MGC=0xa8000400`, `TG0MDAD=0xa000c000`, and
`DAUTHSTATUS=0x000000ff` throughout):

| State | `LC_STATE` / `LC_STATE_RED` | Handoff life cycle | Guest fence | Guests verified / refused |
| --- | --- | --- | --- | --- |
| fused, after `restore` | `0x03` / `0x03` | `0x1000` ASSEMBLY_AND_TEST | armed (FRAD2) | `0x3` / `0x0` |
| `advance 0x07` | `0x07` / `0x07` | `0x2000` PSA_ROT_PROVISIONING | armed | `0x3` / `0x0` |
| `advance 0x0F` | `0x0F` / `0x0F` | `0x5000` RECOVERABLE_PSA_ROT_DEBUG | armed | `0x3` / `0x0` |
| `advance 0xCF` (mock locked) | `0xCF` / `0xCF` | `0x5000` RECOVERABLE_PSA_ROT_DEBUG | armed | `0x3` / `0x0` |
| after each `regress` | `0x03` / `0x03` | `0x1000` ASSEMBLY_AND_TEST | armed | `0x3` / `0x0` |

Each `advance` halted the core inside wolfBoot (`pc` between `0x28004f6a` and
`0x28005394` across runs), wrote both copies, and read them back before
resuming. In the mock locked state the device runs its production posture, with
the fence armed and both guests launched, while the attestation stays below
SECURED because debug is open. Each `regress` restored the fused life cycle
through the reset line.

The rehearsal that `lock` requires was run on the same EVK for every state,
each `advance` followed by `regress`, with the fenced production chain:

| Rehearsal | Handoff life cycle | Guests verified / refused | Record |
| --- | --- | --- | --- |
| `advance 0x07`, `regress` | `0x2000` PSA_ROT_PROVISIONING | `0x3` / `0x0` | `fused=0x03 fence=armed` |
| `advance 0x0F`, `regress` | `0x5000` RECOVERABLE_PSA_ROT_DEBUG | `0x3` / `0x0` | `fused=0x03 fence=armed` |
| `advance 0xCF`, `regress` | `0x5000` RECOVERABLE_PSA_ROT_DEBUG | `0x3` / `0x0` | `fused=0x03 fence=armed` |
| `advance 0x1F`, `regress` | `0x6000` DECOMMISSIONED | not required | `fused=0x03 fence=armed` |

`lock 0x07` then refused without `RT700_ISP`, and with it refused because the
EVK was not in ISP mode, so the fuses could not be read. Nothing was burned.

After the security review the rehearsal was run again with the stricter
checks:
- `advance 0x07` required `verified=0x3 refused=0x0`.
- It read the four flashed images back and matched the host build.
- It recorded the full image SHA-256 with a timestamp.

`lock 0x0F` then refused, because the first stage is not ROM-authenticated.

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
- The guest fence and a shadow life cycle both end at the next hard reset, so a
  board can never be left stuck protected or advanced: flash from a parked core,
  or run `TARGET=mimxrt700 tests/target/provisioning/provisioning_ctrl.sh regress`.
- With an advanced shadow life cycle live, the device-pack reset sequence can
  fail with a FAULT ACK; `regress` resets through the board's reset line, which
  the debug port cannot block, and restores the fused state.
- Never program a life cycle, debug credential, or root key fuse on a
  development board. `LOCK_CFG3` is open on the EVK, so the silicon will not
  stop a burn, and none of it can be undone.

See [Porting](Porting.md) for the generic port contract, [Testing](Testing.md)
for scenario selection, and [Security Model](Security-Model.md) for the policy
enforced after boot.
