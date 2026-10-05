# Porting

wolfTrust separates reusable policy and services from architecture, device,
and board-specific execution. The fully silicon-validated build tuple is
`armv8m-stm32h563`. A second Armv8-M tuple, `armv8m-mimxrt700` (external
octal-NOR execute-in-place), is in hardware bring-up and reuses the
architecture adapter unchanged; see the [STM32H5 Guide](STM32H5-Guide.md) and
[MIMXRT700 Guide](MIMXRT700-Guide.md) for the two worked examples. A third
tuple, `aarch64` with the `qemuvirt` and `versal` targets, is validated under
QEMU (`versal` builds the `xlnx-versal-virt` model today). Support for
additional ports is an intended extension point. Such ports may reuse common
policy and service code and an existing architecture adapter when their
execution and protection models match.

Every new port must report its actual capabilities and must not claim
security properties until they are tested on that target.

## Port layers

| Layer | Location | Responsibility |
| --- | --- | --- |
| Common core | `src/` excluding `src/arch/` | Boot sequence, domains, manifest validation, monitor policy, IPC state, lifecycle, guest verification, recovery, services, and the Secure Partition entry bodies; names no architecture or SoC |
| Public and internal contracts | `include/psa/` and `include/wolftrust/` | PSA APIs, SPM types, the two port contracts (`arch.h`, `platform.h`), manifests, and service interfaces |
| Architecture-neutral gate | `src/arch/common/` | Secure Partition gate dispatch, fault recovery, scheduler, the SP-side PSA API, and the NS FF-M gateway bodies, written once over the `wolftrust/arch.h` primitives and linked by every architecture |
| Architecture | `src/arch/<arch>/` and `include/wolftrust/arch/<arch>/` | Every `wt_arch_*` operation: reset entry, guest context save/restore, exception entry and return, the secure tick, interrupt masking and routing, memory-protection programming, the SP trap and its decoder, NS range checks, and the NS entry mechanism (Armv8-M: CMSE veneers) |
| SoC and board | `port/<soc>/` | Every `wt_platform_*` operation plus the SoC facts: clocks, fabric-level TrustZone filter windows, the memory-protection region tables, UART, flash, entropy, reset, the memory map, guest tables, and the manifest |
| Build | `mk/common.mk`, `mk/arch-<arch>.mk`, `mk/target-<soc>.mk` | Shared rules; toolchain and architecture sources; SoC sources, placement, and image checks |
| Guest integration | `tests/firmware/` or an application repository | Application-domain linker layout, PSA client shim, architecture-specific client boundary, and OS wiring; Armv8-M uses a CMSE import library |

## Current architecture and target contract

The common runtime treats `wt_guest_context_t` and `wt_trap_frame_t` as
opaque, architecture-owned types, and describes memory as
`wt_memory_region_t` lists that carry attributes, never protection-unit
encodings. Two headers split the port contract:

- `include/wolftrust/arch.h` declares the `wt_arch_*` operations an
  architecture implements once for every SoC that uses it: boot setup, the
  secure tick, interrupt masking and routing, guest and partition domain
  programming, guest context prepare/capture/restore, the transitions between
  handler mode, Secure threads and guest threads, fault address and PC
  reads, barriers, privilege queries, the Secure Partition trap and its
  frame-level helpers, deliberate test faults, and the NS range checks.
- `include/wolftrust/platform.h` declares the `wt_platform_*` operations an
  SoC implements: initialization, fabric-level memory windows, fault logging,
  guest measurements, guest-flash write-protection checks, panic, reset,
  the boot-handoff region, the image windows every partition shares, the
  conformance grants, and the test-build probes.

For the supported Armv8-M and STM32H563 pair, `src/arch/armv8m/` supplies
the `wt_arch_*` operations (reset entry, context switching, the exception
handlers, the virtual SysTick, NVIC routing, table-driven SAU and MPU
programming, the SVC trap decoder, the CMSE checks, and the five NS veneers),
`src/arch/common/` supplies the architecture-neutral gate, scheduler, SP-side
PSA API and NS gateway bodies on top of them, and
`port/stm32h563/platform_stm32h563.c` implements the `wt_platform_*`
operations together with the SoC's SAU and MPU region tables.

A port declares what its hardware can do through the capability bits in
`include/wolftrust/partition.h`; the core refuses a manifest that assumes a
capability the port does not provide, so an A-profile port that has no
Non-secure MPU says so instead of faking it.

## MCU and board contract

A target directory must provide:

### Platform operations

Implement every `wt_platform_*` operation in `include/wolftrust/platform.h`
used by the selected build: initialization (which calls `wt_arch_init()`
once the fabric and memory windows are programmed), fabric-level memory
windows, fault logging, guest measurements, guest-flash write-protection
checks, panic, reset, the boot-handoff region, the shared image windows
every partition's thread table starts with, the conformance grants, and the
test-build probes. Never define a `wt_arch_*` operation in a port; the split
guard rejects that.

Do not return unconditional success for a missing security mechanism. Report
the capability accurately and reject a manifest that requires more.

### Guest and capability tables

Implement the declarations in `include/wolftrust/partition.h`:

```c
const wt_guest_config_t* wt_partitions_config_table(size_t* count);
wt_guest_runtime_t* wt_partitions_runtime_table(size_t* count);
const wt_profile_capabilities_t* wt_partitions_profile_capabilities(void);
int wt_partitions_bind_manifest(const wt_system_manifest_t* manifest);
void wt_partition_reset_runtime(const wt_guest_config_t* config,
                                wt_guest_runtime_t* runtime);
```

Guest executable and RAM windows, vector-table access, IRQ ownership, restart
policy, launch policy, and minimum version must match the actual linker and
hardware layout.

The capability bitmap can declare security state, privilege state, RoT
isolation, domain isolation, memory protection, interrupt isolation, and
restart. The validator rejects a domain whose requirements exceed the port's
declaration.

### Persistent flash

Implement `include/wolftrust/port_nvm.h`:

```c
extern const whFlashCb g_wt_hsm_flash_cb;
void* wt_hsm_flash_context(void);
const void* wt_hsm_flash_config(void);
int wt_hsm_flash_format(void);
```

Both crypto engines use this object store. The implementation must preserve
the wolfHSM NVM flash-log semantics, distinguish foreign or corrupt media,
honor checked object flags, and erase only the dedicated vault region when
lifecycle policy allows reformat. See [Crypto Engines](Crypto-Engines.md) for
the engine boundary above the common store.

### Entropy

The current Secure wolfCrypt profile maps
`CUSTOM_RAND_GENERATE_BLOCK` to:

```c
int wolftrust_rng_generate_block(unsigned char* output, unsigned int sz);
```

The STM32H563 callback uses wolfHAL's H5 RNG driver. Its unprivileged entry
traps to a privileged SVC operation. A new target must provide an equivalent
approved entropy source and preserve the privilege boundary.

### Board and memory layout

Provide target constants for:

- Secure, client-gateway, application-domain, update, and persistent flash
  regions;
- Secure Partition, SPM, and guest RAM;
- target clocks, timer, UART, RNG, and security peripherals;
- flash erase and write geometry;
- guest vector-table read aliases, if required; and
- WRP or equivalent hardware-enforced guest-image write protection.

Represent the same resources in `manifest.json`. The generator rejects
bad attributes, overlap, missing stacks, unsupported sharing, invalid signals,
dependency cycles, and unsupported features.

## Bootloader contract

The reference integration expects wolfBoot to:

- authenticate wolfTrust;
- provide `wt_boot_handoff_t` with a SHA-256 measurement, lifecycle,
  and image version;
- reserve the configured wolfTrust image header;
- provide an update partition compatible with the FWU backend; and
- authenticate the staged replacement on reboot.

The handoff is consumed and cleared from Secure RAM. If a different first
loader is used, the port must provide equally authenticated lifecycle,
measurement, and version data and adjust the image layout.

A reference wolfBoot port for a new SoC adds a hardware abstraction layer
(`hal/<soc>.{c,h,ld}`: a debug console and a flash driver for the boot medium),
one or more `config/examples/<soc>*.config` entries, and a target section in
the wolfBoot documentation. The TrustZone configuration enables the generic
Secure-application handoff so the loader writes `wt_boot_handoff_t` to the
agreed Secure-RAM address and stays in Secure state across the jump. It signs
the wolfTrust image and, on parts without a ROM flash API, places the flash
path in RAM. The loader's flash map and the port's memory map must agree on the
Secure image base, the update partition, and the boot-handoff address; the
worked examples above give a concrete map for each board.

## Add a target

1. Add `src/arch/<arch>/` and `include/wolftrust/arch/<arch>/` only when
   the architecture cannot reuse an existing implementation; implement every
   `wt_arch_*` operation there and leave `src/arch/common/` untouched.
2. Create `port/<soc>/` with the platform, flash, entropy, board,
   memory-map, protection-region-table, partition-table, and manifest files.
3. Add `mk/arch-<arch>.mk` (if new) and `mk/target-<soc>.mk`; the root
   Makefile selects them from `ARCH` and `TARGET`, and `mk/common.mk` needs
   no change.
4. Supply startup/vector and linker handling appropriate to the target. On
   Armv8-M, give every object the port links an owner in
   `tools/secure_owners.txt`, which the post-link layout check reads.
5. Generate the manifest at build time; the generated source embeds its
   digest in the Secure image, which a target with an authenticated first
   stage signs.
6. Integrate application domains with the architecture's client boundary and
   matching generated service IDs. Armv8-M targets link Non-secure guests
   against the CMSE import library.
7. On a target with separately built Normal-world guest images (the
   Armv8-M ports today), add image assembly that patches guest ID, version,
   size, and digest records before signing wolfTrust.
8. Add safe provisioning tooling for the target's security attribution,
   application-image write protection, debug policy, and product lifecycle.
9. Implement isolation level 3. Level 3 is required for a new port unless
   the port specifically targets level 1 or 2, which would first need those
   levels implemented. On AArch64, reuse the shared
   layer in `port/common/aarch64/` (below): `mk/arch-aarch64.mk` gates it with
   `WT_ISOLATION_LEVEL` (default `3`), and since only level 3 exists today any
   other value stops the build. The manifest's `isolation_profile` states the
   claim separately: `3`, or `0` (no claim) on a target that cannot yet fence
   the Secure bands.

## AArch64 targets

An AArch64 SoC port adds:

- `mk/target-<soc>.mk`: the EL3 text and RAM bands, the boot CPU count, and
  whether the loader already configured the UART and the counter frequency;
- `port/<soc>/memory_map.h`, `el3_board.c`, and `uart.c` for the monitor;
- `port/<soc>/l3_port.h` for the level 3 layer (below);
- `port/<soc>/manifest.json`, whose optional `ffa` section gives each Secure
  Partition's FF-A properties (see [Building](Building.md)).

The QEMU targets share their Secure EL1 platform code in
`port/common/aarch64/`: the `wolftrust/platform.h` operations, the partition
entry table, a RAM-backed NVM, and a test entropy source that a silicon port
must replace. The EL3 monitor archive `libwt_el3.a` may reference only the
port hooks listed in `tools/el3-symbols.allow` (`wt_platform_board_init`,
`wt_platform_board_system_reset`, the console pair), may define globally only
the monitor symbols `tools/el3-defines.allow` names, and must define no SPM,
service, or crypto code; the link rule runs `tools/check-el3-symbols.sh` on
every build and again whenever either list changes. `wt_platform_board_system_reset`
performs the machine cold reset of PSCI `SYSTEM_RESET` and does not return:
`virt` drives the restart line of its Secure PL061, and `xlnx-versal-virt`,
whose model leaves its reset blocks unimplemented, powers the model off with
the reset exit code for the runner to power it on again. A hook that returns
panics the monitor. A silicon port must also
fence the Secure bands from the Normal world in hardware (a TZASC, XMPU, or
RISAF): QEMU `virt` models the fence with its secure memory, and
`xlnx-versal-virt` does not model one. The port's `memory_map.h` states which
through `WT_PORT_NS_MEMORY_FENCE`, and only a port that sets it to `1` claims
security-state isolation. Every isolation level needs that capability, so the
core refuses a Level 1, 2, or 3 manifest on an unfenced port. The `qemuvirt`
manifests declare Level 3; the `xlnx-versal-virt` manifests declare
`isolation_profile` 0 (service only) and claim no isolation level. A Versal
silicon port sets the flag only once it programs
and locks the XMPU over the Secure bands before the Normal world runs.

### Isolation level 3 on AArch64

Every AArch64 port reuses the level 3 layer in `port/common/aarch64/`
instead of writing it again; whether the port claims level 3 is its
manifests' choice (below):

- `l3_layout.h` places the Secure EL1 bands at default offsets from the
  port's 1 MiB aligned `WT_L3_BAND_BASE`: the SPMC image, its RAM, the
  conformance data window, the keystore window, the RX/TX and shared pages,
  and the FF-A ACS window. The vault, attestation and crypto bands tile the
  keystore window exactly. The boot-information page and the default stage-1
  table pool open `WT_RAM_S_BASE`; a band macro defined before the include
  (the runner moves the table pool for the ACS) takes precedence.
- `platform_l3.c` holds the level 3 platform operations: the code every
  partition maps, the empty partition peripheral table, the SPM-private RAM,
  the privileged-stack check, the conformance data window and the test-build
  probe addresses. `conf_backend.c`, built only with `WT_CONFORMANCE=1`, holds
  the per-partition conformance grants.
- `tools/aarch64_l3_layout.py` reads the layout from the port's
  `memory_map.h` for the compiler, the linker and the target runner, and
  after the link checks that the port's manifest grants exactly the keystore
  bands those same values place. An unreadable layout stops the build.

A port using the shared layer supplies:

- in `memory_map.h`, a literal `WT_L3_BAND_BASE` and `WT_RAM_S_BASE`, then
  `#include "../common/aarch64/l3_layout.h"`; a port that claims level 3
  places them in Secure memory the board fences from the Normal world;
- `l3_port.h`, naming a Secure peripheral only the SPM drives as
  `WT_L3_SPM_PERIPHERAL_BASE`;
- manifests whose vault, attestation and crypto partitions are granted the
  three keystore bands.

No band address is written twice. A port's manifests state its claim: the
`qemuvirt` manifests declare `isolation_profile` 3, and the `versal`
manifests declare profile 0 because the model cannot fence the Secure bands.
A port claiming level 3 runs every scenario in `QEMU_A_L3_REQUIRED`
(`tests/target/lib/scenario_matrix.py`) in its full QEMU tier.
`scenario_matrix.py --selftest`, run in CI, fails when the suite drops a
required scenario or a cell's `l3_exempt` entry names no required scenario or
gives no reason; `versal-virt` lists `secramneg` and `periphneg` there, citing
#45.

## Validation checklist

- Run `make test` for common policy and service behavior.
- Run `WT_SPLIT_STRICT=1 tools/check-core-port-split.sh` and resolve
  hard core-to-architecture leaks (arch or port headers, CMSE, inline
  assembly, retired names, M-profile or A-profile register vocabulary in
  core code, and `wt_arch_*` definitions inside a port).
- Run `tools/check-port-only-diff.sh <base> <arch> <soc>` on a port change
  and confirm it touches nothing outside `src/arch/common/`,
  `src/arch/<arch>/`, `include/wolftrust/arch/<arch>/`, `port/<soc>/`, the
  two build fragments, tests, docs, and workflows.
- Run `tools/check-docs-no-internal-links.sh`; `docs/` is published to the
  wiki and must not reference internal ledgers or developer paths.
- On an AArch64 port, run `tools/check-el3-symbols.sh <libwt_el3.a>`: the
  EL3 monitor archive may leave unresolved only the hooks listed in
  `tools/el3-symbols.allow`, may define globally only the symbols
  `tools/el3-defines.allow` names, and must define no SPM, service, or crypto
  code.
- Cross-build the Secure image with warnings enabled.
- On the current Armv8-M port, inspect `nm` output and confirm only the five
  FF-M veneers are Non-secure-callable.
- On silicon, prove a Non-secure call reaches the Secure side. An IDAU can
  override an SAU Non-secure-callable region (the MIMXRT700 honours NSC only in
  the Code region), which shows up as an INVEP SecureFault despite a correct SG
  instruction.
- Budget the Secure MPU regions against the part's `MPU_TYPE.DREGION`; the
  whitelist, any executable RAM (for example code that must run while the boot
  NOR is busy), and Secure Partition domains share them.
- On a hardware runner, verify every flashed image by readback, start from a
  fresh vault store, and reset through a line the running Secure image cannot
  veto; a stale image or persisted rollback floor looks like a port bug.
- Claim the fabric filter only after a silicon negative passes: a privileged
  guest disables its own Non-secure MPU and stores into another guest's RAM,
  and the store must not land. Programming the fabric rules is not evidence
  that they govern those addresses.
- Test invalid manifests, memory overlap, pointer ranges, stale handles,
  cross-owner access, and unsupported capabilities.
- Run authenticated boot, guest tamper, rollback, restart, Secure Partition
  fault, storage recovery, and update tests in an architecture-accurate
  emulator when one exists.
- Verify attribution, interrupts, entropy, flash failure, WRP-equivalent
  coverage, reset, and recovery on physical hardware.
- Keep emulator and hardware evidence distinct.

See [Architecture](Architecture.md), [Building](Building.md), and [Testing](Testing.md) for the current reference
implementation.
