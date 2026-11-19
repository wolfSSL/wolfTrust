# Porting

A new Armv8-M SoC meeting the contracts on this page registers itself in
`port/<soc>/port.json` and lands with zero handwritten edits to shared
implementation code; the generated outputs (`docs/Ports.md`) regenerate by
tool. That is the guarantee this page documents, and it is scoped to
Armv8-M: reuse by a Cortex-A port is a design goal, not a claim.
`tools/new-port/PLAYBOOK.md` is the agent-facing order of work with its
gates; this page is the human guide.

wolfTrust separates reusable policy and services from architecture, device,
and board-specific execution. The registered ports, each with its guide and
its validation status, are in [Ports](Ports.md); every one reuses the Armv8-M
architecture adapter unchanged. The `aarch64` tuple, with the `qemuvirt` and
`versal` targets, is validated under QEMU (`versal` builds the
`xlnx-versal-virt` model today) and is not in that registry yet; see
[AArch64 targets](#aarch64-targets).

Every new port must report its actual capabilities and must not claim
security properties until they are tested on that target.

## Port layers

| Layer | Location | Responsibility |
| --- | --- | --- |
| Common core | `src/` excluding `src/arch/` | Boot sequence, domains, manifest validation, monitor policy, IPC state, lifecycle, guest verification, recovery, services, and the Secure Partition entry bodies; names no architecture or SoC |
| Public and internal contracts | `include/psa/` and `include/wolftrust/` | PSA APIs, SPM types, the two port contracts (`arch.h`, `platform.h`), manifests, and service interfaces |
| Architecture-neutral gate | `src/arch/common/` | Secure Partition gate dispatch, fault recovery, scheduler, the SP-side PSA API, and the NS FF-M gateway bodies, written once over the `wolftrust/arch.h` primitives and linked by every architecture |
| Architecture | `src/arch/<arch>/` and `include/wolftrust/arch/<arch>/` | Every `wt_arch_*` operation: reset entry, guest context save/restore, exception entry and return, the secure tick, interrupt masking and routing, memory-protection programming, the SP trap and its decoder, NS range checks, and the NS entry mechanism (Armv8-M: CMSE veneers) |
| Shared port layer | `port/common/<arch>/` | The isolation level 3 secure RAM layout, its linker fragments and the level 3 `wt_platform_*` hooks, written once per architecture and linked by every port of it |
| SoC and board | `port/<soc>/` | Every `wt_platform_*` operation plus the SoC facts: clocks, fabric-level TrustZone filter windows, the memory-protection region tables, UART, flash and entropy drivers, reset, and the memory map the shared guest tables and the generated manifest read |
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
`port/common/armv8m/` supplies the isolation level 3 layout, the platform
skeleton and the SAU guest-window backend every Armv8-M port shares, and
`port/<soc>/platform_<soc>.c` supplies the port's hooks together with the
SoC's SAU and MPU region tables.

Armv8-M ports share the profile limits in
`port/common/armv8m/platform_caps.h`, with matching generator values in
`mk/arch-armv8m.mk`; the capability bits are in `include/wolftrust/domain.h`
and `include/wolftrust/partition.h`. A port whose enforcement capabilities
differ defines `WT_PORT_CAPABILITIES` in `port/<soc>/memory_map.h` and the
same value as `WT_PLATFORM_PORT_CAPABILITIES` in `mk/target-<soc>.mk`. The
manifest generator refuses, at build time, a manifest that assumes a
capability the port does not provide, and the generated manifest fails to
compile if the C and generator views differ.
An A-profile port that has no Non-secure MPU says so instead of faking it.

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

### Isolation level 3

A new port must implement isolation level 3 unless it specifically targets
level 1 or 2. `WT_ISOLATION_LEVEL` (default 3) selects the level the secure
image implements and gates the shared level 3 layer; only level 3 exists
today, so any other value stops the build.

Every port of an architecture gets level 3 from `port/common/<arch>/`
instead of writing it again. For Armv8-M that layer provides:

- `l3_layout.h`: the per-partition keystore bands, partition stacks, the
  conformance data window and the VNET band, stacked upward from
  `WT_RAM_S_BASE`;
- `secure_l3_memory.ld`, `secure_l3_symbols.ld`, `secure_l3_bands.ld` and
  `secure_l3_tail.ld`: the matching linker regions, stack symbols, band
  output sections and layout ASSERTs; and
- `platform_l3.c`: the boot-handoff region, the shared image windows, the
  SPM-private RAM, the privileged-stack check, the peripheral table, the
  conformance grants and the test-build probe addresses.

A port supplies:

- in `memory_map.h`, a literal `WT_RAM_S_BASE` and `WT_RAM_S_SIZE`, then
  `#include "../common/armv8m/l3_layout.h"`. The layout needs
  `WT_L3_SPM_RAM_SIZE` plus 20.5 KiB for the keystore bands and partition
  stacks, 4 KiB more with `WT_FWU=1` and 36 KiB more in conformance builds.
  The SPM RAM window also holds the crypto partition's stack and data band,
  sized per engine (5.5 KiB native, 34 KiB wolfHSM), and the VNET band. The
  default window is 308 KiB; a part with less SRAM gives a smaller one under
  `#ifndef` before the include (the Make variable of the same name overrides
  it for every consumer at once), and the build fails if the layout does not
  fit.
  Define `WT_RAMFUNC_BASE` and `WT_RAMFUNC_SIZE` if the SPM runs code from
  RAM, and set `WT_LD_RAM_CODE_BAND := 1` in `mk/target-<soc>.mk` so the
  shared linker script (`port/common/armv8m/secure.ld.in`) places the NSC
  gateway and the flash program code there;
- in `memory_map.h`, a Secure peripheral only the SPM drives as
  `WT_L3_SPM_PERIPHERAL_BASE`, the guests' console window
  (`WT_GUEST_UART_BASE`, `WT_GUEST_UART_SIZE`), the NSC window
  (`WT_NSC_BASE`, `WT_NSC_END`) and the flash geometry, then
  `#include "../common/armv8m/memory_map_check.h"` last, which refuses a map
  whose guest windows, stores or RAM overlap or miss their alignment;
- nothing for the guest tables: `port/common/armv8m/partitions.c` builds
  them from `memory_map.h` (a port whose fabric filter attributes memory in
  blocks larger than the MPU granule defines `WT_GUEST_WINDOW_GRANULE`, and
  one whose guests use different consoles defines
  `WT_GUEST0_CONSOLE_BASE` and `WT_GUEST1_CONSOLE_BASE`);
- `flash_drv.c` and `rng_drv.c`, the device primitives behind the shared
  store, FWU and entropy backends (see Persistent flash and Entropy below),
  with `WT_FLASH_PROGRAM_UNIT` and `WT_FWU_TRAILER_SIZE` in `memory_map.h`;
- attribution read-back for every Secure peripheral the SPM uses, panicking
  at boot on a mismatch; and
- owner lines for every object it adds, in `tools/secure_owners.txt` or in
  the port's own `port/<soc>/secure_owners.txt`, which the secure link
  appends to the shared map.

The build resolves every layout input once (`mk/layout.mk`,
`WT_LAYOUT_CFLAGS`) and reads `WT_RAM_S_BASE`, the band placement for the
linker, the post-link band check and the guest windows from `memory_map.h`
under that one configuration, so no address is written twice and the
firmware, the linker script, the layout check, the guest builds and the host
fixtures cannot disagree (`tests/host/layout_config` proves it for every
registered port).

Level 3 is claimed for a port only when its full M33MU tier runs every
scenario in `L3_REQUIRED` (`tests/target/lib/scenario_matrix.py`). A scenario
a port cannot run yet goes in that port's `l3_exempt` map with the open issue
that tracks it; `scenario_matrix.py --selftest`, run in CI, fails on a
missing scenario, an exemption without a reason, or an exemption for a
scenario the port already runs.

The emulator scenarios themselves are one table (`tests/target/lib/scenarios.py`)
run by one runner (`tests/target/run_target.sh <port> <scenario>`) over the
port's profile (`tests/target/ports/<port>/m33mu.sh`: emulator pin and patch,
first-stage recipe, image offsets, signing geometry). The port's registry
entry says how the table applies to it: `m33mu.guests` names the guest pair
per role (bare-metal, PSA, Zephyr, FreeRTOS, wolfIP), `caps_absent` names the
capabilities the port lacks with a reason (every scenario that needs one is
then exempt, and every assertion block that needs one is reported N/A),
`faults_by_design` names the scenarios whose guest or partition faults on
purpose so the emulator must not stop on the fault, `ends` names the
scenarios whose run the port ends at the partition's deliberate fault
instead of the guest's clean breakpoint, `guest_flags` adds the port's own
guest build flags to a scenario (the FWU stream probe's sizes),
`iso_refusal_src` names the block that refuses `guestisoneg`'s cross-guest
store in the trace (`SAU` by default, `MPCBB` where the GTZC block curtain
decides it), and `exempt` names any other scenario the port does not run with
its reason. `scenarios.py
--selftest` fails a port that neither runs nor exempts a scenario, lists a
port-private name, or names a scenario in its profile outside a case label.

### Guest and capability tables

`port/common/armv8m/partitions.c` implements `include/wolftrust/partition.h`
for every Armv8-M port from `memory_map.h`: each guest's flash and RAM
windows (`WT_GUEST0_RAM_SIZE` and `WT_GUEST1_RAM_SIZE` may differ), its
console, the NSC window and `WT_PORT_CAPABILITIES`. A port ships no
`partitions.c` of its own; the registry self-test refuses one, since the
build would link it in place of the shared table.

The capability bitmap can declare security state, privilege state, RoT
isolation, domain isolation, memory protection, interrupt isolation, and
restart. The validator rejects a domain whose requirements exceed the port's
declaration.

### Test guests

Every port builds the same Non-secure test guests, and its registry entry
(`m33mu.guests`) names the kinds it runs: the STM32H563 runs its Zephyr and
FreeRTOS pair, so its bare-metal board seam (the GPDMA probe in `board.c`)
builds but no scenario runs it yet. `tests/firmware/baremetal-guest`
is the bare-metal lifecycle guest with the isolation, peripheral, fault,
handler and entry-mask probes, and `tests/firmware/psa-guest` is the PSA
client and conformance guest; both are built with `TARGET=<soc>` and take
the board from `tests/firmware/boards/<soc>/`:

| File | Supplies |
| --- | --- |
| `board.h` | `GUEST_BOARD_NAME` (the console banner), `guest_board_uart_init`, `guest_board_uart_putc`, `guest_board_console_id`, `GUEST_SECURE_RAM_ADDR` (the restart probe's Secure read), `GUEST_PERIPH_NS_ADDR` (the SPM peripheral's Non-secure alias) and, when the board runs its own peripheral probe, `GUEST_BOARD_PERIPH_PROBE` |
| `board.mk` | `GUEST_ISO_PROBE_ADDR` (a word inside guest 1's RAM window) and `GUEST_BOARD_SRCS` (a `board.c` with the board's probe, if any) |

The probe flags are the same on every port: `WT_ISO_PROBE=1` stores into the
peer guest's window with the MPU off, `WT_PERIPH_NEG_PROBE=1` reaches the
SPM's peripheral, `WT_GUEST_FAULT_PROBE=1` reads Secure RAM on every launch.

### Hardware evidence

Every board runs the same eight scenarios on silicon, and they are the
contract a new port meets before anything else: `positive`, `guestisoneg`,
`periphneg`, `restart`, `psa`, `wrpoff`, `crossdomain` and `authneg`
(`tests/target/lib/scenarios.py --hardware-minimum`). `make test-hardware
TARGET=<soc>` runs them; `WT_HW_TIER=qualification` adds the extras the
port's registry names as its merge gate, and its `optin` list stays
board-only. The runner (`tests/target/run_hardware.sh <soc> <scenario>`)
builds the chain the emulator boots, programs it through the port's profile
(`tests/target/ports/<soc>/hw.sh`), captures the console, reads the Secure
image's latches and the guests' mailboxes over SWD into
`logs/<soc>-hw/<scenario>-<engine>/`, and hands that evidence to the same
judge the emulator uses with `--env hardware`.

The profile supplies `hw_detect`, `hw_probe_bind` (exactly one probe, bound
for every tool call), `hw_preflight` (reads the fixture and refuses with the
provisioning command that repairs it; empty where the fixture holds no state
the runner depends on, as on the MCXN947), `hw_program`, `hw_boot`, `hw_read32`
and `hw_readback`, plus optional `hw_first_stage`, `hw_collect` (the port's
own SWD words) and `hw_scenario_<name>` flows. No option byte, fuse or life
cycle state is written by the runner; `tests/target/test_hw_runner.sh`
checks that for every port under `make test`.

### Persistent flash

`include/wolftrust/port_nvm.h` (`g_wt_hsm_flash_cb`, `wt_hsm_flash_context`,
`wt_hsm_flash_config`, `wt_hsm_flash_format`) and the FWU staging backend are
implemented once, in `port/common/hsm_flash.c`, over the device primitives a
port supplies in `port/<soc>/flash_drv.c` (`port/common/flash_port.h`):

```c
int  wt_port_flash_read(uintptr_t s_addr, uint8_t* dst, uint32_t size);
int  wt_port_flash_program(uintptr_t s_addr, const uint8_t* src, uint32_t size);
int  wt_port_flash_erase(uintptr_t s_addr, uint32_t size);
int  wt_port_flash_blank_check(uintptr_t s_addr, uint32_t size);
void wt_port_flash_quiesce(void);
int  wt_port_flash_probe_tamper(uintptr_t ns_addr);   /* WT_REMEASURE_PROBE */
```

The shared backend owns every policy: the context a confined partition can
write holds no geometry, so each primitive is called with a privileged
thread and a range already checked against the immutable config its
context's identity names. Programs are aligned to
`WT_FLASH_PROGRAM_UNIT` and erases to `WT_FLASH_SECTOR_SIZE`; reads and
blank checks may cover any byte span inside the checked region. FWU staging
is sequential from offset 0 with an erase high-water mark, so a candidate
of any sector count erases each sector once, and the last
`WT_FWU_TRAILER_SIZE` bytes belong to arm and disarm alone. The wolfHSM
store unit is 16, so the program unit must divide 16. Both crypto engines
use this store; see [Crypto Engines](Crypto-Engines.md) for the engine
boundary above it.

| Primitive | On success | On failure |
| --- | --- | --- |
| `read` | `dst` filled | `WH_ERROR_ABORTED` and `dst` zeroed; never halts |
| `program`, `erase` | the range changed | `WH_ERROR_ABORTED` (device; also a unit programmed twice where the device does not report that apart), `WH_ERROR_NOTBLANK` (a unit programmed twice, where it does); the range may be partly changed and the backend treats it as dirty; interrupt state restored on every return; staged plaintext wiped |
| `blank_check` | `WH_ERROR_OK` | `WH_ERROR_NOTBLANK`, or `WH_ERROR_ABORTED` for a device fault |
| `quiesce` | controller relocked, device idle | bounded: a wedged controller still returns, so the reset that follows can happen |

Whether a read fault is contained depends on the device, and a port claims
only what it implements:

| Port | Read-fault containment |
| --- | --- |
| STM32H563 | An ECC double error inside the read raises the NMI; the handler marks the window and the read returns `ABORTED` with zeroed data. |
| MIMXRT700 | A volatile copy through the XIP alias; the NOR's behaviour on a faulting phrase is not established. |
| MCXN947 | A volatile copy through the Secure alias; the ROM verifies erases and blank checks, and the behaviour of a mapped read of an erased or faulting phrase is not established. |

`tests/host/port_flash` links the production backend and each port's
`flash_drv.c` against a model of the device beneath it and runs the store,
staging, conformance sync, gate and failure paths for every registered port.

### Entropy

The `CUSTOM_RAND_GENERATE_BLOCK` source is implemented once, in
`port/common/rng_entropy.c`, over the port's `port/<soc>/rng_drv.c`
(`port/common/rng_port.h`): `wt_port_rng_init` runs once and is retried
after a failure; `wt_port_rng_fill` delivers the whole request or fails,
after which the shared source zeroes the caller's buffer and refuses every
later request until reset, since a failed request may still complete (a
late DMA page on the MCXN947 lands in the driver's reserved static page,
never in reused memory). A fill never serves a word an earlier request saw.
`tests/host/h5_rng`, `rt700_trng` and `mcxn947_rng` prove this on each
driver over a model of its device.

### Platform hooks

`port/common/armv8m/platform_armv8m.c` owns `wt_platform_init` and every
neutral `wt_platform_*` operation (fault logging, panic, the bounded reset
through `wt_port_flash_quiesce`, the per-dispatch guest windows, the
conformance interrupt source, the probes). A port supplies the hooks of
`port/common/armv8m/platform_port.h`, which that header documents with
their order and guarantees:

| Hook | Runs | Owes |
| --- | --- | --- |
| `wt_port_boot_init` | first | clocks, any RAM code band staged through the alias it is written by, the fabric rules the tables assume; no guest RAM touched |
| `wt_port_fabric_init` | after the gateway and vector table | the fabric filter programmed and read back (nonzero refuses the boot) |
| `wt_port_sau_regions`, `wt_port_mpu_s_regions` | before the arch layer | const tables |
| `wt_port_late_init` | after guest RAM is cleared | console clocks and pins, fabric checking that must follow the clear, silicon checks (nonzero refuses) |
| `wt_port_fabric_windows` | every dispatch | the SAU backend (`fabric_sau.c`) or the port's own curtain |
| `wt_port_conf_irq_set` | conformance builds, on the DRIVER partition's request | the PAL interrupt raised from its peripheral (STM32H563: LPUART1 TXE), or `wt_platform_conf_irq_pend` where no peripheral drives it |

The shared SAU backend refuses, by a panic, a window that is misaligned,
overflows, overlaps an open one, exceeds the SAU's regions or does not read
back; `tests/host/fabric_sau` proves each refusal over a model of the SAU.

### Board and memory layout

Provide target constants for:

- Secure, client-gateway, application-domain, update, and persistent flash
  regions;
- Secure Partition, SPM, and guest RAM;
- target clocks, timer, UART, RNG, and security peripherals;
- flash erase and write geometry;
- guest vector-table read aliases, if required; and
- WRP or equivalent hardware-enforced guest-image write protection.

The manifest needs no port copy: `manifest/base.json` names every window by
its `memory_map.h` macro (the guest flash, RAM and console windows, the SPM
stack, the partition stacks and keystore bands, `WT_CONF_IRQ`), and
`tools/manifest/render.py` renders it for the port under the build's layout
configuration. A port only defines those macros; `tests/host/manifest_render`
checks every rendered window against them. The generator rejects bad
attributes, overlap, missing stacks, unsupported sharing, invalid signals,
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

A port is its own files and nothing else:

| Path | Holds |
| --- | --- |
| `port/<soc>/port.json` | the registration: name, board, guide, CI label and image, engines and build variants, the M33MU tiers and guest pairs, the capabilities the port lacks (with reasons), the hardware qualification and opt-in sets |
| `port/<soc>/memory_map.h`, `<soc>_regs.h` | the flash, RAM, alias, sector, program unit, window and peripheral facts; `memory_map_check.h` refuses an inconsistent map at compile time |
| `port/<soc>/platform_<soc>.c` | the hooks of `port/common/armv8m/platform_port.h` and the SAU and MPU tables |
| `port/<soc>/flash_drv.c`, `rng_drv.c` | the two driver contracts above, plus any chip driver they wrap |
| `port/<soc>/secure_owners.txt` | the owner of every object the port adds |
| `mk/target-<soc>.mk` | the defaults and chip sources; `mk/common.mk` and `mk/arch-armv8m.mk` need no change |
| `tests/firmware/boards/<soc>/` | the guest board seams |
| `tests/target/ports/<soc>/m33mu.sh`, `hw.sh` | the emulator and hardware profiles |
| `tests/target/provisioning/provisioning_ctrl_<soc>.sh` | the provisioning backend: states, commands with their class, reads, mocks and the one permanent write |
| `tests/host/port_flash/models/<soc>.*` | the flash model the contract suite runs the port's driver over |
| `tests/host/<soc>_<name>/`, `tests/firmware/<soc>-<name>/` | the port's own host suites (an RNG or chip-driver model) and any port-only firmware |
| `docs/<SOC>-Guide.md` | the board guide, from `tools/new-port/templates/Guide.md` |

`docs/Ports.md` and the issue template's port list are generated
(`tools/gen-port-docs.py`), so a port PR carries their regenerated copies and
no other shared file.

`tools/new-port/new-port.sh <soc> --from <port>` scaffolds every file from
the closest registered port with a stub on every value the reference manual
must settle, and `--check` reports the stubs still open and runs the registry
self-tests. A new architecture adds `src/arch/<arch>/`,
`include/wolftrust/arch/<arch>/`, `port/common/<arch>/` and `mk/arch-<arch>.mk`
first; `src/arch/common/` stays untouched.

### Bring-up ladder

Run the gates in order; each one's last line is its evidence, and a skip is
never a pass.

| Gate | Command | Passes when |
| --- | --- | --- |
| G0 registry | `tools/new-port/new-port.sh <soc> --check` | `0 stub(s) open, registry ok` |
| G1 build | `make TARGET=<soc> secure-image TOOLPREFIX=arm-none-eabi-` with `WT_ENGINE=native`, `WT_ENGINE=hsm`, then `WT_CONFORMANCE=1` | every link ends with the layout check's `PASS` lines |
| G2 host | `make test`, which runs `tests/host/port_flash` over the port's model and its own suites | every suite passes and `docs/Ports.md is current` |
| G3 layout | `TOOLPREFIX=arm-none-eabi- tools/check-layout-rebuild.sh <soc>` | `PASS: layout rebuild (<soc>)` |
| G4 emulator smoke | `make test-target TARGET=<soc>` inside the port's CI image | `PASS: target/all` |
| G5 emulator full | `WT_TIER=full make test-target TARGET=<soc>` on both engines | `PASS: target/all` twice |
| G6 hardware minimum | `make test-hardware TARGET=<soc>` on the probe host | `PASS: hardware/all`, evidence under `logs/<soc>-hw/` |
| G7 provisioning | `TARGET=<soc> tests/target/provisioning/provisioning_ctrl.sh status`, then `discover` | both exit 0 and nothing is written |

G6 is the eight scenarios every board runs, which a port cannot exempt;
extras go in `port.json` as `hardware.qualification` or `hardware.optin`.
`hardware.iso_probe` says how the board's `guestisoneg` store is refused:
`faults` (the guest is quarantined), `silent` (latch 2 and guest 0 keeps
running) or any other value (latch 1 or 2 and guest 0 stops at the store).

A port is done when every step's last line is in the PR and the emulator and
silicon evidence are recorded apart. A shared change the port needs is made
generic and explained in the PR description.

### Irreversible operations by vendor

Never run from a runner or a script: the STM32H5 product state advance to
Locked and any option byte written outside `provisioning_ctrl.sh`; the NXP
OTP life cycle and root key fuses (`blhost` fuse programs, `nxpfuses`); any
Debug Authentication credential install on a production part. Every one is
a `lock` step behind the typed acceptance, or refused outright by the port.

### Pitfalls

- An IDAU can override an SAU Non-secure-callable region (the MIMXRT700
  honours NSC only in the Code region): an INVEP SecureFault with a correct
  SG instruction means the veneers live in the wrong region.
- A warm reset keeps SRAM: clear the mailboxes and launch masks before a
  boot, or the last run answers for this one.
- A board keeps its vault and wolfBoot trailers across runs: blank them from
  a parked core, or a stale update trigger swaps old content over the fresh
  image.
- The emulator's fault dumps are buffered: an idle-ended run proves the
  lifecycle, and a second boot with `--quit-on-faults` proves the fault.

## AArch64 targets

An AArch64 SoC port implements isolation level 3 with the shared layer in
`port/common/aarch64/` (below): `mk/arch-aarch64.mk` gates it with
`WT_ISOLATION_LEVEL` (default `3`), and since only level 3 exists today any
other value stops the build. The manifest's `isolation_profile` states the
claim separately: `3`, or `0` (no claim) on a target that cannot yet fence
the Secure bands. The port adds:

- `mk/target-<soc>.mk`: the EL3 text and RAM bands, the boot CPU count, and
  whether the loader already configured the UART and the counter frequency;
- `port/<soc>/memory_map.h`, `el3_board.c`, and `uart.c` for the monitor;
- `port/<soc>/l3_port.h` for the level 3 layer (below);
- `port/<soc>/manifest.json`, whose optional `ffa` section gives each Secure
  Partition's FF-A properties (see [Building](Building.md)); the target
  fragment names it in `WT_PORT_MANIFEST`, since the rendered manifest covers
  only the registered Armv8-M ports.

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
- On silicon, prove a Non-secure call reaches the Secure side (see the IDAU
  pitfall above).
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
- Run every `L3_REQUIRED` scenario the port does not exempt and the eight
  hardware scenarios every board runs.
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
