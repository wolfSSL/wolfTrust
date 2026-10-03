# Project Structure

| Path | Contents |
| --- | --- |
| `README.md` | Repository overview and quick start |
| `docs/` | Source pages published to the GitHub wiki |
| `include/psa/` | FF-M client/service, status, storage, update, and lifecycle headers implemented by wolfTrust |
| `include/wolftrust/` | Domain, manifest, monitor, port, scheduler, IPC, service, and VNET contracts |
| `src/` | Architecture-neutral boot sequence, monitor, FF-M runtime, domains, manifests, verification, rollback, recovery, and the Secure Partition entry bodies |
| `src/arch/common/` | Architecture-neutral code every architecture links as is: the Secure Partition gate dispatch, fault recovery, scheduler, the SP-side PSA API, and the NS FF-M gateway bodies, all written over the `wolftrust/arch.h` primitives |
| `src/arch/armv8m/` | Armv8-M mechanisms behind `wolftrust/arch.h`: reset entry, guest context switching, exception handlers, virtual SysTick, NVIC routing, table-driven SAU and MPU programming, the SVC trap decoder, the CMSE range checks, and the five NS veneers |
| `src/arch/aarch64/` | AArch64 mechanisms behind `wolftrust/arch.h`: the EL3 monitor (`el3/`: entry, vectors, world switch, PSCI, console, ESR decoder), the FF-A layer (`ffa/`: the SPMD relay, boot information, messaging, memory transactions, notifications, partition information, runtime model), the Secure EL1 SPMC (`spm/`: MMU and stage-1 tables, partition domains, S-EL0 coroutines, the SVC gate, interrupts, memory relayer), the GICv2 and GICv3 drivers (`gic/`), the PL011 driver, and the freestanding `memset`/`memcpy` |
| `src/client/` | OS-neutral FF-M, storage, firmware-update, HSM, and VNET client transports |
| `src/sched/` | Static coroutine and tasklet scheduling |
| `src/services/` | HSM relay, vault, storage, attestation, firmware update, and VNET service code |
| `src/sync/` | Synchronization primitives used by Secure services |
| `src/vnet/` | Secure virtual Ethernet data plane |
| `port/stm32h563/` | STM32H563 SoC facts and `wolftrust/platform.h` operations: registers, board and memory maps, the SAU and MPU region tables, GTZC windows, clocks, UART, flash, entropy, partition tables, manifest, and the boot-time probes |
| `port/qemuvirt/` | QEMU `virt` (`secure=on`) SoC facts: memory map, GIC and PL011 bases, EL3 board hooks |
| `port/versal/` | AMD Versal SoC facts (the QEMU `xlnx-versal-virt` variant today): OCM and DDR bands, GIC-500 and PS UART bases, EL3 board hooks |
| `port/common/aarch64/` | Secure EL1 platform code the QEMU AArch64 targets share: `wolftrust/platform.h` operations, partition entry table, RAM-backed NVM, test entropy, and the conformance backend |
| `mk/` | Build fragments: `common.mk` (every rule shared by all targets), `arch-<arch>.mk` (toolchain and architecture sources), `target-<soc>.mk` (SoC sources, placement, and image checks) |
| `tools/manifest/` | Manifest validation and C/header generation |
| `tools/measure/` | Guest-measurement record patching before image signing |
| `tools/handoff/` | Boot-handoff record generation and validation for emulator runs and host tests |
| `tests/host/` | Native unit and integration suites |
| `tests/target/` | M33MU, QEMU AArch64, and STM32H563 build, flash, provisioning, and scenario runners, with the shared assertion library and suite driver |
| `tests/firmware/` | Bare-metal, Zephyr, FreeRTOS, conformance, VNET, AArch64 EL3 smoke, and AArch64 Normal-world payload images |
| `tests/upstream/` | Fetch and integration helpers for pinned external validation suites |
| `tests/conformance/ffa-acs/` | The Arm FF-A ACS platform target for wolfTrust and its recorded patches |
| `lib/` | Git submodules for wolfSSL, wolfPSA, wolfHSM, wolfCOSE, wolfHAL, and wolfIP |
| `.github/workflows/` | Build, test, dependency, fuzz, and wiki synchronization workflows |

Generated files belong under `build/`, guest build directories,
ignored workspaces, or `logs/`. Public APIs are declared in `include/`;
architecture-neutral implementation is under `src/`; target-specific
implementation is under `port/` and the active build fragment.

See [Porting](Porting.md) for the boundary between these areas.
