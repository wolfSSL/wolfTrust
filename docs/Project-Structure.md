# Project Structure

| Path | Contents |
| --- | --- |
| `README.md` | Repository overview and quick start |
| `docs/` | Source pages for the HTML and PDF manual |
| `include/psa/` | FF-M client/service, status, storage, update, and lifecycle headers implemented by wolfTrust |
| `include/wolftrust/` | Domain, manifest, monitor, port, scheduler, IPC, service, and VNET contracts |
| `src/` | Architecture-neutral boot sequence, monitor, FF-M runtime, domains, manifests, verification, rollback, recovery, and the Secure Partition entry bodies |
| `src/arch/common/` | Architecture-neutral code every architecture links as is: the Secure Partition gate dispatch, fault recovery, scheduler, the SP-side PSA API, and the NS FF-M gateway bodies, all written over the `wolftrust/arch.h` primitives |
| `src/arch/armv8m/` | Armv8-M mechanisms behind `wolftrust/arch.h`: reset entry, guest context switching, exception handlers, virtual SysTick, NVIC routing, table-driven SAU and MPU programming, the SVC trap decoder, the CMSE range checks, and the five NS veneers |
| `src/client/` | OS-neutral FF-M, storage, firmware-update, HSM, and VNET client transports |
| `src/sched/` | Static coroutine and tasklet scheduling |
| `src/services/` | HSM relay, vault, storage, attestation, firmware update, and VNET service code |
| `src/sync/` | Synchronization primitives used by Secure services |
| `src/vnet/` | Secure virtual Ethernet data plane |
| `port/common/armv8m/` | The shared Armv8-M isolation level 3 layer: Secure RAM band layout, linker fragments, and the level 3 `wt_platform_*` hooks every Armv8-M port links |
| `port/stm32h563/` | STM32H563 SoC facts and `wolftrust/platform.h` operations: registers, board and memory maps, the SAU and MPU region tables, GTZC windows, clocks, UART, flash, entropy, partition tables, manifest, and the boot-time probes |
| `port/mimxrt700/` | MIMXRT700 SoC facts and platform operations: the bit-28 Secure-alias memory map, SAU and MPU tables, AHBSC setup, the XSPI0 NOR driver, TRNG entropy, partition tables, linker script, and manifests |
| `mk/` | Build fragments: `common.mk` (every rule shared by all targets), `arch-<arch>.mk` (toolchain and architecture sources), `target-<soc>.mk` (SoC sources, placement, and image checks) |
| `tools/manifest/` | Manifest validation and C/header generation |
| `tools/measure/` | Guest-measurement record patching before image signing |
| `tools/handoff/` | Boot-handoff record generation and validation for emulator runs and host tests |
| `tests/host/` | Native unit and integration suites |
| `tests/target/` | M33MU, STM32H563, and MIMXRT700 build, flash, and scenario runners; `provisioning/` holds the life cycle control scripts and their gate tests |
| `tests/firmware/` | Bare-metal, Zephyr, FreeRTOS, conformance, and VNET guest images |
| `tests/upstream/` | Fetch and integration helpers for pinned external validation suites |
| `lib/` | Git submodules for wolfSSL, wolfPSA, wolfHSM, wolfCOSE, wolfHAL, and wolfIP |
| `.github/workflows/` | Build, test, dependency, fuzz, and manual publishing workflows |

Generated files belong under `build/`, guest build directories,
ignored workspaces, or `logs/`. Public APIs are declared in `include/`;
architecture-neutral implementation is under `src/`; target-specific
implementation is under `port/` and the active build fragment.

See [Porting](Porting.md) for the boundary between these areas.
