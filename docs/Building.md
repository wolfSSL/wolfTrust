# Building

The default Secure build tuple is Armv8-M on STM32H563; `ARCH=aarch64` builds
the Cortex-A monitor and SPMC instead (see
[AArch64 monitor and SPMC images](#aarch64-monitor-and-spmc-images)). The root
Makefile includes `mk/target-<soc>.mk`, `mk/arch-<arch>.mk`, and
`mk/common.mk` (target facts, architecture facts, and the shared build in that
order) and cross-compiles a freestanding image.

## Prerequisites

- GNU Make
- Python 3
- Git and initialized submodules
- GNU Arm Embedded tools with the `arm-none-eabi-` prefix
- a native C compiler for host tests
- for the AArch64 QEMU scenarios, `qemu-system-aarch64` and a toolchain with
  the `aarch64-none-elf-` prefix; CI uses `ghcr.io/wolfssl/wolfboot-ci-aarch64`,
  which also runs locally through Docker

Some submodule URLs use GitHub SSH. Configure GitHub SSH access or an
equivalent Git URL rewrite before initializing them.

```sh
git submodule update --init --recursive
```

The Zephyr guest build additionally uses a Python virtual environment, CMake,
Ninja, and network access to create its v4.2.0 workspace. The FreeRTOS guest
build uses the Arm cross-toolchain and network access; its default source
reference is the mutable `main` branch, not a pinned workspace.

## Secure image

```sh
make
```

The default uses the native crypto engine. Keep separate output directories
when comparing or retaining both engine builds:

```sh
make secure-image WT_ENGINE=native BUILD_DIR=build-native
make secure-image WT_ENGINE=hsm BUILD_DIR=build-hsm
```

`WT_ENGINE_HSM=0` and `WT_ENGINE_HSM=1` remain as legacy aliases for
`native` and `hsm`, respectively. `WT_ENGINE` is the public selector for new
builds. See [Crypto Engines](Crypto-Engines.md) for the behavior, key model,
and measured footprint of each choice.

The default target builds:

| Output | Purpose |
| --- | --- |
| `build/wolftrust.elf` | Secure image with symbols |
| `build/wolftrust.bin` | Flat Secure binary |
| `build/secure_cmse_implib.o` | CMSE import library for Non-secure linking |
| `build/wolftrust.map` | Link map used to audit code and isolation-band placement |
| `build/manifest/wolftrust_manifest_generated.c` | Generated manifest source |
| `build/manifest/wolftrust_manifest_generated.h` | Generated partition and service constants |
| `build/nsc-syms.txt` | Symbol list used to enforce the five-veneer gateway |

Use another output directory or tool prefix as Make variables:

```sh
make BUILD_DIR=build-h5 TOOLPREFIX=/opt/gcc-arm/bin/arm-none-eabi-
```

The build records the variables enumerated by the
`secure_build_mode.stamp` recipe and regenerates when one of those values
changes. The current stamp omits `TOOLPREFIX`, `WT_GUEST_FLASH_WRP`, the VNET
tuning variables (`WT_VNET_POOL_SLOTS`, `WT_VNET_FRAME_MAX`,
`WT_VNET_RX_QUEUE_DEPTH`, `WT_VNET_RX_IRQ`, `WT_VNET_TIMEOUT_TICKS`, and
`WT_VNET_UNKNOWN_UCAST_FLOOD`), and the test-only
`WT_VAULT_FOREIGN_PROBE`, `WT_VAULT_PROBE_SECURED`, and
`WT_CONF_DIAG_TRAP` variables. Use a fresh `BUILD_DIR` or clean the active
output directory before changing an option that the recipe does not record.

## AArch64 monitor and SPMC images

```sh
make ARCH=aarch64 TARGET=qemuvirt                            # virt, GICv3, cortex-a72
make ARCH=aarch64 TARGET=qemuvirt WT_GIC_VERSION=2 WT_CPU=cortex-a35
make ARCH=aarch64 TARGET=versal                              # WT_VERSAL_VIRT=1 today
```

The AArch64 build produces two images. `el3-image` is the monitor: the
archive `build/libwt_el3.a` (audited by `tools/check-el3-symbols.sh` at link
time) linked whole into `build/wolftrust_el3.elf` and `build/wolftrust_el3.bin`.
`secure-image` is the Secure EL1 SPMC, `build/wolftrust.elf` and
`build/wolftrust.bin`: the neutral core, the services, wolfCrypt and the selected
[crypto engine](Crypto-Engines.md),
the AArch64 Secure EL1 layer, and the port, linked by
`src/arch/aarch64/spm/wolftrust.ld` into the SPM image, RAM, and keystore
bands that `mk/target-<soc>.mk` defines. On QEMU virt the runner places the
SPMC image behind the monitor in the pflash image (`WT_SPM_FLASH_OFFSET`)
and the monitor copies it to its band; on versal-virt the QEMU loader places
the ELF. The QEMU ports share `port/common/aarch64/` (platform operations,
partition tables, a RAM-backed wolfHSM NVM, and a test entropy source that
silicon ports must replace). The `ghcr.io/wolfssl/wolfboot-ci-aarch64`
container carries the toolchain and QEMU; `make test-target-a` boots the
result.

## Manifest generation

The default input is `port/stm32h563/manifest.json`; AArch64 targets use
`port/qemuvirt/manifest.json` and `port/versal/manifest.json`.
`CONFIG_VNET=y` selects `manifest-vnet.json`, and
`WT_CONFORMANCE=1` selects `manifest-conformance.json`.

```sh
make CONFIG_VNET=y
make WT_CONFORMANCE=1
```

The generator is constrained to FF-M framework version `0x0100`,
feature mask `0x1` (connection-based IPC), and 32-bit addresses on Armv8-M.
Unsupported capabilities or an invalid resource layout stop the build.

AArch64 manifests (`--address-bits 64`) may add an optional top-level
`ffa` section with one entry per Secure Partition domain: the FF-A
partition properties of DEN0077A Table 5.1 (`ffa_version`, `uuids`,
`execution_contexts`, `runtime_el`, `messaging`, `ns_interrupt_action`,
`boot_info_register`).
The generator accepts only what the SPMC implements for these partitions: FF-A
`1.2`, one execution context, `S-EL0`, messaging `none` (their services are reached
through the SPMC's PSA endpoint, not by FF-A messages to the partition),
`signaled`, and boot information register `none` (the SPMC hands these
partitions no FF-A boot information blob); any other value stops the build.
The generator emits them as a separate `wt_generated_ffa_partitions` table
declared by `wolftrust/arch/aarch64/ffa_manifest.h`; a 64-bit manifest
without the section gets an empty table (count 0), 32-bit output is
unchanged, and a 32-bit target rejects the section. 64-bit targets also get
`WT_GENERATED_TABLE_POOL_PAGES` in the generated header: the 4 KB pages the
stage-1 tables need (one table per partition, sized from its memory resources
and stack, plus the SPMC's own table pages from `--spm-table-pages` and a spare
set). The count is a lower bound, and the generated source fails the build when
the target's `WT_SPM_TABLE_POOL_PAGES` is smaller.

## Build controls

Examples:

```sh
make WT_TIMESLICE_MS=5
make WT_MAX_GUESTS=1
make BUILD_DIR=build-wrp WT_GUEST_FLASH_WRP=1
make CONFIG_VNET=y
```

Link-time optimization is enabled by default for the Secure image. It lets GCC
optimize across source-file boundaries while retaining the assembly, CMSE, and
isolation-band objects that must keep stable linker behavior. Disable it for a
toolchain diagnostic or an explicit non-LTO comparison:

```sh
make WT_LTO=0
```

`WT_LTO` is recorded in `secure_build_mode.stamp`, so changing it rebuilds the
affected objects. Every Secure link also checks the final ELF for required
exception entries, zero-heap policy, and writable-state placement.

Use separate output directories when comparing footprints:

```sh
make BUILD_DIR=build-lto size-report
make BUILD_DIR=build-no-lto WT_LTO=0 size-report
```

Record the LTO setting with published size results. The locally measured TF-M
v2.1.1 comparison builds did not use LTO.

The AArch64 build keeps `WT_LTO=0` and refuses `1`: its linker script places
the isolation bands, and the EL3 symbol guard audits the monitor archive, by
object name.

Changing guest count, addresses, or sizes also requires matching manifest,
guest linker, emulator-load, flash, and measurement-record settings. See
[Macros](Macros.md) for the supported values and constraints.

## Reference guests

Set up the pinned Zephyr workspace, then build the Zephyr PSA guest and the
FreeRTOS PSA guest together:

```sh
make -C tests/firmware/zephyr-stm32h5 clone
make -C tests/firmware/zephyr-stm32h5 \
    build-guest0-psa build-freertos-guest1
```

`WT_ENGINE` must match the Secure image and every guest image. The guest build
scripts default to `native` and pass the same selector through the Secure and
guest builds:

```sh
WT_ENGINE=native make -C tests/firmware/zephyr-stm32h5 \
    build-guest0-psa build-freertos-guest1
WT_ENGINE=hsm make -C tests/firmware/zephyr-stm32h5 \
    build-guest0-psa build-freertos-guest1
```

For a direct Zephyr configuration rather than the wrapper script:

- native uses `CONFIG_WOLFTRUST_NATIVE_CLIENT=y` and
  `CONFIG_WOLFTRUST_WOLFHSM_CLIENT=n`; and
- hsm uses `CONFIG_WOLFTRUST_WOLFHSM_CLIENT=y` and leaves
  `CONFIG_WOLFTRUST_NATIVE_CLIENT` disabled.

The native Zephyr module links guest wolfCrypt plus
`src/client/crypto_native_client.c`. The wolfHSM module instead links the
wolfHSM client, crypto-callback glue, and
`src/client/hsm_psa_transport.c`. The FreeRTOS
`build_freertos_guest.sh` script makes the same source and preprocessor choice
from its `WT_ENGINE` environment variable.

This produces:

- `tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin`
- `tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin`

The same Makefile also provides:

| Target | Result |
| --- | --- |
| `build-guest0` | Diagnostic Zephyr guest without the full PSA demo |
| `build-guest0-psa` | Zephyr PSA guest |
| `build-guest1` | Bare-metal heartbeat guest |
| `build-freertos-guest1` | FreeRTOS PSA guest |
| `run` | Zephyr PSA plus bare-metal guest under M33MU |
| `run-uarts` | Same pair with separated UART output |
| `run-tui` | Same pair with the M33MU TUI |
| `zephyr-freertos-uarts` | Zephyr and FreeRTOS PSA guests under M33MU |

## Engine coverage in CI

The cross-compile workflow links a Secure image with each engine. The M33MU
lifecycle job crosses `guest: [zephyr, freertos]` with
`engine: [native, hsm]`. The scenario job also adds the engine as a matrix
dimension, and the label-selected pull-request workflow runs each requested
scenario under both engines.

The `hsmattackneg` scenario is intentionally hsm-only. It injects raw wolfHSM
protocol packets and attacks a wolfHSM namespace and NVM relay surface that is
not linked into the native engine. All other scenario rows run under both
engines. See [Testing](Testing.md) for the commands and validation scope.

## Authenticated image assembly

`make` alone produces an unsigned flat Secure binary. The target
runners perform the complete assembly:

1. build wolfBoot and the guest images;
2. copy the unpatched wolfTrust binary;
3. run `tools/measure/patch_guest_digests.py` with each guest ID,
   version, and binary;
4. sign the patched wolfTrust image with the wolfBoot key; and
5. load wolfBoot, signed wolfTrust, and guests at matching addresses.

Do not sign wolfTrust before patching the guest records. An unpatched record
count causes required guest launch to fail.

## Virtual network build

The optional wolfTrust virtual Ethernet switch for wolfIP guests is off by
default:

```sh
make CONFIG_VNET=y
make test-vnet
make test-vnet-target
```

The end-to-end VNET guests use
`tests/firmware/stm32h563-vnet/`, not the Zephyr and FreeRTOS demo
images.

## Clean builds

```sh
make clean
make -C tests/host clean
make -C tests/firmware/zephyr-stm32h5 clean
```

The root target removes the Secure build, bare-metal and VNET reference
firmware, and the host suites it names. The second command clears every native
host-suite build; the third clears Zephyr and FreeRTOS guest outputs. Downloaded
guest workspaces under ignored directories may remain.

See [Getting Started](Getting-Started.md) for the shortest path and [Testing](Testing.md) for validation
commands.
