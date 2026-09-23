# Building

The supported Secure build tuple is Armv8-M on STM32H563. The root Makefile
includes `mk/target-stm32h563.mk`, `mk/arch-armv8m.mk`, and `mk/common.mk`
(target facts, architecture facts, and the shared build in that order) and
cross-compiles a freestanding Cortex-M33 image.

## Prerequisites

- GNU Make
- Python 3
- Git and initialized submodules
- GNU Arm Embedded tools with the `arm-none-eabi-` prefix
- a native C compiler for host tests

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

## Manifest generation

The default input is `port/stm32h563/manifest.json`.
`CONFIG_VNET=y` selects `manifest-vnet.json`, and
`WT_CONFORMANCE=1` selects `manifest-conformance.json`.

```sh
make CONFIG_VNET=y
make WT_CONFORMANCE=1
```

The generator is constrained to FF-M framework version `0x0100`,
feature mask `0x1` (connection-based IPC), and 32-bit addresses.
Unsupported capabilities or an invalid resource layout stop the build.

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
