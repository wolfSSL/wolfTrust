# Getting Started

This guide builds the currently supported STM32H563 Secure image, the Zephyr
and FreeRTOS reference guests, and the host tests. See [Building](Building.md) for
build controls, and read [STM32H5 Guide](STM32H5-Guide.md) before flashing a
board. The AArch64 (Cortex-A) images and their QEMU scenarios are covered in
[Build and run the AArch64 images](#build-and-run-the-aarch64-images).

## Prerequisites

- Git with submodule support
- GNU Make
- Python 3
- An Arm GNU Toolchain providing `arm-none-eabi-gcc`,
  `arm-none-eabi-objcopy`, `arm-none-eabi-nm`, and
  `arm-none-eabi-size`
- A native C compiler for host tests
- CMake and Ninja for the Zephyr workspace
- Docker for the supplied CI-container workflows
- M33MU for emulated Cortex-M33 execution, or a NUCLEO-H563ZI with ST-Link for
  hardware execution
- For the AArch64 images, an `aarch64-none-elf-` toolchain and
  `qemu-system-aarch64`; the `ghcr.io/wolfssl/wolfboot-ci-aarch64` container
  carries both

Guest setup downloads the Zephyr v4.2.0 tag and the FreeRTOS `main` branch by
default, so it requires network access on its first run and the FreeRTOS
revision can change. Before the first FreeRTOS clone, set `FREERTOS_REF` to a
release tag for a reproducible checkout. The current shallow-clone helper does
not accept an arbitrary commit ID or change an existing workspace.

The emulator runner fetches pinned M33MU and wolfBoot revisions, and a fresh
hardware build fetches pinned wolfBoot, so those paths also require network
access.

## Clone the repository

```sh
git clone --recurse-submodules https://github.com/wolfSSL/wolfTrust.git
cd wolfTrust
git submodule update --init --recursive
```

## Build the Secure image

```sh
make
```

The default STM32H563 cross-build produces:

- `build/wolftrust.elf`
- `build/wolftrust.bin`
- `build/secure_cmse_implib.o`, used when linking Non-secure clients

The standalone binary is not a complete authenticated boot chain. The target
runners patch guest measurement records into a copy of the Secure binary and
sign that image with wolfBoot.

## Build both PSA guests

The reference pair is a Zephyr guest in slot 0 and a FreeRTOS guest in slot 1.
Both use wolfPSA entry points and send protected operations through the FF-M
gateway.

```sh
make -C tests/firmware/zephyr-stm32h5 clone
make -C tests/firmware/zephyr-stm32h5 \
    build-guest0-psa build-freertos-guest1
```

The first command creates ignored workspaces under
`tests/firmware/zephyr-stm32h5/.workspace/`. The second command also
builds the matching Secure image and CMSE import library.

## Run host tests

```sh
make test
```

This is the fastest functional check. It does not demonstrate Armv8-M hardware
isolation; see [Testing](Testing.md) for the validation split.

## Run under M33MU

In the configured M33MU environment:

```sh
make test-target
```

The target automatically skips with an explanation when M33MU is unavailable.
When present, it builds the authenticated wolfBoot-to-wolfTrust chain and runs
the positive, guest-restart, cross-domain, and conformance scenarios. Emulator
results are not hardware results.

## Run on STM32H563

Connect a provisioned NUCLEO-H563ZI and make the ST programmer visible on a
Linux host with Bash, GNU userland, pyOCD with STM32H563 support, and a
host-visible `arm-none-eabi-nm` (override with `ARM_NM`). Use the disposable
build container in the published workflow:

```sh
WT_H5_DOCKER_IMAGE=ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.15 make test-hardware
```

For the hardware-enforced guest-flash policy, pass the flag into the container
build explicitly, then pass it again to the host-side flash run:

```sh
docker run --rm \
    -e WT_GUEST_FLASH_WRP=1 \
    -v "$PWD":/workspace \
    -w /workspace \
    ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.15 \
    bash tests/target/run_h5_hardware.sh build positive
WT_GUEST_FLASH_WRP=1 \
    tests/target/run_h5_hardware.sh flash positive
```

Hardware runs flash the board. Configure the TrustZone perimeter and WRP option
bytes first as described in [STM32H5 Guide](STM32H5-Guide.md). The current
`run_h5_suite.sh` wrapper does not forward `WT_GUEST_FLASH_WRP` into its Docker
build, so its shorter `make test-hardware` form must not be used for this
hardened build until the runner is fixed.

## Build and run the AArch64 images

```sh
make ARCH=aarch64 TARGET=qemuvirt
make test-target-a
make test-target-a MACHINE=versal-virt
tests/target/run_suite.sh qemu-a positive confboot ffaacs-memory
```

The build produces the EL3 monitor (`build/wolftrust_el3.elf`) and the Secure
EL1 SPMC (`build/wolftrust.elf`) for QEMU `virt`. `make test-target-a` builds
and boots a quick subset of the QEMU scenarios (`WT_QEMU_A_SCENARIOS`);
`tests/target/run_suite.sh qemu-a` runs any of them. See
[Testing](Testing.md#qemu-aarch64-scenarios) for the full list. These targets
have no wolfBoot port and no authenticated boot yet.

## Next steps

- Read [Architecture](Architecture.md) for the request path and isolation model.
- Use [API Reference](API-Reference.md) when integrating a PSA client.
- Use [Macros](Macros.md) before changing the target profile.
- Use [Porting](Porting.md) when adding another Cortex-M target or architecture adapter.
