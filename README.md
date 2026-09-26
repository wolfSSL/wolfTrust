# wolfTrust

wolfTrust is a Secure Partition Manager (SPM) and secure-services runtime
designed for Cortex-M targets. It separates reusable policy and service code
from architecture- and target-specific execution and protection code. The
common runtime provides interprocess communication (IPC) through the Arm
Platform Security Architecture (PSA) Firmware Framework for M (FF-M), manifest
policy, lifecycle management, scheduling, fault recovery, and PSA services.

The only currently supported and validated reference implementation combines
the Armv8-M adapter with the STM32H563 Cortex-M33 port. Support for additional
Cortex-M ports is an intended extension point. Such ports may reuse the common
runtime and, where applicable, the Armv8-M layer. Cortex-A support is an
architectural goal, not a current capability. It will require a new adapter and
changes to current internal execution and protection contracts; the design goal
is to preserve the public manifest, service, IPC, and PSA API contracts.

## Architecture

```mermaid
flowchart TB
    BOOT[Trusted first-stage loader<br/>current reference: wolfBoot]

    subgraph APP[Application domains]
        GA[Cortex-M client A<br/>Zephyr, FreeRTOS, or bare metal]
        GB[Cortex-M client B<br/>Zephyr, FreeRTOS, or bare metal]
    end

    subgraph PORT[Architecture and target ports]
        GW[Client gateway<br/>current: five Armv8-M CMSE veneers]
        ARCH[Architecture adapter<br/>current: Armv8-M]
        TARGET[Target and board port<br/>current: STM32H563]
        GW --- ARCH
        ARCH --- TARGET
    end

    subgraph WT[wolfTrust policy and service runtime]
        SPM[Secure Partition Manager<br/>policy, identity, IPC, scheduling, lifecycle, recovery]
        subgraph SP[Secure services]
            CR["Cryptography and hardware<br/>security module (HSM)"]
            ST["Internal Trusted Storage (ITS),<br/>Protected Storage, and vault"]
            AT[Initial Attestation]
            FW[Firmware Update]
            VN[Optional virtual networking]
        end
        SPM --> CR
        SPM --> ST
        SPM --> AT
        SPM --> FW
        SPM --> VN
    end

    subgraph LIBS[wolfSSL ecosystem components]
        PSA[wolfPSA<br/>guest wolfCrypt and wolfHSM client]
        WC[Secure wolfCrypt and wolfHSM]
        COSE[wolfCOSE]
        HAL[wolfHAL]
        IP[wolfIP<br/>optional bare-metal reference networking]
    end

    BOOT -->|authenticated measurement, lifecycle, and version handoff| SPM
    GA -->|generic FF-M client API| GW
    GB -->|generic FF-M client API| GW
    GA -->|PSA Crypto| PSA
    GB -->|PSA Crypto| PSA
    PSA -->|protected operations over FF-M| GW
    GA -->|optional networking| IP
    GB -->|optional networking| IP
    IP -->|VNet service over FF-M| GW
    GW -->|validated requests| SPM
    SPM -->|Secure execution operations| ARCH
    SPM -->|platform callbacks| TARGET
    CR --> WC
    ST --> WC
    AT --> COSE
    AT --> WC
    TARGET -->|current register and RNG access| HAL
```

### Current reference port

On the STM32H563 reference chain, wolfBoot authenticates wolfTrust, Armv8-M
TrustZone isolates the Secure runtime from Non-secure guests, and STM32 Global
TrustZone Controller (GTZC) memory attribution isolates guest RAM. Zephyr and
FreeRTOS reference guests use wolfPSA's PSA Crypto API through five Cortex-M
Security Extensions (CMSE) gateway veneers. Those mechanisms describe the
current reference port, not a requirement imposed on every intended port.

## Ports

wolfTrust currently supports two ports; each guide covers the board, the
first-stage loader contract, and the runners:

- STM32H563 (NUCLEO-H563ZI): [STM32H5 Guide](docs/STM32H5-Guide.md)
- NXP MIMXRT700 (MIMXRT700-EVK): [MIMXRT700 Guide](docs/MIMXRT700-Guide.md)

Both build with `TARGET=<port>` (`stm32h563` is the default) and run the
same scenario set under the M33MU emulator with `make test-target
TARGET=<port>`.

## Quick start

For the initial Secure build and host tests, install GNU Make, Python 3, Git, a
native C compiler, and an `arm-none-eabi-` toolchain. Configure GitHub SSH
access before cloning because three configured submodule URLs use SSH. Guest
setup, conformance tests, emulator runs, and fresh hardware builds require
network access. See [Getting Started](docs/Getting-Started.md) for additional
emulator and hardware prerequisites.

The repository currently requires authorized GitHub access.

```sh
git clone --recurse-submodules https://github.com/wolfSSL/wolfTrust.git
cd wolfTrust
git submodule update --init --recursive
make
make test
```

The Secure build produces `build/wolftrust.elf`,
`build/wolftrust.bin`, and `build/secure_cmse_implib.o`.
Target runners assemble the wolfBoot-to-wolfTrust chain, patch
signature-covered guest measurements into wolfTrust, and then sign the
wolfTrust image.

Build both PSA reference guests with:

```sh
make -C tests/firmware/zephyr-stm32h5 clone
make -C tests/firmware/zephyr-stm32h5 \
    build-guest0-psa build-freertos-guest1
```

Common validation entry points:

```sh
make test
make test-target
make test-target TARGET=mimxrt700
make test-conformance
WT_H5_DOCKER_IMAGE=ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.15 make test-hardware
```

`make test-target` runs the port's chain under M33MU: the STM32H563 default
skips explicitly when M33MU is unavailable, and `TARGET=mimxrt700` builds its
pinned emulator and wolfBoot first stage itself.
`make test-conformance` instead runs its 20-test host subset and warns that it
is not full emulator or hardware evidence. `make test-hardware` skips when
board detection fails; on hosts without `lsusb`, a missing ST-Link can instead
surface as a flash failure. The hardware target can flash and reset the
connected board. Use the disposable build container for the published hardware
workflow; the current direct-host build path changes the user's global Git
`safe.directory` configuration.

## Documentation

The version-controlled documentation in [`docs/`](docs/) is the primary
documentation source:

- [Getting Started](docs/Getting-Started.md)
- [Architecture](docs/Architecture.md)
- [Security Model](docs/Security-Model.md)
- [Threat Model](docs/Threat-Model.md)
- [API Reference](docs/API-Reference.md)
- [Services](docs/Services.md)
- [TF-M Compatibility](docs/TF-M-Compatibility.md)
- [Macros](docs/Macros.md)
- [Porting](docs/Porting.md)
- [Building](docs/Building.md)
- [Testing](docs/Testing.md)
- [Project Structure](docs/Project-Structure.md)
- [STM32H5 Guide](docs/STM32H5-Guide.md)

The source tree is authoritative:

| Path | Authority |
| --- | --- |
| `include/` | Public APIs and integration contracts |
| `src/` | Runtime and Secure service behavior |
| `port/` | Target policy, memory layout, flash, entropy, and hardware enforcement |
| `mk/` | Build configuration and linked-image checks |

When enabled, the GitHub wiki is generated from the Markdown sources in
`docs/`.

## License

wolfTrust is licensed under the
[GNU General Public License, version 3 or later](LICENSE).
Submodules under `lib/` retain their own licenses.
