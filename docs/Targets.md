# Ports and supported targets

wolfTrust separates its common runtime, architecture adapter, and device port.
STM32H563, MIMXRT700, MCXN947, and STM32L562 link the same core runtime,
Armv8-M adapter, and shared isolation level 3 layer in `port/common/armv8m/`.
The generated [Ports](Ports.md) page lists the registered boards, engines,
build variants, CI labels, emulator tiers, hardware scenarios, and absent
capabilities. This page explains their validation scope; each board guide
holds its setup and current evidence.

## Armv8-M

### STM32H563 (supported reference port)

The `armv8m-stm32h563` tuple has two validation environments:

| Environment | What it exercises | Guide |
| --- | --- | --- |
| NUCLEO-H563ZI hardware | wolfBoot authenticates wolfTrust; Zephyr and FreeRTOS reference guests use the FF-M gateway. Board provisioning and flash protection are required for the hardened path. | [STM32H563 board guide](STM32H5-Guide.md) |
| M33MU Cortex-M33 emulator | The authenticated chain and target scenarios without a physical board. Emulator results do not establish physical flash or debug-policy enforcement. | [Getting Started](Getting-Started.md#run-under-m33mu) and [Testing](Testing.md) |

### MIMXRT700

The `armv8m-mimxrt700` tuple (`TARGET=mimxrt700`) runs on the compute
Cortex-M33 of the MIMXRT798S and executes in place from external XSPI0 NOR:

| Environment | What it exercises | Guide |
| --- | --- | --- |
| MIMXRT700-EVK hardware | wolfBoot authenticates wolfTrust; bare-metal guests use the FF-M gateway. The suite covers the chain, guest RAM isolation, and the XSPI guest flash fence. `SERVICE_VNET` is not ported. | [MIMXRT700 board guide](MIMXRT700-Guide.md) |
| M33MU RT700 model | The authenticated chain and registered FF-M, PSA, isolation, and recovery scenarios. The model has no DMA; the registry records other model limits. | [MIMXRT700 board guide](MIMXRT700-Guide.md) and [Testing](Testing.md) |

### MCXN947

The `armv8m-mcxn947` tuple (`TARGET=mcxn947`) runs on core 0 of the
MCXN947 on FRDM-MCXN947. It boots wolfBoot and wolfTrust from internal flash
and supports both crypto engines. Its registered M33MU scenarios cover the
authenticated chain, FF-M IPC conformance, PSA services, isolation, and
recovery. The board runner exercises the hardware minimum in the OEM_OPEN
life cycle. Hardware guest-flash fencing is unavailable; a fence-required
image refuses to launch guests. See the [MCXN947 Guide](MCXN947-Guide.md)
for the current evidence and limitations.

### STM32L562

The `armv8m-stm32l562` tuple (`TARGET=stm32l562`) runs on STM32L562E-DK,
using internal flash and GTZC guest-RAM attribution. It supports the native
engine and defaults to guest-local PSA Crypto (`WT_SECURE_PSA=0`). The
M33MU STM32L552 model runs the registered STM32L562 layout
and conformance scenarios with a pinned model patch. The current flash
layout has emulator evidence; earlier DK runs used a different layout and
do not qualify the current one. See the [STM32L562 Guide](STM32L562-Guide.md)
for the required provisioning and remaining hardware work.

All ports share the manual life cycle flow in [Provisioning](Provisioning.md).

### Additional Armv8-M devices

Another Cortex-M33 device needs its own device port, memory layout, manifest,
guest integration, and target validation before it can be listed as
supported. It reuses the Armv8-M adapter and the shared level 3 layer if its
execution and protection model fit the adapter contract. Add a board guide
alongside this page when that port has a validated build and deployment path.

## AArch64

An AArch64 device, such as a future Versal target, requires an AArch64
architecture adapter and a device port. No AArch64 build or hardware
validation is currently claimed. Keep platform-specific setup in a separate
board guide once the port exists; the common [Porting](Porting.md) page defines
the contracts shared across architectures.

Start with [Getting Started](Getting-Started.md) for prerequisites and a first
build. See [Building](Building.md) for build controls and guest images, and
[Porting](Porting.md) for a new device's required architecture and target
contracts. [Security Model](Security-Model.md) describes the protection
mechanisms of the STM32H563 reference implementation; the MIMXRT700 guide
covers where that port differs. The MCXN947 and STM32L562 guides record the
same distinctions for their boards.
