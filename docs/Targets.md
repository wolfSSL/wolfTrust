# Ports and supported targets

wolfTrust separates its common runtime, architecture adapter, and device port.
Two Armv8-M build tuples are supported: STM32H563 and MIMXRT700. Both link the
same core runtime, Armv8-M adapter, and shared isolation level 3 layer in
`port/common/armv8m/`. The entries below separate available builds from future
ports.

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
| M33MU RT700 model | The authenticated chain and the STM32H563 scenario matrix, including every isolation level 3 negative and Arm's conformance suites. The model has no DMA, so the DMA negatives are left to the EVK. | [Testing](Testing.md#mimxrt700-emulator-scenarios) |

Both ports share the manual life cycle flow in [Provisioning](Provisioning.md).

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
covers where that port differs.
