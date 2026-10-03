# Ports and supported targets

wolfTrust separates its common runtime, architecture adapter, and device port.
The only currently supported and validated build tuple is Armv8-M on
STM32H563. The entries below distinguish available builds from future ports.

## Armv8-M

### STM32H563 (supported reference port)

The `armv8m-stm32h563` tuple has two validation environments:

| Environment | What it exercises | Guide |
| --- | --- | --- |
| NUCLEO-H563ZI hardware | wolfBoot authenticates wolfTrust; Zephyr and FreeRTOS reference guests use the FF-M gateway. Board provisioning and flash protection are required for the hardened path. | [STM32H563 board guide](STM32H5-Guide.md) |
| M33MU Cortex-M33 emulator | The authenticated chain and target scenarios without a physical board. Emulator results do not establish physical flash or debug-policy enforcement. | [Getting Started](Getting-Started.md#run-under-m33mu) and [Testing](Testing.md) |

### Additional Armv8-M devices

An additional Cortex-M33 device, such as i.MX RT700, needs its own device port,
memory layout, manifest, guest integration, and target validation before it
can be listed as supported. It may reuse the Armv8-M adapter if its execution
and protection model fit the adapter contract. Add a board guide alongside
this page when that port has a validated build and deployment path.

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
mechanisms of the STM32H563 reference implementation.
