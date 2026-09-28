# Supported Targets

The validated reference target is the STM32H563 Cortex-M33. wolfTrust uses an
Armv8-M architecture adapter and an STM32H563 target port. Other devices need
their own port, memory layout, manifest, guest integration, and validation.

| Environment | Secure image and guests | Guide |
| --- | --- | --- |
| NUCLEO-H563ZI hardware | wolfBoot authenticates wolfTrust; Zephyr and FreeRTOS reference guests use the FF-M gateway. Board provisioning and flash protection are required for the hardened path. | [STM32H563 Board Guide](STM32H5-Guide.md) |
| M33MU Cortex-M33 emulator | Runs the authenticated chain and target scenarios without a physical board. Emulator results do not establish physical flash or debug-policy enforcement. | [Getting Started](Getting-Started.md#run-under-m33mu) and [Testing](Testing.md) |

Start with [Getting Started](Getting-Started.md) for prerequisites and a first
build. See [Building](Building.md) for build controls and guest images, and
[Porting](Porting.md) for a new device's required architecture and target
contracts. [Security Model](Security-Model.md) describes the protection
mechanisms of the STM32H563 reference implementation.
