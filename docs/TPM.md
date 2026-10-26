# TPM 2.0 Interface

A wolfTPM application sends TPM 2.0 commands to `SERVICE_TPM`. The service
runs wolfTPM's firmware TPM directly inside a normal wolfTrust Secure
Partition. It needs no second application image, RTOS, or worker. A bare-metal,
Zephyr, or FreeRTOS client uses the same transport.

```text
Application: wolfTPM TPM2_* API
    |
    | TPM 2.0 frames over FF-M IPC
    v
SERVICE_TPM Secure Partition: fwTPM
    |
    +-- WT_ENGINE=native: wolfCrypt
    +-- WT_ENGINE=hsm: SERVICE_HSM / wolfHSM
```

The transport uses FF-M `psa_connect`, `psa_call`, and `psa_close`. These are
IPC operations, not PSA Crypto calls. TPM and PKCS#11 builds link no wolfPSA
Crypto implementation. Cortex-M reaches the SPM through its CMSE gateway;
Cortex-A uses FF-A through the EL3 SPMD.

## Build and run

All three application interfaces use `WT_ENGINE=native` (default) or
`WT_ENGINE=hsm`. TPM's native configuration does not need wolfHSM crypto.
`WT_CRYPTO_PROFILE=default` exports RNG, SHA-256, P-256 key generation,
signing, verification, and their required lifecycle commands. `full` retains
the broader supported command set, including PCR operations. Individual
commands can be added or removed with [operation profiles](Crypto-Profiles.md).

```sh
make TARGET=stm32h563 CONFIG_TPM=y WT_ENGINE=native secure-image

WT_ENGINE=native WT_CRYPTO_PROFILE=default WT_INTERFACE_OS=zephyr \
    tests/target/run_suite.sh m33mu tpm
WT_ENGINE=hsm WT_CRYPTO_PROFILE=full WT_INTERFACE_OS=freertos \
    tests/target/run_suite.sh m33mu tpm tpmneg

make ARCH=aarch64 TARGET=qemuvirt CONFIG_TPM=y WT_ENGINE=native \
    secure-image TOOLPREFIX=aarch64-none-elf-
WT_ENGINE=native tests/target/run_suite.sh qemu-a tpm tpmneg
```

The Cortex-M runner authenticates wolfBoot, wolfTrust, and one application.
`make test-tpm-target WT_INTERFACE_OS=zephyr` and the `freertos` variant are
focused entry points. The isolation scenario also exercises a bare-metal
wolfTPM application. See [footprint measurements](Interface-Footprint.md) for
matched Secure-image and application sizes across all six configurations.

## Service boundary

The application links the wolfTPM client and `SERVICE_TPM` transport. It does
not link fwTPM. The Secure partition owns the `FWTPM_CTX`, keys, command
buffers, and stack. Native operations run wolfCrypt in this domain; the HSM
configuration registers the wolfHSM callback and calls the existing HSM
service from the Secure partition.

`WT_TPM_OP_TRANSACT` copies one command in, executes it, and copies one response
out in the same call. Each frame is at most `WT_TPM_FRAME_MAX` (512 bytes), so
the combined transfer fits the 1024-byte FF-M budget. fwTPM advertises matching
limits through `TPM2_GetCapability`. The client checks TPM response framing.
Transport errors never cause an automatic replay of a potentially mutating
command. A lost connection is reopened for the next explicit command.

The SPM supplies caller identity. Only the configured application client can
use the service; unrelated Non-secure clients and Secure Partitions are
refused. Command and response staging is wiped after every successful or failed
execution. There are no submit/poll/fetch/respond worker operations.

The volatile `FWTPM_NO_NV` configuration has no heap. Keys and PCR values do
not survive reboot. On Cortex-M the linker and MPU assign the handler a
private state region and stack; on Cortex-A its S-EL0 translation table maps
its private writable pages. Native builds share read-only crypto code while
keeping working state private. HSM builds retain private callback state.

## Validation and supported targets

STM32H563 under M33MU and QEMU `virt` run actual commands and isolation tests.
The default suite checks capabilities, a maximum-sized hash command, RNG,
P-256 key creation, signing, verification, disabled commands, and cleanup.
The full suite also checks PCR extend/read and broader object operations.

`tpmneg` proves that another Secure Partition cannot read or write TPM state,
that the TPM partition cannot read SPM-private RAM or execute its writable
state, that each fault is contained, and that commands succeed after recovery.
The host suite drives the production client/service protocol through a real
FF-M runtime and checks bounds, caller identity, wiping, and no replay.

CI covers both engines and profiles, Zephyr and FreeRTOS applications on
Cortex-M, and Normal-world applications on Cortex-A. Required matrix cells
must report real passes; successful skips are rejected. MIMXRT700 and Versal
have compile and layout gates, without an API runtime qualification claim.
Versal QEMU lacks the XMPU/RISAF needed for Normal-world level-3 isolation.
