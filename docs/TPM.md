# TPM 2.0 Interface

A wolfTPM application sends TPM 2.0 commands to `SERVICE_TPM`. The service
runs wolfTPM's firmware TPM directly inside a normal wolfTrust Secure
Partition. It needs no second application image, RTOS, or worker. A bare-metal,
Zephyr, or FreeRTOS client uses the same transport.

TPM 2.0 is an alternative application API to PSA, not an addition to it. PSA
stays the primary interface and the default build; `CONFIG_TPM=y` is off by
default, and leaving it off keeps the default image byte-for-byte unchanged.

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
Crypto implementation (`WT_SECURE_PSA` defaults to 0 and an explicit 1 is
refused). The application reaches the SPM through the CMSE gateway.

## Build and run

All three application interfaces use `WT_ENGINE=native` (default) or
`WT_ENGINE=hsm`. For TPM 2.0 the engine changes only the Secure image.
`WT_INTERFACE_PROFILE=default` exports RNG, SHA-256, P-256 key generation,
signing, verification, and their required lifecycle commands. `full` retains
the broader supported command set, including PCR operations. Individual
commands can be added or removed with [operation profiles](Interface-Profiles.md).

```sh
make TARGET=mimxrt700 CONFIG_TPM=y WT_ENGINE=native secure-image
make -C tests/firmware/interface-guest TARGET=mimxrt700 WT_INTERFACE=tpm

WT_ENGINE=native tests/target/run_suite.sh mimxrt700 tpm tpmneg
WT_ENGINE=hsm WT_PROFILE=full tests/target/run_suite.sh stm32h563 tpm tpmneg
```

Every Cortex-M33 port registers the `tpm` build variant in its `port.json`;
the STM32L562 builds the native engine only. The runner authenticates
wolfBoot, wolfTrust, the bare-metal wolfTPM application in guest0
(`tests/firmware/interface-guest`), and an idle bare-metal guest1. The
interface profile follows the runner's `WT_PROFILE` unless
`WT_INTERFACE_PROFILE` is set. [Footprint](Footprint.md#tpm-20-and-pkcs11)
has the Secure image and application sizes for every port and engine.

## Service boundary

The application links the wolfTPM client and `SERVICE_TPM` transport. It does
not link fwTPM or a crypto engine client: its wolfCrypt RNG reads
`TPM2_GetRandom` over `SERVICE_TPM` (`wt_tpm_psa_random`). The Secure partition owns the `FWTPM_CTX`, keys, command
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

When the monitor restarts or quarantines the application guest, the next
command first gets a TPM Reset: fwTPM runs `TPM2_Startup(TPM_SU_CLEAR)`, which
flushes the old client's objects, sessions, hash sequences, and PCRs. The
partition itself does not restart. The dictionary-attack count carries over,
so a guest restart cannot clear a lockout.

The volatile `FWTPM_NO_NV` configuration has no heap. Keys and PCR values do
not survive reboot. The linker and MPU assign the handler a private state
region and stack in the interface band above SPM RAM. Native builds share
read-only crypto code while keeping working state private. HSM builds retain
private callback state.

## Validation and supported targets

Every Cortex-M33 port runs actual commands and isolation tests under M33MU.
The default suite checks capabilities, a maximum-sized hash command, RNG,
P-256 key creation, signing, verification, disabled commands, dictionary-attack
lockout after repeated bad authorization, and cleanup.
The full suite also checks PCR extend/read and broader object operations.

`tpmneg` proves that another Secure Partition cannot read or write TPM state,
that the TPM partition cannot read SPM-private RAM or execute its writable
state, that each fault is contained, and that commands succeed after recovery.
`tpmreset` faults the application after it loads a key and fails one
authorization; profiles with PCR commands also extend a PCR. The relaunched
guest must find no object and the same dictionary-attack count, and on those
profiles the PCR reset.
The host suite drives the production client/service protocol through a real
FF-M runtime and checks bounds, caller identity, wiping, and no replay.

The M33MU workflow runs `tpm` and `tpmneg` on every port, each engine the
port builds, and each profile the port registers, from the port registry's
`m33mu.groups`. The STM32L562 runs the default profile only: its interface
layout has no update partition for the full profile's `WT_FWU=1`. The
cross-compile workflow builds the `CONFIG_TPM=y` Secure image on every port
and engine, and the host manifest suite validates its rendered manifest.
