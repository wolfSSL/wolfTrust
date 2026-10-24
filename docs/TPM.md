# TPM 2.0 Interface

wolfTrust lets an application use the wolfTPM API through the Secure Partition
Manager. The reference Cortex-M clients run under Zephyr and FreeRTOS. The
Cortex-A test client runs in the Normal world under QEMU. The TPM application
is independent of PKCS#11 and PSA Crypto. Its TPM 2.0 command traffic crosses
an FF-M service and reaches an isolated firmware TPM.

```text
Application
  wolfTPM TPM2_* API
        |
        v
  wolfTPM transport shim
        |
        | FF-M IPC
        | Cortex-M: CMSE gateway
        | Cortex-A: FF-A through the EL3 SPMD
        v
  SERVICE_TPM Secure Partition
        |
        v
  isolated wolfTPM firmware TPM
```

The transport uses the FF-M `psa_connect`, `psa_call`, and `psa_close` IPC
operations. It does not call the PSA Crypto API. The payload is an unmodified
TPM 2.0 command or response frame.

The runtime-qualified targets in this release are STM32H563 under M33MU and
`qemuvirt` under QEMU. MIMXRT700 and Versal have `CONFIG_TPM=y` compile and
absolute-layout gates, but no TPM application/provider runtime claim yet. The
Versal QEMU model also lacks the XMPU/RISAF needed for a Normal-world level-3
isolation claim.

## Build and run

See [TPM and PKCS#11 footprint](Interface-Footprint.md) for measured Secure
and provider image sizes against the base revision.

Enable the service and its manifest in the Secure image with:

```sh
make TARGET=stm32h563 CONFIG_TPM=y WT_ENGINE=native secure-image \
    TOOLPREFIX=arm-none-eabi-
```

Run the Cortex-M wolfTPM application and isolated fwTPM provider with either
supported guest OS:

```sh
WT_ENGINE=native WT_INTERFACE_OS=zephyr \
    tests/target/run_suite.sh m33mu tpm
WT_ENGINE=native WT_INTERFACE_OS=freertos \
    tests/target/run_suite.sh m33mu tpm
```

`make test-tpm-target WT_INTERFACE_OS=zephyr` and
`make test-tpm-target WT_INTERFACE_OS=freertos` are equivalent focused entry
points.

Build the Cortex-A service and run its positive and isolation scenarios with:

```sh
make ARCH=aarch64 TARGET=qemuvirt CONFIG_TPM=y WT_ENGINE=native \
    secure-image TOOLPREFIX=aarch64-none-elf-
WT_ENGINE=native tests/target/run_suite.sh qemu-a tpm tpmneg
```

## Application and provider boundary

The application image contains wolfTPM and the `SERVICE_TPM` transport. It does
not contain the fwTPM responder. On Cortex-M, a second Non-secure guest contains
the responder but not the application. Link-time checks enforce this split for
both the Zephyr and FreeRTOS application builds.

On Cortex-A, the Normal-world image still contains only the wolfTPM client.
The heap-free volatile fwTPM profile runs inside the `SERVICE_TPM` S-EL0
partition. Its executable and read-only pages come from the shared Secure
image. Its private stack and writable-state pages are mapped only in the TPM
partition's stage-1 translation table.

The shared application suite performs real TPM operations through the relay:

- capability reads for the advertised frame limits;
- a maximum-sized TPM2_Hash command;
- random generation;
- ECC primary-key creation, signing, and verification;
- PCR extend and read;
- handle unload and TPM cleanup.

The M33MU provider logs GetRandom, CreatePrimary, Sign, PCR_Extend, and PCR_Read
when the separate fwTPM guest receives them. The QEMU application requires the
same operations to complete through the S-EL0 TPM partition.

## SERVICE_TPM

`SERVICE_TPM` is a mediated mailbox between the application and fwTPM domains.
The application submits one command frame and polls for the response. The fwTPM
fetches the command and posts the response. The Secure relay copies the data,
enforces bounds and roles from the SPM-stamped caller identity, and never
interprets the TPM packet.

One command and one response can be in flight. Each is bounded by
`WT_TPM_FRAME_MAX`, currently 512 bytes. The fwTPM advertises matching input,
command, and response limits through `TPM2_GetCapability`. The slot is held in
the TPM partition's dedicated data band and is zeroed after completion.

On Cortex-M, the application role owns submit and poll while the provider role
owns fetch and respond. A Secure caller or a caller from the wrong domain is
refused. On Cortex-A, the Normal-world application owns submit and poll, and
the local provider is reachable only from inside the TPM partition.

## Provider placement

wolfTrust keeps its Secure image heap-free. On Cortex-M, the responder stays in
an isolated Non-secure provider domain and the Secure image contains only the
bounded relay. On Cortex-A, the S-EL0 service uses the heap-free volatile
`FWTPM_NO_NV` profile. Keys and PCR values in both test configurations do not
survive a reboot.

## Isolation and CI

The TPM service runs as an isolation-level-3 Secure Partition. On Cortex-M,
the application, fwTPM provider, and Secure relay have separate memory
boundaries. The M33MU `tpmneg` scenario proves that:

- another Secure Partition cannot read or write the TPM data band;
- the relay cannot read fwTPM guest RAM directly;
- the relay cannot execute from its execute-never data band;
- each deliberate fault is contained and the partition restarts;
- a complete mediated TPM transaction succeeds after recovery.

On QEMU `virt`, `tpmneg` proves that another S-EL0 partition cannot read or
write the TPM state band, the TPM partition cannot read another partition's
private RAM, and the TPM state band is execute-never. The full TPM operation
sequence still completes after those contained faults.

Pull-request CI has Zephyr and FreeRTOS `tpm` rows in the same explicit API
matrix as PSA and PKCS#11. A separate `tpmneg` row keeps the L3 isolation proof
visible. The cross-compile workflow builds `CONFIG_TPM=y` Secure images for
STM32H563 and MIMXRT700. The AArch64 QEMU matrix also runs `tpm` and `tpmneg`
on the `virt` cell, including GetRandom, CreatePrimary, Sign, signature
verification, PCR extend, and PCR read.
