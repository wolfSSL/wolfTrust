# PKCS#11 Interface

wolfTrust lets an application call the standard PKCS#11 `C_*` API through the
Secure Partition Manager. The reference Cortex-M clients run under Zephyr and
FreeRTOS. The Cortex-A test client runs in the Normal world under QEMU. The
application uses a PKCS#11 proxy, while the real wolfPKCS11 token runs in an
isolated provider. PKCS#11 is a direct application interface to wolfTrust. It
does not use the PSA Crypto API and it does not depend on TPM support.

```text
Application
  PKCS#11 C_* API
        |
        v
  wolfTrust PKCS#11 proxy
        |
        | FF-M IPC
        | Cortex-M: CMSE gateway
        | Cortex-A: FF-A through the EL3 SPMD
        v
  SERVICE_PKCS11 Secure Partition
        |
        v
  isolated wolfPKCS11 provider
        |
        | SERVICE_HSM
        v
  isolated wolfHSM service
```

The transport uses `psa_connect`, `psa_call`, and `psa_close` because those are
the standard FF-M IPC operations. That does not make it a PSA Crypto path. The
payload and public API are PKCS#11.

The runtime-qualified targets in this release are STM32H563 under M33MU and
`qemuvirt` under QEMU. MIMXRT700 and Versal have `CONFIG_PKCS11=y` compile and
absolute-layout gates, but no PKCS#11 application/provider runtime claim yet.
The Versal QEMU model also lacks the XMPU/RISAF needed for a Normal-world
level-3 isolation claim.

## Build and run

Enable the service and its manifest in the Secure image with:

```sh
make TARGET=stm32h563 CONFIG_PKCS11=y WT_ENGINE=hsm secure-image \
    TOOLPREFIX=arm-none-eabi-
```

Run the complete PKCS#11 application suite with either supported guest OS:

```sh
WT_ENGINE=hsm WT_INTERFACE_OS=zephyr \
    tests/target/run_suite.sh m33mu pkcs11
WT_ENGINE=hsm WT_INTERFACE_OS=freertos \
    tests/target/run_suite.sh m33mu pkcs11
```

`make test-pkcs11-target WT_INTERFACE_OS=zephyr` and
`make test-pkcs11-target WT_INTERFACE_OS=freertos` are equivalent focused
entry points.

Build the Cortex-A provider and run its positive and isolation scenarios with:

```sh
make ARCH=aarch64 TARGET=qemuvirt CONFIG_PKCS11=y WT_ENGINE=hsm \
    secure-image TOOLPREFIX=aarch64-none-elf-
WT_ENGINE=hsm tests/target/run_suite.sh qemu-a pkcs11 pkcs11neg
```

The older `pkcs11core`, `pkcs11objects`, `pkcs11crypto`, and
`pkcs11negative` scenario names remain available for focused debugging. The CI
gate uses `pkcs11`, which runs all four groups in one authenticated boot.

## Application and provider boundary

The application image contains the PKCS#11 proxy and FF-M client transport. It
does not contain the wolfPKCS11 provider, wolfTPM, or a TPM transport. Link-time
checks enforce that separation for the Zephyr, FreeRTOS, and Cortex-A
Normal-world builds.

The proxy supports the PKCS#11 single-threaded initialization contract. It
rejects partial mutex callback sets with `CKR_ARGUMENTS_BAD` and rejects caller
locking callbacks or `CKF_OS_LOCKING_OK` with `CKR_CANT_LOCK`; applications
must serialize `C_*` calls.

On Cortex-M, a second Non-secure image contains wolfPKCS11 and connects to
`SERVICE_HSM` for its cryptographic operations. On Cortex-A, wolfPKCS11 runs
inside the `SERVICE_PKCS11` S-EL0 partition and calls the separate HSM S-EL0
partition through secure-partition-to-secure-partition FF-M IPC. Its code,
read-only data, stack, and writable state are protected by the PKCS#11
partition's stage-1 translation table. The executable and read-only pages come
from the shared Secure image, while the private stack and writable-state pages
are mapped only for this partition.

Both providers are built with `WOLFPKCS11_NO_STORE`. They set
`WOLFPKCS11_DEFAULT_DEVID` to bind token slots to the wolfHSM-backed wolfCrypt
device without enabling a TPM-specific backend. PIN PBKDF2 runs in software so
its 600,000 rounds do not become 600,000 individual HSM IPC transactions; key
operations and the tested token cryptography still use the HSM device. Both
providers define `WC_NO_DEFAULT_DEVID` so the software PBKDF2 path cannot fall
back to the registered HSM device.

The embedded application suite covers:

- library, slot, token, and session behavior;
- object creation, lookup, attributes, and destruction;
- random, digest, HMAC, AES, P-256 ECDSA, and ECDH operations;
- invalid arguments, handles, state transitions, and signatures.

It requires all 38 cases to pass through the real proxy, relay, provider, and
HSM path. This is API-level runtime evidence, not a cross-compile-only check.

## SERVICE_PKCS11

`SERVICE_PKCS11` is a role-checked FF-M relay between the application and the
provider. It copies bounded requests and responses through its own Secure data
band, records the SPM-stamped caller identity, and refuses calls from the wrong
domain or role. The application cannot call `SERVICE_HSM` as the provider, and
the provider cannot impersonate the application.

The wire format carries PKCS#11 operation identifiers, handles, attributes,
mechanism parameters, and bounded data buffers. Handles remain provider-owned;
the proxy never receives a provider pointer.

## Isolation and CI

The PKCS#11 service runs as an isolation-level-3 Secure Partition. On
Cortex-M, the provider runs in a separate Non-secure domain from the
application. The M33MU `pkcs11neg` scenario proves that:

- another Secure Partition cannot read or write the PKCS11 data band;
- the relay cannot read provider guest RAM directly;
- the relay cannot execute from its execute-never data band;
- each deliberate fault is contained and the partition restarts;
- the mediated PKCS#11 path still completes after recovery.

On QEMU `virt`, `pkcs11neg` proves that another S-EL0 partition cannot read or
write the PKCS#11 state band, the PKCS#11 partition cannot read the HSM
partition's private RAM, and the PKCS#11 state band is execute-never. The
38-case suite still completes after those contained faults.

Pull-request CI has Zephyr and FreeRTOS `pkcs11` rows in the same explicit API
matrix as PSA and TPM. A separate `pkcs11neg` row keeps the L3 isolation proof
visible. The cross-compile workflow also builds `CONFIG_PKCS11=y` Secure images
for STM32H563 and MIMXRT700. The AArch64 QEMU matrix also runs `pkcs11` and
`pkcs11neg` on the `virt` cell and requires all 38 cases to pass.
