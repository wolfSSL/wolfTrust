# PKCS#11 Interface

wolfTrust lets an application call the standard PKCS#11 `C_*` API through the
Secure Partition Manager. The reference Cortex-M clients run under Zephyr and
FreeRTOS. The Cortex-A test client runs in the Normal world under QEMU. The
application uses a PKCS#11 proxy, while the real wolfPKCS11 token runs in an
isolated provider. PKCS#11 is a direct application interface to wolfTrust. It
does not use the PSA Crypto API and it does not depend on TPM support.

The HSM backend follows this path:

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

PKCS#11 uses the same `WT_ENGINE=native` (default) or `WT_ENGINE=hsm`
selector as PSA. Use the same engine for the Secure image and provider builds.

See [TPM and PKCS#11 footprint](Interface-Footprint.md) for measured Secure
and provider image sizes against the base revision.

Enable the service and its manifest in the Secure image with:

```sh
make TARGET=stm32h563 CONFIG_PKCS11=y WT_ENGINE=native secure-image \
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

The native provider runs wolfCrypt directly in its isolated domain. The HSM
provider registers the wolfHSM crypto callback and reaches `SERVICE_HSM`
through FF-M IPC. Both retain the same PKCS#11 proxy and relay protocol.

The proxy supports the PKCS#11 single-threaded initialization contract. It
rejects partial mutex callback sets with `CKR_ARGUMENTS_BAD` and rejects caller
locking callbacks or `CKF_OS_LOCKING_OK` with `CKR_CANT_LOCK`; applications
must serialize `C_*` calls.

`C_OpenSession` accepts `pApplication` and `Notify` and ignores them, as
wolfPKCS11 does. Neither pointer is sent to the provider. A NULL `phSession`
is still forwarded, so the provider returns wolfPKCS11's own error codes in
wolfPKCS11's own order.

On Cortex-M, a second Non-secure image contains wolfPKCS11 and uses the selected native or HSM backend for cryptographic operations. On Cortex-A, wolfPKCS11 runs
inside the `SERVICE_PKCS11` S-EL0 partition and uses wolfCrypt directly with `native`, or calls the separate HSM
S-EL0 partition through SP-to-SP FF-M IPC with `hsm`. Its code,
read-only data, stack, and writable state are protected by the PKCS#11
partition's stage-1 translation table. The executable and read-only pages come
from the shared Secure image, while the private stack and writable-state pages
are mapped only for this partition.

Both engine variants are built with `WOLFPKCS11_NO_STORE`. The native variant
keeps the token's device ID at `INVALID_DEVID` and links no wolfHSM client.
The HSM variant sets `WOLFPKCS11_DEFAULT_DEVID` to the wolfHSM device and
keeps `WC_NO_DEFAULT_DEVID` enabled so explicitly local operations stay local.
PIN PBKDF2 always runs in software; its 600,000 rounds do not become 600,000
individual HSM IPC transactions. Neither variant requires a TPM backend.

The M33MU and QEMU emulator gates lower the PBKDF2 count with the test-only
`WT_PKCS11_TEST_PBKDF2_ITERATIONS` setting because emulated hashing is too
slow; production provider builds keep the 600,000-round default.

The embedded application suite covers:

- library, slot, token, and session behavior;
- object creation, lookup, attributes, and destruction;
- random, digest, HMAC, AES, P-256 ECDSA, and ECDH operations;
- invalid arguments, handles, state transitions, and signatures;
- user PIN lockout after repeated wrong PINs, and SO recovery.

It requires all 40 cases to pass through the real proxy, relay, provider, and
HSM path. This is API-level runtime evidence, not a cross-compile-only check.

## PIN attempt limit

The provider partition has no trusted clock, so it is built with
`WOLFPKCS11_NO_TIME`, which removes wolfPKCS11's time-based failed-login
lockout. The provider enforces its own attempt limit instead, and that limit
does not use a clock:

- After `WT_PKCS11_PIN_MAX_FAILURES` consecutive failed checks of the user
  PIN (default 3), every later `C_Login` or `C_SetPIN` that would check the
  user PIN returns `CKR_PIN_LOCKED` without checking it.
- The SO PIN has its own count with the same limit. It covers SO `C_Login`,
  `C_SetPIN` in an SO session, and the SO PIN check in `C_InitToken`.
- Only a wrong PIN (`CKR_PIN_INCORRECT`) counts. A correct PIN before the
  limit resets that PIN's count, and a backend error after a correct PIN
  neither consumes nor clears an attempt.
- While a PIN is locked, a call that wolfPKCS11 rejects before it would test
  the PIN, such as a NULL or wrong-length PIN, an invalid user type, a
  read-only session, or a user who is already logged in, keeps its normal
  error code.
- The counts belong to the token slot. Closing sessions, opening new ones, or
  reconnecting to `SERVICE_PKCS11` does not reset them.
- A locked user PIN stays locked until the SO logs in and sets a new user PIN
  with `C_InitPIN`, or until `C_InitToken` re-initializes the token.
- A locked SO PIN stays locked until `C_InitToken` succeeds, and the provider
  refuses `C_InitToken` while the token is still initialized. The token is
  RAM-only (`WOLFPKCS11_NO_STORE`), so it is erased, along with all of its
  objects, when the last `C_Finalize` releases the library or the provider
  restarts. Both counts are cleared with it. A `C_Finalize` that leaves the
  library loaded, because of an extra `C_Initialize`, keeps the counts.
- `C_GetTokenInfo` reports the counts with the standard
  `CKF_USER_PIN_COUNT_LOW`, `CKF_USER_PIN_FINAL_TRY`, and
  `CKF_USER_PIN_LOCKED` flags and their SO equivalents.

The counts live in provider RAM, the same as the token they protect.

## SERVICE_PKCS11

`SERVICE_PKCS11` is a role-checked FF-M relay between the application and the
provider. It copies bounded requests and responses through its own Secure data
band, records the SPM-stamped caller identity, and refuses calls from the wrong
domain or role. The application cannot call `SERVICE_HSM` as the provider, and
the provider cannot impersonate the application.

The wire format carries PKCS#11 operation identifiers, handles, attributes,
mechanism parameters, and bounded data buffers. Handles remain provider-owned;
the proxy never receives a provider pointer. Caller buffers, templates, output
lists, and mechanism parameters keep their NULL or non-NULL state across the
boundary, even at length zero, so wolfPKCS11 applies its own argument checks.

Mechanism parameters that contain further pointers cannot cross the wire. The
provider therefore leaves `CKM_RSA_PKCS_OAEP`, `CKM_HKDF_DERIVE`,
`CKM_HKDF_DATA`, `CKM_AES_CBC_ENCRYPT_DATA`, the TLS 1.2 key-derivation
mechanisms, and `CKM_PKCS5_PBKD2` out of `C_GetMechanismList`, and
`C_GetMechanismInfo` returns `CKR_MECHANISM_INVALID` for them.

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
40-case suite still completes after those contained faults.

Pull-request CI has Zephyr and FreeRTOS `pkcs11` rows in the same explicit API
matrix as PSA and TPM. A separate `pkcs11neg` row keeps the L3 isolation proof
visible. The cross-compile workflow also builds `CONFIG_PKCS11=y` Secure images
for STM32H563 and MIMXRT700. The AArch64 QEMU matrix also runs `pkcs11` and
`pkcs11neg` on the `virt` cell and requires all 40 cases to pass.
