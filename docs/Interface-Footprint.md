# Application-interface footprint

Measured on 2026-10-26 for STM32H563 with the configurable default operation
profile. All six configurations exercise RNG, SHA-256 and P-256 key generation,
signing and verification. `native` and `hsm` select the engine independently of
PSA, TPM or PKCS#11.

Earlier figures compared a PSA RNG/hash application with broader TPM and
PKCS#11 suites. That comparison overstated the cost of replacing the application
API. The old 11,980-byte native PSA application did not include P-256.

## Comparable default builds

Flash is `text + data`, in bytes. Each total includes the Secure runtime, one
FreeRTOS application, and its isolated provider where required. These are linked
section sizes, excluding debug information, image signatures and unused flash
address gaps. They are not archive, source-file or reserved partition sizes.

| Engine | API | Secure | Application | Provider | Total | Above same-engine PSA |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| native | PSA | 94,960 | 33,488 | 0 | 128,448 | 0 |
| native | TPM | 96,240 | 15,596 | 44,920 | 156,756 | 28,308 |
| native | PKCS#11 | 96,688 | 11,152 | 54,605 | 162,445 | 33,997 |
| hsm | PSA | 119,148 | 43,156 | 0 | 162,304 | 0 |
| hsm | TPM | 123,756 | 15,596 | 40,752 | 180,104 | 17,800 |
| hsm | PKCS#11 | 124,236 | 11,152 | 51,288 | 186,676 | 24,372 |

The default TPM application sends its operations to the TPM provider and links
no application-side wolfCrypt or wolfHSM client. Its size is the same for both
engines. PKCS#11 applications likewise use the provider selected by the build.
Neither interface links wolfPSA Crypto. Their `psa_connect`/`psa_call` functions
are the shared FF-M IPC transport.

This is a common crypto workload, not equal protocol semantics. PKCS#11 also
implements token/session/object state, PIN protection and wire serialization.
TPM implements TPM command parsing, capabilities, authorization and object
lifecycle. Both Cortex-M configurations have an additional isolated provider
runtime. PSA runs its front end in the application. The remaining 18-34 KB gap
is real; these measurements do not establish parity with PSA.

All builds retain the Secure vault, RNG, attestation, storage and update services.
Selecting an application API does not remove those unrelated Secure services.
The API-disabled Secure image exactly matches the pinned base under the same
compiler/settings: 94,960 bytes with native, 119,148 bytes with HSM. Neither
optional interface adds flash when disabled.

## Savings and retained behavior

The previous full reference builds used no guest LTO and kept broader API suites
plus software crypto fallbacks. Their totals are retained here only to show the
combined reduction; they are not operation-equivalent baselines.

| Engine | API | Previous full reference | Current default | Reduction |
| --- | --- | ---: | ---: | ---: |
| native | TPM | 207,014 | 156,756 | 50,258 |
| native | PKCS#11 | 204,276 | 162,445 | 41,831 |
| hsm | TPM | 266,364 | 180,104 | 86,260 |
| hsm | PKCS#11 | 244,008 | 186,676 | 57,332 |

The changes remove unselected API dispatch roots, let the linker discard their
handlers, enable guest crypto LTO with opaque RTOS/IPC boundaries, and remove
unneeded application-side TPM crypto. TPM/PKCS#11 HSM providers use callback-only ECC instead
of retaining software group arithmetic alongside the HSM implementation.
`WT_PROVIDER_ECC_FALLBACK=1` restores that fallback if a custom client needs it.
The HSM server retains software ECC; native builds retain direct wolfCrypt ECC.
PSA keeps software ECC needed by its deterministic-signature API. Removing it
failed two PSA conformance cases, so those bytes are retained.

The default preserves PIN setup, login, attempt limits and SO recovery. Public
HMAC/AES mechanisms can be removed while their primitives remain necessary for
PIN or object protection. No PIN iteration count is reduced in production.
The `full` profile retains the broader reference suites, including the 40-case
PKCS#11 regression. Individual operations can be added or removed independently
as described in [Crypto-Profiles.md](Crypto-Profiles.md).

Static RAM is `data + bss`, including the configured guest heaps. It does not
include dynamic peak usage or unused reserved MPU windows. Operation pruning
primarily reduces flash; it does not automatically shrink heap/stack capacities.

## Reproduce

- Pinned base: `7ae69b3cb6fae0a61e3d184264415d0ea0c01f36`.
- Compiler: Arm GNU Toolchain 15.2.Rel1, GCC 15.2.1.
- Container: `ghcr.io/wolfssl/wolfboot-ci-m33mu@sha256:f6b66c9240ecd94f99400565196f956d1b067059b659a66dbbe83581cc7bf4c7`.
- Cortex-M33, `-Os`, `WT_LTO=1`, two guest slots, default attestation and
  production 600,000-round PKCS#11 PIN KDF.
- The same pinned dependency sources and compiler are used for every row.

Inside that container, initialize the repository dependencies and FreeRTOS
workspace, then run:

```sh
WT_CRYPTO_PROFILE=default bash tools/measure_interface_footprint.sh
```

The output directory contains `sizes.csv`, compiler/source configuration, build
logs, generated operation selections and all measured ELFs. Set the first
argument to choose a separate output directory. Use `WT_CRYPTO_PROFILE=full` for
the broader profile; the reference workloads then differ and must be labeled.

Runtime gates use the same profile selections and authenticated
wolfBoot -> wolfTrust -> application/provider chain under M33MU. Emulator-only
PIN tests explicitly use 25 PBKDF2 rounds to bound execution time; production
size measurements retain 600,000. Emulator evidence is separate from physical
board qualification.

TPM selections containing `ZGen_2Phase` retain software ECC point arithmetic
because its full-point operation is outside the HSM ECDH callback. Adding that
command restores the dependency automatically; it is absent from the small
default profile.
