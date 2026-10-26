# Application-interface footprint

Measured on 2026-10-26 for STM32H563. All six default-profile builds exercise
RNG, SHA-256, P-256 key generation, signing, and verification. Every row has one
FreeRTOS application and one wolfTrust image. TPM and PKCS#11 run directly in
Secure partitions; no provider image, extra RTOS, or worker is built or loaded.

## Matched default builds

Flash is linked `text + data`, in bytes. It excludes debug information, image
signatures, and unused address gaps. It is not source size, archive size, or a
reserved partition's capacity.

| Engine | API | Secure | Application | Total | Above same-engine PSA |
| --- | --- | ---: | ---: | ---: | ---: |
| native | PSA | 94,208 | 33,488 | 127,696 | 0 |
| native | TPM | 116,332 | 15,476 | 131,808 | 4,112 |
| native | PKCS#11 | 125,276 | 11,052 | 136,328 | 8,632 |
| hsm | PSA | 118,076 | 43,156 | 161,232 | 0 |
| hsm | TPM | 160,960 | 15,476 | 176,436 | 15,204 |
| hsm | PKCS#11 | 164,384 | 11,052 | 175,436 | 14,204 |

The API-disabled Secure images exactly match the pinned base under these
settings: 94,208 bytes native and 118,076 bytes HSM. Disabling both optional
interfaces adds no Secure flash cost. Vault, RNG, attestation, storage, and
update services remain enabled in every row.

TPM and PKCS#11 link no wolfPSA Crypto implementation. Their `psa_call` helpers
use the existing FF-M IPC transport. The default TPM application also links no
local wolfCrypt/HSM engine, so its size is identical for both engine choices.
Native PSA runs wolfPSA and wolfCrypt in the application; native TPM and
PKCS#11 run their protocol implementations in Secure partitions.

The extra RTOS and duplicate native math were removable overhead. The current
remaining differences are smaller, but PSA parity has not been reached. These
measurements do not establish a minimum size for either protocol. The retained
code implements TPM commands, authorization, and object formats, or PKCS#11
token/session/object state, PIN protection, and wire handling.

## Reductions and retained operations

The previous default builds used a separate Cortex-M provider guest:

| Engine | API | Previous total | Current total | Reduction |
| --- | --- | ---: | ---: | ---: |
| native | TPM | 156,756 | 131,808 | 24,948 |
| native | PKCS#11 | 162,445 | 136,328 | 26,117 |
| hsm | TPM | 180,104 | 176,436 | 3,668 |
| hsm | PKCS#11 | 186,676 | 175,436 | 11,240 |

The new layout removes the provider guest, its scheduler, and asynchronous
forwarding/polling. TPM executes each command in one copied call. PKCS#11
keeps bounded chunking for 4096-byte messages, with one execution call and no
worker polling. Native domains share stateless crypto code already in flash.
Both engines share low-level integer and assembly code, while HSM callbacks
and the software fallback paths that use them remain private. Writable-state
ownership checks reject unsafe sharing.

Operations remain individually configurable. The default removes unselected
public AES/HMAC mechanism dispatch while keeping the internal PIN primitives
and common structure layouts. The full profile restores the broader reference
suite. Production PIN PBKDF2 remains at 600,000 rounds. See
[Crypto-Profiles.md](Crypto-Profiles.md) for selection and dependencies.

`WT_PROVIDER_ECC_FALLBACK=1` restores optional software ECC fallback in HSM
builds. Native always retains software ECC. TPM `ZGen_2Phase` selections
restore the software point arithmetic they require. PSA retains software ECC
needed by deterministic-signature operations.

Static RAM is `data + bss`, including configured heaps. It is separate from
flash and from dynamic peak usage or unused MPU window capacity. The Cortex-M
interface region reserves 48 KiB for state and 16 KiB for its stack. PKCS#11
uses a bounded private 28-KiB heap inside that state region; the volatile
fwTPM configuration has no heap.

## Reproduce

- Base: `7ae69b3cb6fae0a61e3d184264415d0ea0c01f36`.
- Compiler: Arm GNU Toolchain 15.2.Rel1, GCC 15.2.1.
- Container: `ghcr.io/wolfssl/wolfboot-ci-m33mu@sha256:f6b66c9240ecd94f99400565196f956d1b067059b659a66dbbe83581cc7bf4c7`.
- Cortex-M33, `-Os`, `WT_LTO=1`, one guest slot, default attestation, and
  production PIN KDF settings. All rows use the same pinned dependencies.

Initialize dependencies and the FreeRTOS workspace inside that container, then:

```sh
WT_CRYPTO_PROFILE=default bash tools/measure_interface_footprint.sh
```

The output contains `sizes.csv`, compiler/source configuration, logs, generated
operation selections, symbol/section reports, and all measured ELFs. The first
argument chooses an output directory. `WT_CRYPTO_PROFILE=full` measures the
broader profile, whose reference workloads differ from the default.

Earlier 11,980-byte native PSA application figures covered RNG/hash without
P-256. They are not a comparable baseline for these builds.

## Validation

Local host tests exercise the synchronous production transports through the
FF-M runtime, including exact bounds, identity checks, zeroization, connection
recovery, and prevention of implicit replay. M33MU and QEMU run the actual
fwTPM and wolfPKCS#11 implementations under both engines and profiles, with
partition isolation and restart tests. The Cortex-M clients cover Zephyr,
FreeRTOS, and the bare-metal TPM isolation client.

Emulator-only PIN tests explicitly use 25 PBKDF2 rounds to bound execution
time. Size measurements retain 600,000 rounds. Emulator and cross-build results
are recorded separately from physical hardware qualification. Final commit
and CI evidence are recorded after the tested branch update.
