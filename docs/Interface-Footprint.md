# TPM and PKCS#11 footprint

Measured on 2026-10-23 against base `7ae69b3cb6fae0a61e3d184264415d0ea0c01f36`
and interface revision `55267796d57bac796e087e52079d2b50e25699f7`.
The latter adds license comments to the reviewed interface revision `d943cfb3`.

## Measurement settings

- Compiler: Arm GNU Toolchain 15.2.Rel1, GCC 15.2.1 20251203.
- Container: `ghcr.io/wolfssl/wolfboot-ci-m33mu@sha256:f6b66c9240ecd94f99400565196f956d1b067059b659a66dbbe83581cc7bf4c7`.
- Cortex-M33, `-Os`, default `WT_LTO=1`, two guest slots, default attestation.
- Each revision uses its pinned dependencies. The shared dependency pins are identical.
- Both optional interfaces are disabled for the native and HSM baseline rows.

Flash below is allocated `text + data` from `arm-none-eabi-size`. Static RAM is
`data + bss`. The raw `.bin` includes address gaps and alignment, so its byte
count is reported separately. Debug sections in the ELF are excluded.
Static RAM excludes reserved stacks, unused protection-window space, and
dynamic peaks. These numbers are not a measurement of total runtime RAM.

## Secure image

All sizes are bytes. Base and PR builds with both interfaces disabled have
identical section totals on both targets, for both engines.

| Revision | Target | Configuration | Flash | Static RAM | Raw .bin |
| --- | --- | --- | ---: | ---: | ---: |
| Base | stm32h563 | native, interfaces off | 94,960 | 27,856 | 96,624 |
| Base | stm32h563 | HSM, interfaces off | 119,116 | 67,008 | 120,780 |
| Base | mimxrt700 | native, interfaces off | 94,964 | 29,180 | 97,684 |
| Base | mimxrt700 | HSM, interfaces off | 119,152 | 68,300 | 121,840 |
| PR | stm32h563 | native, interfaces off | 94,960 | 27,856 | 96,624 |
| PR | stm32h563 | HSM, interfaces off | 119,116 | 67,008 | 120,780 |
| PR | stm32h563 | native + TPM | 96,208 | 28,912 | 97,872 |
| PR | stm32h563 | HSM + PKCS#11 | 120,844 | 75,264 | 122,540 |
| PR | mimxrt700 | native, interfaces off | 94,964 | 29,180 | 97,684 |
| PR | mimxrt700 | HSM, interfaces off | 119,152 | 68,300 | 121,840 |
| PR | mimxrt700 | native + TPM | 96,212 | 30,236 | 98,932 |
| PR | mimxrt700 | HSM + PKCS#11 | 120,880 | 76,556 | 123,600 |

On either target, TPM adds 1,248 bytes of flash and 1,056 bytes of static RAM
over the native baseline. PKCS#11 adds 1,728 bytes of flash and 8,256 bytes
of static RAM over the HSM baseline. Its raw `.bin` grows by 1,760 bytes.

PKCS#11 requires `WT_ENGINE=hsm`. Compared with the default native build on
STM32H563, selecting HSM plus PKCS#11 adds 25,884 bytes of flash and 47,408
bytes of static RAM. The HSM engine accounts for most of that difference.

Each interface also uses an 8 KiB Secure partition stack from the existing
conformance scratch window. The STM32H563 TPM mailbox has a 2 KiB protection
window; PKCS#11 carves a 20 KiB data window from general Secure RAM. Reserved
capacity is distinct from the occupied static bytes in the table.

## Service selection

Enabling TPM or PKCS#11 adds its relay to the existing service manifest.
It retains the HSM/native crypto, vault, attestation, ITS, Protected Storage,
and firmware update services. It does not select a profile that strips all
PSA-facing functionality. FF-M `psa_connect`, `psa_call`, and `psa_close`
are also still the transport. Neither interface uses the PSA Crypto API
for its own operation payloads.

On Cortex-M the fwTPM or wolfPKCS11 provider is in a separate Non-secure
image. The Secure-image deltas above do not include that provider or the
application. On Cortex-A the provider runs inside the Secure image, so these
Cortex-M size deltas must not be applied to Cortex-A.

## Reproduce the Secure builds

Use separate clean checkouts at the revisions above, initialize their pinned
submodules, and run the following with the recorded compiler. Repeat with
`TARGET=mimxrt700`. Run only the first two configurations on the base revision.

```sh
make -j8 TARGET=stm32h563 WT_ENGINE=native BUILD_DIR=build/size-native secure-image
make -j8 TARGET=stm32h563 WT_ENGINE=hsm BUILD_DIR=build/size-hsm secure-image
make -j8 TARGET=stm32h563 WT_ENGINE=native CONFIG_TPM=y \
    BUILD_DIR=build/size-tpm secure-image
make -j8 TARGET=stm32h563 WT_ENGINE=hsm CONFIG_PKCS11=y \
    BUILD_DIR=build/size-pkcs11 secure-image
arm-none-eabi-size build/size-*/wolftrust.elf
wc -c build/size-*/wolftrust.bin
```

## Reference guest images

These STM32H563 guest builds use the same compiler, `-Os`, and section garbage
collection as the existing firmware scripts. The scripts do not enable LTO.
The PKCS#11 application uses the complete `all` suite. Its provider keeps the
production 600,000-round PIN PBKDF2 default; emulator-only reductions are not
used for these size rows.

| Image | Flash | Static RAM | Raw .bin |
| --- | ---: | ---: | ---: |
| Base FreeRTOS PSA client, native | 11,980 | 17,200 | 11,980 |
| PR FreeRTOS PSA client, native | 11,980 | 17,200 | 11,980 |
| Base FreeRTOS PSA client, HSM | 32,388 | 18,164 | 32,428 |
| PR FreeRTOS PSA client, HSM | 32,388 | 18,164 | 32,428 |
| PR FreeRTOS TPM test application | 32,754 | 49,196 | 32,754 |
| PR bare-metal fwTPM provider | 78,052 | 37,376 | 78,052 |
| PR FreeRTOS PKCS#11 test application | 16,880 | 49,884 | 16,880 |
| PR FreeRTOS wolfPKCS11 provider | 102,912 | 43,228 | 102,956 |

The PSA reference client is unchanged in size on the PR. Replacing it with
a TPM or PKCS#11 application does not remove the separate provider cost.
For the complete reference test images, Secure image plus application plus
provider totals are 207,014 flash bytes and 115,484 static RAM bytes for TPM,
or 240,636 flash bytes and 168,376 static RAM bytes for PKCS#11. These sums
exclude wolfBoot, image-signing headers, reserved flash slots, reserved
stacks, and protection-window padding.

The reference applications exercise different test workloads, so their size
difference is not an isolated measurement of swapping APIs in one unchanged
product application. The provider profiles are also deliberately limited:
fwTPM is volatile with NV disabled, and wolfPKCS11 is built without backing
store. These are not full persistent TPM/token configurations.

To reproduce the reference guest rows, initialize the FreeRTOS workspace,
use the matching STM32H563 Secure build from the preceding commands, and set
`SECURE_CMSE_IMPLIB` to its `secure_cmse_implib.o`. For the generic PSA client,
run `tests/firmware/zephyr-stm32h5/scripts/build_freertos_guest.sh` with the
matching `WT_ENGINE`. For TPM, run the fixture's `tpm-provider` Make target
and `scripts/build_freertos_tpm.sh` from that fixture. For
PKCS#11, run its `scripts/build_freertos_pkcs11.sh` and
`scripts/build_freertos_pkcs11_provider.sh`. Each script accepts
`FREERTOS_DIR`, and the interface scripts accept a separate `BUILD_DIR`.
Keep `WT_PKCS11_TEST_PBKDF2_ITERATIONS` unset for production provider sizes.

## Validation

The source revision above passed all 70 host suites on macOS and Linux, all
12 Secure builds with their post-link layout checks, and all eight reference
guest builds with their existing symbol checks.

The authenticated wolfBoot-to-wolfTrust chain passed `tpm`, `pkcs11`,
`tpmneg`, and `pkcs11neg` on STM32H563 M33MU with FreeRTOS applications.
The positive PKCS#11 run passed all 40 cases. The negative runs verified
partition isolation, contained faults, restart, and a working service after
recovery. These are emulator results; MIMXRT700 rows are build measurements.

The emulator runs use the runner's 25-round test PIN setting. That setting
was not used for the production provider size measurements above.
