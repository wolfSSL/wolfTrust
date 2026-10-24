# TPM and PKCS#11 footprint

Measured on 2026-10-23 against base `7ae69b3cb6fae0a61e3d184264415d0ea0c01f36`
and engine-selection revision `9ccd5ec04c98f69f212c6a5c93221ca142e43ea3`.
Both interfaces now accept the same `WT_ENGINE=native|hsm` selection as PSA.

## Measurement settings

- Compiler: Arm GNU Toolchain 15.2.Rel1, GCC 15.2.1 20251203.
- Container: `ghcr.io/wolfssl/wolfboot-ci-m33mu@sha256:f6b66c9240ecd94f99400565196f956d1b067059b659a66dbbe83581cc7bf4c7`.
- Cortex-M33, `-Os`, default `WT_LTO=1`, two guest slots, default attestation.
- Both revisions use the same pins for their shared dependencies.

Flash is allocated `text + data` from `arm-none-eabi-size`; static RAM is
`data + bss`. The raw `.bin` includes address gaps and alignment. Debug
sections are excluded. Static RAM excludes reserved stacks, unused memory
protection windows, and dynamic peaks; it is not total runtime RAM.

## Secure image

All sizes are bytes. With both optional interfaces disabled, the PR retains
the base section totals and binary sizes for both engines on both targets.

| Target | Configuration | Flash | Static RAM | Raw .bin |
| --- | --- | ---: | ---: | ---: |
| stm32h563 | Base and PR, native, interfaces off | 94,960 | 27,856 | 96,624 |
| stm32h563 | Base and PR, hsm, interfaces off | 119,116 | 67,008 | 120,780 |
| stm32h563 | tpm, native | 96,208 | 28,912 | 97,872 |
| stm32h563 | tpm, hsm | 123,756 | 68,064 | 125,420 |
| stm32h563 | pkcs11, native | 96,688 | 36,112 | 98,384 |
| stm32h563 | pkcs11, hsm | 124,236 | 75,264 | 125,932 |
| mimxrt700 | Base and PR, native, interfaces off | 94,964 | 29,180 | 97,684 |
| mimxrt700 | Base and PR, hsm, interfaces off | 119,152 | 68,300 | 121,840 |
| mimxrt700 | tpm, native | 96,212 | 30,236 | 98,932 |
| mimxrt700 | tpm, hsm | 123,856 | 69,356 | 126,544 |
| mimxrt700 | pkcs11, native | 96,756 | 37,436 | 99,444 |
| mimxrt700 | pkcs11, hsm | 124,304 | 76,556 | 126,992 |

The increments below compare each interface with its own engine baseline.

| Target | Interface | Engine | Added flash | Added static RAM |
| --- | --- | --- | ---: | ---: |
| stm32h563 | tpm | native | 1,248 | 1,056 |
| stm32h563 | tpm | hsm | 4,640 | 1,056 |
| stm32h563 | pkcs11 | native | 1,728 | 8,256 |
| stm32h563 | pkcs11 | hsm | 5,120 | 8,256 |
| mimxrt700 | tpm | native | 1,248 | 1,056 |
| mimxrt700 | tpm | hsm | 4,704 | 1,056 |
| mimxrt700 | pkcs11 | native | 1,792 | 8,256 |
| mimxrt700 | pkcs11 | hsm | 5,152 | 8,256 |

The HSM interface builds also enable the server cipher modes needed by the
providers, including CFB, CTR, and CCM. Their extra flash includes those
handlers as well as the API relay.

Each interface uses an 8 KiB Secure partition stack from existing reserved
capacity. STM32H563 assigns a 2 KiB mailbox window to TPM or a 20 KiB data
window to PKCS#11. These window capacities differ from occupied static bytes.

## Reference application and provider images

The STM32H563 guest scripts use `-Os` and section garbage collection without
LTO. PKCS#11 uses the complete `all` application suite. Provider measurements
keep the production 600,000-round PIN KDF, with no emulator-only reduction.
The native PKCS#11 provider task uses a 16 KiB stack for software ECC; the
HSM provider task uses 8 KiB. Both allocate these stacks from the existing
28 KiB FreeRTOS heap, which is already counted in static RAM.

| Interface | Engine | Image | Flash | Static RAM | Raw .bin |
| --- | --- | --- | ---: | ---: | ---: |
| tpm | native | app | 32,754 | 49,196 | 32,754 |
| tpm | native | provider | 78,052 | 37,376 | 78,052 |
| tpm | hsm | app | 53,076 | 50,068 | 53,108 |
| tpm | hsm | provider | 89,532 | 38,752 | 89,532 |
| pkcs11 | native | app | 16,860 | 49,884 | 16,860 |
| pkcs11 | native | provider | 90,728 | 42,240 | 90,772 |
| pkcs11 | hsm | app | 16,860 | 49,884 | 16,860 |
| pkcs11 | hsm | provider | 102,912 | 43,224 | 102,956 |

The HSM fwTPM provider was remeasured after enabling implicit-device routing
for ECC and AES. Its ELF contains the device finder and retains the same
section totals shown above.

The existing FreeRTOS PSA reference client is unchanged: 11,980 flash bytes
and 17,200 static RAM bytes under native, or 32,388 flash bytes and 18,164
static RAM bytes under HSM. Its raw binaries are 11,980 and 32,428 bytes.

Secure image plus application plus provider gives these reference totals:

| Interface | Engine | Combined flash | Combined static RAM |
| --- | --- | ---: | ---: |
| tpm | native | 207,014 | 115,484 |
| tpm | hsm | 266,364 | 156,884 |
| pkcs11 | native | 204,276 | 128,236 |
| pkcs11 | hsm | 244,008 | 168,372 |

These sums exclude wolfBoot, signing headers, reserved flash slots, and
protection-window padding. The applications run different test workloads,
so comparing APIs is not a measurement of replacing the API in an otherwise
unchanged product. The fwTPM profile is volatile with NV disabled, and
wolfPKCS11 uses `WOLFPKCS11_NO_STORE`; persistent TPM/token profiles need
their own measurements.

## Service selection

Enabling either interface adds its relay to the existing manifest. It retains
crypto, vault, attestation, ITS, Protected Storage, and firmware update
services. It does not strip all PSA-facing functionality. `native` calls
wolfCrypt directly within the isolated provider; `hsm` uses the mediated
HSM callback for supported operations. Both use the same FF-M API relays.

On Cortex-M the provider is a separate Non-secure guest image. On Cortex-A
it is inside the S-EL0 Secure Partition, so these Cortex-M numbers must not
be applied to Cortex-A.

## Reproduce

Initialize the pinned dependencies in clean base and PR checkouts. Use the
recorded compiler and repeat for each target, engine, and interface:

```sh
for target in stm32h563 mimxrt700; do
    for engine in native hsm; do
        make -j8 TARGET="$target" WT_ENGINE="$engine" \
            BUILD_DIR="build/size-$target-$engine" secure-image
        for config in CONFIG_TPM CONFIG_PKCS11; do
            make -j8 TARGET="$target" WT_ENGINE="$engine" "$config=y" \
                BUILD_DIR="build/size-$target-$engine-$config" secure-image
        done
    done
done
arm-none-eabi-size build/size-*/wolftrust.elf
wc -c build/size-*/wolftrust.bin
```

On the base revision, run only the interface-disabled configuration. For
application/provider rows, initialize the FreeRTOS workspace, set the same
`WT_ENGINE`, and set `SECURE_CMSE_IMPLIB` to the matching Secure build.
The TPM fixture has `tpm-provider` and `tpm-freertos-app` Make targets. The
PKCS#11 fixture has `pkcs11-freertos-app` and `pkcs11-provider` targets.
Keep `WT_PKCS11_TEST_PBKDF2_ITERATIONS` unset for production sizes. Use
`arm-none-eabi-size` and `wc -c` on the resulting guest ELFs and binaries.

## Validation

All 70 host suites passed on macOS and Linux. All eight Cortex-M interface
Secure builds, four default/control Secure builds, eight application/provider
builds, and eight AArch64 interface cross-builds passed their applicable
link and layout checks. The control sizes match the original base.

STM32H563 M33MU passed both engines with Zephyr and FreeRTOS PSA, PKCS#11,
and TPM clients. Each PKCS#11 run passed all 40 cases. Both interface
isolation-negative scenarios passed on each engine. QEMU AArch64 passed
PSA, PKCS#11, TPM, and both interface isolation scenarios under each engine.
The API gates require a terminal pass marker, so an unsupported-engine skip
cannot count as a tested cell. These are emulator results, not physical-board
qualification.

The native Cortex-M provider initially overflowed its 8 KiB task stack in
software ECC. Its native task now uses 16 KiB, and the complete suite passes.
The HSM task retains 8 KiB. Zephyr TPM also links the TPM crypto-callback
source required when the HSM module enables wolfCrypt callbacks.

Runtime emulator gates lower the test PIN KDF to 25 rounds. That reduction
was not used for the production size rows.
