# Footprint

This page records the measured size of the Secure image and lists every build
option that changes it. The native image with PSA Crypto in the guest
(`WT_SECURE_PSA=0`) is the smallest that keeps every PSA service;
`WT_ATTEST_COSE=0` builds a smaller one without Initial Attestation. Each
option below adds a feature back, and the table gives its cost.
[Crypto Engines](Crypto-Engines.md#psa-crypto-in-the-secure-image-wt_secure_psa1)
has the sizes of the `tiny`, `small`, `default` and `extended` profiles with
PSA Crypto in the Secure image.
[Macros](Macros.md#build-profiles) has the full description of each option.

## How sizes are measured

Every size here comes from the linked Secure ELF and its map, built with Arm
GNU 15.2.1 in `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25` with LTO at isolation
level 3. The `interface-footprint` CI job runs in `v1.15`, which ships the same
toolchain and gives byte-identical sizes:

```text
Flash = text + data
RAM   = reserved Secure RAM: SPM .data + .bss, the SPM main stack, and every
        partition data band and stack at its full length
```

`arm-none-eabi-size` cannot give the RAM figure. The level 3 partition stacks
and data bands are linker regions with no section in them, so `data + bss`
leaves them out. `tools/secure_ram.py` reads them from the map. TF-M places its
partition stacks inside its `.bss`, so its `data + bss` already counts them.

To reproduce a size, build the image and read it:

```sh
make TARGET=stm32h563 secure-image
make TARGET=stm32h563 size-report
```

`size-report` prints the reserved Secure RAM with its breakdown, and the
largest sections and `.bss` objects. Use a separate `BUILD_DIR` for each
configuration you compare. The cross-compile workflow fails if the native
`WT_SECURE_PSA=0` image on any port grows past 79,680 bytes of flash or 45,728 bytes of
reserved Secure RAM, TF-M level 3's figures on the STM32L562E-DK. A port that
runs code from a RAM band (`WT_RAMFUNC_SIZE`, 4 KiB on the MIMXRT700) is
allowed that band on top.

## Measured sizes

Measured 2026-11-17 on the `WT_SECURE_PSA=0` image, with wolfCrypt built as
portable C (the default). The `extended` columns turn on the four add-ons the
`extended` profile sets
(`WT_MAX_GUESTS=2 WT_FWU=1 WT_MANIFEST_RUNTIME_CHECK=1 WT_SHA256_FAST=1`).

| Port | Engine | Default flash | Default RAM | `extended` flash | `extended` RAM |
| --- | --- | ---: | ---: | ---: | ---: |
| STM32H563 | native | 70,432 | 45,260 | 79,840 | 58,748 |
| STM32H563 | hsm | 98,308 | 83,932 | 108,032 | 107,916 |
| MIMXRT700 | native | 70,712 | 49,656 | 80,172 | 63,140 |
| MIMXRT700 | hsm | 98,584 | 88,324 | 108,400 | 112,308 |
| MCX N947 | native | 69,208 | 45,456 | 78,676 | 58,940 |
| MCX N947 | hsm | 97,048 | 84,124 | 106,872 | 108,108 |
| STM32L562 | native | 69,496 | 45,280 | 78,928 | 58,780 |

The MIMXRT700 RAM includes its 4 KiB RAM code band (the NSC gateway and the
NOR program code). The STM32L562 figures were measured on the STM32L562 port,
which is under review and not yet in this tree, merged with these sources
before the shared port layer landed. That port builds the native engine only.
Update this table and its date when a change moves an image size.

## Options that change the size

Costs are over the native default on the STM32H563. Every option is off in
the default.

| Option | Adds | Flash / RAM | Speed |
| --- | --- | ---: | --- |
| `WT_MAX_GUESTS=2` | A second Non-secure guest, the scheduling between two, and an IPC message pool of 8 instead of 4 | +2,328 / +9,368 | Adds SAU, MPU and IRQ reprogramming on every guest switch |
| `WT_FWU=1` | PSA Firmware Update and its 4 KiB stack | +3,348 / +4,120 | None |
| `WT_MANIFEST_RUNTIME_CHECK=1` | The boot-time manifest and port-binding validator | +3,316 / 0 | Adds the validator run at boot |
| `WT_SHA256_FAST=1` | The unrolled SHA-256 transform | +384 / 0 | Faster guest verification at boot, attestation and the PSA hash service |
| `WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1` | wolfCrypt's Cortex-M assembly for ECC, AES and SHA-256, and the 9 KiB native crypto stack its P-256 verify needs | +8,956 / +4,096 | Faster ECC, AES and SHA-256 |
| `WT_ENGINE=hsm` | The wolfHSM server as the crypto engine, with its 10 KiB crypto stack and 24 KiB data band | +27,876 / +38,672 | Adds the wolfHSM request layer to each crypto call |
| `extended` profile add-ons | The first four together | +9,408 / +13,488 | As above |

With the wolfHSM engine, `WT_MAX_GUESTS=2` costs +2,648 bytes of flash and
+19,864 bytes of RAM, because each guest gets its own server stack.

Each partition stack is sized from the high-water mark measured on M33MU
across the positive, restart, recovery, update and Arm conformance scenarios
on both engines, with at least 512 bytes and 12.5% of headroom, in 1 KiB
steps. `PSPLIM_S` faults a partition that overruns its stack; the SPM restarts
it under its restart policy, and fails closed once that budget is spent. A
data band its sections outgrow fails the link. Each size is a macro in
`port/common/armv8m/l3_layout.h` a port or build can override.

Stack high-water marks on the STM32H563, read from M33MU RAM dumps filled
with `0xA5` (2026-11-17). The native column is the `nativewire` scenario,
which runs the positive lifecycle and every native wire key op from the
guest; the wolfHSM column is `positive` on the default profile and `bothpsa`
on `extended`.

| Stack | Size | Native, default | wolfHSM, default | wolfHSM, `extended` |
| --- | ---: | ---: | ---: | ---: |
| SPM main | 4,096 | 2,200 | 1,124 | 1,244 |
| Crypto | 5,120 native, 10,240 wolfHSM | 4,416 | 7,608 | 7,676 |
| Protected Storage | 3,072 | 1,880 | 1,880 | 1,880 |
| Internal Trusted Storage | 3,072 | 1,880 | 1,880 | 1,880 |
| Vault | 5,120 | 3,508 | 3,616 | 3,616 |
| Attestation | 5,120 | 3,680 | 3,572 | 3,652 |
| Firmware Update | 4,096 | not built | not built | 1,872 |

With `WT_WOLFCRYPT_SP_ASM=1` the native crypto stack peaks at 7,240 bytes in
the P-256 verify, which is why that build reserves 9 KiB.

These options also add code but are not part of a production size budget:

- `CONFIG_VNET=y` links the virtual network switch for the two-guest VNET
  demo.
- `WT_CONFORMANCE=1` builds the Arm PSA API test manifest and sources.
- `WT_GUEST_FLASH_WRP=1` checks hardware write protection of each guest
  window before launch. Turn it on for hardened production images whatever
  the size.

## Smallest image

Build with no options:

```sh
make TARGET=<port> secure-image
```

That is the native engine, one guest, LTO on, and every add-on off. Keep
`WT_LTO=1`; `WT_LTO=0` is for toolchain diagnostics and builds a larger
image. `-Oz` was measured against the default `-Os` and gave no smaller
image. The default keeps Crypto, Internal Trusted Storage, Protected Storage
and Initial Attestation at isolation level 3. `WT_ATTEST_COSE=0` removes
Initial Attestation and wolfCOSE for a smaller image without that service;
CI compile-checks it in the MIMXRT700 and MCX N947 builds, while every M33MU
run and the TF-M comparison keep attestation.

## Fastest image

Add the unrolled SHA-256 transform and wolfCrypt's Cortex-M assembly for
ECC, AES and SHA-256 (+10,428 bytes of flash and +4,096 bytes of RAM together
on the STM32H563):

```sh
make TARGET=<port> WT_SHA256_FAST=1 WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1 secure-image
```

Leave these at their defaults, which already favor speed:

- `WT_ENGINE=native` calls wolfCrypt directly.
- `WT_MAX_GUESTS=1` skips the per-switch reprogramming.
- `WT_MANIFEST_RUNTIME_CHECK=0` skips the boot-time validator.

## TPM 2.0 and PKCS#11

`CONFIG_TPM=y` or `CONFIG_PKCS11=y` replaces PSA Crypto as the application API,
so the comparison covers both images: the Secure image and the application that
calls it. `tools/measure_interface_footprint.sh` builds each port, engine and
API with `WT_INTERFACE_PROFILE=default` and checks that every pair is present;
the cross-compile workflow publishes its CSV. Measured 2026-11-24.

Flash is Secure plus application, in bytes; RAM is reserved Secure RAM.

| Port | Engine | PSA flash | TPM 2.0 flash | PKCS#11 flash | PSA RAM | TPM 2.0 RAM | PKCS#11 RAM |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| STM32H563 | native | 144,353 | 133,116 (-7.8%) | 115,832 (-19.8%) | 48,332 | 83,148 | 98,508 |
| STM32H563 | hsm | 176,772 | 172,912 (-2.2%) | 152,784 (-13.6%) | 83,932 | 123,868 | 139,228 |
| MIMXRT700 | native | 144,597 | 133,328 (-7.8%) | 116,080 (-19.7%) | 52,728 | 87,544 | 102,904 |
| MIMXRT700 | hsm | 177,016 | 173,128 (-2.2%) | 153,064 (-13.5%) | 88,324 | 128,260 | 143,620 |
| MCX N947 | native | 143,093 | 131,856 (-7.9%) | 114,592 (-19.9%) | 48,528 | 83,344 | 98,704 |
| MCX N947 | hsm | 175,512 | 171,656 (-2.2%) | 151,544 (-13.7%) | 84,124 | 124,060 | 139,420 |
| STM32L562 | native | 135,340 | 132,604 (-2.0%) | 115,332 (-14.8%) | 45,244 | 83,132 | 98,492 |

The application shrinks because it no longer links a PSA Crypto client: the
PKCS#11 proxy is under 8 KB. The Secure image grows by the provider (fwTPM or
wolfPKCS11) and its private wolfCrypt copy. The wolfTPM client keeps its own
wolfCrypt for sessions and takes its entropy from `TPM2_GetRandom`, so it links
no crypto engine client and is the same size under both engines.

TPM 2.0 includes fwTPM dictionary-attack lockout; `WT_TPM_DA=0` saves about
2.3 KB of Secure flash.

The extra RAM is the interface band above SPM RAM, sized from the `extended`
profile on the STM32H563 with the stack method above:

| Band | Data used / reserved | Stack peak / reserved |
| --- | ---: | ---: |
| TPM 2.0, native | 24,736 / 28,672 | 7,712 / 9,216 |
| TPM 2.0, hsm | 26,144 / 28,672 | 7,384 / 9,216 |
| PKCS#11, native | 42,016 / 45,056 | 6,784 / 8,192 |
| PKCS#11, hsm | 43,008 / 45,056 | 5,288 / 8,192 |

PKCS#11 data includes its 28 KiB token heap (`WT_PKCS11_HEAP_SIZE`). With the
hsm engine the crypto partition band grows from 0x6000 to 0x6800 bytes, because
the interface provider holds its own wolfHSM client namespace. On the STM32L562
both interfaces use the 160 KiB Secure slot of the conformance layout; the
default 128 KiB slot leaves too little room once wolfBoot reserves its last
sector.
