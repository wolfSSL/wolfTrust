# Footprint

Image size depends on the port, crypto engine and PSA Crypto placement.
The measurements below cover the native and wolfHSM engines where each port
supports them. [Macros](Macros.md#build-profiles) describes the build options.

## How sizes are measured

Every size here comes from the linked Secure ELF and its map, built with Arm
GNU 15.2.1 in `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25` with LTO at isolation
level 3:

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
configuration you compare. The cross-compile workflow checks the native
`WT_SECURE_PSA=0 WT_ATTEST_COSE=1` image on every port against the TF-M
isolation level 3 budget of 79,680 bytes of flash and 45,728 bytes of Secure
RAM. Ports that run code from RAM add that band to their budget
(`WT_RAMFUNC_SIZE`, 4 KiB on MIMXRT700).

## Measured sizes

Measured on 2026-11-20 from wolfTrust `6dbd14bc` with portable C wolfCrypt.
The figures are in bytes. The `full` profile enables two guests, Firmware
Update, boot-time manifest checks and unrolled SHA-256. PSA Crypto
placement stays the same across both profiles.

| Port | Engine | Default flash | Default RAM | `full` flash | `full` RAM |
| --- | --- | ---: | ---: | ---: | ---: |
| STM32H563 | native | 109,849 | 48,844 | 119,288 | 64,380 |
| STM32H563 | hsm | 98,308 | 83,932 | 108,032 | 107,916 |
| MIMXRT700 | native | 110,125 | 53,240 | 119,624 | 68,772 |
| MIMXRT700 | hsm | 98,584 | 88,324 | 108,400 | 112,308 |
| MCX N947 | native | 108,621 | 49,040 | 118,160 | 64,572 |
| MCX N947 | hsm | 97,048 | 84,124 | 106,872 | 108,108 |
| STM32L562 | native | 69,924 | 45,244 | 79,360 | 58,732 |

The native engine defaults to Secure PSA Crypto with the `compat` profile
on STM32H563, MIMXRT700 and MCX N947. STM32L562 keeps PSA Crypto in the
guest by default. The wolfHSM engine uses its own crypto transport with
`WT_SECURE_PSA=0`. MIMXRT700 RAM includes its 4 KiB code band.

[Crypto Engines](Crypto-Engines.md#psa-crypto-in-the-secure-image-wt_secure_psa1)
lists the supported algorithms and measured sizes for each Secure PSA profile.

To reproduce the guest-local size check for a port, build and report
with matching flags in a separate output directory.

```sh
make TARGET=stm32h563 WT_SECURE_PSA=0 WT_ATTEST_COSE=1 \
    BUILD_DIR=build-guest-local secure-image size-report
```

### Guest-local PSA Crypto

These native images use `WT_SECURE_PSA=0` with attestation enabled. The
cross-compile workflow uses this configuration for its size checks.

| Port | Flash | Secure RAM |
| --- | ---: | ---: |
| STM32H563 | 70,400 | 45,260 |
| MIMXRT700 | 70,712 | 49,656 |
| MCX N947 | 69,176 | 45,456 |
| STM32L562 | 69,924 | 45,244 |

## Options that change the size

Costs are relative to the STM32H563 native image with guest-local PSA
Crypto (`WT_SECURE_PSA=0`).

| Option | Adds | Flash / RAM | Speed |
| --- | --- | ---: | --- |
| `WT_MAX_GUESTS=2` | A second Non-secure guest, the scheduling between two, and an IPC message pool of 8 instead of 4 | +2,360 / +9,368 | Adds SAU, MPU and IRQ reprogramming on every guest switch |
| `WT_FWU=1` | PSA Firmware Update and its 4 KiB stack | +3,380 / +4,120 | None |
| `WT_MANIFEST_RUNTIME_CHECK=1` | The boot-time manifest and port-binding validator | +3,348 / 0 | Adds the validator run at boot |
| `WT_SHA256_FAST=1` | The unrolled SHA-256 transform | +416 / 0 | Faster guest verification at boot, attestation and the PSA hash service |
| `WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1` | wolfCrypt's Cortex-M assembly for ECC, AES and SHA-256, and the 9 KiB native crypto stack its P-256 verify needs | +8,988 / +4,096 | Faster ECC, AES and SHA-256 |
| `WT_ENGINE=hsm` | The wolfHSM server as the crypto engine, with its 10 KiB crypto stack and 24 KiB data band | +27,908 / +38,672 | Adds the wolfHSM request layer to each crypto call |
| `full` profile | The first four together | +9,440 / +13,488 | As above |

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
with guest-local PSA. The wolfHSM columns show `positive` on the default
profile and `bothpsa` on `full`.

| Stack | Size | Native, guest-local PSA | wolfHSM, default | wolfHSM, `full` |
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

For a single guest with guest-local PSA Crypto and all default services,
build the native image with LTO enabled.

```sh
make TARGET=<port> WT_SECURE_PSA=0 secure-image
```

Keep `WT_LTO=1` for size. Use `WT_LTO=0` for toolchain diagnostics.
The recorded `-Oz` build matched the size of the default `-Os` build.
This configuration keeps Crypto, Internal Trusted Storage, Protected Storage
and Initial Attestation at isolation level 3. `WT_ATTEST_COSE=0` removes
Initial Attestation and wolfCOSE for a smaller image without that service;
CI compile-checks it in the MIMXRT700 and MCX N947 builds, while every M33MU
run and the TF-M comparison keep attestation.

## Fastest image

For guest-local PSA Crypto, enable the unrolled SHA-256 transform and
wolfCrypt's Cortex-M assembly. Together they add 10,460 bytes of flash and
4,096 bytes of Secure RAM on STM32H563. Secure PSA Crypto requires the
constant-time C implementation of AES, so the Thumb-2 AES build requires
`WT_SECURE_PSA=0`.

```sh
make TARGET=<port> WT_SECURE_PSA=0 WT_SHA256_FAST=1 \
    WT_WOLFCRYPT_SP_ASM=1 WT_WOLFCRYPT_ARMASM=1 secure-image
```

Leave these at their defaults, which already favor speed:

- `WT_ENGINE=native` calls wolfCrypt directly.
- `WT_MAX_GUESTS=1` skips the per-switch reprogramming.
- `WT_MANIFEST_RUNTIME_CHECK=0` skips the boot-time validator.
