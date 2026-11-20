# Footprint Comparison

These are recorded local measurements, not compatibility or certification
claims. [Footprint](Footprint.md) documents the wolfTrust size accounting,
build options, and per-port measurements; [FF-M Compatibility](FF-M-Compatibility.md)
records the framework contract separately.

## STM32L562 comparison

Both runtimes were built for STM32L562E-DK at isolation level 3 with
Arm GNU 15.2.1. The wolfTrust runtime was remeasured on 2026-11-20 with
the current layout at `6dbd14bc`. The TF-M and bootloader rows retain
their recorded measurements. See the
[STM32L562 Guide](STM32L562-Guide.md#status) for board validation.

| Image | Flash | Secure RAM |
| --- | ---: | ---: |
| wolfTrust Secure runtime, guest-local PSA Crypto | 69,924 bytes | 45,244 bytes |
| TF-M v2.3.1 `tfm_s`, level 3 | 79,680 bytes | 45,728 bytes |
| wolfBoot, STM32L5 secure application handoff | 27,216 bytes | 2,104 bytes |
| TF-M BL2 (MCUboot, EC-P256) | 38,744 bytes | 27,408 bytes |
| Chain: wolfBoot + wolfTrust | 97,140 bytes | |
| Chain: BL2 + TF-M | 118,424 bytes | |

The measured wolfTrust runtime uses 9,756 fewer bytes of flash and 484
fewer bytes of Secure RAM. The flash totals add the two component images.
Each runtime reuses its bootloader's RAM. The cross-compile workflow applies
TF-M's budget to the native guest-local PSA build on every port, with a
separate allowance for any RAM code band. See [Footprint](Footprint.md).

Both builds run one Non-secure application and provide Crypto, Internal
Trusted Storage, Protected Storage and Initial Attestation. TF-M also
includes its platform service. TF-M's STM32L5 profile runs its PSA Root of
Trust partitions privileged. wolfTrust runs every Secure Partition
unprivileged with its own MPU regions.

### Secure PSA Crypto

TF-M serves PSA Crypto from a Secure partition. The native wolfTrust build
in the STM32L562 table runs PSA Crypto in its guest. On STM32H563, the native
wolfTrust `standard` profile serves PSA Crypto from a Secure partition and
measures 103,067 bytes of flash and 48,844 bytes of Secure RAM. It uses
23,387 more bytes of flash and 3,116 more bytes of RAM than the TF-M
STM32L562 build above. The recorded breakdown attributes 52,485 bytes
of flash to wolfTrust's Secure crypto stack and 40,478 bytes to TF-M's
Crypto partition and Mbed TLS. The boards, storage implementations and
configured algorithm sets differ. See [Crypto Engines](Crypto-Engines.md) for the
other Secure PSA profiles and the cost of guest-local PSA.

### Methodology

Footprint is read from the linked Secure ELF and its map:

```text
Flash      = text + data
Secure RAM = all RAM the Secure image reserves, partition stacks included
```

- TF-M places every partition stack and the SPM stack in sections
  (`.ER_TFM_SP_*_BSS`, `.msp_stack`), so `data + bss` from
  `arm-none-eabi-size` is its whole reservation.
- wolfTrust's level 3 partition stacks and data bands are linker regions with
  no section in them, which `data + bss` leaves out. `tools/secure_ram.py`
  (printed by `make size-report`) adds them from the map: the SPM's
  `.data` + `.bss`, the SPM main stack, and every band and stack at its full
  length.
- Neither figure counts Secure RAM a port leaves free.

- wolfTrust STM32L562 uses the native engine, LTO and one guest. Build
  with `make TARGET=stm32l562 WT_SECURE_PSA=0 secure-image` in
  `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25`.
- wolfBoot: `config/examples/stm32l5-tz-wolftrust.config` (ECC256, SHA256,
  `WOLFBOOT_SECURE_APP=1`).
- TF-M: v2.3.1, platform `stm/stm32l562e_dk`, `TFM_ISOLATION_LEVEL=3`,
  `CMAKE_BUILD_TYPE=MinSizeRel`, the TF-PSA-Crypto Medium profile
  (`crypto_config_profile_medium.h`) with asymmetric encryption off,
  `TFM_PARTITION_FIRMWARE_UPDATE=OFF`, SPM and partition logging off,
  `CRYPTO_HW_ACCELERATOR=OFF`, BL2 with EC-P256 signatures.

## Historical cross-platform comparison

This earlier comparison uses `data + bss` for static RAM, which excludes
wolfTrust linker-only stack and band reservations. Its RAM figures are not
comparable to the complete Secure RAM accounting above.

This is a dated local comparison, not a standards-compatibility claim.
The wolfTrust rows use the STM32H563 reference manifest with
`isolation_profile` set to 3 and include Internal Trusted Storage, Protected
Storage, Firmware Update, vault services, and CBOR Object Signing and
Encryption (COSE) attestation. The TF-M rows are the standard Small, Medium,
and Large profiles built for AN521. The table
lists selected services, not every service in those profiles.

| Secure image | Profile and selected services | Flash | Static RAM |
| --- | --- | ---: | ---: |
| wolfTrust native | wolfTrust profile 3; Crypto, Internal Trusted Storage, Protected Storage, Firmware Update, vault, COSE attestation | 86,848 bytes | 27,253 bytes |
| wolfTrust wolfHSM | Same services plus the wolfHSM server | 106,432 bytes | 59,073 bytes |
| TF-M Small | Level 1; Crypto, Internal Trusted Storage, Initial Attestation; Protected Storage and Firmware Update off | 50,968 bytes | 14,296 bytes |
| TF-M Medium | Level 2; Crypto, Internal Trusted Storage, Protected Storage, Initial Attestation; Firmware Update off | 67,332 bytes | 42,468 bytes |
| TF-M Large | Level 3; Crypto, Internal Trusted Storage, Protected Storage, Initial Attestation; Firmware Update off | 115,460 bytes | 45,756 bytes |

In these builds, native wolfTrust uses about 25% less flash than TF-M Large
and less static RAM than TF-M Medium while also including firmware update.
The wolfHSM engine remains smaller in flash than TF-M Large but uses more
static RAM because it adds per-guest server state and stacks. These results do
not imply that the projects, platforms, or enabled feature sets are identical.

### Historical methodology

All five images were built on `wolf-prec5560` with
`arm-none-eabi-gcc (15:13.2.rel1-2) 13.2.1 20231009`. The wolfTrust builds
used `-Os` without link-time optimization (LTO); the cited historical commit
predates the later `WT_LTO=1` default. The TF-M `MinSizeRel` builds also did
not use LTO. Footprint was read from the linked Secure Executable and Linkable
Format (ELF) with `arm-none-eabi-size` and calculated as:

```text
Flash      = text + data
Static RAM = data + bss
```

Reproduction requires Git, GNU Make, CMake, Python 3, the GNU Arm toolchain,
and network access for source checkouts. The commands use POSIX shell syntax;
see the [TF-M build instructions](https://tf-m.docs.trustedfirmware.org/en/latest/building/tfm_build_instruction.html)
for its remaining host prerequisites.

The wolfTrust rows were measured on 2026-09-18 from this wolfTrust commit:

```text
c8baa2681b8b1e2ec57e5720cba28519bb306ab3
```

It records the dependency revisions below. Later commits may produce
different sizes.

- **wolfCOSE** (`v2.0.0`):

  ```text
  f907071b10127f3ae2dd7719749a91b039ff04a1
  ```

- **wolfHSM** (`wolfHSM-v1.4.0-171-ga032315`):

  ```text
  a0323156606282448f00473a3fcb7aaa69361921
  ```

- **wolfIP** (`v1.0-91-g146de4b`):

  ```text
  146de4b6362c3a076787e27332f50daa0a445cf5
  ```

- **wolfPSA** (`v5.9.1-129-g1b9ec29`):

  ```text
  1b9ec29706bc63f785682ad688350195a33b22e8
  ```

- **wolfSSL** (`v5.9.1-stable-1088-g22e505bcf`):

  ```text
  22e505bcfad8ce21067ee4232128728543767a95
  ```

- **wolfHAL** (no reachable tag):

  ```text
  2bc2938b0bbcc977177153a7f38393710702bf70
  ```

To reproduce the wolfTrust snapshot, use a separate checkout at that commit.
Its historical `.gitmodules` has SSH URLs for three submodules; the one-time
Git URL rewrite below fetches them over HTTPS. All other build variables
retain their repository defaults:

```sh
git clone https://github.com/wolfSSL/wolfTrust.git wolftrust-footprint
cd wolftrust-footprint
git checkout c8baa2681b8b1e2ec57e5720cba28519bb306ab3
git -c 'url.https://github.com/.insteadOf=git@github.com:' \
    submodule update --init --recursive
make BUILD_DIR=build_size_native WT_ENGINE=native secure-image
make BUILD_DIR=build_size_hsm WT_ENGINE=hsm secure-image
arm-none-eabi-size build_size_native/wolftrust.elf \
    build_size_hsm/wolftrust.elf
```

The measured wolfTrust files were the two `wolftrust.elf` outputs.

The TF-M source was the `TF-Mv2.1.1-LTS` tag at this commit:

```text
02bf279913439a07082dd581df033f370a8fbb92
```

In a separate directory, clone and check out that revision; run the remaining
commands from its source root. These AN521 GNU Arm builds enable BL2 and no
regression tests:

```sh
git clone https://github.com/TrustedFirmware-M/trusted-firmware-m.git tf-m
cd tf-m
git checkout 02bf279913439a07082dd581df033f370a8fbb92
git submodule update --init --recursive
for profile in small medium large; do
    cmake -S . -B "build_${profile}" \
        -DTFM_PLATFORM=arm/mps2/an521 \
        -DTFM_TOOLCHAIN_FILE=toolchain_GNUARM.cmake \
        -DTFM_PROFILE="profile_${profile}" \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DBL2=ON
    cmake --build "build_${profile}" --parallel
done
arm-none-eabi-size build_small/bin/tfm_s.elf \
    build_medium/bin/tfm_s.elf \
    build_large/bin/tfm_s.elf
```

The measured TF-M file in each case was `tfm_s.elf`.

Only the Secure runtime ELF is counted. wolfBoot and Non-secure wolfTrust
guests are excluded; TF-M BL2 and its Non-secure application are likewise
excluded. Although the TF-M configurations had `BL2=ON`, the separate BL2
image is not part of `tfm_s.elf` and therefore is not in the table.

The TF-M builds target AN521 while wolfTrust targets STM32H563, and their
profiles do not enable the same services. Treat the table as a historical local
comparison, not a platform-normalized benchmark. See
[Crypto Engines](Crypto-Engines.md) for the measured cost within wolfTrust,
where the platform and feature set are held constant.
