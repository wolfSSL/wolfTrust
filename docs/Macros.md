# Macros

The Secure build is configured through GNU Make variables. The build turns
selected values into C preprocessor defines. Defaults below come from
`mk/target-<soc>.mk`, `mk/arch-armv8m.mk`, and `mk/common.mk`.

## Build profiles

`make` with no options builds the lean default image. It runs at isolation
level 3 with one Non-secure image and the PSA services a TF-M level 3 build
ships: Crypto, Internal Trusted Storage, Protected Storage, and Initial
Attestation. The manifest is checked at build time. Each add-on below turns one feature back on with one Make variable.
None of them changes the isolation level.

Costs are over the default image, built with Arm GNU 15.2.1 in
`ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25` with LTO and read with
`arm-none-eabi-size`: flash is `text + data` and static RAM is `data + bss`.
The default native images are 78,844 bytes of flash and 27,368 bytes of RAM
on the STM32H563, and 78,384 and 27,528 bytes on the STM32L562 (measured on
the STM32L562 port, which is under review and not yet in this tree).

| Option | Brings back | STM32H563 flash / RAM | STM32L562 flash / RAM | Enable |
| --- | --- | ---: | ---: | --- |
| [`WT_MAX_GUESTS=2`](#wt_max_guests-a-second-guest) | A second Non-secure image and the scheduling that shares the core between two | +2,392 / +584 | +2,360 / +580 | `make WT_MAX_GUESTS=2 secure-image` |
| [`WT_FWU=1`](#wt_fwu-psa-firmware-update) | The PSA Firmware Update service and its 8 KiB stack band | +3,200 / +36 | +3,296 / +40 | `make WT_FWU=1 secure-image` |
| [`WT_MANIFEST_RUNTIME_CHECK=1`](#wt_manifest_runtime_check-boot-time-manifest-check) | The boot-time manifest and port-binding validator | +3,264 / 0 | +3,232 / 0 | `make WT_MANIFEST_RUNTIME_CHECK=1 secure-image` |
| [`WT_SHA256_FAST=1`](#wt_sha256_fast-unrolled-sha-256) | The unrolled Thumb-2 SHA-256 transform, faster hashing for boot and guest measurement | +1,472 / 0 | +1,440 / 0 | `make WT_SHA256_FAST=1 secure-image` |
| [`WT_ENGINE=hsm`](#wt_enginehsm-the-wolfhsm-engine) | The wolfHSM server as the crypto engine | +29,788 / +22,348 | not supported | `make WT_ENGINE=hsm secure-image` |
| `full` profile | `WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1 WT_SHA256_FAST=1` together | +10,456 / +616 | +10,520 / +620 | `make WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1 WT_SHA256_FAST=1 secure-image` |

The RAM figures leave out the 8 KiB FWU stack band, which the
level 3 layout reserves only when `WT_FWU=1`. The engine is a separate axis:
CI runs both engines on both profiles where the port supports them.

`tests/target/lib/profile.sh` holds the profile flags. A target run picks one
with `WT_PROFILE` (`make test-target WT_PROFILE=default`). Hardware runners
build `full` only, because their checks assert both guests.

## Add-on options

### `WT_MAX_GUESTS`: a second guest

- Default `1`. `2` builds a second Non-secure guest (guest-b) beside the
  first. Any other value stops the build.
- `2` adds back what only two guests need: the virtual SysTick that time
  shares SysTick_NS between the guests, the SAU, Non-secure MPU and IRQ
  reprogramming on every guest switch, the full context save and reschedule
  on each Secure tick, and the re-measurement of a guest right before its
  first dispatch (a peer could have rewritten it). With the wolfHSM engine it
  also adds a second server tasklet and its 10 KiB stack. One guest keeps the
  restart policy, launch verification, the Secure tick and the Secure
  Partition scheduler.
- Cost: STM32H563 native +2,392 bytes flash and +584 bytes RAM, wolfHSM
  +2,776 and +17,388; STM32L562 native +2,360 and +580.
- Enable: `make WT_MAX_GUESTS=2 secure-image`
- CI: the cross-compile job builds it alone and in the `full` profile for
  every port and engine, and checks that `WT_MAX_GUESTS=3` stops the build. The M33MU `full`
  profile runs the two-guest scenarios (`bothpsa`, `bothiso`, `gtzcneg`,
  `restart` and the rest). `tests/host/monitor` builds both guest counts.

### `WT_FWU`: PSA Firmware Update

- Default `0`. `1` builds `SERVICE_FWU` (PSA Firmware Update staging into the
  wolfBoot update partition). Any other value stops the build.
- `1` adds back the update partition and its manifest domain, its 8 KiB stack
  band at the top of the level 3 layout, the port's staging backend (the
  privileged flash ops the update partition reaches through the SVC gate),
  the active-version and rollback-floor queries that backend serves, and on
  the MIMXRT700 the update partition as a NOR write window. `0` leaves all of
  these out. The generator drops `PARTITION_FWU` from the manifest
  (`--exclude-partition`), so `SERVICE_FWU_SID` and `PARTITION_FWU_ID` do not
  exist and a connect to SID `0x1005` is refused like any unknown service.
  Anti-rollback enforcement at boot stays in every image.
  `WT_BOOTUPDATE_PROBE=1` needs `WT_FWU=1`.
- Cost: STM32H563 native +3,200 bytes flash and +36 bytes RAM, wolfHSM
  +3,232 and +36; STM32L562 native +3,296 and +40. Each also reserves the
  8,192-byte stack band.
- Enable: `make WT_FWU=1 secure-image`
- CI: the cross-compile job builds it alone and in the `full` profile for
  every port and engine. The M33MU `full` profile runs `fwustage` and
  `bootupdate`. `tests/host/sp_layout`,
  `tests/host/rt700_xspi`, `tests/host/fwu_service` and
  `tests/host/manifest_ports` (default and full manifests) cover the layout,
  the NOR window, the service and the excluded manifest.

### `WT_MANIFEST_RUNTIME_CHECK`: boot-time manifest check

- Default `0`. The manifest generator validates the manifest at build time
  against the port's platform capabilities (`port/<soc>/platform_caps.h`,
  passed from `mk/target-<soc>.mk`) and the FF-M runtime limits, and the
  generated C asserts the port binding at compile time. Any manifest the
  boot-time checks would reject fails the build, so the default image does
  not repeat them.
- `1` links the boot-time validator back in: `wt_spm_init()` runs
  `wt_manifest_validate()`, `wt_partitions_bind_manifest()` runs
  `wt_partition_validate_port_binding()`, and the monitor runs
  `wt_partition_validate_profile()` for each guest.
- Cost: flash only, RAM does not change. STM32H563 +3,264 bytes native and
  +3,328 wolfHSM; STM32L562 native +3,232.
- Enable: `make WT_MANIFEST_RUNTIME_CHECK=1 secure-image`
- CI: the cross-compile job builds every port and engine with it and checks
  that only the opt-in image links `wt_manifest_validate`. The `manifestneg`
  and `manifestneg2` scenarios corrupt the manifest at boot, so they force it
  on, and the M33MU `full` profile runs every scenario with it.
  `tests/host/manifest_ports` runs the validator over every port manifest.

### `WT_SHA256_FAST`: unrolled SHA-256

- Default `0`, which builds wolfCrypt's looped Thumb-2 SHA-256 transform
  (`WOLFSSL_ARMASM_SHA256_SMALL`), the counterpart of TF-M's
  `MBEDTLS_SHA256_SMALLER` in its Medium crypto profile. `1` builds the fully
  unrolled transform, which hashes faster. Any other value stops the build.
- SHA-256 runs at boot over each guest image (launch verification), in every
  attestation token and in the PSA hash service, so `1` shortens those paths;
  nothing else changes.
- Cost: flash only. STM32H563 +1,472 bytes on both engines; STM32L562
  native +1,440.
- Enable: `make WT_SHA256_FAST=1 secure-image`
- CI: the cross-compile job builds it alone and in the `full` profile for
  every port and engine, the M33MU `full` profile runs every scenario on the
  unrolled transform, and the `default` profile runs them on the looped one.

### `WT_ENGINE=hsm`: the wolfHSM engine

- Default `native`, which runs wolfCrypt directly behind `SERVICE_HSM`.
  `hsm` links the wolfHSM server instead, with server-keystore semantics and
  an external-HSM offload path. The FF-M surface does not change.
- Cost: STM32H563 +29,788 bytes flash and +22,348 bytes RAM over the native
  default. Part of it is AES block decryption, which the wolfHSM server
  serves to clients and the native engine leaves out. The STM32L562 builds the native engine only; its 256 KiB of SRAM
  does not hold the wolfHSM bands.
- Enable: `make WT_ENGINE=hsm secure-image` (guests must use the same
  engine).
- CI: every cross-compile and M33MU tier runs both engines on the ports that
  support them. See [Crypto Engines](Crypto-Engines.md).

## Build selection

| Define | Description | Requirement |
| --- | --- | --- |
| `ARCH` | Architecture build selector; default `armv8m`. | Must match an `mk/arch-<arch>.mk` fragment; `armv8m` is the only architecture today. |
| `TARGET` | Target build selector; default `stm32h563`. | Must match an `mk/target-<soc>.mk` fragment; the root Makefile includes it, the architecture fragment, and `mk/common.mk`. |
| `TOOLPREFIX` | Cross-tool prefix; default `arm-none-eabi-`. | The prefixed GCC, objcopy, nm, and size tools must be available. |
| `BUILD_DIR` | Secure build output directory; default `build`. | Must be writable. |
| `WT_LTO` | Enable Secure-image link-time optimization; default `1`. | Set to `0` for diagnostics or a non-LTO size comparison. The GNU Arm compiler must support `-flto=auto`. |
| `WT_ENGINE` | Secure crypto engine: `native` (default) dispatches wolfCrypt directly behind the SERVICE_HSM door with explicitly vault-backed keys stored as `SENSITIVE` and `NONEXPORTABLE` NVM objects; `hsm` links the wolfHSM server as a key-management add-on (server-keystore semantics and an external-HSM offload path). Legacy `WT_ENGINE_HSM=0/1` maps onto the selector. | Both engines share the identical FF-M surface (5 veneers, SIDs, manifest, and L3 bands) and run every applicable CI scenario. Guest builds must use the same engine as the Secure image. See [Crypto Engines](Crypto-Engines.md). |

## Core target configuration

| Define | Description | Requirement |
| --- | --- | --- |
| `WT_MAX_GUESTS` | Compiled guest contexts; default `1`, `2` adds guest-b (see [`WT_MAX_GUESTS`](#wt_max_guests-a-second-guest)). | Only `1` or `2`; any other value stops the build. The manifest keeps guest-b's domain declared either way. |
| `WT_TIMESLICE_MS` | Guest scheduler interval in milliseconds; default `2`. | Must be nonzero and supported by the target timer. |
| `WT_GUEST_HANDLER_SLICE_LIMIT` | Consecutive slice expiries a guest may spend in a Non-secure handler before it is restarted (Secure calls made from that handler count); default `50`. A C define, not a Make variable: set it with `WT_EXTRA_CFLAGS=-DWT_GUEST_HANDLER_SLICE_LIMIT=<n>`. | Must be 1 to `0xFFFFFFFF` (other values fail the build); size it above the longest legitimate guest interrupt handler. |
| `WT_CO_STACK_SIZE` | Default fixed coroutine stack size in bytes, including each per-guest wolfHSM server tasklet in the hsm engine; default `10240` (measured: the deep M33MU workloads pass at 8K with PSPLIM overflow detection armed, so 10K carries at least 2K margin). With two guests, the hsm-only server slots total 20,480 stack bytes plus 512 guard bytes. Manifest-sized Secure Partition stacks use their declared sizes instead. | Size from measured stack high-water marks and keep at least the scheduler minimum. |
| `WT_SHARED_UART` | Reference guest UART selection; default `3`. | Guest and Secure builds must use a consistent value. |
| `WT_GUEST_CORE_CLOCK_HZ` | Guest core-clock value; default `240000000`. | Must match the configured target clock. |
| `WT_GUEST_UART_CLOCK_HZ` | Guest UART-clock value; default `120000000`. | Must match the selected UART clock source. |

## Security and service options

| Define | Description | Requirement |
| --- | --- | --- |
| `WT_GUEST_FLASH_WRP` | When `1`, verify full hardware write protection of each guest window before launch (STM32 WRP groups, or MIMXRT700 locked XSPI flash region descriptors); default `0`. | Set to `1` for hardened images: provision STM32H563 WRP after flashing, or boot the MIMXRT700 fenced wolfBoot. M33MU models the MIMXRT700 descriptors but not STM32 WRP. |
| `WT_ENGINE_HSM` | Legacy engine selector; unset by default. `0` maps to `WT_ENGINE=native` and `1` maps to `WT_ENGINE=hsm` when the public selector is not supplied. The build also derives this internal value from `WT_ENGINE`. | Prefer `WT_ENGINE` for new builds and do not supply conflicting selectors. The guest and Secure image must select the same engine. |
| `WT_ATTEST_COSE` | Must remain `1` in the current STM32H563 reference build; default `1`. The `0` configuration does not compile because the reset path still references attestation-gated handoff variables. | Requires the wolfCOSE submodule and the configured attestation key backend. |
| `WT_WOLFCRYPT_SP_ASM` | Enable wolfCrypt SP Cortex-M assembly; default `1`. | Requires compatible Armv8-M assembly sources and toolchain. |
| `WT_WOLFCRYPT_ARMASM` | Enable additional wolfCrypt Thumb-2 assembly; default `1`. | Requires a compatible GNU Arm toolchain. [`WT_SHA256_FAST`](#wt_sha256_fast-unrolled-sha-256) picks the SHA-256 transform it builds. |
| `WT_WOLFCRYPT_STM32_HASH` | STM32 HASH acceleration selector; default `0`. | Must remain `0`: the Makefile rejects other values because wolfHSM SHA state is not compatible with the peripheral representation. |
| `WT_CONFORMANCE` | When `1`, select the manifest and sources used by Arm PSA API validation. | Use only for conformance builds; the default production manifest is selected at `0`. |

## Image layout

| Define | Description | Requirement |
| --- | --- | --- |
| `WT_SECURE_FLASH_BASE` | Secure image link base; standalone default `0x0C000000`. | Must match the bootloader slot and linker layout. |
| `WT_SECURE_FLASH_SIZE` | Available Secure image bytes; standalone default `0x00020000`. | Must cover the linked image without overlapping another flash region. |
| `WT_SECURE_IMAGE_HEADER_SIZE` | Bytes reserved before linked code; default `0` (`0x400` for `TARGET=mimxrt700`, wolfBoot's RT700 header). | Set to match the header layout of an image signed for wolfBoot. |
| `WT_GUEST0_FLASH_BASE` | Guest 0 flash base; standalone default `0x08020000`. | Must match the guest link address and manifest executable window. |
| `WT_GUEST1_FLASH_BASE` | Guest 1 flash base; standalone default `0x08040000`. | Must match the guest link address and manifest executable window. |
| `WT_GUEST0_FLASH_SIZE` | Guest 0 flash window; default `0x00020000`. | Must contain the signed record's image size and use valid target alignment. |
| `WT_GUEST1_FLASH_SIZE` | Guest 1 flash window; default `0x00020000`. | Must contain the signed record's image size and use valid target alignment. |

The target runners used for authenticated boot override standalone addresses
for the wolfBoot partition layout. Keep bootloader, Secure image, manifest,
guest linker files, measurement records, and flash commands consistent.

## Virtual network options

| Define | Description | Requirement |
| --- | --- | --- |
| `CONFIG_VNET` | Select the VNET manifest and link the Secure switch when set to `y`; default `n`. | Both guests must use the matching VNET transport and memory layout. |
| `WT_VNET_POOL_SLOTS` | Secure frame-pool slot count; default `8`. | Static VNET data must fit its manifest region. |
| `WT_VNET_FRAME_MAX` | Internal maximum Ethernet frame bytes; default `1536`. | Must be large enough for the selected link frame; PSA transport still limits the exposed MTU to 1000. |
| `WT_VNET_RX_QUEUE_DEPTH` | Per-port receive queue depth; default `8`. | Static queue storage must fit the VNET data region. |
| `WT_VNET_RX_IRQ` | Synthetic Non-secure receive interrupt; default `130`. | Must be representable and assigned consistently in the target IRQ policy. |
| `WT_VNET_TIMEOUT_TICKS` | Frame-expiration threshold in scheduler ticks; default `500`. | When a transmit finds the frame pool full, `SERVICE_VNET` drops queued frames older than this and retries once, so a port that stops fetching cannot hold the pool. Frames are not aged out while the pool has free slots. |
| `WT_VNET_UNKNOWN_UCAST_FLOOD` | Flood unknown unicast frames when set to `1`; default `0`. | Enable only when the guest-network policy permits it. |

## Fixed Secure wolfCrypt defines

These are defined by
`src/services/wolfhsm/runner/user_settings.h` rather than by a Make
command-line option.

| Define | Description | Requirement |
| --- | --- | --- |
| `WOLFCRYPT_ONLY` | Builds only wolfCrypt functionality. | Fixed for the Secure image. |
| `NO_WOLFSSL_MEMORY` | Removes the wolfSSL allocator layer. | Fixed for the Secure image. |
| `WOLFSSL_NO_MALLOC` | Rejects accidental dynamic allocation paths. | Fixed for the Secure image; Secure code must use static or stack storage. |
| `HAVE_ECC` | Enables the configured ECC implementation. | The reference image uses P-256 operations. |
| `HAVE_AESGCM` | Enables AES-GCM. | Required by Protected Storage sealing. |
| `NO_ASN` | Native engine only: drops wolfCrypt ASN.1. | The native engine signs, verifies and imports keys in raw form; the wolfHSM server keeps ASN for its DER keystore. |
| `NO_AES_DECRYPT`, `HAVE_AESGCM_DECRYPT` | Native engine only: drop the AES inverse key schedule and decrypt tables but keep `wc_AesGcmDecrypt`. | Native AES is GCM only, which runs the block cipher forward for both seal and unseal. |
| `HAVE_HKDF` | Enables HKDF. | Required by linked wolfHSM/wolfCrypt code paths. |
| `HAVE_HASHDRBG` | Enables the HashDRBG. | Requires the target `CUSTOM_RAND_GENERATE_BLOCK` entropy callback. |
| `NO_RSA` | Excludes RSA from the Secure profile. | Fixed for the reference image. |

## Manifest controls

`isolation_profile` is a JSON field, not a preprocessor macro. The
reference manifest sets it to numeric value `3`
(`WT_ISOLATION_PROFILE_LEVEL_3`). The manifest also requests feature
mask `1`, which is `WT_MANIFEST_FEATURE_IPC`. The Makefile
invokes the generator with supported features `0x1`, the framework version,
partition limit, and service limit read from `include/psa/client.h` and
`include/wolftrust/ffm.h`, and the port's `WT_PLATFORM_*` capabilities, so an
unsupported manifest request fails generation.

See [Building](Building.md) for command examples and [Security Model](Security-Model.md) for the runtime
meaning of these settings.
