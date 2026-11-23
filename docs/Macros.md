# Macros

The Secure build is configured through GNU Make variables. The build turns
selected values into C preprocessor defines. Defaults below come from
`mk/target-stm32h563.mk`, `mk/layout.mk`, `mk/arch-armv8m.mk`, and
`mk/common.mk`.

## Build profiles

`make` with no options builds the lean default image. It runs at isolation
level 3 with one Non-secure image and the PSA services a TF-M level 3 build
ships: Crypto, Internal Trusted Storage, Protected Storage, and Initial
Attestation. The manifest is checked at build time. Each add-on below turns one feature back on with one Make variable.
None of them changes the isolation level.

Costs are over the default image, built with Arm GNU 15.2.1 in
`ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25` with LTO and read with
`make size-report`: flash is `text + data`, and RAM is the Secure RAM the image
reserves, partition stacks and bands included ([Footprint](Footprint.md#how-sizes-are-measured)).
The default native image serves PSA Crypto from the Secure image and is
108,697 bytes of flash and 48,332 bytes of RAM on the STM32H563, with wolfCrypt
built as portable C. The other rows are measured over the `WT_SECURE_PSA=0`
image, 70,432 and 45,260 bytes on the STM32H563, and 69,496 and 45,280 bytes
on the STM32L562 (measured on the STM32L562 port, which is under review and not
yet in this tree).
[Footprint](Footprint.md) logs the sizes of every port and engine.

| Option | Brings back | STM32H563 flash / RAM | STM32L562 flash / RAM | Enable |
| --- | --- | ---: | ---: | --- |
| [`WT_MAX_GUESTS=2`](#wt_max_guests-a-second-guest) | A second Non-secure image, the scheduling that shares the core between two, and an IPC message pool of 8 instead of 4 | +2,328 / +9,368 | +2,328 / +9,364 | `make WT_MAX_GUESTS=2 secure-image` |
| [`WT_FWU=1`](#wt_fwu-psa-firmware-update) | The PSA Firmware Update service and its 4 KiB stack | +3,348 / +4,120 | +3,372 / +4,136 | `make WT_FWU=1 secure-image` |
| [`WT_MANIFEST_RUNTIME_CHECK=1`](#wt_manifest_runtime_check-boot-time-manifest-check) | The boot-time manifest and port-binding validator | +3,316 / 0 | +3,284 / 0 | `make WT_MANIFEST_RUNTIME_CHECK=1 secure-image` |
| [`WT_SHA256_FAST=1`](#wt_sha256_fast-unrolled-sha-256) | The unrolled SHA-256 transform, faster hashing for boot and guest measurement | +384 / 0 | +416 / 0 | `make WT_SHA256_FAST=1 secure-image` |
| [`WT_ENGINE=hsm`](#wt_enginehsm-the-wolfhsm-engine) | The wolfHSM server as the crypto engine | +27,876 / +38,672 | not supported | `make WT_ENGINE=hsm secure-image` |
| [`WT_SECURE_PSA=0`](Crypto-Engines.md#psa-crypto-in-the-secure-image-wt_secure_psa1) | Removes PSA Crypto from the Secure image and runs wolfPSA in the guest again; saves 38,265 / 3,072 against the `compat` default (`standard` is +27,019 / +2,048 over it) | -38,265 / -3,072 | not measured | `make WT_SECURE_PSA=0 secure-image` |
| `full` profile | `WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1 WT_SHA256_FAST=1` together | +9,408 / +13,488 | +9,432 / +13,500 | `make WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1 WT_SHA256_FAST=1 secure-image` |

The RAM figures include every stack and band an option adds, the 4 KiB FWU
stack for `WT_FWU=1` among them. The engine is a separate axis:
CI runs both engines on both profiles where the port supports them.

`tests/target/lib/profile.sh` holds the profile flags. `make test-target` runs
both profiles; `WT_PROFILE=default` or `WT_PROFILE=full` picks one. Hardware runners
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
- Cost: STM32H563 native +2,328 bytes flash and +9,368 bytes RAM, wolfHSM
  +2,648 and +19,864; STM32L562 native +2,328 and +9,364. Most of the RAM is
  the IPC message pool, which holds 8 messages with two guests and 4 with one
  (`WT_FFM_MAX_MESSAGES`).
- Enable: `make WT_MAX_GUESTS=2 secure-image`
- CI: the cross-compile job builds it alone and in the `full` profile for
  every port and engine, and checks that `WT_MAX_GUESTS=3` stops the build. The M33MU `full`
  profile runs the two-guest scenarios (`bothpsa`, `bothiso`, `guestisoneg`,
  `restart` and the rest). `tests/host/monitor` builds both guest counts.

### `WT_FWU`: PSA Firmware Update

- Default `0`. `1` builds `SERVICE_FWU` (PSA Firmware Update staging into the
  wolfBoot update partition). Any other value stops the build.
- `1` adds back the update partition and its manifest domain, its 4 KiB stack
  at the top of the level 3 layout, the port's staging backend (the
  privileged flash ops the update partition reaches through the SVC gate),
  the active-version and rollback-floor queries that backend serves, and on
  the MIMXRT700 the update partition as a NOR write window. `0` leaves all of
  these out. The generator drops `PARTITION_FWU` from the manifest
  (`--exclude-partition`), so `SERVICE_FWU_SID` and `PARTITION_FWU_ID` do not
  exist and a connect to SID `0x1005` is refused like any unknown service.
  Anti-rollback enforcement at boot stays in every image.
  `WT_BOOTUPDATE_PROBE=1` needs `WT_FWU=1`.
- Cost: STM32H563 native +3,348 bytes flash and +4,120 bytes RAM; STM32L562
  native +3,372 and +4,136. The RAM is almost all the update partition's
  stack.
- Enable: `make WT_FWU=1 secure-image`
- CI: the cross-compile job builds it alone and in the `full` profile for
  every port and engine. The M33MU `full` profile runs `fwustage` and
  `bootupdate`. `tests/host/sp_layout`,
  `tests/host/rt700_xspi`, `tests/host/fwu_service` and
  `tests/host/manifest_ports` (default and full manifests) cover the layout,
  the NOR window, the service and the excluded manifest.

### `WT_MANIFEST_RUNTIME_CHECK`: boot-time manifest check

- Default `0`. The manifest generator validates the manifest at build time
  against the platform capabilities (`port/common/armv8m/platform_caps.h`,
  passed from `mk/arch-armv8m.mk`) and the FF-M runtime limits, and the
  generated C asserts the port binding at compile time. Any manifest the
  boot-time checks would reject fails the build, so the default image does
  not repeat them.
- `1` links the boot-time validator back in: `wt_spm_init()` runs
  `wt_manifest_validate()`, `wt_partitions_bind_manifest()` runs
  `wt_partition_validate_port_binding()`, and the monitor runs
  `wt_partition_validate_profile()` for each guest.
- Cost: flash only, RAM does not change. STM32H563 native +3,316 bytes and
  STM32L562 native +3,284 bytes.
- Enable: `make WT_MANIFEST_RUNTIME_CHECK=1 secure-image`
- CI: the cross-compile job builds every port and engine with it and checks
  that only the opt-in image links `wt_manifest_validate`. The `manifestneg`
  and `manifestneg2` scenarios corrupt the manifest at boot, so they force it
  on, and the M33MU `full` profile runs every scenario with it.
  `tests/host/manifest_ports` runs the validator over every port manifest.

### `WT_SHA256_FAST`: unrolled SHA-256

- Default `0`, which builds wolfCrypt's looped SHA-256 transform
  (`USE_SLOW_SHA256`, or `WOLFSSL_ARMASM_SHA256_SMALL` with
  `WT_WOLFCRYPT_ARMASM=1`), the counterpart of TF-M's
  `MBEDTLS_SHA256_SMALLER` in its Medium crypto profile. `1` builds the fully
  unrolled transform, which hashes faster. Any other value stops the build.
- SHA-256 runs at boot over each guest image (launch verification), in every
  attestation token and in the PSA hash service, so `1` shortens those paths;
  nothing else changes.
- Cost: flash only, +384 bytes on the STM32H563 and +416 on the STM32L562
  with the default portable C build, or +1,472 bytes with
  `WT_WOLFCRYPT_ARMASM=1`.
- Enable: `make WT_SHA256_FAST=1 secure-image`
- CI: the cross-compile job builds it alone and in the `full` profile for
  every port and engine, the M33MU `full` profile runs every scenario on the
  unrolled transform, and the `default` profile runs them on the looped one.

### `WT_ENGINE=hsm`: the wolfHSM engine

- Default `native`, which runs wolfCrypt directly behind `SERVICE_HSM`.
  `hsm` links the wolfHSM server instead, with server-keystore semantics and
  an external-HSM offload path. The FF-M surface does not change.
- Cost: STM32H563 +27,876 bytes flash and +38,672 bytes RAM over the native
  `WT_SECURE_PSA=0` image, including the wolfHSM server's 10 KiB crypto partition stack and
  24 KiB data band. Part of it is AES block decryption, which the wolfHSM server
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
| `TARGET` | Target build selector; default `stm32h563`. | Must match an `mk/target-<soc>.mk` fragment; the root Makefile includes it, `mk/layout.mk`, the architecture fragment, and `mk/common.mk`. |
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
| `WT_GUEST_FLASH_WRP` | When `1`, verify the port's hardware write protection of each guest window before launch; a port with no guest flash fence then refuses every guest. Default `0`. | Set to `1` for hardened images, after provisioning the port's fence as its guide describes. |
| `WT_ENGINE_HSM` | Legacy engine selector; unset by default. `0` maps to `WT_ENGINE=native` and `1` maps to `WT_ENGINE=hsm` when the public selector is not supplied. The build also derives this internal value from `WT_ENGINE`. | Prefer `WT_ENGINE` for new builds and do not supply conflicting selectors. The guest and Secure image must select the same engine. |
| `WT_ATTEST_COSE` | Build the COSE attestation token service; default `1`. CI compile-checks `0`, and builds each port with its `port.json` `attest_cose` value. | `1` requires the wolfCOSE submodule and the configured attestation key backend. |
| `WT_SECURE_PSA` | When `1`, serve PSA Crypto from the Secure image: wolfPSA runs in the crypto partition and the guest links the PSA client instead of wolfPSA. Default `1` with the native engine and `0` with wolfHSM; a port may default it to `0` in its `mk/target-<soc>.mk`. See [Crypto Engines](Crypto-Engines.md#psa-crypto-in-the-secure-image-wt_secure_psa1). | `1` requires `WT_ENGINE=native`; build every guest with the Secure image's value. |
| `WT_SECURE_PSA_PROFILE` | Algorithm set of a `WT_SECURE_PSA=1` image: `compat` (default), `standard`, `lean` or `symmetric`. | Any other value stops the build. |
| `WT_PSA_POOL_BYTES` | Make variable: size of the crypto partition's private wolfPSA pool, split evenly into one arena per guest; empty keeps 2,048 bytes per guest. | A smaller arena fails calls that hold more with `PSA_ERROR_INSUFFICIENT_MEMORY`; below 1,536 bytes per guest stops the build. A pool past the crypto partition's band fails the link. |
| `WT_PSA_KEY_SLOTS`, `WT_PSA_OP_SLOTS` | Make variables: volatile keys and live operations the Secure PSA service tracks, split evenly across the guests; empty keeps `16` and `8`. | Fewer slots than guests, more than 256 operation slots, or a non-number stops the build. Each slot's state is allocated from `WT_PSA_POOL_BYTES`. |
| `WT_WOLFCRYPT_SP_ASM` | Enable wolfCrypt SP Cortex-M assembly; default `0`, the portable C `sp_c32.c`, which is smaller. `1` trades flash for faster ECC and, on the native engine, raises the crypto partition stack to 9 KiB in every profile (from 5 KiB, or 6 KiB in `compat`) for its deeper P-256 verify. | `1` requires compatible Armv8-M assembly sources and toolchain. |
| `WT_AEAD` | AES-256 AEAD of the vault encrypt service and sealed storage, and the one PSA AEAD of the `lean` and `symmetric` Secure PSA profiles: `gcm` or `ccm`, both with a 12-byte nonce and 16-byte tag. Empty picks `ccm` for `lean` and `symmetric` and `gcm` for every other build. `compat` and `standard` offer both through PSA either way. CCM carries no GHASH, so `lean` is 860 bytes smaller with `ccm` than with `gcm` on the STM32H563. | Data sealed or encrypted under one setting does not open under the other, so changing it on a deployed device means re-provisioning its sealed store and re-encrypting vault data. Any other value stops the build. |
| `WT_WOLFCRYPT_ARMASM` | Enable additional wolfCrypt Thumb-2 assembly; default `0`, portable C AES with small tables. `1` trades flash for faster AES and SHA-256. | `1` requires a compatible GNU Arm toolchain and `WT_SECURE_PSA=0`: the Thumb-2 AES is not constant time, which wolfPSA refuses. [`WT_SHA256_FAST`](#wt_sha256_fast-unrolled-sha-256) picks the SHA-256 transform either way. |
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
| `WT_L3_SPM_RAM_SIZE` | SPM-private RAM band size; default from the port's `memory_map.h` or `l3_layout.h` (`0x0004D000`). | Moves every level 3 band above it; the keystore bands, partition stacks and conformance window follow. |
| `WT_SP_HSM_DATA_SIZE` | Crypto partition data band size; default from the port's `memory_map.h` or `l3_layout.h`: `0x00006000` for the wolfHSM engine (`0x00006800` with `CONFIG_TPM` or `CONFIG_PKCS11`, whose provider holds its own wolfHSM server context), `0x00000600` for native, and sized to the PSA pool when the native engine serves Secure PSA Crypto. | Must hold the engine's working set; the post-link layout check reports an overflow. |
| `WT_LD_RAM_CODE_BAND` | `1` links the NSC gateway and the flash program code into the RAM code band; default `0` (`1` for `TARGET=mimxrt700`). | The port's `memory_map.h` must define `WT_RAMFUNC_BASE` and `WT_RAMFUNC_SIZE`. |

Every layout input is a Make variable that `mk/layout.mk` resolves once into
`WT_LAYOUT_CFLAGS` (defines and include paths only). The firmware, the
linker script, `tools/l3_layout_args.py`, the post-link layout check, the
guest builds and the host fixtures all read that one set, and the build-mode
stamp records it, so changing any input regenerates every output.
`make TARGET=<soc> print-layout-cflags` prints the resolved set and
`print-build-mode` the stamp; a layout define passed through
`WT_EXTRA_CFLAGS` is refused.

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

## Application interface options

PSA is the default application API. These select TPM 2.0 or PKCS#11 instead;
[Footprint](Footprint.md#tpm-20-and-pkcs11) has the cost of each on every port.

| Define | Description | Requirement |
| --- | --- | --- |
| `CONFIG_TPM` | `y` adds `SERVICE_TPM` and its manifest overlay, running wolfTPM's firmware TPM in its own partition; default `n`. | Excludes `CONFIG_PKCS11`, `CONFIG_VNET` and `WT_CONFORMANCE`. The port must list `tpm` in its `port.json` `build.variants`. `WT_SECURE_PSA` defaults to `0`, and `1` stops the build. |
| `CONFIG_PKCS11` | `y` adds `SERVICE_PKCS11` and its manifest overlay, running wolfPKCS11 in its own partition; default `n`. | Excludes `CONFIG_TPM`, `CONFIG_VNET` and `WT_CONFORMANCE`. The port must list `pkcs11` in `build.variants`. `WT_SECURE_PSA` as for `CONFIG_TPM`. |
| `WT_INTERFACE_PROFILE` | Operation set the TPM 2.0 or PKCS#11 service exports: `default` (RNG, SHA-256, P-256) or `full`. `WT_INTERFACE_CONFIG`, `WT_INTERFACE_ENABLE` and `WT_INTERFACE_DISABLE` edit it. See [Interface Profiles](Interface-Profiles.md). | Read only when `CONFIG_TPM` or `CONFIG_PKCS11` is `y`. Applications must be built with the same profile. |
| `WT_INTERFACE_LOCAL_PROVIDER` | Internal: `1` builds the provider's wolfCrypt into the interface partition with its symbols renamed apart from the crypto partition's copy. `mk/arch-armv8m.mk` sets it. | Not a user setting. |
| `WT_PKCS11_PIN_MAX_FAILURES` | Consecutive wrong user or SO PINs before that PIN locks; empty keeps `3`. | Must be a positive integer. |
| `WT_PKCS11_TEST_PBKDF2_ITERATIONS` | Emulator only: lowers the PIN PBKDF2 count from 600,000. | Never set it for a product image; the footprint script refuses it. |
| `WT_TPM_DA` | `0` compiles out fwTPM dictionary-attack lockout (about 1.4 to 2.3 KB of Secure flash); default `1` locks DA-protected objects after 32 failed authorizations. | `0` or `1`; read only with `CONFIG_TPM=y`. Without NV the counter resets on reboot. |
| `WT_PROVIDER_ECC_FALLBACK` | `1` keeps software P-256 in the provider of an `hsm` build; default `0` routes every ECC operation through wolfHSM. | `0` or `1`; read only with `WT_ENGINE=hsm`. |

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
| `HAVE_AESGCM` | Enables AES-GCM. | Required by Protected Storage sealing unless `WT_AEAD=ccm`, which needs `HAVE_AESCCM` instead. |
| `NO_ASN` | Native engine only: drops wolfCrypt ASN.1. | The native engine signs, verifies and imports keys in raw form; the wolfHSM server keeps ASN for its DER keystore. |
| `NO_AES_DECRYPT`, `HAVE_AESGCM_DECRYPT` | Native engine only: drop the AES inverse key schedule and decrypt tables but keep `wc_AesGcmDecrypt`. | GCM runs the block cipher forward for both seal and unseal. `WT_AEAD=ccm` undefines `NO_AES_DECRYPT`, which wolfCrypt's CCM decrypt is compiled under, though it also runs forward. |
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
