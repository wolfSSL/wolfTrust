# Macros

The STM32H563 build is configured through GNU Make variables. The build turns
selected values into C preprocessor defines. Defaults below come from
`mk/target-stm32h563.mk`, `mk/arch-armv8m.mk`, and `mk/common.mk`.

## Build selection

| Define | Description | Requirement |
| --- | --- | --- |
| `ARCH` | Architecture build selector; default `armv8m`. | Must match an `mk/arch-<arch>.mk` fragment; `armv8m` is the only architecture today. |
| `TARGET` | Target build selector; default `stm32h563`. | Must match an `mk/target-<soc>.mk` fragment; the root Makefile includes it, the architecture fragment, and `mk/common.mk`. |
| `TOOLPREFIX` | Cross-tool prefix; default `arm-none-eabi-`. | The prefixed GCC, objcopy, nm, and size tools must be available. |
| `BUILD_DIR` | Secure build output directory; default `build`. | Must be writable. |
| `WT_ENGINE` | Secure crypto engine: `native` (default) dispatches wolfCrypt directly behind the SERVICE_HSM door with explicitly vault-backed keys stored as `SENSITIVE` and `NONEXPORTABLE` NVM objects; `hsm` links the wolfHSM server as a key-management add-on (server-keystore semantics and an external-HSM offload path). Legacy `WT_ENGINE_HSM=0/1` maps onto the selector. | Both engines share the identical FF-M surface (5 veneers, SIDs, manifest, and L3 bands) and run every applicable CI scenario. Guest builds must use the same engine as the Secure image. See [Crypto Engines](Crypto-Engines.md). |

## Core target configuration

| Define | Description | Requirement |
| --- | --- | --- |
| `WT_MAX_GUESTS` | Selects one or two compiled STM32H563 guest contexts; default `2`. | The current port supports only `1` or `2`. Larger values require extending the partition tables and matching manifest, linker, emulator, flash, and measurement configuration. |
| `WT_TIMESLICE_MS` | Guest scheduler interval in milliseconds; default `2`. | Must be nonzero and supported by the target timer. |
| `WT_CO_STACK_SIZE` | Default fixed coroutine stack size in bytes, including each per-guest wolfHSM server tasklet in the hsm engine; default `10240` (measured: the deep M33MU workloads pass at 8K with PSPLIM overflow detection armed, so 10K carries at least 2K margin). With two guests, the hsm-only server slots total 20,480 stack bytes plus 512 guard bytes. Manifest-sized Secure Partition stacks use their declared sizes instead. | Size from measured stack high-water marks and keep at least the scheduler minimum. |
| `WT_SHARED_UART` | Reference guest UART selection; default `3`. | Guest and Secure builds must use a consistent value. |
| `WT_GUEST_CORE_CLOCK_HZ` | Guest core-clock value; default `240000000`. | Must match the configured target clock. |
| `WT_GUEST_UART_CLOCK_HZ` | Guest UART-clock value; default `120000000`. | Must match the selected UART clock source. |

## Security and service options

| Define | Description | Requirement |
| --- | --- | --- |
| `WT_GUEST_FLASH_WRP` | When `1`, verify full STM32 guest-window WRP coverage before launch; default `0`. | Set to `1` for the hardened STM32H563 image and provision WRP after flashing. M33MU does not model WRP. |
| `WT_ENGINE_HSM` | Legacy engine selector; unset by default. `0` maps to `WT_ENGINE=native` and `1` maps to `WT_ENGINE=hsm` when the public selector is not supplied. The build also derives this internal value from `WT_ENGINE`. | Prefer `WT_ENGINE` for new builds and do not supply conflicting selectors. The guest and Secure image must select the same engine. |
| `WT_ATTEST_COSE` | Must remain `1` in the current STM32H563 reference build; default `1`. The `0` configuration does not compile because the reset path still references attestation-gated handoff variables. | Requires the wolfCOSE submodule and the configured attestation key backend. |
| `WT_WOLFCRYPT_SP_ASM` | Enable wolfCrypt SP Cortex-M assembly; default `1`. | Requires compatible Armv8-M assembly sources and toolchain. |
| `WT_WOLFCRYPT_ARMASM` | Enable additional wolfCrypt Thumb-2 assembly; default `1`. | Requires a compatible GNU Arm toolchain. |
| `WT_WOLFCRYPT_STM32_HASH` | STM32 HASH acceleration selector; default `0`. | Must remain `0`: the Makefile rejects other values because wolfHSM SHA state is not compatible with the peripheral representation. |
| `WT_CONFORMANCE` | When `1`, select the manifest and sources used by Arm PSA API validation. | Use only for conformance builds; the default production manifest is selected at `0`. |

## Image layout

| Define | Description | Requirement |
| --- | --- | --- |
| `WT_SECURE_FLASH_BASE` | Secure image link base; standalone default `0x0C000000`. | Must match the bootloader slot and linker layout. |
| `WT_SECURE_FLASH_SIZE` | Available Secure image bytes; standalone default `0x00020000`. | Must cover the linked image without overlapping another flash region. |
| `WT_SECURE_IMAGE_HEADER_SIZE` | Bytes reserved before linked code; default `0`. | Set to match the header layout of an image signed for wolfBoot. |
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
| `WT_VNET_TIMEOUT_TICKS` | Reserved frame-expiration threshold; default `500`. | The value is compiled, but production code does not currently call `vnet_switch_drop_expired()`, so changing it has no runtime effect. |
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
| `HAVE_HKDF` | Enables HKDF. | Required by linked wolfHSM/wolfCrypt code paths. |
| `HAVE_HASHDRBG` | Enables the HashDRBG. | Requires the target `CUSTOM_RAND_GENERATE_BLOCK` entropy callback. |
| `NO_RSA` | Excludes RSA from the Secure profile. | Fixed for the reference image. |

## Manifest controls

`isolation_profile` is a JSON field, not a preprocessor macro. The
reference manifest sets it to numeric value `3`
(`WT_ISOLATION_PROFILE_LEVEL_3`). The manifest also requests feature
mask `1`, which is `WT_MANIFEST_FEATURE_IPC`. The Makefile
invokes the generator with supported framework `0x0100` and supported
features `0x1`, so an unsupported manifest request fails generation.

See [Building](Building.md) for command examples and [Security Model](Security-Model.md) for the runtime
meaning of these settings.
