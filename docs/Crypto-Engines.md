# Crypto Engines

wolfTrust provides two Secure crypto engines behind the same Platform Security
Architecture (PSA) Firmware Framework for M (FF-M) service boundary. The native
crypto engine is the default. The wolfHSM engine is an opt-in add-on for
deployments that need the wolfHSM client/server key model or its external-HSM
integration path.

The engine choice does not change the actual Non-secure-to-Secure boundary.
Both builds use the same five CMSE veneers, generated manifest, service IDs,
SPM-owned caller identity, copied IOVEC rules, isolation bands, storage
services, attestation service, firmware-update service, and Secure Partition
recovery path. The STM32H563 manifest requests isolation profile 3 in both
builds. That value is wolfTrust's validated policy profile, not proof of
independent TF-M Level 3 code and data isolation.

## At a glance

| | Native crypto engine | wolfHSM engine |
| --- | --- | --- |
| Selector | `WT_ENGINE=native` (default) | `WT_ENGINE=hsm` |
| Guest PSA Crypto | wolfPSA and wolfCrypt execute in the Non-secure guest; DRBG seed requests cross into the Secure vault | wolfPSA routes supported operations through the wolfHSM client and `SERVICE_HSM` to a per-guest Secure wolfHSM server |
| Secure key service | Native request format dispatches wolfCrypt directly; explicitly vault-backed keys are NVM objects | wolfHSM request format dispatches the wolfHSM server and its keystore |
| Guest volatile PSA keys | Held in the guest's Non-secure memory | Keys for supported offloaded operations are held by the Secure wolfHSM server |
| Persistent Secure keys | Native vault objects marked `SENSITIVE` and `NONEXPORTABLE` | wolfHSM server-keystore objects with wolfHSM key policy |
| Attestation IAK | Vault-backed P-256 key used directly by wolfCrypt | Committed wolfHSM server-keystore key |
| External HSM path | Not provided by this engine | Available through the wolfHSM server model when a deployment configures a backend; the reference build uses software wolfCrypt |
| Secure-image footprint | Lower | Adds the wolfHSM protocol, server, per-guest contexts, and per-guest server stacks |

The native engine is not a mode in which every guest PSA key automatically
moves into the Secure vault. In the reference guests, ordinary wolfPSA
operations and volatile keys remain local to the Non-secure guest. The native
wire is a separate explicit interface for vault-backed key operations. Secure
services such as attestation use that vault backend directly.

## One service seam

`SERVICE_HSM` keeps its existing name and SID in both builds. The service
copies one request into Secure memory, obtains the caller identity stamped by
the SPM, and passes the opaque packet to the engine selected at build time:

```text
Non-secure guest
  |
  | psa_connect / psa_call / psa_close
  v
five WolfTrust_FFM_* CMSE veneers
  |
  v
SPM: caller identity + manifest policy + copied IOVECs
  |
  v
SERVICE_HSM protocol-opaque relay
  |
  +-- WT_ENGINE=native --> native request --> wolfCrypt + vault key backend
  |
  `-- WT_ENGINE=hsm ----> wolfHSM packet --> per-guest wolfHSM server
```

The binding is the `wt_hsm_relay_set_submit()` call in
`src/spm_partitions.c`. It selects `wt_native_submit()` or
`wt_hsm_relay_submit()`. `src/services/hsm_relay_service.c` does not interpret
either protocol. It enforces the copied request and response bounds and passes
the SPM-stamped client ID to the selected backend.

## Native crypto engine

The native engine links wolfCrypt and the shared flash-backed NVM object store,
but not the wolfHSM server, communication layer, or message layer.

The reference guest configuration behaves as follows:

- wolfPSA and wolfCrypt execute locally in each Non-secure guest;
- wolfCrypt DRBG seed material comes from the Secure vault RNG through one
  `SERVICE_HSM` call;
- ITS, Protected Storage, attestation, and firmware update continue to use
  their normal Secure services; and
- clients that need a vault-backed key can use the native request format
  explicitly.

Guest-created vault-backed P-256 and AES-256 key objects are indexed by the
`SERVICE_HSM` partition identity, the SPM-stamped client identity, and a
64-bit UID. They are stored with the wolfHSM NVM library's `SENSITIVE` and
`NONEXPORTABLE` flags. The storage face refuses key-flagged objects, checked
NVM reads reject non-exportable objects, and the native request format has no
private-key export operation. Private-key computations run in the Secure
key-vault domain and temporary plaintext key buffers are zeroized after use.
The attestation IAK is a separate fixed vault object used only by the
attestation path.

### Native request format

One request is a 24-byte `wt_crypto_wire_req_t` followed by an optional
payload. One response is a 32-bit PSA status followed by an optional payload.
Each complete request and response is bounded by the 384-byte
`WT_HSM_RELAY_MSG_MAX` copied buffer.

| Request field | Type | Meaning |
| --- | --- | --- |
| `uid` | `uint64_t` | Key UID for key operations |
| `op` | `uint32_t` | Operation number |
| `usage` | `uint32_t` | Key-usage bits, or requested length for `RANDOM` |
| `key_type` | `uint32_t` | Native P-256 or AES-256 key encoding |
| `reserved` | `uint32_t` | Reserved; must be zero. The Secure parser rejects a nonzero value with `PSA_ERROR_INVALID_ARGUMENT` |
| payload | bytes | Imported key, digest, signature, plaintext, ciphertext, or hash input as required by the operation |

The defined operations are key generate, import, public export, sign, verify,
encrypt, decrypt, and destroy, plus random generation and SHA-256 hashing.
Random responses are limited to 256 bytes per request. P-256 signatures use a
fixed 64-byte `r || s` form and public keys use the 65-byte uncompressed X9.63
form. AES-256 encrypt and decrypt use AES-GCM and return or consume
`nonce || ciphertext || tag`.

The structures are copied directly between the reference Cortex-M client and
Secure image. This is a target-local ABI, not a versioned network protocol.
The header and operation values are declared in
`include/wolftrust/services/crypto_native.h`.

## Shared NVM object store

wolfHSM is not removed in the native engine. Its self-contained flash-backed
object store is linked in **both** engines and owns every persistent object:
the vault, Internal Trusted Storage, Protected Storage, the firmware-update
staging metadata, the anti-rollback version floors, and the native engine's
vault key objects. Only wolfHSM's server, communication, and message layers
are dropped in native. The store's on-flash format is identical in both
engines, so persistent storage objects survive a switch between engines.

The Initial Attestation Key is the exception. The hsm engine keeps the IAK in
the wolfHSM server keystore; the native engine keeps it as a vault key object.
Neither engine migrates the other's, so switching engines on an
already-provisioned device does not carry the attestation identity: a
provisioning lifecycle mints a fresh IAK, and a SECURED device with no IAK for
the running engine fails closed rather than adopting a new one. Choose the
crypto engine at provisioning time and keep it fixed for the device's life.

| Source | Role |
| --- | --- |
| `wh_nvm.c` | Object-store API: add, read, metadata, destroy, and the access-policy checks (`WRITE_ONCE`, `SENSITIVE`, `NONEXPORTABLE`) |
| `wh_nvm_flash.c` | Log-structured object store implemented over a flash callback |
| `wh_flash_unit.c` | Program-unit-aligned read, program, erase, and blank-check helpers under the store |
| `wh_lock.c` | Serialization lock so the shared store is safe across the confined keystore partitions |
| `wh_utils.c` | Endian, constant-time compare, and force-zero helpers the store depends on |
| `wh_keyid.c` | Key-id namespace translation between client and server key identifiers |

These files carry no server, communication, message, or wolfCrypt dependency,
so linking them costs only the store itself. Reusing the proven store rather
than reimplementing it keeps the on-flash format stable and avoids re-testing a
storage rewrite; the flash-backed object store is not where either engine's
size difference lives.

## wolfHSM engine

The wolfHSM engine links the wolfHSM client/server protocol and creates one
Secure server context for each configured guest. Guest wolfPSA calls use
wolfCrypt's crypto-callback path, the wolfHSM client serializes the request,
and the request crosses the same `SERVICE_HSM` FF-M door used by the native
engine.

The relay derives guest `N` from SPM client ID `-(N + 1)` and forces wolfHSM
server client ID `N + 1`. It rejects guest-facing wolfHSM NVM message groups,
so a guest cannot use the crypto door to read vault, rollback, storage-counter,
or attestation objects. The server keystore provides wolfHSM's key lifecycle,
namespace, and non-exportable-key behavior.

The reference engine runs wolfCrypt in the Secure image. Choosing
`WT_ENGINE=hsm` does not by itself select an external device; it retains the
wolfHSM server integration point for a deployment that supplies one.

## Choosing an engine

Use the native crypto engine when:

- Secure flash or SRAM is constrained;
- guest-local wolfPSA and wolfCrypt execution is acceptable;
- the application only needs Secure entropy, the explicit vault-key
  interface, and the other wolfTrust Secure services; or
- the deployment does not need the wolfHSM client/server protocol.

Choose the wolfHSM engine (`WT_ENGINE=hsm`) over the native engine for one of
three reasons, in rough order of how often they apply:

- **External hardware-HSM or secure-element offload.** This is the main reason
  to enable it: the wolfHSM server can front an external device, so crypto and
  keys are delegated off-core rather than run by on-chip wolfCrypt. The native
  engine has no such path.
- **The full wolfHSM server-keystore key-management model**, when a
  deployment's tooling or provisioning flow already expects wolfHSM key
  lifecycle, namespaces, and non-exportable-key semantics as the server
  presents them.
- **Backward compatibility** with existing Non-secure guest code built against
  the wolfHSM client wire (`wh_Client_CryptoCb`), where reworking the guest to
  the native request format is not worth it.

If none of those apply, prefer the native engine: it is smaller, keeps keys
non-exportable in the vault, and needs no wolfHSM server. The wolfHSM engine
adds this key-management and offload model on top of the same isolation
boundary. The native engine is not a weaker FF-M gateway or a reduced-isolation
build.

## Selecting the engine

Build the Secure image with a fresh output directory for each engine:

```sh
make secure-image WT_ENGINE=native BUILD_DIR=build-native
make secure-image WT_ENGINE=hsm BUILD_DIR=build-hsm
```

`WT_ENGINE=native` is the default, so an unset selector builds the native
engine. The legacy selector remains accepted:

| Legacy setting | Equivalent selector |
| --- | --- |
| `WT_ENGINE_HSM=0` | `WT_ENGINE=native` |
| `WT_ENGINE_HSM=1` | `WT_ENGINE=hsm` |

The Secure image and both guest images must use the same engine. See
[Building](Building.md) for the Zephyr and FreeRTOS guest settings.

## Measured Secure-image cost

These Secure-image measurements were reproduced on 2026-09-18 from the source
tree containing this page. The pinned dependency revisions and versions are
listed in
[TF-M Compatibility](TF-M-Compatibility.md). The builds ran on
`wolf-prec5560` with `arm-none-eabi-gcc` 13.2.1, `-Os`, and the repository
defaults other than the engine and output directory:

```sh
make BUILD_DIR=build_size_native WT_ENGINE=native secure-image
make BUILD_DIR=build_size_hsm WT_ENGINE=hsm secure-image
arm-none-eabi-size build_size_native/wolftrust.elf \
    build_size_hsm/wolftrust.elf
```

Flash is `text + data`; static RAM is `data + bss`. Both images use the
STM32H563 reference manifest with `isolation_profile` set to 3 and include two
guests, ITS, Protected Storage, firmware update, vault services, and COSE
attestation. The wolfHSM image also contains two per-guest wolfHSM tasklet
stacks configured at 10 KiB each. wolfBoot and Non-secure guest images are not
included.

| Engine | `text` | `data` | `bss` | Flash | Static RAM |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native | 86,140 bytes | 708 bytes | 26,545 bytes | 86,848 bytes | 27,253 bytes |
| wolfHSM | 105,712 bytes | 720 bytes | 58,353 bytes | 106,432 bytes | 59,073 bytes |
| wolfHSM overhead | 19,572 bytes | 12 bytes | 31,808 bytes | 19,584 bytes | 31,820 bytes |

### Stack contribution

With the default `WT_MAX_GUESTS=2`, the wolfHSM engine adds one server tasklet
stack slot per guest:

```text
2 * (10,240-byte stack + 256-byte underflow guard) = 20,992 bytes
```

The stack payload is therefore 20,480 bytes and the guards add 512 bytes. The
linked wolfHSM image reports `g_co_stack_slots` as `0x5200` bytes, matching the
calculation. A one-guest build allocates one 10,496-byte slot. The remaining
10,828 bytes of the 31,820-byte static-RAM difference are server, protocol,
crypto, and per-guest context state.

`WT_CO_STACK_SIZE` defaults to 10,240 bytes. The positive, Crypto-validation,
and FF-M conformance M33MU workloads also passed with an 8 KiB configured stack
and PSPLIM overflow detection enabled. That threshold test establishes a peak
below 8 KiB for those workloads, so the 10 KiB default provides at least 2 KiB
of allocation headroom over the tested peak. It is not a precise high-water
measurement or a guarantee for different workloads. This is a fixed
allocation, not a heap or a claim that every run consumes all 10 KiB.

See [TF-M Compatibility](TF-M-Compatibility.md) for the complete local
footprint comparison and methodology.

## Build invariants

Both engine builds enforce the following after linking:

1. `mk/arch-armv8m.mk` runs `arm-none-eabi-nm` and writes the complete symbol
   list to `BUILD_DIR/nsc-syms.txt`.
2. The link check rejects any `__acle_se_*` symbol outside this exact `nm`
   set: `__acle_se_WolfTrust_FFM_FrameworkVersion`,
   `__acle_se_WolfTrust_FFM_ServiceVersion`,
   `__acle_se_WolfTrust_FFM_Connect`, `__acle_se_WolfTrust_FFM_Call`, and
   `__acle_se_WolfTrust_FFM_Close`.
3. A separate count check requires exactly five `__acle_se_*` symbols, so a
   missing veneer also fails the build.
4. The same symbol list is searched for `malloc`, `free`, `calloc`,
   `realloc`, `_sbrk`, `_malloc_r`, and `_free_r`; finding one fails the
   zero-heap Secure-image build.

The measured native and wolfHSM images contain exactly those five veneers and
none of the guarded heap symbols. The source profile also defines
`NO_WOLFSSL_MEMORY` and `WOLFSSL_NO_MALLOC`.

See [Security Model](Security-Model.md) for the common boundary and
[Testing](Testing.md) for the engine test matrix.
