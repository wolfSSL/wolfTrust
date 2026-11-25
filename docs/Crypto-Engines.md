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
builds. That value is wolfTrust's validated policy profile.

## At a glance

| | Native crypto engine | wolfHSM engine |
| --- | --- | --- |
| Selector | `WT_ENGINE=native` (default) | `WT_ENGINE=hsm` |
| Guest PSA Crypto | wolfPSA and wolfCrypt execute in the Secure image and the guest links only a client (default). With `WT_SECURE_PSA=0` they execute in the Non-secure guest and only DRBG seed requests cross into the Secure vault | wolfPSA routes supported operations through the wolfHSM client and `SERVICE_HSM` to a per-guest Secure wolfHSM server |
| Secure key service | Native request format dispatches wolfCrypt directly; explicitly vault-backed keys are NVM objects | wolfHSM request format dispatches the wolfHSM server and its keystore |
| Guest volatile PSA keys | Held in the Secure image, or in the guest's Non-secure memory with `WT_SECURE_PSA=0` | Keys for supported offloaded operations are held by the Secure wolfHSM server |
| Persistent Secure keys | Native vault objects marked `SENSITIVE` and `NONEXPORTABLE` | wolfHSM server-keystore objects with wolfHSM key policy |
| Attestation IAK | Vault-backed P-256 key used directly by wolfCrypt | Committed wolfHSM server-keystore key |
| External HSM path | Not provided by this engine | Available through the wolfHSM server model when a deployment configures a backend; the reference build uses software wolfCrypt |
| Secure-image footprint | Lower | Adds the wolfHSM protocol, server, per-guest contexts, and per-guest server stacks |

By default the native engine serves all of PSA Crypto, its keys and its
operation state from the Secure image
([`WT_SECURE_PSA=1`](#psa-crypto-in-the-secure-image-wt_secure_psa1)).
`WT_SECURE_PSA=0` is the smaller opt-out: the
guest runs wolfPSA and wolfCrypt itself, so its volatile keys stay in
Non-secure memory. The native wire is a separate explicit interface for
vault-backed key operations. Secure services such as attestation use that vault
backend directly.

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

- by default (`WT_SECURE_PSA=1`), wolfPSA and wolfCrypt execute in the crypto
  partition and each guest links only the PSA Crypto client; with
  `WT_SECURE_PSA=0` they execute locally in each Non-secure guest instead;
- a guest-local wolfCrypt DRBG takes its seed material from the Secure vault
  RNG through one `SERVICE_HSM` call;
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

The native engine builds wolfCrypt with `NO_ASN` and does not compile
`asn.c`. Its key operations use only raw forms (P-256 scalars, X9.63 public
points, and fixed-width `r || s` signatures), which a `NO_ASN` wolfCrypt signs
and verifies directly, so ASN.1 would be dead code. The wolfHSM engine keeps
ASN because its server stores keys as DER. Attestation signs only through
wolfCOSE's external signer, so both engines build wolfCOSE with
`WOLFCOSE_NO_LOCAL_SIGN`.

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

## PSA Crypto in the Secure image (`WT_SECURE_PSA=1`)

The native engine's default, `WT_SECURE_PSA=1`, links wolfPSA into the
crypto partition and serves the whole PSA Crypto API from the Secure image.
The wolfHSM engine defaults to `0` and refuses `1`. The guest links `src/client/psa_crypto_client.c` in place of wolfPSA:
each `psa_*` call becomes one or more `SERVICE_HSM` requests with operation
`WT_CRYPTO_OP_PSA`, and no key, operation state or intermediate secret is
held in Non-secure memory.

`make WT_SECURE_PSA=0 secure-image` opts out, and a port can set
`WT_SECURE_PSA ?= 0` in its `mk/target-<soc>.mk` when its Secure RAM cannot
hold the larger crypto partition. Build every guest with the Secure image's
value; the M33MU runner exports it from the image's build stamp.

Ownership and lifetime:

- Every key and operation belongs to the SPM-stamped client ID of the guest
  that created it; another guest's handle fails as an invalid handle.
- Operation handles are opaque tokens carrying a 24-bit slot generation and
  a per-boot nonce, so a handle from before a service restart never
  validates. A slot whose generations are spent is retired until the service
  restarts rather than reusing a token.
- Volatile keys and operations are limited per client (`WT_PSA_KEY_SLOTS`,
  default 16, and `WT_PSA_OP_SLOTS`, default 8, split across the guests);
  each client's operations come from its own slot range.
- Key IDs map to vault uids in a reserved range that the native key wire
  refuses, so a native key can neither take nor remove a PSA key's record.
- The client is not thread-safe: a large call is several relay messages, so
  a guest serializes its PSA calls, as the reference guests do.
- `psa_crypto_init()` from a client releases that client's volatile keys and
  operations.
- Persistent keys accept only `PSA_KEY_ID_USER_MIN..PSA_KEY_ID_USER_MAX` and
  are stored as vault objects namespaced by client ID, so two guests can use
  the same key ID. A new image in the same guest slot inherits that slot's
  persistent keys. Builtin and vendor key IDs, including the IAK,
  are not reachable from the Non-secure side.

Transport and memory:

- Every call fits one 384-byte relay message. The client runs a one-shot
  hash, MAC, cipher or AEAD that does not fit as the matching multi-part
  sequence, and splits multi-part updates, random output and key derivation
  output into message-sized pieces. A failed split call leaves no partial
  output. A long message to sign or verify is hashed first and handled as a
  hash, so the key must allow hash signing. Key import, asymmetric
  encryption and key derivation input stay single-message and fail larger
  inputs with `PSA_ERROR_INSUFFICIENT_MEMORY`.
- wolfPSA allocates from a pool private to the crypto partition's isolation
  band, `WT_PSA_POOL_BYTES`, split into one arena per guest (2,048 bytes
  each by default). A call allocates only from its caller's arena, so one
  guest's keys and operations cannot starve another guest. Blocks are
  scrubbed on free and no other partition can reach the allocator. A full
  arena fails the call with `PSA_ERROR_INSUFFICIENT_MEMORY`.
- HKDF output is streamed from the previous block, one-shot GCM and CCM
  read the message in place, and multi-part GCM and ChaCha20-Poly1305 take
  additional data straight into the stream, so none of them copies the
  message, the additional data or the derivation into the pool.

`WT_SECURE_PSA_PROFILE` picks the algorithm set compiled into the Secure
image. The wolfCrypt side lives in
`src/services/wolfhsm/runner/secure_psa_profile.h`, which the host suite
includes too:

| Profile | Algorithms | STM32H563 Secure flash / RAM |
| --- | --- | ---: |
| `compat` (default) | The reference guest's set: P-256 ECDSA (deterministic) and ECDH, AES-GCM, CCM, CTR, CBC and ECB, SHA-256, HMAC, HKDF, PBKDF2, TLS 1.2 PRF | 101,361 / 41,244 |
| `standard` | `compat` without PBKDF2, TLS 1.2 PRF, CBC, ECB and deterministic ECDSA (ECDSA uses a random nonce) | 94,583 / 41,244 |
| `lean` | `standard` without CCM and AES decryption | 92,919 / 41,244 |
| `symmetric` | `lean` without ECC in the PSA surface; ECC key imports and generation return `PSA_ERROR_NOT_SUPPORTED` | 88,183 / 41,244 |

RAM is the Secure RAM the image reserves. It is the same for every profile:
the crypto partition's stack grows from 5 to 6 KiB for wolfPSA's ECDSA, and its
data band from 1.5 KiB to `WT_PSA_POOL_BYTES` plus 2 KiB. The opt-out,
`WT_SECURE_PSA=0`, is 61,916 / 37,660 bytes. The PSA
guest drops from 65,384 to 34,600 bytes of flash; it keeps wolfCrypt only for
the attestation token verifier. In `standard`, wolfCrypt, wolfPSA, the
service and the key glue are 55,021 bytes of that flash.

wolfPSA refuses AES or GHASH whose timing depends on the key or the data, so
the Secure image runs AES on wolfCrypt's touch-lines C core and GHASH on its
masked multiply, and `WT_WOLFCRYPT_ARMASM=1` is refused with `WT_SECURE_PSA=1`.

Moving an existing guest-local application to the `WT_SECURE_PSA=1` default:

- Build the Secure image and every guest with the same value: under `1` the
  reference guests (`tests/firmware/psa-guest`, the Zephyr module's
  `CONFIG_WOLFTRUST_SECURE_PSA` and the FreeRTOS guest) then link
  `psa_crypto_client.c` and wolfPSA's `psa_api_stub.c` in place of wolfPSA.
- Application `psa_*` calls stay unchanged; only `psa/crypto.h` is needed.
- Keys created before the switch lived in guest RAM and are not migrated.
  Persistent keys must be imported or generated again through the Secure
  service.
- Each call is one or more IPC round trips. The M33MU crypto API suite takes
  about 2.6 times the cycles of the guest-local build.
- Code that calls wolfCrypt directly, like the reference attestation token
  verifier, still needs wolfCrypt in the guest.
- To keep the earlier behavior, build the Secure image and the guests with
  `WT_SECURE_PSA=0` (Zephyr: `CONFIG_WOLFTRUST_SECURE_PSA=n`).

`WT_SECURE_PSA=1` covers Non-secure callers. Secure partitions keep using the
vault backend directly. CMAC is not compiled in, so PSA API test c047 stays
skipped as in the guest build. Host coverage is `tests/host/psa_secure_crypto`,
the M33MU `devcrypto` scenario runs the PSA crypto API tests against the
Secure service, and `devcryptolocal` runs them against the `WT_SECURE_PSA=0`
guest.

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

Guest initialization completes wolfHSM's `COMM INIT` handshake before enabling
crypto requests. A failed handshake releases the client transport. Transient
connection failures use the existing initialization retry. When that retry is
active, a failed handshake restores its callback so the next crypto request
can retry without an explicit guest initialization call.

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

- Secure flash or SRAM is constrained (with `WT_SECURE_PSA=0` when guest-local
  wolfPSA and wolfCrypt execution is acceptable);
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

These Secure-image measurements were taken on 2026-11-25 with Arm GNU 15.2.1
in `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25`, LTO on, and the repository
defaults other than the engine, the profile and the output directory:

```sh
make BUILD_DIR=build_size_native WT_ENGINE=native secure-image
make BUILD_DIR=build_size_optout WT_SECURE_PSA=0 secure-image
make BUILD_DIR=build_size_hsm WT_ENGINE=hsm secure-image
arm-none-eabi-size build_size_native/wolftrust.elf \
    build_size_optout/wolftrust.elf build_size_hsm/wolftrust.elf
```

Flash is `text + data`. Secure RAM is everything the image reserves: `data +
bss` plus the SPM main stack and every partition stack and band
([Footprint](Footprint.md#how-sizes-are-measured)). The images use the
STM32H563 reference manifest at isolation level 3. The default profile has
one guest, ITS, Protected Storage, vault services and COSE attestation. The
`full` profile adds `WT_MAX_GUESTS=2 WT_MANIFEST_RUNTIME_CHECK=1 WT_FWU=1 WT_SHA256_FAST=1`.
wolfBoot and Non-secure guest images are not included.

| Engine and profile | `text` | `data` | `bss` | Flash | Secure RAM |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native, default (`WT_SECURE_PSA=1`, `compat`) | 101,301 bytes | 60 bytes | 14,492 bytes | 101,361 bytes | 41,244 bytes |
| Native, `WT_SECURE_PSA=1` `standard` | 94,527 bytes | 56 bytes | 14,492 bytes | 94,583 bytes | 41,244 bytes |
| Native, `WT_SECURE_PSA=0` | 61,868 bytes | 48 bytes | 12,100 bytes | 61,916 bytes | 37,660 bytes |
| wolfHSM, default | 89,764 bytes | 56 bytes | 34,452 bytes | 89,820 bytes | 72,280 bytes |
| wolfHSM over native `WT_SECURE_PSA=0` | 27,896 bytes | 8 bytes | 22,352 bytes | 27,904 bytes | 34,620 bytes |
| Native, `full` | 112,880 bytes | 60 bytes | 21,380 bytes | 112,940 bytes | 52,232 bytes |
| Native, `full`, `WT_SECURE_PSA=0` | 73,444 bytes | 48 bytes | 16,940 bytes | 73,492 bytes | 46,600 bytes |
| wolfHSM, `full` | 101,628 bytes | 56 bytes | 56,140 bytes | 101,684 bytes | 91,760 bytes |

### Stack contribution

The wolfHSM engine adds one server tasklet stack slot per guest. The default
image has one guest and one 10,496-byte slot (10,240-byte stack plus a
256-byte underflow guard). The rest of the 34,620-byte Secure RAM difference
is the crypto partition's larger stack (6 KiB instead of 5 KiB; the wolfHSM
server peaked at 4,856 bytes on it in the 2026-11-25 M33MU runs) and its larger
data band (24 KiB instead of 1.5 KiB), which holds the server, protocol and per-guest state. With
`WT_MAX_GUESTS=2` (the `full` profile):

```text
2 * (10,240-byte stack + 256-byte underflow guard) = 20,992 bytes
```

The linked two-guest wolfHSM image reports `g_co_stack_slots` as `0x5200`
bytes, matching the calculation.

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
