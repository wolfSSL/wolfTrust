# Services

The STM32H563 manifest describes connection-based FF-M 1.0 IPC services. The
default image contains six Secure services; `CONFIG_VNET=y` selects a
manifest with a seventh service.

## Service registry

| Service | SID | Non-secure clients | Purpose |
| --- | ---: | --- | --- |
| `SERVICE_ATTEST` | `0x1000` | Yes | PSA Initial Attestation token generation |
| `SERVICE_VAULT` | `0x1002` | No | Secure-only persistent objects, sealing, and randomness |
| `SERVICE_ITS` | `0x1003` | Yes | PSA Internal Trusted Storage |
| `SERVICE_PS` | `0x1004` | Yes | PSA Protected Storage |
| `SERVICE_FWU` | `0x1005` | Yes | PSA Firmware Update staging for wolfBoot |
| `SERVICE_HSM` | `0x1006` | Yes | Copied request relay for the selected native or wolfHSM crypto engine |
| `SERVICE_VNET` | `0x1007` | Yes, optional | Secure virtual Ethernet switch implemented by wolfTrust for optional Non-secure wolfIP guests |

All service versions are `1`. ITS and Protected Storage declare a
dependency on the Secure-only vault. The default manifest is
`port/stm32h563/manifest.json`; the network variant is
`port/stm32h563/manifest-vnet.json`.

## Runtime model

Every service loop is a scheduled unprivileged Secure coroutine. It waits for
its signal, obtains one message, reads copied input, writes copied output, and
replies. Each thread receives shared Secure text plus its own stack and
manifest-declared data. Privileged hardware operations are performed by narrow
SVC gates that verify which partition issued the request.

## Crypto engines and PSA Crypto

Zephyr and FreeRTOS reference guests expose wolfPSA's PSA Crypto API. The
`WT_ENGINE` build selector chooses how those guests and `SERVICE_HSM` are
wired. Both engines use one input and one output vector, bounded to 384 bytes,
through the same copied FF-M call.

With the default native engine, wolfPSA and wolfCrypt execute in the
Non-secure guest. DRBG seed requests use the native client to reach the Secure
vault RNG. The native wire also exposes explicit vault-backed P-256 and
AES-256 key operations, random generation, and SHA-256. Vault key objects are
namespaced by the SPM-stamped client ID and stored `SENSITIVE` and
`NONEXPORTABLE`.

With the wolfHSM engine, wolfPSA uses a wolfHSM client transport that places
one complete wolfHSM packet in the FF-M call. The relay maps guest `N` to its
dedicated server, forces server client ID `N + 1`, and rejects guest-facing
wolfHSM NVM message groups. The reference build executes the server with
software wolfCrypt; deployments can configure wolfHSM's external-HSM path.

The reference cryptographic profile is controlled by each guest's wolfCrypt
`user_settings.h`. Consult the vendored
`lib/wolfPSA/wolfpsa/psa/crypto.h` and the active guest configuration
before assuming a particular algorithm is available. See
[Crypto Engines](Crypto-Engines.md) for the protocol, key-protection, and
footprint differences.

## Vault

`SERVICE_VAULT` is inaccessible to Non-secure clients. It provides backing
operations for the storage front ends and a Secure randomness operation. Each
object is indexed by:

```text
(calling Secure Partition, delegated end-client, UID)
```

This lets ITS and Protected Storage forward a guest's stamped client ID without
allowing either front end to escape its own vault namespace.

The vault uses the wolfHSM NVM object-store library and checked operations for
write-once and object-metadata policy in both engines. Storage calls cannot
create, read, or overwrite the reserved key-object type. The native engine
installs the vault key backend used by its explicit key wire. The wolfHSM
engine instead manages guest cryptographic keys in its server keystore behind
`SERVICE_HSM`.

## Internal Trusted Storage

`SERVICE_ITS` implements PSA ITS 1.0:

- `psa_its_set`
- `psa_its_get`
- `psa_its_get_info`
- `psa_its_remove`

UID zero is invalid. The current public client shim limits each write, and
therefore every ITS object it creates, to 512 bytes. The underlying Secure
vault uses a 1024-byte object buffer, and its 24-byte request header caps one
copied vault response at 1000 bytes. A client can use `data_offset` when its own
output buffer is smaller than the object. The write-once flag is enforced by
both the front end and checked NVM metadata. ITS data is held in Secure-only
storage, but ITS does not add the Protected Storage sealing flag.

The current storage path always enforces `PSA_STORAGE_FLAG_WRITE_ONCE`,
including during `PSA_ROT_PROVISIONING`. This differs from PSA Secure Storage
1.0, which requires the flag not to be enforced in that lifecycle state. The
same deviation applies to Protected Storage objects created with the flag.

## Protected Storage

`SERVICE_PS` implements the core PSA Protected Storage 1.0
set/get/get-info/remove operations. `psa_ps_get_support()` returns
`0`; `psa_ps_create` and
`psa_ps_set_extended` return
`PSA_ERROR_NOT_SUPPORTED`.

Every Protected Storage object created through the public shim is likewise
limited to 512 bytes. The underlying Secure vault still uses a 1024-byte object
buffer and caps one copied vault response at 1000 bytes.

Every stored object is AES-256-GCM sealed in the vault under a device-local
non-exportable key in the shared NVM store. A persisted write counter supplies
the nonce and the object label is authenticated data. Confidentiality and
replay-protection hint flags do not weaken storage: Protected Storage still
seals and counter-binds the object.
The current `psa_ps_get_info()` behavior echoes the requested flags instead of
reporting the stronger protection actually applied, which differs from the PSA
Secure Storage 1.0 recommendation.

## Initial Attestation

`SERVICE_ATTEST` implements the token and exact-size API operations from PSA
Initial Attestation 1.0. It accepts a 32-, 48-, or 64-byte challenge and returns
a tagged COSE_Sign1 token signed with ES256 through an external signer backed
by the selected engine's protected attestation key. wolfCOSE performs the COSE
encoding.

The emitted token is derived from [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html)
but is not conformant with its advertised
`tag:psacertified.org,2023:psa#tfm` profile. Its boot seed is deterministic
across equivalent boots, its software-component measurement type and
description values are reversed, its signer ID hashes the literal name
`wolfBoot` rather than identifying the signing key, and its implementation ID
hashes a software label rather than identifying the immutable PSA RoT hardware
assembly. [TF-M Compatibility](TF-M-Compatibility.md) records these token-profile and API deviations.

The EAT/PSA claim set binds:

- the challenge;
- device and implementation identifiers;
- the SPM-stamped client ID;
- authenticated lifecycle state;
- the measured wolfTrust boot; and
- one software component for each guest that passed launch verification.

The service also supports internal call types for exact token-size and
uncompressed P-256 public-key queries. The private attestation key is never
exported.

## Firmware Update

`SERVICE_FWU` exposes a single-component subset of PSA Firmware Update 1.0.
Unlike the specification, it rejects unaligned block sizes instead of padding
them and returns `PSA_ERROR_INVALID_ARGUMENT` rather than
`PSA_ERROR_DOES_NOT_EXIST` for unknown component IDs. The normal flow is:

```text
READY -> WRITING -> CANDIDATE -> STAGED -> authenticated reboot
```

Writes are copied, bounded, aligned to the target flash granularity, and staged
in the wolfBoot update partition. Finish validates the complete wolfBoot image
header and binds the candidate version. Install checks the candidate again
against the persistent version floor loaded when the Firmware Update partition
started, then writes the wolfBoot update trigger. A reboot request is allowed
only for the client that owns an armed staged update.

The integration commits the installed image at authenticated reboot and does
not persist a trial state. `psa_fwu_accept()` therefore returns
`PSA_ERROR_NOT_SUPPORTED`. Cancel, reject, and clean disarm or reset
eligible pre-reboot state. A successful `psa_fwu_start()` sets the owner timer.
While the session remains active, any owner operation other than
`psa_fwu_query()` or `psa_fwu_start()` that reaches dispatch refreshes the timer,
even if the operation fails or is unsupported. After 30,000 scheduler ticks
without such a refresh, the next well-formed request from a different client
reclaims the session. Ownership does not expire autonomously.

## Optional virtual network

`CONFIG_VNET=y` adds `SERVICE_VNET` and a Secure virtual
Ethernet switch. Guests open a port, optionally set a MAC address, transmit a
copied frame, fetch a copied received frame, and acknowledge the virtual
receive interrupt through FF-M operations.

Port selection comes from the stamped caller identity. Secure pool tokens and
generation counters do not cross into a guest. The mediated PSA transport MTU
is 1000 bytes so a frame and receive metadata fit the copied-transfer budget.

See [API Reference](API-Reference.md) for client signatures and [Macros](Macros.md) for service build
controls.
