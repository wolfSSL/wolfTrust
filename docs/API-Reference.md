# API Reference

This page describes the public client and Secure Partition interfaces present
in the repository. Header files are authoritative; algorithm availability in
PSA Crypto also depends on the selected wolfPSA and wolfCrypt build
configuration.

## Table of Contents

- [Headers](#headers)
- [Data Structures](#data-structures)
- [FF-M Client API](#ff-m-client-api)
- [Secure Partition API](#secure-partition-api)
- [PSA Crypto](#psa-crypto)
- [Internal Trusted Storage](#internal-trusted-storage)
- [Protected Storage](#protected-storage)
- [Firmware Update](#firmware-update)
- [Initial Attestation](#initial-attestation)
- [Lifecycle](#lifecycle)
- [FF-M Gateway Veneers](#ff-m-gateway-veneers)
- [Error Codes](#error-codes)

## Headers

| API | Header | Version |
| --- | --- | --- |
| FF-M client | `include/psa/client.h` | 1.0 |
| Secure Partition | `include/psa/service.h` | FF-M 1.0 IPC plus a wolfTrust-specific backport of `psa_irq_enable()` from Arm's FF-M 1.1 Extension Beta, Issue 0 |
| Common status | `include/psa/error.h` | PSA status values used by wolfTrust |
| PSA Crypto | `lib/wolfPSA/wolfpsa/psa/crypto.h` | 1.4 |
| Internal Trusted Storage | `include/psa/internal_trusted_storage.h` | 1.0 |
| Protected Storage | `include/psa/protected_storage.h` | 1.0 |
| Firmware Update | `include/psa/update.h` | 1.0 |
| Initial Attestation | `lib/wolfPSA/wolfpsa/psa/initial_attestation.h` | 1.0 API operations; see [TF-M Compatibility](TF-M-Compatibility.md) for API and token-profile deviations |
| Lifecycle | `include/psa/lifecycle.h` | FF-M 1.0, Secure Partition only |
| Gateway vector ABI | `include/wolftrust/ffm_veneer.h` | wolfTrust ABI |

## Data Structures

### FF-M vectors

```c
typedef struct psa_invec {
    const void* base;
    size_t len;
} psa_invec;

typedef struct psa_outvec {
    void* base;
    size_t len;
} psa_outvec;
```

An input vector identifies caller-owned read-only bytes. An output vector
identifies caller-owned writable storage; `psa_call` updates
`len` to the number of bytes returned.
The descriptor arrays can hold up to `PSA_MAX_IOVEC` (4) vectors of either
kind. The current SPM accepts at most four vectors total across input and
output.

### Secure Partition message

```c
typedef struct psa_msg_t {
    int32_t type;
    psa_handle_t handle;
    psa_client_id_t client_id;
    void* rhandle;
    size_t in_size[PSA_MAX_IOVEC];
    size_t out_size[PSA_MAX_IOVEC];
} psa_msg_t;
```

`type` is `PSA_IPC_CONNECT`, a service call type,
or `PSA_IPC_DISCONNECT`. The SPM supplies
`client_id`; a service must not derive identity from request data.

### Storage types

```c
typedef uint64_t psa_storage_uid_t;
typedef uint32_t psa_storage_create_flags_t;

struct psa_storage_info_t {
    size_t capacity;
    size_t size;
    psa_storage_create_flags_t flags;
};
```

Defined flags are `PSA_STORAGE_FLAG_NONE`,
`PSA_STORAGE_FLAG_WRITE_ONCE`,
`PSA_STORAGE_FLAG_NO_CONFIDENTIALITY`, and
`PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION`.

### Firmware Update types

```c
typedef uint8_t psa_fwu_component_t;

typedef struct psa_fwu_image_version_t {
    uint8_t major;
    uint8_t minor;
    uint16_t patch;
    uint32_t build;
} psa_fwu_image_version_t;

typedef struct psa_fwu_impl_info_t {
    uint32_t staged_size;
} psa_fwu_impl_info_t;

typedef struct psa_fwu_component_info_t {
    uint8_t state;
    psa_status_t error;
    psa_fwu_image_version_t version;
    uint32_t max_size;
    uint32_t flags;
    uint32_t location;
    psa_fwu_impl_info_t impl;
} psa_fwu_component_info_t;
```

wolfTrust exposes component `0`. The public header defines a
16-byte write alignment and a maximum block size of 1008 bytes for the
STM32H563 service transport.

### Gateway vector ABI

```c
typedef struct wt_ffm_veneer_invec {
    const void* base;
    uint32_t len;
} wt_ffm_veneer_invec_t;

typedef struct wt_ffm_veneer_outvec {
    void* base;
    uint32_t len;
} wt_ffm_veneer_outvec_t;

typedef struct wt_ffm_veneer_iovec {
    wt_ffm_veneer_invec_t in[WT_FFM_VENEER_IOVEC_MAX];
    wt_ffm_veneer_outvec_t out[WT_FFM_VENEER_IOVEC_MAX];
    uint32_t in_count;
    uint32_t out_count;
} wt_ffm_veneer_iovec_t;
```

This fixed-width descriptor crosses the CMSE boundary. The Secure gateway
copies it before validating or using its fields.

## FF-M Client API

### `psa_framework_version`

```c
uint32_t psa_framework_version(void);
```

Returns `PSA_FRAMEWORK_VERSION`, currently `0x0100`.

### `psa_version`

```c
uint32_t psa_version(uint32_t sid);
```

Returns the accessible service version, or `PSA_VERSION_NONE` when the
service is absent or not available to the caller.

### `psa_connect`

```c
psa_handle_t psa_connect(uint32_t sid, uint32_t version);
```

Opens a connection-based service. A positive value is a valid handle; a
non-positive value is an error status.

### `psa_call`

```c
psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec* in_vec, size_t in_len,
                      psa_outvec* out_vec, size_t out_len);
```

Sends one synchronous copied-vector request. The reference target supports up
to four vectors total across input and output.

### `psa_close`

```c
void psa_close(psa_handle_t handle);
```

Closes a valid connection and queues a disconnect message for its service.

## Secure Partition API

These functions are for Secure Partition service loops, not Non-secure
applications.

```c
psa_signal_t psa_wait(psa_signal_t signal_mask, uint32_t timeout);
psa_status_t psa_get(psa_signal_t signal, psa_msg_t* msg);
void psa_set_rhandle(psa_handle_t msg_handle, void* rhandle);
size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx,
                void* buffer, size_t num_bytes);
size_t psa_skip(psa_handle_t msg_handle, uint32_t invec_idx,
                size_t num_bytes);
void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx,
               const void* buffer, size_t num_bytes);
void psa_reply(psa_handle_t msg_handle, psa_status_t status);
void psa_notify(int32_t partition_id);
void psa_clear(void);
void psa_eoi(psa_signal_t irq_signal);
void psa_irq_enable(psa_signal_t irq_signal);
void psa_panic(void) __attribute__((noreturn));
```

`psa_wait` blocks the current Secure coroutine until a selected
service or interrupt signal is ready. `psa_get` pins one message;
`psa_read` and `psa_write` move copied data; and
`psa_reply` completes the call. Unsupported or invalid Secure-caller
use may panic only that partition, after which the recovery policy applies.

## PSA Crypto

wolfTrust vendors wolfPSA's PSA Crypto 1.4 header. The header is the complete
API contract; the functions below show the principal signatures used by the
reference guests. Declarations in the header do not guarantee implementation
availability. The active `user_settings.h` controls which algorithms and
optional extensions are built.

### Initialization and key management

```c
psa_status_t psa_crypto_init(void);

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t* attributes);

void psa_reset_key_attributes(psa_key_attributes_t* attributes);

psa_status_t psa_import_key(const psa_key_attributes_t* attributes,
                            const uint8_t* data, size_t data_length,
                            psa_key_id_t* key);

psa_status_t psa_generate_key(const psa_key_attributes_t* attributes,
                              psa_key_id_t* key);

psa_status_t psa_destroy_key(psa_key_id_t key);

psa_status_t psa_export_key(psa_key_id_t key, uint8_t* data,
                            size_t data_size, size_t* data_length);

psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t* data,
                                   size_t data_size, size_t* data_length);
```

Key attributes are configured with the inline accessors declared by
`psa/crypto.h`. Export remains subject to the key lifetime and usage
policy; protected private keys used by Secure services do not have a private
export path.

### Hash and MAC

```c
psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t* input, size_t input_length,
                              uint8_t* hash, size_t hash_size,
                              size_t* hash_length);

psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t* input, size_t input_length,
                              const uint8_t* hash, size_t hash_length);

psa_status_t psa_mac_compute(psa_key_id_t key, psa_algorithm_t alg,
                             const uint8_t* input, size_t input_length,
                             uint8_t* mac, size_t mac_size,
                             size_t* mac_length);

psa_status_t psa_mac_verify(psa_key_id_t key, psa_algorithm_t alg,
                            const uint8_t* input, size_t input_length,
                            const uint8_t* mac, size_t mac_length);
```

The header also declares the standard multipart hash and MAC setup, update,
finish, verify, clone, and abort calls.

### Cipher and AEAD

```c
psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg,
                                const uint8_t* input, size_t input_length,
                                uint8_t* output, size_t output_size,
                                size_t* output_length);

psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg,
                                const uint8_t* input, size_t input_length,
                                uint8_t* output, size_t output_size,
                                size_t* output_length);

psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg,
                              const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* additional_data,
                              size_t additional_data_length,
                              const uint8_t* plaintext,
                              size_t plaintext_length,
                              uint8_t* ciphertext, size_t ciphertext_size,
                              size_t* ciphertext_length);

psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg,
                              const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* additional_data,
                              size_t additional_data_length,
                              const uint8_t* ciphertext,
                              size_t ciphertext_length,
                              uint8_t* plaintext, size_t plaintext_size,
                              size_t* plaintext_length);
```

Multipart cipher and AEAD operations are also declared in the wolfPSA header.

### Signatures and key agreement

```c
psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg,
                              const uint8_t* input, size_t input_length,
                              uint8_t* signature, size_t signature_size,
                              size_t* signature_length);

psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg,
                                const uint8_t* input, size_t input_length,
                                const uint8_t* signature,
                                size_t signature_length);

psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
                           const uint8_t* hash, size_t hash_length,
                           uint8_t* signature, size_t signature_size,
                           size_t* signature_length);

psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
                             const uint8_t* hash, size_t hash_length,
                             const uint8_t* signature,
                             size_t signature_length);

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t* peer_key,
                                   size_t peer_key_length,
                                   uint8_t* output, size_t output_size,
                                   size_t* output_length);
```

### Key derivation and random generation

```c
psa_status_t psa_key_derivation_setup(
    psa_key_derivation_operation_t* operation, psa_algorithm_t alg);

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t* operation,
    psa_key_derivation_step_t step,
    const uint8_t* data, size_t data_length);

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t* operation,
    psa_key_derivation_step_t step, psa_key_id_t key);

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t* operation,
    uint8_t* output, size_t output_length);

psa_status_t psa_key_derivation_output_key(
    const psa_key_attributes_t* attributes,
    psa_key_derivation_operation_t* operation,
    psa_key_id_t* key);

psa_status_t psa_key_derivation_abort(
    psa_key_derivation_operation_t* operation);

psa_status_t psa_generate_random(uint8_t* output, size_t output_size);
```

## Internal Trusted Storage

```c
psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length,
                         const void* p_data,
                         psa_storage_create_flags_t create_flags);

psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset,
                         size_t data_size, void* p_data,
                         size_t* p_data_length);

psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                              struct psa_storage_info_t* p_info);

psa_status_t psa_its_remove(psa_storage_uid_t uid);
```

The public client shim limits each write, and therefore every ITS object it
creates, to 512 bytes. The underlying Secure vault uses a 1024-byte object
buffer, and its 24-byte request header caps one copied vault response at 1000
bytes. `data_offset` remains useful when the caller supplies an output buffer
smaller than the object. UID zero is invalid.

The current ITS and Protected Storage paths always enforce
`PSA_STORAGE_FLAG_WRITE_ONCE`, including during
`PSA_ROT_PROVISIONING`. PSA Secure Storage 1.0 requires that flag not to be
enforced in the provisioning lifecycle, so this is a known lifecycle deviation.

## Protected Storage

```c
psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length,
                        const void* p_data,
                        psa_storage_create_flags_t create_flags);

psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset,
                        size_t data_size, void* p_data,
                        size_t* p_data_length);

psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
                             struct psa_storage_info_t* p_info);

psa_status_t psa_ps_remove(psa_storage_uid_t uid);

psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity,
                           psa_storage_create_flags_t create_flags);

psa_status_t psa_ps_set_extended(psa_storage_uid_t uid, size_t data_offset,
                                 size_t data_length, const void* p_data);

uint32_t psa_ps_get_support(void);
```

The current service returns `0` from `psa_ps_get_support`.
It returns `PSA_ERROR_NOT_SUPPORTED` for
`psa_ps_create` and `psa_ps_set_extended`. The core
set/get/get-info/remove calls are implemented.
Every Protected Storage object created through the public shim is likewise
limited to 512 bytes. The underlying Secure vault still uses a 1024-byte object
buffer and caps one copied vault response at 1000 bytes.
Objects remain sealed and counter-bound when callers request the
`NO_CONFIDENTIALITY` or `NO_REPLAY_PROTECTION` hints. The current
`psa_ps_get_info` behavior echoes those requested flags instead of reporting
the stronger protection actually applied.

## Firmware Update

```c
psa_status_t psa_fwu_query(psa_fwu_component_t component,
                           psa_fwu_component_info_t* info);

psa_status_t psa_fwu_start(psa_fwu_component_t component,
                           const void* manifest, size_t manifest_size);

psa_status_t psa_fwu_write(psa_fwu_component_t component,
                           size_t image_offset,
                           const void* block, size_t block_size);

psa_status_t psa_fwu_finish(psa_fwu_component_t component);
psa_status_t psa_fwu_cancel(psa_fwu_component_t component);
psa_status_t psa_fwu_clean(psa_fwu_component_t component);
psa_status_t psa_fwu_install(void);
psa_status_t psa_fwu_request_reboot(void);
psa_status_t psa_fwu_reject(psa_status_t error);
psa_status_t psa_fwu_accept(void);
```

`psa_fwu_start` accepts either `NULL, 0`, which binds the
version from the staged wolfBoot header at finish, or a four-byte detached
monotonic version. The current service supports one primary component and
commits installation at authenticated reboot. It does not offer a persistent
trial state, so `psa_fwu_accept` returns
`PSA_ERROR_NOT_SUPPORTED`.
The service pads an unaligned block size to the backend write alignment. It
returns `PSA_ERROR_INVALID_ARGUMENT` for unknown component IDs instead of
`PSA_ERROR_DOES_NOT_EXIST`.

## Initial Attestation

```c
psa_status_t psa_initial_attest_get_token(
    const uint8_t* auth_challenge, size_t challenge_size,
    uint8_t* token_buf, size_t token_buf_size,
    size_t* token_size);

psa_status_t psa_initial_attest_get_token_size(
    size_t challenge_size, size_t* token_size);
```

Accepted challenge sizes are 32, 48, and 64 bytes. The token is a tagged
COSE_Sign1 object using ES256. The implementation limit is 640 bytes, although
the vendored public header does not currently define
`PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE`. The size query returns the exact encoded
size without producing a signature. A non-NULL token buffer with zero capacity
returns `PSA_ERROR_INVALID_ARGUMENT`; other undersized buffers return
`PSA_ERROR_BUFFER_TOO_SMALL`.

The token advertises `tag:psacertified.org,2023:psa#tfm` but has the
token-profile deviations listed in [TF-M Compatibility](TF-M-Compatibility.md) and must not be
represented as conformant with that profile. The only working Non-secure
attestation adapter currently resides at
`tests/firmware/zephyr-stm32h5/module/wolftrust-tee/src/wolftrust_attestation_client.c`.
The vendored `lib/wolfPSA/src/psa_attestation.c` is a stub that returns
`PSA_ERROR_NOT_SUPPORTED`; do not link it instead of or alongside the Zephyr
adapter because both define the same public PSA symbols.

## Lifecycle

```c
uint32_t psa_rot_lifecycle_state(void);
```

This function is linked into the Secure image for scheduled Secure Partitions
and returns the authenticated lifecycle value supplied by the boot handoff.
There is no Non-secure client adapter or CMSE veneer for it.
Defined PSA state values include:

| Define | Value |
| --- | ---: |
| `PSA_LIFECYCLE_UNKNOWN` | `0x0000` |
| `PSA_LIFECYCLE_ASSEMBLY_AND_TEST` | `0x1000` |
| `PSA_LIFECYCLE_PSA_ROT_PROVISIONING` | `0x2000` |
| `PSA_LIFECYCLE_SECURED` | `0x3000` |
| `PSA_LIFECYCLE_NON_PSA_ROT_DEBUG` | `0x4000` |
| `PSA_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG` | `0x5000` |
| `PSA_LIFECYCLE_DECOMMISSIONED` | `0x6000` |

## FF-M Gateway Veneers

Applications should normally call the PSA client API. The generated CMSE
import library binds those calls to these five target entry points:

```c
uint32_t WolfTrust_FFM_FrameworkVersion(void);
uint32_t WolfTrust_FFM_ServiceVersion(uint32_t sid);
int32_t WolfTrust_FFM_Connect(uint32_t sid, uint32_t version);
int32_t WolfTrust_FFM_Call(int32_t handle, int32_t type,
                          wt_ffm_veneer_iovec_t* ns_iovec);
void WolfTrust_FFM_Close(int32_t handle);
```

The definitions are in `src/arch/armv8m/ffm_nsc.c`. The shared
vector layout is in `include/wolftrust/ffm_veneer.h`, and
`build/secure_cmse_implib.o` is the Non-secure link import.

## Error Codes

### Common PSA status values

| Define | Value | Meaning |
| --- | ---: | --- |
| `PSA_SUCCESS` | 0 | Operation completed |
| `PSA_ERROR_PROGRAMMER_ERROR` | -129 | Invalid client use requiring programmer correction |
| `PSA_ERROR_CONNECTION_REFUSED` | -130 | Service refused the connection |
| `PSA_ERROR_CONNECTION_BUSY` | -131 | Service cannot accept another connection |
| `PSA_ERROR_GENERIC_ERROR` | -132 | Unclassified failure |
| `PSA_ERROR_NOT_PERMITTED` | -133 | Policy denied the operation |
| `PSA_ERROR_NOT_SUPPORTED` | -134 | Interface or option is not implemented |
| `PSA_ERROR_INVALID_ARGUMENT` | -135 | Argument value is invalid |
| `PSA_ERROR_INVALID_HANDLE` | -136 | Handle is invalid for this call |
| `PSA_ERROR_BAD_STATE` | -137 | Operation is invalid in the current state |
| `PSA_ERROR_BUFFER_TOO_SMALL` | -138 | Output capacity is insufficient |
| `PSA_ERROR_ALREADY_EXISTS` | -139 | Object already exists |
| `PSA_ERROR_DOES_NOT_EXIST` | -140 | Object does not exist |
| `PSA_ERROR_INSUFFICIENT_MEMORY` | -141 | Volatile memory is insufficient |
| `PSA_ERROR_INSUFFICIENT_STORAGE` | -142 | Persistent storage is insufficient |
| `PSA_ERROR_INSUFFICIENT_DATA` | -143 | Input data is incomplete |
| `PSA_ERROR_SERVICE_FAILURE` | -144 | Service failed |
| `PSA_ERROR_COMMUNICATION_FAILURE` | -145 | Service communication failed |
| `PSA_ERROR_STORAGE_FAILURE` | -146 | Persistent storage operation failed |
| `PSA_ERROR_HARDWARE_FAILURE` | -147 | Hardware operation failed |
| `PSA_ERROR_INVALID_SIGNATURE` | -149 | Signature or authentication tag is invalid |
| `PSA_ERROR_CORRUPTION_DETECTED` | -151 | Corruption was detected |
| `PSA_ERROR_DATA_CORRUPT` | -152 | Stored data is corrupt |
| `PSA_ERROR_DATA_INVALID` | -153 | Supplied data is invalid |
| `PSA_OPERATION_INCOMPLETE` | -248 | Interruptible operation has more work |

### Firmware Update status values

| Define | Value | Meaning |
| --- | ---: | --- |
| `PSA_SUCCESS_REBOOT` | 1 | Completion requires reboot |
| `PSA_SUCCESS_RESTART` | 2 | Completion requires service restart |
| `PSA_ERROR_DEPENDENCY_NEEDED` | -156 | Another component is required |
| `PSA_ERROR_FLASH_ABUSE` | -160 | Flash use violates update policy |
| `PSA_ERROR_INSUFFICIENT_POWER` | -161 | Power is insufficient for the operation |

For service availability and deviations, see [Services](Services.md) and
[TF-M Compatibility](TF-M-Compatibility.md).
