# PSA Compatibility

wolfTrust exposes selected [PSA APIs](https://arm-software.github.io/psa-api/)
through its STM32H563 reference applications and Secure services. This page
records the implemented Crypto, Secure Storage, Initial Attestation, and
Firmware Update surface against the cited Arm specifications. Algorithms and
features depend on the selected build. The known deviations below prevent a
claim of full PSA API conformance or certification.

The Secure Partition Manager and IPC contract are documented separately in
[FF-M Compatibility](FF-M-Compatibility.md).

## PSA specification sections

| Contract | Normative section | wolfTrust scope |
| --- | --- | --- |
| PSA Crypto | [Crypto API 1.4, section 6.1.1](https://arm-software.github.io/psa-api/crypto/1.4/overview/implementation.html) | wolfPSA API; enabled algorithms depend on the selected guest and crypto-engine configuration |
| Internal Trusted Storage and Protected Storage | [Secure Storage API 1.0, sections 5.3 to 5.4](https://arm-software.github.io/psa-api/storage/1.0/api/api.html) | Core operations; storage deviations are listed below |
| Initial Attestation | [Attestation API 1.0, section 3](https://arm-software.github.io/psa-api/attestation/1.0/overview/report.html) and [section 4](https://arm-software.github.io/psa-api/attestation/1.0/api/api.html) | Token generation and token-size query operations with documented header, status, and token-profile deviations |
| Firmware Update | [Firmware Update API 1.0, section 4](https://arm-software.github.io/psa-api/fwu/1.0/overview/programming-model.html) and [section 5](https://arm-software.github.io/psa-api/fwu/1.0/api/api.html) | Single-component staging and authenticated reboot with documented limits |

## Implemented service APIs

| API or behavior | Version | Status | Repository evidence |
| --- | --- | --- | --- |
| PSA Crypto | 1.4 header | Supported through wolfPSA; algorithms depend on the guest profile | `lib/wolfPSA/wolfpsa/psa/crypto.h` and both reference guest settings |
| Internal Trusted Storage | 1.0 | Core set/get/get-info/remove subset; ordinary objects can be updated, while caller-selected `WRITE_ONCE` is enforced without a provisioning exception | `include/psa/internal_trusted_storage.h` and `src/services/storage_service.c` |
| Protected Storage | 1.0 | Core set/get/get-info/remove subset; optional create/set-extended absent | `include/psa/protected_storage.h` and `src/services/storage_service.c` |
| Initial Attestation | 1.0 API subset with a nonconformant RFC 9783-derived token | Token generation and token-size query are supported, but the advertised TF-M profile has the claim-semantic deviations below | `lib/wolfPSA/wolfpsa/psa/initial_attestation.h` and `src/services/initial_attestation.c` |
| Firmware Update | 1.0 subset | Single-component staging and authenticated reboot supported, with the status deviation below | `include/psa/update.h` and `src/services/fwu_service.c` |

## Service API differences

| Difference | Classification | Reason and impact |
| --- | --- | --- |
| PSA Crypto mechanisms are build-selected. | Implementation-profile behavior | The [PSA Crypto implementation profile](https://arm-software.github.io/psa-api/crypto/1.4/overview/implementation.html) may select an API and algorithm subset. The wolfPSA 1.4 header is present, while each guest's wolfCrypt settings determine available keys and algorithms. |
| Protected Storage does not implement create or set-extended. | Scoped | `psa_ps_get_support()` returns zero and both optional operations return `PSA_ERROR_NOT_SUPPORTED`. |
| Protected Storage always applies confidentiality and replay protection even when `NO_CONFIDENTIALITY` or `NO_REPLAY_PROTECTION` is requested. | Known metadata deviation | Objects remain sealed and counter-bound, but `psa_ps_get_info()` echoes the requested hint flags instead of reporting the stronger protection actually applied, which differs from the PSA Secure Storage 1.0 requirement. |
| Internal Trusted Storage enforces caller-selected `PSA_STORAGE_FLAG_WRITE_ONCE` during provisioning. | Known lifecycle deviation | Ordinary objects can be updated or removed. The ITS request path does not consult lifecycle state, so an object created with the flag cannot be changed during `PSA_ROT_PROVISIONING`, contrary to [PSA Secure Storage 1.0 section 3.2](https://arm-software.github.io/psa-api/storage/1.0/overview/requirements.html). The section 3.2 lifecycle exception is specific to ITS. |
| Initial Attestation's public header omits `PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE`. | Known header deviation | The service limit is 640 bytes, but callers cannot obtain that maximum from the public PSA header. |
| A non-NULL attestation token buffer with zero capacity returns `PSA_ERROR_INVALID_ARGUMENT`. | Known status deviation | PSA Initial Attestation 1.0 specifies `PSA_ERROR_BUFFER_TOO_SMALL` for an undersized token buffer. Nonzero undersized buffers return `PSA_ERROR_BUFFER_TOO_SMALL`. |
| The attestation token advertises `tag:psacertified.org,2023:psa#tfm` but does not implement that profile's claim semantics. | Known token-profile deviation | The boot seed is deterministic across equivalent boots; software-component measurement type and description values are reversed; signer ID hashes the literal name `wolfBoot` rather than identifying the signing key; and implementation ID hashes a software label rather than identifying the immutable PSA RoT hardware assembly. A distinct derived profile identifier should be used until these claims conform to [RFC 9783 section 5.2](https://www.rfc-editor.org/rfc/rfc9783.html#section-5.2). |
| Firmware Update has no persistent trial-accept flow. | Scoped | Installation commits only after wolfBoot authenticates the swapped image at reboot; `psa_fwu_accept()` returns `PSA_ERROR_NOT_SUPPORTED`. |
| wolfTrust's Firmware Update adapter accepts a detached manifest only as a 32-bit version word. | Scoped integration | Passing `NULL, 0` instead binds the version from the staged wolfBoot header. Other manifest encodings require an adapter. |
| Firmware Update reports unknown component IDs as `PSA_ERROR_INVALID_ARGUMENT`. | Known API deviation | PSA Firmware Update 1.0 specifies `PSA_ERROR_DOES_NOT_EXIST` for unknown component IDs. Unaligned block sizes are padded to the backend write alignment. |

The attestation comparison uses the claim definitions for
[Implementation ID](https://www.rfc-editor.org/rfc/rfc9783.html#section-4.2.2),
[Boot Seed](https://www.rfc-editor.org/rfc/rfc9783.html#section-4.3.2), and
[Software Components](https://www.rfc-editor.org/rfc/rfc9783.html#section-4.4.1)
in RFC 9783. Its [derived-profile rules](https://www.rfc-editor.org/rfc/rfc9783.html#section-4.5.2.1)
describe how to identify a different token profile.

## Validation and claim boundary

`make test` exercises native service behavior and negative inputs. Dedicated
guest scenarios under M33MU exercise selected PSA Crypto, Secure Storage, and
Initial Attestation APIs. The STM32H563 hardware runner checks selected
end-to-end behavior on a provisioned board. See [Testing](Testing.md) for the
commands and the scope of each result. These tests do not eliminate the API
and token-profile deviations listed above.

## Porting an existing PSA application

1. Keep application calls on standard PSA headers where wolfTrust provides the
   corresponding Non-secure adapter: FF-M client, Crypto, ITS, Protected
   Storage, and Firmware Update. `psa_rot_lifecycle_state()` is available only
   to scheduled Secure Partitions; there is no Non-secure client adapter for it.
2. Link `src/client/psa_ffm_client.c` and the generated
   `secure_cmse_implib.o` from the selected Secure-image `BUILD_DIR`, then add
   the adapter required by each API:
   wolfPSA plus `src/client/crypto_native_client.c` for the native Crypto
   configuration, or wolfPSA, the wolfHSM client, and
   `src/client/hsm_psa_transport.c` for the wolfHSM configuration;
   `src/client/psa_storage_client.c` for ITS and Protected Storage,
   `src/client/psa_fwu_client.c` for Firmware Update, and
   `src/client/vnet_psa_transport.c` for optional VNET.
3. Initial Attestation currently has only the Zephyr-specific adapter at
   `tests/firmware/zephyr-stm32h5/module/wolftrust-tee/src/wolftrust_attestation_client.c`.
   The vendored `lib/wolfPSA/src/psa_attestation.c` is a stub that returns
   `PSA_ERROR_NOT_SUPPORTED` and must not be linked instead of or alongside that
   adapter.
4. Include the `psa_manifest/sid.h` generated for the selected target
   and manifest.
5. Check data-size assumptions against the copied IPC and service limits.
   Stream update images in blocks no larger than `PSA_FWU_MAX_WRITE_SIZE`.
   For wolfTrust, the image offset must be aligned to
   `1 << PSA_FWU_LOG2_WRITE_ALIGN`. An unaligned final block is padded by the
   service to the backend write alignment.
6. Check optional APIs before use. In particular, treat Protected Storage
   create/set-extended and Firmware Update accept as unsupported.
7. Express Secure services, dependencies, memory, interrupts, restart policy,
   guest launch requirements, and minimum versions in the wolfTrust manifest.
8. Use the wolfBoot and wolfTrust image assembly flow. Patch guest measurement
   records before signing wolfTrust.
9. Run host tests, target conformance under M33MU, and the hardware suite
   separately. An emulator pass does not establish silicon attribution.

See [API Reference](API-Reference.md), [FF-M Compatibility](FF-M-Compatibility.md),
[Porting](Porting.md), and [Testing](Testing.md) for integration details.
