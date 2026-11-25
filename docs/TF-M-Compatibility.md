# TF-M Compatibility

wolfTrust implements the PSA interfaces needed by its reference applications
without linking the Trusted Firmware-M runtime. Compatibility is at the C API
and service-behavior level; image layout, manifests, build integration, and
the SPM implementation are wolfTrust-specific.

This register describes the code in the repository. It is not a certification
statement, and a declaration in a vendored header does not mean every optional
algorithm or feature is enabled in every build.

## Measured Secure-image footprint

Both projects were built for the same board (STM32L562E-DK) at isolation
level 3 with the same compiler (Arm GNU 15.2.1), each with its own size
options. These are local builds, not published reference figures.

| Image | Flash | Secure RAM |
| --- | ---: | ---: |
| wolfTrust Secure runtime, native default | 61,436 bytes | 38,668 bytes |
| TF-M v2.3.1 `tfm_s`, level 3 | 79,680 bytes | 45,728 bytes |
| wolfBoot, STM32L5 secure application handoff | 27,216 bytes | 2,104 bytes |
| TF-M BL2 (MCUboot, EC-P256) | 38,744 bytes | 27,408 bytes |
| Chain: wolfBoot + wolfTrust | 88,652 bytes | |
| Chain: BL2 + TF-M | 118,424 bytes | |

The wolfTrust runtime is 18,244 bytes smaller in flash and 7,060 bytes smaller
in Secure RAM; the boot chain is 29,772 bytes smaller in flash. Both RAM
figures include every partition stack (see Methodology). The bootloader's RAM
is reused by the runtime, so the RAM figures are not summed. The
cross-compile workflow fails if any port's lean native default image grows
past TF-M's 79,680 bytes of flash or 45,728 bytes of Secure RAM, plus the RAM
code band (`WT_RAMFUNC_SIZE`) of a port that runs code from RAM.

Both images carry Crypto, Internal Trusted Storage, Protected Storage and
Initial Attestation with one Non-secure image; TF-M also builds its platform
service, and neither builds Firmware Update. They differ in how level 3 is applied: TF-M's
STM32L5 port runs the PSA RoT partitions (Crypto, ITS, attestation,
platform) privileged (`tfm_hal_isolation.c`), while wolfTrust runs every
Secure Partition unprivileged with its own MPU regions. Each wolfTrust
feature the default leaves out comes back with one Make variable; see
[Build profiles](Macros.md#build-profiles) for each one's cost.

The crypto split matches TF-M's: both serve PSA Crypto from a Secure crypto
partition, which wolfTrust's native default does with `WT_SECURE_PSA=1` (see
[Crypto Engines](Crypto-Engines.md#psa-crypto-in-the-secure-image-wt_secure_psa1)).
That default has more flash than TF-M. On the STM32H563 the `standard`
profile, the closest to TF-M's Medium set, is 94,583 bytes of flash and 42,268
bytes of Secure RAM: 14,903 bytes more flash and 3,460 bytes less RAM than the
TF-M image above. The flash gap is the crypto stack and the non-crypto code
the split below breaks down. The
`WT_SECURE_PSA=0` opt-out, which runs wolfPSA in the Non-secure guest instead,
stays below the TF-M image in both flash and RAM.

### Non-crypto split

`tools/footprint/classify.py` splits a non-LTO map by category with one rules
file per project (`tools/footprint/wolftrust.rules` and `tfm.rules`). Every
flash byte lands in a category, `fill` or `linker`, so the categories sum to
`text + data`, and an object no rule matches fails the run. Crypto is the
crypto library, the crypto partition and its client, key loaders and entropy
glue on both sides; attestation includes its CBOR and COSE libraries; storage
includes the flash drivers and NV counters; guest is the Non-secure guest
management (TF-M's NS agent).

| Category | wolfTrust STM32L562 | wolfTrust STM32H563 | TF-M STM32L562 |
| --- | ---: | ---: | ---: |
| SPM | 10,949 | 10,957 | 7,548 |
| Storage | 17,224 | 17,210 | 13,156 |
| Attestation | 6,308 | 6,308 | 5,585 |
| Guest management | 4,808 | 4,800 | 176 |
| Platform | 3,490 | 4,041 | 9,104 |
| Runtime, fill, linker | 503 | 539 | 1,689 |
| **Non-crypto total** | **43,282** | **43,855** | **37,258** |
| Crypto | 20,954 | 60,469 | 42,422 |

Measured 2026-11-25 with `WT_ENGINE=native WT_ATTEST_COSE=1 WT_LTO=0`. The
STM32L562 default runs PSA Crypto in the guest, so its crypto row holds only
what the Secure services use; the STM32H563 serves PSA Crypto from the Secure
image, as TF-M does.

```sh
make TARGET=stm32h563 WT_ENGINE=native WT_ATTEST_COSE=1 WT_LTO=0 secure-image
python3 tools/footprint/classify.py build/wolftrust.map \
  --rules tools/footprint/wolftrust.rules --elf build/wolftrust.elf --objects
python3 tools/footprint/classify.py tfm_s.map --rules tools/footprint/tfm.rules \
  --elf tfm_s.elf
```

The cross-compile workflow holds each port's non-crypto and SPM flash under
the ceilings in its `port.json` (`build.noncrypto_max`, `build.spm_max`),
lowered as size work lands.

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

- wolfTrust: the STM32L562 port built with its defaults (native engine, LTO,
  one guest, PSA Crypto in the guest): `make TARGET=stm32l562 secure-image` in
  `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25`. The same defaults give 101,361
  bytes of flash and 42,268 bytes of Secure RAM for `TARGET=stm32h563`, which
  serves PSA Crypto from the Secure image, or 61,916 and 38,684 with
  `WT_SECURE_PSA=0`.
- wolfBoot: `config/examples/stm32l5-tz-wolftrust.config` (ECC256, SHA256,
  `WOLFBOOT_SECURE_APP=1`).
- TF-M: v2.3.1, platform `stm/stm32l562e_dk`, `TFM_ISOLATION_LEVEL=3`,
  `CMAKE_BUILD_TYPE=MinSizeRel`, the TF-PSA-Crypto Medium profile
  (`crypto_config_profile_medium.h`) with asymmetric encryption off,
  `TFM_PARTITION_FIRMWARE_UPDATE=OFF`, SPM and partition logging off,
  `CRYPTO_HW_ACCELERATOR=OFF`, BL2 with EC-P256 signatures.

## Compatibility register

| API or behavior | Version | Status | Repository evidence |
| --- | --- | --- | --- |
| FF-M client API | 1.0 with the scoped deviations below | Connection-based IPC is implemented | `include/psa/client.h` and `src/client/psa_ffm_client.c` |
| Secure Partition IPC API | FF-M 1.0 plus a wolfTrust-specific backport of `psa_irq_enable()` from Arm's FF-M 1.1 Extension Beta, Issue 0 | Supported for scheduled IPC partitions; wolfTrust still reports framework version `0x0100` and does not accept 1.1 manifests | `include/psa/service.h`, `include/psa/client.h`, and `src/arch/common/spm_sp_api.c` |
| Framework and service discovery | 1.0 | Supported | `psa_framework_version` and `psa_version` |
| Copied input and output vectors | FF-M 1.0 | Supported, with at most four vectors total and a 1024-byte aggregate budget across input bytes and declared output capacity | `include/wolftrust/spm_core.h` and `src/spm/core.c` |
| Manifest validation | wolfTrust format 1 | Supported for immutable generated C data | `tools/manifest/generate.py`, `src/manifest.c`, and `manifest/base.json` |
| PSA Crypto | 1.4 header | Supported through wolfPSA; algorithms depend on the guest profile, or on `WT_SECURE_PSA_PROFILE` when `WT_SECURE_PSA=1` serves it from the Secure image | `lib/wolfPSA/wolfpsa/psa/crypto.h` and both reference guest settings |
| Internal Trusted Storage | 1.0 | Core set/get/get-info/remove subset with the `WRITE_ONCE` lifecycle deviation below | `include/psa/internal_trusted_storage.h` and `src/services/wolfhsm/wt_hsm_vault.c` |
| Protected Storage | 1.0 | Core set/get/get-info/remove subset; optional create/set-extended absent and the `WRITE_ONCE` lifecycle deviation below applies | `include/psa/protected_storage.h` and `src/services/storage_service.c` |
| Initial Attestation | 1.0 API subset with a nonconformant RFC 9783-derived token | Token and exact-size operations are supported, but the advertised TF-M profile has the claim-semantic deviations below | `lib/wolfPSA/wolfpsa/psa/initial_attestation.h` and `src/services/initial_attestation.c` |
| Firmware Update | 1.0 subset | Single-component staging and authenticated reboot supported, with the status deviation below | `include/psa/update.h` and `src/services/fwu_service.c` |
| RoT lifecycle query | FF-M 1.0 | Secure Partition only; there is no Non-secure adapter or veneer | `include/psa/lifecycle.h` and `src/arch/common/spm_sp_api.c` |
| Secure Partition signals and IRQ APIs | FF-M 1.0 plus one wolfTrust-specific beta-extension backport | The 1.0 signal APIs and `psa_eoi` are supported; only `psa_irq_enable()` is backported from the FF-M 1.1 Extension Beta, Issue 0, while `psa_irq_status_t`, `psa_irq_is_enabled`, `psa_irq_disable`, and `psa_irq_restore` are absent | `include/psa/service.h` and the Armv8-M SVC implementation |
| Guest identity | FF-M convention | Non-secure guest `N` is client `-(N + 1)` | `src/arch/armv8m/ffm_nsc.c` |

## Intentional differences

| Difference | Classification | Reason and impact |
| --- | --- | --- |
| wolfTrust exposes the FF-M Non-secure client API through one five-function CMSE gateway. | Implementation detail | The gateway exports framework version, service version, connect, call, and close; Secure Partition entry points are a separate manifest concern. |
| Only connection-based IPC services are enabled. | Scoped | The production manifest requests only `WT_MANIFEST_FEATURE_IPC`. SFN, stateless services, and memory-mapped I/O vectors are rejected when the manifest is generated, and the runtime refuses SFN partitions at activation. |
| IPC uses fixed copied buffers. | Scoped safety bound | Calls are limited to four vectors and a 1024-byte transfer budget. Services apply smaller bounds. Applications must chunk larger data. |
| A Non-secure connect, call, or close cannot remain pending after the scheduler reaches quiescence for that dispatch. | Scoped deviation | An incomplete message becomes a client error. If already claimed, the service retains its message until reply or partition fault; late output is discarded. A late call reply releases the message, but the connection remains in error until the client requests close. If close was already requested, the late reply allows deferred disconnection to proceed. Shipped Non-secure-facing services reply within the dispatch; Secure Partition callers use the begin/finish path when scheduling another partition is required. |
| Connect and close never take a transfer buffer. | Stronger resource policy | Only a call holds one of the fixed transfers, so pool exhaustion can refuse a call but never a connect or a close. |
| A call vector the caller cannot access is refused before a transfer is taken. | Implementation detail | The call returns `PSA_ERROR_PROGRAMMER_ERROR` and the connection enters its error state, even when every transfer is busy. |
| A `PSA_ERROR_PROGRAMMER_ERROR` reply publishes no output, and a faulted server's staged output is discarded. | Stronger isolation policy | The caller receives the status with every output length zero, so a failing or restarted service cannot leak a partly written reply. |
| A departed client's handles stop resolving as soon as the client is reclaimed. | Implementation detail | A service still holding that client's message finishes it; the reply is discarded and the connection is released afterwards. |
| Connection and message handles carry a 24-bit generation per slot. | Implementation detail | A stale handle is refused until the same slot has been reused 16,777,216 times; a Secure caller that presents a refused handle is panicked as a programmer error. |
| Secure services are linked in one image. | Scoped isolation difference | Service writable state is isolated by unprivileged threads and Secure MPU domains, but executable text is shared rather than separately linked. |
| All shipped service loops run as scheduled coroutines. | Implementation difference | Service code uses the standard Secure Partition API; privileged hardware access goes through identity-pinned SVC gates. |
| Abnormal Non-secure guest termination reclaims the guest's connections without delivering `PSA_IPC_DISCONNECT` to the affected services. | Scoped deviation | Fault-handler cleanup cannot dispatch a Secure service inline without re-entering the scheduler. Shipped services do not use `psa_set_rhandle()` for per-connection cleanup, but a ported service that depends on disconnect cleanup must account for this behavior. |
| PSA Crypto mechanisms are build-selected. | Standard profile behavior | The wolfPSA 1.4 header is present, while each guest's wolfCrypt settings determine available keys and algorithms. |
| Protected Storage does not implement create or set-extended. | Scoped | `psa_ps_get_support()` returns zero and both optional operations return `PSA_ERROR_NOT_SUPPORTED`. |
| Protected Storage always applies confidentiality and replay protection even when `NO_CONFIDENTIALITY` or `NO_REPLAY_PROTECTION` is requested. | Known metadata deviation | Objects remain sealed and counter-bound, but `psa_ps_get_info()` echoes the requested hint flags instead of reporting the stronger protection actually applied, which differs from the PSA Secure Storage 1.0 requirement. |
| ITS and Protected Storage always enforce `PSA_STORAGE_FLAG_WRITE_ONCE`. | Known lifecycle deviation | The request path does not receive lifecycle state and always rejects modification or removal. PSA Secure Storage 1.0 requires the flag not to be enforced during `PSA_ROT_PROVISIONING`. |
| Initial Attestation's public header omits `PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE`. | Known header deviation | The service limit is 640 bytes, but callers cannot obtain that maximum from the public PSA header. |
| A non-NULL attestation token buffer with zero capacity returns `PSA_ERROR_INVALID_ARGUMENT`. | Known status deviation | PSA Initial Attestation 1.0 specifies `PSA_ERROR_BUFFER_TOO_SMALL` for an undersized token buffer. Nonzero undersized buffers return `PSA_ERROR_BUFFER_TOO_SMALL`. |
| The attestation token advertises `tag:psacertified.org,2023:psa#tfm` but does not implement that profile's claim semantics. | Known token-profile deviation | The boot seed is deterministic across equivalent boots; software-component measurement type and description values are reversed; signer ID hashes the literal name `wolfBoot` rather than identifying the signing key; and implementation ID hashes a software label rather than identifying the immutable PSA RoT hardware assembly. A distinct derived profile identifier is required until these claims conform to [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html). |
| Firmware Update has no persistent trial-accept flow. | Scoped | Installation commits only after wolfBoot authenticates the swapped image at reboot; `psa_fwu_accept()` returns `PSA_ERROR_NOT_SUPPORTED`. |
| The firmware-update detached manifest is a 32-bit version word. | Scoped integration | Passing `NULL, 0` instead binds the version from the staged wolfBoot header. Other manifest encodings require an adapter. |
| Firmware Update reports unknown component IDs as `PSA_ERROR_INVALID_ARGUMENT`. | Known API deviation | PSA Firmware Update 1.0 specifies `PSA_ERROR_DOES_NOT_EXIST` for unknown component IDs. Unaligned block sizes are padded to the backend write alignment. |
| Secure memory uses no dynamic allocation. | Stronger resource policy | Fixed pools and buffers can reject excess work rather than expanding at runtime. |
| Manifests use wolfTrust JSON and generated C. | Integration difference | Existing TF-M manifests are not consumed directly. Security resources and services must be represented in the wolfTrust schema. |
| Secure Partition entry functions are bound at build time instead of being selected by each manifest's `entry_point` field. | Integration difference | The numeric field validates an executable window, but adding a service also requires a compiled entry wrapper and an explicit start call in `wt_ffm_boot_start_sched()`. |
| Service IDs are generated from the selected manifest. | Integration difference | Applications should include generated `psa_manifest/sid.h` instead of hard-coding target-specific values. |

## Isolation-profile interpretation

The STM32H563 manifest sets `isolation_profile` to
`WT_ISOLATION_PROFILE_LEVEL_3` and declares the capabilities the manifest
generator checks against the port's own. Only level 3 is implemented, so the
generator and the optional boot-time validator refuse levels 1 and 2. The manifest declares its Non-secure guests
privileged, matching the runtime, which initializes `CONTROL_NS.nPRIV` to zero.
It declares every Secure Partition unprivileged, and the generator and the
validator refuse a privileged one. TrustZone protects Secure state, GTZC isolates peer
guest RAM, and unprivileged Secure threads use per-partition Secure MPU regions.
The guest Non-secure MPU and interrupt masks are scheduling policy because a
privileged guest can reprogram them.

The current single-image layout still shares Secure executable text; every
partition's writable state is its own, and the crypto, vault, and attestation
partitions interact only through FF-M IPC. Treat the profile field as a
requested and validated wolfTrust policy level, not by itself as proof of
independent TF-M isolation certification. [Security Model](Security-Model.md) describes the
actual boundary.

## Migrating an application

1. Keep application calls on standard PSA headers where wolfTrust provides the
   corresponding Non-secure adapter: FF-M client, Crypto, ITS, Protected
   Storage, and Firmware Update. The lifecycle function is Secure-Partition-only.
2. Link `src/client/psa_ffm_client.c` and the generated
   `secure_cmse_implib.o` from the selected Secure-image `BUILD_DIR`, then add
   the adapter required by each API:
   wolfPSA plus `src/client/crypto_native_client.c` for the native Crypto
   configuration, or wolfPSA, the wolfHSM client, and
   `src/client/hsm_psa_transport.c` for the hsm configuration;
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
8. Replace TF-M build and image assembly with the wolfBoot and wolfTrust flow.
   Patch guest measurement records before signing wolfTrust.
9. Run host tests, target conformance under M33MU, and the hardware suite
   separately. An emulator pass does not establish silicon attribution.

See [API Reference](API-Reference.md), [Porting](Porting.md), and [Testing](Testing.md) for integration details.
