# TF-M Compatibility

wolfTrust implements the PSA interfaces needed by its reference applications
without linking the Trusted Firmware-M runtime. Compatibility is at the C API
and service-behavior level; image layout, manifests, build integration, and
the SPM implementation are wolfTrust-specific.

This register describes the code in the repository. It is not a certification
statement, and a declaration in a vendored header does not mean every optional
algorithm or feature is enabled in every build.

## Measured Secure-image footprint

The following table records local builds, not published reference figures.
The wolfTrust rows use the STM32H563 reference manifest with
`isolation_profile` set to 3 and include Internal Trusted Storage, Protected
Storage, Firmware Update, vault services, and COSE attestation. The TF-M rows
are the standard Small, Medium, and Large profiles built for AN521.

| Secure image | Profile and enabled services | Flash | Static RAM |
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

### Methodology

All five images were built on `wolf-prec5560` with
`arm-none-eabi-gcc (15:13.2.rel1-2) 13.2.1 20231009`. Footprint was read from
the linked Secure ELF with `arm-none-eabi-size` and calculated as:

```text
Flash      = text + data
Static RAM = data + bss
```

The wolfTrust rows were reproduced on 2026-09-18 from the source tree
containing this page with the exact dependency set below.

| Component | Pinned revision | Git description |
| --- | --- | --- |
| wolfCOSE | `f907071b10127f3ae2dd7719749a91b039ff04a1` | `v2.0.0` |
| wolfHSM | `a0323156606282448f00473a3fcb7aaa69361921` | `wolfHSM-v1.4.0-171-ga032315` |
| wolfIP | `146de4b6362c3a076787e27332f50daa0a445cf5` | `v1.0-91-g146de4b` |
| wolfPSA | `1b9ec29706bc63f785682ad688350195a33b22e8` | `v5.9.1-129-g1b9ec29` |
| wolfSSL | `22e505bcfad8ce21067ee4232128728543767a95` | `v5.9.1-stable-1088-g22e505bcf` |
| wolfHAL | `2bc2938b0bbcc977177153a7f38393710702bf70` | No reachable tag |

The wolfTrust images used `-Os` and the following commands; all other build
variables retained their repository defaults:

```sh
git submodule update --init --recursive
make BUILD_DIR=build_size_native WT_ENGINE=native secure-image
make BUILD_DIR=build_size_hsm WT_ENGINE=hsm secure-image
arm-none-eabi-size build_size_native/wolftrust.elf \
    build_size_hsm/wolftrust.elf
```

The measured wolfTrust files were the two `wolftrust.elf` outputs. Their raw
`text`, `data`, and `bss` values are recorded in
[Crypto Engines](Crypto-Engines.md).

The TF-M source was the `TF-Mv2.1.1-LTS` tag at commit
`02bf279913439a07082dd581df033f370a8fbb92`. The following commands reproduce
the AN521 GNU Arm builds with BL2 enabled and no regression tests:

```sh
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
profiles do not enable the same services. Treat the table as a reproducible
local build comparison, not a platform-normalized benchmark. See
[Crypto Engines](Crypto-Engines.md) for the measured cost within wolfTrust,
where the platform and feature set are held constant.

## Compatibility register

| API or behavior | Version | Status | Repository evidence |
| --- | --- | --- | --- |
| FF-M client API | 1.0 with the scoped deviations below | Connection-based IPC is implemented | `include/psa/client.h` and `src/client/psa_ffm_client.c` |
| Secure Partition IPC API | FF-M 1.0 plus a wolfTrust-specific backport of `psa_irq_enable()` from Arm's FF-M 1.1 Extension Beta, Issue 0 | Supported for scheduled IPC partitions; wolfTrust still reports framework version `0x0100` and does not accept 1.1 manifests | `include/psa/service.h`, `include/psa/client.h`, and `src/arch/common/spm_sp_api.c` |
| Framework and service discovery | 1.0 | Supported | `psa_framework_version` and `psa_version` |
| Copied input and output vectors | FF-M 1.0 | Supported, with at most four vectors total and a 1024-byte aggregate budget across input bytes and declared output capacity | `include/wolftrust/ffm.h` and `src/ffm.c` |
| Manifest validation | wolfTrust format 1 | Supported for immutable generated C data | `tools/manifest/generate.py`, `src/manifest.c`, and `port/stm32h563/manifest.json` |
| PSA Crypto | 1.4 header | Supported through wolfPSA; algorithms depend on the guest profile | `lib/wolfPSA/wolfpsa/psa/crypto.h` and both reference guest settings |
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
| Only connection-based IPC services are enabled. | Scoped | The production manifest requests only `WT_MANIFEST_FEATURE_IPC`. SFN, stateless services, and memory-mapped I/O vectors are rejected by the runtime. |
| IPC uses fixed copied buffers. | Scoped safety bound | Calls are limited to four vectors and a 1024-byte transfer budget. Services apply smaller bounds. Applications must chunk larger data. |
| A Non-secure connect, call, or close cannot remain pending after the scheduler reaches quiescence for that dispatch. | Scoped deviation | An incomplete message becomes a client error. If already claimed, the service retains its message until reply or partition fault; late output is discarded. A late call reply releases the message, but the connection remains in error until the client requests close. If close was already requested, the late reply allows deferred disconnection to proceed. Shipped Non-secure-facing services reply within the dispatch; Secure Partition callers use the begin/finish path when scheduling another partition is required. |
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
`WT_ISOLATION_PROFILE_LEVEL_3` and declares the capabilities checked
by the manifest validator. The manifest declares its Non-secure guests
unprivileged, but the current runtime initializes `CONTROL_NS.nPRIV` to zero and
launches them privileged. TrustZone protects Secure state, GTZC isolates peer
guest RAM, and unprivileged Secure threads use per-partition Secure MPU regions.
The guest Non-secure MPU and interrupt masks are scheduling policy because a
privileged guest can reprogram them.

The current single-image layout still shares Secure executable text, and crypto,
vault, and attestation share a keystore data band. Treat the profile field as a
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
