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
| wolfTrust Secure runtime, native default | 70,432 bytes | 45,280 bytes |
| TF-M v2.3.1 `tfm_s`, level 3 | 79,680 bytes | 45,728 bytes |
| wolfBoot, STM32L5 secure application handoff | 27,216 bytes | 2,104 bytes |
| TF-M BL2 (MCUboot, EC-P256) | 38,744 bytes | 27,408 bytes |
| Chain: wolfBoot + wolfTrust | 97,648 bytes | |
| Chain: BL2 + TF-M | 118,424 bytes | |

The wolfTrust runtime is 9,248 bytes smaller in flash and 448 bytes smaller
in Secure RAM; the boot chain is 20,776 bytes smaller in flash. Both RAM
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
That default is larger than TF-M. On the STM32H563 the `standard` profile, the
closest to TF-M's Medium set, is
103,223 bytes of flash and 48,880 bytes of Secure RAM: 23,543 bytes more flash
and 3,152 bytes more RAM than the TF-M image above. 12,007 bytes of the flash
gap are the crypto stack (52,485 against 40,478 for TF-M's Crypto partition
and Mbed TLS); the rest is the storage and SPM code outside it. The
`WT_SECURE_PSA=0` opt-out, which runs wolfPSA in the Non-secure guest instead,
stays below TF-M, and CI holds it to TF-M's flash and RAM.

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

- wolfTrust: the STM32L562 port built with its defaults (native engine,
  LTO, one guest): `make TARGET=stm32l562 secure-image` in
  `ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.25`. With `WT_SECURE_PSA=0`, the same
  defaults give 70,940 bytes of flash and 45,296 bytes of Secure RAM for
  `TARGET=stm32h563` in this tree; the `WT_SECURE_PSA=1` default gives 110,005
  and 48,880.
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
| Copied input and output vectors | FF-M 1.0 | Supported, with at most four vectors total and a 1024-byte aggregate budget across input bytes and declared output capacity | `include/wolftrust/ffm.h` and `src/ffm.c` |
| Manifest validation | wolfTrust format 1 | Supported for immutable generated C data | `tools/manifest/generate.py`, `src/manifest.c`, and `manifest/base.json` |
| PSA Crypto | 1.4 header | Supported through wolfPSA; algorithms depend on the guest profile, or on `WT_SECURE_PSA_PROFILE` when `WT_SECURE_PSA=1` serves it from the Secure image | `lib/wolfPSA/wolfpsa/psa/crypto.h` and both reference guest settings |
| Internal Trusted Storage | 1.0 | Core set/get/get-info/remove subset with the `WRITE_ONCE` lifecycle deviation below | `include/psa/internal_trusted_storage.h` and `src/services/wolfhsm/wt_hsm_vault.c` |
| Protected Storage | 1.0 | Core set/get/get-info/remove subset; optional create/set-extended absent and the `WRITE_ONCE` lifecycle deviation below applies | `include/psa/protected_storage.h` and `src/services/storage_service.c` |
| Initial Attestation | 1.0 API subset with a nonconformant RFC 9783-derived token | Token and exact-size operations are supported, but the advertised TF-M profile has the claim-semantic deviations below | `lib/wolfPSA/wolfpsa/psa/initial_attestation.h` and `src/services/initial_attestation.c` |
| Firmware Update | 1.0 subset | Single-component staging and authenticated reboot supported | `include/psa/update.h` and `src/services/fwu_service.c` |
| RoT lifecycle query | FF-M 1.0 | Secure Partition only; there is no Non-secure adapter or veneer | `include/psa/lifecycle.h` and `src/arch/common/spm_sp_api.c` |
| Secure Partition signals and IRQ APIs | FF-M 1.0 plus one wolfTrust-specific beta-extension backport | The 1.0 signal APIs and `psa_eoi` are supported; only `psa_irq_enable()` is backported from the FF-M 1.1 Extension Beta, Issue 0, while `psa_irq_status_t`, `psa_irq_is_enabled`, `psa_irq_disable`, and `psa_irq_restore` are absent | `include/psa/service.h` and the Armv8-M SVC implementation |
| Secure Partition hardware IRQ routing | Port-specific | Conformance builds route the port's `WT_CONF_IRQ`. Production manifests must leave partition IRQs empty. | `port/common/armv8m/platform_caps.h` and `tools/manifest/generate.py` |
| Guest identity | Multi-guest extension | Non-secure guest `N` is client `-(N + 1)`. FF-M expects one negative ID for every SPM-assigned Non-secure connection, which would merge the guests' storage and network ownership; a one-guest build uses `-1` only | `src/arch/armv8m/ffm_nsc.c` |

## Intentional differences

| Difference | Classification | Reason and impact |
| --- | --- | --- |
| wolfTrust exposes the FF-M Non-secure client API through one five-function CMSE gateway. | Implementation detail | The gateway exports framework version, service version, connect, call, and close; Secure Partition entry points are a separate manifest concern. |
| Only connection-based IPC services are enabled. | Scoped | The production manifest requests only `WT_MANIFEST_FEATURE_IPC`. SFN, stateless services, and memory-mapped I/O vectors are rejected when the manifest is generated, and the runtime refuses SFN partitions at activation. |
| IPC uses fixed copied buffers. | Scoped safety bound | Calls are limited to four vectors and a 1024-byte transfer budget. Services apply smaller bounds. Applications must chunk larger data. |
| A Non-secure connect, call, or close cannot remain pending after the scheduler reaches quiescence for that dispatch. | Scoped deviation | An incomplete message becomes a client error. If already claimed, the service retains its message until reply or partition fault; late output is discarded. A late call reply releases the message, but the connection remains in error until the client requests close. If close was already requested, the late reply allows deferred disconnection to proceed. Shipped Non-secure-facing services reply within the dispatch; Secure Partition callers use the begin/finish path when scheduling another partition is required. |
| Secure services are linked in one image. | Scoped isolation difference | Service writable state is isolated by unprivileged threads and Secure MPU domains, but executable text is shared rather than separately linked. |
| All shipped service loops run as scheduled coroutines. | Implementation difference | Service code uses the standard Secure Partition API; privileged hardware access goes through identity-pinned SVC gates. |
| Abnormal Non-secure guest termination reclaims the guest's connections without delivering `PSA_IPC_DISCONNECT` to the affected services. | Scoped deviation | Fault-handler cleanup cannot dispatch a Secure service inline without re-entering the scheduler. Shipped services do not use `psa_set_rhandle()` for per-connection cleanup, but a ported service that depends on disconnect cleanup must account for this behavior. |
| PSA Crypto mechanisms are build-selected. | Standard profile behavior | The wolfPSA 1.4 header is present, while each guest's wolfCrypt settings determine available keys and algorithms. |
| Protected Storage does not implement create or set-extended. | Scoped | `psa_ps_get_support()` returns zero and both optional operations return `PSA_ERROR_NOT_SUPPORTED`. |
| ITS and Protected Storage always enforce `PSA_STORAGE_FLAG_WRITE_ONCE`. | Known lifecycle deviation | The request path does not receive lifecycle state and always rejects modification or removal. PSA Secure Storage 1.0 requires the flag not to be enforced during `PSA_ROT_PROVISIONING`. |
| Initial Attestation's public header omits `PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE`. | Known header deviation | The service limit is 640 bytes, but callers cannot obtain that maximum from the public PSA header. |
| The attestation token uses the `tag:psacertified.org,2023:psa#tfm` identifier. | Known token-profile deviation | The signer ID and implementation ID are software-label hashes. These claims are known deviations from the profile's signer and hardware identity requirements. A distinct derived profile identifier is required until these claims conform. [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html) |
| Firmware Update has no persistent trial-accept flow. | Scoped | Installation commits only after wolfBoot authenticates the swapped image at reboot; `psa_fwu_accept()` returns `PSA_ERROR_NOT_SUPPORTED`. |
| The firmware-update detached manifest is a 32-bit version word. | Scoped integration | Passing `NULL, 0` instead binds the version from the staged wolfBoot header. Other manifest encodings require an adapter. |
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
