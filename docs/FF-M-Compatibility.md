# FF-M Compatibility

wolfTrust targets conformance with the [Arm Firmware Framework for M (FF-M)
1.0 specification](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132).
It is an alternative Secure Partition Manager and services runtime for supported
Cortex-M systems, with its own image, manifest, build, and port integration.
The currently supported reference port is STM32H563 Cortex-M33.

This page records the implemented FF-M 1.0 surface and known differences. It is
not a full conformance statement. The [PSA Compatibility](PSA-Compatibility.md)
page covers Crypto, Storage, Attestation, and Firmware Update APIs separately.

## Arm specification sections

| Contract | Normative section | wolfTrust scope |
| --- | --- | --- |
| Isolation and protection domains | [FF-M sections 3.1.1 to 3.1.6](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132#page=21) | STM32H563 TrustZone, Secure MPU, and Global TrustZone Controller (GTZC) enforcement, meeting isolation level 3; see [Security Model](Security-Model.md#ff-m-isolation-level-3) |
| Secure Partition identity, manifest, and execution | [FF-M sections 3.2.1 to 3.2.4](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132#page=26) and [section 4.1](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132#page=49) | Generated wolfTrust manifest policy, scheduled Secure Partition entry, and lifecycle handling |
| IPC, handles, and copied vectors | [FF-M sections 3.3.1 to 3.3.5](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132#page=31) | Connection-based services with fixed buffer and vector limits |
| Client and Secure Partition APIs | [FF-M section 4.4](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132#page=64) and [section 4.5](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132#page=70) | Implemented functions and limitations are listed in the register below |

## Implemented framework interfaces

| API or behavior | Version | Status | Repository evidence |
| --- | --- | --- | --- |
| FF-M client API | 1.0 with the scoped deviations below | Connection-based IPC is implemented | `include/psa/client.h` and `src/client/psa_ffm_client.c` |
| Secure Partition IPC API | FF-M 1.0 plus a wolfTrust-specific backport of `psa_irq_enable()` from [Arm's FF-M 1.1 Extension Beta, Issue 0](https://developer.arm.com/documentation/aes0039/latest) | Supported for scheduled IPC partitions. The public client contract reports at most `0x0100`. The manifest validator accepts 1.1 partition metadata, but the current runtime rejects 1.1 partitions during activation. | `include/psa/service.h`, `include/psa/client.h`, `src/arch/common/spm_sp_api.c`, `src/manifest.c`, and `src/ffm.c` |
| Framework and service discovery | 1.0 | Supported | `psa_framework_version` and `psa_version` |
| Copied input and output vectors | FF-M 1.0 | Supported, with at most four vectors total and a 1024-byte aggregate budget across input bytes and declared output capacity | `include/wolftrust/ffm.h` and `src/ffm.c` |
| Manifest validation | wolfTrust format 1 | Supported for immutable generated C data | `tools/manifest/generate.py`, `src/manifest.c`, and `port/stm32h563/manifest.json` |
| Root of Trust (RoT) lifecycle query | FF-M 1.0 | Secure Partition only; there is no Non-secure adapter or veneer | `include/psa/lifecycle.h` and `src/arch/common/spm_sp_api.c` |
| Secure Partition signals and IRQ APIs | FF-M 1.0 plus one wolfTrust-specific beta-extension backport | The 1.0 signal APIs and `psa_eoi` are supported; only `psa_irq_enable()` is backported from the [FF-M 1.1 Extension Beta, Issue 0](https://developer.arm.com/documentation/aes0039/latest), while `psa_irq_status_t`, `psa_irq_is_enabled`, `psa_irq_disable`, and `psa_irq_restore` are absent | `include/psa/service.h` and the Armv8-M supervisor-call (SVC) implementation |
| Guest identity | FF-M convention | Non-secure guest `N` is client `-(N + 1)` | `src/arch/armv8m/ffm_nsc.c` |

## Framework differences

| Difference | Classification | Reason and impact |
| --- | --- | --- |
| wolfTrust exposes the FF-M Non-secure client API through one five-function Cortex-M Security Extensions (CMSE) gateway. | Implementation detail | The gateway exports framework version, service version, connect, call, and close; Secure Partition entry points are a separate manifest concern. |
| Only connection-based IPC services are enabled in the reference build. | Scoped | The STM32H563 manifest requests only `WT_MANIFEST_FEATURE_IPC`. It does not enable stateless-function (SFN) partitions, stateless services, or memory-mapped I/O vectors. The common manifest validator recognizes their 1.1 feature bits, but the runtime activates only IPC partitions with a framework version no newer than `0x0100`. |
| IPC uses fixed copied buffers. | Scoped safety bound | Calls are limited to four vectors and a 1024-byte transfer budget. Services apply smaller bounds. Applications must chunk larger data. |
| A Non-secure connect, call, or close cannot remain pending after the scheduler reaches quiescence for that dispatch. | Scoped deviation | An incomplete message becomes a client error. If already claimed, the service retains its message until reply or partition fault; late output is discarded. A late call reply releases the message, but the connection remains in error until the client requests close. If close was already requested, the late reply allows deferred disconnection to proceed. Shipped Non-secure-facing services reply within the dispatch; Secure Partition callers use the begin/finish path when scheduling another partition is required. |
| Secure services are linked in one image. | Scoped isolation difference | Service writable state is isolated by unprivileged threads and Secure MPU domains, but executable text is shared rather than separately linked. |
| All shipped service loops run as scheduled coroutines. | Implementation difference | Service code uses the standard Secure Partition API; privileged hardware access goes through identity-pinned SVC gates. |
| Abnormal Non-secure guest termination reclaims the guest's connections without delivering `PSA_IPC_DISCONNECT` to the affected services. | Scoped deviation | Fault-handler cleanup cannot dispatch a Secure service inline without re-entering the scheduler. Shipped services do not use `psa_set_rhandle()` for per-connection cleanup, but a ported service that depends on disconnect cleanup must account for this behavior. |
| Secure memory uses no dynamic allocation. | Stronger resource policy | Fixed pools and buffers can reject excess work rather than expanding at runtime. |
| Manifests use wolfTrust JSON and generated C. | Integration difference | Security resources and services must be represented in the wolfTrust schema. |
| Secure Partition entry functions are bound at build time instead of being selected by each manifest's `entry_point` field. | Integration difference | The numeric field validates an executable window, but adding a service also requires a compiled entry wrapper and an explicit start call in `wt_ffm_boot_start_sched()`. |
| Service IDs are generated from the selected manifest. | Integration difference | Applications should include generated `psa_manifest/sid.h` instead of hard-coding target-specific values. |

## Isolation level

wolfTrust implements FF-M isolation level 3 only, and refuses a manifest that
declares level 1 or 2 or a privileged Secure Partition. The rule-by-rule
mapping and the deviations are in
[Security Model](Security-Model.md#ff-m-isolation-level-3).

## Validation and claim boundary

`make test` exercises native framework policy, IPC, and negative inputs.
`make test-conformance` runs the pinned PSA architecture tests: with M33MU it
exercises target FF-M IPC; without M33MU it runs only a host subset. The
STM32H563 hardware runner tests the reference boot chain and selected behavior
on a provisioned board. See [Testing](Testing.md) for commands and the limits
of each environment. The differences above prevent a full FF-M conformance
claim today.

See [API Reference](API-Reference.md) for the client and Secure Partition APIs,
[PSA Compatibility](PSA-Compatibility.md) for service APIs, and
[Footprint Comparison](Footprint-Comparison.md) for dated size measurements.
