# Standards and Claims

wolfTrust targets the Arm Firmware Framework for M (FF-M) 1.0 contract and
selected Platform Security Architecture (PSA) service APIs. The reference
implementation is the STM32H563 Cortex-M33 port. Compatibility is documented
per interface, with its limits and test evidence; no full FF-M or PSA
certification is claimed.

| Standard or profile | Implemented scope and deviations |
| --- | --- |
| [Arm FF-M 1.0](https://documentation-service.arm.com/static/64a2ed35df6cd61d528c4132) | [FF-M Compatibility](FF-M-Compatibility.md) covers the client and Secure Partition APIs, manifests, IPC, isolation policy, and differences from the specification. One `psa_irq_enable()` operation is backported from an FF-M 1.1 beta extension. |
| [PSA Crypto API 1.4](https://arm-software.github.io/psa-api/crypto/1.4/) | [PSA Compatibility](PSA-Compatibility.md) records the wolfPSA surface and configuration-dependent algorithm support. [Crypto Engines](Crypto-Engines.md) explains where keys and operations execute. |
| [PSA Secure Storage API 1.0](https://arm-software.github.io/psa-api/storage/1.0/) | [PSA Compatibility](PSA-Compatibility.md) records the implemented ITS and Protected Storage operations and their flag and access-policy differences. |
| [PSA Initial Attestation API 1.0](https://arm-software.github.io/psa-api/attestation/1.0/) and [RFC 9783](https://www.rfc-editor.org/rfc/rfc9783.html) | [PSA Compatibility](PSA-Compatibility.md) records the token API subset and token-profile deviations, including the currently advertised `tag:psacertified.org,2023:psa#tfm` profile. |
| [PSA Firmware Update API 1.0](https://arm-software.github.io/psa-api/fwu/1.0/) | [PSA Compatibility](PSA-Compatibility.md) records the single-component update flow and unsupported trial-accept behavior. |

On the STM32H563, wolfTrust meets FF-M isolation level 3;
[Security Model](Security-Model.md#ff-m-isolation-level-3) maps each isolation
rule and lists the deviations; [Threat Model](Threat-Model.md) describes assumptions
and residual risks. [Testing](Testing.md) separates host, emulator, and
physical-board evidence.

## Deviation register

- [FF-M framework differences](FF-M-Compatibility.md#framework-differences)
  lists the IPC, manifest, lifecycle, and integration differences.
- [FF-M isolation level](FF-M-Compatibility.md#isolation-level) states the
  implemented level and points to the rule mapping.
- [PSA service API differences](PSA-Compatibility.md#service-api-differences)
  lists storage, attestation, and firmware-update deviations.
- [Validation and claim boundaries](FF-M-Compatibility.md#validation-and-claim-boundary)
  and [PSA validation](PSA-Compatibility.md#validation-and-claim-boundary)
  identify the evidence behind each claim.
