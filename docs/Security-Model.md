# Security Model

wolfTrust protects Secure services from application domains through the
isolation mechanisms supplied by an architecture and target port. This page
documents the current STM32H563 reference security profile, which uses
Armv8-M TrustZone and STM32 GTZC attribution for its Secure boundary and guest
RAM isolation. Its security properties come from the authenticated boot chain,
hardware attribution, SPM-owned identity, copied IPC, and service-specific
policy.

## Trusted computing base

The reference trusted computing base includes:

- wolfBoot and its verification key
- the wolfTrust Secure image and generated manifest
- wolfCrypt, wolfHAL, wolfCOSE, the shared wolfHSM NVM components, and the
  full wolfHSM server when the optional hsm engine is selected
- Armv8-M exception, TrustZone, and MPU behavior
- STM32H563 GTZC and flash option-byte configuration
- privileged wolfTrust SVC and fault handlers
- the target entropy and flash implementations

Non-secure guest kernels and applications are not trusted. A Secure Partition
is trusted for the resources its manifest domain can access, but it is not
trusted to access arbitrary SPM or peer-partition writable state.

## Enforced boundaries

| Boundary | Enforcement |
| --- | --- |
| Non-secure to Secure | SAU/IDAU attribution and exactly five CMSE FF-M gateway veneers |
| Guest RAM to guest RAM | GTZC MPCBB attribution closes the shared guest-RAM extent and opens only the scheduled guest's writable SRAM blocks |
| Guest request memory | CMSE security checks, active-guest range checks, overflow checks, vector-count limits, and copied transfers |
| Guest to service | Manifest service policy, connection ownership, generated handles, and SPM-stamped client identity |
| Secure Partition writable state | Unprivileged Secure threads and a per-partition Secure MPU table |
| Secure Partition to hardware backend | Operation-specific SVC gates pinned to the expected partition identity |
| Persistent objects | Vault ownership tuple, checked NVM operations, engine-specific non-exportable key policy, and key/storage type separation |

## The only Non-secure entry path

The linked Secure image exports exactly these Non-secure-callable functions:

- `WolfTrust_FFM_FrameworkVersion`
- `WolfTrust_FFM_ServiceVersion`
- `WolfTrust_FFM_Connect`
- `WolfTrust_FFM_Call`
- `WolfTrust_FFM_Close`

The link rule records symbols with `nm` and rejects any extra or
missing `__acle_se_*` entry. Service-specific operations ride
`psa_call` rather than adding more veneers.

For a call, the gateway:

1. obtains the active guest ID from monitor state;
2. converts guest `N` to PSA client ID `-(N + 1)`;
3. checks and copies the veneer vector structure once;
4. validates input and output counts;
5. validates each range as Non-secure and within that guest's declared
   readable or writable memory; and
6. copies request bytes into SPM-owned buffers before service dispatch.

A guest cannot choose its PSA identity. A racing write to the original vector
descriptor cannot alter the copied descriptor used by the SPM.

## Handles and service policy

Connections and messages carry an owner, type, generation, and state. The SPM
rejects stale handles, wrong-owner handles, invalid transitions, and accesses
disallowed by the manifest. Secure Partition dependencies are also checked:
for example, ITS and Protected Storage may connect to the Secure-only vault,
while a Non-secure client may not.

Each copied call is bounded to four vectors total across input and output and
to the SPM transfer budget. Individual services impose smaller protocol
bounds where needed.

## Guest isolation

Only the selected guest's Non-secure RAM is attributed Non-secure by the GTZC
curtain. The monitor also installs that guest's Non-secure MPU regions and
interrupt mask before returning to it. Reference guests currently run privileged
Non-secure code and can reprogram their MPU and Non-secure NVIC state, so those
controls are scheduling policy rather than adversarial boundaries. Guest RAM
windows are non-overlapping and hardware-isolated by GTZC.

Guest flash windows are non-overlapping but share one Non-secure attribution
window and remain mutually readable. WRP plus `WT_GUEST_FLASH_WRP=1` protects
their integrity, not confidentiality. A hostile guest can also reach peripherals
left Non-secure by the boot chain; manifest resource lists do not independently
enforce peripheral ownership in the current port.

On a guest fault, wolfTrust captures the reason, masks its interrupts, and
applies the bounded restart policy. If restart is allowed, it clears RAM marked
for restart and reconstructs the initial context. The image is verified again
before the guest runs; failed verification or an exhausted restart budget leaves
the guest quarantined.

## Secure Partition isolation

Every shipped service loop runs as a scheduled unprivileged Secure coroutine.
Its Secure MPU view contains:

- shared read/execute Secure image text;
- read-only Secure image constants;
- its private stack and declared writable resources; and
- explicitly shared resources such as the keystore band where required.

Privileged handlers retain the SPM view. Flash, entropy, NVM lock, and reset
operations are available only through narrow SVC operations that check the
originating partition.

This is writable-state isolation inside one linked image. Shared executable
text is not per-partition code isolation, and the crypto, vault, and attestation
domains share the keystore data band required by their backends.

## Per-guest cryptographic keys

The SERVICE_HSM door carries the selected crypto engine's wire (`WT_ENGINE`):
the native engine (default) dispatches wolfCrypt directly, with explicitly
vault-backed keys stored as `SENSITIVE` and `NONEXPORTABLE` NVM objects whose
private material never leaves the Secure key-vault domain; the hsm engine
relays wolfHSM server packets. The FF-M surface, SIDs, and isolation bands are
identical in both engines.

In the hsm engine the service receives one copied wolfHSM request packet
through FF-M IPC. The SPM-stamped negative client ID selects guest `N`, and
the relay forces wolfHSM server client ID `N + 1` before processing the
packet. In the native engine the same SPM-stamped identity becomes the vault
key namespace's delegated sub-owner. A client-provided communication ID
therefore cannot select another guest's key namespace in either engine.

The native reference guests normally run wolfPSA and wolfCrypt locally. Their
ordinary volatile PSA keys therefore live in Non-secure guest RAM; only DRBG
seed requests and explicit native-wire vault-key requests cross the Secure
boundary. In the hsm engine, supported guest PSA operations and their private
key state are routed to the Secure wolfHSM server.

The hsm engine's guest-facing relay rejects wolfHSM NVM message groups. The
native request format exposes no general NVM operation. Guests can use the
intended engine protocol but cannot directly reach storage objects, the
firmware-version floor, the Protected Storage counter table, or the
attestation key. See [Crypto Engines](Crypto-Engines.md) for the complete
selection and key-model comparison.

## Storage protection

ITS and Protected Storage are front-end partitions. They forward every object
operation to a vault service that is not available to Non-secure clients. The
vault key is:

```text
(front-end partition identity, SPM-stamped end-client identity, 64-bit UID)
```

ITS supports the core set/get/get-info/remove interface and the write-once
flag. Protected Storage always adds sealing even when a caller supplies
`NO_CONFIDENTIALITY` or `NO_REPLAY_PROTECTION` hints.
The current `psa_ps_get_info()` implementation echoes those requested hint
flags instead of reporting the stronger protection actually applied.
Sealing uses AES-256-GCM with:

- a device-local non-exportable key stored in the shared Secure NVM store;
- the object label as authenticated data;
- a 12-byte nonce derived from a persisted per-write counter; and
- a 16-byte authentication tag.

The counter is stored before ciphertext, preventing nonce reuse after an
interrupted write. The live per-object counter also detects replay of a stale
ciphertext unless an attacker can coherently roll back the counter store; see
[Threat Model](Threat-Model.md).

Sealed replacement stages the authenticated prior object until the new
counter mapping commits, then destroys the stage. An interrupted replacement
restores that object
without rolling back the global nonce counter. Replacing sealed data with
unsealed data uses the same transaction and retires the old seal counter on
commit. If the recovery copy is missing or invalid, the live object is kept
only if it authenticates under the committed counter; otherwise that object
is discarded and its counter retired. Other objects remain available.
The vault requires wolfHSM's
`wh_NvmFlash` backend, including its capacity and compaction callbacks, and
rejects incompatible backends at initialization. The flash HAL may be supplied
by the target port or the host RAM simulator.

Vault storage rejects its reserved key-object type. In the native engine,
explicit key requests use the vault's separate key face. In the hsm engine,
guest cryptographic keys instead use the wolfHSM server keystore behind
`SERVICE_HSM`. Both paths bind operations to the SPM-stamped caller namespace.

## Authenticated guest launch

The target image builder hashes the exact guest binary and records its guest
ID, version, byte length, and SHA-256 digest in a slot inside wolfTrust. That
slot is patched before wolfBoot signs the Secure image.

At boot, after initial guest-image validation and before any guest executes,
wolfTrust checks the persistent Secure-image and recorded-guest version floors.
Versions that pass the rollback check advance those floors.

During initial validation, immediately before a guest's first dispatch, and
again after a restart, wolfTrust:

- locates the guest's signed record;
- rejects an empty or out-of-window image size;
- checks the record version against the manifest minimum;
- hashes exactly the recorded number of bytes and compares the digest in
  constant work.

When `WT_GUEST_FLASH_WRP=1`, launch also reads the STM32 WRP register
and refuses the guest unless every flash group covering its full window is
protected. This option is disabled in the generic default build because M33MU
does not model WRP; enable it for the hardened STM32H563 image and provision
the option bytes as described in [STM32H5 Guide](STM32H5-Guide.md).

## Static memory

The Secure wolfCrypt settings define both `NO_WOLFSSL_MEMORY` and
`WOLFSSL_NO_MALLOC`. Stacks, IPC transfers, service state, selected-engine
contexts, and cryptographic scratch space use fixed storage. Oversized requests
fail instead of allocating. The link also rejects allocator symbols in both
engine images.

## Source anchors

- [FF-M gateway](../src/arch/armv8m/ffm_nsc.c)
- [Secure Partition scheduler and SVC gates](../src/arch/armv8m/spm_svc.c)
- [Guest verification](../src/guest_verify.c)
- [HSM relay binding](../src/services/wolfhsm/wt_hsm.c)
- [Native crypto dispatch](../src/services/native/crypto_native.c)
- [Native vault key backend](../src/services/native/keyvault.c)
- [Vault storage](../src/services/wolfhsm/wt_hsm_vault.c)

See [Threat Model](Threat-Model.md) for assumptions and residual risks.
