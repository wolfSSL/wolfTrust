# Threat Model

This page describes the STM32H563 reference configuration. A port must
re-evaluate these assumptions against its own attribution, flash, entropy,
interrupt, and debug mechanisms.

## Security objectives

wolfTrust aims to:

- execute only a wolfBoot-authenticated Secure image and authenticated guest
  images;
- prevent one Non-secure guest from reading or modifying another guest's RAM
  and, when WRP is enabled and provisioned, from modifying another guest's
  flash;
- expose Secure services only through bounded, policy-checked FF-M IPC;
- keep the Initial Attestation Key and device-local Protected Storage sealing
  key non-exportable, and protect Protected Storage data at rest;
- bind service access and HSM namespaces to SPM-derived caller identity;
- prevent accepted firmware versions from decreasing outside assembly-and-test
  and provisioning; and
- contain recoverable guest and Secure Partition faults without silently
  widening access.

## Protected assets

- wolfBoot verification keys and the Secure image
- the attestation identity key
- guest cryptographic keys and their namespace ownership
- ITS and Protected Storage objects
- firmware-version floors and update state
- measured-boot and guest measurement records
- Secure Partition private state
- SPM connection, message, scheduler, and lifecycle state
- cross-guest RAM confidentiality and integrity, plus WRP-backed guest-flash
  integrity

## Adversary capabilities

The primary adversary controls all software in one Non-secure guest. It may:

- run privileged Non-secure code;
- issue arbitrary PSA requests, call types, handles, vector counts, addresses,
  lengths, and payloads;
- race its own memory while a gateway call is in progress;
- spoof selected-engine protocol fields, including wolfHSM communication IDs
  when the hsm engine is linked;
- trigger faults, interrupt activity, repeated connects, and abandoned update
  sessions;
- attempt to access peer RAM, Secure memory, peripherals, and inactive guest
  flash; and
- supply malformed storage, attestation, network, and update inputs.

The model also considers accidental power loss during persistent writes,
corrupt NVM contents, stale ciphertext replay, and malformed candidate update
images.

## Assumptions and exclusions

- wolfBoot and the build toolchain are trusted. wolfBoot authenticates the
  wolfTrust image, including its linked cryptographic libraries and generated
  manifest.
- The device's Secure attribution and option bytes are provisioned correctly.
- The target supplies adequate entropy and correct flash semantics.
- Armv8-M isolation and STM32H563 security peripherals behave as documented.
- Invasive physical attacks, fault injection against the silicon, side-channel
  extraction, malicious build infrastructure, and compromise of signing keys
  are outside this software threat model.
- Debug access and product-state transitions are deployment policy. A board
  left in an open debug state does not provide the same physical protection as
  a provisioned device.

## Threats and controls

| Threat | Primary controls |
| --- | --- |
| Direct entry to Secure code | SAU/IDAU and CMSE permit only the five whitelisted FF-M veneers. |
| Caller-ID spoofing | The gateway derives identity from the monitor's active guest; service payloads cannot override it. |
| Pointer substitution or overflow | The vector descriptor is copied once; counts, arithmetic, CMSE attributes, and active-guest windows are checked before copying bytes. |
| Stale or stolen handles | Handle ownership, type, generation, and state transitions are checked by the SPM. |
| Cross-guest RAM access | GTZC MPCBB attribution closes the full guest-RAM extent and reopens only the scheduled guest's writable SRAM blocks. Per-guest Non-secure MPU and interrupt state are restored scheduling policy, not adversarial boundaries against privileged guests. |
| Inactive-guest flash modification | Signature-covered guest digests and runtime verification detect changes; hardened STM32H563 builds also require complete WRP coverage. |
| Cross-guest key use | The SPM-stamped identity selects the native vault sub-owner; the hsm relay maps guest `N` to forced wolfHSM client ID `N + 1`. |
| Direct NVM access through a crypto protocol | The native format exposes no general NVM operation; the hsm relay rejects wolfHSM NVM message groups. |
| Storage object confusion | The vault namespaces objects by front-end partition, stamped client, and UID, and storage requests cannot use its reserved key-object type. |
| Protected Storage disclosure or edit | AES-256-GCM sealing, a non-exportable device key, authenticated labels, and checked NVM operations. |
| Stale sealed-object replay | Each sealed write advances a persisted counter used in its nonce; the current slot counter authenticates reads. |
| Firmware downgrade | Outside assembly-and-test and provisioning, boot checks the Secure-image and recorded-guest floors before first guest execution. Firmware Update separately checks the candidate Secure-image version against its boot-loaded floor before arming wolfBoot. |
| Malformed update | Bounded aligned writes, staged-image header verification, version binding, and wolfBoot authentication before commit. |
| Faulted Secure service | Synchronization is released before pinned calls fail. If policy selects a restart, private state is scrubbed before bounded recovery; otherwise, the port enters its fail-closed path. |
| Resource exhaustion | Fixed-size pools and buffers reject excess requests. A successful firmware-update `psa_fwu_start()` sets the owner timer; while the session remains active, any owner operation other than `psa_fwu_query()` or `psa_fwu_start()` that reaches dispatch refreshes it, including failed or unsupported operations. After 30,000 scheduler ticks without such a refresh, the next well-formed request from another client reclaims the session; ownership does not expire autonomously. |

## Residual risks and operational requirements

### WRP protects guest-flash integrity, not confidentiality

`WT_GUEST_FLASH_WRP` defaults to `0` because the emulator
does not implement STM32 flash option bytes. A production STM32H563 image must
set it to `1` and must program WRP after guest flashing. Otherwise,
digest checks detect changes only when verification runs and do not themselves
prevent a privileged Non-secure guest from rewriting flash between checks.
Because both guest images share one Non-secure flash attribution window, a
privileged guest can reprogram `MPU_NS` and read peer guest flash. Do not place
peer secrets in guest images or claim peer-image confidentiality.

### Persistent counters use the same flash trust boundary

Protected Storage counter records and firmware-version floors reside in the
shared NVM flash pool. The design detects stale object data when its live
counter remains current and fails closed on malformed records. It does not
claim resistance to a physical adversary that can restore a mutually
consistent historical snapshot of the entire NVM pool. A target requiring
that property needs rollback-resistant monotonic storage in its port.

### Secure code is shared

Secure Partition writable state is narrowed by the Secure MPU, but all service
threads execute shared read/execute text from one linked image. The selected
crypto engine, vault, and attestation also share a keystore data band. A defect
in trusted shared code or an allowed shared backend can therefore affect more
than one service.

### Privileged handlers remain security-critical

Unprivileged service threads request flash, entropy, locking, and reset through
SVC gates. The handler validates the originating partition, but a defect in
that privileged dispatcher is within the trusted computing base.

### Availability is bounded, not guaranteed

A hostile guest can spend its own execution time on rejected requests and can
cause its own quarantine. Shared CPU, flash, and service queues still create
availability coupling. Recovery limits stop infinite restart loops but may
leave a guest or service unavailable.

### Non-secure peripheral and interrupt attribution is inherited

The STM32H563 reference port exposes the `0x40000000-0x4FFFFFFF` peripheral
aperture as Non-secure and explicitly leaves USART2 and USART3 Non-secure. It
does not program RCC security attribution. A privileged Non-secure guest can
reprogram `MPU_NS`, alter Non-secure NVIC state, and access any peripheral left
Non-secure by the boot chain. Manifest resource lists therefore do not enforce
adversarial peripheral or interrupt ownership in the current port. Deployments
must configure and validate device-specific peripheral security and privilege
attribution before claiming those boundaries. In particular, access to shared
clock controls can disrupt Secure execution or deny service to peer guests.

### Development lifecycle permits recovery

Assembly-and-test and provisioning lifecycle values intentionally permit NVM
reformat and bypass downgrade refusal. Every other lifecycle value enforces
floors and fails closed on an unknown persistent pool. Operators must verify
the authenticated lifecycle handoff and provisioning state before deployment.

See [Security Model](Security-Model.md) for the implementation boundaries and [STM32H5 Guide](STM32H5-Guide.md)
for option-byte safety.
