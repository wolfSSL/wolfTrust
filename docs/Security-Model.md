# Security Model

wolfTrust protects Secure services from application domains through the
isolation mechanisms supplied by an architecture and target port. This page
documents the current STM32H563 reference security profile, which uses
Armv8-M TrustZone and STM32 GTZC attribution for its Secure boundary and guest
RAM isolation. Its security properties come from the authenticated boot chain,
hardware attribution, SPM-owned identity, copied IPC, and service-specific
policy.

## FF-M isolation level 3

On the STM32H563, wolfTrust implements isolation level 3 of the PSA Firmware
Framework for M 1.0 (Arm DEN 0063) and meets every mandatory isolation rule at
that level, with either crypto engine. The rules are cited by number below;
their text is in the specification.

| Requirement | wolfTrust |
| --- | --- |
| I1, only Code is executable (section 3.1.2) | Partition tables map data execute-never, the SPM maps all writable Secure RAM execute-never, and the domain validator refuses a writable and executable resource. |
| I2, only Private data is writable (section 3.1.2) | Code and constant data are read-only in every partition table; a partition can write only its own stack and data band. |
| I3, NSPE to SPE (sections 3.1.3 and 3.1.4) | SAU/IDAU and GTZC attribution, five CMSE veneers, and copied IPC. HASH, RNG, and PKA are Secure-only and read back at boot, and Non-secure DMA cannot reach Secure memory. |
| I3, Secure Partition to Secure Partition and to the SPM (sections 3.1.3 and 3.1.4) | Each partition runs unprivileged with its own MPU table. The link check places every writable object in its owner's band or in SPM-private RAM, and boot refuses a composed table that can write another partition's memory or reach SPM-private RAM. |
| I3, indirect access (section 3.1.4) | A partition maps a peripheral only if the port assigns it one that is not a bus master and reads back Secure. |
| Private runtime state (section 4.2.1) | A partition's writable state is its own stack and, where it has one, its own data band, restored from the link image when the partition restarts. The image has no heap. |
| Violation handling (section 3.1.6) | A partition access that breaks a rule faults and terminates that partition. A fault in the SPM halts the platform. |

### Deviations

- Only level 3 is implemented. A manifest that declares level 1 or 2 is
  refused.
- Manifest `mmio_regions` are not supported, and no port assigns a peripheral
  to a partition. Partitions reach hardware through SPM operations pinned to
  the calling partition.
- The PSA Root of Trust domain is the SPM and its privileged handlers. The
  crypto, storage, attestation, and update services run as Secure Partitions
  and are isolated like any other partition.
- A faulted partition is restarted under its manifest restart policy, with a
  bounded budget, instead of staying terminated.
- Non-secure guests run privileged. Isolation between guests is a wolfTrust
  hypervisor property outside FF-M; see [Guest isolation](#guest-isolation).
- The claim covers the STM32H563 port. The MIMXRT700 port does not make it yet.

### Evidence

- The Arm psa-arch-tests FF-M IPC suite, pinned in
  [`tests/upstream/psa-arch-tests.rev`](https://github.com/wolfSSL/wolfTrust/blob/main/tests/upstream/psa-arch-tests.rev),
  passes 85 tests with 4 heap tests skipped, recorded test by test in
  [`tests/target/ffm_ipc_results.txt`](https://github.com/wolfSSL/wolfTrust/blob/main/tests/target/ffm_ipc_results.txt).
- The isolation negatives in [Testing](Testing.md#isolation-scenarios) run on
  both engines under M33MU. The STM32H563 hardware suite runs the positive and
  conformance scenarios and the negatives the emulator cannot show.

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
their integrity, not confidentiality. A guest can also reach any peripheral the
boot chain leaves Non-secure; the port does not assign peripherals between
guests.

On a guest fault, wolfTrust captures the reason, masks its interrupts, and
applies the bounded restart policy. If restart is allowed, it clears RAM marked
for restart and reconstructs the initial context. The image is verified again
before the guest runs; failed verification or an exhausted restart budget leaves
the guest quarantined.

## Secure Partition isolation

Each partition's MPU view holds the shared Secure text (read and execute), the
Secure constants (read-only), its own stack, and its own data band. The vault
owns the NVM store, the sealer, and its DRBG; the crypto partition
(`SERVICE_HSM`) owns the engine state; the attestation partition owns the token
state. Persistent keys cross between them only as FF-M IPC:

- the crypto partition reads and writes key objects through the keystore door
  on `SERVICE_VAULT`; and
- the attestation partition obtains signatures and the IAK public key through
  the attestation door on `SERVICE_HSM`.

Each door serves one registered client partition and refuses every other
caller.

Mechanical checks:

- [`tools/secure_owners.txt`](https://github.com/wolfSSL/wolfTrust/blob/main/tools/secure_owners.txt) gives every linked
  object one owner. The post-link check fails the build if writable state
  lands outside its owner's region, an object has no owner, a shared object
  holds writable state, or a production image carries conformance code.
  Objects that hold band state are built without LTO so the map names them.
- The generator and the domain validator refuse writable memory shared between
  partitions.
- Before any partition runs, boot checks every composed MPU table against the
  other partitions' bands and SPM-private RAM.
- A request from a partition is copied once into SPM memory and checked against
  that partition's own table.

Privileged handlers keep the SPM view. Flash, entropy, the NVM lock, and reset
are SVC operations that check the calling partition, and the state they use
lives in SPM-private RAM.

### Partition restart

A restarted partition keeps nothing from its previous instance. Requests it was
serving fail, the connections and handles it held are released, its signals and
interrupt lines are cleared and masked, its stack is cleared, and its band is
restored from the link image. Only the NVM store persists.

### Processor state and the SPM

- Secure floating point is disabled and locked at boot (`CPACR`, `NSACR`, and
  `FPCCR`, each read back), and the post-link check rejects FP instructions in
  the Secure image.
- Every Secure stack carries a two-word seal (`0xFEF5EDA5`) at its top. Boot
  checks the main-stack seal, and the SPM checks each coroutine's seal at every
  switch; a damaged seal faults that partition, or halts if found at dispatch.
- `MSPLIM_S` bounds the 16 KiB SPM stack, and the link fails if `.bss` reaches
  it.
- MemManage, BusFault, and UsageFault share one dispatcher. A fault from a
  partition thread restarts that partition, and a fault in the SPM halts the
  platform after latching the fault registers. A partition that issues the
  scheduler's guest-return SVC is panicked.
- While a partition runs, one MPU region keeps the SPM's own RAM
  privileged-only and execute-never.

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

- FF-M gateway: [copied request handling](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/common/ffm_gateway.c) and [Armv8-M veneers](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/armv8m/ffm_nsc.c)
- Secure Partition scheduling and SVC gates: [common gate](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/common/spm_gate_core.c) and [Armv8-M SVC](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/armv8m/spm_svc.c)
- [Secure stack sealing and context switch](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/armv8m/coroutine_armv8m.c)
- [Secure fault attribution and SPM halt](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/armv8m/sp_fault_armv8m.c)
- [Secure MPU tables and the SPM RAM cover](https://github.com/wolfSSL/wolfTrust/blob/main/src/arch/armv8m/mpu_armv8m.c)
- [Guest verification](https://github.com/wolfSSL/wolfTrust/blob/main/src/guest_verify.c)
- [HSM relay binding](https://github.com/wolfSSL/wolfTrust/blob/main/src/services/hsm_relay_service.c)
- Native crypto dispatch: [service](https://github.com/wolfSSL/wolfTrust/blob/main/src/services/native/crypto_native.c) and [wire protocol](https://github.com/wolfSSL/wolfTrust/blob/main/src/services/native/native_wire.c)
- [Native vault key backend](https://github.com/wolfSSL/wolfTrust/blob/main/src/services/native/keyvault.c)
- [Vault storage](https://github.com/wolfSSL/wolfTrust/blob/main/src/services/wolfhsm/wt_hsm_vault.c)

See [Threat Model](Threat-Model.md) for assumptions and residual risks.
