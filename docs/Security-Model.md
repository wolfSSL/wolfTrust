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
- read-only Secure image constants; and
- its private stack and its own writable data band.

No two Secure Partitions share a writable byte (FF-M isolation level 3). The
vault partition owns the NVM object store, its flash context, the sealer, and
its DRBG; the crypto partition (`SERVICE_HSM`) owns the engine state and
reaches persistent key objects only through `SERVICE_VAULT`'s keystore object
door, an FF-M service that serves the registered crypto partition alone and
only the ids and labels the keystore owns; the attestation partition owns the
token state and holds no key material, obtaining every signature and the IAK
public key from `SERVICE_HSM`'s attestation door. Each door client is
confined to its door: the crypto partition's other vault requests and any
Secure Partition's call on `SERVICE_HSM`'s ordinary crypto wire return
`PSA_ERROR_NOT_PERMITTED`. The manifest generator and
the runtime domain validator both refuse a level 3 manifest that shares a
writable resource between partitions, so the split cannot regress silently.
The keystore door hands the crypto partition the key objects it asks for.
That is an IPC contract between two partitions, not shared memory.

The tables the MPU is programmed from are checked again after they are
composed. Before any partition runs, the SPM refuses to boot if a composed
table grants write access to memory another partition can reach, or any access
to SPM-private RAM. A request from a Secure Partition is checked against that
partition's own composed table, and the SPM acts on one private copy of the
request block, so the memory references it validated are the ones it uses.

### Partition restart

A restarted partition keeps nothing its previous instance held. The SPM:

- fails every request the partition was serving and drops every connection to
  it to the error state;
- releases every connection and request the partition held as a client, so a
  handle from the old instance is refused;
- clears its asserted signals and masks its interrupt lines until the new
  instance enables them;
- clears its stack and returns its data band to its link-time image; and
- rebuilds the band with the setup boot ran, from inputs the SPM holds: the
  boot handoff, the attestation public key, and the contents of the store.

Persistent state is the NVM store alone. Nothing in a partition's RAM survives
its restart.

Privileged handlers retain the SPM view. Flash, entropy, NVM lock, and reset
operations are available only through narrow SVC operations that check the
originating partition: flash and the NVM lock answer only the vault, entropy
only the vault and crypto partitions. The state those handlers consume (the
NVM lock, the flash driver's state, the lifecycle latch, the rollback floors,
and the privileged tasklet stacks) lives in SPM-private RAM, outside every
partition band.

This is writable-state isolation inside one linked image. Shared executable
text is not per-partition code isolation.

### Processor state

Secure floating point is unsupported. Every Armv8-M port retires any FP
context the loader left active (`CONTROL.FPCA`, `SFPA`, `FPCCR.LSPACT`), then
clears CP10/CP11 access in
`CPACR_S`, `CPACR_NS`, and `NSACR`, clears automatic and lazy FP state
preservation in `FPCCR_S`, sets `LSPENS`, `CLRONRET`, and `CLRONRETS`, and
halts unless every one of those bits reads back as programmed. The post-link
check rejects FP instructions and soft-float runtime helpers in the Secure
image, so an FP instruction in a partition raises a UsageFault instead of
creating FP state another context could read.

The top of the Secure main stack and of every Secure coroutine stack carries
two seal words (`0xFEF5EDA5`), written when the stack is created; boot
refuses to continue unless the main-stack seal is in place with MSP below it.
The SPM checks both words of a coroutine stack when the coroutine yields or is
preempted, and again when it is dispatched. A partition that damaged its own
seal, or whose exception frame was stacked over it, is resumed on a trap
instruction below the seal, so it alone faults and restarts under
its recovery policy with a rebuilt stack; a seal found damaged at dispatch,
while its owner was suspended, halts the platform. The post-link check fails
the build if an allocated section reaches the main-stack seal.

The seal words mark the fixed top of each stack. Secure stack pointers are not
moved onto a seal while another context runs, so this check does not replace
the integrity signature the processor places in, and checks on, the Secure
frames it stacks itself.

### SPM stack limit and fault attribution

The Secure main stack has a fixed size (`WT_SPM_STACK_SIZE`, 16 KiB), reserved
by the linker below `_estack`; the link fails if `.bss` reaches it. Reset sets
`MSPLIM_S` to its bottom right after MSP is placed under the seal words, and
boot refuses to continue unless the limit reads back. An SPM stack overflow
raises `UsageFault.STKOF` on the main stack; the handler halts the platform on
the production panic without touching the stack, and a real `HardFault`
handler does the same for any escalated fault, latching `CFSR`, `HFSR`,
`MMFAR`, `BFAR`, the stacked PC and `EXC_RETURN` for a debugger instead of
spinning silently.

`BusFault` is enabled alongside `MemManage` and `UsageFault`. All three take one
dispatcher, which attributes the fault by the frame it finds: a Secure Thread
frame on the process stack with a scheduled partition or wolfHSM tasklet
current is that partition's fault (precise bus errors carry `BFAR`; an
imprecise one is drained by the barrier every context switch issues, so it is
still pending against the partition that issued the write), and the partition
restarts under its manifest policy. A frame from a privileged handler, the
bootstrap thread, or no current coroutine is the SPM's own fault and halts the
platform. A Non-secure bus error targets the Secure `BusFault` as well
(`BFHFNMINS` is 0); it is routed to the guest fault path and restarts the
guest. A partition that issues the scheduler's internal guest-return `SVC` is
resumed on the PROGRAMMER ERROR trap and restarts alone.

### Execute-never Secure RAM

The SPM whitelist maps every writable Secure RAM region execute-never. The one
executable Secure RAM window is the MIMXRT700's RAMFUNC band, which holds the
NSC gateway and NOR routines and is mapped read-only. While an
unprivileged partition thread runs, its MPU table keeps `PRIVDEFENA` so the
privileged SVC gate and its deputies can reach SPM state, and the default map
would let privileged code execute from SRAM; one extra region therefore covers
the SPM's own RAM (the boot-handoff scratch, `.data`, `.bss`, the main stack)
privileged-only and execute-never on every partition dispatch, and a domain
region inside that window fails the dispatch closed. A production partition
table must leave the region free; the Arm conformance client partition fills
an 8-region MPU with its window grants, and the conformance image counts those
dispatches in `g_wt_xn_denied` instead (the STM32H563 implements 12 regions,
so it is covered there).

### Link-time optimization

The Secure image enables GCC link-time optimization by default. LTO can replace
the original input-object names with generated objects, so every object that
places state in a partition data band is compiled without LTO and claimed by
name. CMSE veneers, exception handlers, hand-written assembly, and other
assembly-referenced objects are compiled without LTO so their symbols and
calling conventions stay stable. State from an optimized link unit can only
land in SPM-private RAM.

[`tools/secure_owners.txt`](../tools/secure_owners.txt) gives every linked
object one owner: a partition, the SPM, or `shared` for code that runs in more
than one domain. The post-link layout check reads the linker map and rejects:

- a writable input section outside its owner's region;
- an object with no owner;
- a `shared` object that holds writable state;
- a missing exception entry, a linked heap allocator, or a privileged tasklet
  stack outside SPM-private RAM; and
- in a production image, any conformance object, symbol, or data.

The check runs at every link, with and without LTO, so the optimization cannot
weaken the boundaries described above. `WT_LTO=0` disables the optimization
without changing the memory policy.

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

## Cortex-A isolation level 3

On QEMU `virt`, the AArch64 port implements isolation level 3 of the PSA
Firmware Framework for M 1.0 (FF-M, Arm DEN 0063) with either crypto engine,
`native` or `hsm`. The Secure Partition Manager Core (SPMC) of the Firmware
Framework for Arm A-profile (FF-A) runs at Secure EL1, and every Secure
Partition runs at Secure EL0 under its own stage 1 translation table. The rules are cited by number; their text
is in the specification.

| Requirement | wolfTrust on AArch64 |
| --- | --- |
| I1, only Code is executable (section 3.1.2) | Partition tables map data execute-never, the SPM maps its writable Secure RAM execute-never, and the table builder refuses a writable and executable region. |
| I2, only Private data is writable (section 3.1.2) | Code and constant data are read-only in every partition table; a partition can write only its own stack and data band, plus memory another endpoint shares, lends, or donates to it through FF-A. |
| I3, NSPE to SPE (sections 3.1.3 and 3.1.4) | The Secure bands and the SPM's devices sit where the `virt` bus refuses Normal-world access. The Normal world reaches services only through FF-A calls; for a PSA call the SPMC validates and copies the vectors it names, and a Secure interrupt is claimed as Group 0, disabled, cleared, and read back before its partition runs. |
| I3, Secure Partition to Secure Partition and to the SPM (sections 3.1.3 and 3.1.4) | Each partition has its own data band, and every boot refuses a composed table that can write another partition's band or reach SPM-private RAM. |
| I3, indirect access (section 3.1.4) | No partition is assigned a device, and the SPM's devices are never mapped into a partition table. |
| Private runtime state (section 4.2.1) | A partition's writable state is its own stack and, where it has one, its own data band. On restart the SPMC zeroes the stack and resets the band to its link image. The image has no heap. |
| Violation handling (section 3.1.6) | A partition access that breaks a rule takes an abort at Secure EL0 and ends that run of the partition, which its manifest restart policy restarts within a bounded budget or escalates to a fail-closed platform halt. A fault in the SPMC halts the platform through the EL3 monitor. |

### Deviations

- Level 3 is the only isolation level implemented. A manifest that declares
  level 1 or 2 is refused; level 0 makes no isolation claim.
- A faulted partition is restarted under its manifest restart policy, with a
  bounded budget, instead of staying terminated.
- The Normal world is one FF-A endpoint, not a set of managed guests.
- The claim covers QEMU `virt`. The `xlnx-versal-virt` manifests declare no
  isolation level, because that model has no XMPU or XPPU to fence the
  Secure bands and the SPM's devices from the Normal world.
- The evidence is emulator evidence; no Cortex-A silicon run is recorded yet.

### Evidence

- The Arm psa-arch-tests FF-M IPC suite passes 85 tests with 4 heap tests
  skipped on `virt` with both engines.
- The six Arm FF-A ACS groups meet their recorded floors on `virt` with both
  engines, with the by-design deviations listed in
  [ACS conformance results](FF-A-Compatibility.md#acs-conformance-results).
- The isolation negatives in
  [QEMU AArch64 scenarios](Testing.md#qemu-aarch64-scenarios) run on both
  engines.
- All of the above passed at commit `b3587f01` in the
  [AArch64 CI run](https://github.com/wolfSSL/wolfTrust/actions/runs/37090043983).

## Source anchors

- [FF-M gateway](../src/arch/armv8m/ffm_nsc.c)
- [Secure Partition scheduler and SVC gates](../src/arch/armv8m/spm_svc.c)
- [Secure stack sealing and context switch](../src/arch/armv8m/coroutine_armv8m.c)
- [Secure fault attribution and SPM halt](../src/arch/armv8m/sp_fault_armv8m.c)
- [Secure MPU tables and the SPM RAM cover](../src/arch/armv8m/mpu_armv8m.c)
- [Guest verification](../src/guest_verify.c)
- [HSM relay binding](../src/services/wolfhsm/wt_hsm.c)
- [Native crypto dispatch](../src/services/native/crypto_native.c)
- [Native vault key backend](../src/services/native/keyvault.c)
- [Vault storage](../src/services/wolfhsm/wt_hsm_vault.c)

See [Threat Model](Threat-Model.md) for assumptions and residual risks.
