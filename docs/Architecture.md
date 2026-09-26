# Architecture

wolfTrust places a Secure Partition Manager between a trusted bootloader and
one or more application domains. Reusable policy and service code manages
manifest policy, identity, FF-M IPC, scheduling, lifecycle, recovery, and
Secure service dispatch. Architecture and target ports provide the execution,
memory-protection, interrupt, storage, entropy, and boot mechanisms needed to
enforce that policy.

Two architecture ports run the same policy and service code. The Armv8-M
adapter with the STM32H563 port is the reference implementation validated on
hardware; it runs two Non-secure guests on one Cortex-M33 and exposes Secure
services only through FF-M IPC. The AArch64 adapter replaces Trusted
Firmware-A on Cortex-A and is validated under QEMU; see
[AArch64 architecture](#aarch64-architecture). The boot flow, isolation, and
scheduling sections below describe the Armv8-M reference port.

## Software stack

| Layer | Role |
| --- | --- |
| wolfBoot | Performs the BL2 secure-boot role, authenticates wolfTrust, passes the measured-boot handoff, and swaps authenticated update images. |
| wolfTrust | Configures isolation, validates the manifest and guest images, schedules guests and Secure Partitions, implements FF-M IPC, and manages lifecycle and recovery. |
| wolfPSA | Implements PSA Crypto entry points over wolfCrypt for the Non-secure reference guests. |
| wolfCrypt | Supplies cryptographic implementations used by guest wolfPSA and Secure services. The native engine dispatches it directly. |
| wolfHSM | Optional crypto engine providing the client/server key-management model and external-HSM integration path. Both engines use its NVM object-store subset. |
| wolfCOSE | Encodes and signs COSE_Sign1 attestation tokens. |
| wolfIP | Supplies the TCP/IP stack for the optional bare-metal reference guests; the Secure virtual Ethernet switch itself is implemented by wolfTrust. |

## Portability boundary

Policy and service code lives under `src/` outside `src/arch/` and names no
architecture or SoC. It reaches the hardware through two contracts:
`wolftrust/arch.h` (`wt_arch_*`: execution, opaque trap frames, protection
domains, interrupts) and `wolftrust/platform.h` (`wt_platform_*`: device,
console, flash, entropy, and boot handoff). `src/arch/common/` holds the
Secure Partition gate, scheduler, and FF-M gateway bodies every architecture
links.

`src/arch/armv8m/` supplies the CMSE gateway and pointer checks, Secure
Partition coroutine switching, and the Secure SVC transport; the companion
`port/stm32h563/` supplies device startup and guest exception paths, GTZC
attribution, guest and Secure MPU programming, interrupt routing, flash,
entropy, timers, and boot handoff. `src/arch/aarch64/` supplies the EL3
monitor, the FF-A layer, the Secure EL1 SPMC, and the GIC drivers; the QEMU
ports are `port/qemuvirt/`, `port/versal/`, and the shared
`port/common/aarch64/`. See [Porting](Porting.md) for the boundary.

## Boot flow

1. wolfBoot verifies the wolfTrust image and transfers a measured-boot record
   containing the Secure image measurement, lifecycle, and active image
   version.
2. wolfTrust configures the target's TrustZone, GTZC, Secure MPU, interrupt,
   and memory policies; validates and binds the generated manifest; registers
   the FF-M services; seeds each guest context; and performs an initial
   signed-record, image-size, manifest-version, digest, and optional WRP check.
3. wolfTrust consumes the measured-boot handoff, initializes the selected
   [crypto engine](Crypto-Engines.md) and shared persistent vault backend, and
   checks the persistent Secure-image and guest version floors.
4. wolfTrust starts the scheduled Secure Partitions.
5. Immediately before an accepted guest's first dispatch, the monitor repeats
   its signed-record, image-size, manifest-version, digest, and optional WRP
   checks, then installs that guest's active GTZC, Non-secure MPU, and interrupt
   policy.
6. The monitor begins time-sliced Non-secure execution.

The image assembly and signing order matters: guest records are patched into
`wolftrust.bin` before wolfBoot signs it. See
`tools/measure/patch_guest_digests.py` and the target runners.

## Isolation layers

The reference port combines several mechanisms:

- The Armv8-M SAU/IDAU boundary separates Secure and Non-secure address space.
- STM32 GTZC MPCBB attribution prevents an inactive guest from accessing the
  active guest's RAM through a Non-secure MPU bypass.
- The monitor replaces the Non-secure MPU and allowed interrupt set on each
  guest switch. Reference guests currently run privileged Non-secure code and
  can reprogram those two controls, so they are scheduling policy rather than
  adversarial boundaries.
- CMSE checks require every request pointer to be Non-secure and inside the
  active guest's declared readable or writable window.
- The Secure MPU gives each Secure Partition thread shared read/execute image
  text, read-only constants, its private stack and data, and only its declared
  shared resources.

All shipped service loops are scheduled as unprivileged Secure coroutines.
Operations requiring wider Secure access, including flash programming, entropy,
NVM locking, and platform reset, trap through privileged SVC handlers that
verify the calling partition and operation.

The single-image design shares executable text among Secure Partitions. The
MPU isolates writable state, not code identity; this is an explicit difference
from separately linked partition images.

Both guest images share one Non-secure flash attribution window, so a privileged
guest can read peer flash. WRP plus `WT_GUEST_FLASH_WRP=1` protects guest-flash
integrity but not confidentiality. Peripheral and Non-secure NVIC attribution
are deployment responsibilities; see [Threat Model](Threat-Model.md).

## FF-M request path

A Non-secure client calls a standard PSA API or the generic FF-M client API:

```text
guest API
  -> WolfTrust_FFM_Connect / Call / Close
  -> CMSE and active-guest window validation
  -> SPM-owned connection and copied vectors
  -> scheduled Secure Partition
  -> SVC-gated backend when privileged hardware access is required
  -> copied reply
```

The gateway never accepts a caller ID from the guest. It derives guest
`N` as PSA client ID `-(N + 1)`. Handles carry ownership and
generation state, and the SPM rejects stale, cross-owner, or invalid
transitions.

The link step runs `arm-none-eabi-nm` and requires exactly five
Non-secure-callable symbols:

- `WolfTrust_FFM_FrameworkVersion`
- `WolfTrust_FFM_ServiceVersion`
- `WolfTrust_FFM_Connect`
- `WolfTrust_FFM_Call`
- `WolfTrust_FFM_Close`

Any additional `__acle_se_*` symbol, or a missing expected symbol,
fails the build.

## Secure Partition scheduling

Connection-based services use `psa_wait`, `psa_get`,
`psa_read`, `psa_write`, and `psa_reply`. Each
service has a statically allocated coroutine stack and blocks until its signal
or interrupt is ready. The dispatcher continues running ready partitions until
the system is quiescent, which permits partition-to-partition IPC without
executing one partition on another partition's stack.

A Secure Partition fault first releases held synchronization state and then
completes its pinned client call with a communication failure. If policy selects
a restart, wolfTrust scrubs declared private writable memory before rearming the
partition. A forbidden or exhausted restart, or a failed rearm, escalates to
the port's fail-closed path.

## Guests and lifecycle

The monitor time-slices the configured Non-secure guests. A guest fault masks
its interrupts and applies the restart policy. If restart is allowed, wolfTrust
clears restart-marked RAM and restores a clean context after a bounded delay; if
the budget is exhausted, the guest remains faulted. Runtime remeasurement can
also quarantine a guest without entering it.

The PSA lifecycle value comes from the authenticated boot handoff. Scheduled
Secure Partitions can read it through `psa_rot_lifecycle_state()`; there is no
Non-secure client adapter or CMSE veneer for that function. The value also controls
whether persistent storage may self-recover from an unknown or corrupt NVM
pool: assembly-and-test and provisioning may reformat, while every other
lifecycle value fails closed.

See [Security Model](Security-Model.md), [Services](Services.md), and [Threat Model](Threat-Model.md) for the security
properties built on this design.

## AArch64 architecture

The AArch64 port replaces Trusted Firmware-A with the FF-A configuration of
an SPMD at EL3, an SPMC at Secure EL1, and Secure Partitions at Secure EL0,
with no Normal-world Hypervisor. [FF-A Compatibility](FF-A-Compatibility.md)
lists the implemented interfaces and the intentional differences.

| Level | Component | Role |
| --- | --- | --- |
| EL3 | Monitor and SPMD (`src/arch/aarch64/el3/`, `ffa/ffa_spmd.c`) | Initializes the GIC and the secure timer, switches worlds, answers PSCI, and relays FF-A calls between the Normal world and the SPMC. Its archive holds no SPM, service, or crypto code. |
| Secure EL1 | SPMC (`src/arch/aarch64/spm/`) | Runs the common runtime (manifest, services, scheduler, FF-M gateway), builds each partition's stage-1 translation table, and implements FF-A messaging, memory sharing, notifications, and interrupt handling. |
| Secure EL0 | Secure Partitions | Each runs under its own stage-1 table and ASID, enters by exception return, and calls the SPMC by SVC. |
| NS-EL1 | Normal world | Calls FF-A by SMC; PSA client calls ride FF-A direct requests to the SPMC's framework endpoint. |

On the QEMU targets, the monitor starts from the reset vector, builds the FF-A
boot-information blob, places the SPMC image in its band, and enters Secure
EL1. The SPMC turns on its MMU, validates the manifest, starts the services,
runs each Secure Partition's initialization at Secure EL0 until it calls
`FFA_MSG_WAIT`, and then completes its own initialization with
`FFA_MSG_WAIT`, after which the monitor launches the Normal world.

A Normal-world PSA call is an FF-A direct request that the SPMD relays to the
SPMC. The SPMC's FF-M gateway validates the handle, copies the caller's
vectors through the Normal-world window, and dispatches the request to the
owning partition; the reply returns as a direct response. Partition stage-1
tables are 4 KB-granule, refuse writable and executable mappings, and map
data execute-never. A partition that touches memory outside its domain takes
a data abort at Secure EL0 and is restarted or quarantined by its manifest
policy.

The secure timer and Secure interrupts are Group 0 and reach the SPMC as FIQs
while Secure code runs. The SPMC signals a Secure interrupt to a waiting
owner and queues it for a running one. A Non-secure interrupt either preempts
the Secure world back to the Normal world or stays pending, per the running
partition's manifest action.
