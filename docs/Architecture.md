# Architecture

wolfTrust places a Secure Partition Manager between a trusted bootloader and
one or more application domains. Reusable policy and service code manages
manifest policy, identity, FF-M IPC, scheduling, lifecycle, recovery, and
Secure service dispatch. Architecture and target ports provide the execution,
memory-protection, interrupt, storage, entropy, and boot mechanisms needed to
enforce that policy.

Two architecture ports run the same policy and service code. The Armv8-M
adapter with the STM32H563 port is the reference implementation validated on
hardware; its default configuration runs one Non-secure guest on one
Cortex-M33 (two with `WT_MAX_GUESTS=2`, as the `full` build profile does) and
exposes Secure services through FF-M IPC. The AArch64 adapter replaces Trusted
Firmware-A on Cortex-A and is validated under QEMU; see
[AArch64 architecture](#aarch64-architecture). The boot flow, isolation, and
scheduling sections below describe the Armv8-M reference port.

## Software stack

| Layer | Role |
| --- | --- |
| wolfBoot | Performs the BL2 secure-boot role, authenticates wolfTrust, passes the measured-boot handoff, and swaps authenticated update images. |
| wolfTrust | Configures isolation, validates the manifest at build time and the guest images at boot, schedules guests and Secure Partitions, implements FF-M IPC, and manages lifecycle and recovery. |
| wolfPSA | Implements PSA Crypto entry points over wolfCrypt: in the crypto partition by default (`WT_SECURE_PSA=1`), or in the Non-secure guests with `WT_SECURE_PSA=0` or the wolfHSM engine. |
| wolfCrypt | Supplies cryptographic implementations used by wolfPSA and Secure services. The native engine dispatches it directly and, by default, backs wolfPSA in the crypto partition. |
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
   and memory policies; binds the generated manifest, which the build has
   already validated against the port's capabilities; registers
   the FF-M services; seeds each guest context; and performs an initial
   signed-record, image-size, manifest-version, digest, and optional WRP check.
3. wolfTrust consumes the measured-boot handoff, initializes the selected
   [crypto engine](Crypto-Engines.md) and shared persistent vault backend, and
   checks the persistent Secure-image and guest version floors.
4. wolfTrust starts the scheduled Secure Partitions, runs each one from its
   entry point to its first wait, and drains partition-to-partition IPC until
   all are idle. A partition that faults, or stops anywhere but `psa_wait`,
   refuses boot.
5. Before an accepted guest's first dispatch, the monitor installs that
   guest's active GTZC, Non-secure MPU, and interrupt policy. With two guests
   (`WT_MAX_GUESTS=2`) it first repeats its signed-record, image-size,
   manifest-version, digest, and optional WRP checks, because the other guest
   may have run in between.
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
guest can read peer flash. Hardware write protection (STM32 WRP or the
MIMXRT700 guest fence) plus `WT_GUEST_FLASH_WRP=1` protects guest-flash
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
`N` as PSA client ID `-(N + 1)`. The connect, call, and close veneers mask every
Non-secure exception (Secure `BASEPRI` at the Non-secure priority floor) for
the length of the entry, so a guest handler cannot re-enter the FF-M core
mid-call; the Secure timer, Secure interrupts, and faults stay above the mask.
The caller's Non-secure interrupts, its SysTick and PendSV included, wait for
the call to return, so a long FF-M call (a large crypto operation, for one)
adds its length to that guest's interrupt latency.
An entry that still arrives while another is in flight means that mask failed,
and the gateway stops the system rather than re-enter the core. Handles carry
ownership and generation state, and the SPM rejects stale, cross-owner, or invalid
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

A Secure Partition fault first releases held synchronization state, completes
its pinned client calls with a communication failure, and releases every
connection the partition held as a client. If policy selects a restart,
wolfTrust clears the partition's stack, returns its data band to its link-time
image, and rebuilds the band from inputs the SPM holds before rearming the
partition. A forbidden or exhausted restart, or a failed rearm, escalates to
the port's fail-closed path.

## Guests and lifecycle

The monitor time-slices the configured Non-secure guests. The Secure SysTick,
PendSV, and Secure interrupts run at a priority above the Non-secure range
(`AIRCR.PRIS` set), so Non-secure `PRIMASK`, `BASEPRI`, or `FAULTMASK` cannot
stop the slice, and each guest's masks are saved and restored with its context.
A guest that stays in a Non-secure handler for `WT_GUEST_HANDLER_SLICE_LIMIT`
consecutive slices, counting Secure calls it makes from that handler, is
restarted under its policy, and its Non-secure system handler activations are
cleared. Armv8-M keeps an external interrupt's active bit read-only, so an
external IRQ the guest abandoned is retired by an exception return on the next
exit to a guest whose `FAULTMASK_NS` is clear; until then it can hold off
Non-secure interrupts of equal or lower priority. A guest fault clears the
same handler state, masks its interrupts and applies the restart policy. If
restart is allowed, wolfTrust clears restart-marked RAM and restores a clean
context after a bounded delay; if the budget is exhausted, the guest remains
faulted. Runtime remeasurement can also quarantine a guest without entering it.

When no guest is runnable but recovery is pending, the monitor idles in
Secure Thread mode so Secure SysTick can finish the backoff. It halts only
when every guest is faulted or stopped.

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
