# wolfTrust

wolfTrust is a Secure Partition Manager (SPM) and secure-services runtime for
Arm Cortex-M and Cortex-A targets. It separates reusable policy and service
code from architecture- and target-specific execution and protection code. The
common runtime implements Arm Platform Security Architecture (PSA) Firmware
Framework for M (FF-M) interprocess communication (IPC), manifest policy,
scheduling, lifecycle management, fault recovery, and services.

Two architecture ports share that runtime:

- **Armv8-M** with the STM32H563 Cortex-M33 port, the reference
  implementation validated on hardware.
- **AArch64** (Cortex-A), a Trusted Firmware-A replacement: an EL3 monitor
  that is the Arm Firmware Framework for A-profile (FF-A) Secure Partition
  Manager Dispatcher (SPMD), a Secure EL1 Secure Partition Manager Core (SPMC)
  that runs the same common runtime, and Secure Partitions at Secure EL0.
  Normal-world clients reach the services over FF-A v1.2. This port is
  validated under QEMU on `virt` (GICv2 and GICv3) and `xlnx-versal-virt`; no
  Cortex-A silicon port is validated yet. See
  [FF-A Compatibility](FF-A-Compatibility.md).

Both ports keep the public manifest, service, IPC, and PSA API contracts;
AArch64 manifests add an optional FF-A section. Additional Cortex-M and
Cortex-A ports are an intended extension point.

## Architecture

```mermaid
flowchart TB
    BOOT[Trusted first-stage loader<br/>Armv8-M reference: wolfBoot]

    subgraph APP[Application domains]
        GA[Client A<br/>Cortex-M guest or Cortex-A Normal world]
        GB[Client B<br/>Cortex-M guest or Cortex-A Normal world]
    end

    subgraph PORT[Architecture and target ports]
        GW[Client gateway<br/>Armv8-M: five CMSE veneers<br/>AArch64: FF-A through the EL3 SPMD]
        ARCH[Architecture adapter<br/>Armv8-M, or AArch64 EL3 SPMD and Secure EL1 SPMC]
        TARGET[Target and board port<br/>STM32H563; QEMU virt and Versal]
        GW --- ARCH
        ARCH --- TARGET
    end

    subgraph WT[wolfTrust policy and service runtime]
        SPM[Secure Partition Manager<br/>policy, identity, IPC, scheduling, lifecycle, recovery]
        subgraph SP[Secure services]
            CR["Selected crypto engine<br/>native or wolfHSM"]
            ST["Internal Trusted Storage (ITS),<br/>Protected Storage, and vault"]
            AT[Initial Attestation]
            FW[Firmware Update]
            VN[Optional virtual networking]
        end
        SPM --> CR
        SPM --> ST
        SPM --> AT
        SPM --> FW
        SPM --> VN
    end

    subgraph LIBS[wolfSSL ecosystem components]
        PSA[wolfPSA<br/>guest wolfCrypt; optional wolfHSM client]
        WC[Secure wolfCrypt<br/>optional wolfHSM server]
        COSE[wolfCOSE]
        HAL[wolfHAL]
        IP[wolfIP<br/>optional bare-metal reference networking]
    end

    BOOT -->|authenticated measurement, lifecycle, and version handoff| SPM
    GA -->|generic FF-M client API| GW
    GB -->|generic FF-M client API| GW
    GA -->|PSA Crypto| PSA
    GB -->|PSA Crypto| PSA
    PSA -->|protected operations over FF-M| GW
    GA -->|optional networking| IP
    GB -->|optional networking| IP
    IP -->|VNet service over FF-M| GW
    GW -->|validated requests| SPM
    SPM -->|Secure execution operations| ARCH
    SPM -->|platform callbacks| TARGET
    CR --> WC
    ST --> WC
    AT --> COSE
    AT --> WC
    TARGET -->|STM32H563 register and RNG access| HAL
```

### Current reference ports

In the STM32H563 reference chain, wolfBoot authenticates wolfTrust, TrustZone
isolates the Secure runtime from Non-secure guests, and STM32 Global TrustZone
Controller (GTZC) memory attribution isolates guest RAM. The Zephyr and
FreeRTOS reference guests use wolfPSA's PSA Crypto API through the Armv8-M
port's five CMSE gateway veneers.

On the QEMU AArch64 cells, the EL3 monitor boots first, programs the GIC, and
enters the Secure EL1 SPMC, which runs each Secure Partition at Secure EL0
under its own stage-1 translation table. A Normal-world payload at NS-EL1
reaches the services through FF-A direct requests that carry the PSA client
calls. No wolfBoot AArch64 port exists yet, so these targets have no
authenticated boot or boot handoff record; the handoff region is empty and
the services that depend on it fail closed.

## Key Features

| Feature | Description |
| --- | --- |
| Authenticated chain | The boot port supplies authenticated measurement, lifecycle, and version data. The reference integration uses wolfBoot and signature-covered guest records. |
| One mediated client boundary | Application domains reach services only through the client gateway supplied by the architecture port. The current Armv8-M image exports exactly five `WolfTrust_FFM_*` veneers; on AArch64 the Normal world reaches services only through FF-A calls that the EL3 SPMD relays to the SPMC. |
| Caller-bound IPC | wolfTrust derives the PSA client identity from the active application domain, copies vector descriptors, checks every range, and enforces manifest access policy. |
| Port-defined isolation | Each port declares and enforces the protection capabilities required by its manifest. The STM32H563 reference uses TrustZone, the Secure MPU, and GTZC MPCBB attribution; its exact limits are documented in [Security Model](Security-Model.md). The AArch64 port runs each Secure Partition at Secure EL0 under its own stage-1 translation table, refusing writable and executable mappings. |
| PSA cryptography | Zephyr and FreeRTOS reference guests call wolfPSA's PSA Crypto API. The default native engine runs wolfCrypt in each guest and obtains DRBG seeds from the Secure vault; the optional wolfHSM engine routes supported operations to per-guest Secure server namespaces. |
| Secure services | Connection-based services provide the selected crypto engine, attestation, Internal Trusted Storage (ITS), Protected Storage, firmware update, and an optional Secure virtual Ethernet switch. The optional bare-metal networking guests run wolfIP outside the Secure image. |
| Fault containment | A guest fault either restarts the guest within policy limits or leaves it quarantined. A Secure Partition fault releases synchronization state before failing affected calls. Restart paths scrub declared private writable memory before rearming; forbidden, exhausted, or failed recovery escalates to the port's fail-closed path. |
| Static Secure memory | The Secure image is built with `WOLFSSL_NO_MALLOC` and `NO_WOLFSSL_MEMORY`; service buffers, stacks, and state are statically allocated. |

## Documentation

| Page | Contents |
| --- | --- |
| [Getting Started](Getting-Started.md) | Prerequisites, checkout, first builds, emulator use, and hardware entry points |
| [Architecture](Architecture.md) | Boot flow, isolation layers, FF-M IPC, services, and scheduling |
| [Crypto Engines](Crypto-Engines.md) | Native and wolfHSM engine behavior, selection, key models, and measured cost |
| [Security Model](Security-Model.md) | Trust boundaries and enforced security properties |
| [Threat Model](Threat-Model.md) | Protected assets, attacker capabilities, controls, and residual risks |
| [API Reference](API-Reference.md) | PSA client, service, storage, update, lifecycle, attestation, and gateway APIs |
| [Services](Services.md) | Behavior and access policy for each Secure service |
| [TF-M Compatibility](TF-M-Compatibility.md) | Supported interfaces, intentional differences, and migration guidance |
| [FF-A Compatibility](FF-A-Compatibility.md) | The AArch64 FF-A interface register, intentional differences, and Arm FF-A ACS results |
| [Macros](Macros.md) | Supported build and manifest configuration |
| [Porting](Porting.md) | Architecture and target port contracts |
| [Building](Building.md) | Build targets, outputs, and cross-build options |
| [Testing](Testing.md) | Host, M33MU, QEMU AArch64, and STM32H563 validation |
| [Project Structure](Project-Structure.md) | Repository layout |
| [STM32H5 Guide](STM32H5-Guide.md) | STM32H563 provisioning, flashing, WRP, and recovery safety |
