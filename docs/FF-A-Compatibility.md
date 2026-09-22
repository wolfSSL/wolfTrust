# FF-A Compatibility

wolfTrust implements the Arm Firmware Framework for A-profile (FF-A, DEN0077A
v1.2) needed to run secure partitions on its AArch64 targets, without linking
Trusted Firmware-A, Hafnium, or any other FF-A implementation. The EL3 monitor
is the SPMD, an S-EL1 component is the SPMC, and the secure partitions run at
S-EL0. The Normal world runs without a Hypervisor.

This register describes the code in the repository. It is not a certification
statement. Conformance is measured against the Arm FF-A Architecture Compliance
Suite (ACS), pinned at `tests/upstream/ffa-acs.rev`; the results and the
by-design deviations are below.

## Compatibility register

| Interface or behavior | Version | Status | Repository evidence |
| --- | --- | --- | --- |
| Version negotiation | FF-A 1.2 | `FFA_VERSION` refuses an incompatible version and locks the negotiated one after the caller's first other call | `wt_ffa_version_negotiate` in `include/wolftrust/arch/aarch64/ffa_abi.h` |
| Feature and id discovery | 1.2 | `FFA_FEATURES`, `FFA_ID_GET`, `FFA_SPM_ID_GET` supported; `FFA_FEATURES` reports the schedule-receiver interrupt and the memory-retrieve NS-bit property | `src/arch/aarch64/ffa/ffa_spmd.c`, `src/arch/aarch64/spm/spm_svc_glue.c` |
| Partition discovery | 1.2 | `FFA_PARTITION_INFO_GET` (buffer form) and `FFA_PARTITION_INFO_GET_REGS` (register form), Nil-UUID and by-UUID | `src/arch/aarch64/ffa/ffa_partinfo.c`, `wt_spm_partition_info` |
| RX/TX buffers | 1.2 | `FFA_RXTX_MAP`, `FFA_RXTX_UNMAP`, `FFA_RX_RELEASE`, with per-endpoint RX ownership | mailbox helpers in `src/arch/aarch64/ffa/ffa_mem.c` |
| Direct messaging | 1.2 | `FFA_MSG_SEND_DIRECT_REQ`/`RESP` (32 and 64), `FFA_MSG_SEND_DIRECT_REQ2`/`RESP2`, partition to partition and Normal world to partition | `src/arch/aarch64/ffa/ffa_msg.c`, `src/arch/aarch64/spm/coroutine_aarch64.c` |
| Runtime model | 1.2 | `FFA_MSG_WAIT`, `FFA_RUN`, `FFA_YIELD`, `FFA_NORMAL_WORLD_RESUME`, `FFA_INTERRUPT` | `src/arch/aarch64/ffa/ffa_runtime.c`, `src/arch/aarch64/spm/coroutine_aarch64.c` |
| Console log | 1.2 | `FFA_CONSOLE_LOG` (32 and 64) | `wt_ffa_spmd_console_call`, `ffa_console_log` |
| Memory management | DEN0140 1.2 | Share, lend, and donate; retrieve, relinquish, reclaim; several borrowers, the 1.2 32-byte access descriptor with implementation-defined bytes, permission and type rules, the zero and alignment-hint flags, and the multi-borrower bypass flag | `src/arch/aarch64/ffa/ffa_mem.c`, `src/arch/aarch64/spm/spm_mem.c` |
| Memory permissions | 18.3 | `FFA_MEM_PERM_GET`/`SET` during a partition's initialization | `ffa_mem_perm_get`/`set` in `src/arch/aarch64/spm/spm_svc_glue.c` |
| Boot information | 5.4 | Boot-info blob with an IMPDEF descriptor carrying the wolfBoot handoff | `src/arch/aarch64/ffa/ffa_boot_info.c` |

## Intentional differences

Each row mirrors the deviation grammar of the internal FF-A alignment register.

| Difference | Classification | Reason and impact |
| --- | --- | --- |
| The EL3 monitor time-slices several Normal-world guests and gives each its own endpoint id (`0` for guest 0, `1..` for the rest) rather than the single id 0 the no-Hypervisor configuration assumes. | Scoped product feature | The monitor plays the Hypervisor's id-allocation role of section 6.1; a single-guest system is exactly the spec configuration, which is how the ACS runs. |
| Secure partitions are S-EL0 physical partitions only; there are no S-EL1 or logical partitions, and a single PE (secondaries parked). | Scoped isolation model | `FFA_PARTITION_INFO_GET` reports one execution context per partition; uni-processor migration semantics hold trivially, so the ACS `up_migrate_capable` test skips. |
| `FFA_PARTITION_INFO_GET` does not report a TF-A-style EL3 logical partition. | Scoped configuration | wolfTrust has no EL3 logical partition; the ACS `ffa_partition_info_get_lsp` test looks for one and is a recorded deviation. |
| `FFA_MEM_DONATE` from the Normal world is `NOT_SUPPORTED`; donation is supported between secure partitions. | Scoped | Nothing takes memory away from the Normal world, so it cannot give any away for good; secure-to-secure donation transfers ownership. |
| A secure partition that donates memory keeps its own mapping until the transaction is handed back, and there is no reclaim for a donate. | Implementation detail | Ownership moves in the relayer's records; the physical mapping is not torn down, which keeps a fixed test-buffer pool consistent. Isolation between distinct partitions is unaffected. |
| Memory sharing runs on a fixed, build-sized page pool and handle table with a bounded borrower count; fragmented transfers (`FFA_MEM_FRAG_*`) are not implemented. | Stronger resource policy | The zero-allocation SPM rejects excess work rather than expanding at runtime; exhaustion returns `NO_MEMORY`. Bounds are spec-allowed implementation properties advertised through `FFA_FEATURES`. |
| Indirect messaging (`FFA_MSG_SEND2`) and notifications are not implemented. | Scheduled, not a deviation | Partitions advertise only direct messaging in their properties, so the ACS skips the indirect-messaging tests and the notification group is out of scope; both return `NOT_SUPPORTED` until implemented. |
| The PSA and wolfTrust service protocol rides on direct messaging plus shared regions, and wolfTrust-private partition hypercalls use the SMCCC OEM range. | Scoped product surface | Partition-message payloads are wolfTrust-defined (the spec leaves the payload to the sender and receiver); the private hypercalls are IMPDEF interfaces outside the FF-A function-id ranges. |
| Manifests use the wolfTrust JSON generator and boot information uses an IMPDEF descriptor type. | Integration difference | Allowed by sections 5.2.1 and 5.4; the mandatory partition properties are all present. |

## ACS conformance results

The Arm FF-A ACS runs against the SPMC as a `run_qemu_a_scenario.sh` scenario
per implemented test group, on the three QEMU cells (`virt` GICv2 Cortex-A35,
`virt` GICv3 Cortex-A72, and `versal-virt`), in the `qemu-a-ffa-acs` CI job.

| Group | Result |
| --- | --- |
| `setup_discovery` | 14 passed, 1 skipped (single PE), 1 by-design deviation (`ffa_partition_info_get_lsp`) |
| `direct_messaging` | 3 passed, 3 skipped (indirect messaging not advertised) |
| `memory_management` | 70 passed, 0 failed |

The ACS is a conformance oracle only. It is never a source for the wolfTrust
implementation. A defect in an ACS test itself is corrected by a recorded patch
under `tests/conformance/ffa-acs/patches/`, applied by `build_acs.sh`, and never
by changing wolfTrust to match a wrong expectation. The indirect-messaging,
notification, and interrupt groups are not part of this gate; their tests skip
or are reported by name.
