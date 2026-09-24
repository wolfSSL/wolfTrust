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
| Version negotiation | FF-A 1.2 | `FFA_VERSION` answers a compatible or later version with 1.2 and refuses one below major 1, and locks the version the caller settles on after its first other call | `wt_ffa_version_negotiate` in `include/wolftrust/arch/aarch64/ffa_abi.h` |
| Feature and id discovery | 1.2 | `FFA_FEATURES`, `FFA_ID_GET`, `FFA_SPM_ID_GET` supported; `FFA_FEATURES` reports the schedule-receiver interrupt, the memory-retrieve NS-bit property, and a partition's one-page RX/TX buffer limit | `src/arch/aarch64/ffa/ffa_spmd.c`, `src/arch/aarch64/spm/spm_svc_glue.c` |
| Partition discovery | 1.2 | `FFA_PARTITION_INFO_GET` (buffer form) and `FFA_PARTITION_INFO_GET_REGS` (register form), Nil-UUID and by-UUID; each partition is listed under its live endpoint id with the properties it really has, so a PSA partition, whose services are reached through the PSA framework endpoint and the FF-M gate, advertises only its AArch64 execution state | `src/arch/aarch64/ffa/ffa_partinfo.c`, `wt_spm_partition_info` |
| RX/TX buffers | 1.2 | `FFA_RXTX_MAP`, `FFA_RXTX_UNMAP`, `FFA_RX_RELEASE`, with per-endpoint RX ownership | mailbox helpers in `src/arch/aarch64/ffa/ffa_mem.c` |
| Direct messaging | 1.2 | `FFA_MSG_SEND_DIRECT_REQ`/`RESP` (32 and 64), `FFA_MSG_SEND_DIRECT_REQ2`/`RESP2`, partition to partition and Normal world to partition; a request to an endpoint that does not take that kind of request, or from a partition that does not advertise sending it, is `DENIED`, one to an id that names no endpoint `INVALID_PARAMETERS` | `src/arch/aarch64/ffa/ffa_msg.c`, `src/arch/aarch64/spm/coroutine_aarch64.c` |
| Runtime model | 1.2 | `FFA_MSG_WAIT`, `FFA_RUN`, `FFA_YIELD`, `FFA_NORMAL_WORLD_RESUME`, `FFA_INTERRUPT` | `src/arch/aarch64/ffa/ffa_runtime.c`, `src/arch/aarch64/spm/coroutine_aarch64.c` |
| Console log | 1.2 | `FFA_CONSOLE_LOG` (32 and 64) | `wt_ffa_spmd_console_call`, `ffa_console_log` |
| Memory management | DEN0140 1.2 | Share, lend, and donate; retrieve, relinquish, reclaim; several borrowers, the 1.2 32-byte access descriptor with implementation-defined bytes, permission and type rules, the zero and alignment-hint flags, and the multi-borrower bypass flag; a caller that negotiated v1.0 is read and answered in the v1.0 descriptor layout, and told the NS bit only if its `FFA_FEATURES` asked for it | `src/arch/aarch64/ffa/ffa_mem.c`, `src/arch/aarch64/spm/spm_mem.c` |
| Fragmented memory transmission | DEN0140 4.1.2 | `FFA_MEM_FRAG_TX`/`FRAG_RX` for share, lend, donate, and retrieve requests from partitions and the Normal world; the handle is reserved with the first fragment and names the region once the descriptor is whole | `wt_ffa_mem_frag_*` in `src/arch/aarch64/ffa/ffa_mem.c`, `wt_spm_mem_frag_*` in `src/arch/aarch64/spm/spm_mem.c` |
| Notifications | 1.2 Ch.10 | Bitmap create and destroy, bind and unbind, set and get for partition, VM, and framework sources, `FFA_NOTIFICATION_INFO_GET`, and the schedule-receiver interrupt (SGI 8) | `src/arch/aarch64/ffa/ffa_notif.c`, `src/arch/aarch64/spm/spm_main.c` |
| Indirect messaging | 1.2 | `FFA_MSG_SEND2` from either world into the receiver's RX buffer, with the RX-buffer-full framework notification and per-partition receive properties | `src/arch/aarch64/ffa/ffa_msg.c`, `wt_spm_msg2_deliver` |
| Interrupts | 1.2 Ch.9 | Secure interrupts signaled to a waiting owner and queued for a running or blocked one (delivered as `FFA_INTERRUPT`); Non-secure interrupts preempt a partition whose manifest signals them and stay pending for one that queues them; GICv2 and GICv3 | `src/arch/aarch64/spm/spm_irq.c`, `src/arch/aarch64/spm/coroutine_aarch64.c` |
| Memory permissions | 18.3 | `FFA_MEM_PERM_GET`/`SET` during a partition's initialization | `ffa_mem_perm_get`/`set` in `src/arch/aarch64/spm/spm_svc_glue.c` |
| Boot information | 5.4 | Boot-info blob with an IMPDEF descriptor carrying the wolfBoot handoff | `src/arch/aarch64/ffa/ffa_boot_info.c` |
| Power management | PSCI 1.1 (DEN0022D.b) | The mandatory set for a Normal world on the boot core: `CPU_SUSPEND` (core standby), `CPU_OFF` (`DENIED`: the uniprocessor SPMC is resident), `CPU_ON`/`AFFINITY_INFO` (the Normal world's machine view, DEN0022 4.4, is the boot core alone: it is `ON`, and every other MPIDR, including a secondary the monitor keeps parked, is `INVALID_PARAMETERS`), `MIGRATE`/`MIGRATE_INFO_TYPE`/`MIGRATE_INFO_UP_CPU` (uniprocessor, not migrate capable), `SYSTEM_OFF`, `SYSTEM_RESET` (a machine cold reset through the port's reset hook; `virt` drives its Secure PL061 restart line), `PSCI_FEATURES` | `src/arch/aarch64/el3/psci.c` |
| SMC calling convention | SMCCC 1.2 (DEN0028) | `SMCCC_VERSION` reports 1.2 (discoverable through `PSCI_FEATURES`) and `SMCCC_ARCH_FEATURES` answers for itself and `SMCCC_VERSION` only, to a caller in either world; calls that return only `x0` preserve `x4`-`x17`; an SMC32 call is read as `w1`-`w7`; an AArch32 Normal-world EL1 beneath an NS-EL2 payload makes SMC32 calls as `R0`-`R7`, and an SMC64 id from it is unknown; unknown function ids return `-1`, sign-extended; wolfTrust's private monitor and SVC calls sit in the OEM range with the MBZ bits clear | `src/arch/aarch64/el3/monitor_calls.c`, `include/wolftrust/arch/aarch64/monitor_abi.h` |

## Intentional differences

Each row mirrors the deviation grammar of the internal FF-A alignment register.

| Difference | Classification | Reason and impact |
| --- | --- | --- |
| The EL3 monitor time-slices several Normal-world guests and gives each its own endpoint id (`0` for guest 0, `1..` for the rest) rather than the single id 0 the no-Hypervisor configuration assumes. | Scoped product feature | The monitor plays the Hypervisor's id-allocation role of section 6.1; a single-guest system is exactly the spec configuration, which is how the ACS runs. |
| Secure partitions are S-EL0 physical partitions only; there are no S-EL1 or logical partitions, and a single PE (secondaries parked). | Scoped isolation model | `FFA_PARTITION_INFO_GET` reports one execution context per partition; uni-processor migration semantics hold trivially, so the ACS `up_migrate_capable` test skips. |
| `FFA_PARTITION_INFO_GET` does not report a TF-A-style EL3 logical partition. | Scoped configuration | wolfTrust has no EL3 logical partition; the ACS `ffa_partition_info_get_lsp` test looks for one and is a recorded deviation. |
| A secure partition that donates memory loses its own EL0 access to it when it sends the donate, and may reclaim it until the receiver retrieves it; the retrieve completes the transfer and frees the handle. | Implementation detail | The donor's page entries are held EL1-only rather than unmapped, so a reclaim before retrieval restores each one exactly; DEN0140 1.9.2 frees a donate's handle at the end of a successful retrieval. |
| Memory a partition owns, including memory donated to it, stays with that partition's slot when it faults and is restarted. | Known limitation (Low) | DEN0140 1.3.1 rule 9 (access to a terminated SP's memory passes to the SPM) is not modelled: faulting releases what the partition borrowed and ends what it lent, but not what it owns. |
| Memory sharing runs on a fixed, build-sized page pool and handle table with a bounded borrower count, and a fragmented descriptor reassembles into one page with one transfer in flight per sender. | Stronger resource policy | The zero-allocation SPM rejects excess work rather than expanding at runtime; exhaustion returns `NO_MEMORY`. A declared total that the first fragment's own headers contradict is `INVALID_PARAMETERS` before any handle is reserved. |
| Borrowers map shared and lent memory only as Normal write-back inner-shareable memory. A lend or share naming Device, non-cacheable, or non-shareable memory is `INVALID_PARAMETERS`, as is a retrieve request asking for non-cacheable or non-shareable memory; outer-shareable memory, a retrieve request for Device memory, and a send of the sender's own Device pages, is `DENIED`. | Implementation detail | DEN0140 1.10.4.2 item 5 lets the relayer refuse less permissive attributes it will not map, and items 1 and 2 deny more permissive ones. A lend to one borrower or a donate leaves the attributes to the relayer, and every retrieve response reports the ones the borrower was mapped with. |
| A retrieve response is never sent in fragments, so `FFA_MEM_FRAG_RX` from a borrower is `INVALID_PARAMETERS`. | Implementation detail | The largest descriptor the relayer holds fits every RX buffer, so no response fragment is ever outstanding. |
| Managed exit is not offered; a partition's Non-secure interrupt action is either signaled or queued. | Scoped isolation model | Managed exit applies to S-EL1 partitions; every wolfTrust partition runs at S-EL0. A queued partition runs with the GIC priority mask at the top of the Non-secure range, so Secure interrupts still reach it. |
| The RX-buffer-full framework notification is set in the SPM half for a Secure sender and in the Hypervisor half for a Normal-world sender, and `FFA_NOTIFICATION_GET` returns and clears each half only when its own flag asks for it. | Interpretation | Section 10.8.1 pends a VM sender's RX-buffer-full in the Hypervisor framework bitmap, and section 16.6 says a caller ignores w7 unless it set the Hypervisor flag. Three ACS receivers asked for the SPM half only and then read w7; patch 0011 corrects them. |
| The PSA and wolfTrust service protocol rides on direct messaging plus shared regions, and wolfTrust-private partition hypercalls use the SMCCC OEM range. | Scoped product surface | Partition-message payloads are wolfTrust-defined (the spec leaves the payload to the sender and receiver); the private hypercalls are IMPDEF interfaces outside the FF-A function-id ranges. |
| Manifests use the wolfTrust JSON generator and boot information uses an IMPDEF descriptor type. | Integration difference | Allowed by sections 5.2.1 and 5.4; the mandatory partition properties are all present. |

## ACS conformance results

The Arm FF-A ACS runs against the SPMC as a `run_qemu_a_scenario.sh` scenario
per implemented test group, on the three QEMU cells (`virt` GICv2 Cortex-A35,
`virt` GICv3 Cortex-A72, and `versal-virt`), in the `qemu-a-ffa-acs` CI job.

| Group | Result |
| --- | --- |
| `setup_discovery` | 14 passed, 1 skipped (single PE), 1 by-design deviation (`ffa_partition_info_get_lsp`) |
| `direct_messaging` | 5 passed, 1 skipped |
| `memory_manage` | 70 passed, 0 failed |
| `notifications` | 10 passed |
| `indirect_messaging` | 2 passed |
| `interrupts` | 6 passed (every test that applies to S-EL0 partitions) |

The ACS is a conformance oracle only. It is never a source for the wolfTrust
implementation. A defect in an ACS test itself is corrected by a recorded patch
under `tests/conformance/ffa-acs/patches/`, applied by `build_acs.sh`, and never
by changing wolfTrust to match a wrong expectation. The tests the ACS marks
unverified upstream (`ACS_FFA_UNVERIFIED`) and the S-EL1-partition tests do not
run in this configuration.

The pinned ACS has no fragmented-transmission tests, so `FFA_MEM_FRAG_TX`/
`FRAG_RX` are proven by the host suite (`tests/host/ffa_mem`, every split point)
and by the `ffa-memneg` scenario, where the Normal world sends a share in two
fragments.

| Patch | Why |
| --- | --- |
| 0001 | `up_migrate_capable` is not applicable on a single-PE platform. |
| 0002 | A memory test read its handle after `FFA_FEATURES` had overwritten it. |
| 0003 | Memory-region requests were filled without first clearing them. The three `*_retrieve_with_address_range` servers cleared theirs only after setting the alignment-hint flag, erasing it, so the flag is now set after the clear. |
| 0004 | The platform describes its own endpoint properties. |
| 0005 | The build forwards the partition-message UUID field setting. |
| 0006 | An indirect-messaging test packed physical endpoint ids into logical-id fields. |
| 0007 | GICv2 initialization never probed the CPU interface id (GICv3 only), so every interrupt test asserted during setup. |
| 0008 | `sp_el0_blocked` packed physical endpoint ids into logical-id fields. |
| 0009 | A platform may time S-EL0 partition waits on the virtual counter instead of a loop calibrated for another platform. |
| 0010 | `sp_preempted_el0` set its keep-the-RX-buffer flag after `FFA_MSG_WAIT` instead of before. |
| 0011 | `direct_msg_sp_to_vm`, `ffa_msg_send2` and `ffa_msg_send2_uuid_check` read a VM sender's RX-buffer-full from w7 after an `FFA_NOTIFICATION_GET` that asked only for the SPM framework bitmap. Section 10.8.1 pends that notification in the Hypervisor framework bitmap, and section 16.6 says w7 is ignored unless the Hypervisor flag is set, so they now ask with the Hypervisor flag. |
| 0012 | `ffa_direct_message_error` and `ffa_direct_message_error1` passed the sender's logical id OR-ed with the receiver's id shifted left into the logical-id lookup, reading far past the endpoint table, instead of packing the sender's endpoint id over the receiver's. They now pack the ids as `ffa_msg_send_error` does. |
| 0013 | Thirteen multi-borrower servers named every borrower in their retrieve request with the Non-retrieval Borrower flag clear, asking the relayer to retrieve on the other borrower's behalf. DEN0140 Table 1.17 sets the flag for each other borrower and 1.10.1 makes a wrong encoding INVALID_PARAMETERS, so each server now sets it on every entry but its own. |
| 0014 | `ffa_version` expected `NOT_SUPPORTED` for a caller asking a later minor (1.4) or major (2.2). Section 13.2.2 requires a callee at a lesser version than the caller to return its highest version, so both now expect 1.2. |
