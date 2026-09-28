# wolfTrust CI

Three lanes, modeled on wolfProvider's CI: a fast per-PR host lane, the M33MU
emulator matrix, and the AArch64 QEMU matrix. Both emulator lanes are tiered: a
smoke set on every pull request, and the full matrix on labels, main pushes,
and nightly.

## At a glance

| Tier | Trigger | Purpose |
|------|---------|---------|
| **Fast (per-PR)** | every PR; push to main | host unit suites, ISO C99, house style, bare-scope scan, Arm PSA-FF conformance, cross-compile, compiler matrix, sanitizers, valgrind, integrations, core/port split guard |
| **M33MU smoke** | every PR | per port, on both crypto engines: STM32H563 `positive gtzcneg crossdomain bothpsa confboot devcrypto`; MIMXRT700 `positive ahbscneg crossdomain bothpsa confboot devcrypto` |
| **M33MU full** | PR labels `ci:all`, `ci:h5`, `ci:rt700`; push to main; `cron: 0 8 * * *`; `workflow_dispatch` (port input) | every scenario of that port on both engines (see below) |

The M33MU workflow (`m33mu.yml`) is label-selected the way wolfProvider's
`pr-osp-select.yml` is: a `select` job checks the routing table
(`scenario_matrix.py --selftest`), reads the PR's `ci:*` labels, the
event, and the dispatch input, and one matrix job runs exactly the scenario
groups it picked, so a job that is not selected never appears as skipped.

| Label | Effect |
|-------|--------|
| (no label) | each port's smoke tier on both engines |
| `ci:h5` | the STM32H563 full matrix (the change touched only that port) |
| `ci:rt700` | the MIMXRT700 full matrix (the change touched only that port) |
| `ci:all` / `ci:m33mu` | every scenario of every port (a core change) |

A label keeps applying on later pushes to the PR. Pushes to
`main`, the nightly schedule (via `nightly.yml`), and
manual dispatch (with a `port` input) run the full matrix.

## M33MU matrix

The `select` job fans out into one check per scenario group and engine,
rendered wolfBoot-style as `M33MU / <device>_<scenario>_<engine>` (for
example `M33MU / stm32h563_confboot_native`). The scenario groups per port
and tier live in `tests/target/lib/scenario_matrix.py`, which `make
test-target` also reads. The table below is a representative slice:

| Check name | Scenario key | What it proves |
|------------|--------------|----------------|
| `stm32h563_wolfboot_signed_boot_rollback` | — | upstream wolfBoot signed boot + update/rollback |
| `stm32h563_zephyr_lifecycle_<engine>` | — | full FF-M chain, Zephyr guest |
| `stm32h563_freertos_lifecycle_<engine>` | — | full FF-M chain, FreeRTOS guest |
| `stm32h563_positive_<engine>` | `positive` | lifecycle green, no faults |
| `stm32h563_restart_<engine>` | `restart` | guest faults → monitor restarts it |
| `stm32h563_crossdomain_<engine>` | `crossdomain` | SP-internal probe read blocked |
| `stm32h563_confboot_<engine>` | `confboot` | full Arm FF-M IPC suite |
| `stm32h563_devstorage_<engine>` | `devstorage` | PSA ITS/PS conformance |
| `stm32h563_devcrypto_<engine>` | `devcrypto` | PSA Crypto conformance |
| `stm32h563_vaultrecover_<engine>` | `vaultrecover` | #95 foreign pool reformatted |
| `stm32h563_vaultrecoversec_<engine>` | `vaultrecoversec` | #95 SECURED never wipes |
| `mimxrt700_positive_<engine>` | `positive` | MIMXRT700 chain under the RT700 model, both guests finish |
| `mimxrt700_ahbscneg_<engine>` | `ahbscneg` | guest0's store into guest1's RAM refused by the SAU, contained |
| `mimxrt700_restart_authneg_<engine>` | `restart authneg` | guest0's launch-time SecureFault spends its restart budget and quarantines it; a tampered guest0 is refused at launch; guest1 runs on |
| `mimxrt700_crossdomain_keystoreneg_<engine>` | `crossdomain keystoreneg` | unprivileged SP reads of SPM RAM and the keystore band MemManage-fault, guests ride it out |
| `mimxrt700_spfaultneg_panicneg_<engine>` | `spfaultneg panicneg` | the relay's undefined instruction and the storage SP's programmer-error close UsageFault once, the SPM restarts the SP in place, both guests finish |
| `mimxrt700_bothpsa_bothiso_<engine>` | `bothpsa bothiso` | the portable PSA guest in both windows: crypto, storage, keys, attestation, and the FF-M negatives from each |
| `mimxrt700_attestneg_fwustage_<engine>` | `attestneg fwustage` | invalid attestation requests refused, tampered tokens fail the guest verify; a candidate stages into the update partition and reject/clean restore READY |
| `mimxrt700_hsmattackneg_hsm` | `hsmattackneg` | a forged client id cannot reach the IAK, an NVM-group packet never reaches the server |
| `mimxrt700_confboot_<engine>` | `confboot` | Arm's unmodified psa-arch-tests IPC suite against the RT700 SPM: 85 pass, 4 heap tests skip |
| `mimxrt700_devstorage_devattest_devattestqcbor_<engine>` | `devstorage devattest devattestqcbor` | PSA ITS/PS and Initial Attestation conformance (the token parses under wolfCOSE's shim and reference QCBOR) |
| `mimxrt700_devcrypto_vaultrecover_vaultrecoversec_<engine>` | `devcrypto vaultrecover vaultrecoversec` | PSA Crypto conformance on wolfPSA; a foreign vault pool self-heals in development and fails closed when SECURED |
| `mimxrt700_rollbackneg_remeasureneg_manifestneg_spbudgetneg_<engine>` | `rollbackneg remeasureneg manifestneg spbudgetneg` | shared Secure-verdict table: rollback refusal, re-measure tamper, corrupted manifest, restart budget |

An unlabeled PR runs only each port's smoke tier; the full matrix needs a
`ci:` label. To run a single scenario locally, use `tests/target/run_m33mu_scenario.sh <key>` (the
RT700 checks use `tests/target/run_rt700_m33mu.sh <key>`); to run a port's
full matrix on a PR, add its `ci:` label; off-PR against a branch,
`workflow_dispatch` on `m33mu.yml` with the `port` input.

`nightly.yml` also runs the fast lane + `core-port-split`.

The local box gate `run_m33mu.sh` (a Zephyr+FreeRTOS lifecycle) and the
`make test-target` loop remain the pre-push mirror of the M33MU jobs.

## AArch64 QEMU

`aarch64-cross-compile.yml` (workflow name **AArch64 cross compilation**) runs
in `ghcr.io/wolfssl/wolfboot-ci-aarch64` on three cells, `virt-gicv2-a35`,
`virt-gicv3-a72`, and `versal-virt`, each under `native` and `hsm`:

| Check name | What it proves |
|------------|----------------|
| `EL3 smoke on <cell> (<engine>)` | the EL3 image links under the symbol guard, then every QEMU AArch64 scenario runs through `tests/target/run_suite.sh qemu-a` |
| `FF-A ACS on <cell> (<engine>)` | the Arm FF-A ACS groups (discovery, direct and indirect messaging, memory, notifications, interrupts) at their asserted floors |

To run a scenario locally, use `tests/target/run_qemu_a_scenario.sh <key>`
with `MACHINE`, `GIC`, `CPU`, and `WT_ENGINE` set as in the workflow.

## Host unit suites (per-suite checks)

`unit-tests.yml` reads `UNIT_SUITES` from `tests/host/Makefile` (via
`make -s -C tests/host print-suites`) and fans out one check per suite —
`Unit tests / ffm`, `Unit tests / spm`, `Unit tests / crypto_service`, …
Adding a suite to `UNIT_SUITES` makes it a new CI check automatically; no
workflow edit. The compiler matrix, sanitizers, and valgrind keep running
the aggregate `make test` (one job per compiler/tool) to bound job count.
