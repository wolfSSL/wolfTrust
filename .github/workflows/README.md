# wolfTrust CI

Two lanes, modeled on wolfProvider's CI: a fast per-PR host lane, and the
full M33MU emulator matrix, which runs on every pull request (and nightly).

## At a glance

| Tier | Trigger | Purpose |
|------|---------|---------|
| **Fast (per-PR)** | every PR; push to master/main/dev/churn | host unit suites, ISO C99, house style, bare-scope scan, Arm PSA-FF conformance, cross-compile (Cortex-M33), compiler matrix, sanitizers, valgrind, integrations, core/port split guard |
| **M33MU matrix** | every PR; push to master/main/wolfTrust-dev; `cron: 0 8 * * *`; `workflow_dispatch` | full M33MU emulator matrix (see below) |
| **AArch64 QEMU** | every PR; push to master/main/wolfTrust-dev/wolfTrust-dev2; `workflow_dispatch` | EL3 monitor and SPMC build with the EL3 symbol guard, every QEMU AArch64 scenario, and the Arm FF-A ACS groups, on three QEMU cells under both crypto engines (see below) |

The M33MU workflow (`m33mu.yml`) runs the full matrix on every pull request,
on push to `master`/`main`/`wolfTrust-dev`, on the nightly schedule (via
`nightly.yml`), and on manual dispatch.

## M33MU matrix

`m33mu.yml` (workflow name **M33MU**) fans out into one named check per test —
each renders as `M33MU / <name>`. The table below is a representative slice; the
full scenario list lives in the `matrix` of `m33mu.yml`:

| Check name | Scenario key | What it proves |
|------------|--------------|----------------|
| `M33MU / wolfBoot signed boot and rollback` | — | upstream wolfBoot signed boot + update/rollback |
| `M33MU / wolfTrust zephyr lifecycle` | — | full FF-M chain, Zephyr guest |
| `M33MU / wolfTrust freertos lifecycle` | — | full FF-M chain, FreeRTOS guest |
| `M33MU / Positive lifecycle` | `positive` | lifecycle green, no faults |
| `M33MU / Guest restart recovery` | `restart` | guest faults → monitor restarts it |
| `M33MU / Cross-domain isolation (L3)` | `crossdomain` | SP-internal probe read blocked |
| `M33MU / FF-M IPC conformance (85/4)` | `confboot` | full Arm FF-M IPC suite |
| `M33MU / dev_apis Storage (s001-s017)` | `devstorage` | PSA ITS/PS conformance |
| `M33MU / dev_apis Crypto (c001-c080)` | `devcrypto` | PSA Crypto conformance |
| `M33MU / Vault recovery self-heal` | `vaultrecover` | #95 foreign pool reformatted |
| `M33MU / Vault recovery fail-closed` | `vaultrecoversec` | #95 SECURED never wipes |

Every job runs automatically on every PR — no labels, nothing to add. To run a
single scenario locally, use `tests/target/run_m33mu_scenario.sh <key>`; to run
the whole matrix off-PR against a branch, `workflow_dispatch` on `m33mu.yml`.

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
