# wolfTrust CI

Two lanes, modeled on wolfProvider's CI: a fast per-PR host lane, and the
M33MU emulator matrix, tiered: a per-port smoke set on every pull request,
the full matrix on labels, integration pushes, and nightly.

## At a glance

| Tier | Trigger | Purpose |
|------|---------|---------|
| **Fast (per-PR)** | every PR; push to master/main/dev/churn | host unit suites, ISO C99, house style, bare-scope scan, Arm PSA-FF conformance, cross-compile, compiler matrix, sanitizers, valgrind, integrations, core/port split guard |
| **M33MU smoke** | every PR | per port, on both crypto engines: STM32H563 `positive gtzcneg crossdomain bothpsa confboot devcrypto`; MIMXRT700 `positive ahbscneg crossdomain bothpsa` |
| **M33MU full** | PR labels `ci:all`, `ci:h5`, `ci:rt700`; push to master/main/wolfTrust-dev; `cron: 0 8 * * *`; `workflow_dispatch` (port input) | every scenario of that port on both engines (see below) |

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
`master`/`main`/`wolfTrust-dev`, the nightly schedule (via `nightly.yml`), and
manual dispatch (with a `port` input) run the full matrix.

## M33MU matrix

The `select` job fans out into one check per scenario group and engine,
rendered as `M33MU / <port> <name> (<engine>)`. The scenario groups per port
and tier live in `tests/target/lib/scenario_matrix.py`, which `make
test-target` also reads. The table below is a representative slice:

| Check name | Scenario key | What it proves |
|------------|--------------|----------------|
| `wolfBoot signed boot and rollback` | — | upstream wolfBoot signed boot + update/rollback |
| `wolfTrust zephyr lifecycle` | — | full FF-M chain, Zephyr guest |
| `wolfTrust freertos lifecycle` | — | full FF-M chain, FreeRTOS guest |
| `Positive lifecycle` | `positive` | lifecycle green, no faults |
| `Guest restart recovery` | `restart` | guest faults → monitor restarts it |
| `Cross-domain isolation (L3)` | `crossdomain` | SP-internal probe read blocked |
| `FF-M IPC conformance (85/4)` | `confboot` | full Arm FF-M IPC suite |
| `dev_apis Storage (s001-s017)` | `devstorage` | PSA ITS/PS conformance |
| `dev_apis Crypto (c001-c080)` | `devcrypto` | PSA Crypto conformance |
| `Vault recovery self-heal` | `vaultrecover` | #95 foreign pool reformatted |
| `Vault recovery fail-closed` | `vaultrecoversec` | #95 SECURED never wipes |
| `RT700 positive lifecycle (SAU guest windows)` | `positive` | MIMXRT700 chain under the RT700 model, both guests finish |
| `RT700 cross-guest store faults and is contained` | `ahbscneg` | guest0's store into guest1's RAM refused by the SAU, contained |
| `RT700 guest restart budget and launch refusal` | `restart authneg` | guest0's launch-time SecureFault spends its restart budget and quarantines it; a tampered guest0 is refused at launch; guest1 runs on |
| `RT700 SP domain isolation negatives` | `crossdomain keystoreneg` | unprivileged SP reads of SPM RAM and the keystore band MemManage-fault, guests ride it out |
| `RT700 SP fault and panic recovery` | `spfaultneg panicneg` | the relay's undefined instruction and the storage SP's programmer-error close UsageFault once, the SPM restarts the SP in place, both guests finish |
| `RT700 both-guest PSA lifecycle and isolation` | `bothpsa bothiso` | the portable PSA guest in both windows: crypto, storage, keys, attestation, and the FF-M negatives from each |
| `RT700 attestation negatives` | `attestneg` | invalid attestation requests refused, tampered tokens fail the guest verify |
| `RT700 wolfHSM cross-namespace + NVM relay negatives (hsm)` | `hsmattackneg` | a forged client id cannot reach the IAK, an NVM-group packet never reaches the server |
| `RT700 secure verdict negatives` | `rollbackneg manifestneg spbudgetneg` | shared Secure-verdict table: rollback refusal, corrupted manifest, restart budget |

An unlabeled PR runs only each port's smoke tier; the full matrix needs a
`ci:` label. To run a single scenario locally, use `tests/target/run_m33mu_scenario.sh <key>` (the
RT700 checks use `tests/target/run_rt700_m33mu.sh <key>`); to run a port's
full matrix on a PR, add its `ci:` label; off-PR against a branch,
`workflow_dispatch` on `m33mu.yml` with the `port` input.

`nightly.yml` also runs the fast lane + `core-port-split`.

The local box gate `run_m33mu.sh` (a Zephyr+FreeRTOS lifecycle) and the
`make test-target` loop remain the pre-push mirror of the M33MU jobs.

## Host unit suites (per-suite checks)

`unit-tests.yml` reads `UNIT_SUITES` from `tests/host/Makefile` (via
`make -s -C tests/host print-suites`) and fans out one check per suite —
`Unit tests / ffm`, `Unit tests / spm`, `Unit tests / crypto_service`, …
Adding a suite to `UNIT_SUITES` makes it a new CI check automatically; no
workflow edit. The compiler matrix, sanitizers, and valgrind keep running
the aggregate `make test` (one job per compiler/tool) to bound job count.
