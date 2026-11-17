# wolfTrust CI

CI has a fast per-PR host lane, the tiered M33MU emulator matrix, and static
analysis. M33MU runs each port's smoke set on every pull request, except a
port marked label only in [docs/Ports.md](../../docs/Ports.md), and the full
matrix on labels, main pushes, and nightly.

`codeql.yml` runs C security queries. `coverity.yml` runs on Sundays at
00:00 UTC or by manual dispatch. Both build the host suites and secure images
for every registered port with both crypto engines.

Coverity scans wolfTrust runtime, ports, tests, and generated policy code.
`tools/ci-coverity-filter.py` removes dependency source units before upload
and rejects an invalid capture. Keep submodules under `lib/` and enable
**Ignore component in analysis** for the `Third party dependencies` component
(`.*/lib/.*`) in Coverity Scan to exclude dependency headers too.

An accepted upload queues analysis; results appear after Coverity processes it.

## At a glance

| Tier | Trigger | Purpose |
|------|---------|---------|
| **Fast (per-PR)** | every PR; push to main | host unit suites, ISO C99, house style, bare-scope scan, Arm PSA-FF conformance, cross-compile, compiler matrix, sanitizers, valgrind, integrations, core/port split guard |
| **M33MU smoke** | every PR | each port not marked label only, on both crypto engines (its smoke tier in `port.json`) |
| **M33MU full** | PR labels `ci:all`, `ci:m33mu` or a port's own label; push to main; `cron: 0 8 * * *`; `workflow_dispatch` (port input) | every scenario of that port on both engines (see below) |

The M33MU workflow (`m33mu.yml`) is label-selected the way wolfProvider's
`pr-osp-select.yml` is: a `select` job checks the routing table
(`scenario_matrix.py --selftest`), reads the PR's `ci:*` labels, the
event, and the dispatch input, and one matrix job runs exactly the scenario
groups it picked, so a job that is not selected never appears as skipped.

| Label | Effect |
|-------|--------|
| (no label) | the smoke tier of each port not marked label only, on both engines |
| a port's own label | that port's full matrix (the change touched only that port) |
| `ci:all` / `ci:m33mu` | every scenario of every port (a core change) |

A label keeps applying on later pushes to the PR. Pushes to
`main`, the nightly schedule (via `nightly.yml`), and
manual dispatch (with a `port` input) run the full matrix.

## M33MU matrix

The `select` job fans out into one check per scenario group and engine,
rendered wolfBoot-style as `M33MU / <device>_<scenario>_<engine>` (for
example `M33MU / stm32h563_confboot_native`). The scenario groups per port
and tier live in `tests/target/lib/scenario_matrix.py`, which `make
test-target` also reads. Every group also runs on a build profile: jobs on
the lean `default` image carry `_default` before the engine (for example
`stm32h563_positive_default_native`), jobs without it build the `full`
profile. The table below is a representative slice:

| Check name | Scenario key | What it proves |
|------------|--------------|----------------|
| `stm32h563_wolfboot_signed_boot_rollback` | — | upstream wolfBoot signed boot + update/rollback |
| `<port>_positive_<engine>` | `positive` | lifecycle green, no faults |
| `<port>_restart_<engine>` | `restart` | guest faults; the monitor restarts it through its budget |
| `<port>_guestisoneg_<engine>` | `guestisoneg` | guest0's store into guest1's RAM refused by the fabric, contained |
| `<port>_crossdomain_<engine>` | `crossdomain` | SP-internal probe read of SPM RAM blocked |
| `<port>_confboot_<engine>` | `confboot` | the full Arm FF-M IPC suite, 85 pass, 4 heap tests skip |
| `<port>_<group>_<engine>` | the group's keys | every other scenario, packed per port in `port/<port>/port.json` (`m33mu.groups`); the table and every assertion are in `tests/target/lib/scenarios.py` |

The registered ports, their labels and images are in [docs/Ports.md](../../docs/Ports.md).

To run a single scenario locally, use
`tests/target/run_target.sh <port> <key>`; to run a port's
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
