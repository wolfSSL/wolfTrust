# wolfTrust for agents

wolfTrust is a TrustZone-M Secure Partition Manager that implements the Arm
Firmware Framework for M-profile (FF-M) and the PSA Crypto, Storage and
Attestation APIs. wolfBoot authenticates it as the first stage; it then runs
Secure Partitions over a wolfCrypt or wolfHSM crypto engine and serves
Non-secure Zephyr, FreeRTOS or bare-metal guests. A shared core runs on
per-SoC ports, listed in [docs/Ports.md](docs/Ports.md). Licensed GPLv3 or
later; submodules under `lib/` keep their own licenses.

If `AGENTS.local.md` or `CLAUDE.local.md` exists in the repository root, read
it first. Those files are gitignored, hold maintainer- and machine-specific
instructions, and take precedence over this file.

## Layout

| Path | Holds |
| --- | --- |
| `src/`, `include/` | the architecture-neutral SPM, services and public headers; `src/arch/<arch>/` the architecture mechanisms |
| `port/<soc>/` | one registered port (`port.json`, memory map, platform hooks, flash and RNG drivers) |
| `port/common/` | what every port shares, `armv8m/` for the Armv8-M layer |
| `mk/` | `common.mk`, `arch-<arch>.mk` and `target-<soc>.mk` build fragments |
| `manifest/` | the partition manifest template and overlays |
| `tests/host/` | native host suites |
| `tests/target/` | the emulator and hardware runners, the scenario table and judge, port profiles, provisioning |
| `tests/firmware/` | the guest images |
| `tools/` | manifest generation, layout checks, guards, the new-port scaffold |
| `lib/` | submodules: wolfSSL, wolfHSM, wolfPSA, wolfCOSE, wolfHAL, wolfIP |
| `docs/` | the version-controlled manual source, with navigation in `mkdocs.yml` |

[docs/Project-Structure.md](docs/Project-Structure.md) has the full map.

## Build

Needs GNU Make, Python 3, the `arm-none-eabi-` toolchain, a native C compiler
for host tests, and the submodules. Submodule URLs use public HTTPS.

```sh
git submodule update --init --recursive
make                                         # STM32H563, native engine
make TARGET=<soc> secure-image               # any port in docs/Ports.md
make secure-image WT_ENGINE=hsm BUILD_DIR=build-hsm
make secure-image TOOLPREFIX=/opt/gcc-arm/bin/arm-none-eabi-
```

The image is `build/wolftrust.elf` and `.bin`, with the CMSE import library
`build/secure_cmse_implib.o` that Non-secure guests link against. Every link
ends with the layout check. Build options are in [docs/Macros.md](docs/Macros.md)
and [docs/Building.md](docs/Building.md).

## Test

| Command | Runs | Where |
| --- | --- | --- |
| `make test` | host suites, registry and scenario self-tests, the assertion mutation test, the scaffold self-test, the guards, the provisioning gates, the hardware runner self-tests | the `wolftrust-ci` image the workflows pin (`docker/wolftrust-ci/`), which carries `expect` for the typed provisioning cases |
| `make c99-check CC=gcc`, `sh scripts/check_house_style.sh`, `python3 scripts/check-empty-brace-scopes.py` | the coding-standard gates | any host |
| `make test-compilers`, `make test-sanitize`, `make test-valgrind` | the host suites under each compiler and checker | any host |
| `make test-target TARGET=<soc>` (`WT_TIER=full`, `WT_ENGINE=hsm`) | M33MU emulator scenarios; `tests/target/run_target.sh <soc> <scenario>` runs one | the port's `wolfboot-ci-m33mu` image from docs/Ports.md; NXP ports also need the MCUXpresso SDK (see the guide) |
| `make test-hardware TARGET=<soc>` | the board scenarios; writes flash and resets the board | the host that owns the probe |

`make test` stops at its first failing step. The emulator and hardware
targets report a skip, never a pass, without their emulator or board. See
[docs/Testing.md](docs/Testing.md).

## Rules

- C99, no `goto`, no standalone `{ }` scope blocks, `/* */` comments,
  `WT_STATIC_ASSERT()` for compile-time checks, sensitive buffers erased:
  [docs/Coding-Standard.md](docs/Coding-Standard.md).
- A new SoC follows [tools/new-port/PLAYBOOK.md](tools/new-port/PLAYBOOK.md).
  A port that needs a shared change (`src/`, `include/`, `port/common/`,
  `mk/common.mk`, `mk/arch-*.mk`, `tests/target/lib/`, the runners, the
  workflows) makes it in the same PR and says why in the description.
- `docs/Ports.md` and the bug report's target list are generated: run
  `python3 tools/gen-port-docs.py`, never edit them by hand.
- `docs/` is published as the manual: `tools/check-docs-no-internal-links.sh`
  refuses internal ledgers and developer paths.
- Evidence is kept apart: a compile is not a test, a skip is not a pass, and
  emulator results are never hardware results.
- Never run `lock`, set `WT_PRODUCTION_LOCK` or `WT_FIXTURE_BOUND`, burn a
  fuse, or write an option byte or life-cycle state. Provisioning writes need
  a person.

## Gotchas

- The containers run as root, so files they write in the checkout are
  root-owned. Drive one checkout through the container only, or clean it
  through the container.
- The build-mode stamp does not record every option (`TOOLPREFIX`,
  `WT_GUEST_FLASH_WRP` and others in docs/Building.md). Use a fresh
  `BUILD_DIR` when changing one of those.
- The Zephyr and FreeRTOS guest builds fetch their sources on first use and
  need network access; the emulator runner fetches pinned M33MU and wolfBoot.
- One hardware run owns a board through `logs/<soc>-hw.lock`. Set
  `WT_HW_PROBE` when the host has more than one probe.
