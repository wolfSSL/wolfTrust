# New port playbook

For an agent (or a person) bringing wolfTrust up on a new Armv8-M SoC. The
human guide is [docs/Porting.md](../../docs/Porting.md); this page is the
order of work, the commands that gate each step, the evidence each gate
leaves, and what to stop and ask about. A port that follows it lands with
zero handwritten edits outside its own files.

## Required inputs, or stop

Do not start without every item; guessing a value from another SoC is how a
port claims a security property it does not have.

- The reference manual facts: flash and RAM maps with their Secure aliases,
  sector size and program unit, SAU region count, Secure MPU region count,
  the fabric filter (GTZC, AHBSC, or none), the SPM-only peripheral (the RNG
  or crypto engine) and its Non-secure alias, the console UART and the pins
  the first stage leaves configured, the boot ROM's flash API if the flash is
  driven through it.
- The first stage: a wolfBoot configuration for the part, its image header
  size and sector size for signing, and how the board resets.
- The emulator: whether M33MU models the part (a pinned ref and any carried
  patch), or that the port is hardware-only for now.
- The fixture: the probe (ST-Link serial or MCU-Link unique id), the console
  device, and which option bytes, fuses or life-cycle state the board must be
  in. Never a board whose state you cannot read.

## Forbidden paths

A port PR changes only these: `port/<soc>/`, `mk/target-<soc>.mk`,
`tests/firmware/boards/<soc>/`, `tests/target/ports/<soc>/`,
`tests/target/provisioning/provisioning_ctrl_<soc>.sh`,
`tests/host/port_flash/models/<soc>.*`, its own host suites, `docs/<SOC>-Guide.md`,
and the generated `docs/Ports.md`. `tools/check-port-only-diff.sh --thin <soc>
<base-ref>` refuses anything else. If a shared file seems to need a change, stop and
report what the contract lacks; do not edit `src/`, `include/`,
`port/common/`, `mk/common.mk`, `mk/arch-*.mk`, `tests/target/lib/`,
`tests/target/run_*.sh` or a workflow.

## Files to create

`tools/new-port/new-port.sh <soc> --from <port> --transport stcli|pyocd`
copies the closest registered port under the new name and marks every value
the manual must settle with an `#error` (C) or `NEW_PORT_STUB` (make, shell,
JSON) stub; every provisioning write, the lock included, is replaced by a
refusal. Pick
`--from` by flash and fabric: `stm32h563` (internal flash, GTZC, option-byte
WRP, ST-Link), `mimxrt700` (external XSPI NOR, AHBSC, XSPI fence, MCU-Link),
`mcxn947` (internal flash through the boot ROM API, SAU windows, MCU-Link).

## Gates

Run each gate in order; its last line is the evidence. Do not report a gate
passed on a skip.

| Gate | Command | Passes when |
| --- | --- | --- |
| G0 registry | `tools/new-port/new-port.sh <soc> --check` | `0 stub(s) open, registry ok` |
| G1 build | `make TARGET=<soc> secure-image TOOLPREFIX=arm-none-eabi-` for `WT_ENGINE=native` and `hsm`, then `WT_CONFORMANCE=1` | every link ends with the layout check's `PASS` lines |
| G2 host | `make -C tests/host/port_flash clean run`, the port's RNG model suite, `make test` | `PASS` for every suite, `docs/Ports.md is current` |
| G3 layout | `TOOLPREFIX=arm-none-eabi- tools/check-layout-rebuild.sh <soc>` | `PASS: layout rebuild (<soc>)` |
| G4 emulator smoke | `make test-target TARGET=<soc>` (inside the port's CI image) | `PASS: target/all` |
| G5 emulator full | `WT_TIER=full make test-target TARGET=<soc>` on both engines | `PASS: target/all` twice |
| G6 hardware minimum | `make test-hardware TARGET=<soc>` on the probe host | `PASS: hardware/all` with `logs/<soc>-hw/*/result.json` |
| G7 provisioning | `TARGET=<soc> tests/target/provisioning/provisioning_ctrl.sh status` then `discover` | both exit 0: `status` prints the part's state and identity, `discover` its `PASS` lines; no write |

Evidence per gate: the command's log (keep it under `logs/`), the gate's
last line, and for G4 to G6 the `logs/target-*.log` or evidence directories.
G6 is the contract every board meets (the eight scenarios in
`docs/Porting.md`); a port cannot exempt one of them. Extras go in the
registry as `hardware.qualification` or `hardware.optin`.

## Stop and ask

- Any value the manual does not state plainly (a reserved alias, a sector
  size, an MPU region count); write the `#error` reason instead of a guess.
- Any shared-file change; report what the contract is missing.
- Any `lock`, `WT_PRODUCTION_LOCK=1`, `WT_FIXTURE_BOUND=1`, fuse burn, option
  byte or life-cycle write: never run them; the port author rehearses with
  `advance`/`regress` and a person locks.
- A board whose state `status` cannot read, or a host with more than one
  probe and no `WT_HW_PROBE`.
- A gate that skips (no emulator, no board): say so; a skip is not a pass.

## Never

- Enable a lock write, loosen a gate, or edit a test to make it pass.
- Claim silicon evidence from the emulator, or either from a compile.
- Copy a security claim from another port's guide into the new one.
