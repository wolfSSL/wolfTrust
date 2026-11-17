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

## Shared paths

A port PR mostly changes the paths in the "Add a target" table of
[docs/Porting.md](../../docs/Porting.md#add-a-target). When the port needs a
shared file changed, make the change generic, keep every other port's tests
passing, and say why in the PR description.

## Files to create

`tools/new-port/new-port.sh <soc> --from <port> --transport stcli|pyocd`
copies the closest registered port under the new name and marks every value
the manual must settle with an `#error` (C) or `NEW_PORT_STUB` (make, shell,
JSON) stub; every provisioning write, the lock included, is replaced by a
refusal. Pick
`--from` by flash and fabric: `stm32h563` (internal flash, GTZC, option-byte
WRP, ST-Link), `mimxrt700` (external XSPI NOR, AHBSC, XSPI fence, MCU-Link),
`mcxn947` (internal flash through the boot ROM API, SAU windows, MCU-Link).
The board guide starts from `tools/new-port/templates/Guide.md`, never from
another port's guide.

## Gates

Run gates G0 to G7 of the [bring-up ladder](../../docs/Porting.md#bring-up-ladder)
in order. Keep each command's log under `logs/` with its last line, and do not
report a gate passed on a skip.

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
