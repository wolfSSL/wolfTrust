# Provisioning

Provisioning takes a wolfTrust part from development to production. You flash
the production images, set the protections the part ships with, and move its
life cycle forward until debug is closed and the part can no longer be
reflashed from outside. The last steps are permanent.

One script does this on every port, with the same commands:

```sh
TARGET=<port> tests/target/provisioning/provisioning_ctrl.sh <command> [state]
```

`TARGET` is `stm32h563` (the default) or `mimxrt700`. `help` lists the
commands and the port's states. Only the state codes and a few device commands
differ between ports. This page covers the shared flow; each port guide covers
its states, quirks, and a walkthrough with real output:

- [STM32H5 Guide: Provisioning and product state](STM32H5-Guide.md#provisioning-and-product-state)
- [MIMXRT700 Guide: Provisioning and life cycle](MIMXRT700-Guide.md#provisioning-and-life-cycle)

> **Production locks are permanent.** `lock` is for a production station and a
> part you intend to ship, never a development board. Every step before it is
> reversible: a mock that a reset or a regression undoes.

## The flow

Every port follows the same four stages, one manual command at a time:

| Stage | Command | What it does |
| --- | --- | --- |
| 1. Prepare | `restore`, `status`, `discover` | flash the production images, read the part, run the preflight |
| 2. Rehearse | `advance <state>` | enter the state as a reversible mock and record what the part showed |
| 3. Validate, then return | `status` in the mock state, then `regress` | check the part behaves like the product you will ship, then return it and complete the rehearsal |
| 4. Lock | `lock <state>` | make that one state permanent, after a preview and a typed acceptance |

A state is given by its code or its name: `lock 0x72` or `lock closed` on the
STM32H5, `lock 0x07` or `lock develop2` on the MIMXRT700.

### 1. Prepare

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh restore
tests/target/provisioning/provisioning_ctrl.sh status
tests/target/provisioning/provisioning_ctrl.sh discover
```

Build the production images first, with production signing keys and the guest
flash protection on (`WT_GUEST_FLASH_WRP=1`). Every command that writes to the
board needs `WT_LOCK_CONFIRM=1`.

### 2. Rehearse (the mock lock)

```sh
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh advance <state>
```

`advance` puts the part in `<state>` in a way that can be undone. It records a
pending rehearsal only if the part shows the evidence the port asks for: the
firmware booted in that state, the images read back match the build, and the
part's identity. Leave the part in the mock state for stage 3.

### 3. Validate, then return

```sh
tests/target/provisioning/provisioning_ctrl.sh status
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh regress
```

While the part is in the mock state, check it is the product you intend to
ship: `status`, the guests running, and the attestation token's life cycle.
What the part does here is what it will do once the state is permanent. Then
`regress` takes the part back and completes the rehearsal. A rehearsal is
bound to the part, the images, any credentials it used, and the hour it was
made in; `lock` refuses without one. Repeat stages 2 and 3 for each state you
will lock.

### 4. Lock

```sh
tests/target/provisioning/provisioning_ctrl.sh lock <state>
```

Without `WT_LOCK_CONFIRM=1`, `lock` is a preview: it runs every check, prints
the exact write, and changes nothing. On a production station:

```sh
export WT_PRODUCTION_LOCK=1
WT_LOCK_CONFIRM=1 tests/target/provisioning/provisioning_ctrl.sh lock <state>
```

It previews again, then asks:

```text
!!! Moving this <PORT> to <state>
!!! This is IRREVERSIBLE: <what this port loses for good>
!!! Are you sure? Type "I ACCEPT <code>" to continue:
```

Only a person at a terminal typing the acceptance exactly continues. Each
`lock` writes one state; run it again for the next state.

## The lock gates

Every port runs the same gates, in this order, from one place in
`provisioning_ctrl.sh`. A failed gate exits with status 2 and writes nothing.

1. **Next state only.** `lock` reads the part's real state (fuses or option
   bytes, never the mock) and refuses anything but the next state.
2. **A rehearsal of this state** on this part, with these images and
   credentials, completed in the last hour (`WT_REHEARSAL_MAX_AGE`).
3. **The same part.** If the port can read the part's identity in this state,
   it must match the rehearsal. If it cannot, the step runs only with
   `WT_FIXTURE_BOUND=1`, which a station sets only on a fixture that holds one
   part from the rehearsal to the lock.
4. **Provisioned first.** The port's own checks, such as safe perimeter
   values, guest flash protection, and production credentials.
5. **Preview** of the exact write.
6. **`WT_LOCK_CONFIRM=1`** and **`WT_PRODUCTION_LOCK=1`**.
7. **An interactive terminal**, never a pipe or script.
8. **The typed acceptance**, `I ACCEPT <code>`. Right after it, `lock` reads
   the state and the part again, repeats every rehearsal check (images,
   credentials, part, age), and reruns the port checks, so nothing that changed
   at the prompt is written.
9. **Read-back.** After the write, the new state must read back, or `lock`
   fails and says what state the part is in.
10. **Single use.** A successful lock deletes the rehearsal of its own state,
    and a permanent step deletes whatever rehearsal it used. One exception is
    deliberate: the STM32H5 Provisioning step runs on the Closed rehearsal and
    keeps it, because the closing step that follows needs it and a part in
    Provisioning cannot be rehearsed again (its images are no longer
    readable). That closing step then consumes it, within the same age limit
    and on a fixture that holds the part (`WT_FIXTURE_BOUND=1`).

These follow the vendors' own provisioning tools:
- NXP's Secure Provisioning tool offers a "Test life cycle" mode and lists
  each irreversible operation before it writes.
- ST's `ROT_Provisioning` scripts provision keys and Debug Authentication
  before the product state.
- TF-M advances its PSA life cycle only once provisioning is complete.

`provisioning_ctrl.sh` adds the one-step rule, the bound rehearsal, and a
typed acceptance instead of a keypress.

## What a production lock does to the firmware

wolfBoot passes the life cycle to wolfTrust as a PSA life cycle value. Past
`0x2000` PSA_ROT_PROVISIONING, wolfTrust stops treating the part as a
development board:

- **Rollback floors are enforced.** A guest image older than its recorded
  floor is refused at launch.
- **The vault is never reformatted.** The sealed device key and write-once
  storage survive; a damaged store stops boot provisioning instead of being
  wiped.
- **Attestation reports the life cycle,** so a relying party can tell a
  production part from a development one: `0x3000` SECURED once debug is
  closed, `0x4000` or `0x5000` while some debug is open.
- **Guest flash protection stays in force** at every launch: the STM32H5 WRP,
  the MIMXRT700 XSPI fence.

## How a production lock binds the software

With debug closed, nothing outside the firmware can reflash the part. The
software then only changes through wolfBoot's signed update path
(`SERVICE_FWU`). These keys hold it in place for the life of the part:

| Key | What it decides |
| --- | --- |
| wolfBoot signing key | which wolfTrust images wolfBoot boots and accepts as updates |
| guest measurement records (signed into the wolfTrust image) | which guests wolfTrust launches |
| MIMXRT700 root key table hash (fused) | which first-stage images the BootROM boots |
| STM32H5 Debug Authentication certificate chain | whether a part short of Locked can be regressed |

Back these up before the first lock. A lost signing key means the parts locked
with it can never be updated; a leaked one means they trust whoever holds it.

## PSA life cycle by port

| PSA life cycle | STM32H5 product state | MIMXRT700 life cycle |
| --- | --- | --- |
| `0x1000` ASSEMBLY_AND_TEST | open `0xED` | develop `0x03` |
| `0x2000` PSA_ROT_PROVISIONING | provisioning `0x17` | develop2 `0x07` |
| `0x4000` NON_PSA_ROT_DEBUG | tz-closed `0xC6` | in-field, only Non-secure debug open |
| `0x5000` RECOVERABLE_PSA_ROT_DEBUG | closed, Secure debug open | in-field, Secure debug open |
| `0x3000` SECURED | closed `0x72`, locked `0x5C` | in-field `0x0F`, in-field-locked `0xCF` |
| `0x6000` DECOMMISSIONED | none | in-field-return `0x1F` |
| `0x0000` UNKNOWN | any other value | copies disagree, or an NXP-internal state |

## Environment

| Variable | Meaning |
| --- | --- |
| `TARGET` | the port: `stm32h563` (default) or `mimxrt700` |
| `WT_LOCK_CONFIRM=1` | allow a board write; without it `lock` only previews |
| `WT_PRODUCTION_LOCK=1` | marks a production station; `lock` never writes without it |
| `WT_FIXTURE_BOUND=1` | the fixture holds one part from rehearsal to lock; needed where the part's identity cannot be read |
| `WT_PROVISION_STATE` | where rehearsal records live (default `~/.cache/wolftrust`, one folder per port) |
| `WT_REHEARSAL_MAX_AGE` | seconds a rehearsal stays valid (default `3600`) |
| `WT_DA_OBK`, `WT_DA_KEY`, `WT_DA_CERT`, `WT_DA_PWD` | STM32H5 Debug Authentication inputs; a production lock requires all four, none of them ST's sample |
| `STM32_CLI`, `H5_SERIAL` | STM32H5: STM32CubeProgrammer CLI and the board UART |
| `RT700_ISP`, `RT700_SPSDK_VENV`, `RT700_GUEST_MASK` | MIMXRT700: blhost ISP connection, SPSDK environment, guests a rehearsal must launch |

## Adding a port

A port is one file, `tests/target/provisioning/provisioning_ctrl_<target>.sh`,
that answers device questions through a fixed set of functions:

| Function | Answers |
| --- | --- |
| `port_ladder` | the states: code, name, whether it has a mock, whether it can be locked, permanent or reversible, and the state it is reached from |
| `port_status`, `port_discover`, `port_restore` | read the part, preflight, put the production images back |
| `port_advance_check`, `port_advance`, `port_booted`, `port_regress` | enter and leave a mock state, and the evidence a rehearsal records |
| `port_lock_current`, `port_lock_identity` | the real state, and the part's identity where it can be read |
| `port_image_digest`, `port_cred_fp`, `port_record_ok` | what binds a rehearsal to these images, credentials, and part |
| `port_rehearsal_for`, `port_ready` | which rehearsals count, and the port's provisioned-first checks |
| `port_lock_plan`, `port_lock_write`, `port_lock_verify`, `port_consequence` | the permanent write: preview, do, read back, and what it costs |
| `port_usage_extra`, `port_extra` | device-only commands |

The gates, records, and prompts stay in `provisioning_ctrl.sh`, so a new port
cannot weaken them.

## Testing

`make test` runs `make test-provisioning`: every gate of both ports against
stub vendor tools, from the generic refusals to the typed acceptance. Nothing
touches a board; the typed-acceptance cases need `expect` and skip without it.
