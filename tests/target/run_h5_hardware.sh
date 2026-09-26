#!/usr/bin/env bash
# wolfTrust STM32H563/H5 hardware smoke: build the authenticated
# wolfBoot -> wolfTrust -> guests chain, flash it to a real Nucleo-H563ZI via
# STM32CubeProgrammer, capture the board UART, and assert the production
# lifecycle markers. REAL hardware evidence, distinct from the M33MU emulator.
#
#   run_h5_hardware.sh build [scenario]  build images (needs container toolchain)
#   run_h5_hardware.sh flash [scenario]  flash + capture + assert (needs the host
#                                        that owns the ST-Link + serial VCP)
#   run_h5_hardware.sh all   [scenario]  both, if one env has toolchain AND board
#
# scenario (default positive) selects the on-silicon evidence, mirroring the
# M33MU run_m33mu_scenario.sh set so hardware and emulator prove the same thing:
#   positive     full PSA/FF-M lifecycle green, no faults
#   restart      guest faults on boot; the monitor restarts it restart_limit
#                times then leaves it FAULTED — the system keeps running
#   crossdomain  a probe inside the crypto SP reads SPM-private RAM; the SP
#                domain denies it (fault captured), the SP is quarantined, and
#                the rest of the system survives (L3 isolation on silicon)
#   confboot     the unmodified Arm val NSPE FF-M IPC suite (85/4) against the
#                production SPM; panic tests reboot the chain via real
#                SYSRESETREQ and val resumes off its flash boot flag.
#                Requires SECWM1 to cover the whole boot partition (0x00-0x4F).
#   bootupdate   full boot-and-update swap on silicon: v1 arms wolfBoot's real
#                update trigger for a signed v2 candidate flashed into the
#                update partition and reboots; wolfBoot swaps v2 into the boot
#                slot. Proof is guest-independent — the boot-partition header
#                read back over SWD carries v2's measurement, not v1's.
#
# The build and flash steps run in different environments (container vs host)
# because the box's ARM toolchain lives only in the CI container while the
# ST-Link + /dev/ttyACM0 belong to the host — so the normal flow is
# `build` in the container, then `flash` on the host, sharing the mounted repo.
#
# Hardware variants drop the emulator-only WT_M33MU_EXPECT_BKPT (a bare-metal
# BKPT with no debugger would fault). The board must be TrustZone-provisioned
# already (TZEN on, SECBOOTADD=0x0C000000, SECWM over the secure region).
# Flashing is reversible; option bytes are not touched here.
set -euo pipefail
set -o pipefail

mode="${1:-all}"
scenario="${2:-positive}"
case "$mode" in build|flash|all) ;; *) echo "usage: $0 build|flash|all [scenario]" >&2; exit 2 ;; esac
case "$scenario" in positive|restart|crossdomain|keystoreneg|panicneg|confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec|authneg|writeonce|hsmattackneg|bootupdate|vnet|vnetneg|gtzcneg) ;; *) echo "usage: $0 $mode positive|restart|crossdomain|keystoreneg|panicneg|confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec|authneg|writeonce|hsmattackneg|bootupdate|vnet|vnetneg|gtzcneg" >&2; exit 2 ;; esac

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
. "$repo/tests/target/lib/expect.sh"

# Manifest guest restart_limit (port/stm32h563/manifest.json domain id 1).
RESTART_LIMIT=3
# Secure ELF that matches the flashed image (for cross-domain fault forensics).
self="$repo/build/wolftrust-signed.elf"
NM="${ARM_NM:-/usr/bin/arm-none-eabi-nm}"
PYOCD_TARGET="${PYOCD_TARGET:-stm32h563zitx}"

CLI="${STM32_CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}"
SERIAL="${H5_SERIAL:-/dev/ttyACM0}"
# restart reboots guest0 restart_limit times; give the banners time to land.
# confboot reboots the whole chain once per panic test (real SYSRESETREQ, each
# re-running wolfBoot), so it needs a long ceiling; the capture stops early on
# the suite report.
case "$scenario" in restart) cap_default=32 ;; confboot) cap_default=900 ;; devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec) cap_default=600 ;; bootupdate) cap_default=45 ;; authneg) cap_default=30 ;; writeonce) cap_default=40 ;; *) cap_default=25 ;; esac
CAP_S="${H5_CAPTURE_SECONDS:-$cap_default}"
LOGFILE="${WT_SCENARIO_LOG:-ci-h5-hardware-$scenario.log}"
case "$LOGFILE" in /*) ;; *) LOGFILE="$repo/$LOGFILE" ;; esac
mkdir -p "$(dirname "$LOGFILE")"
# The container build leaves LOGFILE root-owned; fall back to /tmp so the
# host-side flash step's tee cannot fail (pipefail would skip the checks).
if ! : >> "$LOGFILE" 2>/dev/null; then
  LOGFILE="/tmp/$(basename "$LOGFILE").$$"
fi
uart="$repo/h5-uart-capture.log"
cli_log="/tmp/h5-flash-cli.$$.log"
# Both guests raw-write USART3, so another guest's burst can splice into the
# middle of a marker: expect() falls back to its bounded word-gap match.
WT_EXPECT_LOG="$uart"
WT_EXPECT_GAP=1

stage()      { printf '  ... %s\n' "$1"; }

# Flash addresses: secure images to the secure alias (SECWM-covered), guests to
# the Non-secure alias (beyond the watermark). Match WT_*_FLASH_BASE.
WOLFBOOT_ADDR=0x0C000000
WOLFTRUST_ADDR=0x0C060000
GUEST0_ADDR=0x080A0000
# All scenarios use the 256K guest0 layout (guest1 at 0x080E0000) the M33MU
# runner uses, so silicon and emulator flash the same image. (dev_apis crypto
# outgrew the old 128K guest0 window; the rest follow to keep one layout.)
GUEST1_ADDR=0x080E0000
guest0="$repo/tests/firmware/zephyr-stm32h5/build/guest0_psa/zephyr/zephyr.bin"
guest1="$repo/tests/firmware/zephyr-stm32h5/build/freertos_guest1/freertos_guest1.bin"
if [ "$scenario" = "vnet" ] || [ "$scenario" = "vnetneg" ]; then
  guest0="$repo/tests/firmware/stm32h563-vnet/build/guest0.bin"
  guest1="$repo/tests/firmware/stm32h563-vnet/build/guest1.bin"
fi

if [ "$mode" != "flash" ]; then
  : > "$LOGFILE"
  git config --global --add safe.directory '*'
  git config --global --add safe.directory "$repo"

  export CROSS_COMPILE=/usr/local/bin/arm-none-eabi-
  export ZEPHYR_TOOLCHAIN_VARIANT=cross-compile
  export WT_SECURE_FLASH_BASE=0x0C060000
  export WT_SECURE_FLASH_SIZE=0x00040000
  export WOLFBOOT_PARTITION_SIZE=0x40000
  export WOLFBOOT_PARTITION_SWAP_ADDRESS=0x0C140000
  export WT_SECURE_IMAGE_HEADER_SIZE=0x400
  export WT_GUEST0_FLASH_BASE=0x080A0000
  export WT_GUEST1_FLASH_BASE=$GUEST1_ADDR
  export WT_GUEST0_FLASH_SIZE=0x00040000
  export WT_GUEST_RAM_SIZE=0x00010000
  export WT_GUEST1_RAM_BASE=0x20010000
  export WT_ZEPHYR_DTC_OVERLAY_FILE=boards/wolfboot-stm32h563.overlay
  export WT_MAX_GUESTS=2
  export ZEPHYR_BOARD=nucleo_h563zi/stm32h563xx/ns
  WOLFBOOT_REF=d85fa9dbdf6c36f47b7e96eba5c9df750ad3c963

  stage "fetching wolfTrust dependencies"
  {
    git submodule update --init --single-branch
    rm -rf build tests/firmware/zephyr-stm32h5/build
  } >> "$LOGFILE" 2>&1

  # The wolfBoot first stage is identical across scenarios (same WOLFBOOT_REF);
  # reuse it so back-to-back scenario builds don't re-clone. WT_H5_FRESH_DEPS=1
  # forces a clean rebuild.
  if [ "${WT_H5_FRESH_DEPS:-0}" = "1" ] || \
     [ ! -s "$repo/wolfBoot/wolfboot.bin" ] || \
     [ ! -s "$repo/wolfBoot/wolfboot_signing_private_key.der" ]; then
    stage "building wolfBoot first stage"
    {
      rm -rf wolfBoot
      git clone --no-checkout https://github.com/aidangarske/wolfBoot.git wolfBoot
      cd wolfBoot
      git -c protocol.version=2 fetch --depth 1 origin "$WOLFBOOT_REF"
      git checkout --detach "$WOLFBOOT_REF"
      git submodule update --init --single-branch
      cp "$repo/wolfBoot/config/examples/stm32h5-tz-wolftrust.config" .config
      make keytools
      make -j"$(nproc)" wolfboot.bin wolfboot_signing_private_key.der
      cd "$repo"
    } >> "$LOGFILE" 2>&1
  else
    stage "reusing existing wolfBoot first stage"
  fi

  # crossdomain injects a Secure-side probe; restart injects a NS guest fault
  # probe; positive builds the production images. Mirrors run_m33mu_scenario.sh.
  secure_flags=""; guest_flags=""
  [ "$scenario" = "crossdomain" ] && secure_flags="WT_FFM_NEGATIVE_PROBE=1"
  [ "$scenario" = "keystoreneg" ] && secure_flags="WT_KEYSTORE_NEG_PROBE=1"
  [ "$scenario" = "panicneg" ] && secure_flags="WT_PANIC_NEG_PROBE=1"
  [ "$scenario" = "restart" ] && guest_flags="WT_GUEST_FAULT_PROBE=1"
  [ "$scenario" = "writeonce" ] && guest_flags="WT_WRITE_ONCE_RESET_PROBE=1"
  [ "$scenario" = "hsmattackneg" ] && guest_flags="WT_HSM_ATTACK_PROBE=1"
  [ "$scenario" = "gtzcneg" ] && guest_flags="WT_MPU_BYPASS_PROBE=1"
  [ "$scenario" = "bootupdate" ] && secure_flags="WT_BOOTUPDATE_PROBE=1"
  [ "$scenario" = "vnet" ] && secure_flags="CONFIG_VNET=y"
  [ "$scenario" = "vnetneg" ] && secure_flags="CONFIG_VNET=y WT_VNET_NEG_PROBE=1"
  # WT_CONF_DIAG_TRAP=0: the emulator-only hang-probe fault would become a
  # conformance-monitor reset on silicon and can eat the suite's report window.
  [ "$scenario" = "confboot" ] && { secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0"; guest_flags="WT_RUN_CONFORMANCE=1"; }
  [ "$scenario" = "devstorage" ] && { secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0"; guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=storage"; }
  [ "$scenario" = "devcrypto" ] && { secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0"; guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=crypto"; }
  [ "$scenario" = "devattest" ] && { secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0"; guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation"; }
  [ "$scenario" = "devattestqcbor" ] && { tests/upstream/fetch_qcbor.sh >/dev/null; secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0"; guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=attestation WT_ATTEST_CBOR=qcbor"; }
  # Vault-recovery negatives ride the dev_apis crypto image plus the foreign-pool
  # probe: the crypto suite proves the vault still works after recovery, while
  # the probe forces the boot-time recovery (self-heal unlocked / fail closed
  # when it also forces SECURED). Crypto is used because it exercises the vault
  # and boots the same image the board already runs green.
  [ "$scenario" = "vaultrecover" ] && { secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0 WT_VAULT_FOREIGN_PROBE=1"; guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=crypto"; }
  [ "$scenario" = "vaultrecoversec" ] && { secure_flags="WT_CONFORMANCE=1 WT_CONF_DIAG_TRAP=0 WT_VAULT_FOREIGN_PROBE=1 WT_VAULT_PROBE_SECURED=1"; guest_flags="WT_RUN_CONFORMANCE=1 WT_CONF_SUITE=crypto"; }

  stage "building wolfTrust secure image ($scenario)"
  {
    env $secure_flags make build/wolftrust.bin build/secure_cmse_implib.o
    # Patch-then-sign (WT-FFM-0049): stash the pre-patch image; signing waits
    # for the guest digests below so the wolfBoot signature covers the pins.
    cp "$repo/build/wolftrust.bin" "$repo/build/wolftrust-unsigned.bin"
    cp "$repo/build/wolftrust.elf" "$repo/build/wolftrust-signed.elf"
  } >> "$LOGFILE" 2>&1

  # Hardware guest build: NO WT_M33MU_EXPECT_BKPT (emulator-only breakpoint).
  stage "building guests (hardware variant, no emulator BKPT, $scenario)"
  if [ "$scenario" = "vnet" ] || [ "$scenario" = "vnetneg" ]; then
    {
      rm -rf tests/firmware/stm32h563-vnet/build
      make -C tests/firmware/stm32h563-vnet build/guest0.bin build/guest1.bin \
        WT_GUEST0_FLASH_ORIGIN=0x080A0000 WT_GUEST1_FLASH_ORIGIN=0x080E0000 \
        WT_GUEST0_RAM_BASE=0x20000000 WT_GUEST1_RAM_BASE=0x20010000 \
        WT_GUEST_RAM_SIZE=0x00010000
    } >> "$LOGFILE" 2>&1
  else
  {
    make -C tests/firmware/zephyr-stm32h5 clone
    env $guest_flags $secure_flags WT_REUSE_SECURE_BUILD=1 WT_EXPECTED_LIFECYCLE=0x1000u \
      WT_ATTESTATION_DEVELOPMENT_PROFILE=1 \
      make -C tests/firmware/zephyr-stm32h5 build-guest0-psa build-freertos-guest1
  } >> "$LOGFILE" 2>&1
  fi

  stage "pinning guest measurements + signing ($scenario)"
  {
    cp "$repo/build/wolftrust-unsigned.bin" "$repo/build/wolftrust.bin"
    python3 tools/measure/patch_guest_digests.py "$repo/build/wolftrust.bin" \
      "0:${WT_GUEST0_VERSION:-1}:$guest0" \
      "1:${WT_GUEST1_VERSION:-1}:$guest1"
    IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x2000 \
      "$repo/wolfBoot/tools/keytools/sign" --ecc256 \
        "$repo/build/wolftrust.bin" \
        "$repo/wolfBoot/wolfboot_signing_private_key.der" 1
    test -s "$repo/build/wolftrust_v1_signed.bin"
    # bootupdate: also sign the same image at version 2 (higher version + a
    # different hashed-header measurement) as the swap candidate.
    if [ "$scenario" = "bootupdate" ]; then
      IMAGE_HEADER_SIZE=1024 WOLFBOOT_PARTITION_SIZE=0x40000 WOLFBOOT_SECTOR_SIZE=0x2000 \
        "$repo/wolfBoot/tools/keytools/sign" --ecc256 \
          "$repo/build/wolftrust.bin" \
          "$repo/wolfBoot/wolfboot_signing_private_key.der" 2
      test -s "$repo/build/wolftrust_v2_signed.bin"
    fi
  } >> "$LOGFILE" 2>&1

  WT_EXPECTED_MEASUREMENT_HEX="$(python3 tests/scripts/read_wolfboot_measurement.py \
    build/wolftrust_v1_signed.bin 2>>"$LOGFILE")"

  # authneg: corrupt one byte of guest0 AFTER its digest was pinned and the
  # secure image signed, so launch verification must fail closed for guest0
  # while guest1 and the platform keep running. Mirrors run_m33mu_scenario.sh.
  if [ "$scenario" = "authneg" ]; then
    python3 - "$guest0" <<'PYEOF' >> "$LOGFILE" 2>&1
import sys
with open(sys.argv[1], "r+b") as f:
    f.seek(0x400); b = f.read(1)
    f.seek(0x400); f.write(bytes([b[0] ^ 0x01]))
PYEOF
  fi

  test -s "$repo/build/wolftrust_v1_signed.bin"
  test -s "$repo/wolfBoot/wolfboot.bin"
  test -s "$guest0"; test -s "$guest1"
  echo "$scenario" > "$repo/build/h5-scenario.stamp"
  echo "BUILD OK: images ready for flash"
  echo "  wolfboot.bin            -> $WOLFBOOT_ADDR"
  echo "  wolftrust_v1_signed.bin -> $WOLFTRUST_ADDR"
  echo "  guest0_psa zephyr.bin   -> $GUEST0_ADDR"
  echo "  freertos_guest1.bin     -> $GUEST1_ADDR"
fi

if [ "$mode" != "build" ]; then
  if ! "$repo/tests/target/detect_h5.sh" >/dev/null 2>&1; then
    echo "SKIP: H5 hardware ($("$repo/tests/target/detect_h5.sh" 2>&1))"
    exit 0
  fi
  built="$(cat "$repo/build/h5-scenario.stamp" 2>/dev/null || echo unknown)"
  [ "$built" = "$scenario" ] || {
    echo "FAIL: built images are for '$built', not '$scenario' — run build $scenario first" >&2; exit 1; }
  test -s "$repo/wolfBoot/wolfboot.bin" || { echo "FAIL: wolfboot.bin missing — run build first" >&2; exit 1; }
  test -s "$repo/build/wolftrust_v1_signed.bin" || { echo "FAIL: signed secure image missing — run build first" >&2; exit 1; }
  test -s "$guest0" || { echo "FAIL: guest0 image missing — run build first" >&2; exit 1; }
  test -s "$guest1" || { echo "FAIL: guest1 image missing — run build first" >&2; exit 1; }

  # When build and flash run as separate invocations (container build, host
  # flash via run_h5_suite.sh) the build-path measurement is not inherited;
  # recompute it from the on-disk signed image so the attestation check has it.
  if [ -z "${WT_EXPECTED_MEASUREMENT_HEX:-}" ]; then
    WT_EXPECTED_MEASUREMENT_HEX="$(python3 tests/scripts/read_wolfboot_measurement.py \
      "$repo/build/wolftrust_v1_signed.bin" 2>>"$LOGFILE")"
  fi

  # confboot's panic tests resume off a flash-backed boot flag in a reserved
  # secure sector; unlike the emulator (fresh flash each run) the board keeps
  # last run's counters, and stale state makes ~2 tests misresume as SIM ERROR.
  # Erase it so every run starts emulator-fresh.
  if [ "$scenario" = "confboot" ]; then
    stage "erasing conformance boot-flag NVM sector (0x0C1FA000)"
    pyocd erase -t "$PYOCD_TARGET" -s 0x0C1FA000 >/dev/null 2>&1 || true
  fi
  stage "capturing $SERIAL @ 115200 (max ${CAP_S}s)"
  stty -F "$SERIAL" 115200 raw -echo -echoe -echok -onlcr 2>/dev/null || true
  : > "$uart"
  cat "$SERIAL" >> "$uart" 2>/dev/null &
  cap_pid=$!
  sleep 1

  # pyocd erase flakily dies with "flash init timed out" (usually the first
  # invocation after a reset-halt) without reporting it; read back and retry.
  # Check the sector tail too: wolfBoot trailer state lives in the last bytes,
  # so a head-only check false-passes a sector whose front was already blank.
  erase_verified() {
    local addr tail lowh lowt out wh wt attempt
    addr="$1"
    tail=$(printf '0x%08X' $(( addr + 0x1FFC )))
    lowh=$(printf '%s' "${addr#0x}" | tr 'A-F' 'a-f')
    lowt=$(printf '%s' "${tail#0x}" | tr 'A-F' 'a-f')
    for attempt in 1 2 3; do
      pyocd erase -t "$PYOCD_TARGET" -s "$addr" >> "$LOGFILE" 2>&1 || true
      out=$(pyocd cmd -t "$PYOCD_TARGET" -c halt -c "read32 $addr 4" \
        -c "read32 $tail 4" 2>/dev/null)
      wh=$(printf '%s\n' "$out" | awk -v a="$lowh" 'tolower($1)==a":"{print $2}')
      wt=$(printf '%s\n' "$out" | awk -v a="$lowt" 'tolower($1)==a":"{print $2}')
      [ "$wh" = "ffffffff" ] && [ "$wt" = "ffffffff" ] && return 0
    done
    echo "FAIL: sector $addr did not erase (head=${wh:-none} tail=${wt:-none})" >&2
    return 1
  }

  # Scenario images cover only the front of each partition, so wolfBoot's
  # BOOT/UPDATE trailer and SWAP sectors survive reflashes; a bootupdate run
  # leaves its trigger armed there and every later boot then swaps stale
  # update content over the fresh image and halts. Blank them before flashing.
  stage "erasing wolfBoot trailer + swap sectors (halted, verified)"
  pyocd cmd -t "$PYOCD_TARGET" -c "reset halt" >> "$LOGFILE" 2>&1 || true
  erase_verified 0x0C09E000
  erase_verified 0x0C13E000
  erase_verified 0x0C140000

  stage "flashing wolfTrust chain via STM32CubeProgrammer"
  # CubeProgrammer exits nonzero after -hardRst even on success; gate on the
  # verify text instead so set -e does not kill the marker checks below.
  # bootupdate: flash the signed v2 candidate into the update partition so
  # wolfBoot has a real image to swap once v1 arms the trigger and reboots.
  update_d=""
  [ "$scenario" = "bootupdate" ] && \
    update_d="-d $repo/build/wolftrust_v2_signed.bin 0x0C100000"
  # Guest flash is write-protected under WT_GUEST_FLASH_WRP, and a protected
  # sector silently keeps its old contents through erase and program, so the
  # lock a previous WRP run left armed would fail every later verify. Always
  # unlock before flashing; WRP runs re-lock after.
  stage "clearing guest-flash WRP before flashing"
  "$CLI" -c port=SWD mode=UR -ob WRPSGn1=0xFFFFFFFF >> "$LOGFILE" 2>&1 || true
  "$CLI" -c port=SWD mode=UR \
    -d "$repo/wolfBoot/wolfboot.bin" "$WOLFBOOT_ADDR" \
    -d "$repo/build/wolftrust_v1_signed.bin" "$WOLFTRUST_ADDR" \
    -d "$guest0" "$GUEST0_ADDR" \
    -d "$guest1" "$GUEST1_ADDR" \
    $update_d \
    --verify -hardRst > "$cli_log" 2>&1 || true
  cat "$cli_log" >> "$LOGFILE" || true
  grep -aq "verified successfully" "$cli_log" || {
    echo "FAIL: flash verify did not complete" >&2; exit 1; }
  if [ "${WT_GUEST_FLASH_WRP:-0}" = "1" ]; then
    stage "write-protecting guest flash (WRPSGn1=0x000FFFFF)"
    "$CLI" -c port=SWD mode=UR -ob WRPSGn1=0x000FFFFF >> "$LOGFILE" 2>&1 || true
  fi

  # CubeProgrammer -hardRst is unreliable (observed: board left parked in the
  # pre-flash state); always follow with an explicit debug-port reset.
  #
  # dev scenarios: the pool must start blank (emulator-equivalent), and both
  # failure modes observed on silicon come from ordering: erasing a RUNNING
  # target lets the old firmware's cached wolfHSM state rewrite the pool before
  # the reset (s001 finds stale UIDs), and a second reset landing mid
  # vault-format tears a flash write that s003's remove-all later trips over
  # (SIM ERROR reboot). So: park the core at the reset vector, erase while
  # halted, then boot exactly once.
  if [ "$scenario" = "devstorage" ] || [ "$scenario" = "devcrypto" ] || [ "$scenario" = "devattest" ] || [ "$scenario" = "devattestqcbor" ] || [ "$scenario" = "vaultrecover" ] || [ "$scenario" = "vaultrecoversec" ]; then
    stage "reset-halt, erase vault NVM + boot-flag (verified), single boot"
    pyocd cmd -t "$PYOCD_TARGET" -c "reset halt" >> "$LOGFILE" 2>&1 || true
    erase_verified 0x0C1FC000
    erase_verified 0x0C1FE000
    erase_verified 0x0C1FA000
    pyocd cmd -t "$PYOCD_TARGET" -c reset >/dev/null 2>&1 || true
  elif [ "$scenario" = "positive" ] || [ "$scenario" = "bothpsa" ] || [ "$scenario" = "crossdomain" ] || [ "$scenario" = "keystoreneg" ] || [ "$scenario" = "panicneg" ]; then
    # Guest0's ITS+PS lifecycle persists vault objects across runs on silicon
    # (the emulator starts on fresh flash); blank the vault like the dev
    # scenarios do so the pool stays emulator-equivalent.
    stage "reset-halt, erase vault NVM (verified), single boot"
    pyocd cmd -t "$PYOCD_TARGET" -c "reset halt" >> "$LOGFILE" 2>&1 || true
    erase_verified 0x0C1FC000
    erase_verified 0x0C1FE000
    pyocd cmd -t "$PYOCD_TARGET" -c reset >/dev/null 2>&1 || true
  elif [ "$scenario" = "writeonce" ]; then
    # First boot on a blank vault: guest0 seals a WRITE_ONCE object and latches
    # g_write_once_stage=1. The second reset (in the assertion below) boots again
    # and confirms the object survived the reset and is immutable. The halt,
    # erase, and release MUST share one pyocd session — separate invocations let
    # the target resume between them and the running firmware rewrites the pool
    # before the erase lands (same race the dev scenarios avoid).
    stage "writeonce: halt, erase vault NVM, first boot (seed WRITE_ONCE)"
    pyocd cmd -t "$PYOCD_TARGET" -c "reset halt" \
      -c "erase 0x0C1FC000" -c "erase 0x0C1FE000" -c reset \
      >> "$LOGFILE" 2>&1 || true
  else
    pyocd cmd -t "$PYOCD_TARGET" -c reset >/dev/null 2>&1 || true
  fi

  # confboot reboots the chain once per panic test and val resumes off its flash
  # boot flag; the run is done when the suite prints its report, so stop early on
  # it rather than wait the whole ceiling. The others have a fixed settling window.
  case "$scenario" in
    confboot|devstorage|devcrypto|devattest|devattestqcbor|vaultrecover|vaultrecoversec)
      stage "waiting for the suite report (max ${CAP_S}s)"
      waited=0
      while [ "$waited" -lt "$CAP_S" ]; do
        grep -aq "TOTAL FAILED" "$uart" && break
        sleep 5; waited=$((waited + 5))
      done
      ;;
    *)
      sleep "$CAP_S"
      ;;
  esac
  kill "$cap_pid" 2>/dev/null || true
  wait "$cap_pid" 2>/dev/null || true
  echo "----- UART capture -----" >> "$LOGFILE"
  cat "$uart" >> "$LOGFILE"

  # After the run, read a secure global by ELF symbol via a non-secure pyocd
  # halt (Open board exposes secure RAM to the debugger). Prints its uint32 as
  # an 8-hex-digit string (no 0x); callers apply 0x for arithmetic.
  read_secure_u32() {
    local sym addr
    sym="$1"
    addr=$("$NM" "$self" 2>/dev/null | awk -v s="$sym" '$3==s{print $1}')
    [ -n "$addr" ] || { echo ""; return; }
    pyocd cmd -t "$PYOCD_TARGET" -c halt -c "read32 0x$addr 4" 2>/dev/null \
      | awk -v a="$addr" 'tolower($1)==a":"{print $2}'
  }

  # Read a guest0 NS-RAM symbol over SWD. Both guests share USART3, so their
  # banners interleave and a UART grep is unreliable; guest0 latches its
  # lifecycle progress in RAM (g_guest0_lifecycle) which SWD reads cleanly.
  # Guest RAM reads probe both the Non-secure address and its Secure alias
  # (+0x10000000): the GTZC curtain marks the idle guest's blocks Secure, and
  # the debug access is attributed by the alias it targets, so exactly one of
  # the two views returns the live word (the other reads as zero, just like a
  # hostile guest's access).
  read_guest_ram_u32() {
    local addr alias out ns_val s_val
    addr="$1"
    alias=$(printf '%08x' $((0x$addr + 0x10000000)))
    out=$(pyocd cmd -t "$PYOCD_TARGET" -c halt -c "read32 0x$addr 4" \
      -c "read32 0x$alias 4" 2>/dev/null)
    ns_val=$(printf '%s\n' "$out" \
      | awk -v a="$addr" 'tolower($1)==a":"{print $2}')
    s_val=$(printf '%s\n' "$out" \
      | awk -v a="$alias" 'tolower($1)==a":"{print $2}')
    if [ -n "$ns_val" ] && [ $((0x$ns_val)) -ne 0 ]; then
      echo "$ns_val"
    elif [ -n "$s_val" ]; then
      echo "$s_val"
    else
      echo "$ns_val"
    fi
  }

  read_guest0_u32() {
    local sym addr elf
    sym="$1"
    elf="${guest0%/*}/zephyr.elf"
    addr=$("$NM" "$elf" 2>/dev/null | awk -v s="$sym" '$3==s{print $1}')
    [ -n "$addr" ] || { echo ""; return; }
    read_guest_ram_u32 "$addr"
  }

  read_guest1_u32() {
    local sym addr elf
    sym="$1"
    elf="${guest1%.bin}.elf"
    addr=$("$NM" "$elf" 2>/dev/null | awk -v s="$sym" '$3==s{print $1}')
    [ -n "$addr" ] || { echo ""; return; }
    read_guest_ram_u32 "$addr"
  }

  case "$scenario" in
    positive)
      # The full PSA/FF-M lifecycle is gated on guest0's SWD progress latch,
      # not the shared USART3 console (guest1's banners interleave char-by-char
      # and split guest0's markers). Each latched bit is a completed milestone;
      # WT_LC_ALL (0xFF) = TEE init, mediated crypto, ITS, PS, key-ops, SHA-256
      # KAT, attestation COSE verify, and guest0 completion. The UART capture is
      # kept in the log for forensics; the attestation measurement match is
      # cross-checked below against the wolfBoot measurement of the signed image.
      refute_re "no fault markers in UART" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault|BusFault|UsageFault)'
      lc=$(read_guest0_u32 g_guest0_lifecycle)
      if [ -n "$lc" ] && [ $((0x$lc & 0xFF)) -eq 255 ]; then
        check_pass "guest0 full PSA/FF-M lifecycle latched (0x$lc)"
      else
        check_fail "guest0 lifecycle" "latched 0x${lc:-none}, expected all milestones 0xFF"
      fi
      # Best-effort: the attestation COSE verify is already gated by the latch;
      # the measurement hex only confirms via the console when it lands intact.
      if grep -Faq "token measurement=$WT_EXPECTED_MEASUREMENT_HEX" "$uart"; then
        check_pass "attestation token measurement equals the signed image"
      else
        printf '  [check] INFO  measurement match not visible on the interleaved console (latch gates the lifecycle)\n'
      fi
      # Hardware cross-guest isolation proof (WT-FFM-0011): guest1 submits an
      # iovec whose base lies in guest0's NS RAM; the caller-banded memcheck
      # must refuse it on silicon. The shared console shreds guest1 lines
      # char-by-char, so the proof is guest1's SWD-latched negative mask
      # (1 forged, 2 oversized, 4 cross-guest, 8 unknown SID).
      neg=$(read_guest1_u32 g_guest1_ffm_neg)
      if [ -n "$neg" ] && [ $((0x$neg & 0x4)) -ne 0 ]; then
        check_pass "cross-guest vector refused on silicon (mask=0x$neg)"
      else
        check_fail "cross-guest isolation" "guest1 negative mask 0x${neg:-none}, want bit 0x4"
      fi
      ;;
    authneg)
      # Authenticated launch fails closed (WT-SYS-0002): guest0's flashed image
      # was corrupted after its digest was pinned, so launch verification must
      # refuse it while guest1 and the platform keep running. The run ends on
      # the capture timeout — guest1's heartbeats are the survival evidence.
      refute_re "no fault markers on silicon" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
      refute_re "tampered guest0 never entered its domain" 'guest0_psa alive'
      quarantines=$(read_secure_u32 g_wt_quarantine_events)
      if [ -n "$quarantines" ] && [ $((0x$quarantines)) -ge 1 ]; then
        check_pass "monitor quarantined the tampered guest (events=0x$quarantines)"
      else
        check_fail "quarantine" "quarantine events 0x${quarantines:-none}, expected >=1"
      fi
      expect "guest1 (unrelated domain) still runs" "freertos_guest1: heartbeat"
      expect "guest1 mediated crypto still live" "freertos_guest1: ffm sha256 ok"
      ;;
    writeonce)
      # Boot A (post-flash) sealed a WRITE_ONCE object on a blank vault and
      # latched stage 1. Reset once more for boot B, which reads it back
      # (survived the reset) and confirms it refuses set (NONMODIFIABLE) and
      # remove (NONDESTROYABLE), latching stage 2. Read over SWD across boots.
      refute_re "no fault markers on silicon" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
      seeded=$(read_guest0_u32 g_write_once_stage)
      if [ -n "$seeded" ] && [ $((0x$seeded)) -eq 1 ]; then
        check_pass "first boot sealed the WRITE_ONCE object (stage=1)"
      else
        check_fail "seed" "stage 0x${seeded:-none}, expected 1"
      fi
      stage "writeonce: reset for the second boot (verify reset survival)"
      pyocd cmd -t "$PYOCD_TARGET" -c reset >/dev/null 2>&1 || true
      waited=0; st2=""
      while [ "$waited" -lt 20 ]; do
        st2=$(read_guest0_u32 g_write_once_stage)
        [ -n "$st2" ] && [ $((0x$st2)) -ne 0 ] && break
        sleep 2; waited=$((waited + 2))
      done
      if [ -n "$st2" ] && [ $((0x$st2)) -eq 2 ]; then
        check_pass "WRITE_ONCE object survived the reset and refused set/remove (stage=2)"
      else
        check_fail "survival" "stage 0x${st2:-none}, expected 2"
      fi
      ;;
    hsmattackneg)
      # Single boot, no reset needed. guest0 latches a 3-bit result in
      # g_hsm_attack_probe: bit0 IAK-sign refused, bit1 rollback-NVM-read
      # refused, bit2 own-namespace crypto still works. SWD read (not UART
      # grep) for the same interleaved-console reason as g_guest0_lifecycle.
      refute_re "no fault markers on silicon" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
      st=$(read_guest0_u32 g_hsm_attack_probe)
      if [ -n "$st" ] && [ $((0x$st & 0x7)) -eq 7 ]; then
        check_pass "hsmattackneg: IAK sign + NVM read refused, own namespace ok (0x$st)"
      else
        check_fail "hsmattackneg" "latched 0x${st:-none}, expected bit0|bit1|bit2 = 0x7"
      fi
      ;;
    restart)
      # The guest faults on boot each cycle; the monitor restarts it
      # RESTART_LIMIT times then quarantines it FAULTED — the restart budget
      # resets only after a crash-free window, so a crash loop cannot evade the
      # limit. Counted via the monitor's own event counters read over the debug
      # port: UART banners can interleave-split, secure RAM cannot.
      refute_re "no unhandled fault markers" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      restarts=$(read_secure_u32 g_wt_restart_events)
      quarantines=$(read_secure_u32 g_wt_quarantine_events)
      if [ -n "$restarts" ] && [ $((0x$restarts)) -eq "$RESTART_LIMIT" ]; then
        check_pass "monitor restarted the guest exactly $RESTART_LIMIT times"
      else
        check_fail "guest restart count" "restart events 0x${restarts:-none}, expected $RESTART_LIMIT"
      fi
      if [ -n "$quarantines" ] && [ $((0x$quarantines)) -eq 1 ]; then
        check_pass "guest quarantined FAULTED after the limit (events=1)"
      else
        check_fail "quarantine" "quarantine events 0x${quarantines:-none}, expected 1"
      fi
      expect "guest1 alive after guest0 FAULTED" "freertos_guest1: heartbeat"
      ;;
    crossdomain)
      # The unprivileged crypto SP reads SPM-private RAM (WT_RAM_S_BASE) on
      # entry; its MPU domain denies it. With graceful quarantine the fault
      # never escalates to HardFault — proof is the captured fault address in
      # the SPM RAM band, and guest1 surviving.
      refute_re "isolation fault did not escalate to HardFault" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      fault_cnt=$(read_secure_u32 g_tasklet_fault_count)
      fault_addr=$(read_secure_u32 g_last_fault_address)
      if [ -n "$fault_cnt" ] && [ $((0x$fault_cnt)) -ge 1 ]; then
        check_pass "crypto SP faulted on the cross-domain read (count=0x$fault_cnt)"
      else
        check_fail "cross-domain fault" "SP fault count not captured (count=${fault_cnt:-none})"
      fi
      if [ -n "$fault_addr" ] && \
         [ $((0x$fault_addr)) -ge $((0x30028000)) ] && \
         [ $((0x$fault_addr)) -lt $((0x30093000)) ]; then
        check_pass "denied read targeted SPM-private RAM (addr=0x$fault_addr)"
      else
        check_fail "cross-domain isolation" "fault addr 0x$fault_addr not in the SPM RAM band"
      fi
      expect "guest1 alive after SP quarantined" "freertos_guest1: heartbeat"
      ;;
    keystoreneg)
      # The ITS partition (a non-keystore SP) reads the shared keystore band on
      # entry; its MPU domain does not grant the band, so the read faults and is
      # gracefully quarantined. Proof is the captured fault address inside the
      # keystore band and guest1 surviving.
      refute_re "keystore-band fault did not escalate to HardFault" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      fault_cnt=$(read_secure_u32 g_tasklet_fault_count)
      fault_addr=$(read_secure_u32 g_last_fault_address)
      if [ -n "$fault_cnt" ] && [ $((0x$fault_cnt)) -ge 1 ]; then
        check_pass "ITS SP faulted on the keystore-band read (count=0x$fault_cnt)"
      else
        check_fail "keystore-band fault" "SP fault count not captured (count=${fault_cnt:-none})"
      fi
      if [ -n "$fault_addr" ] && \
         [ $((0x$fault_addr)) -ge $((0x30075000)) ] && \
         [ $((0x$fault_addr)) -lt $((0x30089000)) ]; then
        check_pass "denied read targeted the keystore band (addr=0x$fault_addr)"
      else
        check_fail "keystore-band isolation" "fault addr 0x$fault_addr not in the keystore band"
      fi
      expect "guest1 alive after SP quarantined" "freertos_guest1: heartbeat"
      ;;
    panicneg)
      # Secure-caller misuse: the ITS SP closes an error-status handle on its
      # first entry, so the production SPM panics it (resume PC landed on an
      # undefined instruction -> UsageFault UNDEFINSTR in the CFSR latch), the
      # graceful recovery restarts it, and the RESTARTED partition must then
      # serve the full guest lifecycle including ITS/PS storage.
      refute_re "panic did not escalate to HardFault" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      fault_cnt=$(read_secure_u32 g_tasklet_fault_count)
      fault_cfsr=$(read_secure_u32 g_tasklet_fault_cfsr)
      if [ -n "$fault_cnt" ] && [ $((0x$fault_cnt)) -ge 1 ]; then
        check_pass "ITS SP panicked on the bad close (count=0x$fault_cnt)"
      else
        check_fail "SP panic" "SP fault count not captured (count=${fault_cnt:-none})"
      fi
      if [ -n "$fault_cfsr" ] && \
         [ $(( (0x$fault_cfsr >> 16) & 0x1 )) -eq 1 ]; then
        check_pass "panic took the UNDEFINSTR trap (CFSR=0x$fault_cfsr)"
      else
        check_fail "panic trap" "CFSR 0x${fault_cfsr:-none} lacks UNDEFINSTR"
      fi
      # 0xFB = every milestone except ITS (0x04): the panicked partition's leg
      # alone is missing, so the -145 unblock let the client run the rest of
      # the lifecycle to completion instead of hanging on the dead SP.
      lc=$(read_guest0_u32 g_guest0_lifecycle)
      if [ -n "$lc" ] && [ $((0x$lc & 0xFF)) -eq $((0xFB)) ]; then
        check_pass "client unblocked; lifecycle completed minus the panicked leg (0x$lc)"
      else
        check_fail "unblock" "lifecycle 0x${lc:-none} after the panic, expected 0xFB"
      fi
      expect "guest1 alive through the panic" "freertos_guest1: heartbeat"
      ;;
    confboot)
      # The unmodified Arm val NSPE drives the FF-M IPC suite against wolfTrust
      # on real silicon. Panic tests reboot the chain via real SYSRESETREQ and
      # val resumes off its flash boot flag (K2/K3) — no emulator, no BKPT. No
      # fault-marker refute: the panics are by design. Both guests raw-write
      # USART3 and every reboot splices the boot banners mid-word, so the gate
      # is the ACS report block alone: it prints once in the quiet end window
      # and cannot exist unless val ran the suite end to end.
      expect "Arm suite TOTAL TESTS : 89" "TOTAL TESTS     : 89"
      expect "Arm suite TOTAL PASSED : 85" "TOTAL PASSED    : 85"
      expect "Arm suite TOTAL SKIPPED : 4" "TOTAL SKIPPED   : 4"
      expect "Arm suite TOTAL FAILED : 0" "TOTAL FAILED    : 0"
      expect "ACS run completed" "END OF ACS"
      ;;
    devstorage|devcrypto)
      # dev_apis suite report. guest1 raw-writes the same USART3, so strip its
      # lines then flatten before parsing the totals (mirrors the M33MU gate).
      refute_re "no unhandled fault markers" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      flat="$(sed 's/freertos_guest1:.*$//' "$uart" | tr -d '\r\n')"
      passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
      skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
      failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
      : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
      if [ "$scenario" = "devcrypto" ]; then want=77; suite="crypto"; note="c047 CMAC config-skipped"; else want=17; suite="storage"; note="optional PS create/set_extended skipped"; fi
      if [ "$failed" -eq 0 ] && [ "$((passed + skipped))" -eq "$want" ]; then
        check_pass "dev_apis $suite: ${passed} passed, ${skipped} skipped, 0 failed ($want scheduled; $note)"
      else
        check_fail "dev_apis $suite suite" \
          "passed=$passed skipped=$skipped failed=$failed (want failed=0, passed+skipped=$want)"
      fi
      ;;
    devattest|devattestqcbor)
      # dev_apis initial_attestation (test_a001): val verifies the vault-signed
      # tagged COSE_Sign1 against the runtime IAK; shim or reference QCBOR.
      refute_re "no unhandled fault markers" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      flat="$(sed 's/freertos_guest1:.*$//' "$uart" | tr -d '\r\n')"
      passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
      failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
      : "${passed:=-1}"; : "${failed:=-1}"
      if [ "$failed" -eq 0 ] && [ "$passed" -eq 1 ]; then
        check_pass "dev_apis initial_attestation: 1 passed, 0 failed"
      else
        check_fail "dev_apis initial_attestation suite" \
          "passed=$passed failed=$failed (want passed=1 failed=0)"
      fi
      ;;
    vaultrecover|vaultrecoversec)
      # Rides the dev_apis crypto image. The probe forces a foreign-pool ACCESS
      # at first IAK provisioning; the recovery then either self-heals (unlocked)
      # or fails closed (SECURED). Either way the boot must never mute-brick, and
      # the crypto suite must still pass afterward (the vault works). Recovery
      # counters read over SWD.
      refute_re "no HardFault (recovery, not a mute brick)" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      reformatted=$(read_secure_u32 g_vault_reformatted)
      degraded=$(read_secure_u32 g_wt_attest_degraded)
      if [ "$scenario" = "vaultrecover" ]; then
        # Self-heal: attestation recovers, so the guest reaches the crypto suite
        # and it passes -- the vault works after the reformat.
        passed=$(sed 's/freertos_guest1:.*$//' "$uart" | tr -d '\r\n' | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
        failed=$(sed 's/freertos_guest1:.*$//' "$uart" | tr -d '\r\n' | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
        if [ "${failed:-1}" -eq 0 ] && [ "${passed:-0}" -eq 64 ]; then
          check_pass "crypto suite green after self-heal (64 passed, 0 failed)"
        else
          check_fail "crypto after self-heal" "passed=${passed:-none} failed=${failed:-none} (want 64/0)"
        fi
        if [ -n "$reformatted" ] && [ $((0x$reformatted)) -eq 1 ]; then
          check_pass "unlocked lifecycle: vault self-healed (g_vault_reformatted=1)"
        else
          check_fail "self-heal" "g_vault_reformatted=0x${reformatted:-none}, expected 1"
        fi
      else
        # Fail-closed (SECURED): attestation is unavailable by design, so the
        # crypto suite is not the check here -- the security properties are.
        if [ -n "$degraded" ] && [ $((0x$degraded)) -eq 1 ]; then
          check_pass "SECURED lifecycle: failed closed (g_wt_attest_degraded=1, no trap)"
        else
          check_fail "fail closed" "g_wt_attest_degraded=0x${degraded:-none}, expected 1"
        fi
        if [ -n "$reformatted" ] && [ $((0x$reformatted)) -eq 0 ]; then
          check_pass "SECURED lifecycle: vault NOT reformatted (no data wipe)"
        else
          check_fail "no wipe" "g_vault_reformatted=0x${reformatted:-none}, expected 0"
        fi
      fi
      ;;
    bootupdate)
      # Full boot-and-update swap on silicon. v1 armed wolfBoot's real update
      # trigger for the v2 candidate flashed into the update partition and
      # rebooted; wolfBoot swapped v2 into the boot slot. Guest-independent proof
      # (robust to the positive-image guest-boot issue #96): read the boot
      # partition header back over SWD and confirm it now carries v2's wolfBoot
      # measurement, not v1's. A v2 guest hiccup (#96) does not undo the swap.
      v1meas="$(python3 tests/scripts/read_wolfboot_measurement.py build/wolftrust_v1_signed.bin 2>/dev/null)"
      v2meas="$(python3 tests/scripts/read_wolfboot_measurement.py build/wolftrust_v2_signed.bin 2>/dev/null)"
      hdr="/tmp/h5-boot-hdr.$$.bin"
      pyocd cmd -t "$PYOCD_TARGET" -c halt -c "savemem 0x0C060000 0x400 $hdr" >/dev/null 2>&1 || true
      bootmeas="$(python3 tests/scripts/read_wolfboot_measurement.py "$hdr" 2>/dev/null)"
      if [ -n "$bootmeas" ] && [ "$bootmeas" = "$v2meas" ]; then
        check_pass "boot slot holds v2 after the swap (measurement $bootmeas)"
      else
        check_fail "boot-and-update swap" "boot header measurement=${bootmeas:-none}, want v2=$v2meas (v1 was $v1meas)"
      fi
      if [ "$bootmeas" != "$v1meas" ]; then
        check_pass "the pre-update v1 image was swapped out of the boot slot"
      else
        check_fail "swap" "boot slot still holds v1 measurement $v1meas"
      fi
      ;;
    vnet)
      # Mediated inter-guest networking on silicon (WT-FFM-0058): both
      # bare-metal wolfIP guests come up and guest0's ICMP echo round-trips
      # through SERVICE_VNET psa_call. No emulator BKPT on hardware; the
      # capture window plus the needles are the gate.
      refute_re "no fault markers on silicon" \
        '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)'
      expect "guest0 alive" "vnet-guest0: alive"
      expect "guest1 alive" "vnet-guest1: alive"
      expect "guest0 sends the first mediated ping" "ping seq=1 to 10.0.0.2"
      expect "guest0 receives guest1's mediated echo reply" \
        "ping reply from 10.0.0.2 seq=1"
      ;;
    vnetneg)
      # Confined SERVICE_VNET isolation on silicon (WT-FFM-0011/0056): the
      # unprivileged vnet SP reads SPM RAM then executes from its XN data
      # band; each fault quarantines only that partition (SWD fault counter),
      # never a HardFault, and the mediated ping completes after the second
      # restart. First pings can land during quarantine, so any seq counts.
      refute_re "isolation faults did not escalate to HardFault" \
        '^(\[HARDFLT\]|HardFault|SecureFault)'
      fault_cnt=$(read_secure_u32 g_tasklet_fault_count)
      if [ -n "$fault_cnt" ] && [ $((0x$fault_cnt)) -ge 2 ]; then
        check_pass "vnet SP faulted on both probes (count=0x$fault_cnt)"
      else
        check_fail "vnet isolation faults" "SP fault count 0x${fault_cnt:-none}, want >= 2"
      fi
      expect "guest0 alive through the quarantine" "vnet-guest0: alive"
      expect "guest1 alive through the quarantine" "vnet-guest1: alive"
      expect "mediated ping completes after both restarts" \
        "ping reply from 10.0.0.2"
      ;;
    gtzcneg)
      # GTZC curtain on silicon (WT-FFM-0011): guest0 disables its own NS MPU
      # and stores a sentinel into guest1's RAM; the MPCBB block gating must
      # discard or fault the access. SWD latch: 2 = attempted and blocked
      # (RAZ/WI), 1 = the store faulted the guest mid-probe (contained),
      # 3 = the sentinel read back (isolation broken).
      probe=$(read_guest0_u32 g_guest0_gtzc_probe)
      if [ -n "$probe" ] && [ $((0x$probe)) -eq 2 ]; then
        check_pass "NS MPU bypass blocked without a fault (latch=0x$probe)"
      elif [ -n "$probe" ] && [ $((0x$probe)) -eq 1 ]; then
        check_pass "NS MPU bypass faulted and contained (latch=0x$probe)"
      else
        check_fail "NS MPU bypass containment" \
          "gtzc probe latch 0x${probe:-none}, want 1 or 2"
      fi
      refute_re "no HardFault escalation" '^(\[HARDFLT\]|HardFault|SecureFault)'
      ;;
  esac
  echo "PASS: hardware/h5/$scenario"
fi
