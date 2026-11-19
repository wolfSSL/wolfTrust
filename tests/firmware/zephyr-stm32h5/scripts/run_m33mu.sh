#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SUBTREE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MODE="${1:-}"
EMU_CMD="${M33MU:-m33mu}"
EMU_TIMEOUT="${EMU_TIMEOUT:-300}"
SECURE_BIN="${SECURE_BIN:-$SUBTREE_DIR/../../../build/wolftrust.bin}"
GUEST0_BIN="${GUEST0_BIN:-$SUBTREE_DIR/build/guest0/zephyr/zephyr.bin}"
GUEST1_BIN="${GUEST1_BIN:-$SUBTREE_DIR/build/guest1/guest1.bin}"
WT_GUEST0_EMU_OFFSET="${WT_GUEST0_EMU_OFFSET:-0x20000}"
WT_GUEST1_EMU_OFFSET="${WT_GUEST1_EMU_OFFSET:-0x40000}"

make -C "$SUBTREE_DIR" all >/dev/null

case "$MODE" in
--tui)
    exec "$EMU_CMD" --cpu stm32h563 --tui --timeout "$EMU_TIMEOUT" \
        "$SECURE_BIN" \
        "$GUEST0_BIN:$WT_GUEST0_EMU_OFFSET" \
        "$GUEST1_BIN:$WT_GUEST1_EMU_OFFSET"
    ;;
--uarts)
    # --uart-stdout collapses every UART onto m33mu's own stdout, so we can
    # capture both guests' traffic by simply redirecting the emulator —
    # no per-pty cat processes, no race against the pty buffer at boot.
    LOG_FILE=$(mktemp)
    RC_FILE=$(mktemp)
    cleanup() {
        rm -f "$LOG_FILE" "$RC_FILE"
    }
    trap cleanup EXIT INT TERM

    # Pipe through `tee` so output streams live AND is captured for the
    # post-run assertions; the m33mu exit status is shuttled out via the
    # RC_FILE sidechannel since plain POSIX sh doesn't expose PIPESTATUS.
    set +e
    ( stdbuf -oL -eL "$EMU_CMD" --cpu stm32h563 --timeout "$EMU_TIMEOUT" \
          --uart-stdout --quit-on-faults \
          "$SECURE_BIN" \
          "$GUEST0_BIN:$WT_GUEST0_EMU_OFFSET" \
          "$GUEST1_BIN:$WT_GUEST1_EMU_OFFSET" 2>&1
      echo $? >"$RC_FILE"
    ) | tee "$LOG_FILE"
    set -e
    EMU_STATUS=$(cat "$RC_FILE")

    # m33mu repeatedly re-emits `[UART] <hex> attached to <path>` status
    # lines on its own stdout (notably for LPUART1), and with --uart-stdout
    # those messages get spliced into UART output mid-line, breaking
    # `grep -F` against expected guest strings. Strip the attach
    # fragments — including any newline that immediately follows them —
    # so a "guest1[UART]…\n: heartbeat 0" splice rejoins as
    # "guest1: heartbeat 0" before the assertions run.
    CLEAN_LOG=$(mktemp)
    awk '{
        s = $0
        suppress_nl = 0
        while (match(s, /\[UART\] [0-9a-fA-F]+ attached to [^ ]+/)) {
            prefix = substr(s, 1, RSTART - 1)
            rest = substr(s, RSTART + RLENGTH)
            if (rest == "") suppress_nl = 1
            s = prefix rest
        }
        if (suppress_nl) printf "%s", s
        else print s
    }' "$LOG_FILE" >"$CLEAN_LOG"

    if grep -Eq '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)' "$CLEAN_LOG"; then
        rm -f "$CLEAN_LOG"
        exit 1
    fi

    # Assert both guests reached their expected paths. Without these
    # checks a build that boots but never runs would exit cleanly on
    # timeout and look like a pass. EMU_TIMEOUT must allow for at least
    # one guest1 heartbeat cycle (~5 emulated seconds).
    # Common needles — the secure side + Zephyr guest0_psa boot + PSA chain
    # are the same regardless of which guest1 variant is loaded.
    NEEDLES_COMMON="\
*** Booting Zephyr OS|\
wolfHSM client up; devId=0x5748534d registered|\
wolfPSA up; default devId=0x5748534d|\
wolfTrust TEE client initialized|\
tee impl_id=0x57545254|\
tee_invoke_func(cancel) rc=0 ret=0x0|\
psa_initial_attestation short-buffer rejected correctly|\
psa_generate_random st=0|\
psa_hash_compute(SHA-256) KAT verified|\
psa_cipher_encrypt(AES-CTR) st=0"

    # Per-guest1 needles. WT_RUNNER_PROFILE picks which set to assert.
    case "${WT_RUNNER_PROFILE:-baremetal}" in
    freertos)
        NEEDLES_GUEST1="\
freertos_guest1: alive|\
freertos_guest1: ffm sha256 ok|\
freertos_guest1: psa_crypto_init st=0|\
freertos_guest1: psa hash ok|\
freertos_guest1: heartbeat 0"
        ;;
    *)
        NEEDLES_GUEST1="\
guest1: alive|\
guest1: heartbeat 0"
        ;;
    esac

    missing=
    IFS='|'
    set -f
    for needle in $NEEDLES_COMMON $NEEDLES_GUEST1; do
        [ -n "$needle" ] || continue
        if ! grep -Fq "$needle" "$CLEAN_LOG"; then
            missing="${missing}${missing:+, }${needle}"
        fi
    done
    set +f
    unset IFS
    rm -f "$CLEAN_LOG"
    if [ -n "$missing" ]; then
        echo "missing expected output: $missing" >&2
        exit 1
    fi

    # m33mu exits 127 when --timeout fires; for guests that loop forever,
    # that's the expected outcome.
    if [ "$EMU_STATUS" -eq 127 ]; then
        exit 0
    fi
    exit "$EMU_STATUS"
    ;;
*)
    set +e
    "$EMU_CMD" --cpu stm32h563 --timeout "$EMU_TIMEOUT" --quit-on-faults \
        "$SECURE_BIN" \
        "$GUEST0_BIN:$WT_GUEST0_EMU_OFFSET" \
        "$GUEST1_BIN:$WT_GUEST1_EMU_OFFSET"
    EMU_STATUS=$?
    set -e
    if [ "$EMU_STATUS" -eq 127 ]; then
        exit 0
    fi
    exit "$EMU_STATUS"
    ;;
esac
