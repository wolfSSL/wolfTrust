# shellcheck shell=bash
# Shared scenario vocabulary for the target runners. One table maps each
# scenario to its Secure-image probe flags and its verdict, so every port's
# adapter (H5/RT700, emulator/hardware) runs the same matrix; a runner
# supplies the port-specific markers and its own positive checks.

log()   { printf '%s\n' "$*"; }
stage() { log "== $*"; }
fail()  { log "FAIL: $*"; exit 1; }
check() { if [ "$1" -eq 0 ]; then log "  [check] PASS  $2"; \
          else log "  [check] FAIL  $2"; exit 1; fi; }
# shellcheck disable=SC2154  # $log is the sourcing runner's boot log path
count()     { grep -c -F -- "$1" "$log" || true; }
count_re()  { grep -c -E -- "$1" "$log" || true; }
expect()    { check "$([ "$(count "$2")" -ge 1 ]; echo $?)" "$1"; }
refute_re() { check "$([ "$(count_re "$2")" -eq 0 ]; echo $?)" "$1"; }
expect_n()  { local n; n="$(count "$3")"; \
              check "$([ "$n" -eq "$2" ]; echo $?)" "$1 ($n)"; }
expect_n_re() { local n; n="$(count_re "$3")"; \
                check "$([ "$n" -eq "$2" ]; echo $?)" "$1 ($n)"; }

# Secure-image build flags per scenario ("" = the production image).
scenario_secure_flags() {
    case "$1" in
        crossdomain)      echo "WT_FFM_NEGATIVE_PROBE=1" ;;
        keystoreneg)      echo "WT_KEYSTORE_NEG_PROBE=1" ;;
        spfaultneg)       echo "WT_SP_FAULT_PROBE=1" ;;
        panicneg)         echo "WT_PANIC_NEG_PROBE=1" ;;
        confboot|devstorage|devcrypto|devattest|devattestqcbor)
                          echo "WT_CONFORMANCE=1" ;;
        vaultrecover)     echo "WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1" ;;
        vaultrecoversec)  echo "WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1 WT_VAULT_PROBE_SECURED=1" ;;
        rollbackneg)      echo "WT_ROLLBACK_PROBE=1" ;;
        remeasureneg)     echo "WT_REMEASURE_PROBE=1" ;;
        bootupdate)       echo "WT_BOOTUPDATE_PROBE=1" ;;
        spbudgetneg)      echo "WT_SP_FAULT_ALWAYS_PROBE=1" ;;
        vnet)             echo "CONFIG_VNET=y" ;;
        vnetneg)          echo "CONFIG_VNET=y WT_VNET_NEG_PROBE=1" ;;
        manifestneg)      echo "WT_MANIFEST_NEG_PROBE=1" ;;
        *)                echo "" ;;
    esac
}

# How a passing run concludes: "idle" ends however the port's guests normally
# end; "bkpt:0xNN" ends on a Secure verdict breakpoint the emulator exits on.
scenario_end() {
    case "$1" in
        rollbackneg|spbudgetneg) echo "bkpt:0x7d" ;;
        manifestneg)             echo "bkpt:0x7e" ;;
        remeasureneg)            echo "bkpt:0x6c" ;;
        *)                       echo "idle" ;;
    esac
}

# Port-independent assertions for the Secure-verdict scenarios. The adapter
# sets $log, GUEST_STARTED_RE (any guest banner), and GUEST_DONE_RE (a guest
# completed its FF-M lifecycle) before calling.
scenario_assert_verdict() {
    case "$1" in
        rollbackneg)
            refute_re "no fault markers in the boot log" \
                '\[MEMFAULT\]|\[HARDFLT\]|HardFault'
            expect "downgraded boot refused fail-closed (all guests quarantined)" \
                "[BKPT] imm=0x7d"
            refute_re "no guest entered a domain after the floor armed" \
                "$GUEST_STARTED_RE"
            ;;
        remeasureneg)
            refute_re "no fault markers in the boot log" \
                '\[MEMFAULT\]|\[HARDFLT\]|HardFault'
            expect "clean re-measure passed, then the post-launch tamper quarantined" \
                "[BKPT] imm=0x6c"
            ;;
        manifestneg)
            expect "boot halted on the production manifest-validation panic" \
                "[BKPT] imm=0x7e"
            refute_re "no guest scheduled off the corrupted manifest" \
                "$GUEST_STARTED_RE"
            ;;
        spbudgetneg)
            expect "restart budget exhaustion escalated to platform recovery" \
                "[BKPT] imm=0x7d"
            refute_re "the mandatory service never completed a guest lifecycle" \
                "$GUEST_DONE_RE"
            ;;
        *)
            fail "scenario_assert_verdict: no verdict table for '$1'"
            ;;
    esac
}
