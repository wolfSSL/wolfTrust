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
expect_re() { check "$([ "$(count_re "$2")" -ge 1 ]; echo $?)" "$1"; }
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
        periphspneg)      echo "WT_PERIPH_SP_NEG_PROBE=1" ;;
        deputyneg)        echo "WT_DEPUTY_NEG_PROBE=1" ;;
        bandneg[1-6])     echo "WT_BAND_NEG_PROBE=${1#bandneg}" ;;
        restartneg[1-3])  echo "WT_RESTART_NEG_PROBE=${1#restartneg}" ;;
        hsmpinneg)        echo "WT_HSM_PIN_NEG_PROBE=1" ;;
        spfaultneg)       echo "WT_SP_FAULT_PROBE=1" ;;
        hsmfaultneg)      echo "WT_HSM_FAULT_PROBE=1" ;;
        panicneg)         echo "WT_PANIC_NEG_PROBE=1" ;;
        confboot|devstorage|devcrypto|devattest|devattestqcbor)
                          echo "WT_CONFORMANCE=1" ;;
        vaultrecover)     echo "WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1" ;;
        vaultrecoversec)  echo "WT_CONFORMANCE=1 WT_VAULT_FOREIGN_PROBE=1 WT_VAULT_PROBE_SECURED=1" ;;
        rollbackneg)      echo "WT_ROLLBACK_PROBE=1" ;;
        remeasureneg)     echo "WT_REMEASURE_PROBE=1" ;;
        bootupdate)       echo "WT_BOOTUPDATE_PROBE=1" ;;
        spbudgetneg)      echo "WT_SP_FAULT_ALWAYS_PROBE=1" ;;
        wrpfence|wrpoff|wrpneg) echo "WT_GUEST_FLASH_WRP=1" ;;
        vnet)             echo "CONFIG_VNET=y" ;;
        vnetneg)          echo "CONFIG_VNET=y WT_VNET_NEG_PROBE=1" ;;
        manifestneg)      echo "WT_MANIFEST_NEG_PROBE=1" ;;
        manifestneg2)     echo "WT_MANIFEST_NEG_PROBE=2" ;;
        fpneg)            echo "WT_SP_FAULT_PROBE=1 WT_FP_NEG_PROBE=1" ;;
        sealneg)          echo "WT_SEAL_NEG_PROBE=1" ;;
        sealhaltneg)      echo "WT_SEAL_NEG_PROBE=2" ;;
        sealbootneg)      echo "WT_SEAL_NEG_PROBE=3" ;;
        sealpivotneg)     echo "WT_SEAL_NEG_PROBE=4" ;;
        mspovfneg)        echo "WT_MSP_OVF_PROBE=1" ;;
        busfaultneg)      echo "WT_BUSFAULT_NEG_PROBE=1" ;;
        xnneg)            echo "WT_XN_NEG_PROBE=1" ;;
        svcneg)           echo "WT_SVC_NEG_PROBE=1" ;;
        manifestneg3)     echo "WT_MANIFEST_NEG_PROBE=3" ;;
        *)                echo "" ;;
    esac
}

# How a passing run concludes: "idle" ends however the port's guests normally
# end; "bkpt:0xNN" ends on a Secure verdict breakpoint the emulator exits on.
scenario_end() {
    case "$1" in
        rollbackneg|spbudgetneg) echo "bkpt:0x7d" ;;
        manifestneg|manifestneg2|manifestneg3|sealbootneg) echo "bkpt:0x7e" ;;
        sealhaltneg)             echo "bkpt:0x6e" ;;
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
            expect "clean re-measure passed, then the in-flash tamper was caught before dispatch" \
                "[BKPT] imm=0x6c"
            ;;
        manifestneg|manifestneg2|manifestneg3)
            expect "boot halted on the production manifest-validation panic" \
                "[BKPT] imm=0x7e"
            refute_re "no guest scheduled off the corrupted manifest" \
                "$GUEST_STARTED_RE"
            ;;
        sealbootneg)
            expect "boot halted on the damaged main-stack seal" \
                "[BKPT] imm=0x7e"
            refute_re "no guest scheduled after the refused boot" \
                "$GUEST_STARTED_RE"
            ;;
        spbudgetneg)
            expect "restart budget exhaustion escalated to platform recovery" \
                "[BKPT] imm=0x7d"
            refute_re "the mandatory service never completed a guest lifecycle" \
                "$GUEST_DONE_RE"
            ;;
        xnneg)
            # M33MU pends a synchronous fault that cannot preempt the active
            # SVC instead of escalating it, so the production halt is
            # asserted on silicon; the emulator proves the fetch was denied.
            expect_re "privileged execution from SPM RAM faulted (IACCVIOL)" \
                '\[MEMFAULT\] pc=0x30[0-9a-f]{6} addr=0x30[0-9a-f]{6}'
            refute_re "the thunk never returned into the gate" '\[USGFLT\]'
            refute_re "no clean lifecycle after the SPM fault" \
                '\[BKPT\] imm=0x7f'
            ;;
        mspovfneg)
            # M33MU escalates the entry-time STKOF to HardFault and ends the
            # run there without executing the handler; the production halt
            # is asserted on silicon through the SPM fault latch.
            expect_re "main-stack overflow raised STKOF against MSPLIM_S" \
                '\[(USGFLT|HARDFLT)\].*CFSR=0x00[1-9a-f][0-9a-f]0000'
            expect "the emulator ended the run at the SPM fault" \
                "Execution stopped"
            refute_re "no guest scheduled after the refused boot" \
                "$GUEST_STARTED_RE"
            ;;
        *)
            fail "scenario_assert_verdict: no verdict table for '$1'"
            ;;
    esac
}
