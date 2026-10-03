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
        sealhaltneg)
            expect "damaged seal halted the platform at dispatch" \
                "[BKPT] imm=0x6e"
            refute_re "partition with the damaged seal was never resumed" \
                '\[USGFLT\]'
            refute_re "run did not reach a clean success exit" \
                '\[BKPT\] imm=0x7f'
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

# Isolation level 3 addresses of port/$2 (band, partition stack and SPM
# peripheral), read from its memory_map.h so no runner copies them.
l3_layout_load() {
    local vars
    vars="$(python3 "$1/tools/l3_layout_args.py" --shell \
        --cc "${L3_CPP:-arm-none-eabi-gcc}" -I "$1/include" \
        -I "$1/lib/wolfhal" "$1/port/$2/memory_map.h")" ||
        fail "could not read the level 3 layout of port/$2"
    eval "$vars"
}

# The band a bandneg probe touches and the stack its prober runs on.
l3_bandneg_target() {
    case "$1" in
        1) L3_BAND=$L3_VAULT_BAND;  L3_SP_LO=$L3_CRYPTO_STACK_LO
           L3_SP_HI=$L3_CRYPTO_STACK_HI
           L3_WHAT="crypto partition denied the vault's band" ;;
        2) L3_BAND=$L3_ATTEST_BAND; L3_SP_LO=$L3_CRYPTO_STACK_LO
           L3_SP_HI=$L3_CRYPTO_STACK_HI
           L3_WHAT="crypto partition denied the attestation band" ;;
        3) L3_BAND=$L3_VAULT_BAND;  L3_SP_LO=$L3_ATTEST_STACK_LO
           L3_SP_HI=$L3_ATTEST_STACK_HI
           L3_WHAT="attestation partition denied the vault's band" ;;
        4) L3_BAND=$L3_HSM_BAND;    L3_SP_LO=$L3_ATTEST_STACK_LO
           L3_SP_HI=$L3_ATTEST_STACK_HI
           L3_WHAT="attestation partition denied the crypto band" ;;
        5) L3_BAND=$L3_ATTEST_BAND; L3_SP_LO=$L3_VAULT_STACK_LO
           L3_SP_HI=$L3_VAULT_STACK_HI
           L3_WHAT="vault denied the attestation band" ;;
        6) L3_BAND=$L3_HSM_BAND;    L3_SP_LO=$L3_VAULT_STACK_LO
           L3_SP_HI=$L3_VAULT_STACK_HI
           L3_WHAT="vault denied the crypto band" ;;
        *) fail "l3_bandneg_target: no bandneg probe $1" ;;
    esac
}

# MemManage faults at exactly address $1 in $log; with $2/$3, only those whose
# stacked SP (the dump's next line) lies in [$2, $3).
l3_faults_at() {
    awk -v want="$(printf '%s' "$1" | tr 'A-F' 'a-f')" -v lo="${2:-}" \
        -v hi="${3:-}" '
        function h(s,  i, n) {
            s = tolower(s); sub(/^0x/, "", s); n = 0
            for (i = 1; i <= length(s); i++)
                n = n * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1
            return n
        }
        pending && /^\[MEMFAULT\] sp=/ {
            split($2, f, "="); sp = h(f[2])
            if (sp >= h(lo) && sp < h(hi)) n++
            pending = 0; next
        }
        { pending = 0 }
        /^\[MEMFAULT\] pc=/ {
            for (i = 2; i <= NF; i++) if ($i == "addr=" want) {
                if (lo == "") n++; else pending = 1
            }
        }
        END { print n + 0 }' "$log"
}

# Port-independent fault checks for the level 3 negatives. The runner sets
# $log and loads the layout first; lifecycle markers stay with the runner.
scenario_assert_l3() {
    local n
    case "$1" in
        crossdomain)
            n="$(l3_faults_at "$L3_SPM_RAM")"
            check "$([ "$n" -ge 1 ]; echo $?)" \
                "cross-domain read of SPM RAM $L3_SPM_RAM denied (MEMFAULT)" ;;
        keystoreneg)
            n="$(l3_faults_at "$L3_VAULT_BAND")"
            check "$([ "$n" -ge 1 ]; echo $?)" \
                "vault band read $L3_VAULT_BAND denied to a non-keystore SP (MEMFAULT)" ;;
        periphspneg)
            n="$(l3_faults_at "$L3_SPM_PERIPHERAL")"
            check "$([ "$n" -ge 1 ]; echo $?)" \
                "SP read of the SPM's peripheral at $L3_SPM_PERIPHERAL denied (MEMFAULT)" ;;
        bandneg[1-6])
            l3_bandneg_target "${1#bandneg}"
            n="$(l3_faults_at "$L3_BAND")"
            check "$(( n == 2 ? 0 : 1 ))" \
                "$L3_WHAT, read then write (2 MEMFAULTs at $L3_BAND, saw $n)"
            n="$(l3_faults_at "$L3_BAND" "$L3_SP_LO" "$L3_SP_HI")"
            check "$([ "$n" -eq 2 ]; echo $?)" \
                "both faults taken on the prober's own stack (saw $n)"
            refute_re "no access ran past its fault, no keystore pin was open" \
                '^\[USGFLT\]'
            refute_re "faults were contained, not escalated" \
                '^(\[HARDFLT\]|HardFault|SecureFault)' ;;
        restartneg[1-3])
            # The partition faults once (udf #0) after planting band state;
            # a restart on an unreset band traps again on udf #2.
            n="$(count_re '^\[USGFLT\] CFSR=0x00010000')"
            check "$([ "$n" -eq 1 ]; echo $?)" \
                "partition faulted once and restarted on a reset band (saw $n)"
            refute_re "the fault was the planted one" \
                '^\[USGFLT\] mem16\[[^]]*\]=0xde02'
            refute_re "fault was contained, not escalated" \
                '^(\[MEMFAULT\]|\[HARDFLT\]|HardFault|SecureFault)' ;;
        sealneg|sealpivotneg|svcneg)
            # The offending partition is resumed on the panic trap (udf #0x50).
            n="$(count_re '^\[USGFLT\] mem16\[0x[0-9a-f]+\]=0xde50')"
            check "$([ "$n" -ge 1 ] && [ "$(count_re '\[USGFLT\].*CFSR=0x00010000')" -ge 1 ]; echo $?)" \
                "the partition was panicked on the panic trap (Secure-Thread UNDEFINSTR)"
            refute_re "partition fault was contained, not escalated" \
                '(\[HARDFLT\]|HardFault|SecureFault)'
            refute_re "platform did not halt on the partition's fault" \
                '\[BKPT\] imm=0x(6e|7e|7d)' ;;
        hsmfaultneg)
            expect "the guest's HSM tasklet faulted" "[USGFLT]"
            refute_re "HSM fault stayed contained" \
                '(\[HARDFLT\]|HardFault|SecureFault|\[BKPT\] imm=0x7e)' ;;
        *)
            fail "scenario_assert_l3: no level 3 checks for '$1'" ;;
    esac
}

# A probe the scenario relies on must be linked in, or its pass is vacuous.
l3_assert_probe_linked() {
    local syms="$1.syms"
    "${CROSS_COMPILE:-arm-none-eabi-}nm" "$1" > "$syms" ||
        fail "nm on $1 failed"
    check "$(grep -q " $2\$" "$syms"; echo $?)" "$2 linked into the secure image"
}
