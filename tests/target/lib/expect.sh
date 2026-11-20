#!/usr/bin/env bash
# Assertion helpers shared by the target scenario runners (M33MU, STM32H5,
# QEMU). Source it, then point WT_EXPECT_LOG at the capture file; every helper
# reads it at call time. The Makefile and the suite drivers grep the
# "  [check] " lines, so that format is fixed.
#
#   WT_EXPECT_LOG=<file>   capture file the helpers assert on
#   WT_EXPECT_GAP=1        `expect` also accepts the marker with bounded
#                          interleaved fragments between its words (boards
#                          where two guests raw-write one UART)
#
#   tests/target/lib/expect.sh --selftest

check_pass() { printf '  [check] PASS  %s\n' "$1"; }
check_fail() { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }

# expect <label> <fixed-string>
expect() {
  local tol
  if grep -Faq "$2" "$WT_EXPECT_LOG"; then check_pass "$1"; return 0; fi
  if [ "${WT_EXPECT_GAP:-0}" = "1" ]; then
    tol=$(printf "%s" "$2" | \
      sed -e 's/[][\\.^$*+?(){}|/]/\\&/g' -e 's/ /.{0,160}/g')
    if grep -zaEq "$tol" "$WT_EXPECT_LOG"; then check_pass "$1"; return 0; fi
  fi
  check_fail "$1" "missing: $2"
}

# expect_flat <label> <fixed-string>: guest1's console or the emulator's UART
# attach note can interject mid-line, so drop both and rejoin split lines.
expect_flat() {
  if sed -e 's/freertos_guest1:.*$//' \
         -e 's/\[UART\] [0-9a-f]* attached to [^ ]*//' "$WT_EXPECT_LOG" | \
      tr -d '\r\n' | grep -Fq "$2"; then
    check_pass "$1"
  else
    check_fail "$1" "missing: $2"
  fi
}

# expect_once <label> <fixed-string>: the marker must appear exactly once
# (a second copy means a core or a guest ran a path it must not have);
# occurrences are counted, not lines, so two copies on one line still fail.
expect_once() {
  local n
  n=$(grep -Fao -- "$2" "$WT_EXPECT_LOG" | wc -l | tr -d ' ' || true)
  if [ "$n" -eq 1 ]; then
    check_pass "$1"
  else
    check_fail "$1" "expected once, found $n: $2"
  fi
}

# refute_re <label> <ERE>
refute_re() {
  if grep -Eq "$2" "$WT_EXPECT_LOG"; then
    check_fail "$1" "unexpected: $2"
  else
    check_pass "$1"
  fi
}

# acs_failed_tests <log>: the Arm FF-A ACS tests whose verdict is FAILED, one
# name per line, sorted and unique. val prints "TEST: <name> SUITE: <group>"
# when a test starts and "RESULT: <verdict>" when it ends, with the test's own
# output in between; a verdict with no test open is ignored.
acs_failed_tests() {
  awk '/TEST: [A-Za-z0-9_]+/ {
         match($0, /TEST: [A-Za-z0-9_]+/)
         name = substr($0, RSTART + 6, RLENGTH - 6)
         next
       }
       /RESULT: FAILED/ { if (name != "") print name }
       /RESULT: / { name = "" }' "$1" | sort -u
}

# acs_failures_ok <failed-total> <by-design names> <log>: succeeds only when
# the tests parsed as FAILED are exactly the by-design set and the ACS-printed
# failed total is that set's size; otherwise prints why and fails, so a lost
# test header, a new failure, or a count the names do not explain all fail.
acs_failures_ok() {
  local want got n name
  want=$(for name in $2; do printf '%s\n' "$name"; done | sort -u | tr '\n' ' ')
  got=$(acs_failed_tests "$3" | tr '\n' ' ')
  n=$(printf '%s' "$want" | wc -w | tr -d ' ')
  if [ "$got" != "$want" ]; then
    echo "failed tests [${got% }] are not the by-design set [${want% }]"
    return 1
  fi
  if [ "$1" != "$n" ]; then
    echo "failed total $1 is not the $n by design"
    return 1
  fi
  return 0
}

# emu_end <status>: how the emulator run in WT_EXPECT_LOG ended. exit is a
# clean status 0; reset-limit is status 0 at an emulator build's reset limit;
# panic is the AArch64 monitor's 0x7e exit; timeout is timeout(1)'s 124.
emu_end() {
  case "$1" in
    0)
      if grep -Faq -e "system_reset done" -e "[QEMU] power-cycle limit" \
          "$WT_EXPECT_LOG"; then
        echo reset-limit
      else
        echo exit
      fi ;;
    126) echo panic ;;
    124) echo timeout ;;
    *) echo "status $1" ;;
  esac
}

# expect_end <label> <want> <status>: the run ended the way the scenario must,
# so markers printed before a hang or a crash never pass on their own.
expect_end() {
  local got
  got="$(emu_end "$3")"
  if [ "$got" = "$2" ]; then
    check_pass "$1"
  else
    check_fail "$1" "ended by $got, want $2"
  fi
}

selftest() {
  local dir fails=0 out
  dir="$(mktemp -d)" || { echo "SELFTEST FAIL: mktemp failed"; exit 1; }
  printf 'wolfTrust TEE client initialized\r\nTOTAL SKfreertos_guest1: hb\r\nIPPED   : 4\r\nguest0_psa freertos_guest1: hb\r\ndone marker\r\n[EL3] twice [EL3] twice\r\n' \
    > "$dir/log"
  export WT_EXPECT_LOG="$dir/log"
  want() { # label expected-output command...
    local label="$1" expected="$2"
    shift 2
    out="$("$@" 2>&1)"
    if [ "$out" != "$expected" ]; then
      echo "SELFTEST FAIL: $label: got '$out'"; fails=$((fails + 1))
    fi
  }
  want_rc() { # label status command...
    local label="$1" rc="$2" got=0
    shift 2
    if "$@" >/dev/null 2>&1; then got=0; else got=$?; fi
    if [ "$got" != "$rc" ]; then
      echo "SELFTEST FAIL: $label: status $got, want $rc"; fails=$((fails + 1))
    fi
  }
  want_fail() { # label command...
    local label="$1"
    shift
    if out="$("$@" 2>&1)"; then
      echo "SELFTEST FAIL: $label: passed ('$out')"; fails=$((fails + 1))
    elif [ "${out#  \[check\] FAIL  }" = "$out" ]; then
      echo "SELFTEST FAIL: $label: no FAIL line ('$out')"; fails=$((fails + 1))
    fi
  }
  # want_fail_strict: like want_fail, but runs the command in a fresh
  # `set -euo pipefail` subshell, matching how the target runners source
  # this file, so a missing marker must still print the FAIL line.
  want_fail_strict() { # label command...
    local label="$1"
    shift
    if out="$(bash -euo pipefail -c \
        'source "$1"; WT_EXPECT_LOG="$2"; shift 2; "$@"' \
        strict-selftest "${BASH_SOURCE[0]}" "$WT_EXPECT_LOG" "$@" 2>&1)"; then
      echo "SELFTEST FAIL: $label: passed ('$out')"; fails=$((fails + 1))
    elif [ "${out#  \[check\] FAIL  }" = "$out" ]; then
      echo "SELFTEST FAIL: $label: no FAIL line ('$out')"; fails=$((fails + 1))
    fi
  }
  want "exact hit" '  [check] PASS  init' expect init 'TEE client initialized'
  want_fail "exact miss" expect init 'never printed'
  want "flat hit" '  [check] PASS  skipped' expect_flat skipped 'TOTAL SKIPPED   : 4'
  want_fail "flat miss" expect_flat skipped 'TOTAL SKIPPED   : 5'
  want "refute clean" '  [check] PASS  nofault' refute_re nofault '^\[MEMFAULT\]'
  want_fail "refute hit" refute_re nofault 'IPPED'
  want "once hit" '  [check] PASS  single' expect_once single 'done marker'
  want_fail "once twice" expect_once single 'freertos_guest1: hb'
  want_fail "once twice on one line" expect_once single '[EL3] twice'
  want_fail "once miss" expect_once single 'never printed'
  want_fail_strict "once miss under pipefail" expect_once single 'never printed'
  want_fail "gap off" expect finish 'guest0_psa done marker'
  want "clean exit" '  [check] PASS  end' expect_end end exit 0
  want "panic exit" '  [check] PASS  end' expect_end end panic 126
  want_fail "timeout after the markers" expect_end end exit 124
  want_fail "panic wanted, timed out" expect_end end panic 124
  want_fail "clean exit wanted, panicked" expect_end end exit 126
  want_fail "emulator crash" expect_end end exit 139
  printf '[EL3] psci system_reset done\r\n' > "$dir/reset"
  WT_EXPECT_LOG="$dir/reset" want "reset limit" '  [check] PASS  end' \
    expect_end end reset-limit 0
  WT_EXPECT_LOG="$dir/reset" want_fail "reset loop is no clean exit" \
    expect_end end exit 0
  printf '[QEMU] power-cycle limit 1 reached\r\n' > "$dir/reset"
  WT_EXPECT_LOG="$dir/reset" want "power-cycle limit" '  [check] PASS  end' \
    expect_end end reset-limit 0
  # The gap fallback relies on GNU grep -z; the runners only run where it is.
  if grep --version 2>/dev/null | head -1 | grep -q '(GNU grep)'; then
    WT_EXPECT_GAP=1 want "gap on" '  [check] PASS  finish' expect finish 'guest0_psa done marker'
  else
    echo "SELFTEST: gap case skipped (needs GNU grep)"
  fi
  # The ACS verdict parser: names come from the TEST: header that precedes
  # each RESULT:, across the test's own output, and the by-design set must
  # explain both the names and the printed total.
  printf '[0000 0]\tTEST: ffa_version SUITE: setup_discovery \r\n[0000 0]\tRESULT: PASSED\r\n[0000 0]\tTEST: ffa_partition_info_get_lsp SUITE: setup_discovery \r\n[0000 0]\tCheck failed: no lsp\r\nfreertos_guest1: hb\r\n[0000 0]\tRESULT: FAILED\r\n[0000 0]\tTEST: ffa_rx_release SUITE: setup_discovery \r\n[0000 0]\tRESULT: SKIPPED\r\n[0000 0]\tTEST: ffa_features SUITE: setup_discovery \r\n[0000 0]\tRESULT: PASSED\r\n[0000 0]\tRESULT: FAILED\r\n[0000 0]\t   TOTAL FAILED    : 1\r\n' \
    > "$dir/acs"
  want "acs parse" 'ffa_partition_info_get_lsp' acs_failed_tests "$dir/acs"
  want_rc "acs by design" 0 acs_failures_ok 1 'ffa_partition_info_get_lsp' "$dir/acs"
  want_rc "acs total above the names" 1 acs_failures_ok 2 'ffa_partition_info_get_lsp' "$dir/acs"
  want_rc "acs total below the names" 1 acs_failures_ok 0 'ffa_partition_info_get_lsp' "$dir/acs"
  want_rc "acs failure not by design" 1 acs_failures_ok 1 '' "$dir/acs"
  want_rc "acs by-design name missing from the log" 1 acs_failures_ok 1 'ffa_partition_info_get_lsp ffa_features' "$dir/acs"
  want_rc "acs total unparsed" 1 acs_failures_ok -1 'ffa_partition_info_get_lsp' "$dir/acs"
  printf '[0000 0]\tTEST: b_test SUITE: g \r\n[0000 0]\tRESULT: FAILED\r\n[0000 0]\tTEST: a_test SUITE: g \r\n[0000 0]\tRESULT: FAILED\r\n[0000 0]\tTEST: c_test SUITE: g \r\n[0000 0]\tRESULT: PASSED\r\n' \
    > "$dir/acs2"
  want_rc "acs two by design in any order" 0 acs_failures_ok 2 'b_test a_test' "$dir/acs2"
  want_rc "acs two failed, one by design" 1 acs_failures_ok 2 'a_test' "$dir/acs2"
  printf '[0000 0]\tTEST: a_test SUITE: g \r\n[0000 0]\tRESULT: PASSED\r\n' > "$dir/acs3"
  want_rc "acs clean group" 0 acs_failures_ok 0 '' "$dir/acs3"
  want_rc "acs clean group with a deviation recorded" 1 acs_failures_ok 0 'a_test' "$dir/acs3"
  rm -rf "$dir"
  if [ "$fails" -ne 0 ]; then echo "SELFTEST: $fails failure(s)"; exit 1; fi
  echo "SELFTEST: ok"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --selftest) selftest ;;
    *) echo "usage: $0 --selftest  (or source it from a runner)" >&2; exit 2 ;;
  esac
fi
