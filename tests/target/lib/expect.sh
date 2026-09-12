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

# expect_flat <label> <fixed-string>: guest1's console can interject mid-line
# in a secure print, so drop its text and rejoin split lines before matching.
expect_flat() {
  if sed 's/freertos_guest1:.*$//' "$WT_EXPECT_LOG" | tr -d '\r\n' | \
      grep -Fq "$2"; then
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
  n=$(grep -Fao -- "$2" "$WT_EXPECT_LOG" | wc -l | tr -d ' ')
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

selftest() {
  local dir fails=0 out
  dir="$(mktemp -d)"
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
  want_fail() { # label command...
    local label="$1"
    shift
    if out="$("$@" 2>&1)"; then
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
  want_fail "gap off" expect finish 'guest0_psa done marker'
  # The gap fallback relies on GNU grep -z; the runners only run where it is.
  if grep --version 2>/dev/null | head -1 | grep -q '(GNU grep)'; then
    WT_EXPECT_GAP=1 want "gap on" '  [check] PASS  finish' expect finish 'guest0_psa done marker'
  else
    echo "SELFTEST: gap case skipped (needs GNU grep)"
  fi
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
