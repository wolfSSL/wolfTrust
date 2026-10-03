#!/usr/bin/env bash
# provisioning_ctrl.sh
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# wolfTrust provisioning control: one command set for every port. TARGET picks
# the port file (provisioning_ctrl_<target>.sh), which answers the device
# questions; everything that guards a permanent write lives here, once.
# See docs/Provisioning.md.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
target="${TARGET:-stm32h563}"
port_file="$here/provisioning_ctrl_$target.sh"
state_dir="${WT_PROVISION_STATE:-$HOME/.cache/wolftrust}/$target"
rehearsal_max_age="${WT_REHEARSAL_MAX_AGE:-3600}"
cmd="${1:-help}"
[ "$#" -eq 0 ] || shift

pass()   { printf '  [check] PASS  %s\n' "$1"; }
fail()   { printf '  [check] FAIL  %s  (%s)\n' "$1" "$2"; exit 1; }
refuse() { echo "REFUSED: $1" >&2; exit 2; }
confirm() {
  [ "${WT_LOCK_CONFIRM:-0}" = "1" ] ||
    refuse "'$cmd' writes to the board. Re-run with WT_LOCK_CONFIRM=1."
}
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
}
hexstate() { printf '0x%02X' "$(( $1 ))"; }
put()   { mkdir -p "$state_dir"; echo "$2" > "$state_dir/$1"; }
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<<" $2"; }
age_of() { echo $(( $(date +%s) - ${1:-0} )); }
fresh() {
  local age
  [ -n "${1:-}" ] || return 1
  age="$(age_of "$1")"
  [ "$age" -ge 0 ] && [ "$age" -le "$rehearsal_max_age" ]
}

# The port's flashed_images, each address and length ahead of its bytes, so
# moving bytes between images changes the digest.
framed_digest() {
  local a f
  while read -r a f; do [ -s "$f" ] || return 1; done < <(flashed_images)
  flashed_images | while read -r a f; do
    printf '%s %s\n' "$a" "$(wc -c < "$f" | tr -d ' ')"
    cat "$f"
  done | sha256 | cut -c1-64
}

# A rehearsal record binds these images, credentials, and part, recently.
rehearsal_ok() {
  [ -n "$1" ] && [ "$(field image "$1")" = "$2" ] && [ "$(field cred "$1")" = "$3" ] &&
    fresh "$(field completed "$1")" && port_record_ok "$1"
}

ports() {
  local f
  for f in "$here"/provisioning_ctrl_*.sh; do
    f="${f##*/provisioning_ctrl_}"
    printf '%s ' "${f%.sh}"
  done
}
# Evidence (UART captures, image read-backs) stays in a private directory.
wt_tmp="$(mktemp -d "${TMPDIR:-/tmp}/wolftrust.XXXXXX")"
trap 'rm -rf "$wt_tmp"' EXIT
[ -f "$port_file" ] || refuse "no provisioning port for TARGET=$target (have: $(ports))"
# shellcheck source=provisioning_ctrl_stm32h563.sh
. "$port_file"

# The port's ladder: "code name mock lock permanence from-codes" per line.
ladder_line() {
  local code=""
  if [[ "$1" =~ ^0[xX][0-9A-Fa-f]{1,2}$ ]]; then code="$(hexstate "$1")"; fi
  port_ladder | awk -v c="$code" -v n="$1" '$1 == c || $2 == n { print; exit }'
}
state_name() { port_ladder | awk -v c="$1" '$1 == c { print $2; exit }'; }
label() { echo "$(state_name "$1") ($1)"; }
# resolve <state> <column>: the code, if the ladder allows that use.
resolve() {
  local line
  line="$(ladder_line "${1:-}")"
  [ -n "$line" ] || refuse "unknown state '${1:-}'. $PORT_NAME states: $(port_ladder | awk '{ printf "%s %s, ", $1, $2 }')"
  case "$2" in
    mock) [ "$(awk '{print $3}' <<<"$line")" = "yes" ] ||
      refuse "$(awk '{print $2 " (" $1 ")"}' <<<"$line") has no mock: it is a permanent state, set only by 'lock'." ;;
    lock) [ "$(awk '{print $4}' <<<"$line")" = "yes" ] ||
      refuse "$(awk '{print $2 " (" $1 ")"}' <<<"$line") is not a lock target." ;;
  esac
  awk '{print $1}' <<<"$line"
}

usage() {
  cat <<EOF
usage: TARGET=$target $0 <command> [state]

  status              read the part's life cycle and protections
  discover            read-only preflight for this port
  restore             flash the production images and verify them (writes)
  advance <state>     mock: enter <state> reversibly and record a rehearsal (writes)
  regress             return from the mock state and complete the rehearsal (writes)
  lock <state>        real: make the next step permanent; previews unless
                      WT_LOCK_CONFIRM=1, writes only with WT_PRODUCTION_LOCK=1
                      and a typed "I ACCEPT <state>"
$(port_usage_extra)
$PORT_NAME states (code name; mock; lock; permanence; from):
$(port_ladder | awk '{ printf "  %-6s %-18s mock=%-3s lock=%-3s %-10s from %s\n", $1, $2, $3, $4, $5, $6 }')
EOF
}

# The last gate: a production station opts in, and a person at a terminal
# types the acceptance back. Nothing piped or scripted can pass it.
lock_confirm() {
  local answer
  [ "${WT_PRODUCTION_LOCK:-0}" = "1" ] ||
    refuse "$2 is a production lock step. Only a production station sets WT_PRODUCTION_LOCK=1."
  [ -t 0 ] || refuse "a production lock needs an interactive terminal, not a pipe or script."
  printf '\n!!! %s\n!!! %s\n!!! Are you sure? Type "%s" to continue: ' "$2" "$3" "$1" >&2
  read -r answer || answer=""
  [ "$answer" = "$1" ] || refuse "confirmation did not match; nothing was changed."
}

case "$cmd" in
  help|-h|--help) usage ;;
  status) port_status ;;
  discover) port_discover ;;
  restore) confirm; port_restore ;;

  advance)
    confirm
    state="$(resolve "${1:-}" mock)"
    port_advance_check "$state"
    run="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    rm -f "$state_dir/pending"
    port_advance "$state"
    EVIDENCE=""
    if port_booted "$state"; then
      put pending "state=$state run=$run $EVIDENCE time=$(date +%s)"
      echo "rehearsal of $(label "$state") recorded; 'regress' completes it"
    else
      fail "advance" "no rehearsal recorded: $(label "$state") did not show the evidence above"
    fi
    ;;

  regress)
    confirm
    PENDING="$(cat "$state_dir/pending" 2>/dev/null || true)"
    rm -f "$state_dir/pending"
    REGRESS_EXTRA=""
    # With nothing pending this is plain recovery: it returns the part, records nothing.
    port_regress || fail "regress" "regression did not complete; nothing was recorded"
    if [ -n "$PENDING" ]; then
      s="$(field state "$PENDING")"
      put "rehearsal-$s" "$PENDING cred=$(port_cred_fp) $REGRESS_EXTRA completed=$(date +%s)"
      pass "rehearsal of $(label "$s") complete"
    fi
    ;;

  lock)
    # One permanent step: the next state only, rehearsed on this part with
    # these images, previewed, then written only past every gate below.
    [ "$#" -le 1 ] || refuse "lock takes one state."
    state="$(resolve "${1:-}" lock)"
    line="$(ladder_line "$state")"
    cur="$(port_lock_current)"
    from="$(awk '{print $6}' <<<"$line" | tr ',' ' ')"
    case " $from " in
      *" $cur "*) ;;
      *) refuse "the part is $(label "$cur"); lock $state runs only from $(for f in $from; do printf '%s ' "$(label "$f")"; done)" ;;
    esac
    image="$(port_image_digest)" || refuse "missing a flashed image: build the production images first."
    cred="$(port_cred_fp)"
    rec=""
    for s in $(port_rehearsal_for "$state"); do
      r="$(cat "$state_dir/rehearsal-$s" 2>/dev/null || true)"
      if rehearsal_ok "$r" "$image" "$cred"; then
        rec="$r"
        break
      fi
    done
    [ -n "$rec" ] ||
      refuse "no rehearsal for $(label "$state") on this part with these images and credentials in the last ${rehearsal_max_age}s: run 'advance $(port_rehearsal_for "$state" | awk '{print $NF}')' and 'regress' first."
    checked="next state, rehearsal of $(label "$(field state "$rec")") with images ${image:0:16} ($(age_of "$(field completed "$rec")")s ago)"
    id="$(port_lock_identity)"
    if [ -n "$id" ]; then
      [ "$id" = "$(field id "$rec")" ] ||
        refuse "this part ($id) is not the one rehearsed ($(field id "$rec")): rehearse this part."
      checked="$checked, same part $id"
    else
      checked="$checked, part identity not readable here (needs WT_FIXTURE_BOUND=1)"
    fi
    # port_ready refuses or appends ", <check>" items to CHECKED.
    CHECKED="$checked"
    port_ready "$state"
    checked="$CHECKED"
    echo "Lock step: $(label "$cur") -> $(label "$state")"
    echo "  checked: $checked"
    port_lock_plan "$state" | sed 's/^/  will run: /'
    [ "${WT_LOCK_CONFIRM:-0}" = "1" ] ||
      refuse "preview only, nothing was written. A production station re-runs this with WT_LOCK_CONFIRM=1."
    [ -n "$id" ] || [ "${WT_FIXTURE_BOUND:-0}" = "1" ] ||
      refuse "the part's identity cannot be read in this state, so nothing proves it is the rehearsed one: run this only on a fixture that holds one part from rehearsal to lock, and set WT_FIXTURE_BOUND=1 there."
    if [ "$(awk '{print $5}' <<<"$line")" = "permanent" ]; then
      why="This is IRREVERSIBLE: $(port_consequence "$state")"
    else
      why="$(port_consequence "$state")"
    fi
    lock_confirm "I ACCEPT $state" "Moving this $PORT_NAME to $(label "$state")" "$why"
    # The prompt can wait a long time: check the part again right before the write.
    [ "$(port_lock_current)" = "$cur" ] || refuse "the part changed while waiting for the acceptance; nothing was changed."
    if [ "$(cat "$state_dir/rehearsal-$(field state "$rec")" 2>/dev/null || true)" != "$rec" ] ||
       ! rehearsal_ok "$rec" "$(port_image_digest || true)" "$(port_cred_fp)"; then
      refuse "the rehearsal no longer matches these images, credentials, and part, or it expired while waiting; nothing was changed."
    fi
    [ -z "$id" ] || [ "$(port_lock_identity)" = "$id" ] ||
      refuse "a different part is attached than the one checked; nothing was changed."
    port_ready "$state"
    port_lock_write "$state"
    port_lock_verify "$state"
    # Single use: a permanent step consumes even a rehearsal of another state.
    if [ "$(field state "$rec")" = "$state" ] || [ "$(awk '{print $5}' <<<"$line")" = "permanent" ]; then
      rm -f "$state_dir/rehearsal-$(field state "$rec")"
    fi
    pass "$PORT_NAME is $(label "$state")"
    ;;

  *)
    port_extra "$cmd" "$@" || { usage >&2; exit 2; }
    ;;
esac
