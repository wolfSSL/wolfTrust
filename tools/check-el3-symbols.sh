#!/usr/bin/env bash
# EL3 image guard (WT-PORT-0012). The AArch64 monitor archive may leave
# unresolved only the symbols allowed by tools/el3-symbols.allow, may define
# globally only the monitor symbols tools/el3-defines.allow names, and may not
# define anything, global or local, that belongs to the SPM, the services, or
# a crypto library. References resolved inside the archive itself are fine.
#
#   tools/check-el3-symbols.sh <libwt_el3.a> [--nm <nm>]
#   tools/check-el3-symbols.sh --nm-file <listing>     (output of plain nm)
#   tools/check-el3-symbols.sh --selftest
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
ALLOW="$root/tools/el3-symbols.allow"
DEFINES="$root/tools/el3-defines.allow"
DENY='^(wt_ffm_|wt_spm_|wt_monitor_|wt_hsm_|wt_attest|wt_vault|wt_its_|wt_ps_|wt_fwu|wt_vnet|wt_ffa_(notif|partinfo|rt)_|wt_psa_|wc_|wh_|psa_)'

# valid_ere <pattern> : true unless grep -E rejects <pattern> as malformed
# (a grep exit status of 2 or more; 0/1 are match/no-match, both fine).
valid_ere() {
  local rc
  grep -E -q -- "$1" /dev/null 2>/dev/null
  rc=$?
  [ "$rc" -le 1 ]
}

# valid_patterns <label> <patterns> : true only if every non-blank line of
# the newline-separated <patterns> is a valid ERE; names the bad line
# otherwise so a single typo can't silently blind the whole allow-list.
valid_patterns() {
  local label="$1" patterns="$2" line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if ! valid_ere "$line"; then
      echo "  invalid pattern in $label: $line"
      return 1
    fi
  done < <(printf '%s\n' "$patterns")
  return 0
}

# audit <allow-file> <defines-file> < nm-listing : prints offenders, fails if
# there are any. Fails closed (returns 1) on an unreadable or empty
# allow-list, a malformed pattern in either allow-list, or any matcher
# error, instead of treating those as "no offenders".
audit() {
  local allow="$1" defines="$2" pats defpats defined globals undefined bad=0 hit out rc

  if [ ! -r "$allow" ]; then
    echo "  allow-list unreadable: $allow"
    return 1
  fi
  if [ ! -r "$defines" ]; then
    echo "  defines allow-list unreadable: $defines"
    return 1
  fi
  pats="$(grep -vE '^[[:space:]]*(#|$)' "$allow")"
  defpats="$(grep -vE '^[[:space:]]*(#|$)' "$defines")"
  if [ -z "$pats" ]; then
    echo "  allow-list has no patterns: $allow"
    return 1
  fi
  if [ -z "$defpats" ]; then
    echo "  defines allow-list has no patterns: $defines"
    return 1
  fi
  valid_patterns "$allow" "$pats" || return 1
  valid_patterns "$defines" "$defpats" || return 1

  listing="$(cat)"
  defined="$(printf '%s\n' "$listing" | awk 'NF==3 && $2!="U" && $2!="w" && $2!="v" {print $3}' | sort -u)"
  globals="$(printf '%s\n' "$listing" | awk 'NF==3 && (($2 ~ /^[A-Z]$/ && $2!="U") || $2=="u") {print $3}' | sort -u)"
  undefined="$(printf '%s\n' "$listing" | awk 'NF==2 && ($1=="U" || $1=="w" || $1=="v") {print $2}' | sort -u)"
  # Only a global definition resolves a reference from another object.
  if [ -n "$globals" ]; then
    undefined="$(printf '%s\n' "$undefined" | grep -vxF -f <(printf '%s\n' "$globals"))"
    rc=$?
    if [ "$rc" -ge 2 ]; then
      echo "  internal error filtering resolved symbols"
      return 1
    fi
  fi

  out="$(printf '%s\n' "$undefined" | grep -vE -f <(printf '%s\n' "$pats"))"
  rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "  allow-list matcher error: $allow"
    return 1
  fi
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  unresolved symbol outside the allow-list: $hit"
    bad=$((bad + 1))
  done < <(printf '%s\n' "$out")

  out="$(printf '%s\n' "$defined" | grep -E "$DENY")"
  rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "  internal error matching the deny pattern"
    return 1
  fi
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  core, service, or crypto symbol defined inside the EL3 archive: $hit"
    bad=$((bad + 1))
  done < <(printf '%s\n' "$out")

  out="$(printf '%s\n' "$globals" | grep -vE -f <(printf '%s\n' "$defpats"))"
  rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "  defines allow-list matcher error: $defines"
    return 1
  fi
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  global symbol the monitor does not define inside the EL3 archive: $hit"
    bad=$((bad + 1))
  done < <(printf '%s\n' "$out")
  # A local (static) wolfTrust-named definition is held to the same monitor
  # namespaces: a core helper compiled into an EL3 object stays visible.
  # The compiler's clones (name.constprop.N, .isra.N, .part.N, .cold) are
  # matched by the name they were cloned from.
  locals="$(printf '%s\n' "$listing" | awk 'NF==3 && $2 ~ /^[a-z]$/ && $3 ~ /^(g_)?wt_/ {sub(/\..*$/, "", $3); print $3}' | sort -u)"
  out="$(printf '%s\n' "$locals" | grep -vE -f <(printf '%s\n' "$defpats"))"
  rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "  defines allow-list matcher error: $defines"
    return 1
  fi
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  local wolfTrust symbol outside the monitor namespaces inside the EL3 archive: $hit"
    bad=$((bad + 1))
  done < <(printf '%s\n' "$out")

  [ "$bad" -eq 0 ]
}

# The mk/arch-aarch64.mk image rule with stand-in tools, over a copy of the
# policy: a policy change must re-audit an up-to-date image, and an archive
# that fails the audit must leave no EL3 image, not even a stale one.
link_gate() {
  local tmp r b old=200001010000 rc=0 pass
  tmp="$(mktemp -d)" || return 1
  r="$tmp/root"
  b="$tmp/build"
  mkdir -p "$r/tools" "$r/src/arch/aarch64/el3" "$b"
  cp "$root/tools/check-el3-symbols.sh" "$ALLOW" "$DEFINES" "$r/tools/"
  : > "$r/src/arch/aarch64/el3/el3.ld"
  printf '#!/bin/sh\ncat "%s"\n' "$tmp/listing" > "$tmp/fake-nm"
  printf '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && : > "$2"; shift; done\n' > "$tmp/fake-cc"
  chmod +x "$tmp/fake-nm" "$tmp/fake-cc"
  el3_make() {
    make -s -f "$root/mk/arch-aarch64.mk" ROOT="$r" BUILD_DIR="$b" \
      TOOLPREFIX="$tmp/fake-" CC="$tmp/fake-cc" EL3_ARCHIVE_OBJS= \
      "$b/wolftrust_el3.elf" > /dev/null 2>&1
  }
  age_all() {
    touch -t "$old" "$r/tools/"* "$r/src/arch/aarch64/el3/el3.ld" "$b/"*
  }

  printf 'start.o:\n0000000000000000 T wt_el3_entry\n                 U memset\n' > "$tmp/listing"
  : > "$b/libwt_el3.a"
  el3_make || { echo "SELFTEST FAIL: a clean archive did not link"; rc=1; }
  : > "$b/wolftrust_el3.bin"
  age_all
  grep -v 'memset' "$ALLOW" > "$r/tools/el3-symbols.allow"
  if el3_make; then
    echo "SELFTEST FAIL: a policy change did not re-audit the up-to-date EL3 image"
    rc=1
  fi
  if [ -e "$b/wolftrust_el3.elf" ] || [ -e "$b/wolftrust_el3.bin" ]; then
    echo "SELFTEST FAIL: a policy the archive fails left the EL3 image behind"
    rc=1
  fi

  cp "$ALLOW" "$r/tools/"
  printf 'smc.o:\n0000000000000000 T wt_spm_init\n' > "$tmp/listing"
  : > "$b/wolftrust_el3.elf"
  : > "$b/wolftrust_el3.bin"
  age_all
  touch "$b/libwt_el3.a"
  for pass in 1 2; do
    if el3_make; then
      echo "SELFTEST FAIL: make pass $pass built the EL3 image past a failed audit"
      rc=1
    fi
    if [ -e "$b/wolftrust_el3.elf" ] || [ -e "$b/wolftrust_el3.bin" ]; then
      echo "SELFTEST FAIL: make pass $pass left a stale EL3 image past a failed audit"
      rc=1
    fi
  done
  rm -rf "$tmp"
  return "$rc"
}

selftest() {
  local fails=0 out badtmp
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n                 U wt_gic_init_secure\n                 U wt_platform_console_putc\n                 U wt_esr_classify\n                 U memset\n                 U __el3_stack_top\n\nesr.o:\n0000000000000000 T wt_esr_classify\n' \
    | audit "$ALLOW" "$DEFINES")" || { echo "SELFTEST FAIL: clean listing rejected:"; echo "$out"; fails=$((fails + 1)); }
  out="$(printf 'smc.o:\n0000000000000000 T wt_smc_dispatch\n                 U wt_ffm_call\n0000000000000040 T wt_spm_init\n0000000000000080 t wt_hsm_helper\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: bad listing accepted"; fails=$((fails + 1)); }
  case "$out" in *"allow-list: wt_ffm_call"*) ;; *) echo "SELFTEST FAIL: wt_ffm_call not flagged"; fails=$((fails + 1)) ;; esac
  case "$out" in *"EL3 archive: wt_spm_init"*) ;; *) echo "SELFTEST FAIL: wt_spm_init not flagged"; fails=$((fails + 1)) ;; esac
  case "$out" in *"EL3 archive: wt_hsm_helper"*) ;; *) echo "SELFTEST FAIL: local wt_hsm_helper not flagged"; fails=$((fails + 1)) ;; esac
  out="$(printf 'core.o:\n0000000000000000 T wt_boot_run\n0000000000000040 T wt_domain_init\n0000000000000080 T wt_partition_start\n0000000000000000 B g_wt_boot_state\n\nffa_notif.o:\n0000000000000000 t wt_ffa_notif_bind\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: core definitions accepted"; fails=$((fails + 1)); }
  for sym in wt_boot_run wt_domain_init wt_partition_start g_wt_boot_state wt_ffa_notif_bind; do
    case "$out" in *"EL3 archive: $sym"*) ;; *) echo "SELFTEST FAIL: $sym not flagged"; fails=$((fails + 1)) ;; esac
  done
  out="$(printf 'a.o:\n0000000000000000 T wt_el3_entry\n                 U __udivti3\n\nb.o:\n0000000000000000 t __udivti3\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: a local definition resolved another object's reference"; fails=$((fails + 1)); }
  case "$out" in *"allow-list: __udivti3"*) ;; *) echo "SELFTEST FAIL: __udivti3 not flagged"; fails=$((fails + 1)) ;; esac
  out="$(printf 'core.o:\n0000000000000000 T wt_el3_entry\n0000000000000040 t wt_boot_secret_helper\n0000000000000080 t wt_domain_secret_helper\n00000000000000c0 t wt_partition_secret_helper\n0000000000000000 b g_wt_boot_state\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: local core helpers accepted"; fails=$((fails + 1)); }
  for sym in wt_boot_secret_helper wt_domain_secret_helper wt_partition_secret_helper g_wt_boot_state; do
    case "$out" in *"EL3 archive: $sym"*) ;; *) echo "SELFTEST FAIL: local $sym not flagged"; fails=$((fails + 1)) ;; esac
  done
  out="$(printf 'world.o:\n0000000000000000 T wt_el3_entry\n0000000000000040 t wt_el3_mdcr_ok\n0000000000000080 t world_switch\n00000000000000c0 t reply_error\n0000000000000000 b g_wt_el3_ready\n0000000000000100 t wt_ffa_version_negotiate.constprop.0\n' \
    | audit "$ALLOW" "$DEFINES")" || { echo "SELFTEST FAIL: monitor-named, plain, and compiler-cloned local helpers rejected:"; echo "$out"; fails=$((fails + 1)); }
  out="$(printf 'core.o:\n0000000000000000 T wt_el3_entry\n0000000000000040 t wt_boot_helper.isra.0\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: a cloned local core helper accepted"; fails=$((fails + 1)); }
  case "$out" in *"EL3 archive: wt_boot_helper"*) ;; *) echo "SELFTEST FAIL: cloned wt_boot_helper not flagged"; fails=$((fails + 1)) ;; esac
  out="$(printf 'a.o:\n0000000000000000 T wt_el3_entry\n                 v wt_spm_weak_obj\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: weak undefined object reference accepted"; fails=$((fails + 1)); }
  case "$out" in *"allow-list: wt_spm_weak_obj"*) ;; *) echo "SELFTEST FAIL: wt_spm_weak_obj not flagged"; fails=$((fails + 1)) ;; esac
  out="$(printf 'a.o:\n0000000000000000 T wt_el3_entry\n0000000000000040 u wt_bogus_unique\n' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: unique global outside the defines allow-list accepted"; fails=$((fails + 1)); }
  case "$out" in *"does not define inside the EL3 archive: wt_bogus_unique"*) ;; *) echo "SELFTEST FAIL: wt_bogus_unique not flagged"; fails=$((fails + 1)) ;; esac
  # A shell status wraps modulo 256, so exactly 256 offenders must still fail.
  out="$(awk 'BEGIN { print "big.o:"; for (i = 0; i < 256; i++) printf "%016x T wt_spm_leak%d\n", i * 4, i }' \
    | audit "$ALLOW" "$DEFINES")" && { echo "SELFTEST FAIL: 256 offenders accepted"; fails=$((fails + 1)); }

  if valid_ere '['; then
    echo "SELFTEST FAIL: malformed pattern accepted as valid"; fails=$((fails + 1)); fi
  if ! valid_ere '^wt_[a-z_]+$'; then
    echo "SELFTEST FAIL: well-formed pattern rejected"; fails=$((fails + 1)); fi

  # A malformed allow-list entry must fail the audit, not silently pass a
  # symbol that entry would otherwise have hidden.
  badtmp="$(mktemp -d)" || { echo "SELFTEST FAIL: mktemp failed"; exit 1; }
  cp "$ALLOW" "$badtmp/el3-symbols.allow"
  printf '%s\n' '^wt_bad[' >> "$badtmp/el3-symbols.allow"
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n                 U wt_spm_leak\n' \
    | audit "$badtmp/el3-symbols.allow" "$DEFINES")" \
    && { echo "SELFTEST FAIL: malformed allow-list pattern accepted"; fails=$((fails + 1)); }
  case "$out" in *"invalid pattern in $badtmp/el3-symbols.allow"*) ;; \
    *) echo "SELFTEST FAIL: malformed allow-list pattern not reported"; fails=$((fails + 1)) ;; esac

  cp "$DEFINES" "$badtmp/el3-defines.allow"
  printf '%s\n' '^wt_bad[' >> "$badtmp/el3-defines.allow"
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n0000000000000040 T wt_bogus_extra\n' \
    | audit "$ALLOW" "$badtmp/el3-defines.allow")" \
    && { echo "SELFTEST FAIL: malformed defines pattern accepted"; fails=$((fails + 1)); }
  case "$out" in *"invalid pattern in $badtmp/el3-defines.allow"*) ;; \
    *) echo "SELFTEST FAIL: malformed defines pattern not reported"; fails=$((fails + 1)) ;; esac

  : > "$badtmp/empty.allow"
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n                 U wt_totally_unknown\n' \
    | audit "$badtmp/empty.allow" "$DEFINES")" \
    && { echo "SELFTEST FAIL: empty allow-list accepted"; fails=$((fails + 1)); }
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n0000000000000040 T wt_bogus_extra\n' \
    | audit "$ALLOW" "$badtmp/empty.allow")" \
    && { echo "SELFTEST FAIL: empty defines allow-list accepted"; fails=$((fails + 1)); }

  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n' \
    | audit "$badtmp/does-not-exist.allow" "$DEFINES")" \
    && { echo "SELFTEST FAIL: unreadable allow-list accepted"; fails=$((fails + 1)); }
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n' \
    | audit "$ALLOW" "$badtmp/does-not-exist.allow")" \
    && { echo "SELFTEST FAIL: unreadable defines allow-list accepted"; fails=$((fails + 1)); }
  rm -rf "$badtmp"

  link_gate || fails=$((fails + 1))
  if [ "$fails" -ne 0 ]; then echo "SELFTEST: $fails failure(s)"; exit 1; fi
  echo "SELFTEST: ok"
  exit 0
}

NM="${TOOLPREFIX:-aarch64-none-elf-}nm"
source_desc=""
listing_file=""
archive=""
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) selftest ;;
    --nm) NM="$2"; shift ;;
    --nm-file) listing_file="$2"; shift ;;
    -*) echo "usage: $0 <libwt_el3.a> [--nm <nm>] | --nm-file <listing> | --selftest" >&2; exit 2 ;;
    *) archive="$1" ;;
  esac
  shift
done

if [ -n "$listing_file" ]; then
  source_desc="$listing_file"
  listing="$(cat "$listing_file")" || exit 2
elif [ -n "$archive" ]; then
  source_desc="$archive"
  listing="$("$NM" "$archive")" || { echo "FAIL: $NM $archive failed" >&2; exit 2; }
else
  echo "usage: $0 <libwt_el3.a> [--nm <nm>] | --nm-file <listing> | --selftest" >&2
  exit 2
fi

echo "EL3 symbol guard: $source_desc (allow-lists tools/el3-symbols.allow, tools/el3-defines.allow)"
if printf '%s\n' "$listing" | audit "$ALLOW" "$DEFINES"; then
  echo "OK: the EL3 archive references only allowed symbols and defines no core code."
  exit 0
fi
echo "FAIL: the EL3 archive reaches outside the monitor (WT-PORT-0012)."
exit 1
