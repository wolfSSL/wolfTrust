#!/usr/bin/env bash
# EL3 image guard (WT-PORT-0012). The AArch64 monitor archive may leave
# unresolved only the symbols allowed by tools/el3-symbols.allow, and may not
# define anything that belongs to the SPM, the services, or a crypto library.
# References resolved inside the archive itself are fine.
#
#   tools/check-el3-symbols.sh <libwt_el3.a> [--nm <nm>]
#   tools/check-el3-symbols.sh --nm-file <listing>     (output of nm -g)
#   tools/check-el3-symbols.sh --selftest
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
ALLOW="$root/tools/el3-symbols.allow"
DENY='^(wt_ffm_|wt_spm_|wt_monitor_|wt_hsm_|wt_attest|wt_vault|wt_its_|wt_ps_|wt_fwu|wt_vnet|wc_|wh_|psa_)'

# audit <allow-file> < nm-listing : prints offenders, returns their count
audit() {
  local allow="$1" pats defined undefined bad=0 hit
  pats="$(grep -vE '^[[:space:]]*(#|$)' "$allow")"
  listing="$(cat)"
  defined="$(printf '%s\n' "$listing" | awk 'NF==3 && $2!="U" {print $3}' | sort -u)"
  undefined="$(printf '%s\n' "$listing" | awk 'NF==2 && $1=="U" {print $2}' | sort -u)"
  if [ -n "$defined" ]; then
    undefined="$(printf '%s\n' "$undefined" | grep -vxF -f <(printf '%s\n' "$defined") || true)"
  fi
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  unresolved symbol outside the allow-list: $hit"
    bad=$((bad + 1))
  done < <(printf '%s\n' "$undefined" | grep -vE -f <(printf '%s\n' "$pats") || true)
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  core, service, or crypto symbol defined inside the EL3 archive: $hit"
    bad=$((bad + 1))
  done < <(printf '%s\n' "$defined" | grep -E "$DENY" || true)
  return "$bad"
}

selftest() {
  local fails=0 out
  out="$(printf 'start.o:\n0000000000000000 T wt_el3_entry\n                 U wt_gic_init_secure\n                 U wt_platform_console_putc\n                 U wt_esr_classify\n                 U memset\n                 U __el3_stack_top\n\nesr.o:\n0000000000000000 T wt_esr_classify\n' \
    | audit "$ALLOW")" || { echo "SELFTEST FAIL: clean listing rejected:"; echo "$out"; fails=$((fails + 1)); }
  out="$(printf 'smc.o:\n0000000000000000 T wt_smc_dispatch\n                 U wt_ffm_call\n0000000000000040 T wt_spm_init\n' \
    | audit "$ALLOW")" && { echo "SELFTEST FAIL: bad listing accepted"; fails=$((fails + 1)); }
  case "$out" in *"allow-list: wt_ffm_call"*) ;; *) echo "SELFTEST FAIL: wt_ffm_call not flagged"; fails=$((fails + 1)) ;; esac
  case "$out" in *"EL3 archive: wt_spm_init"*) ;; *) echo "SELFTEST FAIL: wt_spm_init not flagged"; fails=$((fails + 1)) ;; esac
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
  listing="$("$NM" -g "$archive")" || { echo "FAIL: $NM -g $archive failed" >&2; exit 2; }
else
  echo "usage: $0 <libwt_el3.a> [--nm <nm>] | --nm-file <listing> | --selftest" >&2
  exit 2
fi

echo "EL3 symbol guard: $source_desc (allow-list tools/el3-symbols.allow)"
if printf '%s\n' "$listing" | audit "$ALLOW"; then
  echo "OK: the EL3 archive references only allowed symbols and defines no core code."
  exit 0
fi
echo "FAIL: the EL3 archive reaches outside the monitor (WT-PORT-0012)."
exit 1
