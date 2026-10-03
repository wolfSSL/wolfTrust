#!/usr/bin/env bash
# Port-only diff audit. A new architecture or SoC port must be a diff that
# touches no architecture-neutral core file: only src/arch/common/,
# src/arch/<arch>/, include/wolftrust/arch/<arch>/, port/common/<arch>/,
# port/<soc>/, the build fragments (never mk/common.mk), tests, docs, and workflows.
#
#   tools/check-port-only-diff.sh <base-ref> [arch] [soc]
#   tools/check-port-only-diff.sh --selftest
#
# Exits non-zero and lists every offending path when the diff against
# <base-ref> reaches outside the allow-list. arch/soc default to any.
set -uo pipefail

allow_re() { # arch soc
  local arch="$1" soc="$2"
  printf '^(src/arch/(common|%s)/|include/wolftrust/arch/%s/|port/(common/%s|%s)/|mk/(arch-%s|target-%s)\\.mk$|tests/|docs/|\\.github/)' \
    "$arch" "$arch" "$arch" "$soc" "$arch" "$soc"
}

audit() { # allow-regex, paths on stdin -> prints offenders, returns count
  local re="$1" bad=0 p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    if ! printf '%s\n' "$p" | grep -qE "$re"; then
      echo "  outside the port allow-list: $p"
      bad=$((bad + 1))
    fi
  done
  return "$bad"
}

selftest() {
  local re fails=0
  re="$(allow_re 'aarch64' 'qemuvirt')"
  if printf '%s\n' 'src/arch/aarch64/el3/start.S' 'src/arch/common/x.c' \
      'include/wolftrust/arch/aarch64/context.h' 'port/qemuvirt/board.h' \
      'port/common/aarch64/platform_l3.c' \
      'mk/arch-aarch64.mk' 'mk/target-qemuvirt.mk' 'tests/host/x/main.c' \
      'docs/Porting.md' '.github/workflows/x.yml' | audit "$re" > /dev/null; then :; else
    echo "SELFTEST FAIL: allowed paths rejected"; fails=$((fails + 1))
  fi
  if printf '%s\n' 'src/monitor.c' | audit "$re" > /dev/null; then
    echo "SELFTEST FAIL: src/monitor.c accepted"; fails=$((fails + 1)); fi
  if printf '%s\n' 'mk/common.mk' | audit "$re" > /dev/null; then
    echo "SELFTEST FAIL: mk/common.mk accepted"; fails=$((fails + 1)); fi
  if printf '%s\n' 'include/wolftrust/arch.h' | audit "$re" > /dev/null; then
    echo "SELFTEST FAIL: include/wolftrust/arch.h accepted"; fails=$((fails + 1)); fi
  if printf '%s\n' 'src/arch/armv8m/spm_svc.c' | audit "$re" > /dev/null; then
    echo "SELFTEST FAIL: another arch accepted"; fails=$((fails + 1)); fi
  if printf '%s\n' 'port/common/armv8m/platform_l3.c' | audit "$re" > /dev/null; then
    echo "SELFTEST FAIL: another arch's shared port layer accepted"; fails=$((fails + 1)); fi
  if "$0" refs/heads/__cpodiff_missing_ref__ > /dev/null 2>&1; then
    echo "SELFTEST FAIL: invalid base ref approved"; fails=$((fails + 1)); fi
  if [ "$fails" -ne 0 ]; then echo "SELFTEST: $fails failure(s)"; exit 1; fi
  echo "SELFTEST: ok"
  exit 0
}

[ "${1:-}" = "--selftest" ] && selftest
[ $# -ge 1 ] || { echo "usage: $0 <base-ref> [arch] [soc] | --selftest" >&2; exit 2; }

base="$1"
arch="${2:-[a-z0-9_]+}"
soc="${3:-[a-z0-9_]+}"
re="$(allow_re "$arch" "$soc")"

if ! git rev-parse --verify --quiet "$base^{commit}" > /dev/null; then
  echo "FAIL: base ref '$base' does not resolve" >&2
  exit 2
fi

echo "port-only diff audit: $base..HEAD (arch=$arch soc=$soc)"
if git diff --name-only "$base"...HEAD | audit "$re"; then
  echo "OK: every changed path is inside the port allow-list."
  exit 0
fi
echo "FAIL: the diff reaches outside the port allow-list (see above)."
exit 1
