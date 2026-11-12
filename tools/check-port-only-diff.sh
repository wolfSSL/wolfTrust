#!/usr/bin/env bash
# Port-only diff audit. A new architecture or SoC port must be a diff that
# touches no architecture-neutral core file: only src/arch/common/,
# src/arch/<arch>/, include/wolftrust/arch/<arch>/, port/common/ and
# port/common/<arch>/, port/<soc>/, the build fragments (never mk/common.mk),
# tests, docs, and workflows.
#
#   tools/check-port-only-diff.sh <base-ref> [arch] [soc]
#   tools/check-port-only-diff.sh --thin <soc> <base-ref>
#   tools/check-port-only-diff.sh --new-ports <base-ref>
#   tools/check-port-only-diff.sh --selftest
#
# --thin is the bar for a registered SoC port on an existing architecture:
# only that port's own directories plus the generated port index. --new-ports
# audits every port whose port.json the diff adds and whose port/<soc>/ did not
# exist at the base, so registering an existing port is not a thin addition.
# Exits non-zero and lists every offending path when the diff against
# <base-ref> reaches outside the allow-list. arch/soc default to any.
set -uo pipefail

allow_re() { # arch soc
  local arch="$1" soc="$2"
  printf '^(src/arch/(common|%s)/|include/wolftrust/arch/%s/|port/common/(%s/|[^/]+$)|port/%s/|mk/(arch-%s|target-%s)\\.mk$|tests/|docs/|\\.github/)' \
    "$arch" "$arch" "$arch" "$soc" "$arch" "$soc"
}

thin_re() { # soc
  local soc="$1"
  printf '^(port/%s/|mk/target-%s\\.mk$|tests/target/ports/%s/|tests/firmware/boards/%s/|tests/firmware/%s-[a-z0-9_-]+/|tests/host/port/models/%s/|tests/host/%s_[a-z0-9_]+/|docs/[A-Za-z0-9]+-Guide\\.md$|docs/Ports\\.md$|\\.github/ISSUE_TEMPLATE/bug_report\\.yml$)' \
    "$soc" "$soc" "$soc" "$soc" "$soc" "$soc" "$soc"
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

check_ref() { # base-ref
  if ! git rev-parse --verify --quiet "$1^{commit}" > /dev/null; then
    echo "FAIL: base ref '$1' does not resolve" >&2
    exit 2
  fi
}

selftest() {
  local re fails=0
  re="$(allow_re 'aarch64' 'qemuvirt')"
  if printf '%s\n' 'src/arch/aarch64/el3/start.S' 'src/arch/common/x.c' \
      'include/wolftrust/arch/aarch64/context.h' 'port/qemuvirt/board.h' \
      'port/common/aarch64/platform_l3.c' 'port/common/hsm_flash.c' \
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
  re="$(thin_re 'wtsynth')"
  if printf '%s\n' 'port/wtsynth/port.json' 'port/wtsynth/memory_map.h' \
      'mk/target-wtsynth.mk' 'tests/target/ports/wtsynth/hw.sh' \
      'tests/firmware/boards/wtsynth/board.h' 'tests/host/port/models/wtsynth/rng_model.c' \
      'docs/WTSYNTH-Guide.md' 'docs/Ports.md' | audit "$re" > /dev/null; then :; else
    echo "SELFTEST FAIL: thin port paths rejected"; fails=$((fails + 1))
  fi
  for p in 'port/common/hsm_flash.c' 'port/otherport/port.json' 'mk/common.mk' \
      'tests/target/lib/scenario_matrix.py' 'docs/Porting.md' 'Makefile'; do
    if printf '%s\n' "$p" | audit "$re" > /dev/null; then
      echo "SELFTEST FAIL: thin port accepted $p"; fails=$((fails + 1)); fi
  done
  if "$0" refs/heads/__cpodiff_missing_ref__ > /dev/null 2>&1; then
    echo "SELFTEST FAIL: invalid base ref approved"; fails=$((fails + 1)); fi
  if [ "$fails" -ne 0 ]; then echo "SELFTEST: $fails failure(s)"; exit 1; fi
  echo "SELFTEST: ok"
  exit 0
}

thin() { # soc base-ref
  local soc="$1" base="$2"
  check_ref "$base"
  echo "thin port audit: $base..HEAD (soc=$soc)"
  if git diff --name-only "$base"...HEAD | audit "$(thin_re "$soc")"; then
    echo "OK: port $soc touches only its own directories."
    return 0
  fi
  echo "FAIL: port $soc reaches outside its own directories (see above)."
  return 1
}

new_ports() { # base-ref
  local base="$1" f soc rc=0 found=0
  check_ref "$base"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    soc="$(basename "$(dirname "$f")")"
    if git ls-tree -d "$base" "port/$soc" 2> /dev/null | grep -q .; then
      echo "port $soc existed at $base; registration is not a thin addition"
      continue
    fi
    found=1
    thin "$soc" "$base" || rc=1
  done < <(git diff --name-only --diff-filter=A "$base"...HEAD -- 'port/*/port.json')
  [ "$found" -eq 1 ] || echo "no new port in $base..HEAD"
  exit "$rc"
}

case "${1:-}" in
  --selftest) selftest ;;
  --thin)
    [ $# -eq 3 ] || { echo "usage: $0 --thin <soc> <base-ref>" >&2; exit 2; }
    thin "$2" "$3"; exit $? ;;
  --new-ports)
    [ $# -eq 2 ] || { echo "usage: $0 --new-ports <base-ref>" >&2; exit 2; }
    new_ports "$2" ;;
esac
[ $# -ge 1 ] || { echo "usage: $0 <base-ref> [arch] [soc] | --thin <soc> <base-ref> | --new-ports <base-ref> | --selftest" >&2; exit 2; }

base="$1"
arch="${2:-[a-z0-9_]+}"
soc="${3:-[a-z0-9_]+}"
re="$(allow_re "$arch" "$soc")"
check_ref "$base"

echo "port-only diff audit: $base..HEAD (arch=$arch soc=$soc)"
if git diff --name-only "$base"...HEAD | audit "$re"; then
  echo "OK: every changed path is inside the port allow-list."
  exit 0
fi
echo "FAIL: the diff reaches outside the port allow-list (see above)."
exit 1
