#!/usr/bin/env bash
# Scaffold a new Armv8-M port from a registered one, or check one.
#
#   tools/new-port/new-port.sh <soc> --from <port> [--transport stcli|pyocd]
#   tools/new-port/new-port.sh <soc> --check
#   (--repo <dir> works on another checkout, as the self-test does)
#
# The scaffold copies the port's own files (port/<soc>, its build fragment,
# board seams, emulator and hardware profiles, provisioning backend, host
# flash model and guide) under the new name and marks every value a reference
# manual must settle with an #error or a refusal (every provisioning write
# refuses), so nothing links or writes a board until a person has replaced
# each stub. Shared code is never touched:
# a port lands with zero handwritten edits outside its own files, and
# tools/check-port-only-diff.sh --thin <soc> <base-ref> proves it. --check reports the
# stubs still open and runs the registry self-tests.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
soc="${1:-}"
shift || true
from=""
transport=""
check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --from) from="$2"; shift 2 ;;
    --transport) transport="$2"; shift 2 ;;
    --repo) repo="$(cd "$2" && pwd)"; shift 2 ;;
    --check) check=1; shift ;;
    *) echo "usage: $0 <soc> --from <port> [--transport stcli|pyocd] | <soc> --check" >&2; exit 2 ;;
  esac
done
# The name is a path component everywhere below: lowercase letters and digits only.
case "$soc" in
  ""|*[!a-z0-9]*|[!a-z]*) echo "usage: $0 <soc> --from <port> [--transport stcli|pyocd] | <soc> --check (a-z, 0-9)" >&2; exit 2 ;;
esac
cd "$repo"
upper="$(printf '%s' "$soc" | tr 'a-z' 'A-Z')"

port_files() {
  printf '%s\n' \
    "port/$1/port.json" "port/$1/memory_map.h" "port/$1/platform_$1.c" \
    "port/$1/flash_drv.c" "port/$1/rng_drv.c" \
    "mk/target-$1.mk" \
    "tests/firmware/boards/$1/board.h" "tests/firmware/boards/$1/board.mk" \
    "tests/target/ports/$1/m33mu.sh" "tests/target/ports/$1/hw.sh" \
    "tests/target/provisioning/provisioning_ctrl_$1.sh" \
    "tests/host/port_flash/models/$1.c" "tests/host/port_flash/models/$1_mock.h"
}

if [ "$check" = 1 ]; then
  rc=0
  open=0
  while IFS= read -r f; do
    if [ ! -e "$f" ]; then echo "MISSING $f"; rc=1; continue; fi
  done < <(port_files "$soc")
  while IFS= read -r f; do
    n="$(grep -cE '#error "new port|NEW_PORT_STUB' "$f" || true)"
    if [ "$n" -gt 0 ]; then echo "STUB    $f ($n to settle)"; open=$((open + n)); fi
  done < <({ port_files "$soc"; ls "port/$soc"/*.[ch] "tests/firmware/boards/$soc"/* \
             "tests/host/port_flash/models/$soc"* "docs/$upper-Guide.md" 2>/dev/null; } | sort -u)
  [ -e "docs/$upper-Guide.md" ] || { echo "MISSING docs/$upper-Guide.md"; rc=1; }
  python3 tests/target/lib/scenario_matrix.py --selftest || rc=1
  python3 tests/target/lib/scenarios.py --selftest || rc=1
  python3 tools/gen-port-docs.py --check >/dev/null 2>&1 || echo "NOTE    docs/Ports.md needs tools/gen-port-docs.py"
  echo "new-port check: $open stub(s) open, registry $([ "$rc" = 0 ] && echo ok || echo NOT ok)"
  [ "$rc" = 0 ] && [ "$open" = 0 ]
  exit $?
fi

[ -n "$from" ] || { echo "--from <port> is required (a registered port to copy)" >&2; exit 2; }
[ -d "port/$from" ] || { echo "no port/$from to copy from" >&2; exit 2; }
[ ! -e "port/$soc" ] || { echo "port/$soc exists; use --check" >&2; exit 2; }
from_upper="$(printf '%s' "$from" | tr 'a-z' 'A-Z')"
from_display="$(python3 tests/target/lib/scenario_matrix.py --port "$from" --get display)"
from_guide="$(python3 tests/target/lib/scenario_matrix.py --port "$from" --get guide)"

copy() {
  local src="$1" dst="$2"
  # A per-port owner file exists only where the port adds objects.
  [ -e "$src" ] || { echo "  (port/$from has no $(basename "$src"); skipped)"; return 0; }
  mkdir -p "$(dirname "$dst")"
  sed -e "s/$from/$soc/g" -e "s/$from_upper/$upper/g" -e "s/$from_display/$upper/g" "$src" > "$dst"
  [ ! -x "$src" ] || chmod +x "$dst"
  echo "  $dst"
}
stub_c() {
  # Every C or header the manual must settle refuses to compile until edited.
  printf '#error "new port %s: settle this file against the reference manual, then delete this line"\n' "$soc" | cat - "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

echo "scaffolding port/$soc from port/$from"
# Every file of the port directory (chip drivers and owner files included),
# then the files that live beside it.
for src in "port/$from"/*; do
  copy "$src" "port/$soc/$(basename "$src" | sed -e "s/$from/$soc/g")"
done
paste -d' ' <(port_files "$from" | grep -vE "^(port|tests/firmware/boards|tests/host/port_flash/models)/") \
           <(port_files "$soc" | grep -vE "^(port|tests/firmware/boards|tests/host/port_flash/models)/") | while read -r src dst; do
  copy "$src" "$dst"
done
# The board seams and the flash model with every companion they include.
for src in "tests/firmware/boards/$from"/*; do
  copy "$src" "tests/firmware/boards/$soc/$(basename "$src" | sed -e "s/$from/$soc/g")"
done
for src in "tests/host/port_flash/models/$from"*; do
  copy "$src" "tests/host/port_flash/models/$(basename "$src" | sed -e "s/$from/$soc/g")"
done
copy "$from_guide" "docs/$upper-Guide.md"
# A guide claim stands only after this board showed it.
sed -i.bak "1a\\
NEW_PORT_STUB $soc: every claim below was copied from the $from guide; keep one only after this board showed it, then delete this line.
" "docs/$upper-Guide.md" && rm -f "docs/$upper-Guide.md.bak"
for f in "port/$soc"/*.[ch] "tests/firmware/boards/$soc"/*.[ch] "tests/host/port_flash/models/$soc"*.[ch]; do
  stub_c "$f"
done
for f in "mk/target-$soc.mk" "tests/firmware/boards/$soc/board.mk" "tests/target/ports/$soc/m33mu.sh" \
         "tests/target/ports/$soc/hw.sh"; do
  sed -i.bak "1a\\
# NEW_PORT_STUB $soc: every value below was copied from $from; settle it, then delete this line
" "$f" && rm -f "$f.bak"
done
# The provisioning backend never writes a board nobody has rehearsed: the lock
# write and every other write refuse until the port author replaces them.
python3 - "tests/target/provisioning/provisioning_ctrl_$soc.sh" "$soc" <<'PYEOF'
import re, sys
path, soc = sys.argv[1:3]
s = open(path).read()
s = re.sub(r"^port_lock_write\(\) \{.*?^\}\n", 'port_lock_write() { refuse "NEW_PORT_STUB %s: no lock write is implemented; nothing was changed."; }\n' % soc, s, count=1, flags=re.S | re.M)
s = re.sub(r"^port_lock_write\(\) \{[^\n]*\}\n", 'port_lock_write() { refuse "NEW_PORT_STUB %s: no lock write is implemented; nothing was changed."; }\n' % soc, s, count=1, flags=re.M)
open(path, "w").write(s)
PYEOF
cat >> "tests/target/provisioning/provisioning_ctrl_$soc.sh" <<EOF

# NEW_PORT_STUB $soc: the writes above were copied from $from and address its
# silicon; each refuses until the port author settles the backend and deletes these.
port_restore() { refuse "NEW_PORT_STUB $soc: restore is not implemented; nothing was changed."; }
port_advance_check() { refuse "NEW_PORT_STUB $soc: advance is not implemented; nothing was changed."; }
port_advance() { refuse "NEW_PORT_STUB $soc: advance is not implemented; nothing was changed."; }
port_regress() { refuse "NEW_PORT_STUB $soc: regress is not implemented; nothing was changed."; }
port_extra() { refuse "NEW_PORT_STUB $soc: '\$1' is not implemented; nothing was changed."; }
EOF
python3 - "port/$soc/port.json" "$soc" "$upper" "$transport" "$from" <<'PYEOF'
import json, sys
path, soc, upper, transport, src = sys.argv[1:6]
d = json.load(open(path))
d["name"] = soc
d["display"] = upper
d["board"] = "NEW_PORT_STUB %s: the board" % soc
d["guide"] = "docs/%s-Guide.md" % upper
d["ci"]["label"] = "ci:" + soc
d["ci"]["label_only"] = True
d["ci"]["mcuxsdk_board"] = ""
d["build"]["vectors"] = ""
d["m33mu"]["arm"] = soc + "-m33mu"
hw = d.setdefault("hardware", {})
# Every reason the source port gave is a claim about its silicon: each stays
# a stub until this port's author confirms or deletes it; the extra hardware
# tiers are the source board's and start empty.
for section in (d["m33mu"].setdefault("caps_absent", {}), d["m33mu"].get("exempt", {}),
                d["m33mu"].get("faults_by_design", {}), d["m33mu"].get("l3_exempt", {}),
                hw.get("caps_absent", {})):
    for key in list(section):
        section[key] = "NEW_PORT_STUB %s: copied from %s: %s" % (soc, src, section[key])
d["m33mu"]["caps_absent"]["prot_trace"] = "NEW_PORT_STUB: declare what the emulator model lacks, or delete"
hw["qualification"] = []
hw["optin"] = []
# What selects how a run ends or which assertions apply is the source board's:
# back to the strict defaults, so this port shows each before it is set again.
for key in ("ends", "guest_flags", "periph_probe"):
    d["m33mu"].pop(key, None)
for key in ("iso_probe", "extra_blocks"):
    hw.pop(key, None)
d["m33mu"]["NEW_PORT_STUB"] = ("%s: ends, guest_flags, periph_probe and the hardware iso_probe and "
                               "extra_blocks start at the strict defaults; set one only after this "
                               "board showed it, then delete this key" % soc)
hw["fixture"] = "NEW_PORT_STUB %s: the fixture (%s probe)" % (soc, transport or "probe")
json.dump(d, open(path, "w"), indent=2)
open(path, "a").write("\n")
PYEOF
echo "  port/$soc/port.json (registered: ci:$soc, label only, every provisioning write refused)"
echo
echo "next: tools/new-port/PLAYBOOK.md gate G0: tools/new-port/new-port.sh $soc --check"
