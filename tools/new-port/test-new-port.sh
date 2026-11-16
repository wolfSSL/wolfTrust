#!/usr/bin/env bash
# The scaffold self-test: in a throwaway copy of the port-related tree, a
# synthetic port scaffolded from every registered port registers cleanly
# (both registry self-tests pass with it present), leaves its stubs open so
# nothing links or writes a board, and refuses every provisioning write; a
# name that is not a plain path component is refused before anything is made.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tests/host/port_flash" "$tmp/tests/target" "$tmp/tests/firmware" "$tmp/tools" "$tmp/docs"
cp -R "$repo/port" "$repo/mk" "$tmp/"
cp -R "$repo/tests/target/lib" "$repo/tests/target/ports" "$repo/tests/target/provisioning" "$tmp/tests/target/"
cp -R "$repo/tests/firmware/boards" "$tmp/tests/firmware/"
cp -R "$repo/tests/host/port_flash/models" "$tmp/tests/host/port_flash/"
cp -R "$repo/tools/new-port" "$repo/tools/gen-port-docs.py" "$tmp/tools/"
cp "$repo"/docs/*-Guide.md "$tmp/docs/"
# A source port that cannot run a level 3 scenario names why; that reason
# is its board's, so the scaffold must reopen it.
python3 -I - "$tmp"/port/*/port.json <<'PY'
import json, sys
for path in sys.argv[1:]:
    d = json.load(open(path))
    m = d["m33mu"]
    m["groups"] = [g for g in m["groups"] if g[0] != "fpneg"]
    m.setdefault("l3_exempt", {})["fpneg"] = "synthetic: the source board's open issue"
    m.setdefault("exempt", {})["fpneg"] = "synthetic: the source board's open issue"
    json.dump(d, open(path, "w"), indent=2)
PY
fails=0
for from in $(python3 "$tmp/tests/target/lib/scenario_matrix.py" --list-ports); do
    soc="synth${from}"
    out="$("$tmp/tools/new-port/new-port.sh" "$soc" --from "$from" --transport pyocd --repo "$tmp" 2>&1)" || {
        echo "FAIL: scaffold from $from: $out"; fails=$((fails + 1)); continue; }
    check="$("$tmp/tools/new-port/new-port.sh" "$soc" --check --repo "$tmp" 2>&1 || true)"
    grep -q "stub(s) open, registry ok" <<<"$check" ||
        { echo "FAIL: $soc check: $check"; fails=$((fails + 1)); }
    grep -q "^STUB.*memory_map.h" <<<"$check" ||
        { echo "FAIL: $soc memory map is not stubbed"; fails=$((fails + 1)); }
    grep -q "NEW_PORT_STUB $soc: no lock write" "$tmp/tests/target/provisioning/provisioning_ctrl_$soc.sh" ||
        { echo "FAIL: $soc lock write is not refused"; fails=$((fails + 1)); }
    prov() { (cd "$tmp" && TARGET="$soc" WT_LOCK_CONFIRM=1 WT_PROVISION_STATE="$tmp/state" \
                bash tests/target/provisioning/provisioning_ctrl.sh "$@" 2>&1); }
    for cmd in restore regress; do
        out="$(prov "$cmd")" && rc=0 || rc=$?
        [ "$rc" -eq 2 ] && grep -q "NEW_PORT_STUB $soc: $cmd is not implemented" <<<"$out" ||
            { echo "FAIL: $soc $cmd is not refused (rc $rc): $out"; fails=$((fails + 1)); }
    done
    # advance reaches the backend only for a state the port can mock: one must.
    reached=0
    for state in $(prov help | grep -oE '0x[0-9A-Fa-f]+' | sort -u); do
        if prov advance "$state" | grep -q "NEW_PORT_STUB $soc: advance is not implemented"; then
            reached=1; break
        fi
    done
    [ "$reached" -eq 1 ] || { echo "FAIL: $soc advance is not refused by the backend"; fails=$((fails + 1)); }
    grep -q '"label_only": true' "$tmp/port/$soc/port.json" ||
        { echo "FAIL: $soc is not label-only in CI"; fails=$((fails + 1)); }
    for src in "$repo/tests/firmware/boards/$from"/* "$repo/tests/target/ports/$from"/* \
               "$repo/tests/host/port_flash/models/$from"*; do
        dst="$tmp/${src#"$repo/"}"; dst="${dst//$from/$soc}"
        [ -e "$dst" ] || { echo "FAIL: $soc lacks $(basename "$dst"), the companion of $(basename "$src")"; fails=$((fails + 1)); }
    done
    grep -q "NEW_PORT_STUB $soc" "$tmp/docs/$(tr '[:lower:]' '[:upper:]' <<<"$soc")-Guide.md" ||
        { echo "FAIL: $soc guide carries no stub"; fails=$((fails + 1)); }
    python3 -I - "$tmp/port/$soc/port.json" "$soc" <<'PY' || { echo "FAIL: $soc registry keeps the source board's CI SDK, hardware tiers or reasons"; fails=$((fails + 1)); }
import json, sys
d = json.load(open(sys.argv[1]))
hw = d.get("hardware", {})
reasons = [r for key in ("caps_absent", "exempt", "l3_exempt") for r in d["m33mu"].get(key, {}).values()]
reasons += list(hw.get("caps_absent", {}).values())
ok = d["ci"].get("mcuxsdk_board", "") == "" and not hw.get("qualification") and not hw.get("optin")
ok = ok and not any(k in d["m33mu"] for k in ("ends", "guest_flags", "periph_probe"))
ok = ok and "iso_probe" not in hw and "extra_blocks" not in hw and "NEW_PORT_STUB" in d["m33mu"]
ok = ok and all(r.startswith("NEW_PORT_STUB") for r in reasons)
sys.exit(0 if ok else 1)
PY
    echo "ok   scaffold from $from registers $soc with its stubs open"
done
before="$(ls "$tmp/port" | sort)"
first="$(python3 "$tmp/tests/target/lib/scenario_matrix.py" --list-ports | awk '{print $1}')"
for bad in "ab/../zz" "a b" "9abc" "Abc" ""; do
    if "$tmp/tools/new-port/new-port.sh" "$bad" --from "$first" --repo "$tmp" >/dev/null 2>&1; then
        echo "FAIL: the name '$bad' was accepted"; fails=$((fails + 1))
    fi
done
[ "$(ls "$tmp/port" | sort)" = "$before" ] || { echo "FAIL: a refused name left files behind"; fails=$((fails + 1)); }
echo "ok   names that are not a plain path component are refused"
echo "new-port self-test: $fails failures"
[ "$fails" -eq 0 ]
