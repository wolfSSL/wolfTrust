#!/usr/bin/env python3
"""Require every hand-written BXNS in a disassembled Secure image to sit at
the end of a straight-line scrub of r0-r12, lr and every APSR flag (NZCVQ and
GE). Compiler CMSE returns (bxns lr) are cleared by -mcmse and not checked;
--sources pins the one hand-written BXNS so no other can claim that pass."""

import argparse
import os
import re
import sys
import tempfile

INSN_LINE = re.compile(r"^\s*([0-9a-f]+):\t(\S+)(?:\s+(.*))?$", re.IGNORECASE)
LABEL_LINE = re.compile(r"^[0-9a-f]+ <([^>]+)>:$", re.IGNORECASE)
ZERO = re.compile(r"^(r[0-9]|r1[0-2]|lr|sl|fp|ip),\s*#0$", re.IGNORECASE)
# objdump prints APSR_nzcvqg as CPSR_fs; CPSR_f alone leaves GE[3:0] live.
FLAGS = re.compile(r"^(apsr_nzcvqg|cpsr_fs\w*),\s*(\w+)$", re.IGNORECASE)
BRANCH_TARGET = re.compile(r"\b([0-9a-f]+)\s+<", re.IGNORECASE)
BARRIERS = ("isb", "dsb", "nop")
ALIASES = {"sl": "r10", "fp": "r11", "ip": "r12"}
ALL_REGS = ["r%d" % n for n in range(13)] + ["lr"]
ASM_BXNS = re.compile(r"(\"\s*|^\s*|;\s*)bxns\b", re.IGNORECASE)
SCRUBBED_SITE = os.path.join("src", "arch", "armv8m", "guest_context_armv8m.c")
SOURCE_EXTS = (".c", ".h", ".s", ".S")


def reg(name):
    name = name.strip().lower()
    return ALIASES.get(name, name)


def parse(lines):
    insns = []
    func = 0
    for line in lines:
        if LABEL_LINE.match(line.strip()) is not None:
            func += 1
            continue
        match = INSN_LINE.match(line.rstrip("\n"))
        if match is None:
            continue
        operands = (match.group(3) or "").split(";")[0].split("@")[0].strip()
        insns.append((int(match.group(1), 16),
                      match.group(2).lower().split(".")[0], operands, func,
                      line.strip()))
    return insns


def in_scrub(mnemonic, operands):
    if mnemonic in ("mov", "movs"):
        return ZERO.match(operands) is not None
    if mnemonic == "msr":
        return FLAGS.match(operands) is not None
    return mnemonic in BARRIERS


def check(lines):
    insns = parse(lines)
    targets = set()
    for _, mnemonic, operands, _, _ in insns:
        if mnemonic.startswith("b") or mnemonic.startswith("cb"):
            for hit in BRANCH_TARGET.findall(operands):
                targets.add(int(hit, 16))
    errors = []
    found = 0
    for index, (addr, mnemonic, operands, func, text) in enumerate(insns):
        if mnemonic != "bxns" or operands.lower() == "lr":
            continue
        found += 1
        start = index
        while (start > 0 and insns[start - 1][3] == func and
               in_scrub(insns[start - 1][1], insns[start - 1][2])):
            start -= 1
        zeroed = set()
        flags = False
        for _, scrub_mnemonic, scrub_operands, _, _ in insns[start:index]:
            if scrub_mnemonic in ("mov", "movs"):
                zeroed.add(reg(scrub_operands.split(",")[0]))
                flags = flags and scrub_mnemonic == "mov"
            elif scrub_mnemonic == "msr":
                flags = reg(FLAGS.match(scrub_operands).group(2)) in zeroed
        target = reg(operands)
        missing = [r for r in ALL_REGS if r != target and r not in zeroed]
        if not flags:
            missing.append("APSR")
        entered = [t for t in targets if insns[start][0] < t <= addr]
        if missing:
            errors.append("%s leaves %s" % (text, " ".join(missing)))
        if entered:
            errors.append("%s: a branch lands inside its scrub" % text)
    if found == 0:
        errors.append("no hand-written bxns found in the disassembly")
    return errors


def source_sites(root):
    sites = []
    for top in ("src", "port", "include"):
        for path, _, names in os.walk(os.path.join(root, top)):
            for name in names:
                if not name.endswith(SOURCE_EXTS):
                    continue
                full = os.path.join(path, name)
                with open(full, "r", errors="replace") as handle:
                    for number, line in enumerate(handle, 1):
                        for _ in ASM_BXNS.finditer(line):
                            sites.append((os.path.relpath(full, root), number))
    return sites


def check_sources(root):
    sites = source_sites(root)
    if len(sites) == 1 and sites[0][0] == SCRUBBED_SITE:
        return []
    return ["hand-written bxns must appear once, in %s; found %s" %
            (SCRUBBED_SITE, ", ".join("%s:%d" % site for site in sites) or
             "none")]


def self_test():
    head = ["08000000 <wt_jump_to_ns>:\n"]
    scrub = [" 8000000:\tmovs\tr0, #0\n", " 8000002:\tmovs\tr1, #0\n",
             " 8000004:\tmovs\tr2, #0\n", " 8000006:\tmovs\tr3, #0\n"]
    scrub += [" %x:\tmov.w\tr%d, #0\n" % (0x8000008 + 4 * (n - 5), n)
              for n in range(5, 10)]
    scrub += [" 800001c:\tmov.w\tsl, #0\n", " 8000020:\tmov.w\tfp, #0\n",
              " 8000024:\tmov.w\tip, #0\n", " 8000028:\tmov.w\tlr, #0\n",
              " 800002c:\tmsr\tCPSR_fs, r0\n", " 8000030:\tisb\tsy\n"]
    jump = [" 8000034:\tbxns\tr4\n"]
    before = [" 7fffff0:\tmov\tr4, r1\n"]
    cases = (
        ("full scrub", head + before + scrub + jump, True),
        ("no bxns", head + scrub, False),
        ("compiler return only", head + [" 8000000:\tbxns\tlr\n"], False),
        ("compiler return beside a scrubbed jump", ["07ff0000 <f>:\n",
         " 7ff0000:\tbxns\tlr\n"] + head + scrub + jump, True),
        ("r10 left", head + [l for l in scrub if "sl," not in l] + jump,
         False),
        ("r7 left", head + [l for l in scrub if "r7," not in l] + jump, False),
        ("flags left", head + scrub[:-2] + jump, False),
        ("GE flags left", head + scrub[:-2] +
         [" 800002c:\tmsr\tCPSR_f, r0\n"] + jump, False),
        ("flags from a live register", head + scrub[:-2] +
         [" 800002c:\tmsr\tCPSR_fs, r4\n"] + jump, False),
        ("register clobbered after scrub", head + scrub[:-2] +
         [" 800002a:\tmov\tr7, r4\n"] + scrub[-2:] + jump, False),
        ("flags clobbered after scrub", head + scrub +
         [" 8000032:\tcmp\tr4, #0\n"] + jump, False),
        ("movs after the flags write", head + scrub[:-1] +
         [" 8000030:\tmovs\tr1, #0\n"] + jump, False),
        ("mov.w after the flags write", head + scrub[:-1] +
         [" 8000030:\tmov.w\tr1, #0\n"] + jump, True),
        ("call after scrub", head + scrub +
         [" 8000032:\tbl\t8000100 <f>\n"] + jump, False),
        ("scrub in another function", head + scrub +
         ["08000032 <other>:\n"] + jump, False),
        ("branch into the scrub", head +
         [" 7fffff0:\tbne.n\t8000020 <wt_jump_to_ns+0x20>\n"] + scrub + jump,
         False),
        ("branch to the scrub start", head +
         [" 7fffff0:\tbne.n\t8000000 <wt_jump_to_ns>\n"] + scrub + jump,
         True),
    )
    failures = 0
    for name, lines, want_ok in cases:
        if (check(lines) == []) != want_ok:
            print("self-test failed: %s" % name, file=sys.stderr)
            failures += 1
    source_cases = (
        ("one scrubbed site", {SCRUBBED_SITE: '"bxns r4 \\n"\n'}, True),
        ("no site", {SCRUBBED_SITE: "/* BXNS in a comment */\n"}, False),
        ("a second site", {SCRUBBED_SITE: '"bxns r4 \\n"\n',
                           "src/other.S": "  bxns lr\n"}, False),
        ("site moved", {"src/other.c": '"bxns lr"\n'}, False),
        ("two on one line", {SCRUBBED_SITE: '"bxns r4 \\n" "bxns lr"\n'},
         False),
    )
    for name, files, want_ok in source_cases:
        with tempfile.TemporaryDirectory() as root:
            for rel, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(root, rel)),
                            exist_ok=True)
                with open(os.path.join(root, rel), "w") as handle:
                    handle.write(text)
            if (check_sources(root) == []) != want_ok:
                print("self-test failed: %s" % name, file=sys.stderr)
                failures += 1
    if failures != 0:
        return 1
    print("PASS: ns_entry_scrub")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disassembly", nargs="?",
                        help="objdump -d --no-show-raw-insn output")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--sources", metavar="ROOT",
                        help="check the tree's hand-written bxns sites")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.sources is not None:
        errors = check_sources(args.sources)
        for error in errors:
            print("FAIL: %s" % error, file=sys.stderr)
        return 1 if errors else 0
    if args.disassembly is None:
        parser.error("disassembly file required")
    try:
        with open(args.disassembly, "r", errors="replace") as handle:
            errors = check(handle)
    except OSError as error:
        errors = ["cannot read %s: %s" % (args.disassembly, error)]
    for error in errors[:20]:
        print("FAIL: %s" % error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
