#!/usr/bin/env bash
# Core/port split guard. The architecture-neutral CORE must not name any
# architecture or SoC detail, so a new port needs zero core edits. CORE is
# src/ (minus src/arch/) plus include/wolftrust/ (minus include/wolftrust/arch/);
# src/arch/common/ is neutral code by construction and is scanned like CORE
# for SoC leaks only.
#
# Report-only by default. WT_SPLIT_STRICT=1 exits non-zero on any HARD leak.
# Hard leaks: a core #include of an arch or port header, CMSE use, inline
# assembly, retired pre-split contract names, and M-profile or A-profile
# register / instruction vocabulary in code (comments are stripped first, so
# prose may still explain the hardware). A port defining a wt_arch_* operation
# is also hard: those belong to src/arch/<arch>/.
#
# --selftest runs the patterns against fixtures instead of the tree.
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

M_VOCAB='\b(PSP|MSP|EXC_RETURN|BXNS|ITNS|AIRCR|VTOR|SCB_[A-Z_]+|SAU_[A-Z_]+|MPU_(S|NS)_[A-Z_]+|NVIC_[A-Z_]+|CONTROL_NS|xPSR|IPSR|PSPLIM|MSPLIM|PendSV|SysTick|GTZC[A-Z_]*|MPU->|SAU->|NVIC->)\b'
A_VOCAB='\b(TTBR[01]|VBAR|SCTLR|ESR|FAR|ELR|SPSR|CNTP(S|CT)?|CNTV|CNTFRQ|GICD_[A-Z0-9_]+|GICR_[A-Z0-9_]+|GICC_[A-Z0-9_]+|ICC_[A-Z0-9_]+|SCR_EL3|HCR_EL2|XMPU|XPPU|RISAF|RISAB|RIFSC|smc|eret|tlbi|mrs|msr)\b|_EL[0-3]\b'
PORT_HEADERS='#[[:space:]]*include[[:space:]]*"(memory_map|board|stm32h563_regs|stm32[a-z0-9_]*)\.h"'
ARCH_HEADERS='#[[:space:]]*include[[:space:]]*"wolftrust/arch/'
CMSE='\bwt_cmse_[a-z_]+[[:space:]]*\(|__attribute__\(\([^)]*cmse'
ASM='__asm|asm[[:space:]]+volatile'
RETIRED='\bwt_mpu_region(_t)?\b|\bWT_MAX_MPU_REGIONS\b|\bmpu_region(s|_count)\b|\bWT_BOOT_HANDOFF_ADDRESS\b'
RETIRED="$RETIRED"'|\bwt_platform_(start_secure_timer|mask_all_guest_irqs|apply_irq_mask|quarantine_pending_irqs|program_ns_mpu|program_secure_partition_domain|program_sp_thread_domain|restore_spm_domain|prepare_guest_return|capture_guest_context|trap_pc|restore_guest_context|svc_guest_return|in_handler_mode|ns_thread_mode_trap|secure_psp_thread_trap|return_to_secure_thread|zero_guest_memory|read_fault_address|restore_ns_bank|secure_irq_(en|dis)able|active_guest_id|configure_ns_irq|set_ns_irq_pending|dmb|dsb|guest_context_ready)\b|\bwt_spm_thread_unprivileged\b|\bwt_ffm_nsc_install\b|__ARM_FEATURE_CMSE'
PORT_ARCH_DEF='^[A-Za-z_][A-Za-z0-9_ *]*[[:space:]*]wt_arch_[a-z0-9_]+[[:space:]]*\('
FFA_FID='\b0x[8Cc]40000[6-9A-Fa-f][0-9A-Fa-f][uU]?\b'

# Replace every block comment with newlines so line numbers survive.
strip_comments() { # file
  perl -0777 -pe 's{/\*.*?\*/}{ my $c = $&; $c =~ tr/\n//cd; $c }gse' "$1"
}

HARD=0
SOFT=0

scan() { # kind(hard|soft)  label  regex  files...
  local kind="$1" label="$2" re="$3" hits count
  shift 3
  hits="$(printf '%s\n' "$@" | xargs grep -nE "$re" 2>/dev/null || true)"
  [ -z "$hits" ] && return 0
  count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
  printf '\n== %s: %s (%s hits) ==\n%s\n' "$kind" "$label" "$count" "$hits"
  if [ "$kind" = hard ]; then HARD=$((HARD + count)); else SOFT=$((SOFT + count)); fi
}

scan_code() { # kind  label  regex  files...   (comments stripped)
  local kind="$1" label="$2" re="$3" f hits="" h count
  shift 3
  for f in "$@"; do
    h="$(strip_comments "$f" | grep -nE "$re" 2>/dev/null | sed "s|^|$f:|" || true)"
    [ -n "$h" ] && hits="${hits:+$hits
}$h"
  done
  [ -z "$hits" ] && return 0
  count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
  printf '\n== %s: %s (%s hits) ==\n%s\n' "$kind" "$label" "$count" "$hits"
  if [ "$kind" = hard ]; then HARD=$((HARD + count)); else SOFT=$((SOFT + count)); fi
}

selftest() {
  local dir fails=0
  dir="$(mktemp -d)"
  printf 'int f(void) { return MPU->CTRL; } /* PendSV */\n' > "$dir/m.c"
  printf 'int g(void) { return SCTLR_EL1; }\n' > "$dir/a.c"
  printf '#include "memory_map.h"\nint h;\n' > "$dir/p.c"
  printf '/* SysTick and PendSV are explained here only */\nint ok;\n' > "$dir/ok.c"
  printf 'void wt_arch_init(void)\n{\n}\n' > "$dir/portdef.c"
  printf 'static void x(void)\n{\n    wt_arch_init();\n}\n' > "$dir/portcall.c"
  printf 'unsigned fid = 0x84000063u; /* 0xC4000066 */\n' > "$dir/fid.c"
  printf 'unsigned id = 0x8000u; unsigned oem = 0xC3800004u;\n' > "$dir/nofid.c"
  check() { # expect(hit|clean) regex file
    local got
    got="$(strip_comments "$3" | grep -cE "$2" || true)"
    if [ "$1" = hit ] && [ "$got" -eq 0 ]; then echo "SELFTEST FAIL: expected a hit in $3"; fails=$((fails + 1)); fi
    if [ "$1" = clean ] && [ "$got" -ne 0 ]; then echo "SELFTEST FAIL: expected no hit in $3"; fails=$((fails + 1)); fi
  }
  check hit "$M_VOCAB" "$dir/m.c"
  check hit "$A_VOCAB" "$dir/a.c"
  check hit "$PORT_HEADERS" "$dir/p.c"
  check clean "$M_VOCAB" "$dir/ok.c"
  check clean "$A_VOCAB" "$dir/ok.c"
  check hit "$PORT_ARCH_DEF" "$dir/portdef.c"
  check clean "$PORT_ARCH_DEF" "$dir/portcall.c"
  check hit "$FFA_FID" "$dir/fid.c"
  check clean "$FFA_FID" "$dir/nofid.c"
  rm -rf "$dir"
  if [ "$fails" -ne 0 ]; then echo "SELFTEST: $fails failure(s)"; exit 1; fi
  echo "SELFTEST: ok"
  exit 0
}

[ "${1:-}" = "--selftest" ] && selftest

core="$({ git ls-files 'src/*' 'include/wolftrust/*' 2>/dev/null \
  || find src include/wolftrust -type f; } \
  | grep -E '\.(c|h)$' \
  | grep -vE '(^|/)src/arch/' \
  | grep -vE '(^|/)include/wolftrust/arch/')"
common="$({ git ls-files 'src/arch/common/*' 2>/dev/null \
  || find src/arch/common -type f 2>/dev/null; } | grep -E '\.(c|h)$' || true)"
ports="$({ git ls-files 'port/*' 2>/dev/null || find port -type f; } | grep -E '\.c$')"
# FF-A function ids live in one table; everything else names them.
ffa_scope="$({ git ls-files 'src/*' 'include/*' 'port/*' 'tests/*' 2>/dev/null \
  || find src include port tests -type f; } \
  | grep -E '\.(c|h|S)$' \
  | grep -vE '(^|/)include/wolftrust/arch/aarch64/ffa_abi\.h$')"

echo "wolfTrust core/port split guard (CORE = src + include/wolftrust, minus arch)"

scan hard 'core #include of an arch header' "$ARCH_HEADERS" $core
scan hard 'core #include of a port header' "$PORT_HEADERS" $core $common
scan hard 'CMSE usage in core' "$CMSE" $core $common
scan hard 'inline assembly in core' "$ASM" $core $common
scan hard 'retired pre-split contract names in core' "$RETIRED" $core $common
scan_code hard 'M-profile register or instruction vocabulary in core code' "$M_VOCAB" $core $common
scan_code hard 'A-profile register or instruction vocabulary in core code' "$A_VOCAB" $core $common
scan_code hard 'port defines an architecture operation (belongs in src/arch/)' "$PORT_ARCH_DEF" $ports
scan_code hard 'FF-A function-id literal outside include/wolftrust/arch/aarch64/ffa_abi.h' "$FFA_FID" $ffa_scope
scan soft 'M-profile vocabulary in core comments' "$M_VOCAB" $core
scan soft 'raw peripheral or system-control addresses in core' '\b0x(E00[0-9A-Fa-f]{5}|[45]0[0-9A-Fa-f]{6}|F[0-9A-Fa-f]{7})[uU]?\b' $core

echo
echo "SUMMARY: hard leaks=$HARD  soft hits=$SOFT"

if [ "${WT_SPLIT_STRICT:-0}" = "1" ]; then
  if [ "$HARD" -gt 0 ]; then
    echo "STRICT: $HARD hard core->arch leak(s) remain."
    exit 1
  fi
  echo "STRICT: no hard core->arch leaks."
fi
exit 0
