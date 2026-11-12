# shellcheck shell=bash disable=SC2034,SC2154
# Helpers every provisioning port shares, sourced by provisioning_ctrl.sh
# before the port file: the PSA life cycle vocabulary, the Secure image's
# symbols, wolfBoot's handoff record, the launch masks, and the flashed image
# list built from the port's hardware profile so provisioning and the
# hardware runner name one flash map.

# bind_probe VAR: WT_HW_PROBE, the probe the hardware runner binds, also
# names the port's own VAR; a VAR naming another probe is refused.
bind_probe() {
  local val
  [ -n "${WT_HW_PROBE:-}" ] || return 0
  val="$(printenv "$1" || true)"
  [ -z "$val" ] || [ "$val" = "$WT_HW_PROBE" ] ||
    refuse "WT_HW_PROBE=$WT_HW_PROBE and $1=$val name different probes; set one of them."
  export "$1=$WT_HW_PROBE"
}

lc_hex() { printf '0x%02X' $(( $1 & 0xFF )); }

psa_name() {
  case "$1" in
    00001000) echo "ASSEMBLY_AND_TEST" ;; 00002000) echo "PSA_ROT_PROVISIONING" ;;
    00003000) echo "SECURED" ;; 00004000) echo "NON_PSA_ROT_DEBUG" ;;
    00005000) echo "RECOVERABLE_PSA_ROT_DEBUG" ;; 00006000) echo "DECOMMISSIONED" ;;
    *) echo "UNKNOWN" ;;
  esac
}

# The PSA life cycles wolfTrust may report while the NXP life cycle is $1.
expect_psa() {
  case "$1" in
    0x03) echo "00001000" ;; 0x07) echo "00002000" ;;
    0x0F|0xCF) echo "00003000 00004000 00005000" ;; 0x1F) echo "00006000" ;;
  esac
}

# The life cycle fused when discover ran (a shadow can differ until a reset).
fused_lc() {
  local w
  w="$(sed -n 's/^LC=\(0x[0-9A-Fa-f]*\) .*/\1/p' "$state_dir/discovery" 2>/dev/null)"
  [ -n "$w" ] && lc_hex "$w"
}

# A wolfTrust global's address from the image the port flashed ($elf).
elf_sym() {
  "${ARM_NM:-arm-none-eabi-nm}" "$elf" | awk -v s="$1" '$3 == s && !f { print "0x" $1; f = 1 }'
}

# Both launch masks as "verified refused", or failure when the image leaves one
# out (a WT_GUEST_FLASH_WRP=1 build drops the verified mask).
launch_masks() {
  local vm rf
  vm="$(elf_sym g_wt_launch_verified_mask)"; rf="$(elf_sym g_wt_launch_refused_mask)"
  [ -n "$vm" ] && [ -n "$rf" ] || return 1
  read_words "$vm" "$rf" | tr '\n' ' '; echo
}

# The life cycle wolfBoot handed wolfTrust: the raw handoff record at $HANDOFF
# while it is intact, else wolfTrust's consumed copy.
handoff_lifecycle() {
  local magic inv lc sym
  read -r magic inv lc < <(read_words "$HANDOFF" $((HANDOFF + 4)) $((HANDOFF + 12)) | tr '\n' ' '; echo)
  if [ "${magic:-}" = "5742484f" ] && [ $((0x$magic ^ 0x${inv:-0})) -eq $((0xFFFFFFFF)) ]; then
    echo "$lc"
    return 0
  fi
  [ -s "$elf" ] || return 1
  sym="$(elf_sym g_boot_lifecycle)"
  [ -n "$sym" ] || return 1
  read_words "$sym"
}

# The flash map of tests/target/ports/<target>/hw.sh, the one the hardware
# runner programs: HW_WOLFBOOT_ADDR, HW_SECURE_ADDR, HW_GUEST0_ADDR,
# HW_GUEST1_ADDR.
hw_profile_addresses() {
  local here="$repo/tests/target" port="$target" evidence="" scenario="" WT_ENGINE="${WT_ENGINE:-native}"
  # shellcheck source=/dev/null
  . "$repo/tests/target/ports/$target/hw.sh"
}

# The four images the chain flashes as "address file" lines: the port names
# the files (port_image_files: wolfBoot, Secure image, guest 0, guest 1).
flashed_images() {
  local files
  files="$(port_image_files)"
  printf '%s %s\n' "$HW_WOLFBOOT_ADDR" "$(sed -n 1p <<<"$files")" \
    "$HW_SECURE_ADDR" "$(sed -n 2p <<<"$files")" \
    "$HW_GUEST0_ADDR" "$(sed -n 3p <<<"$files")" \
    "$HW_GUEST1_ADDR" "$(sed -n 4p <<<"$files")"
}
