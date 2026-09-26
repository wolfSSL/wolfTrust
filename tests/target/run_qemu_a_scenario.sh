#!/usr/bin/env bash
# wolfTrust AArch64 QEMU scenario runner, the emulator twin of
# run_m33mu_scenario.sh: build the images for one machine, boot them under
# qemu-system-aarch64, and assert one scenario's markers. Run inside
# ghcr.io/wolfssl/wolfboot-ci-aarch64 (the image CI uses) or anywhere
# qemu-system-aarch64 and aarch64-none-elf-gcc are on PATH.
#
#   run_qemu_a_scenario.sh smoke   the tests/firmware/aarch64-smoke image runs
#                                  at EL3, prints on the secure console,
#                                  reports the parked secondary cores, exits
#                                  through semihosting
#   run_qemu_a_scenario.sh boot    the wolfTrust EL3 monitor (make ARCH=aarch64
#                                  TARGET=qemuvirt|versal) boots on the boot
#                                  core, prints its banner, drops into Secure
#                                  EL1, and exits through the monitor
#   run_qemu_a_scenario.sh boot-smp2  the same image with a second core: the
#                                  secondary parks at EL3 inside the timed
#                                  handshake and only the boot core runs the
#                                  monitor (virt only; see the SKIP below)
#
#   MACHINE=virt|versal-virt (default virt)   GIC=2|3 (virt, default 3)
#   CPU=cortex-a35|cortex-a72 (virt, default cortex-a72)
#   SMP=<n> (virt: default 2 for smoke, 1 for boot, fixed 2 for boot-smp2;
#            versal-virt: default 4)
#   run_qemu_a_scenario.sh parkneg|rdistneg|tickneg  the same image where a
#                                  declared secondary never parks, the GICv3
#                                  redistributor reads asleep, or the secure
#                                  tick never arrives: the monitor must panic
#                                  before it enters Secure EL1
#   run_qemu_a_scenario.sh psci-el2  the psci checks from a Normal world
#                                  entered at NS-EL2, which then runs an
#                                  AArch32 EL1 caller whose SMCs the monitor
#                                  serves
#   run_qemu_a_scenario.sh positive-secure  the same image; the neutral core
#                                  boots at Secure EL1 and every Secure
#                                  Partition initializes at Secure EL0
#                                  through the SVC gate before the SPMC
#                                  idles on FFA_MSG_WAIT
#
#   QEMU_TIMEOUT=<s> (default 120)  TOOLPREFIX (default aarch64-none-elf-)
set -euo pipefail

scenario="${1:-}"
case "$scenario" in
  smoke|boot|boot-smp2|parkneg|rdistneg|tickneg|positive-secure|crossdomain|spfaultneg|tablesneg|manifestneg|keystoreneg|spbudgetneg|panicneg|ffa-direct|ffa-sint|ns-smoke|ffa-discovery|ffa-guest-direct|psci|psci-el2|el2dirtyneg|ffa-preempt|positive|guest1|smcfuzz|secramneg|resetneg|ffa-memneg|hsmattackneg|attestneg|vaultrecover|vaultrecoversec|confboot|storage|devstorage|devattest|devcrypto|ffaacs-discovery|ffaacs-direct|ffaacs-memory|ffaacs-notify|ffaacs-indirect|ffaacs-interrupts) ;;
  *) echo "usage: $0 smoke|boot|boot-smp2|parkneg|rdistneg|tickneg|positive-secure|crossdomain|spfaultneg|tablesneg|manifestneg|keystoreneg|spbudgetneg|panicneg|ffa-direct|ffa-sint|ns-smoke|ffa-discovery|ffa-guest-direct|psci|psci-el2|el2dirtyneg|ffa-preempt|positive|guest1|smcfuzz|secramneg|resetneg|ffa-memneg|hsmattackneg|attestneg|vaultrecover|vaultrecoversec|confboot|storage|devstorage|devattest|devcrypto|ffaacs-discovery|ffaacs-direct|ffaacs-memory|ffaacs-notify|ffaacs-indirect|ffaacs-interrupts" >&2; exit 2 ;;
esac

# The Arm FF-A ACS runs one test group per scenario: the groups wolfTrust
# implements.
acs_suite=""
acs_floor=0
case "$scenario" in
  ffaacs-discovery) acs_suite=setup_discovery; acs_floor=14 ;;
  ffaacs-direct)    acs_suite=direct_messaging; acs_floor=5 ;;
  ffaacs-memory)    acs_suite=memory_manage; acs_floor=70 ;;
  ffaacs-notify)    acs_suite=notifications; acs_floor=10 ;;
  ffaacs-indirect)  acs_suite=indirect_messaging; acs_floor=2 ;;
  ffaacs-interrupts) acs_suite=interrupts; acs_floor=6 ;;
esac
# Tests that fail by design: this one looks for TF-A's own EL3 logical
# partition, which is an implementation detail of TF-A and not part of FF-A.
# (The S-EL1-partition notification tests are excluded by the ACS itself at
# PLATFORM_SP_EL=0, so the notifications group totals ten tests here.)
acs_deviations="ffa_partition_info_get_lsp"
# The dev_apis Crypto schedule wolfPSA answers: a newly skipped test is a
# regression, not a pass (77 scheduled; c047 is configuration-skipped).
crypto_passed=64
crypto_skipped=13

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
. "$repo/tests/target/lib/expect.sh"
# Crypto engine of the secure image and the Normal-world guest: native or hsm.
. "$repo/tests/target/lib/engine.sh"

MACHINE="${MACHINE:-virt}"
GIC="${GIC:-3}"
CPU="${CPU:-cortex-a72}"
QEMU="${QEMU:-qemu-system-aarch64}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-120}"
# The conformance suite reboots the chain across its panic tests and logs 89
# tests, so it gets its own budget.
case "$scenario" in
  confboot)   QEMU_TIMEOUT="${QEMU_TIMEOUT_CONFBOOT:-1500}" ;;
  devstorage) QEMU_TIMEOUT="${QEMU_TIMEOUT_DEVSTORAGE:-600}" ;;
  devattest|attestneg) QEMU_TIMEOUT="${QEMU_TIMEOUT_DEVATTEST:-600}" ;;
  devcrypto)  QEMU_TIMEOUT="${QEMU_TIMEOUT_DEVCRYPTO:-3600}" ;;
  vaultrecover) QEMU_TIMEOUT="${QEMU_TIMEOUT_VAULTRECOVER:-3600}" ;;
  ffaacs-*) QEMU_TIMEOUT="${QEMU_TIMEOUT_FFAACS:-1800}" ;;
esac
TOOLPREFIX="${TOOLPREFIX:-aarch64-none-elf-}"

case "$MACHINE" in
  virt) tag="virt-gicv$GIC-$CPU"; target=qemuvirt ;;
  versal-virt) tag="versal-virt"; target=versal ;;
  *) echo "unsupported MACHINE=$MACHINE (virt or versal-virt)" >&2; exit 2 ;;
esac

if [ "$scenario" = rdistneg ] && [ "$MACHINE" = virt ] && [ "$GIC" = 2 ]; then
  echo "SKIP: qemu-a/rdistneg (GICv2): a GICv2 has no redistributor to wake"
  exit 0
fi

if [ "$scenario" = guest1 ]; then
  echo "SKIP: qemu-a/guest1: the AArch64 ports run one Normal-world endpoint (id 0x0000) and the SPMC takes Normal-world direct requests from it alone, so there is no second guest identity to exercise; guest 1 is covered on M33MU"
  exit 0
fi

if [ "$scenario" = hsmattackneg ] && [ "$WT_ENGINE" = native ]; then
  echo "SKIP: qemu-a/hsmattackneg (native engine): the native engine links no wolfHSM client wire, server, or message handlers, so the forged COMM_INIT and NVM-group attack surface does not exist"
  exit 0
fi

# cpus = cores the image expects to see (boot core + parked secondaries).
# versal-virt models 2 A72 + 2 R5 and QEMU refuses fewer than 4 CPUs there;
# its APU core 1 is created powered off and the CRF/APU control blocks that
# release it on silicon are unimplemented stubs in QEMU 11, so no firmware
# write starts it: the smoke and boot run on core 0 alone and boot-smp2 skips.
case "$scenario:$MACHINE" in
  smoke:virt) SMP="${SMP:-2}"; cpus="$SMP" ;;
  boot:virt|positive-secure:virt|crossdomain:virt|spfaultneg:virt|tablesneg:virt|manifestneg:virt|keystoreneg:virt|spbudgetneg:virt|panicneg:virt|ffa-direct:virt|ffa-sint:virt|ns-smoke:virt|ffa-discovery:virt|ffa-guest-direct:virt|psci-el2:virt|el2dirtyneg:virt|ffa-preempt:virt|positive:virt|smcfuzz:virt|secramneg:virt|ffa-memneg:virt|hsmattackneg:virt|vaultrecoversec:virt) SMP="${SMP:-1}"; cpus="$SMP" ;;
  boot-smp2:virt) SMP=2; cpus=2 ;;
  # The Normal world probes PSCI with a real parked secondary beside it.
  psci:virt) SMP="${SMP:-2}"; cpus="$SMP" ;;
  # The port declares a second core the machine never starts (virt runs one
  # core; versal-virt keeps APU core 1 powered off).
  parkneg:virt) SMP=1; cpus=2 ;;
  parkneg:versal-virt) SMP=4; cpus=2 ;;
  rdistneg:virt|tickneg:virt) SMP="${SMP:-1}"; cpus="$SMP" ;;
  # A secondary parks again after the reset: the rebooted boot core must
  # count it again.
  resetneg:virt) SMP="${SMP:-2}"; cpus="$SMP" ;;
  boot-smp2:versal-virt)
    echo "SKIP: qemu-a/boot-smp2 (versal-virt): QEMU xlnx-versal-virt keeps APU core 1 powered off and models the CRF and APU control blocks as unimplemented, so firmware cannot release it"
    exit 0 ;;
  secramneg:versal-virt)
    echo "SKIP: qemu-a/secramneg (versal-virt): QEMU xlnx-versal-virt does not model the XMPU/RISAF secure-memory controller, so the secure RAM is not fenced from the Normal world in the model and the port claims no isolation level; the fence is proven on the virt cells (VIRT_SECURE_MEM), and a silicon port claims isolation only once it locks the XMPU/RISAF"
    exit 0 ;;
  *) SMP="${SMP:-4}"; cpus=1 ;;
esac
expected_mask=$(printf '0x%x' $(( (1 << cpus) - 2 )))
el3_base=0xFFFC0000

# --- Build the image for this scenario. ---
if [ "$scenario" = smoke ]; then
  fw="$repo/tests/firmware/aarch64-smoke"
  build="$fw/build/$tag"
  make -C "$fw" MACHINE="$MACHINE" TOOLPREFIX="$TOOLPREFIX" BUILD_DIR="build/$tag" \
    WT_SMOKE_CPUS="$cpus"
  image_bin="$build/smoke.bin"
  image_elf="$build/smoke.elf"
else
  build="$repo/build-aarch64-$tag-$scenario"
  probe=()
  # Secure RAM behind the SPMC's own bands holds the FF-A ACS images, the
  # suite's test NVM, and the enlarged table pool.
  acs_secure_base=0x0E000000
  [ "$target" = versal ] && acs_secure_base=0x7F000000
  acs_pool_pa=$(printf '0x%X' $((acs_secure_base + 0x900000)))
  case "$scenario" in
    crossdomain) probe=(WT_FFM_NEGATIVE_PROBE=1) ;;
    spfaultneg)  probe=(WT_SP_FAULT_PROBE=1) ;;
    tablesneg)   probe=(WT_TABLES_NEGATIVE=1) ;;
    manifestneg) probe=(WT_MANIFEST_NEG_PROBE=1) ;;
    keystoreneg) probe=(WT_KEYSTORE_NEG_PROBE=1) ;;
    spbudgetneg) probe=(WT_SP_FAULT_ALWAYS_PROBE=1) ;;
    panicneg)    probe=(WT_PANIC_NEG_PROBE=1) ;;
    rdistneg)    probe=(WT_EL3_BOOT_NEG_PROBE=1) ;;
    tickneg)     probe=(WT_EL3_BOOT_NEG_PROBE=2) ;;
    confboot|devstorage) probe=(WT_CONFORMANCE=1 WT_EL3_NS_SMOKE=1) ;;
    # The wolfPSA guests carry a heap: one 2 MB block costs the same table page.
    devattest|devcrypto|attestneg) probe=(WT_CONFORMANCE=1 WT_EL3_NS_SMOKE=1 WT_PSA_NS_WINDOW_SIZE=0x00200000 WT_EL3_TEST_HANDOFF=1) ;;
    # Same crypto image, but the foreign-pool probe forces the boot-time vault
    # recovery; the test handoff's unlocked lifecycle lets it self-heal.
    vaultrecover) probe=(WT_CONFORMANCE=1 WT_EL3_NS_SMOKE=1 WT_PSA_NS_WINDOW_SIZE=0x00200000 WT_EL3_TEST_HANDOFF=1 WT_VAULT_FOREIGN_PROBE=1) ;;
    # The Arm FF-A ACS: SP1..SP4 are separately built S-EL0 images the SPMC
    # hosts as FF-A native partitions, VM1 is the Normal-world dispatcher at
    # EL2; the larger table pool covers the four 1 MB image bands.
    ffaacs-*) probe=(WT_EL3_NS_SMOKE=1 WT_FFA_ACS=1 WT_EL3_NS_EL2=1 WT_PSA_NS_WINDOW_SIZE=0x00200000 "WT_SPM_TABLE_POOL_PA=$acs_pool_pa" WT_SPM_TABLE_POOL_PAGES=512) ;;
    ffa-direct|ffa-sint) probe=(WT_EL3_TEST_DRIVER=1) ;;
    ns-smoke|ffa-discovery|psci|positive|smcfuzz|secramneg|resetneg|ffa-memneg|storage|hsmattackneg) probe=(WT_EL3_NS_SMOKE=1) ;;
    # The test handoff's unlocked lifecycle leaves the forced SECURED
    # lifecycle as the only thing that refuses the reformat.
    vaultrecoversec) probe=(WT_EL3_NS_SMOKE=1 WT_VAULT_FOREIGN_PROBE=1 WT_VAULT_PROBE_SECURED=1 WT_EL3_TEST_HANDOFF=1) ;;
    ffa-guest-direct) probe=(WT_EL3_NS_SMOKE=1 WT_NS_GUEST_ECHO=1) ;;
    ffa-preempt) probe=(WT_EL3_NS_SMOKE=1 WT_NS_PREEMPT=1) ;;
    # The monitor starts on EL2 state an earlier stage left dirty (SMC trapped,
    # a foreign virtual MPIDR); the virt cell turns EL2 on so it is live. Under
    # a GICv3 that stage also left every SPI routed to an absent PE.
    el2dirtyneg)
      probe=(WT_EL3_NS_SMOKE=1 WT_EL3_EL2_DIRTY_PROBE=1)
      [ "$GIC" = 3 ] && probe+=(WT_GIC_SPI_ROUTE_PROBE=1) ;;
    # The Normal world starts at NS-EL2 and runs an AArch32 EL1 beneath it.
    psci-el2) probe=(WT_EL3_NS_SMOKE=1 WT_EL3_NS_EL2=1) ;;
  esac
  make ARCH=aarch64 TARGET="$target" TOOLPREFIX="$TOOLPREFIX" WT_GIC_VERSION="$GIC" \
    WT_CPU="$CPU" WT_PORT_BOOT_CPUS="$cpus" BUILD_DIR="build-aarch64-$tag-$scenario" \
    "${probe[@]}"
  image_elf="$build/wolftrust_el3.elf"
  spm_elf="$build/wolftrust.elf"
  # ns-smoke also builds the Normal-world payload the SPMD ERETs to; it loads
  # into NS DRAM at WT_NS_IMAGE_PA, above the virt DTB at the RAM base
  # (0x40000000-0x40100000) so QEMU does not reject an overlapping ROM region.
  ns_base=0x44000000
  if [ "$scenario" = ns-smoke ] || [ "$scenario" = ffa-discovery ] || \
     [ "$scenario" = ffa-guest-direct ] || [ "$scenario" = psci ] || \
     [ "$scenario" = el2dirtyneg ] || [ "$scenario" = psci-el2 ] || \
     [ "$scenario" = ffa-preempt ] || [ "$scenario" = positive ] || \
     [ "$scenario" = smcfuzz ] || \
     [ "$scenario" = secramneg ] || [ "$scenario" = resetneg ] || \
     [ "$scenario" = ffa-memneg ] || [ "$scenario" = storage ] || \
     [ "$scenario" = hsmattackneg ] || [ "$scenario" = vaultrecoversec ] || \
     [ "$scenario" = vaultrecover ] || [ "$scenario" = attestneg ] || \
     [ "$scenario" = confboot ] || [ "$scenario" = devstorage ] || \
     [ "$scenario" = devattest ] || [ "$scenario" = devcrypto ]; then
    nsfw="$repo/tests/firmware/aarch64-ns-smoke"
    ns_echo=0
    [ "$scenario" = ffa-guest-direct ] && ns_echo=1
    ns_psci=0
    [ "$scenario" = psci ] && ns_psci=1
    [ "$scenario" = el2dirtyneg ] && ns_psci=1
    [ "$scenario" = psci-el2 ] && ns_psci=1
    ns_preempt=0
    [ "$scenario" = ffa-preempt ] && ns_preempt=1
    ns_psa=0
    [ "$scenario" = positive ] && ns_psa=1
    ns_hsmattack=0
    [ "$scenario" = hsmattackneg ] && { ns_psa=1; ns_hsmattack=1; }
    [ "$scenario" = vaultrecoversec ] && ns_psa=1
    ns_vault_secured=0
    [ "$scenario" = vaultrecoversec ] && ns_vault_secured=1
    ns_fuzz=0
    [ "$scenario" = smcfuzz ] && ns_fuzz=1
    ns_secram=0
    [ "$scenario" = secramneg ] && ns_secram=1
    ns_reset=0
    [ "$scenario" = resetneg ] && ns_reset=1
    ns_memneg=0
    [ "$scenario" = ffa-memneg ] && ns_memneg=1
    ns_storage=0
    [ "$scenario" = storage ] && ns_storage=1
    # confboot runs Arm's val NSPE from the payload against the conformance
    # image built above (its fetched upstream tree + generated test list).
    ns_conf=0
    ns_suite=ipc
    [ "$scenario" = confboot ] && ns_conf=1
    [ "$scenario" = devstorage ] && { ns_conf=1; ns_suite=storage; }
    [ "$scenario" = devattest ] && { ns_conf=1; ns_suite=attestation; }
    [ "$scenario" = devcrypto ] && { ns_conf=1; ns_suite=crypto; }
    [ "$scenario" = vaultrecover ] && { ns_conf=1; ns_suite=crypto; }
    # attestneg reuses the attestation build but runs a Normal-world negative
    # probe (invalid get_token requests + a tampered/misattributed token) in
    # place of val; the attestation service and EAT code are untouched.
    ns_attest_neg=0
    [ "$scenario" = attestneg ] && { ns_conf=1; ns_suite=attestation; ns_attest_neg=1; }
    # The secure keystore address to probe from NS and the conformance data
    # band the val PAL config names differ per target.
    ns_secure_probe=0x0E300000
    ns_confdata=0x0E2C0000
    [ "$target" = versal ] && { ns_secure_probe=0x7F300000; ns_confdata=0x7F2C0000; }
    # Per-scenario NS build dir, wiped each run so a changed -D flag (probe
    # address, guest id) is always recompiled and never a stale binary.
    rm -rf "$nsfw/build/$tag-$scenario"
    make -C "$nsfw" MACHINE="$MACHINE" TOOLPREFIX="$TOOLPREFIX" \
      BUILD_DIR="build/$tag-$scenario" WT_NS_BASE="$ns_base" \
      WT_NS_GUEST_ECHO="$ns_echo" WT_NS_GUEST_PSCI="$ns_psci" \
      WT_NS_PREEMPT="$ns_preempt" WT_NS_GUEST_PSA="$ns_psa" \
      WT_NS_GUEST_FUZZ="$ns_fuzz" \
      WT_NS_HSM_ATTACK="$ns_hsmattack" WT_ENGINE="$WT_ENGINE" \
      WT_NS_VAULT_SECURED="$ns_vault_secured" \
      WT_NS_GUEST_SECRAM="$ns_secram" WT_NS_SECURE_PROBE_PA="$ns_secure_probe" \
      WT_NS_GUEST_RESET="$ns_reset" WT_NS_GUEST_MEMNEG="$ns_memneg" \
      WT_NS_GUEST_STORAGE="$ns_storage" WT_RUN_CONFORMANCE="$ns_conf" \
      WT_CONF_SUITE="$ns_suite" WT_NS_ATTEST_NEG="$ns_attest_neg" \
      WT_NS_CONF_UPSTREAM="$build/upstream/psa-arch-tests/api-tests" \
      WT_NS_CONFDATA_PA="$ns_confdata" \
      WT_NS_MANIFEST_INC="$build/manifest"
    ns_bin="$nsfw/build/$tag-$scenario/ns.bin"
  fi
  if [ -n "$acs_suite" ]; then
    acs_out="$build/acs"
    # FF-A ids follow coroutine creation order; the hsm engine's guest-0
    # wolfHSM server tasklet takes one slot ahead of the ACS partitions.
    acs_id_base=0x8008
    [ "$WT_ENGINE" = hsm ] && acs_id_base=0x8009
    SUITE="$acs_suite" TOOLPREFIX="$TOOLPREFIX" \
      WT_ACS_SP_ID_BASE="${WT_ACS_SP_ID_BASE:-$acs_id_base}" \
      "$repo/tests/conformance/ffa-acs/build_acs.sh" "$MACHINE" "$acs_out" >/dev/null
    ns_bin="$acs_out/vm1.bin"
    # The suite requires its NVM to read 0xFF at power-on.
    head -c 65536 /dev/zero | tr '\000' '\377' > "$acs_out/nvm.bin"
    # One blob mirroring the Secure RAM layout: four 1 MB bands with each image
    # 0x4000 in, then the NVM.
    acs_blob="$acs_out/acs-secure.bin"
    : > "$acs_blob"
    for acs_n in 1 2 3 4; do
      truncate -s $(( (acs_n - 1) * 0x100000 + 0x4000 )) "$acs_blob"
      cat "$acs_out/sp$acs_n.bin" >> "$acs_blob"
    done
    truncate -s $((0x400000)) "$acs_blob"
    cat "$acs_out/nvm.bin" >> "$acs_blob"
  fi
  # virt boots one pflash image: the monitor at 0, the SPMC image behind it
  # at WT_SPM_FLASH_OFFSET (mk/target-qemuvirt.mk), copied to RAM by EL3.
  image_bin="$build/pflash.bin"
  el3_size=$(wc -c < "$build/wolftrust_el3.bin")
  if [ "$el3_size" -gt $((0x100000)) ]; then
    echo "EL3 image is $el3_size bytes, past the SPMC flash offset 0x100000" >&2
    exit 1
  fi
  cp "$build/wolftrust_el3.bin" "$image_bin"
  truncate -s $((0x100000)) "$image_bin"
  cat "$build/wolftrust.bin" >> "$image_bin"
  if [ -n "$acs_suite" ]; then
    # Behind the SPMC image at WT_FFA_ACS_FLASH_OFFSET (mk/target-qemuvirt.mk).
    truncate -s $((0x200000)) "$image_bin"
    cat "$acs_blob" >> "$image_bin"
  fi
fi

log="$repo/ci-qemu-a-$scenario-$tag.log"
ns_log="$repo/ci-qemu-a-$scenario-$tag-ns.log"
sec_log="$repo/ci-qemu-a-$scenario-$tag-secure.log"
qemu_out="$repo/ci-qemu-a-$scenario-$tag-qemu.log"
: > "$ns_log"; : > "$sec_log"

# virt: the first -serial is the Non-secure PL011, the second the secure one;
# the image boots from flash0 at 0. versal-virt: the loader places the ELF in
# OCM and points core 0 at it; UART0 is the NS console, UART1 the secure one.
if [ "$MACHINE" = virt ]; then
  virt_opts="virt,secure=on,gic-version=$GIC"
  [ -n "$acs_suite" ] && virt_opts="$virt_opts,virtualization=on"
  [ "$scenario" = el2dirtyneg ] && virt_opts="$virt_opts,virtualization=on"
  [ "$scenario" = psci-el2 ] && virt_opts="$virt_opts,virtualization=on"
  args=(-M "$virt_opts" -cpu "$CPU" -smp "$SMP" -m 1G
        -bios "$image_bin"
        -serial "file:$ns_log" -serial "file:$sec_log")
else
  # The model has no reset controller: its monitor powers it off with the
  # reset exit code and this runner powers it on again. The DDR is
  # file-backed so it keeps its contents across that cycle, as virt's RAM does
  # across its machine reset; the consoles append.
  ddr="$build/versal-ddr.bin"
  rm -f "$ddr"
  args=(-M "xlnx-versal-virt,memory-backend=ddr" -smp "$SMP" -m 2G
        -object "memory-backend-file,id=ddr,size=2G,mem-path=$ddr,share=on"
        -device "loader,file=$image_elf")
  if [ "$scenario" != smoke ]; then
    args+=(-device "loader,file=$spm_elf")
  fi
  args+=(-device "loader,addr=$el3_base,cpu-num=0"
         -chardev "file,id=nscon,path=$ns_log,append=on" -serial chardev:nscon
         -chardev "file,id=scon,path=$sec_log,append=on" -serial chardev:scon)
fi
if [ "$scenario" = ns-smoke ] || [ "$scenario" = ffa-discovery ] || \
   [ "$scenario" = ffa-guest-direct ] || [ "$scenario" = psci ] || \
   [ "$scenario" = el2dirtyneg ] || [ "$scenario" = psci-el2 ] || \
   [ "$scenario" = ffa-preempt ] || [ "$scenario" = positive ] || \
   [ "$scenario" = smcfuzz ] || \
   [ "$scenario" = secramneg ] || [ "$scenario" = resetneg ] || \
   [ "$scenario" = ffa-memneg ] || [ "$scenario" = storage ] || \
   [ "$scenario" = hsmattackneg ] || [ "$scenario" = vaultrecoversec ] || \
   [ "$scenario" = vaultrecover ] || [ "$scenario" = attestneg ] || \
   [ "$scenario" = confboot ] || [ "$scenario" = devstorage ] || \
     [ "$scenario" = devattest ] || [ "$scenario" = devcrypto ]; then
  args+=(-device "loader,file=$ns_bin,addr=$ns_base")
fi
if [ -n "$acs_suite" ]; then
  args+=(-device "loader,file=$ns_bin,addr=$ns_base")
  # virt reaches Secure RAM only through the monitor's copy out of pflash;
  # versal-virt's loader places the same blob directly.
  if [ "$MACHINE" != virt ]; then
    args+=(-device "loader,file=$acs_blob,addr=$(printf '0x%X' $((acs_secure_base + 0x400000)))")
  fi
fi
args+=(-nographic -monitor none
       -semihosting-config "enable=on,target=native")
# virt resets through its Secure GPIO: QEMU must reboot the machine, not exit.
[ "$MACHINE" = virt ] || args+=(-no-reboot)

# The versal power-cycle budget mirrors virt's WT_EL3_RESET_LIMIT defaults.
reset_limit=1
case " ${probe[*]:-} " in *" WT_CONFORMANCE=1 "*) reset_limit=256 ;; esac
cycles=0
deadline=$(( $(date +%s) + QEMU_TIMEOUT ))
: > "$qemu_out"
echo "QEMU: $QEMU ${args[*]}"
while :; do
  left=$(( deadline - $(date +%s) ))
  if [ "$left" -le 0 ]; then
    emu_status=124
    break
  fi
  sec_seen=$(wc -c < "$sec_log")
  set +e
  timeout "$left" "$QEMU" "${args[@]}" >> "$qemu_out" 2>&1
  emu_status=$?
  set -e
  if [ "$MACHINE" = virt ] || [ "$emu_status" -ne $((0x7d)) ] || \
     [ "$(tail -c +$((sec_seen + 1)) "$sec_log" | grep -ao '\[BKPT\] imm=0x[0-9a-f]*' | tail -1)" != "[BKPT] imm=0x7d" ]; then
    break
  fi
  if [ "$cycles" -ge "$reset_limit" ]; then
    echo "[QEMU] power-cycle limit $reset_limit reached" >> "$qemu_out"
    emu_status=0
    break
  fi
  cycles=$((cycles + 1))
  echo "[QEMU] power cycle $cycles" >> "$qemu_out"
done
{ cat "$ns_log" "$sec_log" "$qemu_out"; echo "[QEMU EXIT] status=$emu_status"; } > "$log"
if [ "$emu_status" -eq 0 ]; then echo "[EXPECT EXIT] Success" >> "$log"; fi
cat "$log"
echo "wolfTrust QEMU AArch64 exit status: $emu_status ($tag)"

export WT_EXPECT_LOG="$log"

case "$scenario" in
  smoke)
    expect "code runs at EL3 on $MACHINE" "[SMOKE] EL3 machine=$MACHINE"
    expect "generic timer frequency reported" " cntfrq="
    expect "secondary cores parked (PF-Q1, $cpus cores)" " parked_mask=$expected_mask"
    refute_re "no smoke failure marker" '\[SMOKE\] FAIL'
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  parkneg|rdistneg|tickneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    expect "EL3 monitor banner on $MACHINE" "[EL3] wolfTrust monitor cntfrq="
    case "$scenario" in
      parkneg)
        expect "the declared secondary never parked" " secondaries parked mask=0x0"
        expect "the monitor stopped the boot on the missing secondary" "[EL3] panic code=0x000000b2" ;;
      rdistneg)
        expect "the redistributor read asleep" " rdist_woken=0 "
        expect "the monitor stopped the boot on the sleeping redistributor" "[EL3] panic code=0x000000b3" ;;
      tickneg)
        expect "the secure tick never reached EL3" "[EL3] tick TIMEOUT"
        expect "the monitor stopped the boot without its secure tick" "[EL3] panic code=0x000000b4" ;;
    esac
    refute_re "the Secure EL1 runtime was never entered" '\[SPM\] spmc entered'
    refute_re "the run did not end cleanly" '\[EXPECT BKPT\] Success'
    ;;
  boot|boot-smp2)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "EL3 monitor banner on $MACHINE" "[EL3] wolfTrust monitor cntfrq="
    expect "GIC initialized as v$GIC" " gic=v$GIC "
    if [ "$GIC" = 3 ]; then
      expect "GICv3 redistributor woken" " rdist_woken=1 "
    fi
    expect "secondary cores parked ($cpus cores)" " secondaries parked mask=$expected_mask"
    expect "secure timer tick reached EL3 as a Group 0 FIQ" "[EL3] tick ok intid=29"
    expect "SPMD built the FF-A boot information blob" "[EL3] boot info at 0x"
    expect "SPMC image placed in its band" "[EL3] spmc image at 0x"
    expect "monitor dropped into Secure EL1" "[SPM] spmc entered at S-EL1"
    expect "SPMC consumed the boot information blob" "[SPM] boot info ok descs="
    expect "SPMC turned its stage-1 MMU on and still prints" "[SPM] mmu on ttbr0=0x"
    expect "secure timer tick reached the SPMC as a Group 0 FIQ at S-EL1" "[SPM] tick ok intid=29"
    expect "coroutine switch works at Secure EL1" "[SPM] coroutine ok"
    expect "unprivileged partition ran at S-EL0 and yielded through SVC" "[SPM] el0 svc ok"
    expect "a direct request was delivered to a waiting S-EL0 partition and echoed back" "[SPM] ffa direct ok"
    expect "a spinning S-EL0 partition was preempted by the secure timer tick" "[SPM] preempt ok"
    expect "a software-raised Secure SPI reached the SPMC as a Group 0 FIQ" "[SPM] sint gic ok intid=0x28"
    expect "an S-EL0 partition discovered itself under its own endpoint id through FFA_PARTITION_INFO_GET" "[SPM] partinfo ok n=1"
    expect "an S-EL0 partition retrieved a page the SPMC shared, wrote it, relinquished it, and the owner reclaimed it" "[SPM] mem share ok handle="
    refute_re "the memory-sharing self-test did not fail" '\[SPM\] mem share FAIL'
    expect "FF-A version negotiated with the SPMD" "[SPM] ffa version 1.2 negotiated"
    expect "the monitor answered the SMCCC architecture calls from the Secure world" "[SPM] smccc version 1.2"
    expect "FF-A discovery at the Secure physical instance" "[SPM] ffa discovery ok id=0x8000 spmd=0x8001"
    expect "FFA_CONSOLE_LOG SMC32 logged through the SPMD" "[SPM] console32 ok"
    expect "FFA_CONSOLE_LOG SMC64 logged through the SPMD" "[SPM] console64 ok"
    expect "SPMC initialization completed with FFA_MSG_WAIT" "[EL3] spmc ready"
    expect "monitor exit call reached EL3" "[BKPT] imm=0x7f"
    expect "[EXPECT BKPT] Success clean exit" "[EXPECT BKPT] Success"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    if [ "$scenario" = boot-smp2 ]; then
      expect_once "exactly one EL3 banner (the secondary parked before main)" "[EL3] wolfTrust monitor cntfrq="
      expect_once "exactly one Secure EL1 entry" "[SPM] spmc entered at S-EL1"
      expect_once "exactly one monitor exit" "[BKPT] imm=0x7f"
    fi
    ;;
  positive-secure)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "monitor dropped into Secure EL1" "[SPM] spmc entered at S-EL1"
    for id in 8002 8003 8004 8005 8006 8007; do
      expect "partition 0x$id initialized through the SVC gate" "[SP] init id=0x$id"
    done
    expect "every partition initialized" "[SPM] partitions ready n=6"
    expect "SPMC idles on FFA_MSG_WAIT with no Normal world" "[EL3] spmc ready"
    expect "monitor exit call reached EL3" "[BKPT] imm=0x7f"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  confboot)
    # The unmodified Arm FF-M IPC suite (psa-arch-tests val NSPE, pinned rev,
    # zero test edits) runs from the Normal world over FF-A against the
    # conformance SPMC image. Panic tests reboot the whole chain mid-suite
    # (the SPMC's must-panic policy and the NS client's own abort vector both
    # answer with PSCI SYSTEM_RESET) and val resumes off the Secure NVM boot
    # flag, so partition faults are by design here: the suite's own totals
    # and the clean semihosting exit gate correctness. 89 scheduled: 85 pass,
    # the 4 heap tests report SKIPPED (zero-allocation image); i067 is not
    # scheduled (heap).
    # Each test partition's writable globals lie in its own page-aligned
    # segment, the only part of the band it is granted, and nothing else in
    # the band holds a symbol.
    conf_nm=$("${TOOLPREFIX}nm" "$spm_elf")
    conf_addr() { printf '%s\n' "$conf_nm" | awk -v s="$1" '$3 == s && !f { print $1; f = 1 }'; }
    conf_segs=""
    for owner in "server:val_server_sp psa_server_sp server_ipc_test_list g_test_i084" \
                 "client:val_client_sp psa_client_sp client_ipc_test_list" \
                 "driver:g_psa_rot_data g_drv_nvm g_drv_nvm_ready g_drv_wd_enabled log_buffer log_buffer_offset"; do
      seg=${owner%%:*}
      lo=$(conf_addr "_s_conf_${seg}_data"); hi=$(conf_addr "_e_conf_${seg}_data")
      [ -n "$lo" ] && [ -n "$hi" ] || check_fail "the $seg partition has its own data segment" "no _s/_e_conf_${seg}_data"
      conf_segs="$conf_segs $((16#$lo)):$((16#$hi))"
      for s in ${owner#*:}; do
        a=$(conf_addr "$s")
        if [ -z "$a" ] || [ $((16#$a)) -lt $((16#$lo)) ] || [ $((16#$a)) -ge $((16#$hi)) ]; then
          check_fail "the $seg partition's writable globals lie in its own segment" "$s at ${a:-none}, segment $lo-$hi"
        fi
      done
      check_pass "the $seg partition's writable globals lie in its own segment"
    done
    conf_stray=""
    while read -r a t s; do
      [ -n "$s" ] || continue
      case "$t" in A|a) continue ;; esac
      case "$s" in _s_conf_*|_e_conf_*|_si_conf_*) continue ;; esac
      v=$((16#$a))
      { [ "$v" -ge $((ns_confdata)) ] && [ "$v" -lt $((ns_confdata + 0x1C000)) ]; } || continue
      in_seg=0
      for r in $conf_segs; do
        [ "$v" -ge "${r%%:*}" ] && [ "$v" -lt "${r#*:}" ] && in_seg=1
      done
      [ "$in_seg" = 1 ] || conf_stray="$conf_stray $s"
    done <<< "$conf_nm"
    if [ -z "$conf_stray" ]; then
      check_pass "no conformance data lies outside the partitions' own segments"
    else
      check_fail "no conformance data lies outside the partitions' own segments" "shared:$conf_stray"
    fi
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "monitor dropped into Secure EL1" "[SPM] spmc entered at S-EL1"
    for id in 8002 8003 8004 8005 8006 8007 8008 8009; do
      expect "partition 0x$id initialized through the SVC gate" "[SP] init id=0x$id"
    done
    expect "every conformance partition initialized" "[SPM] partitions ready n=8"
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "val started from the payload" "[NS] conformance val_entry start"
    if [ "$MACHINE" = versal-virt ]; then
      # xlnx-versal-virt models no XMPU/RISAF (see secramneg): the seven
      # Normal-world fence tests (i048/i049 pass a Secure iovec array pointer
      # the client dereferences; i072/i073/i075/i076/i077 read Secure
      # data/stack/mmio from NS) read Secure RAM without faulting and report
      # Failed. Every other test must pass; the fence is proven on the virt
      # cells (VIRT_SECURE_MEM), and this port claims no isolation level.
      expect_flat "Arm suite TOTAL PASSED : 78 (versal-virt: no NS fence model)" "TOTAL PASSED    : 78"
      expect_flat "Arm suite TOTAL SKIPPED : 4" "TOTAL SKIPPED   : 4"
      expect_flat "Arm suite TOTAL FAILED : 7" "TOTAL FAILED    : 7"
      # A reboot can split a test header across lines, so key on the Num=
      # token wherever it lands rather than on the Suite= line.
      failed=$(awk '/Num=[0-9]+/ {match($0, /Num=[0-9]+/); n = substr($0, RSTART + 4, RLENGTH - 4)}
                    /^Result=Failed/ && n != "" {print n}' "$log" | sort -un | tr '\n' ' ')
      if [ "$failed" = "48 49 72 73 75 76 77 " ]; then
        check_pass "only the Normal-world fence tests failed on the model"
      else
        check_fail "only the Normal-world fence tests failed on the model" "failed set: $failed"
      fi
    else
      expect_flat "Arm suite TOTAL PASSED : 85" "TOTAL PASSED    : 85"
      expect_flat "Arm suite TOTAL SKIPPED : 4" "TOTAL SKIPPED   : 4"
      expect_flat "Arm suite TOTAL FAILED : 0" "TOTAL FAILED    : 0"
    fi
    expect "val returned to the payload" "[NS] conformance val_entry returned"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  crossdomain)
    refute_re "the fault never escalated to a Secure EL1 exception" '^\[SYNC EL=1'
    expect "a partition read outside its domain and took a data abort at S-EL0" "[SYNC EL=0 EC=0x24"
    expect "the offending partition was restarted under its manifest policy" "[SP] restarted id=0x"
    expect "the persistently-faulting partition spent its restart budget" "[SPM] restart budget exhausted, failing closed"
    expect "the exhausted budget escalated to fail-closed platform recovery" "[EL3] panic code=0x0000007d"
    refute_re "the run did not exit cleanly" '\[EXPECT EXIT\] Success'
    ;;
  spfaultneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC EL=1'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "a partition faulted at S-EL0 during init" "[SYNC EL=0 EC=0x00"
    expect "the faulted partition was restarted under its manifest policy" "[SP] restarted id=0x"
    expect "every partition still reached initialization" "[SPM] partitions ready n=6"
    expect "SPMC idles on FFA_MSG_WAIT with no Normal world" "[EL3] spmc ready"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  tablesneg)
    refute_re "the SPMC never turned its MMU on" '\[SPM\] mmu on'
    refute_re "no partition initialized" '\[SPM\] partitions ready'
    refute_re "the run did not exit cleanly" '\[EXPECT EXIT\] Success'
    expect "a writable and executable region was refused when the SPM table was built (W^X)" "[SPM] FAIL domain x0=0x00000001"
    expect "the SPMC panicked through the monitor" "[EL3] panic code=0x000000f1"
    ;;
  manifestneg)
    refute_re "no partition initialized off the corrupted manifest" '\[SPM\] partitions ready'
    refute_re "the run did not exit cleanly" '\[EXPECT EXIT\] Success'
    expect "the SPMC panicked out of manifest validation" "[SPM] panic from 0x"
    expect "the panic reached the monitor with the manifest-validation code" "[EL3] panic code=0x000000f2"
    ;;
  keystoreneg)
    refute_re "the fault never escalated to a Secure EL1 exception" '^\[SYNC EL=1'
    expect "a non-keystore partition read the keystore band and took a data abort at S-EL0" "[SYNC EL=0 EC=0x24"
    if [ "$MACHINE" = versal-virt ]; then
      expect "the faulting read targeted the keystore band" "FAR=0x000000007f300000"
    else
      expect "the faulting read targeted the keystore band" "FAR=0x000000000e300000"
    fi
    expect "the offending partition was restarted under its manifest policy" "[SP] restarted id=0x"
    expect "the persistently-faulting partition spent its restart budget" "[SPM] restart budget exhausted, failing closed"
    expect "the exhausted budget escalated to fail-closed platform recovery" "[EL3] panic code=0x0000007d"
    refute_re "the run did not exit cleanly" '\[EXPECT EXIT\] Success'
    ;;
  spbudgetneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC EL=1'
    expect "the relay partition faulted at S-EL0 on every entry" "[SYNC EL=0 EC=0x00"
    expect "the faulting partition was restarted under its manifest policy" "[SP] restarted id=0x"
    expect "the restart budget was spent" "[SPM] restart budget exhausted, failing closed"
    expect "the exhausted budget escalated to fail-closed platform recovery" "[EL3] panic code=0x0000007d"
    refute_re "the run did not exit cleanly" '\[EXPECT EXIT\] Success'
    ;;
  panicneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC EL=1'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the ITS partition was panicked for a programmer-error handle close at S-EL0" "[SYNC EL=0 EC=0x00"
    expect "the panicked ITS partition was restarted under its manifest policy" "[SP] restarted id=0x8004"
    expect "every partition still reached initialization after the one-shot recovery" "[SPM] partitions ready n=6"
    expect "SPMC idles on FFA_MSG_WAIT with no Normal world" "[EL3] spmc ready"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-direct)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no unexpected FF-A event at the SPMC" '\[SPM\] unexpected event'
    refute_re "the response was not judged bad" '\[EL3\] direct resp BAD'
    expect "the echo partition initialized alongside the six services" "[SPM] partitions ready n=7"
    expect "the echo partition, preempted before its first wait, was resumed to finish init" "[SP] init resumed id=0x"
    expect "the SPMD sent a direct request to the echo partition" "[EL3] direct req to=0x80fe"
    expect "the SPMC relayed it at the NS-physical instance" "[SPM] direct req from=0x0000 to=0x80fe"
    expect "the echo partition's response reached the SPMD with the payload complemented" "[EL3] direct resp ok from=0x80fe x3=0xedcb5432"
    expect "an AArch32 Secure EL1's SMCs took the lower-AArch32 vector and were answered, not faulted" "[EL3] a32 vector smc version=0x00010002 smc64=0xffffffff psci=0xffffffff"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-sint)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no unexpected FF-A event at the SPMC" '\[SPM\] unexpected event'
    expect "the echo partition initialized alongside the six services" "[SPM] partitions ready n=7"
    expect "the echo partition, preempted before its first wait, was resumed to finish init" "[SP] init resumed id=0x"
    refute_re "every FFA_INTERRUPT the echo partition got carried w1/w2 zero, or its MBZ check would fault it" '^\[SYNC EL=0'
    expect "a Secure interrupt was signalled to the owner while it waited, and a pending Normal-world interrupt stayed queued until the owner waited again" "[SPM] sint signaled id=0x28"
    expect "a Secure interrupt queued while the owner handled another was delivered on its next wait and named by the get" "[SPM] sint queued id=0x28"
    expect "an AArch32 Secure EL1's SMCs took the lower-AArch32 vector and were answered, not faulted" "[EL3] a32 vector smc version=0x00010002 smc64=0xffffffff psci=0xffffffff"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ns-smoke)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world did not misread the version" '\[NS\] ffa version BAD'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    expect "the SPMD launched the Normal world" "[EL3] ns launch pc=0x44000000"
    expect "the Normal-world payload ran at NS-EL1" "[NS] hello el=1"
    expect "the Normal world negotiated FF-A 1.2 with the SPMD" "[NS] ffa version 1.2"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-discovery)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world did not misread discovery" '\[NS\] discovery BAD'
    expect "the Normal world negotiated FF-A 1.2 with the SPMD" "[NS] ffa version 1.2"
    expect "the Normal world discovered the partitions through the SPMC" "[NS] discovery ok n=6"
    refute_re "no 8-register event reached the SPMC with x8-x17 carried over from its last SMC" '\[SPM\] eret sbz BAD'
    expect "8-register events reach the SPMC over ERET with x8-x17 zero (11.2)" "[SPM] eret sbz ok"
    refute_re "the notification SET to a PSA partition was not misanswered" '\[NS\] notif BAD'
    expect "a notification SET naming a PSA partition, which takes none, was DENIED" "[NS] notif set to a PSA partition denied"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-guest-direct)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world did not misread the direct response" '\[NS\] direct resp BAD'
    expect "the Normal world discovered the partitions through the SPMC" "[NS] discovery ok n=6"
    expect "a guest direct request reached the Secure partition and echoed back" "[NS] direct resp ok x3=0x"
    refute_re "a refused REQ2 did not hand back its own payload in x8-x17" '\[NS\] req2 refused BAD'
    expect "a refused REQ2 returned FFA_ERROR with x8-x17 zero" "[NS] req2 refused x8-x17 zero"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  psci|psci-el2|el2dirtyneg)
    # el2dirtyneg: an inherited SMC trap would strand the first NS call at
    # EL2, and an inherited virtual MPIDR would misname the boot core.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "NS-EL1 did not find the GIC system-register interface off" '\[NS\] icc_sre_el1 BAD'
    if [ "$GIC" = 3 ]; then
      expect "NS-EL1 read ICC_SRE_EL1 with SRE set under the GICv3" "[NS] icc_sre_el1 sre=1"
    fi
    expect "secondary cores parked ($cpus cores)" " secondaries parked mask=$expected_mask"
    expect "EL3 set the fail-closed debug and PMU policy in MDCR_EL3" "[EL3] mdcr_el3 ok"
    expect "the Normal world read the PSCI version from the SPMD" "[NS] psci version 1.1"
    refute_re "no PSCI call returned an off-spec value" '\[NS\] psci BAD'
    expect "SMCCC_VERSION reported 1.2 and x4-x7 survived a PSCI call" "[NS] smccc version 1.2"
    expect "the mandatory PSCI 1.1 calls answered as a boot-core-only system" "[NS] psci mandatory set ok"
    if [ "$scenario" = el2dirtyneg ] && [ "$GIC" = 3 ]; then
      expect "an earlier stage left every SPI routed to an absent PE" "[EL3] probe: every SPI routed to an absent PE"
      expect "a Secure SPI the SPMC enabled still reached it as a Group 0 FIQ" "[SPM] sint gic ok intid=0x28"
    fi
    if [ "$scenario" = psci-el2 ]; then
      expect "the Normal-world payload ran at NS-EL2" "[NS] hello el=2"
      expect "an AArch32 EL1 caller's SMC32 calls were served, one forwarded to the SPMC, and its SMC64 id refused" "[NS] a32 smc ok partinfo n="
    fi
    expect "the Normal world powered off through PSCI" "[EL3] psci system_off"
    expect "the PSCI power-off ended the run cleanly" "[EXPECT BKPT] Success"
    ;;
  ffa-preempt)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the Normal world was running" "[NS] spinning"
    expect "a core-standby CPU_SUSPEND returned SUCCESS on the Secure tick" "[NS] psci standby woke"
    expect "a Secure tick preempted the Normal world at EL3" "[EL3] ns preempted"
    refute_re "the SPMD left the interrupt to the SPMC unacknowledged" '\[EL3\] ns preempted intid'
    expect "the SPMC took the Secure interrupt from the GIC itself" "[SPM] ns preempt intid=0x1d"
    expect "the Normal world resumed after the preemption" "[NS] resumed after preempt"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  positive)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the guest did not fail a PSA connect" '\[NS\] psa connect FAIL'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    expect "the Normal-world guest ran at NS-EL1" "[NS] hello el=1"
    expect "the guest discovered the partitions through the SPMC" "[NS] discovery ok n=6"
    expect "the SPMC fielded the guest's PSA requests at the framework endpoint" "[SPM] direct req from=0x0000 to=0x80fd"
    expect "the guest read the PSA framework version over the transport" "[NS] psa framework 0x100"
    expect "the guest read the service version over the transport" "[NS] psa version v=1"
    expect "the guest connected to a Secure service and got a handle" "[NS] psa connect ok handle="
    expect "an unknown service was refused by the gateway" "[NS] psa connect refused"
    refute_re "the data-carrying call was not misjudged" '\[NS\] psa call BAD'
    expect "the guest completed a data-carrying psa_call through the routed gateway" "[NS] psa call ok"
    if [ "$WT_ENGINE" = hsm ]; then
      expect "the wolfHSM client echoed a packet through the relay partition and the wolfHSM server" "[NS] hsm echo ok"
    else
      expect "the native crypto client drew distinct random blocks from the crypto partition" "[NS] native random ok"
    fi
    expect "the guest closed its handle" "[NS] psa close ok"
    refute_re "a call made with a Normal-world interrupt pending neither failed nor consumed it" '\[NS\] psa call with an ns irq pending BAD'
    if [ "$GIC" = 3 ]; then
      expect "a psa_call made with a Normal-world interrupt pending completed, the interrupt queued for the Normal world (9.3.1.3)" "[NS] psa call with an ns irq pending ok"
    fi
    expect "the Normal-world guest reached the services and finished" "[NS] guest0 ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  vaultrecoversec)
    # A foreign vault under a locked lifecycle: the reformat is refused and
    # attestation fails closed, but the boot is not bricked and the guest runs.
    # A reformat would have re-provisioned the IAK, so the IAK query answering
    # is what a wiped vault looks like from the Normal world.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    refute_re "the foreign vault was not reformatted into a fresh IAK" '\[NS\] vault attest key ISSUED'
    expect "attestation failed closed on the unprovisioned IAK" "[NS] vault attest refused st=0x"
    if [ "$WT_ENGINE" = hsm ]; then
      expect "the wolfHSM relay still serves the guest" "[NS] hsm echo ok"
    else
      expect "the native crypto service still serves the guest" "[NS] native random ok"
    fi
    expect "the guest ran to completion under fail-closed attestation" "[NS] guest0 ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  hsmattackneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the guest forged the attestation-reserved client id" "[NS] hsmattack forged COMM_INIT"
    expect "the forged client id did not reach the committed IAK" "[NS] hsmattack IAK read refused"
    expect "the relay refused the NVM-group request" "[NS] hsmattack rollback NVM group refused"
    expect "the guest's own relay namespace still works" "[NS] hsmattack own-namespace relay still works"
    refute_re "the IAK read never succeeded" 'hsmattack IAK read SUCCEEDED'
    refute_re "the NVM group never succeeded" 'hsmattack rollback NVM group SUCCEEDED'
    expect "the Normal-world guest finished" "[NS] guest0 ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  resetneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    expect "the Normal world asked for a system reset" "[NS] psci system_reset"
    expect "the first reset rebooted the machine" "[EL3] psci system_reset reboot"
    expect "the monitor booted the chain a second time" "[EL3] wolfTrust monitor cntfrq="
    boots=$(grep -Fao "[NS] uart ifls=0x" "$log" | wc -l | tr -d ' ')
    if [ "$boots" -eq 2 ]; then
      check_pass "the Normal world read its UART on both boots"
    else
      check_fail "the Normal world read its UART on both boots" "$boots reads"
    fi
    # A cold reset returns the UART the first boot marked to its reset value.
    refute_re "the machine reset restored the marked device register" '\[NS\] uart ifls=0x24'
    refute_re "the reset was not a warm re-entry" 'warm re-entry'
    if [ "$MACHINE" = virt ]; then
      expect "the second reset ended the run through the boot-flag path" "[EL3] psci system_reset done"
      expect "the re-entered chain exited cleanly" "[EXPECT BKPT] Success"
    else
      # xlnx-versal-virt has no reset controller: the monitor powers the model
      # off and the runner powers it on again, once.
      expect "the monitor powered the model off to reset it" "[BKPT] imm=0x7d"
      expect "the model was power-cycled once" "[QEMU] power cycle 1"
      refute_re "the model was power-cycled only once" '\[QEMU\] power cycle 2'
      expect "the second reset ended the run at the power-cycle limit" "[QEMU] power-cycle limit 1 reached"
      expect "the run ended cleanly" "[EXPECT EXIT] Success"
    fi
    parked=$(grep -Fao " secondaries parked mask=$expected_mask" "$log" | wc -l | tr -d ' ')
    if [ "$parked" -eq 2 ]; then
      check_pass "both boots counted every secondary parked ($cpus cores)"
    else
      check_fail "both boots counted every secondary parked ($cpus cores)" \
        "mask=$expected_mask on $parked of 2 boots"
    fi
    ;;
  secramneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "the Normal world never read Secure RAM" '\[NS\] secram LEAK'
    refute_re "no other exception stood in for the fence's refusal" '\[NS\] secram BAD'
    expect "the Normal world attempted the Secure-RAM read" "[NS] secram read 0x"
    expect "the Secure-RAM read took the fence's external data abort at the probe address" \
      "[NS] secram refused ec=0x25 dfsc=0x10 far=0x$(printf '%x' "$ns_secure_probe") "
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  smcfuzz)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no function id was mishandled" '\[NS\] smcfuzz BAD'
    refute_re "the sweep did not fall short" '\[NS\] smcfuzz FAIL'
    expect "every unimplemented function id from the Normal world was refused cleanly" "[NS] smcfuzz ok swept="
    refute_re "no SMC32 call was read with its upper register halves" '\[NS\] smc32 upper halves BAD'
    expect "an SMC32 call's junk upper register halves were ignored" "[NS] smc32 upper halves ignored"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffa-memneg)
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic on a malformed transaction" '\[SPM\] panic'
    refute_re "no malformed transaction was mishandled" '\[NS\] memneg BAD'
    expect "every malformed memory transaction was refused and a reclaimed handle is dead" "[NS] memneg ok"
    expect "FFA_RX_RELEASE checked the VM id and the buffer pair before releasing the RX buffer" "[NS] rx release ok"
    expect "a share sent in two fragments completed under the handle its first one reserved" "[NS] memfrag ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  devstorage)
    # The unmodified Arm dev_apis storage suite (psa-arch-tests s001-s017)
    # runs from the Normal world: every ITS/PS call rides the routed PSA
    # client onto SERVICE_ITS / SERVICE_PS, whose VAULT hop is the SP-to-SP
    # path. No panic tests here; every test must pass or skip, none fail.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "the conformance SPMC image initialized every partition" "[SPM] partitions ready n=8"
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "val started from the payload" "[NS] conformance val_entry start"
    flat="$(tr -d '\r\n' < "$log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
    if [ "$failed" = "0" ] && [ "$((passed + skipped))" -eq 17 ]; then
      check_pass "dev_apis storage: ${passed} passed, ${skipped} skipped, 0 failed (17 total)"
    else
      check_fail "dev_apis storage suite" \
        "passed=$passed skipped=$skipped failed=$failed (want failed=0, passed+skipped=17)"
    fi
    expect "val returned to the payload" "[NS] conformance val_entry returned"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  ffaacs-*)
    # The Arm FF-A ACS regression report, printed by the Normal-world
    # dispatcher once every scheduled test of the group has run.
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "every ACS partition initialized" "EL0 entry.. id"
    expect "the dispatcher printed the regression report" "REGRESSION REPORT"
    flat="$(tr -d '\r\n' < "$log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    sim_error=$(printf '%s' "$flat" | grep -oE 'TOTAL SIM ERROR[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"; : "${sim_error:=-1}"
    # Every failure must be a named, by-design deviation.
    unexpected=""
    # val_test_init prints "TEST: <name> SUITE: ..." (with a space); confirmed
    # against a real setup_discovery log, not "TEST:%s".
    for name in $(grep -aE 'TEST:|RESULT: FAILED' "$log" | grep -a -B1 'RESULT: FAILED' |
                  grep -a 'TEST:' | sed -E 's/.*TEST: ([A-Za-z0-9_]+).*/\1/'); do
      case " $acs_deviations " in
        *" $name "*) ;;
        *) unexpected="$unexpected $name" ;;
      esac
    done
    # A SIM ERROR is a test that could not run to a verdict: never by design.
    if [ -z "$unexpected" ] && [ "$failed" -ge 0 ] && [ "$sim_error" = 0 ] && \
       [ "$passed" -ge "$acs_floor" ]; then
      check_pass "FF-A ACS $acs_suite: ${passed} passed, ${skipped} skipped, ${failed} by-design deviation(s), 0 sim errors"
    else
      check_fail "FF-A ACS $acs_suite" "passed=$passed (want >= $acs_floor) skipped=$skipped failed=$failed sim_error=$sim_error (want 0) unexpected:${unexpected:- none}"
    fi
    expect "the dispatcher ended the run" "END OF ACS"
    expect "the dispatcher's PSCI SYSTEM_OFF ended the emulator cleanly" "[EXPECT EXIT] Success"
    ;;
  attestneg)
    # NS-side negative probe over the routed FF-A path (the attestation service
    # and EAT code are untouched): the secure service rejects invalid get_token
    # requests, the untampered token verifies, and a tampered or misattributed
    # token fails the guest COSE_Sign1 verify.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "the oversized challenge was rejected" "[NS] attestneg oversized challenge rejected"
    expect "the zero token buffer was rejected" "[NS] attestneg zero token buffer rejected"
    expect "a misattributed lifecycle was rejected" "[NS] attestneg lifecycle mismatch rejected"
    expect "the untampered token verified" "[NS] attestneg baseline token verified"
    expect "a tampered token was rejected" "[NS] attestneg tampered token rejected"
    refute_re "no invalid request was accepted" 'attestneg .* ACCEPTED'
    expect "every attestation negative held" "[NS] attestneg ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  vaultrecover)
    # The foreign-pool probe forces the boot-time vault recovery. Under the
    # test handoff's unlocked lifecycle the vault self-heals (reformat and
    # re-provision), attestation comes back, and the crypto suite still totals
    # 64 passed / 13 skipped -- proving the recovery neither bricked the boot
    # nor left the vault unusable (WT-FFM-0017/0051).
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "val started from the payload" "[NS] conformance val_entry start"
    flat="$(tr -d '\r\n' < "$log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
    if [ "$failed" = "0" ] && [ "$passed" = "$crypto_passed" ] && [ "$skipped" = "$crypto_skipped" ]; then
      check_pass "crypto suite green after self-heal: ${passed} passed, ${skipped} skipped, 0 failed (77 total)"
    else
      check_fail "crypto suite after self-heal" \
        "passed=$passed skipped=$skipped failed=$failed (want $crypto_passed passed, $crypto_skipped skipped, 0 failed)"
    fi
    expect "val returned to the payload" "[NS] conformance val_entry returned"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  devattest|devcrypto)
    # The unmodified Arm dev_apis initial-attestation (a001) and crypto
    # (c001-c080) suites run from the Normal world: the token comes from
    # SERVICE_ATTEST over the routed client and val verifies its COSE_Sign1
    # against the runtime IAK public key; the crypto suite runs on wolfPSA in
    # the guest with persistent keys riding SERVICE_ITS.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    expect "the Normal-world test harness ran at NS-EL1" "[NS] hello el=1"
    expect "val started from the payload" "[NS] conformance val_entry start"
    refute_re "the guest heap did not hand out a wrapped oversized request" '\[NS\] heap BAD'
    expect "the guest heap refused requests the alignment rounding would wrap" "[NS] heap bound ok"
    flat="$(tr -d '\r\n' < "$log")"
    passed=$(printf '%s' "$flat" | grep -oE 'TOTAL PASSED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    skipped=$(printf '%s' "$flat" | grep -oE 'TOTAL SKIPPED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    failed=$(printf '%s' "$flat" | grep -oE 'TOTAL FAILED[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
    : "${passed:=-1}"; : "${skipped:=-1}"; : "${failed:=-1}"
    if [ "$scenario" = devattest ]; then want_p=1; want_s=0; else want_p=$crypto_passed; want_s=$crypto_skipped; fi
    if [ "$failed" = "0" ] && [ "$passed" = "$want_p" ] && [ "$skipped" = "$want_s" ]; then
      check_pass "dev_apis $scenario: ${passed} passed, ${skipped} skipped, 0 failed"
    else
      check_fail "dev_apis $scenario suite" \
        "passed=$passed skipped=$skipped failed=$failed (want $want_p passed, $want_s skipped, 0 failed)"
    fi
    expect "val returned to the payload" "[NS] conformance val_entry returned"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
  storage)
    # SERVICE_ITS fronts the VAULT partition, so a guest ITS round trip is the
    # first request whose service calls a second partition: the SVC gate runs
    # VAULT from inside the ITS partition's handler and returns into it.
    refute_re "no synchronous exception reached EL3" '^\[SYNC'
    refute_re "no partition fault" '\[SYNC EL=0'
    refute_re "no EL3 panic" '\[EL3\] panic'
    refute_re "no SPMC panic" '\[SPM\] panic'
    refute_re "the ITS round trip was not misjudged" '\[NS\] its BAD'
    expect "the SPMC completed initialization" "[SPM] partitions ready n=6"
    expect "the Normal-world guest ran at NS-EL1" "[NS] hello el=1"
    expect "an ITS object round-tripped through SERVICE_ITS and the VAULT partition behind it" "[NS] its ok"
    expect "semihosting exit 0 reached QEMU" "[EXPECT EXIT] Success"
    ;;
esac

# The fail-closed negatives end on the monitor's panic exit and resetneg at
# the emulator build's reset limit; every other scenario exits cleanly.
end_want=exit
case "$scenario" in
  parkneg|rdistneg|tickneg|crossdomain|tablesneg|manifestneg|keystoreneg|spbudgetneg) end_want=panic ;;
  resetneg) end_want=reset-limit ;;
esac
expect_end "the emulator ended the run by $end_want" "$end_want" "$emu_status"

echo "PASS: qemu-a/$scenario ($tag)"
