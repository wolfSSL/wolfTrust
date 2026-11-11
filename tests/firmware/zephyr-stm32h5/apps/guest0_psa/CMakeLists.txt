cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftrust_guest0_psa)

if(NOT DEFINED WOLFTRUST_CMSE_IMPLIB)
  message(FATAL_ERROR "WOLFTRUST_CMSE_IMPLIB must point at build/secure_cmse_implib.o")
endif()

zephyr_include_directories(
  ${ZEPHYR_BASE}/modules/cmsis_6
)

set(WT_REPO_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
set(WT_WOLFCOSE_DIR ${WT_REPO_ROOT}/lib/wolfCOSE)

target_sources(app PRIVATE
  src/main.c
  src/attestation_verify.c
  ${WOLFTRUST_CMSE_IMPLIB}
  ${WT_WOLFCOSE_DIR}/src/wolfcose_cbor.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_util.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_alg.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_ecc.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_hdr.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_key.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_struct.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_recipient.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_sign1.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_sign.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_countersign.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_encrypt0.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_mac0.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_encrypt.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_mac.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_eat_psa.c
)
target_include_directories(app PRIVATE
  ${WT_WOLFCOSE_DIR}/include
  ${WT_REPO_ROOT}/include
)
target_compile_definitions(app PRIVATE
  WOLFCOSE_LEAN
  WOLFCOSE_ENABLE_DEPRECATED_ALGS
  WOLFCOSE_NO_SIGN1_SIGN
  WOLFCOSE_NO_ENCRYPT0
  WOLFCOSE_NO_MAC0
  WOLFCOSE_NO_KEY_ENCODE
  WOLFCOSE_NO_KEY_DECODE
)
if(DEFINED WT_EXPECTED_MEASUREMENT_HEX)
    target_compile_definitions(app PRIVATE
        WT_EXPECTED_MEASUREMENT_HEX="${WT_EXPECTED_MEASUREMENT_HEX}")
endif()

if(NOT DEFINED WT_EXPECTED_LIFECYCLE)
    set(WT_EXPECTED_LIFECYCLE 0x3000u)
endif()
target_compile_definitions(app PRIVATE
    WT_EXPECTED_LIFECYCLE=${WT_EXPECTED_LIFECYCLE})

if(WT_ATTESTATION_DEVELOPMENT_PROFILE)
    target_compile_definitions(app PRIVATE
        WT_ATTESTATION_DEVELOPMENT_PROFILE=1)
endif()

if(WT_GUEST_FAULT_PROBE)
    target_compile_definitions(app PRIVATE WT_GUEST_FAULT_PROBE=1)
endif()

if(WT_NS_MASK_PROBE)
    target_compile_definitions(app PRIVATE WT_NS_MASK_PROBE=1)
endif()

if(WT_NS_BUSFAULT_PROBE)
    target_compile_definitions(app PRIVATE WT_NS_BUSFAULT_PROBE=1)
endif()

if(WT_WRITE_ONCE_RESET_PROBE)
    target_compile_definitions(app PRIVATE WT_WRITE_ONCE_RESET_PROBE=1)
endif()

if(WT_ATTEST_NEG_PROBE)
    target_compile_definitions(app PRIVATE WT_ATTEST_NEG_PROBE=1)
endif()

if(WT_FWU_PROBE)
    target_compile_definitions(app PRIVATE WT_FWU_PROBE=1)
endif()

if(WT_HSM_ATTACK_PROBE)
    target_compile_definitions(app PRIVATE WT_HSM_ATTACK_PROBE=1)
endif()

if(WT_MPU_BYPASS_PROBE)
    target_compile_definitions(app PRIVATE WT_MPU_BYPASS_PROBE=1)
endif()

if(WT_PERIPH_NEG_PROBE)
    target_compile_definitions(app PRIVATE WT_PERIPH_NEG_PROBE=1)
endif()

if(WT_M33MU_EXPECT_BKPT)
    target_compile_definitions(app PRIVATE WT_M33MU_EXPECT_BKPT=1)
endif()

set_source_files_properties(
  ${WT_WOLFCOSE_DIR}/src/wolfcose_cbor.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_util.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_alg.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_ecc.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_hdr.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_key.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_struct.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_recipient.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_sign1.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_sign.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_countersign.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_encrypt0.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_mac0.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_encrypt.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_mac.c
  ${WT_WOLFCOSE_DIR}/src/wolfcose_eat_psa.c
  PROPERTIES COMPILE_OPTIONS
    "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter;-Wno-type-limits"
)

# P3a-4a: run Arm's unmodified psa-arch-tests val NSPE in this guest against the
# real SPM. WT_RUN_CONFORMANCE selects the conformance secure image (server/
# client SPs). The val sources and the generated test/manifest headers come from
# the secure build tree (built first). include/ before build/manifest so
# wolfTrust's psa/*.h win; build/manifest/ns holds the i001-only test list.
if(WT_RUN_CONFORMANCE)
  set(WT_CONF_U ${WT_REPO_ROOT}/build/upstream/psa-arch-tests/api-tests)
  set(WT_CONF_GEN ${WT_REPO_ROOT}/build/manifest)
  # P4-S6: WT_CONF_SUITE picks the suite; exactly one builds per configure.
  if(NOT WT_CONF_SUITE)
    set(WT_CONF_SUITE ipc)
  endif()
  if(WT_CONF_SUITE STREQUAL "ipc")
  target_sources(app PRIVATE
    src/conformance_pal.c
    ${WT_CONF_U}/val/common/val_log.c
    ${WT_CONF_U}/val/nspe/val_entry.c
    ${WT_CONF_U}/val/nspe/val_dispatcher.c
    ${WT_CONF_U}/val/nspe/val_framework.c
    ${WT_CONF_U}/val/nspe/val_interfaces.c
    ${WT_CONF_U}/val/nspe/val_peripherals.c
    ${WT_CONF_U}/val/nspe/val_platform.c
    ${WT_CONF_U}/val/nspe/val_crypto.c
    ${WT_CONF_U}/val/nspe/val_storage.c
    ${WT_CONF_U}/val/nspe/val_attestation.c
    ${WT_CONF_U}/platform/targets/common/nspe/pal_weak.c
    ${WT_CONF_U}/ff/ipc/test_i001/test_entry_i001.c
    ${WT_CONF_U}/ff/ipc/test_i001/test_i001.c
    ${WT_CONF_U}/ff/ipc/test_i002/test_entry_i002.c
    ${WT_CONF_U}/ff/ipc/test_i002/test_i002.c
    ${WT_CONF_U}/ff/ipc/test_i003/test_entry_i003.c
    ${WT_CONF_U}/ff/ipc/test_i003/test_i003.c
    ${WT_CONF_U}/ff/ipc/test_i004/test_entry_i004.c
    ${WT_CONF_U}/ff/ipc/test_i004/test_i004.c
    ${WT_CONF_U}/ff/ipc/test_i005/test_entry_i005.c
    ${WT_CONF_U}/ff/ipc/test_i005/test_i005.c
    ${WT_CONF_U}/ff/ipc/test_i006/test_entry_i006.c
    ${WT_CONF_U}/ff/ipc/test_i006/test_i006.c
    ${WT_CONF_U}/ff/ipc/test_i007/test_entry_i007.c
    ${WT_CONF_U}/ff/ipc/test_i007/test_i007.c
    ${WT_CONF_U}/ff/ipc/test_i008/test_entry_i008.c
    ${WT_CONF_U}/ff/ipc/test_i008/test_i008.c
    ${WT_CONF_U}/ff/ipc/test_i009/test_entry_i009.c
    ${WT_CONF_U}/ff/ipc/test_i009/test_i009.c
    ${WT_CONF_U}/ff/ipc/test_i010/test_entry_i010.c
    ${WT_CONF_U}/ff/ipc/test_i010/test_i010.c
    ${WT_CONF_U}/ff/ipc/test_i011/test_entry_i011.c
    ${WT_CONF_U}/ff/ipc/test_i011/test_i011.c
    ${WT_CONF_U}/ff/ipc/test_i012/test_entry_i012.c
    ${WT_CONF_U}/ff/ipc/test_i012/test_i012.c
    ${WT_CONF_U}/ff/ipc/test_i013/test_entry_i013.c
    ${WT_CONF_U}/ff/ipc/test_i013/test_i013.c
    ${WT_CONF_U}/ff/ipc/test_i014/test_entry_i014.c
    ${WT_CONF_U}/ff/ipc/test_i014/test_i014.c
    ${WT_CONF_U}/ff/ipc/test_i015/test_entry_i015.c
    ${WT_CONF_U}/ff/ipc/test_i015/test_i015.c
    ${WT_CONF_U}/ff/ipc/test_i016/test_entry_i016.c
    ${WT_CONF_U}/ff/ipc/test_i016/test_i016.c
    ${WT_CONF_U}/ff/ipc/test_i017/test_entry_i017.c
    ${WT_CONF_U}/ff/ipc/test_i017/test_i017.c
    ${WT_CONF_U}/ff/ipc/test_i018/test_entry_i018.c
    ${WT_CONF_U}/ff/ipc/test_i018/test_i018.c
    ${WT_CONF_U}/ff/ipc/test_i019/test_entry_i019.c
    ${WT_CONF_U}/ff/ipc/test_i019/test_i019.c
    ${WT_CONF_U}/ff/ipc/test_i020/test_entry_i020.c
    ${WT_CONF_U}/ff/ipc/test_i020/test_i020.c
    ${WT_CONF_U}/ff/ipc/test_i021/test_entry_i021.c
    ${WT_CONF_U}/ff/ipc/test_i021/test_i021.c
    ${WT_CONF_U}/ff/ipc/test_i022/test_entry_i022.c
    ${WT_CONF_U}/ff/ipc/test_i022/test_i022.c
    ${WT_CONF_U}/ff/ipc/test_i023/test_entry_i023.c
    ${WT_CONF_U}/ff/ipc/test_i023/test_i023.c
    ${WT_CONF_U}/ff/ipc/test_i024/test_entry_i024.c
    ${WT_CONF_U}/ff/ipc/test_i024/test_i024.c
    ${WT_CONF_U}/ff/ipc/test_i025/test_entry_i025.c
    ${WT_CONF_U}/ff/ipc/test_i025/test_i025.c
    ${WT_CONF_U}/ff/ipc/test_i026/test_entry_i026.c
    ${WT_CONF_U}/ff/ipc/test_i026/test_i026.c
    ${WT_CONF_U}/ff/ipc/test_i027/test_entry_i027.c
    ${WT_CONF_U}/ff/ipc/test_i027/test_i027.c
    ${WT_CONF_U}/ff/ipc/test_i028/test_entry_i028.c
    ${WT_CONF_U}/ff/ipc/test_i028/test_i028.c
    ${WT_CONF_U}/ff/ipc/test_i029/test_entry_i029.c
    ${WT_CONF_U}/ff/ipc/test_i029/test_i029.c
    ${WT_CONF_U}/ff/ipc/test_i030/test_entry_i030.c
    ${WT_CONF_U}/ff/ipc/test_i030/test_i030.c
    ${WT_CONF_U}/ff/ipc/test_i031/test_entry_i031.c
    ${WT_CONF_U}/ff/ipc/test_i031/test_i031.c
    ${WT_CONF_U}/ff/ipc/test_i032/test_entry_i032.c
    ${WT_CONF_U}/ff/ipc/test_i032/test_i032.c
    ${WT_CONF_U}/ff/ipc/test_i033/test_entry_i033.c
    ${WT_CONF_U}/ff/ipc/test_i033/test_i033.c
    ${WT_CONF_U}/ff/ipc/test_i034/test_entry_i034.c
    ${WT_CONF_U}/ff/ipc/test_i034/test_i034.c
    ${WT_CONF_U}/ff/ipc/test_i035/test_entry_i035.c
    ${WT_CONF_U}/ff/ipc/test_i035/test_i035.c
    ${WT_CONF_U}/ff/ipc/test_i036/test_entry_i036.c
    ${WT_CONF_U}/ff/ipc/test_i036/test_i036.c
    ${WT_CONF_U}/ff/ipc/test_i037/test_entry_i037.c
    ${WT_CONF_U}/ff/ipc/test_i037/test_i037.c
    ${WT_CONF_U}/ff/ipc/test_i038/test_entry_i038.c
    ${WT_CONF_U}/ff/ipc/test_i038/test_i038.c
    ${WT_CONF_U}/ff/ipc/test_i039/test_entry_i039.c
    ${WT_CONF_U}/ff/ipc/test_i039/test_i039.c
    ${WT_CONF_U}/ff/ipc/test_i040/test_entry_i040.c
    ${WT_CONF_U}/ff/ipc/test_i040/test_i040.c
    ${WT_CONF_U}/ff/ipc/test_i041/test_entry_i041.c
    ${WT_CONF_U}/ff/ipc/test_i041/test_i041.c
    ${WT_CONF_U}/ff/ipc/test_i042/test_entry_i042.c
    ${WT_CONF_U}/ff/ipc/test_i042/test_i042.c
    ${WT_CONF_U}/ff/ipc/test_i043/test_entry_i043.c
    ${WT_CONF_U}/ff/ipc/test_i043/test_i043.c
    ${WT_CONF_U}/ff/ipc/test_i044/test_entry_i044.c
    ${WT_CONF_U}/ff/ipc/test_i044/test_i044.c
    ${WT_CONF_U}/ff/ipc/test_i045/test_entry_i045.c
    ${WT_CONF_U}/ff/ipc/test_i045/test_i045.c
    ${WT_CONF_U}/ff/ipc/test_i046/test_entry_i046.c
    ${WT_CONF_U}/ff/ipc/test_i046/test_i046.c
    ${WT_CONF_U}/ff/ipc/test_i047/test_entry_i047.c
    ${WT_CONF_U}/ff/ipc/test_i047/test_i047.c
    ${WT_CONF_U}/ff/ipc/test_i048/test_entry_i048.c
    ${WT_CONF_U}/ff/ipc/test_i048/test_i048.c
    ${WT_CONF_U}/ff/ipc/test_i049/test_entry_i049.c
    ${WT_CONF_U}/ff/ipc/test_i049/test_i049.c
    ${WT_CONF_U}/ff/ipc/test_i050/test_entry_i050.c
    ${WT_CONF_U}/ff/ipc/test_i050/test_i050.c
    ${WT_CONF_U}/ff/ipc/test_i051/test_entry_i051.c
    ${WT_CONF_U}/ff/ipc/test_i051/test_i051.c
    ${WT_CONF_U}/ff/ipc/test_i052/test_entry_i052.c
    ${WT_CONF_U}/ff/ipc/test_i052/test_i052.c
    ${WT_CONF_U}/ff/ipc/test_i053/test_entry_i053.c
    ${WT_CONF_U}/ff/ipc/test_i053/test_i053.c
    ${WT_CONF_U}/ff/ipc/test_i054/test_entry_i054.c
    ${WT_CONF_U}/ff/ipc/test_i054/test_i054.c
    ${WT_CONF_U}/ff/ipc/test_i055/test_entry_i055.c
    ${WT_CONF_U}/ff/ipc/test_i055/test_i055.c
    ${WT_CONF_U}/ff/ipc/test_i057/test_entry_i057.c
    ${WT_CONF_U}/ff/ipc/test_i057/test_i057.c
    ${WT_CONF_U}/ff/ipc/test_i058/test_entry_i058.c
    ${WT_CONF_U}/ff/ipc/test_i058/test_i058.c
    ${WT_CONF_U}/ff/ipc/test_i063/test_entry_i063.c
    ${WT_CONF_U}/ff/ipc/test_i063/test_i063.c
    ${WT_CONF_U}/ff/ipc/test_i064/test_entry_i064.c
    ${WT_CONF_U}/ff/ipc/test_i064/test_i064.c
    ${WT_CONF_U}/ff/ipc/test_i065/test_entry_i065.c
    ${WT_CONF_U}/ff/ipc/test_i065/test_i065.c
    ${WT_CONF_U}/ff/ipc/test_i066/test_entry_i066.c
    ${WT_CONF_U}/ff/ipc/test_i066/test_i066.c
    ${WT_CONF_U}/ff/ipc/test_i071/test_entry_i071.c
    ${WT_CONF_U}/ff/ipc/test_i071/test_i071.c
    ${WT_CONF_U}/ff/ipc/test_i056/test_entry_i056.c
    ${WT_CONF_U}/ff/ipc/test_i056/test_i056.c
    ${WT_CONF_U}/ff/ipc/test_i059/test_entry_i059.c
    ${WT_CONF_U}/ff/ipc/test_i059/test_i059.c
    ${WT_CONF_U}/ff/ipc/test_i060/test_entry_i060.c
    ${WT_CONF_U}/ff/ipc/test_i060/test_i060.c
    ${WT_CONF_U}/ff/ipc/test_i061/test_entry_i061.c
    ${WT_CONF_U}/ff/ipc/test_i061/test_i061.c
    ${WT_CONF_U}/ff/ipc/test_i062/test_entry_i062.c
    ${WT_CONF_U}/ff/ipc/test_i062/test_i062.c
    ${WT_CONF_U}/ff/ipc/test_i068/test_entry_i068.c
    ${WT_CONF_U}/ff/ipc/test_i068/test_i068.c
    ${WT_CONF_U}/ff/ipc/test_i069/test_entry_i069.c
    ${WT_CONF_U}/ff/ipc/test_i069/test_i069.c
    ${WT_CONF_U}/ff/ipc/test_i070/test_entry_i070.c
    ${WT_CONF_U}/ff/ipc/test_i070/test_i070.c
    ${WT_CONF_U}/ff/ipc/test_i072/test_entry_i072.c
    ${WT_CONF_U}/ff/ipc/test_i072/test_i072.c
    ${WT_CONF_U}/ff/ipc/test_i073/test_entry_i073.c
    ${WT_CONF_U}/ff/ipc/test_i073/test_i073.c
    ${WT_CONF_U}/ff/ipc/test_i074/test_entry_i074.c
    ${WT_CONF_U}/ff/ipc/test_i074/test_i074.c
    ${WT_CONF_U}/ff/ipc/test_i075/test_entry_i075.c
    ${WT_CONF_U}/ff/ipc/test_i075/test_i075.c
    ${WT_CONF_U}/ff/ipc/test_i076/test_entry_i076.c
    ${WT_CONF_U}/ff/ipc/test_i076/test_i076.c
    ${WT_CONF_U}/ff/ipc/test_i077/test_entry_i077.c
    ${WT_CONF_U}/ff/ipc/test_i077/test_i077.c
    ${WT_CONF_U}/ff/ipc/test_i078/test_entry_i078.c
    ${WT_CONF_U}/ff/ipc/test_i078/test_i078.c
    ${WT_CONF_U}/ff/ipc/test_i079/test_entry_i079.c
    ${WT_CONF_U}/ff/ipc/test_i079/test_i079.c
    ${WT_CONF_U}/ff/ipc/test_i080/test_entry_i080.c
    ${WT_CONF_U}/ff/ipc/test_i080/test_i080.c
    ${WT_CONF_U}/ff/ipc/test_i081/test_entry_i081.c
    ${WT_CONF_U}/ff/ipc/test_i081/test_i081.c
    ${WT_CONF_U}/ff/ipc/test_i082/test_entry_i082.c
    ${WT_CONF_U}/ff/ipc/test_i082/test_i082.c
    ${WT_CONF_U}/ff/ipc/test_i083/test_entry_i083.c
    ${WT_CONF_U}/ff/ipc/test_i083/test_i083.c
    ${WT_CONF_U}/ff/ipc/test_i084/test_entry_i084.c
    ${WT_CONF_U}/ff/ipc/test_i084/test_i084.c
    ${WT_CONF_U}/ff/ipc/test_i085/test_entry_i085.c
    ${WT_CONF_U}/ff/ipc/test_i085/test_i085.c
    ${WT_CONF_U}/ff/ipc/test_i086/test_entry_i086.c
    ${WT_CONF_U}/ff/ipc/test_i086/test_i086.c
    ${WT_CONF_U}/ff/ipc/test_i087/test_entry_i087.c
    ${WT_CONF_U}/ff/ipc/test_i087/test_i087.c
    ${WT_CONF_U}/ff/ipc/test_i089/test_entry_i089.c
    ${WT_CONF_U}/ff/ipc/test_i089/test_i089.c
    ${WT_CONF_U}/ff/ipc/test_i090/test_entry_i090.c
    ${WT_CONF_U}/ff/ipc/test_i090/test_i090.c
    ${WT_CONF_U}/ff/ipc/test_i088/test_entry_i088.c
    ${WT_CONF_U}/ff/ipc/test_i088/test_i088.c
  )
  target_include_directories(app PRIVATE
    ${WT_REPO_ROOT}/include
    ${WT_CONF_GEN}/ns
    ${WT_CONF_GEN}
    ${WT_CONF_U}/val/common
    ${WT_CONF_U}/val/nspe
    ${WT_CONF_U}/val/spe
    ${WT_CONF_U}/platform/targets/common/nspe
    ${WT_REPO_ROOT}/port/stm32h563/conformance
    ${WT_CONF_U}/ff/ipc/test_i001
    ${WT_CONF_U}/ff/ipc/test_i002
    ${WT_CONF_U}/ff/ipc/test_i003
    ${WT_CONF_U}/ff/ipc/test_i004
    ${WT_CONF_U}/ff/ipc/test_i005
    ${WT_CONF_U}/ff/ipc/test_i006
    ${WT_CONF_U}/ff/ipc/test_i007
    ${WT_CONF_U}/ff/ipc/test_i008
    ${WT_CONF_U}/ff/ipc/test_i009
    ${WT_CONF_U}/ff/ipc/test_i010
    ${WT_CONF_U}/ff/ipc/test_i011
    ${WT_CONF_U}/ff/ipc/test_i012
    ${WT_CONF_U}/ff/ipc/test_i013
    ${WT_CONF_U}/ff/ipc/test_i014
    ${WT_CONF_U}/ff/ipc/test_i015
    ${WT_CONF_U}/ff/ipc/test_i016
    ${WT_CONF_U}/ff/ipc/test_i017
    ${WT_CONF_U}/ff/ipc/test_i018
    ${WT_CONF_U}/ff/ipc/test_i019
    ${WT_CONF_U}/ff/ipc/test_i020
    ${WT_CONF_U}/ff/ipc/test_i021
    ${WT_CONF_U}/ff/ipc/test_i022
    ${WT_CONF_U}/ff/ipc/test_i023
    ${WT_CONF_U}/ff/ipc/test_i024
    ${WT_CONF_U}/ff/ipc/test_i025
    ${WT_CONF_U}/ff/ipc/test_i026
    ${WT_CONF_U}/ff/ipc/test_i027
    ${WT_CONF_U}/ff/ipc/test_i028
    ${WT_CONF_U}/ff/ipc/test_i029
    ${WT_CONF_U}/ff/ipc/test_i030
    ${WT_CONF_U}/ff/ipc/test_i031
    ${WT_CONF_U}/ff/ipc/test_i032
    ${WT_CONF_U}/ff/ipc/test_i033
    ${WT_CONF_U}/ff/ipc/test_i034
    ${WT_CONF_U}/ff/ipc/test_i035
    ${WT_CONF_U}/ff/ipc/test_i036
    ${WT_CONF_U}/ff/ipc/test_i037
    ${WT_CONF_U}/ff/ipc/test_i038
    ${WT_CONF_U}/ff/ipc/test_i039
    ${WT_CONF_U}/ff/ipc/test_i040
    ${WT_CONF_U}/ff/ipc/test_i041
    ${WT_CONF_U}/ff/ipc/test_i042
    ${WT_CONF_U}/ff/ipc/test_i043
    ${WT_CONF_U}/ff/ipc/test_i044
    ${WT_CONF_U}/ff/ipc/test_i045
    ${WT_CONF_U}/ff/ipc/test_i046
    ${WT_CONF_U}/ff/ipc/test_i047
    ${WT_CONF_U}/ff/ipc/test_i048
    ${WT_CONF_U}/ff/ipc/test_i049
    ${WT_CONF_U}/ff/ipc/test_i050
    ${WT_CONF_U}/ff/ipc/test_i051
    ${WT_CONF_U}/ff/ipc/test_i052
    ${WT_CONF_U}/ff/ipc/test_i053
    ${WT_CONF_U}/ff/ipc/test_i054
    ${WT_CONF_U}/ff/ipc/test_i055
    ${WT_CONF_U}/ff/ipc/test_i057
    ${WT_CONF_U}/ff/ipc/test_i058
    ${WT_CONF_U}/ff/ipc/test_i063
    ${WT_CONF_U}/ff/ipc/test_i064
    ${WT_CONF_U}/ff/ipc/test_i065
    ${WT_CONF_U}/ff/ipc/test_i066
    ${WT_CONF_U}/ff/ipc/test_i071
    ${WT_CONF_U}/ff/ipc/test_i056
    ${WT_CONF_U}/ff/ipc/test_i059
    ${WT_CONF_U}/ff/ipc/test_i060
    ${WT_CONF_U}/ff/ipc/test_i061
    ${WT_CONF_U}/ff/ipc/test_i062
    ${WT_CONF_U}/ff/ipc/test_i068
    ${WT_CONF_U}/ff/ipc/test_i069
    ${WT_CONF_U}/ff/ipc/test_i070
    ${WT_CONF_U}/ff/ipc/test_i072
    ${WT_CONF_U}/ff/ipc/test_i073
    ${WT_CONF_U}/ff/ipc/test_i074
    ${WT_CONF_U}/ff/ipc/test_i075
    ${WT_CONF_U}/ff/ipc/test_i076
    ${WT_CONF_U}/ff/ipc/test_i077
    ${WT_CONF_U}/ff/ipc/test_i078
    ${WT_CONF_U}/ff/ipc/test_i079
    ${WT_CONF_U}/ff/ipc/test_i080
    ${WT_CONF_U}/ff/ipc/test_i081
    ${WT_CONF_U}/ff/ipc/test_i082
    ${WT_CONF_U}/ff/ipc/test_i083
    ${WT_CONF_U}/ff/ipc/test_i084
    ${WT_CONF_U}/ff/ipc/test_i085
    ${WT_CONF_U}/ff/ipc/test_i086
    ${WT_CONF_U}/ff/ipc/test_i087
    ${WT_CONF_U}/ff/ipc/test_i089
    ${WT_CONF_U}/ff/ipc/test_i090
    ${WT_CONF_U}/ff/ipc/test_i088
  )
  target_compile_definitions(app PRIVATE
    WT_RUN_CONFORMANCE VAL_NSPE_BUILD NONSECURE_TEST_BUILD IPC VERBOSITY=3)
  set_source_files_properties(
    ${WT_CONF_U}/val/common/val_log.c
    ${WT_CONF_U}/val/nspe/val_entry.c
    ${WT_CONF_U}/val/nspe/val_dispatcher.c
    ${WT_CONF_U}/val/nspe/val_framework.c
    ${WT_CONF_U}/val/nspe/val_interfaces.c
    ${WT_CONF_U}/val/nspe/val_peripherals.c
    ${WT_CONF_U}/val/nspe/val_platform.c
    ${WT_CONF_U}/val/nspe/val_crypto.c
    ${WT_CONF_U}/val/nspe/val_storage.c
    ${WT_CONF_U}/val/nspe/val_attestation.c
    ${WT_CONF_U}/platform/targets/common/nspe/pal_weak.c
    ${WT_CONF_U}/ff/ipc/test_i001/test_entry_i001.c
    ${WT_CONF_U}/ff/ipc/test_i001/test_i001.c
    ${WT_CONF_U}/ff/ipc/test_i002/test_entry_i002.c
    ${WT_CONF_U}/ff/ipc/test_i002/test_i002.c
    ${WT_CONF_U}/ff/ipc/test_i003/test_entry_i003.c
    ${WT_CONF_U}/ff/ipc/test_i003/test_i003.c
    ${WT_CONF_U}/ff/ipc/test_i004/test_entry_i004.c
    ${WT_CONF_U}/ff/ipc/test_i004/test_i004.c
    ${WT_CONF_U}/ff/ipc/test_i005/test_entry_i005.c
    ${WT_CONF_U}/ff/ipc/test_i005/test_i005.c
    ${WT_CONF_U}/ff/ipc/test_i006/test_entry_i006.c
    ${WT_CONF_U}/ff/ipc/test_i006/test_i006.c
    ${WT_CONF_U}/ff/ipc/test_i007/test_entry_i007.c
    ${WT_CONF_U}/ff/ipc/test_i007/test_i007.c
    ${WT_CONF_U}/ff/ipc/test_i008/test_entry_i008.c
    ${WT_CONF_U}/ff/ipc/test_i008/test_i008.c
    ${WT_CONF_U}/ff/ipc/test_i009/test_entry_i009.c
    ${WT_CONF_U}/ff/ipc/test_i009/test_i009.c
    ${WT_CONF_U}/ff/ipc/test_i010/test_entry_i010.c
    ${WT_CONF_U}/ff/ipc/test_i010/test_i010.c
    ${WT_CONF_U}/ff/ipc/test_i011/test_entry_i011.c
    ${WT_CONF_U}/ff/ipc/test_i011/test_i011.c
    ${WT_CONF_U}/ff/ipc/test_i012/test_entry_i012.c
    ${WT_CONF_U}/ff/ipc/test_i012/test_i012.c
    ${WT_CONF_U}/ff/ipc/test_i013/test_entry_i013.c
    ${WT_CONF_U}/ff/ipc/test_i013/test_i013.c
    ${WT_CONF_U}/ff/ipc/test_i014/test_entry_i014.c
    ${WT_CONF_U}/ff/ipc/test_i014/test_i014.c
    ${WT_CONF_U}/ff/ipc/test_i015/test_entry_i015.c
    ${WT_CONF_U}/ff/ipc/test_i015/test_i015.c
    ${WT_CONF_U}/ff/ipc/test_i016/test_entry_i016.c
    ${WT_CONF_U}/ff/ipc/test_i016/test_i016.c
    ${WT_CONF_U}/ff/ipc/test_i017/test_entry_i017.c
    ${WT_CONF_U}/ff/ipc/test_i017/test_i017.c
    ${WT_CONF_U}/ff/ipc/test_i018/test_entry_i018.c
    ${WT_CONF_U}/ff/ipc/test_i018/test_i018.c
    ${WT_CONF_U}/ff/ipc/test_i019/test_entry_i019.c
    ${WT_CONF_U}/ff/ipc/test_i019/test_i019.c
    ${WT_CONF_U}/ff/ipc/test_i020/test_entry_i020.c
    ${WT_CONF_U}/ff/ipc/test_i020/test_i020.c
    ${WT_CONF_U}/ff/ipc/test_i021/test_entry_i021.c
    ${WT_CONF_U}/ff/ipc/test_i021/test_i021.c
    ${WT_CONF_U}/ff/ipc/test_i022/test_entry_i022.c
    ${WT_CONF_U}/ff/ipc/test_i022/test_i022.c
    ${WT_CONF_U}/ff/ipc/test_i023/test_entry_i023.c
    ${WT_CONF_U}/ff/ipc/test_i023/test_i023.c
    ${WT_CONF_U}/ff/ipc/test_i024/test_entry_i024.c
    ${WT_CONF_U}/ff/ipc/test_i024/test_i024.c
    ${WT_CONF_U}/ff/ipc/test_i025/test_entry_i025.c
    ${WT_CONF_U}/ff/ipc/test_i025/test_i025.c
    ${WT_CONF_U}/ff/ipc/test_i026/test_entry_i026.c
    ${WT_CONF_U}/ff/ipc/test_i026/test_i026.c
    ${WT_CONF_U}/ff/ipc/test_i027/test_entry_i027.c
    ${WT_CONF_U}/ff/ipc/test_i027/test_i027.c
    ${WT_CONF_U}/ff/ipc/test_i028/test_entry_i028.c
    ${WT_CONF_U}/ff/ipc/test_i028/test_i028.c
    ${WT_CONF_U}/ff/ipc/test_i029/test_entry_i029.c
    ${WT_CONF_U}/ff/ipc/test_i029/test_i029.c
    ${WT_CONF_U}/ff/ipc/test_i030/test_entry_i030.c
    ${WT_CONF_U}/ff/ipc/test_i030/test_i030.c
    ${WT_CONF_U}/ff/ipc/test_i031/test_entry_i031.c
    ${WT_CONF_U}/ff/ipc/test_i031/test_i031.c
    ${WT_CONF_U}/ff/ipc/test_i032/test_entry_i032.c
    ${WT_CONF_U}/ff/ipc/test_i032/test_i032.c
    ${WT_CONF_U}/ff/ipc/test_i033/test_entry_i033.c
    ${WT_CONF_U}/ff/ipc/test_i033/test_i033.c
    ${WT_CONF_U}/ff/ipc/test_i034/test_entry_i034.c
    ${WT_CONF_U}/ff/ipc/test_i034/test_i034.c
    ${WT_CONF_U}/ff/ipc/test_i035/test_entry_i035.c
    ${WT_CONF_U}/ff/ipc/test_i035/test_i035.c
    ${WT_CONF_U}/ff/ipc/test_i036/test_entry_i036.c
    ${WT_CONF_U}/ff/ipc/test_i036/test_i036.c
    ${WT_CONF_U}/ff/ipc/test_i037/test_entry_i037.c
    ${WT_CONF_U}/ff/ipc/test_i037/test_i037.c
    ${WT_CONF_U}/ff/ipc/test_i038/test_entry_i038.c
    ${WT_CONF_U}/ff/ipc/test_i038/test_i038.c
    ${WT_CONF_U}/ff/ipc/test_i039/test_entry_i039.c
    ${WT_CONF_U}/ff/ipc/test_i039/test_i039.c
    ${WT_CONF_U}/ff/ipc/test_i040/test_entry_i040.c
    ${WT_CONF_U}/ff/ipc/test_i040/test_i040.c
    ${WT_CONF_U}/ff/ipc/test_i041/test_entry_i041.c
    ${WT_CONF_U}/ff/ipc/test_i041/test_i041.c
    ${WT_CONF_U}/ff/ipc/test_i042/test_entry_i042.c
    ${WT_CONF_U}/ff/ipc/test_i042/test_i042.c
    ${WT_CONF_U}/ff/ipc/test_i043/test_entry_i043.c
    ${WT_CONF_U}/ff/ipc/test_i043/test_i043.c
    ${WT_CONF_U}/ff/ipc/test_i044/test_entry_i044.c
    ${WT_CONF_U}/ff/ipc/test_i044/test_i044.c
    ${WT_CONF_U}/ff/ipc/test_i045/test_entry_i045.c
    ${WT_CONF_U}/ff/ipc/test_i045/test_i045.c
    ${WT_CONF_U}/ff/ipc/test_i046/test_entry_i046.c
    ${WT_CONF_U}/ff/ipc/test_i046/test_i046.c
    ${WT_CONF_U}/ff/ipc/test_i047/test_entry_i047.c
    ${WT_CONF_U}/ff/ipc/test_i047/test_i047.c
    ${WT_CONF_U}/ff/ipc/test_i048/test_entry_i048.c
    ${WT_CONF_U}/ff/ipc/test_i048/test_i048.c
    ${WT_CONF_U}/ff/ipc/test_i049/test_entry_i049.c
    ${WT_CONF_U}/ff/ipc/test_i049/test_i049.c
    ${WT_CONF_U}/ff/ipc/test_i050/test_entry_i050.c
    ${WT_CONF_U}/ff/ipc/test_i050/test_i050.c
    ${WT_CONF_U}/ff/ipc/test_i051/test_entry_i051.c
    ${WT_CONF_U}/ff/ipc/test_i051/test_i051.c
    ${WT_CONF_U}/ff/ipc/test_i052/test_entry_i052.c
    ${WT_CONF_U}/ff/ipc/test_i052/test_i052.c
    ${WT_CONF_U}/ff/ipc/test_i053/test_entry_i053.c
    ${WT_CONF_U}/ff/ipc/test_i053/test_i053.c
    ${WT_CONF_U}/ff/ipc/test_i054/test_entry_i054.c
    ${WT_CONF_U}/ff/ipc/test_i054/test_i054.c
    ${WT_CONF_U}/ff/ipc/test_i055/test_entry_i055.c
    ${WT_CONF_U}/ff/ipc/test_i055/test_i055.c
    ${WT_CONF_U}/ff/ipc/test_i057/test_entry_i057.c
    ${WT_CONF_U}/ff/ipc/test_i057/test_i057.c
    ${WT_CONF_U}/ff/ipc/test_i058/test_entry_i058.c
    ${WT_CONF_U}/ff/ipc/test_i058/test_i058.c
    ${WT_CONF_U}/ff/ipc/test_i063/test_entry_i063.c
    ${WT_CONF_U}/ff/ipc/test_i063/test_i063.c
    ${WT_CONF_U}/ff/ipc/test_i064/test_entry_i064.c
    ${WT_CONF_U}/ff/ipc/test_i064/test_i064.c
    ${WT_CONF_U}/ff/ipc/test_i065/test_entry_i065.c
    ${WT_CONF_U}/ff/ipc/test_i065/test_i065.c
    ${WT_CONF_U}/ff/ipc/test_i066/test_entry_i066.c
    ${WT_CONF_U}/ff/ipc/test_i066/test_i066.c
    ${WT_CONF_U}/ff/ipc/test_i071/test_entry_i071.c
    ${WT_CONF_U}/ff/ipc/test_i071/test_i071.c
    ${WT_CONF_U}/ff/ipc/test_i056/test_entry_i056.c
    ${WT_CONF_U}/ff/ipc/test_i056/test_i056.c
    ${WT_CONF_U}/ff/ipc/test_i059/test_entry_i059.c
    ${WT_CONF_U}/ff/ipc/test_i059/test_i059.c
    ${WT_CONF_U}/ff/ipc/test_i060/test_entry_i060.c
    ${WT_CONF_U}/ff/ipc/test_i060/test_i060.c
    ${WT_CONF_U}/ff/ipc/test_i061/test_entry_i061.c
    ${WT_CONF_U}/ff/ipc/test_i061/test_i061.c
    ${WT_CONF_U}/ff/ipc/test_i062/test_entry_i062.c
    ${WT_CONF_U}/ff/ipc/test_i062/test_i062.c
    ${WT_CONF_U}/ff/ipc/test_i068/test_entry_i068.c
    ${WT_CONF_U}/ff/ipc/test_i068/test_i068.c
    ${WT_CONF_U}/ff/ipc/test_i069/test_entry_i069.c
    ${WT_CONF_U}/ff/ipc/test_i069/test_i069.c
    ${WT_CONF_U}/ff/ipc/test_i070/test_entry_i070.c
    ${WT_CONF_U}/ff/ipc/test_i070/test_i070.c
    ${WT_CONF_U}/ff/ipc/test_i072/test_entry_i072.c
    ${WT_CONF_U}/ff/ipc/test_i072/test_i072.c
    ${WT_CONF_U}/ff/ipc/test_i073/test_entry_i073.c
    ${WT_CONF_U}/ff/ipc/test_i073/test_i073.c
    ${WT_CONF_U}/ff/ipc/test_i074/test_entry_i074.c
    ${WT_CONF_U}/ff/ipc/test_i074/test_i074.c
    ${WT_CONF_U}/ff/ipc/test_i075/test_entry_i075.c
    ${WT_CONF_U}/ff/ipc/test_i075/test_i075.c
    ${WT_CONF_U}/ff/ipc/test_i076/test_entry_i076.c
    ${WT_CONF_U}/ff/ipc/test_i076/test_i076.c
    ${WT_CONF_U}/ff/ipc/test_i077/test_entry_i077.c
    ${WT_CONF_U}/ff/ipc/test_i077/test_i077.c
    ${WT_CONF_U}/ff/ipc/test_i078/test_entry_i078.c
    ${WT_CONF_U}/ff/ipc/test_i078/test_i078.c
    ${WT_CONF_U}/ff/ipc/test_i079/test_entry_i079.c
    ${WT_CONF_U}/ff/ipc/test_i079/test_i079.c
    ${WT_CONF_U}/ff/ipc/test_i080/test_entry_i080.c
    ${WT_CONF_U}/ff/ipc/test_i080/test_i080.c
    ${WT_CONF_U}/ff/ipc/test_i081/test_entry_i081.c
    ${WT_CONF_U}/ff/ipc/test_i081/test_i081.c
    ${WT_CONF_U}/ff/ipc/test_i082/test_entry_i082.c
    ${WT_CONF_U}/ff/ipc/test_i082/test_i082.c
    ${WT_CONF_U}/ff/ipc/test_i083/test_entry_i083.c
    ${WT_CONF_U}/ff/ipc/test_i083/test_i083.c
    ${WT_CONF_U}/ff/ipc/test_i084/test_entry_i084.c
    ${WT_CONF_U}/ff/ipc/test_i084/test_i084.c
    ${WT_CONF_U}/ff/ipc/test_i085/test_entry_i085.c
    ${WT_CONF_U}/ff/ipc/test_i085/test_i085.c
    ${WT_CONF_U}/ff/ipc/test_i086/test_entry_i086.c
    ${WT_CONF_U}/ff/ipc/test_i086/test_i086.c
    ${WT_CONF_U}/ff/ipc/test_i087/test_entry_i087.c
    ${WT_CONF_U}/ff/ipc/test_i087/test_i087.c
    ${WT_CONF_U}/ff/ipc/test_i089/test_entry_i089.c
    ${WT_CONF_U}/ff/ipc/test_i089/test_i089.c
    ${WT_CONF_U}/ff/ipc/test_i090/test_entry_i090.c
    ${WT_CONF_U}/ff/ipc/test_i090/test_i090.c
    ${WT_CONF_U}/ff/ipc/test_i088/test_entry_i088.c
    ${WT_CONF_U}/ff/ipc/test_i088/test_i088.c
    PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter"
  )
  elseif(WT_CONF_SUITE STREQUAL "storage")
    # dev_apis ITS/PS: test bodies run entirely Non-secure and reach
    # SERVICE_ITS / SERVICE_PS through the OS-neutral src/client PSA storage
    # client.
    set(WT_STORAGE_SRCS
      src/conformance_pal.c
      ${WT_REPO_ROOT}/src/client/psa_storage_client.c
      ${WT_CONF_U}/val/common/val_log.c
      ${WT_CONF_U}/platform/targets/common/nspe/pal_weak.c
      ${WT_CONF_U}/val/nspe/val_entry.c
      ${WT_CONF_U}/val/nspe/val_dispatcher.c
      ${WT_CONF_U}/val/nspe/val_framework.c
      ${WT_CONF_U}/val/nspe/val_interfaces.c
      ${WT_CONF_U}/val/nspe/val_peripherals.c
      ${WT_CONF_U}/val/nspe/val_platform.c
      ${WT_CONF_U}/val/nspe/val_crypto.c
      ${WT_CONF_U}/val/nspe/val_storage.c
      ${WT_CONF_U}/val/nspe/val_attestation.c
      ${WT_CONF_U}/dev_apis/storage/common/test_storage_common.c
    )
    set(WT_STORAGE_INCS
      ${WT_REPO_ROOT}/include
      ${WT_CONF_GEN}/storage/ns
      ${WT_CONF_GEN}
      ${WT_CONF_U}/val/common
      ${WT_CONF_U}/val/nspe
      ${WT_CONF_U}/val/spe
      ${WT_CONF_U}/platform/targets/common/nspe
      ${WT_REPO_ROOT}/port/stm32h563/conformance
      ${WT_CONF_U}/dev_apis/storage/common
    )
    foreach(n RANGE 1 17)
      if(n LESS 10)
        set(sid s00${n})
      else()
        set(sid s0${n})
      endif()
      list(APPEND WT_STORAGE_SRCS
        ${WT_CONF_U}/dev_apis/storage/test_${sid}/test_entry_${sid}.c
        ${WT_CONF_U}/dev_apis/storage/test_${sid}/test_${sid}.c)
      list(APPEND WT_STORAGE_INCS ${WT_CONF_U}/dev_apis/storage/test_${sid})
    endforeach()
    target_sources(app PRIVATE ${WT_STORAGE_SRCS})
    target_include_directories(app PRIVATE ${WT_STORAGE_INCS})
    target_compile_definitions(app PRIVATE
      WT_RUN_CONFORMANCE VAL_NSPE_BUILD NONSECURE_TEST_BUILD STORAGE VERBOSITY=3)
    set_source_files_properties(${WT_STORAGE_SRCS} PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter")
  elseif(WT_CONF_SUITE STREQUAL "crypto")
    # dev_apis Crypto: test bodies run entirely Non-secure against wolfPSA
    # (the guest's psa_* provider); the upstream PAL compiles directly
    # against wolfPSA's psa/crypto.h.
    set(WT_CRYPTO_SRCS
      src/conformance_pal.c
      ${WT_CONF_U}/val/common/val_log.c
      ${WT_CONF_U}/platform/targets/common/nspe/pal_weak.c
      ${WT_CONF_U}/platform/targets/common/nspe/crypto/pal_crypto_intf.c
      ${WT_CONF_U}/val/nspe/val_entry.c
      ${WT_CONF_U}/val/nspe/val_dispatcher.c
      ${WT_CONF_U}/val/nspe/val_framework.c
      ${WT_CONF_U}/val/nspe/val_interfaces.c
      ${WT_CONF_U}/val/nspe/val_peripherals.c
      ${WT_CONF_U}/val/nspe/val_platform.c
      ${WT_CONF_U}/val/nspe/val_crypto.c
      ${WT_CONF_U}/val/nspe/val_storage.c
      ${WT_CONF_U}/val/nspe/val_attestation.c
      ${WT_CONF_U}/dev_apis/crypto/common/test_crypto_common.c
    )
    set(WT_CRYPTO_INCS
      ${WT_REPO_ROOT}/include
      ${WT_CONF_GEN}/crypto/ns
      ${WT_CONF_GEN}
      ${WT_CONF_U}/val/common
      ${WT_CONF_U}/val/nspe
      ${WT_CONF_U}/val/spe
      ${WT_CONF_U}/platform/targets/common/nspe
      ${WT_CONF_U}/platform/targets/common/nspe/crypto
      ${WT_REPO_ROOT}/port/stm32h563/conformance
      ${WT_CONF_U}/dev_apis/crypto/common
    )
    foreach(n RANGE 1 80)
      # c064/c065 (hash suspend/resume) are skipped by the upstream db and c047
      # (CMAC compiled out) by the crypto sched db; their test_entry symbols are
      # only declared for scheduled tests.
      if(n EQUAL 47 OR n EQUAL 64 OR n EQUAL 65)
        continue()
      endif()
      if(n LESS 10)
        set(cid c00${n})
      else()
        set(cid c0${n})
      endif()
      list(APPEND WT_CRYPTO_SRCS
        ${WT_CONF_U}/dev_apis/crypto/test_${cid}/test_entry_${cid}.c
        ${WT_CONF_U}/dev_apis/crypto/test_${cid}/test_${cid}.c)
      list(APPEND WT_CRYPTO_INCS ${WT_CONF_U}/dev_apis/crypto/test_${cid})
    endforeach()
    target_sources(app PRIVATE ${WT_CRYPTO_SRCS})
    target_include_directories(app PRIVATE ${WT_CRYPTO_INCS})
    target_compile_definitions(app PRIVATE
      WT_RUN_CONFORMANCE VAL_NSPE_BUILD NONSECURE_TEST_BUILD CRYPTO VERBOSITY=3)
    set_source_files_properties(${WT_CRYPTO_SRCS} PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter")
  elseif(WT_CONF_SUITE STREQUAL "attestation")
    # dev_apis Initial Attestation (test_a001): the test body runs entirely
    # Non-secure. get_token reaches SERVICE_ATTEST through the wolftrust-tee
    # client; val's own COSE_Sign1 verify runs on the upstream attestation PAL
    # against wolfPSA, with the runtime IAK public key bridged in by
    # conformance_pal.c. The CBOR backend defaults to the wolfCOSE qcbor shim;
    # WT_ATTEST_CBOR=qcbor swaps in the reference QCBOR sources (test-only,
    # fetched to build/upstream/qcbor) to prove the token parses under both.
    set(WT_ATTEST_SRCS
      src/conformance_pal.c
      ${WT_CONF_U}/val/common/val_log.c
      ${WT_CONF_U}/platform/targets/common/nspe/pal_weak.c
      ${WT_CONF_U}/platform/targets/common/nspe/initial_attestation/pal_attestation_intf.c
      ${WT_CONF_U}/platform/targets/common/nspe/initial_attestation/pal_attestation_crypto.c
      ${WT_CONF_U}/val/nspe/val_entry.c
      ${WT_CONF_U}/val/nspe/val_dispatcher.c
      ${WT_CONF_U}/val/nspe/val_framework.c
      ${WT_CONF_U}/val/nspe/val_interfaces.c
      ${WT_CONF_U}/val/nspe/val_peripherals.c
      ${WT_CONF_U}/val/nspe/val_platform.c
      ${WT_CONF_U}/val/nspe/val_crypto.c
      ${WT_CONF_U}/val/nspe/val_storage.c
      ${WT_CONF_U}/val/nspe/val_attestation.c
      ${WT_CONF_U}/dev_apis/initial_attestation/test_a001/test_entry_a001.c
      ${WT_CONF_U}/dev_apis/initial_attestation/test_a001/test_a001.c
    )
    set(WT_ATTEST_INCS
      ${WT_REPO_ROOT}/include
      ${WT_CONF_GEN}/initial_attestation/ns
      ${WT_CONF_GEN}
      ${WT_CONF_U}/val/common
      ${WT_CONF_U}/val/nspe
      ${WT_CONF_U}/val/spe
      ${WT_CONF_U}/platform/targets/common/nspe
      ${WT_CONF_U}/platform/targets/common/nspe/initial_attestation
      ${WT_REPO_ROOT}/port/stm32h563/conformance
      ${WT_CONF_U}/dev_apis/initial_attestation/test_a001
    )
    if(WT_ATTEST_CBOR STREQUAL "qcbor")
      set(WT_QCBOR_DIR ${WT_REPO_ROOT}/build/upstream/qcbor)
      list(APPEND WT_ATTEST_SRCS
        ${WT_QCBOR_DIR}/src/UsefulBuf.c
        ${WT_QCBOR_DIR}/src/qcbor_encode.c
        ${WT_QCBOR_DIR}/src/qcbor_decode.c
        ${WT_QCBOR_DIR}/src/ieee754.c)
      list(APPEND WT_ATTEST_INCS
        ${WT_QCBOR_DIR}/inc
        ${WT_QCBOR_DIR}/inc/qcbor)
    else()
      list(APPEND WT_ATTEST_SRCS
        ${WT_REPO_ROOT}/tests/conformance/qcbor-shim/qcbor_shim.c)
      list(APPEND WT_ATTEST_INCS
        ${WT_REPO_ROOT}/tests/conformance/qcbor-shim)
    endif()
    target_sources(app PRIVATE ${WT_ATTEST_SRCS})
    target_include_directories(app PRIVATE ${WT_ATTEST_INCS})
    target_compile_definitions(app PRIVATE
      WT_RUN_CONFORMANCE VAL_NSPE_BUILD NONSECURE_TEST_BUILD
      INITIAL_ATTESTATION PSA_ATTESTATION_PROFILE_2
      PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE=640 VERBOSITY=3)
    set_source_files_properties(${WT_ATTEST_SRCS} PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter")
  endif()
endif()
