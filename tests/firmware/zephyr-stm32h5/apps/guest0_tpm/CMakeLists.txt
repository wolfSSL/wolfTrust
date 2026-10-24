cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftrust_guest0_tpm)

if(NOT DEFINED WOLFTRUST_CMSE_IMPLIB)
  message(FATAL_ERROR "WOLFTRUST_CMSE_IMPLIB must point at build/secure_cmse_implib.o")
endif()

set(WT_REPO_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
set(WT_WOLFTPM_DIR ${WT_REPO_ROOT}/lib/wolfTPM)
set(WT_TEST_DIR ${WT_REPO_ROOT}/tests/firmware/stm32h563-tpm/tpm-app)

set(WT_WOLFTPM_SOURCES
  ${WT_WOLFTPM_DIR}/src/tpm2.c
  ${WT_WOLFTPM_DIR}/src/tpm2_util.c
  ${WT_WOLFTPM_DIR}/src/tpm2_packet.c
  ${WT_WOLFTPM_DIR}/src/tpm2_wrap.c
  ${WT_WOLFTPM_DIR}/src/tpm2_asn.c
  ${WT_WOLFTPM_DIR}/src/tpm2_crypto.c
  ${WT_WOLFTPM_DIR}/src/tpm2_param_enc.c
  ${WT_WOLFTPM_DIR}/src/tpm2_cryptocb.c
)

target_sources(app PRIVATE
  src/main.c
  ${WT_TEST_DIR}/tpm_tests.c
  ${WT_REPO_ROOT}/src/client/tpm_psa_transport.c
  ${WT_WOLFTPM_SOURCES}
  ${WOLFTRUST_CMSE_IMPLIB}
)

target_include_directories(app PRIVATE
  ${WT_REPO_ROOT}/include
  ${WT_WOLFTPM_DIR}
  ${WT_TEST_DIR}
)

target_compile_definitions(app PRIVATE
  WOLFTPM_USER_SETTINGS
  WOLFTPM_ZEPHYR
  WOLFTPM_SWTPM
  WOLFTPM_SMALL_STACK
  WT_TPM_APP_NAME="tpm-zephyr"
)

if(WT_M33MU_EXPECT_BKPT)
  target_compile_definitions(app PRIVATE WT_M33MU_EXPECT_BKPT=1)
endif()

set_source_files_properties(
  ${WT_WOLFTPM_SOURCES}
  PROPERTIES COMPILE_OPTIONS
    "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter;-Wno-type-limits"
)
