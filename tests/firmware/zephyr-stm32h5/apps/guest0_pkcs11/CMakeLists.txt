cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolftrust_guest0_pkcs11)

if(NOT DEFINED WOLFTRUST_CMSE_IMPLIB)
  message(FATAL_ERROR "WOLFTRUST_CMSE_IMPLIB must point at build/secure_cmse_implib.o")
endif()

set(WT_REPO_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
include(${WT_REPO_ROOT}/tools/cmake/CryptoProfile.cmake)
set(WT_PROFILE_DIR ${CMAKE_CURRENT_BINARY_DIR}/crypto-profile)
wt_crypto_profile(${WT_REPO_ROOT} ${WT_PROFILE_DIR})
target_compile_options(app PRIVATE -include ${WT_PROFILE_DIR}/selected_profile.h)
set(WT_TEST_DIR ${WT_REPO_ROOT}/tests/firmware/stm32h563-tpm/freertos-pkcs11)

target_sources(app PRIVATE
  src/main.c
  ${WT_TEST_DIR}/pkcs11_tests.c
  ${WT_REPO_ROOT}/src/client/psa_ffm_client.c
  ${WT_REPO_ROOT}/src/client/pkcs11_psa_transport.c
  ${WT_REPO_ROOT}/src/client/pkcs11_proxy.c
  ${WT_REPO_ROOT}/src/pkcs11/pkcs11_wire.c
  ${WOLFTRUST_CMSE_IMPLIB}
)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}
  ${WT_REPO_ROOT}/include
  ${WT_REPO_ROOT}/lib/wolfPKCS11
  ${WT_TEST_DIR}
)

if(NOT DEFINED WT_PKCS11_SUITE)
  if(WT_CRYPTO_PROFILE STREQUAL "default")
    set(WT_PKCS11_SUITE profile)
  else()
    set(WT_PKCS11_SUITE all)
  endif()
endif()

if(WT_PKCS11_SUITE STREQUAL "profile")
  set(WT_PKCS11_SUITE_DEF WT_PKCS11_SUITE_PROFILE)
elseif(WT_PKCS11_SUITE STREQUAL "core")
  set(WT_PKCS11_SUITE_DEF WT_PKCS11_SUITE_CORE)
elseif(WT_PKCS11_SUITE STREQUAL "objects")
  set(WT_PKCS11_SUITE_DEF WT_PKCS11_SUITE_OBJECTS)
elseif(WT_PKCS11_SUITE STREQUAL "crypto")
  set(WT_PKCS11_SUITE_DEF WT_PKCS11_SUITE_CRYPTO)
elseif(WT_PKCS11_SUITE STREQUAL "negative")
  set(WT_PKCS11_SUITE_DEF WT_PKCS11_SUITE_NEGATIVE)
elseif(WT_PKCS11_SUITE STREQUAL "all")
  set(WT_PKCS11_SUITE_DEF WT_PKCS11_SUITE_ALL)
else()
  message(FATAL_ERROR "WT_PKCS11_SUITE must be profile, core, objects, crypto, negative, or all")
endif()

target_compile_definitions(app PRIVATE
  WOLFPKCS11_USER_SETTINGS
  WOLFPKCS11_NO_ENV
  ${WT_PKCS11_SUITE_DEF}=1
  WT_PKCS11_APP_NAME="pkcs11-zephyr"
)

if(WT_M33MU_EXPECT_BKPT)
  target_compile_definitions(app PRIVATE WT_M33MU_EXPECT_BKPT=1)
endif()
