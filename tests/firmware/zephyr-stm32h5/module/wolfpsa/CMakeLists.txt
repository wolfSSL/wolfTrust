# wolfPSA Zephyr module
#
# Compiles the lib/wolfPSA submodule into the Zephyr image and registers a
# SYS_INIT hook that points wolfPSA at the WH_DEV_ID crypto_cb registered by
# the wolfhsm-client module. The result: app code calling psa_*() ends up
# in wolfPSA → wolfCrypt → crypto_cb → wolfHSM client → CMSE → secure side.
#
# The wolfHSM-client module already arranged WOLFSSL_USER_SETTINGS / WOLFHSM_CFG
# / wolfssl include paths and compiled a wolfCrypt subset. This module
# extends that subset with the wolfPSA-specific defines (WOLFSSL_PSA_ENGINE)
# and pulls every wolfPSA src/*.c into the link; the wolfPSA TUs covering
# algorithms we don't enable (RSA, ChaCha+Poly1305, ML-DSA, …) compile to
# empty objects under their own `#if defined(HAVE_…)` guards. The POSIX
# key-storage backend is suppressed via WOLFPSA_CUSTOM_STORE; wolfPSA's Zephyr
# backend supplies its no-storage fallback because CONFIG_SECURE_STORAGE is
# disabled, so every PSA key in this port is volatile.

if(CONFIG_WOLFPSA)

  set(WT_REPO_ROOT    ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
  set(WT_WOLFPSA_DIR  ${WT_REPO_ROOT}/lib/wolfPSA)
  set(WT_WOLFSSL_DIR  ${WT_REPO_ROOT}/lib/wolfSSL)
  set(WT_MODULE_DIR   ${CMAKE_CURRENT_LIST_DIR})
  set(WT_WOLFSSL_SETTINGS_DIR
      ${WT_REPO_ROOT}/tests/firmware/zephyr-stm32h5/module/wolfhsm-client/include/wolftrust/wolfhsm)

  # The consumer-visible PSA_WANT_* surface is the Secure image's under
  # WOLFTRUST_SECURE_PSA; otherwise it is generated at configure time from the
  # wolfCrypt features compiled into this guest.
  if(DEFINED AUTOCONF_H)
    set(WT_WOLFPSA_AUTOCONF ${AUTOCONF_H})
  else()
    set(WT_WOLFPSA_AUTOCONF
        ${CMAKE_BINARY_DIR}/zephyr/include/generated/zephyr/autoconf.h)
  endif()
  set(WT_WOLFPSA_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/wolfpsa_gen)
  set(WT_WOLFPSA_GEN_HDR ${WT_WOLFPSA_GEN_DIR}/crypto_config_zephyr.h)
  set(WT_WOLFPSA_PROBE ${WT_WOLFPSA_DIR}/tools/psa_want_probe.c)
  set(WT_WOLFPSA_GEN_PY ${WT_WOLFPSA_DIR}/tools/gen-crypto-config.py)
  file(MAKE_DIRECTORY ${WT_WOLFPSA_GEN_DIR})
  if(CONFIG_WOLFTRUST_SECURE_PSA)
    # The Secure image serves PSA Crypto, so its profile's surface is the one.
    if(DEFINED WOLFTRUST_CMSE_IMPLIB)
      get_filename_component(WT_SECURE_BUILD_DIR ${WOLFTRUST_CMSE_IMPLIB} DIRECTORY)
    else()
      set(WT_SECURE_BUILD_DIR ${WT_REPO_ROOT}/build)
    endif()
    set(WT_SECURE_PSA_HDR ${WT_SECURE_BUILD_DIR}/wolfpsa_cfg/crypto_config_generated.h)
    if(NOT EXISTS ${WT_SECURE_PSA_HDR})
      message(FATAL_ERROR
        "wolfPSA: missing ${WT_SECURE_PSA_HDR}: build the Secure image first")
    endif()
    configure_file(${WT_SECURE_PSA_HDR} ${WT_WOLFPSA_GEN_HDR} COPYONLY)
  else()
    # __ASSEMBLER__: settings.h then skips the Zephyr kernel headers.
    execute_process(
      COMMAND ${PYTHON_EXECUTABLE} ${WT_WOLFPSA_GEN_PY}
              ${WT_WOLFPSA_GEN_HDR} ${CMAKE_C_COMPILER} ${WT_WOLFPSA_PROBE}
              -D__ZEPHYR__=1
              -D__ASSEMBLER__
              -DWOLFSSL_USER_SETTINGS
              -DWOLFSSL_ZEPHYR
              -DWOLFSSL_ECDSA_DETERMINISTIC_K
              -I${WT_WOLFPSA_DIR}
              -I${WT_WOLFPSA_DIR}/wolfpsa
              -I${WT_WOLFSSL_DIR}
              -I${WT_WOLFSSL_SETTINGS_DIR}
              -imacros ${WT_WOLFPSA_AUTOCONF}
      RESULT_VARIABLE WT_WOLFPSA_GEN_RC)
    if(NOT WT_WOLFPSA_GEN_RC EQUAL 0)
      message(FATAL_ERROR
        "wolfPSA: failed to generate the PSA_WANT surface (rc=${WT_WOLFPSA_GEN_RC})")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
      ${WT_WOLFPSA_PROBE}
      ${WT_WOLFPSA_GEN_PY}
      ${WT_WOLFSSL_SETTINGS_DIR}/user_settings.h)
  endif()

  # Expose wolfPSA's public headers globally. Apps that #include <psa/crypto.h>
  # will resolve to lib/wolfPSA/wolfpsa/psa/crypto.h (NOT mbedTLS's copy —
  # the Kconfig depends on !MBEDTLS to enforce this).
  zephyr_system_include_directories(
    ${WT_WOLFPSA_DIR}
    ${WT_WOLFPSA_DIR}/wolfpsa
    ${WT_WOLFPSA_GEN_DIR}
  )
  # wolfPSA src/*.c also include "psa_trace.h", "psa_size.h" without the
  # wolfpsa/ prefix — add src/ to the include search path so those resolve.
  zephyr_system_include_directories(${WT_WOLFPSA_DIR}/src)

  zephyr_compile_definitions(
    # Gate every wolfPSA TU.
    WOLFSSL_PSA_ENGINE
    # Select wolfPSA's Zephyr storage backend instead of its POSIX backend.
    WOLFPSA_CUSTOM_STORE
    # Zephyr has no process environment or stderr-backed trace sink.
    WOLFPSA_NO_TRACE
  )

  zephyr_library_named(wolftrust_wolfpsa)

  if(CONFIG_WOLFTRUST_SECURE_PSA)
  zephyr_library_sources(
    ${WT_REPO_ROOT}/src/client/psa_crypto_client.c
    ${WT_WOLFPSA_DIR}/src/psa_api_stub.c
    ${WT_MODULE_DIR}/src/wolfpsa_zephyr_init.c
  )
  else()
  # Compile every wolfPSA src/*.c EXCEPT psa_store_posix.c (POSIX-only).
  file(GLOB WOLFPSA_SRCS ${WT_WOLFPSA_DIR}/src/*.c)
  list(FILTER WOLFPSA_SRCS EXCLUDE REGEX "psa_store_posix\\.c$")
  # wolfTrust supplies the target-specific Initial Attestation backend.
  list(FILTER WOLFPSA_SRCS EXCLUDE REGEX "psa_attestation\\.c$")
  zephyr_library_sources(${WOLFPSA_SRCS})

  zephyr_library_sources(
    ${WT_MODULE_DIR}/src/wolfpsa_zephyr_init.c
  )

  # wolfPSA needs SHA-384/SHA-512 and a few other wolfCrypt sources that
  # the wolfhsm-client module's minimal subset doesn't include. List them
  # here; CMake dedupes by absolute path if any happen to overlap.
  zephyr_library_sources(
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha512.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/kdf.c
  )

  # Treat third-party warnings as warnings, not errors. wolfHSM-client
  # already tones things down for its own subset; mirror that for wolfPSA.
  set_source_files_properties(
    ${WOLFPSA_SRCS}
    PROPERTIES COMPILE_OPTIONS
      "-include;${WT_MODULE_DIR}/wolfpsa_no_trace.h;-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter;-Wno-type-limits"
  )
  set_source_files_properties(
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha512.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/kdf.c
    PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter;-Wno-type-limits"
  )
  endif()

endif()
