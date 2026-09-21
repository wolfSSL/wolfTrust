# wolfTrust wolfHSM client Zephyr module
#
# Compiles the wolfHSM client subset + the wolfCrypt sources the dual-UART
# baremetal test uses + the local glue/init code into the Zephyr app.
# Generates the `wolfhsm_cfg.h` and `wolfhsm_guest_cfg.h` shim headers
# expected by wh_settings.h, pointing them at the in-module guest config.
#
# Depends on:
#   - CONFIG_WOLFTRUST_WOLFHSM_CLIENT=y          (this module's switch)
#   - WOLFTRUST_CMSE_IMPLIB                      (CMake var pointing at the
#                                                 secure-side import library
#                                                 with the CMSE veneer syms;
#                                                 passed by build_guest.sh)

if(CONFIG_WOLFTRUST_WOLFHSM_CLIENT)

  set(WT_REPO_ROOT      ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
  set(WT_WOLFHSM_DIR    ${WT_REPO_ROOT}/lib/wolfHSM)
  set(WT_WOLFSSL_DIR    ${WT_REPO_ROOT}/lib/wolfSSL)
  set(WT_MODULE_DIR     ${CMAKE_CURRENT_LIST_DIR})
  set(WT_GENERATED_DIR  ${CMAKE_CURRENT_BINARY_DIR}/wolftrust_wolfhsm_client/include)

  # wolfHSM `wh_settings.h` does `#ifdef WOLFHSM_CFG / #include "wolfhsm_cfg.h"`.
  # Generate a trampoline header that pulls in our wh_settings_guest.h, mirroring
  # tests/firmware/stm32h563/Makefile:357-374.
  file(MAKE_DIRECTORY ${WT_GENERATED_DIR})
  file(WRITE  ${WT_GENERATED_DIR}/wolfhsm_cfg.h
       "#include \"${WT_MODULE_DIR}/include/wolftrust/wolfhsm/wh_settings_guest.h\"\n")
  file(WRITE  ${WT_GENERATED_DIR}/wolfhsm_guest_cfg.h
       "#include \"${WT_MODULE_DIR}/include/wolftrust/wolfhsm/wh_settings_guest.h\"\n")

  zephyr_include_directories(
    ${WT_MODULE_DIR}/include
    ${WT_MODULE_DIR}/include/wolftrust/wolfhsm
    ${WT_WOLFHSM_DIR}
    ${WT_WOLFSSL_DIR}
    ${WT_GENERATED_DIR}
    ${WT_REPO_ROOT}/include
  )

  # Make WOLFSSL_USER_SETTINGS / WOLFHSM_CFG visible to every TU that
  # transitively includes wolfssl/wolfhsm headers — including app code.
  zephyr_compile_definitions(
    WOLFSSL_USER_SETTINGS
    WOLFHSM_CFG
    WOLF_CRYPTO_CB
    WC_RESEED_INTERVAL=1000000
    WT_ENGINE_HSM=1
    WOLFSSL_SP_ASM
    WOLFSSL_SP_ARM_CORTEX_M_ASM
    WOLFSSL_ARM_ARCH=8
    WOLFSSL_ECDSA_DETERMINISTIC_K
    WOLFSSL_ARMASM
    WOLFSSL_ARMASM_NO_HW_CRYPTO
    WOLFSSL_ARMASM_INLINE
    WOLFSSL_ARMASM_NO_NEON
    WOLFSSL_ARMASM_THUMB2
    NO_ERROR_STRINGS
    # gcc supports anonymous unions/structs even under -std=c99; the
    # wolfCrypt auto-detect (types.h) defaults this off in C99, but wolfHSM
    # *requires* the feature for its wc_CryptoInfo union. Force it on.
    HAVE_ANONYMOUS_INLINE_AGGREGATES=1
    # Triggers wolfSSL's WOLFSSL_ZEPHYR port path in types.h, which routes
    # XSTRCASECMP through wolfSSL's own wc_strcasecmp instead of a libc
    # symbol picolibc doesn't expose under -std=c99.
    WOLFSSL_ZEPHYR
  )

  zephyr_library_named(wolftrust_wolfhsm_client)

  # wolfHSM client sources (mirror WOLFHSM_GUEST_SRCS in the baremetal Makefile).
  zephyr_library_sources(
    ${WT_WOLFHSM_DIR}/src/wh_client.c
    ${WT_WOLFHSM_DIR}/src/wh_client_crypto.c
    ${WT_WOLFHSM_DIR}/src/wh_client_cryptocb.c
    ${WT_WOLFHSM_DIR}/src/wh_comm.c
    ${WT_WOLFHSM_DIR}/src/wh_crypto.c
    ${WT_WOLFHSM_DIR}/src/wh_keyid.c
    ${WT_WOLFHSM_DIR}/src/wh_message_comm.c
    ${WT_WOLFHSM_DIR}/src/wh_message_crypto.c
    ${WT_WOLFHSM_DIR}/src/wh_message_keystore.c
    ${WT_WOLFHSM_DIR}/src/wh_message_nvm.c
    ${WT_WOLFHSM_DIR}/src/wh_message_customcb.c
    ${WT_WOLFHSM_DIR}/src/wh_message_counter.c
    ${WT_WOLFHSM_DIR}/src/wh_utils.c
  )

  # wolfCrypt sources the guest exercises (mirror WOLFCRYPT_GUEST_SRCS).
  # Use the Zephyr-friendly subset; wolfPSA pulls in additional wolfCrypt
  # bits via its own module — overlap is fine, CMake dedupes by path.
  zephyr_library_sources(
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/aes.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/cryptocb.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/ecc.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/random.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha256.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/asn.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/coding.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/error.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hash.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hmac.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/memory.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/pwdbased.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_cortexm.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_int.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wc_port.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
  )

  # Local glue + Zephyr init, plus the OS-neutral FF-M client core and the
  # SPM-mediated wolfHSM transport (WT-FFM-0054). The module owns
  # psa_ffm_client.c so every client-enabled app links psa_connect/psa_call
  # without carrying its own copy.
  zephyr_library_sources(
    ${WT_MODULE_DIR}/src/wolfhsm_client_glue.c
    ${WT_MODULE_DIR}/src/wolfhsm_zephyr_init.c
    ${WT_REPO_ROOT}/src/client/psa_ffm_client.c
    ${WT_REPO_ROOT}/src/client/hsm_psa_transport.c
  )

  # Tone down third-party warnings; wolftrust-owned code stays strict.
  set_source_files_properties(
    ${WT_WOLFHSM_DIR}/src/wh_client.c
    ${WT_WOLFHSM_DIR}/src/wh_client_crypto.c
    ${WT_WOLFHSM_DIR}/src/wh_client_cryptocb.c
    ${WT_WOLFHSM_DIR}/src/wh_comm.c
    ${WT_WOLFHSM_DIR}/src/wh_crypto.c
    ${WT_WOLFHSM_DIR}/src/wh_keyid.c
    ${WT_WOLFHSM_DIR}/src/wh_message_comm.c
    ${WT_WOLFHSM_DIR}/src/wh_message_crypto.c
    ${WT_WOLFHSM_DIR}/src/wh_message_keystore.c
    ${WT_WOLFHSM_DIR}/src/wh_message_nvm.c
    ${WT_WOLFHSM_DIR}/src/wh_message_customcb.c
    ${WT_WOLFHSM_DIR}/src/wh_message_counter.c
    ${WT_WOLFHSM_DIR}/src/wh_utils.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/aes.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/cryptocb.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/ecc.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/random.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha256.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/asn.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/coding.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/error.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hash.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hmac.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/memory.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/pwdbased.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_cortexm.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_int.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wc_port.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
    PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter;-Wno-type-limits"
  )

endif()

if(CONFIG_WOLFTRUST_NATIVE_CLIENT)

  set(WT_REPO_ROOT      ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
  set(WT_WOLFSSL_DIR    ${WT_REPO_ROOT}/lib/wolfSSL)
  set(WT_MODULE_DIR     ${CMAKE_CURRENT_LIST_DIR})

  zephyr_include_directories(
    ${WT_MODULE_DIR}/include
    ${WT_MODULE_DIR}/include/wolftrust/wolfhsm
    ${WT_WOLFSSL_DIR}
    ${WT_REPO_ROOT}/include
  )

  # Same wolfCrypt shape as the hsm client, minus the crypto_cb routing and
  # every wolfHSM define: primitives run Non-secure, seeds ride the native
  # wire (crypto_native_client.c) to the secure vault RNG.
  zephyr_compile_definitions(
    WOLFSSL_USER_SETTINGS
    WC_RESEED_INTERVAL=1000000
    WT_ENGINE_NATIVE=1
    WOLFSSL_SP_ASM
    WOLFSSL_SP_ARM_CORTEX_M_ASM
    WOLFSSL_ARM_ARCH=8
    WOLFSSL_ECDSA_DETERMINISTIC_K
    WOLFSSL_ARMASM
    WOLFSSL_ARMASM_NO_HW_CRYPTO
    WOLFSSL_ARMASM_INLINE
    WOLFSSL_ARMASM_NO_NEON
    WOLFSSL_ARMASM_THUMB2
    NO_ERROR_STRINGS
    HAVE_ANONYMOUS_INLINE_AGGREGATES=1
    WOLFSSL_ZEPHYR
  )

  zephyr_library_named(wolftrust_native_client)

  zephyr_library_sources(
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/aes.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/ecc.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/random.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha256.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/asn.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/coding.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/error.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hash.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hmac.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/memory.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/pwdbased.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_cortexm.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_int.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wc_port.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
  )

  zephyr_library_sources(
    ${WT_REPO_ROOT}/src/client/crypto_native_client.c
    ${WT_REPO_ROOT}/src/client/psa_ffm_client.c
  )

  set_source_files_properties(
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/aes.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/ecc.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/random.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha256.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/asn.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/coding.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/error.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hash.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/hmac.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/memory.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/pwdbased.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sha.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_cortexm.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/sp_int.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/wc_port.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c
    ${WT_WOLFSSL_DIR}/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
    PROPERTIES COMPILE_OPTIONS
      "-Wno-unused-function;-Wno-unused-variable;-Wno-unused-parameter;-Wno-type-limits"
  )

endif()
