TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size
M33MU ?= m33mu
ROOT := ../../..
PORT_DIR := $(ROOT)/port/stm32h563
WOLFHSM_RUNNER_DIR := $(ROOT)/src/services/wolfhsm/runner
ARCH ?= armv8m
TARGET ?= stm32h563
PORT_HEADERS := $(wildcard $(PORT_DIR)/*.h)

CPU_FLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only
CFLAGS_COMMON := $(CPU_FLAGS) -std=c99 -ffreestanding -fno-builtin -nostdlib -O0 -g -Wall -Wextra
CFLAGS_COMMON += -I$(ROOT)/include -I$(PORT_DIR) -I$(ROOT)/lib/wolfhal
WT_TIMESLICE_MS ?= 2
EMU_TIMEOUT ?= 300
CFLAGS_COMMON += -DWT_TIMESLICE_MS=$(WT_TIMESLICE_MS)
WT_MAX_GUESTS ?= 2
WT_CO_STACK_SIZE ?= 24576
WT_WOLFCRYPT_SP_ASM ?= 1
WT_WOLFCRYPT_ARMASM ?= 1
WT_WOLFCRYPT_STM32_HASH ?= 0
CFLAGS_COMMON += -DWT_MAX_GUESTS=$(WT_MAX_GUESTS)
CFLAGS_COMMON += -DWT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE)
WT_SHARED_UART ?= 3
CFLAGS_COMMON += -DWT_SHARED_UART=$(WT_SHARED_UART)

# wolfHSM resumes SHA-256 operations from the portable digest and length
# fields carried by its wire protocol. STM32 HASH uses opaque peripheral CSR
# state instead, so enabling it here would remove the wolfHSM SHA handler and
# make a client fallback operate on a partially modified context.
ifneq ($(WT_WOLFCRYPT_STM32_HASH),0)
$(error WT_WOLFCRYPT_STM32_HASH is incompatible with the wolfHSM SHA service)
endif
# Guests see virtual SysTick elapsed time from the monitor while still using
# the target core clock when programming SysTick.
WT_GUEST_CORE_CLOCK_HZ ?= 240000000
WT_GUEST_UART_CLOCK_HZ ?= 120000000
CFLAGS_COMMON += -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ)
CFLAGS_COMMON += -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ)
WT_GUEST0_FLASH_ORIGIN ?= 0x08020000
WT_GUEST1_FLASH_ORIGIN ?= 0x08040000
WT_GUEST_FLASH_SIZE ?= 0x00020000
WT_GUEST_RAM_SIZE ?= 0x00008000
WT_GUEST0_EMU_OFFSET ?= 0x20000
WT_GUEST1_EMU_OFFSET ?= 0x40000
WT_GUEST_FLASH_LENGTH ?= $(WT_GUEST_FLASH_SIZE)
WT_BENCH_MIN_RUNTIME_SEC ?= 0.0
CFLAGS_COMMON += -DWT_GUEST0_FLASH_BASE=$(WT_GUEST0_FLASH_ORIGIN)u
CFLAGS_COMMON += -DWT_GUEST1_FLASH_BASE=$(WT_GUEST1_FLASH_ORIGIN)u
CFLAGS_COMMON += -DWT_GUEST_FLASH_SIZE=$(WT_GUEST_FLASH_SIZE)u

SECURE_CFLAGS := $(CFLAGS_COMMON) -mcmse
NONSECURE_CFLAGS := $(CFLAGS_COMMON) -mno-unaligned-access

BUILD_DIR := build
TOP_BUILD_DIR := $(ROOT)/build

SECURE_ELF := $(TOP_BUILD_DIR)/wolftrust.elf
SECURE_BIN := $(TOP_BUILD_DIR)/wolftrust.bin
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o
BUILD_MODE_STAMP := $(BUILD_DIR)/build_mode.stamp

GUEST0_ELF := $(BUILD_DIR)/guest0.elf
GUEST0_BIN := $(BUILD_DIR)/guest0.bin

GUEST1_ELF := $(BUILD_DIR)/guest1.elf
GUEST1_BIN := $(BUILD_DIR)/guest1.bin

NONSECURE_SRCS := nonsecure/guest.c

# ---------------------------------------------------------------------------
# Default goal — declared first so it wins regardless of ifeq blocks below
# ---------------------------------------------------------------------------
.PHONY: all clean run run-tui run-uarts run-hsm run-hsm-uarts FORCE
all: $(SECURE_BIN) $(GUEST0_BIN) $(GUEST1_BIN)
	@$(SIZE) $(SECURE_ELF) $(GUEST0_ELF) $(GUEST1_ELF)

# ---------------------------------------------------------------------------
# wolfHSM / wolfCrypt / wolftrust HSM engine.
# ---------------------------------------------------------------------------
WT_ENGINE_HSM ?= 1
ifeq ($(WT_ENGINE_HSM),1)

WOLFHSM_DIR := $(ROOT)/lib/wolfHSM
WOLFSSL_DIR := $(ROOT)/lib/wolfSSL
WOLFHAL_DIR := $(ROOT)/lib/wolfhal
WT_WOLFHSM_DEV_ID ?= -2

# wolfhsm/wh_settings.h picks up our settings via:
#   #ifdef WOLFHSM_CFG
#   #include "wolfhsm_cfg.h"
#   #endif
# We must provide a file named exactly "wolfhsm_cfg.h" on the include path.
# We generate trampolines in $(BUILD_DIR) and add -I$(BUILD_DIR).
WOLFHSM_CFG_H       := $(BUILD_DIR)/wolfhsm_cfg.h
WOLFHSM_GUEST_CFG_H := $(BUILD_DIR)/wolfhsm_guest_cfg.h

HSM_INCLUDES        := -I$(WOLFHSM_DIR) -I$(WOLFSSL_DIR) -I$(BUILD_DIR)
HSM_INCLUDES_SECURE := $(HSM_INCLUDES) -I$(WOLFHAL_DIR) -I$(abspath $(WOLFHSM_RUNNER_DIR))
HSM_INCLUDES_GUEST  := $(HSM_INCLUDES) -I$(abspath nonsecure)
# WOLF_CRYPTO_CB: required by wolfHSM (wh_settings.h asserts it).
# -UNO_CODING: user_settings.h defines NO_CODING but we compile coding.c.
# WC_RESEED_INTERVAL: wolfssl/wolfcrypt/random.h only defines it when
#   CUSTOM_RAND_GENERATE_BLOCK is not set; since user_settings.h sets it
#   we must provide the interval ourselves.
HSM_DEFS_SECURE  := -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG \
    -DWOLF_CRYPTO_CB -UNO_CODING \
    -DWC_RESEED_INTERVAL=1000000 -DWT_ENGINE_HSM=1
HSM_DEFS_GUEST   := -DWOLFSSL_USER_SETTINGS -DWOLFHSM_CFG \
    -DWOLF_CRYPTO_CB -UNO_CODING \
    -DWC_RESEED_INTERVAL=1000000 -DWT_ENGINE_HSM=1 \
    -DWOLFHSM_CFG_ENABLE_CLIENT \
    -DNO_ERROR_STRINGS
ifeq ($(ARCH),armv8m)
ifeq ($(WT_WOLFCRYPT_SP_ASM),1)
HSM_DEFS_SECURE += -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM \
    -DWOLFSSL_ARM_ARCH=8
HSM_DEFS_GUEST += -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM \
    -DWOLFSSL_ARM_ARCH=8
endif
ifeq ($(WT_WOLFCRYPT_ARMASM),1)
HSM_DEFS_SECURE += -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO \
    -DWOLFSSL_ARMASM_INLINE -DWOLFSSL_ARMASM_NO_NEON \
    -DWOLFSSL_ARMASM_THUMB2
HSM_DEFS_GUEST += -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO \
    -DWOLFSSL_ARMASM_INLINE -DWOLFSSL_ARMASM_NO_NEON \
    -DWOLFSSL_ARMASM_THUMB2
endif
endif
# Switch secure ELF to -Os: wolfCrypt is too slow at -O0 for embedded use.
SECURE_CFLAGS := $(CPU_FLAGS) -std=c99 -ffreestanding -fno-builtin -nostdlib -Os -g \
    -Wall -Wextra \
    -I$(ROOT)/include -I$(PORT_DIR) \
    -DWT_TIMESLICE_MS=$(WT_TIMESLICE_MS) \
    -DWT_MAX_GUESTS=$(WT_MAX_GUESTS) \
    -DWT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE) \
    -DWT_SHARED_UART=$(WT_SHARED_UART) \
    -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
    -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ) \
    -DWHAL_CFG_STM32H5_RNG_DIRECT_API_MAPPING \
    -mcmse \
    $(HSM_INCLUDES_SECURE) $(HSM_DEFS_SECURE)
NONSECURE_CFLAGS := $(CPU_FLAGS) -std=c99 -ffreestanding -fno-builtin -nostdlib -Os -g \
    -Wall -Wextra \
    -mno-unaligned-access \
    -ffunction-sections -fdata-sections \
    -I$(ROOT)/include -I$(PORT_DIR) \
    -DWT_TIMESLICE_MS=$(WT_TIMESLICE_MS) \
    -DWT_MAX_GUESTS=$(WT_MAX_GUESTS) \
    -DWT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE) \
    -DWT_SHARED_UART=$(WT_SHARED_UART) \
    -DWT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
    -DWT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ) \
    $(HSM_INCLUDES_GUEST) $(HSM_DEFS_GUEST)

# Flags for third-party wolfHSM/wolfCrypt sources: suppress their noisy warnings.
# wolftrust's own sources are compiled with the base flags (no suppression).
HSM_LIB_CFLAGS   := $(SECURE_CFLAGS) \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter \
    -Wno-type-limits
HSM_WOLFHSM_CFLAGS := $(HSM_LIB_CFLAGS)
GUEST_LIB_CFLAGS := $(NONSECURE_CFLAGS) \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter
GUEST_BENCH_CFLAGS := $(GUEST_LIB_CFLAGS) \
    -DBENCH_EMBEDDED \
    -DNO_MAIN_FUNCTION \
    -DNO_STDIO_FILESYSTEM \
    -DNO_SW_BENCH \
    -DWOLFSSL_NO_FLOAT_FMT \
    -DWOLFSSL_USER_CURRTIME \
    -DBENCH_MIN_RUNTIME_SEC=$(WT_BENCH_MIN_RUNTIME_SEC) \
    -DWC_USE_DEVID=$(WT_WOLFHSM_DEV_ID) \
    -DXPRINTF=wt_benchmark_printf \
    -DXSNPRINTF=wt_benchmark_snprintf \
    -DXATOI=wt_benchmark_atoi \
    -include $(abspath nonsecure/benchmark_hooks.h)

# ---- secure-side source lists -----------------------------------------------

WOLFHSM_SECURE_SRCS := \
    $(WOLFHSM_DIR)/src/wh_client.c \
    $(WOLFHSM_DIR)/src/wh_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_crypto.c \
    $(WOLFHSM_DIR)/src/wh_message_keystore.c \
    $(WOLFHSM_DIR)/src/wh_message_nvm.c \
    $(WOLFHSM_DIR)/src/wh_message_customcb.c \
    $(WOLFHSM_DIR)/src/wh_message_counter.c \
    $(WOLFHSM_DIR)/src/wh_nvm.c \
    $(WOLFHSM_DIR)/src/wh_nvm_flash.c \
    $(WOLFHSM_DIR)/src/wh_flash_unit.c \
    $(WOLFHSM_DIR)/src/wh_server.c \
    $(WOLFHSM_DIR)/src/wh_server_crypto.c \
    $(WOLFHSM_DIR)/src/wh_server_keystore.c \
    $(WOLFHSM_DIR)/src/wh_server_nvm.c \
    $(WOLFHSM_DIR)/src/wh_server_customcb.c \
    $(WOLFHSM_DIR)/src/wh_server_counter.c \
    $(WOLFHSM_DIR)/src/wh_transport_mem.c \
    $(WOLFHSM_DIR)/src/wh_lock.c \
    $(WOLFHSM_DIR)/src/wh_utils.c \
    $(WOLFHSM_DIR)/src/wh_crypto.c \
    $(WOLFHSM_DIR)/src/wh_keyid.c \
    $(WOLFHSM_DIR)/src/wh_log.c

WOLFCRYPT_SECURE_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/logging.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c

ifeq ($(WT_WOLFCRYPT_ARMASM),1)
ifeq ($(ARCH),armv8m)
WOLFCRYPT_SECURE_SRCS += \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
endif
endif

# ---- guest-side source lists ------------------------------------------------

WOLFHSM_GUEST_SRCS := \
    $(WOLFHSM_DIR)/src/wh_client.c \
    $(WOLFHSM_DIR)/src/wh_client_crypto.c \
    $(WOLFHSM_DIR)/src/wh_client_cryptocb.c \
    $(WOLFHSM_DIR)/src/wh_comm.c \
    $(WOLFHSM_DIR)/src/wh_crypto.c \
    $(WOLFHSM_DIR)/src/wh_keyid.c \
    $(WOLFHSM_DIR)/src/wh_message_comm.c \
    $(WOLFHSM_DIR)/src/wh_message_crypto.c \
    $(WOLFHSM_DIR)/src/wh_message_keystore.c \
    $(WOLFHSM_DIR)/src/wh_message_nvm.c \
    $(WOLFHSM_DIR)/src/wh_message_customcb.c \
    $(WOLFHSM_DIR)/src/wh_message_counter.c \
    $(WOLFHSM_DIR)/src/wh_utils.c

WOLFCRYPT_GUEST_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c

WOLFCRYPT_BENCH_GUEST_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/benchmark/benchmark.c

ifeq ($(WT_WOLFCRYPT_ARMASM),1)
ifeq ($(ARCH),armv8m)
WOLFCRYPT_GUEST_SRCS += \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-aes-asm_c.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c
endif
endif

# Wave 5: guest glue — include only when present. The glue's transport is the
# SPM-mediated PSA path, so the neutral FF-M client core and the wolfHSM psa
# transport ride along (WT-FFM-0054).
WOLFHSM_GUEST_SRCS += $(wildcard nonsecure/wolfhsm_client_glue.c)
WOLFHSM_GUEST_SRCS += \
    $(ROOT)/src/client/psa_ffm_client.c \
    $(ROOT)/src/client/hsm_psa_transport.c

# Guest-side libc stubs (memcpy/memset already inlined by gcc for guest.c,
# but wolfCrypt sources need the full set).
NONSECURE_SRCS += $(wildcard nonsecure/libc_stubs_guest.c)
NONSECURE_COMMON_SRCS := $(filter-out nonsecure/guest.c,$(NONSECURE_SRCS))

# ---- object lists -----------------------------------------------------------

HSM_WOLFHSM_SEC_OBJS    := $(patsubst %.c,$(BUILD_DIR)/wh_sec_%.o,$(notdir $(WOLFHSM_SECURE_SRCS)))
HSM_WOLFCRYPT_SEC_OBJS  := $(patsubst %.c,$(BUILD_DIR)/wc_sec_%.o,$(notdir $(WOLFCRYPT_SECURE_SRCS)))

HSM_NONSECURE_BASE_OBJS  := $(patsubst %.c,$(BUILD_DIR)/ns_%.o,$(notdir $(NONSECURE_COMMON_SRCS)))
HSM_WOLFHSM_GUEST_OBJS   := $(patsubst %.c,$(BUILD_DIR)/wh_guest_%.o,$(notdir $(WOLFHSM_GUEST_SRCS)))
HSM_WOLFCRYPT_GUEST_OBJS := $(patsubst %.c,$(BUILD_DIR)/wc_guest_%.o,$(notdir $(WOLFCRYPT_GUEST_SRCS)))
HSM_WOLFCRYPT_BENCH_GUEST_OBJS := $(patsubst %.c,$(BUILD_DIR)/wc_bench_guest_%.o,$(notdir $(WOLFCRYPT_BENCH_GUEST_SRCS)))
HSM_GUEST0_MAIN_OBJ      := $(BUILD_DIR)/ns_guest0_guest.o
HSM_GUEST1_MAIN_OBJ      := $(BUILD_DIR)/ns_guest1_guest.o

ALL_SECURE_OBJS := \
    $(HSM_WOLFHSM_SEC_OBJS) \
    $(HSM_WOLFCRYPT_SEC_OBJS)

ALL_GUEST_COMMON_OBJS := \
    $(HSM_NONSECURE_BASE_OBJS) \
    $(HSM_WOLFHSM_GUEST_OBJS) \
    $(HSM_WOLFCRYPT_GUEST_OBJS) \
    $(HSM_WOLFCRYPT_BENCH_GUEST_OBJS)

ALL_GUEST0_OBJS := $(HSM_GUEST0_MAIN_OBJ) $(ALL_GUEST_COMMON_OBJS)
ALL_GUEST1_OBJS := $(HSM_GUEST1_MAIN_OBJ) $(ALL_GUEST_COMMON_OBJS)

# ---- wolfhsm_cfg.h trampolines ----------------------------------------------
# wh_settings.h does: #ifdef WOLFHSM_CFG / #include "wolfhsm_cfg.h" / #endif
# We must provide a file of that exact name on the include path.
# The trampoline simply includes our local settings; the include guard in
# the local file prevents double-processing when the compiler also sees
# the local file via other paths.

$(WOLFHSM_CFG_H): | $(BUILD_DIR)
	printf '#include "%s"\n' "$(abspath $(WOLFHSM_RUNNER_DIR)/wh_settings_local.h)" > $@

# Wave 5 guest settings: if wh_settings_guest.h doesn't exist yet, generate
# a placeholder with the minimum defines to satisfy the wolfHSM headers.
$(WOLFHSM_GUEST_CFG_H): | $(BUILD_DIR)
	if [ -f "$(abspath nonsecure/wh_settings_guest.h)" ]; then \
	    printf '#include "%s"\n' "$(abspath nonsecure/wh_settings_guest.h)" > $@; \
	else \
	    { printf '/* placeholder: Wave 5 will provide wh_settings_guest.h */\n'; \
	      printf '#define WOLFHSM_CFG_NO_SYS_TIME\n'; \
	      printf '#define WOLFHSM_CFG_COMM_DATA_LEN 256\n'; \
	      printf '#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 4\n'; \
	      printf '#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 256\n'; \
	      printf '#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 0\n'; \
	      printf '#define WOLFHSM_CFG_NVM_OBJECT_COUNT 8\n'; \
	    } > $@; \
	fi

# ---- per-group compile rules ------------------------------------------------

# wolfHSM sources — compiled with warning suppression
$(BUILD_DIR)/wh_sec_%.o: $(WOLFHSM_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_WOLFHSM_CFLAGS) -c -o $@ $<

# wolfCrypt sources — compiled with warning suppression
$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_sec_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/st/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(HSM_LIB_CFLAGS) -c -o $@ $<

# wolftrust arch/sched/sync/runner/port sources — no warning suppression
$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/arch/armv8m/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/sched/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/sync/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHSM_RUNNER_DIR)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(PORT_DIR)/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHAL_DIR)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wt_sec_%.o: $(WOLFHAL_DIR)/src/rng/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

# Wave 3/4 services sources
$(BUILD_DIR)/wt_sec_%.o: $(ROOT)/src/services/wolfhsm/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

# Secure base sources (SECURE_SRCS)
$(BUILD_DIR)/sec_%.o: $(WOLFHSM_RUNNER_DIR)/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(PORT_DIR)/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/sec_%.o: $(ROOT)/src/%.c $(WOLFHSM_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(SECURE_CFLAGS) -c -o $@ $<

# Guest wolfHSM — warning suppression
$(BUILD_DIR)/wh_guest_%.o: $(WOLFHSM_DIR)/src/%.c $(WOLFHSM_GUEST_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(GUEST_LIB_CFLAGS) -c -o $@ $<

# Guest wolfCrypt — warning suppression
$(BUILD_DIR)/wc_guest_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/%.c $(WOLFHSM_GUEST_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(GUEST_LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_guest_%.o: $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/%.c $(WOLFHSM_GUEST_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(GUEST_LIB_CFLAGS) -c -o $@ $<

# Guest compiles pull in wh_settings.h which does `#include "wolfhsm_cfg.h"`
# under -DWOLFHSM_CFG, so the *secure* config header has to exist on the
# include path even though the guest also consumes wh_settings_guest.h.
# Listing both as prereqs makes the rules safe under parallel make and
# after a clean of the build dir.
$(BUILD_DIR)/wc_bench_guest_%.o: $(WOLFSSL_DIR)/wolfcrypt/benchmark/%.c $(WOLFHSM_CFG_H) $(WOLFHSM_GUEST_CFG_H) nonsecure/benchmark_hooks.h $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(GUEST_BENCH_CFLAGS) -c -o $@ $<

# Guest base sources
$(BUILD_DIR)/ns_%.o: nonsecure/%.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(WOLFHSM_GUEST_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) -c -o $@ $<

$(HSM_GUEST0_MAIN_OBJ): nonsecure/guest.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(WOLFHSM_GUEST_CFG_H) nonsecure/benchmark_hooks.h $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) -DWT_GUEST_ID=0u -c -o $@ $<

$(HSM_GUEST1_MAIN_OBJ): nonsecure/guest.c $(PORT_HEADERS) $(WOLFHSM_CFG_H) $(WOLFHSM_GUEST_CFG_H) nonsecure/benchmark_hooks.h $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) -DWT_GUEST_ID=1u -c -o $@ $<

# Wave 5: wolfhsm_client_glue.c lives in nonsecure/ but is listed under
# WOLFHSM_GUEST_SRCS so it gets the wh_guest_ prefix and the guest lib flags.
$(BUILD_DIR)/wh_guest_wolfhsm_client_glue.o: nonsecure/wolfhsm_client_glue.c $(WOLFHSM_CFG_H) $(WOLFHSM_GUEST_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(GUEST_LIB_CFLAGS) -c -o $@ $<

# Neutral FF-M client core + SPM-mediated wolfHSM transport, same prefix and
# guest lib flags as the glue that consumes them.
$(BUILD_DIR)/wh_guest_%.o: $(ROOT)/src/client/%.c $(WOLFHSM_CFG_H) $(WOLFHSM_GUEST_CFG_H) $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(GUEST_LIB_CFLAGS) -c -o $@ $<

endif  # WT_ENGINE_HSM=1

# ---------------------------------------------------------------------------
# Per-mode ELF link rules
# ---------------------------------------------------------------------------

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_MODE_STAMP): FORCE | $(BUILD_DIR)
	@tmp="$@.tmp"; \
	printf '%s\n' \
		'WT_ENGINE_HSM=$(WT_ENGINE_HSM)' \
		'ARCH=$(ARCH)' \
		'WT_MAX_GUESTS=$(WT_MAX_GUESTS)' \
		'WT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE)' \
		'WT_WOLFCRYPT_SP_ASM=$(WT_WOLFCRYPT_SP_ASM)' \
		'WT_WOLFCRYPT_ARMASM=$(WT_WOLFCRYPT_ARMASM)' \
		'WT_WOLFCRYPT_STM32_HASH=$(WT_WOLFCRYPT_STM32_HASH)' \
		'WT_SHARED_UART=$(WT_SHARED_UART)' \
		'WT_GUEST0_FLASH_ORIGIN=$(WT_GUEST0_FLASH_ORIGIN)' \
		'WT_GUEST1_FLASH_ORIGIN=$(WT_GUEST1_FLASH_ORIGIN)' \
		'WT_GUEST_FLASH_SIZE=$(WT_GUEST_FLASH_SIZE)' \
		'WT_GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_LENGTH)' \
		'WT_GUEST_RAM_SIZE=$(WT_GUEST_RAM_SIZE)' \
		'WT_BENCH_MIN_RUNTIME_SEC=$(WT_BENCH_MIN_RUNTIME_SEC)' \
		'WT_GUEST0_EMU_OFFSET=$(WT_GUEST0_EMU_OFFSET)' \
		'WT_GUEST1_EMU_OFFSET=$(WT_GUEST1_EMU_OFFSET)' \
		'WT_TIMESLICE_MS=$(WT_TIMESLICE_MS)' \
		'WT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ)' \
		'WT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ)' > "$$tmp"; \
	if test -f "$@" && cmp -s "$$tmp" "$@"; then \
		rm -f "$$tmp"; \
	else \
		mv "$$tmp" "$@"; \
	fi

TOPLEVEL_SECURE_MAKE_VARS := \
	ARCH=$(ARCH) \
	TARGET=$(TARGET) \
	TOOLPREFIX=$(TOOLPREFIX) \
	WT_ENGINE_HSM=$(WT_ENGINE_HSM) \
	WT_TIMESLICE_MS=$(WT_TIMESLICE_MS) \
	WT_MAX_GUESTS=$(WT_MAX_GUESTS) \
	WT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE) \
	WT_WOLFCRYPT_SP_ASM=$(WT_WOLFCRYPT_SP_ASM) \
	WT_WOLFCRYPT_ARMASM=$(WT_WOLFCRYPT_ARMASM) \
	WT_WOLFCRYPT_STM32_HASH=$(WT_WOLFCRYPT_STM32_HASH) \
	WT_SHARED_UART=$(WT_SHARED_UART) \
	WT_GUEST_CORE_CLOCK_HZ=$(WT_GUEST_CORE_CLOCK_HZ) \
	WT_GUEST_UART_CLOCK_HZ=$(WT_GUEST_UART_CLOCK_HZ)
TOPLEVEL_SECURE_ELF_TARGET := build/wolftrust.elf
TOPLEVEL_SECURE_BIN_TARGET := build/wolftrust.bin
TOPLEVEL_SECURE_CMSE_TARGET := build/secure_cmse_implib.o

$(SECURE_BIN): FORCE
	$(MAKE) -C $(ROOT) $(TOPLEVEL_SECURE_MAKE_VARS) $(TOPLEVEL_SECURE_BIN_TARGET)

$(SECURE_ELF): FORCE
	$(MAKE) -C $(ROOT) $(TOPLEVEL_SECURE_MAKE_VARS) $(TOPLEVEL_SECURE_ELF_TARGET)

$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) $(TOPLEVEL_SECURE_MAKE_VARS) $(TOPLEVEL_SECURE_CMSE_TARGET)

ifeq ($(WT_ENGINE_HSM),1)

$(GUEST0_ELF): $(ALL_GUEST0_OBJS) $(SECURE_CMSE_IMPLIB) nonsecure/guest.ld $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) \
		-Wl,-Tnonsecure/guest.ld \
		-Wl,--defsym=GUEST_FLASH_ORIGIN=$(WT_GUEST0_FLASH_ORIGIN) \
		-Wl,--defsym=GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_LENGTH) \
		-Wl,--defsym=GUEST_RAM_ORIGIN=0x20000000 \
		-Wl,--defsym=GUEST_RAM_LENGTH=$(WT_GUEST_RAM_SIZE) \
		-Wl,--gc-sections \
		-o $@ $(ALL_GUEST0_OBJS) $(SECURE_CMSE_IMPLIB) -lgcc

$(GUEST1_ELF): $(ALL_GUEST1_OBJS) $(SECURE_CMSE_IMPLIB) nonsecure/guest.ld $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) \
		-Wl,-Tnonsecure/guest.ld \
		-Wl,--defsym=GUEST_FLASH_ORIGIN=$(WT_GUEST1_FLASH_ORIGIN) \
		-Wl,--defsym=GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_LENGTH) \
		-Wl,--defsym=GUEST_RAM_ORIGIN=0x20008000 \
		-Wl,--defsym=GUEST_RAM_LENGTH=$(WT_GUEST_RAM_SIZE) \
		-Wl,--gc-sections \
		-o $@ $(ALL_GUEST1_OBJS) $(SECURE_CMSE_IMPLIB) -lgcc

else

$(GUEST0_ELF): $(NONSECURE_SRCS) nonsecure/guest.ld $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) \
		-DWT_GUEST_ID=0u \
		-Wl,-Tnonsecure/guest.ld \
		-Wl,--defsym=GUEST_FLASH_ORIGIN=$(WT_GUEST0_FLASH_ORIGIN) \
		-Wl,--defsym=GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_LENGTH) \
		-Wl,--defsym=GUEST_RAM_ORIGIN=0x20000000 \
		-Wl,--defsym=GUEST_RAM_LENGTH=$(WT_GUEST_RAM_SIZE) \
		-o $@ $(NONSECURE_SRCS) -lgcc

$(GUEST1_ELF): $(NONSECURE_SRCS) nonsecure/guest.ld $(BUILD_MODE_STAMP) | $(BUILD_DIR)
	$(CC) $(NONSECURE_CFLAGS) \
		-DWT_GUEST_ID=1u \
		-Wl,-Tnonsecure/guest.ld \
		-Wl,--defsym=GUEST_FLASH_ORIGIN=$(WT_GUEST1_FLASH_ORIGIN) \
		-Wl,--defsym=GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_LENGTH) \
		-Wl,--defsym=GUEST_RAM_ORIGIN=0x20008000 \
		-Wl,--defsym=GUEST_RAM_LENGTH=$(WT_GUEST_RAM_SIZE) \
		-o $@ $(NONSECURE_SRCS) -lgcc

endif  # WT_ENGINE_HSM=1

$(GUEST0_BIN): $(GUEST0_ELF)
	$(OBJCOPY) -O binary $< $@

$(GUEST1_BIN): $(GUEST1_ELF)
	$(OBJCOPY) -O binary $< $@

run:
	$(MAKE) all
	$(M33MU) --cpu stm32h563 --timeout $(EMU_TIMEOUT) --quit-on-faults \
		$(SECURE_BIN) $(GUEST0_BIN):$(WT_GUEST0_EMU_OFFSET) $(GUEST1_BIN):$(WT_GUEST1_EMU_OFFSET)

run-tui:
	$(MAKE) all
	$(M33MU) --cpu stm32h563 --tui --timeout $(EMU_TIMEOUT) \
		$(SECURE_BIN) $(GUEST0_BIN):$(WT_GUEST0_EMU_OFFSET) $(GUEST1_BIN):$(WT_GUEST1_EMU_OFFSET)

run-uarts:
	WT_ENGINE_HSM=$(WT_ENGINE_HSM) WT_MAX_GUESTS=$(WT_MAX_GUESTS) WT_CO_STACK_SIZE=$(WT_CO_STACK_SIZE) WT_WOLFCRYPT_SP_ASM=$(WT_WOLFCRYPT_SP_ASM) WT_WOLFCRYPT_ARMASM=$(WT_WOLFCRYPT_ARMASM) WT_WOLFCRYPT_STM32_HASH=$(WT_WOLFCRYPT_STM32_HASH) WT_SHARED_UART=$(WT_SHARED_UART) WT_GUEST0_FLASH_ORIGIN=$(WT_GUEST0_FLASH_ORIGIN) WT_GUEST1_FLASH_ORIGIN=$(WT_GUEST1_FLASH_ORIGIN) WT_GUEST_FLASH_SIZE=$(WT_GUEST_FLASH_SIZE) WT_GUEST_FLASH_LENGTH=$(WT_GUEST_FLASH_LENGTH) WT_GUEST_RAM_SIZE=$(WT_GUEST_RAM_SIZE) WT_BENCH_MIN_RUNTIME_SEC=$(WT_BENCH_MIN_RUNTIME_SEC) WT_GUEST0_EMU_OFFSET=$(WT_GUEST0_EMU_OFFSET) WT_GUEST1_EMU_OFFSET=$(WT_GUEST1_EMU_OFFSET) EMU_TIMEOUT=$(EMU_TIMEOUT) M33MU="$(M33MU)" ./run_dual_uart_test.sh

run-hsm:
	$(MAKE) WT_ENGINE_HSM=1 run

run-hsm-uarts:
	$(MAKE) WT_ENGINE_HSM=1 run-uarts

clean:
	rm -rf $(BUILD_DIR)
