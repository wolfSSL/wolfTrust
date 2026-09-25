# Bare-metal Non-secure guest0 for the MIMXRT700-EVK. Builds the wolfTrust
# Secure image (and its CMSE import library) through the top-level Makefile,
# then links guest0 against that import library so the WolfTrust_FFM_* veneers
# resolve. Flashing and signing are driven by tests/target/run_rt700_hardware.sh.
TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size

ROOT := ../../..
TARGET ?= mimxrt700
ARCH ?= armv8m

BUILD ?= build
TOP_BUILD_DIR := $(ROOT)/build
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o

# The same guest links into both Non-secure windows (port/mimxrt700/memory_map.h);
# the monitor refuses to start unless every configured guest has an image.
GUEST0_FLASH_ORIGIN ?= 0x28080000
GUEST0_FLASH_LENGTH ?= 0x00080000
GUEST0_RAM_ORIGIN ?= 0x20100000
GUEST0_RAM_LENGTH ?= 0x00040000
GUEST1_FLASH_ORIGIN ?= 0x28100000
GUEST1_FLASH_LENGTH ?= 0x00040000
GUEST1_RAM_ORIGIN ?= 0x20140000
GUEST1_RAM_LENGTH ?= 0x00040000

CFLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only -ffreestanding \
    -fno-builtin -nostdlib -Os -g -Wall -Wextra \
    -ffunction-sections -fdata-sections -mno-unaligned-access \
    -I$(ROOT)/include

# WT_AHBSC_PROBE=1 builds guest0's isolation probe: it stores into guest1's RAM
# window, which the per-dispatch SAU window keeps Secure while guest0 runs.
# guest1 carries no probe; it is the peer that must keep running.
WT_AHBSC_PROBE ?= 0
GUEST0_CFLAGS := -DGUEST_NAME=\"guest0\"
GUEST1_CFLAGS := -DGUEST_NAME=\"guest1\"
ifeq ($(WT_AHBSC_PROBE),1)
GUEST0_CFLAGS += -DWT_AHBSC_PROBE -DGUEST_PROBE_ADDR=0x20170000u \
    -DGUEST_PROBE_VALUE=0xDEADBEEFu
endif
# WT_GUEST_FAULT_PROBE=1 makes guest0 read Secure RAM on every launch, so the
# monitor spends its restart budget and quarantines it (restart).
WT_GUEST_FAULT_PROBE ?= 0
ifeq ($(WT_GUEST_FAULT_PROBE),1)
GUEST0_CFLAGS += -DWT_GUEST_FAULT_PROBE -DGUEST_FAULT_ADDR=0x30188000u
endif

CLIENT_OBJ := $(BUILD)/psa_ffm_client.o

all: $(BUILD)/guest0.bin $(BUILD)/guest1.bin

$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) ARCH=$(ARCH) TARGET=$(TARGET) TOOLPREFIX=$(TOOLPREFIX) \
	    WT_ATTEST_COSE=0 build/secure_cmse_implib.o

$(BUILD)/guest0.o: guest0.c | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST0_CFLAGS) -c -o $@ $<

$(BUILD)/guest1.o: guest0.c | $(BUILD)
	$(CC) $(CFLAGS) $(GUEST1_CFLAGS) -c -o $@ $<

$(BUILD)/psa_ffm_client.o: $(ROOT)/src/client/psa_ffm_client.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/guest0.elf: $(BUILD)/guest0.o $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) guest0.ld | $(BUILD)
	$(CC) $(CFLAGS) \
	    -Wl,-Tguest0.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(GUEST0_FLASH_ORIGIN) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(GUEST0_FLASH_LENGTH) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(GUEST0_RAM_ORIGIN) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(GUEST0_RAM_LENGTH) \
	    -Wl,--gc-sections \
	    -o $@ $(BUILD)/guest0.o $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $@

$(BUILD)/guest1.elf: $(BUILD)/guest1.o $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) guest0.ld | $(BUILD)
	$(CC) $(CFLAGS) \
	    -Wl,-Tguest0.ld \
	    -Wl,--defsym=GUEST_FLASH_ORIGIN=$(GUEST1_FLASH_ORIGIN) \
	    -Wl,--defsym=GUEST_FLASH_LENGTH=$(GUEST1_FLASH_LENGTH) \
	    -Wl,--defsym=GUEST_RAM_ORIGIN=$(GUEST1_RAM_ORIGIN) \
	    -Wl,--defsym=GUEST_RAM_LENGTH=$(GUEST1_RAM_LENGTH) \
	    -Wl,--gc-sections \
	    -o $@ $(BUILD)/guest1.o $(CLIENT_OBJ) $(SECURE_CMSE_IMPLIB) -lgcc
	$(SIZE) $@

$(BUILD)/%.bin: $(BUILD)/%.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean FORCE
FORCE:
