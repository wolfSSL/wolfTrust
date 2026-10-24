# Bare-metal Non-secure guest0 for the FRDM-MCXN947. Builds the wolfTrust
# Secure image (and its CMSE import library) through the top-level Makefile,
# then links guest0 against that import library so the WolfTrust_FFM_* veneers
# resolve. Image assembly and the emulator boot are driven by
# tests/target/run_mcxn947_m33mu.sh.
TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size

ROOT := ../../..
TARGET ?= mcxn947
ARCH ?= armv8m

BUILD ?= build
# The Secure image's build directory, relative to the repository root; the
# hardware runner points both at its own tree so an emulator run can share
# the checkout.
WT_BUILD_DIR ?= build
TOP_BUILD_DIR := $(ROOT)/$(WT_BUILD_DIR)
SECURE_CMSE_IMPLIB := $(TOP_BUILD_DIR)/secure_cmse_implib.o

# The same guest links into both Non-secure windows (port/mcxn947/memory_map.h);
# the monitor refuses to start unless every configured guest has an image.
GUEST0_FLASH_ORIGIN ?= 0x00080000
GUEST0_FLASH_LENGTH ?= 0x00080000
GUEST0_RAM_ORIGIN ?= 0x20000000
GUEST0_RAM_LENGTH ?= 0x00018000
GUEST1_FLASH_ORIGIN ?= 0x00100000
GUEST1_FLASH_LENGTH ?= 0x00040000
GUEST1_RAM_ORIGIN ?= 0x20018000
GUEST1_RAM_LENGTH ?= 0x00018000

CFLAGS := -mcpu=cortex-m33 -mthumb -mgeneral-regs-only -ffreestanding \
    -fno-builtin -nostdlib -Os -g -Wall -Wextra \
    -ffunction-sections -fdata-sections -mno-unaligned-access \
    -I$(ROOT)/include

# WT_SAU_PROBE=1 builds guest0's isolation probe: it stores into guest1's RAM
# window, which the per-dispatch SAU window keeps Secure while guest0 runs.
# guest1 carries no probe; it is the peer that must keep running.
WT_SAU_PROBE ?= 0
GUEST0_CFLAGS := -DGUEST_NAME=\"guest0\"
GUEST1_CFLAGS := -DGUEST_NAME=\"guest1\"
ifeq ($(WT_SAU_PROBE),1)
GUEST0_CFLAGS += -DWT_SAU_PROBE -DGUEST_PROBE_ADDR=0x20028000u \
    -DGUEST_PROBE_VALUE=0xDEADBEEFu
endif
# WT_PERIPH_NEG_PROBE=1 makes guest0, its MPU off, read the SPM's ELS through
# the Non-secure alias; the SAU must refuse it on every launch (periphneg).
WT_PERIPH_NEG_PROBE ?= 0
ifeq ($(WT_PERIPH_NEG_PROBE),1)
GUEST0_CFLAGS += -DWT_PERIPH_NEG_PROBE -DGUEST_PERIPH_ADDR=0x40054000u
endif
# WT_GUEST_FAULT_PROBE=1 makes guest0 read Secure RAM on every launch, so the
# monitor spends its restart budget and quarantines it (restart).
WT_GUEST_FAULT_PROBE ?= 0
ifeq ($(WT_GUEST_FAULT_PROBE),1)
GUEST0_CFLAGS += -DWT_GUEST_FAULT_PROBE -DGUEST_FAULT_ADDR=0x30031000u
endif

CLIENT_OBJ := $(BUILD)/psa_ffm_client.o

all: $(BUILD)/guest0.bin $(BUILD)/guest1.bin

# The image's build mode comes from the environment; forcing one here would
# relink the image in another mode and drop the wolftrust.bin the runners sign.
$(SECURE_CMSE_IMPLIB): FORCE
	$(MAKE) -C $(ROOT) ARCH=$(ARCH) TARGET=$(TARGET) TOOLPREFIX=$(TOOLPREFIX) \
	    BUILD_DIR=$(WT_BUILD_DIR) $(WT_BUILD_DIR)/secure_cmse_implib.o

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
