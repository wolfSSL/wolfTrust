# BootROM XIP smoke for the MIMXRT700-EVK: builds smoke.bin linked at the
# XSPI0 MBI offset (flash + 0x4000). Wrapping (FCB + MBI) and flashing are
# done by tests/target/run_rt700_hardware.sh with SPSDK and pyOCD.
TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
OBJCOPY := $(TOOLPREFIX)objcopy
CFLAGS := -mcpu=cortex-m33 -mthumb -Os -ffreestanding -nostdlib -Wall -Wextra
BUILD ?= build

all: $(BUILD)/smoke.bin

$(BUILD)/smoke.elf: smoke.c smoke.ld | $(BUILD)
	$(CC) $(CFLAGS) -T smoke.ld -o $@ smoke.c

$(BUILD)/smoke.bin: $(BUILD)/smoke.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean
