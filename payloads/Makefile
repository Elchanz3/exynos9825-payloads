CROSS_COMPILE ?= aarch64-linux-gnu-

CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump

TARGET := Exynos9825_dump_bootrom

.PHONY: all clean disasm

all: $(TARGET).bin

$(TARGET).elf: $(TARGET).S
	$(CC) -nostdlib -Wl,--build-id=none -o $@ $<

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary -j .text $< $@

disasm: $(TARGET).bin
	$(OBJDUMP) -D -b binary -m aarch64 $(TARGET).bin

clean:
	rm -f $(TARGET).elf $(TARGET).bin
