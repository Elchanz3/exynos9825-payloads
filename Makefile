CROSS_COMPILE ?= aarch64-linux-gnu-

CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump

BUILD_DIR := build
PAYLOADS  := houston_marker dump_bootrom boot_nonsecure_probe \
	nonsecure_transition_probe usb_receive_probe usb_receive_direct_probe \
	usb_receive_event_probe usb_event_repair_probe usb_receive_armed_probe \
	usb_out_state_probe usb_out_cancel_probe usb_receive_rearmed_probe \
	epbl_receive_probe epbl_state_probe epbl_header_probe relocation_probe \
	relocation_fetch_probe relocation_fetch_control_probe \
	relocation_fetch_noic_probe icache_maintenance_probe icache_target_probe

CPPFLAGS := -Iinclude
ASFLAGS  := -ffreestanding -fno-pic -fno-pie -march=armv8-a
LDFLAGS  := -nostdlib -nostartfiles -static -no-pie \
	-Wl,--build-id=none -Wl,-z,max-page-size=0x1000 \
	-Wl,-T,arch/arm64/payload.ld

COMMON_OBJ := $(BUILD_DIR)/common/dwc3_ep1.o
ELFS       := $(PAYLOADS:%=$(BUILD_DIR)/%.elf)
BINS       := $(PAYLOADS:%=$(BUILD_DIR)/%.bin)
DISASMS    := $(PAYLOADS:%=$(BUILD_DIR)/%.disasm)

.SECONDARY: $(ELFS) $(BUILD_DIR)/payloads/houston_marker.o \
	$(BUILD_DIR)/payloads/dump_bootrom.o \
	$(BUILD_DIR)/payloads/boot_nonsecure_probe.o \
	$(BUILD_DIR)/payloads/nonsecure_transition_probe.o \
	$(BUILD_DIR)/payloads/usb_receive_probe.o \
	$(BUILD_DIR)/payloads/usb_receive_direct_probe.o \
	$(BUILD_DIR)/payloads/usb_receive_event_probe.o \
	$(BUILD_DIR)/payloads/usb_event_repair_probe.o \
	$(BUILD_DIR)/payloads/usb_receive_armed_probe.o \
	$(BUILD_DIR)/payloads/usb_out_state_probe.o \
	$(BUILD_DIR)/payloads/usb_out_cancel_probe.o \
	$(BUILD_DIR)/payloads/usb_receive_rearmed_probe.o \
	$(BUILD_DIR)/payloads/epbl_receive_probe.o \
	$(BUILD_DIR)/payloads/epbl_state_probe.o \
	$(BUILD_DIR)/payloads/epbl_header_probe.o \
	$(BUILD_DIR)/payloads/relocation_probe.o \
	$(BUILD_DIR)/payloads/relocation_fetch_probe.o \
	$(BUILD_DIR)/payloads/relocation_fetch_control_probe.o \
	$(BUILD_DIR)/payloads/relocation_fetch_noic_probe.o \
	$(BUILD_DIR)/payloads/icache_maintenance_probe.o \
	$(BUILD_DIR)/payloads/icache_target_probe.o $(COMMON_OBJ)

.PHONY: all clean disasm verify

all: $(BINS)

disasm: $(DISASMS)

verify: all
	@python3 tools/verify_payloads.py $(ELFS)

$(BUILD_DIR)/common/%.o: common/%.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/payloads/%.o: payloads/%.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/payloads/dump_bootrom.o: payloads/Exynos9825_dump_bootrom.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/payloads/relocation_fetch_control_probe.o: \
	payloads/relocation_fetch_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DRELOCATION_FETCH_CONTROL -c $< -o $@

$(BUILD_DIR)/payloads/relocation_fetch_noic_probe.o: \
	payloads/relocation_fetch_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DRELOCATION_FETCH_NOIC -c $< -o $@

$(BUILD_DIR)/houston_marker.elf: $(BUILD_DIR)/payloads/houston_marker.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/dump_bootrom.elf: $(BUILD_DIR)/payloads/dump_bootrom.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/boot_nonsecure_probe.elf: \
	$(BUILD_DIR)/payloads/boot_nonsecure_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/nonsecure_transition_probe.elf: \
	$(BUILD_DIR)/payloads/nonsecure_transition_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_receive_probe.elf: \
	$(BUILD_DIR)/payloads/usb_receive_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_receive_direct_probe.elf: \
	$(BUILD_DIR)/payloads/usb_receive_direct_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_receive_event_probe.elf: \
	$(BUILD_DIR)/payloads/usb_receive_event_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_event_repair_probe.elf: \
	$(BUILD_DIR)/payloads/usb_event_repair_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_receive_armed_probe.elf: \
	$(BUILD_DIR)/payloads/usb_receive_armed_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_out_state_probe.elf: \
	$(BUILD_DIR)/payloads/usb_out_state_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_out_cancel_probe.elf: \
	$(BUILD_DIR)/payloads/usb_out_cancel_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/usb_receive_rearmed_probe.elf: \
	$(BUILD_DIR)/payloads/usb_receive_rearmed_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_receive_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_receive_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_state_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_state_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_header_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_header_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/relocation_probe.elf: \
	$(BUILD_DIR)/payloads/relocation_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/relocation_fetch_probe.elf: \
	$(BUILD_DIR)/payloads/relocation_fetch_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/relocation_fetch_control_probe.elf: \
	$(BUILD_DIR)/payloads/relocation_fetch_control_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/relocation_fetch_noic_probe.elf: \
	$(BUILD_DIR)/payloads/relocation_fetch_noic_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/icache_maintenance_probe.elf: \
	$(BUILD_DIR)/payloads/icache_maintenance_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/icache_target_probe.elf: \
	$(BUILD_DIR)/payloads/icache_target_probe.o \
	$(COMMON_OBJ) arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD_DIR)/%.disasm: $(BUILD_DIR)/%.elf
	$(OBJDUMP) -d $< > $@

clean:
	rm -rf $(BUILD_DIR)
