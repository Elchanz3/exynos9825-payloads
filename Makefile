CROSS_COMPILE ?= aarch64-linux-gnu-

CC      := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump

BUILD_DIR := build
PAYLOADS  := houston_marker dump_bootrom boot_nonsecure_probe \
	nonsecure_transition_probe usb_receive_probe usb_receive_direct_probe \
	usb_receive_event_probe usb_event_repair_probe usb_receive_armed_probe \
	usb_out_state_probe usb_out_cancel_probe usb_receive_rearmed_probe \
	epbl_receive_probe epbl_state_probe epbl_header_probe \
	epbl_header_noic_probe epbl_header_staged_probe epbl_verify_staged_probe \
	epbl_postload_staged_probe epbl_entry_staged_probe epbl_mmio_staged_probe \
	epbl_mmio_trap_staged_probe epbl_mmio_trap_noic_staged_probe \
	epbl_abort_context_staged_probe epbl_cold_context_staged_probe \
	epbl_dump_fwbl1_probe epbl_bypass_probe epbl_verify_diag_probe epbl_bootstate_probe epbl_sboot_noverify_probe \
	epbl_fwbl1_boundary_staged_probe \
	epbl_dispatch_staged_probe \
	relocation_probe \
	relocation_fetch_probe relocation_fetch_control_probe \
	relocation_fetch_noic_probe icache_maintenance_probe icache_target_probe \
	icache_disable_relocated_probe

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
	$(BUILD_DIR)/payloads/epbl_header_noic_probe.o \
	$(BUILD_DIR)/payloads/epbl_header_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_verify_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_postload_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_entry_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_mmio_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_mmio_trap_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_mmio_trap_noic_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_abort_context_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_cold_context_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_dump_fwbl1_probe.o \
	$(BUILD_DIR)/payloads/epbl_bypass_probe.o \
	$(BUILD_DIR)/payloads/epbl_verify_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_bootstate_probe.o \
	$(BUILD_DIR)/payloads/epbl_sboot_noverify_probe.o \
	$(BUILD_DIR)/payloads/epbl_fwbl1_boundary_staged_probe.o \
	$(BUILD_DIR)/payloads/epbl_dispatch_staged_probe.o \
	$(BUILD_DIR)/payloads/relocation_probe.o \
	$(BUILD_DIR)/payloads/relocation_fetch_probe.o \
	$(BUILD_DIR)/payloads/relocation_fetch_control_probe.o \
	$(BUILD_DIR)/payloads/relocation_fetch_noic_probe.o \
	$(BUILD_DIR)/payloads/icache_maintenance_probe.o \
	$(BUILD_DIR)/payloads/icache_target_probe.o \
	$(BUILD_DIR)/payloads/icache_disable_relocated_probe.o $(COMMON_OBJ)

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

$(BUILD_DIR)/payloads/epbl_header_noic_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_HEADER_NOIC -c $< -o $@

$(BUILD_DIR)/payloads/epbl_header_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_HEADER_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_verify_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_VERIFY_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_postload_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_POSTLOAD_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_entry_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_ENTRY_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_mmio_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_MMIO_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_mmio_trap_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_MMIO_TRAP_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_mmio_trap_noic_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_MMIO_TRAP_STAGED \
		-DEPBL_DISABLE_ICACHE -c $< -o $@

$(BUILD_DIR)/payloads/epbl_abort_context_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_ABORT_CONTEXT_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_cold_context_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED \
		-DEPBL_DISABLE_ICACHE -c $< -o $@

$(BUILD_DIR)/payloads/epbl_dump_fwbl1_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED \
		-DEPBL_DISABLE_ICACHE -DEPBL_DUMP_FWBL1 -c $< -o $@

$(BUILD_DIR)/payloads/epbl_bypass_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED \
		-DEPBL_DISABLE_ICACHE -DEPBL_PATCH_VERIFY -c $< -o $@

$(BUILD_DIR)/payloads/epbl_verify_diag_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED \
		-DEPBL_DISABLE_ICACHE -DEPBL_VERIFY_DIAG -c $< -o $@

$(BUILD_DIR)/payloads/epbl_bootstate_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_DUMP_FWBL1 -DPROBE_DUMP_BASE=0x02020000 -DPROBE_DUMP_SIZE=0x00000200 -c $< -o $@

$(BUILD_DIR)/payloads/epbl_sboot_noverify_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_SBOOT_NOVERIFY -c $< -o $@

$(BUILD_DIR)/payloads/epbl_fwbl1_boundary_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_FWBL1_BOUNDARY_STAGED -c $< -o $@

$(BUILD_DIR)/payloads/epbl_dispatch_staged_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_DISPATCH_STAGED -c $< -o $@

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

$(BUILD_DIR)/epbl_header_noic_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_header_noic_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_header_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_header_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_verify_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_verify_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_postload_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_postload_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_entry_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_entry_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_mmio_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_mmio_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_mmio_trap_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_mmio_trap_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_mmio_trap_noic_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_mmio_trap_noic_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_abort_context_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_abort_context_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_cold_context_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_cold_context_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_dump_fwbl1_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_dump_fwbl1_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_bypass_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_bypass_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_verify_diag_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_verify_diag_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_bootstate_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_bootstate_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_sboot_noverify_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_sboot_noverify_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_fwbl1_boundary_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_fwbl1_boundary_staged_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_dispatch_staged_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_dispatch_staged_probe.o \
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

$(BUILD_DIR)/icache_disable_relocated_probe.elf: \
	$(BUILD_DIR)/payloads/icache_disable_relocated_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	$(OBJCOPY) -O binary $< $@

$(BUILD_DIR)/%.disasm: $(BUILD_DIR)/%.elf
	$(OBJDUMP) -d $< > $@

clean:
	rm -rf $(BUILD_DIR)
