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
	epbl_minform_normal_probe epbl_android_boot_probe epbl_inform_dump_probe \
	epbl_custom_key_hmac_probe epbl_custom_key_efuse_probe \
	epbl_boot_ufs_probe epbl_key_state_probe epbl_boot_ufs_chain_probe epbl_boot_ufs_plain_probe epbl_boot_ufs_silent_probe epbl_boot_ufs_native_probe epbl_boot_ufs_native_load_diag_probe epbl_boot_ufs_native_postload_diag_probe epbl_boot_ufs_native_timing_diag_probe epbl_boot_ufs_native_flag_diag_probe epbl_boot_ufs_native_cold_diag_probe epbl_boot_ufs_native_force_cold_probe epbl_boot_ufs_native_diag_probe epbl_boot_ufs_native_triple_probe epbl_boot_ufs_native_keysafe_probe epbl_boot_ufs_native_triple_stock_probe epbl_boot_ufs_native_triple_restore_probe epbl_key_dump_probe \
	epbl_pmu_trace_probe epbl_retention_mark_probe epbl_retention_read_probe \
	ubstage_hello ubstage_download_marker \
	epbl_fwbl1_boundary_staged_probe \
	epbl_dispatch_staged_probe \
	relocation_probe \
	relocation_fetch_probe relocation_fetch_control_probe \
	relocation_fetch_noic_probe icache_maintenance_probe icache_target_probe \
	icache_disable_relocated_probe

CPPFLAGS := -Iinclude
ASFLAGS  := -ffreestanding -fno-pic -fno-pie -march=armv8-a
LDFLAGS_BASE := -nostdlib -nostartfiles -static -no-pie \
	-Wl,--build-id=none -Wl,-z,max-page-size=0x1000
LDFLAGS  := $(LDFLAGS_BASE) -Wl,-T,arch/arm64/payload.ld
# A replacement boot-chain stage is not a Houston payload, so it must not
# inherit payload.ld: that would link it into the iRAM probe region and apply
# the DWC3 TRB ceiling assert, neither of which applies to a DRAM stage.
LDFLAGS_STAGE := $(LDFLAGS_BASE) -Wl,-T,arch/arm64/stage.ld

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
	$(BUILD_DIR)/payloads/epbl_minform_normal_probe.o \
	$(BUILD_DIR)/payloads/epbl_inform_dump_probe.o \
	$(BUILD_DIR)/payloads/epbl_pmu_trace_probe.o \
	$(BUILD_DIR)/payloads/epbl_retention_mark_probe.o \
	$(BUILD_DIR)/payloads/epbl_retention_read_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_plain_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_silent_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_load_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_postload_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_timing_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_flag_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_cold_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_force_cold_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_diag_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_keysafe_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_stock_probe.o \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_restore_probe.o \
	$(BUILD_DIR)/payloads/epbl_android_boot_probe.o \
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
	@python3 tools/verify_payloads.py $(filter-out \
		$(BUILD_DIR)/ubstage_hello.elf \
		$(BUILD_DIR)/ubstage_download_marker.elf,$(ELFS))

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

# Dump the PMU INFORM block (0x15860800..+0x100) over EP1 and stop. Those
# registers are in the always-on domain and survive a warm reset, so this reads
# back what the previous boot left there -- which is how
# `sboot_patch.py --diag-secure-payload` reports the secure-payload return code
# from a boot that never reaches a console.
$(BUILD_DIR)/payloads/epbl_inform_dump_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_DUMP_FWBL1 -DPROBE_DUMP_BASE=0x15860800 \
		-DPROBE_DUMP_SIZE=0x00000100 -c $< -o $@

# MINFORM = 'N','N' only: the stock chain with an unmodified sboot, told that
# this boot is an intentional normal boot, so u-boot takes the normal-boot fork
# instead of Download mode. No verify bypass, nothing in sboot changed.
$(BUILD_DIR)/payloads/epbl_minform_normal_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED \
		-DEPBL_DISABLE_ICACHE -DEPBL_MINFORM_NORMAL -c $< -o $@

# The same MINFORM write plus the is_secure_boot bypass, for running a PATCHED
# sboot (tools/sboot_patch.py --normal-boot) that forces the fork itself.
$(BUILD_DIR)/payloads/epbl_android_boot_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED \
		-DEPBL_DISABLE_ICACHE -DEPBL_MINFORM_NORMAL \
		-DEPBL_SBOOT_NOVERIFY -c $< -o $@

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

# Custom secure-boot key: re-point PTR_SECUREBOOT_KEY (0x0202006c) at our own
# 32-byte key so the BootROM verifies our resigned EPBL against it. Deliberately
# WITHOUT EPBL_SBOOT_NOVERIFY: once our ST1 is trusted, the ST2 stages are
# verified against the st2_key_tee embedded in our own EPBL footer and should
# pass legitimately. Two builds because the expected 32-byte form is not yet
# known; see custom_boot_key in payloads/epbl_header_probe.S.
# Storage-load probe: force the boot device to UFS and call the ROM's own load
# function (0xcc68), then report and halt. No key re-point and no boot
# continuation, so it is safe against the stock sboot already on UFS.
# Replacement boot-chain stage, not a Houston payload: position-independent and
# linked with stage.ld rather than payload.ld.
$(BUILD_DIR)/payloads/ubstage_hello.o: payloads/ubstage_hello.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/ubstage_hello.elf: \
	$(BUILD_DIR)/payloads/ubstage_hello.o \
	arch/arm64/stage.ld
	$(CC) $(LDFLAGS_STAGE) $(filter %.o,$^) -o $@

# Entry trampoline injected into an otherwise complete u-boot stage. It writes
# a PMU marker, clears MINFORM so the attached cable selects Download mode, and
# then resumes the original stage at load+4. The installer patches its final
# self-branch to the fixed resume address after choosing the code cave.
$(BUILD_DIR)/payloads/ubstage_download_marker.o: \
	payloads/ubstage_download_marker.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/ubstage_download_marker.elf: \
	$(BUILD_DIR)/payloads/ubstage_download_marker.o \
	arch/arm64/stage.ld
	$(CC) $(LDFLAGS_STAGE) $(filter %.o,$^) -o $@

# Read-only: dump both 32-byte OTP key slots in full.
$(BUILD_DIR)/payloads/epbl_key_dump_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_KEY_DUMP -c $< -o $@

# Read-only: recover persistent PMU checkpoints from the previous UFS boot.
$(BUILD_DIR)/payloads/epbl_pmu_trace_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_PMU_TRACE -c $< -o $@

# Volatile retention calibration. The first probe writes known markers to PMU
# scratch and proven FWBL1-padding iRAM; the second reads them after a fresh EUB
# entry. This establishes which channel can carry a late-stage checkpoint.
$(BUILD_DIR)/payloads/epbl_retention_mark_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_RETENTION_MARK -c $< -o $@

$(BUILD_DIR)/payloads/epbl_retention_read_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_RETENTION_READ -c $< -o $@

# Boot the chain from UFS with our custom key: only the image SOURCE changes,
# everything downstream is the already-proven path. Needs the custom key, or
# the BootROM verifies our ST1 against Samsung's and rejects it.
$(BUILD_DIR)/payloads/epbl_boot_ufs_chain_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_TRACE \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Legacy UFS handoff used by the earlier BL2 -> u-boot diagnostics. Omitting
# EPBL_UFS_TRACE removes the boundary records and saved-context experiments,
# but EPBL_COLD_CONTEXT_STAGED still redirects the EPBL dispatch through
# fwbl1_noic_entry and installs the diagnostic EL3 vector.
$(BUILD_DIR)/payloads/epbl_boot_ufs_plain_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Strict transport control for the same legacy shim handoff. It is identical
# to the plain build except that it performs no EP1 IN transfer after the UFS
# load.
$(BUILD_DIR)/payloads/epbl_boot_ufs_silent_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native UFS handoff. Keep only the cache-safe relocation stager; do not inherit
# EPBL_CONTEXT_STAGED, replace the EPBL dispatch literal, install an EL3 vector,
# enter FWBL1 through a shim, or reconstruct the cold-dispatch registers. The
# I-cache is disabled only for the freshly loaded EPBL entry; authentic FWBL1
# restores its expected state in its own prologue.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native post-load diagnostic. It differs from the silent native handoff only
# by completing the existing UFSLOAD!/UFSMETA! records immediately after the
# BootROM storage loader returns. It installs no FWBL1 or exception hook.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_load_diag_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native post-verification diagnostic. It stays silent through 0xcc68 and the
# key selector, then completes one EUNPOST! record immediately after 0x5b58.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_postload_diag_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_POSTLOAD_DIAGNOSTIC -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native entry-timing diagnostic. It completes one EUNTIME! record after the
# stock 0x18768 helper returns and before 0x16a10 sets the final boot flag.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_timing_diag_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_TIMING_DIAGNOSTIC -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native boot-flag diagnostic. It completes one EUNFLAG! record after the
# stock 0x16a10 helper returns and before the native entry validation.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_flag_diag_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_FLAG_DIAGNOSTIC -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native cold-path diagnostic. It records the original warm/cold gate and
# dispatch state, then changes only the verified EPBL branch to its cold path.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_cold_diag_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_COLD_DIAGNOSTIC -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native force-cold attempt. It deliberately avoids reading 0x15860990 and
# 0x02020128, verifies the authenticated first gate-load instruction, replaces
# it with a direct branch to the original cold loader, and continues natively.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_force_cold_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_FORCE_COLD -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Three identical read-only records at three positions of the same native
# preparation. Separates "which operation closes EP1" from "how far the
# channel survives": every earlier bisect changed the operation and the
# position together. Writes nothing and leaves the EPBL authentic.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_TRIPLE -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Same probe for a board whose BOOTLOADER partition holds the STOCK sboot.
# Without EPBL_CUSTOM_KEY the BootROM keeps its own PTR_SECUREBOOT_KEY, so
# 0x5b58 verifies Samsung's image against Samsung's key and the handoff is a
# completely stock boot. The three records are the only thing added to it.
# native-triple with the custom key parked at PROBE_CUSTOM_KEY_LOW instead of
# inside the relocated worker. One variable against native-triple: where the
# 32 bytes the BootROM verifier dereferences live. A boot says the worker's
# address was being overwritten on the UFS path after our last observation
# point; a black screen says it was not, and clears the idea.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_keysafe_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_TRIPLE -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE \
		-DEPBL_CUSTOM_KEY_LOW -c $< -o $@

$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_stock_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_TRIPLE -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT -c $< -o $@

# Same as the custom-key triple probe, but it puts the BootROM selector's own
# pointer back into 0x0202006c as soon as the verifier has returned. One
# variable: whether anything after the handoff still reads that pointer.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_restore_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_TRIPLE -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT -DEPBL_RESTORE_KEY_PTR \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Native handoff diagnostic. It keeps the same unhooked EPBL/FWBL1 path, sends
# one completed pre-entry snapshot, and catches only an actual EPBL return.
$(BUILD_DIR)/payloads/epbl_boot_ufs_native_diag_probe.o: \
		payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_UFS_NATIVE_HANDOFF \
		-DEPBL_UFS_NATIVE_DIAGNOSTIC -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS_CHAIN -DEPBL_UFS_SILENT \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

# Read-only: report the BootROM key selector's inputs and the pointer it chose.
$(BUILD_DIR)/payloads/epbl_key_state_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_KEY_STATE -c $< -o $@

$(BUILD_DIR)/payloads/epbl_boot_ufs_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_BOOT_UFS -c $< -o $@

$(BUILD_DIR)/payloads/epbl_custom_key_hmac_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_CUSTOM_KEY -c $< -o $@

$(BUILD_DIR)/payloads/epbl_custom_key_efuse_probe.o: \
	payloads/epbl_header_probe.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -DEPBL_COLD_CONTEXT_STAGED -DEPBL_DISABLE_ICACHE \
		-DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE -c $< -o $@

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

$(BUILD_DIR)/epbl_minform_normal_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_minform_normal_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_android_boot_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_android_boot_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_inform_dump_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_inform_dump_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_key_dump_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_key_dump_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_pmu_trace_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_pmu_trace_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_retention_mark_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_retention_mark_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_retention_read_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_retention_read_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_chain_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_chain_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_plain_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_plain_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_silent_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_silent_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_load_diag_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_load_diag_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_postload_diag_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_postload_diag_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_timing_diag_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_timing_diag_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_flag_diag_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_flag_diag_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_cold_diag_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_cold_diag_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_force_cold_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_force_cold_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_triple_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_keysafe_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_keysafe_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_triple_stock_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_stock_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_triple_restore_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_native_triple_restore_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_native_diag_probe.elf: \
		$(BUILD_DIR)/payloads/epbl_boot_ufs_native_diag_probe.o \
		arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_key_state_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_key_state_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_boot_ufs_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_boot_ufs_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_custom_key_hmac_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_custom_key_hmac_probe.o \
	arch/arm64/payload.ld
	$(CC) $(LDFLAGS) $(filter %.o,$^) -o $@

$(BUILD_DIR)/epbl_custom_key_efuse_probe.elf: \
	$(BUILD_DIR)/payloads/epbl_custom_key_efuse_probe.o \
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
