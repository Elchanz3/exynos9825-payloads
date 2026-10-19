#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import hashlib
import os
import struct
import sys
import threading
import time
from pathlib import Path


EL3_MAGIC = b"NSP1EL3!"
NS_PASS_MAGIC = b"NS2PASS!"
NS_FAIL_MAGIC = b"NS2FAIL!"
NS_CHECKPOINTS = {
    b"NS2PRE!!": "before candidate DRAM access",
    b"NS2COPY!": "candidate stub copied and read back",
    b"NS2ERET!": "immediately before ERET",
}
RX_READY_MAGIC = b"RX1RDY!!"
RX_PASS_MAGIC = b"RX1PASS!"
RX_FAIL_MAGIC = b"RX1FAIL!"
RX_EVENT_MAGIC = b"RX1EVT!!"
RX_ARMED_MAGIC = b"RX1ARM!!"
RX_OUT_MAGIC = b"RX1OUT!!"
RX_CANCEL_MAGIC = b"RX1CANC!"
EPBL_READY_MAGIC = b"EPBRDY!!"
EPBL_PASS_MAGIC = b"EPBPASS!"
EPBL_FAIL_MAGIC = b"EPBFAIL!"
EPBL_HEADER_READY_MAGIC = b"EPHRDY!!"
EPBL_HEADER_PASS_MAGIC = b"EPHPASS!"
EPBL_HEADER_FAIL_MAGIC = b"EPHFAIL!"
EPBL_HEADER_NOIC_RELOCATED_MAGIC = b"EPNREL!!"
EPBL_HEADER_NOIC_READY_MAGIC = b"EPNRDY!!"
EPBL_HEADER_NOIC_PASS_MAGIC = b"EPNPASS!"
EPBL_HEADER_NOIC_FAIL_MAGIC = b"EPNFAIL!"
EPBL_HEADER_STAGED_READY_MAGIC = b"EHSRDY!!"
EPBL_HEADER_STAGED_HASH_MAGIC = b"EHSHASH!"
EPBL_HEADER_STAGED_PASS_MAGIC = b"EHSPASS!"
EPBL_HEADER_STAGED_FAIL_MAGIC = b"EHSFAIL!"
EPBL_VERIFY_STAGED_READY_MAGIC = b"EVSRDY!!"
EPBL_VERIFY_STAGED_HASH_MAGIC = b"EVSHASH!"
EPBL_VERIFY_STAGED_PARSED_MAGIC = b"EVSPARSE"
EPBL_VERIFY_STAGED_PASS_MAGIC = b"EVSPASS!"
EPBL_VERIFY_STAGED_FAIL_MAGIC = b"EVSFAIL!"
EPBL_VERIFY_STAGED_VERIFY_FAIL_MAGIC = b"EVVFAIL!"
EPBL_POSTLOAD_STAGED_READY_MAGIC = b"EPLRDY!!"
EPBL_POSTLOAD_STAGED_HASH_MAGIC = b"EPLHASH!"
EPBL_POSTLOAD_STAGED_PARSED_MAGIC = b"EPLPARSE"
EPBL_POSTLOAD_STAGED_VERIFIED_MAGIC = b"EPLVERFY"
EPBL_POSTLOAD_STAGED_PASS_MAGIC = b"EPLPASS!"
EPBL_POSTLOAD_STAGED_FAIL_MAGIC = b"EPLFAIL!"
EPBL_POSTLOAD_STAGED_VERIFY_FAIL_MAGIC = b"EPLVFAIL"
EPBL_POSTLOAD_STAGED_POSTLOAD_FAIL_MAGIC = b"EPLPFAIL"
EPBL_ENTRY_STAGED_READY_MAGIC = b"EPERDY!!"
EPBL_ENTRY_STAGED_HASH_MAGIC = b"EPEHASH!"
EPBL_ENTRY_STAGED_PARSED_MAGIC = b"EPEPARSE"
EPBL_ENTRY_STAGED_VERIFIED_MAGIC = b"EPEVERFY"
EPBL_ENTRY_STAGED_POSTLOAD_MAGIC = b"EPEPOST!"
EPBL_ENTRY_STAGED_PASS_MAGIC = b"EPEPASS!"
EPBL_ENTRY_STAGED_FAIL_MAGIC = b"EPEFAIL!"
EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC = b"EPEVFAIL"
EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC = b"EPEPFAIL"
EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC = b"EPEFFAIL"
EPBL_MMIO_STAGED_READY_MAGIC = b"EPMRDY!!"
EPBL_MMIO_STAGED_PASS_MAGIC = b"EPMPASS!"
EPBL_MMIO_STAGED_FAIL_MAGIC = b"EPMFAIL!"
EPBL_MMIO_STAGED_VERIFY_FAIL_MAGIC = b"EPMVFAIL"
EPBL_MMIO_STAGED_POSTLOAD_FAIL_MAGIC = b"EPMPFAIL"
EPBL_MMIO_STAGED_FINALIZE_FAIL_MAGIC = b"EPMFFAIL"
EPBL_MMIO_TRAP_STAGED_READY_MAGIC = b"EPTRDY!!"
EPBL_MMIO_TRAP_STAGED_PASS_MAGIC = b"EPTPASS!"
EPBL_MMIO_TRAP_STAGED_TRAP_MAGIC = b"EPTTRAP!"
EPBL_MMIO_TRAP_STAGED_FAIL_MAGIC = b"EPTFAIL!"
EPBL_MMIO_TRAP_STAGED_VERIFY_FAIL_MAGIC = b"EPTVFAIL"
EPBL_MMIO_TRAP_STAGED_POSTLOAD_FAIL_MAGIC = b"EPTPFAIL"
EPBL_MMIO_TRAP_STAGED_FINALIZE_FAIL_MAGIC = b"EPTFFAIL"
EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC = b"EPARDY!!"
EPBL_ABORT_CONTEXT_STAGED_PASS_MAGIC = b"EPAPASS!"
EPBL_ABORT_CONTEXT_STAGED_TRAP_MAGIC = b"EPATRAP!"
EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC = b"EPAFAIL!"
EPBL_ABORT_CONTEXT_STAGED_VERIFY_FAIL_MAGIC = b"EPAVFAIL"
EPBL_ABORT_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC = b"EPAPFAIL"
EPBL_ABORT_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC = b"EPAFFAIL"
EPBL_KEY_STATE_MAGIC = b"EKSTATE!"
EPBL_KEY_DUMP_MAGIC = b"KEXDUM!!"
EPBL_PMU_TRACE_MAGIC = b"PMUTRACE"
EPBL_RETENTION_MARK_MAGIC = b"RTNMARK!"
EPBL_RETENTION_READ_MAGIC = b"RTNREAD!"
EPBL_UFS_LIVE_FWBL1_ENTRY_MAGIC = b"UFWENTR!"
EPBL_UFS_LIVE_FWBL1_DECRYPT_MAGIC = b"UFWDECR!"
EPBL_UFS_LIVE_PRE_HANDOFF_MAGIC = b"UFSPRE!!"
EPBL_UFS_LIVE_HANDOFF_MAGIC = b"UFSHAND!"
EPBL_UFS_LIVE_FWBL1_INIT_MAGIC = b"UFWINIT!"
EPBL_UFS_LIVE_FWBL1_LOG1_MAGIC = b"UFWLOG1!"
EPBL_UFS_LIVE_FWBL1_CFG1_MAGIC = b"UFWCFG1!"
EPBL_UFS_LIVE_FWBL1_CFG2_MAGIC = b"UFWCFG2!"
EPBL_UFS_LIVE_FWBL1_EL3_MAGIC = b"UFWEL3!!"
EPBL_UFS_LIVE_FWBL1_MAIN_MAGIC = b"UFWMAIN!"
EPBL_UFS_LIVE_BL2_ENTRY_MAGIC = b"UBL2ENT!"
EPBL_UFS_LIVE_BL2_MISS_MAGIC = b"UBL2MISS"
EPBL_UFS_LIVE_BL2_PRE_MAGIC = b"UBL2PRE!"
EPBL_UFS_LIVE_BL2_CONTEXT_MAGIC = b"UBL2CTX!"
EPBL_BOOT_UFS_LOADED_MAGIC = b"UFSLOAD!"
EPBL_BOOT_UFS_META_MAGIC = b"UFSMETA!"
UBSTAGE_MAGIC = b"UBSTAGE!"
EPBL_BOOT_UFS_PASS_MAGIC = b"EPUPASS!"
EPBL_BOOT_UFS_FAIL_MAGIC = b"EPUFAIL!"
EPBL_UFS_NATIVE_READY_MAGIC = b"EUNRDY!!"
EPBL_UFS_NATIVE_PASS_MAGIC = b"EUNPASS!"
EPBL_UFS_NATIVE_FAIL_MAGIC = b"EUNFAIL!"
EPBL_UFS_NATIVE_VERIFY_FAIL_MAGIC = b"EUNVFAIL"
EPBL_UFS_NATIVE_POSTLOAD_FAIL_MAGIC = b"EUNPFAIL"
EPBL_UFS_NATIVE_FINALIZE_FAIL_MAGIC = b"EUNFFAIL"
EPBL_UFS_NATIVE_PRE_MAGIC = b"EUNPRE!!"
EPBL_UFS_NATIVE_RETURN_MAGIC = b"EUNRET!!"
EPBL_UFS_NATIVE_POSTLOAD_MAGIC = b"EUNPOST!"
EPBL_UFS_NATIVE_TIMING_MAGIC = b"EUNTIME!"
EPBL_UFS_NATIVE_FLAG_MAGIC = b"EUNFLAG!"
EPBL_UFS_NATIVE_COLD_MAGIC = b"EUNCOLD!"
EPBL_UFS_NATIVE_FORCE_MAGIC = b"EUNFORC!"
EPBL_UFS_NATIVE_TRIPLE_MAGICS = (
    b"EUN3REC0", b"EUN3REC1", b"EUN3REC2", b"EUN3REC3",
)
EPBL_COLD_CONTEXT_STAGED_READY_MAGIC = b"EPCRDY!!"
EPBL_COLD_CONTEXT_STAGED_PASS_MAGIC = b"EPCPASS!"
EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC = b"EPCTRAP!"
EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC = b"EPCFAIL!"
EPBL_COLD_CONTEXT_STAGED_VERIFY_FAIL_MAGIC = b"EPCVFAIL"
EPBL_COLD_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC = b"EPCPFAIL"
EPBL_COLD_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC = b"EPCFFAIL"
EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC = b"EPFRDY!!"
EPBL_FWBL1_BOUNDARY_STAGED_PASS_MAGIC = b"EPFPASS!"
EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC = b"EPFTRAP!"
EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC = b"EPFFAIL!"
EPBL_FWBL1_BOUNDARY_STAGED_VERIFY_FAIL_MAGIC = b"EPFVFAIL"
EPBL_FWBL1_BOUNDARY_STAGED_POSTLOAD_FAIL_MAGIC = b"EPFPFAIL"
EPBL_FWBL1_BOUNDARY_STAGED_FINALIZE_FAIL_MAGIC = b"EPFFFAIL"
EPBL_DISPATCH_STAGED_READY_MAGIC = b"EPDRDY!!"
EPBL_DISPATCH_STAGED_PASS_MAGIC = b"EPDPASS!"
EPBL_DISPATCH_STAGED_FAIL_MAGIC = b"EPDFAIL!"
EPBL_DISPATCH_STAGED_VERIFY_FAIL_MAGIC = b"EPDVFAIL"
EPBL_DISPATCH_STAGED_POSTLOAD_FAIL_MAGIC = b"EPDPFAIL"
EPBL_DISPATCH_STAGED_FINALIZE_FAIL_MAGIC = b"EPDFFAIL"
RELOCATION_COPY_MAGIC = b"RELCPY!!"
RELOCATION_PASS_MAGIC = b"RELPASS!"
RELOCATION_FAIL_MAGIC = b"RELFAIL!"
RELOCATION_FETCH_PASS_MAGIC = b"RFXPASS!"
RELOCATION_FETCH_FAIL_MAGIC = b"RFXFAIL!"
RELOCATION_FETCH_CONTROL_PASS_MAGIC = b"RFCPASS!"
RELOCATION_FETCH_CONTROL_FAIL_MAGIC = b"RFCFAIL!"
RELOCATION_FETCH_NOIC_PRE_MAGIC = b"RNCPRE!!"
RELOCATION_FETCH_NOIC_PASS_MAGIC = b"RNCPASS!"
RELOCATION_FETCH_NOIC_FAIL_MAGIC = b"RNCFAIL!"
ICACHE_PRE_MAGIC = b"ICHPRE!!"
ICACHE_PASS_MAGIC = b"ICHPASS!"
ICACHE_FAIL_MAGIC = b"ICHFAIL!"
ICACHE_TARGET_PRE_MAGIC = b"ICTPRE!!"
ICACHE_TARGET_PASS_MAGIC = b"ICTPASS!"
ICACHE_TARGET_FAIL_MAGIC = b"ICTFAIL!"
ICACHE_DISABLE_PRE_MAGIC = b"ICDPRE!!"
ICACHE_DISABLE_PASS_MAGIC = b"ICDPASS!"
EPBL_STATE_MAGICS = {
    b"EPS0IRAM": 0x02020000,
    b"EPS1IRAM": 0x02020050,
    b"EPS2IRAM": 0x020200A0,
    b"EPS3IRAM": 0x020200F0,
}
RX_PATTERN = bytes(range(0x40))
RECORD_SIZE = 0x60
DUMP_MAGIC = b"EPDUMP!!"
USB_CAPTURE_SIZE = 0x4000
EL3_FIELDS = (
    "CurrentEL",
    "SCR_EL3",
    "SCTLR_EL3",
    "TCR_EL3",
    "TTBR0_EL3",
    "MAIR_EL3",
    "HCR_EL2",
    "SCTLR_EL2",
    "ID_AA64PFR0_EL1",
    "VBAR_EL3",
)

NS_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "original SCR_EL3",
    "original VBAR_EL3",
    "CurrentEL",
    "lower x0",
    "lower x1",
)

RX_FIELDS = (
    "status",
    "BootROM return",
    "destination",
    "receive limit",
    "mismatch offset",
    "received bytes 0..7",
    "received bytes 8..15",
    "CurrentEL",
    "software event index",
    "trigger event word",
)

RX_EVENT_FIELDS = (
    "status",
    "software event index after repair",
    "reserved 0",
    "reserved 1",
    "reserved 2",
    "reserved 3",
    "reserved 4",
    "CurrentEL",
    "software event index at entry",
    "trigger event word",
)

RX_OUT_FIELDS = (
    "status",
    "CurrentEL",
    "software event index",
    "transfer workspace base",
    "EP2 maximum packet size",
    "receive completion flag",
    "EP2 direction selector",
    "BootROM TRB buffer low",
    "BootROM TRB size",
    "BootROM TRB control",
)

RX_CANCEL_FIELDS = (
    "status",
    "CurrentEL",
    "transfer workspace base",
    "TRB buffer before",
    "TRB size before",
    "TRB control before",
    "ENDTRANSFER return",
    "TRB buffer after",
    "TRB size after",
    "TRB control after",
)

EPBL_FIELDS = (
    "status",
    "BootROM return",
    "destination",
    "receive limit",
    "computed FNV-1a",
    "expected FNV-1a",
    "first qword",
    "second qword",
    "last qword",
    "CurrentEL",
)

EPBL_HEADER_FIELDS = (
    "status",
    "ENDTRANSFER return",
    "relocation address",
    "EPBL destination",
    "computed raw FNV-1a",
    "header parser return",
    "parsed BL1 size",
    "parsed BL1 checksum",
    "first qword after parse",
    "CurrentEL",
)

EPBL_VERIFY_FIELDS = (
    "status",
    "verification return",
    "security status 0x1000b014",
    "verification selector",
    "boot state 0x02020064",
    "verification status before",
    "verification status after",
    "parsed BL1 size",
    "parsed BL1 checksum",
    "CurrentEL",
)

UBSTAGE_FIELDS = (
    "status",
    "x0 on entry",
    "x1 on entry",
    "x2 on entry",
    "x3 on entry",
    "CurrentEL",
    "SP on entry",
    "where the stage was loaded",
    "unused",
    "unused",
)

EPBL_BOOT_UFS_META_FIELDS = (
    "status",
    "0x02020030 BL1 size",
    "0x02020034 BL1 checksum",
    "0x02020070 status register 0",
    "0x02020074 status register 1",
    "0x0202007c SBC information",
    "0x02020120 (unidentified on 9825)",
    "0x02020124 (unidentified on 9825)",
    "0x02020128 (unidentified on 9825)",
    "CurrentEL",
)

EPBL_BOOT_UFS_LOADED_FIELDS = (
    "status",
    "load return (BootROM 0xcc68), 1 = success",
    "boot state 0x02020064 before",
    "EPBL destination (written by the stager)",
    "loaded num_of_sector",
    "loaded checksum",
    "boot state 0x02020064 after the load",
    "PTR_SECUREBOOT_KEY before our re-point",
    "PMU 0x15860808 packed reboot reason",
    "CurrentEL",
)

EPBL_KEY_DUMP_FIELDS = (
    "status",
    "KEY2 bytes 0x00-0x07",
    "KEY2 bytes 0x08-0x0f",
    "KEY2 bytes 0x10-0x17",
    "KEY2 bytes 0x18-0x1f",
    "KEY  bytes 0x00-0x07",
    "KEY  bytes 0x08-0x0f",
    "KEY  bytes 0x10-0x17",
    "KEY  bytes 0x18-0x1f",
    "CurrentEL",
)

EPBL_PMU_TRACE_FIELDS = (
    "status",
    "PMU scratch 0x15860800 (UFS/u-boot marker)",
    "PMU scratch 0x15860804 (FWBL1/owner marker)",
    "PMU MINFORM 0x15860808",
    "PMU download magic 0x1586080c",
    "PMU scratch 0x15860810 (FWBL1 decrypted)",
    "PMU scratch 0x15860814",
    "PMU scratch 0x15860818",
    "PMU scratch 0x1586081c",
    "CurrentEL",
)

EPBL_RETENTION_FIELDS = (
    "status",
    "PMU scratch 0x15860800",
    "PMU scratch 0x15860804",
    "iRAM scratch 0x02038800",
    "iRAM scratch 0x02038808",
    "PMU MINFORM 0x15860808",
    "PMU download magic 0x1586080c",
    "CurrentEL",
    "iRAM scratch base",
    "reserved",
)

EPBL_UFS_NATIVE_PRE_FIELDS = (
    "status",
    "boot state before storage force",
    "boot state immediately before EPBL",
    "BootROM key-selector return",
    "post-load verifier return",
    "MMIO 0x15860990",
    "PTR_IS_SECUREBOOT 0x020200a8",
    "dispatch state 0x02020128",
    "SCTLR_EL3 before I-cache disable",
    "stack pointer before EPBL",
)

EPBL_UFS_NATIVE_RETURN_FIELDS = (
    "status",
    "EPBL return value x0",
    "boot state after EPBL return",
    "MMIO 0x15860990",
    "iRAM 0x02020120",
    "iRAM 0x02020124",
    "iRAM 0x02020128",
    "PTR_IS_SECUREBOOT 0x020200a8",
    "CurrentEL after EPBL return",
    "SCTLR_EL3 after EPBL return",
)

EPBL_UFS_NATIVE_POSTLOAD_FIELDS = (
    "status",
    "BootROM key-selector return",
    "post-load verifier return",
    "PTR_SECUREBOOT_KEY after custom redirect",
    "post-load state 0x0202007c",
    "post-load timing start 0x02020084",
    "post-load timing end 0x02020088",
    "SEC0 0x10001000",
    "boot state 0x02020064",
    "CurrentEL after post-load verification",
)

EPBL_UFS_NATIVE_TIMING_FIELDS = (
    "status",
    "BootROM key-selector return",
    "post-load verifier return",
    "entry timing delta 0x0202008c",
    "boot flags 0x02020070 before final update",
    "PTR_SECUREBOOT_KEY after custom redirect",
    "EPBL dispatch literal 0x02022098",
    "EPBL first qword at 0x02022010",
    "SCTLR_EL3 after entry-timing helper",
    "CurrentEL after entry-timing helper",
)

EPBL_UFS_NATIVE_FLAG_FIELDS = (
    "status",
    "BootROM key-selector return",
    "post-load verifier return",
    "entry timing delta 0x0202008c",
    "boot flags 0x02020070 after final update",
    "PTR_SECUREBOOT_KEY after custom redirect",
    "EPBL dispatch literal 0x02022098",
    "packed EPBL entry/hook instructions",
    "SCTLR_EL3 after boot-flag helper",
    "CurrentEL after boot-flag helper",
)

EPBL_UFS_NATIVE_COLD_FIELDS = (
    "status",
    "BootROM key-selector return",
    "post-load verifier return",
    "original EPBL warm/cold gate 0x15860990",
    "original EPBL dispatch state 0x02020128",
    "boot flags 0x02020070",
    "original EPBL gate branch at 0x02022028",
    "patched EPBL gate branch at 0x02022028",
    "EPBL dispatch literal 0x02022098",
    "CurrentEL after cold-path override",
)

EPBL_UFS_NATIVE_FORCE_FIELDS = (
    "status",
    "BootROM key-selector return",
    "post-load verifier return",
    "boot flags 0x02020070",
    "original EPBL gate-load instruction at 0x02022018",
    "patched direct-cold branch at 0x02022018",
    "EPBL dispatch literal 0x02022098",
    "EPBL entry instruction at 0x02022010",
    "SCTLR_EL3 after force-cold override",
    "CurrentEL after force-cold override",
)

EPBL_UFS_NATIVE_TRIPLE_FIELDS = (
    "status",
    "BootROM key-selector return",
    "post-load verifier return",
    "EPBL warm/cold gate 0x15860990",
    "EPBL dispatch state 0x02020128",
    "boot flags 0x02020070",
    "packed EPBL entry 0x02022010 / gate-load 0x02022018",
    "packed EPBL gate branch 0x02022028 / dispatch literal 0x02022098",
    "SCTLR_EL3",
    "CurrentEL",
)

EPBL_UFS_LIVE_FIELDS = (
    "status",
    "checkpoint",
    "CurrentEL",
)

EPBL_UFS_BL2_ENTRY_FIELDS = (
    "status",
    "checkpoint",
    "CurrentEL after ERET",
    "saved ELR_EL3",
    "saved SPSR_EL3",
    "saved SCR_EL3",
    "FWBL1 exception-frame SP",
    "redirected ELR_EL3",
    "BL2 first qword",
    "CurrentEL before ERET",
)

EPBL_UFS_BL2_PRE_FIELDS = (
    "status",
    "checkpoint",
    "CurrentEL before context restore",
    "saved ELR_EL3",
    "saved SPSR_EL3",
    "saved SCR_EL3",
    "FWBL1 exception-frame SP",
    "first qword at saved ELR",
    "BL2 first qword",
    "SCTLR_EL3",
)

EPBL_UFS_BL2_CONTEXT_FIELDS = (
    "status",
    "checkpoint",
    "CurrentEL before context restore",
    "saved ELR_EL3",
    "saved SPSR_EL3",
    "saved SCR_EL3",
    "current SP before SPSel switch",
    "SP_EL3 context-frame base",
    "first qword at saved ELR",
    "SPSel before context restore",
)

EPBL_KEY_STATE_FIELDS = (
    "status",
    "SEC0 0x10001000",
    "SEC1 0x1000b014",
    "PTR_SECUREBOOT_KEY 0x0202006c as the ROM left it",
    "OTP KEY  slot 0x10003000 first word",
    "OTP KEY2 slot 0x10003020 first word",
    "selector predicates packed (A..G = bits 0..6)",
    "boot state 0x02020064",
    "verify status 0x02020070",
    "CurrentEL",
)

EPBL_BOOT_UFS_FIELDS = (
    "status",
    "load return (BootROM 0xcc68), 1 = success",
    "boot state 0x02020064 before",
    "boot state 0x02020064 after",
    "boot device code read back, 1 = storage",
    "loaded num_of_sector (stock EPBL = 0x18)",
    "loaded checksum",
    "expected stock EPBL checksum",
    "nonzero bytes in the first 0x40 loaded",
    "CurrentEL",
)

EPBL_POSTLOAD_FIELDS = (
    "status",
    "post-load return",
    "security info before 0x0202007c",
    "security info after 0x0202007c",
    "timing value 0x02020084",
    "timing value 0x02020088",
    "security status 0x10001000",
    "parsed BL1 size",
    "parsed BL1 checksum",
    "CurrentEL",
)

EPBL_ENTRY_FIELDS = (
    "status",
    "post-load return",
    "entry address",
    "hook site",
    "original entry instruction",
    "original hook instruction",
    "patched hook instruction",
    "timing value 0x0202008c",
    "boot flags 0x02020070",
    "CurrentEL",
)

EPBL_MMIO_FIELDS = (
    "status",
    "post-load return",
    "entry address",
    "hook site",
    "MMIO address",
    "MMIO value",
    "original hook instruction",
    "patched hook instruction",
    "boot flags 0x02020070",
    "CurrentEL",
)

EPBL_MMIO_TRAP_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "original VBAR_EL3",
    "MMIO address",
    "hook site",
    "boot flags 0x02020070",
    "CurrentEL",
)

EPBL_ABORT_CONTEXT_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "link register x30",
    "stack pointer",
    "EPBL x8",
    "EPBL x9",
    "EPBL x22",
)

EPBL_FWBL1_BOUNDARY_TRAP_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "link register x30",
    "dispatch literal value",
    "dispatch state 0x02020128",
    "redirect slot address",
    "redirect slot value",
)

EPBL_COLD_CONTEXT_TRAP_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "link register x30",
    "dispatch literal value",
    "dispatch state 0x02020128",
    "shim entry x4",
    "x12 at exception",
)

EPBL_ABORT_CONTEXT_READY_FIELDS = (
    "receive helper return",
    "ENDTRANSFER return",
    "software event index before repair",
    "software event index after arm",
    "EP2 transfer resource index",
    "DWC3 GEVNTCOUNT0",
    "DWC3 DSTS",
    "DWC3 DALEPENA",
    "EP2 OUT DEPCMD",
    "BootROM TRB control",
)

EPBL_CONTEXT_SETUP_FAILURE_FIELDS = (
    "status",
    "last ENDTRANSFER return",
    "software event index before repair",
    "software event index after arm",
    "EP2 transfer resource index",
    "DWC3 GEVNTCOUNT0",
    "DWC3 DSTS",
    "DWC3 DALEPENA",
    "EP2 OUT DEPCMD",
    "BootROM TRB control",
)

EPBL_FWBL1_BOUNDARY_FIELDS = (
    "status",
    "controlled branch target",
    "observed dispatch state 0x02020128",
    "EPBL dispatch literal site",
    "original dispatch literal",
    "patched dispatch literal",
    "redirect slot value",
    "FWBL1 first qword after parse",
    "FWBL1 second qword",
    "CurrentEL",
)

EPBL_DISPATCH_FIELDS = (
    "status",
    "post-load return",
    "dispatch checkpoint",
    "dispatch MMIO 0x15860990",
    "dispatch state 0x02020128",
    "selected target",
    "original checkpoint instruction",
    "patched checkpoint instruction",
    "boot flags 0x02020070",
    "CurrentEL",
)

RELOCATION_FIELDS = (
    "status",
    "source address",
    "target address",
    "copy size",
    "mismatch offset",
    "source qword",
    "target qword",
    "CurrentEL",
    "reserved 0",
    "reserved 1",
)

RELOCATION_FETCH_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "original VBAR_EL3",
    "target address",
    "CurrentEL",
    "target signature",
    "copy size",
)

ICACHE_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "original VBAR_EL3",
    "CurrentEL",
    "SCTLR_EL3",
    "before signature",
    "after signature",
)

ICACHE_TARGET_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "original VBAR_EL3",
    "CurrentEL",
    "SCTLR_EL3",
    "target address",
    "after signature",
)

ICACHE_DISABLE_FIELDS = (
    "status",
    "CurrentEL before",
    "SCTLR_EL3 before",
    "CurrentEL after",
    "relocation address",
    "SCTLR_EL3 after",
    "reserved 0",
    "reserved 1",
    "reserved 2",
    "reserved 3",
)


def decode_record(data: bytes):
    if len(data) != RECORD_SIZE:
        raise ValueError(
            f"record is 0x{len(data):x} bytes, expected 0x{RECORD_SIZE:x}"
        )

    magic, version, size = struct.unpack_from("<8sII", data)
    if version != 1:
        raise ValueError(f"unsupported record version {version}")
    if size != RECORD_SIZE:
        raise ValueError(f"record declares size 0x{size:x}")

    if magic in EPBL_STATE_MAGICS:
        address = EPBL_STATE_MAGICS[magic]
        print(f"magic                = {magic!r}")
        print(f"version              = {version}")
        for offset in range(0, RECORD_SIZE - 0x10, 4):
            value = struct.unpack_from("<I", data, 0x10 + offset)[0]
            print(f"0x{address + offset:08x}           = 0x{value:08x}")
        return True

    if magic == EL3_MAGIC:
        fields = EL3_FIELDS
    elif magic in (NS_PASS_MAGIC, NS_FAIL_MAGIC, *NS_CHECKPOINTS):
        fields = NS_FIELDS
    elif magic in (RX_READY_MAGIC, RX_ARMED_MAGIC, RX_PASS_MAGIC, RX_FAIL_MAGIC):
        fields = RX_FIELDS
    elif magic == RX_EVENT_MAGIC:
        fields = RX_EVENT_FIELDS
    elif magic == RX_OUT_MAGIC:
        fields = RX_OUT_FIELDS
    elif magic == RX_CANCEL_MAGIC:
        fields = RX_CANCEL_FIELDS
    elif magic in (EPBL_READY_MAGIC, EPBL_PASS_MAGIC, EPBL_FAIL_MAGIC):
        fields = EPBL_FIELDS
    elif magic in (
        EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_UFS_NATIVE_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC,
    ) and struct.unpack_from("<Q", data, 0x10)[0] in (0x200, 0x201, 0x202):
        fields = EPBL_CONTEXT_SETUP_FAILURE_FIELDS
    elif magic in (
        EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_READY_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC,
    ):
        fields = EPBL_ABORT_CONTEXT_READY_FIELDS
    elif magic in (
        EPBL_HEADER_READY_MAGIC,
        EPBL_HEADER_PASS_MAGIC,
        EPBL_HEADER_FAIL_MAGIC,
        EPBL_HEADER_NOIC_RELOCATED_MAGIC,
        EPBL_HEADER_NOIC_READY_MAGIC,
        EPBL_HEADER_NOIC_PASS_MAGIC,
        EPBL_HEADER_NOIC_FAIL_MAGIC,
        EPBL_HEADER_STAGED_READY_MAGIC,
        EPBL_HEADER_STAGED_HASH_MAGIC,
        EPBL_HEADER_STAGED_PASS_MAGIC,
        EPBL_HEADER_STAGED_FAIL_MAGIC,
        EPBL_VERIFY_STAGED_READY_MAGIC,
        EPBL_VERIFY_STAGED_HASH_MAGIC,
        EPBL_VERIFY_STAGED_PARSED_MAGIC,
        EPBL_VERIFY_STAGED_FAIL_MAGIC,
        EPBL_POSTLOAD_STAGED_READY_MAGIC,
        EPBL_POSTLOAD_STAGED_HASH_MAGIC,
        EPBL_POSTLOAD_STAGED_PARSED_MAGIC,
        EPBL_POSTLOAD_STAGED_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_READY_MAGIC,
        EPBL_ENTRY_STAGED_HASH_MAGIC,
        EPBL_ENTRY_STAGED_PARSED_MAGIC,
        EPBL_ENTRY_STAGED_FAIL_MAGIC,
        EPBL_MMIO_STAGED_READY_MAGIC,
        EPBL_MMIO_STAGED_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_READY_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_PASS_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_UFS_NATIVE_PASS_MAGIC,
        EPBL_UFS_NATIVE_FAIL_MAGIC,
        EPBL_UFS_NATIVE_VERIFY_FAIL_MAGIC,
        EPBL_UFS_NATIVE_POSTLOAD_FAIL_MAGIC,
        EPBL_UFS_NATIVE_FINALIZE_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_PASS_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_READY_MAGIC,
        EPBL_DISPATCH_STAGED_FAIL_MAGIC,
    ):
        fields = EPBL_HEADER_FIELDS
    elif magic in (
        EPBL_VERIFY_STAGED_PASS_MAGIC,
        EPBL_VERIFY_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_VERIFY_FAIL_MAGIC,
    ):
        fields = EPBL_VERIFY_FIELDS
    elif magic == UBSTAGE_MAGIC:
        fields = UBSTAGE_FIELDS
    elif magic == EPBL_BOOT_UFS_META_MAGIC:
        fields = EPBL_BOOT_UFS_META_FIELDS
    elif magic == EPBL_BOOT_UFS_LOADED_MAGIC:
        fields = EPBL_BOOT_UFS_LOADED_FIELDS
    elif magic == EPBL_UFS_NATIVE_PRE_MAGIC:
        fields = EPBL_UFS_NATIVE_PRE_FIELDS
    elif magic == EPBL_UFS_NATIVE_RETURN_MAGIC:
        fields = EPBL_UFS_NATIVE_RETURN_FIELDS
    elif magic == EPBL_UFS_NATIVE_POSTLOAD_MAGIC:
        fields = EPBL_UFS_NATIVE_POSTLOAD_FIELDS
    elif magic == EPBL_UFS_NATIVE_TIMING_MAGIC:
        fields = EPBL_UFS_NATIVE_TIMING_FIELDS
    elif magic == EPBL_UFS_NATIVE_FLAG_MAGIC:
        fields = EPBL_UFS_NATIVE_FLAG_FIELDS
    elif magic == EPBL_UFS_NATIVE_COLD_MAGIC:
        fields = EPBL_UFS_NATIVE_COLD_FIELDS
    elif magic == EPBL_UFS_NATIVE_FORCE_MAGIC:
        fields = EPBL_UFS_NATIVE_FORCE_FIELDS
    elif magic in EPBL_UFS_NATIVE_TRIPLE_MAGICS:
        fields = EPBL_UFS_NATIVE_TRIPLE_FIELDS
    elif magic == EPBL_KEY_DUMP_MAGIC:
        fields = EPBL_KEY_DUMP_FIELDS
    elif magic == EPBL_PMU_TRACE_MAGIC:
        fields = EPBL_PMU_TRACE_FIELDS
    elif magic in (EPBL_RETENTION_MARK_MAGIC, EPBL_RETENTION_READ_MAGIC):
        fields = EPBL_RETENTION_FIELDS
    elif magic == EPBL_UFS_LIVE_BL2_ENTRY_MAGIC:
        fields = EPBL_UFS_BL2_ENTRY_FIELDS
    elif magic == EPBL_UFS_LIVE_BL2_PRE_MAGIC:
        fields = EPBL_UFS_BL2_PRE_FIELDS
    elif magic == EPBL_UFS_LIVE_BL2_CONTEXT_MAGIC:
        fields = EPBL_UFS_BL2_CONTEXT_FIELDS
    elif magic in (
        EPBL_UFS_LIVE_FWBL1_ENTRY_MAGIC,
        EPBL_UFS_LIVE_FWBL1_DECRYPT_MAGIC,
        EPBL_UFS_LIVE_PRE_HANDOFF_MAGIC,
        EPBL_UFS_LIVE_HANDOFF_MAGIC,
        EPBL_UFS_LIVE_FWBL1_INIT_MAGIC,
        EPBL_UFS_LIVE_FWBL1_LOG1_MAGIC,
        EPBL_UFS_LIVE_FWBL1_CFG1_MAGIC,
        EPBL_UFS_LIVE_FWBL1_CFG2_MAGIC,
        EPBL_UFS_LIVE_FWBL1_EL3_MAGIC,
        EPBL_UFS_LIVE_FWBL1_MAIN_MAGIC,
        EPBL_UFS_LIVE_BL2_MISS_MAGIC,
    ):
        fields = EPBL_UFS_LIVE_FIELDS
    elif magic == EPBL_KEY_STATE_MAGIC:
        fields = EPBL_KEY_STATE_FIELDS
    elif magic in (EPBL_BOOT_UFS_PASS_MAGIC, EPBL_BOOT_UFS_FAIL_MAGIC):
        fields = EPBL_BOOT_UFS_FIELDS
    elif magic in (
        EPBL_POSTLOAD_STAGED_VERIFIED_MAGIC,
        EPBL_POSTLOAD_STAGED_PASS_MAGIC,
        EPBL_POSTLOAD_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_VERIFIED_MAGIC,
        EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_POSTLOAD_FAIL_MAGIC,
    ):
        fields = EPBL_POSTLOAD_FIELDS
    elif magic in (
        EPBL_POSTLOAD_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC,
    ):
        fields = EPBL_VERIFY_FIELDS
    elif magic in (
        EPBL_ENTRY_STAGED_POSTLOAD_MAGIC,
        EPBL_ENTRY_STAGED_PASS_MAGIC,
        EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        fields = EPBL_ENTRY_FIELDS
    elif magic in (
        EPBL_MMIO_STAGED_PASS_MAGIC,
        EPBL_MMIO_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_PASS_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        fields = EPBL_MMIO_FIELDS
    elif magic == EPBL_MMIO_TRAP_STAGED_TRAP_MAGIC:
        fields = EPBL_MMIO_TRAP_FIELDS
    elif magic in (
        EPBL_ABORT_CONTEXT_STAGED_TRAP_MAGIC,
    ):
        fields = EPBL_ABORT_CONTEXT_FIELDS
    elif magic == EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC:
        fields = EPBL_COLD_CONTEXT_TRAP_FIELDS
    elif magic == EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC:
        fields = EPBL_FWBL1_BOUNDARY_TRAP_FIELDS
    elif magic in (
        EPBL_FWBL1_BOUNDARY_STAGED_PASS_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        fields = EPBL_FWBL1_BOUNDARY_FIELDS
    elif magic == EPBL_MMIO_STAGED_VERIFY_FAIL_MAGIC:
        fields = EPBL_VERIFY_FIELDS
    elif magic == EPBL_MMIO_TRAP_STAGED_VERIFY_FAIL_MAGIC:
        fields = EPBL_VERIFY_FIELDS
    elif magic in (
        EPBL_MMIO_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_POSTLOAD_FAIL_MAGIC,
    ):
        fields = EPBL_POSTLOAD_FIELDS
    elif magic in (
        EPBL_DISPATCH_STAGED_PASS_MAGIC,
        EPBL_DISPATCH_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        fields = EPBL_DISPATCH_FIELDS
    elif magic == EPBL_DISPATCH_STAGED_VERIFY_FAIL_MAGIC:
        fields = EPBL_VERIFY_FIELDS
    elif magic == EPBL_DISPATCH_STAGED_POSTLOAD_FAIL_MAGIC:
        fields = EPBL_POSTLOAD_FIELDS
    elif magic in (
        RELOCATION_COPY_MAGIC,
        RELOCATION_PASS_MAGIC,
        RELOCATION_FAIL_MAGIC,
    ):
        fields = RELOCATION_FIELDS
    elif magic in (
        RELOCATION_FETCH_PASS_MAGIC,
        RELOCATION_FETCH_FAIL_MAGIC,
        RELOCATION_FETCH_CONTROL_PASS_MAGIC,
        RELOCATION_FETCH_CONTROL_FAIL_MAGIC,
        RELOCATION_FETCH_NOIC_PRE_MAGIC,
        RELOCATION_FETCH_NOIC_PASS_MAGIC,
        RELOCATION_FETCH_NOIC_FAIL_MAGIC,
    ):
        fields = RELOCATION_FETCH_FIELDS
    elif magic in (ICACHE_PRE_MAGIC, ICACHE_PASS_MAGIC, ICACHE_FAIL_MAGIC):
        fields = ICACHE_FIELDS
    elif magic in (
        ICACHE_TARGET_PRE_MAGIC,
        ICACHE_TARGET_PASS_MAGIC,
        ICACHE_TARGET_FAIL_MAGIC,
    ):
        fields = ICACHE_TARGET_FIELDS
    elif magic in (
        ICACHE_DISABLE_PRE_MAGIC,
        ICACHE_DISABLE_PASS_MAGIC,
    ):
        fields = ICACHE_DISABLE_FIELDS
    else:
        raise ValueError(f"unexpected magic {magic!r}")

    print(f"magic                = {magic!r}")
    print(f"version              = {version}")
    values = []
    for index, name in enumerate(fields):
        value = struct.unpack_from("<Q", data, 0x10 + index * 8)[0]
        values.append(value)
        print(f"{name:20} = 0x{value:016x}")

    if magic == EL3_MAGIC:
        return True

    if magic == UBSTAGE_MAGIC:
        el = values[5] >> 2
        print("  *** our own signed stage ran: the chain loaded, verified and")
        print("      entered code we built and signed with our own keys ***")
        print(f"  loaded at           = 0x{values[7]:x}  (the stage's real load address)")
        print(f"  CurrentEL           = EL{el} (raw 0x{values[5]:x})")
        print(f"  SP on entry         = 0x{values[6]:x}")
        print(f"  x0..x3 on entry     = 0x{values[1]:x} 0x{values[2]:x} "
              f"0x{values[3]:x} 0x{values[4]:x}")
        return None

    if magic == EPBL_BOOT_UFS_META_MAGIC:
        # On 9825 the BL1 header parser (0x17c54) stores the EPBL size and the
        # expected hash through 0x17c44 / 0x17c34, and BOTH write to
        # 0x02020030 / 0x02020034 -- the same pair the BL1 phase uses. There is
        # no separate 0x02020120/0x02020124 here, so do not read the 9830 names
        # onto those slots; they hold unrelated memory and vary run to run.
        size, hash_ = values[1], values[2]
        print(f"  EPBL size   0x02020030 = 0x{size:x} "
              f"{'(= 0x18 * 512, correct)' if size == 0x3000 else '<- not 0x3000'}")
        print(f"  expect hash 0x02020034 = 0x{hash_:08x} "
              "(compare against the flashed epbl.bin's word at +4)")
        print(f"  SBC info    0x0202007c = 0x{values[5]:08x}")
        print(f"  status regs 0x70 / 0x74 = 0x{values[3]:08x} / 0x{values[4]:08x}")
        print("  (the 9830 status-bit names do not map onto 9825: reg0 reads")
        print("   0x10df here, which fits none of them, so they are not decoded)")
        print(f"  slots 0x120/0x124/0x128 = 0x{values[6]:08x} / 0x{values[7]:08x} "
              f"/ 0x{values[8]:08x}  (unidentified on 9825)")
        return True

    if magic == EPBL_BOOT_UFS_LOADED_MAGIC:
        print(f"  UFS load return      = {values[1]} ({'OK' if values[1] == 1 else 'FAILED'})")
        print(f"  boot device nibble   = 0x{values[2]:08x} -> 0x{values[6]:08x} "
              f"({'switched to storage' if (values[6] >> 4) & 0xf == 1 else 'NOT switched'})")
        print(f"  loaded num_of_sector = 0x{values[4]:x} "
              f"({'as expected' if values[4] == 0x18 else 'UNEXPECTED, want 0x18'})")
        print(f"  loaded checksum      = 0x{values[5]:x} "
              f"{'(cleared by the BootROM, normal)' if values[5] == 0 else ''}")
        print(f"  key pointer was      = 0x{values[7]:08x} "
              f"{'(Samsung KEY slot, about to be re-pointed at ours)' if values[7] == 0x10003000 else ''}")
        rr = values[8]
        b0, b1 = rr & 0xFF, (rr >> 8) & 0xFF
        meaning = {0x4E: "'N' -> intentional normal booting (return 1)",
                   0x70: "'p' -> return 0",
                   0x30: "'0' -> the third branch"}.get(b1, "no special case -> default return 1")
        print(f"  reboot reason        = 0x{rr:08x}  byte0=0x{b0:02x} byte1=0x{b1:02x}")
        print(f"  sboot 0x3280 sees    = {meaning}")
        if b0 == 0 and b1 == 0:
            print("  both bytes zero, so 0x3280 takes its cbz branch instead")
        print("  the chain continues from here; any further output comes from")
        print("  sboot itself, and the BootROM USB link goes away with it")
        return None

    if magic == EPBL_UFS_NATIVE_PRE_MAGIC:
        selected_device = (values[2] >> 4) & 0xF
        mmio_path = "warm dispatcher" if values[5] == 1 else "cold initializer"
        icache_enabled = bool(values[8] & (1 << 12))
        valid = values[0] == 1 and selected_device == 1 and values[4] == 1
        print(
            "  boot-device selection = "
            f"device {selected_device} "
            f"({'storage' if selected_device == 1 else 'unexpected'})"
        )
        print(f"  EPBL entry path       = {mmio_path} (MMIO value 0x{values[5]:x})")
        if values[5] == 1:
            print("  dispatcher warning   = 0x02020128 is consumed before the cold path initializes it")
        else:
            print("  dispatcher note      = the cold path should initialize 0x02020128 itself")
        print(f"  PTR_IS_SECUREBOOT    = 0x{values[6]:08x}")
        print(f"  pre-entry dispatch    = 0x{values[7]:08x}")
        print(
            "  EL3 I-cache before cut = "
            f"{'enabled' if icache_enabled else 'disabled'}; "
            "the payload disables it after this record"
        )
        print(f"  native snapshot      = {'PASS' if valid else 'FAIL'}")
        return valid

    if magic == EPBL_UFS_NATIVE_RETURN_MAGIC:
        print("  *** the authentic EPBL returned instead of continuing into FWBL1/BL2 ***")
        print("  return handling      = captured by the diagnostic sentinel; BootROM 0x250 was not used")
        print(f"  return value         = 0x{values[1]:x}")
        print(f"  boot state           = 0x{values[2]:08x}")
        print(f"  MMIO path selector   = 0x{values[3]:08x}")
        print(
            "  iRAM 0x120/124/128   = "
            f"0x{values[4]:08x} / 0x{values[5]:08x} / 0x{values[6]:08x}"
        )
        print("  native EPBL handoff  = FAIL")
        return False

    if magic == EPBL_UFS_NATIVE_POSTLOAD_MAGIC:
        direct_key = 0x02020000 <= values[3] < 0x02040000
        passed = values[0] == 1 and values[2] == 1 and direct_key
        print(f"  key selector return  = 0x{values[1]:x}")
        print(
            f"  post-load verifier   = 0x{values[2]:x} "
            f"({'success' if values[2] == 1 else 'failure'})"
        )
        print(
            f"  verification key ptr = 0x{values[3]:08x} "
            f"({'custom iRAM key' if direct_key else 'unexpected'})"
        )
        print(
            "  timing words          = "
            f"0x{values[5]:08x} -> 0x{values[6]:08x}"
        )
        print(f"  native post-load     = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_UFS_NATIVE_TIMING_MAGIC:
        direct_key = 0x02020000 <= values[5] < 0x02040000
        entry_ok = values[7] & 0xFFFFFFFF == 0x14000002
        dispatch_ok = values[6] == 0x02020128
        passed = (
            values[0] == 1
            and values[1] == 1
            and values[2] == 1
            and direct_key
            and entry_ok
            and dispatch_ok
        )
        print(f"  key selector return  = 0x{values[1]:x}")
        print(f"  post-load verifier   = 0x{values[2]:x}")
        print(f"  entry timing delta   = 0x{values[3]:08x}")
        print(f"  boot flags before set = 0x{values[4]:08x}")
        print(
            f"  verification key ptr = 0x{values[5]:08x} "
            f"({'custom iRAM key' if direct_key else 'unexpected'})"
        )
        print(
            f"  EPBL dispatch literal = 0x{values[6]:08x} "
            f"({'expected' if dispatch_ok else 'unexpected'})"
        )
        print(
            f"  EPBL first instruction = 0x{values[7] & 0xFFFFFFFF:08x} "
            f"({'expected' if entry_ok else 'unexpected'})"
        )
        print(f"  native entry timing  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_UFS_NATIVE_FLAG_MAGIC:
        direct_key = 0x02020000 <= values[5] < 0x02040000
        final_flag = bool(values[4] & 0x00800000)
        dispatch_ok = values[6] == 0x02020128
        entry_insn = values[7] & 0xFFFFFFFF
        hook_insn = values[7] >> 32
        entry_ok = entry_insn == 0x14000002
        hook_ok = hook_insn == 0x580002D4
        passed = (
            values[0] == 1
            and values[1] == 1
            and values[2] == 1
            and final_flag
            and direct_key
            and dispatch_ok
            and entry_ok
            and hook_ok
        )
        print(f"  key selector return  = 0x{values[1]:x}")
        print(f"  post-load verifier   = 0x{values[2]:x}")
        print(f"  entry timing delta   = 0x{values[3]:08x}")
        print(
            f"  boot flags after set = 0x{values[4]:08x} "
            f"({'final bit present' if final_flag else 'final bit missing'})"
        )
        print(
            f"  verification key ptr = 0x{values[5]:08x} "
            f"({'custom iRAM key' if direct_key else 'unexpected'})"
        )
        print(
            f"  EPBL dispatch literal = 0x{values[6]:08x} "
            f"({'expected' if dispatch_ok else 'unexpected'})"
        )
        print(
            f"  EPBL entry/hook      = 0x{entry_insn:08x} / 0x{hook_insn:08x} "
            f"({'expected' if entry_ok and hook_ok else 'unexpected'})"
        )
        print(f"  native boot flag     = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_UFS_NATIVE_COLD_MAGIC:
        gate = values[3] & 0xFFFFFFFF
        state = values[4] & 0xFFFFFFFF
        warm_target = (state + 0x10) & 0xFFFFFFFF
        final_flag = bool(values[5] & 0x00800000)
        original_ok = values[6] == 0x54000041
        patched_ok = values[7] == 0x14000002
        dispatch_ok = values[8] == 0x02020128
        passed = (
            values[0] == 1
            and values[1] == 1
            and values[2] == 1
            and final_flag
            and original_ok
            and patched_ok
            and dispatch_ok
            and values[9] == 0xC
        )
        if gate == 1:
            stock_path = "warm"
        else:
            stock_path = "cold"
        target_kind = (
            "FWBL1 entry"
            if warm_target == 0x02026010
            else "outside expected FWBL1 entry"
        )
        print(f"  original gate value  = 0x{gate:08x} ({stock_path} path)")
        print(f"  original state base  = 0x{state:08x}")
        print(
            f"  original warm target = 0x{warm_target:08x} "
            f"({target_kind})"
        )
        print(
            f"  boot flags           = 0x{values[5]:08x} "
            f"({'final bit present' if final_flag else 'final bit missing'})"
        )
        print(
            f"  gate branch          = 0x{values[6]:08x} -> "
            f"0x{values[7]:08x} "
            f"({'cold override installed' if original_ok and patched_ok else 'unexpected'})"
        )
        print(
            f"  EPBL dispatch literal = 0x{values[8]:08x} "
            f"({'expected' if dispatch_ok else 'unexpected'})"
        )
        print(f"  native cold override = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in EPBL_UFS_NATIVE_TRIPLE_MAGICS:
        position = EPBL_UFS_NATIVE_TRIPLE_MAGICS.index(magic)
        where = {
            0: "after the 0x18768 entry-timing helper, WITHOUT the suspect reads",
            1: "after the 0x18768 entry-timing helper (EUNTIME! position)",
            2: "after the 0x16a10 boot-flag helper (EUNFLAG! position)",
            3: "after the native entry validation (EUNPRE!/EUNCOLD!/EUNFORC! position)",
        }[position]
        baseline = position == 0
        gate = values[3]
        entry_insn = values[6] & 0xFFFFFFFF
        hook_insn = values[6] >> 32
        gate_branch = values[7] & 0xFFFFFFFF
        dispatch = values[7] >> 32
        epbl_intact = (
            entry_insn == 0x14000002
            and hook_insn == 0x580002D4
            and gate_branch == 0x54000041
        )
        passed = (
            values[0] == 1
            and values[1] == 1
            and values[2] == 1
            and (position < 2 or bool(values[5] & 0x00800000))
            and dispatch == 0x02020128
            and epbl_intact
            and values[9] == 0xC
        )
        print(f"  position             = {position} of 3, {where}")
        print(f"  key selector return  = 0x{values[1]:x}")
        print(f"  post-load verifier   = 0x{values[2]:x}")
        if baseline:
            print("  warm/cold gate       = NOT READ (baseline record)")
            print("  dispatch state       = NOT READ (baseline record)")
        else:
            print(
                f"  warm/cold gate       = 0x{gate:08x} "
                f"({'warm path' if gate == 1 else 'cold path'})"
            )
            print(f"  dispatch state       = 0x{values[4]:08x}")
        print(f"  boot flags           = 0x{values[5]:08x}")
        print(
            f"  EPBL entry/gate-load = 0x{entry_insn:08x} / 0x{hook_insn:08x} "
            f"({'authentic' if epbl_intact else 'MODIFIED'})"
        )
        print(f"  EPBL gate branch     = 0x{gate_branch:08x}")
        print(f"  EPBL dispatch literal = 0x{dispatch:08x}")
        print(f"  SCTLR_EL3            = 0x{values[8]:08x}")
        print(f"  triple record {position}      = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_UFS_NATIVE_FORCE_MAGIC:
        final_flag = bool(values[3] & 0x00800000)
        original_ok = values[4] == 0x580002D4
        patched_ok = values[5] == 0x14000006
        dispatch_ok = values[6] == 0x02020128
        entry_ok = values[7] == 0x14000002
        passed = (
            values[0] == 1
            and values[1] == 1
            and values[2] == 1
            and final_flag
            and original_ok
            and patched_ok
            and dispatch_ok
            and entry_ok
            and values[9] == 0xC
        )
        print(
            f"  boot flags           = 0x{values[3]:08x} "
            f"({'final bit present' if final_flag else 'final bit missing'})"
        )
        print(
            f"  gate-load instruction = 0x{values[4]:08x} -> "
            f"0x{values[5]:08x} "
            f"({'direct cold entry installed' if original_ok and patched_ok else 'unexpected'})"
        )
        print(
            f"  EPBL dispatch literal = 0x{values[6]:08x} "
            f"({'expected' if dispatch_ok else 'unexpected'})"
        )
        print(
            f"  EPBL entry instruction = 0x{values[7]:08x} "
            f"({'expected' if entry_ok else 'unexpected'})"
        )
        print("  warm-state MMIO read = SKIPPED")
        print(f"  native force cold    = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_KEY_DUMP_MAGIC:
        key2 = b"".join(values[i].to_bytes(8, "little") for i in range(1, 5))
        key = b"".join(values[i].to_bytes(8, "little") for i in range(5, 9))
        print(f"  KEY2 = {key2.hex()}")
        print(f"  KEY  = {key.hex()}")
        blank = key2 == bytes(32)
        print(f"  KEY2 is {'BLANK - nothing programmed' if blank else 'PROGRAMMED'}")
        expected = os.environ.get("EXPECT_KEY2")
        if expected:
            want = bytes.fromhex(expected)
            match = key2 == want
            print(f"  expected KEY2 = {want.hex()}")
            print(f"  KEY2 matches expected = {'YES' if match else 'NO'}")
            return match
        print("  (set EXPECT_KEY2=<64 hex chars> to compare against a value)")
        return True

    if magic == EPBL_PMU_TRACE_MAGIC:
        if values[1] == 0x31534255 and values[2] == 0x314E574F:
            print("  u-boot entry marker       = REACHED (UBS1)")
            print("  u-boot owner marker       = REACHED (OWN1)")
            print("  trace result          = full u-boot entry trampoline executed")
            return True

        expected = (
            (values[1], 0x31534655, "UFS handoff", "UFS1"),
            (values[2], 0x31425746, "FWBL1 shim entry", "FWB1"),
            (values[5], 0x31445746, "FWBL1 self-decrypt return", "FWD1"),
        )
        reached = []
        for value, marker, label, tag in expected:
            match = value == marker
            print(f"  {label:<25} = {'REACHED' if match else 'marker absent'} "
                  f"(0x{value:08x}, expected {tag})")
            reached.append(match)
        if reached == [True, True, True]:
            print("  trace result          = EPBL entered FWBL1 and FWBL1 returned from self-decrypt")
        elif reached[:2] == [True, True]:
            print("  trace result          = FWB1 present; FWD1 absent or cleared")
        elif reached[0]:
            print("  trace result          = UFS1 present; later markers absent or cleared")
        else:
            print("  trace result          = inconclusive: markers were not written or were cleared")
        return True

    if magic in (EPBL_RETENTION_MARK_MAGIC, EPBL_RETENTION_READ_MAGIC):
        expected_pmu = (0x31434D50, 0x32434D50)
        expected_iram = (0x314C41434D415249, 0x324C41434D415249)
        pmu_retained = tuple(values[1:3]) == expected_pmu
        iram_retained = tuple(values[3:5]) == expected_iram
        phase = "write/readback" if magic == EPBL_RETENTION_MARK_MAGIC else "fresh EUB read"
        print(f"  calibration phase     = {phase}")
        print(f"  PMU marker pair       = {'PRESENT' if pmu_retained else 'ABSENT'}")
        print(f"  iRAM marker pair      = {'PRESENT' if iram_retained else 'ABSENT'}")
        if magic == EPBL_RETENTION_MARK_MAGIC:
            passed = values[0] == 1 and pmu_retained and iram_retained
            print(f"  marker write/readback = {'PASS' if passed else 'FAIL'}")
            return passed
        print(
            "  retention result      = "
            f"PMU={'YES' if pmu_retained else 'NO'}, "
            f"iRAM={'YES' if iram_retained else 'NO'}"
        )
        return True

    if magic in (
        EPBL_UFS_LIVE_FWBL1_ENTRY_MAGIC,
        EPBL_UFS_LIVE_FWBL1_DECRYPT_MAGIC,
        EPBL_UFS_LIVE_PRE_HANDOFF_MAGIC,
        EPBL_UFS_LIVE_HANDOFF_MAGIC,
        EPBL_UFS_LIVE_FWBL1_INIT_MAGIC,
        EPBL_UFS_LIVE_FWBL1_LOG1_MAGIC,
        EPBL_UFS_LIVE_FWBL1_CFG1_MAGIC,
        EPBL_UFS_LIVE_FWBL1_CFG2_MAGIC,
        EPBL_UFS_LIVE_FWBL1_EL3_MAGIC,
        EPBL_UFS_LIVE_FWBL1_MAIN_MAGIC,
        EPBL_UFS_LIVE_BL2_ENTRY_MAGIC,
        EPBL_UFS_LIVE_BL2_MISS_MAGIC,
        EPBL_UFS_LIVE_BL2_PRE_MAGIC,
        EPBL_UFS_LIVE_BL2_CONTEXT_MAGIC,
    ):
        expected_checkpoint, label = {
            EPBL_UFS_LIVE_FWBL1_ENTRY_MAGIC: (1, "FWBL1 shim entry"),
            EPBL_UFS_LIVE_FWBL1_DECRYPT_MAGIC: (
                2,
                "FWBL1 self-decrypt return",
            ),
            EPBL_UFS_LIVE_PRE_HANDOFF_MAGIC: (
                3,
                "before the final EPBL handoff preparation; no DRAM access",
            ),
            EPBL_UFS_LIVE_HANDOFF_MAGIC: (
                4,
                "immediately before the EPBL handoff",
            ),
            EPBL_UFS_LIVE_FWBL1_INIT_MAGIC: (
                5,
                "FWBL1 early platform initialization returned",
            ),
            EPBL_UFS_LIVE_FWBL1_LOG1_MAGIC: (
                6,
                "FWBL1 checkpoint 0x3100 logger returned",
            ),
            EPBL_UFS_LIVE_FWBL1_CFG1_MAGIC: (
                7,
                "FWBL1 core and stack configuration returned",
            ),
            EPBL_UFS_LIVE_FWBL1_CFG2_MAGIC: (
                8,
                "FWBL1 secondary configuration returned",
            ),
            EPBL_UFS_LIVE_FWBL1_EL3_MAGIC: (
                9,
                "FWBL1 EL3 initialization returned",
            ),
            EPBL_UFS_LIVE_FWBL1_MAIN_MAGIC: (
                10,
                "FWBL1 startup completed; entering context restore and ERET",
            ),
            EPBL_UFS_LIVE_BL2_MISS_MAGIC: (
                11,
                "saved ELR_EL3 was not an aligned BL2 address; ERET redirect was not armed",
            ),
            EPBL_UFS_LIVE_BL2_ENTRY_MAGIC: (
                12,
                "FWBL1 ERET executed the BL2 transition trampoline",
            ),
            EPBL_UFS_LIVE_BL2_PRE_MAGIC: (
                13,
                "FWBL1 context frame captured immediately before restore and ERET",
            ),
            EPBL_UFS_LIVE_BL2_CONTEXT_MAGIC: (
                14,
                "FWBL1 SP_EL3 context frame captured before restore and ERET",
            ),
        }[magic]
        if magic == EPBL_UFS_LIVE_BL2_MISS_MAGIC:
            record_valid = (
                values[0] == 1
                and values[1] == expected_checkpoint
                and values[2] == 0xC
            )
            print(f"  live UFS boundary     = {label}")
            print(
                "  mismatch record       = "
                f"{'VALID' if record_valid else 'MALFORMED'}"
            )
            print("  BL2 entry hook        = FAIL")
            return False

        expected_els = (
            (0x4, 0x8, 0xC)
            if magic == EPBL_UFS_LIVE_BL2_ENTRY_MAGIC
            else (0xC,)
        )
        passed = (
            values[0] == 1
            and values[1] == expected_checkpoint
            and values[2] in expected_els
        )
        print(f"  live UFS boundary     = {label}")
        if magic == EPBL_UFS_LIVE_BL2_ENTRY_MAGIC:
            original_elr = values[3]
            redirected_elr = values[7]
            bl2_qword = values[8]
            target_in_bl2 = (
                0x02100000 <= original_elr < 0x02152000
                and original_elr % 4 == 0
            )
            expected_qword = bl2_qword & 0xFFFFFFFF == 0x14000001
            print(
                "  original ERET target  = "
                f"0x{original_elr:016x} "
                f"({'BL2' if target_in_bl2 else 'outside BL2'})"
            )
            print(
                "  BL2 entry word        = "
                f"0x{bl2_qword & 0xffffffff:08x} "
                f"({'expected' if expected_qword else 'unexpected'})"
            )
            print(f"  trampoline target     = 0x{redirected_elr:016x}")
            passed = passed and target_in_bl2 and redirected_elr != 0
        elif magic == EPBL_UFS_LIVE_BL2_PRE_MAGIC:
            saved_elr = values[3]
            saved_spsr = values[4]
            target_qword = values[7]
            bl2_qword = values[8]
            target_in_bl2 = (
                0x02100000 <= saved_elr < 0x02152000
                and saved_elr % 4 == 0
            )
            mode = saved_spsr & 0xF
            mode_name = {
                0x0: "EL0t",
                0x4: "EL1t",
                0x5: "EL1h",
                0x8: "EL2t",
                0x9: "EL2h",
                0xC: "EL3t",
                0xD: "EL3h",
            }.get(mode, f"unknown 0x{mode:x}")
            expected_base = bl2_qword & 0xFFFFFFFF == 0x14000001
            print(
                "  saved ERET target     = "
                f"0x{saved_elr:016x} "
                f"({'BL2' if target_in_bl2 else 'outside BL2'})"
            )
            print(f"  saved execution mode = {mode_name}")
            print(
                "  target first word     = "
                f"0x{target_qword & 0xffffffff:08x}"
            )
            print(
                "  BL2 base word         = "
                f"0x{bl2_qword & 0xffffffff:08x} "
                f"({'expected' if expected_base else 'unexpected'})"
            )
            print("  context modification = NONE")
            passed = passed and target_in_bl2 and expected_base
        elif magic == EPBL_UFS_LIVE_BL2_CONTEXT_MAGIC:
            saved_elr = values[3]
            saved_spsr = values[4]
            current_sp = values[6]
            frame_sp = values[7]
            target_qword = values[8]
            spsel = values[9]
            target_in_bl2 = (
                0x02100000 <= saved_elr < 0x02152000
                and saved_elr % 4 == 0
            )
            mode = saved_spsr & 0xF
            mode_name = {
                0x0: "EL0t",
                0x4: "EL1t",
                0x5: "EL1h",
                0x8: "EL2t",
                0x9: "EL2h",
                0xC: "EL3t",
                0xD: "EL3h",
            }.get(mode, f"unknown 0x{mode:x}")
            target_word_expected = (
                saved_elr != 0x02100000
                or target_qword & 0xFFFFFFFF == 0x14000001
            )
            print(
                "  saved ERET target     = "
                f"0x{saved_elr:016x} "
                f"({'BL2' if target_in_bl2 else 'outside BL2'})"
            )
            print(f"  saved execution mode = {mode_name}")
            print(f"  current SP            = 0x{current_sp:016x}")
            print(f"  actual frame base     = 0x{frame_sp:016x} (SP_EL3)")
            print(f"  SPSel before restore  = 0x{spsel:x}")
            print(
                "  target first word     = "
                f"0x{target_qword & 0xffffffff:08x}"
            )
            print("  context modification = NONE")
            passed = (
                passed
                and target_in_bl2
                and frame_sp != 0
                and frame_sp != current_sp
                and spsel == 0
                and target_word_expected
            )
        print(f"  boundary capture      = {'PASS' if passed else 'FAIL'}")
        return True if passed else False

    if magic == EPBL_KEY_STATE_MAGIC:
        names = "ABCDEFG"
        bits = values[6]
        pred = {n: (bits >> i) & 1 for i, n in enumerate(names)}
        print("  predicates           = "
              + " ".join(f"{n}={pred[n]}" for n in names))
        # Mirror the selector at 0x5780 so the chosen key is named, not guessed.
        if pred["A"] == 0 and pred["B"] == 1:
            chosen, why = 0x0001FAE0, "ROM key table (A==0 and B==1)"
        elif pred["C"] == 1 and pred["D"] == 0:
            chosen, why = 0x10003020, "fused KEY2 slot (C==1 and D==0)"
        elif pred["E"] == 1:
            chosen, why = 0x10003000, "fused KEY slot (E==1)"
        elif pred["F"] == 1 and pred["G"] == 0:
            chosen, why = 0x0001FAE0, "ROM key table (F==1 and G==0)"
        else:
            chosen, why = 0x0001FAE0, "ROM key table (default)"
        print(f"  selector would pick  = 0x{chosen:08x}, {why}")
        print(f"  pointer the ROM left = 0x{values[3]:08x}")
        agree = values[3] == chosen
        print(f"  agreement            = {'OK' if agree else 'MISMATCH - re-read the selector'}")
        if pred["C"] == 1 and pred["D"] == 0:
            print("  => C/D selected KEY2 before the selector tested E (USE_KEY).")
        else:
            print("  => KEY2 requires C==1 and D==0. C/D are likely the")
            print("     USE_KEY2/BAN_KEY2 pair, but that mapping is not yet proven.")
        print(f"  KEY2 slot            = "
              f"{'still blank' if values[5] == 0 else f'0x{values[5]:08x} - already programmed?'}")
        return None if agree else False

    if magic in (EPBL_BOOT_UFS_PASS_MAGIC, EPBL_BOOT_UFS_FAIL_MAGIC):
        # The load is only believable if the BootROM reported success, the
        # storage handler is the one that ran, and what landed at the
        # destination really is the stock EPBL header.
        load_ok = values[1] == 1
        device_ok = values[4] == 1
        # The BootROM zeroes the header checksum before verifying the ST1
        # signature, because sign_st1 writes that field AFTER signing and it
        # lies inside the signed range. So a cleared checksum here is the
        # normal, expected outcome -- not a failure. Confirmed on hardware:
        # the stock EPBL's first 0x40 holds 38 nonzero bytes intact and 34
        # (0x22) with [4:8] cleared, and the device reported 34.
        checksum_intact = values[6] == values[7]
        checksum_cleared = values[6] == 0
        header_ok = values[5] == 0x18 and (checksum_intact or checksum_cleared)
        passed = magic == EPBL_BOOT_UFS_PASS_MAGIC and load_ok and device_ok and header_ok
        print(f"  BootROM load call    = {'OK' if load_ok else 'FAILED'}")
        print(f"  dispatched to        = "
              f"{'storage (code 1)' if device_ok else f'device code {values[4]}'}")
        if values[5] != 0x18:
            header = f"NOT the stock EPBL (num_of_sector 0x{values[5]:x}, expected 0x18)"
        elif checksum_intact:
            header = "stock EPBL, checksum intact"
        elif checksum_cleared:
            header = "stock EPBL, checksum cleared by the BootROM (normal)"
        else:
            header = f"num_of_sector matches but checksum 0x{values[6]:x} is unexpected"
        print(f"  loaded header        = {header}")
        print(f"  nonzero in first 0x40= {values[8]} "
              f"(stock EPBL: 38 intact, 34 with the checksum cleared)")
        print(f"UFS load result      = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic == RELOCATION_COPY_MAGIC:
        passed = (
            values[0] == 1
            and values[2] == 0x02025000
            and values[3] > 0
            and values[4] == 0xFFFFFFFFFFFFFFFF
            and values[7] == 0xC
        )
        print(f"relocation copy      = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic in (RELOCATION_PASS_MAGIC, RELOCATION_FAIL_MAGIC):
        passed = (
            magic == RELOCATION_PASS_MAGIC
            and values[0] == 2
            and values[2] == 0x02025000
            and values[3] > 0
            and values[4] == 0xFFFFFFFFFFFFFFFF
            and values[7] == 0xC
        )
        print(f"relocated execution = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        RELOCATION_FETCH_PASS_MAGIC,
        RELOCATION_FETCH_FAIL_MAGIC,
        RELOCATION_FETCH_CONTROL_PASS_MAGIC,
        RELOCATION_FETCH_CONTROL_FAIL_MAGIC,
        RELOCATION_FETCH_NOIC_PASS_MAGIC,
        RELOCATION_FETCH_NOIC_FAIL_MAGIC,
    ):
        ec = (values[1] >> 26) & 0x3F
        is_noic = magic in (
            RELOCATION_FETCH_NOIC_PASS_MAGIC,
            RELOCATION_FETCH_NOIC_FAIL_MAGIC,
        )
        is_control = is_noic or magic in (
            RELOCATION_FETCH_CONTROL_PASS_MAGIC,
            RELOCATION_FETCH_CONTROL_FAIL_MAGIC,
        )
        expected_magic = (
            RELOCATION_FETCH_NOIC_PASS_MAGIC
            if is_noic
            else (
                RELOCATION_FETCH_CONTROL_PASS_MAGIC
                if is_control
                else RELOCATION_FETCH_PASS_MAGIC
            )
        )
        expected_target = 0x02024000 if is_control else 0x02025000
        expected_signature = (
            0x2143455845434E52
            if is_noic
            else (0x2143455845434652 if is_control else 0x2143455845584652)
        )
        passed = (
            magic == expected_magic
            and values[0] == 1
            and values[1] == 0
            and values[2] == 0
            and values[3] == 0
            and values[4] == 0
            and values[6] == expected_target
            and values[7] == 0xC
            and values[8] == expected_signature
            and values[9] == 8
        )
        print(f"ESR exception class  = 0x{ec:02x}")
        print(f"relocated fetch      = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == RELOCATION_FETCH_NOIC_PRE_MAGIC:
        print(
            "checkpoint            = copied target verified; before branch "
            "without I-cache maintenance"
        )
        return None

    if magic == ICACHE_PRE_MAGIC:
        print("checkpoint            = before EL3 instruction-cache invalidation")
        return None

    if magic in (ICACHE_PASS_MAGIC, ICACHE_FAIL_MAGIC):
        ec = (values[1] >> 26) & 0x3F
        passed = (
            magic == ICACHE_PASS_MAGIC
            and values[0] == 1
            and values[1] == 0
            and values[2] == 0
            and values[3] == 0
            and values[4] == 0
            and values[6] == 0xC
            and values[8] == 0x45524F4645424349
            and values[9] == 0x2152455446414349
        )
        print(f"ESR exception class  = 0x{ec:02x}")
        print(f"I-cache maintenance  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == ICACHE_TARGET_PRE_MAGIC:
        print("checkpoint            = before targeted I-cache invalidation")
        return None

    if magic == ICACHE_DISABLE_PRE_MAGIC:
        print(
            "checkpoint            = "
            "relocated worker running; before SCTLR_EL3.I clear"
        )
        return None

    if magic == ICACHE_DISABLE_PASS_MAGIC:
        before = values[2]
        after = values[5]

        passed = (
            values[0] == 1
            and values[1] == 0xC
            and values[3] == 0xC
            and values[4] == 0x02025000
            and (before & 0x1000) != 0
            and after == (before & ~0x1000)
        )

        print(
            f"I-cache disable       = "
            f"{'PASS' if passed else 'FAIL'}"
        )
        return passed

    if magic in (ICACHE_TARGET_PASS_MAGIC, ICACHE_TARGET_FAIL_MAGIC):
        ec = (values[1] >> 26) & 0x3F
        passed = (
            magic == ICACHE_TARGET_PASS_MAGIC
            and values[0] == 1
            and values[1] == 0
            and values[2] == 0
            and values[3] == 0
            and values[4] == 0
            and values[6] == 0xC
            and values[8] == 0x02024000
            and values[9] == 0x21454E4F44544349
        )
        print(f"ESR exception class  = 0x{ec:02x}")
        print(f"targeted I-cache     = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        RX_READY_MAGIC,
        RX_ARMED_MAGIC,
        EPBL_READY_MAGIC,
        EPBL_HEADER_READY_MAGIC,
        EPBL_HEADER_NOIC_READY_MAGIC,
        EPBL_HEADER_STAGED_READY_MAGIC,
        EPBL_VERIFY_STAGED_READY_MAGIC,
        EPBL_POSTLOAD_STAGED_READY_MAGIC,
        EPBL_ENTRY_STAGED_READY_MAGIC,
        EPBL_MMIO_STAGED_READY_MAGIC,
        EPBL_MMIO_TRAP_STAGED_READY_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_READY_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC,
        EPBL_DISPATCH_STAGED_READY_MAGIC,
    ):
        if magic in (
            EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_READY_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC,
        ):
            depcmd_active = (values[8] & (1 << 10)) != 0
            depcmd_status = (values[8] >> 12) & 0xF
            depcmd_resource = (values[8] >> 16) & 0x7F
            link_state = (values[6] >> 18) & 0xF
            controller_halted = (values[6] & (1 << 22)) != 0
            core_idle = (values[6] & (1 << 23)) != 0
            physical_ep4_enabled = (values[7] & (1 << 4)) != 0
            trb_hardware_owned = (values[9] & 1) != 0
            resource_allocated = (
                values[4] != 0
                and depcmd_resource == values[4]
            )
            arm_state_passed = (
                values[0] == 1
                and values[1] == 1
                and resource_allocated
                and not depcmd_active
                and depcmd_status == 0
                and not controller_halted
                and physical_ep4_enabled
                and trb_hardware_owned
            )
            print(
                "EP2 transfer resource = "
                f"{'ALLOCATED' if resource_allocated else 'MISSING'}"
            )
            print(f"EP2 DEPCMD status    = 0x{depcmd_status:x}")
            print(f"DWC3 USB link state = 0x{link_state:x}")
            print(
                "DWC3 controller halted = "
                f"{'YES' if controller_halted else 'NO'}"
            )
            print(f"DWC3 core idle       = {'YES' if core_idle else 'NO'}")
            print(f"DWC3 pending events  = 0x{values[5]:x} bytes")
            print(
                "physical EP4 enabled = "
                f"{'YES' if physical_ep4_enabled else 'NO'}"
            )
            print(
                "TRB hardware ownership = "
                f"{'YES' if trb_hardware_owned else 'NO'}"
            )
            print(
                "EP2 OUT activation    = "
                f"{'PASS' if arm_state_passed else 'FAIL'}"
            )
        checkpoint = {
            EPBL_DISPATCH_STAGED_READY_MAGIC:
                "staged dispatch probe armed EP2 OUT at the stock EPBL destination",
            EPBL_MMIO_STAGED_READY_MAGIC:
                "staged MMIO probe armed EP2 OUT at the stock EPBL destination",
            EPBL_MMIO_TRAP_STAGED_READY_MAGIC:
                "staged MMIO trap probe armed EP2 OUT at the stock EPBL destination",
            EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC:
                "receive helper returned; post-arm EP2 OUT state captured",
            EPBL_COLD_CONTEXT_STAGED_READY_MAGIC:
                "cold-path probe armed EP2 OUT for the initial EPBL",
            EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC:
                "cold EPBL armed for FWBL1 boundary capture",
            EPBL_ENTRY_STAGED_READY_MAGIC:
                "staged entry probe armed EP2 OUT at the stock EPBL destination",
            EPBL_POSTLOAD_STAGED_READY_MAGIC:
                "staged post-load probe armed EP2 OUT at the stock EPBL destination",
            EPBL_VERIFY_STAGED_READY_MAGIC:
                "staged verifier armed EP2 OUT at the stock EPBL destination",
            EPBL_HEADER_STAGED_READY_MAGIC:
                "staged no-cache worker armed EP2 OUT at the stock EPBL destination",
            EPBL_HEADER_NOIC_READY_MAGIC:
                "relocated no-cache worker armed EP2 OUT at the stock EPBL destination",
            EPBL_HEADER_READY_MAGIC:
                "relocated worker armed EP2 OUT at the stock EPBL destination",
            EPBL_READY_MAGIC: "EP2 OUT armed; waiting for Binary 9 EPBL",
            RX_ARMED_MAGIC: "EP2 OUT armed; waiting for framed transfer",
            RX_READY_MAGIC: "waiting for framed EP2 OUT transfer",
        }[magic]
        print(f"checkpoint            = {checkpoint}")
        return None

    if magic in (
        EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC,
    ) and values[0] in (0x200, 0x201, 0x202):
        setup_failure = {
            0x200: "ENDTRANSFER command failed",
            0x201: "stale EP2 TRB did not clear",
            0x202: "EP2 STARTTRANSFER event timed out after 8 attempts",
        }[values[0]]
        print(f"receive setup failure = {setup_failure}")
        return False

    if magic == RX_EVENT_MAGIC:
        passed = values[0] == 1
        print(f"event repair result  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == RX_OUT_MAGIC:
        passed = values[0] == 1
        print(f"OUT state snapshot   = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == RX_CANCEL_MAGIC:
        passed = (
            values[0] == 1
            and (values[5] & 1) == 1
            and values[6] == 1
            and values[7] == 0
            and values[8] == 0
            and values[9] == 0
        )
        print(f"OUT cancellation     = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (EPBL_PASS_MAGIC, EPBL_FAIL_MAGIC):
        passed = (
            magic == EPBL_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and values[2] == 0x02030000
            and values[3] == 0x3000
            and values[4] == values[5]
            and values[5] == 0xFDFB55E38228E523
            and values[6] == 0xB82C55E700000018
            and values[7] == 0
            and values[8] == 0x17B84398A0C70F76
            and values[9] == 0xC
        )
        print(f"EPBL receive result  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (EPBL_HEADER_PASS_MAGIC, EPBL_HEADER_FAIL_MAGIC):
        passed = (
            magic == EPBL_HEADER_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[5] == 1
            and values[6] == 0x3000
            and values[7] == 0xB82C55E7
            and values[8] == 0x18
            and values[9] == 0xC
        )
        print(f"EPBL header result   = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_HEADER_NOIC_RELOCATED_MAGIC:
        passed = (
            values[0] == 0
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[9] == 0xC
        )
        print(f"relocated checkpoint = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic == EPBL_HEADER_STAGED_HASH_MAGIC:
        passed = (
            values[0] == 0
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[9] == 0xC
        )
        print(f"raw EPBL checkpoint  = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic == EPBL_VERIFY_STAGED_HASH_MAGIC:
        passed = (
            values[0] == 0
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[9] == 0xC
        )
        print(f"raw EPBL checkpoint  = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic in (
        EPBL_POSTLOAD_STAGED_HASH_MAGIC,
        EPBL_ENTRY_STAGED_HASH_MAGIC,
    ):
        passed = (
            values[0] == 0
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[9] == 0xC
        )
        print(f"raw EPBL checkpoint  = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic == EPBL_VERIFY_STAGED_PARSED_MAGIC:
        passed = (
            values[0] == 0
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[5] == 1
            and values[6] == 0x3000
            and values[7] == 0xB82C55E7
            and values[8] == 0x18
            and values[9] == 0xC
        )
        print(f"EPBL parser checkpoint = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic in (
        EPBL_POSTLOAD_STAGED_PARSED_MAGIC,
        EPBL_ENTRY_STAGED_PARSED_MAGIC,
    ):
        passed = (
            values[0] == 0
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[5] == 1
            and values[6] == 0x3000
            and values[7] == 0xB82C55E7
            and values[8] == 0x18
            and values[9] == 0xC
        )
        print(f"EPBL parser checkpoint = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic == EPBL_VERIFY_STAGED_FAIL_MAGIC:
        print("EPBL verification prerequisite = FAIL")
        return False

    if magic == EPBL_POSTLOAD_STAGED_FAIL_MAGIC:
        print("EPBL post-load prerequisite = FAIL")
        return False

    if magic == EPBL_ENTRY_STAGED_FAIL_MAGIC:
        print("EPBL entry prerequisite = FAIL")
        return False

    if magic in (
        EPBL_VERIFY_STAGED_PASS_MAGIC,
        EPBL_VERIFY_STAGED_VERIFY_FAIL_MAGIC,
    ):
        expected_selector = 0 if values[2] & 0x80 else 1
        passed = (
            magic == EPBL_VERIFY_STAGED_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and values[3] == expected_selector
            and (values[4] & 0xF) == 1
            and (values[5] & 0xC0) == 0
            and (values[6] & 0xC0) == 0xC0
            and values[7] == 0x3000
            and values[8] == 0xB82C55E7
            and values[9] == 0xC
        )
        branch = "CryptoCell" if values[3] == 1 else "software SHA-256"
        print(f"verification branch  = {branch}")
        print(f"EPBL verification    = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        EPBL_POSTLOAD_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC,
    ):
        expected_selector = 0 if values[2] & 0x80 else 1
        passed = (
            values[0] == 1
            and values[1] == 1
            and values[3] == expected_selector
            and (values[4] & 0xF) == 1
            and (values[5] & 0xC0) == 0
            and (values[6] & 0xC0) == 0xC0
            and values[7] == 0x3000
            and values[8] == 0xB82C55E7
            and values[9] == 0xC
        )
        print(f"EPBL verification    = {'PASS' if passed else 'FAIL'}")
        return False

    if magic in (
        EPBL_POSTLOAD_STAGED_VERIFIED_MAGIC,
        EPBL_ENTRY_STAGED_VERIFIED_MAGIC,
    ):
        passed = (
            values[0] == 0
            and values[1] == 0
            and values[7] == 0x3000
            and values[8] == 0xB82C55E7
            and values[9] == 0xC
        )
        print(f"verification checkpoint = {'PASS' if passed else 'FAIL'}")
        return None if passed else False

    if magic in (
        EPBL_MMIO_STAGED_FAIL_MAGIC,
        EPBL_MMIO_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_MMIO_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_POSTLOAD_FAIL_MAGIC,
    ):
        print("controlled MMIO read = FAIL")
        return False

    if magic in (
        EPBL_DISPATCH_STAGED_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_POSTLOAD_FAIL_MAGIC,
    ):
        print("controlled dispatch  = FAIL")
        return False

    if magic in (
        EPBL_POSTLOAD_STAGED_PASS_MAGIC,
        EPBL_POSTLOAD_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC,
    ):
        passed = (
            magic == EPBL_POSTLOAD_STAGED_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and values[7] == 0x3000
            and values[8] == 0xB82C55E7
            and values[9] == 0xC
        )
        print(f"EPBL post-load setup = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        EPBL_ENTRY_STAGED_POSTLOAD_MAGIC,
        EPBL_ENTRY_STAGED_PASS_MAGIC,
        EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        branch_immediate = values[6] & 0x03FFFFFF
        if branch_immediate & 0x02000000:
            branch_immediate -= 0x04000000
        branch_target = (values[3] + branch_immediate * 4) & 0xFFFFFFFFFFFFFFFF
        patched_branch = (
            (values[6] & 0xFC000000) == 0x14000000
            and branch_target == 0x020252C4
        )
        checkpoint_passed = (
            values[0] == 0
            and values[1] == 1
            and values[2] == 0x02022010
            and values[3] == 0x02022018
            and values[4] == 0x14000002
            and values[5] == 0x580002D4
            and patched_branch
            and values[7] != 0
            and (values[8] & 0x00800000) != 0
            and values[9] == 0xC
        )
        passed = magic == EPBL_ENTRY_STAGED_PASS_MAGIC and values[0] == 1
        passed = passed and all(
            (
                values[1] == 1,
                values[2] == 0x02022010,
                values[3] == 0x02022018,
                values[4] == 0x14000002,
                values[5] == 0x580002D4,
                patched_branch,
                values[7] != 0,
                (values[8] & 0x00800000) != 0,
                values[9] == 0xC,
            )
        )
        if magic == EPBL_ENTRY_STAGED_POSTLOAD_MAGIC:
            print(f"patched branch target = 0x{branch_target:016x}")
            print(
                "entry checkpoint     = "
                f"{'PASS' if checkpoint_passed else 'FAIL'}"
            )
            return None if checkpoint_passed else False
        print(f"patched branch target = 0x{branch_target:016x}")
        print(f"controlled EPBL entry = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        EPBL_MMIO_STAGED_PASS_MAGIC,
        EPBL_MMIO_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_PASS_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        hook_site = values[3]
        branch_immediate = values[7] & 0x03FFFFFF
        if branch_immediate & 0x02000000:
            branch_immediate -= 0x04000000
        branch_target = (hook_site + branch_immediate * 4) & 0xFFFFFFFFFFFFFFFF
        passed = (
            magic in (
                EPBL_MMIO_STAGED_PASS_MAGIC,
                EPBL_MMIO_TRAP_STAGED_PASS_MAGIC,
            )
            and values[0] == 1
            and values[1] == 1
            and values[2] == 0x02022010
            and hook_site == 0x02022020
            and values[4] == 0x15860990
            and values[6] == 0xD2800035
            and (values[7] & 0xFC000000) == 0x14000000
            and 0x02025000 <= branch_target < 0x02026000
            and (values[8] & 0x00800000) != 0
            and values[9] == 0xC
        )
        print(f"patched branch target = 0x{branch_target:016x}")
        print(f"dispatch MMIO value   = 0x{values[5] & 0xFFFFFFFF:08x}")
        print(f"controlled MMIO read = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == EPBL_MMIO_TRAP_STAGED_TRAP_MAGIC:
        ec = (values[1] >> 26) & 0x3F
        capture_passed = (
            values[0] == 0x107
            and ec in (0x24, 0x25)
            and values[6] == 0x15860990
            and values[7] == 0x02022020
            and (values[8] & 0x00800000) != 0
            and values[9] == 0xC
        )
        targeted_mmio = (
            values[2] == 0x15860990 and values[3] == 0x0202201C
        )
        print(f"ESR exception class  = 0x{ec:02x}")
        print(f"EL3 exception capture = {'PASS' if capture_passed else 'FAIL'}")
        print(f"targeted MMIO fault  = {'YES' if targeted_mmio else 'NO'}")
        return capture_passed

    if magic in (
        EPBL_ABORT_CONTEXT_STAGED_TRAP_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC,
    ):
        ec = (values[1] >> 26) & 0x3F
        il = (values[1] >> 25) & 1
        iss = values[1] & 0x01FFFFFF
        wnr = (iss >> 6) & 1
        dfsc = iss & 0x3F
        elr_in_epbl = 0x02022000 <= values[3] < 0x02025000
        lr_in_epbl = 0x02022000 <= values[5] < 0x02025000
        lr_in_worker = 0x02025000 <= values[5] < 0x02025800
        if magic in (
            EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC,
        ):
            capture_passed = (
                values[0] == 0x108
                and (values[4] & 0xF) == 0xD
                and 0x02022000 <= values[5] < 0x02025800
            )
        else:
            capture_passed = (
                values[0] == 0x108
                and (values[4] & 0xF) == 0xD
                and (values[6] & 0xF) == 0
            )
        print(f"ESR exception class  = 0x{ec:02x}")
        print(f"instruction length   = {32 if il else 16} bits")
        print(f"ELR inside EPBL      = {'YES' if elr_in_epbl else 'NO'}")
        print(f"x30 inside EPBL      = {'YES' if lr_in_epbl else 'NO'}")
        print(
            "x30 inside relocated worker = "
            f"{'YES' if lr_in_worker else 'NO'}"
        )
        if lr_in_epbl:
            print(f"probable EPBL call site = 0x{values[5] - 4:016x}")
        elif lr_in_worker:
            print(f"probable worker call site = 0x{values[5] - 4:016x}")
        if ec in (0x24, 0x25):
            print(f"abort access         = {'write' if wnr else 'read'}")
            print(f"data fault status    = 0x{dfsc:02x}")
        elif ec == 0x22:
            print("exception syndrome   = PC alignment fault")
            if magic == EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC:
                print(
                    "literal redirect retained = "
                    f"{'YES' if values[6] == values[8] else 'NO'}"
                )
            if magic == EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC:
                print(
                    "redirected slot target = "
                    f"0x{(values[9] + 0x10) & 0xffffffffffffffff:016x}"
                )
        elif ec == 0:
            print("exception syndrome   = uncategorized")
        if magic == EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC:
            # Field 8 holds x4 as stored by the first shim instruction.
            if values[8] == 0:
                print("FWBL1 shim reached    = NO (fault before the shim)")
                if values[3] == values[9]:
                    print("ELR equals x12        = YES (stale stager branch)")
            else:
                print("FWBL1 shim reached    = YES")
                print(
                    "shim x4 as expected   = "
                    f"{'YES' if values[8] == 0x02025610 else 'NO'}"
                )
        label = {
            EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC:
                "cold-path context capture",
            EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC:
                "FWBL1-boundary capture",
        }.get(magic, "EPBL context capture")
        print(f"{label:21} = {'PASS' if capture_passed else 'FAIL'}")
        return capture_passed

    if magic in (
        EPBL_FWBL1_BOUNDARY_STAGED_PASS_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        redirected_target = (values[6] + 0x10) & 0xFFFFFFFFFFFFFFFF
        passed = (
            magic == EPBL_FWBL1_BOUNDARY_STAGED_PASS_MAGIC
            and values[0] == 1
            and values[1] == redirected_target
            and values[3] == 0x02022098
            and values[4] == 0x02020128
            and 0x02025000 <= values[5] < 0x02025800
            and values[5] != values[4]
            and values[7] == 0x0000000000000098
            and values[8] == 0x0000000068656164
            and values[9] == 0xC
        )
        print(f"redirected target     = 0x{redirected_target:016x}")
        print(f"FWBL1 boundary       = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        EPBL_ABORT_CONTEXT_STAGED_PASS_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_PASS_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        passed = (
            magic in (
                EPBL_ABORT_CONTEXT_STAGED_PASS_MAGIC,
                EPBL_COLD_CONTEXT_STAGED_PASS_MAGIC,
            )
            and values[0] == 1
        )
        print(f"EPBL execution       = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        EPBL_DISPATCH_STAGED_PASS_MAGIC,
        EPBL_DISPATCH_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        checkpoint = values[2]
        mmio_value = values[3] & 0xFFFFFFFF
        state_value = values[4] & 0xFFFFFFFF
        expected_target = (
            0x02022DF8
            if checkpoint == 0x02022054
            else (state_value + 0x10) & 0xFFFFFFFF
        )
        expected_original = (
            0x14000369 if checkpoint == 0x02022054 else 0xD61F0080
        )
        branch_immediate = values[7] & 0x03FFFFFF
        if branch_immediate & 0x02000000:
            branch_immediate -= 0x04000000
        branch_target = (checkpoint + branch_immediate * 4) & 0xFFFFFFFFFFFFFFFF
        checkpoint_valid = (
            (checkpoint == 0x02022054 and mmio_value != 1)
            or (checkpoint == 0x0202206C and mmio_value == 1)
        )
        passed = (
            magic == EPBL_DISPATCH_STAGED_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and checkpoint_valid
            and values[5] == expected_target
            and values[6] == expected_original
            and (values[7] & 0xFC000000) == 0x14000000
            and 0x02025000 <= branch_target < 0x02026000
            and (values[8] & 0x00800000) != 0
            and values[9] == 0xC
        )
        print(f"patched branch target = 0x{branch_target:016x}")
        print(f"EPBL dispatch path    = {'warm' if checkpoint == 0x0202206C else 'cold'}")
        print(f"controlled dispatch  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (
        EPBL_HEADER_NOIC_PASS_MAGIC,
        EPBL_HEADER_NOIC_FAIL_MAGIC,
        EPBL_HEADER_STAGED_PASS_MAGIC,
        EPBL_HEADER_STAGED_FAIL_MAGIC,
    ):
        passed = (
            magic in (
                EPBL_HEADER_NOIC_PASS_MAGIC,
                EPBL_HEADER_STAGED_PASS_MAGIC,
            )
            and values[0] == 1
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[5] == 1
            and values[6] == 0x3000
            and values[7] == 0xB82C55E7
            and values[8] == 0x18
            and values[9] == 0xC
        )
        print(f"EPBL header result   = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (RX_PASS_MAGIC, RX_FAIL_MAGIC):
        passed = magic == RX_PASS_MAGIC and values[0] == 1 and values[1] == 1
        print(f"receive result       = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in NS_CHECKPOINTS:
        print(f"checkpoint            = {NS_CHECKPOINTS[magic]}")
        return None

    ec = (values[1] >> 26) & 0x3F
    print(f"ESR exception class  = 0x{ec:02x}")
    passed = magic == NS_PASS_MAGIC and values[0] == 4 and ec == 0x17
    print(f"transition result    = {'PASS' if passed else 'FAIL'}")
    return passed


def wait_for_device(usb_core):
    print("Waiting for EUB 04e8:1234...")
    while True:
        device = usb_core.find(idVendor=0x04E8, idProduct=0x1234)
        if device is not None:
            return device
        time.sleep(0.05)


def claim_device(device, usb_core, usb_util) -> None:
    try:
        device.get_active_configuration()
    except usb_core.USBError:
        device.set_configuration()

    try:
        if device.is_kernel_driver_active(0):
            device.detach_kernel_driver(0)
    except (NotImplementedError, usb_core.USBError):
        pass

    usb_util.claim_interface(device, 0)


def find_probe_record(data: bytes):
    header = struct.pack("<II", 1, RECORD_SIZE)

    for offset in range(0, len(data) - RECORD_SIZE + 1):
        magic = data[offset:offset + 8]
        if (
            data[offset + 8:offset + 16] == header
            and all(0x21 <= value <= 0x5A for value in magic)
        ):
            return offset, data[offset:offset + RECORD_SIZE]

    return None


def report_non_probe_usb_data(data: bytes) -> None:
    shown = data[:0x200]
    print(
        "Observed non-probe EP1 IN data: "
        f"size=0x{len(data):x}, SHA-256={hashlib.sha256(data).hexdigest()}",
        file=sys.stderr,
    )
    for offset in range(0, len(shown), 16):
        chunk = shown[offset:offset + 16]
        print(
            f"  {offset:04x}: " + " ".join(f"{value:02x}" for value in chunk),
            file=sys.stderr,
        )
    if len(shown) != len(data):
        print(
            f"  ... 0x{len(data) - len(shown):x} additional bytes omitted",
            file=sys.stderr,
        )


class Ep1ChainReader(threading.Thread):
    """Collect every EP1 IN transfer while the main thread writes stages."""

    def __init__(self, device, usb_core, timing_origin):
        super().__init__(daemon=True)
        self.device = device
        self.usb_core = usb_core
        self.origin = timing_origin or time.monotonic()
        self.stop_event = threading.Event()
        self.chunks = []
        self.error = None

    def run(self):
        while not self.stop_event.is_set():
            try:
                chunk = bytes(
                    self.device.read(0x81, USB_CAPTURE_SIZE, timeout=200)
                )
            except self.usb_core.USBTimeoutError:
                continue
            except self.usb_core.USBError as error:
                self.error = error
                break
            if chunk:
                self.chunks.append((time.monotonic() - self.origin, chunk))

    def finish(self, listen_seconds, *, expected_disconnect=False):
        """Listen a little longer, then report text and any probe records."""
        self.join(listen_seconds)
        self.stop_event.set()
        self.join(1.0)
        records = []
        for elapsed, chunk in self.chunks:
            found = find_probe_record(chunk)
            if found is not None:
                records.append(found[1])
                print(f"[{elapsed:7.3f}s] probe record {found[1][:8]!r}")
                continue
            text = chunk.rstrip(b"\0").decode("ascii", "replace")
            print(f"[{elapsed:7.3f}s] EP1 IN 0x{len(chunk):x}: {text!r}")
        if self.error is not None:
            if expected_disconnect and getattr(self.error, "errno", None) == 19:
                print(
                    "EP1 IN device disconnected after handoff; accepted for "
                    "this silent mode, but this is not proof of downstream "
                    f"boot: {self.error}",
                    file=sys.stderr,
                )
            else:
                print(f"EP1 IN reader stopped: {self.error}", file=sys.stderr)
        return records


def read_probe_record(device, usb_core) -> bytes:
    deadline = time.monotonic() + 5.0

    while time.monotonic() < deadline:
        try:
            chunk = bytes(device.read(0x81, USB_CAPTURE_SIZE, timeout=500))
        except usb_core.USBTimeoutError:
            continue

        if not chunk:
            continue

        found = find_probe_record(chunk)
        if found is not None:
            offset, record = found
            if offset or len(chunk) != RECORD_SIZE:
                if offset:
                    report_non_probe_usb_data(chunk[:offset])
                trailing = chunk[offset + RECORD_SIZE:]
                if trailing:
                    report_non_probe_usb_data(trailing)
            return record

        report_non_probe_usb_data(chunk)

    return b""


def read_probe_records(device, usb_core) -> bytes:
    records = []

    while True:
        record = read_probe_record(device, usb_core)
        if not record:
            break
        if len(record) != RECORD_SIZE:
            raise RuntimeError(
                f"received partial record of 0x{len(record):x} bytes"
            )

        records.append(record)
        magic = record[:8]
        print(f"Received record {len(records)}: {magic!r}")
        if magic in (
            EL3_MAGIC,
            NS_PASS_MAGIC,
            NS_FAIL_MAGIC,
            RX_PASS_MAGIC,
            RX_FAIL_MAGIC,
            RX_EVENT_MAGIC,
            RX_OUT_MAGIC,
            RX_CANCEL_MAGIC,
            EPBL_PASS_MAGIC,
            EPBL_FAIL_MAGIC,
            EPBL_HEADER_PASS_MAGIC,
            EPBL_HEADER_FAIL_MAGIC,
            EPBL_HEADER_NOIC_PASS_MAGIC,
            EPBL_HEADER_NOIC_FAIL_MAGIC,
            EPBL_HEADER_STAGED_PASS_MAGIC,
            EPBL_HEADER_STAGED_FAIL_MAGIC,
            EPBL_VERIFY_STAGED_PASS_MAGIC,
            EPBL_VERIFY_STAGED_FAIL_MAGIC,
            EPBL_VERIFY_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_POSTLOAD_STAGED_PASS_MAGIC,
            EPBL_POSTLOAD_STAGED_FAIL_MAGIC,
            EPBL_POSTLOAD_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_POSTLOAD_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_ENTRY_STAGED_PASS_MAGIC,
            EPBL_ENTRY_STAGED_FAIL_MAGIC,
            EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC,
            EPBL_MMIO_TRAP_STAGED_PASS_MAGIC,
            EPBL_MMIO_TRAP_STAGED_TRAP_MAGIC,
            EPBL_MMIO_TRAP_STAGED_FAIL_MAGIC,
            EPBL_MMIO_TRAP_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_MMIO_TRAP_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_MMIO_TRAP_STAGED_FINALIZE_FAIL_MAGIC,
            EPBL_ABORT_CONTEXT_STAGED_PASS_MAGIC,
            EPBL_ABORT_CONTEXT_STAGED_TRAP_MAGIC,
            EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
            EPBL_ABORT_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_ABORT_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_ABORT_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_PASS_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_COLD_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_PASS_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_VERIFY_FAIL_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_FWBL1_BOUNDARY_STAGED_FINALIZE_FAIL_MAGIC,
            RELOCATION_PASS_MAGIC,
            RELOCATION_FAIL_MAGIC,
            RELOCATION_FETCH_PASS_MAGIC,
            RELOCATION_FETCH_FAIL_MAGIC,
            RELOCATION_FETCH_CONTROL_PASS_MAGIC,
            RELOCATION_FETCH_CONTROL_FAIL_MAGIC,
            RELOCATION_FETCH_NOIC_PASS_MAGIC,
            RELOCATION_FETCH_NOIC_FAIL_MAGIC,
            ICACHE_PASS_MAGIC,
            ICACHE_FAIL_MAGIC,
            ICACHE_TARGET_PASS_MAGIC,
            ICACHE_TARGET_FAIL_MAGIC,
            ICACHE_DISABLE_PASS_MAGIC,
            b"EPS3IRAM",
            # Every one of these is the last thing its payload sends: the
            # read-only probes halt straight after, and the UFS chain hands
            # off to sboot, which takes the USB link away. Without them in
            # this list the loop reads again, that read fails, and the records
            # already in hand are thrown away before being saved or decoded --
            # which is exactly why the key-dump run needed three attempts.
            EPBL_KEY_STATE_MAGIC,
            EPBL_KEY_DUMP_MAGIC,
            EPBL_PMU_TRACE_MAGIC,
            EPBL_RETENTION_MARK_MAGIC,
            EPBL_RETENTION_READ_MAGIC,
            EPBL_UFS_LIVE_BL2_ENTRY_MAGIC,
            EPBL_UFS_LIVE_BL2_MISS_MAGIC,
            EPBL_BOOT_UFS_META_MAGIC,
            UBSTAGE_MAGIC,
            EPBL_BOOT_UFS_PASS_MAGIC,
            EPBL_BOOT_UFS_FAIL_MAGIC,
        ):
            break

    return b"".join(records)


def make_dnw_frame(payload: bytes) -> bytes:
    total = len(payload) + 10
    frame = bytearray(total)
    struct.pack_into("<4sI", frame, 0, b"\x1bDNW", total)
    frame[8:-2] = payload
    struct.pack_into("<H", frame, total - 2, sum(payload) & 0xFFFF)
    return bytes(frame)


def make_binary9_stage_frame(payload: bytes) -> bytes:
    total = len(payload) + 10
    frame = bytearray(total)
    struct.pack_into("<II", frame, 0, 0xFFFFFFFE, total)
    frame[8:-2] = payload
    struct.pack_into("<H", frame, total - 2, sum(payload) & 0xFFFF)
    return bytes(frame)


def load_binary9_epbl(path: Path, allow_unpinned: bool = False) -> bytes:
    transfer = path.read_bytes()
    if len(transfer) != 0x3000:
        raise RuntimeError(
            f"EPBL file is 0x{len(transfer):x} bytes, expected 0x3000"
        )

    digest = hashlib.sha256(transfer).hexdigest()
    expected = "d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d"
    if digest != expected:
        if not allow_unpinned:
            raise RuntimeError(
                f"EPBL SHA-256 is {digest}, expected Binary 9 {expected}"
                "\n(pass --allow-unpinned-stages to send a stage that is not "
                "in the known-image allowlist, e.g. a chain resigned with our "
                "own keys -- the size check still applies)"
            )
        print(f"EPBL: unpinned, SHA-256 {digest}")
    return transfer


BINARY9_FOLLOWUP_STAGES = (
    (
        "FWBL1",
        0x13000,
        "34da240b4f91319d3151c32577c57f308ff2b76d4ad6ae2a6b19de88f15f12ee",
    ),
    (
        "BL2",
        0x52000,
        "f7bb1492737382bb23c8c9511f461fe0b5a5a87d923c5a20573731a4d522aa8c",
    ),
    (
        "sboot",
        0x180000,
        "501ae58a701478345e751db2937f6a8e667ee64f721b2a72063b538213044b87",
    ),
    (
        "EL3 monitor",
        0x40000,
        "b79e2d6c23ec9c5a5aaba7f44c26ffcbad573a002ad01095c20bd14f3817c6c2",
    ),
)

# Accepted non-stock variants, keyed by stage name. The testkey sboot is the
# stock image with the 0x167c SMC query patched to return one.
BINARY9_FOLLOWUP_VARIANTS = {
    "sboot": (
        (
            "sboot testkey",
            "5b93c6d9eda29c40335536e64d9444eaa4188b33d99f162d2874a59d89ad3b0a",
        ),
        (
            "sboot Note10+ modified (stock + 1 byte @0x100000 ^0xAA)",
            "f16a77433ef9b7d4a04491ef31e143a8e3abc7848d42fbbb8acbb8eb32d261aa",
        ),
        (
            "sboot Note10+ sig-flip (stock + 1 byte @0x17ff00 ^0xAA, code intact)",
            "acafb4d9c443f656beb18cc1de761196650eeec788a1dd918ee31d45b9bab65e",
        ),
        (
            "sboot Note10+ meme (CURRENT BINARY string -> 'Sambug EL2 bypassed')",
            "a8e3ef46e41de3b714981fb329c7a5bc744aecea1fab2a621525fc45ce115cfe",
        ),
        (
            "sboot Note10+ eng (have_this_mode->1, etc_development=1)",
            "863a7721dadcb2e9bb2a47c682162f8afc61d2d1c9b71cff391b30c6ec07a27b",
        ),
    ),
}


def load_binary9_followup_stage(
    path: Path, index: int, allow_unpinned: bool = False
):
    if index >= len(BINARY9_FOLLOWUP_STAGES):
        raise RuntimeError("too many --receive-next-file arguments")

    name, expected_size, expected_digest = BINARY9_FOLLOWUP_STAGES[index]
    payload = path.read_bytes()
    if len(payload) != expected_size:
        raise RuntimeError(
            f"{name} file is 0x{len(payload):x} bytes, expected "
            f"0x{expected_size:x}"
        )

    digest = hashlib.sha256(payload).hexdigest()
    for variant_name, variant_digest in BINARY9_FOLLOWUP_VARIANTS.get(
        name, ()
    ):
        if digest == variant_digest:
            return payload, f"{variant_name} (SHA-256 {digest})"
    if digest != expected_digest:
        if not allow_unpinned:
            raise RuntimeError(
                f"{name} SHA-256 is {digest}, expected Binary 9 "
                f"{expected_digest}"
                "\n(pass --allow-unpinned-stages to send a stage that is not "
                "in the known-image allowlist, e.g. a chain resigned with our "
                "own keys -- the size check still applies)"
            )
        return payload, f"{name} unpinned (SHA-256 {digest})"
    return payload, f"Binary 9 {name} (SHA-256 {digest})"


def read_fwbl1_dump(device, usb_core) -> bytes:
    """Read the EPDUMP!! header, then the raw FWBL1 region that follows."""
    header = read_probe_record(device, usb_core)
    if header[:8] != DUMP_MAGIC:
        print(
            f"expected {DUMP_MAGIC!r}, got {header[:8]!r}", file=sys.stderr
        )
        return header
    base = struct.unpack_from("<Q", header, 0x10)[0]
    size = struct.unpack_from("<Q", header, 0x18)[0]
    cur_el = struct.unpack_from("<Q", header, 0x20)[0]
    print(
        f"FWBL1 dump: base=0x{base:08x} size=0x{size:x} CurrentEL=0x{cur_el:x}"
    )
    buf = bytearray()
    deadline = time.monotonic() + 20.0
    while len(buf) < size and time.monotonic() < deadline:
        want = min(USB_CAPTURE_SIZE, size - len(buf))
        try:
            chunk = bytes(device.read(0x81, want, timeout=1000))
        except usb_core.USBTimeoutError:
            continue
        except usb_core.USBError as error:
            print(f"dump read stopped: {error}", file=sys.stderr)
            break
        if chunk:
            buf.extend(chunk)
    print(f"collected 0x{len(buf):x} of 0x{size:x} bytes")
    return header + bytes(buf)


def run_receive_probe(
    device,
    usb_core,
    receive_payload=None,
    receive_frame=None,
    receive_label=None,
    timing_origin=None,
    followup_frames=(),
    dump_mode=False,
) -> bytes:
    records = []

    if receive_payload is not None:
        epbl_frame = receive_frame or make_dnw_frame(receive_payload)
        epbl_label = receive_label or (
            "Binary 9 EPBL (SHA-256 "
            f"{hashlib.sha256(receive_payload).hexdigest()})"
        )
    else:
        epbl_frame = None
        epbl_label = None

    def read_after_checkpoint(marker):
        try:
            return read_probe_record(device, usb_core)
        except usb_core.USBError as error:
            print(
                f"USB read stopped after {marker!r}: {error}; preserving "
                f"{len(records)} record(s)",
                file=sys.stderr,
            )
            return b""

    ready = read_probe_record(device, usb_core)
    if len(ready) != RECORD_SIZE:
        raise RuntimeError(
            f"received 0x{len(ready):x} ready bytes, expected 0x{RECORD_SIZE:x}"
        )

    if ready[:8] == EPBL_HEADER_NOIC_RELOCATED_MAGIC:
        records.append(ready)
        print(f"Received record {len(records)}: {ready[:8]!r}")
        ready = read_after_checkpoint(EPBL_HEADER_NOIC_RELOCATED_MAGIC)
        if len(ready) != RECORD_SIZE:
            print(
                "No complete ready record followed "
                f"{EPBL_HEADER_NOIC_RELOCATED_MAGIC!r}: got 0x{len(ready):x} "
                f"bytes, expected 0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)

    if ready[:8] in (
        RX_FAIL_MAGIC,
        EPBL_FAIL_MAGIC,
        EPBL_HEADER_FAIL_MAGIC,
        EPBL_HEADER_NOIC_FAIL_MAGIC,
        EPBL_HEADER_STAGED_FAIL_MAGIC,
        EPBL_VERIFY_STAGED_FAIL_MAGIC,
        EPBL_POSTLOAD_STAGED_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_FAIL_MAGIC,
        EPBL_MMIO_STAGED_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_FAIL_MAGIC,
    ):
        records.append(ready)
        print(f"Received record {len(records)}: {ready[:8]!r}")
        return b"".join(records)
    if ready[:8] not in (
        RX_READY_MAGIC,
        RX_ARMED_MAGIC,
        EPBL_READY_MAGIC,
        EPBL_HEADER_READY_MAGIC,
        EPBL_HEADER_NOIC_READY_MAGIC,
        EPBL_HEADER_STAGED_READY_MAGIC,
        EPBL_VERIFY_STAGED_READY_MAGIC,
        EPBL_POSTLOAD_STAGED_READY_MAGIC,
        EPBL_ENTRY_STAGED_READY_MAGIC,
        EPBL_MMIO_STAGED_READY_MAGIC,
        EPBL_MMIO_TRAP_STAGED_READY_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_READY_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC,
        EPBL_DISPATCH_STAGED_READY_MAGIC,
    ):
        raise RuntimeError(f"unexpected receive-probe marker {ready[:8]!r}")

    records.append(ready)
    ready_marker = ready[:8]
    ready_elapsed = (
        time.monotonic() - timing_origin
        if timing_origin is not None
        else None
    )
    if ready[:8] in (
        EPBL_READY_MAGIC,
        EPBL_HEADER_READY_MAGIC,
        EPBL_HEADER_NOIC_READY_MAGIC,
        EPBL_HEADER_STAGED_READY_MAGIC,
        EPBL_VERIFY_STAGED_READY_MAGIC,
        EPBL_POSTLOAD_STAGED_READY_MAGIC,
        EPBL_ENTRY_STAGED_READY_MAGIC,
        EPBL_MMIO_STAGED_READY_MAGIC,
        EPBL_MMIO_TRAP_STAGED_READY_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_READY_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_READY_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC,
        EPBL_DISPATCH_STAGED_READY_MAGIC,
    ):
        if receive_payload is None:
            raise RuntimeError("EPBL probe requires --receive-file")
        frame = epbl_frame
        label = epbl_label
        timeout = 10000
    else:
        if receive_payload is not None:
            raise RuntimeError("--receive-file requires the EPBL receive probe")
        frame = make_dnw_frame(RX_PATTERN)
        label = "test pattern"
        timeout = 5000

    try:
        written = device.write(0x02, frame, timeout=timeout)
    except usb_core.USBError as error:
        write_elapsed = (
            time.monotonic() - timing_origin
            if timing_origin is not None
            else None
        )
        print(f"Received record {len(records)}: {ready_marker!r}")
        if ready_elapsed is not None:
            print(
                "USB timing since detection: "
                f"ready={ready_elapsed:.3f}s, write-failed={write_elapsed:.3f}s"
            )
        print(
            f"USB write stopped after {ready_marker!r}: {error}; preserving "
            f"{len(records)} record(s)",
            file=sys.stderr,
        )
        return b"".join(records)
    if written != len(frame):
        print(f"Received record {len(records)}: {ready_marker!r}")
        print(
            f"Short EP2 OUT write after {ready_marker!r}: "
            f"0x{written:x}/0x{len(frame):x}; preserving "
            f"{len(records)} record(s)",
            file=sys.stderr,
        )
        return b"".join(records)
    print(f"Received record {len(records)}: {ready_marker!r}")
    if ready_elapsed is not None:
        write_elapsed = time.monotonic() - timing_origin
        print(
            "USB timing since detection: "
            f"ready={ready_elapsed:.3f}s, write-done={write_elapsed:.3f}s"
        )
    print(f"Sent framed {label}: 0x{written:x} bytes")

    followup_ready_markers = (
        EPBL_COLD_CONTEXT_STAGED_READY_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC,
    )
    if followup_frames and ready_marker not in followup_ready_markers:
        raise RuntimeError(
            "--receive-next-file requires a staged cold-path probe"
        )

    if ready_marker in followup_ready_markers:
        if not followup_frames:
            print(
                "No follow-up Binary 9 stage was supplied; the cold EPBL may "
                "wait for FWBL1",
                file=sys.stderr,
            )
        followup_count = len(followup_frames)
        boundary_count_invalid = (
            ready_marker == EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC
            and followup_count != 1
        )
        cold_count_invalid = (
            ready_marker == EPBL_COLD_CONTEXT_STAGED_READY_MAGIC
            and not 1 <= followup_count <= 4
        )
        if followup_frames and (boundary_count_invalid or cold_count_invalid):
            expected = (
                "exactly one"
                if ready_marker == EPBL_FWBL1_BOUNDARY_STAGED_READY_MAGIC
                else "between one and four"
            )
            raise RuntimeError(
                f"{ready_marker!r} requires {expected} "
                "--receive-next-file argument(s)"
            )
        if (
            ready_marker == EPBL_COLD_CONTEXT_STAGED_READY_MAGIC
            and 0 < followup_count < 4
        ):
            print(
                f"Cold-path diagnostic stops after {followup_count} "
                "follow-up stage(s) and reads EP1 IN immediately"
            )
        # Once FWBL1 runs, each stage prints over EP1 IN and may wait for the
        # host to consume it before arming the next OUT transfer. Drain EP1
        # concurrently so a blocked stage write cannot deadlock that print.
        chain_reader = None
        if followup_count > 1:
            chain_reader = Ep1ChainReader(device, usb_core, timing_origin)
            chain_reader.start()
        for followup_label, followup_frame in followup_frames:
            try:
                followup_written = device.write(
                    0x02,
                    followup_frame,
                    timeout=30000 if chain_reader else 10000,
                )
            except usb_core.USBError as error:
                elapsed = (
                    time.monotonic() - timing_origin
                    if timing_origin is not None
                    else None
                )
                if elapsed is not None:
                    print(
                        "USB timing since detection: "
                        f"follow-up-write-failed={elapsed:.3f}s"
                    )
                print(
                    f"USB write stopped while sending {followup_label}: "
                    f"{error}; preserving {len(records)} record(s)",
                    file=sys.stderr,
                )
                if chain_reader:
                    records.extend(chain_reader.finish(2.0))
                return b"".join(records)
            if followup_written != len(followup_frame):
                print(
                    f"Short EP2 OUT write for {followup_label}: "
                    f"0x{followup_written:x}/0x{len(followup_frame):x}; "
                    f"preserving {len(records)} record(s)",
                    file=sys.stderr,
                )
                return b"".join(records)
            elapsed = (
                time.monotonic() - timing_origin
                if timing_origin is not None
                else None
            )
            timing = f" at {elapsed:.3f}s" if elapsed is not None else ""
            print(
                f"Sent framed {followup_label}: "
                f"0x{followup_written:x} bytes{timing}"
            )
        if chain_reader:
            print("All stages sent; listening on EP1 IN for 15 seconds")
            records.extend(chain_reader.finish(15.0))
            return b"".join(records)

    if dump_mode:
        return read_fwbl1_dump(device, usb_core)

    result = read_after_checkpoint(ready[:8])
    if len(result) != RECORD_SIZE:
        print(
            f"Receive probe stopped after {ready[:8]!r}: got 0x{len(result):x} "
            f"result bytes, expected 0x{RECORD_SIZE:x}",
            file=sys.stderr,
        )
        return b"".join(records)
    if result[:8] not in (
        RX_PASS_MAGIC,
        RX_FAIL_MAGIC,
        EPBL_PASS_MAGIC,
        EPBL_FAIL_MAGIC,
        EPBL_HEADER_PASS_MAGIC,
        EPBL_HEADER_FAIL_MAGIC,
        EPBL_HEADER_NOIC_PASS_MAGIC,
        EPBL_HEADER_NOIC_FAIL_MAGIC,
        EPBL_HEADER_STAGED_HASH_MAGIC,
        EPBL_HEADER_STAGED_PASS_MAGIC,
        EPBL_HEADER_STAGED_FAIL_MAGIC,
        EPBL_VERIFY_STAGED_HASH_MAGIC,
        EPBL_VERIFY_STAGED_FAIL_MAGIC,
        EPBL_POSTLOAD_STAGED_HASH_MAGIC,
        EPBL_POSTLOAD_STAGED_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_HASH_MAGIC,
        EPBL_ENTRY_STAGED_PASS_MAGIC,
        EPBL_ENTRY_STAGED_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_MMIO_STAGED_PASS_MAGIC,
        EPBL_MMIO_STAGED_FAIL_MAGIC,
        EPBL_MMIO_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_MMIO_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_MMIO_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_PASS_MAGIC,
        EPBL_MMIO_TRAP_STAGED_TRAP_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_MMIO_TRAP_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_PASS_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_TRAP_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ABORT_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_PASS_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_TRAP_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_COLD_CONTEXT_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_PASS_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_TRAP_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_FWBL1_BOUNDARY_STAGED_FINALIZE_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_PASS_MAGIC,
        EPBL_DISPATCH_STAGED_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_VERIFY_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_DISPATCH_STAGED_FINALIZE_FAIL_MAGIC,
    ):
        raise RuntimeError(f"unexpected receive result {result[:8]!r}")
    records.append(result)
    print(f"Received record {len(records)}: {result[:8]!r}")

    if result[:8] == EPBL_HEADER_STAGED_HASH_MAGIC:
        terminal = read_after_checkpoint(EPBL_HEADER_STAGED_HASH_MAGIC)
        if len(terminal) != RECORD_SIZE:
            print(
                f"Header parser stopped after {result[:8]!r}: got "
                f"0x{len(terminal):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if terminal[:8] not in (
            EPBL_HEADER_STAGED_PASS_MAGIC,
            EPBL_HEADER_STAGED_FAIL_MAGIC,
        ):
            raise RuntimeError(f"unexpected parser result {terminal[:8]!r}")
        records.append(terminal)
        print(f"Received record {len(records)}: {terminal[:8]!r}")

    if result[:8] == EPBL_VERIFY_STAGED_HASH_MAGIC:
        parsed = read_after_checkpoint(EPBL_VERIFY_STAGED_HASH_MAGIC)
        if len(parsed) != RECORD_SIZE:
            print(
                f"Header parser stopped after {result[:8]!r}: got "
                f"0x{len(parsed):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if parsed[:8] not in (
            EPBL_VERIFY_STAGED_PARSED_MAGIC,
            EPBL_VERIFY_STAGED_FAIL_MAGIC,
        ):
            raise RuntimeError(f"unexpected parser result {parsed[:8]!r}")
        records.append(parsed)
        print(f"Received record {len(records)}: {parsed[:8]!r}")
        if parsed[:8] == EPBL_VERIFY_STAGED_FAIL_MAGIC:
            return b"".join(records)

        terminal = read_after_checkpoint(EPBL_VERIFY_STAGED_PARSED_MAGIC)
        if len(terminal) != RECORD_SIZE:
            print(
                f"EPBL verification stopped after {parsed[:8]!r}: got "
                f"0x{len(terminal):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if terminal[:8] not in (
            EPBL_VERIFY_STAGED_PASS_MAGIC,
            EPBL_VERIFY_STAGED_VERIFY_FAIL_MAGIC,
        ):
            raise RuntimeError(f"unexpected verification result {terminal[:8]!r}")
        records.append(terminal)
        print(f"Received record {len(records)}: {terminal[:8]!r}")

    if result[:8] == EPBL_POSTLOAD_STAGED_HASH_MAGIC:
        parsed = read_after_checkpoint(EPBL_POSTLOAD_STAGED_HASH_MAGIC)
        if len(parsed) != RECORD_SIZE:
            print(
                f"Header parser stopped after {result[:8]!r}: got "
                f"0x{len(parsed):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if parsed[:8] not in (
            EPBL_POSTLOAD_STAGED_PARSED_MAGIC,
            EPBL_POSTLOAD_STAGED_FAIL_MAGIC,
        ):
            raise RuntimeError(f"unexpected parser result {parsed[:8]!r}")
        records.append(parsed)
        print(f"Received record {len(records)}: {parsed[:8]!r}")
        if parsed[:8] == EPBL_POSTLOAD_STAGED_FAIL_MAGIC:
            return b"".join(records)

        verified = read_after_checkpoint(EPBL_POSTLOAD_STAGED_PARSED_MAGIC)
        if len(verified) != RECORD_SIZE:
            print(
                f"EPBL verification stopped after {parsed[:8]!r}: got "
                f"0x{len(verified):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if verified[:8] not in (
            EPBL_POSTLOAD_STAGED_VERIFIED_MAGIC,
            EPBL_POSTLOAD_STAGED_VERIFY_FAIL_MAGIC,
        ):
            raise RuntimeError(
                f"unexpected verification result {verified[:8]!r}"
            )
        records.append(verified)
        print(f"Received record {len(records)}: {verified[:8]!r}")
        if verified[:8] == EPBL_POSTLOAD_STAGED_VERIFY_FAIL_MAGIC:
            return b"".join(records)

        terminal = read_after_checkpoint(EPBL_POSTLOAD_STAGED_VERIFIED_MAGIC)
        if len(terminal) != RECORD_SIZE:
            print(
                f"EPBL post-load setup stopped after {verified[:8]!r}: got "
                f"0x{len(terminal):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if terminal[:8] not in (
            EPBL_POSTLOAD_STAGED_PASS_MAGIC,
            EPBL_POSTLOAD_STAGED_POSTLOAD_FAIL_MAGIC,
        ):
            raise RuntimeError(
                f"unexpected post-load result {terminal[:8]!r}"
            )
        records.append(terminal)
        print(f"Received record {len(records)}: {terminal[:8]!r}")

    if result[:8] == EPBL_ENTRY_STAGED_HASH_MAGIC:
        parsed = read_after_checkpoint(EPBL_ENTRY_STAGED_HASH_MAGIC)
        if len(parsed) != RECORD_SIZE:
            print(
                f"Header parser stopped after {result[:8]!r}: got "
                f"0x{len(parsed):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if parsed[:8] not in (
            EPBL_ENTRY_STAGED_PARSED_MAGIC,
            EPBL_ENTRY_STAGED_FAIL_MAGIC,
        ):
            raise RuntimeError(f"unexpected parser result {parsed[:8]!r}")
        records.append(parsed)
        print(f"Received record {len(records)}: {parsed[:8]!r}")
        if parsed[:8] == EPBL_ENTRY_STAGED_FAIL_MAGIC:
            return b"".join(records)

        verified = read_after_checkpoint(EPBL_ENTRY_STAGED_PARSED_MAGIC)
        if len(verified) != RECORD_SIZE:
            print(
                f"EPBL verification stopped after {parsed[:8]!r}: got "
                f"0x{len(verified):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if verified[:8] not in (
            EPBL_ENTRY_STAGED_VERIFIED_MAGIC,
            EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC,
        ):
            raise RuntimeError(
                f"unexpected verification result {verified[:8]!r}"
            )
        records.append(verified)
        print(f"Received record {len(records)}: {verified[:8]!r}")
        if verified[:8] == EPBL_ENTRY_STAGED_VERIFY_FAIL_MAGIC:
            return b"".join(records)

        postload = read_after_checkpoint(EPBL_ENTRY_STAGED_VERIFIED_MAGIC)
        if len(postload) != RECORD_SIZE:
            print(
                f"EPBL post-load setup stopped after {verified[:8]!r}: got "
                f"0x{len(postload):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if postload[:8] not in (
            EPBL_ENTRY_STAGED_POSTLOAD_MAGIC,
            EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC,
            EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC,
        ):
            raise RuntimeError(
                f"unexpected post-load result {postload[:8]!r}"
            )
        records.append(postload)
        print(f"Received record {len(records)}: {postload[:8]!r}")
        if postload[:8] != EPBL_ENTRY_STAGED_POSTLOAD_MAGIC:
            return b"".join(records)

        terminal = read_after_checkpoint(EPBL_ENTRY_STAGED_POSTLOAD_MAGIC)
        if len(terminal) != RECORD_SIZE:
            print(
                f"EPBL entry stopped after {postload[:8]!r}: got "
                f"0x{len(terminal):x} result bytes, expected "
                f"0x{RECORD_SIZE:x}",
                file=sys.stderr,
            )
            return b"".join(records)
        if terminal[:8] not in (
            EPBL_ENTRY_STAGED_PASS_MAGIC,
            EPBL_ENTRY_STAGED_FINALIZE_FAIL_MAGIC,
        ):
            raise RuntimeError(f"unexpected EPBL entry result {terminal[:8]!r}")
        records.append(terminal)
        print(f"Received record {len(records)}: {terminal[:8]!r}")

    return b"".join(records)


def run_direct_receive_probe(device, usb_core) -> bytes:
    frame = make_dnw_frame(RX_PATTERN)
    written = device.write(0x02, frame, timeout=5000)
    if written != len(frame):
        raise RuntimeError(f"short EP2 OUT write: 0x{written:x}/0x{len(frame):x}")
    print(
        "Sent framed test pattern without a preceding EP1 marker: "
        f"0x{written:x} bytes"
    )

    result = read_probe_record(device, usb_core)
    if len(result) != RECORD_SIZE:
        raise RuntimeError(
            f"received 0x{len(result):x} result bytes, expected 0x{RECORD_SIZE:x}"
        )
    if result[:8] not in (RX_PASS_MAGIC, RX_FAIL_MAGIC):
        raise RuntimeError(f"unexpected receive result {result[:8]!r}")
    print(f"Received record 1: {result[:8]!r}")
    return result


def run_live(args) -> bytes:
    houston_dir = args.houston_dir.resolve()
    if not (houston_dir / "modules" / "exploit.py").is_file():
        raise RuntimeError(f"Houston checkout not found at {houston_dir}")

    sys.path.insert(0, str(houston_dir))

    try:
        import usb.core
        import usb.util

        from modules.exploit import overwrite_iram, send_payload
        from modules.soc_data import SOC_DATA
    except ModuleNotFoundError as error:
        houston_python = houston_dir / ".venv" / "bin" / "python3"
        hint = "activate the environment containing Houston's requirements"
        if houston_python.is_file():
            hint = f"rerun with sudo {houston_python}"
        raise RuntimeError(f"missing Python module {error.name!r}; {hint}") from error

    payload = args.payload.resolve()
    if not payload.is_file():
        raise RuntimeError(f"payload not found: {payload}")

    # A silent handoff intentionally creates no capture. Remove an older file
    # before touching hardware so a failed or empty run cannot leave stale
    # records that look as if they came from the current session.
    if args.allow_no_records:
        args.output.unlink(missing_ok=True)

    receive_payload = None
    receive_frame = None
    receive_label = None
    followup_frames = []
    if args.receive_file is not None:
        receive_payload = load_binary9_epbl(
            args.receive_file.resolve(), args.allow_unpinned_stages
        )
        receive_frame = make_dnw_frame(receive_payload)
        receive_label = (
            "Binary 9 EPBL (SHA-256 "
            f"{hashlib.sha256(receive_payload).hexdigest()})"
        )
    for index, path in enumerate(args.receive_next_file):
        followup_payload, followup_label = load_binary9_followup_stage(
            path.resolve(), index, args.allow_unpinned_stages
        )
        followup_frames.append(
            (followup_label, make_binary9_stage_frame(followup_payload))
        )

    device = wait_for_device(usb.core)
    device_seen_at = time.monotonic()
    claim_device(device, usb.core, usb.util)

    try:
        product = usb.util.get_string(device, device.iProduct)
        if product not in SOC_DATA:
            raise RuntimeError(f"Houston has no parameters for {product!r}")

        parameters = SOC_DATA[product]
        if parameters["rx_address"] != 0x02022000:
            raise RuntimeError("unexpected Houston receive address")
        if parameters["usb_struct_offset"] != 0x0480:
            raise RuntimeError("unexpected Houston USB structure offset")

        print(f"Device product: {product!r}")

        if product == "Exynos9820\0":
            exynos9825_handler = houston_dir / "modules" / "exynos9825.py"
            if not exynos9825_handler.is_file():
                raise RuntimeError(
                    "Houston is missing the Exynos9825 handler introduced by PR #12: "
                    f"{exynos9825_handler}"
                )
            print(
                "Exynos9825 USB policy: Houston PR #12 handler present; "
                "retaining the original EUB handle after ACE (no re-enumeration)"
            )

        try:
            startup = bytes(device.read(0x81, 511, timeout=500))
            if startup:
                print(f"Startup response: {startup!r}")
        except usb.core.USBTimeoutError:
            pass

        send_payload(device, str(payload))
        overwrite_iram(
            device,
            args.debug,
            parameters["rx_address"],
            parameters["usb_struct_offset"],
        )

        listener = None
        if args.receive_test_direct:
            data = run_direct_receive_probe(device, usb.core)
        elif args.receive_test:
            data = run_receive_probe(
                device,
                usb.core,
                receive_payload,
                receive_frame,
                receive_label,
                device_seen_at,
                followup_frames,
                dump_mode=args.dump_fwbl1,
            )
        elif args.listen_ep1:
            # Ep1ChainReader must be the ONLY consumer of EP1 IN: running it
            # alongside read_probe_records has the two racing for the same
            # endpoint, the thread wins, and the probe record is consumed
            # before the reader loop ever sees it -- which looked exactly like
            # the payload having stopped emitting records at all.
            # finish() already pulls probe records out of the chunks and prints
            # everything else as text, so take the records from it.
            print(
                f"Draining EP1 IN for {args.listen_ep1:g}s; text below is from "
                "whatever owns the chain once our payload hands over"
            )
            listener = Ep1ChainReader(device, usb.core, device_seen_at)
            listener.start()
            data = b"".join(
                listener.finish(
                    args.listen_ep1,
                    expected_disconnect=args.allow_no_records,
                )
            )
        else:
            data = read_probe_records(device, usb.core)
        if not data:
            if args.allow_no_records:
                if listener is None or listener.error is None:
                    print(
                        "No probe records arrived during the listen window; "
                        "accepted because this payload uses a silent handoff. "
                        "This is not a downstream boot PASS."
                    )
                else:
                    print(
                        "No probe records arrived before the USB device left; "
                        "accepted because this payload uses a silent handoff. "
                        "This is not a downstream boot PASS."
                    )
                return b""
            raise RuntimeError("received no probe records")

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
        print(f"Saved raw record to {args.output}")
        return data
    finally:
        try:
            usb.util.release_interface(device, 0)
        except usb.core.USBError:
            pass
        usb.util.dispose_resources(device)


def parse_args():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run or decode the Exynos9825 boot probes"
    )
    parser.add_argument(
        "--decode",
        type=Path,
        metavar="FILE",
        help="decode one or more captured 0x60-byte probe records",
    )
    parser.add_argument(
        "--receive-test",
        action="store_true",
        help="send the framed test pattern requested by usb_receive_probe",
    )
    parser.add_argument(
        "--receive-file",
        type=Path,
        metavar="FILE",
        help="send the exact Binary 9 EPBL requested by epbl_receive_probe",
    )
    parser.add_argument(
        "--receive-next-file",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help=(
            "send one to four pinned Binary 9 stages after EPBL in FWBL1, "
            "BL2, sboot, EL3 monitor order; a partial cold-path run reads "
            "EP1 IN immediately after its last supplied stage"
        ),
    )
    parser.add_argument(
        "--dump-fwbl1",
        action="store_true",
        help="send EPBL+FWBL1 then save the decrypted FWBL1 region the probe streams out",
    )
    parser.add_argument(
        "--receive-test-direct",
        action="store_true",
        help="send the framed test pattern without waiting for an EP1 marker",
    )
    parser.add_argument(
        "--payload",
        type=Path,
        default=root / "build" / "boot_nonsecure_probe.bin",
        help="probe payload (default: build/boot_nonsecure_probe.bin)",
    )
    parser.add_argument(
        "--houston-dir",
        type=Path,
        default=root.parent / "houston-pub",
        help="Houston checkout containing modules/",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/exynos9825_boot_nonsecure_probe.bin"),
        help="raw output record",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show Houston iRAM hexdumps",
    )
    parser.add_argument(
        "--listen-ep1",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "after the payload's record, keep draining EP1 IN for this long "
            "and print what arrives. Needed when the payload hands control to "
            "a chain that prints on its own: without it that output is lost "
            "and a hang looks identical to a successful boot."
        ),
    )
    parser.add_argument(
        "--allow-no-records",
        action="store_true",
        help=(
            "with --listen-ep1, accept an intentionally silent handoff that "
            "returns no probe record; any stale output file is removed"
        ),
    )
    parser.add_argument(
        "--allow-unpinned-stages",
        action="store_true",
        help=(
            "send stages whose SHA-256 is not in the known-image allowlist "
            "(the per-stage size check still applies). Needed for a chain "
            "resigned with our own keys: ECDSA uses a random nonce, so every "
            "rebuild produces different signatures and a different hash, and "
            "pinning them is not possible. Verify such a chain with "
            "scripts/verify_9825.py before sending it."
        ),
    )
    args = parser.parse_args()
    if args.receive_test and args.receive_test_direct:
        parser.error("--receive-test and --receive-test-direct are mutually exclusive")
    if args.receive_file and not args.receive_test:
        parser.error("--receive-file requires --receive-test")
    if args.receive_next_file and not args.receive_file:
        parser.error("--receive-next-file requires --receive-file")
    if args.receive_next_file and not 1 <= len(args.receive_next_file) <= 4:
        parser.error(
            "--receive-next-file must be supplied between one and four times"
        )
    if args.allow_no_records and not args.listen_ep1:
        parser.error("--allow-no-records requires --listen-ep1")
    return args


def main() -> int:
    args = parse_args()
    try:
        data = args.decode.read_bytes() if args.decode else run_live(args)
        if not data and args.allow_no_records and args.decode is None:
            print(
                "Silent handoff capture completed without a probe record; "
                "there is no record to decode and no downstream PASS is "
                "implied."
            )
            return 0
        if len(data) % RECORD_SIZE:
            raise ValueError(
                f"capture is 0x{len(data):x} bytes, not a record multiple"
            )

        results = []
        for offset in range(0, len(data), RECORD_SIZE):
            if results:
                print()
            print(f"=== Record {offset // RECORD_SIZE + 1} ===")
            results.append(decode_record(data[offset:offset + RECORD_SIZE]))

        passed = bool(results and results[-1] is True)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
