#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import hashlib
import struct
import sys
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
EPBL_STATE_MAGICS = {
    b"EPS0IRAM": 0x02020000,
    b"EPS1IRAM": 0x02020050,
    b"EPS2IRAM": 0x020200A0,
    b"EPS3IRAM": 0x020200F0,
}
RX_PATTERN = bytes(range(0x40))
RECORD_SIZE = 0x60
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
        EPBL_DISPATCH_STAGED_READY_MAGIC,
        EPBL_DISPATCH_STAGED_FAIL_MAGIC,
    ):
        fields = EPBL_HEADER_FIELDS
    elif magic in (
        EPBL_VERIFY_STAGED_PASS_MAGIC,
        EPBL_VERIFY_STAGED_VERIFY_FAIL_MAGIC,
    ):
        fields = EPBL_VERIFY_FIELDS
    elif magic in (
        EPBL_POSTLOAD_STAGED_VERIFIED_MAGIC,
        EPBL_POSTLOAD_STAGED_PASS_MAGIC,
        EPBL_POSTLOAD_STAGED_POSTLOAD_FAIL_MAGIC,
        EPBL_ENTRY_STAGED_VERIFIED_MAGIC,
        EPBL_ENTRY_STAGED_POSTLOAD_FAIL_MAGIC,
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
    ):
        fields = EPBL_MMIO_FIELDS
    elif magic == EPBL_MMIO_STAGED_VERIFY_FAIL_MAGIC:
        fields = EPBL_VERIFY_FIELDS
    elif magic == EPBL_MMIO_STAGED_POSTLOAD_FAIL_MAGIC:
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
        EPBL_DISPATCH_STAGED_READY_MAGIC,
    ):
        checkpoint = {
            EPBL_DISPATCH_STAGED_READY_MAGIC:
                "staged dispatch probe armed EP2 OUT at the stock EPBL destination",
            EPBL_MMIO_STAGED_READY_MAGIC:
                "staged MMIO probe armed EP2 OUT at the stock EPBL destination",
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
    ):
        hook_site = values[3]
        branch_immediate = values[7] & 0x03FFFFFF
        if branch_immediate & 0x02000000:
            branch_immediate -= 0x04000000
        branch_target = (hook_site + branch_immediate * 4) & 0xFFFFFFFFFFFFFFFF
        passed = (
            magic == EPBL_MMIO_STAGED_PASS_MAGIC
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


def read_probe_record(device, usb_core) -> bytes:
    received = bytearray()
    deadline = time.monotonic() + 5.0

    while len(received) < RECORD_SIZE and time.monotonic() < deadline:
        try:
            chunk = bytes(
                device.read(
                    0x81,
                    RECORD_SIZE - len(received),
                    timeout=500,
                )
            )
        except usb_core.USBTimeoutError:
            continue

        if chunk:
            received.extend(chunk)

    return bytes(received)


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
            b"EPS3IRAM",
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


def load_binary9_epbl(path: Path) -> bytes:
    transfer = path.read_bytes()
    if len(transfer) != 0x3000:
        raise RuntimeError(
            f"EPBL file is 0x{len(transfer):x} bytes, expected 0x3000"
        )

    digest = hashlib.sha256(transfer).hexdigest()
    expected = "d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d"
    if digest != expected:
        raise RuntimeError(
            f"EPBL SHA-256 is {digest}, expected Binary 9 {expected}"
        )
    return transfer


def run_receive_probe(device, usb_core, receive_payload=None) -> bytes:
    records = []

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
        EPBL_DISPATCH_STAGED_READY_MAGIC,
    ):
        raise RuntimeError(f"unexpected receive-probe marker {ready[:8]!r}")

    records.append(ready)
    print(f"Received record {len(records)}: {ready[:8]!r}")
    if ready[:8] in (
        EPBL_READY_MAGIC,
        EPBL_HEADER_READY_MAGIC,
        EPBL_HEADER_NOIC_READY_MAGIC,
        EPBL_HEADER_STAGED_READY_MAGIC,
        EPBL_VERIFY_STAGED_READY_MAGIC,
        EPBL_POSTLOAD_STAGED_READY_MAGIC,
        EPBL_ENTRY_STAGED_READY_MAGIC,
        EPBL_MMIO_STAGED_READY_MAGIC,
        EPBL_DISPATCH_STAGED_READY_MAGIC,
    ):
        if receive_payload is None:
            raise RuntimeError("EPBL probe requires --receive-file")
        transfer = receive_payload
        label = f"Binary 9 EPBL (SHA-256 {hashlib.sha256(transfer).hexdigest()})"
        timeout = 10000
    else:
        if receive_payload is not None:
            raise RuntimeError("--receive-file requires the EPBL receive probe")
        transfer = RX_PATTERN
        label = "test pattern"
        timeout = 5000

    frame = make_dnw_frame(transfer)
    try:
        written = device.write(0x02, frame, timeout=timeout)
    except usb_core.USBError as error:
        print(
            f"USB write stopped after {ready[:8]!r}: {error}; preserving "
            f"{len(records)} record(s)",
            file=sys.stderr,
        )
        return b"".join(records)
    if written != len(frame):
        print(
            f"Short EP2 OUT write after {ready[:8]!r}: "
            f"0x{written:x}/0x{len(frame):x}; preserving "
            f"{len(records)} record(s)",
            file=sys.stderr,
        )
        return b"".join(records)
    print(f"Sent framed {label}: 0x{written:x} bytes")

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

    receive_payload = None
    if args.receive_file is not None:
        receive_payload = load_binary9_epbl(args.receive_file.resolve())

    device = wait_for_device(usb.core)
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

        if args.receive_test_direct:
            data = run_direct_receive_probe(device, usb.core)
        elif args.receive_test:
            data = run_receive_probe(device, usb.core, receive_payload)
        else:
            data = read_probe_records(device, usb.core)
        if not data:
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
    args = parser.parse_args()
    if args.receive_test and args.receive_test_direct:
        parser.error("--receive-test and --receive-test-direct are mutually exclusive")
    if args.receive_file and not args.receive_test:
        parser.error("--receive-file requires --receive-test")
    return args


def main() -> int:
    args = parse_args()
    try:
        data = args.decode.read_bytes() if args.decode else run_live(args)
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
