#!/usr/bin/env python3
"""Validate the signed u-boot diagnostic that forces Download reason 4."""

import argparse
import hashlib
import struct
from pathlib import Path


SLOT_SIZE = 0x180000
ST2_FOOTER_SIZE = 0x210
MAGIC_LOAD_OFFSET = 0x33F0
DOWNLOAD_CALL_OFFSET = 0x38F0
SIGNATURE_STUB_OFFSET = 0x4FC68
MARKER_CAVE_OFFSET = 0x17CE00

MOV_W19_ZERO = 0x52800013
MOV_W0_FOUR = 0x52800080
MOV_W21_W0 = 0x2A0003F5
RETURN_ZERO = bytes.fromhex("00 00 80 d2 c0 03 5f d6")


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def check(base_path: Path, slot_path: Path, proven_path: Path) -> None:
    base = base_path.read_bytes()
    slot = slot_path.read_bytes()
    proven = proven_path.read_bytes()

    if len(base) != SLOT_SIZE or len(slot) != SLOT_SIZE or len(proven) != SLOT_SIZE:
        raise SystemExit("error: unexpected u-boot slot size")

    footer = SLOT_SIZE - ST2_FOOTER_SIZE
    if base[:footer] != proven[:footer]:
        raise SystemExit("error: forced-Download base differs from proven ecdsa_eng")
    if u32(slot, MAGIC_LOAD_OFFSET) != MOV_W19_ZERO:
        raise SystemExit("error: stale MAGIC_CODE load is not forced to zero")
    if u32(slot, DOWNLOAD_CALL_OFFSET) != MOV_W0_FOUR:
        raise SystemExit("error: s5p_check_download call is not forced to reason 4")
    if u32(slot, DOWNLOAD_CALL_OFFSET + 4) != MOV_W21_W0:
        raise SystemExit("error: u-boot no longer preserves the Download reason in w21")
    if u32(slot, DOWNLOAD_CALL_OFFSET + 8) & 0xFF00001F != 0x34000000:
        raise SystemExit("error: u-boot Download fork is no longer cbz w0")
    if slot[SIGNATURE_STUB_OFFSET:SIGNATURE_STUB_OFFSET + 8] != RETURN_ZERO:
        raise SystemExit("error: diagnostic contains an OTP-capable signature stub")
    if any(slot[MARKER_CAVE_OFFSET:MARKER_CAVE_OFFSET + 0x80]):
        raise SystemExit("error: diagnostic unexpectedly contains an entry trampoline")

    allowed = set(range(MAGIC_LOAD_OFFSET, MAGIC_LOAD_OFFSET + 4))
    allowed.update(range(DOWNLOAD_CALL_OFFSET, DOWNLOAD_CALL_OFFSET + 4))
    allowed.update(range(footer, SLOT_SIZE))
    unexpected = [
        offset
        for offset, (before, after) in enumerate(zip(base, slot))
        if before != after and offset not in allowed
    ]
    if unexpected:
        raise SystemExit(
            f"error: unexpected forced-Download change at {unexpected[0]:#x}"
        )

    print(f"forced-Download u-boot = PASS ({hashlib.sha256(slot).hexdigest()})")
    print("base body matches proven ecdsa_eng = YES")
    print("entry trampoline = ABSENT")
    print("stale pre-fork MAGIC_CODE = FORCED ZERO")
    print("s5p_check_download result = FORCED REASON 4")
    print("OTP command injection = ABSENT")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("slot", type=Path)
    parser.add_argument("proven", type=Path)
    args = parser.parse_args()
    check(args.base, args.slot, args.proven)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
