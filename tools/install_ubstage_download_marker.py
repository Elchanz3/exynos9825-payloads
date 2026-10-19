#!/usr/bin/env python3
"""Inject the UFS u-boot entry marker into a verified zero code cave."""

import argparse
import hashlib
import shutil
import struct
from pathlib import Path


LOAD_ADDRESS = 0xC9000000
SLOT_SIZE = 0x180000
ST2_FOOTER_SIZE = 0x210
CAVE_OFFSET = 0x17CE00
ORIGINAL_ENTRY = 0x14000001  # b load+4
SELF_BRANCH = 0x14000000     # b .


def branch(from_address: int, to_address: int) -> int:
    delta = to_address - from_address
    if delta & 3:
        raise ValueError(f"unaligned branch delta {delta:#x}")
    if not -(1 << 27) <= delta < (1 << 27):
        raise ValueError(f"branch delta {delta:#x} is outside AArch64 B range")
    return 0x14000000 | ((delta >> 2) & 0x03FFFFFF)


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def install(marker_path: Path, slot_path: Path, base_path: Path) -> None:
    marker = bytearray(marker_path.read_bytes())
    slot = bytearray(slot_path.read_bytes())

    if len(slot) != SLOT_SIZE:
        raise SystemExit(f"error: expected a {SLOT_SIZE:#x}-byte u-boot slot")
    if not marker or len(marker) & 3:
        raise SystemExit("error: marker must contain whole AArch64 instructions")
    if len(marker) > 0x100:
        raise SystemExit(f"error: marker is unexpectedly large ({len(marker):#x})")
    if u32(slot, 0) != ORIGINAL_ENTRY:
        raise SystemExit(
            f"error: unexpected u-boot entry instruction {u32(slot, 0):#010x}"
        )
    if u32(marker, len(marker) - 4) != SELF_BRANCH:
        raise SystemExit("error: marker does not end in the expected self-branch")

    footer = len(slot) - ST2_FOOTER_SIZE
    if CAVE_OFFSET + len(marker) > footer:
        raise SystemExit("error: marker overlaps the ST2 footer")
    if any(slot[CAVE_OFFSET : CAVE_OFFSET + len(marker)]):
        raise SystemExit("error: selected u-boot code cave is not empty")

    base_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(slot_path, base_path)

    entry_branch = branch(LOAD_ADDRESS, LOAD_ADDRESS + CAVE_OFFSET)
    resume_offset = CAVE_OFFSET + len(marker) - 4
    resume = branch(LOAD_ADDRESS + resume_offset, LOAD_ADDRESS + 4)
    write_u32(slot, 0, entry_branch)
    write_u32(marker, len(marker) - 4, resume)
    slot[CAVE_OFFSET : CAVE_OFFSET + len(marker)] = marker
    slot_path.write_bytes(slot)

    print(f"full u-boot base  {base_path}")
    print(f"base sha256       {hashlib.sha256(base_path.read_bytes()).hexdigest()}")
    print(f"entry branch      {entry_branch:#010x} -> {LOAD_ADDRESS + CAVE_OFFSET:#x}")
    print(f"marker cave       {CAVE_OFFSET:#x}..{CAVE_OFFSET + len(marker):#x}")
    print(f"resume branch     {resume:#010x} -> {LOAD_ADDRESS + 4:#x}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("marker", type=Path)
    parser.add_argument("slot", type=Path)
    parser.add_argument("base", type=Path)
    args = parser.parse_args()
    install(args.marker, args.slot, args.base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
