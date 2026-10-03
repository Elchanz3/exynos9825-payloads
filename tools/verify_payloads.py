#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import struct
import sys
from pathlib import Path


LOAD_ADDRESS = 0x02022000
TRB_ADDRESS = 0x02024800
NOP = bytes.fromhex("1f2003d5")


def check_elf(path: Path) -> None:
    data = path.read_bytes()

    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("expected a little-endian ELF64 file")

    entry = struct.unpack_from("<Q", data, 24)[0]
    if entry != LOAD_ADDRESS:
        raise ValueError(f"entry is 0x{entry:08x}, expected 0x{LOAD_ADDRESS:08x}")

    binary = path.with_suffix(".bin").read_bytes()
    if not binary.startswith(NOP * 4):
        raise ValueError("binary does not start with the four-NOP Houston entry")

    limit = TRB_ADDRESS - LOAD_ADDRESS
    if len(binary) > limit:
        raise ValueError(f"binary size 0x{len(binary):x} exceeds 0x{limit:x}")

    print(f"{path.name}: entry=0x{entry:08x} size=0x{len(binary):x} OK")


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {Path(sys.argv[0]).name} PAYLOAD.elf [...]", file=sys.stderr)
        return 2

    failed = False
    for name in sys.argv[1:]:
        path = Path(name)
        try:
            check_elf(path)
        except (OSError, ValueError, struct.error) as error:
            failed = True
            print(f"{path}: {error}", file=sys.stderr)

    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
