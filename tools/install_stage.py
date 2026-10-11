#!/usr/bin/env python3
"""Pad a replacement stage to a chain slot and install it there.

The boot chain's stage sizes are fixed by the SoC layout, and the host probe
tool validates each one exactly, so a replacement has to be padded to the slot
size before signing. The signer then writes its ST2 footer into the last 0x210
bytes, which is why the tail must be left clear.

usage:
  install_stage.py build/ubstage_hello.bin <chain-dir>/sboot/u-boot.bin
  install_stage.py --size 0x180000 <stage.bin> <destination>

The destination's existing size is used as the slot size unless --size says
otherwise, so installing over a split chain picks the right slot automatically.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

FOOTER_SIZE = 0x210


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("stage", type=Path, help="the position-independent stage image")
    ap.add_argument("destination", type=Path, help="slot to overwrite")
    ap.add_argument(
        "--size",
        type=lambda v: int(v, 0),
        help="slot size; defaults to the destination's current size",
    )
    args = ap.parse_args(argv)

    stage = args.stage.read_bytes()

    size = args.size
    if size is None:
        if not args.destination.exists():
            ap.error(
                f"{args.destination} does not exist, so the slot size is unknown; "
                "pass --size"
            )
        size = args.destination.stat().st_size

    if len(stage) > size - FOOTER_SIZE:
        ap.error(
            f"{args.stage} is 0x{len(stage):x} bytes, which leaves no room for the "
            f"0x{FOOTER_SIZE:x}-byte ST2 footer in a 0x{size:x} slot"
        )

    padded = bytearray(stage + bytes(size - len(stage)))

    # Carry the slot's footer metadata across. The signer always rewrites
    # sign_type and key_type, but it only touches rb_count and key_index when
    # it is told to -- otherwise it preserves whatever bytes are already there.
    # Left as padding zeros, our stage would end up with rb_count 0 and
    # key_index 0 while every other stage in the chain carries 9 and
    # 0x31fb208f, which is the kind of mismatch that gets an image rejected
    # with no explanation.
    if args.destination.exists() and args.destination.stat().st_size == size:
        original = args.destination.read_bytes()
        footer = size - FOOTER_SIZE
        rb_count, _, _, key_index = struct.unpack_from("<IIII", original, footer)
        struct.pack_into("<I", padded, footer, rb_count)
        struct.pack_into("<I", padded, footer + 0xC, key_index)
        print(f"  carried over rb_count=0x{rb_count:x} "
              f"key_index=0x{key_index:08x} from the slot being replaced")

    args.destination.write_bytes(bytes(padded))

    print(f"stage       {args.stage}")
    print(f"  size      0x{len(stage):x}")
    print(f"  sha256    {hashlib.sha256(stage).hexdigest()}")
    print(f"installed into {args.destination}")
    print(f"  slot size 0x{size:x}  (0x{size - FOOTER_SIZE - len(stage):x} spare "
          f"before the footer region)")
    print("  the signer will overwrite the last 0x210 bytes with the ST2 footer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
