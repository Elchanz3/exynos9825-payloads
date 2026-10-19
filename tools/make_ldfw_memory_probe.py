#!/usr/bin/env python3
"""Build a read-only post-initialization LDFW memory diagnostic.

The input is the previously validated Note10 LDFW diagnostic sboot.  Its
wrapper calls the CM/LDFW initializer and reports two words through the normal
sboot printf path.  This patch moves the reads after the initializer returns
and points them at the CryptoManagerV50 load address, 0x82001000.

No OTP command is issued and no fuse-programming path is enabled by this tool.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


INPUT_SHA256 = "5a0bb52549af3cac7d4028243d7f32ee88a5b059c13bd055f9e675af9bd46151"
WRAPPER_OFFSET = 0xA1ED0
FORMAT_OFFSET = 0xA1F0C

# Original wrapper body from sboot_note10_ldfwdiag.bin.  It reads 0x80000000
# before calling the LDFW initializer at 0xc90a616c.
EXPECTED_WRAPPER = bytes.fromhex(
    "0a 00 80 d2"  # mov  x10, #0
    " 0a 00 b0 f2"  # movk x10, #0x8000, lsl #16
    " 4b 01 40 b9"  # ldr  w11, [x10]
    " 4c 11 40 b9"  # ldr  w12, [x10, #0x10]
    " eb 33 02 a9"  # stp  x11, x12, [sp, #0x20]
    " a2 10 00 94"  # bl   0xc90a616c
    " e0 33 00 b9"  # str  w0, [sp, #0x30]
)

# Call the initializer first, retain its result, then read 32-bit words at
# 0x82001000 and 0x82001010.  The remaining wrapper still prints them as x5/x6.
PATCHED_WRAPPER = bytes.fromhex(
    "a7 10 00 94"  # bl   0xc90a616c (branch moved five instructions earlier)
    " e0 33 00 b9"  # str  w0, [sp, #0x30]
    " 0a 00 82 d2"  # mov  x10, #0x1000
    " 0a 40 b0 f2"  # movk x10, #0x8200, lsl #16
    " 4b 01 40 b9"  # ldr  w11, [x10]
    " 4c 11 40 b9"  # ldr  w12, [x10, #0x10]
    " eb 33 02 a9"  # stp  x11, x12, [sp, #0x20]
)

EXPECTED_FORMAT = b"LDFW m0=%llx m1=%llx ret=%llx\n\0"
PATCHED_FORMAT = b"LDFW p0=%llx p1=%llx ret=%llx\n\0"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_replace(data: bytearray, offset: int, expected: bytes,
                    replacement: bytes, description: str) -> None:
    if len(expected) != len(replacement):
        raise ValueError(f"{description}: replacement changes image size")
    actual = bytes(data[offset:offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"{description}: unexpected bytes at 0x{offset:x}: {actual.hex()}"
        )
    data[offset:offset + len(replacement)] = replacement


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path,
                        help="validated sboot_note10_ldfwdiag.bin")
    parser.add_argument("--out", type=Path,
                        default=Path("build/sboot_note10_ldfwmem.bin"))
    args = parser.parse_args()

    original = args.image.read_bytes()
    digest = sha256(original)
    if digest != INPUT_SHA256:
        raise ValueError(
            f"input SHA-256 mismatch: got {digest}, expected {INPUT_SHA256}"
        )

    patched = bytearray(original)
    checked_replace(patched, WRAPPER_OFFSET, EXPECTED_WRAPPER,
                    PATCHED_WRAPPER, "post-init LDFW read wrapper")
    checked_replace(patched, FORMAT_OFFSET, EXPECTED_FORMAT,
                    PATCHED_FORMAT, "diagnostic format")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(patched)
    print(f"wrote      {args.out}")
    print(f"size       0x{len(patched):x}")
    print(f"sha256     {sha256(patched)}")
    print("operation  read-only LDFW memory diagnostic; no OTP command")
    print("reads      u32[0x82001000], u32[0x82001010] after LDFW init")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
