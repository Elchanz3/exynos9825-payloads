#!/usr/bin/env python3
"""Validate the irreversible KEY2 stub embedded in a generated sboot chain."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path


CHECK_SIGNATURE_OFFSET = 0x4FC68
CHECK_SIGNATURE_CALLERS = (
    0x4FD98,
    0x50090,
    0x50190,
    0x50AF4,
    0x52954,
    0x55C1C,
    0xA64A4,
    0xB6A4C,
    0xB6C48,
    0xB9170,
)
UH_LOADER_CHECK_SIGNATURE_CALL_OFFSET = 0xB9170
# The CM/LDFW initializer's four mutually exclusive result diagnostics,
# resolved by message in sboot_patch.patch_key2_after_ldfw:
#
#   0xA63E4  "ldfw: No ldfw is inited"
#   0xA6460  "ldfw: signature of ldfw is corrupted!"
#   0xA64A4  "ldfw: try to init ... have been inited done."   <- success
#   0xA64D0  "ldfw: It is dump_gpr state. It does not load ldfw."
#
# Only the success path may reach the stub. On the other three the LDFW never
# came up, so the OTP service does not exist, and the command behind the stub
# burns a one-shot fuse.
LDFW_SUCCESS_CALL_OFFSET = 0xA64A4
LDFW_FAILURE_CALL_OFFSETS = (0xA63E4, 0xA6460, 0xA64D0)
FORCE_SECURE_PAYLOAD_OFFSET = 0x1F330
NORMAL_BOOT_CALL_OFFSET = 0x38F0
MAGIC_CODE_LOAD_OFFSET = 0x33F0
LDFW_MODE0_LOAD_OFFSET = 0xA61A4
LDFW_MODE1_LOAD_OFFSET = 0xA61B0
MOV_W1_ZERO = bytes.fromhex("01 00 80 52")
MOV_W0_ZERO = bytes.fromhex("00 00 80 52")
MOV_W19_ZERO = bytes.fromhex("13 00 80 52")
MOV_W20_ZERO = bytes.fromhex("14 00 80 52")

STUBS = {
    "program": bytes.fromhex(
        "fd 7b bf a9"  # stp x29, x30, [sp, #-0x10]!
        " c0 00 00 10"  # adr x0, embedded anchor
        " 01 04 80 52"  # mov w1, #0x20
        " c6 4a 01 94"  # bl cm_otp_write_rom_sec_boot_key2
        " 00 00 80 d2"  # mov x0, #0
        " fd 7b c1 a8"  # ldp x29, x30, [sp], #0x10
        " c0 03 5f d6"  # ret
    ),
    "program-use": bytes.fromhex(
        "fd 7b bf a9"  # stp x29, x30, [sp, #-0x10]!
        " 00 01 00 10"  # adr x0, embedded anchor
        " 01 04 80 52"  # mov w1, #0x20
        " c6 4a 01 94"  # bl cm_otp_write_rom_sec_boot_key2
        " 40 00 00 b5"  # cbnz x0, out
        " d9 4b 01 94"  # bl cm_otp_write_use_rom_sec_boot_key2
        " 00 00 80 d2"  # mov x0, #0
        " fd 7b c1 a8"  # ldp x29, x30, [sp], #0x10
        " c0 03 5f d6"  # ret
    ),
}


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def branch_target(data: bytes, offset: int) -> int | None:
    word = u32(data, offset)
    if word & 0xFC000000 != 0x94000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return offset + immediate * 4


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_anchor(custom_dir: Path) -> bytes:
    scripts = custom_dir / "scripts"
    sys.path.insert(0, str(scripts))
    previous = Path.cwd()
    try:
        os.chdir(custom_dir)
        import patch_9825  # type: ignore

        return patch_9825.get_efuse_data()
    finally:
        os.chdir(previous)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=STUBS)
    parser.add_argument("chain", type=Path,
                        help="directory containing sboot.bin and sboot/u-boot.bin")
    parser.add_argument(
        "--custom-dir", type=Path,
        default=Path("/home/chanz22/EUB-N10/9825_customkey"),
    )
    args = parser.parse_args()

    image = args.chain / "sboot.bin"
    uboot = args.chain / "sboot" / "u-boot.bin"
    if image.stat().st_size != 0x400000:
        raise ValueError(f"unexpected sboot size: {image.stat().st_size:#x}")
    data = uboot.read_bytes()
    if len(data) != 0x180000:
        raise ValueError(f"unexpected u-boot size: {len(data):#x}")

    stub = STUBS[args.mode]
    actual = data[CHECK_SIGNATURE_OFFSET:CHECK_SIGNATURE_OFFSET + len(stub)]
    if actual != stub:
        raise ValueError(
            f"unexpected {args.mode} stub at {CHECK_SIGNATURE_OFFSET:#x}: "
            f"{actual.hex()}"
        )

    embedded = data[
        CHECK_SIGNATURE_OFFSET + len(stub):
        CHECK_SIGNATURE_OFFSET + len(stub) + 32
    ]
    if embedded != expected_anchor(args.custom_dir):
        raise ValueError("embedded KEY2 trust anchor does not match the signer")

    if data[FORCE_SECURE_PAYLOAD_OFFSET:FORCE_SECURE_PAYLOAD_OFFSET + 4] != MOV_W1_ZERO:
        raise ValueError("secure-payload load flag is not forced clear")

    if data[NORMAL_BOOT_CALL_OFFSET:NORMAL_BOOT_CALL_OFFSET + 4] != MOV_W0_ZERO:
        raise ValueError("s5p_check_download call is not forced to return zero")

    if data[MAGIC_CODE_LOAD_OFFSET:MAGIC_CODE_LOAD_OFFSET + 4] != MOV_W19_ZERO:
        raise ValueError("main MAGIC_CODE read is not forced to zero")

    if data[LDFW_MODE0_LOAD_OFFSET:LDFW_MODE0_LOAD_OFFSET + 4] != MOV_W20_ZERO:
        raise ValueError("LDFW mode word 0 read is not forced to zero")

    if data[LDFW_MODE1_LOAD_OFFSET:LDFW_MODE1_LOAD_OFFSET + 4] != MOV_W19_ZERO:
        raise ValueError("LDFW mode word 1 read is not forced to zero")

    if branch_target(data, LDFW_SUCCESS_CALL_OFFSET) != CHECK_SIGNATURE_OFFSET:
        raise ValueError(
            "the CM/LDFW success path does not call the KEY2 OTP stub"
        )
    for offset in LDFW_FAILURE_CALL_OFFSETS:
        if branch_target(data, offset) == CHECK_SIGNATURE_OFFSET:
            raise ValueError(
                f"a CM/LDFW FAILURE path at {offset:#x} reaches the KEY2 OTP "
                "stub; the service does not exist there and the command burns "
                "a one-shot fuse"
            )

    callers = tuple(
        offset
        for offset in range(0, len(data) - 3, 4)
        if branch_target(data, offset) == CHECK_SIGNATURE_OFFSET
    )
    if callers != CHECK_SIGNATURE_CALLERS:
        raise ValueError(
            "unexpected check_signature caller set: "
            + ", ".join(f"{offset:#x}" for offset in callers)
        )
    if u32(data, UH_LOADER_CHECK_SIGNATURE_CALL_OFFSET + 4) & 0xFF00001F \
            != 0x35000000:
        raise ValueError("uH loader no longer checks the OTP stub return with cbnz w0")

    print(f"mode         {args.mode}")
    print(f"sboot        {image}")
    print(f"sboot sha256 {digest(image)}")
    print(f"u-boot sha256 {digest(uboot)}")
    print("anchor       matches the P-384 signer-derived KEY2 value")
    print("secure path  forced on for CM/LDFW initialization")
    print("boot path    forced through the normal-boot fork")
    print("mode gates   three stale EUB DRAM reads forced to zero in u-boot")
    print("post-LDFW   only the initializer SUCCESS path calls the OTP stub")
    print("late retry   uH image loader still calls the OTP stub after secure init")
    print("result       PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
