#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# sboot_patch.py - Exynos9825 (SM-N975F) sboot / U-Boot engineering patcher.
#
# Locates engineering / verification gate functions inside the signed sboot
# stage by Samsung's own diagnostic strings (cross-reference, version robust)
# and neutralizes them with tiny AArch64 return stubs, so the stage reports the
# unit as an engineering device and stops refusing non-stock images.
#
# This only rewrites the sboot image on disk. The patched image still has to be
# accepted by the preceding chain (see the custom-key resign step); patching
# alone does not make a modified sboot boot.
#
# Usage:
#   tools/sboot_patch.py sboot_stage.bin [--out patched.bin] [--all] [--dry-run]
#
# Default patches (engineering identity):
#   - have_this_mode  -> return 1   (every ENG MODE query is allowed)
#   - etc_market = 0, etc_development = 1   (report a development unit)
# With --all, also relax the checks that otherwise reject a non-stock image:
#   - check_signature            -> return 0
#   - set_warranty_bit / reason  -> return 0
#   - [KG]/[RLC] read_data (RPMB) -> return 0

import argparse
import struct
import sys

RETURN_ZERO = bytes.fromhex("00 00 80 D2 C0 03 5F D6")  # mov w0,#0 ; ret
RETURN_ONE = bytes.fromhex("20 00 80 D2 C0 03 5F D6")   # mov w0,#1 ; ret


def u32(data, off):
    return int.from_bytes(data[off:off + 4], "little")


def put_u32(data, off, value):
    struct.pack_into("<I", data, off, value)


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def is_bl(data, off):
    return u32(data, off) & 0xFC000000 == 0x94000000


def bl_target(data, off):
    return off + sign_extend(u32(data, off) & 0x03FFFFFF, 26) * 4


def is_prologue(data, off):
    # stp x29,x30,[sp,#-N]!  or  sub sp,sp,#N
    return u32(data, off) & 0xFFC003FF in (0xA98003FD, 0xD10003FF)


def adrp_add_target(data, off):
    # Resolve an ADRP (+ nearby ADD xd,xd,#imm) to the byte offset it addresses.
    adrp = u32(data, off)
    if adrp & 0x9F000000 != 0x90000000:
        return None
    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    page = (off & ~0xFFF) + (sign_extend(imm, 21) << 12)
    for distance in range(4, 17, 4):
        add = u32(data, off + distance)
        if add & 0xFF000000 == 0x91000000 and (add >> 5) & 31 == adrp & 31:
            shift = 12 if add & 0x400000 else 0
            return page + (((add >> 10) & 0xFFF) << shift)
    return None


def find_string(data, text):
    needle = text.encode() + b"\0"
    off = data.find(needle)
    if off < 0:
        raise KeyError(f"string not found: {text!r}")
    if data.find(needle, off + 1) >= 0:
        raise KeyError(f"string not unique: {text!r}")
    return off


def find_single_xref(data, text):
    string_off = find_string(data, text)
    refs = [o for o in range(0, string_off & ~3, 4)
            if adrp_add_target(data, o) == string_off]
    if len(refs) != 1:
        raise KeyError(f"expected one xref to {text!r}, found {len(refs)}")
    return refs[0]


def function_start(data, inside, limit=0x800):
    for off in range(inside & ~3, max(0, inside - limit), -4):
        if is_prologue(data, off):
            return off
    raise KeyError(f"no function prologue within {limit:#x} before {inside:#x}")


class Patcher:
    def __init__(self, data, dry_run=False):
        self.data = data
        self.dry_run = dry_run
        self.log = []

    def _write(self, off, blob, what):
        before = self.data[off:off + len(blob)].hex()
        if not self.dry_run:
            self.data[off:off + len(blob)] = blob
        self.log.append(f"  {what:28} @0x{off:06x}  {before} -> {blob.hex()}")

    def stub_function_at_string(self, text, stub, what, back):
        # The diagnostic string is printed inside the target function; the
        # function start is the nearest prologue before its xref.
        xref = find_single_xref(self.data, text)
        start = function_start(self.data, xref)
        self._write(start, stub, what)
        return start

    def patch_have_this_mode(self):
        # Reporter that prints "ENG MODE : ... ALLOWED(%s)" calls a gate
        # (BL ; CBZ w0) whose target ends in TST ; CSET w0,ne ; RET. Force it
        # to return 1 so every engineering mode is allowed.
        xref = find_single_xref(self.data, "ENG MODE : ENG ALLOWED(%s)\n")
        gate = None
        for off in range(xref - 0x80, xref, 4):
            if is_bl(self.data, off) and \
               self.data[off + 4] & 0x1F == 0 and \
               u32(self.data, off + 4) & 0xFF00001F == 0x34000000:  # CBZ w0
                target = bl_target(self.data, off)
                tail = [u32(self.data, target + k) for k in (12, 16, 20)]
                if tail == [0x6A01001F, 0x1A9F07E0, 0xD65F03C0]:  # TST;CSET;RET
                    gate = target
                    break
        if gate is None:
            raise KeyError("have_this_mode gate not found")
        self._write(gate, RETURN_ONE, "have_this_mode->1")

    def patch_eng_efuse_bits(self):
        # Inside the efuse-init routine (holds the nantirbk0/commercial_bit
        # diagnostics) a run of "mov w0,#k ; bl ; str w0,[xN,#off]" programs the
        # reported fuse fields. etc_market is the mov that feeds [#0x40]; the
        # next such mov (16 bytes on) feeds etc_development at [#0x44].
        func = function_start(self.data, find_single_xref(
            self.data, "commercial_bit mismatch!(%d vs %d), updating...\n"))
        def is_mov_w0(word):          # mov w0,#imm16
            return word & 0x7F80001F == 0x52800000
        def is_str_w0(word, off64):   # str w0,[xN,#off64]
            return (word & 0xFFC00000 == 0xB9000000
                    and (word >> 10) & 0xFFF == off64 // 4
                    and word & 0x1F == 0)
        etc_market = None
        for off in range(func, func + 0x400, 4):
            if is_mov_w0(u32(self.data, off)) \
               and is_bl(self.data, off + 4) \
               and is_str_w0(u32(self.data, off + 12), 0x40):
                etc_market = off
                break
        if etc_market is None:
            raise KeyError("etc_market store not found")
        self._write(etc_market, bytes.fromhex("00 00 80 52"), "etc_market=0")       # mov w0,#0
        self._write(etc_market + 16, bytes.fromhex("20 00 80 52"), "etc_development=1")  # mov w0,#1

    def patch_check_signature(self):
        self.stub_function_at_string(
            "There is no signature\n", RETURN_ZERO, "check_signature->0", 0x200)

    def patch_warranty(self):
        self.stub_function_at_string(
            "[EFUSE] Set warranty bit(%d)\n", RETURN_ZERO, "set_warranty_bit->0", 0x200)

    def patch_rpmb(self):
        for tag in ("[KG] read_data fail...\n", "[RLC] read_data fail...\n"):
            try:
                self.stub_function_at_string(tag, RETURN_ZERO, f"rpmb {tag.split(']')[0][1:]}->0", 0x200)
            except KeyError as err:
                self.log.append(f"  (skip {tag!r}: {err})")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Patch Exynos9825 sboot for engineering mode")
    ap.add_argument("image")
    ap.add_argument("--out")
    ap.add_argument("--all", action="store_true",
                    help="also relax signature / warranty / RPMB checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="locate and report patches without writing")
    args = ap.parse_args(argv)

    data = bytearray(open(args.image, "rb").read())
    p = Patcher(data, dry_run=args.dry_run)

    p.patch_have_this_mode()
    p.patch_eng_efuse_bits()
    if args.all:
        p.patch_check_signature()
        p.patch_warranty()
        p.patch_rpmb()

    print(f"sboot_patch: {len(p.log)} site(s)")
    print("\n".join(p.log))

    if not args.dry_run:
        out = args.out or args.image
        with open(out, "wb") as f:
            f.write(data)
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
