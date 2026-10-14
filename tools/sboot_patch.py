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
# With --normal-boot, force the Download-vs-normal-boot fork to normal boot, so
# a chain booted over USB continues into Android instead of the Odin screen.

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


def adrp_pointer_values(data, off, window=7):
    """Every address an ADRP at `off` can form with the ADDs that follow it.

    Samsung builds a __func__ pointer in two steps, and not always in the same
    register:

        adrp x20, <page>
        add  x1, x20, #0x240      <- destination differs from the source
        add  x1, x1, #0x20

    so a resolver that insists on `add xd,xd,#imm` (which is all the format
    strings need) sees nothing here. Follow the renames and return the page
    plus every partial sum, because which one is the real pointer depends on
    how far the chain goes.
    """
    adrp = u32(data, off)
    if adrp & 0x9F000000 != 0x90000000:
        return ()
    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    page = (off & ~0xFFF) + (sign_extend(imm, 21) << 12)
    live = {adrp & 31: page}
    values = {page}
    for step in range(1, window + 1):
        word = u32(data, off + 4 * step)
        if word & 0xFF000000 != 0x91000000:          # add xd,xs,#imm
            continue
        src, dst = (word >> 5) & 31, word & 31
        if src not in live:
            continue
        shift = 12 if word & 0x400000 else 0
        value = live[src] + (((word >> 10) & 0xFFF) << shift)
        live[dst] = value
        values.add(value)
    return tuple(values)


def find_function_by_name_string(data, name):
    """The function that references its own __func__ string `name`.

    All references to a __func__ literal are inside the function it names, so
    several xrefs are expected; they just have to agree on the function.
    """
    string_off = find_string(data, name)
    funcs = set()
    for off in range(0, len(data) - 32, 4):
        if string_off in adrp_pointer_values(data, off):
            try:
                funcs.add(function_start(data, off))
            except KeyError:
                pass
    if len(funcs) != 1:
        raise KeyError(f"xrefs to {name!r} resolve to {len(funcs)} functions")
    return funcs.pop()


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


_call_targets = {}


def call_targets(data):
    key = id(data)
    if key not in _call_targets:
        _call_targets[key] = sorted({bl_target(data, o)
                                     for o in range(0, len(data) - 3, 4)
                                     if is_bl(data, o)})
    return _call_targets[key]


def function_start(data, inside, limit=0x800):
    # The entry is the nearest BL target at or before `inside`. Scanning back
    # for the first prologue is wrong when a function opens with
    # `sub sp,sp,#N` followed by `stp x29,x30,...` (e.g. [KG] read_data).
    entry = max((t for t in call_targets(data)
                 if inside - limit <= t <= inside), default=None)
    if entry is None or not is_prologue(data, entry):
        raise KeyError(f"no called function entry within {limit:#x} before {inside:#x}")
    return entry


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
        # diagnostics) a run of "mov w0,#k ; bl read ; ldr ; str w0,[xN,#off]"
        # programs the reported fuse fields. The mov selects WHICH field is
        # read, so the result is forced by replacing the BL: etc_market feeds
        # [#0x40], etc_development (16 bytes on) feeds [#0x44].
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
        if not (is_bl(self.data, etc_market + 20)
                and is_str_w0(u32(self.data, etc_market + 28), 0x44)):
            raise KeyError("etc_development read does not follow etc_market")
        self._write(etc_market + 4, bytes.fromhex("00 00 80 52"), "etc_market=0")       # bl -> mov w0,#0
        self._write(etc_market + 20, bytes.fromhex("20 00 80 52"), "etc_development=1")  # bl -> mov w0,#1

    def patch_normal_boot(self):
        # Force the Download-vs-normal-boot fork to normal boot.
        #
        # The call site is
        #
        #     bl   s5p_check_download
        #     mov  w21, w0            (the reason, for do_download)
        #     cbz  w0, <normal boot>
        #
        # and six of the seven reasons it can answer are explicit requests:
        # param[0] == 1 or 0xd, the 0xabcf magic in param[3], param[4], a
        # pressed key. The seventh is the one a USB-booted device falls into --
        # is_normal_booting() == 0 (MINFORM is the reset value on a cold boot)
        # together with ifconn_check_jig_adc_value() == 1 (a cable is attached
        # by definition, the payload arrives over it).
        #
        # Replace the CALL with `mov w0, #0` rather than making the branch
        # unconditional. The difference matters: the normal-boot path opens
        # with `bl get_param(w0)`, so it reads w0 as a parameter INDEX. Forcing
        # the branch leaves the download reason in w0 and the first thing the
        # normal path does is fetch the wrong parameter -- which is exactly how
        # the first attempt died, silently, with a black screen. Returning 0
        # from the call reproduces the legitimate "no reason to download" state
        # register for register, and the keypad escape is the only thing lost.
        func = find_function_by_name_string(self.data, "s5p_check_download")
        callers = [o for o in range(0, len(self.data) - 3, 4)
                   if is_bl(self.data, o) and bl_target(self.data, o) == func]
        if len(callers) != 1:
            raise KeyError(f"s5p_check_download has {len(callers)} callers, expected 1")
        site = callers[0]
        # Confirm the shape before touching it: the test has to be a `cbz w0`
        # within a few instructions, or this is not the fork.
        for step in range(1, 5):
            word = u32(self.data, site + 4 * step)
            if word & 0xFF00001F == 0x34000000:          # cbz w0, label
                break
        else:
            raise KeyError("no `cbz w0, label` within 4 instructions of the call")
        self._write(site, bytes.fromhex("00 00 80 52"),   # mov w0, #0
                    "s5p_check_download -> 0")

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
    ap.add_argument("--normal-boot", action="store_true",
                    help="force the Download-vs-normal-boot fork to normal boot")
    ap.add_argument("--dry-run", action="store_true",
                    help="locate and report patches without writing")
    args = ap.parse_args(argv)

    data = bytearray(open(args.image, "rb").read())
    p = Patcher(data, dry_run=args.dry_run)

    p.patch_have_this_mode()
    p.patch_eng_efuse_bits()
    if args.normal_boot:
        p.patch_normal_boot()
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
