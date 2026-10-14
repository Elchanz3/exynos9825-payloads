#!/usr/bin/env python3
"""Recover function names from an Exynos9825 sboot/u-boot image.

Samsung's u-boot logs with `printf("%s: ...", __func__, ...)`, so the name of
almost every interesting function is in the image as a plain string, loaded
right before the call. Resolving those loads gives a symbol table for an image
that ships with none.

The one thing that makes this non-obvious: the pointer is built with

    adrp x19, <page>
    add  x19, x19, #0x6f8
    add  x19, x19, #0x98      <- a SECOND add, same register

so a scanner that only accepts `adrp` + one `add` (which is what
tools/sboot_patch.py needs for format strings) finds nothing for __func__ and
reports zero xrefs. Both shapes are handled here.

A name is attributed to the nearest called entry at or before the load, which
is the same rule tools/sboot_patch.py uses to find a function start.

Usage:
    tools/sboot_symbols.py sboot_stage.bin                 # every name found
    tools/sboot_symbols.py sboot_stage.bin --grep download # names matching
    tools/sboot_symbols.py sboot_stage.bin --at 0xc9003280 # name of one VA
"""
import argparse
import re
import sys

BASE = 0xc9000000
IDENT = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]{2,63}$")


def u32(data, off):
    return int.from_bytes(data[off:off + 4], "little")


def sign_extend(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def is_bl(data, off):
    return u32(data, off) & 0xFC000000 == 0x94000000


def bl_target(data, off):
    return off + (sign_extend(u32(data, off) & 0x03FFFFFF, 26) << 2)


def is_prologue(data, off):
    return u32(data, off) & 0xFFC003FF in (0xA98003FD, 0xD10003FF)


def adrp_page(data, off):
    word = u32(data, off)
    if word & 0x9F000000 != 0x90000000:
        return None, None
    imm = ((word >> 29) & 3) | (((word >> 5) & 0x7FFFF) << 2)
    return (off & ~0xFFF) + (sign_extend(imm, 21) << 12), word & 31


def add_imm(word, reg):
    """immediate of `add xreg, xreg, #imm` (optionally lsl 12), else None."""
    if word & 0xFF000000 != 0x91000000:
        return None
    if (word >> 5) & 31 != reg or word & 31 != reg:
        return None
    imm = (word >> 10) & 0xFFF
    return imm << 12 if word & 0x400000 else imm


def pointer_targets(data):
    """Every (load offset, resolved byte offset) an adrp(+add)(+add) forms."""
    out = []
    for off in range(0, len(data) - 12, 4):
        page, reg = adrp_page(data, off)
        if page is None:
            continue
        total = 0
        last = off
        # Up to two adds, which do not have to be adjacent to the adrp.
        for _ in range(2):
            found = False
            for distance in range(4, 21, 4):
                imm = add_imm(u32(data, last + distance), reg)
                if imm is not None:
                    total += imm
                    last = last + distance
                    found = True
                    break
            if not found:
                break
        if total:
            out.append((off, page + total))
    return out


def call_targets(data):
    return sorted({bl_target(data, o) for o in range(0, len(data) - 3, 4)
                   if is_bl(data, o)})


def cstring(data, off, limit=72):
    end = data.find(b"\0", off)
    if end < 0 or not (0 < end - off <= limit):
        return None
    return data[off:end]


def symbols(data):
    """{function offset: name} recovered from __func__ loads."""
    entries = call_targets(data)
    names = {}
    for load, target in pointer_targets(data):
        s = cstring(data, target)
        if not s or not IDENT.match(s):
            continue
        # The nearest called entry at or before the load, with a real prologue.
        cand = [t for t in entries if load - 0x1000 <= t <= load]
        if not cand:
            continue
        func = max(cand)
        if not is_prologue(data, func):
            continue
        name = s.decode()
        names.setdefault(func, set()).add(name)
    # A function usually references only its own name; keep the ambiguous ones
    # visible rather than guessing.
    return {f: "|".join(sorted(n)) for f, n in names.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--base", default=hex(BASE),
                    help="load address of the image (default %(default)s)")
    ap.add_argument("--grep", help="only names matching this substring")
    ap.add_argument("--at", help="print the name of the function at this VA")
    args = ap.parse_args(argv)

    base = int(args.base, 0)
    data = open(args.image, "rb").read()
    syms = symbols(data)

    if args.at:
        want = int(args.at, 0) - base
        if want in syms:
            print(f"0x{base + want:08x} {syms[want]}")
            return 0
        before = [f for f in syms if f <= want]
        if before:
            f = max(before)
            print(f"0x{base + want:08x} inside 0x{base + f:08x} {syms[f]}")
            return 0
        print("no name", file=sys.stderr)
        return 1

    for func in sorted(syms):
        name = syms[func]
        if args.grep and args.grep.lower() not in name.lower():
            continue
        print(f"0x{base + func:08x}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
