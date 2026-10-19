#!/usr/bin/env python3
"""Differential gate for any image that may reach a one-shot OTP command.

Counting direct callers of the programming wrapper is not a safety property.
It proves only that no new `bl` reaches one resolved address, while an image
could still get there by `b`/`br`/`blr`, by branching into the middle of the
wrapper where the SMC arguments are built, by editing the console dispatch
table, or by changing an existing site's `x1` from 0x115 to 0x16. "No route
exists in stock" is false as well: the console route is there.

What does hold is differential. Pin the base by hash, declare every range
the patcher is allowed to touch, and require that the candidate differs from
the base nowhere else. Everything sensitive -- the three wrapper bodies,
every SMC site and the window that prepares its arguments, the dispatch
tables -- is then protected by construction, because it is simply not in the
allowlist.

usage:
  check_fuse_image_diff.py CANDIDATE [--base FILE] [--allow LO:HI ...]
                           [--expect-program-call] [--anchor HEX32]
"""
import argparse
import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_sp", str(Path(__file__).with_name("sboot_patch.py")))
_sp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sp)

STOCK_SBOOT = "/home/chanz22/EUB-N10/9825_customkey/input/sboot.bin"
UBOOT_OFF, UBOOT_LEN = 0xA4000, 0x180000
SMC = 0xD4000003
ARG_WINDOW = 0x20          # bytes before an SMC that build x0..x3

# The old fuse chain put its stub over check_signature, which has 13 callers,
# and never carried the Secure-Payload sentinel bypass, so it could not even
# reach the path it was meant to run on. It must never be accepted again.
REFUSED = {
    "7d7609efbb596bba3a0c2f97e0daa081731a56048b3719e79f3ca23cbfb53862":
        "the superseded key2_program_chain u-boot: 13 call sites and no "
        "sentinel bypass",
}

ONE_SHOT = (
    ("program ROM_SECURE_BOOT_KEY2", "[OTP] ROM_SECURE_BOOT_KEY2 program start\n"),
    ("program USE_ROM_SEC_BOOT_KEY2", "[OTP] USE_ROM_SEC_BOOT_KEY2 program start\n"),
    ("program BAN_ROM_SEC_BOOT_KEY2", "[OTP] BAN_ROM_SEC_BOOT_KEY2 program start\n"),
)


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def is_entry(d, off):
    """A prologue whose predecessor ends the function before it."""
    if not _sp.is_prologue(d, off):
        return False
    if off == 0:
        return True
    prev = u32(d, off - 4)
    return (prev == 0xD65F03C0                 # ret
            or prev & 0xFC000000 == 0x14000000  # b
            or prev == 0xD503201F               # nop
            or prev == 0)


def function_extent(d, entry, limit=0x1000):
    """[entry, next entry).

    Stopping at the first `ret` is wrong: these wrappers return from several
    places, and for the KEY2 programming function the first one sits at
    0xa27e0 while the SMC that actually burns the fuse is at 0xa28f8. A check
    built that way protected 0x58 bytes and left the dangerous part of the
    function unguarded.
    """
    off = entry + 4
    while off < entry + limit:
        if is_entry(d, off):
            return entry, off
        off += 4
    raise SystemExit(f"no following entry within {limit:#x} of {entry:#x}")


def ranges_overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("candidate")
    ap.add_argument("--base", default=None,
                    help="base u-boot; default is the stock image's slice")
    ap.add_argument("--allow", action="append", default=[], metavar="LO:HI",
                    help="a range the patcher may change, hex, repeatable")
    ap.add_argument("--expect-program-call", action="store_true",
                    help="this is the fuse image: require exactly one")
    ap.add_argument("--anchor", help="32 bytes the fuse image must carry")
    args = ap.parse_args()

    cand = Path(args.candidate).read_bytes()
    if args.base:
        base = Path(args.base).read_bytes()
    else:
        base = Path(STOCK_SBOOT).read_bytes()[UBOOT_OFF:UBOOT_OFF + UBOOT_LEN]
    if len(cand) != len(base):
        raise SystemExit(f"size differs: {len(cand):#x} vs {len(base):#x}")

    ok = True

    def check(label, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"{label:<48} {'PASS' if cond else '*** FAIL ***'}  {detail}")

    digest = hashlib.sha256(cand).hexdigest()
    check("candidate is not a refused image",
          digest not in REFUSED, REFUSED.get(digest, digest[:16]))

    allow = []
    for spec in args.allow:
        lo, hi = (int(x, 16) for x in spec.split(":"))
        allow.append((lo, hi))

    # 1. every difference must sit inside the allowlist
    diff = [i for i in range(len(base)) if base[i] != cand[i]]
    outside = [i for i in diff
               if not any(lo <= i < hi for lo, hi in allow)]
    runs = []
    for i in outside:
        if runs and i == runs[-1][1]:
            runs[-1][1] = i + 1
        else:
            runs.append([i, i + 1])
    check(f"differences confined to the allowlist ({len(diff)} bytes differ)",
          not outside,
          " ".join(f"{a:#x}-{b:#x}" for a, b in runs[:6]) or "none outside")

    # 2. the allowlist must not reach anything that can issue an SMC
    smcs = [o for o in range(0, len(base) - 3, 4) if u32(base, o) == SMC]
    check("SMC site count unchanged",
          len([o for o in range(0, len(cand) - 3, 4) if u32(cand, o) == SMC])
          == len(smcs), f"{len(smcs)} sites")
    protected = [(o - ARG_WINDOW, o + 4) for o in smcs]
    for name, message in ONE_SHOT:
        entry = _sp.function_start_or_prologue(
            base, _sp.find_single_xref(base, message))
        protected.append(function_extent(base, entry))
    bad = [(a, p) for a in allow for p in protected if ranges_overlap(a, p)]
    check("allowlist disjoint from SMC windows and one-shot bodies",
          not bad,
          " ".join(f"{a[0]:#x}-{a[1]:#x} hits {p[0]:#x}-{p[1]:#x}"
                   for a, p in bad[:3]))

    # 3. the one-shot wrapper bodies, byte for byte
    for name, message in ONE_SHOT:
        entry = _sp.function_start_or_prologue(
            base, _sp.find_single_xref(base, message))
        lo, hi = function_extent(base, entry)
        check(f"{name} body identical",
              cand[lo:hi] == base[lo:hi], f"{lo:#x}-{hi:#x}")

    # 4. who reaches the programming wrapper, by any branch at all
    prog_entry = _sp.function_start_or_prologue(
        base, _sp.find_single_xref(base, ONE_SHOT[0][1]))
    plo, phi = function_extent(base, prog_entry)
    # Branches from outside the function only: a wrapper branches to its own
    # epilogue, and counting those would drown the signal.
    reach = []
    for o in range(0, len(cand) - 3, 4):
        if plo <= o < phi:
            continue
        w = u32(cand, o)
        if w & 0x7C000000 == 0x14000000:          # b / bl
            imm = w & 0x03FFFFFF
            if imm & (1 << 25):
                imm -= 1 << 26
            if plo <= o + imm * 4 < phi:
                reach.append(o)
    want = 1 if args.expect_program_call else 0
    check(f"branches reaching the programming wrapper == {want}",
          len(reach) == want,
          " ".join(f"{r:#x}" for r in reach) or "none")

    if args.expect_program_call and len(reach) == 1:
        site = reach[0]
        inside = any(lo <= site < hi for lo, hi in allow)
        check("that branch sits inside the allowlist", inside, f"{site:#x}")
        check("it targets the entry, not the middle",
              (lambda t: t == prog_entry)(
                  site + ((u32(cand, site) & 0x03FFFFFF)
                          - (1 << 26) * ((u32(cand, site) >> 25) & 1)) * 4),
              f"{prog_entry:#x}")

    if args.anchor:
        want_bytes = bytes.fromhex(args.anchor)
        check("the anchor is present exactly once",
              cand.count(want_bytes) == 1, args.anchor[:16] + "...")

    print()
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
