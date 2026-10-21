#!/usr/bin/env python3
"""Check a vbmeta's hash descriptors against the images that will be flashed.

A board that loops on "Hash of data does not match digest in descriptor"
cannot tell you which partition it means -- the name scrolls past, or the
camera cutout sits on it. The same question is answerable on the host, with
no device and no weakening of anything: every descriptor carries its own
salt, digest and image_size, so the digest can simply be recomputed.

Usage:
    check_avb_descriptors.py --vbmeta vbmeta.img \\
        --image bootloader=sboot.bin --image cm=cm.bin ...

Reports PASS/FAIL per descriptor and exits nonzero if any named image
mismatches. Descriptors with no image given are listed as unchecked rather
than quietly ignored.
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

HDR = 256


def hash_descriptors(vb):
    (magic, _vmaj, _vmin, auth_sz, aux_sz) = struct.unpack_from(">4sIIQQ", vb, 0)
    if magic != b"AVB0":
        raise SystemExit("not a vbmeta image")
    out = {}
    off = HDR + auth_sz
    end = off + aux_sz
    while off + 16 <= end:
        tag, following = struct.unpack_from(">QQ", vb, off)
        total = 16 + following
        if total <= 16 or off + total > end:
            break
        if tag == 2:
            image_size = struct.unpack_from(">Q", vb, off + 16)[0]
            alg = bytes(vb[off + 24:off + 56]).rstrip(b"\x00").decode()
            name_len, salt_len, digest_len, _flags = struct.unpack_from(
                ">IIII", vb, off + 56)
            name = bytes(vb[off + 132:off + 132 + name_len]).decode()
            salt = bytes(vb[off + 132 + name_len:off + 132 + name_len + salt_len])
            dig = bytes(vb[off + 132 + name_len + salt_len:
                           off + 132 + name_len + salt_len + digest_len])
            out[name] = (image_size, alg, salt, dig)
        off += total
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vbmeta", required=True)
    ap.add_argument("--image", action="append", default=[], metavar="PART=FILE")
    args = ap.parse_args()

    vb = Path(args.vbmeta).read_bytes()
    descs = hash_descriptors(vb)
    given = dict(pair.split("=", 1) for pair in args.image)

    unknown = set(given) - set(descs)
    if unknown:
        raise SystemExit(f"no descriptor for: {', '.join(sorted(unknown))}")

    print(f"{args.vbmeta}  descriptors: {', '.join(sorted(descs))}\n")
    bad = 0
    for name in sorted(descs):
        image_size, alg, salt, want = descs[name]
        if name not in given:
            print(f"  {name:12} UNCHECKED  (covers {image_size:#x}, no image given)")
            continue
        if alg != "sha256":
            print(f"  {name:12} SKIPPED    (algorithm {alg})")
            continue
        blob = Path(given[name]).read_bytes()
        if len(blob) < image_size:
            print(f"  {name:12} *** FAIL *** image is {len(blob)} bytes, "
                  f"descriptor covers {image_size}")
            bad += 1
            continue
        got = hashlib.sha256(salt + blob[:image_size]).digest()
        ok = got == want
        bad += not ok
        print(f"  {name:12} {'PASS' if ok else '*** FAIL ***'}  "
              f"covers {image_size:#x} of {given[name]}")
        if not ok:
            print(f"               vbmeta says {want.hex()}")
            print(f"               image gives {got.hex()}")

    print()
    print("RESULT:", "PASS" if bad == 0 else f"FAIL ({bad} mismatched)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
