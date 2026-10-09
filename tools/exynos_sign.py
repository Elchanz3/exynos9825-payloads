#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# exynos_sign.py - RSA (sign_type 0) code signer for the Exynos9825 boot chain.
#
# Our own implementation of the Samsung "CodeSigner V4" RSA scheme used by the
# 9820/9825 family (confirmed: keystorage.bin is SLSI v0x20, 1056-byte RSA
# public-key slots). It generates an st1/st2 RSA-2048 key pair, emits the
# bootloader public-key blob, and signs an ST2 stage (bl2 / sboot / el3_mon)
# with an RSA-PSS(SHA-256) signature over the image up to and including the
# footer header. A self-consistency round trip (sign -> verify with our own
# public key over the same byte range) validates the cryptography offline.
#
# What this does NOT do yet: prove the device accepts our key. That depends on
# chaining our st2 public key into the predecessor ST1 (and entering the first
# stage unsigned via the EL3 foothold), which is the separate acceptance step.
#
# Usage:
#   exynos_sign.py genkey keys/            # write keys/st1.pem, keys/st2.pem
#   exynos_sign.py sign   stage.bin keys/  # resign an ST2 stage in place
#   exynos_sign.py verify stage.bin keys/  # verify an ST2 stage against our key
#   exynos_sign.py selftest stage.bin      # gen ephemeral key, sign+verify a copy

import argparse
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

RSA_MOD_SIZE = 0x100          # 2048-bit modulus
RSA_EXP_SIZE = 0x04
PUBKEY_BLOB_SIZE = 0x10C      # {u32 mod_size, modulus[0x100], u32 exp_size, exp[4]}
FOOTER_HEADER = 0x10          # rb_count, sign_type, key_type, key_index
SIG_SIZE = 0x100
FOOTER_SIZE = FOOTER_HEADER + SIG_SIZE  # 0x110
PSS_SALT = 0x20


def pubkey_blob(pub):
    n = pub.public_numbers()
    return struct.pack(
        f"<I{RSA_MOD_SIZE}sI{RSA_EXP_SIZE}s",
        RSA_MOD_SIZE, n.n.to_bytes(RSA_MOD_SIZE, "little"),
        RSA_EXP_SIZE, n.e.to_bytes(RSA_EXP_SIZE, "little"),
    )


def rsa_pss_sign(key, data):
    # Samsung stores the PSS signature byte-reversed.
    sig = key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT),
        hashes.SHA256(),
    )
    return sig[::-1]


def rsa_pss_verify(pub, signature, data):
    pub.verify(
        signature[::-1], data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT),
        hashes.SHA256(),
    )


def target_boundary(data):
    # A trailing "AVBf" footer records the real signed length; otherwise the
    # footer sits at the end of the image.
    if len(data) >= 0x40 and data[-0x40:-0x3C] == b"AVBf":
        return struct.unpack_from(">Q", data[-0x40:], 12)[0]
    return len(data)


def footer_offset(data):
    return target_boundary(data) - FOOTER_SIZE


def sign_st2(data, st2_key, rb_count=None, key_type=0, key_index=0):
    off = footer_offset(data)
    struct.pack_into("<4I", data, off,
                     rb_count if rb_count is not None else
                     struct.unpack_from("<I", data, off)[0],
                     0,            # sign_type 0 = RSA
                     key_type, key_index)
    signed = bytes(data[:off + FOOTER_HEADER])
    data[off + FOOTER_HEADER:off + FOOTER_SIZE] = rsa_pss_sign(st2_key, signed)
    return off


def verify_st2(data, st2_pub):
    off = footer_offset(data)
    signed = bytes(data[:off + FOOTER_HEADER])
    sig = bytes(data[off + FOOTER_HEADER:off + FOOTER_SIZE])
    rsa_pss_verify(st2_pub, sig, signed)
    return off


def load_key(path):
    return serialization.load_pem_private_key(open(path, "rb").read(), password=None)


def save_key(key, path):
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    open(path, "wb").write(pem)


def genkey(keys_dir):
    os.makedirs(keys_dir, exist_ok=True)
    for name in ("st1", "st2"):
        key = rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
        save_key(key, os.path.join(keys_dir, f"{name}.pem"))
        print(f"wrote {keys_dir}/{name}.pem")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Exynos9825 RSA code signer (sign_type 0)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey"); g.add_argument("keys_dir")
    s = sub.add_parser("sign"); s.add_argument("image"); s.add_argument("keys_dir")
    s.add_argument("--rb-count", type=int, default=None)
    v = sub.add_parser("verify"); v.add_argument("image"); v.add_argument("keys_dir")
    t = sub.add_parser("selftest"); t.add_argument("image")
    args = ap.parse_args(argv)

    if args.cmd == "genkey":
        genkey(args.keys_dir)
        return 0

    if args.cmd == "selftest":
        data = bytearray(open(args.image, "rb").read())
        key = rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
        off = sign_st2(data, key, rb_count=0)
        print(f"signed ST2 footer @0x{off:x} (image 0x{len(data):x}), "
              f"blob {len(pubkey_blob(key.public_key()))} bytes")
        try:
            verify_st2(data, key.public_key())
            print("round-trip verify: OK (signature matches our key over "
                  f"data[:0x{off + FOOTER_HEADER:x}])")
            return 0
        except InvalidSignature:
            print("round-trip verify: FAILED", file=sys.stderr)
            return 1

    data = bytearray(open(args.image, "rb").read())
    if args.cmd == "sign":
        st2 = load_key(os.path.join(args.keys_dir, "st2.pem"))
        off = sign_st2(data, st2, rb_count=args.rb_count)
        open(args.image, "wb").write(data)
        print(f"signed {args.image} ST2 footer @0x{off:x}")
    elif args.cmd == "verify":
        st2 = load_key(os.path.join(args.keys_dir, "st2.pem"))
        try:
            off = verify_st2(data, st2.public_key())
            print(f"verify OK @0x{off:x}")
        except InvalidSignature:
            print("verify FAILED", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
