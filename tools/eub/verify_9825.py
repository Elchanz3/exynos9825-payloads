#!/usr/bin/env python3
# Verify an Exynos9825 sboot.bin the way the DEVICE does, not the way we signed it.
#
# This exists because a signer and its own key will always agree with each other.
# The 9825 is CodeSigner V5 / ECDSA P-384 (sign_type 4); signing it as RSA
# (sign_type 0) puts the signature at end-0x110, which on this SoC is the
# *unsigned* padding after the real signature at end-0x200 -- so an RSA resign
# verifies perfectly against its own RSA key while the device rejects the image.
#
# So: always verify against the public key EMBEDDED IN THE IMAGE, using split.py's
# own verify functions, and require that the stock Samsung key is REJECTED.
#
# usage: verify_9825.py <sboot.bin> [...]
#        exit 0 only if every image fully passes as our-key-signed.

import hashlib
import hmac as hmaclib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

from sbl1 import SBL1ECDSA
from split import get_target_boundary, is_good_sig_ecdsa, load_public_key_p348

# Stock N975F keys, so a resign that silently kept them is reported as a failure.
STOCK_ST2_TEE = bytes.fromhex(
    "00" * 20
    + "a6bc5d80a0612e824034826d76061136596c0835b58805c83ccfaa01ce13e442"
    + "5cf439254e3d4b96743c9a73550bc71b"
    + "00" * 20
    + "ba8227eee27c74d554c467119b552aef76bc49bdd4bb840d561607335b95e999"
    + "9ea3767424b0a46748348954959f7d41"
)
STOCK_ST1 = bytes.fromhex(
    "00" * 20
    + "d163d059ef372418d12e3b77f11479df3fd2b3fafa4cd7655aa29f1bd8cacf13"
    + "2c756796da7f75dd8946089f9161c868"
    + "00" * 20
    + "76ee369c2c7e44b059403613b7698108deaf75bd86cbc2d68ad631c8f641a32c"
    + "604c62d049712a979f51fa3bdb1c833f"
)

# offset, size, name -- the ST2-signed stages of s5e9825 (pad/tail are unsigned)
STAGES = (
    (0x003000, 0x013000, "fwbl1.bin"),
    (0x016000, 0x052000, "bl2.bin"),
    (0x0A4000, 0x180000, "u-boot.bin"),
    (0x224000, 0x040000, "el3_mon.bin"),
    (0x264000, 0x100000, "secure_payload.bin"),
)

CLEAN_BLOB_LEN = 524


def load_point(blob):
    # A mangled blob (e.g. an RSA pubkey written into the ECDSA slot) is not a
    # curve point at all. Report that as a failure, never as a traceback.
    try:
        return load_public_key_p348(blob)
    except ValueError:
        return None


def clean_blob_shape(blob):
    # pubkey_blob(sign_type != 0) = 20*00 + x(48 BE) + 20*00 + y(48 BE) + 388*00
    return (
        len(blob) == CLEAN_BLOB_LEN
        and blob[:20] == bytes(20)
        and blob[0x44:0x58] == bytes(20)
        and blob[0x88:] == bytes(CLEAN_BLOB_LEN - 0x88)
    )


def verify_st1(data, footer, sbl1_size):
    # sign_st1 writes `checksum` AFTER signing and the checksum is inside the
    # signed range, so the checksum bytes must be zeroed to verify.
    key = load_point(bytes(footer.st1_publickey))
    if key is None:
        return False
    sig_offset = SBL1ECDSA(sbl1_size).signature.offset
    body = data[:4] + bytes(4) + data[8:sig_offset]
    sig = bytes(footer.signature)
    r = int.from_bytes(sig[:68], "big")
    s = int.from_bytes(sig[68:136], "big")
    try:
        key.verify(
            encode_dss_signature(r, s),
            hashlib.sha512(body).digest(),
            ec.ECDSA(Prehashed(hashes.SHA512())),
        )
    except InvalidSignature:
        return False
    return True


def verify(path, keys_dir):
    data = open(path, "rb").read()
    sbl1_size = 512 * int.from_bytes(data[:4], "little")
    footer = SBL1ECDSA(sbl1_size).from_buffer_copy(data[:sbl1_size])

    print(f"### {path}  len=0x{len(data):x}  sbl1=0x{sbl1_size:x}")
    if footer.codesigner_version != 5:
        print(f"  FAIL: codesigner_version={footer.codesigner_version}, expected 5")
        return False
    print(
        f"  codesigner_version=5 ap_info={footer.ap_info!r} "
        f"rb_count={footer.rb_count} signing_type={footer.signing_type}"
    )

    ok = True
    tee = bytes(footer.st2_key_tee)
    ree = bytes(footer.st2_key_ree)
    st1 = bytes(footer.st1_publickey)

    # An embedded key is the padded 0x20c blob; the STOCK_* constants are the
    # 136-byte point. Comparing the blobs made every image read is_stock=False
    # on a length mismatch, which hid the one case that matters below.
    def same_key(blob, stock):
        return blob[:len(stock)] == stock

    print("  -- embedded keys")
    key_is_stock = {}
    for name, blob, stock in (
        ("st2_key_tee", tee, STOCK_ST2_TEE),
        ("st2_key_ree", ree, STOCK_ST2_TEE),
        ("st1_publickey", st1, STOCK_ST1),
    ):
        shape = clean_blob_shape(blob)
        is_stock = same_key(blob, stock)
        key_is_stock[name] = is_stock
        # st2_key_tee is allowed to be Samsung's: see keeps_stock_st2 below.
        # The ST1 anchor never is -- it is the one thing we must own.
        tolerated = is_stock and name == "st2_key_tee"
        good = shape and (not is_stock or tolerated)
        status = "OK  " if good else "FAIL"
        ok &= good
        print(
            f"     {status} {name:14} shape_clean={shape} is_stock={is_stock} "
            f"x={blob[0x14:0x24].hex()}..."
        )

    keeps_stock_st2 = key_is_stock["st2_key_tee"]

    print("  -- ST1 (epbl)")
    st1_ok = verify_st1(data, footer, sbl1_size)
    ok &= st1_ok
    print(f"     {'OK  ' if st1_ok else 'FAIL'} ECDSA P-384 vs embedded st1_publickey")
    expect = struct.pack("<I", footer.checksum)
    got = hashlib.sha512(data[0x10:sbl1_size]).digest()[:4]
    ok &= expect == got
    print(f"     {'OK  ' if expect == got else 'FAIL'} checksum == sha512(data[0x10:sbl1_size])[:4]")

    hmac_path = os.path.join(keys_dir, "hmac.bin")
    if os.path.exists(hmac_path):
        hmac_key = open(hmac_path, "rb").read()
        want = hmaclib.digest(hmac_key, st1[:136], hashlib.sha512)[:32]
        match = want == bytes(footer.hmac)
        ok &= match
        print(f"     {'OK  ' if match else 'FAIL'} footer.hmac == HMAC-SHA512(hmac_key, st1_pub[:136])[:32]")
    else:
        print(f"     SKIP footer.hmac (no {hmac_path})")

    ours = {
        label: key
        for label, key in (("ours/tee", load_point(tee)), ("ours/ree", load_point(ree)))
        if key is not None
    }
    if not ours:
        print("     FAIL no usable ST2 key embedded in the image (not a curve point)")
        print("  ==> FAIL\n")
        return False
    stock_key = {"STOCK": load_public_key_p348(STOCK_ST2_TEE)}

    if keeps_stock_st2:
        print("  -- ST2 stages (this image KEEPS Samsung's ST2-TEE key on purpose,")
        print("                so the stock stages must still verify; the usual")
        print("                'must NOT pass with STOCK' rule cannot apply here)")
    else:
        print("  -- ST2 stages (must pass with ours, must NOT pass with STOCK)")
    boundary = get_target_boundary(data)
    blocks = [(data[o : o + s], o + s - 0x210, n) for o, s, n in STAGES]
    blocks.append((data[:boundary], boundary - 0x210, f"WHOLE@0x{boundary:x}"))
    for blob, foot_off, name in blocks:
        rb, st, kt, ki = struct.unpack_from("<IIII", data, foot_off)
        hits = [
            label
            for label, key in {**ours, **stock_key}.items()
            for cd in (False, True)
            if is_good_sig_ecdsa(blob, key, cd)
        ]
        mine = any(h.startswith("ours") for h in hits)
        stolen = any(h == "STOCK" for h in hits)
        # With the stock ST2-TEE key embedded, "ours/tee" and "STOCK" are the
        # same key under two labels, so a STOCK hit carries no information.
        good = mine if keeps_stock_st2 else (mine and not stolen)
        ok &= good
        print(
            f"     {'OK  ' if good else 'FAIL'} {name:18} "
            f"rb={rb} sign_type={st} key_type={kt} key_index=0x{ki:08x} "
            f"-> {hits or 'NO MATCH'}"
        )

    print(f"  ==> {'PASS' if ok else 'FAIL'}\n")
    return ok


def main(argv):
    if not argv:
        print(__doc__ or "usage: verify_9825.py <sboot.bin> [...]", file=sys.stderr)
        return 2
    keys_dir = os.environ.get("KEYS_DIR", "keys")
    return 0 if all(verify(p, keys_dir) for p in argv) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
