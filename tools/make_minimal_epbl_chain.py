#!/usr/bin/env python3
"""Build the smallest custom chain that still boots from UFS, to split one
question in two: is the failure our resigned EPBL, or our resigned stages?

Every byte outside the EPBL's signing block is Samsung's. The EPBL keeps
Samsung's ST2-TEE public key, so the stock fwbl1/bl2/u-boot/el3_mon/
secure_payload verify against the key they were actually signed with. Only
the ST1 anchor is ours, which is the one thing the BootROM checks and the one
thing our payload redirects.

Layout of the ST1 block, confirmed against SBL1ECDSA(0x3000) and against the
BootROM verifier's own operands:

    0x26d0  codesigner_version = 5      ctx base, = image_end - 0x930
    0x26d4  ap_info "SLSI"
    0x26d8  time (u64)
    0x26e0  rb_count = 9
    0x26e4  signing_type = 4
    0x272c  st2_key_tee   (524 = 0x20c) ctx+0x5c, exactly the verifier's x3/w4
    0x2938  st2_key_ree   (524)
    0x2b44  func_ptr      (128)         ctx+0x474; [ctx+0x478] and [ctx+0x484]
                                        are entries the EPBL fills at runtime
    0x2bd0  st1_publickey (524)
    0x2ddc  hmac          (32)          HMAC-SHA512(hmac.bin, st1_pub[:136])[:32];
                                        the OTP anchor is this XOR hmac.bin
    0x2e00  signature     (136)
    0x2e88  padding       (376)

A public key blob is 20 zero bytes, X (48, big-endian), 20 zero bytes,
Y (48), then 388 zero bytes.

verify_9825.py used to report ==> FAIL on this image, and the verdict did
not apply. Its rule for the ST2 stages is "must pass with ours, must NOT
pass with STOCK", which is right for ecdsa_resigned and ecdsa_eng and wrong
for this build by construction: keeping Samsung's ST2-TEE key is the whole
point, so the stock stages must still verify.

Writing that down was not enough -- run_custom_key_test.sh runs under
`set -e`, so the FAIL aborted the script and the hardware test never
started. The verifier now recognises the case instead: when the embedded
st2_key_tee *is* Samsung's, it says so and drops the "must NOT pass with
STOCK" clause, because "ours/tee" and "STOCK" are then one key under two
labels. The relaxation is derived from the image, not from a flag, so it
cannot be turned on for a chain that should be held to the strict rule.
A copy of the fixed verifier is kept at tools/eub/verify_9825.py, since
$EUB is not version controlled.

Checked: ecdsa_resigned, ecdsa_eng and ecdsa_fuse still take the strict
path and still pass, and a one-byte body change to a stage of this image
is still caught (bl2 -> NO MATCH, whole-image footer -> NO MATCH, exit 1).

What applies here, and passes: ST1 verifies against our embedded
st1_publickey, the header checksum matches, footer.hmac is consistent with
hmac_key, and the whole-image footer verifies against our ST2-REE key.

The container's own ST2 footer covers the whole prefix including the EPBL, so
it has to be re-signed. It is signed with our ST2-REE key and marked
key_type=1, and our ST2-REE public key goes in the REE slot, so that footer
stays self-consistent without disturbing the TEE slot the stages need. Its
376-byte trailing field is preserved from stock rather than zeroed, which is
what scripts/sign.py does and what this build deliberately does not.
"""
import argparse
import hashlib
import hmac as hmaclib
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

EPBL_SIZE = 0x3000
# SBL1ECDSA(0x3000) field offsets.
OFF_CHECKSUM = 0x04
OFF_TIME = 0x26D8
OFF_ST2_TEE = 0x272C
OFF_ST2_REE = 0x2938
OFF_ST1_PUB = 0x2BD0
OFF_HMAC = 0x2DDC
OFF_SIGSIZE = 0x2DFC
OFF_SIGNATURE = 0x2E00
KEY_BLOB = 524
SIG_LEN = 136

# Container ST2 footer, from get_target_boundary() on the stock image.
CONTAINER_FOOTER = 0x364100
CONTAINER_SIGNED_END = CONTAINER_FOOTER + 0x10
CONTAINER_SIG = CONTAINER_FOOTER + 0x10


def load_key(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def pubkey_blob(pub):
    n = pub.public_numbers()
    return (b"\x00" * 20 + n.x.to_bytes(48, "big")
            + b"\x00" * 20 + n.y.to_bytes(48, "big") + b"\x00" * 388)


def sign_p384(key, digest):
    r, s = decode_dss_signature(
        key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA512()))))
    return (b"\x00" * 20 + r.to_bytes(48, "big")
            + b"\x00" * 20 + s.to_bytes(48, "big"))


def header_digest(data):
    return hashlib.sha512(bytes(data[0x10:])).digest()[:4]


def verify_p384(pub_blob, digest, signature):
    """Verify the way the device does: raw r||s in 0x44-byte slots."""
    x = int.from_bytes(pub_blob[20:68], "big")
    y = int.from_bytes(pub_blob[88:136], "big")
    r = int.from_bytes(signature[20:68], "big")
    s = int.from_bytes(signature[88:136], "big")
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key()
    try:
        pub.verify(encode_dss_signature(r, s), digest,
                   ec.ECDSA(utils.Prehashed(hashes.SHA512())))
        return True
    except Exception:
        return False


PAD_OFFSET = 0x68000          # pad.bin, unsigned filler between bl2 and u-boot
EPBL_PAD = 0x2E88             # ST1 `padding`, past the end of the ST1 signature


def pad_tamper(args):
    """Stock image with one byte of unsigned filler flipped.

    No stage signature covers `pad.bin`; only the container footer at
    0x364100 does, because it is taken over the whole prefix. So this image
    has every stage valid under Samsung's own keys and exactly one thing
    wrong: the container signature. Booting it answers a question no other
    test can — whether that footer is checked at boot at all, or whether it
    is only Odin/model metadata.

    It matters because the minimal chain cannot make that footer valid: it
    keeps Samsung's ST2-TEE key so the stock stages verify, and we do not
    have Samsung's private half to re-sign the container with.
    """
    stock = Path(args.stock).read_bytes()
    data = bytearray(stock)
    before = data[PAD_OFFSET]
    data[PAD_OFFSET] ^= 0xFF
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))
    print(f"wrote {out}  {len(data):#x} bytes")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"flipped pad byte at {PAD_OFFSET:#x}: {before:#04x} -> {data[PAD_OFFSET]:#04x}")
    print(f"bytes differing from stock: "
          f"{sum(1 for a, b in zip(stock, data) if a != b)}")
    print("every stage signature is Samsung's own and still valid;")
    print("only the container footer at 0x364100 no longer matches.")
    return 0


def epbl_pad_tamper(args):
    """Stock image with one byte of the EPBL's unsigned ST1 padding flipped.

    Same question as --pad-tamper, but inside the first 0x3000 bytes, which
    is the one region of the partition we can already read back from EUB: the
    BootROM loader fetches exactly 0x18 sectors and `native-load-diagnose`
    reports the loaded BL1 checksum. So a black screen can be told apart from
    a flash that never took.

    The ST1 signature ends at 0x2e00 and covers data[:0x2e00], so `padding` at
    0x2e88 is outside it and the anchor stays valid. The header checksum is
    sha512(data[0x10:])[:4], which does cover it, so it is recomputed — and
    that is free, because the checksum is zeroed while ST1 is signed and is
    therefore not part of the signed data. The container footer covers the
    whole prefix, so it alone becomes invalid.
    """
    stock = Path(args.stock).read_bytes()
    data = bytearray(stock)
    before = data[EPBL_PAD]
    data[EPBL_PAD] ^= 0xFF
    data[OFF_CHECKSUM:OFF_CHECKSUM + 4] = header_digest(data[:EPBL_SIZE])
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))

    st1_pub = bytes(data[OFF_ST1_PUB:OFF_ST1_PUB + KEY_BLOB])
    d = bytearray(data[:OFF_SIGNATURE])
    d[4:8] = bytes(4)
    ok = verify_p384(st1_pub, hashlib.sha512(bytes(d)).digest(),
                     bytes(data[OFF_SIGNATURE:OFF_SIGNATURE + SIG_LEN]))
    print(f"wrote {out}  {len(data):#x} bytes")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"flipped EPBL ST1 padding at {EPBL_PAD:#x}: "
          f"{before:#04x} -> {data[EPBL_PAD]:#04x}")
    print(f"EPBL header checksum recomputed to "
          f"{bytes(data[4:8]).hex()} (stock {stock[4:8].hex()})")
    print(f"EPBL ST1 still verifies against Samsung's key: "
          f"{'PASS' if ok else 'FAIL'}")
    print(f"bytes differing from stock: "
          f"{sum(1 for a, b in zip(stock, data) if a != b)}")
    print("every stage signature is Samsung's own and still valid;")
    print("only the container footer at 0x364100 no longer matches.")
    print()
    print("after flashing, confirm the write reached UFS with:")
    print("  tools/run_ubstage_test.sh native-load-diagnose")
    print(f"  UFSMETA must report BL1 checksum {int.from_bytes(data[4:8],'little'):#010x}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stock", default="/home/chanz22/EUB-N10/9825_customkey/input/sboot.bin")
    ap.add_argument("--keys", default="/home/chanz22/EUB-N10/9825_customkey/keys")
    ap.add_argument("--out", default="build/minimal_epbl_chain/sboot.bin")
    ap.add_argument("--keep-ree", action="store_true",
                    help="leave Samsung's st2_key_ree and the container footer "
                         "untouched, so the only difference from stock is the "
                         "ST1 anchor; splits the REE slot off from the anchor")
    ap.add_argument("--epbl-pad-tamper", action="store_true",
                    help="better control: flip one byte of the EPBL's own "
                         "unsigned ST1 padding, which the UFS-load probe can "
                         "read back and confirm")
    ap.add_argument("--pad-tamper", action="store_true",
                    help="instead, flip one byte of the unsigned pad filler and "
                         "leave everything else stock, to find out whether the "
                         "container footer is enforced at boot at all")
    args = ap.parse_args()

    if args.pad_tamper:
        return pad_tamper(args)
    if args.epbl_pad_tamper:
        return epbl_pad_tamper(args)

    stock = Path(args.stock).read_bytes()
    if len(stock) != 0x400000:
        raise SystemExit(f"stock image is {len(stock):#x} bytes, expected 0x400000")
    data = bytearray(stock)

    st1 = load_key(f"{args.keys}/4/st1.pem")
    st2r = load_key(f"{args.keys}/4/st2r.pem")
    hmac_key = Path(f"{args.keys}/hmac.bin").read_bytes()

    stock_tee = bytes(stock[OFF_ST2_TEE:OFF_ST2_TEE + KEY_BLOB])
    stock_time = struct.unpack_from("<Q", stock, OFF_TIME)[0]

    # --- the EPBL: swap only the ST1 anchor and the REE slot ---
    st1_pub = pubkey_blob(st1.public_key())
    data[OFF_ST1_PUB:OFF_ST1_PUB + KEY_BLOB] = st1_pub
    if not args.keep_ree:
        data[OFF_ST2_REE:OFF_ST2_REE + KEY_BLOB] = pubkey_blob(st2r.public_key())
    data[OFF_HMAC:OFF_HMAC + 0x20] = hmaclib.digest(
        hmac_key, st1_pub[:136], hashlib.sha512)[:32]
    # Keep Samsung's timestamp and TEE key: the stages must still verify.
    struct.pack_into("<Q", data, OFF_TIME, stock_time)
    assert bytes(data[OFF_ST2_TEE:OFF_ST2_TEE + KEY_BLOB]) == stock_tee

    struct.pack_into("<I", data, OFF_CHECKSUM, 0)   # signed with it zeroed
    epbl_digest = hashlib.sha512(bytes(data[:OFF_SIGNATURE])).digest()
    data[OFF_SIGNATURE:OFF_SIGNATURE + SIG_LEN] = sign_p384(st1, epbl_digest)
    data[OFF_CHECKSUM:OFF_CHECKSUM + 4] = header_digest(data[:EPBL_SIZE])

    if args.keep_ree:
        # Leave Samsung's REE key in place and leave the container footer
        # exactly as it came. The footer is then stale, which the
        # epbl_pad_tamper run proved is harmless at boot -- only u-boot's
        # Download/OTA path parses it. That trade buys a chain whose only
        # difference from stock is the ST1 anchor itself.
        pass
    else:
        # --- the container footer, re-signed with the REE key it now carries ---
        struct.pack_into("<I", data, CONTAINER_FOOTER + 8, 1)   # key_type = ree
        container_digest = hashlib.sha512(bytes(data[:CONTAINER_SIGNED_END])).digest()
        data[CONTAINER_SIG:CONTAINER_SIG + SIG_LEN] = sign_p384(st2r, container_digest)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))

    # --- verify the way the device does, not the way we wrote it ---
    print(f"wrote {out}  {len(data):#x} bytes")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")
    print()
    ok = True

    def signed_digest(img, end, zero_header):
        view = bytearray(img[:end])
        if zero_header:
            view[4:8] = bytes(4)
        return hashlib.sha512(bytes(view)).digest()

    d = signed_digest(data, OFF_SIGNATURE, True)
    r = verify_p384(st1_pub, d, bytes(data[OFF_SIGNATURE:OFF_SIGNATURE + SIG_LEN]))
    print(f"EPBL ST1 against OUR st1 key          : {'PASS' if r else 'FAIL'}")
    ok &= r
    r = not verify_p384(bytes(stock[OFF_ST1_PUB:OFF_ST1_PUB + KEY_BLOB]), d,
                        bytes(data[OFF_SIGNATURE:OFF_SIGNATURE + SIG_LEN]))
    print(f"EPBL ST1 rejected by Samsung's key    : {'PASS' if r else 'FAIL'}")
    ok &= r
    r = header_digest(data[:EPBL_SIZE]) == bytes(data[4:8])
    print(f"EPBL header checksum                  : {'PASS' if r else 'FAIL'}")
    ok &= r
    r = bytes(data[OFF_ST2_TEE:OFF_ST2_TEE + KEY_BLOB]) == stock_tee
    print(f"ST2-TEE slot still Samsung's          : {'PASS' if r else 'FAIL'}")
    ok &= r

    # Each stock stage must verify against the TEE key the EPBL still carries.
    stages = {"fwbl1": (0x3000, 0x13000), "bl2": (0x16000, 0x52000),
              "u-boot": (0xA4000, 0x180000), "el3_mon": (0x224000, 0x40000),
              "secure_payload": (0x264000, 0x100000)}
    for name, (off, size) in stages.items():
        img = bytes(data[off:off + size])
        foot = size - 0x210
        d = signed_digest(img, foot + 0x10, name == "fwbl1")
        r = verify_p384(stock_tee, d, img[foot + 0x10:foot + 0x10 + SIG_LEN])
        nz = sum(1 for b in img[foot + 0x98:foot + 0x210] if b)
        print(f"{name:<15} ST2 against Samsung TEE key: "
              f"{'PASS' if r else 'FAIL'}   trailing field {nz}/376 non-zero")
        ok &= r

    d = signed_digest(data, CONTAINER_SIGNED_END, False)
    r = verify_p384(pubkey_blob(st2r.public_key()), d,
                    bytes(data[CONTAINER_SIG:CONTAINER_SIG + SIG_LEN]))
    print(f"container ST2 against OUR st2r key    : {'PASS' if r else 'FAIL'}")
    ok &= r

    changed = sum(1 for a, b in zip(stock, data) if a != b)
    print(f"\nbytes differing from stock: {changed} of {len(stock)}")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
