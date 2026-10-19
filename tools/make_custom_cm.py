#!/usr/bin/env python3
"""Re-sign the CM partition image with our ST2-TEE key.

Hardware narrowed the fuse blocker to one message: with the Secure-Payload
sentinel bypassed, u-boot's CM/LDFW initializer reads the CM partition,
measures the blob, and then reports

    ldfw: signature of ldfw is corrupted! ret = [0x%llX]

because `cm.bin` is signed by Samsung while our chain carries our keys.

The container turns out to have exactly the layout the sboot container uses,
and the offline verifier built for that one accepts it unchanged:

    0x3f4000  SignerInfo  "SignerVer03" "69546063R"
    0x3f4100  ST2 footer  rb_count=9 sign_type=4 key_type=0
                          key_index=0x31fb208f
    0x3f4110  signature, over sha512(cm[:0x3f4110])
    0x3f4198  the 376-byte trailing field, 374/376 non-zero in stock

So re-signing is the same operation, with one deliberate difference from
`scripts/sign.py`: the trailing field is preserved rather than zeroed. Its
name there is a reverse-engineering guess and nothing has shown it to be
discardable.

Nothing is written to the device by this tool.
"""
import argparse
import hashlib
import importlib.util
import struct
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_mk", Path(__file__).with_name("make_minimal_epbl_chain.py"))
_mk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mk)

SIGNER_MAGIC = b"SignerVer03"
SIG_LEN = 136


def locate(data):
    """(signerinfo, footer) offsets, found by the signer magic."""
    hits = [i for i in range(0, len(data) - len(SIGNER_MAGIC), 0x100)
            if data[i:i + len(SIGNER_MAGIC)] == SIGNER_MAGIC]
    if len(hits) != 1:
        raise SystemExit(f"expected one SignerInfo block, found {len(hits)}")
    return hits[0], hits[0] + 0x100


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stock", default="/home/chanz22/EUB-N10/cm.bin")
    ap.add_argument("--keys", default="/home/chanz22/EUB-N10/9825_customkey/keys")
    ap.add_argument("--out", default="build/custom_cm/cm.bin")
    args = ap.parse_args()

    stock = Path(args.stock).read_bytes()
    data = bytearray(stock)
    signerinfo, footer = locate(data)
    signed_end = footer + 0x10
    st2t = _mk.load_key(f"{args.keys}/4/st2t.pem")
    stock_tee = Path("/home/chanz22/EUB-N10/9825_customkey/input/sboot.bin").read_bytes()[
        _mk.OFF_ST2_TEE:_mk.OFF_ST2_TEE + _mk.KEY_BLOB]

    rb, sign_type, key_type, key_index = struct.unpack_from("<IIII", data, footer)
    print(f"SignerInfo {signerinfo:#x}   footer {footer:#x}")
    print(f"rb_count={rb} sign_type={sign_type} key_type={key_type} "
          f"key_index={key_index:#010x}")
    if sign_type != 4 or key_type != 0:
        raise SystemExit("unexpected footer: this tool only handles ECDSA/TEE")

    before = hashlib.sha512(bytes(data[:signed_end])).digest()
    if not _mk.verify_p384(stock_tee, before,
                           bytes(data[signed_end:signed_end + SIG_LEN])):
        raise SystemExit("stock cm.bin does not verify against Samsung's TEE "
                         "key — refusing to touch an image I cannot model")
    print("stock signature vs Samsung TEE key        : PASS")

    trailing = bytes(data[footer + 0x98:footer + 0x210])
    data[signed_end:signed_end + SIG_LEN] = _mk.sign_p384(st2t, before)
    if bytes(data[footer + 0x98:footer + 0x210]) != trailing:
        raise SystemExit("the trailing field was disturbed")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))

    ours = _mk.pubkey_blob(st2t.public_key())
    after = hashlib.sha512(bytes(data[:signed_end])).digest()
    ok = _mk.verify_p384(ours, after,
                         bytes(data[signed_end:signed_end + SIG_LEN]))
    rejected = not _mk.verify_p384(stock_tee, after,
                                   bytes(data[signed_end:signed_end + SIG_LEN]))
    nz = sum(1 for b in data[footer + 0x98:footer + 0x210] if b)
    changed = sum(1 for a, b in zip(stock, data) if a != b)
    print(f"resigned signature vs OUR st2t key        : {'PASS' if ok else 'FAIL'}")
    print(f"resigned signature rejected by Samsung    : {'PASS' if rejected else 'FAIL'}")
    print(f"trailing field preserved                  : {nz}/376 non-zero")
    print(f"bytes differing from stock                : {changed} of {len(stock)}")
    print(f"\nwrote {out}")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")
    return 0 if (ok and rejected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
