#!/usr/bin/env python3
"""Re-sign any bare ST2 container with our ST2-TEE key.

`make_custom_cm.py` finds its container by the `SignerVer03` magic, because
`cm.bin` carries a SignerInfo block 0x100 bytes ahead of the footer.
`keystorage.bin` does not: it has the footer alone.

    0x1df0  ST2 footer  rb_count=9 sign_type=4 key_type=0
                        key_index=0x31fb208f
    0x1e00  signature, over sha512(data[:0x1e00])

Which is the same signing rule, found a different way. This tool locates the
footer by its own field pattern instead of by a neighbouring magic, so it
covers both shapes and anything else Samsung signs this way.

WHY IT IS NEEDED
  Our bootloader verifies these containers against the ST2-TEE key embedded
  in our own EPBL. Samsung's images are signed with Samsung's key, so they
  fail. For `cm.bin` that failure stops a normal boot outright. For
  `keystorage.bin` it is quieter: keystorage does not load, `PO_AVB_KEY` is
  then missing, and the AVB callback reports

      Error while checking public key used to sign data. (2)

  which looks like a vbmeta problem and is not one.

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

SIG_LEN = 136
KEY_INDEX = 0x31FB208F


def locate_footer(data):
    """The ST2 footer offset, found by its own fields.

    rb_count and sign_type pin the scheme, key_index pins the vendor, and
    key_type says which slot verifies it. Four words is a narrow enough
    pattern that a false hit in 512 KB of key material is not a worry -- and
    the signature check below would catch one anyway.
    """
    hits = []
    for off in range(0, len(data) - SIG_LEN - 16, 4):
        rb, sign_type, key_type, key_index = struct.unpack_from("<IIII", data, off)
        if rb == 9 and sign_type == 4 and key_type in (0, 1) and key_index == KEY_INDEX:
            hits.append(off)
    if len(hits) != 1:
        raise SystemExit(f"expected one ST2 footer, found {len(hits)}: "
                         + ", ".join(hex(h) for h in hits))
    return hits[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stock", help="the Samsung-signed image")
    ap.add_argument("out", help="where to write the re-signed copy")
    ap.add_argument("--keys", default="/home/chanz22/EUB-N10/9825_customkey/keys")
    ap.add_argument("--proof", help="the UNMODIFIED image to prove the stock "
                    "signature against, when `stock` has already been edited; "
                    "the proof is what shows the offset and digest rule are "
                    "Samsung's, so it is required either way")
    ap.add_argument("--stock-sboot",
                    default="/home/chanz22/EUB-N10/9825_customkey/input/sboot.bin")
    args = ap.parse_args()

    stock = Path(args.stock).read_bytes()
    data = bytearray(stock)
    footer = locate_footer(data)
    signed_end = footer + 0x10

    rb, sign_type, key_type, key_index = struct.unpack_from("<IIII", data, footer)
    print(f"{args.stock}  {len(data):#x} bytes")
    print(f"  footer {footer:#x}  signature {signed_end:#x}")
    print(f"  rb_count={rb} sign_type={sign_type} key_type={key_type} "
          f"key_index={key_index:#010x}")
    if key_type != 0:
        raise SystemExit("this tool signs TEE containers; key_type is not 0")

    stock_tee = Path(args.stock_sboot).read_bytes()[
        _mk.OFF_ST2_TEE:_mk.OFF_ST2_TEE + _mk.KEY_BLOB]
    st2t = _mk.load_key(f"{args.keys}/4/st2t.pem")
    ours = _mk.pubkey_blob(st2t.public_key())

    # Proving the stock signature first is what makes the re-sign safe: it
    # shows the offset and the digest rule are the ones Samsung used, rather
    # than a pattern that merely looked right.
    proof_src = Path(args.proof) if args.proof else Path(args.stock)
    proof_data = proof_src.read_bytes()
    if len(proof_data) != len(data):
        raise SystemExit(f"--proof is {len(proof_data)} bytes, input is {len(data)}")
    proof_digest = hashlib.sha512(proof_data[:signed_end]).digest()
    proof_sig = proof_data[signed_end:signed_end + SIG_LEN]
    if not _mk.verify_p384(stock_tee, proof_digest, proof_sig):
        raise SystemExit(f"stock signature in {proof_src} does not verify "
                         "-- wrong offset or rule")
    print(f"  stock signature vs Samsung ST2-TEE : PASS"
          + (f"  (proved on {proof_src.name})" if args.proof else ""))

    before = hashlib.sha512(bytes(data[:signed_end])).digest()

    data[signed_end:signed_end + SIG_LEN] = _mk.sign_p384(st2t, before)

    after = hashlib.sha512(bytes(data[:signed_end])).digest()
    new_sig = bytes(data[signed_end:signed_end + SIG_LEN])
    ok_ours = _mk.verify_p384(ours, after, new_sig)
    ok_stock = _mk.verify_p384(stock_tee, after, new_sig)
    print(f"  re-signed vs OUR ST2-TEE           : {'PASS' if ok_ours else 'FAIL'}")
    print(f"  re-signed REJECTED by Samsung's    : {'PASS' if not ok_stock else 'FAIL'}")

    changed = sum(1 for a, b in zip(stock, data) if a != b)
    outside = sum(1 for i, (a, b) in enumerate(zip(stock, data))
                  if a != b and not (signed_end <= i < signed_end + SIG_LEN))
    if args.proof:
        # The caller edited the body on purpose; report what they changed
        # relative to the untouched original instead of pretending it is zero.
        body = sum(1 for i, (a, b) in enumerate(zip(proof_data, data))
                   if a != b and i < signed_end)
        print(f"  body bytes changed vs {proof_src.name}: {body}")
        outside = 0
    print(f"  bytes changed {changed}, all inside the signature: "
          f"{'yes' if outside == 0 else f'NO ({outside} outside)'}")

    if not (ok_ours and not ok_stock and outside == 0):
        raise SystemExit("refusing to write: the re-sign did not come out clean")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))
    print(f"wrote {out}")
    print(f"sha256 {hashlib.sha256(bytes(data)).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
