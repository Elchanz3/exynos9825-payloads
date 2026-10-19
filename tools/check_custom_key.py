#!/usr/bin/env python3
"""Check that a custom-key probe's embedded 32-byte key matches the live keys.

payloads/epbl_header_probe.S hardcodes the key value, but the value is derived
from $EUB/9825_customkey/keys/4/st1.pem + keys/hmac.bin. Regenerating those keys
silently invalidates every built payload, and the symptom on hardware would look
exactly like "this candidate is the wrong form" -- a wrong conclusion from a
stale binary. So recompute both candidates here and require the payload to
contain the one its build selected.

usage:
  check_custom_key.py build/epbl_custom_key_hmac_probe.bin   [--keys DIR]
  check_custom_key.py build/epbl_custom_key_efuse_probe.bin  [--keys DIR]
  check_custom_key.py build/epbl_boot_ufs_plain_probe.bin --candidate efuse

Which candidate a payload is expected to carry is taken from its filename
(..._hmac_... or ..._efuse_...), unless --candidate states it explicitly.
Exit 0 only if it matches.
"""

import argparse
import hashlib
import hmac
import sys
from pathlib import Path

DEFAULT_KEYS = Path("/home/chanz22/EUB-N10/9825_customkey/keys")
SIGNING_TYPE = 4  # 9825 is CodeSigner V5 / ECDSA P-384


def candidates(keys_dir: Path):
    """Return {name: 32-byte value}, mirroring sign_st1 and get_efuse_data."""
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )
    except ImportError:  # pragma: no cover
        raise SystemExit("error: python-cryptography is required")

    hmac_key = (keys_dir / "hmac.bin").read_bytes()
    if len(hmac_key) != 32:
        raise SystemExit(
            f"error: {keys_dir / 'hmac.bin'} is {len(hmac_key)} bytes, expected 32"
        )

    st1_path = keys_dir / str(SIGNING_TYPE) / "st1.pem"
    key = load_pem_private_key(st1_path.read_bytes(), password=None)
    numbers = key.public_key().public_numbers()
    if numbers.curve.name != "secp384r1":
        raise SystemExit(
            f"error: {st1_path} is {numbers.curve.name}, expected secp384r1"
        )

    # pubkey_blob(sign_type != 0): 20*00 + x(48 BE) + 20*00 + y(48 BE) + 388*00
    blob = (
        bytes(20)
        + numbers.x.to_bytes(48, "big")
        + bytes(20)
        + numbers.y.to_bytes(48, "big")
    )
    # sign_st1, non-RSA branch: HMAC-SHA512 over the first 136 bytes, cut to 32
    digest = hmac.digest(hmac_key, blob[:136], hashlib.sha512)[:32]
    return {
        "hmac": digest,
        "efuse": bytes(a ^ b for a, b in zip(digest, hmac_key)),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("payload", type=Path, nargs="+")
    ap.add_argument("--keys", type=Path, default=DEFAULT_KEYS)
    ap.add_argument(
        "--candidate",
        choices=("hmac", "efuse"),
        help="expected key form for payload names that do not encode it",
    )
    args = ap.parse_args(argv)

    values = candidates(args.keys)
    print(f"keys: {args.keys}")
    for name, value in values.items():
        print(f"  {name:6} = {value.hex()}")
    print()

    ok = True
    for path in args.payload:
        blob = path.read_bytes()
        name = path.name
        if args.candidate is not None:
            want = args.candidate
        elif "_hmac_" in name:
            want = "hmac"
        elif "_efuse_" in name:
            want = "efuse"
        else:
            print(f"FAIL {name}: cannot tell which candidate from the filename")
            ok = False
            continue

        expected = values[want]
        other = values["efuse" if want == "hmac" else "hmac"]
        at = blob.find(expected)
        if at < 0:
            print(
                f"FAIL {name}: does not contain the current {want} value "
                f"{expected.hex()}"
            )
            print(
                "     the payload is STALE relative to the keys - rebuild it, "
                "and update custom_boot_key in payloads/epbl_header_probe.S"
            )
            ok = False
            continue
        if other in blob:
            print(f"FAIL {name}: also contains the {'efuse' if want=='hmac' else 'hmac'} value")
            ok = False
            continue
        print(f"OK   {name}: carries the current {want} value at offset 0x{at:x}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
