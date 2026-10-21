#!/usr/bin/env python3
"""Put our own key under AVB, so a locked bootloader accepts our images.

THE PROBLEM
  vbmeta carries a hash descriptor for the `bootloader` partition. With the
  bootloader locked, u-boot checks it, our sboot does not hash to Samsung's
  recorded digest, and the boot stops at

      Hash of data does not match digest in descriptor.[2nd] (3)

  Editing the digest alone does not help: the whole vbmeta is signed with
  Samsung's RSA-4096 AVB key, which we do not have.

THE WAY IN
  The public key u-boot checks that signature against is not baked into the
  bootloader. It is `PO_AVB_KEY`, a 1032-byte AVB public key blob living in
  `keystorage.bin` at offset 0x4c0 -- byte-identical to the copy embedded in
  vbmeta itself. And `keystorage.bin` is an ST2 container we already re-sign
  with our own ST2-TEE key.

  So the trust can be re-rooted one level up: put OUR AVB public key in
  keystorage, re-sign keystorage with our ST2-TEE key, and sign vbmeta with
  our AVB private key. After that AVB answers to us for every partition it
  covers, boot.img included.

THE RULES, EACH VERIFIED AGAINST SAMSUNG'S OWN IMAGES BEFORE BEING USED
  vbmeta signature   hash = SHA256(header[0:256] || aux_block)
                     sig  = RSA-4096 PKCS#1 v1.5 over that hash
  bootloader digest  SHA256(salt || sboot[0:image_size])
                     image_size comes out of the descriptor itself and is
                     0x364310 here -- the AVBf target boundary, not the whole
                     4 MB partition
  descriptor layout  AvbHashDescriptor is 132 bytes, then name, salt, digest

Nothing is written to the device by this tool.
"""
import argparse
import hashlib
import importlib.util
import struct
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

_spec = importlib.util.spec_from_file_location(
    "_mk", Path(__file__).with_name("make_minimal_epbl_chain.py"))
_mk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mk)

HDR = 256
PUBKEY_BLOB_LEN = 1032
KEYSTORAGE_AVB_KEY_OFF = 0x4C0
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def avb_blocks(vbmeta):
    (magic, _vmaj, _vmin, auth_sz, aux_sz, alg,
     hash_off, hash_sz, sig_off, sig_sz,
     pk_off, pk_sz) = struct.unpack_from(">4sIIQQIQQQQQQ", vbmeta, 0)
    if magic != b"AVB0":
        raise SystemExit("not a vbmeta image")
    if alg != 2:
        raise SystemExit(f"expected SHA256_RSA4096 (2), got algorithm {alg}")
    return dict(auth=auth_sz, aux=aux_sz, aux_off=HDR + auth_sz,
                hash_off=HDR + hash_off, hash_sz=hash_sz,
                sig_off=HDR + sig_off, sig_sz=sig_sz,
                pk_off=HDR + auth_sz + pk_off, pk_sz=pk_sz)


def vbmeta_digest(data, b):
    return hashlib.sha256(bytes(data[0:HDR])
                          + bytes(data[b["aux_off"]:b["aux_off"] + b["aux"]])).digest()


def rsa_verify_pkcs1(pub_blob, digest, sig):
    """True if `sig` is a PKCS#1 v1.5 SHA256 signature under the AVB blob."""
    n = int.from_bytes(pub_blob[8:8 + 512], "big")
    em = pow(int.from_bytes(sig, "big"), 65537, n).to_bytes(512, "big")
    return em[0:2] == b"\x00\x01" and em.endswith(SHA256_DIGESTINFO + digest)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vbmeta", required=True, help="Samsung's stock vbmeta.img")
    ap.add_argument("--keystorage", required=True, help="Samsung's stock keystorage.bin")
    ap.add_argument("--stock-image", action="append", default=[], metavar="PART=FILE",
                    help="Samsung's own image for PART; the tool checks it "
                         "hashes to the digest already in the descriptor, "
                         "which proves the rule for that descriptor before "
                         "anything is replaced")
    ap.add_argument("--image", action="append", default=[], metavar="PART=FILE",
                    help="replace the hash descriptor for PART with the digest "
                         "of FILE; repeatable. The keystorage entry is added "
                         "automatically once it has been re-signed.")
    ap.add_argument("--avb-key", default="/home/chanz22/EUB-N10/9825_customkey/keys/4/avb.pem")
    ap.add_argument("--keys", default="/home/chanz22/EUB-N10/9825_customkey/keys")
    ap.add_argument("--out-dir", default="build/custom_avb")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    avb_key = Path(args.avb_key)
    if not avb_key.exists():
        print(f"== generating {avb_key} (RSA-4096) ==")
        avb_key.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "genrsa", "-out", str(avb_key), "4096"],
                       check=True, capture_output=True)
    our_pub = out / "avb_pubkey.bin"
    subprocess.run(["avbtool", "extract_public_key", "--key", str(avb_key),
                    "--output", str(our_pub)], check=True)
    our_pub_blob = our_pub.read_bytes()
    if len(our_pub_blob) != PUBKEY_BLOB_LEN:
        raise SystemExit(f"unexpected AVB pubkey blob length {len(our_pub_blob)}")
    print(f"our AVB key   {avb_key}")
    print(f"  pubkey blob {len(our_pub_blob)} bytes  "
          f"sha256 {hashlib.sha256(our_pub_blob).hexdigest()[:32]}...")

    # ---- vbmeta ----
    vb = bytearray(Path(args.vbmeta).read_bytes())
    b = avb_blocks(vb)
    stock_pub = bytes(vb[b["pk_off"]:b["pk_off"] + b["pk_sz"]])

    # Prove we can reproduce Samsung's own signature before replacing it.
    stock_digest = vbmeta_digest(vb, b)
    if bytes(vb[b["hash_off"]:b["hash_off"] + 32]) != stock_digest:
        raise SystemExit("vbmeta hash rule does not reproduce Samsung's hash")
    if not rsa_verify_pkcs1(stock_pub, stock_digest,
                            bytes(vb[b["sig_off"]:b["sig_off"] + b["sig_sz"]])):
        raise SystemExit("Samsung's vbmeta signature does not verify -- rule is wrong")
    print("\nvbmeta")
    print("  stock hash rule reproduces Samsung's hash : PASS")
    print("  stock signature verifies under stock key  : PASS")

    # ---- keystorage first ----
    # Its own descriptor in vbmeta covers keystorage[:0x2000], which contains
    # both the AVB key we swap and the ST2 signature over it. So keystorage
    # has to be finished before its digest can be taken. There is no loop:
    # keystorage's ST2 signature covers only itself, and vbmeta is signed
    # afterwards.
    ks = bytearray(Path(args.keystorage).read_bytes())
    at = KEYSTORAGE_AVB_KEY_OFF
    if bytes(ks[at:at + PUBKEY_BLOB_LEN]) != stock_pub:
        found = ks.find(stock_pub)
        raise SystemExit(f"PO_AVB_KEY not at {at:#x}"
                         + (f"; found at {found:#x}" if found >= 0 else "; not found"))
    ks[at:at + PUBKEY_BLOB_LEN] = our_pub_blob
    staged = out / "keystorage.avbkey.bin"
    staged.write_bytes(bytes(ks))
    print(f"\nkeystorage")
    print(f"  PO_AVB_KEY at {at:#x} replaced with ours")
    final_ks = out / "keystorage.bin"
    subprocess.run(["python3", str(Path(__file__).with_name("resign_st2_container.py")),
                    str(staged), str(final_ks),
                    "--proof", args.keystorage,
                    "--keys", args.keys], check=True)
    args.image.append(f"keystorage={final_ks}")

    # Walk the descriptor list rather than searching for a name: "cm" as a
    # byte string occurs all over an 8 KB aux block, and vbmeta covers four
    # partitions here, not one. Each descriptor carries its own image_size,
    # and they differ -- 0x364310 for the bootloader, 0x3f4110 for cm, 0x2000
    # for keystorage -- so none of them can be assumed.
    replacements = dict(pair.split("=", 1) for pair in args.image)
    seen = {}
    off = b["aux_off"]
    aux_end = b["aux_off"] + b["aux"]
    while off + 16 <= aux_end:
        tag, following = struct.unpack_from(">QQ", vb, off)
        total = 16 + following
        if total <= 16 or off + total > aux_end:
            break
        if tag == 2:  # AVB_DESCRIPTOR_TAG_HASH
            image_size = struct.unpack_from(">Q", vb, off + 16)[0]
            alg = bytes(vb[off + 24:off + 56]).rstrip(b"\x00")
            name_len, salt_len, digest_len, _flags = struct.unpack_from(
                ">IIII", vb, off + 56)
            name = bytes(vb[off + 132:off + 132 + name_len]).decode()
            salt_off = off + 132 + name_len
            dig_off = salt_off + salt_len
            salt = bytes(vb[salt_off:salt_off + salt_len])
            old_digest = bytes(vb[dig_off:dig_off + digest_len])
            seen[name] = (image_size, alg, salt, dig_off, digest_len, old_digest)
        off += total

    print(f"\n  hash descriptors: {', '.join(sorted(seen))}")
    unknown = set(replacements) - set(seen)
    if unknown:
        raise SystemExit(f"no descriptor for: {', '.join(sorted(unknown))}")

    # Prove each descriptor's own rule before trusting it. The sizes differ
    # per partition and none of them is the whole image, so a wrong one would
    # otherwise produce a digest that is confidently wrong.
    for pair in args.stock_image:
        name, path = pair.split("=", 1)
        if name not in seen:
            raise SystemExit(f"--stock-image {name}: no such descriptor")
        image_size, _alg, salt, _do, _dl, old_digest = seen[name]
        blob = Path(path).read_bytes()
        got = hashlib.sha256(salt + blob[:image_size]).digest()
        status = "PASS" if got == old_digest else "FAIL"
        print(f"  {name:11} stock hashes to its descriptor digest : {status}")
        if got != old_digest:
            raise SystemExit(f"{name}: the rule does not reproduce Samsung's digest")

    for name in sorted(replacements):
        image_size, alg, salt, dig_off, digest_len, old_digest = seen[name]
        if alg != b"sha256" or digest_len != 32:
            raise SystemExit(f"{name}: unsupported {alg!r}/{digest_len}")
        blob = Path(replacements[name]).read_bytes()
        if len(blob) < image_size:
            raise SystemExit(f"{name}: image is {len(blob)} bytes, "
                             f"descriptor covers {image_size}")
        new_digest = hashlib.sha256(salt + blob[:image_size]).digest()
        print(f"  {name}")
        print(f"    covers {replacements[name]}[:{image_size:#x}]")
        print(f"    was {old_digest.hex()}")
        print(f"    now {new_digest.hex()}")
        vb[dig_off:dig_off + digest_len] = new_digest

    untouched = sorted(set(seen) - set(replacements))
    if untouched:
        print(f"  left alone (still Samsung's): {', '.join(untouched)}")

    vb[b["pk_off"]:b["pk_off"] + b["pk_sz"]] = our_pub_blob

    new_hash = vbmeta_digest(vb, b)
    priv = serialization.load_pem_private_key(avb_key.read_bytes(), password=None)
    sig = priv.sign(new_hash, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    if len(sig) != b["sig_sz"]:
        raise SystemExit(f"signature is {len(sig)} bytes, expected {b['sig_sz']}")
    vb[b["hash_off"]:b["hash_off"] + 32] = new_hash
    vb[b["sig_off"]:b["sig_off"] + b["sig_sz"]] = sig

    if not rsa_verify_pkcs1(our_pub_blob, new_hash, sig):
        raise SystemExit("our own signature does not verify -- refusing to write")
    if rsa_verify_pkcs1(stock_pub, new_hash, sig):
        raise SystemExit("re-signed vbmeta still verifies under Samsung's key")
    print("  re-signed vbmeta verifies under OUR key   : PASS")
    print("  re-signed vbmeta rejected by Samsung's    : PASS")
    (out / "vbmeta.img").write_bytes(bytes(vb))

    print(f"\nwrote {out}/vbmeta.img and {final_ks}")
    print("Both must be flashed together: the key in one signs the other's chain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
