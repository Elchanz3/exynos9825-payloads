#!/usr/bin/env python3
"""Sign kernel images and update the existing custom AVB chain for MIF 2133.

Reuse existing keys and keystorage. Preserve recovery/product trust and all
unrelated vbmeta descriptors. Do not access the device or generate new keys.
"""
import argparse
import hashlib
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from build_mif_2133 import require
from make_minimal_epbl_chain import load_key
from make_custom_avb import avb_blocks, vbmeta_digest
from check_avb_descriptors import hash_descriptors


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def embedded_vbmeta(image):
    magic, _major, _minor, _size, offset, size = struct.unpack_from('>4sIIQQQ', image, len(image)-64)
    require(magic == b'AVBf', 'missing AVB footer')
    return image[offset:offset+size]


def verify_root(vb, key, public_blob):
    b = avb_blocks(vb)
    require(vb[b['pk_off']:b['pk_off']+b['pk_sz']] == public_blob, 'AVB root key mismatch')
    digest = vbmeta_digest(vb, b)
    require(vb[b['hash_off']:b['hash_off']+32] == digest, 'AVB digest mismatch')
    key.public_key().verify(bytes(vb[b['sig_off']:b['sig_off']+b['sig_sz']]), digest,
                            padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def descriptors(vb):
    b = avb_blocks(vb)
    relative, size = struct.unpack_from('>QQ', vb, 96)
    pos, end = b['aux_off']+relative, b['aux_off']+relative+size
    while pos < end:
        tag, following = struct.unpack_from('>QQ', vb, pos)
        require(following % 8 == 0 and pos+16+following <= end, 'malformed descriptor')
        yield tag, pos, 16+following
        pos += 16+following
    require(pos == end, 'descriptor size mismatch')


def update_root(vb, changes, public_blob, key):
    verify_root(vb, key, public_blob)
    result = bytearray(vb)
    seen, chains = set(), set()
    allowed = set()
    for tag, pos, size in descriptors(vb):
        if tag == 2:
            name_len, salt_len, digest_len = struct.unpack_from('>III', vb, pos+56)
            name = vb[pos+132:pos+132+name_len].decode()
            if name not in changes:
                continue
            original_size = struct.unpack_from('>Q', vb, pos+16)[0]
            data, new_size = changes[name]
            new_size = original_size if new_size is None else new_size
            require(0 < new_size <= len(data), 'hash size outside image')
            salt_at = pos+132+name_len
            salt = vb[salt_at:salt_at+salt_len]
            digest_at = salt_at+salt_len
            require(digest_len == 32 and vb[pos+24:pos+30] == b'sha256', 'unsupported hash')
            struct.pack_into('>Q', result, pos+16, new_size)
            result[digest_at:digest_at+32] = hashlib.sha256(salt+data[:new_size]).digest()
            allowed.update(range(pos+16,pos+24))
            allowed.update(range(digest_at,digest_at+32))
            seen.add(name)
        elif tag == 4:
            rollback, name_len, pk_len = struct.unpack_from('>III', vb, pos+16)
            name = vb[pos+92:pos+92+name_len].decode()
            if name not in ('dtb', 'dtbo'):
                continue
            require(rollback == {'dtb':6, 'dtbo':7}[name] and pk_len == len(public_blob),
                    'unexpected DT chain descriptor')
            at = pos+92+name_len
            result[at:at+pk_len] = public_blob
            allowed.update(range(at,at+pk_len))
            chains.add(name)
    require(seen == set(changes) and chains == {'dtb','dtbo'}, 'missing AVB descriptor')
    b = avb_blocks(result)
    digest = vbmeta_digest(result, b)
    result[b['hash_off']:b['hash_off']+32] = digest
    result[b['sig_off']:b['sig_off']+b['sig_sz']] = key.sign(
        digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    allowed.update(range(b['hash_off'],b['hash_off']+32))
    allowed.update(range(b['sig_off'],b['sig_off']+b['sig_sz']))
    require(all(a == c or i in allowed for i,(a,c) in enumerate(zip(vb,result))),
            'unrelated AVB descriptor changed')
    verify_root(result, key, public_blob)
    return bytes(result)


def odin_archive(out, name, members):
    path = out/name
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for member in members:
            tar.add(out/member, arcname=member, recursive=False)
    raw = path.read_bytes()
    suffix = hashlib.md5(raw).hexdigest().encode()+b'  '+path.name.removesuffix('.md5').encode()+b'\n'
    with path.open('ab') as stream:
        stream.write(suffix)
    with tarfile.open(path) as tar:
        require(tar.getnames() == members, 'archive member mismatch')
        for member in members:
            require(tar.extractfile(member).read() == (out/member).read_bytes(), 'archive data mismatch')
    require(path.read_bytes() == raw+suffix, 'Odin checksum suffix mismatch')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--kernel-out', type=Path, required=True)
    ap.add_argument('--base-avb', type=Path, required=True)
    ap.add_argument('--key', type=Path, required=True)
    ap.add_argument('--cm', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    require(args.key.is_file(), 'existing private AVB key required')
    out = args.out.resolve()
    require((out/'sboot.bin').is_file(), 'build signed sboot first')
    key = load_key(args.key)
    require(key.key_size == 4096, 'expected RSA-4096 AVB key')
    run('avbtool','extract_public_key','--key',args.key,'--output',out/'avb_pubkey.bin')
    pub = (out/'avb_pubkey.bin').read_bytes()
    base_vb = (args.base_avb/'vbmeta.img').read_bytes()
    verify_root(base_vb,key,pub)
    ks = (args.base_avb/'keystorage.bin').read_bytes()
    require(ks[0x4c0:0x4c0+len(pub)] == pub, 'keystorage key mismatch')
    (out/'keystorage.bin').write_bytes(ks)
    shutil.copyfile(args.cm,out/'cm.bin')
    images = args.kernel_out/'images'
    boot_size = None
    for filename,part in [('boot.img','boot'),('dt.img','dtb'),('dtbo.img','dtbo')]:
        data = (images/filename).read_bytes()
        if part == 'boot':
            require(data[:8] == b'ANDROID!', 'missing Android boot header')
            kernel_size = struct.unpack_from('<I',data,8)[0]
            page = struct.unpack_from('<I',data,36)[0]
            content_size = page+((kernel_size+page-1)//page)*page+len(b'SEANDROIDENFORCE')
            require(data[content_size-len(b'SEANDROIDENFORCE'):content_size] == b'SEANDROIDENFORCE',
                    'boot tag mismatch')
            salt = hash_descriptors(base_vb)['boot'][2]
            boot_size = content_size
        else:
            require(data[:4] == bytes.fromhex('d7b7ab1e'), 'missing DT table')
            content_size = struct.unpack_from('>I',data,4)[0]
            stock_vb = embedded_vbmeta((images/'.stock'/filename).read_bytes())
            salt = hash_descriptors(stock_vb)[part][2]
        require(set(data[content_size:]) <= {0}, 'unexpected unsigned image trailer')
        (out/filename).write_bytes(data[:content_size])
        run('avbtool','add_hash_footer','--image',out/filename,'--partition_name',part,
            '--partition_size',len(data),'--algorithm','SHA256_RSA4096','--key',args.key,
            '--salt',salt.hex(),'--rollback_index','0')
        # Samsung calls the file dt.img; AVB calls the partition dtb.
        if part == 'dtb':
            alias = out/'dtb.img'
            if not alias.exists():
                alias.symlink_to('dt.img')
            require(alias.resolve() == (out/'dt.img').resolve(), 'unexpected dtb alias')
        run('avbtool','verify_image','--image',out/filename,'--key',args.key)
        require((out/filename).stat().st_size == len(data), 'partition size changed')
    new_vb = update_root(base_vb, {'bootloader':((out/'sboot.bin').read_bytes(),None),
                                  'boot':((out/'boot.img').read_bytes(),boot_size)}, pub,key)
    (out/'vbmeta.img').write_bytes(new_vb)
    for part,filename in [('bootloader','sboot.bin'),('boot','boot.img'),('cm','cm.bin'),
                          ('keystorage','keystorage.bin')]:
        size,algorithm,salt,digest = hash_descriptors(new_vb)[part]
        require(algorithm == 'sha256' and hashlib.sha256(salt+(out/filename).read_bytes()[:size]).digest() == digest,
                f'final {part} descriptor mismatch')
        print(f'{part}: full AVB hash coverage verified ({size:#x} bytes)')
    # CM and keystorage are reference copies of the already deployed custom
    # trust chain, not partitions changed by this experiment.
    odin_archive(out,'BL_mif2133.tar.md5',['sboot.bin','vbmeta.img'])
    odin_archive(out,'AP_mif2133.tar.md5',['boot.img','dt.img','dtbo.img'])
    files = ['sboot.bin','bl2.bin','boot.img','dt.img','dtbo.img','cm.bin','keystorage.bin',
             'vbmeta.img','BL_mif2133.tar.md5','AP_mif2133.tar.md5']
    (out/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256((out/f).read_bytes()).hexdigest()}  {f}\n' for f in files))
    print('Offline signatures, all four root hash descriptors, DT chain keys, and archive contents: PASS')
    print('Hardware validation: pending. No device was accessed.')


if __name__ == '__main__':
    main()
