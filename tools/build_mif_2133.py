#!/usr/bin/env python3
"""Build a separately signed HWHA BL2/ECT MIF experiment; never access USB.

The nominal 2133 MHz row uses integer PLL P=3 M=492 S=0: 4264 MHz
PLL / 2 = 2132 MHz memory. Keep the independent 2093 MHz row unchanged.
Only the ECT tables, BL2 signature and outer sboot signature may change.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from make_minimal_epbl_chain import load_key, pubkey_blob, sign_p384, verify_p384

BL2_OFF, BL2_SIZE = 0x16000, 0x52000
ECT_OFF, ECT_ROOM = 0x36C00, 0x14000
FOOTER = BL2_SIZE - 0x210
WHOLE_FOOTER = 0x364100
BASE_BODY_SHA256 = '435f455c25c8a033a4a7c6994c133c00e802d85cc70ba73a9f0d52a4a9f2d6ba'
RATES = [2094000, 2093000, 1794000, 1539000, 1352000,
         1014000, 845000, 676000, 546000, 421000]
PLL_NEW = (4264000000, 3, 492, 0, 0)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def put(data, off, value):
    struct.pack_into('<I', data, off, value)


def directory(data, pos, count):
    result = {}
    for _ in range(count):
        size = u32(data, pos)
        require(0 < size < 128, 'bad ECT name length')
        pos += 4
        name = bytes(data[pos:pos + size]).decode('ascii')
        require(data[pos + size] == 0 and name not in result, 'bad ECT name')
        pos += (size + 4) & ~3
        result[name] = (u32(data, pos), pos)
        pos += 4
    return result


def blocks(data):
    require(data[:8] == b'PARA2005', 'unexpected ECT header')
    return directory(data, 16, u32(data, 12))


def tables(data, block):
    base = blocks(data)[block][0]
    return base, directory(data, base + 12, u32(data, base + 8))


def table(data, block, name):
    base, entries = tables(data, block)
    return base + entries[name][0]


def dvfs_offsets(data):
    base, _ = tables(data, 'DVFS')
    p = table(data, 'DVFS', 'dvfs_mif')
    require(u32(data, base) == 3, 'unsupported DVFS parser version')
    require(struct.unpack_from('<3I', data, p + 16) == (2, 5, 10),
            'expected address-mode MIF with five clocks and ten levels')
    levels = p + 28 + 5 * 4
    return levels, levels + 10 * 8


def patch_ect(original):
    data = bytearray(original)
    outer = blocks(data)
    require(u32(data, 8) == 0xB728, 'unexpected ECT length')
    base, entries = tables(data, 'PLL')
    p = table(data, 'PLL', 'PLL_MIF')
    require(u32(data, p + 4) == 10, 'unexpected PLL_MIF count')
    require(struct.unpack_from('<5I', data, p + 8) == (4186000000, 3, 483, 0, 0),
            'PLL_MIF entry zero does not match HWHA')
    insert = p + 8 + 10 * 20
    require(data[-20:] == bytes(20), 'no free ECT padding for new PLL entry')
    # Retain the entire copied ECT region, including its trailing thermal word.
    # The stock size field is not a reliable end-of-content delimiter.
    data[insert:] = struct.pack('<5I', *PLL_NEW) + data[insert:-20]
    put(data, p + 4, 11)
    for offset, pointer in entries.values():
        if base + offset >= insert:
            put(data, pointer, offset + 20)
    for offset, pointer in outer.values():
        if offset >= insert:
            put(data, pointer, offset + 20)
    put(data, 8, u32(data, 8) + 20)

    levels, params = dvfs_offsets(data)
    require([u32(data, levels + i * 8) for i in range(10)] == RATES,
            'unexpected MIF DVFS levels')
    require(struct.unpack_from('<5I', data, params) == (0, 0, 0, 6, 0),
            'unexpected top MIF clock parameters')
    put(data, levels, 2133000)
    put(data, params, 10)
    asv = table(data, 'ASV', 'dvfs_mif')
    require(struct.unpack_from('<3I', data, asv) == (16, 10, 5), 'unexpected ASV shape')
    require([u32(data, asv + 12 + 4*i) * 1000 for i in range(10)] == RATES,
            'ASV and DVFS rates disagree')
    put(data, asv + 12, 2133)
    gen = table(data, 'GEN', 'MINMAX_dvfs_mif')
    require(struct.unpack_from('<2I', data, gen) == (6, 7), 'unexpected MINMAX shape')
    for i in range(7):
        p = gen + 8 + i * 24
        require(struct.unpack_from('<4I', data, p + 8) == (421, 2093, 2093, 421),
                'unexpected MIF min/max/boot/resume')
        put(data, p + 12, 2133)

    # Independent inverse check: erase only the allowed semantic edits and
    # remove the appended PLL entry. Every byte must reproduce the base.
    inverse = bytearray(data)
    put(inverse, levels, 2094000)
    put(inverse, params, 0)
    put(inverse, asv + 12, 2094)
    for i in range(7):
        put(inverse, gen + 8 + i * 24 + 12, 2093)
    inverse[insert:] = inverse[insert + 20:] + bytes(20)
    put(inverse, table(original, 'PLL', 'PLL_MIF') + 4, 10)
    for offset, pointer in entries.values():
        put(inverse, pointer, offset)
    for offset, pointer in outer.values():
        put(inverse, pointer, offset)
    put(inverse, 8, 0xB728)
    require(inverse == original, 'unexpected ECT change outside allowlist')
    return bytes(data)


def sign_stage(data, footer, key, embedded):
    require(struct.unpack_from('<4I', data, footer) == (9, 4, 0, 0x31FB208F),
            'unexpected ST2 footer')
    end = footer + 16
    data[end:end + 136] = sign_p384(key, hashlib.sha512(data[:end]).digest())
    require(verify_p384(embedded, hashlib.sha512(data[:end]).digest(),
                        data[end:end + 136]), 'new signature failed verification')


def build(base, keys, out):
    original = base.read_bytes()
    require(len(original) == 0x400000, 'expected 4 MB sboot')
    bl2 = bytearray(original[BL2_OFF:BL2_OFF + BL2_SIZE])
    require(hashlib.sha256(bl2[:FOOTER]).hexdigest() == BASE_BODY_SHA256,
            'BL2 body differs from reviewed HWHA binary')
    key = load_key(keys / '4/st2t.pem')
    embedded = original[0x272C:0x2938]
    require(pubkey_blob(key.public_key()) == embedded, 'signing key does not match EPBL TEE')
    for blob, foot in ((original, WHOLE_FOOTER), (bl2, FOOTER)):
        end = foot + 16
        require(verify_p384(embedded, hashlib.sha512(blob[:end]).digest(),
                            blob[end:end + 136]), 'base signature invalid')
    before = bytes(bl2)
    bl2[ECT_OFF:ECT_OFF + ECT_ROOM] = patch_ect(before[ECT_OFF:ECT_OFF + ECT_ROOM])
    sign_stage(bl2, FOOTER, key, embedded)
    result = bytearray(original)
    result[BL2_OFF:BL2_OFF + BL2_SIZE] = bl2
    sign_stage(result, WHOLE_FOOTER, key, embedded)
    # Keep all instructions, other stages, footer padding and keys unchanged.
    require(bl2[:ECT_OFF] == before[:ECT_OFF], 'BL2 code changed')
    require(bl2[ECT_OFF + ECT_ROOM:FOOTER + 16] == before[ECT_OFF + ECT_ROOM:FOOTER + 16],
            'BL2 data outside ECT changed')
    require(bl2[FOOTER + 152:] == before[FOOTER + 152:], 'BL2 signature padding changed')
    restored = bytearray(result)
    restored[BL2_OFF:BL2_OFF + BL2_SIZE] = original[BL2_OFF:BL2_OFF + BL2_SIZE]
    restored[WHOLE_FOOTER + 16:WHOLE_FOOTER + 152] = original[WHOLE_FOOTER + 16:WHOLE_FOOTER + 152]
    require(restored == original, 'sboot changed outside BL2 and container signature')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'sboot.bin').write_bytes(result)
    (out / 'bl2.bin').write_bytes(bl2)
    report = dict(base=str(base.resolve()), base_sha256=hashlib.sha256(original).hexdigest(),
                  sboot_sha256=hashlib.sha256(result).hexdigest(),
                  bl2_sha256=hashlib.sha256(bl2).hexdigest(), nominal_khz=2133000,
                  calculated_memory_hz=2132000000, pll_hz=4264000000,
                  pll_pms=dict(p=3, m=492, s=0), new_pll_index=10,
                  boot_khz=2093000, resume_khz=421000,
                  asv_voltage_bytes='unchanged for all versions and groups',
                  training_code_and_newtime='unchanged',
                  preserved_lower_levels=RATES[1:], hardware_validation='pending')
    (out / 'bl2-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--base', type=Path, required=True)
    ap.add_argument('--keys', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    build(args.base, args.keys, args.out)
