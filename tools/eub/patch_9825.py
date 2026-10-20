#!/usr/bin/env python3
# Exynos9825 (SM-N975F) u-boot patcher, adapted from patch_9810/patch_9840.
#
# 9825 differences vs 9810 (verified on N975FXXS9HWG3 u-boot.bin):
#   - function entries are the nearest BL target before the diagnostic xref
#     (several 9825 functions start with `sub sp`, and check_signature is at
#     xref-0xdc like 9840, not xref-0x104 like 9810)
#   - etc_market/etc_development stores use swapped scratch registers
#   - no [RMM] RPMB reader; the equivalent is [RLC]
#   - the fuse targets the FREE slot KEY2 (Samsung's KEY is in use, USE_KEY=1);
#     9825 has dedicated KEY2/USE_KEY2 program functions (SMC cmd 0x16/0x17),
#     called directly instead of patching selectors like 9840, and USE_KEY2 is
#     only set if KEY2 programmed successfully.

import os
import struct
import sys

RETURN_ZERO = bytes.fromhex("00 00 80 D2 C0 03 5F D6")
RETURN_ONE = bytes.fromhex("20 00 80 D2 C0 03 5F D6")
MOV_W0_0 = 0x52800000
MOV_W0_1 = 0x52800020

def write_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value)

def word(data, offset):
    return int.from_bytes(data[offset : offset + 4], "little")

def signed(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign

def is_bl(data, offset):
    return word(data, offset) & 0xFC000000 == 0x94000000

def resolve_bl(data, offset):
    if not is_bl(data, offset):
        raise ValueError(f"expected BL at {offset:#x}")
    return offset + signed(word(data, offset) & 0x03FFFFFF, 26) * 4

_targets = {}
def called_targets(data):
    key = id(data)
    if key not in _targets:
        _targets[key] = sorted({
            resolve_bl(data, offset)
            for offset in range(0, len(data) - 3, 4)
            if is_bl(data, offset)
        })
    return _targets[key]

def unique_offset(offsets, description):
    if len(offsets) != 1:
        raise ValueError(f"expected one {description}, found {len(offsets)}")
    return offsets[0]

def is_entry(data, offset):
    instruction = word(data, offset) & 0xFFC003FF
    return instruction in (0xA98003FD, 0xD10003FF)  # stp x29,x30,[sp,#-N]! / sub sp,sp,#N

def function_containing(data, offset, limit=0x400):
    entry = max((t for t in called_targets(data) if offset - limit <= t <= offset), default=None)
    if entry is None or not is_entry(data, entry):
        raise ValueError(f"no called function entry before {offset:#x}")
    return entry

def adrp_add(data, offset):
    adrp = word(data, offset)
    if adrp & 0x9F000000 != 0x90000000:
        return None

    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    page = (offset & ~0xFFF) + (signed(imm, 21) << 12)
    for distance in range(4, 17, 4):
        add = word(data, offset + distance)
        if add & 0xFF000000 == 0x91000000 and (add >> 5) & 31 == adrp & 31:
            return page + (((add >> 10) & 0xFFF) << (12 if add & 0x400000 else 0))
    return None

def find_xref(data, string):
    string_offset = data.find(string)
    if string_offset < 0:
        raise ValueError(f"string not found: {string!r}")
    if data.find(string, string_offset + 1) >= 0:
        raise ValueError(f"expected one copy of {string!r}")

    refs = [
        offset
        for offset in range(0, string_offset & ~3, 4)
        if adrp_add(data, offset) == string_offset
    ]
    if len(refs) != 1:
        raise ValueError(f"expected one xref to {string!r}, found {len(refs)}")
    return refs[0]

def stub_function(data, string, stub, name):
    entry = function_containing(data, find_xref(data, string))
    print(f"{name}: {entry:#x}")
    data[entry : entry + len(stub)] = stub
    return entry

def write_words(data, offset, words):
    for i, word_value in enumerate(words):
        write_u32(data, offset + i * 4, word_value)

def jump_to_func_from(from_addr, to_addr):
    return 0x94000000 | (((to_addr - from_addr) >> 2) & 0x03FFFFFF)

def is_str_w0(value, imm):
    # str w0, [xN, #imm] for any base register N
    return value & 0xFFFFFC1F == 0xB9000000 | ((imm // 4) << 10)

def patch_check_signature(data):
    stub_function(data, b"There is no signature\n\0", RETURN_ZERO, "check_signature")

def patch_initialize_efuse_data(data):
    nantirbk_xref = find_xref(data, b"nantirbk0 mismatch!(%d vs %d), updating...\n\0")
    etc_market = unique_offset([
        offset + 4
        for offset in range(max(0, nantirbk_xref - 0x200), nantirbk_xref - 28, 4)
        if word(data, offset) == 0x528000E0  # MOV W0, #7
        and is_bl(data, offset + 4)
        and is_str_w0(word(data, offset + 12), 0x40)
        and word(data, offset + 16) == 0x52800100  # MOV W0, #8
        and is_bl(data, offset + 20)
        and is_str_w0(word(data, offset + 28), 0x44)
    ], "etc_market call near nantirbk0")
    commercial_bit = find_xref(data, b"commercial_bit mismatch!(%d vs %d), updating...\n\0") - 0x6C
    if not all(is_bl(data, commercial_bit + distance) for distance in (0, 16, 32)):
        raise ValueError("commercial/test/warranty efuse calls do not match")
    if not all(is_str_w0(word(data, commercial_bit + distance), imm)
               for distance, imm in ((4, 4), (24, 8), (36, 12))):
        raise ValueError("commercial/test/warranty efuse stores do not match")
    print(f"etc_market: {etc_market:#x}")
    print(f"commercial_bit: {commercial_bit:#x}")
    write_u32(data, etc_market, MOV_W0_0)          # etc_market 0
    write_u32(data, etc_market + 16, MOV_W0_1)     # etc_development 1
    write_u32(data, commercial_bit, MOV_W0_0)      # commercial_bit 0
    write_u32(data, commercial_bit + 16, MOV_W0_1) # test_bit 1
    write_u32(data, commercial_bit + 32, MOV_W0_0) # warranty_bit 0

def patch_set_warranty_void_bit_reason(data):
    reason_xref = find_xref(data, b"%s : no reason\n\0")
    set_warranty_void_bit_reason = unique_offset([
        target
        for target in called_targets(data)
        if reason_xref < target < reason_xref + 0x80
        and (word(data, target) == 0x529FFFE1 or is_entry(data, target))
        and any(word(data, target + distance) == 0x529FFFE1 for distance in range(0, 16, 4))
        and any(word(data, target + distance) == 0x6B01001F for distance in range(4, 24, 4))
    ], "set_warranty_void_bit_reason after its diagnostic")
    print(f"set_warranty_void_bit_reason: {set_warranty_void_bit_reason:#x}")
    data[set_warranty_void_bit_reason : set_warranty_void_bit_reason + len(RETURN_ZERO)] = RETURN_ZERO

def patch_set_warranty_bit(data):
    stub_function(data, b"[EFUSE] Set warranty bit(%d)\n\0", RETURN_ZERO, "set_warranty_bit")

def patch_read_rlc_rpmb(data):
    stub_function(data, b"[RLC] read_data fail...\n\0", RETURN_ZERO, "read_rlc_rpmb")

def patch_read_kg_rpmb(data):
    stub_function(data, b"[KG] read_data fail...\n\0", RETURN_ZERO, "read_kg_rpmb")

def patch_have_this_mode(data):
    mode_xref = find_xref(data, b"ENG MODE : ENG ALLOWED(%s)\n\0")
    have_this_mode = unique_offset([
        target
        for offset in range(mode_xref - 0x50, mode_xref - 4, 4)
        if is_bl(data, offset)
        and word(data, offset + 4) & 0xFF00001F == 0x34000000  # CBZ W0
        for target in [resolve_bl(data, offset)]
        if [word(data, target + distance) for distance in (12, 16, 20)] == [
            0x6A01001F, 0x1A9F07E0, 0xD65F03C0  # TST, CSET, RET
        ]
    ], "have_this_mode call before ENG MODE diagnostic")
    print(f"have_this_mode: {have_this_mode:#x}")
    data[have_this_mode : have_this_mode + len(RETURN_ONE)] = RETURN_ONE

def get_efuse_data():
    # Must mirror sign_st1()'s hmac computation exactly, or the fused value will
    # not match the hmac the signer wrote into the SBL1 footer. 9825 is
    # CodeSigner V5 (signing_type 4, ECDSA P-384), so the non-RSA branch
    # applies: HMAC-SHA512 over the first 136 bytes of the pubkey blob
    # (= x||y in 68-byte big-endian slots), truncated to 32 bytes.
    import hmac
    from s5e9825 import soc_data
    from sign import load_private_key, pubkey_blob

    signing_type = soc_data().signing_type
    with open("keys/hmac.bin", "rb") as f:
        hmac_key = f.read()
    if len(hmac_key) != 32:
        raise ValueError("hmac.bin should be 32 bytes")
    key = load_private_key(f"keys/{signing_type}/st1.pem")
    public_blob = pubkey_blob(key.public_key(), signing_type)
    if signing_type == 0:
        digest = hmac.digest(hmac_key, public_blob, "sha256")
    else:
        digest = hmac.digest(hmac_key, public_blob[:136], "sha512")[:32]
    return bytes(a ^ b for a, b in zip(digest, hmac_key))

def otp_program_function(data, string, back, smc_cmd):
    # Entry of the OTP program routine that prints `string` and issues
    # SMC 0xc2001014 with x1 == smc_cmd. These are not direct BL targets.
    entry = find_xref(data, string) - back
    if not is_entry(data, entry):
        raise ValueError(f"{string!r}: no function entry at {entry:#x}")
    mov_x1 = 0xD2800001 | (smc_cmd << 5)
    if not any(word(data, o) == mov_x1 and word(data, o + 16) == 0xD4000003
               for o in range(entry, entry + 0x200, 4)):
        raise ValueError(f"{string!r}: no smc with x1={smc_cmd:#x}")
    return entry

def patch_force_secure_payload_load(data):
    """Stop sboot from flagging itself out of loading the Secure Payload.

    The OTP SMC 0xc2001014 needs the secure payload and a CM-partition LDFW.
    On this path sboot skips secure-payload loading before LDFW initialization:

        0x1f2c0  adrp x0, <flags> ; mov w1, #0x10000000 ; str w1, [x0, #0xb28]
        0x1ee9c  ldr w0, [<flags> + 0xb28] ; return (w0 != 0)
        0x343c   bl 0x1ee9c ; cbnz w0 -> "Skip to load Secure Payload"

    The flag word is written by exactly ONE instruction, so clearing the value
    it stores makes 0x1ee9c return 0 and the load go ahead. Located
    structurally: the single `str w1, [xN, #0xb28]` in the image, required to
    be preceded by `movz w1, #0x1000, lsl #16`.

    The flag word is a bitfield (another accessor at 0x1eeb0 extracts an
    arbitrary bit of it), and this write initialises the whole word rather than
    OR-ing into it, so storing 0 just leaves bit 28 clear. Other consumers of
    that bit will therefore also see "not set" -- acceptable for the fuse
    experiment, but it is a behaviour change, not a no-op.
    """
    store = 0xB90B2801          # str w1, [x0, #2856]  (Rn=0, Rt=1)
    sites = [
        offset
        for offset in range(0, len(data) - 3, 4)
        if word(data, offset) & 0xFFFFFC00 == 0xB90B2800
    ]
    site = unique_offset(sites, "store to the secure-payload skip flag")
    if word(data, site) != store:
        raise ValueError(f"unexpected skip-flag store encoding at {site:#x}")
    if word(data, site - 4) != 0x52A20001:  # movz w1, #0x1000, lsl #16
        raise ValueError(
            f"{site - 4:#x}: expected `movz w1, #0x1000, lsl #16` before the "
            "skip-flag store"
        )
    print(f"force_secure_payload_load: {site - 4:#x}")
    write_words(data, site - 4, [0x52800001])  # mov w1, #0


def adr_x0(offset):
    """`adr x0, PC+offset`, encoded from the offset so it cannot go stale."""
    if offset % 4 or not 0 <= offset < (1 << 20):
        raise ValueError(f"bad adr offset {offset:#x}")
    immlo = offset & 3
    immhi = offset >> 2
    return 0x10000000 | (immlo << 29) | (immhi << 5)


def cbnz_x0(offset):
    """`cbnz x0, PC+offset`."""
    if offset % 4 or not 0 < offset < (1 << 20):
        raise ValueError(f"bad cbnz offset {offset:#x}")
    return 0xB5000000 | ((offset >> 2) << 5)


UBOOT_VA_BASE = 0xC9000000

LDFW_SUCCESS_MESSAGE = (
    b"ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) "
    b"have been inited done.\n\0"
)


def ldfw_success_return_address(data):
    """The runtime LR a call from the CM/LDFW initializer's success path leaves.

    The stub replaces check_signature, so every one of that function's
    original callers reaches it: pit_check_integrity, pit_flash_sdcard twice,
    pit_flash_binary, the OTA path, set_oneshot_recovery,
    check_samsung_secure_info twice and f_load_hypervisor. Their ordering
    against the LDFW initializer is not established, and the command behind
    this stub burns a one-shot fuse, so the stub refuses to act unless it was
    reached from the one site that is allowed to reach it.

    The site is resolved by message rather than by address, and is the same
    one tools/sboot_patch.py rewires. At this point it still holds the
    original printf call, which is what makes it findable.
    """
    xref = find_xref(data, LDFW_SUCCESS_MESSAGE)
    calls = [off for off in range(xref + 4, xref + 0x14, 4) if is_bl(data, off)]
    if len(calls) != 1:
        raise ValueError(
            f"expected exactly one call after the LDFW success message, "
            f"found {len(calls)}"
        )
    return UBOOT_VA_BASE + calls[0] + 4


def movz_w1(imm16):
    return 0x52800001 | ((imm16 & 0xFFFF) << 5)


def movk_w1_lsl16(imm16):
    return 0x72A00001 | ((imm16 & 0xFFFF) << 5)


CMP_X30_X1 = 0xEB0103DF


def bne_words(words_forward):
    return 0x54000001 | ((words_forward & 0x7FFFF) << 5)


def patch_fuse_boot_key(data):
    check_signature = function_containing(data, find_xref(data, b"There is no signature\n\0"))
    write_key2 = otp_program_function(data, b"[OTP] ROM_SECURE_BOOT_KEY2 program start\n\0", 0x58, 0x16)
    expected_lr = ldfw_success_return_address(data)

    print(f"check_signature: {check_signature:#x}")
    print(f"cm_otp_write_rom_sec_boot_key2: {write_key2:#x}")
    print(f"caller gate: acts only when LR == {expected_lr:#x}")

    # x30 still holds the caller's return address after the stp, which stores
    # it without modifying it, so the comparison can sit anywhere before the
    # OTP call.
    gate = [
        movz_w1(expected_lr & 0xFFFF),
        movk_w1_lsl16((expected_lr >> 16) & 0xFFFF),
        CMP_X30_X1,
    ]

    # The stub replaces check_signature, so it must still return 0 (success)
    # for every caller: 8 of the 9 call sites test `tbnz w0, #31` and the 9th
    # (the uH loader at 0xb9170) tests `cbnz w0`, so 0 reads as success at all.
    #
    # Instruction stream is built first, then the key is appended, so the adr
    # offset is derived rather than hardcoded.
    if fuse_mode == FUSE_PROGRAM_KEY2_ONLY:
        # Program KEY2 and stop. Does NOT set USE_KEY2, so nothing about boot
        # changes: the BootROM's KEY2 condition remains false and the device
        # keeps verifying against the fused KEY slot. This exists so the fused
        # value can be read back and checked before anything commits to it.
        print("fuse mode: PROGRAM KEY2 ONLY (USE_KEY2 is NOT set)")
        body = [
            0xA9BF7BFD,  # stp x29, x30, [sp, #-0x10]!
            *gate,       # movz/movk w1, <expected LR> ; cmp x30, x1
            bne_words(4),   # not our caller -> fall through to the ret
            None,        # adr x0, key   (patched below)
            0x52800401,  # mov w1, #0x20
            jump_to_func_from(check_signature + 7 * 4, write_key2),
            0xD2800000,  # out: mov x0, #0
            0xA8C17BFD,  # ldp x29, x30, [sp], #0x10
            0xD65F03C0,  # ret
        ]
    elif fuse_mode == FUSE_SET_USE_ONLY:
        # Set USE_KEY2 and nothing else. For a board whose KEY2 slot is
        # already programmed and read back correct: re-running 0x16 against a
        # programmed slot may well return an error, and in FUSE_PROGRAM_AND_COMMIT
        # the cbnz guard would then skip 0x17 and the run would be wasted.
        #
        # No key is appended and no adr is emitted, because the USE command
        # takes no buffer -- it is the single bit.
        write_use_key2 = otp_program_function(
            data, b"[OTP] USE_ROM_SEC_BOOT_KEY2 program start\n\0", 0x4, 0x17
        )
        print(f"cm_otp_write_use_rom_sec_boot_key2: {write_use_key2:#x}")
        print("fuse mode: SET USE_KEY2 ONLY - this commits the board to KEY2")
        body = [
            0xA9BF7BFD,  # stp x29, x30, [sp, #-0x10]!
            *gate,       # movz/movk w1, <expected LR> ; cmp x30, x1
            bne_words(2),   # not our caller -> fall through to the ret
            jump_to_func_from(check_signature + 5 * 4, write_use_key2),
            0xD2800000,  # out: mov x0, #0
            0xA8C17BFD,  # ldp x29, x30, [sp], #0x10
            0xD65F03C0,  # ret
        ]
    elif fuse_mode == FUSE_PROGRAM_AND_COMMIT:
        write_use_key2 = otp_program_function(
            data, b"[OTP] USE_ROM_SEC_BOOT_KEY2 program start\n\0", 0x4, 0x17
        )
        print(f"cm_otp_write_use_rom_sec_boot_key2: {write_use_key2:#x}")
        print("fuse mode: PROGRAM KEY2 **AND SET USE_KEY2** - this commits")
        body = [
            0xA9BF7BFD,  # stp x29, x30, [sp, #-0x10]!
            *gate,       # movz/movk w1, <expected LR> ; cmp x30, x1
            bne_words(6),   # not our caller -> fall through to the ret
            None,        # adr x0, key   (patched below)
            0x52800401,  # mov w1, #0x20
            jump_to_func_from(check_signature + 7 * 4, write_key2),
            cbnz_x0(8),  # KEY2 program failed (nonzero) -> never set USE_KEY2
            jump_to_func_from(check_signature + 9 * 4, write_use_key2),
            0xD2800000,  # out: mov x0, #0
            0xA8C17BFD,  # ldp x29, x30, [sp], #0x10
            0xD65F03C0,  # ret
        ]
    else:
        raise ValueError(f"unknown fuse_mode {fuse_mode!r}")

    print("WARNING: patching for burning BOOT_KEY2!")
    # The key is appended after the body, so the adr distance is derived from
    # where the placeholder actually sits rather than assumed.
    if None in body:
        adr_index = body.index(None)
        body[adr_index] = adr_x0((len(body) - adr_index) * 4)
        payload = body + list(struct.unpack("<8I", get_efuse_data()))
    else:
        # USE-only carries no buffer, so no anchor is appended.
        payload = body
    write_words(data, check_signature, payload)


FUSE_PROGRAM_KEY2_ONLY = "key2"       # write KEY2, leave USE_KEY2 alone
FUSE_SET_USE_ONLY = "use"             # set USE_KEY2 only, for an already-programmed slot
FUSE_PROGRAM_AND_COMMIT = "key2+use"  # write KEY2 then set USE_KEY2

# Which half of the fuse to emit when should_fuse_key is on. Default to the
# reversible-in-effect half: programming KEY2 alone changes no boot behaviour,
# because the BootROM selects KEY2 only when its C/D condition is active. The
# likely mapping is C=USE_KEY2 and D=BAN_KEY2, but that mapping must be proven
# before FUSE_PROGRAM_AND_COMMIT is used. See docs/custom_key_fuse_port.md.
fuse_mode = os.environ.get("FUSE_MODE", FUSE_PROGRAM_KEY2_ONLY)

# Burns BOOT_KEY2 once, after a UFS boot. Off unless the environment asks for it
# by its full name, so a plain `patch_9825.py u-boot.bin` can never emit the
# fuse stub by accident, while a fuse build stays reproducible from a command
# line instead of a source edit:
#     FUSE_BOOT_KEY=yes-burn-key2 python3 scripts/patch_9825.py <u-boot.bin>
should_fuse_key = os.environ.get("FUSE_BOOT_KEY") == "yes-burn-key2"

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = bytearray(f.read())

    # patch_fuse_boot_key installs its own stub over check_signature, ending in
    # `mov x0,#0 / ldp / ret`, so it already subsumes patch_check_signature.
    # It must run while check_signature still has its original prologue:
    # function_containing()/is_entry() locate the function by that prologue
    # (stp x29,x30 / sub sp), and patch_check_signature's RETURN_ZERO
    # overwrites it, which made the scan fail with "no called function entry".
    if should_fuse_key:
        patch_fuse_boot_key(data)
        # The fuse stub calls the OTP SMC, which needs the secure payload and
        # its CM-partition LDFW initialized. This path otherwise skips the
        # secure payload before LDFW initialization can complete.
        patch_force_secure_payload_load(data)
    else:
        patch_check_signature(data)

    patch_initialize_efuse_data(data)
    patch_set_warranty_void_bit_reason(data)
    patch_set_warranty_bit(data)
    patch_read_rlc_rpmb(data)
    patch_read_kg_rpmb(data)
    patch_have_this_mode(data)

    with open(sys.argv[1], "wb") as f:
        f.write(data)
