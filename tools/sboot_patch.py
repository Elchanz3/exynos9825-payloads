#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# sboot_patch.py - Exynos9825 (SM-N975F) sboot / U-Boot engineering patcher.
#
# Locates engineering / verification gate functions inside the signed sboot
# stage by Samsung's own diagnostic strings (cross-reference, version robust)
# and neutralizes them with tiny AArch64 return stubs, so the stage reports the
# unit as an engineering device and stops refusing non-stock images.
#
# This only rewrites the sboot image on disk. The patched image still has to be
# accepted by the preceding chain (see the custom-key resign step); patching
# alone does not make a modified sboot boot.
#
# Usage:
#   tools/sboot_patch.py sboot_stage.bin [--out patched.bin] [--all] [--dry-run]
#
# Default patches (engineering identity):
#   - have_this_mode  -> return 1   (every ENG MODE query is allowed)
#   - etc_market = 0, etc_development = 1   (report a development unit)
# With --all, also relax the checks that otherwise reject a non-stock image:
#   - check_signature            -> return 0
#   - set_warranty_bit / reason  -> return 0
#   - [KG]/[RLC] read_data (RPMB) -> return 0
# With --normal-boot, force the Download-vs-normal-boot fork to normal boot, so
# a chain booted over USB continues into Android instead of the Odin screen.

import argparse
import struct
import sys

RETURN_ZERO = bytes.fromhex("00 00 80 D2 C0 03 5F D6")  # mov w0,#0 ; ret
RETURN_ONE = bytes.fromhex("20 00 80 D2 C0 03 5F D6")   # mov w0,#1 ; ret


def u32(data, off):
    return int.from_bytes(data[off:off + 4], "little")


def put_u32(data, off, value):
    struct.pack_into("<I", data, off, value)


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def is_bl(data, off):
    return u32(data, off) & 0xFC000000 == 0x94000000


def bl_target(data, off):
    return off + sign_extend(u32(data, off) & 0x03FFFFFF, 26) * 4


def function_start_or_prologue(data, inside, limit=0x1000):
    """The entry of the function containing `inside`.

    Two obvious rules are both wrong here. Walking back to the first prologue
    stops at an inner `stp x29,x30,[sp,#-N]!`, and a safety check built that
    way resolved the KEY2 programming function 0x10 past its real entry and
    then reported "no callers" for the one image that calls it. Taking the
    nearest call target is wrong too: the OTP commands are dispatched from a
    console table, so most of them are never the target of a `bl`.

    What does hold is that a function entry is a prologue whose preceding
    instruction ends the function before it -- a `ret` or an unconditional
    branch -- or is padding.
    """
    def ends_a_function(off):
        if off < 0:
            return True
        word = u32(data, off)
        return (word == 0xD65F03C0                      # ret
                or word & 0xFC000000 == 0x14000000      # b
                or word == 0xD503201F                   # nop padding
                or word == 0)

    start = inside - (inside % 4)
    while start > inside - limit:
        if is_prologue(data, start) and ends_a_function(start - 4):
            return start
        start -= 4
    raise KeyError(f"no entry within {limit:#x} before {inside:#x}")


def function_start_or_block(data, inside):
    """The first instruction of the basic block a string load belongs to.

    A diagnostic is usually loaded with adrp+add; the branch that reaches the
    block lands on the adrp, which may be a word or two before the xref the
    scanner returns.
    """
    for back in (0, 4, 8, 0xC):
        candidate = inside - back
        if u32(data, candidate) & 0x9F000000 == 0x90000000:   # adrp
            return candidate
    return inside


def encode_b(site, target):
    delta = target - site
    if delta & 3:
        raise ValueError(f"unaligned B target: {site:#x} -> {target:#x}")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError(f"B target out of range: {site:#x} -> {target:#x}")
    return 0x14000000 | (immediate & 0x03FFFFFF)


def encode_bl(site, target):
    delta = target - site
    if delta & 3:
        raise ValueError(f"unaligned BL target: {site:#x} -> {target:#x}")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError(f"BL target out of range: {site:#x} -> {target:#x}")
    return 0x94000000 | (immediate & 0x03FFFFFF)


def is_prologue(data, off):
    # stp x29,x30,[sp,#-N]!  or  sub sp,sp,#N
    return u32(data, off) & 0xFFC003FF in (0xA98003FD, 0xD10003FF)


def adrp_add_target(data, off):
    # Resolve an ADRP (+ nearby ADD xd,xd,#imm) to the byte offset it addresses.
    adrp = u32(data, off)
    if adrp & 0x9F000000 != 0x90000000:
        return None
    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    page = (off & ~0xFFF) + (sign_extend(imm, 21) << 12)
    for distance in range(4, 17, 4):
        add = u32(data, off + distance)
        if add & 0xFF000000 == 0x91000000 and (add >> 5) & 31 == adrp & 31:
            shift = 12 if add & 0x400000 else 0
            return page + (((add >> 10) & 0xFFF) << shift)
    return None


def adrp_pointer_values(data, off, window=7):
    """Every address an ADRP at `off` can form with the ADDs that follow it.

    Samsung builds a __func__ pointer in two steps, and not always in the same
    register:

        adrp x20, <page>
        add  x1, x20, #0x240      <- destination differs from the source
        add  x1, x1, #0x20

    so a resolver that insists on `add xd,xd,#imm` (which is all the format
    strings need) sees nothing here. Follow the renames and return the page
    plus every partial sum, because which one is the real pointer depends on
    how far the chain goes.
    """
    adrp = u32(data, off)
    if adrp & 0x9F000000 != 0x90000000:
        return ()
    imm = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2)
    page = (off & ~0xFFF) + (sign_extend(imm, 21) << 12)
    live = {adrp & 31: page}
    values = {page}
    for step in range(1, window + 1):
        word = u32(data, off + 4 * step)
        if word & 0xFF000000 != 0x91000000:          # add xd,xs,#imm
            continue
        src, dst = (word >> 5) & 31, word & 31
        if src not in live:
            continue
        shift = 12 if word & 0x400000 else 0
        value = live[src] + (((word >> 10) & 0xFFF) << shift)
        live[dst] = value
        values.add(value)
    return tuple(values)


def find_function_by_name_string(data, name):
    """The function that references its own __func__ string `name`.

    All references to a __func__ literal are inside the function it names, so
    several xrefs are expected; they just have to agree on the function.
    """
    string_off = find_string(data, name)
    funcs = set()
    for off in range(0, len(data) - 32, 4):
        if string_off in adrp_pointer_values(data, off):
            try:
                funcs.add(function_start(data, off))
            except KeyError:
                pass
    if len(funcs) != 1:
        raise KeyError(f"xrefs to {name!r} resolve to {len(funcs)} functions")
    return funcs.pop()


def find_string(data, text):
    needle = text.encode() + b"\0"
    off = data.find(needle)
    if off < 0:
        raise KeyError(f"string not found: {text!r}")
    if data.find(needle, off + 1) >= 0:
        raise KeyError(f"string not unique: {text!r}")
    return off


def find_single_xref(data, text):
    string_off = find_string(data, text)
    refs = [o for o in range(0, string_off & ~3, 4)
            if adrp_add_target(data, o) == string_off]
    if len(refs) != 1:
        raise KeyError(f"expected one xref to {text!r}, found {len(refs)}")
    return refs[0]


_call_targets = {}


def call_targets(data):
    key = id(data)
    if key not in _call_targets:
        _call_targets[key] = sorted({bl_target(data, o)
                                     for o in range(0, len(data) - 3, 4)
                                     if is_bl(data, o)})
    return _call_targets[key]


def function_start(data, inside, limit=0x800):
    # The entry is the nearest BL target at or before `inside`. Scanning back
    # for the first prologue is wrong when a function opens with
    # `sub sp,sp,#N` followed by `stp x29,x30,...` (e.g. [KG] read_data).
    entry = max((t for t in call_targets(data)
                 if inside - limit <= t <= inside), default=None)
    if entry is None or not is_prologue(data, entry):
        raise KeyError(f"no called function entry within {limit:#x} before {inside:#x}")
    return entry


class Patcher:
    def __init__(self, data, dry_run=False):
        self.data = data
        self.dry_run = dry_run
        self.log = []

    def _write(self, off, blob, what):
        before = self.data[off:off + len(blob)].hex()
        if not self.dry_run:
            self.data[off:off + len(blob)] = blob
        self.log.append(f"  {what:28} @0x{off:06x}  {before} -> {blob.hex()}")

    def stub_function_at_string(self, text, stub, what, back):
        # The diagnostic string is printed inside the target function; the
        # function start is the nearest prologue before its xref.
        xref = find_single_xref(self.data, text)
        start = function_start(self.data, xref)
        self._write(start, stub, what)
        return start

    def patch_have_this_mode(self):
        # Reporter that prints "ENG MODE : ... ALLOWED(%s)" calls a gate
        # (BL ; CBZ w0) whose target ends in TST ; CSET w0,ne ; RET. Force it
        # to return 1 so every engineering mode is allowed.
        xref = find_single_xref(self.data, "ENG MODE : ENG ALLOWED(%s)\n")
        gate = None
        for off in range(xref - 0x80, xref, 4):
            if is_bl(self.data, off) and \
               self.data[off + 4] & 0x1F == 0 and \
               u32(self.data, off + 4) & 0xFF00001F == 0x34000000:  # CBZ w0
                target = bl_target(self.data, off)
                tail = [u32(self.data, target + k) for k in (12, 16, 20)]
                if tail == [0x6A01001F, 0x1A9F07E0, 0xD65F03C0]:  # TST;CSET;RET
                    gate = target
                    break
        if gate is None:
            raise KeyError("have_this_mode gate not found")
        self._write(gate, RETURN_ONE, "have_this_mode->1")

    def patch_eng_efuse_bits(self):
        # Inside the efuse-init routine (holds the nantirbk0/commercial_bit
        # diagnostics) a run of "mov w0,#k ; bl read ; ldr ; str w0,[xN,#off]"
        # programs the reported fuse fields. The mov selects WHICH field is
        # read, so the result is forced by replacing the BL: etc_market feeds
        # [#0x40], etc_development (16 bytes on) feeds [#0x44].
        func = function_start(self.data, find_single_xref(
            self.data, "commercial_bit mismatch!(%d vs %d), updating...\n"))
        def is_mov_w0(word):          # mov w0,#imm16
            return word & 0x7F80001F == 0x52800000
        def is_str_w0(word, off64):   # str w0,[xN,#off64]
            return (word & 0xFFC00000 == 0xB9000000
                    and (word >> 10) & 0xFFF == off64 // 4
                    and word & 0x1F == 0)
        etc_market = None
        for off in range(func, func + 0x400, 4):
            if is_mov_w0(u32(self.data, off)) \
               and is_bl(self.data, off + 4) \
               and is_str_w0(u32(self.data, off + 12), 0x40):
                etc_market = off
                break
        if etc_market is None:
            raise KeyError("etc_market store not found")
        if not (is_bl(self.data, etc_market + 20)
                and is_str_w0(u32(self.data, etc_market + 28), 0x44)):
            raise KeyError("etc_development read does not follow etc_market")
        self._write(etc_market + 4, bytes.fromhex("00 00 80 52"), "etc_market=0")       # bl -> mov w0,#0
        self._write(etc_market + 20, bytes.fromhex("20 00 80 52"), "etc_development=1")  # bl -> mov w0,#1

    # A PMU INFORM register nothing in this stage touches (0x15860800, 804,
    # 810..81c are all unused; 808 is MINFORM and 80c is the download magic).
    # The always-on domain keeps it across a warm reset, so a value left here
    # by a dying boot can be read back by the next payload.
    SCRATCH_INFORM = 0x15860818

    def patch_skip_usb_recovery(self):
        # Never draw the blue "USB RECOVERY MODE" prompt.
        #
        # It is the tail of the secure-payload block: when
        # `load_secure_payload()` fails, u-boot prints "Fail to load Secure
        # Payload!!", prints the debug info, and tail-branches into this
        # function, which draws
        #
        #     UP KEY : NORMAL BOOTING / DOWN KEY : DOWNLOAD MODE
        #     USB RECOVERY MODE
        #
        # waits for a key, and writes 0x66265999 to DRAM 0x80000000 on the way
        # out -- so the screen arms itself for the next boot, and a bench board
        # on USB power never loses the word. It already returns 0 without
        # drawing when neither magic matches, so a `mov w0,#0 ; ret` is that
        # same answer, unconditionally.
        xref = find_single_xref(self.data, "USB RECOVERY MODE\n")
        start = xref
        while start > xref - 0x400:
            if is_prologue(self.data, start):
                break
            start -= 4
        else:
            raise KeyError("no prologue before the USB RECOVERY MODE string")
        self._write(start, RETURN_ZERO, "usb_recovery_prompt->0")

    def patch_report_secure_payload(self):
        # Park the secure-payload loader's return code in a PMU INFORM
        # register, because the failure is otherwise invisible: the message it
        # prints goes to a console this board does not expose, and by the time
        # anything could be read back the device is off the USB bus.
        #
        #     mov  w0, #0x20
        #     bl   load_secure_payload
        #     cbz  x0, <ok>
        #     mov  x1, x0                 <- overwritten from here
        #     adrp x0, "Fail to load Secure Payload!! [ret = %lx]"
        #     add  x0, x0, #0x808
        #     bl   printf
        #
        # Four instructions are replaced by movz/movk/str/nop, which keeps the
        # layout and costs only the printf nobody can read.
        xref = find_single_xref(
            self.data, "Fail to load Secure Payload!! [ret = %lx]\n")
        site = None
        for off in range(xref - 0x20, xref, 4):
            if u32(self.data, off) == 0xAA0003E1:        # mov x1, x0
                site = off
                break
        if site is None:
            raise KeyError("no `mov x1,x0` before the secure-payload message")
        low = self.SCRATCH_INFORM & 0xFFFF
        high = (self.SCRATCH_INFORM >> 16) & 0xFFFF
        blob = struct.pack(
            "<IIII",
            0xD2800001 | (low << 5),          # movz x1, #low
            0xF2A00001 | (high << 5),         # movk x1, #high, lsl #16
            0xB9000020,                       # str  w0, [x1]
            0xD503201F)                       # nop
        self._write(site, blob,
                    f"secure payload ret -> {self.SCRATCH_INFORM:#x}")

    def patch_normal_boot(self):
        # Force the Download-vs-normal-boot fork to normal boot.
        #
        # The call site is
        #
        #     bl   s5p_check_download
        #     mov  w21, w0            (the reason, for do_download)
        #     cbz  w0, <normal boot>
        #
        # and six of the seven reasons it can answer are explicit requests:
        # param[0] == 1 or 0xd, the 0xabcf magic in param[3], param[4], a
        # pressed key. The seventh is the one a USB-booted device falls into --
        # is_normal_booting() == 0 (MINFORM is the reset value on a cold boot)
        # together with ifconn_check_jig_adc_value() == 1 (a cable is attached
        # by definition, the payload arrives over it).
        #
        # Replace the CALL with `mov w0, #0` rather than making the branch
        # unconditional. The difference matters: the normal-boot path opens
        # with `bl get_param(w0)`, so it reads w0 as a parameter INDEX. Forcing
        # the branch leaves the download reason in w0 and the first thing the
        # normal path does is fetch the wrong parameter -- which is exactly how
        # the first attempt died, silently, with a black screen. Returning 0
        # from the call reproduces the legitimate "no reason to download" state
        # register for register, and the keypad escape is the only thing lost.
        func = find_function_by_name_string(self.data, "s5p_check_download")
        callers = [o for o in range(0, len(self.data) - 3, 4)
                   if is_bl(self.data, o) and bl_target(self.data, o) == func]
        if len(callers) != 1:
            raise KeyError(f"s5p_check_download has {len(callers)} callers, expected 1")
        site = callers[0]
        # Confirm the shape before touching it: the test has to be a `cbz w0`
        # within a few instructions, or this is not the fork.
        for step in range(1, 5):
            word = u32(self.data, site + 4 * step)
            if word & 0xFF00001F == 0x34000000:          # cbz w0, label
                break
        else:
            raise KeyError("no `cbz w0, label` within 4 instructions of the call")
        self._write(site, bytes.fromhex("00 00 80 52"),   # mov w0, #0
                    "s5p_check_download -> 0")

    def patch_force_download(self):
        # Force the same fork to take the real Download path with reason 4.
        # Keep the following `mov w21,w0` intact because do_download consumes
        # that saved reason. The call is replaced instead of the CBZ so the
        # register state matches a legitimate s5p_check_download() result.
        func = find_function_by_name_string(self.data, "s5p_check_download")
        callers = [o for o in range(0, len(self.data) - 3, 4)
                   if is_bl(self.data, o) and bl_target(self.data, o) == func]
        if len(callers) != 1:
            raise KeyError(f"s5p_check_download has {len(callers)} callers, expected 1")
        site = callers[0]
        if u32(self.data, site + 4) != 0x2A0003F5:       # mov w21,w0
            raise KeyError("download reason is not saved in w21 after the call")
        if u32(self.data, site + 8) & 0xFF00001F != 0x34000000:
            raise KeyError("download fork is not the expected cbz w0")
        self._write(site, bytes.fromhex("80 00 80 52"),   # mov w0, #4
                    "s5p_check_download -> 4")

    def patch_ignore_magic_code(self):
        # Ignore the MAGIC_CODE word in DRAM.
        #
        # Early in its main flow u-boot does
        #
        #     mov  x1, #0x80000000
        #     ldr  w19, [x1]                 ; printf("MAGIC_CODE 0x%x", w19)
        #     ... == 0x66269633 || == 0x66265999 || == 0x6626ccca -> upload path
        #
        # and that path ends at the blue "USB RECOVERY MODE" prompt, which on
        # its way out writes 0x66265999 back to 0x80000000. The word therefore
        # survives into the next attempt, and since a bench board on USB power
        # only ever warm-resets, DRAM keeps it: one failed boot hijacks every
        # run after it, before the download fork is even reached.
        #
        # Reading zero instead makes each run independent of the last. A full
        # power-off clears it too, but that is a thing to remember rather than
        # a property of the image.
        xref = find_single_xref(self.data, "MAGIC_CODE 0x%x\n")
        base = None
        for off in range(xref - 0x20, xref + 0x20, 4):
            if u32(self.data, off) == 0xD2B00001:        # mov x1, #0x80000000
                base = off
                break
        if base is None:
            raise KeyError("no `mov x1,#0x80000000` next to the MAGIC_CODE print")
        for off in range(base + 4, base + 0x20, 4):
            word = u32(self.data, off)
            if word & 0xFFFFFC00 == 0xB9400000 and (word >> 5) & 31 == 1:
                reg = word & 31                          # ldr wN,[x1]
                self._write(off, struct.pack("<I", 0x52800000 | reg),
                            "MAGIC_CODE -> 0")
                return
        raise KeyError("no `ldr wN,[x1]` after the MAGIC_CODE base load")

    def patch_ignore_ldfw_mode(self):
        # Let the normal UFS path initialize the CM/LDFW services even when
        # DRAM still contains the mode pair left by the preceding EUB boot.
        #
        # FUN_c90a616c opens with:
        #
        #     x2 = 0x80000000
        #     x1 = 0x80000010
        #     ldr w20, [x2]
        #     ...
        #     ldr w19, [x1]
        #
        # and returns zero before reading the CM partition when the pair is
        # one of the three download-mode values. BL2 has initialized DRAM by
        # the time u-boot executes, so neutralize the two reads here instead
        # of touching DRAM from the much earlier EPBL trampoline.
        xref = find_single_xref(
            self.data,
            "MAGIC_RAM_BASE: %x, MAGIC_RAM_BASE2: %x, ompin: %x\n",
        )
        start = xref
        while start > xref - 0x100 and not is_prologue(self.data, start):
            start -= 4
        if not is_prologue(self.data, start):
            raise KeyError("no prologue before the LDFW mode diagnostic")

        expected = {
            start + 0x04: 0xD2B00002,  # mov x2, #0x80000000
            start + 0x08: 0xD2800201,  # mov x1, #0x10
            start + 0x20: 0xF2B00001,  # movk x1, #0x8000, lsl #16
            start + 0x38: 0xB9400054,  # ldr w20, [x2]
            start + 0x44: 0xB9400033,  # ldr w19, [x1]
        }
        for off, word in expected.items():
            if u32(self.data, off) != word:
                raise KeyError(
                    f"unexpected LDFW mode sequence at {off:#x}: "
                    f"{u32(self.data, off):#010x}"
                )

        self._write(start + 0x38, struct.pack("<I", 0x52800014),
                    "LDFW mode[0] -> 0")
        self._write(start + 0x44, struct.pack("<I", 0x52800013),
                    "LDFW mode[1] -> 0")

    all_ldfw_paths = False

    otp_check_anchor = None

    def patch_probe_otp_check(self):
        """Rehearse the buffer path with the CHECK command, which never writes.

        Command 0x16 hands the secure side a 32-byte buffer. So does 0x114,
        except that it compares instead of burning:

            0xc90a299c  ROM_SECURE_BOOT_KEY2 check
                        x0 = key buffer, w1 = length, must be 0x20
                        -> "check: valid key"
                        -> "check: invalid key"
                        -> "hasn't been programed yet"

        Wiring the prompt to "hasn't been programed yet" asks the device's own
        service to confirm the slot is still blank, over exactly the path the
        irreversible command would use. The answer does not depend on which
        32 bytes are passed, so the anchor is used only for realism.
        """
        anchor = bytes.fromhex(self.otp_check_anchor)
        if len(anchor) != 0x20:
            raise KeyError("the anchor must be 32 bytes")
        check_fn = function_start_or_prologue(
            self.data, find_single_xref(
                self.data, "[OTP] ROM_SECURE_BOOT_KEY2 check start\n"))
        blank_xref = find_single_xref(
            self.data,
            "[OTP] ROM_SECURE_BOOT_KEY2 hasn't been programed yet\n")
        prompt = function_start_or_prologue(
            self.data, find_single_xref(self.data, "USB RECOVERY MODE\n"))

        cave = 0x17CE00
        body = [
            0xA9BF7BFD,                       # stp x29,x30,[sp,#-16]!
            0x100000A0,                       # adr x0, cave+0x18
            0x52800401,                       # mov w1, #0x20
            encode_bl(cave + 0xC, check_fn),  # bl  <check KEY2>
            0xA8C17BFD,                       # ldp x29,x30,[sp],#16
            0xD65F03C0,                       # ret
        ]
        blob = b"".join(struct.pack("<I", w) for w in body) + b"\0" * 8 + anchor
        if self.data[cave:cave + len(blob)] != bytes(len(blob)):
            raise KeyError(f"cave at {cave:#x} is not free")
        self._write(cave, blob, "OTP check trampoline + anchor")

        success = find_single_xref(
            self.data,
            "ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) "
            "have been inited done.\n")
        calls = [off for off in range(success + 4, success + 0x18, 4)
                 if is_bl(self.data, off)]
        self._write(calls[0], struct.pack("<I", encode_bl(calls[0], cave)),
                    "LDFW success -> OTP check")

        prints = [off for off in range(blank_xref + 4, blank_xref + 0x18, 4)
                  if is_bl(self.data, off)]
        if not prints:
            raise KeyError("no call after the not-programmed diagnostic")
        self._write(prints[0], struct.pack("<I", encode_bl(prints[0], prompt)),
                    "'not programmed' -> draw the prompt")

        tails = [off for off in range(0, len(self.data) - 3, 4)
                 if u32(self.data, off) & 0xFC000000 == 0x14000000
                 and off + sign_extend(u32(self.data, off) & 0x03FFFFFF, 26) * 4
                 == prompt]
        if len(tails) != 1:
            raise KeyError("expected one tail branch to the prompt")
        self._write(tails[0], struct.pack("<I", 0xD65F03C0),
                    "usb-recovery tail branch -> ret")

    def patch_probe_otp_read(self):
        """Issue the READ-ONLY OTP command 0x115 and show whether it answers.

        The CM/LDFW initializer now succeeds, so the question is whether the
        secure side will actually answer an OTP command. The one to ask is a
        read, never a write:

            0xc90a2c94  USE_ROM_SEC_BOOT_KEY2 read
                        x0 = pointer for the result
                        smc(0xc2001014, 0x115, 0, 0)
                        ret == -1  -> "[OTP] LDFW hasn't been loaded"
                        ret != 0   -> "[OTP] ... read failed"
                        ret == 0   -> "[OTP] ... read value: 0x%llx"

        A trampoline in the cave calls it with a scratch pointer, the LDFW
        success diagnostic calls the trampoline, and the prompt is wired to
        the read's own success print. Blue therefore means the SMC returned
        zero and the service is live.

        Command 0x16, the irreversible one, is nowhere in this path.
        """
        read_fn = function_start_or_prologue(
            self.data, find_single_xref(
                self.data, "[OTP] USE_ROM_SEC_BOOT_KEY2 read: start\n"))
        value_xref = find_single_xref(
            self.data, "[OTP] USE_ROM_SEC_BOOT_KEY2 read value: 0x%llx\n")
        prompt = function_start_or_prologue(
            self.data, find_single_xref(self.data, "USB RECOVERY MODE\n"))

        cave = 0x17CE00
        body = [
            0xA9BF7BFD,                      # stp x29,x30,[sp,#-16]!
            0x100000A0,                      # adr x0, cave+0x18
            encode_bl(cave + 8, read_fn),    # bl  <read USE_KEY2>
            0xA8C17BFD,                      # ldp x29,x30,[sp],#16
            0xD65F03C0,                      # ret
            0, 0, 0,
        ]
        if self.data[cave:cave + 4 * len(body)] != bytes(4 * len(body)):
            raise KeyError(f"cave at {cave:#x} is not free")
        self._write(cave, b"".join(struct.pack("<I", w) for w in body),
                    "OTP read trampoline")

        success = find_single_xref(
            self.data,
            "ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) "
            "have been inited done.\n")
        calls = [off for off in range(success + 4, success + 0x18, 4)
                 if is_bl(self.data, off)]
        if not calls:
            raise KeyError("no call after the LDFW success diagnostic")
        self._write(calls[0], struct.pack("<I", encode_bl(calls[0], cave)),
                    "LDFW success -> OTP read")

        prints = [off for off in range(value_xref + 4, value_xref + 0x18, 4)
                  if is_bl(self.data, off)]
        if not prints:
            raise KeyError("no call after the OTP read-value diagnostic")
        self._write(prints[0], struct.pack("<I", encode_bl(prints[0], prompt)),
                    "OTP read value -> draw the prompt")

        tails = [off for off in range(0, len(self.data) - 3, 4)
                 if u32(self.data, off) & 0xFC000000 == 0x14000000
                 and off + sign_extend(u32(self.data, off) & 0x03FFFFFF, 26) * 4
                 == prompt]
        if len(tails) != 1:
            raise KeyError("expected one tail branch to the prompt")
        self._write(tails[0], struct.pack("<I", 0xD65F03C0),
                    "usb-recovery tail branch -> ret")

    def patch_ignore_secpayload_sentinel(self):
        """Let the CM/LDFW initializer run even when the Secure OS is absent.

        u-boot stores 0xfa11 into a global before asking the EL3 monitor for
        the Secure Payload, and clears it only when that SMC returns zero:

            0xc90033f4  str w2, [x20, #648]     ; w2 = 0xfa11
            0xc9003500  str wzr, [x20, #648]    ; only on success

        The initializer reads the same word first and bails out before it
        ever looks for the CM partition:

            0xc90a6254  ldr w1, [x0, #648]
            0xc90a625c  cmp w1, #0xfa11
            0xc90a6260  b.eq -> "[ldfw] Skip ldfw & Security initialize.
                                 Secure Payload was not loaded."  ; ret -1

        That single gate explains every LDFW result so far: the initializer
        does run, it just leaves through an exit that none of the four result
        diagnostics cover. Reading zero instead sends it down the real path,
        where those four finally mean something.
        """
        xref = find_single_xref(
            self.data,
            "[ldfw] Skip ldfw & Security initialize. "
            "Secure Payload was not loaded.\n")
        skip = function_start_or_block(self.data, xref)
        sites = [off for off in range(0, len(self.data) - 3, 4)
                 if u32(self.data, off) & 0xFF00001F == 0x54000000
                 and off + sign_extend((u32(self.data, off) >> 5) & 0x7FFFF, 19) * 4
                 == skip]
        if len(sites) != 1:
            raise KeyError(f"expected one branch to the skip block, "
                           f"found {len(sites)}")
        site = sites[0]
        expected = {site - 0x4: 0x6B00003F,     # cmp w1, w0
                    site - 0x8: 0x529F4220,     # mov w0, #0xfa11
                    site - 0xC: 0xB9428801}     # ldr w1, [x0, #648]
        for off, word in expected.items():
            if u32(self.data, off) != word:
                raise KeyError(f"unexpected sentinel sequence at {off:#x}: "
                               f"{u32(self.data, off):#010x}")
        self._write(site - 0xC, bytes.fromhex("01 00 80 52"),   # mov w1, #0
                    "secure-payload sentinel -> 0")

    prompt_after = None

    def patch_prompt_after(self):
        """Point the blue prompt at the first call after a chosen message.

        The relocated prompt is the only reliable output this board has on the
        normal-boot path, so make it a general instrument instead of a patch
        per question: name any diagnostic string and the prompt is drawn when
        the code that prints it is reached. Blue means reached; a crash cannot
        draw a prompt, so the positive direction stays unambiguous.
        """
        start = function_start_or_prologue(
            self.data, find_single_xref(self.data, "USB RECOVERY MODE\n"))
        tails = [off for off in range(0, len(self.data) - 3, 4)
                 if u32(self.data, off) & 0xFC000000 == 0x14000000
                 and off + sign_extend(u32(self.data, off) & 0x03FFFFFF, 26) * 4
                 == start]
        if len(tails) != 1:
            raise KeyError(f"expected one tail branch to the prompt, "
                           f"found {len(tails)}")
        self._write(tails[0], struct.pack("<I", 0xD65F03C0),
                    "usb-recovery tail branch -> ret")

        xref = find_single_xref(self.data, self.prompt_after)
        # Some diagnostics build several argument registers before the call,
        # so allow a wider window than the LDFW result sites need.
        calls = [off for off in range(xref + 4, xref + 0x40, 4)
                 if is_bl(self.data, off)]
        if not calls:
            raise KeyError(f"no call after {self.prompt_after!r}")
        self._write(calls[0], struct.pack("<I", encode_bl(calls[0], start)),
                    f"prompt at {self.prompt_after.strip()!r}")


    def patch_ldfw_success_prompt(self):
        # Turn the blue prompt into a positive oracle for the LDFW result.
        #
        # With no UART and with EP1 gone after the EL3 monitor, the only
        # output proven to work on the normal-boot path is that prompt: the
        # previous run drew it. So instead of suppressing it, move it.
        #
        #   1. the tail branch that reaches it from the secure-payload block
        #      becomes `ret`, so the function stays intact but is no longer a
        #      dead end for the normal path;
        #   2. the CM/LDFW success diagnostic calls it instead of printf.
        #
        # Blue screen then means "ldfw: try to init N ldfw(s)" was reached,
        # which is the one fact the fuse route depends on. Black means it was
        # not, and a crash cannot draw a prompt.
        start = function_start_or_prologue(
            self.data, find_single_xref(self.data, "USB RECOVERY MODE\n"))

        tails = [off for off in range(0, len(self.data) - 3, 4)
                 if u32(self.data, off) & 0xFC000000 == 0x14000000
                 and off + sign_extend(u32(self.data, off) & 0x03FFFFFF, 26) * 4
                 == start]
        if len(tails) != 1:
            raise KeyError(f"expected one tail branch to the prompt, "
                           f"found {len(tails)}")
        self._write(tails[0], struct.pack("<I", 0xD65F03C0),
                    "usb-recovery tail branch -> ret")

        messages = ["ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) "
                    "have been inited done.\n"]
        if self.all_ldfw_paths:
            messages += ["ldfw: No ldfw is inited\n",
                         "ldfw: signature of ldfw is corrupted! ret = [0x%llX]\n",
                         "ldfw: It is dump_gpr state. It does not load ldfw.\n"]
        for message in messages:
            xref = find_single_xref(self.data, message)
            calls = [off for off in range(xref + 4, xref + 0x14, 4)
                     if is_bl(self.data, off)]
            if not calls:
                raise KeyError(f"no call after {message!r}")
            self._write(calls[0], struct.pack("<I", encode_bl(calls[0], start)),
                        "LDFW result -> draw the prompt")

    def patch_probe_ldfw_result(self):
        # Answer "does the CM/LDFW initializer run on this path at all?"
        #
        # The initializer at 0xc90a616c has no direct caller -- it is reached
        # through a function pointer -- so the call graph cannot say whether
        # it executes in Download mode. Its four mutually exclusive result
        # diagnostics can: hang all of them and compare against the Download
        # baseline from the same chain.
        #
        #   Download -> none of the four was reached: the initializer never
        #               ran on this path
        #   black    -> one of them was reached: it ran
        #
        # The polarity is the usable one. A crash produces black, so black
        # alone would be ambiguous -- but here the baseline run of the very
        # same image reached Download, so black can only come from the change.
        messages = (
            "ldfw: No ldfw is inited\n",
            "ldfw: signature of ldfw is corrupted! ret = [0x%llX]\n",
            "ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) have been inited done.\n",
            "ldfw: It is dump_gpr state. It does not load ldfw.\n",
        )
        target = None
        for message in messages:
            xref = find_single_xref(self.data, message)
            calls = [off for off in range(xref + 4, xref + 0x14, 4)
                     if is_bl(self.data, off)]
            if target is None:
                if not calls:
                    raise KeyError(f"no call after {message!r}")
                site = calls[0]
                target = bl_target(self.data, site)
            else:
                matching = [o for o in calls if bl_target(self.data, o) == target]
                if len(matching) != 1:
                    raise KeyError(f"expected one printf after {message!r}")
                site = matching[0]
            self._write(site, struct.pack("<I", 0x14000000),
                        "LDFW result -> hang")

    def patch_prove_secure_payload(self):
        # Turn "did the Secure Payload actually load?" into Download vs black.
        #
        # Reaching Download mode only proves the load attempt did not hang:
        #
        #     mov  w0, #0x20 ; bl <loader>
        #     cbz  x0, <success>      ; "%s: Load done."
        #     mov  x1, x0             ; "Fail to load Secure Payload!! [ret=%lx]"
        #     ... both paths fall through and continue to the fork
        #
        # Hanging the failure path makes the Download screen mean success and
        # nothing else. The polarity matters: a crash anywhere produces a
        # black screen, so black is ambiguous, while Download cannot be
        # produced by a crash.
        done = find_single_xref(self.data, "%s: Load done.\n")
        fail = find_single_xref(
            self.data, "Fail to load Secure Payload!! [ret = %lx]\n")
        sites = [off for off in range(fail - 0x20, fail, 4)
                 if u32(self.data, off) & 0xFF00001F == 0xB4000000
                 and off + sign_extend((u32(self.data, off) >> 5) & 0x7FFFF, 19) * 4
                 in range(done - 0x10, done + 4, 4)]
        if len(sites) != 1:
            raise KeyError(
                f"expected one `cbz x0, load-done`, found {len(sites)}")
        self._write(sites[0] + 4, struct.pack("<I", 0x14000000),
                    "secure-payload failure path -> hang")

    def patch_force_secure_payload(self):
        # Let u-boot load the Secure Payload even when the flag says not to.
        #
        # There are two independent gates before `load_secure_payload`:
        # the MAGIC_CODE comparisons (handled by patch_ignore_magic_code or,
        # better, by patch_clear_boot_magic) and a flag bit:
        #
        #     bl   <reader>          ; returns bit 28 of a word at 0xc93d4b28
        #     cbnz w0, <skip>        ; "%s: Skip to load Secure Payload"
        #     ...
        #     mov  w0, #0x20 ; bl <loader>
        #
        # Neutralizing the *call* rather than the flag word is deliberate:
        # another accessor extracts arbitrary bits of the same word, so
        # zeroing it would change every other consumer too. Replacing the
        # call with `mov w0,#0` affects exactly this decision.
        #
        # Without the Secure Payload there is no CSMC/fuse broker, and every
        # OTP command comes back as -1, which u-boot renders as
        # "[OTP] LDFW hasn't been loaded".
        # The branch lands on the first instruction of the skip block, which
        # is a few words before the adrp that forms the message pointer.
        skip = find_single_xref(self.data, "%s: Skip to load Secure Payload\n")
        window = range(skip - 0x10, skip + 4, 4)
        sites = [off for off in range(0, len(self.data) - 3, 4)
                 if u32(self.data, off) & 0xFF00001F == 0x35000000
                 and off + sign_extend((u32(self.data, off) >> 5) & 0x7FFFF, 19) * 4
                 in window]
        if len(sites) != 1:
            raise KeyError(
                f"expected one `cbnz w0, skip-handler`, found {len(sites)}")
        site = sites[0]
        if u32(self.data, site) & 31 != 0:
            raise KeyError("the skip branch does not test w0")
        if not is_bl(self.data, site - 4):
            raise KeyError("no call immediately before the skip branch")
        self._write(site - 4, bytes.fromhex("00 00 80 52"),   # mov w0, #0
                    "secure-payload skip check -> 0")

    def patch_clear_boot_magic(self):
        # Clear the DRAM boot-mode words once, instead of neutralizing the
        # reads one at a time.
        #
        # 24 places in u-boot read 0x80000000 and compare it against the three
        # download magics 0x66269633 / 0x66265999 / 0x6626ccca.
        # patch_ignore_magic_code covers one of them (the load_secure_payload
        # gate at 0x33f0) and patch_ignore_ldfw_mode two more. The remaining
        # 21 still see whatever EUB left in DRAM, so the image runs in a state
        # no stock boot produces: a few paths told it is a normal boot while
        # two dozen still believe it is Download mode.
        #
        # BL2 initializes DRAM before u-boot runs -- u-boot is executing from
        # 0xc9000000, which is DRAM -- so u-boot can simply zero the words at
        # its own entry and let all 24 sites agree. The EPBL payload cannot do
        # this: the UFSPRE result showed those stores running before BL2 and
        # stopping the chain.
        #
        # The entry word is `b .+4`, so it is a free hook: point it at the
        # cave, do the stores, and branch back to where it would have gone.
        entry = u32(self.data, 0)
        if entry != 0x14000001:
            raise KeyError(f"u-boot entry is {entry:#010x}, expected a b .+4")

        cave = 0x17CE00
        body = [
            0xD2B00010,    # movz x16, #0x8000, lsl #16   -> 0x80000000
            0xB900021F,    # str  wzr, [x16]
            0xB900121F,    # str  wzr, [x16, #0x10]
            0xD5033F9F,    # dsb  sy
            encode_b(cave + 16, 4),
        ]
        if self.data[cave:cave + 4 * len(body)] != bytes(4 * len(body)):
            raise KeyError(f"cave at {cave:#x} is not free")

        self._write(cave, b"".join(struct.pack("<I", w) for w in body),
                    "clear-boot-magic trampoline")
        self._write(0, struct.pack("<I", encode_b(0, cave)),
                    "entry -> clear-boot-magic")

    def patch_key2_after_ldfw(self):
        # Retry the KEY2 programming stub immediately after the CM/LDFW
        # initializer returns. The initializer has four mutually exclusive
        # result diagnostics (no LDFW, signature error, partial/successful
        # initialization, and dump-GPR mode), and every path then converges on
        # the original secure-chip-state query. Replacing each diagnostic's
        # printf call means exactly one OTP attempt runs per boot while the
        # original control flow and state query remain intact.
        #
        # The external custom-key patcher has already replaced
        # check_signature with the KEY2 OTP stub. Locate that entry through
        # the untouched diagnostic xref instead of relying on an address.
        check_xref = find_single_xref(self.data, "There is no signature\n")
        key2_stub = function_start(self.data, check_xref)
        if u32(self.data, key2_stub) != 0xA9BF7BFD:
            raise KeyError(
                f"unexpected KEY2 stub prologue at {key2_stub:#x}: "
                f"{u32(self.data, key2_stub):#010x}"
            )

        result_messages = (
            "ldfw: No ldfw is inited\n",
            "ldfw: signature of ldfw is corrupted! ret = [0x%llX]\n",
            "ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) have been inited done.\n",
            "ldfw: It is dump_gpr state. It does not load ldfw.\n",
        )
        print_target = None
        sites = []
        for message in result_messages:
            xref = find_single_xref(self.data, message)
            calls = [off for off in range(xref + 4, xref + 0x14, 4)
                     if is_bl(self.data, off)]
            if not calls:
                raise KeyError(
                    f"no call found after {message!r}"
                )
            if print_target is None:
                site = calls[0]
                print_target = bl_target(self.data, site)
            else:
                matching = [off for off in calls
                            if bl_target(self.data, off) == print_target]
                if len(matching) != 1:
                    raise KeyError(
                        f"expected one printf after {message!r}, "
                        f"found {len(matching)}"
                    )
                site = matching[0]
            if bl_target(self.data, site) != print_target:
                raise KeyError(
                    f"unexpected LDFW result callee at {site:#x}"
                )
            sites.append(site)

        for site in sites:
            self._write(
                site,
                struct.pack("<I", encode_bl(site, key2_stub)),
                "KEY2 retry after LDFW",
            )

    def patch_check_signature(self):
        self.stub_function_at_string(
            "There is no signature\n", RETURN_ZERO, "check_signature->0", 0x200)

    def patch_warranty(self):
        self.stub_function_at_string(
            "[EFUSE] Set warranty bit(%d)\n", RETURN_ZERO, "set_warranty_bit->0", 0x200)

    def patch_rpmb(self):
        for tag in ("[KG] read_data fail...\n", "[RLC] read_data fail...\n"):
            try:
                self.stub_function_at_string(tag, RETURN_ZERO, f"rpmb {tag.split(']')[0][1:]}->0", 0x200)
            except KeyError as err:
                self.log.append(f"  (skip {tag!r}: {err})")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Patch Exynos9825 sboot for engineering mode")
    ap.add_argument("image")
    ap.add_argument("--out")
    ap.add_argument("--all", action="store_true",
                    help="also relax signature / warranty / RPMB checks")
    boot_path = ap.add_mutually_exclusive_group()
    boot_path.add_argument("--normal-boot", action="store_true",
                           help="force the Download-vs-normal-boot fork to normal boot")
    boot_path.add_argument("--force-download", action="store_true",
                           help="clear the stale pre-fork magic and force Download reason 4")
    ap.add_argument("--probe-otp-check", metavar="HEX32",
                    help="rehearse the buffer path with the read-only CHECK "
                         "command 0x114 and draw the prompt if the service "
                         "reports KEY2 blank")
    ap.add_argument("--probe-otp-read", action="store_true",
                    help="run the READ-ONLY OTP command 0x115 after the "
                         "CM/LDFW success and draw the prompt if it answers")
    ap.add_argument("--ignore-secpayload-sentinel", action="store_true",
                    help="make the CM/LDFW initializer read 0 instead of the "
                         "0xfa11 Secure-Payload-absent sentinel, so it takes "
                         "its real path")
    ap.add_argument("--prompt-after", metavar="STRING",
                    help="draw the blue prompt where this diagnostic string "
                         "is printed, turning 'was this reached?' into a "
                         "screen you can see")
    ap.add_argument("--ldfw-any-prompt", action="store_true",
                    help="like --ldfw-success-prompt but all four result "
                         "paths draw it, so blue means the initializer ran "
                         "at all rather than that it succeeded")
    ap.add_argument("--ldfw-success-prompt", action="store_true",
                    help="move the blue prompt: unreachable from the "
                         "secure-payload dead end, drawn by the CM/LDFW "
                         "success path instead")
    ap.add_argument("--skip-usb-recovery", action="store_true",
                    help="never draw the blue USB RECOVERY MODE prompt, which "
                         "is the tail of the failed secure-payload block and "
                         "re-arms the download magic on its way out")
    ap.add_argument("--probe-ldfw-result", action="store_true",
                    help="hang all four CM/LDFW result paths, so Download "
                         "means the initializer never ran on this path")
    ap.add_argument("--prove-secure-payload", action="store_true",
                    help="hang the Secure Payload failure path, so reaching "
                         "Download mode means it really loaded")
    ap.add_argument("--force-secure-payload", action="store_true",
                    help="neutralize the flag check that skips "
                         "load_secure_payload, so the CSMC/fuse broker exists")
    ap.add_argument("--clear-boot-magic", action="store_true",
                    help="zero the DRAM boot-mode words at u-boot's entry, so "
                         "all 24 readers of 0x80000000 agree instead of three")
    ap.add_argument("--key2-post-ldfw", action="store_true",
                    help="call the installed KEY2 OTP stub after the CM/LDFW "
                         "initializer returns")
    ap.add_argument("--diag-secure-payload", action="store_true",
                    help="skip the USB RECOVERY prompt and park the "
                         "secure-payload loader's return code in a PMU INFORM "
                         "register for the next payload to read")
    ap.add_argument("--no-eng", action="store_true",
                    help="skip the engineering-identity patches (have_this_mode, "
                         "etc_market/etc_development), leaving the unit reporting "
                         "as the commercial device it is")
    ap.add_argument("--dry-run", action="store_true",
                    help="locate and report patches without writing")
    args = ap.parse_args(argv)

    data = bytearray(open(args.image, "rb").read())
    p = Patcher(data, dry_run=args.dry_run)

    if not args.no_eng:
        p.patch_have_this_mode()
        p.patch_eng_efuse_bits()
    if args.normal_boot:
        p.patch_normal_boot()
        p.patch_ignore_magic_code()
        p.patch_ignore_ldfw_mode()
    elif args.force_download:
        p.patch_ignore_magic_code()
        p.patch_force_download()
    if args.force_secure_payload:
        p.patch_force_secure_payload()
    if args.prove_secure_payload:
        p.patch_prove_secure_payload()
    if args.ignore_secpayload_sentinel:
        p.patch_ignore_secpayload_sentinel()
    if args.probe_otp_check:
        p.otp_check_anchor = args.probe_otp_check
        p.patch_probe_otp_check()
    if args.probe_otp_read:
        p.patch_probe_otp_read()
    if args.prompt_after:
        p.prompt_after = args.prompt_after.encode().decode("unicode_escape")
        p.patch_prompt_after()
    if args.ldfw_success_prompt or args.ldfw_any_prompt:
        p.all_ldfw_paths = args.ldfw_any_prompt
        p.patch_ldfw_success_prompt()
    if args.skip_usb_recovery:
        p.patch_skip_usb_recovery()
    if args.probe_ldfw_result:
        p.patch_probe_ldfw_result()
    if args.clear_boot_magic:
        p.patch_clear_boot_magic()
    if args.key2_post_ldfw:
        p.patch_key2_after_ldfw()
    if args.diag_secure_payload:
        p.patch_skip_usb_recovery()
        p.patch_report_secure_payload()
    if args.all:
        p.patch_check_signature()
        p.patch_warranty()
        p.patch_rpmb()

    print(f"sboot_patch: {len(p.log)} site(s)")
    print("\n".join(p.log))

    if not args.dry_run:
        out = args.out or args.image
        with open(out, "wb") as f:
            f.write(data)
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
