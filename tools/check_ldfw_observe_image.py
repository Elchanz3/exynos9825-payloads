#!/usr/bin/env python3
"""Refuse an LDFW-observation chain that could program the fuse.

This chain exists to answer one question with no irreversible step: does the
Secure Payload load and does the CM/LDFW initializer report success? So the
checks here are mostly negative — it must carry no path that reaches OTP
command 0x16.
"""
import struct
import sys
from pathlib import Path

ENTRY = 0x000000
MAGIC_GATE = 0x0033F0       # ldr w19,[0x80000000] -> mov w19,#0
SKIP_GATE = 0x003438        # bl <flag reader>     -> mov w0,#0
DOWNLOAD_FORK = 0x0038F0    # bl s5p_check_download -> mov w0,#0
CHECK_SIGNATURE = 0x04FC68
CAVE = 0x17CE00
LDFW_RESULT_SITES = (0x0A63E4, 0x0A6460, 0x0A64A4, 0x0A64D0)
USB_RECOVERY = 0x008B4C


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def bl_target(d, o):
    imm = u32(d, o) & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return o + imm * 4


IRREVERSIBLE = (
    "[OTP] ROM_SECURE_BOOT_KEY2 program start\n",
    "[OTP] USE_ROM_SEC_BOOT_KEY2 program start\n",
    "[OTP] BAN_ROM_SEC_BOOT_KEY2 program start\n",
)


def irreversible_callers(d):
    """Direct callers of the three one-shot OTP commands.

    Stock u-boot has none: they are reached through a console command table,
    never by a `bl`. So any direct caller in one of our images is something
    we put there, and counting them is a complete check that an experiment
    cannot burn a fuse. It runs on every build, not only the fuse one.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_sp", str(Path(__file__).with_name("sboot_patch.py")))
    sp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sp)
    found = {}
    for message in IRREVERSIBLE:
        fn = sp.function_start_or_prologue(d, sp.find_single_xref(d, message))
        callers = [o for o in range(0, len(d) - 3, 4)
                   if u32(d, o) & 0xFC000000 == 0x94000000
                   and bl_target(d, o) == fn]
        found[message.split()[1]] = (fn, callers)
    return found


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    download = "--download" in sys.argv
    ldfw_hang = "--ldfw-hang" in sys.argv
    normalboot = "--normalboot" in sys.argv
    ldfwsignal = "--ldfwsignal" in sys.argv or "--ldfwany" in sys.argv
    ldfwany = "--ldfwany" in sys.argv
    otpread = "--otpread" in sys.argv
    otpcheck = "--otpcheck" in sys.argv
    path = Path(argv[0] if argv
                else "build/ldfw_observe_chain/sboot/u-boot.bin")
    d = path.read_bytes()
    ok = True

    allow_program = "--allow-program-key2" in sys.argv

    def check(label, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"{label:<44} {'PASS' if cond else '*** FAIL ***'}  {detail}")

    # Runs for every mode: stock has zero direct callers of the one-shot
    # commands, so anything above that is ours and has to be deliberate.
    for name, (fn, callers) in irreversible_callers(d).items():
        want = 1 if (allow_program and name == "ROM_SECURE_BOOT_KEY2") else 0
        check(f"direct callers of {name} == {want}",
              len(callers) == want,
              f"{fn:#x}: " + (" ".join(f"{c:#x}" for c in callers) or "none"))

    # --- the four things that must be patched ---
    if otpcheck:
        CAVE = 0x17CE00
        import importlib.util as _ilu
        _s = _ilu.spec_from_file_location(
            "_sp", str(Path(__file__).with_name("sboot_patch.py")))
        _sp = _ilu.module_from_spec(_s); _s.loader.exec_module(_sp)

        def _func(msg):
            return _sp.function_start_or_prologue(d, _sp.find_single_xref(d, msg))

        check_fn = _func("[OTP] ROM_SECURE_BOOT_KEY2 check start\n")
        prog_fn = _func("[OTP] ROM_SECURE_BOOT_KEY2 program start\n")
        target = bl_target(d, CAVE + 0xC)
        check("secure-payload sentinel bypassed",
              u32(d, 0x0A6254) == 0x52800001)
        check("trampoline shape",
              [u32(d, CAVE + 4 * i) for i in (0, 1, 2, 4, 5)] ==
              [0xA9BF7BFD, 0x100000A0, 0x52800401, 0xA8C17BFD, 0xD65F03C0])
        check("length argument is 0x20", u32(d, CAVE + 8) == 0x52800401)
        check("trampoline calls the CHECK function (0x114)",
              target == check_fn, f"{target:#x} vs check fn {check_fn:#x}")
        check("trampoline is NOT the program function (0x16)",
              target != prog_fn, f"program fn {prog_fn:#x}")
        check("LDFW success calls the trampoline",
              bl_target(d, 0x0A64A4) == CAVE)
        check("'not programmed' draws the prompt",
              bl_target(d, 0x0A2BD0) == USB_RECOVERY,
              f"{bl_target(d, 0x0A2BD0):#x}")
        check("check_signature is the inert stub",
              d[CHECK_SIGNATURE:CHECK_SIGNATURE + 8]
              == bytes.fromhex("000080d2c0035fd6"))
        print()
        print("RESULT:", "PASS - the only OTP command reachable is the check 0x114"
              if ok else "FAIL")
        return 0 if ok else 1
    if otpread:
        CAVE = 0x17CE00
        # The one thing that must be true: the only OTP command this image
        # can reach is the read, 0x115. Locate the read function by its own
        # message and require the trampoline to call exactly it.
        import importlib.util as _ilu
        _s = _ilu.spec_from_file_location(
            "_sp", str(Path(__file__).with_name("sboot_patch.py")))
        _sp = _ilu.module_from_spec(_s)
        _s.loader.exec_module(_sp)

        def _func(message):
            return _sp.function_start_or_prologue(
                d, _sp.find_single_xref(d, message))

        read_fn = _func("[OTP] USE_ROM_SEC_BOOT_KEY2 read: start\n")
        prog_fn = _func("[OTP] ROM_SECURE_BOOT_KEY2 program start\n")
        check("entry left alone", u32(d, ENTRY) == 0x14000001)
        check("download fork forced to normal boot",
              u32(d, DOWNLOAD_FORK) == 0x52800000)
        check("secure-payload sentinel bypassed",
              u32(d, 0x0A6254) == 0x52800001, f"{u32(d, 0x0A6254):#010x}")
        check("trampoline shape",
              [u32(d, CAVE + 4 * i) for i in (0, 1, 3, 4)] ==
              [0xA9BF7BFD, 0x100000A0, 0xA8C17BFD, 0xD65F03C0])
        target = bl_target(d, CAVE + 8)
        check("trampoline calls the READ function (0x115)",
              target == read_fn, f"{target:#x} vs read fn {read_fn:#x}")
        check("trampoline is NOT the program function (0x16)",
              target != prog_fn, f"program fn {prog_fn:#x}")
        check("LDFW success calls the trampoline",
              bl_target(d, 0x0A64A4) == CAVE, f"{bl_target(d, 0x0A64A4):#x}")
        check("the read's success print draws the prompt",
              bl_target(d, 0x0A2CFC) == USB_RECOVERY,
              f"{bl_target(d, 0x0A2CFC):#x}")
        check("check_signature is the inert stub",
              d[CHECK_SIGNATURE:CHECK_SIGNATURE + 8]
              == bytes.fromhex("000080d2c0035fd6"))
        print()
        print("RESULT:", "PASS - the only OTP command reachable is the read 0x115"
              if ok else "FAIL")
        return 0 if ok else 1
    if ldfwsignal:
        check("entry left alone (no clear-boot-magic)",
              u32(d, ENTRY) == 0x14000001, f"{u32(d, ENTRY):#010x}")
        check("download fork forced to normal boot",
              u32(d, DOWNLOAD_FORK) == 0x52800000,
              f"{u32(d, DOWNLOAD_FORK):#010x}")
        check("USB RECOVERY prompt left intact",
              d[USB_RECOVERY:USB_RECOVERY + 4] != bytes.fromhex("000080d2"),
              d[USB_RECOVERY:USB_RECOVERY + 4].hex())
        check("its dead-end tail branch is now ret",
              u32(d, 0x0034D4) == 0xD65F03C0, f"{u32(d, 0x0034D4):#010x}")
        others = {bl_target(d, s) for s in (0x0A63E4, 0x0A6460, 0x0A64D0)}
        check("LDFW success path draws the prompt",
              bl_target(d, 0x0A64A4) == USB_RECOVERY,
              f"{bl_target(d, 0x0A64A4):#x}")
        if ldfwany:
            check("all four LDFW paths draw the prompt",
                  others == {USB_RECOVERY},
                  " ".join(f"{t:#x}" for t in sorted(others)))
        else:
            check("the other three LDFW paths untouched", len(others) == 1)
        check("LDFW mode reads neutralized",
              u32(d, 0x0A61A4) == 0x52800014 and u32(d, 0x0A61B0) == 0x52800013)
        check("secure-payload skip check neutralized",
              u32(d, SKIP_GATE) == 0x52800000)
        stub = d[CHECK_SIGNATURE:CHECK_SIGNATURE + 8]
        check("check_signature is the inert stub",
              stub == bytes.fromhex("000080d2c0035fd6"), stub.hex())
        print()
        print("RESULT:", "PASS - no path reaches an OTP command" if ok else "FAIL")
        return 0 if ok else 1
    if normalboot:
        check("entry left alone (no clear-boot-magic)",
              u32(d, ENTRY) == 0x14000001, f"{u32(d, ENTRY):#010x}")
        check("download fork forced to normal boot",
              u32(d, DOWNLOAD_FORK) == 0x52800000,
              f"{u32(d, DOWNLOAD_FORK):#010x}")
        check("USB RECOVERY prompt stubbed",
              d[USB_RECOVERY:USB_RECOVERY + 8]
              == bytes.fromhex("000080d2c0035fd6"),
              d[USB_RECOVERY:USB_RECOVERY + 8].hex())
        check("LDFW mode reads neutralized",
              u32(d, 0x0A61A4) == 0x52800014 and u32(d, 0x0A61B0) == 0x52800013,
              f"{u32(d, 0x0A61A4):#010x} {u32(d, 0x0A61B0):#010x}")
    elif download:
        check("entry left alone (no clear-boot-magic)",
              u32(d, ENTRY) == 0x14000001, f"{u32(d, ENTRY):#010x}")
        check("download fork forced to reason 4",
              u32(d, DOWNLOAD_FORK) == 0x52800080,
              f"{u32(d, DOWNLOAD_FORK):#010x}")
    else:
        check("entry redirected to the cave",
              u32(d, ENTRY) == 0x14000000 | (CAVE // 4), f"{u32(d, ENTRY):#010x}")
        check("cave zeroes 0x80000000 and +0x10",
              [u32(d, CAVE + 4 * i) for i in range(4)] ==
              [0xD2B00010, 0xB900021F, 0xB900121F, 0xD5033F9F])
        check("download fork forced to normal boot",
              u32(d, DOWNLOAD_FORK) == 0x52800000,
              f"{u32(d, DOWNLOAD_FORK):#010x}")
    check("secure-payload skip check neutralized",
          u32(d, SKIP_GATE) == 0x52800000, f"{u32(d, SKIP_GATE):#010x}")
    check("MAGIC_CODE read neutralized",
          u32(d, MAGIC_GATE) == 0x52800013, f"{u32(d, MAGIC_GATE):#010x}")

    # --- the things that must NOT be there ---
    stub = d[CHECK_SIGNATURE:CHECK_SIGNATURE + 8]
    check("check_signature is the inert stub",
          stub == bytes.fromhex("0000 80D2 C003 5FD6".replace(" ", "")),
          stub.hex())
    if ldfw_hang:
        # Each site is `b .`, a self-branch, which is the whole point of the
        # probe: reaching any of the four stops the chain.
        check("all four LDFW results hang",
              all(u32(d, site) == 0x14000000 for site in LDFW_RESULT_SITES),
              " ".join(f"{u32(d, s):#010x}" for s in LDFW_RESULT_SITES))
    else:
        targets = {bl_target(d, s) for s in LDFW_RESULT_SITES}
        check("LDFW result paths not redirected",
              CHECK_SIGNATURE not in targets,
              " ".join(f"{t:#x}" for t in sorted(targets)))
        check("all four LDFW results share one callee", len(targets) == 1)

    print()
    print("RESULT:", "PASS - no path reaches an OTP command" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
