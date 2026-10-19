#!/usr/bin/env python3
"""Validate an unhooked native UFS EPBL/FWBL1 handoff payload."""

import argparse
import re
import subprocess
from pathlib import Path


PAYLOAD_BASE = 0x02022000
RELOCATED_BASE = 0x02025000


def run(*argv: str) -> str:
    return subprocess.run(
        argv,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout


def symbols(elf: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in run("aarch64-linux-gnu-nm", "-an", str(elf)).splitlines():
        fields = line.split()
        if len(fields) >= 3:
            try:
                result[fields[2]] = int(fields[0], 16)
            except ValueError:
                pass
    return result



LDR_LITERAL = re.compile(
    r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+ldr\s+(x\d+), ([0-9a-f]+)\b"
)
STORE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+st[rp]\b.*\[(x\d+)")
RELOAD = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f]{8}\s+\S+\s+(x\d+),")


def epbl_region_stores(disasm: str) -> list[str]:
    """Sites that store through a register holding a loaded-EPBL address."""
    lines = disasm.splitlines()
    literals: dict[int, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) >= 3 and fields[2] == ".word" and fields[0].endswith(":"):
            literals[int(fields[0][:-1], 16)] = int(fields[3], 16)
    found = []
    for index, line in enumerate(lines):
        match = LDR_LITERAL.match(line)
        if not match:
            continue
        site, register, pool = match.groups()
        value = literals.get(int(pool, 16))
        # 0x02022000 itself is the load destination the payload legitimately
        # zeroes before calling 0xcc68; any address past it is EPBL content.
        if value is None or not 0x02022000 < value < 0x02025000:
            continue
        # Follow the register until it is written again.
        for follow in lines[index + 1:]:
            store = STORE.match(follow)
            if store and store.group(2) == register:
                found.append(f"{store.group(1)} (address from {site})")
                break
            reload_ = RELOAD.match(follow)
            if reload_ and reload_.group(1) == register:
                break
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("epbl", type=Path)
    parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="expect the pre-handoff record and EPBL-return sentinel",
    )
    parser.add_argument(
        "--post-load-records",
        action="store_true",
        help="expect UFSLOAD!/UFSMETA! immediately after the storage load",
    )
    parser.add_argument(
        "--postload-result-record",
        action="store_true",
        help="expect EUNPOST! immediately after BootROM 0x5b58 returns",
    )
    parser.add_argument(
        "--timing-result-record",
        action="store_true",
        help="expect EUNTIME! immediately after BootROM 0x18768 returns",
    )
    parser.add_argument(
        "--flag-result-record",
        action="store_true",
        help="expect EUNFLAG! immediately after BootROM 0x16a10 returns",
    )
    parser.add_argument(
        "--cold-result-record",
        action="store_true",
        help="expect EUNCOLD! after installing the native cold-path override",
    )
    parser.add_argument(
        "--force-cold-record",
        action="store_true",
        help="expect EUNFORC! without reading the warm-state MMIO",
    )
    parser.add_argument(
        "--triple-records",
        action="store_true",
        help="expect EUN3REC1/2/3: the same read-only record at three positions",
    )
    parser.add_argument(
        "--no-custom-key",
        action="store_true",
        help="payload leaves PTR_SECUREBOOT_KEY alone (stock sboot on UFS)",
    )
    args = parser.parse_args()
    modes = (
        args.diagnostic,
        args.post_load_records,
        args.postload_result_record,
        args.timing_result_record,
        args.flag_result_record,
        args.cold_result_record,
        args.force_cold_record,
        args.triple_records,
    )
    if sum(modes) > 1:
        parser.error("native diagnostic record modes are mutually exclusive")

    blob = args.binary.read_bytes()
    epbl = args.epbl.read_bytes()
    syms = symbols(args.elf)
    disasm = run("aarch64-linux-gnu-objdump", "-d", str(args.elf))

    required = {
        "_start": PAYLOAD_BASE,
        "relocated_start": PAYLOAD_BASE + 0xC0,
        "boot_ufs_chain_path": syms.get("boot_ufs_chain_path", -1),
        "relocated_end": syms.get("relocated_end", -1),
    }
    if args.no_custom_key:
        if "custom_boot_key" in syms:
            raise SystemExit(
                "error: --no-custom-key payload still embeds a custom boot key"
            )
    else:
        required["custom_boot_key"] = syms.get("custom_boot_key", -1)
    for name, expected in required.items():
        actual = syms.get(name)
        if actual is None:
            raise SystemExit(f"error: native payload is missing symbol {name}")
        if name in ("_start", "relocated_start") and actual != expected:
            raise SystemExit(
                f"error: {name} is {actual:#x}, expected {expected:#x}"
            )

    forbidden = (
        "el3_exception",
        "el3_vectors",
        "epbl_dispatch_redirect_slot",
        "fwbl1_noic_entry",
        "fwbl1_after_decrypt",
        "fwbl1_before_eret",
        "install_fwbl1_transition_hook",
        "saved_vbar_el3",
    )
    present = [name for name in forbidden if name in syms]
    if present:
        raise SystemExit(
            "error: native payload still contains diagnostic hook symbol(s): "
            + ", ".join(present)
        )

    return_symbol = "native_epbl_returned"
    if args.diagnostic and return_symbol not in syms:
        raise SystemExit("error: native diagnostic is missing its EPBL-return sentinel")
    if not args.diagnostic and return_symbol in syms:
        raise SystemExit("error: silent native payload contains the diagnostic sentinel")

    if len(epbl) != 0x3000:
        raise SystemExit(f"error: EPBL is {len(epbl):#x} bytes, expected 0x3000")
    if blob[0x40:0xC0] != epbl[0x40:0xC0]:
        raise SystemExit("error: cache-line mirror does not match the UFS EPBL")

    relocated_size = syms["relocated_end"] - syms["relocated_start"]
    if relocated_size <= 0 or relocated_size % 8:
        raise SystemExit(
            f"error: relocated worker size {relocated_size:#x} is not qword aligned"
        )
    if RELOCATED_BASE + relocated_size > 0x02026000:
        raise SystemExit("error: relocated worker overlaps the FWBL1 destination")

    key_selector = (0x00005780).to_bytes(8, "little")
    if blob.count(key_selector) != 1:
        raise SystemExit(
            "error: native payload does not call the BootROM key selector at 0x5780"
        )
    epbl_branch = (0x0001C9A0).to_bytes(8, "little")
    if blob.count(epbl_branch) != 1:
        raise SystemExit(
            "error: native payload does not use the BootROM EPBL helper at 0x1c9a0"
        )

    required_text = ["msr\tsctlr_el3", "br\tx16"]
    if args.diagnostic:
        required_text.extend(("adr\tx30", "<native_epbl_returned>"))
    else:
        required_text.append("mov\tx30, #0x250")
    missing = [text for text in required_text if text not in disasm]
    if missing:
        raise SystemExit(
            "error: native handoff sequence is incomplete: " + ", ".join(missing)
        )
    if "msr\tvbar_el3" in disasm:
        raise SystemExit("error: native payload still installs a diagnostic VBAR")
    if "2022df8" in disasm.lower():
        raise SystemExit("error: native payload still calls the reconstructed cold target")

    diagnostic_magics = (b"EUNPRE!!", b"EUNRET!!")
    if args.diagnostic:
        for magic in diagnostic_magics:
            if blob.count(magic) != 1:
                raise SystemExit(
                    f"error: native diagnostic carries {blob.count(magic)} copies of {magic!r}"
                )
    elif any(magic in blob for magic in diagnostic_magics):
        raise SystemExit("error: silent native payload contains diagnostic record magic")

    post_load_magics = (b"UFSLOAD!", b"UFSMETA!")
    if args.post_load_records:
        for magic in post_load_magics:
            if blob.count(magic) != 1:
                raise SystemExit(
                    f"error: post-load diagnostic carries {blob.count(magic)} copies of {magic!r}"
                )
    elif any(magic in blob for magic in post_load_magics):
        raise SystemExit("error: silent native payload contains post-load record magic")

    postload_result_magic = b"EUNPOST!"
    if args.postload_result_record:
        if blob.count(postload_result_magic) != 1:
            raise SystemExit(
                "error: native postload diagnostic must carry exactly one "
                f"{postload_result_magic!r}"
            )
    elif postload_result_magic in blob:
        raise SystemExit("error: native payload contains an unexpected postload record")

    timing_result_magic = b"EUNTIME!"
    if args.timing_result_record:
        if blob.count(timing_result_magic) != 1:
            raise SystemExit(
                "error: native timing diagnostic must carry exactly one "
                f"{timing_result_magic!r}"
            )
    elif timing_result_magic in blob:
        raise SystemExit("error: native payload contains an unexpected timing record")

    flag_result_magic = b"EUNFLAG!"
    if args.flag_result_record:
        if blob.count(flag_result_magic) != 1:
            raise SystemExit(
                "error: native boot-flag diagnostic must carry exactly one "
                f"{flag_result_magic!r}"
            )
    elif flag_result_magic in blob:
        raise SystemExit("error: native payload contains an unexpected boot-flag record")

    cold_result_magic = b"EUNCOLD!"
    if args.cold_result_record:
        if blob.count(cold_result_magic) != 1:
            raise SystemExit(
                "error: native cold-path diagnostic must carry exactly one "
                f"{cold_result_magic!r}"
            )
    elif cold_result_magic in blob:
        raise SystemExit("error: native payload contains an unexpected cold-path record")

    triple_magics = (b"EUN3REC0", b"EUN3REC1", b"EUN3REC2", b"EUN3REC3")
    if args.triple_records:
        for magic in triple_magics:
            if blob.count(magic) != 1:
                raise SystemExit(
                    f"error: triple-record payload carries {blob.count(magic)} "
                    f"copies of {magic!r}"
                )
        # The whole point of this build is that the three positions differ in
        # nothing but position, so it must not patch the loaded EPBL at all.
        # Every address it forms inside the loaded EPBL has to be read-only:
        # find each `ldr xN, <literal>` whose literal lands in the EPBL and
        # require that nothing stores through xN before it is reloaded.
        stores = epbl_region_stores(disasm)
        if stores:
            raise SystemExit(
                "error: triple-record payload writes into the loaded EPBL at "
                + ", ".join(stores)
            )
        for name in ("EUNPRE!!", "EUNCOLD!", "EUNFORC!", "EUNTIME!", "EUNFLAG!"):
            if name.encode() in blob:
                raise SystemExit(
                    f"error: triple-record payload also carries {name}"
                )
    elif any(magic in blob for magic in triple_magics):
        raise SystemExit("error: native payload contains an unexpected triple record")

    force_cold_magic = b"EUNFORC!"
    if args.force_cold_record:
        if blob.count(force_cold_magic) != 1:
            raise SystemExit(
                "error: native force-cold payload must carry exactly one "
                f"{force_cold_magic!r}"
            )
        original_gate_load = (0x580002D4).to_bytes(4, "little")
        direct_cold_branch = (0x14000006).to_bytes(4, "little")
        if epbl[0x18:0x1C] != original_gate_load:
            raise SystemExit(
                "error: UFS EPBL gate-load instruction is not 0x580002d4"
            )
        if blob.count(original_gate_load) != 1:
            raise SystemExit(
                "error: force-cold payload must carry one authenticated "
                "gate-load instruction"
            )
        if blob.count(direct_cold_branch) != 1:
            raise SystemExit(
                "error: force-cold payload must carry one direct branch "
                "to 0x02022030"
            )
    elif force_cold_magic in blob:
        raise SystemExit("error: native payload contains an unexpected force-cold record")

    print("native UFS handoff payload = PASS")
    print("cold stager only          = YES")
    print("EPBL mirror matches UFS   = YES")
    print("EPBL dispatch redirect    = ABSENT")
    print("diagnostic EL3 VBAR       = ABSENT")
    print("FWBL1 entry shim          = ABSENT")
    print("saved-context modification = ABSENT")
    print("BootROM key selector       = 0x00005780")
    print("BootROM EPBL helper        = 0x0001c9a0")
    if args.diagnostic:
        print("pre-handoff snapshot      = PRESENT")
        print("EPBL-return sentinel      = PRESENT")
        print("BootROM return link       = relocated diagnostic sentinel")
    else:
        print("pre-handoff snapshot      = ABSENT")
        print("EPBL-return sentinel      = ABSENT")
        print("BootROM return link       = 0x00000250")
    print(
        "post-load records         = "
        + ("UFSLOAD! + UFSMETA!" if args.post_load_records else "ABSENT")
    )
    print(
        "postload result record    = "
        + ("EUNPOST!" if args.postload_result_record else "ABSENT")
    )
    print(
        "entry-timing record       = "
        + ("EUNTIME!" if args.timing_result_record else "ABSENT")
    )
    print(
        "boot-flag record          = "
        + ("EUNFLAG!" if args.flag_result_record else "ABSENT")
    )
    print(
        "cold-path record          = "
        + ("EUNCOLD!" if args.cold_result_record else "ABSENT")
    )
    print(
        "force-cold record         = "
        + ("EUNFORC!" if args.force_cold_record else "ABSENT")
    )
    print(
        "triple records            = "
        + ("EUN3REC0 (baseline) + EUN3REC1 + EUN3REC2 + EUN3REC3"
           if args.triple_records else "ABSENT")
    )
    print(
        "PTR_SECUREBOOT_KEY        = "
        + ("untouched (stock key)" if args.no_custom_key else "redirected to custom key")
    )
    print(f"relocated worker          = {relocated_size:#x} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
