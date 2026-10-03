#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import hashlib
import struct
import sys
import time
from pathlib import Path


EL3_MAGIC = b"NSP1EL3!"
NS_PASS_MAGIC = b"NS2PASS!"
NS_FAIL_MAGIC = b"NS2FAIL!"
NS_CHECKPOINTS = {
    b"NS2PRE!!": "before candidate DRAM access",
    b"NS2COPY!": "candidate stub copied and read back",
    b"NS2ERET!": "immediately before ERET",
}
RX_READY_MAGIC = b"RX1RDY!!"
RX_PASS_MAGIC = b"RX1PASS!"
RX_FAIL_MAGIC = b"RX1FAIL!"
RX_EVENT_MAGIC = b"RX1EVT!!"
RX_ARMED_MAGIC = b"RX1ARM!!"
RX_OUT_MAGIC = b"RX1OUT!!"
RX_CANCEL_MAGIC = b"RX1CANC!"
EPBL_READY_MAGIC = b"EPBRDY!!"
EPBL_PASS_MAGIC = b"EPBPASS!"
EPBL_FAIL_MAGIC = b"EPBFAIL!"
EPBL_HEADER_READY_MAGIC = b"EPHRDY!!"
EPBL_HEADER_PASS_MAGIC = b"EPHPASS!"
EPBL_HEADER_FAIL_MAGIC = b"EPHFAIL!"
EPBL_STATE_MAGICS = {
    b"EPS0IRAM": 0x02020000,
    b"EPS1IRAM": 0x02020050,
    b"EPS2IRAM": 0x020200A0,
    b"EPS3IRAM": 0x020200F0,
}
RX_PATTERN = bytes(range(0x40))
RECORD_SIZE = 0x60
EL3_FIELDS = (
    "CurrentEL",
    "SCR_EL3",
    "SCTLR_EL3",
    "TCR_EL3",
    "TTBR0_EL3",
    "MAIR_EL3",
    "HCR_EL2",
    "SCTLR_EL2",
    "ID_AA64PFR0_EL1",
    "VBAR_EL3",
)

NS_FIELDS = (
    "status",
    "ESR_EL3",
    "FAR_EL3",
    "ELR_EL3",
    "SPSR_EL3",
    "original SCR_EL3",
    "original VBAR_EL3",
    "CurrentEL",
    "lower x0",
    "lower x1",
)

RX_FIELDS = (
    "status",
    "BootROM return",
    "destination",
    "receive limit",
    "mismatch offset",
    "received bytes 0..7",
    "received bytes 8..15",
    "CurrentEL",
    "software event index",
    "trigger event word",
)

RX_EVENT_FIELDS = (
    "status",
    "software event index after repair",
    "reserved 0",
    "reserved 1",
    "reserved 2",
    "reserved 3",
    "reserved 4",
    "CurrentEL",
    "software event index at entry",
    "trigger event word",
)

RX_OUT_FIELDS = (
    "status",
    "CurrentEL",
    "software event index",
    "transfer workspace base",
    "EP2 maximum packet size",
    "receive completion flag",
    "EP2 direction selector",
    "BootROM TRB buffer low",
    "BootROM TRB size",
    "BootROM TRB control",
)

RX_CANCEL_FIELDS = (
    "status",
    "CurrentEL",
    "transfer workspace base",
    "TRB buffer before",
    "TRB size before",
    "TRB control before",
    "ENDTRANSFER return",
    "TRB buffer after",
    "TRB size after",
    "TRB control after",
)

EPBL_FIELDS = (
    "status",
    "BootROM return",
    "destination",
    "receive limit",
    "computed FNV-1a",
    "expected FNV-1a",
    "first qword",
    "second qword",
    "last qword",
    "CurrentEL",
)

EPBL_HEADER_FIELDS = (
    "status",
    "ENDTRANSFER return",
    "relocation address",
    "EPBL destination",
    "computed raw FNV-1a",
    "header parser return",
    "parsed BL1 size",
    "parsed BL1 checksum",
    "first qword after parse",
    "CurrentEL",
)


def decode_record(data: bytes):
    if len(data) != RECORD_SIZE:
        raise ValueError(
            f"record is 0x{len(data):x} bytes, expected 0x{RECORD_SIZE:x}"
        )

    magic, version, size = struct.unpack_from("<8sII", data)
    if version != 1:
        raise ValueError(f"unsupported record version {version}")
    if size != RECORD_SIZE:
        raise ValueError(f"record declares size 0x{size:x}")

    if magic in EPBL_STATE_MAGICS:
        address = EPBL_STATE_MAGICS[magic]
        print(f"magic                = {magic!r}")
        print(f"version              = {version}")
        for offset in range(0, RECORD_SIZE - 0x10, 4):
            value = struct.unpack_from("<I", data, 0x10 + offset)[0]
            print(f"0x{address + offset:08x}           = 0x{value:08x}")
        return True

    if magic == EL3_MAGIC:
        fields = EL3_FIELDS
    elif magic in (NS_PASS_MAGIC, NS_FAIL_MAGIC, *NS_CHECKPOINTS):
        fields = NS_FIELDS
    elif magic in (RX_READY_MAGIC, RX_ARMED_MAGIC, RX_PASS_MAGIC, RX_FAIL_MAGIC):
        fields = RX_FIELDS
    elif magic == RX_EVENT_MAGIC:
        fields = RX_EVENT_FIELDS
    elif magic == RX_OUT_MAGIC:
        fields = RX_OUT_FIELDS
    elif magic == RX_CANCEL_MAGIC:
        fields = RX_CANCEL_FIELDS
    elif magic in (EPBL_READY_MAGIC, EPBL_PASS_MAGIC, EPBL_FAIL_MAGIC):
        fields = EPBL_FIELDS
    elif magic in (
        EPBL_HEADER_READY_MAGIC,
        EPBL_HEADER_PASS_MAGIC,
        EPBL_HEADER_FAIL_MAGIC,
    ):
        fields = EPBL_HEADER_FIELDS
    else:
        raise ValueError(f"unexpected magic {magic!r}")

    print(f"magic                = {magic!r}")
    print(f"version              = {version}")
    values = []
    for index, name in enumerate(fields):
        value = struct.unpack_from("<Q", data, 0x10 + index * 8)[0]
        values.append(value)
        print(f"{name:20} = 0x{value:016x}")

    if magic == EL3_MAGIC:
        return True

    if magic in (
        RX_READY_MAGIC,
        RX_ARMED_MAGIC,
        EPBL_READY_MAGIC,
        EPBL_HEADER_READY_MAGIC,
    ):
        checkpoint = (
            "relocated worker armed EP2 OUT at the stock EPBL destination"
            if magic == EPBL_HEADER_READY_MAGIC
            else (
                "EP2 OUT armed; waiting for Binary 9 EPBL"
                if magic == EPBL_READY_MAGIC
                else (
                    "EP2 OUT armed; waiting for framed transfer"
                    if magic == RX_ARMED_MAGIC
                    else "waiting for framed EP2 OUT transfer"
                )
            )
        )
        print(f"checkpoint            = {checkpoint}")
        return None

    if magic == RX_EVENT_MAGIC:
        passed = values[0] == 1
        print(f"event repair result  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == RX_OUT_MAGIC:
        passed = values[0] == 1
        print(f"OUT state snapshot   = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic == RX_CANCEL_MAGIC:
        passed = (
            values[0] == 1
            and (values[5] & 1) == 1
            and values[6] == 1
            and values[7] == 0
            and values[8] == 0
            and values[9] == 0
        )
        print(f"OUT cancellation     = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (EPBL_PASS_MAGIC, EPBL_FAIL_MAGIC):
        passed = (
            magic == EPBL_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and values[2] == 0x02030000
            and values[3] == 0x3000
            and values[4] == values[5]
            and values[5] == 0xFDFB55E38228E523
            and values[6] == 0xB82C55E700000018
            and values[7] == 0
            and values[8] == 0x17B84398A0C70F76
            and values[9] == 0xC
        )
        print(f"EPBL receive result  = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (EPBL_HEADER_PASS_MAGIC, EPBL_HEADER_FAIL_MAGIC):
        passed = (
            magic == EPBL_HEADER_PASS_MAGIC
            and values[0] == 1
            and values[1] == 1
            and values[2] == 0x02025000
            and values[3] == 0x02022000
            and values[4] == 0xFDFB55E38228E523
            and values[5] == 1
            and values[6] == 0x3000
            and values[7] == 0xB82C55E7
            and values[8] == 0x18
            and values[9] == 0xC
        )
        print(f"EPBL header result   = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in (RX_PASS_MAGIC, RX_FAIL_MAGIC):
        passed = magic == RX_PASS_MAGIC and values[0] == 1 and values[1] == 1
        print(f"receive result       = {'PASS' if passed else 'FAIL'}")
        return passed

    if magic in NS_CHECKPOINTS:
        print(f"checkpoint            = {NS_CHECKPOINTS[magic]}")
        return None

    ec = (values[1] >> 26) & 0x3F
    print(f"ESR exception class  = 0x{ec:02x}")
    passed = magic == NS_PASS_MAGIC and values[0] == 4 and ec == 0x17
    print(f"transition result    = {'PASS' if passed else 'FAIL'}")
    return passed


def wait_for_device(usb_core):
    print("Waiting for EUB 04e8:1234...")
    while True:
        device = usb_core.find(idVendor=0x04E8, idProduct=0x1234)
        if device is not None:
            return device
        time.sleep(0.05)


def claim_device(device, usb_core, usb_util) -> None:
    try:
        device.get_active_configuration()
    except usb_core.USBError:
        device.set_configuration()

    try:
        if device.is_kernel_driver_active(0):
            device.detach_kernel_driver(0)
    except (NotImplementedError, usb_core.USBError):
        pass

    usb_util.claim_interface(device, 0)


def read_probe_record(device, usb_core) -> bytes:
    received = bytearray()
    deadline = time.monotonic() + 5.0

    while len(received) < RECORD_SIZE and time.monotonic() < deadline:
        try:
            chunk = bytes(
                device.read(
                    0x81,
                    RECORD_SIZE - len(received),
                    timeout=500,
                )
            )
        except usb_core.USBTimeoutError:
            continue

        if chunk:
            received.extend(chunk)

    return bytes(received)


def read_probe_records(device, usb_core) -> bytes:
    records = []

    while True:
        record = read_probe_record(device, usb_core)
        if not record:
            break
        if len(record) != RECORD_SIZE:
            raise RuntimeError(
                f"received partial record of 0x{len(record):x} bytes"
            )

        records.append(record)
        magic = record[:8]
        print(f"Received record {len(records)}: {magic!r}")
        if magic in (
            EL3_MAGIC,
            NS_PASS_MAGIC,
            NS_FAIL_MAGIC,
            RX_PASS_MAGIC,
            RX_FAIL_MAGIC,
            RX_EVENT_MAGIC,
            RX_OUT_MAGIC,
            RX_CANCEL_MAGIC,
            EPBL_PASS_MAGIC,
            EPBL_FAIL_MAGIC,
            EPBL_HEADER_PASS_MAGIC,
            EPBL_HEADER_FAIL_MAGIC,
            b"EPS3IRAM",
        ):
            break

    return b"".join(records)


def make_dnw_frame(payload: bytes) -> bytes:
    total = len(payload) + 10
    frame = bytearray(total)
    struct.pack_into("<4sI", frame, 0, b"\x1bDNW", total)
    frame[8:-2] = payload
    struct.pack_into("<H", frame, total - 2, sum(payload) & 0xFFFF)
    return bytes(frame)


def load_binary9_epbl(path: Path) -> bytes:
    transfer = path.read_bytes()
    if len(transfer) != 0x3000:
        raise RuntimeError(
            f"EPBL file is 0x{len(transfer):x} bytes, expected 0x3000"
        )

    digest = hashlib.sha256(transfer).hexdigest()
    expected = "d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d"
    if digest != expected:
        raise RuntimeError(
            f"EPBL SHA-256 is {digest}, expected Binary 9 {expected}"
        )
    return transfer


def run_receive_probe(device, usb_core, receive_payload=None) -> bytes:
    ready = read_probe_record(device, usb_core)
    if len(ready) != RECORD_SIZE:
        raise RuntimeError(
            f"received 0x{len(ready):x} ready bytes, expected 0x{RECORD_SIZE:x}"
        )
    if ready[:8] in (RX_FAIL_MAGIC, EPBL_FAIL_MAGIC, EPBL_HEADER_FAIL_MAGIC):
        print(f"Received record 1: {ready[:8]!r}")
        return ready
    if ready[:8] not in (
        RX_READY_MAGIC,
        RX_ARMED_MAGIC,
        EPBL_READY_MAGIC,
        EPBL_HEADER_READY_MAGIC,
    ):
        raise RuntimeError(f"unexpected receive-probe marker {ready[:8]!r}")

    print(f"Received record 1: {ready[:8]!r}")
    if ready[:8] in (EPBL_READY_MAGIC, EPBL_HEADER_READY_MAGIC):
        if receive_payload is None:
            raise RuntimeError("EPBL probe requires --receive-file")
        transfer = receive_payload
        label = f"Binary 9 EPBL (SHA-256 {hashlib.sha256(transfer).hexdigest()})"
        timeout = 10000
    else:
        if receive_payload is not None:
            raise RuntimeError("--receive-file requires the EPBL receive probe")
        transfer = RX_PATTERN
        label = "test pattern"
        timeout = 5000

    frame = make_dnw_frame(transfer)
    written = device.write(0x02, frame, timeout=timeout)
    if written != len(frame):
        raise RuntimeError(f"short EP2 OUT write: 0x{written:x}/0x{len(frame):x}")
    print(f"Sent framed {label}: 0x{written:x} bytes")

    result = read_probe_record(device, usb_core)
    if len(result) != RECORD_SIZE:
        print(
            f"Receive probe stopped after {ready[:8]!r}: got 0x{len(result):x} "
            f"result bytes, expected 0x{RECORD_SIZE:x}",
            file=sys.stderr,
        )
        return ready
    if result[:8] not in (
        RX_PASS_MAGIC,
        RX_FAIL_MAGIC,
        EPBL_PASS_MAGIC,
        EPBL_FAIL_MAGIC,
        EPBL_HEADER_PASS_MAGIC,
        EPBL_HEADER_FAIL_MAGIC,
    ):
        raise RuntimeError(f"unexpected receive result {result[:8]!r}")
    print(f"Received record 2: {result[:8]!r}")
    return ready + result


def run_direct_receive_probe(device, usb_core) -> bytes:
    frame = make_dnw_frame(RX_PATTERN)
    written = device.write(0x02, frame, timeout=5000)
    if written != len(frame):
        raise RuntimeError(f"short EP2 OUT write: 0x{written:x}/0x{len(frame):x}")
    print(
        "Sent framed test pattern without a preceding EP1 marker: "
        f"0x{written:x} bytes"
    )

    result = read_probe_record(device, usb_core)
    if len(result) != RECORD_SIZE:
        raise RuntimeError(
            f"received 0x{len(result):x} result bytes, expected 0x{RECORD_SIZE:x}"
        )
    if result[:8] not in (RX_PASS_MAGIC, RX_FAIL_MAGIC):
        raise RuntimeError(f"unexpected receive result {result[:8]!r}")
    print(f"Received record 1: {result[:8]!r}")
    return result


def run_live(args) -> bytes:
    houston_dir = args.houston_dir.resolve()
    if not (houston_dir / "modules" / "exploit.py").is_file():
        raise RuntimeError(f"Houston checkout not found at {houston_dir}")

    sys.path.insert(0, str(houston_dir))

    try:
        import usb.core
        import usb.util

        from modules.exploit import overwrite_iram, send_payload
        from modules.soc_data import SOC_DATA
    except ModuleNotFoundError as error:
        houston_python = houston_dir / ".venv" / "bin" / "python3"
        hint = "activate the environment containing Houston's requirements"
        if houston_python.is_file():
            hint = f"rerun with sudo {houston_python}"
        raise RuntimeError(f"missing Python module {error.name!r}; {hint}") from error

    payload = args.payload.resolve()
    if not payload.is_file():
        raise RuntimeError(f"payload not found: {payload}")

    receive_payload = None
    if args.receive_file is not None:
        receive_payload = load_binary9_epbl(args.receive_file.resolve())

    device = wait_for_device(usb.core)
    claim_device(device, usb.core, usb.util)

    try:
        product = usb.util.get_string(device, device.iProduct)
        if product not in SOC_DATA:
            raise RuntimeError(f"Houston has no parameters for {product!r}")

        parameters = SOC_DATA[product]
        if parameters["rx_address"] != 0x02022000:
            raise RuntimeError("unexpected Houston receive address")
        if parameters["usb_struct_offset"] != 0x0480:
            raise RuntimeError("unexpected Houston USB structure offset")

        print(f"Device product: {product!r}")

        try:
            startup = bytes(device.read(0x81, 511, timeout=500))
            if startup:
                print(f"Startup response: {startup!r}")
        except usb.core.USBTimeoutError:
            pass

        send_payload(device, str(payload))
        overwrite_iram(
            device,
            args.debug,
            parameters["rx_address"],
            parameters["usb_struct_offset"],
        )

        if args.receive_test_direct:
            data = run_direct_receive_probe(device, usb.core)
        elif args.receive_test:
            data = run_receive_probe(device, usb.core, receive_payload)
        else:
            data = read_probe_records(device, usb.core)
        if not data:
            raise RuntimeError("received no probe records")

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
        print(f"Saved raw record to {args.output}")
        return data
    finally:
        try:
            usb.util.release_interface(device, 0)
        except usb.core.USBError:
            pass
        usb.util.dispose_resources(device)


def parse_args():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run or decode the Exynos9825 boot probes"
    )
    parser.add_argument(
        "--decode",
        type=Path,
        metavar="FILE",
        help="decode one or more captured 0x60-byte probe records",
    )
    parser.add_argument(
        "--receive-test",
        action="store_true",
        help="send the framed test pattern requested by usb_receive_probe",
    )
    parser.add_argument(
        "--receive-file",
        type=Path,
        metavar="FILE",
        help="send the exact Binary 9 EPBL requested by epbl_receive_probe",
    )
    parser.add_argument(
        "--receive-test-direct",
        action="store_true",
        help="send the framed test pattern without waiting for an EP1 marker",
    )
    parser.add_argument(
        "--payload",
        type=Path,
        default=root / "build" / "boot_nonsecure_probe.bin",
        help="probe payload (default: build/boot_nonsecure_probe.bin)",
    )
    parser.add_argument(
        "--houston-dir",
        type=Path,
        default=root.parent / "houston-pub",
        help="Houston checkout containing modules/",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/exynos9825_boot_nonsecure_probe.bin"),
        help="raw output record",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show Houston iRAM hexdumps",
    )
    args = parser.parse_args()
    if args.receive_test and args.receive_test_direct:
        parser.error("--receive-test and --receive-test-direct are mutually exclusive")
    if args.receive_file and not args.receive_test:
        parser.error("--receive-file requires --receive-test")
    return args


def main() -> int:
    args = parse_args()
    try:
        data = args.decode.read_bytes() if args.decode else run_live(args)
        if len(data) % RECORD_SIZE:
            raise ValueError(
                f"capture is 0x{len(data):x} bytes, not a record multiple"
            )

        results = []
        for offset in range(0, len(data), RECORD_SIZE):
            if results:
                print()
            print(f"=== Record {offset // RECORD_SIZE + 1} ===")
            results.append(decode_record(data[offset:offset + RECORD_SIZE]))

        passed = bool(results and results[-1] is True)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
