#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import struct
import sys
import time
from pathlib import Path


EL3_MAGIC = b"NSP1EL3!"
NS_PASS_MAGIC = b"NS2PASS!"
NS_FAIL_MAGIC = b"NS2FAIL!"
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


def decode_record(data: bytes) -> bool:
    if len(data) != RECORD_SIZE:
        raise ValueError(
            f"record is 0x{len(data):x} bytes, expected 0x{RECORD_SIZE:x}"
        )

    magic, version, size = struct.unpack_from("<8sII", data)
    if version != 1:
        raise ValueError(f"unsupported record version {version}")
    if size != RECORD_SIZE:
        raise ValueError(f"record declares size 0x{size:x}")

    if magic == EL3_MAGIC:
        fields = EL3_FIELDS
    elif magic in (NS_PASS_MAGIC, NS_FAIL_MAGIC):
        fields = NS_FIELDS
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

        data = read_probe_record(device, usb.core)
        if len(data) != RECORD_SIZE:
            raise RuntimeError(
                f"received 0x{len(data):x} bytes, expected 0x{RECORD_SIZE:x}"
            )

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
        help="decode an existing 0x60-byte probe record",
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        data = args.decode.read_bytes() if args.decode else run_live(args)
        passed = decode_record(data)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
