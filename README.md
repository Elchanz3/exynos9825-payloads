# exynos9825-payloads

Small AArch64 payloads for Samsung Exynos 9825 (S5E9825) BootROM research.
The tested device is a Samsung Galaxy Note10+ SM-N975F.

This repository is an incremental S5E9825 port of the payload infrastructure
used by [halal-beef/exynos990-payloads](https://github.com/halal-beef/exynos990-payloads).
The SoC separation also follows the approach used by the
[Exynos9810 open-mini-bl1 change](https://github.com/Robotix22/open-mini-bl1/commit/954fe3e2aea5865db92b0a8be5d610040ac31aa4).

## Safety and scope

The current payloads operate only on volatile iRAM and the already configured
USB controller state. They do not write eFuses, OTP, UFS, or persistent flash.
PMU, GPIO, CryptoCell, secure-boot state changes, stage execution, and later
boot-stage loading are not implemented because their S5E9825 addresses and
behavior have not been validated.

## Confirmed target data

| Item | Value |
| --- | --- |
| EUB USB product | `Exynos9820` |
| USB VID:PID | `04e8:1234` |
| USB Booting version | `v0.5` |
| Execution level | Secure EL3 (`CurrentEL = 0xC`) |
| Houston receive address | `0x02022000` |
| Houston USB structure offset | `0x0480` |
| Houston quirks | `0` |
| BootROM size | `0x20000` |
| BootROM SHA-256 | `895eaa3b833a6fc1168461be3d7df38416107872d530fdece90c7f689d671225` |

The USB product string identifies this device as `Exynos9820`; Houston must
therefore use that string as the lookup key while applying the S5E9825 values
shown above.

## Payloads

| Payload | Purpose | Status |
| --- | --- | --- |
| `dump_bootrom` | Sends BootROM as two sequential `0x10000` EP1 IN transfers | Hardware tested on SM-N975F. The new build is byte-identical to the validated binary. |
| `houston_marker` | Sends `HOUSTON!` over EP1 IN after callback hijack | Hardware tested on SM-N975F through Houston. `HOUSTON!` was received on the existing EP1 IN session. |
| `boot_nonsecure_probe` | Reports EL3 and EL2 architectural state without leaving Secure EL3 | Hardware tested on SM-N975F through Houston. |
| `nonsecure_transition_probe` | Diagnoses access to the Binary 9 sboot address before a minimal EL3 to Non-secure EL2h transition | Hardware tested on SM-N975F. Execution stops at the first access to `0xbfe80000`, before `ERET`. |
| `usb_receive_probe` | Tests a bounded BootROM receive after an EP1 ready marker | Hardware tested on SM-N975F. `RX1RDY!!` was received and the host write completed, but the BootROM receive did not return. |
| `usb_receive_direct_probe` | Repeats the bounded receive without a preceding EP1 transfer | Hardware tested on SM-N975F. The host write completed, but no terminal record returned. |
| `usb_receive_event_probe` | Retires Houston's triggering event before the bounded receive | Hardware tested on SM-N975F. The host write completed, but no terminal record returned. |
| `usb_event_repair_probe` | Reports immediately after retiring Houston's triggering event | Hardware tested on SM-N975F. Event repair and subsequent EP1 IN transfer passed. |
| `usb_receive_armed_probe` | Arms EP2 OUT before requesting the bounded host transfer | Hardware tested on SM-N975F. Execution stopped inside the arming path before `RX1ARM!!`. |
| `usb_out_state_probe` | Captures the BootROM EP2 and TRB state after event repair | Hardware tested on SM-N975F. The existing EP2 TRB remains hardware-owned. |
| `usb_out_cancel_probe` | Cancels the stale EP2 transfer through the BootROM path and reports the TRB before and after | Hardware tested on SM-N975F. `ENDTRANSFER` succeeded and the TRB was cleared. |
| `usb_receive_rearmed_probe` | Cancels the stale transfer, rearms EP2 OUT, and receives a bounded test frame | Hardware tested on SM-N975F. The framed transfer returned `RX1PASS!` and all 64 bytes matched. |
| `epbl_receive_probe` | Receives and verifies the current Binary 9 EPBL in a bounded iRAM diagnostic area without executing it | Hardware tested on SM-N975F. The complete `0x3000`-byte EPBL returned `EPBPASS!`. |
| `epbl_state_probe` | Captures the complete iRAM state window consumed by the Binary 9 EPBL without calling its pointers | Hardware tested on SM-N975F. All four state records were received. |
| `epbl_header_probe` | Relocates itself, receives Binary 9 EPBL at the stock BootROM destination, and invokes only the matched header parser | Built and statically verified. Hardware validation is pending. |

The non-secure port plan, reference address inventory, and current Binary 9
reverse-engineering results are documented in
[`docs/boot_nonsecure_port.md`](docs/boot_nonsecure_port.md).

### Houston marker validation

The current `build/houston_marker.bin` was validated on hardware on 2026-10-03:

- size: `0x98` (152 bytes)
- SHA-256: `b8451fc128cbe9f2fe0d2d42eaf0e2aa0039f10c8d90c3e8f412ae1c305b9b33`
- Houston detected `Exynos9820`, leaked iRAM, changed the callback from
  `0x00001b2c` to `0x02022000`, and triggered the payload
- the host received `HOUSTON!` through EP1 IN

This confirms the fixed-address entry, four-NOP layout, callback execution,
shared DWC3 sender, TRB configuration, and EP1 IN path on S5E9825.

The BootROM dumper deliberately retains its standalone, known-good assembly
instead of being refactored onto the common sender before another device test.

### EL3 state probe

`boot_nonsecure_probe` is the first diagnostic step toward a non-secure boot
path. It stays in Secure EL3 and only reads architectural registers. It does
not execute `ERET`, change `SCR_EL3`, or access a security controller.

With the Houston checkout next to this repository, run:

```sh
sudo "$(command -v python3)" tools/boot_nonsecure_probe.py --debug
```

The tool uses Houston's payload upload and callback-overwrite functions on the
existing USB session. It saves a versioned `0x60`-byte record to
`/tmp/exynos9825_boot_nonsecure_probe.bin` and prints `CurrentEL`, `SCR_EL3`,
the EL3 translation state, the relevant EL2 state, `ID_AA64PFR0_EL1`, and
`VBAR_EL3`. Using the resolved interpreter path is required when the Houston
dependencies are installed in an active virtual environment: plain
`sudo python3` normally selects root's system Python instead.

The probe was hardware-tested on 2026-10-03. It reported Secure EL3 with MMU
and D-cache disabled, I-cache enabled, `SCR_EL3 = 0`, `HCR_EL2 = 2`,
`SCTLR_EL2 = 0x30c50838`, `ID_AA64PFR0_EL1 = 0x10112222`, and
`VBAR_EL3 = 0x1c000`. `TCR_EL3` was zero, so the observed `TTBR0_EL3` and
`MAIR_EL3` contents are inactive stale state rather than an active EL3
translation regime.

Decode an already captured record without accessing USB:

```sh
python3 tools/boot_nonsecure_probe.py \
    --decode /tmp/exynos9825_boot_nonsecure_probe.bin
```

### Non-secure transition probe

`nonsecure_transition_probe` copies a 16-byte `SMC` stub to the Binary 9 sboot
address `0xbfe80000`, verifies the copy from Secure EL3, installs a private EL3
vector table, and attempts an exception return to Non-secure EL2h. It uses
`SCR_EL3 = 0x40f` and `SPSR_EL3 = 0x3c9`, then restores the hardware-confirmed
original `SCR_EL3` and `VBAR_EL3` before reporting over USB.

The report distinguishes a successful lower-EL `SMC`, an EL3 data abort while
accessing the candidate DRAM address, a Non-secure instruction abort, and a
copy mismatch. The test is volatile and does not load Samsung stages or write
persistent storage.

The checkpoint revision was hardware-tested on 2026-10-03. It returned only
`NS2PRE!!`, with `CurrentEL = 0xc`, then stopped at the first access to
`0xbfe80000`. It did not reach `NS2COPY!` or `NS2ERET!`, so this run never
executed `ERET`. The candidate sboot address is not usable in the initial
BootROM/Houston state; the stock boot stage that initializes DRAM must be
identified before another transition attempt.

Run it with:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/nonsecure_transition_probe.bin \
    --output /tmp/exynos9825_nonsecure_transition_checkpoints.bin \
    --debug
```

Hardware validation passed on 2026-10-03. The original TRB again contained
buffer `0x02021570`, size `0x200`, and control `0x813`. `ENDTRANSFER` returned
`1`, and all three TRB fields were zero after the BootROM clear helper. The
96-byte raw record has SHA-256
`923ea0b41d93d2168c85b8f2d47962522bbb989cfcc60b27d8ea4e65316bdc1d`.

`usb_receive_rearmed_probe` applies that validated cancellation before calling
the BootROM receive arming helper. It sends `RX1ARM!!` only after `0x1174`
returns. The host then submits the bounded `0x4a`-byte DNW frame:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_receive_rearmed_probe.bin \
    --receive-test \
    --output /tmp/exynos9825_usb_receive_rearmed_probe.bin \
    --debug
```

Hardware validation passed on 2026-10-03. The device returned `RX1ARM!!`, the
host sent the complete `0x4a`-byte frame, and the device returned `RX1PASS!`.
The final record reported BootROM return `1`, destination `0x02030000`, receive
limit `0x100`, and matching bytes `00` through `3f`. The payload artifact has
SHA-256
`befab368e6926e421deec9202713288aa96fec089e4b65b15d2291d84446a4fd`.
The 192-byte two-record capture has SHA-256
`a0fadaba800998f7818ae775e0d7953a1434c1ca698819016a2f79e7e4cd36a5`.
This confirms bounded BootROM EP2 OUT reception on the existing Houston USB
session after event repair and stale-transfer cancellation.

### Binary 9 EPBL receive probe

`epbl_receive_probe` extends the validated transport test to the exact
`0x3000`-byte EPBL from `N975FXXS9HWHA`. It receives the file at the diagnostic
address `0x02030000`, verifies all bytes with FNV-1a, checks the first two and
last 64-bit words, and reports `EPBPASS!` or `EPBFAIL!`. It does not execute
the EPBL or change any persistent state. The host rejects another bootloader
revision by checking the EPBL size and SHA-256 before sending it.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_receive_probe.bin \
    --receive-test \
    --receive-file /path/to/N975FXXS9HWHA/epbl.bin \
    --output /tmp/exynos9825_epbl_receive_probe.bin \
    --debug
```

Hardware validation passed on 2026-10-03. The device returned `EPBRDY!!`, the
host sent the complete `0x300a`-byte frame, and the device returned
`EPBPASS!`. The final record reported BootROM return `1`, destination
`0x02030000`, receive limit `0x3000`, matching FNV-1a values
`0xfdfb55e38228e523`, and the expected first, second, and last qwords. The
payload artifact has SHA-256
`2b8cf71b910c4b296e0060c81c219c5f93bd52b712f570b053ec473a289a2db4`.
The 192-byte two-record capture has SHA-256
`db33e602f4429ce395ec8cabcaf9cf79ab4b71e5ed4d71043cef6b6ce7494a20`.
This validates the diagnostic destination and complete EPBL transfer. It does
not validate the stock EPBL load address, its expected iRAM state, or EPBL
execution.

### Binary 9 EPBL state probe

`epbl_state_probe` captures `0x02020000..0x0202013f`, including the BL1
bookkeeping and function-pointer table read by the current EPBL. It returns
four records named `EPS0IRAM` through `EPS3IRAM`. The host prints every
32-bit word with its source address. The probe does not receive or execute a
Samsung stage, call any captured pointer, or access a new MMIO block.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_state_probe.bin \
    --output /tmp/exynos9825_epbl_state_probe.bin \
    --debug
```

Hardware validation passed on 2026-10-03. The device returned all four records
from `EPS0IRAM` through `EPS3IRAM`, covering every 32-bit word through
`0x0202013c`. The 384-byte capture has SHA-256
`b11f7c34a187601acbca7b6e03c65be70d72ed632e2cc195ba4679d9c9f7b07a`.

The function-pointer area is coherent and includes the confirmed BootROM USB
receive pointer `0x00000a3c` at `0x020200dc` and USB initialization pointer
`0x000006e8` at `0x020200e0`. The captured stage bookkeeping is not ready for
execution: `0x02020030` is `0x00de8e8f`, while
`0x02020120..0x0202013c` contains non-address data. The EPBL must not be called
until the required fields are reconstructed from the matching Binary 9 path.

### Binary 9 EPBL header probe

`epbl_header_probe` validates the first legitimate stock-state reconstruction
step without executing EPBL. It relocates a self-contained worker to
`0x02025000`, receives the pinned Binary 9 EPBL at the BootROM destination
`0x02022000`, verifies the complete raw file, and invokes only BootROM header
parser `0x17c54`. The parser must derive size `0x3000`, preserve checksum
`0xb82c55e7` in the BL1 state, and clear the checksum word in the received
header.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_header_probe.bin \
    --receive-test \
    --receive-file /path/to/N975FXXS9HWHA/epbl.bin \
    --output /tmp/exynos9825_epbl_header_probe.bin \
    --debug
```

The expected records are `EPHRDY!!` followed by `EPHPASS!`. This probe does
not invoke the following BootROM verification path or transfer control to the
Samsung stage. Hardware validation is pending.

### Same-session USB receive probe

`usb_receive_probe` sends `RX1RDY!!`, receives one framed 64-byte test pattern
through the BootROM receive core at `0x11cc`, verifies it in iRAM, and reports
`RX1PASS!` or `RX1FAIL!`. The candidate buffer at `0x02030000` is local to
this diagnostic and is not promoted to a platform constant before hardware
validation. The probe performs no persistent write.

The first hardware test received `RX1RDY!!` and completed the host-side
`0x4a`-byte EP2 OUT write, but returned no terminal record. This means the
payload reached the receive checkpoint; it does not prove that the BootROM
consumed the transfer. The call at `0x11cc` did not return during the capture.
The probe runner now preserves the ready record when this failure repeats.

Run it with:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_receive_probe.bin \
    --receive-test \
    --output /tmp/exynos9825_usb_receive_probe.bin \
    --debug
```

`usb_receive_direct_probe` isolates one possible cause of that result. It
enters the same BootROM receive core without first submitting an EP1 IN
transfer, while the host sends the same DNW frame immediately after Houston's
callback overwrite. Run it with:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_receive_direct_probe.bin \
    --receive-test-direct \
    --output /tmp/exynos9825_usb_receive_direct_probe.bin \
    --debug
```

Hardware testing produced the same missing terminal record. This excludes the
preceding EP1 marker as the cause. BootROM analysis shows that Houston invokes
the payload from inside the USB event dispatcher, before that dispatcher
advances and acknowledges the event which caused execution. A nested call to
the BootROM receive loop can therefore encounter the same pending event again.

`usb_receive_event_probe` restores the observed original callback `0x1b2c`,
runs it for the triggering event, advances the BootROM software event index,
and calls the BootROM event acknowledgement helper at `0x2fbc`. It then runs
the same bounded receive without an EP1 checkpoint. Test it with:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_receive_event_probe.bin \
    --receive-test-direct \
    --output /tmp/exynos9825_usb_receive_event_probe.bin \
    --debug
```

This test also completed the host-side EP2 OUT write without returning a
terminal record. Because the first observable output followed both event
repair and the receive call, that result does not yet identify which operation
failed. The event-repair sequence must be checked independently before further
receive changes.

`usb_event_repair_probe` performs only the event repair and reports
`RX1EVT!!` over EP1 IN. It does not arm or receive an OUT transfer:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_event_repair_probe.bin \
    --output /tmp/exynos9825_usb_event_repair_probe.bin \
    --debug
```

Hardware testing returned `RX1EVT!!` with `CurrentEL = 0xc`. The software
event index advanced from `0x0b` to `0x0c`, confirming that the original
handler, index update, acknowledgement helper, and following EP1 transfer all
completed. The triggering callback result word was zero.

`usb_receive_armed_probe` performs the validated event repair, configures the
bounded receive state, calls BootROM helper `0x1174`, and sends `RX1ARM!!` only
after EP2 OUT has been armed. Its EP1 marker uses a payload-local TRB, leaving
both the BootROM EP2 TRB at `0x020214a0` and the confirmed EP1 IN sender TRB at
`0x02024800` untouched. The host then submits the test frame:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_receive_armed_probe.bin \
    --receive-test \
    --output /tmp/exynos9825_usb_receive_armed_probe.bin \
    --debug
```

Hardware testing returned no `RX1ARM!!` record. Since the preceding event
repair is independently validated, execution stopped while `0x1174` was
arming the OUT endpoint. No test frame was sent in this run.

`usb_out_state_probe` reads the relevant BootROM state before `0x1174`. It
does not arm EP2 or receive data and uses a payload-local TRB for its report:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_out_state_probe.bin \
    --output /tmp/exynos9825_usb_out_state_probe.bin \
    --debug
```

The first hardware run confirmed the transfer workspace at `0x02021400`, an
EP2 maximum packet size of `0x200`, a clear receive-completion flag, and an
EP2 direction selector of zero. That revision incorrectly treated
`workspace + 0x170` as a TRB. BootROM helper `0x29a4` instead returns that
address as the receive data buffer, explaining why the reported words held
DNW and payload bytes. Disassembly of the matching S5E9825 BootROM shows that
the EP2 path at `0x1920` selects `workspace + 0xa0`, or `0x020214a0`.

The corrected probe passed on hardware. It reported buffer `0x02021570`, size
`0x200`, and control `0x813`. Control bit zero is HWO and remains set, so the
DWC3 still owns the existing EP2 TRB when the payload starts. This explains
why the arming helper blocks in the HWO wait at `0x1920`. The corrected
96-byte record has SHA-256
`5817a9ecde272cd685dca56cc9b0d9c11f593d70a4ac3b358db9ed4a5ecd4841`.

`usb_out_cancel_probe` records that TRB and performs the same two BootROM calls
used by cancellation helper `0x27f4` for logical EP2 OUT. It preserves the
return from endpoint-command function `0x1268`, then calls `0x19e4` to clear
the selected TRB and records its resulting state. The probe does not arm
another transfer or receive data:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_out_cancel_probe.bin \
    --output /tmp/exynos9825_usb_out_cancel_probe.bin \
    --debug
```

## Build

Install an AArch64 GNU toolchain and Python dependencies. On Debian or Ubuntu:

```sh
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu python3-pip
python3 -m pip install -r requirements.txt
```

Build and perform host-side layout checks:

```sh
make
make verify
make disasm
```

Artifacts are written to `build/`. You can override the toolchain prefix, for
example `make CROSS_COMPILE=/opt/toolchains/bin/aarch64-none-elf-`.

`make verify` checks the ELF entry address, the four-NOP Houston entry, and the
maximum payload size before the confirmed TRB at `0x02024800`. These checks do
not replace physical-device validation.

## BootROM dump

Build the payload, put the phone into EUB mode, and run:

```sh
python3 tools/dump_bootrom.py
```

The tool waits for `04e8:1234`, triggers the Houston callback overwrite, reads
exactly `0x20000` bytes, writes `bootrom_exynos9825.bin`, and verifies the known
SHA-256 digest.

## USB re-enumeration status

Automatic USB re-enumeration after code execution is not working. Calling the
BootROM USB initialization helper at `0x000006e8` with
`x0 = 0x02021400`, `w1 = 300`, and `w2 = 0` or `w2 = 1` did not make the device
return. Houston's message that a missing device most likely indicates USB was
reinitialized is not proof of re-enumeration on S5E9825.

The current payloads use the known-good direct EP1 IN sender and do not call
the USB initialization helper.

## License

This project is licensed under GPL-2.0-only. See [`LICENSE`](LICENSE).
