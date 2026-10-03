# exynos9825-payloads

Small AArch64 payloads for Samsung Exynos 9825 (S5E9825) BootROM research.
The tested device is a Samsung Galaxy Note10+ SM-N975F.

This repository is an incremental S5E9825 port of the payload infrastructure
used by [halal-beef/exynos990-payloads](https://github.com/halal-beef/exynos990-payloads).
The SoC separation also follows the approach used by the
[Exynos9810 open-mini-bl1 change](https://github.com/Robotix22/open-mini-bl1/commit/954fe3e2aea5865db92b0a8be5d610040ac31aa4).

## Safety and scope

The current payloads only transmit data through an already configured USB
endpoint. They do not write eFuses, OTP, UFS, or persistent flash. PMU, GPIO,
CryptoCell, secure-boot state changes, and later boot-stage loading are not
implemented because their S5E9825 addresses and behavior have not been
validated.

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
| `usb_receive_probe` | Tests a bounded BootROM receive on the existing Houston USB session | Builds and passes host-side verification; hardware validation is pending. |

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

### Same-session USB receive probe

`usb_receive_probe` sends `RX1RDY!!`, receives one framed 64-byte test pattern
through the BootROM receive core at `0x11cc`, verifies it in iRAM, and reports
`RX1PASS!` or `RX1FAIL!`. The candidate buffer at `0x02030000` is local to
this diagnostic and is not promoted to a platform constant before hardware
validation. The probe performs no persistent write.

Run it with:

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/usb_receive_probe.bin \
    --receive-test \
    --output /tmp/exynos9825_usb_receive_probe.bin \
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
