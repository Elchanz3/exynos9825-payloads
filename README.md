# exynos9825-payloads

AArch64 payloads and host tooling for Samsung Exynos 9825 (S5E9825) BootROM
research. The tested device is a Samsung Galaxy Note10+ SM-N975F, which reports
the EUB USB product string `Exynos9820`.

The payloads enter at Secure EL3 over the EUB/BootROM USB download path, boot the
signed firmware chain entirely from RAM, and exercise the secure-boot decision
without forging a signature. Nothing is written to eFuses, OTP, UFS, or flash
unless a tool explicitly says so.

## Confirmed target data

| Item | Value |
| --- | --- |
| EUB USB product | `Exynos9820` |
| USB VID:PID | `04e8:1234` |
| USB Booting version | `v0.5` |
| Execution level | Secure EL3 (`CurrentEL = 0xC`) |
| Receive address | `0x02022000` |
| USB structure offset | `0x0480` |
| BootROM size | `0x20000` |
| BootROM SHA-256 | `895eaa3b833a6fc1168461be3d7df38416107872d530fdece90c7f689d671225` |

## What works

- BootROM payload execution at Secure EL3, with the stale-I-cache `0x17` fault at
  the EPBL→FWBL1 handoff fixed (single-cache-line stager + byte-exact EPBL mirror).
- Full stock chain booted from RAM over EUB: EPBL → FWBL1 → BL2 (DRAM trained,
  `BL2 Pass`) → sboot → EL3 monitor → Samsung Odin/Download screen.
- The encrypted FWBL1 body is dumped after it self-decrypts at runtime, for
  offline analysis of the EL3 code.
- Non-destructive secure-boot bypass for sboot (confirmed on hardware): re-pointing
  the iRAM `PTR_IS_SECUREBOOT` pointer (`0x020200A8`) to a return-0 stub makes the
  chain verify sboot hash-only, so a body-modified sboot is accepted and runs to
  the full Download screen. iRAM-only, reversible on reboot, no OTP fuse.
- An engineering-mode sboot (`tools/sboot_patch.py`) that reports the unit as a
  development device, confirmed to display `ENG MODE : ... ALLOWED` on the panel
  when run through the bypass.

The full methodology, memory map, verification internals, errors with their fixes,
key addresses, and the OTP fuse study are in
[`docs/boot_nonsecure_current_state.md`](docs/boot_nonsecure_current_state.md).

## Payloads

Built with `make` from `payloads/` into `build/`. The main families:

| Payload | Purpose |
| --- | --- |
| `dump_bootrom` | Streams the BootROM over EP1 IN in two `0x10000` transfers. |
| `houston_marker` | Confirms the callback-hijack and EP1 IN path (sends `HOUSTON!`). |
| `boot_nonsecure_probe` | Reports EL3/EL2 architectural state without leaving Secure EL3. |
| `usb_*_probe` | Same-session USB event repair, stale EP2 cancel/rearm, and bounded receive diagnostics. |
| `epbl_*_probe` | Staged EPBL receive, hash, header-parse, CryptoCell verify, post-load, and entry diagnostics. |
| `epbl_cold_context_staged_probe` | Boots the full stock chain from the authentic EPBL cold dispatcher. |
| `epbl_dump_fwbl1_probe` | Dumps the FWBL1 region after it self-decrypts. |
| `epbl_bootstate_probe` | Dumps the iRAM secure-boot control block (`0x02020000`). |
| `epbl_sboot_noverify_probe` | The non-destructive bypass (re-points `PTR_IS_SECUREBOOT`). |

## Tools

- `tools/boot_nonsecure_probe.py` — host driver: uploads a payload through the EUB
  session, drives the chain, drains EP1 IN concurrently, and supports the
  dump/bypass flows.
- `tools/dump_bootrom.py` — dumps the BootROM and verifies its SHA-256.
- `tools/sboot_patch.py` — engineering-mode sboot patcher (string-xref located,
  offsets derived from the image).
- `tools/exynos_sign.py` — RSA (sign_type 0) code signer for the ST1/ST2 format.

## Build

Install an AArch64 GNU toolchain and the Python dependencies. On Debian/Ubuntu:

```sh
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu python3-pip
python3 -m pip install -r requirements.txt
```

Then:

```sh
make            # assemble payloads into build/
make verify     # rebuild and compare against the tracked known-good binaries
make disasm     # disassemble the built payloads
```

Override the toolchain prefix with, for example,
`make CROSS_COMPILE=/opt/toolchains/bin/aarch64-none-elf-`. `make verify` checks
the ELF entry address, the four-NOP Houston entry, and the maximum payload size
before the confirmed TRB at `0x02024800`; it does not replace device validation.

## Run

With a Houston checkout beside this repository and the official Binary 9 stage
files available locally, a probe is launched through the host driver. Example
(EL3 state probe):

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/boot_nonsecure_probe.bin \
    --output /tmp/exynos9825_boot_nonsecure_probe.bin
```

Full chain with the bypass and a modified sboot (`$STAGES` holds the locally
supplied official firmware images):

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_sboot_noverify_probe.bin \
    --receive-test \
    --receive-file      "$STAGES/epbl.bin" \
    --receive-next-file "$STAGES/fwbl1.bin" \
    --receive-next-file "$STAGES/bl2.bin" \
    --receive-next-file "$STAGES/sboot_modified.bin" \
    --receive-next-file "$STAGES/el3_mon.bin" \
    --output /tmp/exynos9825_bypass.bin
```

Resolving the interpreter through the Houston virtualenv is required when its
dependencies are installed there: a plain `sudo python3` selects root's system
Python instead. Omit `--debug` for timing-sensitive chain runs, since large
hexdumps consume part of the ~6.5-second BootROM window.

## BootROM dump

Build the payload, put the phone into EUB mode, and run:

```sh
python3 tools/dump_bootrom.py
```

The tool waits for `04e8:1234`, triggers the Houston callback overwrite, reads
exactly `0x20000` bytes, writes `bootrom_exynos9825.bin`, and verifies the known
SHA-256 digest.

## Safety and scope

The payloads operate on volatile iRAM and the already-configured USB controller
state. The secure-boot bypass is iRAM-only and reversible on reboot. The OTP fuse
path is studied but no fuse is programmed; any OTP write is irreversible and gated
behind an explicit, separate step.

## License

GPL-2.0-only. See [`LICENSE`](LICENSE).
