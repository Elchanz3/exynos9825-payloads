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
Direct PMU, GPIO, secure-boot state changes, stage execution, and later
boot-stage loading are not implemented because their S5E9825 addresses and
behavior have not been validated. The matched BootROM verifier's CryptoCell
branch has been exercised without patching its security decision.

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
| `epbl_header_probe` | Relocates itself, receives Binary 9 EPBL at the stock BootROM destination, and invokes only the matched header parser | Hardware tested on SM-N975F. No `EPHRDY!!` record returned, so execution stopped before the receive checkpoint. |
| `epbl_header_noic_probe` | Repeats the matched Binary 9 header-parser probe without the blocking EL3 I-cache operation | Hardware tested on SM-N975F. Relocation and EP2 rearm passed; USB disconnected during the EPBL host write. |
| `epbl_header_staged_probe` | Separates exact EPBL reception and hash verification from the matched BootROM header-parser call | Hardware tested on SM-N975F. Exact reception and the stock header parser passed. |
| `epbl_verify_staged_probe` | Runs the matched stock BootROM verifier only after separate receive, hash, and parser checkpoints | Hardware tested on SM-N975F. Exact reception, parsing, and the stock CryptoCell verification branch passed. |
| `epbl_postload_staged_probe` | Runs the stock EUB post-load helper after authenticated EPBL checkpoints without entering EPBL | Hardware tested on SM-N975F. All five checkpoints and the stock post-load setup passed. |
| `epbl_entry_staged_probe` | Reproduces the final stock timer and boot-flag calls, then reaches a controlled reporter through the authentic EPBL entry instruction | Hardware tested on SM-N975F. The authentic entry branch and controlled second-instruction hook passed. |
| `epbl_mmio_staged_probe` | Executes through the first authentic EPBL MMIO load and reports before the comparison | Host validated; hardware test pending. |
| `epbl_dispatch_staged_probe` | Executes the authentic EPBL entry prefix and reports which first-stage dispatch path it selects | Initial hardware run stopped after `EPDRDY!!`; the reporter was revised to preserve the authentic MMIO value and awaits retest. |
| `relocation_probe` | Separately verifies the worker copy and Secure EL3 execution at `0x02025000` | Hardware tested on SM-N975F. The copy passed, but no relocated-worker record returned. |
| `relocation_fetch_probe` | Tests two Secure EL3 instructions at `0x02025000` and reports from the original Houston region | Hardware tested on SM-N975F. No result record returned. |
| `relocation_fetch_control_probe` | Runs the same two-instruction test at `0x02024000` inside the reserved payload window | Hardware tested on SM-N975F. No result record returned. |
| `relocation_fetch_noic_probe` | Copies and branches to the two-instruction control stub at `0x02024000` without an I-cache maintenance operation | Hardware tested on SM-N975F. Secure EL3 fetch and return passed. |
| `icache_maintenance_probe` | Isolates the EL3 instruction-cache invalidation sequence without relocating code | Hardware tested on SM-N975F. Only the pre-invalidation checkpoint returned. |
| `icache_target_probe` | Invalidates only the candidate target line with `ic ivau` while execution remains in the Houston image | Hardware tested on SM-N975F. Only the pre-invalidation checkpoint returned. |

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
Samsung stage.

The first hardware run on 2026-10-03 returned zero ready bytes. The host did
not send EPBL, so neither the BootROM parser nor Samsung code ran. The new
operations before the missing checkpoint are the worker copy, EL3 instruction
cache invalidation, and first instruction fetch at `0x02025000`. These steps
must be isolated before the header probe is attempted again.

`relocation_probe` performs that isolation without receiving a Samsung stage.
It compares the complete copied worker and emits `RELCPY!!` from the original
Houston area. It then invalidates the EL3 instruction cache, branches to
`0x02025000`, and emits `RELPASS!` from the relocated worker. Receiving both
records proves the copy and relocated Secure EL3 instruction fetch separately.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/relocation_probe.bin \
    --output /tmp/exynos9825_relocation_probe.bin \
    --debug
```

Hardware validation on 2026-10-03 returned `RELCPY!!` with source
`0x02022110`, target `0x02025000`, size `0x128`, no mismatch, and
`CurrentEL = 0xc`. No `RELPASS!` record followed. The 96-byte capture has
SHA-256 `1cece05adacd278a9984932c19ddc2dc6b388f5c1c1c685d2bc9972f219ac426`.
This confirms the full data copy but does not distinguish an instruction-fetch
failure from a stalled second USB send in the relocated worker.

`relocation_fetch_probe` removes the second USB sender from the relocated
path. It installs a private EL3 vector, copies an eight-byte stub to
`0x02025000`, and branches to it. The stub writes a fixed signature into the
result record and returns to the original Houston-linked code through an
address held in a register. Only the original code sends the final record.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/relocation_fetch_probe.bin \
    --output /tmp/exynos9825_relocation_fetch_probe.bin \
    --debug
```

`RFXPASS!` proves both instructions were fetched and the return completed.
`RFXFAIL!` with status `0x100` reports an EL3 exception together with
`ESR_EL3`, `FAR_EL3`, `ELR_EL3`, and `SPSR_EL3`. Status `0x101` reports a copy
mismatch, and `0x102` reports that control returned without the expected
signature. This diagnostic does not receive or execute a Samsung boot stage.

The hardware run on 2026-10-03 returned no probe record. Houston completed the
callback overwrite, but neither `RFXPASS!` nor `RFXFAIL!` reached the host.
Together with the earlier verified copy, this bounds the failure to entry into
`0x02025000`, return from that stub, or exception handling after the branch.
Because the runner received zero bytes, it did not create the requested output
file. A control run in the reserved payload window below the confirmed TRB is
required before interpreting this as a definitive execute restriction at
`0x02025000`.

`relocation_fetch_control_probe` provides that control without changing the
test sequence. Its target is `0x02024000`, after the linked image and before
the confirmed DWC3 TRB at `0x02024800`. It uses separate `RFCPASS!` and
`RFCFAIL!` records so the capture identifies the tested address unambiguously.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/relocation_fetch_control_probe.bin \
    --output /tmp/exynos9825_relocation_fetch_control_probe.bin \
    --debug
```

`RFCPASS!` confirms that the copy, cache maintenance, indirect branch, target
store, indirect return, and original USB reporter all work at the control
address. `RFCFAIL!` has the same exception and status layout as the primary
fetch probe.

The hardware run on 2026-10-03 also returned zero records. The host therefore
did not create the requested output file. Because both fetch probes execute
`ic iallu` immediately before their indirect branch, cache maintenance must be
tested without relocation before either address result can be interpreted.

`icache_maintenance_probe` sends `ICHPRE!!`, executes `dsb sy`, `ic iallu`,
`dsb sy`, and `isb` without branching away from the linked image, then sends
`ICHPASS!`. Its private EL3 vector reports `ICHFAIL!` if the operation raises a
synchronous exception.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/icache_maintenance_probe.bin \
    --output /tmp/exynos9825_icache_maintenance_probe.bin \
    --debug
```

Both `ICHPRE!!` and `ICHPASS!` are required for PASS. Receiving only
`ICHPRE!!` isolates the stop to the cache-maintenance sequence or the first
instruction fetch immediately after it.

The hardware run on 2026-10-03 returned `ICHPRE!!` and no terminal record.
The captured state was EL3 with `SCTLR_EL3 = 0x00c51838`. The raw 96-byte
record has SHA-256
`b6efa10462b29684d7c89650eeca2986b8f7b4de2835648aabe39af301ee1125`.
This result shows that global instruction-cache invalidation does not return to
the reporting path used by this probe. It does not distinguish a stop in
`ic iallu` from failure to refill the next instruction, and it does not prove
that either relocation target is non-executable.

`icache_target_probe` narrows the next test to one cache line. It sends
`ICTPRE!!`, executes `dsb sy`, `ic ivau` for `0x02024000`, `dsb sy`, and
`isb`, then sends `ICTPASS!`. Its private EL3 vector reports `ICTFAIL!` with
the architectural exception state. The probe does not copy or execute code at
the target. Since the measured `SCTLR_EL3.C` bit is clear, this isolated test
does not add a data-cache clean operation.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/icache_target_probe.bin \
    --output /tmp/exynos9825_icache_target_probe.bin \
    --debug
```

`ICTPRE!!` followed by `ICTPASS!` confirms that targeted invalidation returns
to the current EL3 image. `ICTFAIL!` reports a synchronous exception. Receiving
only `ICTPRE!!` means the targeted maintenance path did not reach the terminal
report.

The hardware run on 2026-10-03 returned only `ICTPRE!!`. The record confirmed
EL3 execution, `SCTLR_EL3 = 0x00c51838`, and target `0x02024000`. The raw
96-byte record has SHA-256
`2af7778ab629260624ddb101dc6d6bd989118a3fc6716daffb5ac75a0ce1d39b`.
Because the invalidated line is outside the executing image, this result
isolates the stop to `ic ivau` or the following completion barrier. It still
does not test an instruction fetch from `0x02024000`.

`relocation_fetch_noic_probe` now performs that fetch test without executing
either failing I-cache operation. It copies the same eight-byte register-only
stub to `0x02024000`, reads it back, and sends `RNCPRE!!`. It then branches
directly to the target. The stub records a signature and returns to the linked
image, which sends `RNCPASS!`. A private EL3 vector reports `RNCFAIL!` if the
fetch raises a synchronous exception. The target has not previously been an
instruction address in this boot session, and EL3 data caching is disabled.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/relocation_fetch_noic_probe.bin \
    --output /tmp/exynos9825_relocation_fetch_noic_probe.bin \
    --debug
```

`RNCPRE!!` followed by `RNCPASS!` proves Secure EL3 execution and return at
`0x02024000` without I-cache maintenance. `RNCFAIL!` reports the exception.
Receiving only `RNCPRE!!` bounds the stop to the branch, target fetch, stub, or
return path.

The hardware run on 2026-10-03 returned both `RNCPRE!!` and `RNCPASS!`. The
terminal record confirmed target `0x02024000`, `CurrentEL = 0xc`, the expected
eight-byte stub size, and signature `0x2143455845434e52`. The raw 192-byte
capture has SHA-256
`db41546a71fcdc59bb1184f466df255b7ac358b975e5541a31ea373ece10e5db`.
This proves that freshly written iRAM at `0x02024000` is executable in Secure
EL3 without explicit instruction-cache maintenance in the tested state. It
also identifies the `ic` operations as the blocker in the earlier relocation
diagnostics.

`epbl_header_noic_probe` applies the validated first-fetch method to the
header-parser experiment as a separate payload. It leaves the original
`epbl_header_probe` unchanged, copies the same self-contained worker to
`0x02025000`, and branches there without an `ic` instruction. The relocated
worker sends `EPNREL!!` before touching the stale USB event state. After event
repair, stale OUT cancellation, and EP2 rearming, it sends `EPNRDY!!`. The host
then sends only the pinned `0x3000`-byte Binary 9 EPBL. `EPNPASS!` requires the
raw FNV-1a and the matched BootROM header-parser outputs to agree; `EPNFAIL!`
reports the bounded failure status. The probe does not execute EPBL or write
persistent storage.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_header_noic_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_header_noic_probe.bin \
    --debug
```

PASS requires `EPNREL!!`, `EPNRDY!!`, and `EPNPASS!` in that order. An
`EPNREL!!` record alone confirms execution at `0x02025000` and bounds the stop
to the USB repair or ready-report path. `EPNREL!!` plus `EPNRDY!!` confirms the
receive setup and bounds a later stop to transfer completion, raw verification,
or header parsing. No record means that the new target fetch did not reach the
first relocated checkpoint.

The hardware run on 2026-10-03 returned `EPNREL!!` and `EPNRDY!!`. The device
then disconnected while the host's EP2 OUT write was in progress, and libusb
reported `[Errno 19] No such device` before the runner printed the completed
write. This confirms relocation, USB event repair, stale transfer cancellation,
and EP2 rearm. It does not distinguish a partial transfer from a complete
transfer followed by a reset because a USB disconnect can be reported before
the host call returns. The runner used for that test aborted before writing the
two records to the requested output file.

`epbl_header_staged_probe` removes the extra marker before USB event repair and
adds a checkpoint between raw-image verification and header parsing. It sends
`EHSRDY!!` after EP2 rearm. After receiving the pinned Binary 9 EPBL and matching
FNV-1a `0xfdfb55e38228e523`, it sends `EHSHASH!` and waits for the host to
consume that record before calling the BootROM parser at `0x17c54`. It then
sends `EHSPASS!` or `EHSFAIL!`. The runner now preserves every complete record
already received if the device disconnects during a later USB read or write.
The locally validated 1016-byte artifact has SHA-256
`907f34b8292c8903d667e2c043d4c573abe7b62911d2451a8f555d0fffd3a3e5`.

The 2026-10-04 hardware run returned `EHSRDY!!`, `EHSHASH!`, and
`EHSPASS!`. The raw FNV-1a matched `0xfdfb55e38228e523`; parser `0x17c54`
returned one and produced size `0x3000`, checksum `0xb82c55e7`, and first
qword `0x18`. The 288-byte capture at
`/tmp/exynos9825_epbl_header_staged_probe.bin` has SHA-256
`c1ebfabf6c677b04f18ae833dc2f5b5b3c2a54b54a9beff07fe84ad089668c11`.

```sh
sudo ../houston-pub/.venv/bin/python3 tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_header_staged_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_header_staged_probe.bin \
    --debug
```

Full PASS requires `EHSRDY!!`, `EHSHASH!`, and `EHSPASS!`; the 2026-10-04
hardware run satisfied all three checkpoints. A capture ending at
`EHSRDY!!` isolates the stop to the EPBL transfer or its completion path. A
capture ending at `EHSHASH!` proves that the exact `0x3000` bytes arrived and
isolates the subsequent stop to the parser call or terminal report. Failure
status `0x100` reports receive completion, `0x101` the raw hash, `0x102` the
parser return, `0x103` the parsed state, `0x200` ENDTRANSFER, and `0x201` TRB
clearing. The probe does not execute EPBL or write persistent storage.

`epbl_verify_staged_probe` preserves the successful staged receive and parser
flow, then isolates BootROM verifier `0xc9a0`. It emits `EVSRDY!!` after EP2
rearm, `EVSHASH!` after the exact raw EPBL hash matches, and `EVSPARSE` after
parser `0x17c54` returns the expected size, checksum, and first qword. The
worker waits for the host to consume each checkpoint before entering the next
BootROM call. It then invokes only verifier `0xc9a0` and emits `EVSPASS!` when
the verifier returns one or `EVVFAIL!` when it returns a failure.

The terminal record captures security status `0x1000b014`, selector return
`0x17334`, boot state `0x02020064`, and verification status
`0x02020070..0x02020077` before and after the call. The decoder additionally
requires the Binary 9 state type, both verification status bits, parsed size
`0x3000`, checksum `0xb82c55e7`, and Secure EL3. This probe does not branch to
the EPBL entry point or write persistent storage. The locally validated
1232-byte artifact has SHA-256
`fd129f3af4f1bdbac7524f8a49e619923b89b0c9433d6619fbf01ca1b1c40862`.

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads

sudo /home/chanz22/Documents/GitHub/houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_verify_staged_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_verify_staged_probe.bin \
    --debug
```

Full PASS requires `EVSRDY!!`, `EVSHASH!`, `EVSPARSE`, and `EVSPASS!` in
that order. A capture ending at one checkpoint bounds the stop to the next
single stage. Generic failure status `0x100` through `0x103` and `0x200`
through `0x201` retain the staged receive and parser meanings; status `0x104`
with `EVVFAIL!` identifies a verifier return other than one.

The 2026-10-04 hardware run completed all four checkpoints. Verifier `0xc9a0`
returned one with security status `0x10000006` and selector one, confirming
the CryptoCell branch. The volatile verification status changed from `0x1f`
to `0xdf`; the parsed size and checksum remained `0x3000` and `0xb82c55e7`,
and the terminal record reported Secure EL3 (`CurrentEL = 0xc`). The saved
384-byte capture at `/tmp/exynos9825_epbl_verify_staged_probe.bin` has SHA-256
`c4c43705ac582927382ef51d1151bb7563af9a01b269243847deb78798da4cb0`.

`epbl_postload_staged_probe` extends the proven chain through the stock
post-load helper before EPBL execution. Static analysis of the matching BootROM
shows that the EUB dispatcher calls `0x5b58` with argument one after verifier
`0xc9a0` succeeds. It then records another timing value and eventually
branches through the EPBL entry pointer at `0x02022010`. Routine `0x5b58(1)`
updates volatile security and timing state through its stock helpers; it does
not enter EPBL itself.

The new probe emits `EPLRDY!!`, `EPLHASH!`, `EPLPARSE`, and `EPLVERFY` at
the same already validated boundaries. Only after the host consumes
`EPLVERFY` does it call `0x5b58(1)`. `EPLPASS!` requires return one, preserved
parsed size `0x3000`, preserved checksum `0xb82c55e7`, and Secure EL3.
`EPLVFAIL` identifies verifier failure and `EPLPFAIL` with status `0x105`
identifies a failed post-load return or damaged parsed metadata. The records
also capture `0x0202007c`, timing words `0x02020084` and `0x02020088`, and
security status `0x10001000`. The probe stops after reporting and does not
branch to `0x02022010`.

The locally validated 1544-byte artifact has SHA-256
`4535245f668b52e53bb671c8408e4435a21cfc331df3d481dddab5263da7b20c`.

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads

sudo /home/chanz22/Documents/GitHub/houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_postload_staged_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_postload_staged_probe.bin \
    --debug
```

Full PASS requires `EPLRDY!!`, `EPLHASH!`, `EPLPARSE`, `EPLVERFY`, and
`EPLPASS!` in that order. The 2026-10-04 hardware run completed this sequence.
Routine `0x5b58(1)` returned one, security information at `0x0202007c`
changed from zero to `0x10003004`, and timing words `0x02020084` and
`0x02020088` became `0x384` and `0x39c`. Security status `0x10001000`
remained one, parsed size and checksum remained `0x3000` and `0xb82c55e7`,
and the terminal record reported Secure EL3 (`CurrentEL = 0xc`). The saved
480-byte capture at `/tmp/exynos9825_epbl_postload_staged_probe.bin` has
SHA-256 `070e973bb646e79a4e08d8bef7f3fb1be7273e9b32e85c19cf2401e06a42e6de`.

`epbl_entry_staged_probe` extends that boundary through the remaining stock
sequence. It calls timing helper `0x18768` with state word `0x0202008c`, then
calls `0x16a10(0, 0x00800000)` to set the corresponding volatile flag in
`0x02020070`. The stock branch helper at `0x1c9a0` loads the EPBL entry address
`0x02022010`. The authentic instruction there, `b 0x02022018`, remains
unchanged.

Before entering, the probe verifies that the original instruction at
`0x02022018` is `0x580002d4` and temporarily replaces only that instruction
with a direct branch to its relocated reporter. To fit the measured 6.5-second
EUB connection window, this final probe omits the intermediate hash, parser,
verifier, and post-load records whose stages passed independently. It calls
the stock branch helper immediately after validating the chain. `EPEPASS!`
records both original instructions, the read-back branch, the timing word,
the boot flags, and `CurrentEL`; it can be emitted only after the CPU fetches
and follows the authentic entry instruction. The probe does not execute later
EPBL initialization and makes no persistent write.

The locally validated 1440-byte artifact has SHA-256
`436b529d175909678927baaff1f6523b2adeacdf830888f158e3fcf14e229bfe`.

The 2026-10-04 hardware run returned `EPERDY!!` and `EPEPASS!`. The stock
entry at `0x02022010` retained `0x14000002`, the original hook instruction was
`0x580002d4`, and the temporary branch `0x14000cab` reached `0x020252c4`.
The terminal record also captured timing value `0x3d7`, boot flags
`0x00b00edf`, and Secure EL3 (`CurrentEL = 0xc`). The saved 192-byte capture
at `/tmp/exynos9825_epbl_entry_staged_probe.bin` has SHA-256
`e9349e66da39247948196c79ab379e4c6327070ebaba3d1d8fb8686924b548f9`.

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads

sudo /home/chanz22/Documents/GitHub/houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_entry_staged_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_entry_staged_probe.bin
```

Full PASS requires `EPERDY!!` followed directly by `EPEPASS!`. `EPEFAIL!`,
`EPEVFAIL`, and `EPEPFAIL` identify failures in receive or hash, verification,
and post-load setup. `EPEFFAIL` with status `0x106` identifies an unexpected
original entry instruction, a missing boot flag, or a return from the stock
branch helper.

`epbl_mmio_staged_probe` narrows the next entry boundary. It preserves the
authentic instructions at `0x02022010`, `0x02022018`, and `0x0202201c`, then
replaces the comparison setup at `0x02022020` with a branch to the relocated
reporter. A successful `EPMPASS!` therefore proves that the EPBL loaded the
32-bit value at `0x15860990`. The probe records that value and stops before
the comparison or either dispatch path.

The locally validated 1464-byte artifact has SHA-256
`45de73f373dcea1438d693deb03a223360dd49cffa1590fe843c3e16fbe814c2`.

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads

sudo /home/chanz22/Documents/GitHub/houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_mmio_staged_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_mmio_staged_probe.bin
```

Full PASS requires `EPMRDY!!` followed directly by `EPMPASS!`.

`epbl_dispatch_staged_probe` moves the controlled hook past the first EPBL
decision. It preserves the entry prefix through the read of `0x15860990` and
patches both possible dispatch instructions before entry. A cold path stops at
`0x02022054`, immediately before the branch to `0x02022df8`. A warm path stops
at `0x0202206c`, before the indirect branch to the 32-bit value from
`0x02020128` plus `0x10`. The probe records the MMIO value, dispatch state,
selected target, original and patched checkpoint instructions, boot flags, and
`CurrentEL`. The reporter preserves the MMIO value already loaded by the EPBL
instead of reading the register again. It does not execute either selected
target or make a persistent write.

The locally validated 1568-byte artifact has SHA-256
`f11593f801bcf55f9c06af9cd2e3a8300dc853b52210a48423d6b9fe79dd6794`.

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads

sudo /home/chanz22/Documents/GitHub/houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_dispatch_staged_probe.bin \
    --receive-test \
    --receive-file /home/chanz22/EUB-N10/hwha_stages/epbl.bin \
    --output /tmp/exynos9825_epbl_dispatch_staged_probe.bin
```

Full PASS requires `EPDRDY!!` followed directly by `EPDPASS!`. The terminal
decoder reports either `cold` or `warm` and validates the selected target and
the relocated reporter branch.

The first SM-N975F run used the earlier 1576-byte artifact with SHA-256
`228c44b288c36a9f4fd39ef109f05e7f3cf640dca20de7384b32a733b4ccf9ac`.
It returned `EPDRDY!!`, accepted the complete framed EPBL, and then returned
zero result bytes. The preserved 96-byte ready record has
SHA-256 `eb2ad348285462b26aa8a0cb1e26d648c5004b7b372f10f8036f35842db18898`.
This bounds the failure after EP2 OUT was armed but before either dispatch hook
reported.

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
