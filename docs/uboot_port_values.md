# Exynos9825 (SM-N975F): what a U-Boot port already has, and what it does not

Inventory of the values this project has established on hardware, written for
the original goal — U-Boot as the central bootloader. Everything here was
measured or read out of the device's own binaries; nothing is copied from a
datasheet we do not have.

The short answer: **a minimal bring-up has everything it needs, because the
port does not have to start from reset.** A self-contained bootloader does not,
and the gaps are listed at the end.

## The shape that makes this cheap

Do not replace the whole chain. Replace **one stage**:

```
BootROM → EPBL → FWBL1 → BL2 → [ U-Boot ] → (kernel)
          stock  stock   stock   ours
```

By the time the stage we replace is entered, the stock chain has already done
the three things that are expensive to port:

- **DRAM is trained.** BL2 does it and says so (`DMC01`..`DMC25`, then
  `BL2 Pass` on EP1). No DDR PHY work, no timings, no per-board calibration.
- **Clocks are up** far enough that the stock u-boot prints and drives USB.
- **The EL3 secure monitor is resident** and answers SMCs.

That is why the whole chain already runs from RAM over USB with no UFS
involved, and why a replacement stage inherits a working machine.

## Entry and memory map

| | |
|---|---|
| EPBL | `0x02022000` (iRAM) |
| FWBL1 | `0x02026000`; plaintext stub to `0x02028000`, body encrypted, self-decrypts at runtime |
| FWBL1 padding, free for our code | `0x02038000`.. (the `is_secure_boot` stub lives at `0x02038010`) |
| BL2 | loaded by FWBL1; reads MINFORM bits 4..7 at `bl2.bin+0xe4` (literal pool `+0x2c8`) |
| **u-boot / the stage we replace** | **`0xc9000000`**, size `0x180000` |
| EL3 monitor | relocated to ~`0xff80000` (TZDRM); entry transfer is `(*0xff80020)()` |
| DRAM base | `0x80000000` |
| Legacy diagnostic payload entry | EL3, `CurrentEL = 0x0c`, through the altered EPBL→FWBL1 shim |
| Native UFS discriminator | EL3, then original BootROM helper `0x1c9a0` → authentic EPBL `0x02022010`; no FWBL1 shim |

The stage is entered with the MMU off and the caches in the state FWBL1 left;
the probes disable I-cache deliberately (`EPBL_DISABLE_ICACHE`) because cache
maintenance hangs on this SoC in that window.

## How the stage is loaded, if you want to keep using the stock loader

BL2 asks the EL3 monitor through a mailbox at `0xc8ffe000`:

```
smc(0xffffffffffffff1a, mode, &mailbox, mode)   load + verify sboot
                                                mailbox { size = 0x180000,
                                                          dest = 0x2024c00 }
smc(0xffffffffffffff19, tag, 0x40000, 0xc9000000)  load the EL3 monitor
```

Verification of that stage is defeated non-destructively by re-pointing the
iRAM function pointer `PTR_IS_SECUREBOOT` (`0x020200A8`) at a `mov w0,#0 ; ret`
stub, which makes the check hash-only. Confirmed on hardware: a body-modified
stage then loads and runs. No fuse, iRAM only, gone on reboot.

## iRAM control block (`0x02020000`)

| offset | meaning |
|---|---|
| `+0x64` | boot state / verify-type selector (table `0x0202f990 = {0x20,0x14,0x00,0x40}`; index 2 → type `0x00` = no verify) |
| `+0x6C` | pointer to the secure-boot key |
| `+0x70`, `+0x74` | status words |
| `+0x7C` | SBC_INFORMATION |
| `+0xA8` | `PTR_IS_SECUREBOOT` — RAM function pointer, the bypass |
| `+0xd0` | the monitor's own print routine pointer (used by the `VERIFY_DIAG` probe to print over EP1) |

Live values read on hardware: `+0x64 = 0xcb000041`, `PTR_IS_SECUREBOOT =
0x58b4`, SBC_INFO `= 0x10003004`, STATUS0 `= 0xf6b00edf`.

## PMU (`0x15860000`)

| register | meaning |
|---|---|
| `0x15860404` | read by `update_minform_magic` (reset status) |
| `0x15860808` | **MINFORM**, the boot-intent word |
| `0x1586080c` | download magic; `0x12345671` / `0x12345678` mean "go to Download" |
| `0x15860800`, `0x804`, `0x810`..`0x81c` | **unused by sboot**, but a physical two-session calibration returned `PMU=NO`; fresh EUB clears them, so they cannot carry checkpoints across reentry |
| `0x15860820`, `0x824` | used by sboot |
| `0x15860990` | secure-boot-enable gate (`== 1` in FWBL1's `fn 0x202661c`) |

MINFORM field layout, from `get_minform_magic` (`0xc900819c`) and its jump
table at `0xc90d4bd0`:

| index | bits |
|---|---|
| 0 | 31..24 |
| 1 | 23..16 |
| 2 | 7..4 |
| 3 | 11..8 |
| 4 | 15..12 |
| 5 | 3..0 |

`is_normal_booting()` returns 1 when field 1 is `'N'` (0x4e). Field 2 = 8 or 9
is what BL2 looks for. A key-combo reset keeps all of this; pulling the battery
clears it.

## Peripherals a replacement stage can reach

| | |
|---|---|
| Debug UART (console) | **`0x10440000`** — `serial_0`, and `CONFIG_S3C_LOWLEVEL_UART_PORT=0` in the kernel config, so this is the port the platform prints on. It is already initialised by the time our stage runs: the stock u-boot prints through it without touching the pinmux |
| UFS host | `0x13d60000` (+`0x13d61100`, `0x13d50000`, `0x13d70000`) |
| USB (DWC3) | the controller is live during the early EUB handoff, but inherited BootROM EP1 is not a reliable channel after BL2 transfers control to u-boot; a replacement stage must initialize or re-enumerate USB itself |
| PMIC rails | `m_vdd_buck1..8` and `s_vdd_buck1` (G3D), all `regulator-min-microvolt = 450000`; PMIC step 6250 µV |
| CPU/GPU DVFS | ECT inside `sboot.bin` at offset `0x4cc00` (`PARA`, version `2005`); voltages in its ASV block, one byte per level per ASV group; the live table is the ACPM's fvmap in SRAM at the ACPM firmware + `0xa400` |
| OTP / fuses | SMC `0xc2001014`: `0x16` program KEY2, `0x17` set USE_KEY2, `0x18` set BAN_KEY2, `0x114` check KEY2, `0x115` read USE_KEY2, `0x116` read BAN_KEY2; implementation is in encrypted CM LDFW |

## What a minimal bring-up needs, and whether we have it

| need | status |
|---|---|
| Entry address and ABI for the replaced stage | **have** — `0xc9000000`, EL3, MMU off |
| A way to get our code there | **have** — the USB chain, plus the verify bypass |
| DRAM | **have, for free** — BL2 trains it |
| Console | **have** — UART0 `0x10440000`, already initialised; EP1 also works before BL2 takes over |
| Timer | **assumed** — ARM generic timer; `CNTFRQ_EL0` has not been read out, do that first |
| Stack / scratch RAM | **have** — DRAM from `0x80000000`, iRAM padding `0x02038000`+ |
| Something to boot | **have, over USB** — the host already streams stages |

So a U-Boot that replaces the stage, prints on UART0, and jumps to a kernel
pushed over USB is reachable with what is written down here.

## What is missing, in the order it would bite

1. **UFS driver.** The base addresses are known, nothing else is. Without it
   the port cannot read `boot.img`, `dtb`, `param` or the PIT from flash, which
   is the difference between a demo and a bootloader.
2. **The Secure OS handoff.** The stock stage loads a "secure payload"
   (`0xc90016dc`, arg `0x20`) and the kernel expects it. Whether that call can
   be made from a replacement stage is **unknown and is the live question** —
   see `boot_nonsecure_current_state.md`, the normal-boot path dies shortly
   after it and nothing readable comes out.
3. **PMIC control.** Rails and ranges are known; the bus and the register map
   are not. Needed for anything beyond what BL2 leaves powered.
4. **Display.** DECON/DSIM and panel init are not characterised at all. The
   panel does work in the stock stage (it draws the download and recovery
   screens), so it is a port-the-driver problem, not a research problem.
5. **Charger / battery policy, keypad, PIT parsing.** All stock-stage
   behaviour we have only read about, never reimplemented.

## The two things not to repeat

- **Do not force a conditional branch when the call's return value is live.**
  The download fork is `bl s5p_check_download ; mov w21,w0 ; cbz w0,<normal>`,
  and the normal path immediately uses `w0` as a parameter index. Patch the
  call to `mov w0,#0`, not the branch.
- **Do not issue repeated EP1 transfers during FWBL1 initialization.** A
  16-byte report added there broke the following USB BL2 write in three runs
  out of three. The completed uninstrumented UFS control emitted only
  `UFSLOAD!` and `UFSMETA!` before handoff, but still ended on a black screen.
  The strict follow-up emitted no post-load EP1 record and also ended on a
  black screen, which rules those transfers out. Forcing reason 4 at u-boot's
  own Download fork also stayed black. A build audit then found that all three
  tests still replaced the EPBL dispatch literal, installed a diagnostic
  `VBAR_EL3`, and entered `fwbl1_noic_entry`. The next proof uses
  `tools/run_ubstage_test.sh native-trigger`, which keeps only the cache-safe
  relocation stager and hands control to the original BootROM helper at
  `0x1c9a0`. It writes no UFS partition; the expected BOOTLOADER image is
  `/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`.

## Native UFS result and the next boundary measurement

The hardware `native-trigger` result was another black screen. Since that
payload contained no old EPBL dispatch redirect, diagnostic VBAR, FWBL1 shim,
or saved-context edit, those diagnostic changes are no longer candidates for
the complete explanation.

The accompanying `Errno 19` means the host lost the BootROM EUB USB device
after the handoff. The payload had intentionally sent no record, and the old
host policy mislabeled the resulting empty capture as an error. It is an
observation after the board-side branch, not a board-side failure. Silent
actions now pass `--allow-no-records` and report this boundary without a false
failure.

The current RAM-only measurement is:

```sh
tools/run_ubstage_test.sh native-diagnose
```

It expects the already-flashed image at the absolute path:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

No Odin step is involved. `EUNPRE!!` captures the last state before authentic
EPBL entry. In particular, `0x15860990 == 1` selects the EPBL warm dispatcher,
which consumes `0x02020128` before the cold initializer writes it; any other
value selects the cold path. `EUNRET!!` proves that EPBL returned and records
the resulting iRAM state. If only `EUNPRE!!` arrives before the USB device
leaves, the next diagnostic must move into the EPBL/FWBL1 path without relying
on inherited BootROM EP1 after the handoff.

The hardware `native-diagnose` run returned no `EUNPRE!!` or `EUNRET!!` and
the screen stayed black. The local Houston checkout was then compared directly
with PR #12: its HEAD is the exact `Exynos9825 Support` commit
`fab5783854d1b363511bddcfc59c838e06bf0d61`, and both its handler and the local
runner keep the original EUB handle after ACE. The runner now reports that
policy explicitly in the live log.

Use the earlier boundary next:

```sh
tools/run_ubstage_test.sh native-load-diagnose
```

It is RAM-only and expects
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`
already on UFS. Its native payload has no FWBL1 hook or context modification;
it sends only `UFSLOAD!` and `UFSMETA!` immediately after BootROM `0xcc68`
returns. Those records separate a completed UFS load from a loss inside that
loader boundary before the later EPBL-entry snapshot.

Hardware returned both records: `0xcc68` returned 1, the boot-state device
nibble changed from USB to storage, `0x18` sectors were loaded, and the BL1
size was `0x3000` at EL3. The PR #12 transport and UFS load are therefore
confirmed. The following `ENODEV` occurred after the records completed.

The next test is:

```sh
tools/run_ubstage_test.sh native-postload-diagnose
```

It emits one `EUNPOST!` immediately after the custom-key verification helper
at `0x5b58`, before the final timing copy and boot-flag call. This separates a
successful BL1 verification from USB or execution loss during the last entry
preparation.

Hardware returned `EUNPOST!` with selector return 1, verifier return 1 and the
active verification key at custom iRAM address `0x020254a8`. The post-load
state was `0x020254ac`, boot state was `0xcb000011`, and execution remained at
EL3. The custom-key verification boundary is therefore proven.

The next RAM-only command is:

```sh
tools/run_ubstage_test.sh native-diagnose
```

It reruns the final `EUNPRE!!` snapshot with the PR #12 same-handle policy now
physically confirmed. It expects the unchanged BOOTLOADER image at
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`
and does not require Odin.

The repeated `native-diagnose` run under that confirmed host policy still
returned no final record. Use the narrower RAM-only boundary next:

```sh
tools/run_ubstage_test.sh native-timing-diagnose
```

It emits `EUNTIME!` immediately after BootROM `0x18768` returns and before
`0x16a10` sets the final boot flag. The unchanged BOOTLOADER image expected on
UFS is
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`;
no Odin step is involved.

Hardware returned `EUNTIME!` with successful selector and verifier returns,
timing delta `0x3ce`, pre-update flags `0x00300edf`, custom key pointer
`0x020254a8`, authentic dispatch `0x02020128`, intact entry qword
`0x1400000014000002`, and EL3 state. Therefore `0x18768` is no longer a
candidate for the black-screen stop.

Use the next RAM-only boundary:

```sh
tools/run_ubstage_test.sh native-flag-diagnose
```

It expects the unchanged BOOTLOADER image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

No Odin step is involved. `EUNFLAG!` runs immediately after
`0x16a10(0, 0x00800000)` and before the native entry validation. A pass proves
the expected `0x00300edf -> 0x00b00edf` flag transition and confirms the entry,
hook and dispatch values that validation will consume. The diagnostic artifact
is `build/epbl_boot_ufs_native_flag_diag_probe.bin`, size `0x6e0`, SHA-256
`12bbac2dadc965dc827c1525d394d2e5384685613d8450e4f2361648d4f05821`.

Hardware returned `EUNFLAG!` with selector 1, verifier 1, timing delta `0x426`,
final flags `0x00b00edf`, custom key pointer `0x020254a8`, authentic dispatch
literal `0x02020128`, entry/hook instructions `0x14000002 / 0x580002d4`,
`SCTLR_EL3=0x00c51838`, and `CurrentEL=0xc`. This proves every stock
pre-entry operation and validation input. The following host `EIO` occurred
after the complete record.

The next RAM-only discriminator is:

```sh
tools/run_ubstage_test.sh native-cold-diagnose
```

It expects the unchanged image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

No Odin step is involved. `EUNCOLD!` records the original `0x15860990` gate
and `0x02020128` dispatch state, verifies the conditional instruction
`0x54000041` at `0x02022028`, and records its replacement with `0x14000002`.
That single RAM patch forces the EPBL's authentic cold path before entering
the unchanged BootROM helper flow. The artifact is
`build/epbl_boot_ufs_native_cold_diag_probe.bin`, size `0x6f8`, SHA-256
`50096841987fef5562c55b5aca328fef53d916b3e8824b572455bd7eeefcc2b4`.

The hardware returned no `EUNCOLD!`; the old USB device left with `ENODEV`.
The branch change and gate value therefore remain unobserved. This missing
record and the earlier missing `EUNPRE!!` share one first operation that the
successful `EUNFLAG!` record did not perform: a direct read from
`0x15860990`.

The next RAM-only command avoids that read in both the diagnostic and the
executing EPBL:

```sh
tools/run_ubstage_test.sh native-force-cold
```

It verifies the gate-load instruction `0x580002d4` at `0x02022018`, replaces
that single RAM word with branch `0x14000006`, and therefore enters the
original cold loader at `0x02022030` without evaluating the warm-state MMIO.
`EUNFORC!` reports the installed override before handoff. No Odin step is
involved; the unchanged UFS image is:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

The artifact is `build/epbl_boot_ufs_native_force_cold_probe.bin`, size
`0x6e8`, SHA-256
`8178bae0b8eff2e0748831c2fa1b75d5213a132065aa22105dd906aeea25b596`.
