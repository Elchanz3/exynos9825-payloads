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
| Our payload entry | EL3, `CurrentEL = 0x0c`, at the EPBL→FWBL1 shim |

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
| `0x15860800`, `0x804`, `0x810`..`0x81c` | **unused by sboot** — usable as scratch that survives a warm reset |
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
| USB (DWC3) | the controller is live and already enumerated — our payload speaks to the host over EP1/EP2 through the BootROM's own helpers |
| PMIC rails | `m_vdd_buck1..8` and `s_vdd_buck1` (G3D), all `regulator-min-microvolt = 450000`; PMIC step 6250 µV |
| CPU/GPU DVFS | ECT inside `sboot.bin` at offset `0x4cc00` (`PARA`, version `2005`); voltages in its ASV block, one byte per level per ASV group; the live table is the ACPM's fvmap in SRAM at the ACPM firmware + `0xa400` |
| OTP / fuses | SMC `0xc2001014`: cmd `0x16` program KEY2, `0x2` set USE_KEY, `0x101`/`0x115`/`0x114` reads |

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
- **Do not send on EP1 from the FWBL1 hook.** A 16-byte report added there
  broke the following BL2 write in three runs out of three.
