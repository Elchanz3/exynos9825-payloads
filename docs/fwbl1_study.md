# FWBL1 (BL31 / secure monitor) — a deep read (SM-N975F, N975FXXS9HWG3)

Until now FWBL1 was only ever re-signed with our ST2 key and otherwise treated as
a black box. This is the first full static read of it. Done 2026-10-26 from the
`segundo` sboot (`d41c6fa7`, u-boot = green3) and the runtime-decrypted dump at
`~/EUB-N10/fwbl1_decrypted_runtime.bin`. Static analysis only; nothing flashed.

## What FWBL1 is

In the s5e9825 container `fwbl1.bin` occupies `0x003000..0x016000` (size
`0x13000`) and is the **ARM Trusted Firmware BL31 / EL3 secure monitor** for this
SoC, built by Samsung. The one string that dates it:

    BL31 %s   /   Built : 00:52:51, Dec  3 2019

It links/runs in iRAM at base `0x02026000`. It is *not* a general-purpose stage
with spare room — it runs before DRAM is trained and is then replaced by the
relocated monitor (see "Lifetime" below).

### Our image vs stock: identical code

Our re-signed `fwbl1` and the stock HWG3 `fwbl1` differ in **only three places**,
all metadata, no instructions:

| Offset (in sboot) | Len | What |
|---|---|---|
| `0x3004` | 4 | SBL1 body checksum = `SHA-512(data[0x10:sbl1_size])[:4]` |
| `0x15e14` | `0x30` | ECDSA signature footer (ours) vs Samsung RSA (stock) |
| `0x15e58` | `0x1a8` | rest of the signature footer |

So "só reassinado com nossa key" is literally true: the FWBL1 we ship is
byte-for-byte stock ARM-TF code, only the checksum word and the trailing
signature blob change. This read therefore describes stock behaviour exactly.

### The dump carries the probe hook

The decompile is of a **runtime** image captured by `epbl_dump_fwbl1_probe`, not
the on-flash body, so two code bytes reflect the probe, not stock:

- `0x020260cc`: dump = `69 fd ff 17` (branch to the relocated dumper at
  `0x2025670`); **stock = `03 00 00 14`** (branch forward to `0x020260d8`).
  So the `LAB_02025670` / `halt_baddata` tail inside `FUN_02026010` is the
  probe's, not a stock code path.
- `0x02027c88` holds `SUCC` and `0x02026004` is zeroed — both set at runtime by
  the self-check, absent in the on-flash image.

## Lifetime / memory map (iRAM, base 0x02026000)

```
BootROM → EPBL (0x02022000) → FWBL1/BL31 (0x02026000) → BL2 → sboot/u-boot (0xc9000000)
                                     │
                                     └─ installs the relocated monitor at ~0xff80000 (TZDRM)
```

| Region | Range | Notes |
|---|---|---|
| EPBL | `0x02022000..` | hands control to FWBL1 entry `0x02026010` |
| FWBL1 plaintext stub | `0x02026000..0x02027ca0` | entry, self-decrypt, SMC table, strings |
| FWBL1 encrypted body | `0x02027ca0..0x02031d20` | `0xa080` bytes, AES at rest (entropy ~8.0); self-decrypts in place |
| decrypted globals / stacks | `0x02032000..0x02039000` | `.bss`-like; `0x2036000` load scratch, `0x2038800` live (see below) |
| relocated EL3 monitor | `~0xff80000` (TZDRM/DRAM) | the live monitor after DRAM is up |

**It is replaced, not extended.** FWBL1 copies the real monitor into TZDRM at
`~0xff80000` and every later EL3 service (BL2's load/verify SMCs, and anything at
runtime) is handled *there*, not in the iRAM image. The iRAM copy at
`0x02026000` is dead once DRAM is trained. This is why FWBL1 is **not** a place to
add a fastboot payload: there is no persistent iRAM code here after early boot,
and the slack above the image (`0x02036000` load scratch, `0x02038800` passed to
`FUN_0202d7ac`) is live, not free — the known-good `is_secure_boot` stub only fits
because it sits at `0x02038010`, below `0x02038800`. Anything larger overlaps.

## Entry and early flow (`FUN_02026010`)

1. Clears `CPTR_EL3` trap bits (FP/SIMD/trace) and sets `SCTLR_EL3.I` (I-cache),
   then `ISB`.
2. Reads PMU `0x10005000` — if bit 6 set, returns early with `SP_EL1 = 0` (a
   warm/secondary entry).
3. Reads PMU `0x15860404` masked `0x11000000` — a reset/boot-reason sticky; if
   set, writes `0xdab` to `0x1586098c` and returns (a reboot-reason relay).
4. Otherwise: `FUN_020261e0` (sets up a `0x800`-byte block at `0x2032f80`),
   `FUN_0202623c`, then conditionally `FUN_02026720` (the self-decrypt).
5. Reaches `0x020260d8`, calls `FUN_0202e760(0x3100)` (stamps PMU `0x15860814`
   low-half = a progress/stage code), `FUN_02029b48` (the main bring-up),
   `FUN_0202e760(0x3200)`, and tail-calls `FUN_0202a9d4` (eret into the next EL).

PMU registers touched (base `0x15860000`, confirmed as the PMU block by the
kernel DT `pmu_base = <0x15860000>`, `reg = <0x0 0x15860000 0x10000>`):

| Addr | Use (inferred unless noted) |
|---|---|
| `0x15860404` | reset/boot-reason sticky (mask `0x11000000`) |
| `0x15860814` | progress/stage stamp (`0x3100`, `0x3200`, …) — low 16 bits |
| `0x15860804` | boot-type word; FWBL1 compares it to `0xbad` (meaning not confirmed) |
| `0x15860908` | `== 0` gate in `FUN_0202628c` before the main load |
| `0x15860990` | `FUN_0202661c` returns `*0x15860990 != 1` (download vs normal, inferred) |
| `0x1586098c` | written `0xdab` / `0` as a handoff flag |

> `0xbad` and `0xdab` are sentinels FWBL1 reads/writes in the PMU; the earlier
> guess that `0xbad` == "download mode" is **not** confirmed — the kernel's only
> `0xbad` is an unrelated MIF regulator constant. Treat these as boot-type
> sentinels of unknown exact meaning.

## Self-decrypt and self-integrity (`FUN_02026720`)

FWBL1's encrypted body is decrypted in place by a hardware crypto engine at
`0x13e00000` (SSS/SlimSSS style block: `0x13e01xxx` = key/IV/data ports,
`0x13e000xx` = control/status). The routine:

- programs the engine, streams the body (`src = 0x02027ca0`, `len = 0xa080`),
- then recomputes a digest and compares it, word by word, to an embedded expected
  digest at `0x02027c60` (32 bytes). On match it writes `SUCC` into the status
  string `0x02027c7f`; **on mismatch it spins forever** (`LAB_02026d98`, a silent
  `do {} while(true)`).

Same silent-hang idiom as the rest of the family: compute a HW digest, compare to
a baked-in expected value, hang on mismatch, no error string.

## Secure-boot verification (the part that matters for signing)

### Verify-type selection (`FUN_0202c57c`)

The verify *type* is chosen from the iRAM word `_DAT_02020064` (the secure-boot
control block at `0x02020000`):

```c
idx  = (_DAT_02020064 >> ((_DAT_02020064 & 7) << 2)) & 0xf;   // a nibble, self-indexed
type = (idx-1 < 4) ? table[idx-1] : 0;   // table @ 0x0202f990 = { 0x20, 0x14, 0x00, 0x40 }
```

The returned `type` drives the dispatch in the load/verify handler:

| type | primitive called | fail behaviour |
|---|---|---|
| `0x20` | `_DAT_020200bc(...)` per `0xa000` chunk | result != 1 → hang (`0x0202c3c0`) |
| `0x14` | `_DAT_020200b4(...)` | result 0 → hang (`0x0202c244`) |
| `0x00` | `_DAT_020200a0(...)` | **no fail check — hash-only, no signature** |
| `0x40` | USB-load print path | — |

The `0x00` row is exactly the hole the confirmed non-destructive bypass drives:
`is_secure_boot() == 0` steers selection to the hash-only primitive, so a
body-modified stage is accepted. The crypto primitives themselves
(`0x020200a0/a4/b4/bc`) are iRAM service pointers set up elsewhere; **FWBL1
contains no embedded RSA/ECDSA public key** — stage trust is anchored in the
hardware-fused key, not in a key inside FWBL1.

### The secure monitor and its SMC table

The relocated monitor dispatches fast SMCs through an ARM-TF `rt_svc` descriptor
at `0x0202ff80`:

    { start_oen=2, end_oen=2, type=FAST (0x1), name="mon_smc", handler=0x0202e798 }

`FUN_02030400` is the EL3 sync-exception entry: for `ESR_EL3.EC` in
`{0x17 SMC, 0x1f}` it normalizes the FID and calls `(*0x0202ff98)()` =
`FUN_0202e798`. FID normalization maps the legacy `0xFFFFFFxx` ids BL2 uses to
`0x82000000 | (-fid)`, so BL2's `0xffffff1a → 0x820000e6` and
`0xffffff19 → 0x820000e7`.

FIDs handled by `FUN_0202e798` (read as 32-bit words from the literal pool at
`0x0202e828`):

| FID | Target | Role |
|---|---|---|
| `0x82000065` | `0x202e5d4` | restricted register peek/poke (address-gated to `0x4000_0000`/`0xc000_0000` windows) |
| `0x820000e6` | `0x202aeec` | stage load+verify (parses a `0x1c` header via `FUN_0202d95c`) — BL2 `ff1a` |
| `0x820000e7` | `0x202af68` | stage load+verify (the main path; prints `[BL2]/[U-boot]/[EL3_MON] USB Loading`) — BL2 `ff19` |
| `0x820000e9` / `0x820000ec` | `0x202aea8` / `0x202e750` | world-switch / FID echo |
| `0x820000f4/f5/f6` | `0x202d1cc` | OTP-key service (buffers `0x2113c00`, `0x2136c00`) — see the OTP study |
| `0x82000300` | `0x202d528` | set `_DAT_02020064 &~0xf | 2` then `FUN_0202e074` |
| `0x82000301` | `0x202c5b8` | USB-load copy, gated to the `0x2100000..0x2159000` window |

Both `e6` and `e7` converge on the verify-type dispatch above, differing only in
how they parse the incoming descriptor. The exact stage→FID pairing should be read
from BL2, not inferred here; what is certain is that this handler is where every
stage after FWBL1 (sboot, u-boot, el3_mon) is loaded and verified.

The `0x1000b000` block is a secure/OTP shadow: `FUN_0202df14` returns
`(*0x1000b000 >> 6) & 1`, a fuse bit that gates whether a stage is staged through
the `0x2036000` scratch and verified, or loaded straight to its final address.
This is a *different* word from the `0x1000b014` "fused state" named in the older
docs — do not conflate them.

### EL3-ENC (el3_mon) — described only at the level already public

`FUN_0202a120` is the handler that brings in the encrypted EL3 monitor: it reads
the EL3-ENC header (`version 0x10000`, base `0xff80000`, etc.), decrypts the RO
and data sections, and does an integrity check — on failure it logs
`[EL3 ENC] integrity check was failed` (code `0x104`) and hangs; on success the
monitor runs at `0xff80020`. This is the same hash-or-hang contract as everywhere
else and no further detail of its keying is recorded here.

## Consequences for this project

- **Signing:** because our FWBL1 is stock code with only the checksum + ECDSA
  footer swapped, nothing in FWBL1 needs patching for the custom-key chain — the
  trust root is the fused key, and FWBL1 carries no key of its own.
- **The bypass is a FWBL1-selection fact:** the hash-only `type 0x00` row and the
  `is_secure_boot()` gate live here; the confirmed `PTR_IS_SECUREBOOT` re-point is
  a legitimate consequence of this dispatch, not a code edit.
- **Not a fastboot host:** FWBL1 runs pre-DRAM and is replaced by the TZDRM
  monitor; its iRAM image is dead afterwards and its slack is live. The fastboot
  work stays in the u-boot stage, as planned.
```
