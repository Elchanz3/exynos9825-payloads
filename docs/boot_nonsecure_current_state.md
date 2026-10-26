# Exynos9825 Secure Boot: Technical Reference

Target: Samsung SM-N975F (Note10+), Exynos9825, reports EUB product `Exynos9820`.
Transport: EUB/BootROM USB download path driven by `tools/boot_nonsecure_probe.py`.
Scope: device-only, injected over USB; nothing is written to UFS unless stated.

## Summary of what works

- BootROM payload executes at EL3 (`CurrentEL = 0x0c`).
- The full stock chain boots entirely from RAM over EUB:
  EPBL → FWBL1 → BL2 (DRAM trained, `BL2 Pass`) → sboot → EL3 monitor →
  Samsung Odin/Download screen. Reproducible.
- The FWBL1 body is encrypted at rest and self-decrypts at runtime; the decrypted
  FWBL1 + EL3 code is dumped from RAM for offline analysis.
- Non-destructive secure-boot bypass for sboot (CONFIRMED on hardware): re-point
  the iRAM function pointer `PTR_IS_SECUREBOOT` (`0x020200A8`) to a
  `mov w0,#0; ret` stub. `is_secure_boot()` then returns 0, the sboot stage is
  verified hash-only (no signature), and a body-modified sboot is accepted and
  runs to the full Download screen. iRAM-only, reversible on reboot, no OTP fuse.
- Engineering-mode patcher (`tools/sboot_patch.py`) produces an sboot that reports
  the unit as an engineering/development device; CONFIRMED to show
  `ENG MODE : ... ALLOWED` on the panel when run through the bypass.
- RSA code signer (`tools/exynos_sign.py`) for sign_type 0; self-validated.

Current reach: a modified or engineering sboot runs via USB to Download mode with
no fuse. Persistent boot from UFS (without the USB payload) still requires an OTP
fuse; see the fuse section.

## Boot chain and memory map

```
BootROM → EPBL (0x02022000) → FWBL1 (0x02026000) → BL2 → sboot/U-Boot (0xc9000000)
        → EL3 secure monitor (relocated to ~0xff80000, TZDRM)
```

- `sboot.bin` container (official BL tar, Binary 9) starts WITH the EPBL at
  offset 0: `18 00 00 00 ... 15860990 ... 02023aac` (the EPBL dispatch literals).
  It is EPBL + FWBL1 + BL2 + u-boot + el3_mon concatenated.
- FWBL1: plaintext stub (`0x02026000..0x02027ca0`) + encrypted body
  (`0x02027ca0..0x02031d20`, `0xa080` bytes, byte-entropy ~8.0;
  `src=0x02027ca0,len=0xa080` in `FUN_02026720`). The stub self-decrypts the body at runtime;
  the decrypted body is plaintext ARM (entropy ~6, strings `mon_smc`,
  `[EL3 ENC]`, `Wrong boot state`).
- EL3 monitor: FWBL1 installs `vbar_el3 = 0x02030000` in the iRAM copy, but the
  live monitor that services BL2's load/verify SMC runs relocated at ~`0xff80000`.
  FWBL1 main tail `FUN_0202ad38` ends with `(*0xff80020)()`, the transfer into it.
- BL2 runs at a lower EL and reaches the monitor by SMC through a mailbox at
  `0xc8ffe000`/`0xc9000000`:
  - `smc(0xffffffffffffff1a, mode, &mailbox, mode)` loads+verifies sboot
    (mailbox `{size=0x180000, dest=0x2024c00, ...}`).
  - `smc(0xffffffffffffff19, tag, 0x40000, 0xc9000000)` loads the EL3 monitor.

## Secure-boot verification internals

- The stage verify TYPE is selected in the decrypted FWBL1 by `FUN_0202c57c`
  from the iRAM word `_DAT_02020064` (`0x02020064`) via the table at
  `0x0202f990 = {0x20, 0x14, 0x00, 0x40}`. The handler dispatches on type to
  service-pointer crypto primitives in iRAM:
  - type `0x14` → `_DAT_020200b4(...)`; result 0 → hang at `0x0202c278`.
  - type `0x20` → `_DAT_020200bc(...)` per 0xa000 chunk; result != 1 → hang at
    `0x0202c3c0`.
  - type `0x00` → `_DAT_020200a0(...)`, no fail check (hash-only, no signature).
  - type `0x40` → USB-load print. else → `FUN_0202a120` (EL3-ENC).
- The iRAM secure-boot control block base is `0x02020000`:
  `+0x64` boot-state / verify-type selector, `+0x6C` PTR_SECUREBOOT_KEY,
  `+0x70/0x74` status, `+0x7C` SBC_INFORMATION, `+0xA8` PTR_IS_SECUREBOOT
  (RAM function pointer `is_secure_boot()` calls through; stock value `0x58b4`).
- `is_secure_boot()` gates the verify type: when it returns 0, the chain selects a
  hash-only check (no signature). The relocated monitor reads these absolute iRAM
  addresses live at verify time, so values written there are visible to it. This
  is the control point the bypass uses.
- Enforcement idiom across the family: compute a hardware digest, compare to an
  embedded expected digest, and hang forever silently on mismatch (no error
  string). Examples: FWBL1 self-check `FUN_02026720` (engine `0x13e00000`, expected
  digest `0x02027c60`, writes `SUCC`/hangs); EL3-ENC `FUN_0202a120`
  (`[EL3 ENC] integrity check was failed`, code 0x104, `do{}while` hang at
  `0x0202a4ac`). A rejected image therefore stops silently after
  `[U-boot] USB Loading Done` with no `[EL3_MON]` request.
- The sboot signature root is the hardware-fused key via CryptoCell
  (`0x15860000` window; fused state at `0x1000b014`). The decrypted FWBL1 contains
  NO embedded RSA public key (no size-prefixed pubkey blob, no 0x100 modulus, only
  its own self-check digest). Stage trust is hardware-anchored, not software-keyed.

## The non-destructive bypass (confirmed)

`epbl_sboot_noverify_probe` re-points iRAM `PTR_IS_SECUREBOOT` (`0x020200A8`) to a
`mov w0,#0; ret` stub, then boots the full chain with a body-modified sboot.

Hook (in `fwbl1_after_decrypt`, after FWBL1 self-decrypts; caches off so the store
and later fetch both hit memory):

```asm
movz x4,#0x8010 ; movk x4,#0x0203,lsl#16     ; stub @ 0x02038010
movz w5,#0x0000 ; movk w5,#0x5280,lsl#16 ; str w5,[x4]      ; mov w0,#0  (0x52800000)
movz w5,#0x03c0 ; movk w5,#0xd65f,lsl#16 ; str w5,[x4,#4]   ; ret        (0xd65f03c0)
movz x6,#0x00a8 ; movk x6,#0x0202,lsl#16 ; str w4,[x6]      ; 0x020200A8 -> stub
dsb sy ; ldr x16,=0x020260d8 ; br x16                        ; rejoin stock boot
```

Result on hardware with the body-modified meme sboot (`sboot_note10_meme.bin`,
`CURRENT BINARY` → `Sambug EL2 bypassed`):

```
[U-boot] USB Loading Start/Done
[EL3_MON] USB Loading Start/Done   <- BL2 only requests this after sboot verify succeeds
device: USB recovery mode -> full Samsung Download/Odin screen
```

Rigor: the meme is a real body modification whose rejection by the STOCK chain was
confirmed by a control run (hung at `[U-boot] USB Loading Done`, no `[EL3_MON]`).
The only change in the bypass run is the `PTR_IS_SECUREBOOT` re-point, after which
the same modified sboot is accepted. This distinguishes it from the earlier false
positive (see Errors).

## Tools

### `tools/sboot_patch.py` — engineering-mode patcher

Locates engineering/verification gate functions in the signed sboot by Samsung's
diagnostic strings (ADRP+ADD xref → nearest function prologue) and writes
2-instruction AArch64 return stubs. Offsets are derived from the image, not
hard-coded. Stubs: `RETURN_ZERO = 00 00 80 D2 C0 03 5F D6` (`mov w0,#0; ret`),
`RETURN_ONE = 20 00 80 D2 C0 03 5F D6` (`mov w0,#1; ret`).

Default (engineering identity), validated against `hwha_stages/sboot_stage.bin`:
- `have_this_mode` @0x0a9e6c → RETURN_ONE (every `ENG MODE : ... ALLOWED` passes).
- `etc_market` @0x0a1680 `mov w0,#7`→`#0`; `etc_development` @0x0a1690
  `mov w0,#8`→`#1` (reports a development unit).

With `--all`, also relaxes the non-stock-image checks: `check_signature`
@0x04fc68 →0, `set_warranty_bit` @0x0a1da0 →0, `[KG]` read_data @0x00c90c →0,
`[RLC]` read_data @0x00c624 →0 (RPMB/KG gates).

Patching only rewrites sboot on disk; the patched image is still rejected by the
stock chain at the BL2→sboot boundary. It runs only through the bypass above.

### `tools/sboot_symbols.py` — function names out of an image with no symbols

Samsung's u-boot logs with `printf("%s: ...", __func__, ...)`, so the name of
almost every interesting function is in the image as a plain string, loaded just
before the call. Resolving those loads gives a symbol table for a stage that
ships without one.

The catch, and the reason this did not work on the first attempt: the pointer is
built in two steps, and the destination register is not always the source.

```
adrp x20, <page>
add  x1, x20, #0x240
add  x1, x1,  #0x20       -> 0xc90d5260 = "s5p_check_download"
```

A resolver that only accepts `adrp` + one `add xd,xd,#imm` — which is all the
format strings in `sboot_patch.py` need — reports zero references for every
`__func__` literal. `adrp_pointer_values()` (in `sboot_patch.py`, used by
`--normal-boot`) follows the renames and returns every partial sum.

```sh
tools/sboot_symbols.py sboot_stage.bin                  # ~490 names
tools/sboot_symbols.py sboot_stage.bin --grep download
tools/sboot_symbols.py sboot_stage.bin --at 0xc9003280  # -> is_normal_booting
```

Attribution is by "nearest called entry at or before the load", the same rule
`sboot_patch.py` uses, so a function that is not itself a call target can absorb
a neighbour's name (`0xc9047f44` comes out as `ustar`). Confirm a name against
the disassembly before relying on it.

### `tools/exynos_sign.py` — RSA code signer (sign_type 0)

The 9825/9820 family signs with sign_type 0 (RSA-2048, RSA-PSS SHA-256), confirmed
from `keystorage.bin` (magic `SLSI`, version 0x20, 1056-byte RSA pubkey slots,
keys cp_key/vbmeta/fimc). Format: ST1 header embeds the st2 pubkey; ST2 stages
carry a trailing `0x110` footer `{rb_count, sign_type, key_type, key_index,
signature[0x100]}`; the PSS signature is stored byte-reversed.

`exynos_sign.py` generates an st1/st2 RSA-2048 pair, emits the `0x10C` pubkey blob
`{u32 mod_size, modulus[0x100], u32 exp_size, exp[4]}`, signs an ST2 stage over
`data[:footer_offset+0x10]`, and verifies. Self-consistency round trip passes.
Private keys are generated locally and git-ignored.

Note: the resign-and-chain approach (edit each ST1's embedded st2 pubkey, resign
the chain with a generated key) does NOT map to 9825. Scans of the extracted
stages, the 4 MB official `sboot.bin`, and `keystorage.bin` find no editable
per-stage RSA pubkeys (only one AVB/vbmeta key at `0x206c50` in the u-boot region).
Stage-chain trust is hardware-rooted (fuses + CryptoCell + encrypted/relocated
monitor), so changing the trusted key requires the OTP fuse, not a software swap.

## Probes

Built from `payloads/epbl_header_probe.S` via compile-time modes (Makefile
targets), run with `tools/boot_nonsecure_probe.py`.

- `epbl_cold_context_staged_probe` — boots the stock chain from the validated cold
  path (EPBL receive/parse/verify, then the cold dispatcher via the data-literal
  redirect into the shim). Artifact `build/epbl_cold_context_staged_probe.bin`
  (2096 bytes, SHA-256 `264462ed...5a31`).
- `epbl_dump_fwbl1_probe` — at the shim, patches `0x020260cc` to branch into a
  relocated dumper, enters FWBL1 at the continue point `0x02026034`; FWBL1 runs its
  setup and self-decrypts the body via `FUN_02026720`, returns to `0x020260cc`, and
  the dumper streams `0x02026000..0x02039000` (decrypted) over EP1 IN. Host flag
  `--dump-fwbl1`.
- `epbl_bootstate_probe` — dumps the iRAM block `0x02020000..0x02020200`. Live read:
  `0x02020064 = 0xcb000041`, PTR_IS_SECUREBOOT = `0x58b4`, SBC_INFO = `0x10003004`,
  STATUS0 = `0xf6b00edf`.
- `epbl_sboot_noverify_probe` — the confirmed bypass (re-point PTR_IS_SECUREBOOT).
- `epbl_minform_normal_probe` — writes MINFORM (`0x15860808`) = `0x4e4e0000` at the
  post-decrypt hook and rejoins the stock boot. Nothing else changes, and sboot is
  the stock image, so no verify bypass is involved. See the section on the
  Download fork below. Artifact `build/epbl_minform_normal_probe.bin` (2176 bytes).
- `epbl_android_boot_probe` — the same MINFORM write plus the PTR_IS_SECUREBOOT
  bypass, for running a patched sboot (`tools/sboot_patch.py --normal-boot`).
  Artifact `build/epbl_android_boot_probe.bin` (2224 bytes).

EP2 `STARTTRANSFER` activation is intermittent; a full power cycle (Vol-Down+Power
~10 s) clears a bad streak (software event index `0x1f`). This is device USB state,
not a code fault.

## Host driver usage

Partial (EPBL + FWBL1) diagnostic:

```sh
sudo ../houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_cold_context_staged_probe.bin \
    --receive-test \
    --receive-file  $STAGES/epbl.bin \
    --receive-next-file $STAGES/fwbl1.bin \
    --output /tmp/exynos9825_fwbl1_entry_diagnostic.bin
```

Full chain with the bypass and a modified sboot (swap in `sboot_note10_eng.bin`
for engineering mode):

```sh
sudo ../houston-pub/.venv/bin/python3 \
    tools/boot_nonsecure_probe.py \
    --houston-dir ../houston-pub \
    --payload build/epbl_sboot_noverify_probe.bin \
    --receive-test \
    --receive-file  $STAGES/epbl.bin \
    --receive-next-file $STAGES/fwbl1.bin \
    --receive-next-file $STAGES/bl2.bin \
    --receive-next-file $EUB/sboot_note10_meme.bin \
    --receive-next-file $STAGES/el3_mon.bin \
    --output /tmp/exynos9825_bypass.bin
```

The host drains EP1 IN on a background thread (`Ep1ChainReader`) while writing BL2,
sboot, and the EL3 monitor (30 s per-stage write timeout), then listens and prints
each stage message with a timestamp. This avoids a deadlock when a stage waits for
its print to be consumed before arming the next OUT transfer. Do not pass `--debug`
for timing-sensitive runs: large hexdumps consume part of the USB window.

## Errors and fixes

- `0x17` PC-alignment fault (`ESR_EL3 = 0x8a000000`, `FAR = ELR = 0x17`) at the
  EPBL→FWBL1 handoff. Cause: a stale I-cache line at the EPBL dispatch helper
  (`0x0202205c`), fetched after DMA overwrote that memory; BootROM/stages do no IC
  maintenance and `ic` hangs from the payload context. Fix: run the whole stager
  inside one 64-byte line (`0x02022010..0x0202203c`), mirror EPBL bytes
  `0x40..0xbf` byte-exact, keep `SCTLR_EL3.I` clear, and continue the unmodified
  FWBL1 at `0x02026034` via a relocated shim.
- False-positive "bypass". `sboot_note10_sigflip.bin` (byte @`0x17ff00`) PASSES the
  stock chain with no patch: `0x17ff00` is unverified padding after the signature,
  outside the verified region. The rigorous test is a BODY modification
  (`sboot_note10_meme.bin`, byte @`0xe7d60`), confirmed rejected by the stock chain.
- iRAM FWBL1 patches ineffective. Patches to `0x0202c274`/`0x0202c3c0`/`0x0202a4ac`
  and a diagnostic hook at the iRAM SMC dispatch `0x0202afac` never fired: the live
  verify runs in the monitor relocated to ~`0xff80000`, not in the iRAM FWBL1 copy
  at `0x0202xxxx`. Resolved by acting on WRITABLE iRAM state the relocated monitor
  reads live (`PTR_IS_SECUREBOOT` at `0x020200A8`) rather than patching the dead
  iRAM code copy.
- `etc_market` detection mask. The store-match for `str w0,[xN,#64]` must be
  `(word & 0xFFC00000 == 0xB9000000) && ((word>>10)&0xFFF == 64/4) && (word&0x1F ==
  0)`; an earlier `0xFFC003E0` mask was wrong.
- OTP string xrefs. `[OTP]` strings end in `"\n\0"`; search needles must include
  the trailing `\n` or the xref scan finds nothing.
- Probe dump header size field corrupted (`0x17ffff1d`) because FWBL1 execution
  scribbled the relocated `probe_record`. Cosmetic; the body bytes are valid.

## Key addresses (decrypted FWBL1, base 0x02026000)

| Item | Address |
|---|---|
| EPBL base / dispatch helper | `0x02022000` / `0x0202205c` |
| FWBL1 stub entry / post-decrypt hook / continue | `0x02026010` / `0x020260cc` / `0x020260d8` |
| FWBL1 self-check (hash-or-hang) | `FUN_02026720` |
| EL3-ENC decrypt+verify (hash-or-hang) | `FUN_0202a120`, branch `0x0202a4ac` |
| EL3 vbar (iRAM copy) / SMC sync handler / dispatch table | `0x02030000` / `0x02030400` / `0x0202ff98` |
| load+verify handler (iRAM copy) / type-select | `FUN_0202e798` / `FUN_0202c57c` |
| verify-type table | `0x0202f990 = {0x20,0x14,0x00,0x40}` |
| iRAM secure-boot block / verify-type word / PTR_IS_SECUREBOOT | `0x02020000` / `0x02020064` / `0x020200A8` |
| service-pointer crypto primitives | `0x020200a0/a4/b4/bc` |
| relocated secure monitor entry | `(*0xff80020)()` ~`0xff80000` |
| hardware hash engine / CryptoCell / fused state | `0x13e00000` / `0x15860000` / `0x1000b014` |

## OTP fuse (studied; no write performed)

The non-destructive sboot bypass reaches the OTP wrappers. Successful buffer
operations require the secure payload plus the matching LDFW initialized from
the UFS `CM` partition; the reduced Download-mode path does not provide that
complete environment.

OTP SMC interface, `CallSecureMonitor(0)` with SMC id `0xc2001014` and a command:
- `0x16`  program ROM_SECURE_BOOT_KEY2 (`FUN_c90a278c(key[0x20], 0x20)`); the 0x20
  bytes are SHA-256 of the public key, copied into a 0xa0 buffer, CRC32 appended,
  then SMC. KEY2 is one-shot.
- `0x2`   set USE_ROM_SEC_BOOT_KEY (`FUN_c90a2618`).
- `0x17` set USE_ROM_SEC_BOOT_KEY2; `0x18` set BAN_ROM_SEC_BOOT_KEY2.
- `0x101` read USE_ROM_SEC_BOOT_KEY; `0x114` check KEY2; `0x115` read USE_KEY2;
  `0x116` read BAN_KEY2.
- `secure_boot_enable` (`FUN_c90a5368`): read USE_KEY; if unset, program
  ROM_SECURE_BOOT_KEY + set USE_KEY (manufacturing flow, slot 1 KEY not KEY2).

BootROM selector audit: KEY and KEY2 are selected by priority, rather than by an
additive OR check. The decoded order at ROM `0x5780` is `A/B -> ROM`, then
`C==1 && D==0 -> KEY2`, then `E==1 -> KEY`, then `F/G -> ROM`, otherwise ROM.
The current state (`C=0`, `D=0`, `E=1`) therefore selects Samsung's KEY, but
KEY2 remains reachable because its C/D condition is tested first. The most
likely mapping is C=USE_KEY2 and D=BAN_KEY2; this still needs an independent
read-only proof before any fuse write. If confirmed, setting USE_KEY2 while it
is not banned would make KEY2 take priority over the existing KEY. The stock
KEY should not be treated as an additive fallback in that state.

Safe next step (no write): an OTP-READ experiment — a modified sboot (via the
bypass) patched to call the read commands (USE_KEY `0x101`, USE_KEY2 `0x115`, KEY2
check `0x114`) and surface the values (the routines already printf
`[OTP] ... read value: 0x%llx`; confirm whether that reaches EP1 or the panel).
This confirmed that KEY2 is free and USE_KEY is set, and validated the flag-read
part of the OTP SMC from this context without programming anything. It did not
map the returned flags to SEC0 bits C/D; that is the remaining selector proof.
Ghidra found only the generic `dev://fuse`/CSMC broker in `secure_payload`; the
physical bit mapping appears to reside in encrypted `CryptoManagerV50` modules
inside `cm.bin`, so it is not recoverable from the available static binaries.
A read-only live-memory follow-up called the CM/LDFW initializer and then read
the advertised CryptoManager load address `0x82001000`. Hardware first returned
`LDFW p0=ffffffff p1=ffffffff ret=0`. The mode discriminator then returned
`LDFW m0=66269633 m1=77279733`, exactly the second zero-return early-exit pair
in `FUN_c90a616c`. This proves the USB/EUB path returned before reading the CM
partition or initializing LDFW. The all-ones words therefore were not a loaded
CryptoManager image. Further forced calls in the reduced download context do
not supply the missing normal-boot dependencies; the remaining useful path is
the mapped UFS boot flow. Construction details and the other pairs are recorded
in `docs/custom_key_fuse_port.md`.

The UFS trampoline has since been updated to clear those two proven mode words
and set MINFORM to `0x4e4e0000` after loading sboot from UFS. The generated
KEY2-only fuse chain also forces the secure-payload load and makes the later
`s5p_check_download()` call return the legitimate zero reason. Both the
trampoline and the fully resigned four-megabyte chain pass their static and
cryptographic checks; the next evidence required is the KEY2-only hardware
program/readback sequence documented in `docs/custom_key_fuse_port.md`.

## Why the chain stops at Download mode, and the fork that decides it

Everything below is static analysis of `hwha_stages/sboot_stage.bin` (u-boot
runs at `0xc9000000`, so VA = `0xc9000000` + file offset). Nothing here has been
run on hardware yet.

The fork is in u-boot's main flow:

```
0xc90038f0   bl   s5p_check_download          (0xc900e9e0)
0xc90038f4   mov  w21, w0                     (keep the reason for do_download)
0xc90038f8   cbz  w0, 0xc90039fc              -> NORMAL BOOT (draws the logo)
             ...  print "AST_DLOAD.."; do_download(w21)   (0xc900eee8)
```

`s5p_check_download()` returns a download reason, zero meaning "boot normally".
It tests, in order:

| reason | condition |
|---|---|
| 2 | `param[0] == 1` (a `reboot download` request; it clears the param) |
| 7 | `param[0] == 0xd` |
| 3 | `param[3] & 0xffff0000 == 0xabcf0000` |
| 6 | `param[4] != 0` |
| 1 | a key is pressed (`0xc900e484`) |
| — | **`is_normal_booting()` != 0 → returns 0, i.e. normal boot** |
| 4 | otherwise, if `ifconn_check_jig_adc_value()` (`0xc9023eac`) == 1 |

The last two lines are what matters for a USB-booted chain:

- `is_normal_booting()` (`0xc9003280`) reads **MINFORM** (PMU `0x15860808`) and
  asks `get_minform_magic()` (`0xc900819c`) for two of its fields — index 0 is
  bits 31..24, index 1 is bits 23..16 (the remaining four indexes are nibbles;
  the order comes from the jump table at `0xc90d4bd0`). It returns 1 when field 1
  is `'N'` (0x4e) — "intentional normal booting" — and 0 when both fields are
  zero, which it reports as "minform is reset value". A cold boot over the
  BootROM USB path leaves exactly that zero.
- `ifconn_check_jig_adc_value()` then reads the connector's ADC. A cable is
  attached by definition here, since the payload arrives over it, so this
  returns 1 and the function answers reason **4**.

So the Download screen is not a verification failure or a USB-boot gate: it is
u-boot concluding that nobody asked for a normal boot and a cable is plugged in.

Two levers, both prepared:

1. **MINFORM** — write `0x4e4e0000` ('N','N') before u-boot reads it, and the
   stock, unmodified sboot takes the normal-boot fork. Nothing in the chain
   fights that write: EPBL, FWBL1 (encrypted and decrypted) and el3_mon never
   reference `0x15860808`; BL2 only reads bits 4..7 (its own upload check, at
   `bl2.bin+0xe4`, literal pool at `+0x2c8`); u-boot's own six setters
   (`0xc90080a8`..`0xc9008130`, reached through `update_minform_magic`
   `0xc9008238`) are read-modify-write of one field each, and the only full-word
   write is `MINFORM = 0x12345678` inside the download path itself
   (`0xc900ebbc`), after the decision.
2. **The fork** — `tools/sboot_patch.py --normal-boot` turns the `cbz` at
   `0xc90038f8` into an unconditional branch, which answers all seven reasons at
   once. It costs the keypad escape, which is free here: everything runs from
   RAM, so a power cycle boots the stock sboot from UFS again.

If the normal path then fails, u-boot says so before falling back, and the
message names the stage: `Could not do normal boot. (invalid ppi)`,
`(DT LOAD Fail..)`, `(invalid magic)`. The panel is the only console for that,
so photograph the screen.

## What happens after the fork (2026-10-14, hardware)

The fork patch works -- the device stopped going to Download -- but the boot
does not reach Android. In order, with what each run showed:

| sboot | result |
|---|---|
| stock + MINFORM = 'N','N' | Odin. MINFORM alone does not decide it |
| fork forced by `cbz` -> `b` | black screen, no USB |
| same, battery in and battery out | identical, so not the battery/LPM guard |
| fork forced by `bl` -> `mov w0,#0` | blue "USB RECOVERY MODE", then off |
| + prompt stubbed, 4-byte minimal, with and without the eng identity | black screen |

Two corrections to earlier readings, both from the disassembly:

**Forcing the branch was wrong.** The call site is `bl s5p_check_download ; mov
w21,w0 ; cbz w0,<normal>`, and the normal path opens with `bl get_param` using
**w0 as the parameter index**. Making the branch unconditional leaves the
download reason in w0, so the first thing the normal path does is read the
wrong parameter. Replacing the CALL with `mov w0,#0` reproduces the legitimate
state register for register; that is what `--normal-boot` does now.

**The blue screen is not the failure handler.** Both outcomes of the
secure-payload load converge:

```
0xc900345c   mov w0,#0x20 ; bl 0xc90016dc      load secure payload
0xc9003464   cbz x0, 0xc90034f4                 0 = loaded
             printf("Fail to load Secure Payload!! [ret = %lx]")
0xc90034f4   printf("%s: Load done.") ; [0xc917d030] = 1 ; b 0xc9003478
0xc9003478   "[Debug Info.]", " SecureOS : %d (MB)"
0xc90034d4   b 0xc9008b4c                       tail call, both paths
```

`0xc9008b4c` reads DRAM `0x80000000` and `0x80000010`, returns 0 when neither
holds a magic, and only otherwise draws

```
UP KEY : NORMAL BOOTING / DOWN KEY : DOWNLOAD MODE / USB RECOVERY MODE
```

waits for a key and writes `0x66265999` back to `0x80000000` on the way out. So
it arms itself: one run that lands there hijacks every run after it, because a
bench board on USB power only warm-resets and DRAM keeps the word. Whether the
secure payload actually failed is still unknown -- the print goes to a console
this board does not expose.

### Reading anything back is the open problem

- The panel is the only console, and `printf` does not reach it this early.
- EP1 belongs to the chain once BL2 takes over.
- **Do not send on EP1 from the FWBL1 hook.** A 16-byte report added there
  broke the BL2 write in three runs out of three, at exactly that point; the
  packet desynchronises the transfer the host is in the middle of. Reverted.
- `epbl_inform_dump_probe` (dump `0x15860800..+0x100`) came back with a
  corrupted length (`size=0x17ffff1d`) and transferred nothing. EPBL scribbles
  near the probe record on the cold path, which is the likely cause.
- `sboot_patch.py --diag-secure-payload` does the recording half: it stubs the
  prompt and replaces the four instructions that print the failure with
  `movz x1,#0x818 ; movk x1,#0x1586,lsl#16 ; str w0,[x1] ; nop`, parking the
  return code in PMU INFORM `0x15860818`. That register is untouched by this
  stage, but the physical two-session calibration later proved that entering
  fresh EUB clears the PMU scratch range. It therefore cannot provide the
  required post-EUB readback.

An idea that needs no readback at all: the prompt draws on the panel, so
branching to its drawing code from a checkpoint in the normal-boot path turns
"did it get this far?" into a blue screen appearing or not. One four-byte patch
per checkpoint, one run per question, no console required.

## Open items

### KEY2 UFS trigger result and live boundary trace (2026-10-15 through 2026-10-17)

The custom KEY2-programming image was flashed successfully to BOOTLOADER. The
first UFS trigger proved BootROM loaded its EPBL (`UFSLOAD!`, return 1,
`0xcb000041 -> 0xcb000011`, size `0x3000`) and returned the expected metadata.
The subsequent full 32-byte OTP dump showed KEY2 still entirely zero. A later
read of all three PMU checkpoint words also returned zero. The later
two-session calibration returned `PMU=NO`, so only the KEY2 dump is conclusive
and the zero PMU read does not locate the stop.

An intermediate RAM payload reported boundaries over the still-live EP1
connection:

| record | checkpoint | boundary |
|---|---:|---|
| `UFSPRE!!` | 3 | before the final EPBL handoff preparation; no DRAM access |
| `UFSHAND!` | 4 | immediately before the EPBL handoff |
| `UFWENTR!` | 1 | FWBL1 shim entered |
| `UFWDECR!` | 2 | FWBL1 self-decrypt returned |
| `UFWINIT!` | 5 | early FWBL1 platform initialization returned |
| `UFWLOG1!` | 6 | the FWBL1 `0x3100` checkpoint logger returned |
| `UFWCFG1!` | 7 | core and stack configuration returned |
| `UFWCFG2!` | 8 | secondary configuration returned |
| `UFWEL3!!` | 9 | EL3 initialization returned |
| `UFWMAIN!` | 10 | FWBL1 startup completed and branched to context restore |

An earlier 2026-10-15 image stopped after `UFSPRE!!`; it still accessed
untrained DRAM between `UFSPRE!!` and `UFSHAND!`. After removing those accesses,
the hardware returned all six live records: `UFSLOAD!`, `UFSMETA!`, `UFSPRE!!`,
`UFSHAND!`, `UFWENTR!`, and `UFWDECR!`. This proves the no-DRAM handoff ran, the
FWBL1 shim was entered, and FWBL1 returned from self-decryption. It does not
prove BL2 or u-boot entry. A full KEY2 dump after this run was still all zero,
so the previous late OTP retry did not successfully program the slot.

The final KEY2-only image was then flashed successfully from the absolute path
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/key2_program_chain/sboot.bin`
(SHA-256 `687041e3ccc9ea28eb33b82963ac336fd7e10f6d0df91aba8a77474bc3a5aa92`).
Three subsequent UFS triggers all returned the same six records through
`UFWDECR!`, including the build in which every CM/LDFW initializer result path
calls the OTP stub. The following full-slot dump still reported all 32 KEY2
bytes as zero.

The following instrumentation revision then returned `UFSLOAD!`, `UFSMETA!`,
`UFWENTR!`, `UFWDECR!`, and `UFWMAIN!`; the last marker arrived at 0.576 s.
The omitted intermediate markers do not represent failed initializer calls,
because execution reached the later `UFWMAIN!` site. Static disassembly also
corrected that marker's old description: the replaced instruction at
`0x02026100` is `b 0x0202a9d4`, and `0x0202a9d4` restores `SCR_EL3`, `SPSR_EL3`,
`ELR_EL3`, and the saved register frame before executing `ERET`. The result
therefore proves that FWBL1 completed its startup sequence and reached the
final context restore immediately before BL2. It still does not directly prove
that the processor executed the first BL2 instruction.

That run printed `load return = 0x3000` in the first `UFSLOAD!` record. This is
not a storage-load failure: FWBL1 subsequently executed, and `0x3000` is exactly
the BL1-size field written into the following `UFSMETA!` record. The bounded
send had returned while DWC3 still owned the shared record buffer, allowing the
next record to overwrite the earlier DMA. The current payload makes
`UFSLOAD!` and `UFSMETA!` blocking again, so each transfer completes before the
buffer is reused.

The next physical run confirmed the record-lifetime correction: `UFSLOAD!`
reported return 1, followed by an intact `UFSMETA!`. It returned neither
`UBL2ENT!` nor `UBL2MISS`. The old hook modified BL2's first instruction in
DRAM immediately before ERET, so the missing final record cannot distinguish
an instruction-cache visibility failure from the EP1 endpoint becoming
unavailable after ERET. It is not evidence that FWBL1 regressed or that BL2 was
not entered.

The saved-ELR revision removed the instruction-cache ambiguity: it changed only
the context-frame ELR and left BL2 byte-for-byte intact. Its physical run again
returned only valid `UFSLOAD!` and `UFSMETA!` records. Because the only new
record was attempted after ERET, the result is consistent with EP1 or the
BootROM USB helper becoming unavailable in the restored context. It does not
show whether the transition trampoline ran, and that diagnostic itself may
have interrupted the downstream chain.

The first pre-ERET revision returned `UBL2PRE!` at 0.581 s. It confirmed the
hook ran and that the BL2 base contained the expected `0x14000001`, but reported
zero ELR/SPSR/SCR and current SP `0x02033780`. Disassembly explains the zeros:
at `0x0202a9d8` the stock restore copies the current SP, switches `SPSel` to 1,
and only then reads offsets `0x110`, `0x118`, and `0x120`. The context frame is
therefore based at `SP_EL3`, not at the pre-switch current SP used by
`UBL2PRE!`. The earlier saved-ELR redirect also wrote the wrong stack and never
changed the real ERET target.

The `SP_EL3` revision was then run on hardware. It returned valid `UFSLOAD!`
and `UFSMETA!` records, but no `UBL2CTX!`. Like the post-ERET tests, that
absence cannot distinguish a missing transition from EP1 or the BootROM USB
helper becoming unusable late in FWBL1. A fresh full-slot dump after this run
still showed all 32 KEY2 bytes as zero. A second fresh EUB session showed the
same selector state as before: `SEC0=1`, `SEC1=0x10000006`, predicates
`A=0 B=0 C=0 D=0 E=1 F=0 G=0`, and `PTR_SECUREBOOT_KEY=0x10003000`.
Therefore the latest trigger did not program KEY2 or alter key selection.

The isolated 0x108-byte u-boot reporter was then built, flashed and triggered
twice. Both hardware runs returned intact `UFSLOAD!` and `UFSMETA!` records,
then the EUB USB handle closed. Neither the plain-text banner nor `UBSTAGE!`
returned. This remains inconclusive about BL2 -> u-boot execution because the
reporter depended on the inherited BootROM EP1 helper after the execution
context had changed.

The local Houston checkout already contains commit `fab5783` from
[houston-pub PR #12](https://github.com/halal-beef/houston-pub/pull/12), including
the Exynos9825 same-handle path. The relevant review observation is that a
payload must explicitly reinitialize USB when it expects a new enumeration.
The two early records prove that the same-handle path works before the handoff;
they do not make the old EP1 helper valid at u-boot entry.

The replacement diagnostic preserves the complete engineering u-boot. It
patches only the entry word and a 0x30-byte trampoline in the verified zero
cave at offset `0x17ce00`; the remaining body is byte-identical before the ST2
footer to the `ecdsa_eng` u-boot that already reached Download mode over the
USB-loaded chain. The trampoline writes `UBS1` and `OWN1` to PMU scratch
`0x15860800` and `0x15860804`, clears MINFORM at `0x15860808`, and returns to the original entry
at `0xc9000004`.

This image was flashed successfully and triggered on hardware. The old EUB
handle closed before even `UFSLOAD!` or `UFSMETA!` completed, no replacement
USB device enumerated, and the panel stayed black. This disproves the expected
fresh Download-mode outcome for this revision. It does not show whether the
u-boot trampoline ran: the downstream stage can shut down the inherited DWC3
instance before the two queued early records finish. The first
`tools/run_ubstage_test.sh trace` read returned zero for every PMU scratch word,
but the retention calibration below proves that this readback channel cannot
carry evidence across the required fresh EUB entry.

The two-session calibration was run on hardware. Session 1 wrote `PMC1` and
`PMC2` to PMU scratch plus `IRAMCAL1` and `IRAMCAL2` to iRAM `0x02038800`, and
read all four markers back correctly. In the fresh EUB session, both PMU words
were zero and both iRAM words had unrelated contents. The final result was
`PMU=NO, iRAM=NO`:

```sh
tools/run_ubstage_test.sh calibrate-retention
```

This calibration did not access UFS or issue an OTP command. It left the
currently flashed diagnostic unchanged at
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_test_chain/sboot.bin`.
The exact EUB reentry method clears PMU scratch and overwrites this iRAM area,
so the earlier all-zero `trace` remains inconclusive and neither channel will
be used again as a cross-session oracle. The `trace` action is now retired and
does not ask for another hardware run.

The entry-trampoline control has now been completed. It used the exact
`ecdsa_eng` chain that already reached Samsung Download mode when streamed
over USB. Its u-boot had the original entry word, the `0x17ce00` cave was
empty, and the signature stub at `0x4fc68` was the inert `mov x0,#0; ret`;
there was no OTP command injection. The image written to BOOTLOADER was:

```text
/home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot.bin
```

The subsequent `control-trigger` returned valid `UFSLOAD!` and `UFSMETA!`
records. The UFS loader returned 1, loaded 0x18 sectors, changed boot state
from `0xcb000041` to `0xcb000011`, and reported BL1 size `0x3000` with checksum
`0x20d184e7`. The inherited EUB handle then closed and the screen remained
black. The raw output is `/tmp/exynos9825_ubstage_control.bin`, SHA-256
`fd84b7dab355b81c551fb443332861a02ab2a97d969a7e35716c03a73de7891d`.

This rules out the PMU-writing u-boot entry trampoline as the cause. It does
not prove that u-boot entry was never reached: the visible Download path can
still fail after entry because the UFS path presents different boot and
controller state from the USB-streamed path.

The silent transport control was then run with the same UFS image. Its RAM
payload performed the UFS load and key re-point, then handed off without
sending `UFSLOAD!`, `UFSMETA!`, or any other EP1 record on its success path.
The screen again remained black. This rules out both completed early EP1
transfers as the cause and leaves the UFS execution state or the FWBL1/BL2
handoff as the difference from the proven USB-streamed chain.

The forced-Download discriminator moved the visible proof into the original
u-boot body. The signed image has no entry trampoline and no OTP injection.
Relative to the proven `ecdsa_eng` body, it changes exactly two instructions:

| u-boot offset | replacement | purpose |
|---:|---|---|
| `0x33f0` | `mov w19,#0` | neutralize the stale pre-fork `MAGIC_CODE` |
| `0x38f0` | `mov w0,#4` | replace `bl s5p_check_download` with Download reason 4 |

It was prepared and flashed through the documented manual Odin sequence:

```sh
tools/run_ubstage_test.sh force-download-flash
```

After that screen reaches 100%, manually write exactly:

```sh
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

`tools/run_ubstage_test.sh force-download-trigger` also produced a black
screen. That result did not reach the visible pass condition, but a subsequent
build audit found that it cannot place the stop at the u-boot fork. Both the
plain and silent payloads were still compiled with
`EPBL_COLD_CONTEXT_STAGED`. That macro replaces the EPBL dispatch literal at
`0x02022098`, installs the diagnostic `VBAR_EL3`, reconstructs the cold-path
register state, and enters FWBL1 through `fwbl1_noic_entry`. The entry-marker,
uninstrumented control, silent control, and forced-Download test therefore all
shared the same altered EPBL -> FWBL1 boundary.

The next discriminator removes that shared path. The
`epbl_boot_ufs_native_probe` build keeps only the 0x40-byte cache-safe
relocation stager and the authentic EPBL cache-line mirror. It does not define
`EPBL_CONTEXT_STAGED`, replace the dispatch literal, install an EL3 vector,
enter a FWBL1 shim, or modify a saved exception frame. Immediately before
handoff it disables EL3 I-cache so the EPBL bytes that replaced the payload at
`0x02022000` are fetched from iRAM. It then branches to the original BootROM
helper at `0x0001c9a0` with the original return link `0x00000250`; the helper
enters the authentic EPBL at `0x02022010`, whose FWBL1 prologue restores its
own expected cache state.

The forced-Download image is already expected on UFS at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

Run the RAM-only discriminator with:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-trigger
```

This action writes no UFS partition and requires no Odin step. A fresh
Download/Odin screen reaching 100% proves that the legacy FWBL1 shim caused
the earlier black screens. Another black screen keeps the stop in the native
UFS state/handoff or before u-boot's forced fork; in either case KEY2 must not
be programmed yet.

The current hook performs no DRAM access in that interval. The three stale EUB
values are neutralized later in the flashed u-boot, after BL2 has initialized
DRAM:

| u-boot offset | original operation | replacement |
|---:|---|---|
| `0x33f0` | load the main `MAGIC_CODE` word | `mov w19,#0` |
| `0xa61a4` | load mode word at `0x80000000` | `mov w20,#0` |
| `0xa61b0` | load mode word at `0x80000010` | `mov w19,#0` |

All nine original calls to the replaced `check_signature` routine remain
present. Four additional calls now replace the mutually exclusive CM/LDFW
initializer result diagnostics:

| u-boot offset | initializer result path |
|---:|---|
| `0xa63e4` | no LDFW initialized |
| `0xa6460` | LDFW signature error |
| `0xa64a4` | general nonzero/initialized-count result |
| `0xa64d0` | dump-GPR mode |

Exactly one of these four calls executes per invocation. Each branches to the
verified KEY2-only stub at `0x4fc68`, which passes the embedded 32-byte anchor
to OTP command `0x16`. The original secure-chip-state query at `0xa63e8`
remains intact. The uH-image loader call at `0xb9170` also remains as a later
fallback.

The aligned EL3 exception table remains at `VBAR_EL3 = 0x02025800`, with the
required vector entries reserved at `0x02025800` and `0x02025a00`.

The older best-effort PMU markers remain available:

| register | marker | boundary |
|---|---:|---|
| `0x15860800` | `0x31534655` (`UFS1`) | immediately before EPBL handoff |
| `0x15860804` | `0x31425746` (`FWB1`) | FWBL1 shim entered |
| `0x15860810` | `0x31445746` (`FWD1`) | FWBL1 self-decrypt returned |

The complete u-boot Download-mode reporter was built, flashed, and produced
the black-screen result described above. Its build and flash procedure is:

```sh
tools/run_ubstage_test.sh build
tools/run_ubstage_test.sh flash
```

Wait for the Download/Odin screen to reach 100%, then flash exactly:

```sh
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_test_chain/sboot.bin
```

Then run:

```sh
tools/run_ubstage_test.sh trigger
```

The diagnostic contains no injected OTP call. After `trigger`, the old EUB
handle is expected to close; success is the Download/Odin screen reappearing
and reaching 100%. After the result, restore the programming image from the
exact path
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/key2_program_chain/sboot.bin`
before another KEY2 attempt. Both scripts print the complete absolute path and
leave Odin invocation manual. The current artifacts are:

```text
build/epbl_boot_ufs_plain_probe.bin       0xd80  46be69585bc7252ba161d2d8b040e82c9873156acbbf3f3922a194bdc8c297dd
build/epbl_boot_ufs_silent_probe.bin      0xc70  be4450ef0c5caad3a018e586ec4f3d22ab5af250e4c6b2eca6d809a5ad871fc8
build/epbl_boot_ufs_native_probe.bin      0x648  226b5cc6b5097b3a2cc3bee4137d64fab34214b1d26c49614ddef90a32350f16
build/ubstage_forced_download_chain/u-boot.base.bin 0x180000  582f7d626d0686c71bc07abfe5a712f533c7e0de3e3b3062d23bdc708ad421fd
build/ubstage_forced_download_chain/sboot/u-boot.bin 0x180000  9749c7781e503e6ea0a80199d3e8667ae636c9102dc9fec17ce21318f07e4d3d
build/ubstage_forced_download_chain/sboot.bin 0x400000  98c788e11d89b367bed2d9423f3b3de2d75b494662f4a50912d22937ef2ab257
build/ubstage_download_marker.bin         0x30  e3e416aa397d2eb48e6e1ab5716029b7dbaf3d1fbdd13dda9cbe210848bba4ae
build/ubstage_test_chain/u-boot.base.bin  0x180000  582f7d626d0686c71bc07abfe5a712f533c7e0de3e3b3062d23bdc708ad421fd
build/ubstage_test_chain/sboot/u-boot.bin 0x180000  a5ea4e6443afbccad070e5ecf32c1534ec7226f9b157285c325802e1bbb71476
build/ubstage_test_chain/sboot.bin        0x400000  c15c8563a57c4ed9cd0c6291ad4ca7c866b43a0e3a0f18efa525b071244d485a
/home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot/u-boot.bin  0x180000  5706a79e6573666c77f0adc248283a086683fb9d1fc4d3d22412d6250aa817d7
/home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot.bin         0x400000  5edf79c327ebf330d74cb30243c4ad5094d1bb5b312d7630a4d4c0c222d696e0
build/key2_program_chain/sboot/u-boot.bin  7d7609efbb596bba3a0c2f97e0daa081731a56048b3719e79f3ca23cbfb53862
build/key2_program_chain/sboot.bin         687041e3ccc9ea28eb33b82963ac336fd7e10f6d0df91aba8a77474bc3a5aa92
```

- Persistent UFS boot (no USB payload) requires the OTP fuse; the bypass does not
  persist across reboot.
- Booting into Android over USB: the fork is located and both levers are built
  (`epbl_minform_normal_probe` with a stock sboot, `epbl_android_boot_probe` with
  `--normal-boot`), but neither has been run on hardware.
- No verification vulnerability found in the BootROM/EPBL/monitor verify path; the
  fuse is the only known route to a persistent custom trusted key.

## 2026-10-17: native handoff also stayed black

The physical `native-trigger` run used the forced-Download image already on
UFS and the clean native payload:

```text
BOOTLOADER image: /home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
payload:          /home/chanz22/Documents/GitHub/exynos9825-payloads/build/epbl_boot_ufs_native_probe.bin
payload SHA-256:  226b5cc6b5097b3a2cc3bee4137d64fab34214b1d26c49614ddef90a32350f16
```

The EUB USB device disappeared immediately after the native handoff, no probe
record arrived, and the screen stayed black. This run contained none of the
old EPBL dispatch redirect, diagnostic VBAR, `fwbl1_noic_entry`, or saved-frame
changes. It therefore rules out that shim as the sole cause. The remaining
stop is in the native UFS state/handoff or before the forced u-boot Download
fork.

The host messages from that run were misleading:

```text
EP1 IN reader stopped: [Errno 19] No such device
error: received no probe records
```

`Errno 19` is PyUSB reporting that the BootROM-owned EUB USB device left the
bus after control had already been handed away. The native payload deliberately
sent no record, so the old host code then converted the empty record list into
an error. Neither message executes on the board and neither can cause the black
screen. `boot_nonsecure_probe.py` now has `--allow-no-records`; silent actions
use it, remove any stale capture first, describe the expected disconnect, and
return success with no file to decode.

Houston PR #12 does not identify a different failure here. Its Exynos9825
handler documents that this SoC does not re-enumerate immediately after ACE,
so it deliberately keeps using the original device handle while streaming the
Binary 9 stages. `boot_nonsecure_probe.py` already follows that contract: it
calls `overwrite_iram()` and continues on the same claimed handle. The
`ENODEV` in `native-trigger` occurs later, after the UFS handoff, when there are
no follow-up USB stages to send. The PR supports treating a released handle as
a transport boundary; it does not explain the board-side black screen.

The next RAM-only discriminator is:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-diagnose
```

It does not write UFS and does not require Odin. It emits one completed
`EUNPRE!!` record immediately before I-cache is disabled and the authentic
EPBL is entered. That record contains both boot-state values, the BootROM key
selector and post-load returns, `0x15860990`, `PTR_IS_SECUREBOOT`,
`0x02020128`, `SCTLR_EL3`, and SP.

For this diagnostic only, the EPBL return link points to a relocated sentinel.
A successful EPBL/FWBL1/BL2 path never returns there. If EPBL unwinds, the
sentinel emits `EUNRET!!` with the return value and post-return iRAM state,
then halts. This avoids executing BootROM address `0x250`, whose epilogue would
otherwise use the Houston callback's stack and hide the original failure.

Interpret the result as follows:

- `EUNPRE!!` plus disconnect and no `EUNRET!!`: the old BootROM USB instance
  left after handoff; EPBL did not return while that channel remained usable.
- `EUNRET!!`: the authentic EPBL returned and its captured state localizes the
  failure.
- no `EUNPRE!!`: execution stopped before the final snapshot, or EP1 could not
  complete that transfer.

The diagnostic artifact is:

```text
build/epbl_boot_ufs_native_diag_probe.bin  0x7d0  14ca3a60dc43a04891873635f126ec12129ca475365bfd20b4bde92a9535c36d
```

KEY2 programming remains paused until this boundary is resolved.

## 2026-10-17: PR #12 verified; move the record to the UFS-load boundary

The physical `native-diagnose` run returned no `EUNPRE!!` or `EUNRET!!`
record and the display remained black. This does not show that the host opened
a replacement USB device. The exact Houston checkout used by the command is:

```text
/home/chanz22/Documents/GitHub/houston-pub
HEAD fab5783854d1b363511bddcfc59c838e06bf0d61 (Exynos9825 Support)
```

That is the commit carried by Houston PR #12. Its `houston.py` selects
`modules/exynos9825.py` for product `Exynos9820\0` and does not call
`find_device(True)` after `overwrite_iram()`. The local
`boot_nonsecure_probe.py` follows the same rule: one device is found and
claimed before ACE, and that exact object is used for every later EP1/EP2
operation. It now checks that the PR #12 handler is present and prints the
active no-re-enumeration policy in every Exynos9825 hardware log.

The missing `EUNPRE!!` remains ambiguous because that record was attempted
only after `0xcc68`, the key selector, the post-load verifier and the final
entry preparation. The next RAM-only test moves the observable boundary back
to the return from the BootROM storage loader:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-load-diagnose
```

It does not write UFS and does not require Odin. The UFS image expected by the
test is printed explicitly as:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

The payload sends the existing blocking `UFSLOAD!` and `UFSMETA!` records
immediately after `0xcc68` returns success, then continues through the clean
native handoff. It contains no diagnostic VBAR, FWBL1 shim, dispatch redirect,
saved-context change, or EPBL-return sentinel. Both records prove that the
original PR #12 USB handle survived ACE and that the UFS load completed. No
record localizes the loss to `0xcc68` or its EP1 side effects, before the later
selector/post-load preparation.

The validated artifact is:

```text
build/epbl_boot_ufs_native_load_diag_probe.bin  0x748  9e192f6c211069f13c5c91e73b094e8ae3c08c8b00d91dcd189318735247f9c6
```

### Hardware result

The hardware returned both records on the original PR #12 USB handle:

```text
UFSLOAD!: load return 1, 0xcb000041 -> 0xcb000011, 0x18 sectors
UFSMETA!: BL1 size 0x3000, checksum 0xdc47f7c9, CurrentEL 0xc
```

This proves that ACE handle retention works, the storage device was selected,
the complete EPBL was loaded, and `0xcc68` returned success. The following
`ENODEV` happened only after both blocking transfers completed, so it cannot
explain or cause the board-side failure. The words at `0x02020120/124/128`
remain unidentified on Exynos9825 and are not used as a pass/fail condition.

The next RAM-only discriminator is:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-postload-diagnose
```

It remains silent through `0xcc68` and the repeated key selector, redirects
the verifier to the custom iRAM key, and emits exactly one `EUNPOST!` record
immediately after `0x5b58` returns. This is before the final `0x18768` timing
copy and `0x16a10` boot-flag call. A successful record proves the selector and
custom-key BL1 verification and moves the missing late-EP1 boundary into those
two final preparation calls. No record places the loss inside the selector or
`0x5b58` interval.

The expected UFS image remains:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

The validated payload is:

```text
build/epbl_boot_ufs_native_postload_diag_probe.bin  0x6f8  91994f4c3fbd223a8624f3ae79d93156d2193721a69e9808d8e7d1a1032e1605
```

### Hardware result: selector and custom-key verification pass

The hardware returned `EUNPOST!` on the original PR #12 handle:

```text
key selector return  = 1
post-load verifier   = 1
verification key ptr = 0x020254a8
post-load state      = 0x020254ac
timing words         = 0x0000041a -> 0x00000432
SEC0                 = 1
boot state           = 0xcb000011
CurrentEL            = 0xc
```

This proves that the repeated selector completed, `0x5b58` accepted the UFS
EPBL with the custom key in iRAM, and execution remained at EL3. The following
`EIO` happened after the completed record and therefore does not invalidate
that result. The custom-key verifier and UFS loader are no longer candidates
for the black-screen cause.

The next RAM-only discriminator repeats the final native snapshot now that
the PR #12 same-handle path is physically confirmed:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-diagnose
```

It requires no Odin step and expects the existing image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

`EUNPRE!!` proves that the final `0x18768` timing copy, the
`0x16a10(0, 0x00800000)` boot-flag update, and the immutable EPBL entry checks
all completed. `EUNRET!!` is emitted only if the authentic EPBL later returns
to the diagnostic sentinel. The validated diagnostic is:

```text
build/epbl_boot_ufs_native_diag_probe.bin  0x7d0  14ca3a60dc43a04891873635f126ec12129ca475365bfd20b4bde92a9535c36d
```

### Hardware result: final combined snapshot is still missing

The repeated `native-diagnose` run used the confirmed PR #12 same-handle
policy but returned neither `EUNPRE!!` nor `EUNRET!!`; the host observed
`ENODEV`. Together with the preceding successful `EUNPOST!`, this confines
the missing observable boundary to the code after `0x5b58` and before the
final pre-entry transfer.

The next RAM-only test places one record immediately after `0x18768` and
before `0x16a10`:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-timing-diagnose
```

It requires no Odin step and expects the existing image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

`EUNTIME!` proves that the stock timing helper returned while the custom key,
authenticated EPBL entry and dispatch literal remained intact. No record after
the proven `EUNPOST!` confines the loss to `0x18768` or its immediate effect on
EP1. The validated artifact is:

```text
build/epbl_boot_ufs_native_timing_diag_probe.bin  0x6e0  035bdda117ced87dff9ca1ebc2bff059f807199b09931132151e8ed7da28d7ca
```

### Hardware result: entry timing passes

The hardware returned `EUNTIME!` before the old EUB device disconnected:

```text
key selector return   = 1
post-load verifier    = 1
entry timing delta    = 0x000003ce
boot flags before set = 0x00300edf
verification key ptr  = 0x020254a8
EPBL dispatch literal = 0x02020128
EPBL entry qword      = 0x1400000014000002
SCTLR_EL3             = 0x00c51838
CurrentEL             = 0xc
```

This proves that `0x18768` returned and that EP1 remained usable afterward.
The custom verification key, authentic dispatch pointer, entry instructions,
EL3 state and pre-update flags were all intact. The following `ENODEV` happened
after the complete record and does not invalidate this boundary.

The next RAM-only test moves the record past only the remaining stock helper,
`0x16a10(0, 0x00800000)`:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-flag-diagnose
```

It requires no Odin step and expects the unchanged UFS image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

`EUNFLAG!` proves that `0x16a10` returned, bit `0x00800000` was set and every
input for the subsequent native entry validation remained intact. The expected
flag transition is `0x00300edf -> 0x00b00edf`. If no `EUNFLAG!` follows the
proven `EUNTIME!`, execution or EP1 availability was lost in `0x16a10` or as
its immediate side effect. The validated artifact is:

```text
build/epbl_boot_ufs_native_flag_diag_probe.bin  0x6e0  12bbac2dadc965dc827c1525d394d2e5384685613d8450e4f2361648d4f05821
```

### Hardware result: final boot-flag preparation passes

The hardware returned a complete `EUNFLAG!` record:

```text
key selector return   = 1
post-load verifier    = 1
entry timing delta    = 0x00000426
boot flags after set  = 0x00b00edf
verification key ptr  = 0x020254a8
EPBL dispatch literal = 0x02020128
EPBL entry/hook       = 0x14000002 / 0x580002d4
SCTLR_EL3             = 0x00c51838
CurrentEL             = 0xc
```

This proves that `0x16a10(0, 0x00800000)` returned, the final flag is present,
and every value consumed by the native entry validation is intact. The host
reported `EIO` only after receiving the complete record, so it does not
invalidate the result. The entire stock preparation sequence before the EPBL
handoff is now physically proven.

The strongest remaining hypothesis is the EPBL's own first warm/cold choice.
It reads `0x15860990`; value 1 takes the warm branch and derives its target
from residual state at `0x02020128`, while another value follows the cold
loader. An earlier hardware capture observed value 1 with stale dispatch
state, but the current native path has not yet returned those two values.

The next RAM-only command records both values and forces only the verified
conditional branch at `0x02022028` to the authentic cold path:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-cold-diagnose
```

It requires no Odin step and expects the unchanged UFS image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

`EUNCOLD!` reports the original gate, original dispatch state, final flags,
and the verified instruction change `0x54000041 -> 0x14000002`. After that
completed record the payload disables I-cache and enters BootROM helper
`0x1c9a0` with the native return link `0x250`. A new Download/Odin screen at
100% proves that stale warm-state dispatch caused the black screen. A complete
`EUNCOLD!` followed by another black screen moves the stop downstream of the
forced cold choice.

The validated artifact is:

```text
build/epbl_boot_ufs_native_cold_diag_probe.bin  0x6f8  50096841987fef5562c55b5aca328fef53d916b3e8824b572455bd7eeefcc2b4
```

### Hardware result: the warm-state read boundary loses the old USB channel

The `native-cold-diagnose` run returned no `EUNCOLD!` or failure record. The
host saw `ENODEV` after the handoff attempt. This does not prove the value of
the gate or that the branch patch ran, because the record was never emitted.

The result is nevertheless a narrow discriminator. `EUNFLAG!` completed at
the immediately preceding boundary, while both missing records, `EUNPRE!!`
and `EUNCOLD!`, first add a read from `0x15860990`. An asynchronous USB loss
cannot yet be excluded, but directly reading that warm-state register is now
the only common new board-side operation before both missing records.

The next RAM-only attempt removes that operation from both the diagnostic and
the EPBL itself:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-force-cold
```

It verifies the EPBL instruction `0x580002d4` at `0x02022018` and replaces
only that RAM word with `0x14000006`, a direct branch to the original cold
loader at `0x02022030`. This bypasses the load from `0x15860990`, its compare,
and the residual warm dispatch while retaining the complete authentic cold
loader. `EUNFORC!` reports the installed override before the native handoff.

No Odin step is involved. The unchanged image expected on UFS is:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

The validated artifact is:

```text
build/epbl_boot_ufs_native_force_cold_probe.bin  0x6e8  8178bae0b8eff2e0748831c2fa1b75d5213a132065aa22105dd906aeea25b596
```

`EUNFORC!` plus a Download/Odin screen at 100% proves that the warm-state gate
sequence caused the black screen. A complete `EUNFORC!` followed by a black
screen proves that the MMIO gate sequence was skipped and moves the stop into
the original cold loader or a later stage.

### Hardware result: force-cold also returned nothing, so the boundary is positional

The `native-force-cold` run returned no `EUNFORC!` and no `EUNPFAIL`; the host
saw `[Errno 19] No such device` and the panel stayed black with no Download
screen.

That falsifies the warm-state hypothesis. `EUNFORC!` reads neither
`0x15860990` nor `0x02020128`, and the channel still closed before its single
record. Laying the five native records side by side leaves no operation that
separates the ones that arrived from the ones that did not:

| record | reads `0x15860990` | writes the loaded EPBL | source line | arrived |
|---|:-:|:-:|---:|:-:|
| `EUNTIME!` | no | no | after `0x18768` | yes |
| `EUNFLAG!` | no | no | after `0x16a10` | yes |
| *(native entry validation)* | — | — | — | — |
| `EUNCOLD!` | yes | yes | after validation | no |
| `EUNFORC!` | **no** | yes | after validation | no |
| `EUNPRE!!` | yes | **no** | after validation | no |

Each candidate operation on its own "explains" the loss, which means neither
is established: every bisect so far moved the operation and the position in
the same build. The validation block between the two groups is not the cause
either, because `EUNFLAG!` already reports the same four words that block
reads, all with their expected values.

Two static checks were made before proposing another run, and both came back
negative. The payload is linked at `0x02022000` and relocates to
`PROBE_RELOCATION_ADDRESS = 0x02025000`, while the loaded EPBL occupies
`0x02022000`–`0x02025000`: adjacent, not overlapping. And `EPBL_DISABLE_ICACHE`
clears `SCTLR_EL3.I` after every record block, which `EUNFLAG!`'s reported
`SCTLR_EL3=0x00c51838` (I set) confirms.

### The three-position measurement

`EPBL_UFS_NATIVE_TRIPLE` emits one record shape, unchanged, at four points:

| record | position | reads `0x15860990` / `0x02020128` | previously |
|---|---|:-:|---|
| `EUN3REC0` | after the `0x18768` entry-timing helper | **no** | baseline |
| `EUN3REC1` | after the `0x18768` entry-timing helper | yes | `EUNTIME!` arrived here |
| `EUN3REC2` | after the `0x16a10` boot-flag helper | yes | `EUNFLAG!` arrived here |
| `EUN3REC3` | after the native entry validation | yes | three records lost here |

`EUN3REC0` is what makes the measurement decidable. Without it, a run in which
the suspect reads are themselves what closes the channel would return nothing,
and would be indistinguishable from a run that failed upstream of everything
measured. With it, position 0 succeeding and position 1 failing isolates the
reads directly.

None of the four writes anything: the loaded EPBL stays byte-for-byte
authentic and is entered through the stock helper at `0x1c9a0` with
`LR=0x250`. `check_native_ufs_payload.py --triple-records` enforces the
read-only property structurally — it resolves every `ldr xN, <literal>` whose
literal falls inside the loaded EPBL and fails if anything stores through that
register before it is reloaded.

How the outcomes read:

| records received | conclusion |
|---|---|
| none | upstream of everything measured, or an unreliable channel; the `EUNTIME!` position worked before, so repeat once |
| 0 | the reads themselves close the channel |
| 0, 1 | the reads are harmless; something from the boot-flag call onward kills every later send |
| 0, 1, 2 | the boundary is purely positional, after the entry validation |
| all four | no operation is responsible; the earlier losses were nondeterministic |

Every outcome that includes record 1 also yields the warm/cold gate value,
which no run has returned yet.

Two builds exist because the board's BOOTLOADER content decides which one
applies:

```sh
tools/run_ubstage_test.sh native-triple-stock   # stock Samsung sboot on UFS
tools/run_ubstage_test.sh native-triple         # resigned chain on UFS
```

The stock variant drops `EPBL_CUSTOM_KEY`, so `PTR_SECUREBOOT_KEY` keeps the
pointer the BootROM selector chose and `0x5b58` verifies Samsung's image
against Samsung's key: a fully stock trust path.

For that variant **the screen is the stronger signal, and it is independent of
the records**. Stock u-boot carries none of the patches the resigned chain
needed against stale EUB state — the `0x33f0` `MAGIC_CODE` read and the
`0xa61a4`/`0xa61b0` LDFW mode reads — and it still runs `s5p_check_download`,
so a successful handoff may land in Download mode, the USB RECOVERY prompt, a
Samsung logo or Android. *Any* visible screen proves the instrumented native
handoff reached u-boot, which moves the whole problem into the resigned chain
regardless of what the records say. A black screen means the handoff fails
even with Samsung's own image and Samsung's own key.

The EPBL it validates against is the first `0x3000` bytes of the stock
`sboot.bin`, byte-identical to every resigned chain's EPBL except the cleared
header checksum and the ST1/ST2 signature, neither of which the payload reads.

Both are RAM-only: no Odin step, no partition write, no OTP command.

| build | size | sha256 |
|---|---:|---|
| `build/epbl_boot_ufs_native_triple_stock_probe.bin` | `0x868` | `1fa9aac6969da3dc654f1d424c69328f3b3b1d0cba1c9b833be28348382b6cce` |
| `build/epbl_boot_ufs_native_triple_probe.bin` | `0x8a8` | `5fcd6c35f4dc60fe1971a5cbc1d1daeeb18c9bb37b5346c19642a49dce5fdc81` |

### Hardware result: the native handoff reaches u-boot, and missing records mean nothing

`native-triple-stock` was run with the stock Samsung sboot on BOOTLOADER.
`EUN3REC0`, `EUN3REC1` and `EUN3REC2` all arrived at 0.038 s; `EUN3REC3` did
not, and the host saw `ENODEV`. **The panel then showed the bootloader's
charging screen** (battery connected, USB cable attached).

That screen is the result. A visible screen requires the display to be
initialized, which happens no earlier than u-boot, so the instrumented native
UFS handoff carries EPBL, FWBL1, BL2 and u-boot to completion. The handoff
mechanism is not what produced any of the earlier black screens.

Two conclusions follow, and the second one is retroactive:

1. **The record pattern of a successful boot is identical to the pattern that
   was read as failure.** The resigned-chain runs delivered `EUNTIME!` and
   `EUNFLAG!` — positions 1 and 2 — and lost everything after the entry
   validation. This run delivered exactly positions 0, 1 and 2, lost position
   3, and booted. Record presence therefore carries no information about
   whether the chain continues, and every conclusion in the sections above
   that was drawn from a missing record ("the stop is at this boundary", "the
   warm-state read is the narrow boundary") is unsupported. EP1 simply stops
   being usable part-way through the final preparation, on a successful boot
   as much as on a failed one.
2. **The warm/cold question was chasing nothing.** `0x15860990` reads
   `0x00000000`, so the EPBL takes its cold path natively; there was never a
   warm branch to force. `0x02020128` holds `0x7466ecb3`, residual garbage
   that the cold path does not consult. `native-cold-diagnose` and
   `native-force-cold` were both forcing a path the EPBL was already taking.

Everything else matches the resigned runs value for value: key-selector return
1, verifier return 1, boot flags `0x00300edf` before the `0x16a10` call and
`0x00b00edf` after it, EPBL entry/gate-load `0x14000002`/`0x580002d4`, gate
branch `0x54000041`, dispatch literal `0x02020128`, `SCTLR_EL3=0x00c51838`,
`CurrentEL=0xc`. Nothing the payload can observe differs between the chain
that boots and the chain that does not.

One decoder defect was found and fixed by this run: positions 0 and 1 execute
before `0x16a10`, so requiring the `0x00800000` boot flag marked `EUN3REC1`
FAIL although the record was correct. The flag is now required only at
positions 2 and 3.

### The remaining difference is the resigned chain, and the screen is the oracle

Since the handoff is proven with Samsung's image and Samsung's key, the black
screens belong to the resigned chain or to the custom-key redirect. The next
measurement is the same payload with `EPBL_CUSTOM_KEY` restored, against the
resigned chain on BOOTLOADER:

```sh
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
tools/run_ubstage_test.sh native-triple
```

Read the screen, not the records. That chain forces Download reason 4, so a
Download/Odin screen means the resigned chain executes u-boot and the problem
is narrowed to what the custom chain does afterwards; a black screen under the
same battery and cable conditions as this run isolates the failure to the
resigned stages themselves.

Before trusting any comparison, confirm one thing about the earlier runs: this
one had the battery connected and the cable attached, which is what produces
the charging screen. If the earlier `force-download-trigger`, `native-trigger`
and `native-*-diagnose` runs were performed without the battery, their "black
screen" may never have been a boot failure at all.

### The A/B is closed: the resigned chain is the cause

The battery was connected on every native run, so the earlier black screens
were genuine failures and the comparison is sound:

| run | payload | UFS image | key | screen |
|---|---|---|---|---|
| `native-trigger` | `epbl_boot_ufs_native_probe` | `ubstage_forced_download_chain` | custom redirect | black |
| `native-triple-stock` | `epbl_boot_ufs_native_triple_stock_probe` | stock `sboot.bin` | stock (no redirect) | charging screen |

Both use the same clean native handoff: no diagnostic VBAR, no dispatch-literal
replacement, no FWBL1 shim, no saved-context change, entry through `0x1c9a0`
with `LR=0x250`. The only variables left are the image on BOOTLOADER and the
`PTR_SECUREBOOT_KEY` redirect. No further hardware run is needed to place the
failure: it is in the resigned chain or in the redirect.

The charging screen is the expected u-boot behaviour for this entry method —
EUB means USB power with no power-key press, so u-boot picks low-power
charging rather than a normal boot. It proves u-boot ran and drove the panel.
It does not test whether Android boots.

### Lead: the EPBL verifies the next stage itself, through a context pointer

Static reading of the stock EPBL (`build/stock_epbl.bin`, the first `0x3000`
bytes of `sboot.bin`, disassembled at `0x02022000`):

```text
0x02022010  b 0x02022018
0x02022018  ldr x20, [0x02022070 -> 0x15860990]   ; warm/cold gate, reads 0
0x02022028  b.ne 0x02022030                        ; cold path taken
0x02022054  b 0x02022df8                           ; cold entry

0x02022df8  w22 = 0x020200a8                       ; PTR_IS_SECUREBOOT
0x02022e0c  ldr w8,[x22]; blr x8  -> w19 = is_secure_boot()
...
0x02022e78  mov w0,w19; bl 0x020231bc              ; stage verification

0x020231bc  if w0 != 0:  0x0202323c() && 0x02023778()   ; secure boot on
            else:        0x02022240()

0x0202323c  blr [0x020200d8]      ; ROM 0x17cd0 = *(u32*)0x02020030, BL1 size
            w1 = 0x020216d0 + that size
            bl 0x020238a8(w0=1, x1=ctx, x2=image, w3=len-0x200,
                          x4=image+len-0x200, w5=0x200)

0x020238a8  ldr w12, [x1, #0x478]   ; function pointer
            add x2, x1, #0x5c       ; key material
            mov w3, #0x20c          ; 0x20c bytes of it
            br  x12
```

So the EPBL does not reuse the BootROM's `PTR_SECUREBOOT_KEY` path for the
next stage. It verifies through a pointer and a `0x20c`-byte key taken from a
context structure, with a `0x200`-byte footer. That is a second trust anchor,
separate from the one our payload redirects, and it is the obvious candidate
for a chain that passes BootROM verification and then stops dead.

Open: the context base. `0x020216d0 + 0x3000` lands at EPBL blob offset
`0x26d0`, but `[+0x478]` and `[+0x484]` read zero there in both the stock and
the resigned EPBL, so that base is wrong or the size used is not the `0x3000`
in `0x02020030` at that moment. Resolving it is the next step, and it is
static work: no hardware, no flashing.

For reference, the resigned EPBL differs from stock only in the cleared header
checksum at `0x04` and fifteen ranges from `0x26d8` to `0x2e87` — the
signature and key material the signer rewrites. The code is byte-identical.

### The EPBL's own trust anchor, mapped

The context base is `image_end - 0x930`: `0x020216d0` is `0x02022000 - 0x930`,
so `0x020216d0 + *(0x02020030)` is the EPBL's load base plus its size minus
`0x930`. With the measured `0x3000`, that is `0x020246d0` — blob offset
`0x26d0`. There are two consecutive `0x20c`-byte key contexts:

| context | blob offset | key at `+0x70` | holds |
|---|---:|---:|---|
| ctx[0] | `0x26d0` | `0x2740` | ST2-T public key |
| ctx[1] | `0x28dc` | `0x294c` | ST2-R public key |

Matched exactly against `keys/4/st2t.pem` and `keys/4/st2r.pem`:

```text
slot 0x2740 == st2t pubkey  21010375c300ea56...0ca4f08d
slot 0x294c == st2r pubkey  cdcc93e17e0a214d...e53fb52f
```

Stock has the *same* key in both slots; our chain has two distinct ones. That
is the signer working as designed, not a defect — `keys/4/` holds three EC
keys (`st1.pem`, `st2r.pem`, `st2t.pem`) and Samsung simply reuses one value.

`sign_type` is `4` for `fwbl1`, `bl2`, `u-boot`, `el3_mon` and
`secure_payload`, identical in stock and resigned. `0x020238a8` computes
`7 >> sign_type`, so `4` clears bit 0 and every downstream stage takes the
second verify entry at `[ctx+0x484]` with the extra `0x44`-byte argument,
never the `[ctx+0x478]` one. Both pointers read zero in the image, so the
vtable is installed at runtime by one of the EPBL's init calls
(`0x2023150`, `0x20221d0`, `0x20221e4`, `0x2023348`).

So the EPBL carries our keys and dispatches to the right verifier. Two
candidate defects are eliminated: the keys are present, and `sign_type` is
unchanged.

**Slot selection is not eliminated, and stock cannot eliminate it.** Stock
holds the same value in both slots, so a stock boot passes whichever slot the
EPBL reads. Our chain holds two distinct keys. If `fwbl1` is signed with one
and the EPBL verifies against the other, only the resigned chain fails — which
is exactly the observed pattern.

What remains unchecked is the one thing that has already produced two latent
bricks in this project: whether our ST2 signatures verify under *the device's*
scheme rather than under our own `verify_9825.py`. The decisive offline test
is to reproduce Samsung's verification — take the stock `fwbl1`, its `0x200`
footer and the `0x44`-byte trailer the second entry is handed, and verify it
against the stock ST2 key at EPBL offset `0x2740` with plain ECDSA P-384.
Once that reproduces, applying the identical procedure to the resigned
`fwbl1` and our key settles it with no hardware.

### ST2 verification with our keys is hardware-proven, so the signer is not the bug

The ST1 block sits at ctx[0] and is fully legible:

```text
0x26d0  00000005  "SLSI"  <key fingerprint>  00000000
0x26e0  rb_count=9  sign_type=4  key_type=0  key_index=0
0x2740  ST2-T X (48 bytes in a 0x44 field)
0x2784  ST2-T Y
0x28dc  ctx[1], same layout, ST2-T -> ST2-R at 0x294c
```

The `0x44`-byte field is now explained: each P-384 coordinate occupies 48
bytes inside a 68-byte slot, which is the same `0x44` the second verify entry
is handed for the signature halves (`136 = 2 * 68` in `ST2ECDSA`). The only
word the signer changes in the ST1 header is the fingerprint at `+0x08`
(`0x64dda3ea` stock, `0x6ad34a3f` resigned), which it recomputes.

Every ST2 footer carries `rb_count=9, sign_type=4, key_type=0,
key_index=0x31fb208f`, byte-identical between stock and resigned. `key_type=0`
is `st2t`, matching `scripts/sign.py` (`0 = tee, 1 = ree`, default 0) and
`scripts/s5e9825.py`, which marks no stage `ree`. The EPBL reads ctx[0], which
holds `st2t`. **Slot selection is correct**, and the retained Samsung
`key_index` is not matched against anything in the EPBL — `0x31fb208f` appears
nowhere in either image.

Decisively: the USB run that reached Download mode used
`epbl_custom_key_efuse_probe`, built with only `-DEPBL_COLD_CONTEXT_STAGED
-DEPBL_DISABLE_ICACHE -DEPBL_CUSTOM_KEY -DEPBL_CUSTOM_KEY_EFUSE`. It does
**not** define `EPBL_SBOOT_NOVERIFY`, and the literal `0x020200a8` does not
appear in the built binary at all, so `PTR_IS_SECUREBOOT` was untouched.

And that pointer really does select the secure branch here.
`[0x020200a8]` is ROM `0x58b4`, which tail-branches to `0x16eb4`:

```text
16eb4  x0 = 0x02020070          ; boot flags
16ebc  ldr w0,[x0]; and w0,w0,#4
16ec8  b.eq -> return 0 ; else return 1
```

`is_secure_boot()` is simply `boot_flags & 4`. The triple-record run measured
those flags directly: `0x00300edf` and `0x00b00edf`, both with bit 2 set. So
the function returns 1, the EPBL takes its secure branch, and the USB run
loaded and ran our resigned `fwbl1`, `bl2` and `u-boot` through it. **Our ST2
signatures verify on hardware, under the device's own scheme, with our keys.**

The failing intersection is therefore UFS **and** the resigned image — not
the `PTR_SECUREBOOT_KEY` redirect, which is also ruled out: the stock EPBL
disassembly contains no read of `0x0202006c` anywhere. Only the BootROM's own
verifier consults it, and that already returned 1. The EPBL branches on the
boot device at the start of its cold path:

```text
0x2022e18  bl 0x202237c    ; *(0x02020064) & 0xf        -> w20
0x2022e20  bl 0x202234c    ; decoded boot device nibble -> w0
0x2022e24  cmp w0, #4      ; 4 = USB
0x2022e28  b.ne 0x2022e30
0x2022e2c  bl 0x2022fe8    ; USB-only initialization, skipped for storage
0x2022e40  bl 0x2022430    ; load+verify the next stage
0x2022e48  b.eq 0x2022e90  ; on failure, 0x2022470 then the device-retry loop
```

Our native payload sets the nibble to 1 (storage) before calling `0xcc68`, so
the EPBL takes the storage path — the one the USB run never exercised with
our image, and the one the stock run exercised successfully with Samsung's.
That intersection is where the next analysis goes.


### Image layout and the one anomaly found

The assembled resigned `sboot.bin` was checked against the stock one stage by
stage. Total size `0x400000` in both, every stage at the stock offset and
size, and every stage's bytes equal to its split file:

```text
epbl 0x0  fwbl1 0x3000  bl2 0x16000  pad 0x68000
u-boot 0xa4000  el3_mon 0x224000  secure_payload 0x264000  tail 0x364000
```

One region does differ from its split file, and it is the only part of the
assembled image the signer rewrites outside a stage: `0x364000`, the start of
`tail.bin`. It holds Samsung's signer metadata and a matching ST2 footer:

```text
0x364000  "SignerVer03"  "69546063R"  "N975FXXS9HWHA"
0x364100  rb_count=9  sign_type=4  key_type=0  key_index=0x31fb208f
0x364124  signature material, re-signed by build.py (468 bytes changed)
```

Re-signing it is correct. The anomaly is at the end of that block: stock
carries `61bff182 1998d774 56387edc 54cea393` at `0x364300..0x36430f` and the
resigned image leaves those sixteen bytes zero. Whether anything in the boot
chain reads that block is unknown — it sits past `secure_payload` and looks
like Odin/model-binding metadata rather than something the EPBL consults — so
this is recorded as an observation, not a diagnosis.

### Where this leaves the next hardware run

Static work has cleared the signer, the key slots, `sign_type`, the key
redirect and the image layout. The remaining hypothesis needs the board, and
the right image for it is **`ecdsa_eng/sboot.bin`** — the exact image proven
over USB — not the forced-download chain. That chain has never been run over
UFS with the clean native handoff: the one `ecdsa_eng`-over-UFS attempt on
record used `EPBL_COLD_CONTEXT_STAGED`, the FWBL1 shim that stock-native has
now shown was never needed.

```sh
sudo odin flash --BOOTLOADER /home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot.bin
tools/run_ubstage_test.sh native-triple
```

Any visible screen means the delta is in the forced-download u-boot patches.
A black screen, with the payload and the image each independently proven,
confirms that the failure is the resigned chain on the UFS path specifically.

### Hardware result: ecdsa_eng over UFS is black too

`ecdsa_eng/sboot.bin` was flashed to BOOTLOADER and `native-triple` run
against it. `EUN3REC0`, `EUN3REC1` and `EUN3REC2` arrived at 0.039 s;
`EUN3REC3` did not; the screen stayed black.

Every measured value is identical to the successful stock run — key selector
1, verifier 1, gate `0x00000000`, flags `0x00300edf` then `0x00b00edf`, EPBL
entry/gate-load `0x14000002`/`0x580002d4`, gate branch `0x54000041`, dispatch
literal `0x02020128`, `SCTLR_EL3=0x00c51838`, `CurrentEL=0xc`. Only the
residual dispatch word differs (`0x3466e433` here, `0x7466ecb3` on the stock
run), and that is stale garbage the cold path never reads.

This is now a clean three-point result:

| image on UFS | key redirect | storage path | screen |
|---|:-:|:-:|---|
| stock | no | yes | charging screen |
| `ecdsa_eng` (resigned) | yes | no (USB-streamed) | Download mode |
| `ecdsa_eng` (resigned) | yes | yes | **black** |

Both variables that distinguish the failing row are now isolated, and the
`ecdsa_eng` row removes the forced-download u-boot patches from suspicion.

### Next: is the redirected key pointer the variable, or the image?

A stronger scan than the earlier one was run over the stock EPBL, the
decrypted FWBL1 runtime and the BootROM, looking for the literal word
`0x0202006c`, `movz`/`movk` pairs forming it, and `add xN, xM, #0x6c`:

```text
stock EPBL                   0 hits
FWBL1 (decrypted runtime)    0 hits
BootROM                      5 hits  (0x5764, 0x5774, 0x15d2c, 0x15da4, 0x1a2bc)
```

Only ROM code touches it. But the EPBL reaches ROM code through the iRAM
pointer table and through the runtime-installed `[ctx+0x484]` verifier, so
"the EPBL image contains no reference" is not the same as "nothing reads it".

That matters because our key sits at `0x020254a8`, inside the
`0x02025000`–`0x02026000` gap between the loaded EPBL and FWBL1 — exactly
where a storage driver would put descriptors or bounce buffers. The USB run
never ran that driver; the successful stock run never redirected the pointer.
The combination has never been isolated.

`EPBL_RESTORE_KEY_PTR` isolates it. The payload saves whatever pointer the
BootROM selector left in `0x0202006c`, redirects it at our key for the
`0x5b58` verification exactly as before, and writes the original value back
the instant that verifier returns:

```sh
tools/run_ubstage_test.sh native-triple-restore
```

RAM-only, and it expects the `ecdsa_eng` image already on BOOTLOADER.

| outcome | conclusion |
|---|---|
| any visible screen | ROM code reached from the EPBL does read `0x0202006c` after the handoff, and the UFS path destroys our key in that gap; the fix is to relocate the key |
| black again | the pointer is irrelevant downstream and the difference is the resigned image bytes on the storage path alone |

| build | size | sha256 |
|---|---:|---|
| `build/epbl_boot_ufs_native_triple_restore_probe.bin` | `0x8c8` | `fd2dbed46076ab2896f93e9aa0a8b2787f360b6ad55d79655edd13b30f156a12` |

### The first restore run returned nothing, which is not a result

`native-triple-restore` returned no records at all and a black screen. The
identical measurement had delivered `EUN3REC0`/`EUN3REC1`/`EUN3REC2` at
0.039 s on the two runs immediately before it, so losing record 0 as well
means execution or the channel died before anything this test was meant to
measure. The run says nothing about the key pointer.

Alignment was checked and is not the cause. Runtime addresses after
relocation, in all three builds:

| build | `probe_record` | `probe_ep1_trb` | 16-byte aligned |
|---|---:|---:|:-:|
| triple (3 records received) | `0x02025578` | `0x020255e0` | yes |
| triple-stock (3 received) | `0x02025560` | `0x020255c0` | yes |
| triple-restore (0 received) | `0x020255a0` | `0x02025600` | yes |

The restore build's TRB is in fact the best aligned of the three. The
relocated worker grew from `0x7e8` to `0x808` bytes, still far inside the
`0x02025000`–`0x02026000` gap.

One correction to the previous section: the custom key's runtime address in
the current builds is `0x02025658` (triple) and `0x02025678` (restore), not
the `0x020254a8` reported by the older `EUNPOST!`/`EUNFLAG!` payloads. It is
still inside the same gap, so the hypothesis is unchanged.

The payload was reordered so that this outcome cannot recur ambiguously. The
restore now happens **after** records 0 and 1, which have arrived on every
run, and still before the handoff:

```text
0x2022278  save the selector's pointer, then redirect   (before 0x5b58)
0x2022334  EUN3REC0
0x20223c0  EUN3REC1
0x20223c4  restore the original pointer
0x2022474  EUN3REC2
           ... boot-flag helper, entry validation, handoff
```

Records 0 and 1 now prove the payload reached the restore. If they are
missing again, the cause is upstream of this change and the run is void.

| build | size | sha256 |
|---|---:|---|
| `build/epbl_boot_ufs_native_triple_restore_probe.bin` | `0x8c8` | `3fb04639e442844e2bd52defe00cb3a4364cd7e73d01e8d12a104658c35eea9b` |

### Second void run, and the save removed entirely

The reordered restore build also returned no records and a black screen. Two
void runs in a row is reproducible, not flaky, so the three instructions that
still sat *ahead* of record 0 are implicated — even though there is no
mechanism for them to be:

```text
ldr w5, [x6]                 ; read 0x0202006c, 4-byte aligned iRAM
adr x7, saved_key_pointer    ; PC-relative, resolves into the relocated worker
str w5, [x7]                 ; 4-byte store at 0x02025598
```

A normalized instruction-stream diff against the proven `triple` build
confirmed those three plus the six after record 1 were the only changes; the
slot's `.word` and some alignment padding aside, nothing else moved. No
explanation was found, so the code was removed rather than explained.

The current build saves nothing. It writes the pointer back as a constant,
`0x10003000`, the fused KEY slot the selector was observed choosing on this
device and which the probe's own call to `0x5780` re-establishes before the
load. The normalized diff against `triple` is now exactly six instructions,
all of them after record 1's transfer:

```text
0x2022328  EUN3REC0
0x20223b4  EUN3REC1
0x20223c8  str w5, [0x0202006c]   <- the only variable
0x2022468  EUN3REC2
```

Records 0 and 1 therefore certify the run before the change can matter. If
they are missing again, the problem is in this analysis, not in the pointer.

| build | size | sha256 |
|---|---:|---|
| `build/epbl_boot_ufs_native_triple_restore_probe.bin` | `0x8b8` | `dfcea46cdaae521cb40de36f6e76d19e4a599cdfced8e61b6db992345a8cf9ad` |

### The cache-line theory for the void runs is wrong

The obvious explanation for the two void runs was that
`str w5, [saved_key_pointer]` landed in the same 64-byte line as the tail of
`probe_usb_send_wait`, which with `SCTLR_EL3=0x00c51838` (MMU off, D-cache
off, I-cache **on**) and this SoC's known I/D coherency problems could hang
the next call into that function — which is exactly where record 0 is sent.

It does not hold. In the build that *works*, the same overlap already exists:

| build | `probe_usb_send_wait` | ends at | next data object | same line? |
|---|---:|---:|---|:-:|
| triple (3 records) | `0x02025528` | `0x02025574` | `probe_record` `0x02025578` | **yes** |
| triple-restore v2 (0 records) | `0x0202554c` | `0x02025594` | `saved_key_pointer` `0x02025598` | yes |

Writing data into a line that contains code is therefore not fatal here, and
the two builds are structurally identical in that respect. The void runs
remain unexplained. The current build removes the suspect instructions rather
than relying on any theory about them.

### The EPBL's storage path, mapped

The BootROM's iRAM function table at `0x020200a0..0x0202011c` was extracted
from the ROM's own initialization sequence:

```text
[0x020200a8] 0x058b4  is_secure_boot        [0x020200d0] 0x05338  print(buf,len)
[0x020200bc] 0x12974  storage read          [0x020200d8] 0x17cd0  *(0x02020030)
[0x020200c4] 0x11ac0                        [0x020200dc] 0x00a3c  usb recv
[0x020200e8] 0x16a10  set boot flag         [0x020200e0] 0x006e8  usb init
```

The cold path reaches the loader like this:

```text
0x2022470  bl 0x2023120(0x02020130)         ; prepare
           bl 0x202234c -> boot device, saved on the stack
           blr [0x020200e8]                 ; 0x16a10, flag depends on device==1
           w8 = device - 1 ; cmp #6 ; b.hi
           x9 = 0x020239b0                  ; jump table, 7 entries
           ldr x8, [x9, w8, lsl #3] ; br x8
```

The table, read out of the image:

```text
[0] device 1 -> 0x020224e0  mov w0,#0 ; bl 0x2022754   <- storage, our path
[1] device 2 -> 0x020224ec  nop
[2] device 3 -> 0x020224f4
[3] device 4 -> 0x02022508  bl 0x2022b90               <- USB, the proven path
[4] device 5 -> 0x02022510  bl 0x202269c
[5] device 6 -> 0x02022518  mov w0,#1 ; bl 0x2022754   <- the other storage
[6] device 7 -> 0x02022524  bl 0x20225f8
```

`0x2022754` is the storage loader. It takes `w0` as the storage selector,
calls `0x20234f0` and compares the result with `0x11`, then enters a
three-attempt loop (`w21` 1..3) whose body calls `[0x020200bc]` = ROM
`0x12974` with the next stage's load address from `*(0x02020128)`, a `0xb0`
tag, `w5=1` and `w6=0x1000`. On a failed attempt it calls `0x202305c` and
either retries or gives up at attempt 3.

Device 1 and device 4 therefore run completely different code inside the
EPBL — `0x2022754` versus `0x2022b90` — which is the structural reason the
USB success and the UFS failure can coexist with identical pre-handoff state.

### Header checksums are correct in both resigned chains

The stage header holds `num_sectors` at `+0x00` and a checksum at `+0x04`.
`scripts/sign.py` computes it as `sha512(image[0x10:])[:4]` for `sign_type 4`
(`header_digest`), writes zeros into `[4:8]` first, and re-writes it after
signing; `s5e9825.py` sets `update_header=True` for `fwbl1`, and `sign_st1`
does the same for `epbl`. `bl2`, `u-boot`, `el3_mon` and `secure_payload`
begin with code (`0x14000001`, `0xd5034fdf`), so they carry no such header.

That function reproduces the stock values exactly, which makes it a valid
model of the device's own check, and all three images pass:

| image | epbl `+0x04` | fwbl1 `+0x04` | recomputed |
|---|---|---|---|
| stock | `e7552cb8` | `5ef0e858` | both match |
| `ecdsa_eng` | `e784d120` | `68a5eb1b` | both match |
| forced-download | `c9f747dc` | `f9786211` | both match |

A stale header checksum would have been an ideal explanation — the storage
path parses the header while the USB path is handed each file directly — but
it is not the bug.

### Second-model review (Codex, 2026-10-18) and what survives cross-checking

A second model was given the full state and asked five questions. Its
substantive findings, with the parts that survive checking marked.

**Confirmed and valuable — the signer destroys 376 bytes per ECDSA footer.**
`scripts/sign.py:139` does `footer.padding[:] = bytes(len(footer.padding))`
for every `sign_type != 0` footer. The field is called `padding` in
`st2.py`, but that name is a reverse-engineering guess, and in stock it is
not padding at all:

| stage | stock non-zero bytes | resigned |
|---|---:|---:|
| `fwbl1` | 376/376 | 0/376 |
| `bl2` | 375/376 | 0/376 |
| `u-boot` | 374/376 | 0/376 |
| `el3_mon` | 374/376 | 0/376 |
| `secure_payload` | 376/376 | 0/376 |

1875 bytes of high-entropy stock content are replaced with zeros across the
internal footers, plus another 376 in the container footer at `0x364000`.
This is a real defect in the signer and should be fixed regardless.

**But it cannot explain the matrix.** The USB run that reached Download mode
streamed `ecdsa_eng/sboot/{epbl,fwbl1,bl2,u-boot,el3_mon}.bin` — the same
resigned files, with the same zeroed field — and `fwbl1`, `bl2` and `u-boot`
all executed. Whatever reads that field, if anything does, is not on the path
USB exercised. It stays on the list as a correctness bug, not as the
differentiator.

**Confirmed — anti-rollback is not the answer.** `0x02022f34` reads 128 fuse
bits from `0x10008000`, derives a minimum from the bitmap and compares it
with the footer's `rb_count`. It is called from `0x02023778` *after* the
crypto check, and both the USB and storage loaders converge on the same
`0x020231bc`. `rb_count` is 9 everywhere, so the control is identical in all
three rows of the matrix.

**Confirmed and new — how the storage path finds the next stage.**
`0x02023348` computes the next destination as `0x02023000 + EPBL size`, which
with `0x3000` is `0x02026000`, FWBL1's load address. The EPBL holds no table
of stage offsets: `0x02022754` initializes the storage backend, calls ROM
`0x12974` with that destination and tag `0xb0`, reads the first sector, and
takes the sector count from the stage's own header (`0x98` for `fwbl1`, i.e.
`0x13000`). It then walks the container sequentially. USB, by contrast, gets
each file framed by the host. Also mapped: `0x02022430` is a PMU gate on bit
24 of `0x15860404` and the low nibble of `0x158609bc`, and `0x02022fe8` is
USB-only, writing `0x1300` to `0x1586030c`.

**Rejected — stale I-cache as the cause of the void runs.** The proposal was
that the relocation to the fixed address `0x02025000` could execute a mix of
cached lines from an earlier revision and bytes from the new image, which
would explain sensitivity to three harmless instructions. It cannot apply
here: EUB is entered only by powering the board down and shorting the
testpoints, so every run starts from a cold reset with a cold I-cache, and
there is no earlier revision resident at `0x02025000` to be stale. The void
runs remain unexplained.

**Adopted — the layout control.** A build with three `nop`s in place of the
three removed instructions, identical in size and layout, separates "those
instructions" from "the shifted layout" if that question ever needs settling.

### The ST1 block, fully resolved

`SBL1ECDSA(0x3000)` in `scripts/sbl1.py` accounts for every byte the BootROM
verifier touches, and for every byte the signer changes:

| offset | field | note |
|---:|---|---|
| `0x26d0` | `codesigner_version` = 5 | **this is `ctx`**, = image_end − `0x930` |
| `0x26d4` | `ap_info` = `"SLSI"` | |
| `0x26d8` | `time` (u64) | the one header word the signer rewrites |
| `0x26e0` | `rb_count` = 9, `signing_type` = 4 | |
| `0x272c` | `st2_key_tee` (524) | **`ctx+0x5c`, exactly the verifier's `x3`/`w4`** |
| `0x2938` | `st2_key_ree` (524) | |
| `0x2b44` | `func_ptr` (128) | **`[ctx+0x478]` and `[ctx+0x484]` live here** |
| `0x2bd0` | `st1_publickey` (524) | |
| `0x2ddc` | `hmac` (32) | the value that would be fused |
| `0x2e00` | `signature` (136) | |
| `0x2e88` | `padding` (376) | |

A key blob is `20 zeros ‖ X(48) ‖ 20 zeros ‖ Y(48) ‖ 388 zeros` = `0x20c`,
which is why X sits at `ctx+0x70` and Y at `ctx+0xb4`. There is no "ctx[1]":
the earlier reading of a second `0x20c` context at `0x28dc` was wrong — that
address is simply `st2_key_ree`. And `[ctx+0x478]`/`[ctx+0x484]` read zero in
the image because they are `func_ptr` slots the EPBL fills at runtime, not
because the context base was wrong.

Every differing range between stock and resigned is now accounted for:
`0x04` checksum, `0x26d8` time, `0x2740`/`0x2784` TEE X/Y, `0x294c`/`0x2990`
REE X/Y, `0x2be4`/`0x2c28` ST1 X/Y, `0x2ddc` hmac, `0x2e14`/`0x2e58` sig r/s.

### An offline verifier that reproduces Samsung's own chain

`tools/make_minimal_epbl_chain.py` carries a verifier written from the
device's operand layout — raw `r‖s` in `0x44`-byte slots, SHA-512 prehash,
and the header checksum zeroed while signing, which is what `sign_st2` and
`sign_st1` do. Run against the untouched stock image it accepts everything:

```text
STOCK EPBL ST1 vs its own embedded ST1 key : PASS
STOCK fwbl1/bl2/u-boot/el3_mon/secure_payload ST2 vs embedded TEE key : PASS
STOCK container ST2 vs embedded TEE key    : PASS
```

This is the end-to-end check the project twice failed to have. It is a model
of the device's scheme, validated against Samsung's own signatures rather
than against our own signer.

### The minimal chain

`tools/make_minimal_epbl_chain.py` builds `build/minimal_epbl_chain/sboot.bin`:
Samsung's image with **only the ST1 anchor replaced**. The ST2-TEE slot keeps
Samsung's key, so the untouched stock stages still verify against the key they
were actually signed with. 418 bytes of 4 MB differ from stock.

```text
EPBL ST1 against OUR st1 key          : PASS
EPBL ST1 rejected by Samsung's key    : PASS
EPBL header checksum                  : PASS
ST2-TEE slot still Samsung's          : PASS
fwbl1/bl2/u-boot/el3_mon/secure_payload ST2 against Samsung TEE key : PASS
container ST2 against OUR st2r key    : PASS
```

The container's own ST2 footer at `0x364100` covers the whole prefix, so it
cannot stay stock once the EPBL changes. It is re-signed with our ST2-REE key
and marked `key_type=1`, with our ST2-REE public key in the REE slot, which
keeps it self-consistent without touching the TEE slot the stages need. Stock
signs that footer with the TEE key, so this is a deliberate deviation. Its
376-byte trailing field is also preserved from stock rather than zeroed.

### The control that makes the minimal chain readable

If the container footer *is* enforced at boot, the minimal chain could fail
for that reason alone, and we have no way to sign it with Samsung's key. So a
one-byte control settles that first:

```sh
tools/make_minimal_epbl_chain.py --pad-tamper --out build/pad_tamper_chain/sboot.bin
```

`build/pad_tamper_chain/sboot.bin` is the stock image with a single byte of
`pad.bin` flipped at `0x68000`. `pad.bin` is unsigned filler between `bl2` and
`u-boot`; no stage signature covers it, and the container footer is the only
thing that does. So every stage is Samsung's own and still valid, and exactly
one thing is wrong.

| result | conclusion |
|---|---|
| boots | the container footer is not checked at boot; the minimal chain's result is unambiguous |
| black | the container footer is enforced, and no custom chain can satisfy it without Samsung's private key |

| image | sha256 |
|---|---|
| `build/pad_tamper_chain/sboot.bin` | `477cbe4c8ab858840b7b30e929886234569626f8394e3c16aafcf98413ddce1b` |
| `build/minimal_epbl_chain/sboot.bin` | rebuilt per run; ECDSA is non-deterministic |

### Second-model round two: the container footer, and the HMAC field

**The container footer is a flash-path artifact, not a boot-path one.**
Neither the BootROM, the EPBL, the decrypted FWBL1 nor BL2 contains
`SignerVer01/02/03`, a `GetSigner*` symbol, or a literal for
`0x364000`/`0x364100`. u-boot does: `0xc90a7718` recognizes the three
`SignerVer` strings, `0xc90a7644`/`0xc90a76ac` locate the `SignerInfo` and
signature in a buffer, and the Download/OTA ingest path compares the
partition name against `BOOTLOADER` and at `0xc9052b60` loads exactly
`0x364310` — the end of `SignerInfo` + footer. The neighbouring strings are
`EMMC BOOTLOADER partition - size check skip`, `'%s' is flashed fully`,
`BOTA Update`. So the block is parsed when an image is ingested, and no edge
was found that re-reads `BOOTLOADER` and re-checks it during a cold boot.

Our own history settles the flash side: `ecdsa_eng/sboot.bin` has that footer
signed with *our* key and was flashed successfully from stock Download mode,
and the `native-triple` run that followed had the BootROM verifier return 1
against our custom key — which can only happen if our EPBL really reached
UFS. The flash writes, and the Download path does not enforce that signature.

**The `hmac` field at `0x2ddc` is checked by the BootROM**, through
`0x5b58 -> 0x599c -> 0xc1f8 -> 0xc114`, with the ST1 public key at `ctx+0x500`
and the HMAC at `public key + 0x20c`. The relation, verified offline:

```text
footer_hmac      = HMAC-SHA512(hmac.bin, st1_pub[:136])[:32]
OTP anchor       = footer_hmac XOR hmac.bin
BootROM accepts  when HMAC(footer_hmac XOR anchor, st1_pub[:136])[:32]
                 == footer_hmac
```

For our chains `footer_hmac = 007cd770…a2` and the anchor is
`1d12d364…0b`, which is exactly the value the payload embeds and points
`PTR_SECUREBOOT_KEY` at. The minimal chain's `hmac` and `st1_publickey` are
byte-identical to `ecdsa_eng`'s, so no payload change is needed. The earlier
docstring calling `0x2ddc` "the value that would be fused" was wrong and has
been corrected: the fused value is that field XOR `hmac.bin`.

**Residual risks named in the review, both outside the resigned EPBL:** the
container footer's `key_type=1`/ST2-REE provenance is unproven, and stock
never ships a chain whose TEE and REE slots differ. Neither affects the boot
path as far as anything found so far.

### A better control than the pad byte

`--pad-tamper` has a gap: if the board stays black, it cannot be told apart
from a flash that never took. `--epbl-pad-tamper` closes it by moving the
flipped byte inside the first `0x3000` bytes — the one region of the
partition EUB can already read back, because the BootROM loader fetches
exactly `0x18` sectors and `native-load-diagnose` reports the loaded BL1
checksum.

It flips `0x2e88`, the EPBL's ST1 `padding`. The ST1 signature ends at
`0x2e00`, so the anchor stays valid; the header checksum covers the field and
is recomputed, which is free because it is zeroed while ST1 is signed. Five
bytes differ from stock in total.

```text
build/epbl_pad_tamper_chain/sboot.bin
sha256 7b322f073b7bd1a6abd5b027165ad2dbe67d1784b0a1d2cf7816f2fa96f1ce91
flipped 0x2e88: 0xea -> 0x15 ; header checksum e7552cb8 -> a856415c
EPBL ST1 still verifies against Samsung's key: PASS
after flashing, UFSMETA must report BL1 checksum 0x5c4156a8
```

### The USB shortcut: why the OTP returned -1, and what the patches actually cover

`[OTP] LDFW hasn't been loaded` is not a pre-check in u-boot. All 44 OTP
wrappers share one result decoder, e.g. around `0xc90a2708`:

```text
cmp x19, #0xffffffff   ; the SMC return value
b.eq -> print "[OTP] LDFW hasn't been loaded"   (0xc91067e0)
cbnz x19 -> print the generic failure           (0xc9106c90)
else     -> print success                       (0xc9106ce8)
```

So `-1` is simply what the secure side answers when no CSMC/fuse broker is
there. The gate is in the secure world, not in u-boot.

And the reason there is no broker is now exact. `0xc9003374` is the `0x3374`
the fuse document refers to:

```text
0xc90033e0  x1 = 0x80000000
0xc90033f0  ldr w19, [x1]                     ; MAGIC_CODE
0xc9003410  cmp w19, #0x66269633  -> skip
0xc9003418  cmp w19, #0x66265999  -> skip
0xc9003430  cmp w19, #0x6626ccca  -> skip
0xc9003438  bl 0xc901ee9c ; cbnz -> skip
0xc900345c  mov w0,#0x20 ; bl 0xc90016dc       ; load_secure_payload
```

When `MAGIC_CODE` holds one of the three download magics, `load_secure_payload`
is skipped — no broker, and every OTP command returns `-1`.

`patch_ignore_magic_code` replaces that one `ldr` with `mov w19,#0`:

| image | `0x33f0` | effect |
|---|---|---|
| stock | `b9400033` `ldr w19,[x1]` | |
| `ecdsa_eng` | `b9400033` | **unpatched — the secure payload is skipped** |
| forced-download | `52800013` `mov w19,#0` | the secure payload is loaded |

So the recorded conclusion that "the USB path cannot fuse" was measured with
`ecdsa_eng`, which never loads the secure payload. The shortcut has not
actually been tested with the patch that removes that exact obstacle.

**But the patch is far from complete.** A scan of every
`movz xN,#0x8000,lsl#16` followed by a load through that register finds
**24 sites in u-boot that read `0x80000000`**:

```text
0x012f0 0x01528 0x016f4 0x033e0 0x0360c 0x03b78 0x08b54 0x08f78
0x0970c 0x0d01c 0x0f018 0x14464 0x145d8 0x1e4e0 0x27650 0x546a0
0x60b4c 0x620c0 0x72b34 0xa14e4 0xa5ddc 0xa8114 0xa85cc 0xb8d3c
```

`--force-download` neutralizes exactly one (`0x33f0`). `--normal-boot` adds
`0xa61a4` and `0xa61b0`, so three of twenty-four. `ecdsa_eng` neutralizes
none. Every chain we have ever booted therefore runs u-boot in a state no
stock boot ever produces: a handful of paths told it is a normal boot and two
dozen still reading the download magic. One of those is `0x01710`, inside a
function adjacent to the secure-payload loader, which tests the same three
magics and bails.

### A better patch than neutralizing reads one at a time

The word lives in DRAM, and BL2 initializes DRAM before u-boot runs — u-boot
itself is executing from `0xc9000000`, which is DRAM. So a single early store
of a non-download value to `0x80000000` and `0x80000010` makes all 24 sites
agree, with no per-site patching and no inconsistent state. The EPBL payload
cannot do this, which is why it was ruled out before — the earlier `UFSPRE`
result showed those stores running before BL2 and stopping the chain — but
u-boot can, trivially, from its own entry.

That is the patch to build before any further USB-fuse attempt:
`--clear-boot-magic`, a store pair placed in the verified zero cave at
`0x17ce00` and entered from u-boot's first instruction.

### Correction: there are two gates before the secure payload, and both are handled

The analysis above was incomplete. `load_secure_payload` sits behind two
independent checks, not one:

```text
0xc9003410/18/30  cmp w19, <three download magics>   -> skip   (MAGIC_CODE)
0xc9003438        bl 0xc901ee9c ; cbnz w0 -> skip             (a flag bit)
0xc900345c        mov w0,#0x20 ; bl 0xc90016dc                 load_secure_payload
```

The second reads bit 28 of a flag word at `0xc93d4b28`, written by a single
`str w1,[x0,#0xb28]` preceded by `movz w1,#0x1000,lsl#16` at file `0x1f330`.
`scripts/patch_9825.py:patch_force_secure_payload_load` already neutralizes
exactly that, and `patch_9825.py` applies it whenever
`FUSE_BOOT_KEY=yes-burn-key2`, which is what `build_key2_fuse_chain.sh` sets.

Measured across every image we have:

| image | `0x33f0` MAGIC gate | `0x1f330` flag gate | `0xa61a4` LDFW mode |
|---|---|---|---|
| stock | `ldr` | `movz 0x10000000` | `ldr` |
| `ecdsa_eng` | `ldr` | `movz` | `ldr` |
| forced-download | `mov w19,#0` | `movz` | `ldr` |
| **`key2_program_chain`** | **`mov w19,#0`** | **`mov w1,#0`** | **`mov w20,#0`** |

So `key2_program_chain` is the only image with all three gates open, and it
has only ever been triggered over **UFS**, never streamed over USB. The
recorded "-1" result was produced by `ecdsa_eng`, which opens none of them.
The USB route has therefore never been tried with the one image that could
work.

### `--clear-boot-magic`

Added to `tools/sboot_patch.py`. The entry word of u-boot is `b .+4`, a free
hook, so it is redirected into the verified zero cave at `0x17ce00`:

```text
0xc9000000  b 0xc917ce00
0xc917ce00  mov x16, #0x80000000
0xc917ce04  str wzr, [x16]
0xc917ce08  str wzr, [x16, #16]
0xc917ce0c  dsb sy
0xc917ce10  b 0xc9000004
```

Five instructions, using only `x16` (IP0), reaching DRAM that BL2 has already
initialized — u-boot is itself executing from `0xc9000000`, which is DRAM.
All 24 readers of `0x80000000` then agree, instead of three being patched and
twenty-one left believing the device is in Download mode. The cave is inside
the ST2-signed body, so the chain must be re-signed, which `build.py` does.

This is a deliberate behaviour change, not a no-op: twenty-one code paths
that currently take their download branch will take their normal-boot branch.
That is the intent — it is the state a real boot has — but it is the first
change in this project that moves that many paths at once.

### `--force-secure-payload`, and the observation chain

The second gate is now handled in our own patcher too, and more narrowly than
by zeroing the flag word. `patch_force_secure_payload` anchors on the
`"%s: Skip to load Secure Payload\n"` message, finds the single
`cbnz w0, <skip block>` that reaches it, and replaces the **call** before it
with `mov w0,#0`:

```text
0xc9003434  b.eq 0xc9003478
0xc9003438  mov  w0, #0          <- was bl <flag reader>
0xc900343c  cbnz w0, 0xc90034d8  <- never taken
0xc900345c  mov  w0,#0x20 ; bl <loader>
```

Neutralizing the call rather than the flag word matters: another accessor
extracts arbitrary bits of the same word, so zeroing it would change every
other consumer. This changes exactly one decision.

`tools/build_ldfw_observe_chain.sh` then builds the chain that answers the
LDFW question with no irreversible step:

```sh
tools/build_ldfw_observe_chain.sh     # build and validate
tools/run_ldfw_observe.sh             # stream over USB, read the console
```

It is the stock image resigned with our keys, patched with `--normal-boot
--force-secure-payload --clear-boot-magic --no-eng`, and **without**
`FUSE_BOOT_KEY`, so `check_signature` stays the inert `mov w0,#0 ; ret`
instead of becoming the KEY2 stub. `tools/check_ldfw_observe_image.py`
enforces that, and the build fails rather than producing an image with a path
to an OTP command:

```text
entry redirected to the cave                 PASS  0x1405f380
cave zeroes 0x80000000 and +0x10             PASS
secure-payload skip check neutralized        PASS  0x52800000
download fork forced to normal boot          PASS  0x52800000
MAGIC_CODE read neutralized                  PASS  0x52800013
check_signature is the inert stub            PASS  000080d2c0035fd6
LDFW result paths not redirected             PASS  0x58c7c
all four LDFW results share one callee       PASS
RESULT: PASS - no path reaches an OTP command
```

`verify_9825.py` also accepts it, with every stage verifying under our keys
and failing under Samsung's.

```text
build/ldfw_observe_chain/sboot.bin
sha256 ebe8f48d2affa23d25c001c1e5586dd2896cb66153baedf0265dd65f7ebf96af
```

What the run decides, from u-boot's own console over EP1:

| output | meaning |
|---|---|
| `Start to Load` / `Load done.` | the Secure Payload loaded; the CSMC broker exists |
| `Skip to load Secure Payload` | a gate patch did not take |
| `Fail to load Secure Payload!! [ret = %lx]` | it tried and failed; the code matters |
| `ldfw: try to init N ldfw(s)...` with N non-zero | the fuse route is open |
| `ldfw: No ldfw is inited` / `signature of ldfw is corrupted` | OTP would still return -1 |

Only if both the Secure Payload loads and the initializer reports a non-zero
count does arming OTP `0x16` become meaningful. Until then the fuse route is
not blocked by risk — it is blocked by the command having nobody to answer it.

### Hardware result: the chain runs to u-boot, but EP1 is not u-boot's console

`run_ldfw_observe.sh` streamed the chain and the whole pre-u-boot sequence
worked:

```text
[0.054s] EPBL RX Done / Pass: Loading EPBL
[0.553s] [BL2] USB Loading Start / Done
[1.103s] DMC01 … DMC25            (full DRAM training)
[2.865s] BL2 Pass
[4.199s] [U-boot] USB Loading Start / Done
[4.246s] [EL3_MON] USB Loading Start / Done
         EP1 IN reader stopped: ENODEV
```

Screen black. EPBL, FWBL1 and BL2 all executed with our resigned stages, DRAM
trained, and u-boot and the EL3 monitor were both loaded. Nothing before
u-boot is broken.

**But the test cannot answer the question it was built for.** Every line
above is printed by the EPBL or BL2 through the BootROM's EP1 helper. Not one
is from u-boot. The design assumed u-boot's own console reaches EP1; nothing
in this repository supports that, and this run gives no evidence for it
either — u-boot prints several lines early (`MMU: enable start`,
`MAGIC_CODE 0x%x`) and none of them appeared.

Two readings fit, and this run cannot separate them:

1. u-boot's console is UART-only, so we would see nothing regardless of what
   u-boot did.
2. u-boot died before its first `printf`. The prime suspect is the
   `--clear-boot-magic` trampoline, which is now literally the first thing
   u-boot executes and stores to `0x80000000`. DRAM is trained by then and
   u-boot itself runs from `0xc9000000`, which is inside DRAM, but a carveout
   or protection at the DRAM base would fault that store.

### The calibration that separates them

Stream the plain `ecdsa_eng` chain, which has none of our u-boot patches and
is known to reach Download mode — so u-boot certainly runs:

```sh
/home/chanz22/EUB-N10/9825_customkey/run_custom_key_test.sh efuse ecdsa_eng
```

| EP1 output | conclusion |
|---|---|
| no u-boot lines, Download screen appears | u-boot's console is not EP1; the observation design needs a different channel |
| u-boot lines appear | the console is EP1, and our chain died before its first print — drop `--clear-boot-magic` and retry |

If the console turns out not to be EP1, there are two ways forward: a USB-TTL
UART cable, or patching u-boot's low-level console write to call the BootROM
print helper whose pointer sits at iRAM `0x020200d0` (x0 = buffer,
x1 = length). The second needs no hardware but adds a patch to the very path
we are trying to observe.

### The software console redirect is not viable either

With no UART cable, the plan was to redirect u-boot's console to the BootROM
print helper. Two findings kill it:

1. **The helper is not `(buffer, length)`.** `[0x020200d0]` is ROM `0x5338`,
   which takes four arguments — `w0`, `w1` compared against `0x100`, `x2` as a
   buffer and `w3` as a mode flag. It is a USB transfer helper, not a console
   write, and our own payload does not use it: `probe_usb_send_wait` drives
   DWC3 directly. The earlier note describing it as a simple print routine was
   wrong.
2. **EP1 is gone before u-boot's output would matter.** The observe run lost
   the device with `ENODEV` immediately after `[EL3_MON] USB Loading Done`.
   Whatever tears USB down happens between the EL3 monitor load and u-boot's
   first console write, so no redirect into that channel can be read.

u-boot's `printf` at `0xc9058c7c` is also a hand-rolled formatter that walks
the format string and emits as it goes, with no single `(buf, len)` sink to
hook. Hooking it would mean finding and replacing the character sink, which is
a large change inside the exact path under investigation.

### What is left: the screen, and one variable at a time

The only output channel proven to work past the EL3 monitor is the display
(and, equivalently, the Odin gadget enumerating). So the next test keeps the
`ecdsa_eng` Download path, which reaches that screen, and adds exactly one
behaviour: letting the Secure Payload load.

```sh
tools/build_secpayload_download_chain.sh
tools/run_secpayload_download.sh
```

`--force-download --force-secure-payload --no-eng`, and deliberately **no**
`--clear-boot-magic`, so the untested trampoline is not a second variable.

| outcome | conclusion |
|---|---|
| Download/Odin screen | the Secure Payload loaded and the chain survived; the CSMC broker exists and the fuse route's main obstacle is gone |
| black | loading the Secure Payload is itself what kills the chain |

```text
build/secpayload_download_chain/sboot.bin
sha256 c42b99bd137cdf5343834177abb6a451d6f6560e69102a97eeec3c145d7329f5
```

### Hardware result: the Secure Payload load does not kill the chain

`run_secpayload_download.sh` reached the **Samsung Download/Odin screen**.
Same EP1 trace as before (EPBL, BL2, DMC01–25, `BL2 Pass`, u-boot and EL3
monitor loaded, then `ENODEV`), and this time the device entered Odin.

That disproves the recorded claim that "forcing LDFW/secure-payload load in
download context either faults the OTP crypto or hangs sboot". Opening both
gates and letting `load_secure_payload` run leaves the chain alive all the
way to Download mode. The only difference from the proven `ecdsa_eng` run was
`--force-secure-payload`.

It does **not** prove the payload loaded. Both outcomes fall through:

```text
0xc900345c  mov w0,#0x20 ; bl <loader>
0xc9003464  cbz x0, 0xc90034f4     ; x0 == 0 -> "%s: Load done."
0xc9003468  mov x1, x0             ; else   -> "Fail to load Secure Payload!!
0xc9003474  bl printf              ;            [ret = %lx]"
0xc9003478  ... both continue
```

Also learned: the CM/LDFW initializer at `0xc90a616c` has **no direct caller**
in u-boot — it is reached through a function pointer, which is why
`patch_key2_after_ldfw` hooks the four result diagnostics rather than the
call. Whether it runs at all on the Download path cannot be settled from the
call graph.

### `--prove-secure-payload`

One instruction, and it fixes the polarity: hang the failure path, so the
Download screen means the payload really loaded and nothing else. A crash
anywhere produces black, so black stays ambiguous while Download cannot be
faked by a crash.

```text
0xc9003468  mov x1, x0   ->   b .     (hang)
```

```sh
tools/build_secpayload_proof_chain.sh
tools/run_secpayload_proof.sh
```

| outcome | conclusion |
|---|---|
| Download/Odin screen | `load_secure_payload` returned 0; the CSMC broker is up |
| black | it returned non-zero, i.e. the load itself failed |

The next question after that is whether the LDFW initializer runs on this
path, which the four result diagnostics can answer the same way: hang them
and compare against this run's Download baseline.

### Hardware result: the Secure Payload load fails, and it is an SMC

`run_secpayload_proof.sh` went black. The only difference from the run that
reached Odin is one instruction at `0xc9003468`, and that instruction is
reachable **only** when the loader returns non-zero. So the failure path was
taken: `load_secure_payload` failed.

A second signal confirms the hang executed. The Odin run ended with `ENODEV`
because the device re-enumerated; this run produced no disconnect at all —
the 15-second drain simply expired with the board still attached, which is
what a tight loop looks like.

What the loader actually is:

```text
0xc900345c  mov w0, #0x20
0xc9003460  bl  0xc90016dc
0xc90016dc  mov w1, w0 ; mov x2,#0x264 ; mov x0,#-300 ; mov x3,#0
0xc90016ec  b   0xc9001634          -> secure monitor call, ends in `smc #0`
```

So `load_secure_payload` does not read storage itself: it asks the EL3
monitor, over SMC, to produce the payload. The monitor is `el3_mon`, which we
do stream. The payload it fetches is `secure_payload`, which we **never**
send over USB — the host tool accepts at most four `--receive-next-file`
arguments and all four are used by `fwbl1`, `bl2`, `u-boot` and `el3_mon`.

That gives two candidate causes, and they are separable with one flash:

1. the monitor reads `secure_payload` from the UFS `BOOTLOADER` partition,
   which currently holds **stock** — Samsung's payload signed with Samsung's
   key, while our monitor carries our ST2 keys, so verification fails;
2. the monitor expects it somewhere our USB-streamed boot never filled.

### The test that separates them

Flash the same image we stream, so the `secure_payload` on UFS is ours:

```sh
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/secpayload_proof_chain/sboot.bin
tools/run_secpayload_proof.sh
```

| outcome | conclusion |
|---|---|
| Download/Odin screen | cause 1 — the monitor reads it from UFS and the key mismatch was the whole problem; the fuse route opens |
| black | cause 2 — the failure is elsewhere, and streaming a fifth stage or changing where the monitor looks becomes the next step |

Restore afterwards with
`sudo odin flash --BOOTLOADER /home/chanz22/EUB-N10/9825_customkey/input/sboot.bin`.

```text
build/secpayload_proof_chain/sboot.bin
sha256 fd64b33f7ec9c00b2dfe574a939cc3c2e9df1977ca076638e5775a5c45c03649
```

The image carries the deliberate hang on the Secure Payload failure path, so
if it were ever cold-booted from UFS it would stop there. That is a hang, not
a write, and it carries no OTP command.

### Hardware result: our signed payload on UFS does not fix the load

`build/secpayload_proof_chain/sboot.bin` was flashed to BOOTLOADER and the
same USB-streamed test re-run. Still black, still no disconnect. So cause 1
is out: the EL3 monitor is not simply fetching `secure_payload` from the
`BOOTLOADER` partition and failing a key check. Putting our own signed copy
there changes nothing.

What remains is that the monitor looks somewhere a USB-streamed boot never
fills, or that the storage it would read from is not initialized at that
point in a USB boot — neither of which a resigned image can fix.

### This reframes what the fuse route actually needs

`load_secure_payload` is an SMC into the EL3 monitor, and the neighbouring
debug string is `" SecureOS : %d (MB)"`, so `secure_payload` looks like the
Secure OS image rather than the CSMC broker itself. The error we are chasing
is `[OTP] LDFW hasn't been loaded`, and the LDFW modules come from the
separate `CM` partition, loaded by u-boot's own initializer at `0xc90a616c` —
not by this SMC.

So the Secure Payload may not be the prerequisite at all. The run that
reached Odin had the load fail silently and the chain carried on. The open
question is narrower than assumed: **does the CM/LDFW initializer run on this
path, and what does it report?**

### `--probe-ldfw-result`

The initializer has no direct caller, so the call graph cannot answer it. Its
four mutually exclusive result diagnostics can. All four are replaced with
`b .`:

```text
0x0a63e4  ldfw: No ldfw is inited
0x0a6460  ldfw: signature of ldfw is corrupted! ret = [0x%llX]
0x0a64a4  ldfw: try to init %d ldfw(s)...
0x0a64d0  ldfw: It is dump_gpr state...
```

Against the Download baseline from the identical chain:

| outcome | conclusion |
|---|---|
| Download/Odin | none of the four was reached — the initializer never runs on this path, and the fuse route needs a real UFS boot after all |
| black | it ran, and the next single bit identifies which of the four |

```sh
tools/run_ldfw_probe.sh
```

```text
build/ldfw_probe_chain/sboot.bin
sha256 f2979ceba5999c0fa59d5e57c3ae7b17945c3204b8096d396bec1fd3856b40cc
```

No OTP command, nothing written to UFS. The UFS content is irrelevant to this
run — the previous result showed the flashed image does not participate.

### Hardware result: the CM/LDFW initializer does not run in Download mode

`run_ldfw_probe.sh` reached Odin with all four result diagnostics replaced by
`b .`. None of them was reached, so the initializer never executes on the
Download path.

**That closes the USB/Download shortcut for the fuse.** OTP command `0x16`
would return `-1` there no matter what else is patched, because the LDFW the
secure side needs is never loaded. Three runs' worth of hypotheses resolve at
once, and none of them cost anything irreversible.

It also means the chase after `load_secure_payload` was partly beside the
point. That SMC loads what the neighbouring string calls `SecureOS`, while
the thing the OTP path is missing comes from the `CM` partition through
u-boot's own initializer.

### The run that was never done

Reviewing what has actually been streamed over USB:

| chain | patches | result |
|---|---|---|
| `ldfw_observe` | `--normal-boot --force-secure-payload --clear-boot-magic` | black |
| `secpayload_download` | `--force-download --force-secure-payload` | **Odin** |
| `secpayload_proof` | the same `+ --prove-secure-payload` | black (the load fails) |
| `ldfw_probe` | the same `+ --probe-ldfw-result` | **Odin** (initializer absent) |

The normal-boot path has been tried exactly once over USB, and that run also
carried `--clear-boot-magic`, the trampoline flagged as an untested suspect
the moment it was written. So the confound was never removed.

`build/normalboot_chain/sboot.bin` is `--normal-boot --force-secure-payload
--no-eng` and nothing else:

```text
0x0038f0  s5p_check_download -> 0     normal boot instead of Download
0x0033f0  MAGIC_CODE -> 0             first secure-payload gate
0x003438  skip check -> 0             second secure-payload gate
0x0a61a4  LDFW mode[0] -> 0           the stale EUB mode words the
0x0a61b0  LDFW mode[1] -> 0           initializer bails out on
```

```sh
tools/run_normalboot.sh
```

| screen | conclusion |
|---|---|
| Samsung logo, Android, or any boot UI | the normal path survives; the LDFW initializer can then be probed exactly as the Download path was, and `--clear-boot-magic` is exonerated |
| a verification/recovery UI | still a live normal path, stopped later — the exact text matters |
| black | the normal path itself dies, and that is the next bit |

```text
sha256 70651eade6a95babf5d2a355aef58bf97125eea501027b4923357a26f8f11229
```

### Hardware result: the blue prompt, which is a dead end rather than a failure

`run_normalboot.sh` drew the blue **USB RECOVERY MODE** screen and then
rebooted. That is not a black screen — u-boot was alive and driving the
display, so the normal-boot path survives, and `--clear-boot-magic` is
exonerated as the cause of the earlier black run.

The prompt is already understood in this codebase. `patch_skip_usb_recovery`
describes it exactly: it is the tail of the secure-payload block. When
`load_secure_payload()` fails, u-boot prints `Fail to load Secure Payload!!`,
prints the debug info, and tail-branches into the prompt at `0x008b4c`, which
draws

```text
UP KEY : NORMAL BOOTING / DOWN KEY : DOWNLOAD MODE
USB RECOVERY MODE
```

waits for a key, and writes `0x66265999` to DRAM `0x80000000` on its way out
— re-arming the download magic for the next boot.

So the three results line up into one story: the Secure Payload load fails
(proven), the failure path falls into this prompt (observed), and the prompt
is where the normal boot ends. Nothing downstream — including the CM/LDFW
initializer — has had a chance to run.

### The prompt is now stubbed

`--skip-usb-recovery` is exposed as its own flag and the normal-boot chain
rebuilt with it:

```text
0x0038f0  s5p_check_download -> 0
0x0033f0  MAGIC_CODE -> 0
0x003438  secure-payload skip check -> 0
0x008b4c  usb_recovery_prompt -> mov w0,#0 ; ret
0x0a61a4  LDFW mode[0] -> 0
0x0a61b0  LDFW mode[1] -> 0
```

```sh
tools/run_normalboot.sh
```

| screen | conclusion |
|---|---|
| Samsung logo, Android, or any boot UI | the chain runs past the prompt and the LDFW initializer becomes probeable |
| another prompt or error text | still alive; the exact text locates it |
| black | it stops immediately after the prompt |

```text
sha256 cb577adb43489848dbb9acdc0009815c0880d3bb48db16d69f2c23b63c72da24
```

### Hardware result: past the prompt, and then nothing

With `--skip-usb-recovery` the chain went black. So it does get past the
secure-payload dead end, and then stops with nothing drawing. On the
normal-boot path there is no output channel left at all — no UART, and EP1
is gone after the EL3 monitor — so a black screen carries no information
beyond "not the prompt".

### Moving the one thing that is proven to draw

Rather than suppress the prompt, relocate it. `--ldfw-success-prompt`:

```text
0x0034d4  b 0xc9008b4c  ->  ret      the dead-end tail branch from the
                                     failed secure-payload block
0x0a64a4  bl printf     ->  bl 0xc9008b4c
                                     the CM/LDFW success diagnostic
                                     "ldfw: try to init %d ldfw(s)..."
```

The prompt function itself is untouched, and the other three LDFW result
paths keep their printf. So:

| screen | conclusion |
|---|---|
| blue USB RECOVERY MODE | the LDFW success path was reached — the initializer ran and succeeded, which is the single fact the fuse route depends on |
| anything else, including black | it was not reached; a crash cannot draw a prompt, so this stays unambiguous |

```sh
tools/run_ldfwsignal.sh
```

```text
build/ldfwsignal_chain/sboot.bin
sha256 174330e90c9b41e0eaa654af146489f39cfefaa6d258cc9d721bc18734e86c7b
```

This is the same trick that made the Download screen usable as an oracle,
carried over to the normal-boot path: pick an output the board is already
proven to produce, and make the fact under test be what produces it.

### Hardware result: the LDFW success path is not reached on the normal path either

`run_ldfwsignal.sh` went black, so `ldfw: try to init N ldfw(s)` was never
reached. That rules out success but not failure: the other three result paths
still call `printf`, which draws nothing on this board.

`--ldfw-any-prompt` closes the gap by pointing all four at the prompt:

| screen | conclusion |
|---|---|
| blue USB RECOVERY MODE | the initializer ran and hit one of the four; the next run splits which, and the fuse route is alive |
| black | it never runs on the normal path either, exactly as in Download mode, and the chain dies upstream of it |

```sh
tools/run_ldfwany.sh
```

```text
build/ldfwany_chain/sboot.bin
sha256 6e901c2e600f5c98a1301510a8b0d960245404a58735cf672e5ed4af28db41bb
```

Running total of what the screen has settled, all RAM-only and all free:

| question | answer |
|---|---|
| does forcing the Secure Payload hang sboot? | no — Odin reached |
| does `load_secure_payload` succeed? | no, it returns non-zero |
| is our signed payload on UFS the fix? | no |
| does the CM/LDFW initializer run in Download mode? | no |
| does the normal path survive the secure-payload block? | yes — it draws the blue prompt |
| is the prompt a failure or a dead end? | a dead end, and it re-arms the download magic |
| does the LDFW success path run on the normal path? | no |
| does the initializer run at all there? | **this run** |

### Hardware result: the CM/LDFW initializer never runs on the normal path either

`run_ldfwany.sh`, with all four result diagnostics drawing the prompt, went
black. So the initializer is not reached in Download mode *or* in normal boot.

**The USB route is closed for the fuse.** OTP `0x16` cannot be answered there
under any patch set we can apply, because the LDFW the secure side needs is
never loaded. Everything the fuse depends on now runs through the UFS route.

### The relocated prompt, generalized

The one technique that kept working deserves to be an instrument rather than
a patch per question. `--prompt-after STRING` neutralizes the prompt's
dead-end tail branch and points it at the first call after any chosen
diagnostic string:

```sh
tools/build_prompt_probe_chain.sh 'Starting kernel...\n\n'
tools/run_prompt_probe.sh
```

Blue means the marked code ran. A crash cannot draw a prompt, so the positive
direction never lies. Useful anchors found in u-boot:

```text
0x0e57c0  "Starting kernel...\n\n"     the last thing before the kernel jump
0x0e8608  "ODIN MODE (AVB Fail)\n"     verified boot rejected the image
0x0e2f90  "avb_main"                   verified boot started
0x0d4980  "load_kernel"                the kernel loader
```

The first one is the most informative single marker left on this path: if the
board draws blue at `Starting kernel...`, then u-boot completed an entire
normal boot and the CM/LDFW initializer is simply never called in this
configuration — not crashed, just absent. If it stays black, the chain dies
somewhere between the secure-payload block and the kernel jump, and the other
three anchors bisect it.

```text
build/prompt_probe_chain/sboot.bin
sha256 66bd038d9c40204e22a8092804b84451a91177e8e9d348bb9c267fca17eb199a
```

### Correction: the CM/LDFW initializer does run, and one gate explains everything

A second model reviewing the six hardware results found the gate, and it
verifies instruction by instruction:

```text
0xc90033e8  mov w2, #0xfa11
0xc90033f4  str w2, [x20, #648]      ; set before asking for the Secure OS
0xc9003500  str wzr, [x20, #648]     ; cleared only when that SMC returns 0

0xc90a6250  ldr x0, [x23, #3768]     ; the same global
0xc90a6254  ldr w1, [x0, #648]
0xc90a6258  mov w0, #0xfa11
0xc90a625c  cmp w1, w0
0xc90a6260  b.eq 0xc90a6530
0xc90a6530  "[ldfw] Skip ldfw & Security initialize.
             Secure Payload was not loaded."   ; return -1
```

**The earlier conclusion in this document was wrong.** The initializer is not
"never called": it runs, reads the sentinel, and leaves through a fifth exit
at `0xc90a6530` that none of the four instrumented result diagnostics cover.
That single gate explains the Download run, the success-path run and the
all-four run at once, and it means the USB route is **not** closed.

There is exactly one blocker: `load_secure_payload` returning non-zero.
Everything else measured so far is downstream of it.

Two further exits also exist and are uninstrumented — missing CM partition,
bad magic and bad size, around `0xa64d8`, `0xa64fc` and `0xa6510`.

The same review over-read one thing. It proposed switching the SMC's `x1`
from `0x20` to `0x40` on the grounds that those are UFS and USB boot devices,
citing the table at line 54 of this document. That table is the stage
**verify-type** table in FWBL1 (`{0x20, 0x14, 0x00, 0x40}`), not a boot-device
enumeration, so the mapping is an analogy from a different SoC rather than a
measurement here. The strong half of the reading stands: `x2 = 0x264` and
`0x264 * 0x1000 = 0x264000`, exactly where `secure_payload` sits in the
container, so `x2` is a block offset.

### `--ignore-secpayload-sentinel`

The sentinel is a RAM word, so the cheapest way past it is to read zero:

```text
0x0a6254  ldr w1, [x0, #648]  ->  mov w1, #0
```

One instruction, anchored on the skip message, with the `cmp`/`mov`/`ldr`
sequence checked before patching. Combined with `--ldfw-any-prompt` so all
four real results draw the blue prompt:

```sh
tools/build_sentinel_chain.sh
tools/run_sentinel.sh
```

| screen | conclusion |
|---|---|
| blue USB RECOVERY MODE | past the gate, and one of the four real results was reached |
| black | the initializer dies inside, before any result |

```text
build/sentinel_chain/sboot.bin
sha256 3211e330854fe1b77d833f5a40cb4e6c8078d433da00bb54a45ce438c9f9eb42
```

### A fuse-safety item to fix before any irreversible run

`patch_key2_after_ldfw` currently calls the OTP stub from **all four** result
paths, including "no LDFW", "signature corrupted" and dump-GPR. For the
irreversible run the `0x16` command must exist only on the confirmed success
path, and exactly once. The pre-fuse gate should be: Secure Payload SMC == 0,
the CM/LDFW success path reached, read-only OTP `0x114` answering as a loaded
service, the 32-byte buffer equal to the expected anchor, and one call.

### Hardware result: past the gate, and a real LDFW outcome was reached

`run_sentinel.sh` drew the blue prompt and then went black. With all four
CM/LDFW result diagnostics wired to the prompt, blue means one of them was
reached — so making the initializer read `0` instead of the `0xfa11`
sentinel does send it down its real path. The black afterwards is the prompt
returning and the boot continuing until it stops, which carries no extra
information.

This also **voids the earlier success-path run**. That one went black with
only `0xa64a4` wired to the prompt, but the sentinel gate was still closing
the initializer down at `0xc90a6530` before any of the four could be reached.
It has to be repeated with the bypass in place.

### Splitting the four

`build/ldfwok_chain/sboot.bin` is the sentinel bypass with only the success
diagnostic drawing:

```text
ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) have been inited done.
```

```sh
tools/run_ldfwok.sh
```

| screen | conclusion |
|---|---|
| blue USB RECOVERY MODE | the CM/LDFW initializer **succeeded** — the precondition the fuse route has been blocked on all along |
| black | one of the three failure paths; the next run splits which, and the message names what is missing |

```text
sha256 9679853e99aba7a5c8c923612d41e74815c5d80e6d134987975f08e508a94e36
```

If this comes back blue, the next step is still **not** the fuse. It is the
read-only OTP command `0x114`, which answers whether the service is loaded
without writing anything.

### Hardware result: not the success path, and the outcome set is larger than four

`run_ldfwok.sh` went black, so with the sentinel bypassed the initializer
still does not reach `ldfw: try to init N ldfw(s)`.

Enumerating every string pointer formed inside `0xa616c..0xa6570` shows the
outcome set was never four:

```text
0xa6194  "MAGIC_RAM_BASE: %x, MAGIC_RAM_BASE2: %x, ompin: %x"
0xa6200  "[ldfw] Skip ldfw initialize. (0x%x)"      <- an earlier skip, with a code
0xa6254  the 0xfa11 sentinel we now bypass
0xa6264  "CM"                                        <- the partition name
0xa62a8  "[ldfw] read whole CM partition from the storage"
0xa6320  "ldfw: %dth ldfw's version 0x%x name : %s"
0xa6394  "ldfw: init ldfw(s). whole ldfws size 0x%x"
0xa6454  "ldfw: signature of ldfw is corrupted! ret = [0x%llX]"
0xa6480  "Can not read secure chip state"
0xa6498  "ldfw: try to init %d ldfw(s)..."           <- success
0xa63f0  "Secure boot is disabled (non-secure chip)"
```

Two things follow. There is a skip at `0xa6200` that runs *before* the
sentinel check and carries a status code. And the LDFW modules come from the
**CM partition on UFS**, so the initializer needs storage — which a
USB-streamed boot may never have brought up.

### The marker that decides it

`build_prompt_probe_chain.sh` now includes the sentinel bypass, so every
further marker is measured past the gate. The chosen marker is the CM read
itself:

```sh
tools/build_prompt_probe_chain.sh '[ldfw] read whole CM partition from the storage\n'
tools/run_prompt_probe.sh
```

| screen | conclusion |
|---|---|
| blue | the initializer reaches the CM read, so storage is up and the failure is in the modules themselves |
| black | it never gets there, and the earlier skip at `0xa6200` or the CM lookup is the wall |

```text
build/prompt_probe_chain/sboot.bin
sha256 3a0f10349b8ac51ccb01c91e48eeb2f8ce6609ac81e46feb1a4e470168bcda51
```

Further anchors, usable with the same one-line instrument:

```text
'[ldfw] Skip ldfw initialize. (0x%x)\n'
'ldfw: init ldfw(s). whole ldfws size 0x%x\n'
"ldfw: %dth ldfw's version 0x%x name : %s\n"
'Can not read secure chip state\n'
```

### Hardware result: the CM partition read is reached

The CM-read marker drew blue. So in a USB-streamed boot, with the Secure
Payload absent and the sentinel bypassed, the CM/LDFW initializer still gets
as far as reading the CM partition from storage. Storage is up, and the
failure is downstream of the read — in the modules themselves.

That keeps the USB route alive and narrows the remaining span to:

```text
0xa62a8  "[ldfw] read whole CM partition from the storage"   <- reached
0xa6394  "ldfw: init ldfw(s). whole ldfws size 0x%x"         <- next marker
0xa6320  "ldfw: %dth ldfw's version 0x%x name : %s"
0xa6454  "ldfw: signature of ldfw is corrupted! ret = [0x%llX]"
0xa6498  "ldfw: try to init %d ldfw(s)..."                   <- success, not reached
```

```sh
tools/run_prompt_probe.sh
```

| screen | conclusion |
|---|---|
| blue | the blob was read and sized; the failure is per-module verification or installation, which is where the absent Secure OS would bite |
| black | the read returns nothing usable, and the CM content or its lookup is the wall |

```text
build/prompt_probe_chain/sboot.bin
sha256 348b3caa5eef098d7e7fd209fcc91eb949778adb61ad1eb383a12cdae7068cde
```

### Hardware result: the blob is read and sized — and the battery matters

The `whole ldfws size` marker drew blue, so the CM content is read and
measured. The remaining span is now two messages wide.

**More important: the owner ran the same image twice and found that without
the battery connected the prompt does not draw, and with it connected it
does.** The panel needs more than USB power.

That makes every black result from a battery-less run void, because the
oracle itself could not fire. The runs this could affect are the LDFW ones
that came back black:

| run | what black was taken to mean | still valid? |
|---|---|---|
| `secpayload_proof` | the Secure Payload load fails | **yes** — corroborated by the absence of `ENODEV`, which is independent of the display |
| `ldfwany` (all four) | **blue**, so one real outcome was reached | yes |
| `ldfwsignal` (success only) | already voided by the sentinel gate | — |
| `prompt at "Starting kernel"` | the boot dies before the kernel jump | yes |
| `ldfwok` (success, gate bypassed) | the success path is not reached | yes |

Resolved: every run was made with the battery connected except the single
deliberate comparison. So all the black results stand, and `ldfwok` was
re-run with the battery to be sure — black again. The success path is
genuinely not reached.

Rule for every run from here: **battery connected, always.** A black screen
is only evidence when the oracle was capable of firing.

### Diagnosis closed: the LDFW modules fail signature verification

The `signature of ldfw is corrupted` marker drew blue. Combined with the
earlier results, the CM/LDFW initializer's behaviour is now fully pinned:

```text
reads the CM partition               blue, reached
measures the blob                    blue, reached
verifies the modules                 blue, FAILS here
"try to init N ldfw(s)"              black, never reached
```

The cause is the obvious one once stated: `cm.bin` is signed by Samsung and
our chain carries our keys.

### `cm.bin` has the same container layout, and the offline verifier accepts it

```text
0x3f4000  SignerInfo  "SignerVer03"  "69546063R"
0x3f4100  ST2 footer  rb_count=9 sign_type=4 key_type=0 key_index=0x31fb208f
0x3f4110  signature over sha512(cm[:0x3f4110])
0x3f4198  the 376-byte trailing field, 374/376 non-zero
```

```text
stock cm.bin signature vs Samsung's ST2-TEE key : PASS
```

So the model built for the sboot container describes this one unchanged, and
re-signing is the same operation. `tools/make_custom_cm.py`:

```text
resigned signature vs OUR st2t key        : PASS
resigned signature rejected by Samsung    : PASS
trailing field preserved                  : 374/376 non-zero
bytes differing from stock                : 95 of 7340032

build/custom_cm/cm.bin
sha256 6a896581057529799b790720da0e7be1d70882d8873f7c794fe452f15d4a72c8
```

Unlike `scripts/sign.py`, the trailing field is preserved rather than zeroed.

### Before flashing it: read the PIT

This would be the first write to a partition the project has never touched,
so the next step is read-only. `odin` here is heimdall, which has
`download-pit`:

```sh
odin download-pit --output /tmp/pit.bin --no-reboot
```

That gives the exact partition name to pass to `flash --<name>`, and
confirms a CM partition exists at all. The initializer refers to it as `CM`.

Risk, stated plainly. Recovery is a re-flash of the original
`/home/chanz22/EUB-N10/cm.bin`, which we have. The exposure in between is
that **stock** sboot would then fail the same signature check against
Samsung's key, so an ordinary boot may be degraded or may not complete. The
Download path runs before LDFW matters, so it should stay reachable, which is
what makes the recovery possible — but that reasoning has not been tested.

### Hardware result: the CM/LDFW initializer succeeds

The re-signed `cm.bin` was flashed to the `CM` partition — confirmed by the
PIT: name `CM`, id 91, 1792 blocks x 4096 = `0x700000`, exactly the image
size — and `run_ldfwok.sh` drew blue.

`ldfw: try to init N ldfw(s). except N ldfw N ldfw(s) have been inited done.`
is reached. **The precondition the fuse route has been blocked on since the
beginning is met.** The diagnosis held exactly: the only thing wrong was that
the LDFW modules were signed by Samsung while our chain carries our keys.

### Asking the secure side a read-only question

`--probe-otp-read` wires a trampoline in the cave to the LDFW success path:

```text
0x17ce00  stp x29,x30,[sp,#-16]!
0x17ce04  adr x0, 0x17ce18          ; scratch for the result
0x17ce08  bl  0xc90a2c94            ; USE_ROM_SEC_BOOT_KEY2 read
0x17ce0c  ldp x29,x30,[sp],#16
0x17ce10  ret
```

and the prompt to that function's own success print. The read issues
`smc(0xc2001014, 0x115, 0, 0)` and never touches a buffer.

`check_ldfw_observe_image.py --otpread` refuses to build unless the
trampoline's callee is the read function and is **not** the programming one,
resolving both by their own messages:

```text
trampoline calls the READ function (0x115)    PASS  0xa2c94 vs read fn 0xa2c94
trampoline is NOT the program function (0x16) PASS  program fn 0xa279c
RESULT: PASS - the only OTP command reachable is the read 0x115
```

```sh
tools/run_otpread.sh
```

| screen | conclusion |
|---|---|
| blue | the SMC returned 0 and the value was read; the OTP service is live |
| black | it still answers `-1` or an error, and the next marker splits which |

```text
build/otpread_chain/sboot.bin
sha256 3cee419bc457b642fc93eebedef5f7980b306c77f73eecf372c2563306ea8366
```

### Hardware result: the OTP service is live

`run_otpread.sh` drew blue. `smc(0xc2001014, 0x115, 0, 0)` returned 0 and the
USE_ROM_SEC_BOOT_KEY2 value was read back. The secure side answers OTP
commands.

Gates A and B are met:

| gate | state |
|---|---|
| A — silicon: KEY2 free, reachable, ahead of KEY in the selector | met, verified in the BootROM disassembly |
| B — execution: LDFW loaded and the OTP service answering | **met, on hardware** |
| C — mapping: `0x17` sets `SEC0.1` | still inference; needed only to *activate*, not to program |
| D — safety: one `0x16` call, on the confirmed success path, anchor checked | not done |

### Rehearsing the buffer path, read-only

`0x16` hands the secure side a 32-byte buffer. `0x114` hands it the same kind
of buffer and compares instead of burning:

```text
0xc90a299c  ROM_SECURE_BOOT_KEY2 check
            x0 = buffer, w1 = length, rejected unless 0x20
            -> "check: valid key" / "check: invalid key"
            -> "hasn't been programed yet"
```

`--probe-otp-check HEX32` puts the anchor and a trampoline in the cave, calls
the check from the LDFW success path, and wires the prompt to the
not-programmed message. The answer is independent of the bytes passed, so the
anchor is there only to make the rehearsal faithful.

```text
trampoline calls the CHECK function (0x114)   PASS  0xa299c vs check fn 0xa299c
trampoline is NOT the program function (0x16) PASS  program fn 0xa279c
length argument is 0x20                       PASS
RESULT: PASS - the only OTP command reachable is the check 0x114
```

```sh
tools/run_otpcheck.sh
```

| screen | conclusion |
|---|---|
| blue | the device's own service reports KEY2 blank, over exactly the path `0x16` would use |
| black | it answered "valid" or "invalid" instead — surprising, and worth stopping on |

```text
build/otpcheck_chain/sboot.bin
sha256 83d483a53b69709a68a5a6d29bb11a2b7f64b8f1cb2e0c8d161b2a5ec3805f81
```

### Hardware result: the service reports KEY2 blank, over the buffer path

`run_otpcheck.sh` drew blue. The device's own OTP service, reached through
`smc(0xc2001014, 0x114, ...)` with a 32-byte buffer, answers
`ROM_SECURE_BOOT_KEY2 hasn't been programed yet`. That is the same buffer
path `0x16` uses, exercised read-only, and it confirms the slot is still
blank from the device rather than from our own reasoning.

### The anchor value, settled against Samsung's own fused slot

Two claims in this project disagreed about what the 32 bytes are, and
burning the wrong one is irreversible. They are now reconciled, and the
decisive test needed no unknowns, because the KEY slot is already programmed
with Samsung's value and a full dump of it exists:

```text
st1_pub        stock EPBL +0x2bd0, 524 bytes
footer_hmac    stock EPBL +0x2ddc  b2106b55fb309df54ef821f824e4a8616c052bb588da6f2026b481a580233dc4
fused KEY      b444be33c467c9e58ef54d6067641a6ea2fb9d61e2d30ee219d1ad3b79425f0c

derived = footer_hmac XOR fused
        = 0654d5663f575410c00d6c984380b20fcefeb6d46a0961c23f652c9ef96162c8
HMAC-SHA512(derived, st1_pub[:136])[:32]
        = b2106b55fb309df54ef821f824e4a8616c052bb588da6f2026b481a580233dc4
        == footer_hmac                                              ✓
```

So the fused value is `footer_hmac XOR hmac_key`, and the relation closes on
Samsung's own key, its own hmac and its own programmed slot. As a by-product
it derives Samsung's `hmac_key` for this model.

None of the SHA-256 readings match:

```text
SHA256(pub[:136])  fae155fe...   no
SHA256(X||Y)       5981b859...   no
SHA256(pub 524)    ea6da353...   no
```

**The claim in `custom_key_fuse_port.md` that the `0x16` buffer is SHA-256 of
the public key is wrong, and has been corrected there.** Our anchor,
`1d12d364cf441dfe7d5084a054691cf1c7f71e068e2470881e52ce280c7c330b`, is
`our footer_hmac XOR our hmac.bin` — computed by the right rule, and now
checked against a slot the silicon already accepts.

This is the third time in this project that a self-consistent assumption
would have burned something unusable. The difference is that this one was
caught by testing the rule against hardware's own data instead of against
our signer.

### A safety check that was itself wrong

A global invariant was added to `check_ldfw_observe_image.py`: stock u-boot
has **zero** direct `bl` callers of the three one-shot OTP commands — they
are dispatched from a console table — so any direct caller in one of our
images is something we put there. Counting them is a complete statement that
an experiment cannot burn a fuse, and it runs on every build.

Auditing the eighteen chains built so far, the invariant flagged that
`key2_program_use_chain` calls the USE command. Good. But it reported
`key2_program_chain` as having **no** caller of the programming command,
which is false — that image exists precisely to call it:

```text
0xc904fc68  stp x29,x30,[sp,#-16]!
0xc904fc6c  adr x0, 0xc904fc84       ; the embedded 32-byte anchor
0xc904fc70  mov w1, #0x20
0xc904fc74  bl  0xc90a278c           ; program ROM_SECURE_BOOT_KEY2
```

The resolver walked back from the diagnostic string to the first prologue,
which lands on an inner `stp x29,x30,[sp,#-N]!` rather than the entry — it
returned `0xa279c` for a function that starts at `0xa278c`. The check then
counted callers of an address nobody calls, and passed.

Replacing it with "nearest call target" was also wrong: these commands are
never the target of a `bl` in stock, so that rule resolved all of them to
whichever function our own stub happened to call. The rule that holds is
that an entry is a prologue whose preceding instruction ends the previous
function — a `ret`, an unconditional branch, or padding. That resolves all
five OTP entries correctly:

```text
program KEY2  0xa278c      check KEY2  0xa298c      read USE_KEY2  0xa2c94
USE_KEY2      0xa2be0      BAN_KEY2    0xa2d54
```

### What that bug had already done

`--probe-otp-check` was built with the bad resolver, so its trampoline called
`0xc90a299c` — `sub sp,sp,#0xe0`, four instructions past the entry, skipping
the save of `x29`/`x30`, `x19`/`x20` and `x21`. The function ran on a
corrupted frame and returned through a link register restored from garbage.

The blue result still means what it meant: the `not programmed` print comes
before the epilogue, so the service did answer that KEY2 is blank. But the
call was malformed, and **the identical defect would have gone into the
programming chain** — entering a one-shot fuse command four instructions past
its prologue. The rebuilt image calls the real entry:

```text
trampoline calls the CHECK function (0x114)   PASS  0xa298c vs check fn 0xa298c
trampoline is NOT the program function (0x16) PASS  program fn 0xa278c

build/otpcheck_chain/sboot.bin
sha256 9213d96d82449a40105f871bba9536bed077293493b4ca09562640bc8ba50b6e
```

A second, independent net was added at the same time: the count of `smc #0`
instructions. Stock u-boot has 81; every chain built so far has exactly 81
and no new site, so none of them smuggles an inline SMC past the caller count.

### Hardware result: KEY2 blank, confirmed over a well-formed call

The rebuilt check chain drew blue. With the trampoline entering
`0xc90a298c` — the real prologue — the device's own OTP service again reports
`ROM_SECURE_BOOT_KEY2 hasn't been programed yet`. The earlier result stands,
and now it stands on a correct call.

### State of the fuse route

| gate | state |
|---|---|
| A — silicon: KEY2 free, reachable, tested ahead of KEY in the selector | met, from the BootROM disassembly |
| B — execution: Secure Payload absent but bypassed, CM/LDFW initialized, OTP service answering | **met, on hardware** |
| anchor value: `footer_hmac XOR hmac_key` | **verified against Samsung's own programmed slot** |
| KEY2 still blank | **confirmed by the device's own service** |
| C — mapping: `0x17` sets `SEC0.1` | still inference; needed only to *activate*, not to program |
| D — safety: one `0x16` call, on the confirmed success path, anchor checked at build time | not built |

What made B fall was a single fix: `cm.bin` re-signed with our ST2-TEE key
and flashed to the `CM` partition. Everything downstream of it had been a
consequence of LDFW modules signed by Samsung meeting a chain carrying our
keys.

Nothing irreversible has been done. KEY2 is 32 zero bytes. No image built
today can reach command `0x16`: the build refuses on two independent
invariants — zero direct callers of the three one-shot commands, and an
unchanged count of 81 `smc` sites.

What remains before the fuse is a decision rather than an investigation, and
gate D is the work that should precede it.

### Second-model review of the irreversible path, and what it found

Four concrete claims, all verified here:

**1. The existing `key2_program_chain` must be rejected, on two counts.**
Its fuse stub is installed over `check_signature` at `0x4fc68`, and that
function has **13 callers**. So the chain does not have "one call to the
programming command" — it has up to thirteen. And its `0xa6254` still reads
`0xb9428801`, the unpatched sentinel load, so it never had the Secure-Payload
bypass and could not have reached the LDFW success path at all. That is
consistent with every earlier trigger leaving KEY2 blank. Its SHA-256
`7d7609ef…53862` should be refused explicitly.

**2. On the u-boot side, `0x16` does not touch USE_KEY2.** The body of
`0xa278c` is byte-identical to stock, contains the single
`mov x1,#0x16` / `smc #0` pair at `0xa28e8`/`0xa28f8`, and never calls
`0xa2be0`. The three commands are separate wrappers. What cannot be ruled
out is a side effect inside the encrypted CM LDFW, and no read-only test can
prove the absence of an effect of a future write.

**3. The trampoline must consume its own result.** After `0xa64a4` the
caller does `ldr x23,[x23,#3768]` / `mov w0,#1` / `str w0,[x23,#704]`, so
`x0` is discarded immediately. Any signalling has to happen inside the
trampoline.

**4. The "zero direct `bl` callers" invariant is incomplete.** It proves only
that no new `bl` reaches the resolved entry. An image could still reach
`0x16` through `b`/`br`/`blr`, by branching into `0xa28e4` where the SMC
arguments are prepared, by altering the console dispatch table, by changing
an existing SMC's `x1` from `0x115` to `0x16`, or by code built in RAM. The
unchanged count of 81 `smc` sites says nothing about their arguments. And
"no route exists in stock" is false: the console route exists.

The property that would actually hold is differential, not absolute:

```text
the final image may differ from the pinned base only inside an explicit
allowlist of ranges; the full bodies of 0xa278c, 0xa2be0 and 0xa2d54 are
byte-identical to the base; all 81 SMC sites and their argument windows are
byte-identical; the console dispatch table is byte-identical; the cave holds
exactly one new entry, reached only from 0xa64a4.
```

and the base itself should be pinned by SHA-256 rather than located by text.

**On verification after the fact**, `0x114 == valid` is necessary but not
sufficient, because in the same boot it may be answering from shadow state.
The adequate evidence is: `0x16 == 0`, then `0x114(anchor) == 0`,
`0x115 == 0` and `0x116 == 0` before any reset; then a full cold cycle; then
in a fresh EUB session read the 32 bytes at `0x10003020` and require exact
equality with the anchor, re-read KEY and require it unchanged, and read
SEC0/SEC1 and require the selector still at `0x10003000`.

### The differential gate

`tools/check_fuse_image_diff.py`, wrapped by `tools/fuse_gate.sh` with this
project's allowlist. It replaces the caller count, which was not a safety
property, with a differential one:

```text
candidate is not a refused image                 PASS
differences confined to the allowlist            PASS
SMC site count unchanged                         PASS  81 sites
allowlist disjoint from SMC windows and bodies   PASS
program ROM_SECURE_BOOT_KEY2 body identical      PASS  0xa278c-0xa298c
program USE_ROM_SEC_BOOT_KEY2 body identical     PASS  0xa2be0-0xa2c94
program BAN_ROM_SEC_BOOT_KEY2 body identical     PASS  0xa2d54-0xa2e08
branches reaching the programming wrapper == 0   PASS
the anchor is present exactly once               PASS
```

The base is the stock image after `scripts/patch_9825.py`, pinned by SHA-256
`582f7d62…21fd`, so the eng transformation is audited once rather than per
chain. The ST2 footer range is allowed because it is the re-signature, and
it is checked by `verify_9825.py` and by the offline verifier instead.

Writing it found two defects in itself, both of the class that bricks:

- `function_extent` stopped at the first `ret`. These wrappers return from
  several places, so for the programming function it covered `0xa278c-0xa27e4`
  — 0x58 bytes — while the `smc` that burns the fuse sits at `0xa28f8`,
  outside. The "body identical" check was guarding the harmless half. Fixed
  by ending the extent at the next function entry; each wrapper now covers
  its own single SMC.
- the branch scan counted a function's branches to its own epilogue. Fixed
  by ignoring branches that originate inside the function.

It also refuses the superseded fuse image by hash, with the reason attached:
`7d7609ef…53862`, 13 call sites and no sentinel bypass.

### Audit across every chain built

Only the two legacy `key2_program_*` images contain a branch reaching the
programming wrapper, at `0x4fc74`. The sixteen chains built and run today
contain none:

```text
key2_program_chain        FAIL  0x4fc74
key2_program_use_chain    FAIL  0x4fc74
everything else           PASS  none
```

So every experiment run today was, verifiably, incapable of burning a fuse.

### Where the two halves of the goal stand

The objective — a custom sboot booting from UFS on a cold start, without EUB
— needs two independent things, and only one moved today.

| half | state |
|---|---|
| the fuse: KEY2 programmed and then activated so the BootROM trusts our anchor | preconditions all met on hardware; gate D now has its tool; `0x17` still rests on the unproven C/D mapping |
| the chain: our resigned sboot actually booting from UFS | **unchanged and still unexplained** — `epbl_pad_tamper` and the minimal chain were built and never run |

Programming the hash (`0x16`) changes nothing about booting: while `SEC0.1`
is 0 the selector never reads the KEY2 slot. Activation (`0x17`) is what
makes the BootROM stop consulting Samsung's key, and doing that before the
UFS boot works would leave the board EUB-only — recoverable through
`BAN_KEY2` only if the C/D mapping is right, which is exactly what is not
proven.

So the order that keeps every step reversible is: program the hash, solve
the UFS boot, then consider activation.

### Hardware result: the container footer is not enforced, and a bad LDFW is fatal

`build/epbl_pad_tamper_chain/sboot.bin` — the stock image with one byte of
the EPBL's unsigned ST1 padding flipped at `0x2e88` and the header checksum
recomputed, five bytes in all, which leaves every stage signature valid and
only the container footer at `0x364100` wrong — was flashed to BOOTLOADER.

With our re-signed `cm.bin` still on the CM partition it went black. With the
stock `cm.bin` restored it **booted normally**. Two answers:

1. **The container footer is not checked at boot.** It is flash/OTA metadata,
   which matches the earlier finding that only u-boot's Download/update path
   parses `SignerVer03`. The minimal chain is therefore interpretable: a
   black screen from it would be about the EPBL, not about a signature we
   cannot produce.
2. **An invalid LDFW stops a normal boot.** The first black was our
   re-signed `cm.bin` meeting stock's verification against Samsung's key.

The second matters for activation. After `USE_KEY2` is set, the board needs
**both** our chain booting from UFS **and** our `cm.bin` on the CM partition.
The two are coupled, and either one wrong is a board that does not boot.

### EUB is unavailable for about a week

Entry to EUB was done by shorting two resistors on the testpoint traces, and
one of them broke. A fine tweezer to contact the exposed trace is up to six
days out.

**Nothing irreversible may be attempted until EUB is back.** The recovery
path for a bad activation — stream the chain over USB, initialize CM/LDFW,
issue `BAN_KEY2` — runs entirely through EUB. Without it there is no way to
undo an activation that leaves the board unable to boot. Programming the
hash alone would still be inert, but there is no reason to spend the
one-shot slot while the safety net is down.

What is still possible meanwhile: Download-mode flashing, and cold-boot tests
of Samsung-signed images. What is blocked: anything needing the payload,
which includes the minimal chain, because our EPBL only verifies when the
payload redirects `PTR_SECUREBOOT_KEY`.

### 2026-10-20: the minimal chain is black from UFS too, so it is not the stages

`minimal/sboot.bin` was flashed to BOOTLOADER with the **stock** `cm.bin` on
CM, and `native-triple minimal` run against it. `EUN3REC0`, `EUN3REC1` and
`EUN3REC2` arrived at 0.039 s, `EUN3REC3` did not, and **the screen stayed
black**. Record presence carries no information -- the successful stock run
lost `EUN3REC3` as well -- so the screen is the whole result.

Every observable matches the successful stock run value for value: key
selector 1, **post-load verifier 1**, warm/cold gate `0x00000000`, boot flags
`0x00300edf` then `0x00b00edf`, EPBL entry/gate-load
`0x14000002`/`0x580002d4`, gate branch `0x54000041`, dispatch literal
`0x02020128`, `SCTLR_EL3=0x00c51838`, `CurrentEL=0xc`. Only the residual
dispatch word differs (`0x7466e433`, against `0x7466ecb3` stock), and the cold
path never reads it.

The image is the point. Against the stock EPBL it differs in 321 bytes, and
every one of them is identity:

```text
0x0004..0x0007    4   header checksum
0x294c..0x29bf   95   st2_key_ree      <- ours
0x2be4..0x2c57   96   st1_publickey    <- ours
0x2ddc..0x2dfb   31   hmac             <- ours
0x2e14..0x2e87   95   signature        <- ours
```

**Not one byte of EPBL code, and `st2_key_tee` untouched**, so FWBL1, BL2,
u-boot, el3_mon and secure_payload on UFS are Samsung's own, carrying
Samsung's signatures, verified against Samsung's key. The same image reached
the Odin screen when streamed over USB earlier the same day, so it is not
malformed.

| image on UFS | key redirect | storage path | screen |
|---|:-:|:-:|---|
| stock | no | yes | charging screen |
| `ecdsa_eng` | yes | no (USB) | Download mode |
| `minimal` | yes | no (USB) | Download mode |
| `ecdsa_eng` | yes | yes | black |
| `minimal` | yes | yes | **black** |

So **the resigned ST2 stages are not the cause**. That hypothesis is closed.
What remains inside the image is the ST1 identity block, plus `st2_key_ree`
and the container footer re-signed with it.

#### The confound that is left, and it cannot be tested directly

The redirect is present in every black row and absent from the only white
one. It cannot be separated by testing stock-image-plus-redirect, because the
BootROM would then verify Samsung's EPBL against our key and reject it for a
trivial reason. The two are entangled by construction.

What can still be split is inside the image. A variant that keeps Samsung's
`st2_key_ree` and leaves the container footer alone -- legitimate, since the
`epbl_pad_tamper` run proved an invalid footer boots -- reduces the diff to
checksum, `st1_publickey`, `hmac` and `signature`: pure ST1 identity. Black
there puts it on the identity or the redirect; a boot puts it on
`st2_key_ree` or the re-signed footer.

#### A hypothesis worth measuring, from where the key lives

`PTR_SECUREBOOT_KEY` is pointed at `custom_boot_key`, which sits inside the
relocated worker at `RELOCATED_BASE = 0x02025000` (the payload loads at
`0x02022000`, which is also the EPBL's load destination, which is why the
worker relocates at all). The post-load verifier returning 1 proves the
pointer was still good at that moment. It proves nothing about later: the
EPBL goes on to load and verify FWBL1 and BL2 from UFS itself, and if the UFS
path reuses `0x02025000`, every verification after our last observation point
reads a clobbered key and fails. That would be black with a verifier that
already said 1, and it would not happen on the USB path. Unmeasured.

### 2026-10-20: moving the key did not help, so the clobber idea is closed

`native-keysafe minimal` ran against the same `minimal/sboot.bin` on
BOOTLOADER, with the 32 key bytes copied to `0x02021800` and
`PTR_SECUREBOOT_KEY` aimed there instead of at `custom_boot_key` inside the
relocated worker at `0x02025000`. **Black screen.**

So the bytes the verifier dereferences were not being overwritten where they
used to live, and the hypothesis is closed. In hindsight the static evidence
was already against it: `0x02025000` is the gap the payload author picked
precisely because the EPBL image ends there and FWBL1 starts at
`0x02026000`.

### What is still standing, and the control that was never run

Eliminated so far: the resigned ST2 stages, and the address of the key.
Still standing, inside the image: the ST1 identity (`st1_publickey`, `hmac`,
`signature`, checksum) and `st2_key_ree` with the footer re-signed under it.
Still standing, outside it: the redirect.

The redirect has never been testable because it is entangled with the image
-- a stock image with our key is rejected, and our image without the redirect
is rejected, both for trivial reasons. There is one configuration that breaks
the entanglement and it has not been tried:

**stock `sboot.bin` on UFS, redirect machinery fully active, pointed at
Samsung's own fused KEY value** (`b444be33...`, read off this device's
`0x10003000` and recorded above). Verification then passes for exactly the
reason it passes on a stock boot, and against the one row that boots the only
difference left is that `PTR_SECUREBOOT_KEY` aims at our iRAM copy instead of
at the fuse slot.

| image on UFS | pointer aims at | expected to verify | screen |
|---|---|:-:|---|
| stock | fuse slot (no redirect) | yes | charging screen |
| `minimal` / `ecdsa_eng` | our key in iRAM | yes (verifier returned 1) | black |
| stock | **Samsung's value in iRAM** | yes | **unmeasured** |

A boot on that third row clears the redirect and puts the failure squarely in
our ST1 identity. A black screen says the redirect itself breaks the UFS path
and the image was never the variable -- which would mean the chain cannot be
tested on UFS at all before the fuse is burned, and that is worth knowing
before anything irreversible.

Built as `epbl_boot_ufs_native_stockkey_probe`, run with
`tools/run_ubstage_test.sh native-stockkey`. It needs the stock sboot back on
BOOTLOADER, which also returns the board to a state that boots on its own.

### 2026-10-20: the redirect is cleared, and Samsung puts the same key in both slots

`native-stockkey` was run with the stock `sboot.bin` back on BOOTLOADER and
the redirect machinery fully active, aimed at Samsung's own fused KEY value.
**Charging screen.** So the redirect is harmless on the UFS path, and the
failure is inside the image.

| image on UFS | pointer aims at | screen |
|---|---|---|
| stock | fuse slot, no redirect | charging screen |
| stock | **Samsung's value in iRAM** | **charging screen** |
| `minimal` | our key in iRAM | black |
| `ecdsa_eng` | our key in iRAM | black |

Rows 1 and 2 differ only in where the pointer aims, so the redirect is clean.
Rows 2 and 3 differ only in the image, so the image is the variable. Both
halves of the entanglement are now resolved.

#### A property of the stock image that both our builds break

```text
stock       tee=a6bc5d80a0612e82...  ree=a6bc5d80a0612e82...  tee == ree
minimal     tee=a6bc5d80a0612e82...  ree=cdcc93e17e0a214d...  differ
ecdsa_eng   tee=21010375c300ea56...  ree=cdcc93e17e0a214d...  differ
```

**Samsung puts the same key in both ST2 slots.** Every image that boots has
`st2_key_tee == st2_key_ree`; every image that is black has them different.
That is 4/4 across the table, and it suggests the storage path verifies with
the REE slot where the USB path uses the TEE slot -- which would explain the
whole history at once, including why `ecdsa_eng` fails even though its stages
are signed with its own TEE key.

It is a fit, not a mechanism. Nothing in the disassembly has been shown to
select the slot by boot source yet.

#### The chain that tests it

`make_minimal_epbl_chain.py --keep-ree` leaves Samsung's `st2_key_ree` in
place and leaves the container footer stale -- harmless at boot, as the
`epbl_pad_tamper` run established. The result differs from the stock 4 MB
image in **226 bytes, every one of them the ST1 anchor**:

```text
0x0004..0x0007    4   header checksum
0x2be4..0x2c57   96   st1_publickey
0x2ddc..0x2dfb   31   hmac
0x2e14..0x2e87   95   signature
```

Both key slots are Samsung's. Run with
`tools/run_ubstage_test.sh native-triple keepree`.

A charging screen means the REE slot was the whole problem, and the fix for
`ecdsa_eng` is to sign the container with the same key that is in the TEE
slot. A black screen puts it on the ST1 anchor itself, 226 bytes that the
BootROM verifier has already accepted -- a much stranger place to be.

### 2026-10-20: the screen oracle is invalid, and everything read off it falls

`native-nohandoff` was run with stock on BOOTLOADER and stock on CM. The
payload parks in an infinite loop where it would branch into the EPBL, so
nothing entered the EPBL and nothing could reach u-boot.

**The charging screen appeared anyway.**

So a stall produces the screen by itself. The mechanism is the one that was
raised and not taken seriously enough: the run stalls, the device resets, the
BootROM cold-boots whatever is on UFS with the **fused** key, and the panel
lights if that image verifies.

Every conclusion drawn from this oracle is withdrawn:

| run | what was concluded | what it actually showed |
|---|---|---|
| `native-triple-stock` | the handoff carries EPBL→u-boot | stock cold-boots |
| `native-stockkey` | the redirect is clean on the UFS path | stock cold-boots |
| `native-triple minimal` | the ST1 anchor fails on the UFS path | our image cannot cold-boot under Samsung's fused key |
| `native-triple` (eng) | the resigned chain fails on the UFS path | same |

EP1 is no help either: it died at 0.046 s in this run too, with the payload
sitting in a loop, so its disappearance has nothing to do with the handoff.

#### What is actually known about the UFS path

Nothing. The instrumented handoff's outcome has never been observed. The
screen reported a later cold boot in every case, and that cold boot used the
fused key, which is why our images were black and Samsung's was not. Both
outcomes were determined before the handoff was ever reached.

So there is **no evidence that our chain fails to boot from UFS**, and none
that it succeeds. The question is unmeasured, not answered. The earlier
reading -- "the resigned ST2 stages are cleared", "the failure is the ST1
identity" -- rested on this oracle and goes with it.

#### Why that changes the fuse calculus

Every black screen came from a cold boot verifying against Samsung's fused
KEY. After `USE_KEY2` the BootROM consults our KEY2 instead, so that
mechanism disappears: a cold boot would verify our image against our anchor.
The thing that produced every failure was the absence of the fuse.

That is an argument, not a demonstration. Activating would still be the first
time our chain is known to have been given a fair attempt from UFS.
