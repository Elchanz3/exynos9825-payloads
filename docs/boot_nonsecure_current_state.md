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
- FWBL1: ~8 KB plaintext stub (`0x02026000..0x02028000`) + encrypted body
  (`0x02028000..`, byte-entropy ~8.0). The stub self-decrypts the body at runtime;
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

The non-destructive sboot bypass makes the fuse reachable: a modified sboot can run
to Download mode with LDFW up, where the OTP SMC is available.

OTP SMC interface, `CallSecureMonitor(0)` with SMC id `0xc2001014` and a command:
- `0x16`  program ROM_SECURE_BOOT_KEY2 (`FUN_c90a278c(key[0x20], 0x20)`); the 0x20
  bytes are SHA-256 of the public key, copied into a 0xa0 buffer, CRC32 appended,
  then SMC. KEY2 is one-shot.
- `0x2`   set USE_ROM_SEC_BOOT_KEY (`FUN_c90a2618`).
- `0x101` read USE_ROM_SEC_BOOT_KEY; `0x115` read USE_KEY2; `0x114` check KEY2.
- `secure_boot_enable` (`FUN_c90a5368`): read USE_KEY; if unset, program
  ROM_SECURE_BOOT_KEY + set USE_KEY (manufacturing flow, slot 1 KEY not KEY2).

Additive vs replace: KEY and KEY2 have independent USE flags
(USE_ROM_SEC_BOOT_KEY, USE_ROM_SEC_BOOT_KEY2) plus a BAN_ROM_SEC_BOOT_KEY2, which
implies the ROM accepts a stage if `(USE_KEY && hash==KEY) || (USE_KEY2 &&
hash==KEY2)` — additive. If so, programming KEY2 = SHA-256(st1 pubkey) and setting
USE_ROM_SEC_BOOT_KEY2 while leaving Samsung's KEY/USE_KEY intact keeps the stock
chain bootable as a fallback (low brick risk). This is inference, not proof; the
authoritative logic is in the secure ROM/LDFW.

Safe next step (no write): an OTP-READ experiment — a modified sboot (via the
bypass) patched to call the read commands (USE_KEY `0x101`, USE_KEY2 `0x115`, KEY2
check `0x114`) and surface the values (the routines already printf
`[OTP] ... read value: 0x%llx`; confirm whether that reaches EP1 or the panel).
Confirms KEY2 is free and USE_KEY is set, and validates the OTP SMC from this
context, without programming anything.

## Open items

- Persistent UFS boot (no USB payload) requires the OTP fuse; the bypass does not
  persist across reboot.
- Running a live Android image (not only Download mode) over USB is unexplored.
- No verification vulnerability found in the BootROM/EPBL/monitor verify path; the
  fuse is the only known route to a persistent custom trusted key.
