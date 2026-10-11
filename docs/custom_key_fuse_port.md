# Exynos9825 Custom-Key / Fuse Port (persistent custom sboot)

Goal: run a custom-key-signed boot chain persistently (no EUB each boot). This
requires fusing a custom secure-boot key, then booting a resigned chain from UFS.
Method: port the henr1kas/Exynos custom-key methodology to 9825 (approved by the
owner to base on / copy-adapt from henr1kas; the earlier `payloads/` work stays
original). 9825 = EPBL-based stages (like 9840) + **CodeSigner V5 / ECDSA P-384
(`sign_type 4`)** — see "Signature scheme" below. It is *not* RSA `sign_type 0`.

Working files are persisted at `$EUB/9825_customkey/` (scripts, keys, resigned
output, 9840 reference payloads). `$EUB` = the local firmware dir.

## Why the download-mode OTP attempts failed (settled)

The fuse is done by sboot's own OTP program functions (SMC `0xc2001014`), which
require LDFW (secure firmware) loaded. LDFW loads only during a real boot from
UFS (full secure init), NOT during USB-download injection:

- USB-download injection → download mode → sboot releases USB after `el3_mon`
  and goes to Odin; the secure payload / LDFW (loaded by sboot from the UFS
  partition) is skipped (`0x3374` decision keyed on the iRAM boot-mode magic at
  `0x80000000`). OTP SMC then returns `-1` ("[OTP] LDFW hasn't been loaded").
- Forcing LDFW/secure-payload load in download context either faults the OTP
  crypto or hangs sboot (dependencies tied to normal boot).
- Confirmed read-only OTP state (via a force-LDFW probe that only enables the
  simple flag reads): **USE_KEY=1, USE_KEY2=0, BAN_KEY2=0**. Buffer-passing OTP
  ops (KEY2-check, KEY2-program) additionally need the buffer at a DRAM address
  (stack VA faults the secure monitor) AND full LDFW crypto; they fault without
  the complete secure init.

Conclusion: the fuse must run during a UFS boot (LDFW present), which is exactly
what the henr1kas `boot_ufs` payload triggers.

## The flow (henr1kas, adapted to 9825)

1. Resign the whole chain with our keys (`build.py` + `keys/`).
2. Boot the resigned chain to Download mode with
   **`build/epbl_custom_key_efuse_probe.bin`** — **this works on hardware**. It
   `str`s the address of our 32-byte key into `0x0202006c`, so the BootROM
   verifies our ST1 against *our* key. Non-destructive: no fuse, nothing written
   to UFS, and the iRAM pointer is gone on reboot. Verification is *redirected*,
   not disabled, so `epbl_sboot_noverify_probe` is **not** needed on this path —
   the ST2 stages verify legitimately against the `st2_key_tee` embedded in our
   own EPBL footer.

   Proven run (`./run_custom_key_test.sh efuse`, chain `ecdsa_resigned`, no eng
   patches, no noverify):

   ```
   EPBL RX Done / Pass: Loading EPBL      <- our ST1 accepted by the BootROM
   [BL2] USB Loading Start / Done
   DMC01..DMC25                           <- real DRAM training
   BL2 Pass
   [U-boot] USB Loading Start / Done
   [EL3_MON] USB Loading Start / Done
   ```

   and the phone reached USB Download mode on screen.

   (`epbl_sboot_noverify_probe` remains available as a fallback: it re-points
   `PTR_IS_SECUREBOOT (0x020200a8)` at a `mov w0,#0; ret` stub in the FWBL1
   padding (`0x02038010`), which *disables* verification. It cannot boot our own
   ST1 — it only defeats a later check — so it is only useful with the stock
   EPBL.)
3. `boot_ufs` via Houston (USB): sets the iRAM boot-state (`0x02020064`) and
   loads the chain from UFS → full secure init, LDFW loads
   → the fuse-patched sboot burns our key (irreversible, one-shot).
4. Reboot: the BootROM now trusts the fused (our) key → boots the resigned chain
   from UFS with no EUB. Persistent.

EUB is needed only a few times (flash + fuse), never after.

## Key mechanism details

- Fuse code (`patch_fuse_boot_key`): replaces `check_signature` in u-boot with a
  stub that calls the OTP program routines with the embedded key. On 9825 the
  targets are the **free slot KEY2** (`cm_otp_write_rom_sec_boot_key2`, SMC cmd
  `0x16`) and `cm_otp_write_use_rom_sec_boot_key2` (cmd `0x17`), because
  Samsung's own key occupies slot 1 (`USE_KEY=1`). Located by the strings
  "There is no signature", "[OTP] ROM_SECURE_BOOT_KEY2 program start",
  "[OTP] USE_ROM_SEC_BOOT_KEY2 program start". USE_KEY2 is set only if KEY2
  programming returned success. `should_fuse_key = False` by default (the
  irreversible switch).
- Fused key value (`get_efuse_data`): must mirror `sign_st1` exactly, or the
  one-shot fuse burns a hash that can never match the footer. On 9825
  (`sign_type 4`) that is `HMAC_SHA512(hmac_key, st1_pubkey_blob[:136])[:32] XOR
  hmac_key`, from `keys/hmac.bin` (32 bytes) + `keys/4/st1.pem`. The RSA variant
  (`HMAC_SHA256` over the full blob, `keys/0/st1.pem`) applies only to
  `sign_type 0` SoCs. Verified: the result XOR `hmac_key` equals the `hmac` field
  the signer writes into the SBL1 footer.
- iRAM control block:
  - `0x020200a8` = PTR_IS_SECUREBOOT — our proven non-destructive bypass target.
  - `0x02020064` = boot-state (read live `0xcb000041`; 9840 boot_ufs sets
    `0xCB000010`). Present in the BootROM's control-block reader literal pool.
  - `0x0202006c` = **PTR_SECUREBOOT_KEY, and it is LIVE on 9825** — see
    "The secure-boot key pointer" below. (An earlier revision of this document
    claimed it was inert here. That was a method error: the search looked for
    `0x0202006c` as a literal-pool constant, but all three references build the
    address with `movz`/`movk`, which such a search cannot find. The
    control-block reader at `0x1cbc8` really does not read `0x6c` — but `0x6c`
    has its own dedicated accessor pair, and that is what the verify path uses.)

## The secure-boot key pointer (`0x0202006c`)

Three references, all building the address with `movz`/`movk`:

| site | role |
|---|---|
| `0x5760` | getter: `mov x0,#0x6c ; movk x0,#0x202,lsl#16 ; ldr w0,[x0] ; ret` |
| `0x5770` | setter: `mov x1,#0x6c ; movk x1,#0x202,lsl#16 ; str w0,[x1] ; ret` |
| `0x1a2bc` | diagnostic dumper (also reads `0x7c` the same way) |

The selector at `0x5780` writes one of three pointers through `0x5770`:

| selector | pointer written | then |
|---|---|---|
| 1 | `0x10003000` — fused KEY slot | `bl 0x16eac` |
| 3 | `0x10003020` — fused KEY2 slot | `bl 0x16eac` |
| 2 | `0x0001fae0` — ROM key table | `bl 0x16eac` |
| 4 / default | `0x0001fae0` | — |

`0x16eac` is `mov w0,#4 ; b 0x16368` (records the key source). `0x10003000`
and `0x10003020` are `0x20` apart — the two 32-byte OTP key slots, dumped
register-by-register at `0x1a7cc..0x1aa24`. That matches the OTP state we read:
`USE_KEY=1, USE_KEY2=0, BAN_KEY2=0`.

The consumer, at `0x59d0` (and the same shape at `0x58f8`):

```
bl   0x5760                 ; w19 = key pointer
ldr  w1, [x0, #20]          ; w1 = key_index from the image footer
and  w0, w19, #0xfffe0000   ; is the pointer inside ROM (< 0x20000)?
b.ne 0x59f0
add  w19, w19, w1, lsl #5   ;   if ROM: w19 += key_index * 32  -> it is a TABLE
...
mov  w2, #0x20              ; KEY SIZE = 32 BYTES
ubfx x1, x19, #0, #32       ; the key pointer
bl   0xc1f8                 ; verify(0, key_ptr, 32, ...)
```

So `0x0202006c` points at a **32-byte** key/hash, and the pointer value decides
how it is read:

- **below `0x20000`** → a ROM-internal key *table*, indexed by the image's
  `key_index` with stride 32. `0x1fae0..0x20000` is `0x520` = 41 slots; the SBL1
  footer's `key_index = 0` selects `0x1fae0` exactly, and the ROM data there is
  high-entropy key material.
- **at or above `0x20000`** → used directly as a single 32-byte key, with no
  indexing. This is how the fused slots are consumed, and it is the case we can
  exploit.

**Consequence.** A payload can place our own 32-byte key value anywhere in iRAM
(at an address `>= 0x20000`, so the table indexing is skipped) and `str` that
address into `0x0202006c`. The BootROM then performs a *real* signature
verification of ST1 against **our** key — no fuse, nothing disabled, and fully
reversible because iRAM is volatile. This is strictly better than the noverify
bypass, which only switches verification off.

The fuse is therefore needed only for **persistence** across reboot. The entire
custom-key chain can be validated non-destructively first.

**Confirmed on hardware.** The expected 32-byte value is the form
`get_efuse_data()` returns — `HMAC-SHA512(hmac_key, st1_publickey[:136])[:32]
XOR hmac_key`, i.e. what the fuse would burn — **not** the un-XORed
`footer.hmac`. So the OTP slot stores the XORed form and `0x599c` compares
against it directly. The un-XORed candidate was rejected with status `0x105`.

Writing the pointer immediately before the `0x5b58` call is late enough: the
BootROM's own selector does not run again afterwards and does not overwrite it.

## 9825 stage layout (`scripts/s5e9825.py`, validated by split)

`sboot.bin` (0x400000) splits by ST2 signature into:
`epbl(st1) 0x3000, fwbl1(update_header) 0x13000, bl2 0x52000, pad 0x3c000,
u-boot 0x180000, el3_mon 0x40000, secure_payload 0x100000, tail 0x9c000`.
The `secure_payload` (1 MB) holds the LDFW and was the stage we never sent.
Odin set also includes `cm.bin`, `keystorage.bin` (SLSI v0x20).

`sboot.bin` also carries an **`AVBf` footer in its last 0x40 bytes**, so
`get_target_boundary()` returns `0x364310`, not `0x400000`. Any footer offset
math must use that boundary. Resulting footer offsets:

| block | span | ST2 footer |
|---|---|---|
| epbl (ST1) | `0x0`–`0x3000` | SBL1 footer fields @ `0x26e0`, sig @ `0x2e00` |
| fwbl1 | `0x3000`–`0x16000` | `0x15df0` |
| bl2 | `0x16000`–`0x68000` | `0x67df0` |
| pad | `0x68000`–`0xa4000` | unsigned |
| u-boot | `0xa4000`–`0x224000` | `0x223df0` |
| el3_mon | `0x224000`–`0x264000` | `0x263df0` |
| secure_payload | `0x264000`–`0x364000` | `0x363df0` |
| tail | `0x364000`–`0x400000` | unsigned |
| whole image | `0x0`–`0x364310` | `0x364100` |

## Signature scheme (measured on stock N975F `sboot.bin`)

The SBL1/EPBL footer reports `codesigner_version = 5`, `ap_info = 'SLSI'`,
`rb_count = 9`, `signing_type = 4`, `signature_size = 136`. The RSA/V4
interpretation of the same bytes yields garbage in every field
(`ap_info = ',ug\x96'`), so the V5 parse is decisive. Note the two footer
structs put `codesigner_version` at *different* offsets — ECDSA/V5 at
`sbl1_size-2352`, RSA/V4 at `sbl1_size-1024` — and `load_sbl1_footer` tries
ECDSA first.

- **ST2 stages**: footer `ST2ECDSA` (0x210) at `end-0x210` =
  `rb_count(4) sign_type(4) key_type(4) key_index(4) signature(136) padding(376)`.
  Signature at `end-0x200` is `r`,`s` as 68-byte **big-endian** slots holding
  48-byte P-384 values (20 leading zero bytes each). Signed range is
  `data[:end-0x200]`, i.e. only the four metadata words are covered;
  everything from `end-0x200` on is **not signed**. Algorithm: ECDSA
  SECP384R1 over `SHA-512(signed_range)`, passed as `Prehashed(SHA512)`.
  Measured metadata, identical in all five stock stages:
  `rb_count=9 sign_type=4 key_type=0 (TEE) key_index=0x31fb208f` — `rb_count`
  and `sign_type` match the SBL1 footer, which cross-confirms the layout.
  `fwbl1` verifies with the checksum cleared (`data[4:8]` zeroed), matching its
  `update_header=True`; the other four verify as-is.
- **ST1 / epbl**: ECDSA P-384 over `SHA-512(data[:0x2e00])`, verified against
  the embedded `st1_publickey`. `sign_st1` writes `checksum` *after* signing and
  the checksum lies inside the signed range, so **any ST1 verify must zero
  `data[4:8]` first**. Stock behaves identically. Also
  `checksum == SHA-512(data[0x10:sbl1_size])[:4]`.
- **Embedded keys** live in the SBL1 footer as 524-byte blobs:
  `20×00 ‖ x(48 BE) ‖ 20×00 ‖ y(48 BE) ‖ 388×00`, so `x` at `blob[0x14:0x44]`
  and `y` at `blob[0x58:0x88]`; loaders read `blob[:68]` / `blob[68:136]`.
  Fields: `st2_key_tee`, `st2_key_ree` (byte-identical on stock — one key for
  both) and `st1_publickey`. All five stock ST2 stages verify against
  `st2_key_tee`.
- The `hmac` field = `HMAC_SHA512(hmac_key, st1_publickey[:136])[:32]`.

## Status

- DONE: `s5e9825.py` (stage layout validated by split; `signing_type = 4`);
  `split.py s5e9825` extracts all stages including `secure_payload`;
  P-384 keys at `keys/4/{st1,st2t,st2r}.pem` + `keys/hmac.bin`.
- DONE: `patch_9825.py`. All 7 eng patches resolve structurally (string xrefs,
  no hardcoded addresses) onto real prologues: `check_signature 0x4fc68`,
  `etc_market 0xa1684`, `etc_development 0xa1694`, `commercial_bit 0xa1704`,
  `set_warranty_void_bit_reason 0xb468`, `set_warranty_bit 0xa1da0`,
  `read_rlc_rpmb 0xc624`, `read_kg_rpmb 0xc900`, `have_this_mode 0xa9e6c`.
  `patch_fuse_boot_key` resolves `write_key2 0xa278c` (SMC cmd 0x16) and
  `write_use_key2 0xa2be0` (SMC cmd 0x17); its emitted stub is hand-verified
  (adr → `0x4fc8c`, both BL targets, `cbnz` guard so USE_KEY2 is never set if
  KEY2 programming fails). Note `patch_fuse_boot_key` runs **instead of and
  before** `patch_check_signature` — it installs its own stub ending in
  `mov x0,#0 / ldp / ret` over the same function, and `is_entry()` needs the
  original prologue still intact to locate it.
- DONE: **full chain resigned with our keys under ECDSA P-384 and verified
  against the device's own algorithm.** Artifacts: `ecdsa_resigned/sboot.bin`
  (plain resign control) and `ecdsa_eng/sboot.bin` (eng-patched, the step-2
  artifact). Both: ST1 valid vs our embedded `st1_publickey`, all five ST2
  stages plus the whole-image footer valid vs our `st2_key_tee`, the stock
  Samsung key rejected everywhere, metadata preserved
  (`rb_count=9 sign_type=4 key_type=0 key_index=0x31fb208f`), and
  `footer.hmac` consistent with `get_efuse_data()`.
  Build recipe, from `$EUB/9825_customkey/`:

  ```sh
  rm -rf <dir> && mkdir <dir>
  python3 scripts/split.py s5e9825 input <dir>
  python3 scripts/patch_9825.py <dir>/sboot/u-boot.bin   # eng build only
  python3 scripts/build.py s5e9825 keys <dir>
  ```

  Omitting the `rb_count` argument preserves the stock `rb_count = 9` already
  present in the footer bytes.
- SUPERSEDED, do not flash: `resigned_output/` and `output_eng/` were produced
  under `signing_type = 0`. Their RSA signatures landed at `end-0x110`, which on
  this SoC is the **unsigned padding** after the real ECDSA signature (which
  ends at `end-0x178`), so they never replaced anything: 4/5 stages still
  carried valid *Samsung* signatures and the eng-patched `u-boot` carried a
  **broken** one. They would be rejected. The earlier "resign validated, RC=0"
  was a false positive — it checked our own RSA signature with our own RSA key
  at an offset the device never reads.
- RULE: never accept a signature "validated" by our own signer+key pair. Verify
  against the key embedded in the image, using the splitter's own verify
  function (`is_good_sig_ecdsa` / `load_public_key_p348`), which is the device's
  algorithm. A negative control must fail: a body-modified stage must not pass.
- DONE, on hardware: **the custom-key chain boots non-destructively.**
  `build/epbl_custom_key_efuse_probe.bin` + `ecdsa_resigned` reached USB
  Download mode with our ST1 accepted by the BootROM and every ST2 stage
  verified against our own embedded key. No fuse, no UFS write. So the fuse is
  now only about **persistence across reboot**.
- TODO, roughly in order:
  1. Run the same path with the eng build:
     `./run_custom_key_test.sh efuse ecdsa_eng`. Still non-destructive. This is
     the build we would actually want on UFS.
  2. **Then** the Odin flash to UFS — and note what it costs. After our `sboot`
     is on UFS, a normal boot uses the fused/ROM key (the iRAM re-point is
     gone), so the BootROM rejects our EPBL and the phone will not boot from
     UFS until either the fuse is burned or stock `sboot` is reflashed.
     Recoverable only through EUB plus the custom-key payload: reversible, but
     it makes the phone EUB-dependent in the meantime.
  3. `9825_boot_ufs`: adapt from `9840_boot_ufs.S` — needs our BootROM's storage
     (UFS) load function + verify + continue, plus setting `0x02020064`. Still
     required for the fuse, because the OTP SMC needs LDFW, which lives in
     `secure_payload` and is not loaded on the USB-download path (we do not even
     send that stage). The UFS controller base is **not yet identified**.
     `0x13e00000` was a candidate, because the offsets the BootROM touches there
     (`0x20`, `0x24`, `0x30`, `0x34`, `0x40`, `0x44`, `0x4c`) happen to match
     UFSHCI's IS/IE/HCS/HCE/UECN/UECT/UTRIACR — but that was wrong: those
     offsets are generic, and the call graph settles it. The BL1 verifier
     reaches that block, `0x599c -> 0xc1f8 -> 0xc114 -> 0x9878`, and `0x9878`
     alone has 81 references into `0x13e0xxxx`. So **`0x13e00000` is the crypto
     engine**, and the register bank at `+0x1100..+0x117c` (32 consecutive
     words) is key/data, not UNIPRO. The control-block reader `0x16360` does
     *not* reach it, which is consistent.
     What is known: the boot-state writer is at `0x17eb4` (`0xcb000000` into
     `0x02020064` at `0x17ec0`), and `0x02020064` is also read at `0x17f04`,
     `0x17f18` and `0x1a4b4`. The boot-device decision keyed on that state is
     the thread to follow.
  4. `write_key2`'s return convention (0 = success) is assumed, not
     device-confirmed. Only matters at actual fuse time, but it is what the
     `cbnz` guard depends on.
- BootROM map started (`bootrom_exynos9825.bin`, 0x20000): iRAM ptr table at
  `0x020200c0..fc` (recv `[0x020200dc]=0xa3c`, usb-init `[0x020200e0]=0x6e8`,
  print `[0x020200d0]=0x5338`); header parser `0x17c54`, CryptoCell verify
  `0xc9a0`, fail strings "BL1 Header Fail" `0xa94` / "BL1 Checksum Fail" `0xaa4`.
  The 9840 payload addresses (`0x162e4` storage, `0x48bc`, `0xb5f4`, `0x1120`,
  etc.) do NOT map 1:1 to 9825 and must be re-identified by function role.

## The fuse is not possible on this device (settled on hardware)

`run_key_state_test.sh` read the selector's inputs, twice, identically:

| | |
|---|---|
| `SEC0 0x10001000` | `0x00000001` → E (bit 0) = **1** |
| `SEC1 0x1000b014` | `0x10000006` → F (bit 0) = 0, G (bit 3) = 0 |
| pointer the ROM left in `0x0202006c` | `0x10003000` — the fused **KEY** slot |
| OTP KEY slot first word | `0x33be44b4` (Samsung's, programmed) |
| OTP KEY2 slot first word | `0x00000000` (never programmed) |

The mirrored selector logic agreed with the hardware pointer, so the decode is
right. The ROM takes the `E == 1 → KEY` branch, which is tested **before** the
F/G branch that can reach KEY2.

E is `USE_KEY`: `SEC0` bit 0 is 1, the independently measured OTP state is
`USE_KEY=1`, and E selects the KEY slot.

And it cannot be undone. sboot's OTP inventory has `ROM_SECURE_BOOT_KEY`,
`USE_ROM_SEC_BOOT_KEY`, `ROM_SECURE_BOOT_KEY2`, `USE_ROM_SEC_BOOT_KEY2`,
`BAN_ROM_SEC_BOOT_KEY2` and `SSS_CPU_SECURE_BOOT_KEY` — there is **no
`BAN_ROM_SEC_BOOT_KEY`**. No fuse revokes the KEY slot, and OTP bits are
one-way, so `SEC0` bit 0 can never return to 0. Whatever that bit is called, it
is 1 here, it short-circuits to the KEY slot, and nothing can clear it.

So programming KEY2 and setting USE_KEY2 would change nothing — KEY2 is
permanently unreachable on this part. **Do not spend the fuse.**

Two things not to do as workarounds:

- **Do not program the KEY slot.** It already holds Samsung's hash, and OTP
  programming only turns bits 0→1, so our value would have to be a bitwise
  superset of Samsung's. It is not. The attempt would corrupt the slot so that
  *neither* key verifies, killing normal boot permanently with no fuse able to
  undo it. EUB would survive — the Houston exploit reaches EL3 without needing a
  valid signature — so not a hard brick, but permanently EUB-only, which is
  strictly worse than today for no gain.
- **Do not flash our sboot to UFS.** With stock sboot on UFS the phone boots
  normally *and* we can still EUB-boot our chain whenever we want. With ours on
  UFS, normal boot is dead and there is no fuse to fix it.

Other persistence angles, all ruled out: the ROM key table at `0x1fae0` is mask
ROM; `SSS_CPU_SECURE_BOOT_KEY` belongs to a different subsystem and is not the
BootROM's ST1 anchor; and the BootROM reads its control block from iRAM, not
from storage, so nothing on UFS can influence the pre-verification path.

## What this port did achieve

A complete, working custom-key boot chain: our own P-384 keys, our own resigned
`sboot`, verification *redirected* at our key rather than disabled, both the
plain and the eng build reaching Download mode, and the UFS load path mapped and
proven. It needs EUB on each boot. For development that is a fully functional
custom-bootloader setup; only unattended persistence is unavailable.

## Risk

The fuse (step 3) is irreversible and one-shot. It programs the free slot KEY2
and then sets USE_KEY2, and relies on the additive semantics being as expected.
Owner accepts the risk and has a spare board. Validate the resign + the
noverify boot + the UFS boot (all non-fuse) fully before enabling
`should_fuse_key`.

Two latent bricks were caught before any fuse, both of the same shape — a
self-consistent check that did not test what the device tests:

1. The chain was signed RSA while the device verifies ECDSA P-384. Our verify
   used our own key at an offset the device never reads, so it passed.
2. `get_efuse_data()` computed the RSA-variant HMAC, so the one-shot fuse would
   have burned a hash that can never match the footer the signer writes —
   unrecoverable.

Before enabling the fuse, re-run the end-to-end verification and require: all
stages valid against the key **embedded in the image**, the stock Samsung key
rejected, and `get_efuse_data() XOR hmac_key == footer.hmac`.
