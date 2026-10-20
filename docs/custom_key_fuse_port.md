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

The fuse is done by sboot's own OTP wrappers (SMC `0xc2001014`), which require
the matching LDFW service to be initialized. Static analysis corrected an
earlier packaging assumption: `secure_payload` provides the secure monitor and
CSMC/fuse broker, while sboot reads the LDFW modules from the separate `CM`
partition (`cm.bin`). Both sides are initialized only during a real boot from
UFS, not during the reduced USB-download path:

- USB-download injection → download mode → sboot releases USB after `el3_mon`
  and goes to Odin; secure initialization and the CM-partition LDFW load are
  skipped (`0x3374` decision keyed on the iRAM boot-mode magic at `0x80000000`).
  OTP SMC then returns `-1` ("[OTP] LDFW hasn't been loaded").
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

## Audit of the S5E8890 / S5E9810 / S5E9840 fuse reference

The local reference at
`/run/media/chanz22/ROM/exploit-another/Exynos-master` was compared byte-for-byte
with upstream `henr1kas/Exynos` commit
`88338d8b3bb2938ab64d6081e97a6ddd534453c6` on 2026-10-16. Its three fuse
patchers are useful as protocol evidence, but none is a drop-in 9825 payload.
The source tree contains no returned OTP dump or device log proving that the
new key was read back after a write. Upstream also describes the operation as
an *attempt* to burn a free slot, and every current `should_fuse_key` setting is
disabled by default.

- S5E8890 uses a different SMC ABI. It sends four 8-byte chunks in `w1/w3`,
  places commands `0x10..0x13` in `w2`, and finally sends command `1` in `w2`.
  Its SHA-256 / RSA-era anchor derivation is also different. Neither its direct
  SMC loop nor its key bytes can be reused on 9825.
- S5E9810 calls stock OTP wrapper functions, but its injected stub does not
  test the program result before calling the activation wrapper and then forces
  a success return. That is the failure-masking pattern already removed from
  the 9825 port.
- S5E9840 is the relevant independent comparison. It uses CodeSigner V5,
  ECDSA P-384 and the same
  `HMAC-SHA512(pubkey_blob[:136])[:32] XOR hmac_key` anchor derivation. Its
  patch changes the wrapper selectors to `mov x1,#0x16` for KEY2 and
  `mov x1,#0x17` for USE_KEY2. This corroborates the command IDs already found
  directly in the 9825 u-boot disassembly. It does not make S5E9840 addresses,
  its BootROM loader calls, or its BL1/EPBL/BL2/bootload/LDFW/TZSW layout valid
  on 9825.

The useful design rule from this comparison is to call the 9825 stock wrappers
after its own CM/LDFW initialization, retain the raw wrapper return, and keep
USE_KEY2 clear until a complete KEY2 readback matches the signer-derived
anchor. The present blocker is earlier: prove that a native UFS handoff enters
the custom u-boot slot. The earlier entry, control, silent, and forced-Download
tests all inherited the same FWBL1 shim; `native-trigger` is the next hardware
test for that boundary.

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

The selector at `0x5780` writes one of three pointers through `0x5770`.
Instruction-level control-flow reconstruction gives:

| selector | pointer written | then |
|---|---|---|
| 0 | `0x10003020` — fused KEY2 slot | `bl 0x16eac` |
| 1 | `0x10003000` — fused KEY slot | `bl 0x16eac` |
| 2 | `0x0001fae0` — ROM key table | `bl 0x16eac` |
| 3 / 4 / default | `0x0001fae0` — ROM key table | — |

This was re-audited by importing the raw BootROM as AArch64 LE in Ghidra and
checking the resulting control flow against the instruction-level disassembly.
The decisive edges are `0x57b0 -> 0x57c0 -> 0x57e8` (selector 0), followed by
`0x580c -> 0x5860`, where the ROM loads `0x10003020`. Selector 3 instead falls
through `0x5828`, where the ROM loads `0x0001fae0`.

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
The `secure_payload` (1 MB) is the secure monitor/payload stage that we never
sent. The LDFWs are stored separately in `cm.bin`; sboot contains the strings
`read whole CM partition from the storage` and `init ldfw(s)`. The local 7 MiB
`cm.bin` contains six `CryptoManagerV50` containers at `0x0`, `0x219000`,
`0x230000`, `0x381000`, `0x3d2000`, and `0x3f3000`. Their signed headers expose
names, versions, and load addresses, but their executable bodies are encrypted,
so static Ghidra analysis cannot map SMC commands to physical OTP bits inside
the LDFW. The Odin set also includes `keystorage.bin` (SLSI v0x20).

Ghidra identified the live initialization boundary in u-boot. `FUN_c90a616c`
reads the complete CM partition into `0xca000000`, enumerates the signed
containers, and calls the LDFW initializer at `0xc90a63ac` as
`FUN_c9001654(&DAT_ca000000, container_size + 0x210)`. It then wipes the raw CM
staging buffer before returning. The first container advertises load address
`0x82001000`, so a post-return read there can determine whether the decrypted
CryptoManager remains addressable to u-boot.

`tools/make_ldfw_memory_probe.py` converts the validated diagnostic u-boot
`sboot_note10_ldfwdiag.bin` (SHA-256
`5a0bb52549af3cac7d4028243d7f32ee88a5b059c13bd055f9e675af9bd46151`)
into a read-only post-initialization probe. The original wrapper read
`0x80000000` before calling `FUN_c90a616c`; the new wrapper calls it first and
then reads 32-bit words at `0x82001000` and `0x82001010`. It emits no OTP
command. Generated local artifact:

```text
build/sboot_note10_ldfwmem.bin
size    0x180000
sha256  74e778bb973402d165e321e45c4a636fa3e98d58dbb60cba5bde43ab92461d6a
```

That u-boot was placed into `build/ldfwmem_chain/`, the complete chain was
resigned with the already validated P-384 keys, and
`scripts/verify_9825.py` passed ST1, all five ST2 stages, the whole-image
footer, the embedded-key checks, and the stock-key negative controls. The
current generated `sboot.bin` SHA-256 is
`0574ec53847bcca672cbd9743e9cc80e5ab131636831647f547a304ec0145fe2`.
ECDSA signatures are non-deterministic, so a clean rebuild can have a different
hash while still passing the same verifier.

The first hardware run returned:

```text
LDFW p0=ffffffff p1=ffffffff ret=0
```

This is not a readable decrypted image. It proves that the u-boot load from
`0x82001000` did not synchronously abort, but an all-ones bus value does not
prove that memory was populated. The `ret=0` value is also ambiguous:
`FUN_c90a616c` returns zero after a successful load and through several early
exit paths. In particular, it reads `0x80000000` and `0x80000010` before doing
any CM-partition work and returns zero for three download/boot-mode magic pairs.

The follow-up read-only hardware command was:

```sh
tools/run_ldfw_memory_probe.sh mode
```

It sends the diagnostic chain through the proven volatile custom-key path and
reports the two mode words as `LDFW m0=<word> m1=<word> ret=<value>`.
The physical run returned:

```text
LDFW m0=66269633 m1=77279733
```

This exactly matches the second early-exit pair. It proves that, in this
USB/EUB boot, `FUN_c90a616c` returns before reading the CM partition or calling
the LDFW initializer. Consequently, the earlier all-ones values at
`0x82001000` were reads from an unpopulated/unavailable LDFW address, not a
loaded CryptoManager image. Another forced call from the same download context
cannot establish the missing normal-boot dependencies; the useful next branch
is the already mapped UFS boot path. Both diagnostic variants listen to EP1 and
perform no flash or fuse operation.

The three zero-return early-exit pairs, reconstructed from `0xc90a61c0` through
`0xc90a6248`, are:

| `m0 = [0x80000000]` | `m1 = [0x80000010]` |
|---:|---:|
| `0x66265999` | `0x77275999` |
| `0x66269633` | `0x77279733` |
| `0x6626ccca` | `0x7727ccca` |

The mode diagnostic uses the original validated wrapper and was resigned as a
complete chain. Current generated artifacts:

```text
build/ldfwmode_chain/sboot/u-boot.bin  ccd9e82da1d800e81776e671e0ea2f1303321bea61f9983112cb138eb4f0a603
build/ldfwmode_chain/sboot.bin         77fe50d9648c55c8cbff6ae724bd667e8e3a99b99d3f4d8d3628c697e3035d6b
```

`scripts/verify_9825.py` passes ST1, all five ST2 stages, the whole-image
signature, embedded custom keys, and stock-key negative controls. Rebuilding
will change the ECDSA signatures and therefore the hashes.

### Prepared KEY2 programming flow

The KEY2-only chain is generated by
`tools/build_key2_fuse_chain.sh program`. It embeds the 32-byte trust anchor
derived from the custom P-384 ST1 public key and HMAC key; the private key is
never written to OTP. Its u-boot stub calls SMC command `0x16`, leaves
`USE_KEY2` unchanged, forces the secure-payload load flag clear, and replaces
the single `s5p_check_download()` call with `mov w0,#0` so the attached USB
cable cannot divert the later flow back to Download mode.

The UFS trampoline does not touch `0x80000000` or `0x80000010`: BL2 has not
trained DRAM at that point. Instead the persistent u-boot neutralizes all three
stale EUB reads after BL2 has initialized memory. `sboot_patch.py --normal-boot`
replaces the main `MAGIC_CODE` load at `0x33f0` and the two LDFW mode loads at
`0xa61a4` and `0xa61b0` with zero-valued moves. This directly addresses the
physical `0x66269633/0x77279733` LDFW early-exit result without performing an
early DRAM store. The current instrumented RAM payload is
`build/epbl_boot_ufs_chain_probe.bin`, 0xf20 bytes, SHA-256
`e285401fb5441b5807ca00c701ef8590c9a856c86de411744e89f9066d95c41e`.
It waits for its two early EP1 records to complete, emits nothing during FWBL1
initialization, captures the final saved context immediately before ERET, and
then resumes the unmodified context restore without changing BL2.
It also retains the older best-effort PMU checkpoints. The later physical
calibration proved that fresh EUB entry clears them, so they are useful only
while the same execution is still alive and cannot be recovered afterward.

Current KEY2-only artifact after a clean split, patch, resign and complete
verification:

```text
build/key2_program_chain/sboot/u-boot.bin  7d7609efbb596bba3a0c2f97e0daa081731a56048b3719e79f3ca23cbfb53862
build/key2_program_chain/sboot.bin         687041e3ccc9ea28eb33b82963ac336fd7e10f6d0df91aba8a77474bc3a5aa92
```

`tools/check_key2_fuse_image.py` verifies the exact OTP stub, embedded anchor,
secure-payload flag patch, normal-boot patch, and all three stale-mode read
patches. All nine original calls to the replaced `check_signature` routine
remain present. Four new branches at `0xa63e4`, `0xa6460`, `0xa64a4`, and
`0xa64d0` replace the mutually exclusive CM/LDFW result diagnostics, so exactly
one OTP attempt runs immediately after the initializer returns. The original
secure-chip-state query at `0xa63e8` remains intact. The late uH-image loader
call at `0xb9170` is retained as a fallback.
`verify_9825.py` additionally passes ST1, every ST2 stage, the whole-image
signature, embedded-key checks, and the stock-key negative controls.

The hardware order is split so KEY2 can be read back before its selector is
committed:

```sh
tools/run_key2_program.sh check
tools/run_key2_program.sh flash
# Wait until the Samsung Download/Odin screen reaches 100%, then run:
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/key2_program_chain/sboot.bin
tools/run_key2_program.sh trigger
tools/run_key2_program.sh trace
tools/run_key2_program.sh verify
```

`flash` only enters Samsung Download mode and prints the absolute image path
and manual Odin command. It does not invoke Odin. After the Download/Odin
screen reaches 100%, the explicit Odin command writes only the `BOOTLOADER`
partition from
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/key2_program_chain/sboot.bin`.
`trigger` performs the irreversible KEY2 OTP write. `verify` must show all 32
KEY2 bytes matching the derived anchor while `USE_KEY2` remains clear.
It uses two fresh EUB sessions and still reads the selector state when the
first full-slot dump is valid but does not match the expected anchor.
Selector activation is a later, separate OTP operation.

### First hardware programming attempt: KEY2 remained blank

The BOOTLOADER flash completed successfully. The UFS trigger then returned
`UFSLOAD!` and `UFSMETA!`: BootROM load return was 1, the boot-device state
changed from `0xcb000041` to `0xcb000011`, and the loaded EPBL size was the
expected `0x3000`. The link disappeared immediately after the trampoline
handed control onward.

The following full-slot dump returned:

```text
KEY2 = 0000000000000000000000000000000000000000000000000000000000000000
KEY  = b444be33c467c9e58ef54d6067641a6ea2fb9d61e2d30ee219d1ad3b79425f0c
```

Therefore the attempt did not program KEY2. The following PMU dump returned
all zeros. The later retention calibration returned `PMU=NO`, so that result
is inconclusive. An intermediate live EP1 trace stopped after `UFSPRE!!`; that
image still accessed untrained DRAM before `UFSHAND!`. Removing those accesses
produced all six records on hardware: `UFSLOAD!`, `UFSMETA!`, `UFSPRE!!`,
`UFSHAND!`, `UFWENTR!`, and `UFWDECR!`. This proves the UFS EPBL handoff, FWBL1
shim entry, and FWBL1 self-decrypt return. The following full OTP dump still
showed KEY2 entirely zero.

The final image at
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/key2_program_chain/sboot.bin`
(SHA-256 `687041e3ccc9ea28eb33b82963ac336fd7e10f6d0df91aba8a77474bc3a5aa92`)
was flashed successfully. Three UFS triggers then produced the same six live
records through `UFWDECR!`, including the version with the post-LDFW OTP calls,
and KEY2 remained completely blank.

The persistent u-boot calls the KEY2 stub directly from all four mutually
exclusive CM/LDFW initializer result paths. That image is already on UFS. A
subsequent RAM instrumentation revision returned `UFSLOAD!`, `UFSMETA!`,
`UFWENTR!`, `UFWDECR!`, and `UFWMAIN!`; `UFWMAIN!` arrived at 0.576 s. Reaching
that later site proves that all omitted initializer calls returned even though
their EP1 records were not observed.

Disassembly corrected the old `UFWMAIN!` label: the instruction at
`0x02026100` is `b 0x0202a9d4`. The target restores the saved exception context,
including `SCR_EL3`, `SPSR_EL3`, and `ELR_EL3`, before executing `ERET` into
BL2. The run therefore reached the final FWBL1 transition, but the marker was
still emitted before direct BL2 execution.

The same run displayed `UFSLOAD!` return `0x3000`. This was record corruption,
not a failed load: the chain executed FWBL1, and `0x3000` is the next
`UFSMETA!` record's BL1-size field at the same shared-buffer offset. A bounded
transfer had left DWC3 owning the record while the following record overwrote
it. The current RAM payload waits for both early transfers to finish and never
reuses a buffer after a bounded transfer.

The direct BL2 instruction-hook run then returned a corrected `UFSLOAD!`
value of 1 and an intact `UFSMETA!`, but neither `UBL2ENT!` nor `UBL2MISS`.
That test wrote the first BL2 instruction immediately before ERET, so the
absence of a record still mixed two causes: instruction-cache visibility at
`0x02100000`, and EP1 availability after the architectural transition.

The saved-ELR diagnostic removed the first cause: it left BL2 unchanged and
redirected only the context-frame ELR through a post-ERET trampoline. Its
physical run still returned only `UFSLOAD!` and `UFSMETA!`. That result leaves
post-ERET EP1/helper availability as the main diagnostic limitation and does
not prove whether the trampoline executed.

The first pre-ERET diagnostic returned `UBL2PRE!` at 0.581 s, with the expected
BL2 base word but zero saved ELR/SPSR/SCR and current SP `0x02033780`. The
result exposed a stack-selection error in the diagnostic: the stock restore
copies the current SP, executes `msr SPSel,#1`, and then reads the context from
`SP_EL3`. The corrected `UBL2CTX!` revision used `SP_EL3`, modified neither the
frame nor BL2, and resumed the original restore. Its hardware run nevertheless
returned only `UFSLOAD!` and `UFSMETA!`. A full KEY2 dump immediately afterward
was still all zero; a separate selector read still chose `0x10003000` with
predicates `A=0 B=0 C=0 D=0 E=1 F=0 G=0`. The run therefore did not program
KEY2, while the missing late record remains subject to the known EP1 limitation.

The minimal u-boot reporter was built, flashed and triggered twice. Both runs
returned valid `UFSLOAD!` and `UFSMETA!`, then lost the EUB USB handle without
the banner or `UBSTAGE!`. The result did not prove that BL2 skipped u-boot: the
reporter still depended on the inherited BootROM EP1 helper at a boundary where
USB ownership and execution context had already changed.

The local Houston checkout is already commit `fab5783` from
[houston-pub PR #12](https://github.com/halal-beef/houston-pub/pull/12). Its
same-handle support explains the valid early records, while the review note
about payload-driven USB reinitialization explains why waiting on that old
handle is not a valid late-stage oracle.

The full-u-boot test keeps the complete engineering u-boot and injects a signed
0x30-byte entry trampoline into its zero cave at offset `0x17ce00`. It writes
`UBS1`/`OWN1` to PMU scratch, clears MINFORM and resumes the original entry at
`0xc9000004`. Its body before the ST2 footer is byte-identical to the
`ecdsa_eng` u-boot already proven to reach Download mode over the USB-loaded
chain. U-boot then initializes its own Download USB stack. A fresh
Download/Odin screen reaching 100% directly proves execution of the custom
u-boot without requiring the old BootROM EP1 channel. No FWBL1 instruction,
exception frame or BL2 byte is changed, and the diagnostic contains no
injected OTP call.

The image was flashed and triggered on hardware. The EUB device disconnected
before either early record completed, no new USB device enumerated, and the
screen remained black. Thus this revision did not reach its visible pass
condition. The missing records alone cannot locate the stop because the next
stage can disable the old controller while their DMA is pending. The first
read-only `tools/run_ubstage_test.sh trace` action returned all-zero PMU
scratch, but the calibration below proves that the fresh EUB entry destroys
that evidence.

The two-session calibration was run on hardware with:

```sh
tools/run_ubstage_test.sh calibrate-retention
```

Session 1 wrote and read back both PMU markers and both iRAM markers. The fresh
EUB session returned both PMU words as zero and unrelated data at both iRAM
addresses: `PMU=NO, iRAM=NO`. The action did not access UFS or issue an OTP
command, and left
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_test_chain/sboot.bin`
unchanged. PMU scratch and this iRAM area are therefore invalid cross-session
oracles; the earlier zero trace says nothing about u-boot entry, and the
`trace` action is retired.

The no-marker hardware control was completed with the exact `ecdsa_eng` image
already proven over the USB-loaded chain. Its original u-boot entry, empty
`0x17ce00` cave and inert signature stub were verified before flashing. The
exact BOOTLOADER image was:

```text
/home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot.bin
```

`control-trigger` returned valid `UFSLOAD!` and `UFSMETA!` records: load return
1, 0x18 sectors, boot state `0xcb000041 -> 0xcb000011`, BL1 size `0x3000`, and
checksum `0x20d184e7`. The inherited EUB USB handle then closed and the screen
remained black. The raw file is `/tmp/exynos9825_ubstage_control.bin`, SHA-256
`fd84b7dab355b81c551fb443332861a02ab2a97d969a7e35716c03a73de7891d`.

The result rules out the preceding PMU-writing u-boot entry trampoline as the
cause. It does not distinguish a stop before u-boot entry from a failure inside
the original u-boot before its visible Download path.

The silent transport control was then completed. Its success path sent no
`UFSLOAD!`, `UFSMETA!`, or other EP1 record, used the exact control image
already on UFS, and again produced a black screen. This rules out the two early
EP1 transfers as the cause.

The forced-Download diagnostic moved the proof into u-boot's real Download
fork. Its body matches the proven `ecdsa_eng` u-boot except at two verified
instructions:
offset `0x33f0` returns zero for the stale pre-fork `MAGIC_CODE`, and offset
`0x38f0` replaces the `s5p_check_download()` call with `mov w0,#4`. The
following `mov w21,w0` and `cbz w0,<normal>` remain intact, so the register
state matches a legitimate Download reason 4. The image contains no entry
trampoline and no OTP command injection.

Prepare the Download screen with:

```sh
tools/run_ubstage_test.sh force-download-flash
```

After it reaches 100%, manually flash exactly:

```sh
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

`tools/run_ubstage_test.sh force-download-trigger` produced another black
screen. Neither action issued an OTP command. The result initially appeared to
place the stop before the fork, but a build audit found that the plain and
silent RAM payloads still defined `EPBL_COLD_CONTEXT_STAGED`. They therefore
replaced the EPBL dispatch literal, installed the diagnostic EL3 vector and
entered FWBL1 through `fwbl1_noic_entry`. Every preceding UFS entry test shared
that altered boundary, so the black screen does not isolate stock FWBL1, BL2,
or the forced u-boot fork.

The replacement `epbl_boot_ufs_native_probe` keeps only the cache-safe first
line stager and authentic EPBL mirror. It installs no diagnostic VBAR, leaves
the dispatch literal at `0x02020128`, makes no FWBL1 or saved-context patch,
and enters the original BootROM helper at `0x0001c9a0` with
`LR=0x00000250`. Its structural checker confirms that the binary contains no
`fwbl1_noic_entry`, exception vector, redirect slot, or reconstructed cold
target.

The forced-Download BOOTLOADER image remains on UFS at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

The next test is RAM-only and needs no Odin operation:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-trigger
```

A Download/Odin screen reaching 100% proves the legacy FWBL1 shim caused the
black screens. Another black screen leaves the blocker in the native UFS
state/handoff or before the forced u-boot fork. KEY2 programming remains
paused until this boundary is resolved.

```sh
tools/run_ubstage_test.sh build
tools/run_ubstage_test.sh flash
```

After the Download/Odin screen reaches 100%, manually flash exactly:

```sh
sudo odin flash --BOOTLOADER /home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_test_chain/sboot.bin
```

Then run `tools/run_ubstage_test.sh trigger`. The inherited EUB handle should
close; the pass condition is a new Download/Odin screen reaching 100%. Restore
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/key2_program_chain/sboot.bin`
before the next programming attempt.

The exception table is now architecturally aligned: `VBAR_EL3` is
`0x02025800`, with CurrentEL synchronous entries at `0x02025800` and
`0x02025a00`. The worker reserves both slots and ends at runtime `0x02025e60`,
below the FWBL1 load area at `0x02026000`.

Current entry-test artifacts:

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
```

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
     required for the fuse, because the OTP SMC needs both the secure payload
     and an initialized LDFW loaded from the UFS `CM` partition. Neither is
     available in the reduced USB-download path. The UFS controller base is
     **not yet identified**.
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

## KEY2 remains reachable; the fuse-bit mapping is not settled

`run_key_state_test.sh` read the selector's inputs, twice, identically:

| | |
|---|---|
| `SEC0 0x10001000` | `0x00000001` → E (bit 0) = **1** |
| `SEC1 0x1000b014` | `0x10000006` → F (bit 0) = 0, G (bit 3) = 0 |
| pointer the ROM left in `0x0202006c` | `0x10003000` — the fused **KEY** slot |
| OTP KEY slot first word | `0x33be44b4` (Samsung's, programmed) |
| OTP KEY2 slot first word | `0x00000000` (never programmed) |

The observed pointer agrees with the current hardware inputs: `C=0`, `D=0`,
and `E=1`, so this device currently selects KEY. That agreement validates the
executed branch for the present state, but it did not validate the earlier
decode of the untaken branches.

The corrected BootROM control flow is:

```text
if A == 0 and B == 1:       ROM table
elif C == 1 and D == 0:     KEY2
elif E == 1:                KEY
elif F == 1 and G == 0:     ROM table
else:                       ROM table
```

Therefore `E=1` does **not** make KEY2 unreachable. The ROM tests the KEY2
condition (`C==1 && D==0`) before it tests E. The previous analysis had the
targets of the `C/D` and default paths reversed.

sboot exposes independent OTP operations for `ROM_SECURE_BOOT_KEY2`,
`USE_ROM_SEC_BOOT_KEY2`, and `BAN_ROM_SEC_BOOT_KEY2`. Their shape strongly
suggests that C and D are the USE_KEY2 and BAN_KEY2 states respectively:
`USE_KEY2=1 && BAN_KEY2=0 -> KEY2`. This is a control-flow-based inference,
not yet a proven mapping. The single measured state cannot distinguish C/D
from F/G because all four bits read zero while both reported KEY2 flags were
zero.

The Ghidra audit of `sboot_stage.bin` confirmed the complete independent
operation set around SMC `0xc2001014`:

| sboot function | command | operation |
|---|---:|---|
| `FUN_c90a278c` | `0x16` | program `ROM_SECURE_BOOT_KEY2` |
| `FUN_c90a298c` | `0x114` | check `ROM_SECURE_BOOT_KEY2` |
| `FUN_c90a2be0` | `0x17` | program `USE_ROM_SEC_BOOT_KEY2` |
| `FUN_c90a2c94` | `0x115` | read `USE_ROM_SEC_BOOT_KEY2` |
| `FUN_c90a2d54` | `0x18` | program `BAN_ROM_SEC_BOOT_KEY2` |
| `FUN_c90a2e08` | `0x116` | read `BAN_ROM_SEC_BOOT_KEY2` |

The registered `dev://fuse`/CSMC code in `secure_payload` does not contain the
SEC0/SEC1 addresses or the command implementation. The best current evidence
places that implementation in the encrypted CM LDFW. Consequently, Ghidra
proves that KEY2 has a deliberate lifecycle, but it cannot by itself prove that
commands `0x17`/`0x18` correspond to SEC0 bits 1/3.

The persistence path is consequently **not ruled out**. Do not spend the fuse
until a read-only experiment or a trusted fuse map independently proves that
SMC command `0x17` sets C (`SEC0.1`) and command `0x18` sets D (`SEC0.3`), and
the complete fused value has passed the existing signer/footer checks.

If that mapping is confirmed, KEY2 has priority over KEY. The stock Samsung
key should therefore not be treated as an additive fallback after USE_KEY2 is
set; persistence would depend on the custom-key chain remaining valid.

Two things not to do as workarounds:

- **Do not program the KEY slot.** It already holds Samsung's hash, and OTP
  programming only turns bits 0→1, so our value would have to be a bitwise
  superset of Samsung's. It is not. The attempt would corrupt the slot so that
  *neither* key verifies, killing normal boot permanently with no fuse able to
  undo it. EUB would survive — the Houston exploit reaches EL3 without needing a
  valid signature — so not a hard brick, but permanently EUB-only, which is
  strictly worse than today for no gain.
- **The board now holds the STOCK Samsung sboot again** (restored by the user
  before 2026-10-18, because the phone was needed). Earlier in this document the KEY2-programming
  sboot is described as being on BOOTLOADER; that is no longer true, and the
  distinction is a safety one: a `native-*` run that finally reaches u-boot
  performs the OTP write only if the KEY2-programming chain is the image on
  UFS. Confirm the flashed image before every native run. Its one trigger
  while it was flashed did not alter OTP; KEY2 read back completely blank.
  Keep the matching image and signer material while the execution trace
  isolates the missed stage boundary.

Other persistence details remain unchanged: the ROM key table at `0x1fae0` is
mask ROM; `SSS_CPU_SECURE_BOOT_KEY` belongs to a different subsystem and is not
the BootROM's ST1 anchor; and the BootROM reads its control block from iRAM, not
from storage, so UFS cannot directly replace the pre-verification key pointer.

## What this port did achieve

A complete, working custom-key boot chain: our own P-384 keys, our own resigned
`sboot`, verification *redirected* at our key rather than disabled, both the
plain and the eng build reaching Download mode, and the UFS load path mapped and
proven. It currently needs EUB on each boot. For development that is a fully
functional custom-bootloader setup. Unattended persistence now depends on
proving the C/D fuse mapping and validating the irreversible KEY2 sequence.

## Risk

Programming KEY2 is irreversible and one-shot. The current programming image
only writes the free KEY2 slot and deliberately leaves USE_KEY2 clear; selector
activation remains a separate later operation.
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

## Native UFS handoff result and current fuse gate

The clean native handoff was run on hardware with the forced-Download chain
already present at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

It also ended on a black screen. That payload installed no diagnostic VBAR,
did not replace the EPBL dispatch literal, did not enter
`fwbl1_noic_entry`, and did not modify the saved exception context. The old
FWBL1 shim is therefore not the sole blocker.

The simultaneous host output `Errno 19` was only the EUB USB device leaving
after handoff. Because the native payload intentionally emitted no records,
the host then incorrectly reported the empty capture as an error. Silent
handoff actions now use `--allow-no-records`, which treats that condition as
expected and removes stale output files. This host correction does not change
the code executed by the board.

Before any further OTP attempt, run the RAM-only boundary diagnostic:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-diagnose
```

It uses the same UFS image above and writes no partition. `EUNPRE!!` reports
the exact native EPBL entry state, including the `0x15860990` cold/warm gate.
`EUNRET!!` is emitted only if the authentic EPBL returns instead of continuing
through FWBL1 and BL2. The diagnostic return sentinel also prevents a failed
EPBL from falling into BootROM's `0x250` epilogue on the wrong stack.

Until that result is returned from hardware, KEY2 remains blank and another
programming trigger is not justified.

The subsequent hardware run of `native-diagnose` returned neither
`EUNPRE!!` nor `EUNRET!!` and remained on a black screen. The Houston checkout
used by the runner is exactly commit
`fab5783854d1b363511bddcfc59c838e06bf0d61` (`Exynos9825 Support`), the commit
from PR #12. Both Houston's Exynos9825 handler and the local runner retain the
original claimed USB handle after ACE; the runner now prints this policy in
the live log and fails early if `modules/exynos9825.py` is missing.

The next fuse gate is therefore an earlier RAM-only boundary test:

```sh
tools/run_ubstage_test.sh native-load-diagnose
```

It expects the already-flashed image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

No Odin step is involved. `UFSLOAD!` plus `UFSMETA!` proves that BootROM
`0xcc68` returned success and that EP1 remained usable on the original handle.
No record moves the stop to the loader boundary rather than the later key
selector/post-load/EPBL-entry preparation. The payload is
`build/epbl_boot_ufs_native_load_diag_probe.bin`, SHA-256
`9e192f6c211069f13c5c91e73b094e8ae3c08c8b00d91dcd189318735247f9c6`.
KEY2 programming remains paused pending that result.

The `native-load-diagnose` hardware result returned both `UFSLOAD!` and
`UFSMETA!`: BootROM `0xcc68` returned 1, switched the boot state from
`0xcb000041` to `0xcb000011`, loaded `0x18` sectors, and left a `0x3000`-byte
EPBL while still at EL3. This proves the PR #12 handle and the UFS load. The
later `ENODEV` occurred after both completed transfers and is not the cause.

The next RAM-only fuse gate is now:

```sh
tools/run_ubstage_test.sh native-postload-diagnose
```

It expects the same already-flashed image at
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`
and requires no Odin step. `EUNPOST!` is emitted immediately after `0x5b58`
returns and reports the selector result, verifier return and active custom-key
pointer before the final entry preparation. The validated payload SHA-256 is
`91994f4c3fbd223a8624f3ae79d93156d2193721a69e9808d8e7d1a1032e1605`.
KEY2 programming remains paused pending that result.

The hardware returned `EUNPOST!` with selector return 1, verifier return 1,
custom key pointer `0x020254a8`, post-load state `0x020254ac`, SEC0 1, storage
boot state `0xcb000011`, and `CurrentEL=0xc`. Therefore the UFS load and the
custom-key BL1 verification are both physically proven. The subsequent host
`EIO` occurred after the record completed.

Repeat the last pre-entry boundary under the now-confirmed PR #12 host policy:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-diagnose
```

This remains RAM-only, requires no Odin step, and expects
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`
already on UFS. `EUNPRE!!` proves the final timing and boot-flag calls returned;
`EUNRET!!` proves that the authentic EPBL subsequently returned. KEY2
programming remains paused until this boundary is observed.

The repeated final-boundary run used the confirmed PR #12 handle but returned
neither `EUNPRE!!` nor `EUNRET!!`. The next fuse gate is therefore:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-timing-diagnose
```

It is RAM-only, requires no Odin step, and expects
`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin`
already on UFS. Its single `EUNTIME!` record runs immediately after `0x18768`
and before the final `0x16a10` boot-flag update. The payload SHA-256 is
`035bdda117ced87dff9ca1ebc2bff059f807199b09931132151e8ed7da28d7ca`.
KEY2 programming remains paused pending this result.

Hardware returned `EUNTIME!` with selector and verifier returns equal to 1,
timing delta `0x3ce`, flags `0x00300edf`, custom key pointer `0x020254a8`,
dispatch literal `0x02020128`, authentic EPBL entry qword
`0x1400000014000002`, `SCTLR_EL3=0x00c51838`, and `CurrentEL=0xc`. This proves
that `0x18768` completed and that EP1 was still usable after it. The subsequent
`ENODEV` happened after the complete record.

The next fuse gate is the remaining boot-flag helper:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-flag-diagnose
```

This is RAM-only, requires no Odin step, and expects the unchanged image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

Its `EUNFLAG!` record is emitted immediately after
`0x16a10(0, 0x00800000)` returns. A passing record must contain the final flag
bit and the authentic EPBL entry, hook and dispatch values. The validated
payload is `build/epbl_boot_ufs_native_flag_diag_probe.bin`, size `0x6e0`,
SHA-256 `12bbac2dadc965dc827c1525d394d2e5384685613d8450e4f2361648d4f05821`.
KEY2 programming remains paused pending this result.

Hardware returned `EUNFLAG!` with selector and verifier returns equal to 1,
timing delta `0x426`, final flags `0x00b00edf`, custom key pointer
`0x020254a8`, authentic dispatch literal `0x02020128`, intact entry/hook
instructions `0x14000002 / 0x580002d4`, `SCTLR_EL3=0x00c51838`, and
`CurrentEL=0xc`. The complete stock preparation before native EPBL entry is
therefore proven. The later host `EIO` occurred after the record completed.

The next fuse gate tests the EPBL's own warm/cold selection without writing
UFS or issuing an OTP command:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-cold-diagnose
```

It expects the existing BOOTLOADER image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

No Odin step is involved. The payload records `0x15860990` and `0x02020128`,
verifies the original branch word `0x54000041` at `0x02022028`, and changes
only that RAM instruction to `0x14000002`, which forces the authentic cold
path. `EUNCOLD!` proves the patch and preserves the original values for
diagnosis. The validated payload is
`build/epbl_boot_ufs_native_cold_diag_probe.bin`, size `0x6f8`, SHA-256
`50096841987fef5562c55b5aca328fef53d916b3e8824b572455bd7eeefcc2b4`.
KEY2 programming remains paused until this result is known.

The hardware returned no `EUNCOLD!` record; the host observed `ENODEV`. Since
the immediately preceding `EUNFLAG!` boundary completed, and both the older
`EUNPRE!!` and this missing record first read `0x15860990`, the direct
warm-state MMIO read is the current narrow boundary. Its value and the branch
patch were not observed, so this result alone does not prove either one.

The next RAM-only fuse gate bypasses that read in the executing EPBL:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
tools/run_ubstage_test.sh native-force-cold
```

It expects the existing image at:

```text
/home/chanz22/Documents/GitHub/exynos9825-payloads/build/ubstage_forced_download_chain/sboot.bin
```

No Odin step is involved. After the proven native preparation, the payload
verifies `0x580002d4` at `0x02022018` and replaces it in RAM with
`0x14000006`, which branches directly to the original cold loader at
`0x02022030`. Thus the EPBL does not read `0x15860990` or evaluate the warm
path. `EUNFORC!` reports the applied change before handoff. The artifact is
`build/epbl_boot_ufs_native_force_cold_probe.bin`, size `0x6e8`, SHA-256
`8178bae0b8eff2e0748831c2fa1b75d5213a132065aa22105dd906aeea25b596`.
KEY2 programming remains paused pending this result.


## 2026-10-18: boundary work continues on stock, fuse untouched

KEY2 is still 32 zero bytes. Nothing has been programmed.

The BootROM selector at `0x5780` was re-read independently and the corrected
reading above is confirmed instruction by instruction:

```text
A = SEC0 bit 8  (0x10001000)   via 0x17514      E = SEC0 bit 0   via 0x17604
B = SEC1 bit 31 (0x1000b014)   via 0x1744c      F = SEC1 bit 0   via 0x173ac
C = SEC0 bit 1                 via 0x175dc      G = SEC1 bit 3   via 0x17424
D = SEC0 bit 3                 via 0x175b4

0x5790  if   A==0 && B==1  -> 4 -> ROM table 0x1fae0
0x57a8  elif C==1 && D==0  -> 0 -> KEY2 0x10003020      <- before E
0x57cc  elif E==1          -> 1 -> KEY  0x10003000
0x57d8  elif F==1 && G==0  -> 2 -> ROM table
0x5804  else               -> 3 -> ROM table
0x5770  stores the chosen pointer in 0x0202006c
```

`E=1` does not short-circuit anything: the `C/D` test precedes it. Two
consequences that were not spelled out before:

- Activating KEY2 is not additive. Once `C=1 && D=0` the ROM returns the KEY2
  pointer and never evaluates `E`, so Samsung's own key stops being consulted
  and stock-signed bootloaders stop verifying.
- `BAN_KEY2` is the escape hatch. `C==1 && D==1` falls through to `E==1` and
  restores the KEY path. Both directions are one-way fuses, but the recovery
  direction exists — *if* the C/D mapping holds, which is the same unproven
  inference the activation depends on.

Programming the KEY2 hash alone (command `0x16`) does not depend on that
mapping, because the selector never reads the slot while `C=0`. That is what
`build_key2_fuse_chain.sh program` builds, and it is also the cheapest way to
measure the mapping: program the hash, then read `SEC0`/`SEC1` and see which
bits the command moved. The residual risk is that `0x16` internally sets
USE_KEY2 as well; the existence of separate commands `0x17`/`0x18` argues
against it but does not rule it out.

None of this is reachable until the chain executes u-boot, which is still the
blocker. See the three-position boundary measurement at the end of
[boot_nonsecure_current_state.md](boot_nonsecure_current_state.md).


> **Correction (2026-10-18):** the claim elsewhere in this file that
> the `0x16` buffer is SHA-256 of the public key is wrong. The value is
> `footer_hmac XOR hmac_key`, verified against Samsung's own fused slot.

## 2026-10-20: the pre-burn baseline, read fresh

Both read-only probes were run in the same session, so the gate C delta that
follows a programming run has a "before" that nothing has happened to since.

`run_key_dump_test.sh`:

```text
KEY2 = 0000000000000000000000000000000000000000000000000000000000000000
KEY  = b444be33c467c9e58ef54d6067641a6ea2fb9d61e2d30ee219d1ad3b79425f0c
```

`run_key_state_test.sh`:

```text
SEC0 0x10001000 = 0x00000001      A=0 B=0 C=0 D=0 E=1 F=0 G=0
SEC1 0x1000b014 = 0x10000006
PTR_SECUREBOOT_KEY as the ROM left it = 0x10003000
selector would pick                   = 0x10003000, fused KEY (E==1)
agreement                             = OK
boot state   0x02020064 = 0xcb000452
verify status 0x02020070 = 0x0000101f
```

Every value matches what this document already recorded, so the older figures
are still good. The `KEY` slot also matches the constant compiled into
`epbl_boot_ufs_native_stockkey_probe` for the redirect control earlier the
same day, which confirms that constant independently.

Nothing is programmed. The measurement gate C needs is the difference in
`SEC0`/`SEC1` across a `0x16` run, and both halves of the "before" are now
dated today.
