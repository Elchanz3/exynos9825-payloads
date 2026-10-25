# Exynos9825 MIF 2133 nominal experiment

Built on 2026-10-23/24. Offline validation passed; device boot, DRAM stability,
PLL readback and power consumption have not been tested. Nothing was flashed.

## Deliverables

Release directory:

`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/mif_2133/release`

| File | Contents / destination |
| --- | --- |
| `sboot.bin` | Signed 4 MiB BOOTLOADER image with patched BL2 ECT |
| `bl2.bin` | Signed BL2 extracted from that image; not a separate partition |
| `BL_mif2133.tar.md5` | `sboot.bin`, `vbmeta.img` |
| `AP_mif2133.tar.md5` | `boot.img`, `dt.img`, `dtbo.img` |
| `kernel-mif2133.patch` | Kernel source change, relative to the original working tree |
| `kernel.config` | Exact compiled configuration |
| `bl2-report.json`, `kernel-report.json` | Base hashes and build details |
| `SHA256SUMS` | Image and archive digests |

The BL and AP archives form a matched set. The top-level vbmeta covers both
the new sboot and the new boot image and trusts the new DT/DTBO signatures.
Using only one archive with the old companion images can fail AVB verification.
The `cm.bin` and `keystorage.bin` files in the release directory are reference
copies of the existing custom chain, not members of either archive. Their
hashes must match the installed custom trust chain documented in this project.
Recovery/product trust and the existing vbmeta flags are unchanged.

No flashing command was executed. If flashing is subsequently requested, the
BOOTLOADER image is exactly:

`/home/chanz22/Documents/GitHub/exynos9825-payloads/build/mif_2133/release/sboot.bin`

Wait for the Download/Odin screen to finish loading before starting a manual
transfer, as required for this board. This build contains no OTP programming
operation and requires no new fuse operation.

## Frequency and voltage

This is **2133 MHz nominal, 2132 MHz calculated**, not exact 2133 MHz silicon
operation. The existing MIF PLL has an integer 10-bit multiplier. For a 26 MHz
reference, P=3, M=492, S=0 gives:

```
PLL = 26,000,000 * 492 / 3 = 4,264,000,000 Hz
memory clock = PLL / 2    = 2,132,000,000 Hz
DVFS row label           = 2,133,000 kHz
```

Exact 2133 MHz would require a multiplier divisible by 2133 (with P divisible
by 13) under this integer formula, exceeding the 10-bit M field. No fractional
PLL programming was invented. Physical readback is still required to confirm
the requested PMS was applied by ACPM.

The original nominal 2094 and 2093 rows both used PLL entry zero (P=3, M=483,
S=0), giving 2093 MHz memory. The patch appends a separate eleventh PLL_MIF
entry, index 10, and changes only the former 2094 row to use it. Entry zero
and the 2093 row stay intact.

| Property | Result |
| --- | --- |
| Highest nominal DVFS rate | 2133000 kHz |
| Calculated memory rate | 2132000 kHz |
| Boot / resume | 2093000 / 421000 kHz |
| ASV voltage data | Identical for every version and group |
| Lower DVFS rows | Identical |
| DRAM training code and NEWTIME profiles | Identical |
| Kernel voltage margins | No changes introduced |

The top row retains the voltage of the old **2094** row, which can differ from
the voltage of the 2093 row. The experiment does not add voltage to compensate
for the frequency increase. Existing timing/training profiles are reused;
successful signing and compilation do not establish that they are stable at
the higher clock. Once enabled by the matching BL2, the governor can select
the new row under load; keeping the boot frequency at 2093 does not prevent it.

## BL2 changes and signing

Base: `/home/chanz22/EUB-N10/9825_customkey/ecdsa_green3/sboot.bin`.
SHA-256: `591dbe7b65aede649c302801292184a94876e8ca39f2193774369cfdbffc3f6f`.
This retains the existing information-screen u-boot and all its current patches.

BL2 is at sboot offset `0x16000`, length `0x52000`; ECT starts at BL2 offset
`0x36c00`. The builder pins the complete BL2 body hash before modifying it.

Changes:

1. Append PLL_MIF index 10: `(4264000000, 3, 492, 0, 0)`; count 10 to 11.
2. Shift subsequent PLL records and ECT blocks by 20 bytes, updating their
   directory offsets and size. Consume verified zero padding at the end of
   the copied `0x14000`-byte ECT region. Preserve the trailing thermal word,
   which lies beyond the original header's size field.
3. Rename only DVFS row 2094000 to 2133000 and select PLL index 10.
4. Rename only ASV frequency label 2094 to 2133, preserving all voltage bytes.
5. Change the maximum in all seven `MINMAX_dvfs_mif` rows from 2093 to 2133;
   preserve minimum, boot, resume and version selectors.
6. Re-sign BL2 and the outer sboot ST2 signature with the existing
   `keys/4/st2t.pem`. Preserve signature padding, all other stages and ST1.

`tools/build_mif_2133.py` verifies both input signatures, the embedded public
key, output signatures, and an inverse transformation of the complete ECT
region. Only the explicit allowed edits can survive that check.

## Kernel and AVB

Source: `/home/chanz22/Documents/GitHub/android_kernel_samung_s5e9825-oneui`.
Base commit: `9c744e3150f8df6c9fc9520192d2e2e9cd4d7848`, including the user's
existing working-tree changes. The source was copied into
`build/mif_2133/kernel-source`; the original tree was not edited.

Only the MIF `freq_info` property in `exynos9825.dts` was changed for this
experiment. The kernel already builds its OPP list from ECT and clamps the
device-tree maximum to CAL's maximum. Therefore the matching patched ECT is
needed to expose 2133000; stock ECT still clamps to its old limit. No hardcoded
voltage table or direct kernel PLL programming was added.

Configuration: `exynos9820-d2s_opt_defconfig`, KernelSU enabled, optional
62 Hz panel experiment disabled. Build uses the existing Clang r383902b and
Android GCC 4.9 binutils with `CCACHE_DISABLE=1`. Full kernel, explicit DTBs
and modules builds passed. Existing duplicate `fpsensor_goto_suspend` export
and two modpost section-mismatch warnings remain in the build log.

`tools/package_mif_2133.py` signs boot/DT/DTBO using the existing RSA-4096
`keys/4/avb.pem`, updates the boot/bootloader hash descriptors and the dtb/dtbo
chain keys, and re-signs the existing custom top-level vbmeta. It preserves
the existing keystorage, recovery/product keys, rollback slots and vbmeta
flags. It refuses to generate a missing key.

AVB descriptors and chained partition keys follow the [AOSP AVB format](https://android.googlesource.com/platform/external/avb/+/master/README.md).

## Reproduction and validation

Build the signed BL2/sboot:

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads
python3 tools/build_mif_2133.py \
  --base /home/chanz22/EUB-N10/9825_customkey/ecdsa_green3/sboot.bin \
  --keys /home/chanz22/EUB-N10/9825_customkey/keys \
  --out build/mif_2133/release
python3 tools/test_mif_2133.py
```

The kernel source patch is included in the release directory. Apply it to a
copy of the same source working tree before building with:

```sh
env CCACHE_DISABLE=1 \
  TOOLCHAIN_ROOT=/home/chanz22/Documents/GitHub/android_kernel_samung_s5e9825-oneui/toolchain \
  DEFCONFIG=exynos9820-d2s_opt_defconfig JOBS=8 \
  OUT_DIR=/home/chanz22/Documents/GitHub/exynos9825-payloads/build/mif_2133/kernel-out \
  RELEASE_DIR=/home/chanz22/Documents/GitHub/exynos9825-payloads/build/mif_2133/unsigned-packaging \
  bash build/mif_2133/kernel-source/build_kernel.sh

python3 tools/package_mif_2133.py \
  --kernel-out build/mif_2133/kernel-out \
  --base-avb build/custom_avb_infoscreen \
  --key /home/chanz22/EUB-N10/9825_customkey/keys/4/avb.pem \
  --cm build/custom_cm/cm.bin \
  --out build/mif_2133/release
```

Do not use the intermediate archive in `unsigned-packaging`: it lacks the
final signatures. Rebuilding sboot generates fresh ECDSA signatures, so rerun
the packaging step afterwards to refresh vbmeta and the archives.

Completed checks:

- All ST1/ST2 signatures pass the project's independent `verify_9825.py`.
- Four ECT tests check independent PLL selection, all ASV voltage payloads,
  lower levels, unchanged NEWTIME/thermal data, missing-padding rejection,
  and rejection of a second patch application.
- `fdtget` on the compiled DTB reports MIF maximum 2133000 and boot 2093000.
- `avbtool verify_image` passes for boot, dt and dtbo under the existing key.
- All four root hash descriptors match the final boot, sboot, CM and
  keystorage images; top-level RSA signature and DT chain keys are checked.
- Both archive member lists, member bytes, partition sizes and MD5 suffixes
  are checked; SHA-256 hashes are supplied.

Hardware acceptance remains separate: boot successfully, confirm the live
MIF OPP/voltage table, exercise transitions under memory load, read the actual
MIF PLL PMS/rate, and check for ACPM timeouts or memory errors. A visible
2133000 entry alone does not demonstrate a working overclock.

## 2026-10-25: the ECT is not the whole RAM config — the "libdmc" lead

Static analysis of `hwha_stages/bl2.bin` (the HWHA BL2 stage; file offset == VA,
base 0). Prompted by an external hint (mustafacooTR, author of the ECT editor):
"deep search 2093/2093000, PMSK of 2093 MHz MIF, 2093*2; if you don't see it,
reload bl2 as arm32 and sniff again, then you start the big eye-opening of the
hardcoded RAM config in bl2." Every one of those points checks out.

### There is a hardcoded MIF rate table in BL2 code, outside the ECT

At **`bl2+0x033fb0`** (below the ECT, which starts at `0x36C00`) there is a
10-entry table of `{rate_kHz: u32, code: u32}`, 8 bytes each, that matches
`RATES` exactly and **still has 2094000 at the top**:

```
0x033fb0  2094000  code=0x0f04     0x033fe0   845000  code=0x0f04
0x033fb8  2093000  code=0x0f04     0x033fe8   676000  code=0x0d03
0x033fc0  1794000  code=0x0f04     0x033ff0   546000  code=0x0a02
0x033fc8  1539000  code=0x0f04     0x033ff8   421000  code=0x0802
0x033fd0  1352000  code=0x0f04
0x033fd8  1014000  code=0x0f04
```

`2093000` therefore appears twice in the image: here (code) and at `bl2+0x037e18`
(ECT `dvfs_mif`); `2094000` likewise at `0x033fb0` and `0x037e10`. The MIF-2133
build edits only the ECT (PLL_MIF, the `dvfs_mif` label, MINMAX, ASV), so this
code-side table is untouched and still names 2094000 as the top rate. The `code`
column is an opaque per-rate selector that steps down with frequency
(`0x0f04` for the top seven rates, then `0x0d03`, `0x0a02`, `0x0802`); it is not
yet decoded.

The PLL side is different: `2093*2 = 4186 MHz` is the VCO, and `4186000000`
(with `P=3, M=483, S=0`) exists **only** in the ECT `PLL_MIF` entry 0
(`bl2+0x037344`/`0x03734c`). There is no hardcoded PLL PMS in the code. So the
PLL is fully ECT-driven; what is hardcoded is the rate list + `code`.

### Part of BL2 is ARM32/Thumb — an embedded DRAM-controller blob

A dense, continuous code region runs from roughly `bl2+0x018800` to past
`0x022000`. Disassembled as **AArch64** it is `udf`/garbage; disassembled as
**ARM32/Thumb** it is real code (confirmed with capstone `CS_ARCH_ARM`/
`CS_MODE_THUMB`). This is the "reload as arm32" that the hint refers to, and it
is what Samsung's build calls `libdmc`: the DRAM memory-controller / training
code. There is no literal `libdmc` string in the image.

What it does, from the disassembly:

- It programs the DRAM controller directly. The code is a long run of
  `movw rN,#low ; movt rN,#0xa586 ; str rM,[rN]`, i.e. MMIO writes to register
  blocks based at **`0xA5860000`** and **`0xA5870000`** (DREX/PHY/DMC). Example
  at `0x020e20`: writes `0xa5861008`, `0xa586eae0 = 0x15` then `0x16`,
  `0xa5869044`, `0xa58690c4`, `0xa586d048 = 5`, … dozens of them.
- It keeps an in-image global context/state at **`0x1a934`** (plus
  `0x1a93c..0x1a94c`, `0x1aa24/0x1aa28`) and name buffers at `0x19dc0/dcc/dd8`
  (zero at rest, filled at runtime).
- A Thumb function-pointer table at **`bl2+0x033f60`** (18 slots, odd/Thumb
  addresses into the blob; a few slots are zero) feeds a two-level `blx`
  dispatcher at `0x020c38` (`idx = value & 0xf`, table at `0x19e70`).
- The ECT block/table **names** live as strings at `bl2+0x00f604..0x00f7f8`
  (`PLL_MIF`, `NEWTIME`, `TIMING`, `dvfs_mif`, `SCI_dvfs_mif`, `MINMAX_`,
  `OFFSET_`, `ASV`, `MARGIN`, `G3D_DD_margin`, …) right next to the DMC training
  banners: `DRAM INFO MISMATCH!! STOP!!`, `DMC `, `Done for sure.`,
  `0123456789ABCDEF`. So the ECT parser and the DRAM trainer are the same
  component, and it has distinct `TIMING` and `NEWTIME` blocks (per-frequency
  DRAM timing — the ECT `NEWTIME` block is at `bl2+0x03e0e8`, the largest block).

Neither `0x33fb0`, `0x33f60`, nor the ECT/NEWTIME addresses appear as plain u32
literals anywhere, so they are reached via `movw/movt` (Thumb) or `adrp`
(the AArch64 side), not a literal pool — "unreferenced" scans are misleading.

### What this means for a real 2133

Relabelling one ECT DVFS row does not produce a trained 2133. The actual RAM
configuration lives in three places the current build does not touch:

1. the hardcoded rate table at `bl2+0x033fb0` (still `2094000` at the top);
2. the `NEWTIME`/`TIMING` per-rate timing sets in the ECT (reused from the 2094
   profile — see the `training_code_and_newtime='unchanged'` note above);
3. the DREX/PHY register sequences in the Thumb DMC blob, keyed by the `code`
   column and the timing sets.

A genuine 2133 needs the PLL M in the ECT **and** a matching top-rate timing
set **and** consistency with (1); otherwise the DMC trains with 2094 timings at
a 2133 clock. This is exactly the stability gap already flagged.

### Open items (next-step RE, Ghidra with this region loaded as ARM32/Thumb)

- Load `bl2+0x018800..0x022000+` as Thumb; find the blob's entry/boundaries and
  how the AArch64 BL2 invokes it (mode switch vs. separate core — the MMIO base
  `0xA586xxxx` and the M-profile-style code suggest a power/DRAM-management
  firmware, not the main AP).
- Decode the `code` column (`0x0f04`/`0x0d03`/`0x0a02`/`0x0802`) and find the
  consumer of the `0x33fb0` table.
- Map how a rate selects its `NEWTIME`/`TIMING` set and the DREX/PHY sequence.

Method/repro: capstone (`pip install capstone`), `Cs(CS_ARCH_ARM, CS_MODE_THUMB)`
over `bl2.bin` slices; the hardcoded table is a plain `{u32 kHz, u32 code}` array
at offset `0x033fb0`. Analysis was static only; nothing was built or flashed.

## 2026-10-25: how DRAM training actually selects timings (Ghidra, both ISAs)

The "libdmc lead" above was followed to a conclusion with Ghidra headless on
`hwha_stages/bl2.bin` (base 0x0): once as **AArch64** for the BL2 proper and
once as **ARM:LE:32:v7 Thumb** for the embedded blob. Scripts:
`tools/ghidra/Exy9825_DmcTrace.java` and `Exy9825_ThumbBlob.java`; reports in
`build/dmc_trace_report*.txt` and `build/thumb_blob_report.txt`. This revises
the guesses in the section above — in particular about the `0x33fb0` table.

### The ECT access API (AArch64 BL2)

Function names recovered from the `printf("%s", __func__)` idiom and roles read
from the decompiler:

- `FUN_00004668(name)` — `ect_get_block("NEWTIME"/"GEN"/…)`; 0 → silent hang.
- `FUN_000048b4(block, "dvfs_mif"/"SCI_dvfs_mif"/…)` — `ect_get_table`; data at
  `tbl+0x18`.
- `FUN_000049a0(block, key)` — `ect_get_newtime_subtable(key)`; `+0x10`=width,
  `+0x14`=count, `+0x18`=data.
- `FUN_0000464c(ptr, i)` — read a NEWTIME cell (64-bit).

### Timing is selected by DRAM part, then indexed by DVFS level

Not by frequency. Two stages:

1. **Per-part selection.** `NEWTIME` (`0x2764`, caller `FUN_0000604c`) reads the
   DRAM manufacturer/rank id — `(*(u64*)(DAT_f318+0xc0) >> 4) & 0xf`, itself from
   the PMU DRAM-info register `_DAT_158609b0` guarded by a `0xfeed0000` magic —
   and searches the **NEWTIME master table, key `0x11111111`**, for the row whose
   column 0 equals that id. That row lists the sub-table keys (`ac1..ac6`,
   `b1..b5`, `ca1..ca4`, …) to load for this exact DRAM part. The master table's
   column 0 holds packed part ids, not frequencies.
2. **Per-level programming.** `NEWTIME` (`0xdd74`) is called as
   `NEWTIME(level_count, level_index)` by `FUN_0000eabc`/`FUN_00006084`, and
   strides the loaded tables by the **DVFS level index**: `index*0x78`,
   `index*0x20`, `(width*4)*index`. The level index comes from the DMC context
   (`DAT_f318+0xc` = number of DVFS levels; boot/target points from
   `FUN_000086d0/0874c/087cc`, clamped to that count). No frequency value is
   compared anywhere; the row **is** the level index.

`FUN_00001df8` (`dvfs_cal_init`) separately builds the per-domain DVFS/PLL
structures for all 15 DVFS domains from ECT `dvfs_mif`, `PLL_SHARED1/3`,
`SCI_dvfs_mif` — this is the path that consumes the ECT rate label.

### The embedded Thumb blob is a DREX/PHY sequencer, nothing more

Imported as Thumb, it is a two-level **command interpreter** (dispatcher
`0x20c38`: `fn = table[0x19e70][(cmd>>4)&0xf][cmd&0xf]; fn(arg)`) plus a static
DREX/PHY bring-up (`0x20d5c`, constant writes). It touches only MMIO at
`0xA5860000`/`0xA5870000` and its own data region (`0x18xxx..0x21xxx`,
context `0x1a934`). A definitive movw/movt scan confirms the blob **never forms
the address of `0x33fb0`, `0x33f60`, or the ECT**. It writes what the AArch64
side hands it; it does not parse the ECT or scale by frequency.

### Verdict on the `0x33fb0` table and `aa1[2093]`

- **`0x33fb0` has no consumer anywhere in `bl2.bin`.** Ghidra reports 0 refs; a
  58k-instruction AArch64 sweep forms the address by no means (no adrp/adr, no
  base+offset add chain); the Thumb blob does not reference it either. Its reader
  is a separate image — almost certainly the **ACPM** firmware — so its `code`
  column cannot be decoded from this BL2. **Editing `0x33fb0` has no demonstrated
  effect on DRAM training or on the DVFS rate label.** The rate label the kernel
  and `dvfs_cal_init` use lives in ECT `dvfs_mif`.
- **`NEWTIME/aa1` row 0 = `2093` is a label**, the top reference frequency, not a
  scaling divisor: the selection is part-based and index-strided, with nothing
  dividing by 2093.

### What this means for 2132

A real 2132 MHz point does **not** need a new timing set. Timings are chosen by
the installed DRAM part and indexed by DVFS level; 2093→2132 changes neither the
part nor the top level index, and 2132 stays inside the same JEDEC 4266 bin — so
the existing top-level timing applies (consistent with `r0==r1` across every
per-frequency table). The overclock levers are the MIF PLL in the ECT (M=492,
done) and the ECT `dvfs_mif` rate label; the `NEWTIME` top timing should be left
as is. The `0x33fb0` table and the Thumb blob are not levers for this.
