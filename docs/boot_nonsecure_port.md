# Exynos9825 `boot_nonsecure` port analysis

This document records the reference flow and the evidence required before an
Exynos9825 non-secure boot payload can be implemented. It deliberately keeps
confirmed S5E9825 facts separate from values found in Exynos990, Exynos9810,
and Samsung boot-stage binaries.

## Status and safety boundary

No `boot_nonsecure` payload is implemented yet. The current result is a port
plan and a reverse-engineering checkpoint.

All proposed experiments are volatile. This work must not program eFuses or
OTP, alter rollback state, write UFS or RPMB, flash a partition, or make any
persistent security change. Addresses from the reference SoCs are evidence
about the shape of the boot flow only; they are not S5E9825 constants.

The following labels are used below:

- **hardware-confirmed**: observed on the target SM-N975F;
- **source-confirmed**: read directly from a referenced source revision;
- **artifact-derived**: recovered from the current Binary 9 Samsung binaries;
- **candidate**: supported by static analysis, but still requires a target
  device test;
- **unknown**: insufficient evidence to implement safely.

## Inputs examined

### Public reference sources

- [`halal-beef/exynos990-payloads`](https://github.com/halal-beef/exynos990-payloads),
  revision `862036098caae22ff65feddbe6d43314475eeace`
- [`Robotix22/open-mini-bl1` Exynos9810 change](https://github.com/Robotix22/open-mini-bl1/commit/954fe3e2aea5865db92b0a8be5d610040ac31aa4),
  revision `954fe3e2aea5865db92b0a8be5d610040ac31aa4`
- the later Exynos9810 revision `ff6ffcfc478949f5d1c718283671b3c53b655fb4`,
  whose message is `Full Boot Works now`
- the local Houston fork, including its DNW framing and post-exploit file loop

The public projects call the payload **OpenMiniBL1**. Neither repository has a
function or target named `boot_nonsecure`.

### Exynos9825 artifacts

The analysis used the hardware-validated BootROM dump and the current Binary 9
stage files extracted from the Odin BL `sboot.bin` supplied for this research.
The image identifies itself as `N975FXXS9HWHA`. Files under `old-bin/` belong
to an older bootloader revision and are deliberately excluded.

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| BootROM | `0x20000` | `895eaa3b833a6fc1168461be3d7df38416107872d530fdece90c7f689d671225` |
| Binary 9 `sboot.bin` | `0x400000` | `d2d3a9a580f17069dc627587c95daed8ed7611fab96492f7ccb1815085a88bc0` |
| `epbl.bin` | `0x3000` | `d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d` |
| `fwbl1.bin` | `0x13000` | `34da240b4f91319d3151c32577c57f308ff2b76d4ad6ae2a6b19de88f15f12ee` |
| `bl2.bin` | `0x52000` | `f7bb1492737382bb23c8c9511f461fe0b5a5a87d923c5a20573731a4d522aa8c` |
| `sboot_stage.bin` | `0x180000` | `501ae58a701478345e751db2937f6a8e667ee64f721b2a72063b538213044b87` |
| `el3_mon.bin` | `0x40000` | `b79e2d6c23ec9c5a5aaba7f44c26ffcbad573a002ad01095c20bd14f3817c6c2` |

The five stage files match byte-for-byte slices of `sboot.bin`:

| Stage | Offset in `sboot.bin` | Meaning established so far |
| --- | --- | --- |
| EPBL | `0x000000..0x003000` | first Samsung stage accepted after the BootROM path |
| FWBL1 | `0x003000..0x016000` | later BL1 functionality and EL3 setup helpers |
| BL2 | `0x016000..0x068000` | stage loader and secure-monitor interface |
| sboot | `0x0a4000..0x224000` | Samsung bootloader, linked at `0xbfe80000` |
| EL3 monitor | `0x224000..0x264000` | secure monitor payload, linked at `0xbff80000` |

The gap from `0x068000` to `0x0a4000` remains outside this analysis. The stage
names describe the extracted files; they do not prove the exact protocol name
used by every firmware revision.

## Exynos990 OpenMiniBL1 reference flow

The Exynos990 reference is a replacement for the part of BL1 that was
overwritten by Houston. Its complete visible flow is:

1. The image is linked at `0x02022000`.
2. The entry begins with a NOP sled, clears `.bss`, and calls `main`.
3. `main` calls the BootROM USB reinitialization function indirectly through
   an iRAM function pointer. Its arguments are `0x02021400`, `300`, and `0`.
4. It reconstructs selected BL1 bookkeeping: BL1 size `0x3000`, checksum
   `0x7a1a1bef`, block count at `0x02022000`, and eight CryptoCell function
   pointers.
5. It writes `0x1300` to the Exynos9830 PS_HOLD register.
6. It stores the EPBL receive destination in an iRAM variable. The expression
   is `BL1 size + 0x02023000`, which evaluates to `0x02026000`.
7. It calls the BootROM USB receive function indirectly and permits data up to
   `0x02071000`.
8. It checks the received Samsung header: block count at `+0x0`, expected hash
   at `+0x4`, and ASCII `head` at `+0x8`. It converts the block count to bytes
   and clears the hash word at `+0x4`.
9. Its hash, signature, and rollback functions are stubs that only set status
   bits. They do not implement cryptographic verification.
10. For an already decrypted EPBL, it looks for the `EBRE` marker and changes
    volatile decryption status fields around that marker.
11. It sets the BL1 end status and calls `EPBL load address + 0x10` as a normal
    C function.

The last operation is a secure branch through `blr`; it is not an exception
return. The exact target in the main reference is therefore `0x02026010`.
The source never writes `SCR_EL3`, `SPSR_EL3`, or `ELR_EL3`, and never executes
`ERET`. Any eventual transition to a lower non-secure exception level is done
by a later proprietary Samsung stage.

The `load-different-first-stage-bl` branch adds a receive hook. It recognizes
a later receive destination of `0xbfe80000`, first receives 2.5 MiB at
`0xe8000000`, then restores the original receive path and receives the stage
at `0xbfe80000`. These are Exynos990 research values, not validated S5E9825
values. The separate `secureboot-off-boot` branch clears bit 2 at `0x02020070`;
that behavior is outside the scope of this port and must not be copied.

## Exynos9810 OpenMiniBL1 reference flow

Revision `954fe3e` preserves the same structure with Exynos9810 values and
renames the incoming stage to BL31:

1. Link at `0x02021800`, enter through the NOP/header compatibility area,
   clear `.bss`, and call `main`.
2. Reinitialize USB through the iRAM function pointer with structure address
   `0x02021000`, delay `300`, and speed `0`.
3. Perform an additional receive of `0x2000` bytes at `0x02024800`.
4. Send status text with a direct physical endpoint 3 DWC3 transfer.
5. Reconstruct BL1 state for a `0x2000` byte BL1 and install the Exynos9810
   CryptoCell pointer table.
6. Write PS_HOLD and, in revision `954fe3e`, configure several ALIVE GPIO pull
   fields. The later working revision removes the GPIO operation and corrects
   the PS_HOLD register address.
7. Set the BL31 destination to `BL1 size + 0x02022000`, which evaluates to
   `0x02024000`.
8. Receive the Samsung `head` image with an upper bound of `0x02059000`, apply
   the same verification stubs, set the BL1 end status, and call destination
   `+0x10`, exactly `0x02024010`.

The Exynos9810 payload also contains no `SCR_EL3`, `SPSR_EL3`, `ELR_EL3`, or
`ERET` sequence. Its README tells Houston to send `BL31-EL3_MON` after the
payload, but the open source payload only performs the first BL31 receive.
The received Samsung stage owns the remaining chain.

## Architecture-generic parts

The following ideas can be reused after supplying independently confirmed
S5E9825 values:

- freestanding AArch64 build and fixed-address linker script;
- entry padding required by Houston, followed by `.bss` initialization;
- small MMIO read/write helpers;
- separation between transport, stage parsing, and payload control flow;
- bounded receive buffers;
- parsing the Samsung block-count/checksum/`head` header when that format is
  confirmed for the selected S5E9825 stage;
- barriers and explicit cache maintenance before executing newly written code;
- reporting failures and stopping instead of continuing with partial state;
- keeping the EL3 exception-vector and result-reporting path resident while a
  lower-EL test runs.

The status-bit meanings, footer size, incoming header details, and `+0x10`
entry convention are still stage and SoC contracts. They must not be promoted
to generic S5E9825 behavior without validation.

## SoC-specific parts

The following parts of both references are SoC-specific:

- payload link address and available iRAM window;
- BootROM function addresses and iRAM function-pointer slots;
- USB context address and whether USB reinitialization succeeds;
- BL1 size, checksum, footer, status-bit assignments, and time fields;
- CryptoCell function addresses and their pointer-table location;
- RTC, PMU, GPIO, USB PHY, and DWC3 addresses;
- TRB location and endpoint mapping;
- incoming-stage destination, maximum receive boundary, and entry offset;
- decrypted-image flags and marker layout;
- secure-monitor ABI, stage descriptors, DRAM placement, and security
  controller programming;
- any TZPC, TZASC, or interconnect security setup.

None of those values may be copied into the S5E9825 implementation solely
because Exynos9810 or Exynos990 used it.

## Complete reference address inventory

This section inventories addresses that affect the reference flows. An iRAM
address is listed separately from MMIO so that a RAM bookkeeping write is not
mistaken for a peripheral register write.

### Exynos990 addresses

| Address or range | Kind | Reference use |
| --- | --- | --- |
| `0x02020000` | iRAM base | BL1 state block |
| `0x0202002c` | iRAM | saved RTC tick |
| `0x02020030` | iRAM | BL1 size |
| `0x02020034` | iRAM | BL1 checksum |
| `0x0202006c` | iRAM | secure-boot key pointer |
| `0x02020070`, `0x02020074` | iRAM | status words |
| `0x0202007c` | iRAM | secure-boot information |
| `0x02020084..0x0202008c` | iRAM | BL1 timing values |
| `0x020200a8` | iRAM | `is_secure_boot` function pointer |
| `0x020200d0` | iRAM | USB send function pointer |
| `0x020200dc` | iRAM | USB receive function pointer |
| `0x020200e0` | iRAM | USB reinitialization function pointer |
| `0x020200e8` | iRAM | status setter function pointer |
| `0x02020120..0x0202013c` | iRAM | EPBL size, checksum, destination, and timing |
| `0x02021400` | iRAM | USB structure passed to reinitialization |
| `0x020216d0 + BL1 size + 0x474` | iRAM | CryptoCell pointer table; `0x02024b44` for size `0x3000` |
| `0x02022000` | iRAM | payload link address and reconstructed block count |
| `0x02026000` | iRAM | computed EPBL receive destination |
| `0x02026010` | iRAM | direct EPBL call target |
| `0x02071000` | iRAM boundary | maximum end used by the EPBL receive |
| `0x0000a984`, `0x0000adc8`, `0x0000ae04`, `0x00012bf0`, `0x000167d8`, `0x00016850`, `0x00016910`, `0x000169a0` | BootROM code | CryptoCell helper pointers installed by the reference |
| `0x1586030c` | MMIO | Exynos9830 PS_HOLD control; value `0x1300` |
| `0x15920090` | MMIO | Exynos9830 current RTC tick read by timing code |
| `0xbfe80000` | later RAM destination | recognized by the optional receive-hook branch |
| `0xe8000000` | temporary RAM destination | optional branch receives 2.5 MiB here |

The Exynos9830 header defines the wider RTC range `0x15920030` through
`0x15920094`, but the visible payload flow only reads `0x15920090`.

### Exynos9810 addresses at revision `954fe3e`

| Address or range | Kind | Reference use |
| --- | --- | --- |
| `0x02020000` | iRAM base | BL1 state block |
| `0x0202002c`, `0x02020030`, `0x02020034` | iRAM | tick, BL1 size, and checksum |
| `0x0202006c..0x0202008c` | iRAM | secure-boot, status, and timing fields |
| `0x020200a8` | iRAM | `is_secure_boot` pointer |
| `0x020200dc`, `0x020200e0`, `0x020200e8`, `0x020200f4` | iRAM | receive, reinit, status, and delay function pointers |
| `0x02020120..0x0202013c` | iRAM | BL31 size, checksum, destination, and timing |
| `0x02021000` | iRAM | USB structure passed to reinitialization |
| `0x02021400 + BL1 size + 0x144` | iRAM | CryptoCell pointer table; `0x02023544` for size `0x2000` |
| `0x02021800` | iRAM | payload link address |
| `0x02021804` | iRAM | checksum word cleared by the payload |
| `0x02024000` | iRAM | computed BL31 receive destination |
| `0x02024010` | iRAM | direct BL31 call target |
| `0x02024800` | iRAM | extra pre-message receive destination |
| `0x02037000` | iRAM | direct sender TRB |
| `0x02059000` | iRAM boundary | maximum end used by the BL31 receive |
| `0x00004860`, `0x000048a4`, `0x000049bc`, `0x00008f60`, `0x000090dc`, `0x000091f4`, `0x00009348`, `0x00009528` | BootROM code | CryptoCell helper pointers installed by the reference |
| `0x10c0c834` | MMIO | physical endpoint 3 `DEPCMDPAR1` |
| `0x10c0c838` | MMIO | physical endpoint 3 `DEPCMDPAR0` |
| `0x10c0c83c` | MMIO | physical endpoint 3 `DEPCMD` |
| `0x14050020` | MMIO | ALIVE GPA0 configuration register used by revision `954fe3e` |
| `0x14050028` | MMIO | ALIVE GPA0 pull register used by revision `954fe3e` |
| `0x14050060` | MMIO | ALIVE GPA2 configuration register used by revision `954fe3e` |
| `0x14050068` | MMIO | ALIVE GPA2 pull register used by revision `954fe3e` |
| `0x1406030c` | MMIO | PS_HOLD address written with `0x5300` in revision `954fe3e`; later found incorrect |
| `0x141e0090` | MMIO | Exynos9810 current RTC tick |

The direct sender writes TRB control `0xc13`, places `0x02037000` in
`DEPCMDPAR1`, clears `DEPCMDPAR0`, and writes `0x406` to `DEPCMD`.

The later `ff6ffcf` revision removes the GPIO setup, corrects PS_HOLD to
`0x1406330c`, and performs a read-modify-write at USB/PHY register
`0x11100004`, setting bit `0x100` before reinitialization. These later changes
show why even closely related Exynos MMIO must be verified independently.

## USB behavior and Houston file framing

The two references call a BootROM USB reinitialization function before doing
their first receive. That is not currently usable on S5E9825: calls to the
confirmed BootROM USB init entry `0x000006e8` with `x0 = 0x02021400`,
`w1 = 300`, and `w2 = 0` or `1` did not make the target enumerate again.

Houston's normal exploit path closes over that assumption: after overwriting
iRAM, it waits for a returning USB device before it sends positional files.
The successful S5E9825 marker test instead read `HOUSTON!` on the existing USB
session. The Exynos9825 design therefore has to reuse the live controller and
host handle until a separate device test proves a reinitialization sequence.

For each file after the payload, Houston constructs this DNW frame:

| Offset | Contents |
| ---: | --- |
| `+0x0` | bytes `1b 44 4e 57` (`\x1bDNW`) |
| `+0x4` | little-endian total frame size |
| `+0x8` | raw file bytes |
| final 2 bytes | 16-bit additive checksum of the raw file bytes |

It sends frames to USB endpoint 2 in command-line order. For the older EUB
protocol it does not attach a semantic stage identifier. The code waiting for
the receive and the order supplied by the host determine which stage a file
represents.

In the Exynos990 reference, OpenMiniBL1 directly requests only EPBL. Its README
then describes the remaining input collectively as `EPBL-EL3_MON`; EPBL and
later Samsung code perform subsequent receives. In the Exynos9810 reference,
the corresponding first image is called BL31 and the README says
`BL31-EL3_MON`.

The Binary 9 Exynos9825 research sender uses five ordered slices—EPBL, FWBL1,
BL2, sboot, and EL3 monitor—and a destination selector of `0xfffffffe` in
place of Houston's `\x1bDNW` word. Each slice matches the corresponding range
of the current `sboot.bin`. That proves the content boundaries for the stock
EUB flow. It does not yet prove that the same five frames can be sent unchanged
after a Houston callback hijack.

## Secure-to-non-secure handoff analysis

### BootROM

The complete `0x20000` S5E9825 BootROM contains no aligned encoding for:

- `MSR SCR_EL3, Xn` or `MRS Xn, SCR_EL3`;
- `MSR ELR_EL3, Xn` or `MRS Xn, ELR_EL3`;
- `MSR SPSR_EL3, Xn` or `MRS Xn, SPSR_EL3`;
- `ERET`.

The BootROM therefore does not contain the requested direct handoff sequence.
Its visible final transfers are indirect branches through iRAM state. This
also prevents treating a generic BootROM return helper as the missing handoff.

### FWBL1

FWBL1 has a small accessor at file offset `0x1b10` that executes
`MSR SCR_EL3, X0`, followed by a separate read accessor at `0x1b18`. Static
direct-branch searches did not identify a caller, and FWBL1 contains no
`ERET`, `ELR_EL3`, or `SPSR_EL3` access. This accessor is architectural support
code rather than proof of the boot handoff.

### BL2

BL2's entry code reads `SCR_EL3`, ORs in `0xf`, and writes it back at offsets
`0x20..0x28`. The same startup sequence appears in a relocated copy at
`0x12420..0x12428`. The low four bits set are `NS | IRQ | FIQ | EA`; the code
does not set `SCR_EL3.RW` explicitly and it does not execute `ERET`.

BL2 uses SMC wrappers and constructs a stage descriptor at `0xc8ffe000`. The
visible descriptor writes include a destination/scratch value `0xc9000000`, a
size `0x180000`, and an iRAM value `0x02024c00`; another SMC setup references a
`0x40000` monitor and `0xc9000000`. These values describe proprietary monitor
calls and are not safe S5E9825 payload constants without dynamic validation.

### sboot

The Binary 9 sboot stage is position-dependent code linked at `0xbfe80000`. Its
entry reads `CurrentEL` and installs a vector base appropriate for EL1, EL2, or
EL3. If entered at EL3, it also ORs `0xf` into `SCR_EL3`. The stage contains
only this one SCR write.

The apparent write of `VBAR_EL3` immediately after the SCR write uses the same
register and looks inconsistent when read in isolation. This is another reason
to treat the entry as multi-EL startup code and avoid lifting individual
instructions without the normal caller state.

Seventeen `ERET` instructions occur in the sboot stage. Their callers lead to
the exception-vector save/restore machinery around linked address
`0xbfe90580`: the routine loads a saved ELR and SPSR from an exception frame,
selects EL1, EL2, or EL3 registers according to `CurrentEL`, restores general
registers, and executes `ERET`. These are generic exception returns. They are
not the boot handoff and do not establish a fixed non-secure entry address.

The later `JUMP2K`/`Starting kernel...` path is around `0xbfe84f48`. It performs
platform shutdown and bookkeeping, then calls an indirect function with boot
arguments and loops forever if the call returns. This path uses monitor SMC
wrappers, but it has no inline SCR/SPSR/ELR/ERET sequence. The secure-state
transition is therefore most likely implemented by the installed EL3 monitor
or by a monitor service invoked through SMC. That is an inference from the
call structure, not a decoded monitor implementation.

### EL3 monitor

The Binary 9 `el3_mon.bin` is linked at `0xbff80000`, has code entry at `+0x20`,
and contains encrypted or otherwise non-code regions after its early setup.
The static image has no direct SCR, SPSR_EL3, ELR_EL3, or `ERET` encoding.
Consequently, static disassembly of the stored image is insufficient to name
the monitor's runtime handoff routine or the exact `ELR_EL3` it installs.

### Candidate first non-secure executable address

`0xbfe80000` is the strongest current candidate for the first Samsung
non-secure stage address because:

- the Binary 9 sboot image is linked for `0xbfe80000`, as shown by its
  position-dependent references;
- its entry is explicitly written to tolerate EL1, EL2, or EL3;
- the Exynos990 receive-hook research branch recognizes `0xbfe80000` as the
  later main-bootloader receive destination.

This does **not** yet prove that S5E9825 enters the stage at `0xbfe80000` in
non-secure EL2, nor that arbitrary code placed there is executable with the
same interconnect attribution. The exact legitimate `ELR_EL3` remains
**unknown**. A runtime trace of the monitor handoff, or a controlled probe at
the candidate DRAM address, is required before using it as an exception-return
target.

The known Houston iRAM target `0x02022000` is ruled out: an `ERET` to EL2h with
`SCR_EL3 = 0x40f` and `SPSR_EL3 = 0x3c9` produced
`ESR_EL3 = 0x82000010` and `FAR_EL3 = ELR_EL3 = 0x020220a8`, a synchronous
external instruction abort on the first non-secure fetch.

## TZPC, TZASC, and security-controller evidence

Neither OpenMiniBL1 source configures TZPC, TZASC, or another memory security
controller. It relies on the Samsung stages to establish those attributes.

The Binary 9 artifacts contain evidence that such configuration exists later:

- BL2 strings include `DtzpcRS+`, `DtzpcRS-`, `DtzpcSV+`, `DtzpcSV-`, and
  `DtzpcER`;
- sboot strings include `set_tzpc_secureport`, `set_tzpc_secure_camera`, and
  `ese_tzpc_configs`;
- BL2 and sboot contain many direct MMIO and SMC operations around platform
  initialization.

Static string proximity does not identify which write changes the executable
security attribution of `0xbfe80000`, and no verified TZPC/TZASC register
address can yet be added to `include/s5e9825.h`. The controller sequence
immediately preceding the real handoff remains **unknown**.

## Proposed Exynos9825 architecture

The port should proceed as three independently testable stages.

### Stage 1: read-only EL3 state probe

Add `payloads/boot_nonsecure_probe.S` as a Houston payload linked at
`0x02022000` with the required four leading NOP instructions. It should:

- remain entirely in secure EL3;
- read `CurrentEL`, `SCR_EL3`, `SCTLR_EL3`, `HCR_EL2`, `SCTLR_EL2`, and the
  relevant feature register;
- optionally read candidate Samsung descriptor/state locations only after the
  static analysis gives each field a clear purpose;
- emit one versioned, fixed-size binary record through the already validated
  EP1 IN sender;
- make no peripheral, security-controller, storage, or persistent-state write.

The fixed record should begin with a short magic and version, followed by
64-bit little-endian fields. A host decoder can print the values without
putting formatting code in the payload.

### Stage 2: minimal non-secure transition probe

This stage must wait until a candidate region has enough evidence to justify a
device test. Keep two pieces of code:

1. a secure EL3 resident that installs a private EL3 vector table, records
   exceptions, performs cache maintenance and barriers, and controls the
   transition;
2. a tiny lower-EL stub copied to the candidate region that executes a few
   instructions and immediately issues a controlled SMC.

The EL3 vector path must report `ESR_EL3`, `FAR_EL3`, `ELR_EL3`, and
`SPSR_EL3` through EP1 IN. A successful SMC return must use a separate marker
from an abort report. The first proposed candidate is `0xbfe80000`, but it must
remain a build-time experiment value rather than a public S5E9825 constant
until hardware confirms non-secure execution.

No full Samsung stage receive should be combined with this test. A PASS means
the lower-EL stub fetched and reached EL3 through SMC. Any instruction abort,
data abort, reset, or missing marker is a FAIL that must be analyzed before the
next change.

### Stage 3: minimal OpenMiniBL1/`boot_nonsecure` payload

Only after Stage 2 passes should `payloads/boot_nonsecure.S` be created. Its
components should be:

- the verified Houston entry and fixed linker layout;
- a transport layer that reuses the existing USB session;
- bounded stage receive into independently verified destinations;
- the minimum Samsung header parsing needed by the selected stock stage;
- the minimum volatile BL1 state required by that stage;
- verified cache and security-controller setup;
- transfer to the legitimate Samsung entry through the same exception-level
  mechanism found in the stock chain.

The current Houston post-exploit loop cannot drive this stage unchanged
because it waits for re-enumeration. Host support must retain the existing USB
handle, wait for an explicit payload request or agreed receive point, and then
send the selected Binary 9 stage frames in order.

The following reference features are intentionally excluded unless later
evidence proves they are required and safe: Exynos990/9810 PMU and GPIO
writes, CryptoCell pointer tables, secure-boot flag patches, decrypted-image
status patches, USB PHY writes, and all guessed TZPC/TZASC programming.

## Gates before implementation

Stage 1 can be implemented from already confirmed transport and system-register
facts after this document is reviewed. Stage 2 is blocked on choosing and
reviewing a legitimate candidate region, currently `0xbfe80000`. Stage 3 is
blocked on all of the following:

- hardware confirmation of non-secure instruction fetch and SMC return;
- the exact lower-EL target and execution level;
- the monitor or security-controller sequence that makes that target usable;
- confirmed S5E9825 destinations and bounds for each required incoming stage;
- a same-session Houston host transfer path;
- device validation of each incremental payload.

No `build/boot_nonsecure.bin` target should exist before these gates are met.
