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

## Binary 9 early-stage path

The current EPBL is position-independent code with its executable entry at
file offset `+0x10`. Its normal path derives the next receive destination by
adding the BL1 size stored at `0x02020030` to `0x02023000`, then writes the
result to `0x02020128`. With the expected `0x3000` BL1 size, that expression
produces `0x02026000`. The terminal transfer reads `0x02020128`, adds `0x10`,
and branches indirectly. This independently supports an FWBL1 entry at
`0x02026010` without treating the Exynos990 value as an S5E9825 constant.

The extracted FWBL1 starts with a Samsung `head` header and executable code at
file offset `+0x10`. Its early code is position-dependent at `0x02026000`, and
the literal `0x02026010` appears in initialization code. The visible prefix
configures EL3 architectural state and several SoC blocks, then transfers into
regions of the stored image that do not decode as the instructions expected by
their direct callers. The later body is therefore transformed before use or
otherwise unavailable to plain static disassembly. The DRAM initialization
routine and its exact call point have not been recovered from the stored
FWBL1 image.

Executing isolated FWBL1 MMIO fragments would omit the EPBL verification,
transformation, and state setup that precede them in the stock chain. The port
will instead validate same-session BootROM receive first, then test the stock
EPBL/FWBL1 path with explicit checkpoints. No FWBL1 MMIO writes are copied into
the open payload.

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

`payloads/boot_nonsecure_probe.S` is implemented as a Houston payload linked at
`0x02022000` with the required four leading NOP instructions. It:

- remains entirely in secure EL3;
- reads `CurrentEL`, `SCR_EL3`, `SCTLR_EL3`, `HCR_EL2`, `SCTLR_EL2`, and the
  relevant feature register;
- emits one versioned, fixed-size binary record through the already validated
  EP1 IN sender;
- makes no peripheral, security-controller, storage, or persistent-state write.

The `0x60`-byte record begins with magic `NSP1EL3!`, version and size words,
then ten 64-bit little-endian fields. The accompanying host tool runs the
Houston upload and callback overwrite on the existing USB session and decodes
the result.

Hardware validation on the SM-N975F returned `CurrentEL = 0xc`,
`SCR_EL3 = 0`, `SCTLR_EL3 = 0x00c51838`, `TCR_EL3 = 0`, `HCR_EL2 = 2`,
`SCTLR_EL2 = 0x30c50838`, `ID_AA64PFR0_EL1 = 0x10112222`, and
`VBAR_EL3 = 0x1c000`. EL3 therefore had its MMU and D-cache disabled and its
I-cache enabled. Since `TCR_EL3` was zero, the nonzero `TTBR0_EL3` and
`MAIR_EL3` values do not describe an active translation regime.

### Stage 2: minimal non-secure transition probe

`payloads/nonsecure_transition_probe.S` implements this device-test stage with
two pieces of code:

1. a secure EL3 resident that installs a private EL3 vector table, records
   exceptions, performs cache maintenance and barriers, and controls the
   transition;
2. a tiny lower-EL stub copied to the candidate region that executes a few
   instructions and immediately issues a controlled SMC.

The probe first attempts to write and read back the 16-byte lower-EL stub at
`0xbfe80000`. Its EL3 vector path reports `ESR_EL3`, `FAR_EL3`, `ELR_EL3`,
`SPSR_EL3`, the original SCR/vector state, and lower-EL sentinels through EP1
IN. Magic `NS2PASS!` is reserved for an SMC64 exception class from the stub;
all other exceptions and copy mismatches use `NS2FAIL!`. The candidate remains
local to this experiment rather than becoming a public S5E9825 platform
constant until hardware confirms Non-secure execution.

The first hardware attempt, using artifact SHA-256
`4bef115dab82a46fc893ba75bc2032c6c0e3cd5b55eae20bb02ceac6aa819f23`,
returned no USB record after the callback overwrite. Since that revision first
accessed `0xbfe80000` before reporting, the result did not distinguish a stalled
or asynchronous DRAM access from an earlier payload failure. The instrumented
revision emits `NS2PRE!!` before candidate DRAM access, `NS2COPY!` after
write/readback, and `NS2ERET!` immediately before exception return.

The instrumented revision, artifact SHA-256
`4153ff9861e437dfb5357736a0ad5ffb23d2e185176b78545633094bb191bbb3`,
was tested on the SM-N975F on 2026-10-03. The host received exactly one
record, `NS2PRE!!`, before the payload attempted to access `0xbfe80000`. The
record contained `CurrentEL = 0xc`, the original `SCR_EL3 = 0`, the original
`VBAR_EL3 = 0x1c000`, and zero exception state. Its raw capture is 96 bytes
with SHA-256
`36e9dbe3d2d0abc24ab53029dbfd670ed65a8caddcbeeb440738e0469ec375c2`.

No `NS2COPY!`, `NS2ERET!`, exception record, or terminal result followed.
The first Secure EL3 access to the sboot-linked address therefore did not
complete in the BootROM/Houston environment. The test did not execute `ERET`
and provides no new Non-secure fetch result. This is consistent with DRAM not
yet being initialized or available at this early boot point. Static analysis
of the current Binary 9 EPBL/FWBL1/BL2 chain must identify the responsible
initialization stage before the address is tested again.

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

The first transport prerequisite is isolated in `usb_receive_probe`. It uses
the artifact-derived BootROM ABI at `0x11cc` (`w0 = destination`, `w1 = size
limit`) and asks the host for one normally framed DNW transfer after sending an
`RX1RDY!!` checkpoint. The test destination `0x02030000`, limit `0x100`, and
64-byte pattern remain local to the probe. A hardware PASS is required before
this receive path can be used to feed a Samsung stage.

The first hardware test on 2026-10-03 received `RX1RDY!!`. The host then
reported a complete `0x4a`-byte EP2 OUT write, but no `RX1PASS!` or `RX1FAIL!`
record followed. The result proves execution through the ready checkpoint and
host submission of the frame. It does not prove that the BootROM parsed the
frame or wrote the destination buffer. The call at `0x11cc` did not return
during the observation window, so same-session BootROM receive remains
unvalidated.

`usb_receive_direct_probe` changes one condition: it does not send an EP1 IN
checkpoint before calling `0x11cc`. The host submits the same DNW frame
immediately after Houston completes the callback overwrite. This checks
whether a pending completion event from the ready marker interfered with the
BootROM event loop. It retains the same iRAM destination, bound, pattern, and
receive entry point. No Samsung boot stage is sent by this diagnostic.

The marker-free artifact, SHA-256
`ec0e3ee1ae24ae496acac6b162b12143480c91fb4a94349e571faeb5a2cea803`,
was tested on 2026-10-03. The host completed the same `0x4a`-byte EP2 OUT
write, but received zero result bytes. Removing the preceding EP1 transfer did
not make `0x11cc` return.

Static analysis explains a more fundamental reentrancy problem. Houston
replaces the BootROM device-event callback at USB state offset `+0x10`. The
BootROM dispatcher at `0x2af0` calls that callback before it advances the
software event index and acknowledges four bytes through its helper at
`0x2fbc`. The Houston payload therefore starts while its triggering event is
still pending. Calling `0x11cc` from that context enters `0x2af0` recursively,
where the same event and overwritten callback can be encountered again. The
next diagnostic must restore the observed original callback `0x1b2c`, process
the current event through that handler, advance the software event index, and
use the BootROM acknowledgement helper before entering the receive loop.

`usb_receive_event_probe` implements that sequence without adding direct DWC3
register writes. It uses the hardware-observed USB state pointer
`0x02021970`, the hardware-observed original callback `0x1b2c`, and the event
acknowledgement helper `0x2fbc` identified in the matching BootROM dump. The
helper writes the four-byte acknowledgement used by the dispatcher itself.
The probe records the software event index and triggering event word, then
performs the same bounded iRAM receive. These BootROM-derived operations remain
local to the diagnostic until hardware validation.

The first hardware run of `usb_receive_event_probe`, artifact SHA-256
`febc85fd0ca072f11a645851aa818611f3ebe379cc567bc7ccaa8fbff3ea664b`,
completed the `0x4a`-byte host write but returned zero result bytes. This does
not disprove the dispatcher analysis because the payload had no checkpoint
between repairing the event and entering `0x11cc`. A smaller probe must perform
the repair and report immediately, without starting an OUT transfer.

`usb_event_repair_probe` is that isolated checkpoint. It restores and invokes
the original callback, advances and acknowledges the triggering event, then
sends `RX1EVT!!` through the validated EP1 IN sender. It performs no receive.
The record preserves the event index and event word observed at payload entry.

The following reference features are intentionally excluded unless later
evidence proves they are required and safe: Exynos990/9810 PMU and GPIO
writes, CryptoCell pointer tables, secure-boot flag patches, decrypted-image
status patches, USB PHY writes, and all guessed TZPC/TZASC programming.

## Gates before implementation

Stage 1 is hardware-confirmed. Stage 2 reached its pre-access checkpoint and
then stopped at the first access to `0xbfe80000`; it never attempted the
Non-secure transition. Stage 2 and Stage 3 are blocked on all of the following:

- identification and safe execution of the stock DRAM initialization path;
- hardware confirmation of non-secure instruction fetch and SMC return;
- the exact lower-EL target and execution level;
- the monitor or security-controller sequence that makes that target usable;
- confirmed S5E9825 destinations and bounds for each required incoming stage;
- a same-session Houston host transfer path;
- device validation of each incremental payload.

No `build/boot_nonsecure.bin` target should exist before these gates are met.
