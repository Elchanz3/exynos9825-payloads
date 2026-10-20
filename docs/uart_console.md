# The UART console on Exynos9825 (SM-N975F)

Both the BootROM and sboot's u-boot stage drive a real serial port. Nothing
about it is conditional on an engineering build: the hardware is brought up
unconditionally, at 115200 8N1, on the same controller in both stages.

This matters because every oracle this project has used so far -- the EP1
record, the relocated blue prompt, the charging screen -- is a one-bit channel
bought with a full cold-boot cycle and, for the streamed chains, with EUB.
The serial port is a byte channel that costs nothing and needs no EUB.

Addresses below: BootROM offsets are file offsets into
`bootrom_exynos9825.bin`. u-boot addresses are the VAs the stage runs at;
the stage begins at `sboot.bin` offset `0xa4000`, so
`file = VA - 0xc9000000 + 0xa4000`.

## The controller

One Samsung-style UART, base **`0x10440000`**, with the usual register map:

| offset | register | |
|---|---|---|
| `0x00` | ULCON | `3` = 8 bits, 1 stop, no parity |
| `0x04` | UCON | `0x3000` (ROM) / `0x3c5` (u-boot) |
| `0x08` | UFCON | `0` (ROM, FIFO off) / `0x117` (u-boot, FIFO on) |
| `0x0c` | UMCON | `0` |
| `0x10` | UTRSTAT | bit0 = rx ready, bit1 = tx empty |
| `0x18` | UFSTAT | bit8 = tx FIFO full |
| `0x20` | UTXH | |
| `0x24` | URXH | |
| `0x28` | UBRDIV | |
| `0x2c` | UFRACVAL | |
| `0x38` | UINTM | `0xf` = all interrupts masked (ROM) |

Pin mux: the ROM does a read-modify-write on **`0x10430060`**, writing `0x33`
into bits `[15:8]`. u-boot does not touch it again, so the ROM's mux survives
into the u-boot stage.

The kernel device tree confirms that write independently.
`arch/arm64/boot/dts/exynos/exynos9820.dts` has `pinctrl@10430000` (so
`0x10430060` is GPP3_CON -- 0x20 per bank, gpp0/1/2/3) and
`uart@10440000`, whose `uart0-bus` node reads:

```
samsung,pins = "gpp3-2", "gpp3-3";
samsung,pin-function = <0x3>;
```

Pins 2 and 3 of GPP3 occupy bits `[11:8]` and `[15:12]` of GPP3_CON, and
function 3 in each nibble is exactly `0x33` written at bit 8. Two
independent sources, the ROM's own store and Samsung's device tree, agree
on the same two pads.

That node is `status = "disabled"`, which is consistent with the rest: the
production kernel does not use this port (`console=ram`), the bootloader
does.

### Baud rate: 115200 in both stages

The ROM (`0x19fa8`) calls its configure routine (`0x19798`) with the baud in
w2 and the source clock in w3:

```
1a050:  mov  w21, #0xba80 ; movk w21, #0x18c, lsl #16   -> 26 000 000 Hz
1a068:  mov  w2,  #0xc200 ; movk w2,  #0x1,   lsl #16   ->    115 200 baud
```

`0x196a8` then writes `UBRDIV = clk/(16*baud) - 1` and `UFRACVAL` as the
fractional remainder -- the standard Samsung divisor.

u-boot's `uart_init` (**`0xc9002f38`**) reads its clock from `0xc901c46c` and
divides by a reciprocal constant instead of a literal:

```
c9002f8c:  lsr   x0, x0, #9
c9002fa4:  umulh x0, x0, #0x0123456789abcdf2
```

`0x0123456789abcdf2 / 2^64 = 1/225`, and `225 * 512 = 115200`. Same rate.

## Where the output goes

u-boot:

| | |
|---|---|
| `0xc9002f38` | `uart_init` -- called unconditionally from `0xc9002260` |
| `0xc902fe30` | `serial_putc`: spin on UTRSTAT bit1, store to UTXH |
| `0xc902fe8c` | `serial_getc`: spin on UTRSTAT bit0, read URXH |
| `0xc902fe1c` | `serial_tstc`: UTRSTAT & 1 |
| `0xc902fa00` | `puts`, through the stdio vtable at `[0xc93e6760] + 16` |
| `0xc9058c7c` | `printf` |

`printf` also mirrors into a RAM log at `0xfd910000` when the magic word at
`0xfd910204` equals `0x4d474f4c` ("LOGM") -- that is the `console=ram` path,
and it is *in addition to*, not instead of, the stdio device.

`serial_getc` exists and is wired, and the image carries
`"[Timeout] serial input waiting time is over 60s(%s)"` (`0xc90e5238`,
referenced from `0xc90045d0`), so at least one sboot code path reads from the
port. Whether a full interactive console is reachable is **not yet
established** -- it needs the jig and a keypress.

## Getting the port out of the phone: the MUIC

The AP UART does not reach a connector by itself. It goes through the
MAX77705 MUIC/CCIC, which multiplexes it onto the USB-C data lines. sboot
makes the decision in `board_ccic_check_uart` (**`0xc9002ff0`**):

```
c9003140:  bl   0xc901b2b8        ; ccic_read_adc()
c9003144:  cmp  w0, #0x5
c9003148:  b.ne <skip>
c900314c:  adrp x0, "CC UART\n"
c9003154:  bl   printf
c9003158:  mov  w0, #0x2
c900315c:  bl   0xc9023ce8        ; ifconn_com_to_uart(2) -> MUIC switch
```

### The ADC code is an RID index, and 5 is 523 k

The value is not a raw ADC reading, it is Samsung's RID enum. The device's
own kernel tree (`android_kernel_Samsung_Exynos9825_d2s`,
`include/linux/ccic/ccic_notifier.h:147`) fixes the ordering:

```
RID_UNDEFINED = 0, RID_000K, RID_001K, RID_255K, RID_301K, RID_523K, RID_619K, RID_OPEN
```

So `cmp w0, #5` is **RID_523K**, and `ifconn_is_ccic_jig_device`'s range
3..6 is exactly the four jig resistors 255 k / 301 k / 523 k / 619 k.

`drivers/muic/max77705-muic.c:126` names them:

| resistor | RID | vps_name |
|---|---|---|
| 523 k | 5 | `JIG UART OFF` |
| 619 k | 6 | `JIG UART ON` |

Both route UART *in the kernel*, but sboot only matches 5. 619 k is the
"ON" variant, which is also what drives sboot's `"%s: JIG On. reboot!!!"`
path.

**Knowing the value is not the same as being able to produce it.** The
Black Hat USA 2020 / HITCON talk "Breaking Samsung's Root of Trust:
Exploiting Samsung S10 Secure Boot" (Cheng-Yu Chao, "Jeffxx") reports the
identical `rid == 5` check in the S10's S-Boot, identifies 5 as RID_523K,
and then states that the author's attempts to fake it with **Type-C VDM,
accessory mode, and pull-up/pull-down resistors all failed** -- the slides
conclude a debug cable is required.

So a bare 523 k resistor between CC1 and GND is **not** a validated recipe,
and the CC1-GND wiring in particular is an assumption this document cannot
support: on USB-C the RID does not arrive the way the micro-USB ID pin did,
and someone competent already failed with the obvious approaches. Treat the
jig as an unsolved problem, not a soldering job.

### The UART lands on D+ / D-, and the schematic says which is which

`COM_UART` (`include/linux/muic/max77705-muic.h:369`) writes
`MAX77705_MUIC_COM_UART = 0x03` into *both* `COMP2SW` and `COMN1SW` -- the
MUIC's switches for the connector's DP and DN. So the serial port appears on
the USB-C **D+ and D-** pins, not on SBU.

A board schematic settles the rest.
`Samsung_Galaxy_Note_10_+_Schematic_Diagram.pdf`
(`SM-N976B_SLAVE_REV0.6_0517_FINAL`, Mentor Graphics, Aug 2019, 168 pages)
page 7 is the IF_PMIC page, and the MAX77705's pins carry their datasheet
names next to their nets:

| MAX77705 pin | net |
|---|---|
| `DN` | `MUIC_D_N_IFPMIC` -> `MUIC_D_N` -> `USB_DN` |
| `DP` | `MUIC_D_P_IFPMIC` -> `MUIC_D_P` -> `USB_DP` |
| `DN1` | `USB_AP_D_N` |
| `DP2` | `USB_AP_D_P` |
| **`UT1`** | **`AP_UART_TXD`** |
| **`UR2`** | **`AP_UART_RXD`** |
| `AUT1` / `AUR2` | the CP-side UART, via a discrete "UART SWITCH" on `UART_CTRL` |
| `CC1` / `CC2` | `CC1` / `CC2` |
| `JIG` | `JIG_ONB_CC` |
| `UID` | `JTAG_USB_ID` |

`COMN1SW` picks what reaches `DN` out of {`DN1`, `UT1`, `ADN1`} and
`COMP2SW` picks what reaches `DP` out of {`DP2`, `UR2`, `ADP2`}. In UART
mode that gives:

- **D- carries `UT1` = `AP_UART_TXD`** -- the phone transmits here. This
  is the pin the adapter's **RX** goes to.
- **D+ carries `UR2` = `AP_UART_RXD`** -- the phone listens here.

(An earlier revision of this document guessed D+ for the phone's transmit
line. It is D-.)

The same page shows `CC_SBU1` / `CC_SBU2` going elsewhere, which confirms
the negative: the UART is not on SBU.

Two caveats. The schematic is the **N976B** (Note10+ 5G), not the N975F --
same family, not the same board. And this is pin-name-to-net adjacency read
out of a text extraction of the PDF, not a parsed netlist; the pin names
(`UT1`, `UR2`, `DN1`, `DP2`, `ADN1`, `ADP2`) are distinctive enough that the
pairing is reliable, but ball numbers from the same extraction are not.

### rustproof does not gate this in sboot

The kernel's `com_to_uart_ap()` can substitute `COM_OPEN` for `COM_UART`
when `rustproof_on` is set, so detecting the jig does not by itself
guarantee the lines are routed. sboot has a `check_rustproof` of its own,
at **`0xc902b848`**, which returns the flag and prints `On`/`Off`.

It has exactly one caller, `0xc90568c0`, inside the bootargs/DT builder at
`0xc9056454`, where the result is folded into a value as
`w22 | (rustproof << 3) | (ccic << 4)` and appended to a string handed to
the kernel. Nothing on the `board_ccic_check_uart` -> `ifconn_com_to_uart`
path consults it.

So in the bootloader, rustproof is **passed to the kernel, not applied**.
The COM_OPEN substitution is a kernel-era behaviour and does not affect the
sboot console. (It does mean Android may close the path again after boot.)

`ccic_read_adc` reads the MAX77705 over I2C (slave `0x4a`, register `0x4a`,
via the write/read pair at `0xc90235bc` / `0xc9023478`). The line just above
the switch prints `"%s: jig_adc=%02x, cc_adc=%02x\n"` with both values --
but that log only reaches the port *after* the switch has been thrown, so a
wrong resistor is silent rather than self-diagnosing.

## The jig is not the only way in: patch the branch

The Black Hat author had to produce RID 5 because S-Boot was the thing they
were attacking -- they could not change it. This project's position is the
opposite. `board_ccic_check_uart` is a branch in an image we already
rebuild, re-sign and flash:

```
c9003144:  cmp  w0, #0x5
c9003148:  b.ne 0xc90030e0      <- neutralise this
c900315c:  bl   0xc9023ce8      ; ifconn_com_to_uart(2)
```

Make the comparison always fall through and sboot throws the MUIC switch
with no jig attached at all. The whole RID problem disappears for the
u-boot-era console. It does nothing for the BootROM, which runs before any
of our code.

**This is dangerous in a specific way, and it must not be done yet.**
`COM_UART` takes D+ and D- away from USB, and Download mode runs on those
same two lines. An unconditional switch early in sboot removes Odin, which
is the only flashing path available while EUB is down -- a one-way trip.

The safe shape is the one this project already uses for everything else:
flip the switch only on the specific path being investigated, late, after
the download-mode decision, so a normal boot and a Download-mode boot both
leave USB intact. Even then it waits until EUB is back, because the first
attempt is exactly when the gating could be wrong.

## SWITCH_SEL and DEBUG_LEVEL

sboot keeps a parameter array in the `PARAM` partition. `param.bin` here is a
tar holding `adv-env.img`, and the array starts at offset `0x400`, one u32
per parameter id:

| offset | id | value on this device | |
|---|---|---|---|
| `0x400` | 0 | `4` | |
| `0x404` | 1 | `3` | **SWITCH_SEL** -- USB and UART both routed to the AP |
| `0x408` | 2 | `0x00004f4c` | **DEBUG_LEVEL** = `"LO"` |
| `0x428` | 10 | `0x000055ff` | |

The ids come from the Download-mode parameter handler around `0xc9008838`,
which calls `write_param(id, value, 0, 1)` at `0xc90479d4`: id 1 for
`"setting SWITCH_SEL to %d"`, id 2 for `"setting DEBUG_LEVEL to 0x%x"`.
DEBUG_LEVEL accepts exactly three values -- `0x4948` `"HI"`, `0x494d` `"MI"`,
`0x4f4c` `"LO"` -- and setting `"LO"` also zeroes id `0x1c`.

SWITCH_SEL is already 3, so the AP owns the UART path; no change needed
before trying the jig.

## The BootROM fault packet

This is the part worth the most to this project.

The ROM's boot loop lives at `0x19c`:

```
1dc:  bl   0x5780        ; the key selector -- KEY2 (0x10003020) vs KEY (0x10003000)
1e0:  mov  w20, w0       ; the chosen key pointer
200:  mov  w0, w19       ; device index 1, then 2
204:  bl   0xcc68        ; try to load from that device
210:  mov  w0, w20
214:  bl   0x5b58        ; verify with the chosen key
230:  b.eq 0x264         ; nothing booted
264:  mov  w0, #1
268:  bl   0x16340       ; -> 0x1a0b4, the UART dump
```

`0x16340` is `fatal(flag)`: with flag 1 it calls the dumper at `0x1a0b4`,
with flag 0 (the other call site, `0xcc64`) it takes a silent path and hangs.
So **when the BootROM cannot boot anything, it brings up the UART and prints
a structured fault packet.**

### The dump has a fuse gate, and this device passes it

`0x1a0b4` does not dump unconditionally. Its first act is:

```
1a028:  bl   0x17564        ; (SEC0 & 0x400) != 0
1a02c:  cmp  w0, #1
1a030:  b.eq 0x1a0a0        ; -> return, no UART, no output
```

`0x17564` reads bit 10 of `0x10001000`. That register is **SEC0** -- the
same one the key selector's predicates A/C/D/E come from (`0x17514` bit 8,
`0x175dc` bit 1, `0x175b4` bit 3, `0x17604` bit 0); SEC1 is `0x1000b014`.
This project has already measured **SEC0 = `0x00000001`** on this unit
(`docs/custom_key_fuse_port.md`), so bit 10 is clear and **the gate passes**.
A unit with that fuse blown would print nothing.

The second guard at `0x1a034` is only a once-only flag, and the tail call at
`0x1a09c` goes to `0x19ba8`, which is a bare `ret`. The
`"[UART BOOT] ... Can not connect to DNW"` strings sit in the literal pool
just before this function and belong to the ROM's separate UART-boot path,
not to the dump -- this is a one-shot print, not a handshake.

The packet is assembled in a 640-byte buffer: `"\r\n\r\n"`, then `"UUUUUUUU"`,
then `"V0000001"`, then a run of 8-character hex fields, then `"ZZZZZZZZ"`.
The fields, in order, are the words at:

```
0x10000000  0x10000004  0x10000008   chip id
<arg0> <arg1>                        the two fatal() codes
0x15860404  0x02020068  0x15860000
<zero>
0x0202006c                           the key pointer written by ROM 0x5770
0x0202007c  0x02020200
0x1000c000  0x1000b014  0x1000b018
0x10001000  0x10001004  0x10006000
0x1d020160  0x1a240160
<zero> <zero>
0x02020064  0x02020070  0x02020074
<zero>
0x020201c0 .. 0x020201fc             16 words
0x10003000 .. 0x1000301c             KEY   -- 8 words, 32 bytes
0x10003020 .. 0x1000303c             KEY2  -- 8 words, 32 bytes
0x1000b030  0x1000b034  0x1000b038  0x1000b03c  0x1000b030
```

The ROM prints **both fused key slots in full**, plus the pointer the
selector chose between them. Every question this project has been answering
one cold boot at a time -- is KEY2 blank, which slot is the ROM reading, what
did the selector decide -- is one line of a failing boot's serial output.

Caveat: this is the *total failure* path only. A boot that gets as far as
sboot never reaches it; for those, u-boot's own console is the channel.

## What is not established

- **How to make the MUIC report RID 5 at all.** This is now the first
  obstacle, ahead of everything below -- see the Black Hat result above.
  The firmware side is settled; the physical side is not.
- **Whether anything from before u-boot reaches the connector at all.**
  sboot has to throw the MUIC switch itself, which says the MUIC is not
  already routing UART when u-boot gets there. If the MAX77705 does not
  switch autonomously on jig attach during the ROM/EPBL/BL2 window, then the
  fault packet above is written to a port whose far end is disconnected, and
  only u-boot-onward output is visible. This is the single biggest open
  question, and it is what decides whether the fault packet is useful.
  If it turns out the MUIC stays on USB, the AP-side UART pads between the
  SoC and the MUIC are the fallback, and they would have to be found on a
  boardview rather than in firmware.
- Whether u-boot's stdio console is actually bound to the serial device on a
  retail `DEBUG_LEVEL=LO` unit, or only to the RAM log. `uart_init` runs
  either way, so the port will be configured; whether bytes come out of
  `printf` is an observation, not a deduction.
- Whether the sboot serial input path is an interactive console.

All of these are answered by plugging the jig in and booting once.

## Electrical

The Exynos UART pins are **1.8 V**. The MUIC is an analog switch and does not
level-shift, so whatever is on the connector's data lines is 1.8 V logic.

- A CH341 at **5 V would be destructive**. Set it to 3.3 V.
- Phone TX -> adapter RX at 1.8 V into a 3.3 V CMOS input is below the
  nominal threshold but typically above the CH341's actual one. It usually
  reads; it is not guaranteed.
- Adapter TX -> phone RX at 3.3 V into a 1.8 V pin is the direction that can
  damage the AP. Divide it (e.g. 1.8 k series, 2.2 k to ground) or use a real
  1.8 V level shifter.
- Receive-only is the safe first experiment: leave the adapter's TX
  disconnected entirely, and only the phone drives the line.

Ground must be common between the adapter and the phone.

Two things to check on the CH341 board before it is connected:

- It needs its **UART-mode jumper** set; in programmer mode the TXD/RXD pins
  are not driven as a serial port.
- On many cheap boards the 3.3 V / 5 V jumper sets the *supply rail offered
  to the target*, not the chip's own I/O level. **Measure TXD against GND
  with a multimeter while idle** -- it should sit at 3.3 V, not 5 V -- before
  it goes anywhere near the phone.
