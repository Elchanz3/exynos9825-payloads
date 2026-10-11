/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Minimal replacement for the sboot ("u-boot") stage.
 *
 * Purpose: prove that a stage signed with our own keys is loaded, verified and
 * entered, and report what it was entered with. If its banner appears on
 * EP1 IN, replacing the bootloader is proven and the rest is ordinary work.
 *
 * Fully position-independent, so it does not need the stage's load address --
 * which is just as well, since that address is not established. The stock
 * stage's own prologue is `b +4` then `adr x0, ...`, i.e. it is PC-relative at
 * entry too.
 *
 * Entry offset is NOT known: the BootROM enters the EPBL at load+0x10, but
 * whether BL2 enters this stage at +0x00 or +0x10 has never been established.
 * So every 4-byte slot in the first 0x14 branches to the same place, and the
 * question stops mattering.
 *
 * Output goes through the BootROM's iRAM function-pointer table, which
 * survives into this phase -- it is how BL2's own "[U-boot] USB Loading"
 * messages reach EP1 IN. PTR_USB_SEND is 0x020200D0 (the pointer there is
 * 0x5338 on this SoC) and takes (w0 = address, w1 = length).
 */

#define PTR_USB_SEND            0x020200D0
#define PROBE_RECORD_SIZE       0x60

.section .text.entry, "ax"
.global _start
.type _start, %function
_start:
    b       stage_main          /* +0x00 */
    b       stage_main          /* +0x04 */
    b       stage_main          /* +0x08 */
    b       stage_main          /* +0x0c */
    b       stage_main          /* +0x10 */
.size _start, . - _start

.type stage_main, %function
stage_main:
    /* Capture the entry state before anything can clobber it. */
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mrs     x24, CurrentEL
    mov     x25, sp

    /* Banner first: plain text still shows up even if record parsing misses. */
    adr     x0, banner
    mov     w1, #(banner_end - banner)
    bl      usb_send

    /* Then a record the host decodes, carrying the entry state. */
    adr     x19, record
    mov     x0, #1
    str     x0, [x19, #0x10]    /* status */
    str     x20, [x19, #0x18]   /* x0 on entry */
    str     x21, [x19, #0x20]   /* x1 on entry */
    str     x22, [x19, #0x28]   /* x2 on entry */
    str     x23, [x19, #0x30]   /* x3 on entry */
    str     x24, [x19, #0x38]   /* CurrentEL */
    str     x25, [x19, #0x40]   /* SP */
    adr     x0, _start
    str     x0, [x19, #0x48]    /* where we actually got loaded */
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      usb_send

halt:
    b       halt
.size stage_main, . - stage_main

/*
 * w0 = address, w1 = length. Tail-calls through the iRAM pointer so the
 * BootROM routine returns straight to our caller.
 */
.type usb_send, %function
usb_send:
    movz    x16, #(PTR_USB_SEND & 0xffff)
    movk    x16, #(PTR_USB_SEND >> 16), lsl #16
    ldr     w16, [x16]
    br      x16
.size usb_send, . - usb_send

.balign 4
banner:
    .ascii  "OUR OWN SIGNED STAGE IS RUNNING"
banner_end:

/*
 * The host accepts any 8-byte magic whose bytes are all in 0x21..0x5A when it
 * is followed by the (version, size) pair, so this is a decodable record.
 */
.balign 8
.global record
record:
    .ascii  "UBSTAGE!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .space  PROBE_RECORD_SIZE - 0x10, 0
.size record, . - record
