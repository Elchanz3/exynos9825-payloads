/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60

/* Derived from the hardware-matched S5E9825 BootROM dump. */
#define PROBE_ORIGINAL_EVENT_CALLBACK  0x00001b2c
#define PROBE_ACK_EVENT_HELPER         0x00002fbc

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    mov     x19, x0
    ldr     x22, =S5E9825_USB_STATE_POINTER

    /* Complete the event whose callback Houston replaced. */
    ldr     x21, =PROBE_ORIGINAL_EVENT_CALLBACK
    str     x21, [x22, #0x10]
    dsb     sy
    mov     x0, x19
    blr     x21
    ldr     w21, [x22]
    add     w21, w21, #1
    and     w21, w21, #0x1f
    str     w21, [x22]
    mov     w0, #1
    ldr     x16, =PROBE_ACK_EVENT_HELPER
    blr     x16
    dsb     sy

    adr     x20, probe_record
    ldr     x21, =0x212154554f315852  /* "RX1OUT!!" */
    str     x21, [x20]
    mov     x21, #1
    str     x21, [x20, #0x10]
    mrs     x21, CurrentEL
    str     x21, [x20, #0x18]
    ldr     w21, [x22]
    str     x21, [x20, #0x20]
    ldr     w23, [x22, #0x2c]
    str     x23, [x20, #0x28]
    ldr     w21, [x22, #0xb8]
    str     x21, [x20, #0x30]
    ldrb    w21, [x22, #0xbc]
    str     x21, [x20, #0x38]
    ldr     w21, [x22, #0xa4]
    str     x21, [x20, #0x40]

    /* BootROM 0x1920 selects workspace + 0xa0 for logical EP2. */
    add     x23, x23, #0xa0
    ldr     w21, [x23]
    str     x21, [x20, #0x48]
    ldr     w21, [x23, #8]
    str     x21, [x20, #0x50]
    ldr     w21, [x23, #0xc]
    str     x21, [x20, #0x58]

    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

1:
    b       1b

.size payload_main, . - payload_main

.type probe_usb_send_wait, %function
probe_usb_send_wait:
    and     w1, w1, #0x00ffffff
    adr     x2, probe_ep1_trb
    mov     w3, #S5E9825_DWC3_TRB_CTRL_NORMAL
    stp     w0, wzr, [x2]
    stp     w1, w3, [x2, #8]
    dsb     sy
    ldr     x4, =S5E9825_DWC3_EP1_IN_DEPCMDPAR1
    str     w2, [x4]
    ldr     x4, =S5E9825_DWC3_EP1_IN_DEPCMDPAR0
    str     wzr, [x4]
    ldr     x4, =S5E9825_DWC3_EP1_IN_DEPCMD
    mov     w5, #S5E9825_DWC3_STARTTRANSFER
    str     w5, [x4]
    dsb     sy
2:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 2b
    dsb     sy
    ret
.size probe_usb_send_wait, . - probe_usb_send_wait

.section .data, "aw"
.balign 8
.type probe_record, %object
probe_record:
    .ascii  "RX1INIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record

.balign 16
.type probe_ep1_trb, %object
probe_ep1_trb:
    .zero   0x10
.size probe_ep1_trb, . - probe_ep1_trb
