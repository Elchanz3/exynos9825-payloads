/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"
#include "dwc3_ep1.h"

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
    adr     x20, probe_record
    mrs     x21, CurrentEL
    str     x21, [x20, #0x48]

    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w21, [x22]
    str     x21, [x20, #0x50]
    ldr     w21, [x19]
    str     x21, [x20, #0x58]

    /* Reproduce the work deferred by Houston's non-returning callback. */
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
    ldr     x21, =0x2121545645315852  /* "RX1EVT!!" */
    str     x21, [x20]
    mov     x21, #1
    str     x21, [x20, #0x10]
    ldr     w21, [x22]
    str     x21, [x20, #0x18]

    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

1:
    b       1b

.size payload_main, . - payload_main

.section .data, "aw"
.balign 8
.type probe_record, %object
probe_record:
    .ascii  "RX1INIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record
