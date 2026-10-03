/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"
#include "dwc3_ep1.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RX_DESTINATION           0x02030000
#define PROBE_RX_LIMIT                 0x100
#define PROBE_PATTERN_SIZE             0x40

/* Derived from the hardware-matched S5E9825 BootROM dump. */
#define PROBE_ORIGINAL_EVENT_CALLBACK  0x00001b2c
#define PROBE_ACK_EVENT_HELPER         0x00002fbc

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    /* Houston replaces this callback while the triggering event is pending. */
    mov     x19, x0
    adr     x20, probe_record
    mrs     x21, CurrentEL
    str     x21, [x20, #0x48]
    mov     x21, #PROBE_RX_DESTINATION
    str     x21, [x20, #0x20]
    mov     x21, #PROBE_RX_LIMIT
    str     x21, [x20, #0x28]

    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w21, [x22]
    str     x21, [x20, #0x50]
    ldr     w21, [x19]
    str     x21, [x20, #0x58]

    /* Run the original handler, then retire the current dispatcher event. */
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

    /* Poison the bounded iRAM buffer before entering the receive core. */
    ldr     x21, =PROBE_RX_DESTINATION
    mov     x22, #PROBE_PATTERN_SIZE
1:
    strb    wzr, [x21], #1
    subs    x22, x22, #1
    b.ne    1b
    dsb     sy

    mov     w0, #PROBE_RX_DESTINATION
    mov     w1, #PROBE_RX_LIMIT
    ldr     x16, =S5E9825_BOOTROM_USB_RECEIVE_FORWARD
    blr     x16

    adr     x19, probe_record
    uxtw    x20, w0
    str     x20, [x19, #0x18]

    ldr     x21, =PROBE_RX_DESTINATION
    adr     x22, expected_pattern
    mov     x23, #0
2:
    ldrb    w24, [x21, x23]
    ldrb    w25, [x22, x23]
    cmp     w24, w25
    b.ne    receive_failed
    add     x23, x23, #1
    cmp     x23, #PROBE_PATTERN_SIZE
    b.ne    2b

    cmp     w20, #1
    b.ne    receive_failed

    ldr     x20, =0x2153534150315852  /* "RX1PASS!" */
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    mov     x20, #-1
    str     x20, [x19, #0x30]
    b       report_result

receive_failed:
    ldr     x20, =0x214c494146315852  /* "RX1FAIL!" */
    str     x20, [x19]
    mov     x20, #0x100
    str     x20, [x19, #0x10]
    str     x23, [x19, #0x30]

report_result:
    ldr     x20, =PROBE_RX_DESTINATION
    ldp     x21, x22, [x20]
    str     x21, [x19, #0x38]
    str     x22, [x19, #0x40]

    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

3:
    b       3b

.size payload_main, . - payload_main

.balign 8
expected_pattern:
    .byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    .byte 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    .byte 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    .byte 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    .byte 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    .byte 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    .byte 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    .byte 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f

.section .data, "aw"
.balign 8
.type probe_record, %object
probe_record:
    .ascii  "RX1INIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record
