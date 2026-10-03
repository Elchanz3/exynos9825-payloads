/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RX_DESTINATION           0x02030000
#define PROBE_RX_LIMIT                 0x100
#define PROBE_PATTERN_SIZE             0x40

/* Derived from the hardware-matched S5E9825 BootROM dump. */
#define PROBE_ORIGINAL_EVENT_CALLBACK  0x00001b2c
#define PROBE_ARM_RECEIVE              0x00001174
#define PROBE_ENDPOINT_COMMAND         0x00001268
#define PROBE_CLEAR_TRB                0x000019e4
#define PROBE_POLL_EVENTS              0x00002af0
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
    mov     x21, #PROBE_RX_DESTINATION
    str     x21, [x20, #0x20]
    mov     x21, #PROBE_RX_LIMIT
    str     x21, [x20, #0x28]

    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w21, [x22]
    str     x21, [x20, #0x50]
    ldr     w21, [x19]
    str     x21, [x20, #0x58]

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

    /* Retire the stale logical EP2 OUT transfer through the BootROM path. */
    mov     w0, #2
    mov     w1, #8
    mov     w2, #0
    mov     w3, #0
    ldr     x16, =PROBE_ENDPOINT_COMMAND
    blr     x16
    adr     x20, probe_record
    str     x0, [x20, #0x18]
    cbz     w0, cancel_command_failed

    mov     w0, #2
    ldr     x16, =PROBE_CLEAR_TRB
    blr     x16
    dsb     sy

    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w23, [x22, #0x2c]
    add     x23, x23, #0xa0
    ldr     w24, [x23]
    ldr     w25, [x23, #8]
    orr     w24, w24, w25
    ldr     w25, [x23, #0xc]
    orr     w24, w24, w25
    cbnz    w24, cancel_clear_failed

    /* Match the state setup performed by BootROM receive core 0x11cc. */
    mov     w21, #PROBE_RX_DESTINATION
    str     w21, [x22, #0xc0]
    mov     w21, #PROBE_RX_LIMIT
    str     w21, [x22, #0xc4]

    ldr     x21, =PROBE_RX_DESTINATION
    mov     x23, #PROBE_PATTERN_SIZE
1:
    strb    wzr, [x21], #1
    subs    x23, x23, #1
    b.ne    1b
    dsb     sy

    /* Arm logical EP2 OUT before asking the host to submit its frame. */
    ldr     x16, =PROBE_ARM_RECEIVE
    blr     x16

    adr     x20, probe_record
    ldr     x21, =0x21214d5241315852  /* "RX1ARM!!" */
    str     x21, [x20]
    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

    ldr     x22, =S5E9825_USB_STATE_POINTER
2:
    ldr     x16, =PROBE_POLL_EVENTS
    blr     x16
    ldrb    w20, [x22, #0xbc]
    cbz     w20, 2b

    adr     x19, probe_record
    cmp     w20, #1
    cset    w20, eq
    str     x20, [x19, #0x18]

    ldr     x21, =PROBE_RX_DESTINATION
    adr     x22, expected_pattern
    mov     x23, #0
3:
    ldrb    w24, [x21, x23]
    ldrb    w25, [x22, x23]
    cmp     w24, w25
    b.ne    receive_failed
    add     x23, x23, #1
    cmp     x23, #PROBE_PATTERN_SIZE
    b.ne    3b

    cbz     w20, receive_failed
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
    b       report_result

cancel_command_failed:
    mov     w20, #0x200
    b       report_setup_failure

cancel_clear_failed:
    mov     w20, #0x201

report_setup_failure:
    adr     x19, probe_record
    ldr     x21, =0x214c494146315852  /* "RX1FAIL!" */
    str     x21, [x19]
    str     x20, [x19, #0x10]
    mov     x21, #-2
    str     x21, [x19, #0x30]

report_result:
    ldr     x20, =PROBE_RX_DESTINATION
    ldp     x21, x22, [x20]
    str     x21, [x19, #0x38]
    str     x22, [x19, #0x40]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

4:
    b       4b

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
5:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 5b
    dsb     sy
    ret
.size probe_usb_send_wait, . - probe_usb_send_wait

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

.balign 16
.type probe_ep1_trb, %object
probe_ep1_trb:
    .zero   0x10
.size probe_ep1_trb, . - probe_ep1_trb
