/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RELOCATION_ADDRESS       0x02025000
#define PROBE_EPBL_DESTINATION         0x02022000
#define PROBE_EPBL_SIZE                0x3000

/* Binary 9 N975FXXS9HWHA EPBL. */
/* SHA-256: d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d */
#define PROBE_EPBL_FNV1A64             0xfdfb55e38228e523
#define PROBE_EPBL_CHECKSUM            0xb82c55e7

/* Derived from the hardware-matched S5E9825 BootROM dump. */
#define PROBE_ORIGINAL_EVENT_CALLBACK  0x00001b2c
#define PROBE_ARM_RECEIVE              0x00001174
#define PROBE_ENDPOINT_COMMAND         0x00001268
#define PROBE_CLEAR_TRB                0x000019e4
#define PROBE_POLL_EVENTS              0x00002af0
#define PROBE_ACK_EVENT_HELPER         0x00002fbc
#define PROBE_PARSE_BL1_HEADER         0x00017c54

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    /* Keep the triggering event argument while moving the complete worker. */
    mov     x19, x0
    adr     x9, relocated_start
    adr     x10, relocated_end
    ldr     x11, =PROBE_RELOCATION_ADDRESS
    mov     x12, x11
1:
    ldr     x13, [x9], #8
    str     x13, [x12], #8
    cmp     x9, x10
    b.lo    1b

    /* EL3 enters with the I-cache enabled, so discard stale target lines. */
    dsb     sy
    ic      iallu
    dsb     sy
    isb

    adr     x12, relocated_entry
    adr     x13, relocated_start
    sub     x12, x12, x13
    add     x12, x11, x12
    mov     x0, x19
    br      x12
.size payload_main, . - payload_main

.balign 16
relocated_start:
.type relocated_entry, %function
relocated_entry:
    mov     x19, x0
    adr     x20, probe_record
    ldr     x21, =PROBE_RELOCATION_ADDRESS
    str     x21, [x20, #0x20]
    ldr     x21, =PROBE_EPBL_DESTINATION
    str     x21, [x20, #0x28]

    /* Complete the event whose callback Houston replaced. */
    ldr     x22, =S5E9825_USB_STATE_POINTER
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

    /* Retire and clear the stale logical EP2 OUT transfer. */
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

    /* Clear and arm the stock BootROM EPBL destination. */
    ldr     w21, =PROBE_EPBL_DESTINATION
    str     w21, [x22, #0xc0]
    mov     w21, #PROBE_EPBL_SIZE
    str     w21, [x22, #0xc4]

    ldr     x21, =PROBE_EPBL_DESTINATION
    mov     x23, #PROBE_EPBL_SIZE
2:
    str     xzr, [x21], #8
    subs    x23, x23, #8
    b.ne    2b
    dsb     sy

    ldr     x16, =PROBE_ARM_RECEIVE
    blr     x16

    adr     x20, probe_record
    ldr     x21, =0x2121594452485045  /* "EPHRDY!!" */
    str     x21, [x20]
    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

    ldr     x22, =S5E9825_USB_STATE_POINTER
3:
    ldr     x16, =PROBE_POLL_EVENTS
    blr     x16
    ldrb    w20, [x22, #0xbc]
    cbz     w20, 3b

    adr     x19, probe_record
    cmp     w20, #1
    b.ne    receive_failed

    /* Validate the exact raw EPBL before allowing BootROM to mutate word 1. */
    ldr     x21, =PROBE_EPBL_DESTINATION
    mov     x22, #PROBE_EPBL_SIZE
    ldr     x23, =0xcbf29ce484222325
    ldr     x24, =0x100000001b3
4:
    ldrb    w25, [x21], #1
    eor     x23, x23, x25
    mul     x23, x23, x24
    subs    x22, x22, #1
    b.ne    4b
    str     x23, [x19, #0x30]

    ldr     x24, =PROBE_EPBL_FNV1A64
    cmp     x23, x24
    b.ne    hash_failed

    /* Use the matched BootROM routine that parses the BL1 block header. */
    ldr     x16, =PROBE_PARSE_BL1_HEADER
    blr     x16
    str     x0, [x19, #0x38]
    cmp     w0, #1
    b.ne    parser_failed

    ldr     x21, =0x02020030
    ldr     w22, [x21]
    ldr     w23, [x21, #4]
    str     x22, [x19, #0x40]
    str     x23, [x19, #0x48]
    ldr     x24, =PROBE_EPBL_DESTINATION
    ldr     x25, [x24]
    str     x25, [x19, #0x50]
    mrs     x25, CurrentEL
    str     x25, [x19, #0x58]

    cmp     w22, #PROBE_EPBL_SIZE
    b.ne    parsed_state_failed
    ldr     w24, =PROBE_EPBL_CHECKSUM
    cmp     w23, w24
    b.ne    parsed_state_failed
    ldr     x24, =0x0000000000000018
    ldr     x25, [x19, #0x50]
    cmp     x25, x24
    b.ne    parsed_state_failed

    ldr     x20, =0x2153534150485045  /* "EPHPASS!" */
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    b       report_result

receive_failed:
    mov     x20, #0x100
    b       report_failure

hash_failed:
    mov     x20, #0x101
    b       report_failure

parser_failed:
    mov     x20, #0x102
    b       report_failure

parsed_state_failed:
    mov     x20, #0x103
    b       report_failure

cancel_command_failed:
    mov     x20, #0x200
    b       report_setup_failure

cancel_clear_failed:
    mov     x20, #0x201

report_setup_failure:
    adr     x19, probe_record

report_failure:
    ldr     x21, =0x214c494146485045  /* "EPHFAIL!" */
    str     x21, [x19]
    str     x20, [x19, #0x10]

report_result:
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

5:
    b       5b
.size relocated_entry, . - relocated_entry

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
6:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 6b
    dsb     sy
    ret
.size probe_usb_send_wait, . - probe_usb_send_wait

.balign 8
.type probe_record, %object
probe_record:
    .ascii  "EPHINIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record

.balign 16
.type probe_ep1_trb, %object
probe_ep1_trb:
    .zero   0x10
.size probe_ep1_trb, . - probe_ep1_trb

.ltorg
.balign 8
relocated_end:
