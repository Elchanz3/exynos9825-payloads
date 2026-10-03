/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RX_DESTINATION           0x02030000
#define PROBE_EPBL_SIZE                0x3000

/* Binary 9 N975FXXS9HWHA EPBL. */
/* SHA-256: d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d */
#define PROBE_EPBL_FNV1A64             0xfdfb55e38228e523
#define PROBE_EPBL_HEADER0             0xb82c55e700000018
#define PROBE_EPBL_HEADER1             0x0000000000000000
#define PROBE_EPBL_LAST_QWORD          0x17b84398a0c70f76

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
    str     x21, [x20, #0x58]
    mov     x21, #PROBE_RX_DESTINATION
    str     x21, [x20, #0x20]
    mov     x21, #PROBE_EPBL_SIZE
    str     x21, [x20, #0x28]
    ldr     x21, =PROBE_EPBL_FNV1A64
    str     x21, [x20, #0x38]

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

    /* Configure and clear the bounded diagnostic receive area. */
    mov     w21, #PROBE_RX_DESTINATION
    str     w21, [x22, #0xc0]
    mov     w21, #PROBE_EPBL_SIZE
    str     w21, [x22, #0xc4]

    ldr     x21, =PROBE_RX_DESTINATION
    mov     x23, #PROBE_EPBL_SIZE
1:
    str     xzr, [x21], #8
    subs    x23, x23, #8
    b.ne    1b
    dsb     sy

    ldr     x16, =PROBE_ARM_RECEIVE
    blr     x16

    adr     x20, probe_record
    ldr     x21, =0x2121594452425045  /* "EPBRDY!!" */
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
    b.ne    receive_failed

    /* Hash every received byte before checking selected boundary words. */
    ldr     x21, =PROBE_RX_DESTINATION
    mov     x22, #PROBE_EPBL_SIZE
    ldr     x23, =0xcbf29ce484222325
    ldr     x24, =0x100000001b3
3:
    ldrb    w25, [x21], #1
    eor     x23, x23, x25
    mul     x23, x23, x24
    subs    x22, x22, #1
    b.ne    3b
    str     x23, [x19, #0x30]

    ldr     x24, =PROBE_EPBL_FNV1A64
    cmp     x23, x24
    b.ne    hash_failed

    ldr     x21, =PROBE_RX_DESTINATION
    ldp     x22, x23, [x21]
    str     x22, [x19, #0x40]
    str     x23, [x19, #0x48]
    ldr     x24, =PROBE_EPBL_HEADER0
    cmp     x22, x24
    b.ne    boundary_failed
    ldr     x24, =PROBE_EPBL_HEADER1
    cmp     x23, x24
    b.ne    boundary_failed

    add     x21, x21, #PROBE_EPBL_SIZE
    ldr     x22, [x21, #-8]
    str     x22, [x19, #0x50]
    ldr     x24, =PROBE_EPBL_LAST_QWORD
    cmp     x22, x24
    b.ne    boundary_failed

    ldr     x20, =0x2153534150425045  /* "EPBPASS!" */
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

boundary_failed:
    mov     x20, #0x102
    b       report_failure

cancel_command_failed:
    mov     x20, #0x200
    b       report_setup_failure

cancel_clear_failed:
    mov     x20, #0x201

report_setup_failure:
    adr     x19, probe_record

report_failure:
    ldr     x21, =0x214c494146425045  /* "EPBFAIL!" */
    str     x21, [x19]
    str     x20, [x19, #0x10]

report_result:
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

.section .data, "aw"
.balign 8
.type probe_record, %object
probe_record:
    .ascii  "EPBINIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record

.balign 16
.type probe_ep1_trb, %object
probe_ep1_trb:
    .zero   0x10
.size probe_ep1_trb, . - probe_ep1_trb
