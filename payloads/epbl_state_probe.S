/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"
#include "dwc3_ep1.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_STATE_BASE               0x02020000
#define PROBE_STATE_CHUNKS             4
#define PROBE_WORDS_PER_CHUNK          20

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

    /*
     * Snapshot the complete iRAM state window consumed by the Binary 9 EPBL.
     * No pointer from this window is called and no new MMIO block is touched.
     */
    ldr     x19, =PROBE_STATE_BASE
    adr     x20, probe_records
    mov     x21, #PROBE_STATE_CHUNKS

1:
    add     x22, x20, #0x10
    mov     x23, #PROBE_WORDS_PER_CHUNK
2:
    ldr     w24, [x19], #4
    str     w24, [x22], #4
    subs    x23, x23, #1
    b.ne    2b

    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

    add     x20, x20, #PROBE_RECORD_SIZE
    subs    x21, x21, #1
    b.ne    1b

3:
    b       3b

.size payload_main, . - payload_main

.section .data, "aw"
.balign 8
.type probe_records, %object
probe_records:
    .ascii  "EPS0IRAM"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10

    .ascii  "EPS1IRAM"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10

    .ascii  "EPS2IRAM"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10

    .ascii  "EPS3IRAM"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_records, . - probe_records
