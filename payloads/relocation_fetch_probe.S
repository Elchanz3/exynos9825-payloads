/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "dwc3_ep1.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RELOCATION_ADDRESS       0x02025000
#define PROBE_REACHED_SIGNATURE        0x2143455845584652

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    adr     x20, probe_record
    mrs     x21, VBAR_EL3
    str     x21, [x20, #0x38]
    ldr     x21, =PROBE_RELOCATION_ADDRESS
    str     x21, [x20, #0x40]
    mrs     x21, CurrentEL
    str     x21, [x20, #0x48]

    adr     x21, relocated_stub_end
    adr     x22, relocated_stub
    sub     x21, x21, x22
    str     x21, [x20, #0x58]

    adr     x21, el3_vectors
    msr     VBAR_EL3, x21
    isb

    ldr     x23, =PROBE_RELOCATION_ADDRESS
    ldr     x24, [x22]
    str     x24, [x23]
    dsb     sy
    ldr     x25, [x23]
    cmp     x24, x25
    b.ne    copy_failed

    /* Keep every address needed by the copied stub in a register. */
    adr     x19, relocated_return
    adr     x20, probe_record
    ldr     x21, =PROBE_REACHED_SIGNATURE

    ic      iallu
    dsb     sy
    isb
    br      x23

relocated_return:
    ldr     x22, [x20, #0x50]
    cmp     x22, x21
    b.ne    return_failed

    ldr     x22, =0x2153534150584652  /* "RFXPASS!" */
    str     x22, [x20]
    mov     x22, #1
    str     x22, [x20, #0x10]
    b       send_result

copy_failed:
    adr     x20, probe_record
    ldr     x21, =0x214c494146584652  /* "RFXFAIL!" */
    str     x21, [x20]
    mov     x21, #0x101
    str     x21, [x20, #0x10]
    str     x25, [x20, #0x50]
    b       send_result

return_failed:
    ldr     x22, =0x214c494146584652  /* "RFXFAIL!" */
    str     x22, [x20]
    mov     x22, #0x102
    str     x22, [x20, #0x10]

send_result:
    ldr     x22, [x20, #0x38]
    msr     VBAR_EL3, x22
    dsb     sy
    isb

    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait
1:
    b       1b
.size payload_main, . - payload_main

/*
 * This code is copied as one qword. It uses only addresses prepared in
 * registers, proving instruction fetch independently of relocated USB code.
 */
.balign 8
relocated_stub:
    str     x21, [x20, #0x50]
    br      x19
relocated_stub_end:

/* Every EL3 exception reports from the original Houston-linked image. */
.type el3_exception, %function
el3_exception:
    adr     x20, probe_record
    ldr     x21, =0x214c494146584652  /* "RFXFAIL!" */
    str     x21, [x20]
    mov     x21, #0x100
    str     x21, [x20, #0x10]

    mrs     x21, ESR_EL3
    str     x21, [x20, #0x18]
    mrs     x21, FAR_EL3
    str     x21, [x20, #0x20]
    mrs     x21, ELR_EL3
    str     x21, [x20, #0x28]
    mrs     x21, SPSR_EL3
    str     x21, [x20, #0x30]
    mrs     x21, CurrentEL
    str     x21, [x20, #0x48]
    b       send_result
.size el3_exception, . - el3_exception

.macro VECTOR_SLOT
    b       el3_exception
    .space  0x7c
.endm

.section .text.vectors, "ax"
.balign 0x800
.type el3_vectors, %object
el3_vectors:
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
    VECTOR_SLOT
.size el3_vectors, . - el3_vectors

.section .data, "aw"
.balign 8
.type probe_record, %object
probe_record:
    .ascii  "RFXINIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record

