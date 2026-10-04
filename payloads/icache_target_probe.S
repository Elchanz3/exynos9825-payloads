/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "dwc3_ep1.h"

#define PROBE_RECORD_SIZE       0x60
#define TARGET_ADDRESS          0x02024000
#define AFTER_SIGNATURE         0x21454e4f44544349

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    adr     x19, probe_record
    mrs     x20, VBAR_EL3
    str     x20, [x19, #0x38]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x40]
    mrs     x20, SCTLR_EL3
    str     x20, [x19, #0x48]

    adr     x20, el3_vectors
    msr     VBAR_EL3, x20
    isb

    ldr     x20, =TARGET_ADDRESS
    str     x20, [x19, #0x50]
    ldr     x20, =0x2121455250544349  /* "ICTPRE!!" */
    str     x20, [x19]
    str     xzr, [x19, #0x10]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

    /* Invalidate only the candidate target line, not the executing image. */
    ldr     x20, =TARGET_ADDRESS
    dsb     sy
    ic      ivau, x20
    dsb     sy
    isb

    adr     x19, probe_record
    ldr     x20, =AFTER_SIGNATURE
    str     x20, [x19, #0x58]
    ldr     x20, =0x2153534150544349  /* "ICTPASS!" */
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    b       send_result
.size payload_main, . - payload_main

.type el3_exception, %function
el3_exception:
    adr     x19, probe_record
    ldr     x20, =0x214c494146544349  /* "ICTFAIL!" */
    str     x20, [x19]
    mov     x20, #0x100
    str     x20, [x19, #0x10]

    mrs     x20, ESR_EL3
    str     x20, [x19, #0x18]
    mrs     x20, FAR_EL3
    str     x20, [x19, #0x20]
    mrs     x20, ELR_EL3
    str     x20, [x19, #0x28]
    mrs     x20, SPSR_EL3
    str     x20, [x19, #0x30]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x40]

send_result:
    ldr     x20, [x19, #0x38]
    msr     VBAR_EL3, x20
    dsb     sy
    isb

    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait
1:
    b       1b
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
    .ascii  "ICTINIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record
