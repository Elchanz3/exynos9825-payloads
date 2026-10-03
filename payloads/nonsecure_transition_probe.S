/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "dwc3_ep1.h"

#define PROBE_RECORD_SIZE       0x60
#define CANDIDATE_NS_ENTRY      0xbfe80000
#define SCR_NS_AARCH64_ROUTED   0x040f
#define SPSR_EL2H_MASKED        0x03c9

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    adr     x19, probe_record
    mrs     x20, SCR_EL3
    str     x20, [x19, #0x38]
    mrs     x20, VBAR_EL3
    str     x20, [x19, #0x40]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x48]

    adr     x20, el3_vectors
    msr     VBAR_EL3, x20
    isb

    /* Checkpoint 0: the payload and private EL3 vectors are active. */
    ldr     x20, =0x212145525032534e  /* "NS2PRE!!" */
    str     x20, [x19]
    str     xzr, [x19, #0x10]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

    /* Phase 1: test whether the candidate DRAM address is writable in EL3. */
    mov     x20, #1
    str     x20, [x19, #0x10]

    ldr     x21, =CANDIDATE_NS_ENTRY
    adr     x22, ns_stage
    ldp     x23, x24, [x22]
    stp     x23, x24, [x21]
    dsb     sy

    ldp     x25, x26, [x21]
    cmp     x23, x25
    b.ne    copy_mismatch
    cmp     x24, x26
    b.ne    copy_mismatch

    /* Checkpoint 2: the candidate address accepted and retained the stub. */
    mov     x20, #2
    str     x20, [x19, #0x10]
    ldr     x20, =0x2159504f4332534e  /* "NS2COPY!" */
    str     x20, [x19]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

    /* Discard stale instruction-cache contents. */
    ic      iallu
    dsb     sy
    isb

    /* Checkpoint 3: all preparation before ERET completed. */
    mov     x20, #3
    str     x20, [x19, #0x10]
    ldr     x20, =0x215445524532534e  /* "NS2ERET!" */
    str     x20, [x19]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

    mov     x20, #SCR_NS_AARCH64_ROUTED
    msr     SCR_EL3, x20
    isb

    msr     ELR_EL3, x21
    mov     x20, #SPSR_EL2H_MASKED
    msr     SPSR_EL3, x20

    /* Sentinels must survive until the first lower-EL exception. */
    mov     x0, #0x7788
    movk    x0, #0x5566, lsl #16
    movk    x0, #0x3344, lsl #32
    movk    x0, #0x1122, lsl #48
    mov     x1, #0xff00
    movk    x1, #0xddee, lsl #16
    movk    x1, #0xbbcc, lsl #32
    movk    x1, #0x99aa, lsl #48

    dsb     sy
    isb
    eret

copy_mismatch:
    mov     x20, #0x100
    str     x20, [x19, #0x10]
    b       report_failure

.size payload_main, . - payload_main

/* Position-independent lower-EL stage copied to CANDIDATE_NS_ENTRY. */
.balign 8
ns_stage:
    smc     #0
1:
    b       1b
    nop
    nop

/* All exceptions are terminal and return one diagnostic record over USB. */
.type el3_exception, %function
el3_exception:
    adr     x9, probe_record
    str     x0, [x9, #0x50]
    str     x1, [x9, #0x58]

    mrs     x10, ESR_EL3
    str     x10, [x9, #0x18]
    mrs     x11, FAR_EL3
    str     x11, [x9, #0x20]
    mrs     x11, ELR_EL3
    str     x11, [x9, #0x28]
    mrs     x11, SPSR_EL3
    str     x11, [x9, #0x30]
    mrs     x11, CurrentEL
    str     x11, [x9, #0x48]

    ubfx    x11, x10, #26, #6
    cmp     x11, #0x17
    b.ne    report_failure

    /* SMC64 from the lower EL proves that the candidate code executed. */
    ldr     x10, =0x215353415032534e  /* "NS2PASS!" */
    str     x10, [x9]
    mov     x10, #4
    str     x10, [x9, #0x10]
    b       send_result

report_failure:
    adr     x9, probe_record
    ldr     x10, =0x214c49414632534e  /* "NS2FAIL!" */
    str     x10, [x9]

send_result:
    ldr     x10, [x9, #0x38]
    msr     SCR_EL3, x10
    ldr     x10, [x9, #0x40]
    msr     VBAR_EL3, x10
    dsb     sy
    isb

    mov     x0, x9
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

2:
    b       2b

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
    .ascii  "NS2INIT!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record
