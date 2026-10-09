/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RELOCATION_ADDRESS       0x02025000
#define SCTLR_I_BIT                    0x1000

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    /*
     * Copy a self-contained worker to fresh iRAM.
     * Do not perform IC maintenance.
     */
    adr     x19, relocated_start
    adr     x20, relocated_end
    ldr     x21, =PROBE_RELOCATION_ADDRESS
    mov     x22, x19
    mov     x23, x21
1:
    ldr     x24, [x22], #8
    str     x24, [x23], #8
    cmp     x22, x20
    b.lo    1b
    dsb     sy

    adr     x24, relocated_entry
    sub     x24, x24, x19
    add     x24, x21, x24
    br      x24
.size payload_main, . - payload_main


.balign 16
relocated_start:

.type relocated_entry, %function
relocated_entry:
    adr     x19, probe_record

    mrs     x20, CurrentEL
    str     x20, [x19, #0x18]

    mrs     x20, SCTLR_EL3
    str     x20, [x19, #0x20]

    ldr     x20, =PROBE_RELOCATION_ADDRESS
    str     x20, [x19, #0x30]

    /* ICDPRE!! */
    ldr     x20, =0x2121455250444349
    str     x20, [x19]
    str     xzr, [x19, #0x10]

    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      relocated_usb_send_wait

    /*
     * Clear only SCTLR_EL3.I.
     *
     * No IC IALLU / IVAU.
     * MMU and D-cache are left untouched.
     */
    dsb     sy
    mrs     x20, SCTLR_EL3
    mov     x21, #SCTLR_I_BIT
    bic     x22, x20, x21
    msr     SCTLR_EL3, x22
    isb

    /*
     * If we reach this point, instruction fetch continued
     * after disabling the EL3 I-cache.
     */
    adr     x19, probe_record

    mrs     x23, CurrentEL
    str     x23, [x19, #0x28]

    mrs     x23, SCTLR_EL3
    str     x23, [x19, #0x38]

    /* ICDPASS! */
    ldr     x24, =0x2153534150444349
    str     x24, [x19]

    mov     x24, #1
    str     x24, [x19, #0x10]

    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      relocated_usb_send_wait

2:
    b       2b
.size relocated_entry, . - relocated_entry


.type relocated_usb_send_wait, %function
relocated_usb_send_wait:
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

3:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 3b

    dsb     sy
    ret
.size relocated_usb_send_wait, . - relocated_usb_send_wait


.balign 8
.type probe_record, %object
probe_record:
    .ascii  "ICDINIT!"
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
