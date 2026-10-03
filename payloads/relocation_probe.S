/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RELOCATION_ADDRESS       0x02025000

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    adr     x19, relocated_start
    adr     x20, relocated_end
    sub     x21, x20, x19
    ldr     x22, =PROBE_RELOCATION_ADDRESS

    adr     x23, probe_record
    str     x19, [x23, #0x18]
    str     x22, [x23, #0x20]
    str     x21, [x23, #0x28]
    mrs     x24, CurrentEL
    str     x24, [x23, #0x48]

    mov     x24, x19
    mov     x25, x22
1:
    ldr     x26, [x24], #8
    str     x26, [x25], #8
    cmp     x24, x20
    b.lo    1b
    dsb     sy

    /* Compare the full worker image before attempting to execute it. */
    mov     x24, x19
    mov     x25, x22
    mov     x26, #0
2:
    ldr     x27, [x24, x26]
    ldr     x28, [x25, x26]
    cmp     x27, x28
    b.ne    copy_failed
    add     x26, x26, #8
    cmp     x26, x21
    b.lo    2b

    adr     x23, probe_record
    ldr     x24, =0x21215950434c4552  /* "RELCPY!!" */
    str     x24, [x23]
    mov     x24, #1
    str     x24, [x23, #0x10]
    mov     x24, #-1
    str     x24, [x23, #0x30]
    mov     x0, x23
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

    dsb     sy
    ic      iallu
    dsb     sy
    isb

    adr     x24, relocated_entry
    sub     x24, x24, x19
    add     x24, x22, x24
    br      x24

copy_failed:
    adr     x23, probe_record
    ldr     x24, =0x214c4941464c4552  /* "RELFAIL!" */
    str     x24, [x23]
    mov     x24, #0x100
    str     x24, [x23, #0x10]
    str     x26, [x23, #0x30]
    str     x27, [x23, #0x38]
    str     x28, [x23, #0x40]
    mov     x0, x23
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
3:
    b       3b
.size payload_main, . - payload_main

.balign 16
relocated_start:
.type relocated_entry, %function
relocated_entry:
    adr     x19, probe_record
    ldr     x20, =0x21535341504c4552  /* "RELPASS!" */
    str     x20, [x19]
    mov     x20, #2
    str     x20, [x19, #0x10]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x48]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
4:
    b       4b
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
5:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 5b
    dsb     sy
    ret
.size probe_usb_send_wait, . - probe_usb_send_wait

.balign 8
.type probe_record, %object
probe_record:
    .ascii  "RELINIT!"
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

