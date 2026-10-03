// SPDX-License-Identifier: GPL-2.0-only

.text
.global _start

_start:
    nop
    nop
    nop
    nop

    // First half: 0x00000000 - 0x0000ffff
    mov     w0, #0x0
    mov     w1, #0x10000
    bl      usb_send_wait

    // Second half: 0x00010000 - 0x0001ffff
    mov     w0, #0x10000
    mov     w1, #0x10000
    bl      usb_send_wait

1:
    b       1b


usb_send_wait:
    and     w1, w1, #0x00ffffff

    // Keep TRB pointer in x4.
    mov     x4, #0x4800
    movk    x4, #0x0202, lsl #16

    // Normal TRB control used by the validated tests.
    mov     w3, #0xc13

    // buffer low / buffer high
    stp     w0, wzr, [x4]

    // size / control
    stp     w1, w3, [x4, #8]

    dsb     sy

    // DEPCMDPAR1
    mov     x5, #0xc834
    movk    x5, #0x10c0, lsl #16
    str     w4, [x5]

    // DEPCMDPAR0
    mov     x5, #0xc838
    movk    x5, #0x10c0, lsl #16
    str     wzr, [x5]

    // STARTTRANSFER | CMDACT
    mov     x5, #0xc83c
    movk    x5, #0x10c0, lsl #16
    mov     w6, #0x406
    str     w6, [x5]

    dsb     sy

    // Wait until DWC3 releases ownership of the TRB.
2:
    ldr     w6, [x4, #0xc]
    tbnz    w6, #0, 2b

    dsb     sy
    ret
