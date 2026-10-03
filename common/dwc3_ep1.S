/* SPDX-License-Identifier: GPL-2.0-only */

#include "s5e9825.h"
#include "dwc3_ep1.h"

.section .text, "ax"

s5e9825_usb_send_wait:
    and     w1, w1, #0x00ffffff

    ldr     x2, =S5E9825_DWC3_EP1_IN_TRB
    mov     w3, #S5E9825_DWC3_TRB_CTRL_NORMAL

    /* TRB buffer low/high followed by size/control. */
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

1:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 1b

    dsb     sy
    ret

.size s5e9825_usb_send_wait, . - s5e9825_usb_send_wait
