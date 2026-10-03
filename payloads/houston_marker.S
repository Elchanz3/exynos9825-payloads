/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "dwc3_ep1.h"

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    adr     x0, marker
    mov     w1, #8
    bl      s5e9825_usb_send_wait

1:
    b       1b

.size payload_main, . - payload_main

.section .rodata, "a"
.balign 8
marker:
    .ascii "HOUSTON!"
