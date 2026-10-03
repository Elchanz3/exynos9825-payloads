/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "dwc3_ep1.h"

#define PROBE_RECORD_SIZE 0x60

HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    adr     x9, probe_record

    mrs     x10, CurrentEL
    str     x10, [x9, #0x10]
    mrs     x10, SCR_EL3
    str     x10, [x9, #0x18]
    mrs     x10, SCTLR_EL3
    str     x10, [x9, #0x20]
    mrs     x10, TCR_EL3
    str     x10, [x9, #0x28]
    mrs     x10, TTBR0_EL3
    str     x10, [x9, #0x30]
    mrs     x10, MAIR_EL3
    str     x10, [x9, #0x38]
    mrs     x10, HCR_EL2
    str     x10, [x9, #0x40]
    mrs     x10, SCTLR_EL2
    str     x10, [x9, #0x48]
    mrs     x10, ID_AA64PFR0_EL1
    str     x10, [x9, #0x50]
    mrs     x10, VBAR_EL3
    str     x10, [x9, #0x58]

    mov     x0, x9
    mov     w1, #PROBE_RECORD_SIZE
    bl      s5e9825_usb_send_wait

1:
    b       1b

.size payload_main, . - payload_main

.section .data, "aw"
.balign 8
.type probe_record, %object
probe_record:
    .ascii  "NSP1EL3!"
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record
