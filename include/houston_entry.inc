/* SPDX-License-Identifier: GPL-2.0-only */

/* Houston overwrites the callback with RX_ADDRESS. Keep executable code at
 * RX_ADDRESS + 0x10, matching the layout validated on S5E9825.
 */
.macro HOUSTON_ENTRY target
    .section .text.entry, "ax"
    .global _start
    .type _start, %function
_start:
    nop
    nop
    nop
    nop
    b       \target
    .size _start, . - _start
.endm
