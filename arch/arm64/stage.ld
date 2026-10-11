/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Link script for a replacement boot-chain stage, as opposed to a Houston
 * payload. Two differences from payload.ld: the stage runs from DRAM at an
 * address we have not established, so it is written position-independently and
 * the VMA here is irrelevant; and there is no DWC3 TRB to avoid, so no ceiling
 * assert. The only real limit is the stage slot itself, and the padding step
 * checks that.
 */

ENTRY(_start)

SECTIONS
{
    . = 0;

    .text :
    {
        KEEP(*(.text.entry))
        *(.text*)
        *(.rodata*)
        *(.data*)
    }

    __stage_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.gnu*)
        *(.bss*)
    }
}
