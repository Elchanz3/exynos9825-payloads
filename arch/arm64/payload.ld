/* SPDX-License-Identifier: GPL-2.0-only */

ENTRY(_start)

MEMORY
{
    payload (rwx) : ORIGIN = 0x02022000, LENGTH = 0x2800
}

SECTIONS
{
    . = ORIGIN(payload);

    .text :
    {
        KEEP(*(.text.entry))
        *(.text*)
    } > payload

    .rodata :
    {
        *(.rodata*)
    } > payload

    .data :
    {
        *(.data*)
    } > payload

    __payload_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.gnu*)
    }

    ASSERT(__payload_end <= 0x02024800,
           "payload overlaps the confirmed DWC3 TRB")
}
