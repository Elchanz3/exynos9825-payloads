/* SPDX-License-Identifier: GPL-2.0-only */

ENTRY(_start)

MEMORY
{
    payload (rwx) : ORIGIN = 0x02022000, LENGTH = 0x2800
}

PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = ORIGIN(payload);

    .text :
    {
        KEEP(*(.text.entry))
        *(.text*)
    } > payload :text

    .rodata :
    {
        *(.rodata*)
    } > payload :text

    .data :
    {
        *(.data*)
    } > payload :data

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
