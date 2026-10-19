/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Entry trampoline for the full u-boot stage used by the UFS execution test.
 *
 * The previous diagnostic replaced all of u-boot and tried to send an EP1
 * record through the BootROM helper inherited from EUB. That channel is no
 * longer reliable at the BL2 -> u-boot boundary. This trampoline instead
 * leaves the complete engineering u-boot intact and lets u-boot initialize
 * its own Samsung Download USB stack.
 *
 * It is copied into the verified zero cave at u-boot offset 0x17ce00. The
 * installer replaces the entry instruction at offset 0 with a direct branch
 * here, and replaces the final self-branch below with a direct branch back to
 * the original entry at load+4.
 *
 * x16 and x17 are temporary registers in the AArch64 procedure-call standard.
 * The original code begins at load+4 and does not consume their entry values.
 */

#define PMU_INFORM0             0x15860800
#define PMU_STAGE_MARKER        0x31534255  /* "UBS1" in little endian */
#define PMU_OWNER_MARKER        0x314e574f  /* "OWN1" in little endian */

.section .text.entry, "ax"
.global _start
.type _start, %function
_start:
    movz    x16, #(PMU_INFORM0 & 0xffff)
    movk    x16, #(PMU_INFORM0 >> 16), lsl #16

    movz    w17, #(PMU_STAGE_MARKER & 0xffff)
    movk    w17, #(PMU_STAGE_MARKER >> 16), lsl #16
    str     w17, [x16, #0x00]

    movz    w17, #(PMU_OWNER_MARKER & 0xffff)
    movk    w17, #(PMU_OWNER_MARKER >> 16), lsl #16
    str     w17, [x16, #0x04]

    /* A zero MINFORM makes the attached USB cable select Download mode. */
    str     wzr, [x16, #0x08]
    dsb     sy
    isb

.global resume_branch
resume_branch:
    /* Patched by install_ubstage_download_marker.py. */
    b       resume_branch
.size _start, . - _start
