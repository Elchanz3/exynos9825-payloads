/* SPDX-License-Identifier: GPL-2.0-only */

#include "houston_entry.inc"
#include "s5e9825.h"

#define PROBE_RECORD_SIZE              0x60
#define PROBE_RELOCATION_ADDRESS       0x02025000
#define PROBE_EPBL_DESTINATION         0x02022000
#define PROBE_EPBL_SIZE                0x3000
#if defined(EPBL_BOOT_UFS) || defined(EPBL_KEY_STATE) || \
    defined(EPBL_BOOT_UFS_CHAIN) || defined(EPBL_KEY_DUMP)
/*
 * These paths make the relocated worker reach 0x02025868, past the usual
 * 0x02025800 vector slot, and the probe WRITES branch instructions into that
 * slot -- the two would overwrite each other. Push the vectors clear of the
 * worker. Both this and its +0x200 companion stay below 0x02026000, which is
 * where FWBL1 lives (PROBE_FWBL1_ENTRY 0x02026010), so the region is free.
 */
#define PROBE_EXCEPTION_VBAR           0x02025c00
#else
#define PROBE_EXCEPTION_VBAR           0x02025800
#endif
#define PROBE_DWC3_GEVNTCOUNT0         0x10c0c40c
#define PROBE_DWC3_DSTS                0x10c0c70c
#define PROBE_DWC3_DALEPENA            0x10c0c720
#define PROBE_DWC3_EP2_OUT_DEPCMD      0x10c0c84c

#if defined(EPBL_ABORT_CONTEXT_STAGED) || \
    defined(EPBL_COLD_CONTEXT_STAGED) || \
    defined(EPBL_FWBL1_BOUNDARY_STAGED)
#define EPBL_CONTEXT_STAGED
#endif

#if defined(EPBL_MMIO_TRAP_STAGED) || defined(EPBL_CONTEXT_STAGED)
#define EPBL_EXCEPTION_STAGED
#endif

#ifdef EPBL_FWBL1_BOUNDARY_STAGED
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPFINIT!"
#define PROBE_READY_MAGIC              0x2121594452465045
#define PROBE_HASH_MAGIC               0x2148534148465045
#define PROBE_PARSED_MAGIC             0x4553524150465045
#define PROBE_VERIFIED_MAGIC           0x5946524556465045
#define PROBE_POSTLOAD_MAGIC           0x2154534f50465045
#define PROBE_PASS_MAGIC               0x2153534150465045
#define PROBE_FAIL_MAGIC               0x214c494146465045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c49414656465045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c49414650465045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c49414646465045
#define PROBE_TRAP_MAGIC               0x2150415254465045
#elif defined(EPBL_COLD_CONTEXT_STAGED)
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPCINIT!"
#define PROBE_READY_MAGIC              0x2121594452435045
#define PROBE_HASH_MAGIC               0x2148534148435045
#define PROBE_PARSED_MAGIC             0x4553524150435045
#define PROBE_VERIFIED_MAGIC           0x5946524556435045
#define PROBE_POSTLOAD_MAGIC           0x2154534f50435045
#define PROBE_PASS_MAGIC               0x2153534150435045
#define PROBE_FAIL_MAGIC               0x214c494146435045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c49414656435045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c49414650435045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c49414646435045
#define PROBE_TRAP_MAGIC               0x2150415254435045
#define PROBE_DUMP_MAGIC               0x2121504d55445045
#ifndef PROBE_DUMP_BASE
#define PROBE_DUMP_BASE                0x02026000
#endif
#ifndef PROBE_DUMP_SIZE
#define PROBE_DUMP_SIZE                0x00013000
#endif
#define PROBE_FWBL1_DECRYPT_RET        0x020260cc
#define PROBE_FWBL1_DECRYPT_CONT       0x020260d8
#define PROBE_FWBL1_VERIFY_PATCH_SITE  0x0202a4ac
#define PROBE_FWBL1_VERIFY_PATCH_INSN  0x14000019
#elif defined(EPBL_ABORT_CONTEXT_STAGED)
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPAINIT!"
#define PROBE_READY_MAGIC              0x2121594452415045
#define PROBE_HASH_MAGIC               0x2148534148415045
#define PROBE_PARSED_MAGIC             0x4553524150415045
#define PROBE_VERIFIED_MAGIC           0x5946524556415045
#define PROBE_POSTLOAD_MAGIC           0x2154534f50415045
#define PROBE_PASS_MAGIC               0x2153534150415045
#define PROBE_FAIL_MAGIC               0x214c494146415045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c49414656415045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c49414650415045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c49414646415045
#define PROBE_TRAP_MAGIC               0x2150415254415045
#elif defined(EPBL_MMIO_TRAP_STAGED)
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPTINIT!"
#define PROBE_READY_MAGIC              0x2121594452545045
#define PROBE_HASH_MAGIC               0x2148534148545045
#define PROBE_PARSED_MAGIC             0x4553524150545045
#define PROBE_VERIFIED_MAGIC           0x5946524556545045
#define PROBE_POSTLOAD_MAGIC           0x2154534f50545045
#define PROBE_PASS_MAGIC               0x2153534150545045
#define PROBE_FAIL_MAGIC               0x214c494146545045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c49414656545045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c49414650545045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c49414646545045
#define PROBE_TRAP_MAGIC               0x2150415254545045
#elif defined(EPBL_ENTRY_STAGED)
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPEINIT!"
#define PROBE_READY_MAGIC              0x2121594452455045
#define PROBE_HASH_MAGIC               0x2148534148455045
#define PROBE_PARSED_MAGIC             0x4553524150455045
#define PROBE_VERIFIED_MAGIC           0x5946524556455045
#define PROBE_POSTLOAD_MAGIC           0x2154534f50455045
#define PROBE_PASS_MAGIC               0x2153534150455045
#define PROBE_FAIL_MAGIC               0x214c494146455045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c49414656455045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c49414650455045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c49414646455045
#elif defined(EPBL_MMIO_STAGED)
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPMINIT!"
#define PROBE_READY_MAGIC              0x21215944524d5045
#define PROBE_HASH_MAGIC               0x21485341484d5045
#define PROBE_PARSED_MAGIC             0x45535241504d5045
#define PROBE_VERIFIED_MAGIC           0x59465245564d5045
#define PROBE_POSTLOAD_MAGIC           0x2154534f504d5045
#define PROBE_PASS_MAGIC               0x21535341504d5045
#define PROBE_FAIL_MAGIC               0x214c4941464d5045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c494146564d5045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c494146504d5045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c494146464d5045
#elif defined(EPBL_DISPATCH_STAGED)
#define EPBL_ENTRY_PATH
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPDINIT!"
#define PROBE_READY_MAGIC              0x2121594452445045
#define PROBE_HASH_MAGIC               0x2148534148445045
#define PROBE_PARSED_MAGIC             0x4553524150445045
#define PROBE_VERIFIED_MAGIC           0x5946524556445045
#define PROBE_POSTLOAD_MAGIC           0x2154534f50445045
#define PROBE_PASS_MAGIC               0x2153534150445045
#define PROBE_FAIL_MAGIC               0x214c494146445045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c49414656445045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c49414650445045
#define PROBE_FINALIZE_FAIL_MAGIC      0x4c49414646445045
#elif defined(EPBL_POSTLOAD_STAGED)
#define EPBL_VERIFY_PATH
#define EPBL_POSTLOAD_PATH
#define PROBE_INIT_MAGIC               "EPLINIT!"
#define PROBE_READY_MAGIC              0x21215944524c5045
#define PROBE_HASH_MAGIC               0x21485341484c5045
#define PROBE_PARSED_MAGIC             0x45535241504c5045
#define PROBE_VERIFIED_MAGIC           0x59465245564c5045
#define PROBE_PASS_MAGIC               0x21535341504c5045
#define PROBE_FAIL_MAGIC               0x214c4941464c5045
#define PROBE_VERIFY_FAIL_MAGIC        0x4c494146564c5045
#define PROBE_POSTLOAD_FAIL_MAGIC      0x4c494146504c5045
#elif defined(EPBL_VERIFY_STAGED)
#define EPBL_VERIFY_PATH
#define PROBE_INIT_MAGIC               "EVSINIT!"
#define PROBE_READY_MAGIC              0x2121594452535645
#define PROBE_HASH_MAGIC               0x2148534148535645
#define PROBE_PARSED_MAGIC             0x4553524150535645
#define PROBE_PASS_MAGIC               0x2153534150535645
#define PROBE_FAIL_MAGIC               0x214c494146535645
#define PROBE_VERIFY_FAIL_MAGIC        0x214c494146565645
#elif defined(EPBL_HEADER_STAGED)
#define PROBE_INIT_MAGIC               "EHSINIT!"
#define PROBE_READY_MAGIC              0x2121594452534845
#define PROBE_HASH_MAGIC               0x2148534148534845
#define PROBE_PASS_MAGIC               0x2153534150534845
#define PROBE_FAIL_MAGIC               0x214c494146534845
#elif defined(EPBL_HEADER_NOIC)
#define PROBE_INIT_MAGIC               "EPNINIT!"
#define PROBE_RELOCATED_MAGIC          0x21214c45524e5045
#define PROBE_READY_MAGIC              0x21215944524e5045
#define PROBE_PASS_MAGIC               0x21535341504e5045
#define PROBE_FAIL_MAGIC               0x214c4941464e5045
#else
#define PROBE_INIT_MAGIC               "EPHINIT!"
#define PROBE_READY_MAGIC              0x2121594452485045
#define PROBE_PASS_MAGIC               0x2153534150485045
#define PROBE_FAIL_MAGIC               0x214c494146485045
#endif

/* Binary 9 N975FXXS9HWHA EPBL. */
/* SHA-256: d25e155bb032eebe43a832de9781bc6c88ee8f599b4888159ddedd6fde42511d */
#define PROBE_EPBL_FNV1A64             0xfdfb55e38228e523
#define PROBE_EPBL_CHECKSUM            0xb82c55e7

/* Derived from the hardware-matched S5E9825 BootROM dump. */
#define PROBE_ORIGINAL_EVENT_CALLBACK  0x00001b2c
#define PROBE_ARM_RECEIVE              0x00001174
#define PROBE_ENDPOINT_COMMAND         0x00001268
#define PROBE_CLEAR_TRB                0x000019e4
#define PROBE_POLL_EVENTS              0x00002af0
#define PROBE_ACK_EVENT_HELPER         0x00002fbc
#define PROBE_PARSE_BL1_HEADER         0x00017c54
#define PROBE_VERIFY_BL1               0x0000c9a0
#define PROBE_VERIFY_SELECTOR          0x00017334
#define PROBE_SECURITY_STATUS          0x1000b014
#define PROBE_BOOT_STATE               0x02020064
#define PROBE_VERIFY_STATUS            0x02020070
#define PROBE_POSTLOAD                 0x00005b58
#define PROBE_POSTLOAD_STATE           0x0202007c
#define PROBE_POSTLOAD_TIMING_START    0x02020084
#define PROBE_POSTLOAD_TIMING_END      0x02020088
#define PROBE_POSTLOAD_SECURITY        0x10001000
#define PROBE_ENTRY_TIMING             0x00018768
#define PROBE_SET_BOOT_FLAG            0x00016a10
#define PROBE_EPBL_BRANCH              0x0001c9a0
#define PROBE_EPBL_ENTRY               0x02022010
#define PROBE_EPBL_HOOK_SITE           0x02022018
#define PROBE_EPBL_ENTRY_INSN          0x14000002
#define PROBE_EPBL_HOOK_INSN           0x580002d4
#define PROBE_EPBL_MMIO_SITE           0x02022020
#define PROBE_EPBL_MMIO_INSN           0xd2800035
#define PROBE_EPBL_DISPATCH_STATE      0x02020128
#define PROBE_EPBL_DISPATCH_MMIO       0x15860990
#define PROBE_EPBL_COLD_SITE           0x02022054
#define PROBE_EPBL_COLD_INSN           0x14000369
#define PROBE_EPBL_COLD_TARGET         0x02022df8
#define PROBE_EPBL_WARM_SITE           0x0202206c
#define PROBE_EPBL_WARM_INSN           0xd61f0080
#define PROBE_EPBL_DISPATCH_LITERAL    0x02022098
#define PROBE_EPBL_DISPATCH_POINTER    0x02020128
#define PROBE_FWBL1_ENTRY              0x02026010
#define PROBE_FWBL1_NOIC_CONTINUE      0x02026034
#define PROBE_FWBL1_FIRST_QWORD        0x0000000000000098
#define PROBE_FWBL1_SECOND_QWORD       0x0000000068656164
#define PROBE_ENTRY_TIMING_WORD        0x0202008c
#define PROBE_BOOT_FLAGS               0x02020070
#define PROBE_ENTRY_FLAG               0x00800000

#ifdef EPBL_KEY_STATE
/*
 * Read-only probe for the BootROM key selector's inputs and its result.
 *
 * The ROM runs the selector at 0x5780 from its boot function at 0x1dc, well
 * before our payload gets control, so iRAM 0x0202006c already holds whichever
 * key pointer it chose. Reading that, plus the two security-status registers
 * the selector tests, identifies which key the chip is actually rooted on.
 *
 * Selector logic (0x5780), where SEC0 = 0x10001000 and SEC1 = 0x1000b014:
 *   A SEC0.8  B SEC1.31  C SEC0.1  D SEC0.3  E SEC0.0  F SEC1.0  G SEC1.3
 *   A==0 && B==1        -> ROM table 0x1fae0
 *   C==1 && D==0        -> ROM table 0x1fae0
 *   E==1                -> KEY  0x10003000
 *   F==1 && G==0        -> ROM table 0x1fae0
 *   else                -> KEY2 0x10003020
 * E is tested before F/G, so if E is USE_KEY then a device with USE_KEY=1 can
 * never reach KEY2 -- which would block fusing KEY2 entirely. This probe is
 * how we find out, and it only reads.
 */
#define PROBE_SEC_STATUS0              0x10001000
#define PROBE_SEC_STATUS1              0x1000b014
#define PROBE_KEY_POINTER              0x0202006c
#define PROBE_OTP_KEY_SLOT             0x10003000
#define PROBE_OTP_KEY2_SLOT            0x10003020
#define PROBE_KEY_STATE_MAGIC          0x2145544154534b45  /* "EKSTATE!" */
#endif

#ifdef EPBL_KEY_DUMP
/*
 * Dump both 32-byte OTP key slots, so a programmed KEY2 can be compared
 * byte-for-byte against get_efuse_data(). Read-only.
 */
#define PROBE_OTP_KEY_SLOT             0x10003000
#define PROBE_OTP_KEY2_SLOT            0x10003020
#define PROBE_KEY_DUMP_MAGIC           0x21214d554458454b  /* "KEXDUM!!" */
#endif

#if defined(EPBL_BOOT_UFS) || defined(EPBL_BOOT_UFS_CHAIN)
/*
 * Load the next stage from storage instead of over USB.
 *
 * The ROM's top-level boot function at 0x160 loads with 0xcc68 and then
 * verifies with 0x5b58 (our PROBE_POSTLOAD). 0xcc68 reads the boot-device code
 * by calling 0x17f14, then dispatches:
 *     1 -> 0x13554   storage (UFS)        <- what we want
 *     2 -> 0x10bf4   3 -> 0x11448
 *     4 -> 0x17654   USB                  <- the live value in EUB
 *     5 -> 0xcd34    6 -> 0xcd40   7 -> 0x574c
 * The boot-state word at 0x02020064 is
 *     0xCB000000 | (A << 8) | (device << 4) | index
 * so forcing bits 7:4 to 1 selects storage. Observed live in EUB:
 * 0xcb000041, i.e. device 4 = USB.
 *
 * 0x17f14(w0=index) sets the low nibble to w0 and returns the nibble at that
 * index, i.e. the device code -- used here to read the selection back.
 */
#define PROBE_LOAD_IMAGE               0x0000cc68
#define PROBE_BOOT_DEVICE              0x00017f14
#define PROBE_BOOT_UFS_KEY_POINTER     0x0202006c
/*
 * PMU register holding sboot's packed reboot-reason bytes. sboot's
 * boot-mode decision at u-boot 0x3280 reads byte 1 of this through
 * 0x819c(1) and compares it: 0x4e 'N' -> "intentional normal booting"
 * (return 1), 0x70 'p' -> return 0. Read it here before deciding what to
 * write, rather than guessing which byte already holds what.
 */
#define PROBE_PMU_REBOOT_REASON        0x15860808
#define PROBE_BOOT_UFS_LOADED_MAGIC    0x2144414f4c534655  /* "UFSLOAD!" */
#define PROBE_BOOT_UFS_META_MAGIC      0x214154454d534655  /* "UFSMETA!" */
/*
 * iRAM metadata the BL1 header parse normally fills in. Reading these after a
 * storage load shows whether 0xcc68 populates them the way the USB path's
 * header parse (0x17c54) does -- the UFS path skips that parse, so if these are
 * stale the chain inherits wrong metadata.
 *   0x02020030 BL1 size            0x02020034 BL1 checksum
 *   0x02020070 status register 0    0x02020074 status register 1
 *   0x0202007c SBC information
 *   0x02020120 EPBL size            0x02020124 EPBL expected hash
 *   0x02020128 EPBL load address
 */
#define PROBE_IRAM_BL1_SIZE            0x02020030
#define PROBE_IRAM_STATUS_REG0         0x02020070
#define PROBE_IRAM_EPBL_SIZE           0x02020120
#define PROBE_BOOT_UFS_PASS_MAGIC      0x2153534150555045  /* "EPUPASS!" */
#define PROBE_BOOT_UFS_FAIL_MAGIC      0x214c494146555045  /* "EPUFAIL!" */
#endif

#ifdef EPBL_COLD_CONTEXT_STAGED
    /*
     * The I-cache still holds every line this stager executed from
     * 0x02022000 after the received EPBL overwrites it, and IC maintenance
     * hangs on this SoC. The old stager left `br x12` cached at 0x0202205c,
     * exactly where the EPBL dispatch helper lives, which produced the
     * branch to 0x17. Run the whole stager inside the first 64-byte line,
     * which only covers the EPBL entry this path bypasses, and mirror the
     * authentic EPBL bytes in the next two lines so a prefetched line is
     * identical to the received image.
     */
    .section .text.entry, "ax"
    .global _start
    .type _start, %function
_start:
    nop
    nop
    nop
    nop
    msr     daifset, #0xf
    adr     x9, relocated_start
    adr     x10, relocated_end
    movz    x11, #(PROBE_RELOCATION_ADDRESS & 0xffff)
    movk    x11, #(PROBE_RELOCATION_ADDRESS >> 16), lsl #16
    mov     x12, x11
1:
    ldr     x13, [x9], #8
    str     x13, [x12], #8
    cmp     x9, x10
    b.lo    1b
    add     x12, x11, #(relocated_entry - relocated_start)
    br      x12
    .size _start, . - _start
    .if . - _start != 0x40
    .error "cold stager must end exactly at the first cache line"
    .endif

    /* Authenticated EPBL bytes 0x40..0xbf (pinned SHA-256 d25e155b...). */
epbl_mirror:
    .word   0xd2800002, 0xeb01007f, 0x54000060, 0xb8004462
    .word   0x17fffffd, 0x14000369, 0x14000000, 0x580001e4
    .word   0xb9400084, 0x180001e5, 0x0b050084, 0xd61f0080
    .word   0x15860990, 0x00000000, 0x02023aac, 0x00000000
    .word   0x02023aac, 0x00000000, 0x02023aac, 0x00000000
    .word   0x02023aac, 0x00000000, 0x02020128, 0x00000000
    .word   0x00000010, 0xd10083ff, 0xf9000bfe, 0xa90077f3
    .word   0x910023fd, 0xaa0003f3, 0x2a0103e0, 0xaa0203e1
    .if . - _start != 0xc0
    .error "EPBL mirror must cover 0x40..0xbf"
    .endif

.section .text, "ax"
#else
HOUSTON_ENTRY payload_main

.section .text, "ax"
.type payload_main, %function
payload_main:
    msr     daifset, #0xf

    /* Keep the triggering event argument while moving the complete worker. */
    mov     x19, x0
    adr     x9, relocated_start
    adr     x10, relocated_end
    ldr     x11, =PROBE_RELOCATION_ADDRESS
    mov     x12, x11
1:
    ldr     x13, [x9], #8
    str     x13, [x12], #8
    cmp     x9, x10
    b.lo    1b

#if !defined(EPBL_HEADER_NOIC) && !defined(EPBL_HEADER_STAGED) && \
    !defined(EPBL_VERIFY_PATH)
    /* Preserve the original diagnostic for comparison with its hardware run. */
    dsb     sy
    ic      iallu
    dsb     sy
    isb
#endif

    adr     x12, relocated_entry
    adr     x13, relocated_start
    sub     x12, x12, x13
    add     x12, x11, x12
    mov     x0, x19
    br      x12
.size payload_main, . - payload_main
#endif

.balign 16
relocated_start:
#ifdef EPBL_EXCEPTION_STAGED
#ifndef EPBL_CONTEXT_STAGED
.type el3_vectors, %object
el3_vectors:
    /* Synchronous exceptions from CurrentEL with SP0 or SPx. */
    b       el3_exception
    .space  0x1fc
    b       el3_exception
.size el3_vectors, . - el3_vectors
#endif

.balign 8
saved_vbar_el3:
    .quad   0

.balign 16
#endif
.type relocated_entry, %function
relocated_entry:
    mov     x19, x0
    adr     x20, probe_record
    ldr     x21, =PROBE_RELOCATION_ADDRESS
    str     x21, [x20, #0x20]
    ldr     x21, =PROBE_EPBL_DESTINATION
    str     x21, [x20, #0x28]

#ifdef EPBL_EXCEPTION_STAGED
    mrs     x21, VBAR_EL3
    adr     x22, saved_vbar_el3
    str     x21, [x22]
#endif

#ifdef EPBL_HEADER_NOIC
    mrs     x21, CurrentEL
    str     x21, [x20, #0x58]
    ldr     x21, =PROBE_RELOCATED_MAGIC
    str     x21, [x20]
    str     xzr, [x20, #0x10]
    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
#endif

    /* Complete the event whose callback Houston replaced. */
    ldr     x22, =S5E9825_USB_STATE_POINTER
#ifdef EPBL_CONTEXT_STAGED
    /* Preserve the software event index before retiring the trigger event. */
    ldr     w21, [x22]
    str     x21, [x20, #0x20]
#endif
    ldr     x21, =PROBE_ORIGINAL_EVENT_CALLBACK
    str     x21, [x22, #0x10]
    dsb     sy
    mov     x0, x19
    blr     x21
    ldr     w21, [x22]
    add     w21, w21, #1
    and     w21, w21, #0x1f
    str     w21, [x22]
    mov     w0, #1
    ldr     x16, =PROBE_ACK_EVENT_HELPER
    blr     x16
    dsb     sy

    /* Retire and clear the stale logical EP2 OUT transfer. */
    mov     w0, #2
    mov     w1, #8
    mov     w2, #0
    mov     w3, #0
    ldr     x16, =PROBE_ENDPOINT_COMMAND
    blr     x16
    adr     x20, probe_record
    str     x0, [x20, #0x18]
    cbz     w0, cancel_command_failed

    mov     w0, #2
    ldr     x16, =PROBE_CLEAR_TRB
    blr     x16
    dsb     sy

    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w23, [x22, #0x2c]
    add     x23, x23, #0xa0
    ldr     w24, [x23]
    ldr     w25, [x23, #8]
    orr     w24, w24, w25
    ldr     w25, [x23, #0xc]
    orr     w24, w24, w25
    cbnz    w24, cancel_clear_failed

#ifdef EPBL_KEY_STATE
    b       key_state_path
#endif

#ifdef EPBL_BOOT_UFS_CHAIN
    b       boot_ufs_chain_path
#endif

#ifdef EPBL_KEY_DUMP
    b       key_dump_path
#endif

#ifdef EPBL_BOOT_UFS
    /*
     * Branch out to the storage-load path. The body lives past the
     * `.org relocated_start + 0x600` slot below, so this variant does not
     * disturb the proven layout the other variants depend on.
     */
    b       boot_ufs_path
#endif


    /* Clear and arm the stock BootROM EPBL destination. */
    ldr     w21, =PROBE_EPBL_DESTINATION
    str     w21, [x22, #0xc0]
    mov     w21, #PROBE_EPBL_SIZE
    str     w21, [x22, #0xc4]

    ldr     x21, =PROBE_EPBL_DESTINATION
    mov     x23, #PROBE_EPBL_SIZE
2:
    str     xzr, [x21], #8
    subs    x23, x23, #8
    b.ne    2b
    dsb     sy

#ifdef EPBL_CONTEXT_STAGED
    mov     w27, #8
arm_receive_attempt:
#endif
    ldr     x16, =PROBE_ARM_RECEIVE
    blr     x16

#ifdef EPBL_CONTEXT_STAGED
    /*
     * STARTTRANSFER is issued with command-completion notification enabled.
     * DEPCMD.CMDACT can clear before that event reaches GEVNTCOUNT0.  The
     * hardware runs which accepted the following OUT transfer all exposed
     * the four-byte event here; announcing readiness earlier left the host
     * write queued until the BootROM timeout.
     */
    ldr     x23, =PROBE_DWC3_GEVNTCOUNT0
    mrs     x24, CNTFRQ_EL0
    mov     x25, #100
    udiv    x24, x24, x25
    mrs     x25, CNTPCT_EL0
    add     x24, x25, x24
wait_for_arm_event:
    ldr     w21, [x23]
    cbnz    w21, arm_event_ready
    mrs     x25, CNTPCT_EL0
    cmp     x25, x24
    b.lo    wait_for_arm_event

    subs    w27, w27, #1
    b.eq    arm_event_timeout

    /* Retire the inactive arm before allocating a replacement resource. */
    mov     w0, #2
    mov     w1, #8
    mov     w2, #0
    mov     w3, #0
    ldr     x16, =PROBE_ENDPOINT_COMMAND
    blr     x16
    adr     x20, probe_record
    str     x0, [x20, #0x18]
    cbz     w0, cancel_command_failed

    /* Let late STARTTRANSFER and ENDTRANSFER events settle, then drain both. */
    ldr     x23, =PROBE_DWC3_GEVNTCOUNT0
    mrs     x24, CNTFRQ_EL0
    mov     x25, #100
    udiv    x24, x24, x25
    mrs     x25, CNTPCT_EL0
    add     x24, x25, x24
wait_for_cancel_event:
    mrs     x25, CNTPCT_EL0
    cmp     x25, x24
    b.lo    wait_for_cancel_event
    ldr     w21, [x23]
    cbz     w21, clear_retry_trb
    str     w21, [x23]
    dsb     sy

clear_retry_trb:
    mov     w0, #2
    ldr     x16, =PROBE_CLEAR_TRB
    blr     x16
    dsb     sy

    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w23, [x22, #0x2c]
    add     x23, x23, #0xa0
    ldr     w24, [x23]
    ldr     w25, [x23, #8]
    orr     w24, w24, w25
    ldr     w25, [x23, #0xc]
    orr     w24, w24, w25
    cbnz    w24, cancel_clear_failed

    ldr     w21, =PROBE_EPBL_DESTINATION
    str     w21, [x22, #0xc0]
    mov     w21, #PROBE_EPBL_SIZE
    str     w21, [x22, #0xc4]
    dsb     sy
    b       arm_receive_attempt

arm_event_timeout:
    mov     x20, #0x202
    b       report_setup_failure
arm_event_ready:
#endif

    adr     x20, probe_record
    ldr     x21, =PROBE_READY_MAGIC
    str     x21, [x20]
#ifdef EPBL_CONTEXT_STAGED
    /* Distinguish a prepared TRB from an active DWC3 transfer resource. */
    str     x0, [x20, #0x10]
    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w21, [x22]
    str     x21, [x20, #0x28]
    /* Endpoint state starts at +0x38 with a 0x28-byte logical-EP stride. */
    ldr     w21, [x22, #0x88]
    str     x21, [x20, #0x30]

    ldr     x23, =PROBE_DWC3_GEVNTCOUNT0
    ldr     w21, [x23]
    str     x21, [x20, #0x38]

    ldr     x23, =PROBE_DWC3_DSTS
    ldr     w21, [x23]
    str     x21, [x20, #0x40]

    ldr     x23, =PROBE_DWC3_DALEPENA
    ldr     w21, [x23]
    str     x21, [x20, #0x48]

    ldr     x23, =PROBE_DWC3_EP2_OUT_DEPCMD
    ldr     w21, [x23]
    str     x21, [x20, #0x50]

    ldr     w23, [x22, #0x2c]
    add     x23, x23, #0xa0
    ldr     w21, [x23, #0xc]
    str     x21, [x20, #0x58]
#endif
    mov     x0, x20
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

    ldr     x22, =S5E9825_USB_STATE_POINTER
3:
    ldr     x16, =PROBE_POLL_EVENTS
    blr     x16
    ldrb    w20, [x22, #0xbc]
    cbz     w20, 3b

    adr     x19, probe_record
    cmp     w20, #1
    b.ne    receive_failed

#ifndef EPBL_CONTEXT_STAGED
    /* Validate the exact raw EPBL before allowing BootROM to mutate word 1. */
    ldr     x21, =PROBE_EPBL_DESTINATION
    mov     x22, #PROBE_EPBL_SIZE
    ldr     x23, =0xcbf29ce484222325
    ldr     x24, =0x100000001b3
4:
    ldrb    w25, [x21], #1
    eor     x23, x23, x25
    mul     x23, x23, x24
    subs    x22, x22, #1
    b.ne    4b
    str     x23, [x19, #0x30]

    ldr     x24, =PROBE_EPBL_FNV1A64
    cmp     x23, x24
    b.ne    hash_failed
#endif

#if defined(EPBL_HEADER_STAGED) || \
    (defined(EPBL_VERIFY_PATH) && !defined(EPBL_ENTRY_PATH))
    mrs     x25, CurrentEL
    str     x25, [x19, #0x58]
    ldr     x25, =PROBE_HASH_MAGIC
    str     x25, [x19]
    str     xzr, [x19, #0x10]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
#endif

epbl_loaded:
    /* Use the matched BootROM routine that parses the BL1 block header. */
    ldr     x16, =PROBE_PARSE_BL1_HEADER
    blr     x16
#ifndef EPBL_ENTRY_PATH
    str     x0, [x19, #0x38]
#endif
    cmp     w0, #1
    b.ne    parser_failed

#ifndef EPBL_CONTEXT_STAGED
    ldr     x21, =0x02020030
    ldr     w22, [x21]
    ldr     w23, [x21, #4]
#ifndef EPBL_ENTRY_PATH
    str     x22, [x19, #0x40]
    str     x23, [x19, #0x48]
#endif
    ldr     x24, =PROBE_EPBL_DESTINATION
    ldr     x25, [x24]
#ifndef EPBL_ENTRY_PATH
    str     x25, [x19, #0x50]
    mrs     x25, CurrentEL
    str     x25, [x19, #0x58]
#endif

    cmp     w22, #PROBE_EPBL_SIZE
    b.ne    parsed_state_failed
    ldr     w24, =PROBE_EPBL_CHECKSUM
    cmp     w23, w24
    b.ne    parsed_state_failed
    ldr     x24, =0x0000000000000018
#ifndef EPBL_ENTRY_PATH
    ldr     x25, [x19, #0x50]
#endif
    cmp     x25, x24
    b.ne    parsed_state_failed
#endif

#ifdef EPBL_VERIFY_PATH
#ifndef EPBL_ENTRY_PATH
    /* Bound the next hardware step after the matched parser has passed. */
    ldr     x20, =PROBE_PARSED_MAGIC
    str     x20, [x19]
    str     xzr, [x19, #0x10]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
#endif

    /* Snapshot the branch selector and volatile BootROM verification state. */
#ifndef EPBL_ENTRY_PATH
    ldr     x20, =PROBE_SECURITY_STATUS
    ldr     w21, [x20]
#endif
    ldr     x16, =PROBE_VERIFY_SELECTOR
    blr     x16
#ifndef EPBL_ENTRY_PATH
    mov     w22, w0
    ldr     x20, =PROBE_BOOT_STATE
    ldr     w23, [x20]
    ldr     x20, =PROBE_VERIFY_STATUS
    ldr     x24, [x20]
#endif

    ldr     x16, =PROBE_VERIFY_BL1
    blr     x16
    mov     w25, w0

#ifndef EPBL_ENTRY_PATH
    adr     x19, probe_record
    ldr     x20, =PROBE_VERIFY_STATUS
    ldr     x26, [x20]
    ldr     x20, =0x02020030
    ldr     w27, [x20]
    ldr     w0, [x20, #4]
    mrs     x28, CurrentEL

    str     x25, [x19, #0x18]
    str     x21, [x19, #0x20]
    str     x22, [x19, #0x28]
    str     x23, [x19, #0x30]
    str     x24, [x19, #0x38]
    str     x26, [x19, #0x40]
    str     x27, [x19, #0x48]
    str     x0, [x19, #0x50]
    str     x28, [x19, #0x58]
#endif

    cmp     w25, #1
    b.ne    verifier_failed

epbl_verified:
#ifdef EPBL_POSTLOAD_PATH
#ifndef EPBL_ENTRY_PATH
    /* Snapshot the exact stock boundary before its post-load setup routine. */
    ldr     x20, =PROBE_VERIFIED_MAGIC
    str     x20, [x19]
    str     xzr, [x19, #0x10]
    str     xzr, [x19, #0x18]
    ldr     x20, =PROBE_POSTLOAD_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x20]
    str     x21, [x19, #0x28]
    ldr     x20, =PROBE_POSTLOAD_TIMING_START
    ldr     w22, [x20]
    str     x22, [x19, #0x30]
    ldr     x20, =PROBE_POSTLOAD_TIMING_END
    ldr     w23, [x20]
    str     x23, [x19, #0x38]
    ldr     x20, =PROBE_POSTLOAD_SECURITY
    ldr     w24, [x20]
    str     x24, [x19, #0x40]
    ldr     x20, =0x02020030
    ldr     w26, [x20]
    ldr     w27, [x20, #4]
    str     x26, [x19, #0x48]
    str     x27, [x19, #0x50]
    mrs     x28, CurrentEL
    str     x28, [x19, #0x58]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
#endif

#ifdef EPBL_CUSTOM_KEY
    /*
     * Custom secure-boot key, non-destructive. 0x5b58 below calls the BootROM
     * BL1 verifier at 0x599c, which reads PTR_SECUREBOOT_KEY from iRAM
     * 0x0202006c and verifies the loaded EPBL against the 32-byte key it
     * points at (0x599c: bl 0x5760 getter; ldr w1,[x0,#20] key_index;
     * mov w2,#0x20; bl 0xc1f8). Normally the BootROM's own selector (0x5780)
     * has pointed it at the ROM key table (0x0001fae0, indexed by key_index
     * with stride 32) or at a fused OTP slot (KEY 0x10003000 / KEY2
     * 0x10003020), so an EPBL signed with our key is rejected -- that is the
     * status 0x105 postload_failed we observed.
     *
     * The verifier skips the table indexing when the pointer is outside the
     * ROM (`and w0, ptr, #0xfffe0000` non-zero), so pointing it at our key
     * inside this payload (iRAM, 0x0202xxxx) makes it a single direct key.
     * This REDIRECTS verification at our key rather than disabling it, and
     * touches iRAM only, so it is fully reversible on reboot.
     *
     * Write it as late as possible -- here, immediately before the verifier --
     * so the BootROM selector cannot overwrite the pointer afterwards.
     */
    adr     x4, custom_boot_key
    movz    x6, #0x006c
    movk    x6, #0x0202, lsl #16        /* PTR_SECUREBOOT_KEY = 0x0202006c */
    str     w4, [x6]
    dsb     sy
#endif

    /* Match the EUB main path: the mode selector passed one to 0x5b58. */
    mov     w0, #1
    ldr     x16, =PROBE_POSTLOAD
    blr     x16
    mov     w25, w0

#ifndef EPBL_ENTRY_PATH
    adr     x19, probe_record
    str     x25, [x19, #0x18]
    ldr     x20, =PROBE_POSTLOAD_STATE
    ldr     w22, [x20]
    str     x22, [x19, #0x28]
    ldr     x20, =PROBE_POSTLOAD_TIMING_START
    ldr     w22, [x20]
    str     x22, [x19, #0x30]
    ldr     x20, =PROBE_POSTLOAD_TIMING_END
    ldr     w23, [x20]
    str     x23, [x19, #0x38]
    ldr     x20, =PROBE_POSTLOAD_SECURITY
    ldr     w24, [x20]
    str     x24, [x19, #0x40]
    ldr     x20, =0x02020030
    ldr     w26, [x20]
    ldr     w27, [x20, #4]
    str     x26, [x19, #0x48]
    str     x27, [x19, #0x50]
    mrs     x28, CurrentEL
    str     x28, [x19, #0x58]
#elif !defined(EPBL_CONTEXT_STAGED)
    ldr     x20, =0x02020030
    ldr     w26, [x20]
    ldr     w27, [x20, #4]
#endif

    cmp     w25, #1
    b.ne    postload_failed
#ifndef EPBL_CONTEXT_STAGED
    cmp     w26, #PROBE_EPBL_SIZE
    b.ne    postload_failed
    ldr     w20, =PROBE_EPBL_CHECKSUM
    cmp     w27, w20
    b.ne    postload_failed
#endif

#ifdef EPBL_ENTRY_PATH
    /* Complete the two stock calls immediately before the EPBL branch. */
    ldr     w0, =PROBE_ENTRY_TIMING_WORD
    ldr     x16, =PROBE_ENTRY_TIMING
    blr     x16
    mov     w0, #0
    ldr     w1, =PROBE_ENTRY_FLAG
    ldr     x16, =PROBE_SET_BOOT_FLAG
    blr     x16

#ifndef EPBL_CONTEXT_STAGED
    /* Validate the authentic entry prefix before installing a later hook. */
    ldr     x20, =PROBE_EPBL_ENTRY
    ldr     w21, [x20]
    ldr     x22, =PROBE_EPBL_HOOK_SITE
    ldr     w23, [x22]
    ldr     w24, =PROBE_EPBL_ENTRY_INSN
    cmp     w21, w24
    b.ne    finalize_failed
    ldr     w24, =PROBE_EPBL_HOOK_INSN
    cmp     w23, w24
    b.ne    finalize_failed

#if defined(EPBL_MMIO_STAGED) || defined(EPBL_MMIO_TRAP_STAGED)
    /* Stop after the authentic MMIO read and before its comparison setup. */
    ldr     x22, =PROBE_EPBL_MMIO_SITE
    ldr     w23, [x22]
    ldr     w24, =PROBE_EPBL_MMIO_INSN
    cmp     w23, w24
    b.ne    finalize_failed
    adr     x24, epbl_mmio_hook
    sub     x24, x24, x22
    asr     x24, x24, #2
    and     w24, w24, #0x03ffffff
    ldr     w26, =0x14000000
    orr     w24, w24, w26
    str     w24, [x22]
#elif defined(EPBL_DISPATCH_STAGED)
    /* Stop at either side of the first EPBL dispatch decision. */
    ldr     x22, =PROBE_EPBL_COLD_SITE
    ldr     w23, [x22]
    ldr     w24, =PROBE_EPBL_COLD_INSN
    cmp     w23, w24
    b.ne    finalize_failed
    adr     x24, epbl_cold_dispatch_hook
    sub     x24, x24, x22
    asr     x24, x24, #2
    and     w24, w24, #0x03ffffff
    ldr     w26, =0x14000000
    orr     w24, w24, w26
    str     w24, [x22]

    ldr     x22, =PROBE_EPBL_WARM_SITE
    ldr     w23, [x22]
    ldr     w24, =PROBE_EPBL_WARM_INSN
    cmp     w23, w24
    b.ne    finalize_failed
    adr     x24, epbl_warm_dispatch_hook
    sub     x24, x24, x22
    asr     x24, x24, #2
    and     w24, w24, #0x03ffffff
    ldr     w26, =0x14000000
    orr     w24, w24, w26
    str     w24, [x22]
#else
    /* Stop on the second executed instruction for the entry-only probe. */
    adr     x24, epbl_entry_hook
    sub     x24, x24, x22
    asr     x24, x24, #2
    and     w24, w24, #0x03ffffff
    ldr     w26, =0x14000000
    orr     w24, w24, w26
    str     w24, [x22]
#endif
    dsb     sy
    isb
#ifndef EPBL_DISPATCH_STAGED
    ldr     w24, [x22]
#endif

    ldr     x20, =PROBE_BOOT_FLAGS
    ldr     w22, [x20]
    tst     w22, #PROBE_ENTRY_FLAG
    b.eq    finalize_failed
#endif

#if defined(EPBL_COLD_CONTEXT_STAGED) || \
    defined(EPBL_FWBL1_BOUNDARY_STAGED)
    /*
     * Keep the original final dispatch instructions intact. Their cache line
     * was already fetched before this worker regains control. Instead, point
     * the dispatch literal at a private 32-bit target word. The stock helper
     * still loads that word, adds the 16-byte container header, and branches.
     */
    ldr     x22, =PROBE_EPBL_DISPATCH_LITERAL
    ldr     x23, [x22]
    ldr     x24, =PROBE_EPBL_DISPATCH_POINTER
    cmp     x23, x24
    b.ne    finalize_failed

#ifdef EPBL_FWBL1_BOUNDARY_STAGED
    adr     x24, epbl_fwbl1_boundary_hook
    sub     w24, w24, #0x10
#else
    /* Let the stock helper add the container header and enter the shim. */
    adr     x24, fwbl1_noic_entry
    sub     w24, w24, #0x10
#endif
    adr     x25, epbl_dispatch_redirect_slot
    str     w24, [x25]
    str     x25, [x22]
    dsb     sy
#endif

#ifdef EPBL_EXCEPTION_STAGED
#ifdef EPBL_CONTEXT_STAGED
    /*
     * Keep the large architectural vector spacing outside the uploaded
     * worker. Only synchronous CurrentEL SP0/SPx entries are needed here.
     */
    adr     x20, el3_exception
    ldr     x21, =PROBE_EXCEPTION_VBAR
    sub     x22, x20, x21
    asr     x22, x22, #2
    and     w22, w22, #0x03ffffff
    ldr     w23, =0x14000000
    orr     w22, w22, w23
    str     w22, [x21]

    add     x21, x21, #0x200
    sub     x22, x20, x21
    asr     x22, x22, #2
    and     w22, w22, #0x03ffffff
    orr     w22, w22, w23
    str     w22, [x21]
    dsb     sy

    ldr     x20, =PROBE_EXCEPTION_VBAR
#else
    adr     x20, el3_vectors
#endif
    msr     VBAR_EL3, x20
    isb
#endif

#ifdef EPBL_DISABLE_ICACHE
    /*
     * The Houston payload previously executed from 0x02022000 and
     * the received EPBL overwrites that same region.
     *
     * Explicit IC maintenance has already hung on this SoC, while
     * clearing SCTLR_EL3.I from the relocated worker was physically
     * validated.
     *
     * Disable EL3 instruction caching before fetching the EPBL.
     */
    dsb     sy
    mrs     x20, SCTLR_EL3
    mov     x21, #0x1000
    bic     x20, x20, x21
    msr     SCTLR_EL3, x20
    isb
#endif

#if defined(EPBL_COLD_CONTEXT_STAGED) || \
    defined(EPBL_FWBL1_BOUNDARY_STAGED)
    /* Recreate the register state at the authentic cold dispatch branch. */
    ldr     x0, =0x02023aac
    mov     x1, x0
    mov     x2, #0
    mov     x3, x0
    mov     w20, #0
    mov     w21, #1
    ldr     x16, =PROBE_EPBL_COLD_TARGET
    blr     x16
#else
    /* Enter through the exact stock indirect branch helper at 0x1c9a0. */
    ldr     x16, =PROBE_EPBL_BRANCH
    blr     x16
#endif
    b       finalize_failed
#else
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    b       report_result
#endif
#else
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    b       report_result
#endif
#else
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    b       report_result
#endif

receive_failed:
    mov     x20, #0x100
    b       report_failure

#ifndef EPBL_CONTEXT_STAGED
hash_failed:
    mov     x20, #0x101
    b       report_failure
#endif

parser_failed:
    mov     x20, #0x102
    b       report_failure

#ifndef EPBL_CONTEXT_STAGED
parsed_state_failed:
    mov     x20, #0x103
    b       report_failure
#endif

#ifdef EPBL_VERIFY_PATH
verifier_failed:
    ldr     x20, =PROBE_VERIFY_FAIL_MAGIC
    str     x20, [x19]
    mov     x20, #0x104
    str     x20, [x19, #0x10]
    b       report_result
#endif

#ifdef EPBL_POSTLOAD_PATH
postload_failed:
    ldr     x20, =PROBE_POSTLOAD_FAIL_MAGIC
    str     x20, [x19]
    mov     x20, #0x105
    str     x20, [x19, #0x10]
    b       report_result
#endif

#ifdef EPBL_ENTRY_PATH
finalize_failed:
    adr     x19, probe_record
    ldr     x20, =PROBE_FINALIZE_FAIL_MAGIC
    str     x20, [x19]
    mov     x20, #0x106
    str     x20, [x19, #0x10]
    b       report_result

/* Reached only after the stock helper fetched the authentic EPBL entry. */
#if defined(EPBL_FWBL1_BOUNDARY_STAGED)
epbl_fwbl1_boundary_hook:
    mov     x27, x4
    adr     x19, probe_record
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    str     x27, [x19, #0x18]
    ldr     x20, =PROBE_EPBL_DISPATCH_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x20]
    ldr     x20, =PROBE_EPBL_DISPATCH_LITERAL
    str     x20, [x19, #0x28]
    ldr     x20, =PROBE_EPBL_DISPATCH_POINTER
    str     x20, [x19, #0x30]
    ldr     x20, =PROBE_EPBL_DISPATCH_LITERAL
    ldr     x21, [x20]
    str     x21, [x19, #0x38]
    ldr     w21, [x21]
    str     x21, [x19, #0x40]
    ldr     x20, =PROBE_FWBL1_ENTRY
    sub     x20, x20, #0x10
    ldr     x21, [x20]
    str     x21, [x19, #0x48]
    ldr     x21, [x20, #8]
    str     x21, [x19, #0x50]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x58]
    b       report_result
#elif defined(EPBL_MMIO_STAGED) || defined(EPBL_MMIO_TRAP_STAGED)
epbl_mmio_hook:
    mov     x27, x20
    adr     x19, probe_record
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    str     x25, [x19, #0x18]
    ldr     x20, =PROBE_EPBL_ENTRY
    str     x20, [x19, #0x20]
    ldr     x20, =PROBE_EPBL_MMIO_SITE
    str     x20, [x19, #0x28]
    ldr     x20, =PROBE_EPBL_DISPATCH_MMIO
    str     x20, [x19, #0x30]
    str     x27, [x19, #0x38]
    ldr     w20, =PROBE_EPBL_MMIO_INSN
    str     x20, [x19, #0x40]
    ldr     x20, =PROBE_EPBL_MMIO_SITE
    ldr     w21, [x20]
    str     x21, [x19, #0x48]
    ldr     x20, =PROBE_BOOT_FLAGS
    ldr     w21, [x20]
    str     x21, [x19, #0x50]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x58]
    b       report_result
#elif defined(EPBL_DISPATCH_STAGED)
epbl_cold_dispatch_hook:
    ldr     x27, =PROBE_EPBL_COLD_TARGET
    ldr     x28, =PROBE_EPBL_COLD_SITE
    b       epbl_dispatch_hook

epbl_warm_dispatch_hook:
    mov     x27, x4
    ldr     x28, =PROBE_EPBL_WARM_SITE

epbl_dispatch_hook:
    mov     x26, x20
    adr     x19, probe_record
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    str     x25, [x19, #0x18]
    str     x28, [x19, #0x20]
    str     x26, [x19, #0x28]
    ldr     x20, =PROBE_EPBL_DISPATCH_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x30]
    str     x27, [x19, #0x38]
    ldr     w20, =PROBE_EPBL_COLD_INSN
    ldr     w21, =PROBE_EPBL_WARM_INSN
    ldr     x22, =PROBE_EPBL_COLD_SITE
    cmp     x28, x22
    csel    w20, w20, w21, eq
    str     x20, [x19, #0x40]
    ldr     w20, [x28]
    str     x20, [x19, #0x48]
    ldr     x20, =PROBE_BOOT_FLAGS
    ldr     w21, [x20]
    str     x21, [x19, #0x50]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x58]
    b       report_result
#elif defined(EPBL_ENTRY_STAGED)
epbl_entry_hook:
    adr     x19, probe_record
    ldr     x20, =PROBE_PASS_MAGIC
    str     x20, [x19]
    mov     x20, #1
    str     x20, [x19, #0x10]
    ldr     x20, =PROBE_EPBL_ENTRY
    str     x20, [x19, #0x20]
    ldr     x20, =PROBE_EPBL_HOOK_SITE
    str     x20, [x19, #0x28]
    ldr     w20, =PROBE_EPBL_ENTRY_INSN
    str     x20, [x19, #0x30]
    ldr     w20, =PROBE_EPBL_HOOK_INSN
    str     x20, [x19, #0x38]
    ldr     x20, =PROBE_EPBL_HOOK_SITE
    ldr     w21, [x20]
    str     x21, [x19, #0x40]
    ldr     x20, =PROBE_ENTRY_TIMING_WORD
    ldr     w21, [x20]
    str     x21, [x19, #0x48]
    ldr     x20, =PROBE_BOOT_FLAGS
    ldr     w21, [x20]
    str     x21, [x19, #0x50]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x58]
    b       report_result
#endif
#endif

cancel_command_failed:
    mov     x20, #0x200
    b       report_setup_failure

cancel_clear_failed:
    mov     x20, #0x201

report_setup_failure:
    adr     x19, probe_record

#ifdef EPBL_CONTEXT_STAGED
    ldr     x21, =PROBE_FAIL_MAGIC
    str     x21, [x19]
    str     x20, [x19, #0x10]

    /* Preserve the final controller state after all bounded arm attempts. */
    ldr     x22, =S5E9825_USB_STATE_POINTER
    ldr     w21, [x22]
    str     x21, [x19, #0x28]
    ldr     w21, [x22, #0x88]
    str     x21, [x19, #0x30]

    ldr     x23, =PROBE_DWC3_GEVNTCOUNT0
    ldr     w21, [x23]
    str     x21, [x19, #0x38]
    ldr     x23, =PROBE_DWC3_DSTS
    ldr     w21, [x23]
    str     x21, [x19, #0x40]
    ldr     x23, =PROBE_DWC3_DALEPENA
    ldr     w21, [x23]
    str     x21, [x19, #0x48]
    ldr     x23, =PROBE_DWC3_EP2_OUT_DEPCMD
    ldr     w21, [x23]
    str     x21, [x19, #0x50]

    ldr     w23, [x22, #0x2c]
    add     x23, x23, #0xa0
    ldr     w21, [x23, #0xc]
    str     x21, [x19, #0x58]
    b       report_result
#endif

report_failure:
    ldr     x21, =PROBE_FAIL_MAGIC
    str     x21, [x19]
    str     x20, [x19, #0x10]

report_result:
#ifdef EPBL_EXCEPTION_STAGED
    /* Never leave the diagnostic vector table installed while reporting. */
    adr     x20, saved_vbar_el3
    ldr     x20, [x20]
    msr     VBAR_EL3, x20
    dsb     sy
    isb
#endif
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait

5:
    b       5b
.size relocated_entry, . - relocated_entry

#ifdef EPBL_EXCEPTION_STAGED
.type el3_exception, %function
el3_exception:
#ifdef EPBL_CONTEXT_STAGED
    /* Preserve the indirect-call context before using any scratch registers. */
    mov     x25, x8
    mov     x26, x9
    mov     x27, x22
    mov     x24, x30
    mov     x23, sp
    adr     x19, probe_record
    ldr     x20, =PROBE_TRAP_MAGIC
    str     x20, [x19]
    mov     x20, #0x108
    str     x20, [x19, #0x10]
#ifdef EPBL_COLD_CONTEXT_STAGED
    /* EPBL scribbles near this record; restore the host-visible header. */
    mov     w20, #1
    str     w20, [x19, #0x8]
    mov     w20, #PROBE_RECORD_SIZE
    str     w20, [x19, #0xc]
#endif
    mrs     x20, ESR_EL3
    str     x20, [x19, #0x18]
    mrs     x20, FAR_EL3
    str     x20, [x19, #0x20]
    mrs     x20, ELR_EL3
    str     x20, [x19, #0x28]
    mrs     x20, SPSR_EL3
    str     x20, [x19, #0x30]
    str     x24, [x19, #0x38]
#if defined(EPBL_FWBL1_BOUNDARY_STAGED) || \
    defined(EPBL_COLD_CONTEXT_STAGED)
    ldr     x20, =PROBE_EPBL_DISPATCH_LITERAL
    ldr     x21, [x20]
    str     x21, [x19, #0x40]
    ldr     x20, =PROBE_EPBL_DISPATCH_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x48]
    adr     x20, epbl_dispatch_redirect_slot
#ifdef EPBL_COLD_CONTEXT_STAGED
    adr     x21, fwbl1_shim_entry_x4
    ldr     x21, [x21]
    str     x21, [x19, #0x50]
    /*
     * The slot value has been constant across runs; report x12 instead.
     * The stale stager line branched through x12, so 0x17 here confirms it.
     */
    str     x12, [x19, #0x58]
#else
    str     x20, [x19, #0x50]
    ldr     w21, [x20]
    str     x21, [x19, #0x58]
#endif
#else
    str     x23, [x19, #0x40]
    str     x25, [x19, #0x48]
    str     x26, [x19, #0x50]
    str     x27, [x19, #0x58]
#endif
#else
    adr     x19, probe_record
    ldr     x20, =PROBE_TRAP_MAGIC
    str     x20, [x19]
    mov     x20, #0x107
    str     x20, [x19, #0x10]
    mrs     x20, ESR_EL3
    str     x20, [x19, #0x18]
    mrs     x20, FAR_EL3
    str     x20, [x19, #0x20]
    mrs     x20, ELR_EL3
    str     x20, [x19, #0x28]
    mrs     x20, SPSR_EL3
    str     x20, [x19, #0x30]
    adr     x21, saved_vbar_el3
    ldr     x20, [x21]
    str     x20, [x19, #0x38]
    ldr     x21, =PROBE_EPBL_DISPATCH_MMIO
    str     x21, [x19, #0x40]
    ldr     x21, =PROBE_EPBL_MMIO_SITE
    str     x21, [x19, #0x48]
    ldr     x21, =PROBE_BOOT_FLAGS
    ldr     w21, [x21]
    str     x21, [x19, #0x50]
    mrs     x21, CurrentEL
    str     x21, [x19, #0x58]
#endif
    b       report_result
.size el3_exception, . - el3_exception

#endif

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
6:
    ldr     w5, [x2, #0xc]
    tbnz    w5, #0, 6b
    dsb     sy
    ret
.size probe_usb_send_wait, . - probe_usb_send_wait

.balign 8
.type probe_record, %object
probe_record:
    .ascii  PROBE_INIT_MAGIC
    .word   1
    .word   PROBE_RECORD_SIZE
    .zero   PROBE_RECORD_SIZE - 0x10
.size probe_record, . - probe_record

.balign 16
.type probe_ep1_trb, %object
probe_ep1_trb:
    .zero   0x10
.size probe_ep1_trb, . - probe_ep1_trb

#if defined(EPBL_COLD_CONTEXT_STAGED) || \
    defined(EPBL_FWBL1_BOUNDARY_STAGED)
#ifdef EPBL_COLD_CONTEXT_STAGED
    /*
     * An earlier slot at relocated offset 0x580 appeared to be overwritten
     * with 7, but that was inferred from the same 0x17 fault, now explained
     * by a stale stager line. Offset 0x600 is proven to survive, so keep it.
     */
    .org relocated_start + 0x600, 0
#endif
.balign 8
epbl_dispatch_redirect_slot:
    .word   0
    .word   0
#endif

#ifdef EPBL_COLD_CONTEXT_STAGED
    /* Keep the shim beside the slot, in the area proven to survive. */
.balign 8
fwbl1_shim_entry_x4:
    .quad   0

.type fwbl1_noic_entry, %function
fwbl1_noic_entry:
    /*
     * Record the stock helper's branch register first. A trap that still
     * reports zero here never reached the shim.
     */
    adr     x16, fwbl1_shim_entry_x4
    str     x4, [x16]
    dsb     sy
#if defined(EPBL_DUMP_FWBL1) || defined(EPBL_PATCH_VERIFY) || defined(EPBL_VERIFY_DIAG) || defined(EPBL_SBOOT_NOVERIFY) || defined(EPBL_MINFORM_NORMAL)
    /*
     * The FWBL1 body is still encrypted at the shim; the stub self-decrypts
     * it when FWBL1 runs (decrypt+verify routine at 0x02026720, whose caller
     * returns to 0x020260cc). Keep I-cache disabled, patch the instruction at
     * 0x020260cc to branch into our hook, then enter FWBL1 at the normal
     * continue point. FWBL1 runs its real setup and decrypts the body, then
     * reaches our hook with the plaintext body resident. With I-cache and
     * D-cache off the patched words go to and are fetched from memory, so no
     * IC maintenance (which hangs on this SoC) is needed.
     */
    mrs     x10, CPTR_EL3
    and     w10, w10, #0x7fffffff
    and     w10, w10, #0xffefffff
    and     w10, w10, #0xfffffbff
    msr     CPTR_EL3, x10
    mrs     x10, SCTLR_EL3
    mov     x11, #0x1000
    bic     x10, x10, x11
    msr     SCTLR_EL3, x10
    isb

    ldr     x17, =PROBE_FWBL1_DECRYPT_RET
    adr     x18, fwbl1_after_decrypt
    sub     x18, x18, x17
    asr     x18, x18, #2
    and     w18, w18, #0x03ffffff
    movz    w19, #0x1400, lsl #16
    orr     w18, w18, w19
    str     w18, [x17]
    dsb     sy

    ldr     x16, =PROBE_FWBL1_NOIC_CONTINUE
    br      x16

fwbl1_after_decrypt:
#ifdef EPBL_MINFORM_NORMAL
    /*
     * Tell u-boot that this boot is an intentional normal boot.
     *
     * MINFORM (PMU 0x15860808) is Samsung's boot-intent word. u-boot splits it
     * into fields with get_minform_magic(idx): idx 0 = bits 31..24, idx 1 =
     * bits 23..16, and four nibbles below. is_normal_booting() (sboot
     * 0xc9003280) reads fields 0 and 1 and returns 1 when field 1 is 'N'
     * (0x4e); 0 when both are zero ("minform is reset value"), which is what a
     * cold boot over the BootROM USB path leaves behind.
     *
     * That zero is why the chain lands in Download mode. s5p_check_download()
     * (0xc900e9e0) consults is_normal_booting() last, and when it returns 0 it
     * falls through to ifconn_check_jig_adc_value() -- a cable IS attached,
     * since we are booting over it -- and returns download reason 4. With
     * field 1 = 'N' it returns 0 instead, and the caller's `cbz` at
     * 0xc90038f8 takes the normal-boot path.
     *
     * 0x4e4e0000 sets both bytes to 'N' and leaves the nibbles at zero, which
     * is what they already are. Nothing else in the chain writes this word:
     * EPBL, FWBL1 (encrypted and decrypted) and el3_mon never reference it;
     * BL2 only reads bits 4..7 (its own upload-mode check, +0xe4); and u-boot's
     * own setters are read-modify-write of a single field each. So the value
     * survives from here to the read.
     */
    /*
     * Before touching anything, report the PMU scratch registers over EP1.
     *
     * 0x15860810..0x1586081c are in the always-on domain and nothing in this
     * chain writes them, so they survive the warm reset between runs: a
     * breadcrumb left by u-boot in the previous boot (see
     * sboot_patch.py --diag-secure-payload) is still there when the next
     * payload starts. The host prints anything that is not a probe record as a
     * hexdump, which is enough -- and it costs no extra run, unlike dumping a
     * region after the fact.
     */
    movz    x4, #0x8020
    movk    x4, #0x0203, lsl #16        /* scratch buffer in FWBL1 padding */
    movz    x5, #0x0810
    movk    x5, #0x1586, lsl #16
    ldr     w6, [x5]
    str     w6, [x4]
    ldr     w6, [x5, #4]
    str     w6, [x4, #4]
    ldr     w6, [x5, #8]
    str     w6, [x4, #8]
    ldr     w6, [x5, #12]
    str     w6, [x4, #12]
    dsb     sy
    mov     x0, x4
    mov     w1, #0x10
    bl      probe_usb_send_wait

    movz    x4, #0x0808
    movk    x4, #0x1586, lsl #16        /* MINFORM = 0x15860808 */
    movz    w5, #0x0000
    movk    w5, #0x4e4e, lsl #16        /* 'N','N' */
    str     w5, [x4]
    dsb     sy
#endif
#if defined(EPBL_DUMP_FWBL1)
    adr     x19, probe_record
    ldr     x20, =PROBE_DUMP_MAGIC
    str     x20, [x19]
    mov     w20, #1
    str     w20, [x19, #0x8]
    mov     w20, #PROBE_RECORD_SIZE
    str     w20, [x19, #0xc]
    ldr     x20, =PROBE_DUMP_BASE
    str     x20, [x19, #0x10]
    ldr     x20, =PROBE_DUMP_SIZE
    str     x20, [x19, #0x18]
    mrs     x20, CurrentEL
    str     x20, [x19, #0x20]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
    ldr     x0, =PROBE_DUMP_BASE
    ldr     w1, =PROBE_DUMP_SIZE
    bl      probe_usb_send_wait
7:
    b       7b
#elif defined(EPBL_VERIFY_DIAG)
    /*
     * Diagnostic: hook the SMC load+verify handler's type dispatch (0x0202afac,
     * right after FUN_0202c7ac returns the command type in x0), report the
     * selected type over EP1 IN via the monitor's own print pointer at
     * 0x020200d0, then continue the dispatch. This fires at the real
     * sboot-verify moment; the host's EP1 reader captures "SBG:XX". The stub is
     * copied into FWBL1 padding at 0x02038000 so it survives until verify time,
     * written position-independently (movz/movk only).
     */
    adr     x0, verify_diag_stub
    movz    x1, #0x8000
    movk    x1, #0x0203, lsl #16        /* dst 0x02038000 */
    adr     x2, verify_diag_stub_end
3:
    ldr     w3, [x0], #4
    str     w3, [x1], #4
    cmp     x0, x2
    b.lo    3b

    movz    x4, #0xafac
    movk    x4, #0x0202, lsl #16        /* dispatch hook 0x0202afac */
    movz    x5, #0x8000
    movk    x5, #0x0203, lsl #16        /* stub 0x02038000 */
    sub     x6, x5, x4
    asr     x6, x6, #2
    and     w6, w6, #0x03ffffff
    movz    w7, #0x1400, lsl #16
    orr     w6, w6, w7                  /* b 0x02038000 */
    str     w6, [x4]
    dsb     sy

    ldr     x16, =PROBE_FWBL1_DECRYPT_CONT
    br      x16
#elif defined(EPBL_SBOOT_NOVERIFY)
    /*
     * Non-destructive secure-boot experiment: write a `mov w0,#0; ret` stub into
     * FWBL1 padding (0x02038010) and re-point PTR_IS_SECUREBOOT (iRAM 0x020200A8)
     * at it, so any caller of is_secure_boot() through that pointer gets 0
     * (secure boot off => hash-only, no signature verify). Then rejoin the stock
     * boot. If the sboot-load path consults is_secure_boot via this pointer when
     * choosing its verify type, a modified sboot (fixed hash) is accepted.
     * iRAM only; fully reversible on reboot.
     */
    movz    x4, #0x8010
    movk    x4, #0x0203, lsl #16        /* stub at 0x02038010 */
    movz    w5, #0x0000
    movk    w5, #0x5280, lsl #16        /* mov w0, #0  (0x52800000) */
    str     w5, [x4]
    movz    w5, #0x03c0
    movk    w5, #0xd65f, lsl #16        /* ret        (0xd65f03c0) */
    str     w5, [x4, #4]
    movz    x6, #0x00a8
    movk    x6, #0x0202, lsl #16        /* PTR_IS_SECUREBOOT = 0x020200A8 */
    str     w4, [x6]                    /* point it at our stub */
    dsb     sy
    ldr     x16, =PROBE_FWBL1_DECRYPT_CONT
    br      x16
#elif defined(EPBL_MINFORM_NORMAL)
    /* MINFORM only: the write above is the whole payload, rejoin the boot. */
    ldr     x16, =PROBE_FWBL1_DECRYPT_CONT
    br      x16
#else
    /*
     * EPBL_PATCH_VERIFY: the decrypted FWBL1 contains several verify-or-hang
     * routines. Each computes a digest/signature result and, on failure,
     * spins in an infinite loop. Overwrite the deciding branch in each so the
     * success path is always taken, then rejoin the stock boot at 0x020260d8.
     */
    adr     x17, fwbl1_patch_table
1:
    ldr     w18, [x17], #4          /* target address (0 terminates) */
    cbz     w18, 2f
    ldr     w19, [x17], #4          /* replacement instruction */
    str     w19, [x18]
    b       1b
2:
    dsb     sy
    ldr     x16, =PROBE_FWBL1_DECRYPT_CONT
    br      x16

.balign 4
fwbl1_patch_table:
    .word   0x0202c274, 0x14000002
    .word   0x0202c3c0, 0x14000002
    .word   0x0202a4ac, 0x14000019
    .word   0, 0
#endif

#ifdef EPBL_VERIFY_DIAG
/*
 * Position-independent stub copied to 0x02038000. On entry x0 = command type
 * returned by FUN_0202c7ac. Prints "SBG:XX\n" (XX = type low byte in hex) via
 * the monitor print pointer at 0x020200d0, restores state, redoes the
 * overwritten `mov x1,x0`, and rejoins the dispatch at 0x0202afb0.
 */
.balign 4
verify_diag_stub:
    sub     sp, sp, #32
    stp     x29, x30, [sp, #16]
    str     x0, [sp]                    /* save type */
    movz    x8, #0x8800
    movk    x8, #0x0203, lsl #16        /* string buffer 0x02038800 */
    mov     w9, #0x53
    strb    w9, [x8]                    /* 'S' */
    mov     w9, #0x42
    strb    w9, [x8, #1]                /* 'B' */
    mov     w9, #0x47
    strb    w9, [x8, #2]                /* 'G' */
    mov     w9, #0x3a
    strb    w9, [x8, #3]                /* ':' */
    and     w10, w0, #0xff
    lsr     w11, w10, #4
    add     w12, w11, #0x30
    add     w13, w11, #0x37
    cmp     w11, #9
    csel    w11, w13, w12, hi
    strb    w11, [x8, #4]               /* high nibble */
    and     w11, w10, #0xf
    add     w12, w11, #0x30
    add     w13, w11, #0x37
    cmp     w11, #9
    csel    w11, w13, w12, hi
    strb    w11, [x8, #5]               /* low nibble */
    mov     w9, #0x0a
    strb    w9, [x8, #6]                /* '\n' */
    strb    wzr, [x8, #7]
    movz    x9, #0x00d0
    movk    x9, #0x0202, lsl #16        /* 0x020200d0 print pointer */
    ldr     x9, [x9]
    mov     x0, x8
    mov     x1, #7
    blr     x9
    ldr     x0, [sp]                    /* restore type */
    ldp     x29, x30, [sp, #16]
    add     sp, sp, #32
    mov     x1, x0                      /* redo overwritten mov x1,x0 */
    movz    x16, #0xafb0
    movk    x16, #0x0202, lsl #16       /* continue dispatch at 0x0202afb0 */
    br      x16
verify_diag_stub_end:
#endif
#else
    /*
     * Reproduce FWBL1 0x02026010..0x02026030 while keeping SCTLR_EL3.I
     * clear. The authenticated image enables I-cache before its first real
     * branch, which would expose any stale line at 0x02026000. Continue at
     * the first literal load after that prefix.
     */
    mrs     x10, CPTR_EL3
    and     w10, w10, #0x7fffffff
    and     w10, w10, #0xffefffff
    and     w10, w10, #0xfffffbff
    msr     CPTR_EL3, x10
    mrs     x10, SCTLR_EL3
    mov     x11, #0x1000
    bic     x10, x10, x11
    msr     SCTLR_EL3, x10
    isb
    ldr     x16, =PROBE_FWBL1_NOIC_CONTINUE
    br      x16
#endif
.size fwbl1_noic_entry, . - fwbl1_noic_entry
#endif

#ifdef EPBL_KEY_DUMP
/*
 * Read both OTP key slots in full and halt. Writes nothing.
 * Each slot is read as 32-bit accesses and packed two words per record field.
 */
.type key_dump_path, %function
key_dump_path:
    adr     x19, probe_record
    add     x25, x19, #0x18             /* first KEY2 field */
    ldr     x20, =PROBE_OTP_KEY2_SLOT
    mov     w23, #4
key_dump_key2:
    ldr     w21, [x20]
    ldr     w22, [x20, #4]
    orr     x21, x21, x22, lsl #32
    str     x21, [x25], #8
    add     x20, x20, #8
    subs    w23, w23, #1
    b.ne    key_dump_key2

    ldr     x20, =PROBE_OTP_KEY_SLOT
    mov     w23, #4
key_dump_key:
    ldr     w21, [x20]
    ldr     w22, [x20, #4]
    orr     x21, x21, x22, lsl #32
    str     x21, [x25], #8
    add     x20, x20, #8
    subs    w23, w23, #1
    b.ne    key_dump_key

    mrs     x21, CurrentEL
    str     x21, [x19, #0x58]
    ldr     x20, =PROBE_KEY_DUMP_MAGIC
    str     x20, [x19]
    mov     x21, #1
    str     x21, [x19, #0x10]
    b       report_result
.size key_dump_path, . - key_dump_path
#endif

#ifdef EPBL_BOOT_UFS_CHAIN
/*
 * Load the chain from UFS instead of over USB, then rejoin the normal flow.
 *
 * Only the SOURCE of the image changes. Everything downstream is the path that
 * is already proven on hardware: the header parse, the EPBL_CUSTOM_KEY
 * re-point of PTR_SECUREBOOT_KEY, the 0x5b58 verify, and the boot
 * continuation. Build this together with -DEPBL_CUSTOM_KEY
 * -DEPBL_CUSTOM_KEY_EFUSE, or the BootROM will verify our ST1 against
 * Samsung's key and reject it.
 *
 * Mirrors the ROM's own sequence at 0x204: set the boot-device nibble, call
 * 0xcc68, require 1.
 */
.type boot_ufs_chain_path, %function
boot_ufs_chain_path:
    /* Zero the destination, so a failed or short read cannot look like data. */
    ldr     x21, =PROBE_EPBL_DESTINATION
    mov     x23, #PROBE_EPBL_SIZE
boot_ufs_chain_clear:
    str     xzr, [x21], #8
    subs    x23, x23, #8
    b.ne    boot_ufs_chain_clear
    dsb     sy

    adr     x19, probe_record
    ldr     x20, =PROBE_BOOT_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x20]           /* boot state before */
    and     w22, w21, #0xffffff0f
    orr     w22, w22, #0x10             /* device 1 = storage */
    str     w22, [x20]
    dsb     sy

    mov     w0, #1                      /* attempt 1, as the ROM does */
    ldr     x16, =PROBE_LOAD_IMAGE
    blr     x16
    str     x0, [x19, #0x18]            /* 0xcc68 return */
    cmp     w0, #1
    b.ne    receive_failed

    /*
     * Report before continuing. On the EPBL_ENTRY_PATH the stock flow emits no
     * records, so without this the only signal is "the device vanished" --
     * which looks identical whether the chain booted or the payload crashed.
     */
    ldr     x20, =PROBE_EPBL_DESTINATION
    ldr     w21, [x20]
    str     x21, [x19, #0x30]           /* loaded num_of_sector */
    ldr     w21, [x20, #4]
    str     x21, [x19, #0x38]           /* loaded checksum */
    ldr     x20, =PROBE_BOOT_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x40]           /* boot state after the load */
    ldr     x20, =PROBE_BOOT_UFS_KEY_POINTER
    ldr     w21, [x20]
    str     x21, [x19, #0x48]           /* key pointer before our re-point */
    ldr     x20, =PROBE_PMU_REBOOT_REASON
    ldr     w21, [x20]
    str     x21, [x19, #0x50]           /* packed reboot reason, byte 1 decides */
    mrs     x21, CurrentEL
    str     x21, [x19, #0x58]
    ldr     x20, =PROBE_BOOT_UFS_LOADED_MAGIC
    str     x20, [x19]
    mov     x21, #1
    str     x21, [x19, #0x10]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
    adr     x19, probe_record

    /* Second record: the iRAM metadata a header parse would have filled in. */
    adr     x19, probe_record
    ldr     x20, =PROBE_IRAM_BL1_SIZE
    ldr     w21, [x20]
    str     x21, [x19, #0x18]           /* 0x02020030 BL1 size */
    ldr     w21, [x20, #4]
    str     x21, [x19, #0x20]           /* 0x02020034 BL1 checksum */
    ldr     x20, =PROBE_IRAM_STATUS_REG0
    ldr     w21, [x20]
    str     x21, [x19, #0x28]           /* 0x02020070 status register 0 */
    ldr     w21, [x20, #4]
    str     x21, [x19, #0x30]           /* 0x02020074 status register 1 */
    ldr     w21, [x20, #0xc]
    str     x21, [x19, #0x38]           /* 0x0202007c SBC information */
    ldr     x20, =PROBE_IRAM_EPBL_SIZE
    ldr     w21, [x20]
    str     x21, [x19, #0x40]           /* 0x02020120 EPBL size */
    ldr     w21, [x20, #4]
    str     x21, [x19, #0x48]           /* 0x02020124 EPBL expected hash */
    ldr     w21, [x20, #8]
    str     x21, [x19, #0x50]           /* 0x02020128 EPBL load address */
    mrs     x21, CurrentEL
    str     x21, [x19, #0x58]
    ldr     x20, =PROBE_BOOT_UFS_META_MAGIC
    str     x20, [x19]
    mov     x21, #1
    str     x21, [x19, #0x10]
    mov     x0, x19
    mov     w1, #PROBE_RECORD_SIZE
    bl      probe_usb_send_wait
    adr     x19, probe_record

    /*
     * Rejoin AFTER the header parse and the 0xc9a0 verify, not before them.
     * 0xcc68 already did both internally -- that is why the image it leaves
     * has its header checksum CLEARED, exactly as the read-only storage probe
     * observed. Calling 0x17c54 and 0xc9a0 again over an already-processed
     * image fails the second time (status 0x104), which is what the first
     * attempt at this path hit. The USB path needs those two calls because a
     * USB receive parses and verifies nothing.
     */
    adr     x19, probe_record
    mov     w25, #1
    b       epbl_verified
.size boot_ufs_chain_path, . - boot_ufs_chain_path
#endif

#ifdef EPBL_KEY_STATE
/*
 * Read-only: report the selector's inputs and the pointer it already chose,
 * then halt. Writes nothing at all.
 */
.type key_state_path, %function
key_state_path:
    adr     x19, probe_record

    ldr     x20, =PROBE_SEC_STATUS0
    ldr     w21, [x20]
    str     x21, [x19, #0x18]           /* SEC0 0x10001000 */
    mov     w23, w21                    /* keep for the packed predicates */

    ldr     x20, =PROBE_SEC_STATUS1
    ldr     w22, [x20]
    str     x22, [x19, #0x20]           /* SEC1 0x1000b014 */

    ldr     x20, =PROBE_KEY_POINTER
    ldr     w21, [x20]
    str     x21, [x19, #0x28]           /* the pointer the ROM selector chose */

    /* First word of each OTP key slot: KEY2 should still read as zero. */
    ldr     x20, =PROBE_OTP_KEY_SLOT
    ldr     w21, [x20]
    str     x21, [x19, #0x30]
    ldr     x20, =PROBE_OTP_KEY2_SLOT
    ldr     w21, [x20]
    str     x21, [x19, #0x38]

    /*
     * Pack the seven predicates so the host does not have to re-derive them:
     * bit0 A(SEC0.8) bit1 B(SEC1.31) bit2 C(SEC0.1) bit3 D(SEC0.3)
     * bit4 E(SEC0.0) bit5 F(SEC1.0)  bit6 G(SEC1.3)
     */
    mov     w24, #0
    ubfx    w21, w23, #8, #1
    orr     w24, w24, w21
    ubfx    w21, w22, #31, #1
    orr     w24, w24, w21, lsl #1
    ubfx    w21, w23, #1, #1
    orr     w24, w24, w21, lsl #2
    ubfx    w21, w23, #3, #1
    orr     w24, w24, w21, lsl #3
    ubfx    w21, w23, #0, #1
    orr     w24, w24, w21, lsl #4
    ubfx    w21, w22, #0, #1
    orr     w24, w24, w21, lsl #5
    ubfx    w21, w22, #3, #1
    orr     w24, w24, w21, lsl #6
    str     x24, [x19, #0x40]

    ldr     x20, =PROBE_BOOT_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x48]

    ldr     x21, =PROBE_VERIFY_STATUS
    ldr     w21, [x21]
    str     x21, [x19, #0x50]           /* 0x02020070 verify status */

    mrs     x21, CurrentEL
    str     x21, [x19, #0x58]

    ldr     x20, =PROBE_KEY_STATE_MAGIC
    str     x20, [x19]
    mov     x21, #1
    str     x21, [x19, #0x10]
    b       report_result
.size key_state_path, . - key_state_path
#endif

#ifdef EPBL_BOOT_UFS
/*
 * Storage-load path. Deliberately does NOT re-point PTR_SECUREBOOT_KEY and
 * does NOT continue the boot: it loads from UFS, reports what landed, and
 * halts in report_result. That makes it safe against the STOCK sboot already
 * on UFS, which is the point -- it validates the load path on its own before
 * anything is flashed. Re-pointing the key here would make stock fail
 * verification, since stock is signed with Samsung's key.
 *
 * Placed after the `.org relocated_start + 0x600` slot, so this variant
 * leaves the layout the other variants depend on untouched.
 */
.type boot_ufs_path, %function
boot_ufs_path:
    ldr     x21, =PROBE_EPBL_DESTINATION
    mov     x23, #PROBE_EPBL_SIZE
boot_ufs_clear:
    str     xzr, [x21], #8
    subs    x23, x23, #8
    b.ne    boot_ufs_clear
    dsb     sy

    adr     x19, probe_record
    ldr     x20, =PROBE_BOOT_STATE
    ldr     w21, [x20]
    str     x21, [x19, #0x20]           /* boot state before */

    /* Force the device nibble (bits 7:4) to 1 = storage, keep the rest. */
    and     w22, w21, #0xffffff0f
    orr     w22, w22, #0x10
    str     w22, [x20]
    dsb     sy
    ldr     w22, [x20]
    str     x22, [x19, #0x28]           /* boot state after */

    /* Attempt 1, exactly as the ROM's retry loop at 0x200 does. */
    mov     w0, #1
    ldr     x16, =PROBE_LOAD_IMAGE
    blr     x16
    mov     w25, w0
    str     x25, [x19, #0x18]           /* 0xcc68 return, 1 = success */

    /* Read the device code back, to prove which handler ran. */
    mov     w0, #1
    ldr     x16, =PROBE_BOOT_DEVICE
    blr     x16
    str     x0, [x19, #0x30]

    /* Header of whatever landed: stock EPBL is 0x18 sectors, checksum known. */
    ldr     x20, =PROBE_EPBL_DESTINATION
    ldr     w21, [x20]
    str     x21, [x19, #0x38]           /* num_of_sector, expect 0x18 */
    ldr     w21, [x20, #4]
    str     x21, [x19, #0x40]           /* checksum */
    ldr     w21, =PROBE_EPBL_CHECKSUM
    str     x21, [x19, #0x48]           /* expected checksum */

    /* Nonzero byte count over the first 0x40, so "nothing loaded" is visible. */
    mov     w22, #0
    mov     x23, #0
boot_ufs_count:
    ldrb    w24, [x20, x23]
    cmp     w24, #0
    cinc    w22, w22, ne
    add     x23, x23, #1
    cmp     x23, #0x40
    b.lo    boot_ufs_count
    str     x22, [x19, #0x50]

    mrs     x21, CurrentEL
    str     x21, [x19, #0x58]

    cmp     w25, #1
    b.ne    boot_ufs_failed
    ldr     x20, =PROBE_BOOT_UFS_PASS_MAGIC
    b       boot_ufs_emit
boot_ufs_failed:
    ldr     x20, =PROBE_BOOT_UFS_FAIL_MAGIC
boot_ufs_emit:
    str     x20, [x19]
    mov     x21, #1
    str     x21, [x19, #0x10]           /* status */
    b       report_result
.size boot_ufs_path, . - boot_ufs_path
#endif

#ifdef EPBL_CUSTOM_KEY
/*
 * Our 32-byte secure-boot key value, for PTR_SECUREBOOT_KEY (0x0202006c).
 *
 * Derived from $EUB/9825_customkey/keys/4/st1.pem + keys/hmac.bin. Which of
 * the two forms the BootROM compares against is not yet known, so there is one
 * build per candidate and the hardware decides: a run that still reports
 * status 0x105 rules that candidate out, a run that proceeds past the verifier
 * confirms it.
 *
 *   EPBL_CUSTOM_KEY_HMAC  the un-XORed HMAC, i.e. what sign_st1 writes into
 *                         the SBL1 footer's `hmac` field:
 *                         HMAC-SHA512(hmac_key, st1_publickey[:136])[:32]
 *   EPBL_CUSTOM_KEY_EFUSE what patch_9825.py's get_efuse_data() returns, i.e.
 *                         what the fuse actually burns: that HMAC XOR hmac_key
 *
 * These bytes are tied to those key files. tools/check_custom_key.py
 * recomputes both from the keys and compares them against a built payload, so
 * a stale copy here is caught before anything is sent to the phone.
 */
.balign 8
.globl custom_boot_key
custom_boot_key:
#if defined(EPBL_CUSTOM_KEY_EFUSE)
    /* 1d12d364cf441dfe7d5084a054691cf1c7f71e068e2470881e52ce280c7c330b */
    .byte 0x1d, 0x12, 0xd3, 0x64, 0xcf, 0x44, 0x1d, 0xfe
    .byte 0x7d, 0x50, 0x84, 0xa0, 0x54, 0x69, 0x1c, 0xf1
    .byte 0xc7, 0xf7, 0x1e, 0x06, 0x8e, 0x24, 0x70, 0x88
    .byte 0x1e, 0x52, 0xce, 0x28, 0x0c, 0x7c, 0x33, 0x0b
#else
    /* 007cd770ac3d05e04e156a8e0bf4d8999c3161d95923ec9d2873e771d51be5a2 */
    .byte 0x00, 0x7c, 0xd7, 0x70, 0xac, 0x3d, 0x05, 0xe0
    .byte 0x4e, 0x15, 0x6a, 0x8e, 0x0b, 0xf4, 0xd8, 0x99
    .byte 0x9c, 0x31, 0x61, 0xd9, 0x59, 0x23, 0xec, 0x9d
    .byte 0x28, 0x73, 0xe7, 0x71, 0xd5, 0x1b, 0xe5, 0xa2
#endif
custom_boot_key_end:
.size custom_boot_key, . - custom_boot_key
#endif

.ltorg
.balign 8
relocated_end:
