/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef S5E9825_H
#define S5E9825_H

/* Houston and BootROM values confirmed on an SM-N975F. */
#define S5E9825_HOUSTON_RX_ADDRESS          0x02022000
#define S5E9825_HOUSTON_USB_STRUCT_OFFSET   0x0480
#define S5E9825_USB_STATE_POINTER           0x02021970
#define S5E9825_USB_CONTEXT_BASE            0x020214f0
#define S5E9825_BOOTROM_USB_INIT            0x000006e8
#define S5E9825_BOOTROM_USB_RECEIVE         0x00000a3c
#define S5E9825_BOOTROM_USB_RECEIVE_FORWARD 0x000011cc
#define S5E9825_BOOTROM_SIZE                0x00020000

/* Confirmed DWC3 logical EP1 IN (physical EP3) transfer state. */
#define S5E9825_DWC3_BASE                   0x10c0c000
#define S5E9825_DWC3_EP1_IN_DEPCMDPAR1      0x10c0c834
#define S5E9825_DWC3_EP1_IN_DEPCMDPAR0      0x10c0c838
#define S5E9825_DWC3_EP1_IN_DEPCMD          0x10c0c83c
#define S5E9825_DWC3_EP1_IN_TRB             0x02024800
#define S5E9825_DWC3_TRB_CTRL_NORMAL        0x00000c13
#define S5E9825_DWC3_STARTTRANSFER          0x00000406

#endif
