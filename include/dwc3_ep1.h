/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DWC3_EP1_H
#define DWC3_EP1_H

/*
 * Send one buffer through the already configured logical EP1 IN endpoint.
 *
 * x0: physical buffer address
 * w1: byte count (low 24 bits are used)
 *
 * The function waits for DWC3 to clear the TRB HWO bit. It does not initialize
 * or re-enumerate USB.
 */
.global s5e9825_usb_send_wait
.type s5e9825_usb_send_wait, %function

#endif
