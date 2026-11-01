/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_USB_PROBE_H
#define PW_USB_PROBE_H

#include <stddef.h>

/* Read-only visibility probe for USB devices the PS5 kernel enumerates but no
 * driver claims (an Xbox 360 guitar is vendor-class, so no usb_hid attaches).
 *
 * It lists `<root>` and `<root>/usb`, stats every USB-looking node and opens
 * each device node once with O_RDONLY, closing it at once. It never reads,
 * writes, issues an ioctl or claims an interface, and it changes no input
 * path. Every observation goes to `log` as one line. The caller names the
 * stage (before or after the /data grant changes the title's credentials).
 *
 * Returns the number of device nodes it tried to open. */
#define PW_USB_PROBE_MAX_NODES 32

int pw_usb_probe_run(const char *stage, const char *root, void (*log)(const char *line));

/* True for the names a USB device node can have directly under /dev. */
int pw_usb_probe_is_usb_name(const char *name);

#endif
