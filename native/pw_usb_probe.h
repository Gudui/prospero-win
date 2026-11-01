/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_USB_PROBE_H
#define PW_USB_PROBE_H

#include <stddef.h>
#include <stdint.h>

/* Read-only visibility probe for USB devices the PS5 kernel enumerates but no
 * driver claims (an Xbox 360 guitar is vendor-class, so no usb_hid attaches).
 *
 * It lists `<root>` and `<root>/usb`, stats up to PW_USB_PROBE_MAX_NODES
 * USB-looking nodes and tests opening each with O_RDONLY and O_RDWR, closing
 * immediately. On nodes that open, it also queries the kernel's cached 18-byte
 * device descriptor (USB_GET_DEVICE_DESC) and 9-byte RX interface descriptor
 * (USB_GET_RX_INTERFACE_DESC) without generating bus traffic or claiming an
 * interface, and changes no input path.
 *
 * Returns the number of device nodes it tried to open. */
#define PW_USB_PROBE_MAX_NODES 128

int pw_usb_probe_run(const char *stage, const char *root, void (*log)(const char *line));

/* True for the names a USB device node can have directly under /dev. */
int pw_usb_probe_is_usb_name(const char *name);

/* Format cached FreeBSD USB device/interface descriptor bytes for logging. */
void pw_usb_probe_format_desc(const uint8_t *dev_desc, int dev_ok,
                              const uint8_t *if_desc, int if_ok,
                              char *out, size_t cap);

#endif
