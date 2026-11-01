/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_XINPUT_USB_WINE_H
#define PW_XINPUT_USB_WINE_H
#include "pw_xinput_usb_freebsd.h"
#include "../wine/ps5/pw_wine_sink.h"
typedef int (*PwXinputUsbSetSlot)(uint32_t,const PwWinePad *,const PwWinePadCaps *);
typedef struct PwXinputUsbWine {
    PwXinputUsbFreebsd usb;
    PwXinputUsbSetSlot set_slot;
    void (*log)(const char *);
    unsigned capture,records[3],button_records[3],analog_records[3];
    PwXinputUsbState last[3];
} PwXinputUsbWine;
/* DualSense remains slot 0. USB users occupy stable slots 1..3 only.
 * Without the indexed sink, capture-only mode can qualify raw input;
 * normal mode remains disabled rather than overwriting controller 0. */
int pw_xinput_usb_wine_init(PwXinputUsbWine *,const PwXinputUsbOps *,PwXinputUsbSetSlot,
                            void (*log)(const char *),int capture);
void pw_xinput_usb_wine_poll(PwXinputUsbWine *,uint64_t tick,uint64_t retry_ticks);
void pw_xinput_usb_wine_close(PwXinputUsbWine *);
#endif
