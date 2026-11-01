/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_xinput_usb_wine.h"
#include <stdio.h>
#include <string.h>

static void report(void *context,unsigned slot,const PwXinputUsbDevice *device,
                    const PwXinputUsbState *state,const uint8_t *raw)
{
    PwXinputUsbWine *bridge=context;
    if(slot>=3)return;
    if(bridge->set_slot) {
        PwWinePad pad={0};
        PwWinePadCaps caps={device->subtype,device->vendor_id,device->product_id,device->revision,0};
        if(state) {
            pad.buttons=state->buttons;pad.left_trigger=state->left_trigger;pad.right_trigger=state->right_trigger;
            pad.thumb_lx=state->thumb_lx;pad.thumb_ly=state->thumb_ly;pad.thumb_rx=state->thumb_rx;pad.thumb_ry=state->thumb_ry;
        }
        (void)bridge->set_slot(slot+1,state?&pad:NULL,&caps);
    }
    if(!state) {
        if(bridge->log) {
            char line[64];snprintf(line,sizeof(line),"usb360 disconnected xinput=%u",slot+1);bridge->log(line);
        }
        bridge->records[slot]=0;
        memset(&bridge->last[slot],0,sizeof(bridge->last[slot]));
        return;
    }
    if(bridge->capture && bridge->log && bridge->records[slot]<256 &&
       (!bridge->records[slot] || memcmp(&bridge->last[slot],state,sizeof(*state)))) {
        char line[160],hex[2*PW_XINPUT_USB_REPORT+1];
        for(unsigned i=0;i<PW_XINPUT_USB_REPORT;i++)snprintf(hex+2*i,3,"%02x",raw[i]);
        snprintf(line,sizeof(line),"usb360 report xinput=%u vid=%04x pid=%04x subtype=%u bytes=%s",
                 slot+1,device->vendor_id,device->product_id,device->subtype,hex);
        bridge->log(line);bridge->records[slot]++;
    }
    bridge->last[slot]=*state;
}
int pw_xinput_usb_wine_init(PwXinputUsbWine *bridge,const PwXinputUsbOps *ops,PwXinputUsbSetSlot set_slot,
                            void (*log)(const char *),int capture)
{
    if(!bridge)return -1;
    memset(bridge,0,sizeof(*bridge));bridge->set_slot=set_slot;bridge->log=log;bridge->capture=capture!=0;
    if(!set_slot && !capture)return 0;
    return pw_xinput_usb_freebsd_init(&bridge->usb,ops,3,report,bridge);
}
void pw_xinput_usb_wine_poll(PwXinputUsbWine *bridge,uint64_t tick,uint64_t retry_ticks)
{
    if(!bridge || !bridge->usb.limit)return;
    if(tick==1 || (retry_ticks && tick%retry_ticks==0)) {
        int rc=pw_xinput_usb_freebsd_scan(&bridge->usb);
        if(rc && bridge->log) {
            char line[64];snprintf(line,sizeof(line),"usb360 scan errno=%d",-rc);bridge->log(line);
        }
    }
    pw_xinput_usb_freebsd_poll(&bridge->usb);
}
void pw_xinput_usb_wine_close(PwXinputUsbWine *bridge)
{
    if(bridge)pw_xinput_usb_freebsd_close(&bridge->usb);
}
