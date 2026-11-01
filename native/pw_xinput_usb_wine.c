/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_xinput_usb_wine.h"
#include <stdio.h>
#include <string.h>

/* Capture selection only. The sink above this diagnostic still receives
 * every unmodified report. Compare analogs to the last logged sample so
 * gradual movement accumulates, while small idle jitter costs no records. */
static int delta(int a,int b,int step) { return a-b>=step || b-a>=step; }
static int analog_changed(const PwXinputUsbState *a,const PwXinputUsbState *b)
{
    return delta(a->left_trigger,b->left_trigger,32) || delta(a->right_trigger,b->right_trigger,32) ||
           delta(a->thumb_lx,b->thumb_lx,4096) || delta(a->thumb_ly,b->thumb_ly,4096) ||
           delta(a->thumb_rx,b->thumb_rx,4096) || delta(a->thumb_ry,b->thumb_ry,4096);
}

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
        bridge->button_records[slot]=bridge->analog_records[slot]=0;
        memset(&bridge->last[slot],0,sizeof(bridge->last[slot]));
        return;
    }
    if(bridge->capture && bridge->log) {
        int initial=!bridge->records[slot];
        int buttons=!initial && bridge->last[slot].buttons!=state->buttons;
        int analogs=!initial && !buttons && analog_changed(&bridge->last[slot],state);
        unsigned *budget=buttons?&bridge->button_records[slot]:&bridge->analog_records[slot];
        if((initial || buttons || analogs) && *budget<=256) {
            char line[192];
            if(*budget==256) {
                snprintf(line,sizeof(line),"usb360 capture limit xinput=%u channel=%s",slot+1,buttons?"buttons":"analog");
                bridge->log(line);(*budget)++;
            } else {
                char hex[2*PW_XINPUT_USB_REPORT+1];
                for(unsigned i=0;i<PW_XINPUT_USB_REPORT;i++)snprintf(hex+2*i,3,"%02x",raw[i]);
                snprintf(line,sizeof(line),"usb360 report xinput=%u vid=%04x pid=%04x subtype=%u change=%s bytes=%s",
                         slot+1,device->vendor_id,device->product_id,device->subtype,
                         initial?"initial":buttons?"buttons":"analog",hex);
                bridge->log(line);bridge->records[slot]++;(*budget)++;
            }
            bridge->last[slot]=*state;
        }
        if(buttons)bridge->last[slot].buttons=state->buttons;
    }
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
