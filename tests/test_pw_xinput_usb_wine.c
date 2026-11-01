/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_xinput_usb_wine.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

static int pending,button=0x11,logs,disconnected;
static int enumerate(void *ctx,PwXinputUsbNode *nodes,size_t cap)
{
    (void)ctx;assert(cap>=2);
    nodes[0]=(PwXinputUsbNode){"/dev/usb/2.2.0",2,2,0};
    nodes[1]=(PwXinputUsbNode){"/dev/usb/2.2.1",2,2,1};
    return 2;
}
static int open_read(void *ctx,const char *path){(void)ctx;return path[strlen(path)-1]=='0'?100:101;}
static int descriptor(void *ctx,int fd,unsigned kind,uint8_t *out,size_t len)
{
    const uint8_t dev[18]={18,1,0,2,0xff,0xff,0xff,8,0x30,0x14,0x48,0x47,0,1};
    const uint8_t iface[9]={9,4,0,0,2,0xff,0x5d,1,0};
    const uint8_t ep[7]={7,5,0x81,3,32,0,4};
    (void)ctx;(void)fd;
    if(kind==1){assert(len==18);memcpy(out,dev,len);}
    else if(kind==4){assert(len==9);memcpy(out,iface,len);}
    else {assert(kind==5 && len==7);memcpy(out,ep,len);}
    return 0;
}
static int short_reads(void *ctx,int fd){(void)ctx;(void)fd;return 0;}
static ssize_t read_report(void *ctx,int fd,uint8_t *out,size_t len)
{
    (void)ctx;assert(fd==101 && len==64);
    if(disconnected)return -ENXIO;
    if(!pending)return -EAGAIN;
    pending--;memset(out,0,20);out[1]=20;out[2]=(uint8_t)button;out[3]=0x90;out[10]=0;out[11]=0x80;
    return 20;
}
static void close_fd(void *ctx,int fd){(void)ctx;assert(fd==100 || fd==101);}
static void log_line(const char *line){assert(strstr(line,"usb360"));logs++;}
int main(void)
{
    PwXinputUsbOps ops={NULL,enumerate,open_read,descriptor,short_reads,read_report,close_fd,NULL};
    PwXinputUsbWine bridge;
    PwWinePad pad={0},got;
    PwWinePadCaps caps;
    pad.buttons=0x2000;pw_wine_set_pad(&pad);
    assert(!pw_xinput_usb_wine_init(&bridge,&ops,pw_wine_set_pad_slot,log_line,0));
    pending=1;pw_xinput_usb_wine_poll(&bridge,1,300);
    assert(pw_wine_pad_slot(1,&got) && got.buttons==0x9011 && got.thumb_rx==-32768 && got.packet==1);
    assert(pw_wine_pad_caps(1,&caps) && caps.subtype==7 && caps.vendor_id==0x1430 && caps.product_id==0x4748);
    assert(!caps.flags && pw_wine_pad(&got) && got.buttons==0x2000);
    assert(!pw_wine_pad_slot(2,&got) && !logs);
    pending=1;pw_xinput_usb_wine_poll(&bridge,2,300);
    assert(pw_wine_pad_slot(1,&got) && got.packet==1);
    button=0x22;pending=1;pw_xinput_usb_wine_poll(&bridge,3,300);
    assert(pw_wine_pad_slot(1,&got) && got.packet==2 && got.buttons==0x9022);
    disconnected=1;pw_xinput_usb_wine_poll(&bridge,4,300);
    assert(!pw_wine_pad_slot(1,&got) && logs==1);
    pw_xinput_usb_wine_close(&bridge);
    disconnected=0;logs=0;
    assert(!pw_xinput_usb_wine_init(&bridge,&ops,NULL,log_line,1));
    pending=1;pw_xinput_usb_wine_poll(&bridge,1,300);
    assert(logs==1 && !pw_wine_pad_slot(1,&got)); /* capture does not inject */
    pending=1;pw_xinput_usb_wine_poll(&bridge,2,300);assert(logs==1);
    button=0x33;pending=1;pw_xinput_usb_wine_poll(&bridge,3,300);assert(logs==2);
    assert(pw_wine_pad(&got) && got.buttons==0x2000);
    pw_xinput_usb_wine_close(&bridge);
    assert(!pw_xinput_usb_wine_init(&bridge,&ops,NULL,log_line,0) && !bridge.usb.limit);
    pw_xinput_usb_wine_poll(&bridge,1,300);pw_xinput_usb_wine_close(&bridge);
    return 0;
}
