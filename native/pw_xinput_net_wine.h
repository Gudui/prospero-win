/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_XINPUT_NET_WINE_H
#define PW_XINPUT_NET_WINE_H
#include "../src/pw_xinput_net.h"
#include "../wine/ps5/pw_wine_sink.h"

/* XInput controllers described over loopback UDP (src/pw_xinput_net.h)
 * into the game's XInput slots 1..3, beside the DualSense in slot 0 and the
 * wired USB guitars. The socket is the platform's (pw_xinput_net_ps5.c);
 * tests give their own. */
typedef struct PwXinputNetOps {
    int (*open)(void *ctx,uint16_t port);                    /* fd, or -errno */
    long (*receive)(void *ctx,int fd,uint8_t *data,size_t cap); /* bytes, 0: none waiting, or -errno */
    void (*close)(void *ctx,int fd);
    void *ctx;
} PwXinputNetOps;
typedef int (*PwXinputNetSetSlot)(uint32_t,const PwWinePad *,const PwWinePadCaps *);
typedef int (*PwXinputNetPadSlot)(uint32_t,PwWinePad *);

typedef struct PwXinputNetWine {
    PwXinputNet net;
    PwXinputNetOps ops;
    int fd;
    PwXinputNetSetSlot set_slot;
    PwXinputNetPadSlot pad_slot;
    void (*log)(const char *);
    uint64_t received,rejected;
} PwXinputNetWine;

/* Listens when the indexed sink is there; 0 when listening or disabled
 * (no sink), else the socket's -errno, logged, and the bridge stays off. */
int pw_xinput_net_wine_init(PwXinputNetWine *bridge,const PwXinputNetOps *ops,
                            PwXinputNetSetSlot set_slot,PwXinputNetPadSlot pad_slot,
                            void (*log)(const char *));
/* Takes what arrived (a bounded number per call) and lets silent sources go. */
void pw_xinput_net_wine_poll(PwXinputNetWine *bridge,uint64_t now_ms);
/* Every held slot disconnected, the socket closed. */
void pw_xinput_net_wine_close(PwXinputNetWine *bridge);

/* The console's loopback UDP socket (sceNet). */
const PwXinputNetOps *pw_xinput_net_ps5_ops(void);
#endif
