/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../wine/wowprospero/service_timing.h"
#include <assert.h>

static void span(PwWowServiceTiming *p, uint32_t id, uint64_t ns)
{
    pw_wow_service_begin(p, id, 100);
    pw_wow_service_end(p, 100 + ns);
}

int main(void)
{
    PwWowServiceTiming p={0};
    const PwWowServiceEntry *top[PW_WOW_SERVICE_TOP];
    pw_wow_service_end(&p,100); /* No pending boundary. */
    assert(!p.total.calls && !pw_wow_service_top(&p,top));
    span(&p,0,0); /* Service zero and a zero-duration span are valid. */
    span(&p,0x1000,500000); /* Same low bits; distinct service table. */
    span(&p,0x1000,499999);
    span(&p,UINT32_MAX,235000000000ull); /* Long blocking span. */
    assert(p.total.calls==4 && p.total.long_calls==2 && p.total.max_ns==235000000000ull);
    assert(pw_wow_service_top(&p,top)==3 && top[0]->id==UINT32_MAX && top[1]->id==0x1000);
    assert(top[1]->stats.calls==2 && top[1]->stats.long_calls==1 && top[2]->id==0);
    for (unsigned kind=0;kind<3;kind++) {
        pw_wow_service_begin(&p,3,kind==0?0:100);
        pw_wow_service_end(&p,kind==1?0:kind==2?99:200);
    }
    assert(p.clock_errors==3 && p.total.calls==4 && !p.pending);
    pw_wow_service_begin(&p,4,10);
    pw_wow_service_begin(&p,5,20);
    pw_wow_service_end(&p,30);
    assert(p.abandoned==1 && !p.pending && p.total.calls==5);
    p=(PwWowServiceTiming){0};
    for (unsigned i=0;i<PW_WOW_SERVICE_SLOTS;i++) span(&p,i,100);
    span(&p,0x80000000,10000); /* Full table: explicit overflow, no alias. */
    span(&p,127,200);
    assert(p.overflow.calls==1 && p.overflow.wall_ns==10000 && p.total.calls==130);
    assert(pw_wow_service_top(&p,top)==4 && top[0]->id==127 && top[0]->stats.wall_ns==300);
    assert(top[1]->id==0 && top[2]->id==1 && top[3]->id==2); /* Stable ties. */
    p=(PwWowServiceTiming){0};
    p.total.calls=p.total.wall_ns=p.total.long_calls=UINT64_MAX;
    span(&p,1,500000);
    assert(p.saturated && p.total.calls==UINT64_MAX && p.total.wall_ns==UINT64_MAX &&
           p.total.long_calls==UINT64_MAX);
    p=(PwWowServiceTiming){.abandoned=UINT64_MAX,.pending=1};
    pw_wow_service_begin(&p,1,10);
    assert(p.saturated && p.abandoned==UINT64_MAX);
    return 0;
}
