/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "wine/wowprospero/sync_bop_adapter.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define BASE 0x20000u
struct fixture
{
    unsigned char memory[256];
    struct pw_wow_sync_registers canonical, saved_canonical;
    uint8_t guest_fp[512], native_fp[512], saved_fp[512];
    uint32_t object, op, handle, count;
    unsigned reads, probes, writes, publishes, finishes, calls;
    int deny_read, deny_probe, deny_publish, backend_miss, reset;
    uint32_t write_status;
    unsigned published;
};
static struct pw_wow_sync_bindings bindings={1,{4,0x20,0xe,0xdd,0xa},1};
static int read_guest(void *opaque,uint32_t address,void *out,size_t bytes)
{
    struct fixture *f=opaque;f->reads++;
    if(f->deny_read || address<BASE || address-BASE>sizeof(f->memory) ||
       bytes>sizeof(f->memory)-(address-BASE))return 0;
    memcpy(out,f->memory+(address-BASE),bytes);return 1;
}
static int probe_guest(void *opaque,uint32_t address,size_t bytes)
{
    struct fixture *f=opaque;f->probes++;
    return !f->deny_probe && address>=BASE && address-BASE<=sizeof(f->memory) &&
           bytes<=sizeof(f->memory)-(address-BASE);
}
static uint32_t write_guest(void *opaque,uint32_t address,const void *in,size_t bytes)
{
    struct fixture *f=opaque;f->writes++;
    assert(f->published && f->calls==1);
    if(f->write_status)return f->write_status;
    assert(address>=BASE && address-BASE<=sizeof(f->memory) && bytes<=sizeof(f->memory)-(address-BASE));
    memcpy(f->memory+(address-BASE),in,bytes);return 0;
}
static int publish(void *opaque,const struct pw_wow_sync_registers *registers)
{
    struct fixture *f=opaque;f->publishes++;
    assert(!f->published && !f->calls);
    if(f->deny_publish)return 0;
    f->saved_canonical=f->canonical;f->canonical=*registers;memcpy(f->saved_fp,f->native_fp,512);
    memcpy(f->native_fp,f->guest_fp,512);f->published=1;return 1;
}
static int finish(void *opaque,enum pw_wow_sync_result result,struct pw_wow_sync_registers *replacement)
{
    struct fixture *f=opaque;f->finishes++;
    assert(f->published && f->calls==1);
    if(f->reset){*replacement=f->canonical;memcpy(f->guest_fp,f->native_fp,512);}
    else if(result==PW_WOW_SYNC_MISS)f->canonical=f->saved_canonical;
    else f->canonical=*replacement;
    memcpy(f->native_fp,f->saved_fp,512);f->published=0;return f->reset;
}
static int cached(void *opaque,uint32_t op,uint32_t handle,uint32_t count,uint32_t *previous)
{
    struct fixture *f=opaque;f->calls++;assert(f->published);
    assert(!memcmp(f->native_fp,f->guest_fp,512));
    assert(f->canonical.pc==0x41000 && f->canonical.gpr[4]==BASE+4);
    f->op=op;f->handle=handle;f->count=count;
    if(f->reset){f->canonical.gpr[0]=0x991;f->canonical.pc=0x42000;f->canonical.gpr[4]=BASE+128;f->native_fp[17]=0x39;}
    if(f->backend_miss)return 0;
    if(op==PW_WOW_SYNC_WAIT && !f->object)return 0;
    *previous=op==PW_WOW_SYNC_RELEASE_MUTEX?1u-f->object:f->object;
    switch(op){
    case PW_WOW_SYNC_WAIT:if(!f->object)return 0;f->object--;break;
    case PW_WOW_SYNC_RELEASE_MUTEX:assert(f->object);f->object--;break;
    case PW_WOW_SYNC_SET_EVENT:f->object=1;break;
    case PW_WOW_SYNC_RESET_EVENT:f->object=0;break;
    case PW_WOW_SYNC_RELEASE_SEMAPHORE:f->object+=count;break;
    default:assert(0);
    }
    return 1;
}
static struct pw_wow_sync_access access_for(struct fixture *f)
{
    struct pw_wow_sync_access access={f,read_guest,probe_guest,write_guest,publish,finish,cached};
    return access;
}
static void prepare(struct fixture *f,struct pw_wow_sync_registers *state,unsigned op)
{
    uint32_t words[5]={0x41000,0x60000,0x88,BASE+64,0};
    memset(f,0,sizeof(*f));memset(state,0,sizeof(*state));
    for(unsigned i=0;i<8;i++)state->gpr[i]=0x500+i;
    state->gpr[0]=bindings.ids[op];state->gpr[4]=BASE;state->pc=0x40000;state->flags=0xcd7;
    if(op==PW_WOW_SYNC_WAIT){words[3]=0;words[4]=BASE+80;}
    if(op==PW_WOW_SYNC_RELEASE_SEMAPHORE){words[3]=3;words[4]=BASE+64;}
    memcpy(f->memory,words,sizeof(words));f->object=op==2?0u:op==3?1u:7u;
    memset(f->native_fp,0xab,512);memset(f->guest_fp,0xc7,512);
}
static void ordinary_reference(struct fixture *f,struct pw_wow_sync_registers *state,unsigned op)
{
    /* Independent ordinary CPU/Wow64 marshalling order: pop stub return,
     * capture arguments as scalars, execute the selected service, then status. */
    uint32_t frame[5], previous=op==1?1u-f->object:f->object;
    memcpy(frame,f->memory,sizeof(frame));state->pc=frame[0];state->gpr[4]+=4;
    switch(op){
    case 0:assert(!(uint8_t)frame[3]);f->object-=1;break;
    case 1:f->object-=1;break;
    case 2:f->object=1;break;
    case 3:f->object=0;break;
    case 4:f->object+=frame[3];break;
    default:assert(0);
    }
    uint32_t status=0;
    if(op){uint32_t output=frame[op==4?4:3];if(output){
        /* Model the ordinary syscall handler's NTSTATUS return, without
         * generating any real fault or executing Wine's exception path. */
        if(f->write_status)status=f->write_status;
        else memcpy(f->memory+output-BASE,&previous,4);
    }}
    if(f->reset){state->gpr[0]=0x991;state->pc=0x42000;state->gpr[4]=BASE+128;f->guest_fp[17]=0x39;}
    else state->gpr[0]=status;
}
static void check_miss(struct fixture *f,struct pw_wow_sync_registers *state)
{
    struct pw_wow_sync_registers before=*state,canonical=f->canonical;unsigned char before_memory[256];
    memcpy(before_memory,f->memory,256);uint32_t object=f->object,fault=0x771;
    struct pw_wow_sync_access access=access_for(f);
    assert(pw_wow_sync_try(&bindings,&access,state,&fault)==PW_WOW_SYNC_MISS);
    assert(!memcmp(state,&before,sizeof(before)) && !memcmp(before_memory,f->memory,256));
    assert(object==f->object && fault==0x771 && !f->published && !f->writes);
    assert(!memcmp(&canonical,&f->canonical,sizeof(canonical)));
    assert(f->publishes==f->finishes+(unsigned)(f->deny_publish!=0));
}
int main(void)
{
    unsigned successes=0;struct fixture f,reference;struct pw_wow_sync_registers state,expected;
    for(unsigned op=0;op<5;op++)for(unsigned alias=0;alias<4;alias++){
        prepare(&f,&state,op);
        if(op){uint32_t output=alias==0?BASE+64:alias==1?0:alias==2?BASE:BASE+8;
               memcpy(f.memory+(op==4?16:12),&output,4);}
        reference=f;expected=state;ordinary_reference(&reference,&expected,op);
        struct pw_wow_sync_access access=access_for(&f);uint32_t fault=0x881;
        assert(pw_wow_sync_try(&bindings,&access,&state,&fault)==PW_WOW_SYNC_HIT);
        assert(!memcmp(&state,&expected,sizeof(state)) && !memcmp(f.memory,reference.memory,256));
        assert(f.object==reference.object && f.op==op && f.handle==0x88 && f.count==(op==4?3u:0u));
        assert(fault==0x881 && f.calls==1 && f.publishes==1 && f.finishes==1 && !f.published);
        for(unsigned i=0;i<512;i++)assert(f.native_fp[i]==0xab && f.guest_fp[i]==0xc7);
        successes++;
    }
    for(unsigned op=0;op<5;op++)for(unsigned failure=0;failure<5;failure++){
        prepare(&f,&state,op);
        switch(failure){case 0:f.deny_read=1;break;case 1:f.backend_miss=1;break;
                       case 2:f.deny_publish=1;break;case 3:state.gpr[0]=0x1fff;break;
                       case 4:state.gpr[4]=0xffffeffc;break;}
        check_miss(&f,&state);
    }
    prepare(&f,&state,2);f.deny_probe=1;check_miss(&f,&state);assert(!f.calls);
    prepare(&f,&state,0);uint32_t alert=1;memcpy(f.memory+12,&alert,4);check_miss(&f,&state);assert(!f.calls);
    prepare(&f,&state,0);alert=0x100;memcpy(f.memory+12,&alert,4);
    struct pw_wow_sync_access access=access_for(&f);assert(pw_wow_sync_try(&bindings,&access,&state,NULL)==PW_WOW_SYNC_HIT);
    prepare(&f,&state,0);uint32_t timeout=BASE+253;memcpy(f.memory+16,&timeout,4);check_miss(&f,&state);assert(!f.calls);
    for(unsigned i=0;i<3;i++){
        struct pw_wow_sync_bindings invalid=bindings;
        if(i==0)invalid.attested=0;else if(i==1)invalid.ids[3]=invalid.ids[2];else invalid.version++;
        prepare(&f,&state,2);access=access_for(&f);
        assert(pw_wow_sync_try(&invalid,&access,&state,NULL)==PW_WOW_SYNC_MISS && !f.reads && !f.calls);
    }
    const uint32_t statuses[]={0xc0000005u,0x80000001u,0xc0000006u};
    unsigned status_cases=0;
    for(unsigned op=1;op<5;op++)for(unsigned s=0;s<3;s++)for(unsigned reset_case=0;reset_case<2;reset_case++){
        prepare(&f,&state,op);f.write_status=statuses[s];f.reset=reset_case;
        reference=f;expected=state;ordinary_reference(&reference,&expected,op);
        access=access_for(&f);uint32_t fault=0x123;
        assert(pw_wow_sync_try(&bindings,&access,&state,&fault)==
               (reset_case?PW_WOW_SYNC_CONTEXT_RESET:PW_WOW_SYNC_OUTPUT_STATUS));
        assert(!memcmp(&state,&expected,sizeof(state)) && !memcmp(f.memory,reference.memory,256));
        assert(f.object==reference.object && f.calls==1 && f.writes==1 && f.finishes==1 && !f.published);
        assert(!memcmp(&f.canonical,&state,sizeof(state)) && f.guest_fp[17]==reference.guest_fp[17]);
        assert(fault==(reset_case?0x123u:BASE+64));status_cases++;
    }
    for(unsigned miss=0;miss<2;miss++){
        prepare(&f,&state,2);f.reset=1;f.backend_miss=miss;access=access_for(&f);
        assert(pw_wow_sync_try(&bindings,&access,&state,NULL)==PW_WOW_SYNC_CONTEXT_RESET);
        assert(state.gpr[0]==0x991 && state.pc==0x42000 && state.gpr[4]==BASE+128);
        assert(f.guest_fp[17]==0x39 && f.native_fp[17]==0xab && f.finishes==1);
        assert(f.object==(miss?0u:1u));
    }
    printf("PASS: %u ordinary-reference transactions; %u mocked post-CAS NTSTATUS/reset cases; stack/output aliases, 25 misses, BOOLEAN truncation, timeout/output preflight and FP callbacks\n",successes,status_cases);
    return 0;
}
