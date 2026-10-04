/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Bounded valid arithmetic and FP across actual generated-code backends. */
#define _GNU_SOURCE
#include "../src/pw_x86_engine.h"
#include "../src/pw_x86_reencode.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/* A private baseline comparison may allow the old three-lookup crossing. */
#ifndef PW_DISPATCH_LOOKUP_BUDGET
#define PW_DISPATCH_LOOKUP_BUDGET 2
#endif

typedef struct Source {
    uint8_t bytes[50];
} Source;
static unsigned maximum_mixed_lookups;

static int view(void *opaque,uint32_t pc,const uint8_t **bytes,size_t *length)
{
    Source *source=opaque;
    if(pc<0x1000 || pc>=0x1000+sizeof(source->bytes))return PW_ERR_NOT_FOUND;
    *bytes=source->bytes+pc-0x1000;
    *length=sizeof(source->bytes)-(pc-0x1000);
    return PW_OK;
}

static const PwX86CacheEntry *find(const PwX86Engine *engine,uint32_t pc)
{
    /* Observe without charging another lookup to the tested resource budget. */
    for(unsigned i=0;i<engine->cache.capacity;i++) {
        const PwX86CacheEntry *entry=&engine->cache.entries[i];
        if(entry->used && entry->generation==engine->cache.generation && entry->guest_pc==pc)
            return entry;
    }
    return NULL;
}

static void run(PwX86Engine *engine,uint32_t low,unsigned dividend,unsigned *crossings)
{
    PwX86State state={.eip=0x1000,.eflags=2,.stack_low=low,.stack_high=low+0x10000,
                      .memory_count=1};
    state.memory[0]=(PwX86Memory){low,low+0x10000,PW_X86_READ|PW_X86_WRITE};
    state.gpr[4]=low+0x8000;
    state.gpr[6]=low+0x1000;
    pw_guest_fp_init(&state.fp);
    const uint32_t stop=0xeeeeeeee;
    const double value=2.25;
    memcpy((void *)(uintptr_t)state.gpr[4],&stop,4);
    memcpy((void *)(uintptr_t)state.gpr[6],&value,8);
    memset((void *)(uintptr_t)(state.gpr[6]+64),0,32);
    unsigned steps=0;
    while(state.eip!=stop) {
        PwX86StepReport report;
        PwX86LinkSlot *slot=(PwX86LinkSlot *)state.last_exit_slot;
        const PwX86CacheEntry *source=NULL,*target=NULL;
        unsigned crossing=0,resolved=0;
        if(engine->chaining_enabled && slot &&
           !slot->is_linked && slot->target_pc==state.eip) {
            source=find(engine,slot->source_pc);
            target=find(engine,state.eip);
            resolved=source && target;
            crossing=engine->native_fp && resolved &&
                pw_x86_reencoded(&source->exit_contract)!=pw_x86_reencoded(&target->entry_contract);
        }
        uint64_t hits=engine->cache.hits,misses=engine->cache.misses;
        int status=pw_x86_engine_step(engine,&state,&report);
        if(status!=PW_OK || steps>=96)
            fprintf(stderr,"bounded arithmetic harness: status=%d pc=%x steps=%u native_fp=%u chaining=%u ecx=%u\n",
                    status,state.eip,steps,engine->native_fp,engine->chaining_enabled,state.gpr[1]);
        assert(status==PW_OK && ++steps<=96);
        if(resolved) {
            assert(report.cache_hit);
            assert(engine->cache.misses==misses);
            assert(engine->cache.hits-hits<=PW_DISPATCH_LOOKUP_BUDGET);
        }
        if(crossing) {
            assert(!slot->is_linked);
            unsigned lookups=(unsigned)(engine->cache.hits-hits);
            if(lookups>maximum_mixed_lookups)maximum_mixed_lookups=lookups;
            (*crossings)++;
        }
    }
    pw_x86_engine_fp_sync(engine,&state);
    double sum,doubled;
    uint32_t quotient;
    memcpy(&sum,(void *)(uintptr_t)(state.gpr[6]+64),8);
    memcpy(&doubled,(void *)(uintptr_t)(state.gpr[6]+72),8);
    memcpy(&quotient,(void *)(uintptr_t)(state.gpr[6]+80),4);
    assert(sum==(engine->native_fp?5*value:0) &&
           doubled==(engine->native_fp?32*value:0) && quotient==dividend/7);
    assert(state.gpr[0]==dividend/7 && state.gpr[1]==0 && state.gpr[2]==dividend%7);
    assert(state.gpr[3]==7 && state.gpr[4]==low+0x8004 && state.gpr[6]==low+0x1000);
    assert((state.eflags&0x8d5)==0x44 && !state.fp.x87_pending && state.fp.x87_tag==0xffff);
    memcpy(&sum,state.fp.xmm[1],8);
    memcpy(&doubled,state.fp.xmm[2],8);
    assert(sum==(engine->native_fp?5*value:0) && doubled==(engine->native_fp?value:0));
}

int main(void)
{
    /* Five iterations, each with a valid 100/7 divide; both FP accumulators
     * must survive the emitter, which may use the host XMM registers. */
    static const uint8_t program[50]={
        0xf2,0x0f,0x10,0x16,0x66,0x0f,0x57,0xc9,0xdd,0x06,
        0xb9,0x05,0x00,0x00,0x00,0xf2,0x0f,0x58,0xca,
        0xb8,0x64,0x00,0x00,0x00,0x31,0xd2,0xbb,0x07,0x00,0x00,0x00,
        0xf7,0xf3,0xd8,0xc0,0x49,0x75,0xe9,
        0xf2,0x0f,0x11,0x4e,0x40,0xdd,0x5e,0x48,0x89,0x46,0x50,0xc3};
    /* FP arithmetic requires the native-FP backend. Exercise the disabled
     * mode with a separate integer loop using supported emitter forms. */
    static const uint8_t integer_program[50]={
        0xb9,0x05,0x00,0x00,0x00,0xb8,0x64,0x00,0x00,0x00,
        0x31,0xd2,0xbb,0x07,0x00,0x00,0x00,0xf7,0xf3,
        0x49,0x75,0xef,0x89,0x46,0x50,0xc3};
    void *memory=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    assert(memory!=MAP_FAILED && (uintptr_t)memory>=0x10000 &&
           (uintptr_t)memory+0x10000<0x80000000ull);
    uint32_t low=(uint32_t)(uintptr_t)memory;
    unsigned crossings=0;
    for(unsigned native_fp=0;native_fp<2;native_fp++) {
        for(unsigned chaining=0;chaining<2;chaining++) {
            Source source;
            memcpy(source.bytes,native_fp?program:integer_program,sizeof(program));
            PwVmBackend vm;
            PwX86Engine engine;
            PwX86CacheEntry entries[32];
            assert(pw_vm_posix_backend(&vm)==PW_OK);
            assert(pw_x86_engine_init(&engine,&vm,entries,32,1u<<20,1,view,&source)==PW_OK);
            assert(pw_x86_engine_set_chaining(&engine,chaining)==PW_OK);
            assert(pw_x86_engine_set_quantum(&engine,32)==PW_OK);
            assert(pw_x86_engine_set_counters(&engine,0)==PW_OK);
            assert(pw_x86_engine_set_residency(&engine,1)==PW_OK);
            assert(pw_x86_engine_set_lazy_flags(&engine,1)==PW_OK);
            assert(pw_x86_engine_set_indirect(&engine,1)==PW_OK);
            assert(pw_x86_engine_set_flat_memory(&engine,low,low+0x10000)==PW_OK);
            assert(pw_x86_engine_set_reencode(&engine,1)==PW_OK);
            assert(pw_x86_engine_set_global_resident(&engine,0xfb)==PW_OK);
            assert(pw_x86_engine_set_native_fp(&engine,native_fp)==PW_OK);
            for(unsigned generation=1;generation<=3;generation++) {
                if(generation>1)assert(pw_x86_engine_reset(&engine,generation)==PW_OK);
                source.bytes[native_fp?20:6]=(uint8_t)(99+generation);
                run(&engine,low,99+generation,&crossings);
                uint64_t compiles=engine.compiles;
                for(unsigned repeat=0;repeat<4;repeat++) {
                    run(&engine,low,99+generation,&crossings);
                    assert(engine.compiles==compiles);
                }
            }
            assert(pw_x86_engine_destroy(&engine)==PW_OK);
        }
    }
    assert(crossings>=30);
    assert(!munmap(memory,0x10000));
    printf("dispatcher reuse: registers/flags/SSE/x87, warm/cold/reset, FP/chaining modes PASS; %u mixed crossings, maximum %u lookups (budget %u)\n",
           crossings,maximum_mixed_lookups,PW_DISPATCH_LOOKUP_BUDGET);
    return 0;
}
