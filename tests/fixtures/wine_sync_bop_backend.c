/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual native helper bodies; local legal words/cache, no Wine or faults. */
#include "ps5_mutex_backend.h"
#include "ps5_sync_backend.h"
#include "ps5_sync_bop.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#define WINE_INPROCESS_SERVER 1
#define DECLSPEC_EXPORT
#define STATUS_SUCCESS 0u
#define STATUS_NOT_IMPLEMENTED 0xc0000002u
typedef uintptr_t HANDLE;
typedef uintptr_t ULONG_PTR;
typedef uint32_t obj_handle_t;
typedef int32_t LONG;
typedef int64_t timeout_t;
typedef union { int64_t QuadPart; } LARGE_INTEGER;
struct thread_data { uint32_t tid, ps5_mutex_token; };
static _Thread_local struct thread_data local_thread = {1, 7};
static struct thread_data *get_thread_data(void) { return &local_thread; }
static obj_handle_t wine_server_obj_handle(HANDLE h) { return (obj_handle_t)h; }
static uintptr_t mutex_slots[64], sync_slots[64];
static uintptr_t *slot(uintptr_t *slots, uint32_t h, int allocate) {
    assert(!allocate);
    if (!h || h % 4 || h / 4 >= 64) return NULL;
    return &slots[h / 4];
}
static uintptr_t *shared_mutex_slot(uint32_t h,int allocate) { return slot(mutex_slots,h,allocate); }
static uintptr_t *shared_sync_slot(uint32_t h,int allocate) { return slot(sync_slots,h,allocate); }
static _Atomic unsigned fills, sections;
static uintptr_t next_mutex, next_sync;
static uintptr_t shared_mutex_fill(struct thread_data *d,uint32_t h) {
    assert(d==&local_thread); ++fills; return mutex_slots[h / 4]=next_mutex;
}
static uintptr_t shared_sync_fill(struct thread_data *d,uint32_t h) {
    assert(d==&local_thread); ++fills; return sync_slots[h / 4]=next_sync;
}
static pthread_mutex_t fd_cache_mutex=PTHREAD_MUTEX_INITIALIZER;
static void server_enter_uninterrupted_section(pthread_mutex_t *m,sigset_t *s) {
    (void)m; (void)s; ++sections;
}
static void server_leave_uninterrupted_section(pthread_mutex_t *m,sigset_t *s) { (void)m; (void)s; }
static int ready=1;
static const struct pw_mutex_backend mutex_api={.ready=&ready};
static const struct pw_sync_backend sync_api={.ready=&ready};
static const struct pw_mutex_backend *shared_mutex_backend=&mutex_api;
static const struct pw_sync_backend *shared_sync_backend=&sync_api;
#include "actual_helpers.inc"
static const struct pw_sync_bop_backend *bop;
static struct pw_mutex_word mutex_word;
static struct pw_sync_word auto_word,manual_word,semaphore_word;
static void initialize(void) {
    mutex_word.word=0;
    pw_sync_word_init(&auto_word,PW_SYNC_AUTO_EVENT,1,1);
    pw_sync_word_init(&manual_word,PW_SYNC_MANUAL_EVENT,1,1);
    pw_sync_word_init(&semaphore_word,PW_SYNC_SEMAPHORE,1,3);
    assert(pw_sync_word_publish(&auto_word,1));
    assert(pw_sync_word_publish(&manual_word,1));
    assert(pw_sync_word_publish(&semaphore_word,1));
    mutex_slots[1]=(uintptr_t)&mutex_word|PW_MUTEX_SLOT_SYNCHRONIZE;
    sync_slots[1]=PW_SYNC_SLOT_NEGATIVE;
    mutex_slots[2]=mutex_slots[3]=mutex_slots[4]=PW_MUTEX_SLOT_NEGATIVE;
    sync_slots[2]=(uintptr_t)&auto_word|PW_SYNC_SLOT_SYNCHRONIZE|PW_SYNC_SLOT_MODIFY;
    sync_slots[3]=(uintptr_t)&manual_word|PW_SYNC_SLOT_SYNCHRONIZE|PW_SYNC_SLOT_MODIFY;
    sync_slots[4]=(uintptr_t)&semaphore_word|PW_SYNC_SLOT_SYNCHRONIZE|PW_SYNC_SLOT_MODIFY;
}
static void hit(unsigned op,unsigned h,unsigned count,unsigned old) {
    unsigned result=99;
    assert(bop->try_cached(op,h,count,&result));
    assert(result==(op==PW_BOP_SYNC_WAIT?99:old));
}
static void miss(unsigned op,unsigned h,unsigned count) {
    unsigned result=99;
    uint64_t m=pw_mutex_word_load(&mutex_word);
    uint64_t a=pw_sync_word_load(&auto_word),n=pw_sync_word_load(&manual_word),s=pw_sync_word_load(&semaphore_word);
    assert(!bop->try_cached(op,h,count,&result) && result==99);
    assert(m==pw_mutex_word_load(&mutex_word) && a==pw_sync_word_load(&auto_word) &&
           n==pw_sync_word_load(&manual_word) && s==pw_sync_word_load(&semaphore_word));
}
static void abi(void) {
    bop=__wine_ps5_sync_bop_backend(PW_SYNC_BOP_VERSION);
    assert(pw_sync_bop_backend_valid(bop) && !pw_sync_bop_backend_valid(NULL));
    assert(!__wine_ps5_sync_bop_backend(PW_SYNC_BOP_VERSION+1));
    struct pw_sync_bop_backend wrong=*bop;
    ++wrong.version; assert(!pw_sync_bop_backend_valid(&wrong)); wrong=*bop;
    --wrong.size; assert(!pw_sync_bop_backend_valid(&wrong)); wrong=*bop;
    --wrong.pointer_size; assert(!pw_sync_bop_backend_valid(&wrong)); wrong=*bop;
    wrong.operations=0; assert(!pw_sync_bop_backend_valid(&wrong)); wrong=*bop;
    wrong.try_cached=NULL; assert(!pw_sync_bop_backend_valid(&wrong));
}
static unsigned protected_count;
static void *worker(void *arg) {
    local_thread.tid=(unsigned)(uintptr_t)arg; local_thread.ps5_mutex_token=7;
    for (unsigned i=0;i<2000;++i) {
        while (!bop->try_cached(PW_BOP_SYNC_WAIT,16,0,NULL)) sched_yield();
        ++protected_count;
        assert(bop->try_cached(PW_BOP_SYNC_RELEASE_SEMAPHORE,16,1,NULL));
    }
    return NULL;
}
int main(void) {
    abi(); initialize();
    for (unsigned h=0;h<=24;h+=4) miss(99,h,1);
    miss(PW_BOP_SYNC_WAIT,0,0); miss(PW_BOP_SYNC_WAIT,5,0);
    miss(PW_BOP_SYNC_WAIT,UINT32_MAX,0);
    miss(PW_BOP_SYNC_WAIT,20,0); miss(PW_BOP_SYNC_RELEASE_MUTEX,20,0);
    miss(PW_BOP_SYNC_SET_EVENT,20,0); miss(PW_BOP_SYNC_RELEASE_SEMAPHORE,20,1);
    assert(!mutex_slots[5] && !sync_slots[5] && !fills && !sections);
    local_thread.ps5_mutex_token=0; miss(PW_BOP_SYNC_WAIT,4,0); miss(PW_BOP_SYNC_RELEASE_MUTEX,4,0);
    local_thread.ps5_mutex_token=7;
    local_thread.tid=0; miss(PW_BOP_SYNC_WAIT,4,0); miss(PW_BOP_SYNC_WAIT,8,0); local_thread.tid=1;
    ready=0; miss(PW_BOP_SYNC_WAIT,4,0); miss(PW_BOP_SYNC_WAIT,8,0);
    miss(PW_BOP_SYNC_RELEASE_MUTEX,4,0); miss(PW_BOP_SYNC_SET_EVENT,8,0); ready=1;
    shared_mutex_backend=NULL; miss(PW_BOP_SYNC_WAIT,4,0); miss(PW_BOP_SYNC_RELEASE_MUTEX,4,0);
    shared_sync_backend=NULL; miss(PW_BOP_SYNC_WAIT,8,0); miss(PW_BOP_SYNC_SET_EVENT,8,0);
    shared_mutex_backend=&mutex_api; shared_sync_backend=&sync_api;
    hit(PW_BOP_SYNC_WAIT,4,0,0); hit(PW_BOP_SYNC_WAIT,4,0,0);
    hit(PW_BOP_SYNC_RELEASE_MUTEX,4,0,UINT32_MAX); hit(PW_BOP_SYNC_RELEASE_MUTEX,4,0,0);
    miss(PW_BOP_SYNC_RELEASE_MUTEX,4,0);
    local_thread.ps5_mutex_token=9; hit(PW_BOP_SYNC_WAIT,4,0,0);
    local_thread.ps5_mutex_token=7; miss(PW_BOP_SYNC_WAIT,4,0); miss(PW_BOP_SYNC_RELEASE_MUTEX,4,0);
    local_thread.ps5_mutex_token=9; hit(PW_BOP_SYNC_RELEASE_MUTEX,4,0,0); local_thread.ps5_mutex_token=7;
    hit(PW_BOP_SYNC_WAIT,8,0,0); miss(PW_BOP_SYNC_WAIT,8,0);
    hit(PW_BOP_SYNC_SET_EVENT,8,0,0); hit(PW_BOP_SYNC_RESET_EVENT,8,0,1); hit(PW_BOP_SYNC_SET_EVENT,8,0,0);
    hit(PW_BOP_SYNC_WAIT,12,0,0); hit(PW_BOP_SYNC_WAIT,12,0,0);
    hit(PW_BOP_SYNC_RESET_EVENT,12,0,1); miss(PW_BOP_SYNC_WAIT,12,0); hit(PW_BOP_SYNC_SET_EVENT,12,0,0);
    hit(PW_BOP_SYNC_RELEASE_SEMAPHORE,16,2,1); miss(PW_BOP_SYNC_RELEASE_SEMAPHORE,16,1);
    miss(PW_BOP_SYNC_RELEASE_SEMAPHORE,16,0); miss(PW_BOP_SYNC_RELEASE_SEMAPHORE,16,UINT32_MAX);
    miss(PW_BOP_SYNC_SET_EVENT,16,0); miss(PW_BOP_SYNC_RELEASE_SEMAPHORE,8,1);
    hit(PW_BOP_SYNC_WAIT,16,0,0); hit(PW_BOP_SYNC_WAIT,16,0,0);
    for (unsigned i=0;i<3000;++i) {
        hit(PW_BOP_SYNC_WAIT,4,0,0); hit(PW_BOP_SYNC_RELEASE_MUTEX,4,0,0);
        hit(PW_BOP_SYNC_WAIT,8,0,0); hit(PW_BOP_SYNC_SET_EVENT,8,0,0);
        hit(PW_BOP_SYNC_RESET_EVENT,12,0,1); hit(PW_BOP_SYNC_SET_EVENT,12,0,0);
        hit(PW_BOP_SYNC_WAIT,16,0,0); hit(PW_BOP_SYNC_RELEASE_SEMAPHORE,16,1,0);
    }
    for (unsigned kind=1;kind<=3;++kind) for (unsigned permissions=0;permissions<4;++permissions) {
        struct pw_sync_word word; unsigned h=24;
        pw_sync_word_init(&word,kind,1,kind==PW_SYNC_SEMAPHORE?2:1); assert(pw_sync_word_publish(&word,1));
        sync_slots[h/4]=(uintptr_t)&word | (permissions&1 ? PW_SYNC_SLOT_SYNCHRONIZE:0) |
            (permissions&2 ? PW_SYNC_SLOT_MODIFY:0); mutex_slots[h/4]=PW_MUTEX_SLOT_NEGATIVE;
        unsigned old=99; int success=bop->try_cached(PW_BOP_SYNC_WAIT,h,0,&old);
        assert(success==!!(permissions&1) && old==99);
        unsigned state=kind==PW_SYNC_MANUAL_EVENT || !success ? 1:0;
        assert(pw_sync_word_load(&word)==state);
        success=bop->try_cached(kind==PW_SYNC_SEMAPHORE?PW_BOP_SYNC_RELEASE_SEMAPHORE:PW_BOP_SYNC_SET_EVENT,h,1,&old);
        assert(success==!!(permissions&2) && old==(success?state:99));
        sync_slots[h/4]=0;
    }
    uintptr_t saved=mutex_slots[1]; mutex_slots[1]&=~PW_MUTEX_SLOT_SYNCHRONIZE;
    miss(PW_BOP_SYNC_WAIT,4,0); mutex_slots[1]=saved;
    uint64_t m; uint32_t s; assert(pw_mutex_word_freeze(&mutex_word,&m));
    miss(PW_BOP_SYNC_WAIT,4,0); miss(PW_BOP_SYNC_RELEASE_MUTEX,4,0); pw_mutex_word_publish(&mutex_word,m);
    assert(pw_sync_word_freeze(&auto_word,&s)); miss(PW_BOP_SYNC_WAIT,8,0); miss(PW_BOP_SYNC_SET_EVENT,8,0);
    assert(pw_sync_word_publish(&auto_word,s));
    /* Simulate the existing under-lock invalidation: retired cell, empty slot,
     * then ordinary fill. Warm entry must not resurrect or fill the stale handle. */
    assert(pw_sync_word_freeze(&auto_word,&s)); sync_slots[2]=0;
    miss(PW_BOP_SYNC_SET_EVENT,8,0); assert(!sync_slots[2]);
    struct pw_sync_word replacement; pw_sync_word_init(&replacement,PW_SYNC_MANUAL_EVENT,1,1);
    assert(pw_sync_word_publish(&replacement,1)); sync_slots[2]=(uintptr_t)&replacement|6;
    hit(PW_BOP_SYNC_WAIT,8,0,0); assert(pw_sync_word_load(&auto_word)&PW_SYNC_WORD_SLOW);
    assert(!fills && !sections);
    /* Both original wrappers keep their ordinary cold-fill behavior. */
    next_mutex=(uintptr_t)&mutex_word|PW_MUTEX_SLOT_SYNCHRONIZE;
    next_sync=(uintptr_t)&manual_word|PW_SYNC_SLOT_SYNCHRONIZE|PW_SYNC_SLOT_MODIFY;
    assert(server_try_shared_mutex(20,0,NULL,NULL)==STATUS_SUCCESS);
    assert(server_try_shared_sync_inprocess(20,PW_SYNC_WAIT,0,NULL,NULL)==STATUS_SUCCESS);
    assert(fills==2 && sections==2); hit(PW_BOP_SYNC_RELEASE_MUTEX,20,0,0);
    unsigned before_fills=fills,before_sections=sections;
    pw_sync_word_freeze(&semaphore_word,&s); assert(pw_sync_word_publish(&semaphore_word,1));
    pthread_t threads[4];
    for (unsigned i=0;i<4;++i) assert(!pthread_create(&threads[i],NULL,worker,(void *)(uintptr_t)(10+i)));
    for (unsigned i=0;i<4;++i) assert(!pthread_join(threads[i],NULL));
    assert(protected_count==8000 && pw_sync_word_load(&semaphore_word)==1);
    assert(fills==before_fills && sections==before_sections);
    puts("PASS: exact native ABI/helper bodies, 24000 warm operations, fallback/access/retirement/reuse, original cold wrappers, 8000 concurrent semaphore sections");
    return 0;
}
