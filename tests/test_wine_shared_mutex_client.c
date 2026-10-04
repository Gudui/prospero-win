/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual client bodies, native local metadata and ordinary legal lifecycle.
 * No Wine, application faults, signals or asynchronous termination. */
#define _GNU_SOURCE
#include "ps5_mutex_backend.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define WINE_INPROCESS_SERVER 1
#define STATUS_SUCCESS 0u
#define STATUS_NOT_IMPLEMENTED 0xc0000002u
#define SYNCHRONIZE 0x100000u
typedef uint32_t obj_handle_t;
typedef uintptr_t HANDLE;
typedef int32_t LONG;
typedef int64_t timeout_t;
typedef union { int64_t QuadPart; } LARGE_INTEGER;
struct thread_data { unsigned tid, ps5_mutex_token; };
static _Thread_local struct thread_data fixture_thread={.tid=1};
static struct thread_data *get_thread_data(void) { return &fixture_thread; }
static obj_handle_t wine_server_obj_handle(HANDLE h) { return (obj_handle_t)h; }
static uint64_t inprocess_teb(void) { return (uint64_t)(uintptr_t)&fixture_thread; }
static pthread_mutex_t fd_cache_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Atomic unsigned cold_calls, sections;
static _Thread_local unsigned section_depth;
static void *pages[8]; static unsigned page_count;
static void *anon_mmap_alloc(size_t size,int prot) {
    assert(prot==(PROT_READ|PROT_WRITE) && page_count<8);
    void *p=calloc(1,size); if (!p) return MAP_FAILED; pages[page_count++]=p; return p;
}
static void server_enter_uninterrupted_section(pthread_mutex_t *lock,sigset_t *set) {
    (void)set; assert(!pthread_mutex_lock(lock)); ++section_depth; atomic_fetch_add(&sections,1);
}
static void server_leave_uninterrupted_section(pthread_mutex_t *lock,sigset_t *set) {
    (void)set; assert(section_depth); --section_depth; assert(!pthread_mutex_unlock(lock));
}
struct node { struct pw_mutex_word word; unsigned handle,kind,access; };
static struct node nodes[100]; static unsigned node_count;
static int ready=1, retry_once;
#define DECLSPEC_EXPORT
#define TERMINATED 1
#define inprocess_direct_ok ready
struct thread { uint64_t teb; unsigned id,state,error,refs,req_toread,reply_towrite;
    int reply_fd; void *req_data,*reply_data; };
static struct thread server_threads[256];
static struct thread *current;
static unsigned global_error=7,server_depth;
static int debug_level;
static unsigned missing_tid,thread_lookups,gate_checks;
static int allow_thread=1;
static pthread_mutex_t inprocess_server_mutex=PTHREAD_MUTEX_INITIALIZER;
static struct thread *get_thread_from_id(unsigned tid) {
    assert(tid<256); struct thread *t=&server_threads[tid];
    ++thread_lookups;
    if (tid==missing_tid) { global_error=11; return NULL; }
    if (!t->id) { t->id=tid; t->teb=inprocess_teb(); t->reply_fd=1; t->error=9; }
    ++t->refs; return t;
}
static int thread_can_fast_mutex(struct thread *t) { (void)t; return allow_thread; }
static void release_object(struct thread *t) { assert(t->refs); --t->refs; }
static void clear_error(void) { global_error=0; if (current) current->error=0; }
static void ps5_mutex_server_begin(void) { ++server_depth; }
static void ps5_mutex_server_end(void) { assert(server_depth); --server_depth; }
static void ps5_mutex_server_reconcile(void) { assert(!server_depth); }
static int mock_get_word(uint32_t version,uint32_t tid,uint64_t teb,uint32_t handle,
                         struct pw_mutex_word **word,uint32_t *token,uint32_t *access) {
    assert(version==PW_MUTEX_BACKEND_VERSION && tid && teb);
    atomic_fetch_add(&cold_calls,1);
    if (retry_once) { retry_once=0; return PW_MUTEX_LOOKUP_RETRY; }
    for (unsigned i=0;i<node_count;i++) if (nodes[i].handle==handle) {
        if (!nodes[i].kind) return PW_MUTEX_LOOKUP_NEGATIVE;
        *word=&nodes[i].word; *token=100+tid; *access=nodes[i].access;
        return PW_MUTEX_LOOKUP_READY;
    }
    return PW_MUTEX_LOOKUP_RETRY;
}
static int ps5_describe_mutex_word(struct thread *t,obj_handle_t handle,
                                   struct pw_mutex_word **word,unsigned *token,unsigned *access) {
    assert(current==t && t->error==0 && global_error==0 && server_depth==1);
    return mock_get_word(PW_MUTEX_BACKEND_VERSION,t->id,t->teb,handle,word,token,access);
}
#include "shared_mutex_server_abi.inc"
static const struct pw_mutex_backend *shared_mutex_backend;
#include "shared_mutex_client.inc"
static const char *config_dir;
#include "shared_mutex_switch.inc"

/* Compile the actual NtCreateMutant body with native request/attribute
 * callbacks. Caller buffers are valid local storage; no Wine or faults. */
typedef uint32_t NTSTATUS;
typedef uint32_t ACCESS_MASK;
typedef unsigned BOOLEAN;
typedef unsigned data_size_t;
#define OBJ_INHERIT 2u
#define WINAPI
#define TRACE(...) ((void)0)
typedef struct { unsigned Attributes, name_len; } OBJECT_ATTRIBUTES;
struct object_attributes { unsigned attributes, name_len; };
static struct { unsigned access, owned; } create_request;
static struct { unsigned handle; } create_reply;
static unsigned create_handle=6000,create_status,alloc_status,create_calls;
#define SERVER_START_REQ(kind) do { typeof(create_request) *req=&create_request; typeof(create_reply) *reply=&create_reply;
#define SERVER_END_REQ } while(0)
static NTSTATUS wine_server_alloc_object_attributes(const OBJECT_ATTRIBUTES *attr,
                                                     struct object_attributes **out,data_size_t *size) {
    if (alloc_status) return alloc_status;
    *out=calloc(1,sizeof(**out)); assert(*out); *size=sizeof(**out);
    if (attr) { (*out)->attributes=attr->Attributes; (*out)->name_len=attr->name_len; }
    return 0;
}
static void wine_server_add_data(void *request,const void *data,unsigned size) {
    assert(request==&create_request && data && size==sizeof(struct object_attributes));
}
static NTSTATUS wine_server_call(void *request) {
    assert(request==&create_request && section_depth==(unsigned)server_shared_mutex_enabled());
    create_reply.handle=(int32_t)create_status<0 ? 0 : create_handle; ++create_calls; return create_status;
}
static HANDLE wine_server_ptr_handle(unsigned h) { return h; }
static void server_clear_fast_mutex_hint(HANDLE h) { (void)h; }
#include "shared_mutex_create.inc"

static void mark_candidate(HANDLE handle) {
    sigset_t set; server_enter_uninterrupted_section(&fd_cache_mutex,&set);
    server_init_shared_mutex_slot(handle,1);
    server_leave_uninterrupted_section(&fd_cache_mutex,&set);
}
static unsigned admission_checks;
static void observe_probation(HANDLE handle) {
    uintptr_t *slot=shared_mutex_slot(handle,0);
    assert(slot && __atomic_load_n(slot,__ATOMIC_ACQUIRE)==PW_MUTEX_SLOT_CANDIDATE);
    unsigned calls=cold_calls,locks=sections,token=fixture_thread.ps5_mutex_token;
    LARGE_INTEGER timeout={.QuadPart=0}; LONG previous=99;
    for (unsigned i=0;i<PW_MUTEX_ORDINARY_ATTEMPTS;i++) {
        assert(server_try_shared_mutex(handle,i&1,&timeout,&previous)==STATUS_NOT_IMPLEMENTED);
        assert(__atomic_load_n(slot,__ATOMIC_ACQUIRE)==PW_MUTEX_SLOT_CANDIDATE+4u*(i+1));
        assert(previous==99 && !timeout.QuadPart && fixture_thread.ps5_mutex_token==token);
        assert(cold_calls==calls && sections==locks && !section_depth);
        ++admission_checks;
    }
    assert(__atomic_load_n(slot,__ATOMIC_ACQUIRE)==PW_MUTEX_SLOT_CANDIDATE_READY);
}
static void prime_candidate(HANDLE handle) { mark_candidate(handle); observe_probation(handle); }

static void expect_no_probe(HANDLE handle) {
    unsigned cold_before=cold_calls,sections_before=sections;
    for (unsigned i=0;i<100;i++) {
        assert(server_try_shared_mutex(handle,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
        assert(server_try_shared_mutex(handle,1,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    }
    assert(cold_calls==cold_before && sections==sections_before);
}
static void test_creation(void) {
    HANDLE result=99; unsigned before=sections,calls=create_calls;
    const struct pw_mutex_backend *api=shared_mutex_backend;
    shared_mutex_backend=NULL;
    assert(!server_shared_mutex_enabled());
    assert(!NtCreateMutant(&result,SYNCHRONIZE,NULL,0) && result==create_handle);
    assert(sections==before && !shared_mutex_slot(create_handle,0));
    shared_mutex_backend=api;
    assert(server_shared_mutex_enabled());
    assert(!NtCreateMutant(&result,SYNCHRONIZE,NULL,0));
    uintptr_t *slot=shared_mutex_slot(result,0); assert(slot && *slot==PW_MUTEX_SLOT_CANDIDATE);
    assert(create_request.access==SYNCHRONIZE && !create_request.owned && !section_depth);
    /* A newly created handle resets a stale negative, and published output
     * is ordinary caller storage after the uninterrupted section ends. */
    __atomic_store_n(slot,PW_MUTEX_SLOT_NEGATIVE,__ATOMIC_RELEASE);
    assert(!NtCreateMutant(&result,0,NULL,1) && *slot==PW_MUTEX_SLOT_CANDIDATE);
    assert(!create_request.access && create_request.owned);
    OBJECT_ATTRIBUTES named={.name_len=8},inherited={.Attributes=OBJ_INHERIT};
    assert(!NtCreateMutant(&result,SYNCHRONIZE,&named,0) && !*slot); expect_no_probe(result);
    assert(!NtCreateMutant(&result,SYNCHRONIZE,&inherited,0) && !*slot); expect_no_probe(result);
    /* Selection remains on before native readiness: publish a marker for
     * later lookup, while current operations immediately fall through. */
    __atomic_store_n(&ready,0,__ATOMIC_RELEASE);
    assert(server_shared_mutex_enabled() && !NtCreateMutant(&result,0,NULL,0));
    assert(*slot==PW_MUTEX_SLOT_CANDIDATE); expect_no_probe(result);
    __atomic_store_n(&ready,1,__ATOMIC_RELEASE);
    create_status=0x40000000u; /* Existing named object: informational success. */
    assert(NtCreateMutant(&result,0,&named,0)==create_status && result==create_handle && !*slot);
    create_status=0xc000000du;
    assert(NtCreateMutant(&result,0,NULL,0)==create_status && !result);
    create_status=0; alloc_status=0xc000000du; before=sections;
    assert(NtCreateMutant(&result,0,NULL,0)==alloc_status && !result);
    assert(sections==before && !section_depth); alloc_status=0;
    assert(create_calls==calls+8);
}

static void write_switch(const char *name,const char *value) {
    char *path; assert(asprintf(&path,"%s/%s",config_dir,name)>0);
    FILE *f=fopen(path,"w"); assert(f);
    assert(fputs(value,f)>=0 && !fclose(f)); free(path);
}
static void remove_switch(const char *name) {
    char *path; assert(asprintf(&path,"%s/%s",config_dir,name)>0);
    assert(!remove(path)); free(path);
}
static void test_switches(void) {
    const char *envs[]={"WINE_PS5_MUTEX_FAST","WINE_PS5_MUTEX_SHARED"};
    const char *files[]={"pw_mutex_fast","pw_mutex_shared"};
    const char *values[]={"","0","1","1\n","11","1\nextra","on","1\r\n"};
    for (unsigned lane=0;lane<2;lane++) {
        assert(!unsetenv(envs[lane]));
        assert(!server_mutex_switch_enabled(envs[lane],files[lane]));
        for (unsigned i=0;i<8;i++) {
            write_switch(files[lane],values[i]);
            assert(server_mutex_switch_enabled(envs[lane],files[lane])==(i==2 || i==3));
            assert(!setenv(envs[lane],"0",1));
            assert(!server_mutex_switch_enabled(envs[lane],files[lane]));
            assert(!setenv(envs[lane],"1",1));
            assert(server_mutex_switch_enabled(envs[lane],files[lane]));
            assert(!setenv(envs[lane],"on",1));
            assert(!server_mutex_switch_enabled(envs[lane],files[lane]));
            assert(!unsetenv(envs[lane]));
        }
        remove_switch(files[lane]);
    }
    write_switch(files[0],"1");
    assert(server_mutex_switch_enabled(envs[0],files[0]));
    assert(!server_mutex_switch_enabled(envs[1],files[1]));
    write_switch(files[1],"1");
    assert(!setenv(envs[0],"0",1));
    assert(!server_mutex_switch_enabled(envs[0],files[0]));
    assert(server_mutex_switch_enabled(envs[1],files[1]));
    assert(!unsetenv(envs[0]));
    remove_switch(files[0]); remove_switch(files[1]);
}

static struct node *node(unsigned handle,unsigned kind,unsigned access) {
    assert(node_count<100); struct node *n=&nodes[node_count++];
    n->handle=handle; n->kind=kind; n->access=access; return n;
}
static void expect_lookup_retry(const struct pw_mutex_backend *api,uint32_t version,uint64_t teb) {
    struct pw_mutex_word *word=&nodes[0].word;
    uint32_t token=23,access=47;
    unsigned before=cold_calls;
    struct thread *saved_current=current;
    assert(api->get_word(version,1,teb,4,&word,&token,&access)==PW_MUTEX_LOOKUP_RETRY);
    assert(word==&nodes[0].word && token==23 && access==47);
    assert(cold_calls==before && global_error==7 && !server_depth);
    assert(current==saved_current && !server_threads[1].refs && server_threads[1].error==9);
    assert(!pw_mutex_word_load(&nodes[0].word));
    ++gate_checks;
}
static void test_lookup_gates(const struct pw_mutex_backend *api) {
    struct thread *t=get_thread_from_id(1); release_object(t);
    unsigned lookups=thread_lookups;
    uint64_t teb=inprocess_teb(),saved_teb=t->teb;
    int data;
    expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION+1,teb);
    __atomic_store_n(&ready,0,__ATOMIC_RELEASE);
    expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb);
    __atomic_store_n(&ready,1,__ATOMIC_RELEASE);
    assert(!pthread_mutex_lock(&inprocess_server_mutex));
    expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb);
    assert(!pthread_mutex_unlock(&inprocess_server_mutex));
    current=t; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); current=NULL;
    debug_level=1; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); debug_level=0;
    assert(thread_lookups==lookups);
    missing_tid=1; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); missing_tid=0;
    t->teb=0; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->teb=saved_teb;
    expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,0);
    /* Fixture state only; no actual thread is terminated or signaled. */
    t->state=TERMINATED; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->state=0;
    t->reply_fd=0; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->reply_fd=1;
    t->req_toread=1; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->req_toread=0;
    t->reply_towrite=1; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->reply_towrite=0;
    t->req_data=&data; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->req_data=NULL;
    t->reply_data=&data; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); t->reply_data=NULL;
    allow_thread=0; expect_lookup_retry(api,PW_MUTEX_BACKEND_VERSION,teb); allow_thread=1;
    assert(gate_checks==15 && thread_lookups==lookups+10);
}
static void take_release(HANDLE handle) {
    assert(server_try_shared_mutex(handle,0,NULL,NULL)==STATUS_SUCCESS);
    assert(server_try_shared_mutex(handle,1,NULL,NULL)==STATUS_SUCCESS);
}
static pthread_barrier_t admission_barrier;
static unsigned admission_counter;
static void *admission_worker(void *arg) {
    fixture_thread=(struct thread_data){.tid=(unsigned)(uintptr_t)arg};
    int result=pthread_barrier_wait(&admission_barrier);
    assert(!result || result==PTHREAD_BARRIER_SERIAL_THREAD);
    for (unsigned i=0;i<64;i++) {
        if (server_try_shared_mutex(1804,0,NULL,NULL)==STATUS_SUCCESS) {
            ++admission_counter;
            assert(server_try_shared_mutex(1804,1,NULL,NULL)==STATUS_SUCCESS);
        }
    }
    return NULL;
}
static void test_admission(void) {
    struct node *short_lived=node(1800,1,SYNCHRONIZE);
    unsigned calls=cold_calls,locks=sections;
    /* Ten ordinary close/create cycles with four hook attempts each must
     * never perform metadata lookup or mutate a shared ownership word. */
    for (unsigned cycle=0;cycle<10;cycle++) {
        mark_candidate(1800); locks=sections;
        LONG previous=99;
        for (unsigned i=0;i<4;i++) {
            assert(server_try_shared_mutex(1800,i&1,NULL,&previous)==STATUS_NOT_IMPLEMENTED);
            assert(previous==99 && cold_calls==calls && sections==locks);
            assert(!pw_mutex_word_load(&short_lived->word)); ++admission_checks;
        }
        assert(!pthread_mutex_lock(&fd_cache_mutex));
        server_clear_shared_mutex_slot(1800);
        assert(!pthread_mutex_unlock(&fd_cache_mutex));
        assert(!__atomic_load_n(shared_mutex_slot(1800,0),__ATOMIC_ACQUIRE));
    }
    /* The actual cold fill must recheck creation's fresh probation marker,
     * even when a caller observed a ready marker before taking the lock. */
    prime_candidate(1800); calls=cold_calls;
    sigset_t set; server_enter_uninterrupted_section(&fd_cache_mutex,&set);
    server_init_shared_mutex_slot(1800,1);
    assert(!shared_mutex_fill(get_thread_data(),1800));
    assert(__atomic_load_n(shared_mutex_slot(1800,0),__ATOMIC_ACQUIRE)==PW_MUTEX_SLOT_CANDIDATE);
    assert(cold_calls==calls); server_leave_uninterrupted_section(&fd_cache_mutex,&set); ++admission_checks;
    observe_probation(1800); take_release(1800);
    /* Concurrent admission never turns an integer tag into a word pointer
     * and eventually installs one canonical cell for live threads. */
    struct node *concurrent=node(1804,1,SYNCHRONIZE); mark_candidate(1804);
    assert(!pthread_barrier_init(&admission_barrier,NULL,4));
    pthread_t threads[4];
    for (unsigned i=0;i<4;i++) assert(!pthread_create(&threads[i],NULL,admission_worker,(void *)(uintptr_t)(30+i)));
    for (unsigned i=0;i<4;i++) assert(!pthread_join(threads[i],NULL));
    assert(!pthread_barrier_destroy(&admission_barrier));
    assert(admission_counter && !pw_mutex_word_load(&concurrent->word));
    uintptr_t value=__atomic_load_n(shared_mutex_slot(1804,0),__ATOMIC_ACQUIRE);
    assert(!shared_mutex_is_candidate(value) && pw_mutex_slot_word(value)==&concurrent->word);
    ++admission_checks;
}

static unsigned protected_counter;
static void *worker(void *arg) {
    fixture_thread=(struct thread_data){.tid=(unsigned)(uintptr_t)arg};
    for (unsigned i=0;i<3000;i++) {
        while (server_try_shared_mutex(4,0,NULL,NULL)!=STATUS_SUCCESS) sched_yield();
        ++protected_counter;
        assert(server_try_shared_mutex(4,1,NULL,NULL)==STATUS_SUCCESS);
    }
    return NULL;
}
int main(int argc,char **argv) {
    assert(argc==2); config_dir=argv[1]; test_switches();
    /* Native ABI mismatch discovery never invokes metadata or reads a word. */
    const struct pw_mutex_backend *api=pw_wineserver_mutex_backend(PW_MUTEX_BACKEND_VERSION);
    assert(api && !pw_wineserver_mutex_backend(PW_MUTEX_BACKEND_VERSION+1));
    shared_mutex_backend=api;
    assert(pw_mutex_backend_valid(api) && !pw_mutex_backend_valid(NULL));
    struct pw_mutex_backend wrong=*api;
    wrong.version++; assert(!pw_mutex_backend_valid(&wrong)); wrong=*api;
    wrong.size--; assert(!pw_mutex_backend_valid(&wrong)); wrong=*api;
    wrong.word_size--; assert(!pw_mutex_backend_valid(&wrong)); wrong=*api;
    wrong.pointer_size--; assert(!pw_mutex_backend_valid(&wrong)); wrong=*api;
    wrong.ready=NULL; assert(!pw_mutex_backend_valid(&wrong)); wrong=*api;
    wrong.get_word=NULL; assert(!pw_mutex_backend_valid(&wrong));
    struct node *first=node(4,1,SYNCHRONIZE);
    test_lookup_gates(api);
    /* Unknown events/pseudo/out-of-table values never enter a cold section. */
    expect_no_probe(4); expect_no_probe(0); expect_no_probe((HANDLE)-1);
    expect_no_probe((HANDLE)-2); expect_no_probe(5556);
    expect_no_probe(4u*(PW_MUTEX_CACHE_PAGES*PW_MUTEX_CACHE_SLOTS+1u));
    test_creation();
    unsigned first_sections=sections; prime_candidate(4);
    take_release(4); assert(fixture_thread.ps5_mutex_token==101 && cold_calls==1 && sections==first_sections+2);
    assert(global_error==7 && server_threads[1].error==9 && !server_threads[1].refs && !current);
    unsigned cold_before=cold_calls, sections_before=sections;
    for (unsigned i=0;i<12000;i++) take_release(4);
    assert(cold_calls==cold_before && sections==sections_before && !pw_mutex_word_load(&first->word));
    /* Recursion and the caller's valid local previous-count storage. */
    LARGE_INTEGER expired={.QuadPart=0}; LONG previous=99;
    assert(server_try_shared_mutex(4,0,&expired,NULL)==STATUS_SUCCESS);
    assert(server_try_shared_mutex(4,0,NULL,NULL)==STATUS_SUCCESS);
    assert(server_try_shared_mutex(4,1,NULL,&previous)==STATUS_SUCCESS && previous==-1);
    assert(server_try_shared_mutex(4,1,NULL,&previous)==STATUS_SUCCESS && previous==0);
    /* Zero wait access cannot acquire, while release keeps Wine access 0. */
    struct node *without_access=node(8,1,0);
    prime_candidate(8);
    assert(server_try_shared_mutex(8,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    assert(!pw_mutex_word_load(&without_access->word));
    assert(pw_mutex_word_try_acquire(&without_access->word,fixture_thread.ps5_mutex_token));
    assert(server_try_shared_mutex(8,1,NULL,NULL)==STATUS_SUCCESS);
    /* Server-side reuse can turn a marked candidate into an event. More
     * than 64 such valid negatives retain independent exact slots. */
    for (unsigned i=0;i<80;i++) {
        unsigned h=1000+4*i; node(h,0,0); prime_candidate(h);
        assert(server_try_shared_mutex(h,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    }
    cold_before=cold_calls; sections_before=sections;
    for (unsigned pass=0;pass<25;pass++) for (unsigned i=0;i<80;i++)
        assert(server_try_shared_mutex(1000+4*i,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    assert(cold_calls==cold_before && sections==sections_before);
    /* A reused negative becomes a candidate on eligible mutant creation. */
    nodes[2].kind=1; nodes[2].access=SYNCHRONIZE; prime_candidate(1000); take_release(1000);
    /* A valid cold retry must not create a lasting negative. */
    struct node *retry=node(1400,1,SYNCHRONIZE); retry_once=1;
    prime_candidate(1400);
    assert(server_try_shared_mutex(1400,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    assert(__atomic_load_n(shared_mutex_slot(1400,0),__ATOMIC_ACQUIRE)==PW_MUTEX_SLOT_CANDIDATE_READY); take_release(1400);
    assert(!pw_mutex_word_load(&retry->word));
    /* A second page is allocated only on candidate creation. */
    unsigned high=4*(PW_MUTEX_CACHE_SLOTS+7)+4; node(high,1,SYNCHRONIZE); prime_candidate(high); take_release(high);
    assert(page_count==1); cold_before=cold_calls; sections_before=sections; take_release(high);
    assert(cold_calls==cold_before && sections==sections_before);
    /* Readiness downgrade is a fallback with zero extra cold calls/locks. */
    __atomic_store_n(&ready,0,__ATOMIC_RELEASE); cold_before=cold_calls; sections_before=sections;
    assert(server_try_shared_mutex(4,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    assert(cold_calls==cold_before && sections==sections_before && !pw_mutex_word_load(&first->word));
    __atomic_store_n(&ready,1,__ATOMIC_RELEASE);
    /* Temporary ordinary SLOW mode can recover without a cache refill. */
    uint64_t snapshot;
    assert(pw_mutex_word_freeze(&first->word,&snapshot) && !snapshot);
    cold_before=cold_calls; sections_before=sections;
    assert(server_try_shared_mutex(4,0,NULL,NULL)==STATUS_NOT_IMPLEMENTED);
    assert(cold_calls==cold_before && sections==sections_before);
    pw_mutex_word_publish(&first->word,0); take_release(4);
    assert(cold_calls==cold_before && sections==sections_before);
    /* Complete ordinary close/invalidation then reuse for a different cell.
     * Retired storage is retained and never recycled by the fixture. */
    assert(!pthread_mutex_lock(&fd_cache_mutex));
    uint64_t old; pw_mutex_word_freeze(&first->word,&old); first->handle=0;
    server_clear_shared_mutex_slot(4); struct node *replacement=node(4,1,SYNCHRONIZE);
    server_init_shared_mutex_slot(4,1);
    assert(!pthread_mutex_unlock(&fd_cache_mutex)); observe_probation(4); take_release(4);
    assert(pw_mutex_word_load(&first->word)&PW_MUTEX_WORD_SLOW);
    assert(!pw_mutex_word_load(&replacement->word));
    test_admission();
    /* Legal concurrent ownership on the real client/CAS path. Each live
     * thread needs its own token even when another filled the shared slot. */
    pthread_t threads[4];
    for (unsigned i=0;i<4;i++) assert(!pthread_create(&threads[i],NULL,worker,(void *)(uintptr_t)(10+i)));
    for (unsigned i=0;i<4;i++) assert(!pthread_join(threads[i],NULL));
    assert(protected_counter==12000 && !pw_mutex_word_load(&replacement->word));
    assert(global_error==7 && !current && !server_depth);
    for (unsigned i=0;i<256;i++) assert(!server_threads[i].refs);
    for (unsigned i=0;i<page_count;i++) free(pages[i]);
    printf("PASS: actual creation gate, unknown/pseudo/out-of-table immediate fallback, strict independent switches, 15 lookup gates, 24000 warm hits without cold calls/locks, 80 exact negatives, legal lifecycle, 12000 concurrent sections\n");
    printf("PASS: %u admission checks, short-lived fallback, reuse recheck and concurrent canonical fill\n",admission_checks);
    return 0;
}
