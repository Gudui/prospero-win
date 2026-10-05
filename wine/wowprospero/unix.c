/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * prospero-win WoW64 CPU backend, Unix side: owns one IA-32 DBT engine per
 * host thread and runs guest code from the canonical I386_CONTEXT until EIP
 * reaches a BOP address or the engine reports a fault.
 */
#if 0
#pragma makedep unix
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#if defined(__linux__)
#include <ucontext.h>
#endif
#include <sys/stat.h>
#include <time.h>
#include <x86intrin.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/unixlib.h"
#include "wowprospero.h"

#include "pw_x86_engine.h"
#include "pw_x86_reencode.h"
#include "pw_guest_fp.h"
#include "pw_x86_hostexec.h"
#include "code_pages.h"
#include "thread_budget.h"
#include "tsc_clock.h"
#include "host_memory.h"
#ifdef __PROSPERO__
#include "wine/ps5_sync_bop.h"
#include "wine/ps5_sync_bop_context.h"
#include "wine/ps5_sync_bop_memory.h"
#include "wine/ps5_sync_bop_pending.h"
#include "sync_bop_bindings.h"
#endif

/* The guest range every translated access is checked against (load_state). */
enum { GUEST_LOW = 0x10000u, GUEST_HIGH = 0xfffff000u };
/* The guest GPRs held in host registers across linked blocks: seven fit, and
 * leaving out EDX measured best on 7-Zip (docs/DBT_BENCHMARK.md), unless
 * PW_WOW_RESIDENT names others. */
enum { GLOBAL_RESIDENT = 0xfb };
/* Linked blocks per dispatcher return (docs/DBT_BENCHMARK.md). */
enum { QUANTUM = 1024 };
/* Host return addresses of the guest calls in a chain (the engine's call
 * stack): 32768 nested calls, beyond which the stack starts again. */
enum { CALL_STACK = 0x40000 };

struct pw_thread
{
    PwVmBackend vm;
    PwX86Engine engine;
    PwX86State state;
    uint64_t generation;     /* code_generation this cache was built for */
    uint32_t cache_epoch;    /* engine generation, bumped on every reset */
    uint64_t cache_publishes_at_reset, cache_report_id;
    uint32_t trace;          /* PW_WOW_TRACE: quantum 1 and an EIP ring */
    uint32_t prefer_host;    /* PW_WOW_HOSTEXEC_ALL: reference execution */
    uint32_t ring[64], ring_pos;
    PwX86HostExec hostexec;  /* single-instruction fallback */
    /* Last committed, readable region NtQueryVirtualMemory reported, valid
     * for readable_generation: consecutive blocks rarely leave it. */
    uintptr_t readable_low, readable_high;
    uint64_t readable_generation;
    uint64_t readable_queries, readable_hits;
    PwX86CacheEntry *entries;  /* the budget's count (thread_budget.h) */
    void *call_stack;          /* guard, then CALL_STACK bytes, or NULL */
    /* PW_WOW_TIMING: TSC cycles spent inside run(), and outside it by the
     * reason the previous run returned for, since t_window. */
    uint64_t t_mark, t_window, t_inside, t_unix, t_sys, t_other, t_unix_long;
    uint64_t wall_window;
    double tsc_per_us;       /* measured at the last report */
    uint32_t n_unix, n_sys, n_other, n_unix_long, n_resets, n_flushes, last_reason;
    PwX86HotspotProfile *profile;
    uint64_t profile_last_tsc;  /* TSC at the last report (tsc_clock.h) */
    uint64_t execution_clock_cost, execution_clock_resolution;
#ifdef __PROSPERO__
    DECLSPEC_ALIGN(16) struct pw_sync_bop_pending_view sync_pending;
    struct pw_sync_bop_memory_view sync_memory;
    struct pw_sync_bop_context_view sync_context;
    DECLSPEC_ALIGN(16) BYTE sync_image[sizeof(I386_CONTEXT) + 16];
    I386_CONTEXT *sync_canonical;
    USHORT *sync_cpu_flags;
    int sync_attached, sync_fatal, sync_published, sync_backend_called, sync_committed;
    unsigned sync_operation, sync_wait_slot;
    uint64_t sync_attempts[5], sync_hits[5], sync_preflight_misses[5];
    uint64_t sync_backend_misses[5], sync_output_statuses[5], sync_lease_misses[5];
    uint64_t sync_resets, sync_report_tsc, sync_wait_overflow;
    struct { uint32_t used, handle; uint64_t calls, hits, misses, alertable, infinite; } sync_wait[16];
#endif
};

C_ASSERT( sizeof(((I386_CONTEXT *)0)->ExtendedRegisters) == PW_GUEST_FXSAVE_BYTES );

static __thread struct pw_thread *self;
static uint64_t next_cache_report_id;

/* Fault markers (pw_x86_block.h): re-encoded blocks do not check their
 * accesses against the guest range; an access outside it faults on the
 * host, and the SIGSEGV handler below resumes the block at the path that
 * reports it to the guest, as the check did. Only such faults are taken:
 * one inside the guest range (a guard page, a write watch, memory Wine has
 * not mapped) stays Wine's, as before. The handler reads the translators'
 * code ranges from this table rather than thread-local storage. */
enum { MAX_ARENAS = 1024 };
static struct { uintptr_t low, high; PwX86Engine *engine; PwX86State *state; PwX86HotspotProfile *profile; } arenas[MAX_ARENAS];
#ifndef __PROSPERO__
static struct sigaction wine_segv;
#endif
static int fault_markers;
static void register_arena( struct pw_thread *thread, int add );
static void profile_add_thread( struct pw_thread *thread );
static PwWowHostMemory host_memory;
/* Set once a thread has its DBT: the threads after it take the smaller
 * budget (thread_budget.h). */
static int first_thread_ready;
/* Bumped when a memory notification touches a page translated code was read
 * from: every thread then discards its translations on its next entry. */
static volatile uint64_t code_generation = 1;
/* Bumped by every memory notification: protection may have changed. */
static volatile uint64_t protect_generation = 1;
static PwX86CodePages code_pages;
static volatile int flush_lock;

/* Translation reads source bytes straight from the identity-mapped guest.
 * A span never extends into an unreadable page. Readability comes from
 * Wine's own view of the address space (NtQueryVirtualMemory is resolved in
 * process, without a kernel call), which is the same on every host; the
 * last readable region is cached per thread until the next memory
 * notification, because frees and protection changes bump
 * protect_generation. */
static int readable( uintptr_t address )
{
    struct pw_thread *thread = self;
    MEMORY_BASIC_INFORMATION info;
    const ULONG readable_mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    uint64_t generation = __atomic_load_n( &protect_generation, __ATOMIC_ACQUIRE );

    if (thread && thread->readable_generation == generation &&
        address >= thread->readable_low && address < thread->readable_high)
    {
        thread->readable_hits++;
        return 1;
    }
    if (thread) thread->readable_queries++;
    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)address, MemoryBasicInformation,
                              &info, sizeof(info), NULL ))
        return 0;
    if (info.State != MEM_COMMIT || !(info.Protect & readable_mask) || (info.Protect & PAGE_GUARD))
        return 0;
    if (thread)
    {
        thread->readable_low = (uintptr_t)info.BaseAddress;
        thread->readable_high = (uintptr_t)info.BaseAddress + info.RegionSize;
        thread->readable_generation = generation;
    }
    return 1;
}

static int source_view( void *opaque, uint32_t pc, const uint8_t **source, size_t *bytes )
{
    const uintptr_t page = 0x1000;
    uintptr_t end = ((uintptr_t)pc | (page - 1)) + 1;

    if (pc < 0x10000 || !readable( pc )) return PW_ERR_NOT_FOUND;
    if (end - pc < PW_X86_ENGINE_MAX_SOURCE && end < 0x100000000ull && readable( end ))
        end += page;
    *source = (const uint8_t *)(uintptr_t)pc;
    *bytes = end - pc;
    if (*bytes > PW_X86_ENGINE_MAX_SOURCE) *bytes = PW_X86_ENGINE_MAX_SOURCE;
    /* Whatever a translation may read from; flush() keys on these marks. */
    pw_x86_code_pages_mark( &code_pages, pc, *bytes );
    return PW_OK;
}

/* Zeroed memory above the guest's 4 GiB, from Wine's own virtual memory
 * (host_memory.h), committed, or only reserved (type MEM_RESERVE); NULL
 * when there is none. */
static void *place_above_guest( size_t bytes, ULONG type, ULONG protect )
{
    MEM_ADDRESS_REQUIREMENTS requirements = { (void *)0x100000000, NULL, 0 };
    MEM_EXTENDED_PARAMETER parameter = { 0 };
    SIZE_T size = bytes;
    void *base = NULL;

    parameter.Type = MemExtendedParameterAddressRequirements;
    parameter.Pointer = &requirements;
    if (NtAllocateVirtualMemoryEx( NtCurrentProcess(), &base, &size, type, protect, &parameter, 1 ))
        return NULL;
    return base;
}

static void *allocate_above_guest( size_t bytes, ULONG protect )
{
    return place_above_guest( bytes, MEM_RESERVE | MEM_COMMIT, protect );
}

static void *allocate_code( size_t bytes )
{
    return allocate_above_guest( bytes, PAGE_EXECUTE_READWRITE );
}

/* A code arena is reserved, and committed as translations fill it
 * (host_memory.h): on the console committed memory is direct memory. */
static void *reserve_code( size_t bytes )
{
    return place_above_guest( bytes, MEM_RESERVE, PAGE_NOACCESS );
}

static int commit_code( void *base, size_t bytes )
{
    SIZE_T size = bytes;

    return NtAllocateVirtualMemory( NtCurrentProcess(), &base, 0, &size, MEM_COMMIT,
                                    PAGE_EXECUTE_READWRITE ) ? -1 : 0;
}

static void release( void *base, size_t bytes )
{
    SIZE_T size = 0;

    NtFreeVirtualMemory( NtCurrentProcess(), &base, &size, MEM_RELEASE );
}

/* The thread's cache entries, engine and fallback within one budget; 0, or
 * -1 with nothing left allocated. */
static int setup_thread( void *context, const PwWowThreadBudget *budget )
{
    struct pw_thread *thread = context;
    const size_t entry_bytes = budget->entries * sizeof(*thread->entries);

    if (!(thread->entries = allocate_above_guest( entry_bytes, PAGE_READWRITE ))) return -1;
    if (pw_x86_engine_init( &thread->engine, &thread->vm, thread->entries, budget->entries,
                            budget->arena_bytes, (uint32_t)code_generation, source_view, NULL ) == PW_OK)
    {
        if (pw_x86_hostexec_init( &thread->hostexec, &thread->vm, budget->hostexec_bytes ) == PW_OK)
            return 0;
        pw_x86_engine_destroy( &thread->engine );
    }
    release( thread->entries, entry_bytes );
    thread->entries = NULL;
    return -1;
}

static uint64_t execution_clock( void *opaque )
{
    struct timespec now;
    (void)opaque;
    if (clock_gettime( CLOCK_THREAD_CPUTIME_ID, &now )) return 0;
    return now.tv_sec * 1000000000ull + now.tv_nsec;
}

static void execution_report( struct pw_thread *thread )
{
    if (thread->engine.dispatch_profile)
        fprintf( stderr, "wowprospero dispatch: tid=%04x cumulative=1 table_matches=%llu table_empty=%llu table_collisions=%llu\n",
                 (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueThread,
                 (unsigned long long)thread->engine.dispatch_chain_matches,
                 (unsigned long long)thread->engine.dispatch_chain_empty,
                 (unsigned long long)thread->engine.dispatch_chain_collisions );
    if (!thread->engine.execution_clock) return;
    fprintf( stderr, "wowprospero execution: tid=%04x cumulative=1 sample_cpu_ns=%llu calls=%llu samples=%llu stride=%u clock_batch_read_ns=%llu clock_resolution_ns=%llu clock_errors=%llu\n",
             (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueThread,
             (unsigned long long)thread->engine.execution_ns,
             (unsigned long long)thread->engine.execution_calls,
             (unsigned long long)thread->engine.execution_samples,
             thread->engine.execution_stride,
             (unsigned long long)thread->execution_clock_cost,
             (unsigned long long)thread->execution_clock_resolution,
             (unsigned long long)thread->engine.execution_clock_errors );
}

static struct pw_thread *get_thread(void)
{
    struct pw_thread *thread = self;
    PwWowThreadBudget budget;
    int first, attempt;

    if (thread) return thread;
    if (!(thread = calloc( 1, sizeof(*thread) ))) return NULL;
    first = !__atomic_load_n( &first_thread_ready, __ATOMIC_ACQUIRE );
    if (pw_wow_host_backend( &thread->vm, &host_memory ) != PW_OK ||
        (attempt = pw_wow_thread_fit( first, setup_thread, thread, &budget )) < 0)
    {
        fprintf( stderr, "wowprospero: no memory for a %s thread's translator\n",
                 first ? "first" : "further" );
        free( thread );
        return NULL;
    }
    if (attempt)
        fprintf( stderr, "wowprospero: %s thread's translator reduced to %u entries, %zu KiB of code\n",
                 first ? "first" : "further", budget.entries, budget.arena_bytes >> 10 );
    __atomic_store_n( &first_thread_ready, 1, __ATOMIC_RELEASE );
    {
        /* PW_WOW_MODES=<chaining><residency><lazy-flags>[<indirect>[<flat>[<reencode>]]],
         * e.g. "00000" for the plainest translation; used to bisect
         * optimisation defects. Digits left out stay on; indirect targets
         * take effect only with chaining; residency 2 is the per-block
         * allocator instead of the global one. */
        const char *modes = getenv( "PW_WOW_MODES" );
        size_t digits = modes ? strlen( modes ) : 0;

        if (digits < 3 || digits > 6) { modes = "111111"; digits = 6; }
        pw_x86_engine_set_chaining( &thread->engine, modes[0] == '1' );
        /* Residency '1': the guest GPRs in fixed host registers across
         * linked blocks (PW_WOW_RESIDENT=<hex mask> picks which); '2': the
         * older per-block allocator; '0': none. */
        pw_x86_engine_set_residency( &thread->engine, modes[1] != '0' );
        if (modes[1] == '1')
        {
            const char *mask = getenv( "PW_WOW_RESIDENT" );
            pw_x86_engine_set_global_resident( &thread->engine,
                                               mask ? (uint8_t)strtoul( mask, NULL, 16 ) : GLOBAL_RESIDENT );
        }
        pw_x86_engine_set_lazy_flags( &thread->engine, modes[2] == '1' );
        /* Without the table the dynamic exits simply return. */
        (void)pw_x86_engine_set_indirect( &thread->engine, digits < 4 || modes[3] != '0' );
        /* The guest range load_state gives the stack and the one region. */
        if (digits < 5 || modes[4] != '0')
            pw_x86_engine_set_flat_memory( &thread->engine, GUEST_LOW, GUEST_HIGH );
        /* The same-ISA re-encoder where it takes a block (it needs the flat
         * range and no counters); the emitter elsewhere. */
        pw_x86_engine_set_reencode( &thread->engine, digits < 6 || modes[5] != '0' );
        /* Accesses outside the flat range fault instead of being checked. */
        if (fault_markers && (digits < 5 || modes[4] != '0'))
        {
            register_arena( thread, 1 );
            pw_x86_engine_set_fault_markers( &thread->engine, 1 );
        }
        /* Nothing here reads the step statistics; PW_WOW_STATS keeps them. */
        pw_x86_engine_set_counters( &thread->engine, getenv( "PW_WOW_STATS" ) != NULL );
        /* Blocks from the older emitter return to this loop after QUANTUM
         * linked blocks. PW_WOW_QUANTUM overrides it, and also makes
         * re-encoded blocks spend it (below). */
        {
            const char *quantum = getenv( "PW_WOW_QUANTUM" );
            unsigned long value = quantum ? strtoul( quantum, NULL, 10 ) : QUANTUM;
            pw_x86_engine_set_quantum( &thread->engine, value ? (uint32_t)value : QUANTUM );
        }
    }
    thread->prefer_host = getenv( "PW_WOW_HOSTEXEC_ALL" ) != NULL;
    if (getenv( "PW_WOW_TRACE" ))
    {
        thread->trace = 1;
        pw_x86_engine_set_quantum( &thread->engine, 1 );
    }
    /* Nothing here needs the dispatcher between linked blocks: code flushes
     * are noticed when run() starts, and Wine suspends a thread with a
     * signal. So re-encoded chains spend no budget, unless a mode above
     * steps block by block or PW_WOW_QUANTUM asks for one. */
    pw_x86_engine_set_unbounded_chains( &thread->engine, !thread->trace && !thread->prefer_host &&
                                        !getenv( "PW_WOW_QUANTUM" ) );
    /* Blocks go on past conditional branches, whose side exits link
     * themselves in the code memory, which stays writable here
     * (PW_WOW_SUPERBLOCKS=0 ends blocks at every branch). */
    /* The guest's x87, MMX and SSE state runs in the host FPU in re-encoded
     * code, which copies FP and SIMD instructions (PW_WOW_NATIVE_FP=0 leaves
     * them to the emitter's software FPU). */
    pw_x86_engine_set_native_fp( &thread->engine, thread->engine.reencode_enabled &&
                                 (!getenv( "PW_WOW_NATIVE_FP" ) || strcmp( getenv( "PW_WOW_NATIVE_FP" ), "0" )) );
    pw_x86_engine_set_superblocks( &thread->engine, thread->engine.unbounded_chains &&
                                   (!getenv( "PW_WOW_SUPERBLOCKS" ) || strcmp( getenv( "PW_WOW_SUPERBLOCKS" ), "0" )) );
    /* Calls through a register or memory learn their target in the same
     * writable code, as side exits do; off unless PW_WOW_CALL_PREDICT=1 or,
     * on the console, /data/prospero-win/pw_wow_call_predict exists. */
    {
        int predict = getenv( "PW_WOW_CALL_PREDICT" ) && !strcmp( getenv( "PW_WOW_CALL_PREDICT" ), "1" );
#ifdef __PROSPERO__
        struct stat predict_st;

        if (!stat( "/data/prospero-win/pw_wow_call_predict", &predict_st )) predict = 1;
#endif
        pw_x86_engine_set_call_predict( &thread->engine, thread->engine.superblocks && predict );
    }
    /* Calls and returns on a call stack, so the host predicts the returns
     * (PW_WOW_CALL_STACK=0 keeps the lookup); its guard sends a call that
     * runs out of it to redirect_fault. */
    if (thread->engine.unbounded_chains && thread->engine.reencode_enabled && fault_markers &&
        (!getenv( "PW_WOW_CALL_STACK" ) || strcmp( getenv( "PW_WOW_CALL_STACK" ), "0" )) &&
        (thread->call_stack = allocate_above_guest( PW_X86_ENGINE_CALL_STACK_GUARD + CALL_STACK,
                                                    PAGE_READWRITE )))
    {
        void *guard = thread->call_stack;
        SIZE_T size = PW_X86_ENGINE_CALL_STACK_GUARD;
        ULONG old;

        if (NtProtectVirtualMemory( NtCurrentProcess(), &guard, &size, PAGE_NOACCESS, &old ) ||
            pw_x86_engine_set_call_stack( &thread->engine, (char *)thread->call_stack +
                                          PW_X86_ENGINE_CALL_STACK_GUARD, CALL_STACK ) != PW_OK)
        {
            release( thread->call_stack, 0 );
            thread->call_stack = NULL;
        }
    }
    /* Predicted calls need the call stack; say per thread whether they run. */
    if (thread->engine.call_predict)
        fprintf( stderr, "wowprospero call_predict: tid=%04x active=%u\n",
                 (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueThread,
                 thread->engine.call_stack_base != NULL );
    thread->cache_epoch = (uint32_t)code_generation;
    thread->cache_report_id = __atomic_add_fetch( &next_cache_report_id, 1, __ATOMIC_RELAXED );
    pw_guest_fp_init( &thread->state.fp );
    thread->generation = code_generation;
    {
        int dispatch = getenv( "PW_WOW_DISPATCH_PROFILE" ) != NULL;
        int enabled = getenv( "PW_WOW_EXEC_TIMING" ) != NULL;
#ifdef __PROSPERO__
        struct stat dispatch_st;
        if (!stat( "/data/prospero-win/pw_wow_dispatch_profile", &dispatch_st )) dispatch = 1;
#endif
        pw_x86_engine_set_dispatch_profile( &thread->engine, dispatch );
#ifdef __PROSPERO__
        struct stat st;
        if (!stat( "/data/prospero-win/pw_wow_exec_timing", &st )) enabled = 1;
#endif
        if (enabled)
        {
            const char *option = getenv( "PW_WOW_EXEC_STRIDE" );
            unsigned long stride = option ? strtoul( option, NULL, 10 ) : 64;
            if (!stride || stride > UINT32_MAX) stride = 64;
            struct timespec resolution;
            if (!clock_getres( CLOCK_THREAD_CPUTIME_ID, &resolution ))
                thread->execution_clock_resolution = resolution.tv_sec * 1000000000ull + resolution.tv_nsec;
            if (pw_x86_execution_clock_batch( execution_clock, NULL, &thread->execution_clock_cost ) == PW_OK)
                pw_x86_engine_set_execution_clock( &thread->engine, execution_clock, NULL, (uint32_t)stride );
            else fprintf( stderr, "wowprospero execution: unavailable thread CPU clock; timing disabled\n" );
        }
    }
    profile_add_thread( thread );
    return self = thread;
}

static void load_state( PwX86State *state, const I386_CONTEXT *ctx, UINT teb32 )
{
    state->gpr[0] = ctx->Eax;
    state->gpr[1] = ctx->Ecx;
    state->gpr[2] = ctx->Edx;
    state->gpr[3] = ctx->Ebx;
    state->gpr[4] = ctx->Esp;
    state->gpr[5] = ctx->Ebp;
    state->gpr[6] = ctx->Esi;
    state->gpr[7] = ctx->Edi;
    state->eip = ctx->Eip;
    state->eflags = (ctx->EFlags & 0x00000cd5) | 0x2;
    state->deferred_flags.known_mask = 0;
    state->fs_base = teb32;
    state->fs_bytes = 0x1000;
    /* Wine owns the address space; every translated access is checked only
     * against the identity-mapped guest range and faults natively. */
    state->stack_low = GUEST_LOW;
    state->stack_high = GUEST_HIGH;
    state->memory_count = 1;
    state->memory[0].low = GUEST_LOW;
    state->memory[0].high = GUEST_HIGH;
    state->memory[0].permissions = PW_X86_READ | PW_X86_WRITE | PW_X86_EXEC;
    state->selector[0] = LOWORD(ctx->SegEs);
    state->selector[1] = LOWORD(ctx->SegCs);
    state->selector[2] = LOWORD(ctx->SegSs);
    state->selector[3] = LOWORD(ctx->SegDs);
    state->selector[4] = LOWORD(ctx->SegFs);
    state->selector[5] = LOWORD(ctx->SegGs);
}

/* The guest's x87 and SSE state is the thread's own hardware state whenever
 * the guest is not running, as with wow64cpu: cpu.c saves it into the
 * context's FXSAVE image just before this call and restores it from there
 * after. So what Wine's NtContinue, SetThreadContext and exception dispatch
 * write into the thread's FP state reaches the guest, and GetThreadContext
 * reads the guest's. In between, the image is the guest's. */
static void sync_fp_in( struct pw_thread *thread, const I386_CONTEXT *ctx )
{
    pw_x86_engine_fp_load( &thread->engine, &thread->state, (const uint8_t *)ctx->ExtendedRegisters );
}

static void sync_fp_out( struct pw_thread *thread, I386_CONTEXT *ctx )
{
    pw_x86_engine_fp_store( &thread->engine, &thread->state, (uint8_t *)ctx->ExtendedRegisters );
}

static void store_state( const PwX86State *state, I386_CONTEXT *ctx )
{
    ctx->Eax = state->gpr[0];
    ctx->Ecx = state->gpr[1];
    ctx->Edx = state->gpr[2];
    ctx->Ebx = state->gpr[3];
    ctx->Esp = state->gpr[4];
    ctx->Ebp = state->gpr[5];
    ctx->Esi = state->gpr[6];
    ctx->Edi = state->gpr[7];
    ctx->Eip = state->eip;
    ctx->EFlags = (ctx->EFlags & ~0x00000cd5) | (state->eflags & 0x00000cd5);
}

/* The saved RIP in a signal context, or NULL where it is not known. */
/* The saved RSP, in the same layout. */
static uintptr_t *context_rsp( void *context )
{
#if defined(__PROSPERO__)
    return (uintptr_t *)((char *)context + 248);  /* mcontext at 64, mc_rsp at 184 */
#elif defined(__linux__)
    return (uintptr_t *)&((ucontext_t *)context)->uc_mcontext.gregs[REG_RSP];
#elif defined(__FreeBSD__)
    return (uintptr_t *)&((ucontext_t *)context)->uc_mcontext.mc_rsp;
#else
    (void)context;
    return NULL;
#endif
}

static uintptr_t *context_rip( void *context )
{
#if defined(__PROSPERO__)
    return (uintptr_t *)((char *)context + 224);  /* the live slot (WINE_INTEGRATION.md) */
#elif defined(__linux__)
    return (uintptr_t *)&((ucontext_t *)context)->uc_mcontext.gregs[REG_RIP];
#elif defined(__FreeBSD__)
    return (uintptr_t *)&((ucontext_t *)context)->uc_mcontext.mc_rip;
#else
    (void)context;
    return NULL;
#endif
}

/* Resumes a fault at a marked access outside the guest range at the
 * access's refused-access path; nonzero when it did. */
static int redirect_fault( siginfo_t *info, void *context )
{
    const uintptr_t address = (uintptr_t)info->si_addr;
    uintptr_t *rip = context_rip( context ), target = 0;
    PwX86State *state = NULL;
    uint32_t eip;

    for (unsigned int i = 0; i < MAX_ARENAS && !target; i++)
    {
        uintptr_t high = __atomic_load_n( &arenas[i].high, __ATOMIC_ACQUIRE );
        uintptr_t low = __atomic_load_n( &arenas[i].low, __ATOMIC_ACQUIRE );
        if (low && high && *rip >= low && *rip < high)
        {
            uintptr_t rsp;
            /* A call that ran out of call stack: start it again. */
            if (context_rsp( context ) &&
                pw_x86_engine_call_stack_fault( arenas[i].engine, address, &rsp ))
            {
                *context_rsp( context ) = rsp;
                return 1;
            }
            target = pw_x86_engine_fault_redirect( arenas[i].engine, *rip );
            state = arenas[i].state;
        }
    }
    if (!target) return 0;
    if (address >= GUEST_LOW && address < GUEST_HIGH)
    {
        /* Wine's to handle (a guard page, a write watch); the block stored
         * no EIP before the access, so give Wine the exact one. */
        if (state && pw_x86_cold_path_eip( target, &eip )) state->eip = eip;
        return 0;
    }
    *rip = target;
    return 1;
}

#ifdef __PROSPERO__
/* An access violation Wine could not resolve, at a marked access in our code
 * (a real guest fault, not a guard page or write watch): resume it at the
 * access's refused-access path, which leaves translated code with the exact
 * EIP and address for BTCpuSimulate to raise as the guest's own exception.
 * Wine cannot dispatch it itself: translated code runs on our stack, outside
 * the thread's kernel stack (patch 0710). */
static int redirect_unresolved( siginfo_t *info, void *context )
{
    uintptr_t *rip = context_rip( context ), target = 0;

    (void)info;
    for (unsigned int i = 0; i < MAX_ARENAS && !target; i++)
    {
        uintptr_t high = __atomic_load_n( &arenas[i].high, __ATOMIC_ACQUIRE );
        uintptr_t low = __atomic_load_n( &arenas[i].low, __ATOMIC_ACQUIRE );
        if (low && high && *rip >= low && *rip < high)
            target = pw_x86_engine_fault_redirect( arenas[i].engine, *rip );
    }
    if (!target) return 0;
    *rip = target;
    return 1;
}

/* On the PS5, Wine's own handler calls redirect_fault first (patch 0610), and
 * redirect_unresolved for what it could not resolve (patch 0710). */
extern void __wine_ps5_set_segv_hook( int (*hook)( siginfo_t *info, void *context ) );
extern void __wine_ps5_set_segv_unresolved_hook( int (*hook)( siginfo_t *info, void *context ) );
#else
static void segv_handler( int signal, siginfo_t *info, void *context )
{
    if (redirect_fault( info, context )) return;
    if (wine_segv.sa_flags & SA_SIGINFO) wine_segv.sa_sigaction( signal, info, context );
    else if (wine_segv.sa_handler != SIG_DFL && wine_segv.sa_handler != SIG_IGN) wine_segv.sa_handler( signal );
    else sigaction( SIGSEGV, &wine_segv, NULL );  /* the default action on the retry */
}
#endif

/* Profiles belong to the sampled thread. Resolve the PC immediately, before
 * cache invalidation can reuse its arena, and retain only addresses/counts.
 * No cache of another thread or proprietary guest bytes is read by reporting. */
static const char *profile_path;
static uint64_t profile_ticks, profile_unattributed;
/* The report period runs on the TSC (tsc_clock.h): run() returns too often
 * for a clock_gettime there, a system call on the PS5. */
enum { PROFILE_PERIOD_MS = 5000, PROFILE_CALIBRATION_NS = 20000000 };
static uint64_t profile_tsc_rate, profile_period_ticks;
#include <sys/time.h>
#ifndef __PROSPERO__
#include <dlfcn.h>
#endif
/* Native PCs are process-wide and cumulative. Keys never move or disappear;
 * atomic publication/counts allow signals on different threads to sample
 * without a lock, TLS, or access to another thread's cache. */
enum { PROFILE_NATIVE_SLOTS = 4096 };
static struct profile_native { uintptr_t pc; uint64_t samples; } profile_native[PROFILE_NATIVE_SLOTS];
static uint64_t profile_native_overflow, profile_native_last_dump;
static void profile_native_sample(uintptr_t pc)
{
    unsigned bucket = (unsigned)((pc >> 4) * 2654435761u) & (PROFILE_NATIVE_SLOTS - 1);
    if(!pc) return;
    for(unsigned i = 0; i < PROFILE_NATIVE_SLOTS; i++) {
        uintptr_t key = __atomic_load_n(&profile_native[bucket].pc, __ATOMIC_ACQUIRE);
        if(!key) {
            uintptr_t empty = 0;
            if(__atomic_compare_exchange_n(&profile_native[bucket].pc, &empty, pc, 0,
                                           __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) key = pc;
            else key = empty;
        }
        if(key == pc) {
            __atomic_fetch_add(&profile_native[bucket].samples, 1, __ATOMIC_RELAXED);
            return;
        }
        bucket = (bucket + 1) & (PROFILE_NATIVE_SLOTS - 1);
    }
    __atomic_fetch_add(&profile_native_overflow, 1, __ATOMIC_RELAXED);
}
static void profile_handler(int signal, siginfo_t *info, void *context)
{
    const uintptr_t rip = *context_rip(context);
    (void)signal; (void)info;
    __atomic_fetch_add(&profile_ticks, 1, __ATOMIC_RELAXED);
    /* Wine may change FS before entering translated code: compiler TLS access
     * (including __tls_get_addr) is unsafe here. Locate the interrupted arena
     * instead. Only its owner can execute it, so no other cache is inspected. */
    for(unsigned i = 0; i < MAX_ARENAS; i++) {
        uintptr_t low = __atomic_load_n(&arenas[i].low, __ATOMIC_ACQUIRE);
        if(low && rip >= low && rip < __atomic_load_n(&arenas[i].high, __ATOMIC_ACQUIRE)) {
            PwX86HotspotProfile *profile = __atomic_load_n(&arenas[i].profile, __ATOMIC_ACQUIRE);
            if(profile) {
                pw_x86_engine_sample(arenas[i].engine, rip, profile);
                return;
            }
            break;
        }
    }
    __atomic_fetch_add(&profile_unattributed, 1, __ATOMIC_RELAXED);
    profile_native_sample(rip);
}

static uint64_t profile_monotonic_ns(void)
{
    struct timespec now;

    if(clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return now.tv_sec * 1000000000ull + now.tv_nsec;
}

/* The TSC's rate against CLOCK_MONOTONIC over about 20 ms, once. Each clock
 * read is bracketed by two TSC reads and matched to their midpoint, so the
 * system call's own cost does not bias the rate. */
static uint64_t profile_calibrate(void)
{
    struct timespec pause = { 0, PROFILE_CALIBRATION_NS };
    uint64_t before, after, tsc0, ns0, tsc1, ns1;

    before = __rdtsc(); ns0 = profile_monotonic_ns(); after = __rdtsc();
    tsc0 = before + (after - before) / 2;
    while(nanosleep(&pause, &pause) && errno == EINTR) {}
    before = __rdtsc(); ns1 = profile_monotonic_ns(); after = __rdtsc();
    tsc1 = before + (after - before) / 2;
    if(!ns0 || !ns1 || ns1 - ns0 < PROFILE_CALIBRATION_NS / 2) return 0;
    return pw_tsc_rate(tsc0, ns0, tsc1, ns1);
}

static void profile_start(void)
{
    profile_path = getenv("PW_WOW_PROFILE");
#ifdef __PROSPERO__
    if(!profile_path) {
        struct stat st;
        if(!stat("/data/prospero-win/pw_wow_profile", &st)) profile_path = "1";
    }
#endif
    if(!profile_path || !*profile_path) { profile_path = NULL; return; }
    /* Before the timer starts, so no SIGPROF cuts the calibration short. */
    profile_tsc_rate = profile_calibrate();
    if(!profile_tsc_rate) {
        fprintf(stderr, "wowprospero profile: TSC calibration failed\n");
        profile_path = NULL;
        return;
    }
    profile_period_ticks = pw_tsc_ticks(PROFILE_PERIOD_MS, profile_tsc_rate);
    fprintf(stderr, "wowprospero profile_clock: tsc_hz=%llu calibration_ms=%u period_ms=%u\n",
            (unsigned long long)profile_tsc_rate, PROFILE_CALIBRATION_NS / 1000000, PROFILE_PERIOD_MS);
    struct sigaction action;
    struct itimerval timer = { { 0, 1000 }, { 0, 1000 } };
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = profile_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if(sigaction(SIGPROF, &action, NULL) || setitimer(ITIMER_PROF, &timer, NULL)) {
        fprintf(stderr, "wowprospero profile: sampling timer unavailable\n");
        profile_path = NULL;
    }
}

static void profile_add_thread(struct pw_thread *thread)
{
    if(profile_path && !thread->engine.fault_markers) {
        fprintf(stderr, "wowprospero profile: requires fault-marker block map\n");
        return;
    }
    if(profile_path) {
        thread->profile = calloc(1, sizeof(*thread->profile));
        for(unsigned i = 0; i < MAX_ARENAS; i++)
            if(__atomic_load_n(&arenas[i].high, __ATOMIC_ACQUIRE) && arenas[i].engine == &thread->engine) {
                __atomic_store_n(&arenas[i].profile, thread->profile, __ATOMIC_RELEASE);
                break;
            }
    }
}

static int compare_hotspots(const void *a, const void *b)
{
    const PwX86Hotspot *x = a, *y = b;
    return x->samples < y->samples ? 1 : x->samples > y->samples ? -1 : 0;
}

static int compare_native_samples(const void *a, const void *b)
{
    const struct profile_native *x = a, *y = b;
    return x->samples < y->samples ? 1 : x->samples > y->samples ? -1 : 0;
}

static void profile_native_dump(uint64_t now, FILE *out)
{
    uint64_t last = __atomic_load_n(&profile_native_last_dump, __ATOMIC_RELAXED);
    struct profile_native *rows;
    if(now - last < PROFILE_PERIOD_MS || !__atomic_compare_exchange_n(&profile_native_last_dump, &last, now, 0,
                                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED)) return;
    rows = malloc(sizeof(profile_native));
    if(!rows) return;
    for(unsigned i = 0; i < PROFILE_NATIVE_SLOTS; i++) {
        rows[i].pc = __atomic_load_n(&profile_native[i].pc, __ATOMIC_ACQUIRE);
        rows[i].samples = __atomic_load_n(&profile_native[i].samples, __ATOMIC_RELAXED);
    }
    qsort(rows, PROFILE_NATIVE_SLOTS, sizeof(*rows), compare_native_samples);
    fprintf(out, "wowprospero native_summary: cumulative=1 overflow=%llu\n",
            (unsigned long long)__atomic_load_n(&profile_native_overflow, __ATOMIC_RELAXED));
    for(unsigned i = 0; i < 12 && rows[i].samples; i++) {
        const char *module = "?", *symbol = "?";
        uintptr_t offset = rows[i].pc;
#ifndef __PROSPERO__
        Dl_info info;
        if(dladdr((void *)rows[i].pc, &info)) {
            if(info.dli_fname) module = info.dli_fname;
            if(info.dli_sname) symbol = info.dli_sname;
            offset -= (uintptr_t)(info.dli_saddr ? info.dli_saddr : info.dli_fbase);
        }
#endif
        fprintf(out, "wowprospero native: pc=%#lx samples=%llu module=%s symbol=%s offset=%#lx\n",
                (unsigned long)rows[i].pc, (unsigned long long)rows[i].samples,
                module, symbol, (unsigned long)offset);
    }
    free(rows);
}

static void profile_maybe_dump(void)
{
    struct pw_thread *thread = self;
    sigset_t mask, previous;
    PwX86HotspotProfile *snapshot;
    uint64_t tsc, interval, entry_samples = 0, body_samples = 0, exit_samples = 0, emitted_samples = 0;
    unsigned tid = HandleToULong(NtCurrentTeb()->ClientId.UniqueThread);
    FILE *out = stderr;
    char path[512];

    if(!thread || !thread->profile) return;
    /* No system call until a report is due: one TSC read and a compare. */
    tsc = __rdtsc();
    if(!thread->profile_last_tsc) { thread->profile_last_tsc = tsc; return; }
    if(tsc - thread->profile_last_tsc < profile_period_ticks) return;
    interval = pw_tsc_ms(tsc - thread->profile_last_tsc, profile_tsc_rate);
    thread->profile_last_tsc = tsc;
    snapshot = malloc(sizeof(*snapshot));
    if(!snapshot) return;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPROF);
    if(sigprocmask(SIG_BLOCK, &mask, &previous)) { free(snapshot); return; }
    memcpy(snapshot, thread->profile, sizeof(*snapshot));
    memset(thread->profile, 0, sizeof(*thread->profile));
    sigprocmask(SIG_SETMASK, &previous, NULL);
    for(unsigned i = 0; i < PW_X86_HOTSPOT_SLOTS; i++) {
        entry_samples += snapshot->slots[i].entry;
        body_samples += snapshot->slots[i].body;
        exit_samples += snapshot->slots[i].exit;
        emitted_samples += snapshot->slots[i].emitted;
    }
    qsort(snapshot->slots, PW_X86_HOTSPOT_SLOTS, sizeof(snapshot->slots[0]), compare_hotspots);
#ifndef __PROSPERO__
    if(strcmp(profile_path, "1")) {
        snprintf(path, sizeof(path), "%s.%04x", profile_path, tid);
        out = fopen(path, "w");
        if(!out) out = stderr;
    }
#else
    (void)path;
#endif
    fprintf(out, "wowprospero profile: tid=%04x interval_ms=%llu samples=%llu outside=%llu stubs=%llu overflow=%llu\n",
            tid, (unsigned long long)interval, (unsigned long long)snapshot->samples, (unsigned long long)snapshot->outside,
            (unsigned long long)snapshot->stubs, (unsigned long long)snapshot->overflow);
    fprintf(out, "wowprospero profile_process: ticks=%llu unattributed=%llu\n",
            (unsigned long long)__atomic_load_n(&profile_ticks, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&profile_unattributed, __ATOMIC_RELAXED));
    fprintf(out, "wowprospero profile_parts: tid=%04x entry=%llu body=%llu exit=%llu emitted=%llu\n",
            tid, (unsigned long long)entry_samples, (unsigned long long)body_samples,
            (unsigned long long)exit_samples, (unsigned long long)emitted_samples);
    for(unsigned i = 0; i < 20 && snapshot->slots[i].samples; i++) {
        const PwX86Hotspot *row = &snapshot->slots[i];
        fprintf(out, "wowprospero hotspot: tid=%04x pc=%08x samples=%llu entry=%llu body=%llu exit=%llu emitted=%llu\n",
                tid, row->guest_pc, (unsigned long long)row->samples, (unsigned long long)row->entry,
                (unsigned long long)row->body, (unsigned long long)row->exit, (unsigned long long)row->emitted);
    }
    profile_native_dump(pw_tsc_ms(tsc, profile_tsc_rate), out);
    if(out != stderr) fclose(out);
    free(snapshot);
}

static void register_arena( struct pw_thread *thread, int add )
{
    const uintptr_t low = (uintptr_t)thread->engine.code.exec_base;

    for (unsigned int i = 0; i < MAX_ARENAS; i++)
    {
        if (add)
        {
            /* Claim a free slot, then publish it: the handler skips a slot
             * whose high is still 0. */
            uintptr_t none = 0;
            if (__atomic_compare_exchange_n( &arenas[i].low, &none, low, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
            {
                __atomic_store_n(&arenas[i].profile, NULL, __ATOMIC_RELEASE);
                arenas[i].engine = &thread->engine;
                arenas[i].state = &thread->state;
                __atomic_store_n( &arenas[i].high, low + thread->engine.code.bytes, __ATOMIC_RELEASE );
                return;
            }
        }
        else if (__atomic_load_n( &arenas[i].low, __ATOMIC_ACQUIRE ) == low)
        {
            __atomic_store_n( &arenas[i].high, 0, __ATOMIC_RELEASE );
            __atomic_store_n( &arenas[i].profile, NULL, __ATOMIC_RELEASE );
            __atomic_store_n( &arenas[i].low, 0, __ATOMIC_RELEASE );
            return;
        }
    }
}

#ifdef __PROSPERO__
extern const struct pw_sync_bop_backend *__wine_ps5_sync_bop_backend(uint32_t);
extern const struct pw_sync_bop_context_backend *__wine_ps5_sync_bop_context_backend(uint32_t);
extern const struct pw_sync_bop_memory_backend *__wine_ps5_sync_bop_memory_backend(uint32_t);
extern const struct pw_sync_bop_pending_backend *__wine_ps5_sync_bop_pending_backend(uint32_t);

static const struct pw_sync_bop_backend *sync_backend;
static const struct pw_sync_bop_context_backend *sync_context;
static const struct pw_sync_bop_memory_backend *sync_memory;
static const struct pw_sync_bop_pending_backend *sync_pending;
static struct pw_wow_sync_attestation sync_attestation;
/* Persistent storage also survives a mocked OS cleanup refusal. */
static struct pw_sync_bop_memory_view sync_init_memory;
static int sync_bound, sync_diagnostics;

static int sync_requested(void)
{
    const char *value = getenv( "PW_WOW_SYNC_BOP" );
    char bytes[3];
    FILE *file;
    size_t count;

    if (value) return !strcmp( value, "1" );
    if (!(file = fopen( "/data/prospero-win/pw_wow_sync_bop", "rb" ))) return 0;
    count = fread( bytes, 1, sizeof(bytes), file );
    if (ferror(file)) count = 0;
    fclose( file );
    return (count == 1 && bytes[0] == '1') ||
           (count == 2 && bytes[0] == '1' && bytes[1] == '\n');
}

static int sync_diagnostics_requested(void)
{
    const char *value = getenv( "PW_WOW_SYNC_BOP_DIAGNOSTICS" );
    char bytes[3];
    FILE *file;
    size_t count;

    if (value) return !strcmp( value, "1" );
    if (!(file = fopen( "/data/prospero-win/pw_wow_sync_bop_diagnostics", "rb" ))) return 0;
    count = fread( bytes, 1, sizeof(bytes), file );
    if (ferror(file)) count = 0;
    fclose( file );
    return (count == 1 && bytes[0] == '1') ||
           (count == 2 && bytes[0] == '1' && bytes[1] == '\n');
}

static int sync_loaded_read32( void *opaque, uint64_t address, void *out, size_t bytes )
{
    if (address > UINT32_MAX || bytes > PW_BOP_MEMORY_MAX_BYTES) return 0;
    return sync_memory->read( opaque, (uint32_t)address, out, (uint32_t)bytes );
}

static int sync_loaded_read64( void *opaque, uint64_t address, void *out, size_t bytes )
{
    const struct pw_wow_init_params *params = opaque;
    pw_wow_image_read_t read = (pw_wow_image_read_t)(ULONG_PTR)params->read64;

    if (!read || bytes > 32) return 0;
    return read( address, out, (UINT)bytes );
}

static int sync_loaded_image32( struct pw_sync_bop_memory_view *view,
                                uint64_t base, struct pw_wow_sync_image *image )
{
    uint8_t dos[2], header[24], magic[2], size_bytes[4];
    uint32_t offset, bytes;
    uint64_t optional;

    if (base < GUEST_LOW || base > GUEST_HIGH - 64 ||
        !sync_loaded_read32(view,base,dos,2) || dos[0] != 'M' || dos[1] != 'Z' ||
        !sync_loaded_read32(view,base + 60,size_bytes,4)) return 0;
    offset = pw_wow_sync_read_le32( size_bytes );
    if (offset < 64 || offset > 0x100000 || base + offset > GUEST_HIGH - 88 ||
        !sync_loaded_read32(view,base + offset,header,sizeof(header)) ||
        memcmp(header,"PE\0\0",4) || header[4] != 0x4c || header[5] != 1 ||
        ((unsigned)header[20] | (unsigned)header[21] << 8) < 96) return 0;
    optional = base + offset + sizeof(header);
    if (!sync_loaded_read32(view,optional,magic,2) || magic[0] != 0x0b || magic[1] != 1 ||
        !sync_loaded_read32(view,optional + 56,size_bytes,4)) return 0;
    bytes = pw_wow_sync_read_le32( size_bytes );
    if (bytes < offset + 24 + 96 || bytes > GUEST_HIGH - base) return 0;
    *image = (struct pw_wow_sync_image){base,bytes,view,sync_loaded_read32};
    return 1;
}

static int sync_loaded_end( struct pw_sync_bop_memory_view *view )
{
    unsigned attempt;

    for (attempt = 0; attempt < 8; attempt++) if (sync_memory->end(view)) return 1;
    return 0;
}

static NTSTATUS sync_loaded_init( const struct pw_wow_init_params *params )
{
    struct pw_wow_sync_identity_source source = {0};
    struct pw_wow_sync_attestation candidate;
    pw_wow_export_t resolve;
    uint32_t begun;
    unsigned i;
    int accepted = 0;

    sync_bound = sync_diagnostics = 0;
    if (!sync_requested()) return STATUS_SUCCESS;
    if (!params || params->version != PW_WOW_INIT_VERSION || params->size != sizeof(*params) ||
        !params->retained64 || !params->module64 || !params->module64_size ||
        !params->read64 || !params->resolve32) goto disabled;
    sync_backend = __wine_ps5_sync_bop_backend( PW_SYNC_BOP_VERSION );
    sync_context = __wine_ps5_sync_bop_context_backend( PW_BOP_CONTEXT_VERSION );
    sync_memory = __wine_ps5_sync_bop_memory_backend( PW_BOP_MEMORY_VERSION );
    sync_pending = __wine_ps5_sync_bop_pending_backend( PW_BOP_PENDING_VERSION );
    if (!pw_sync_bop_backend_valid(sync_backend) || !sync_context || !sync_memory || !sync_pending ||
        sync_context->version != PW_BOP_CONTEXT_VERSION || sync_context->size != sizeof(*sync_context) ||
        sync_context->pointer_size != sizeof(void *) || sync_context->context_size != sizeof(I386_CONTEXT) ||
        !sync_context->publish || !sync_context->finish ||
        sync_memory->version != PW_BOP_MEMORY_VERSION || sync_memory->size != sizeof(*sync_memory) ||
        sync_memory->pointer_size != sizeof(void *) || sync_memory->view_size != sizeof(sync_init_memory) ||
        !sync_memory->begin || !sync_memory->end || !sync_memory->read ||
        !sync_memory->writable || !sync_memory->write ||
        sync_pending->version != PW_BOP_PENDING_VERSION || sync_pending->size != sizeof(*sync_pending) ||
        sync_pending->pointer_size != sizeof(void *) ||
        sync_pending->view_size != sizeof(struct pw_sync_bop_pending_view) ||
        !sync_pending->attach || !sync_pending->take || !sync_pending->detach || !sync_pending->checkpoint) goto disabled;
    sync_init_memory.version = PW_BOP_MEMORY_VERSION;
    sync_init_memory.size = sizeof(sync_init_memory);
    begun = sync_memory->begin( &sync_init_memory );
    if (begun == PW_BOP_MEMORY_EMPTY) goto disabled;
    if (begun != PW_BOP_MEMORY_HELD)
    {
        if (!sync_loaded_end(&sync_init_memory)) return STATUS_INTERNAL_ERROR;
        goto disabled;
    }
    source.version = PW_WOW_SYNC_IMAGE_VERSION;
    /* Native64 is pinned; the VM lease retains the actual32 read window.
     * Future calls must revalidate their32 stub/helper/dispatcher under a
     * fresh lease. There is no permanent32 native-loader pin assumption. */
    source.retained = 1;
    source.pe64 = (struct pw_wow_sync_image){params->module64,params->module64_size,
                                           (void *)params,sync_loaded_read64};
    resolve = (pw_wow_export_t)(ULONG_PTR)params->resolve32;
    if (sync_loaded_image32(&sync_init_memory,params->module32,&source.pe32))
    {
        for (i = 0; i < PW_WOW_SYNC_OPERATIONS; i++)
        {
            source.exports32[i] = resolve( params->module32, pw_wow_sync_export_name(i) );
            source.exports64[i] = params->exports64[i];
        }
        source.dispatcher32 = resolve( params->module32, "__wine_syscall_dispatcher" );
        accepted = pw_wow_sync_attest( &source, &candidate );
    }
    if (!sync_loaded_end(&sync_init_memory)) return STATUS_INTERNAL_ERROR;
    if (!accepted) goto disabled;
    sync_attestation = candidate;
    sync_bound = 1;
    sync_diagnostics = sync_diagnostics_requested();
    fprintf( stderr, "wowprospero sync BOP: loaded identities bound (consumer configured)\n" );
    return STATUS_SUCCESS;
disabled:
    fprintf( stderr, "wowprospero sync BOP: ordinary fallback (binding unavailable)\n" );
    return STATUS_SUCCESS;
}
#endif

static NTSTATUS process_init( void *args )
{
    long page = sysconf( _SC_PAGESIZE );

    host_memory.allocate = allocate_code;
    host_memory.release = release;
    host_memory.reserve = reserve_code;
    host_memory.commit = commit_code;
    host_memory.lazy_bytes = (size_t)8 << 20;  /* the code arenas */
    host_memory.page = page > 0 ? (size_t)page : 0x1000;
    host_memory.alignment = 0x10000;  /* the allocation granularity */
    {
        /* PW_WOW_FAULT_MARKERS=0 keeps the checks. */
        const char *markers = getenv( "PW_WOW_FAULT_MARKERS" );

        if (!markers || strcmp( markers, "0" ))
        {
#ifdef __PROSPERO__
            __wine_ps5_set_segv_hook( redirect_fault );
            __wine_ps5_set_segv_unresolved_hook( redirect_unresolved );
            fault_markers = 1;
#else
            struct sigaction action;

            memset( &action, 0, sizeof(action) );
            if (context_rip( &action ) && !sigaction( SIGSEGV, NULL, &wine_segv ))
            {
                action.sa_sigaction = segv_handler;
                action.sa_mask = wine_segv.sa_mask;
                action.sa_flags = wine_segv.sa_flags | SA_SIGINFO | SA_ONSTACK;
                fault_markers = !sigaction( SIGSEGV, &action, NULL );
            }
#endif
        }
    }
    profile_start();
#ifdef __PROSPERO__
    return sync_loaded_init( args );
#else
    return STATUS_SUCCESS;
#endif
}

/* PW_WOW_TIMING=1 (in a title, which passes Wine no such variable: the
 * trigger file below) times every thread with the TSC, without signals.
 * Every few seconds each thread that crossed to the host often logs how its
 * wall time split between run() (translated code and the translator) and the
 * time outside it after a Unix call (OpenGL, Vulkan, audio...) or a system
 * call, with the rate and mean cost of each, and how often the translations
 * were discarded. */
#ifdef __PROSPERO__
#define PW_WOW_TIMING_TRIGGER "/data/prospero-win/pw_wow_timing"
#endif
static int timing_enabled = -1;

static uint64_t timing_now_ns(void)
{
    struct timespec now;

    clock_gettime( CLOCK_MONOTONIC, &now );
    return now.tv_sec * 1000000000ull + now.tv_nsec;
}

static void timing_init(void)
{
    timing_enabled = getenv( "PW_WOW_TIMING" ) != NULL || getenv( "PW_WOW_EXEC_TIMING" ) != NULL ||
                     getenv( "PW_WOW_DISPATCH_PROFILE" ) != NULL;
#ifdef PW_WOW_TIMING_TRIGGER
    {
        struct stat st;  /* access() is refused to a title */

        if (!stat( PW_WOW_TIMING_TRIGGER, &st )) timing_enabled = 1;
        if (!stat( "/data/prospero-win/pw_wow_exec_timing", &st )) timing_enabled = 1;
        if (!stat( "/data/prospero-win/pw_wow_dispatch_profile", &st )) timing_enabled = 1;
    }
#endif
}

/* Owner-thread counters only: no table walk, signal-handler work or extra
 * per-lookup accounting. Publishes survive reset; occupancy does not. */
static void cache_report( struct pw_thread *thread, uint64_t wall, unsigned final )
{
    const PwX86Cache *cache = &thread->engine.cache;

    fprintf( stderr, "wowprospero cache: tid=%04x instance=%llu cumulative=1 time_ns=%llu final=%u "
             "generation=%u capacity=%u occupied=%llu arena_used=%zu arena_bytes=%zu "
             "hits=%llu misses=%llu probes=%llu max_probe=%u publishes=%llu resets=%llu\n",
             (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueThread,
             (unsigned long long)thread->cache_report_id, (unsigned long long)wall, final,
             cache->generation, cache->capacity,
             (unsigned long long)(cache->publishes - thread->cache_publishes_at_reset),
             cache->cursor, cache->arena_bytes, (unsigned long long)cache->hits,
             (unsigned long long)cache->misses, (unsigned long long)cache->lookup_probes,
             cache->max_probe, (unsigned long long)cache->publishes,
             (unsigned long long)cache->resets );
}

static void timing_report( struct pw_thread *thread, uint64_t tsc )
{
    uint64_t wall = timing_now_ns();
    double cycles = (double)(tsc - thread->t_window);
    double seconds = (wall - thread->wall_window) / 1e9;
    double per_us = cycles / seconds / 1e6;

    execution_report( thread );

    cache_report( thread, wall, 0 );
    if (thread->n_unix + thread->n_sys > 1000)
        fprintf( stderr, "wowprospero timing: tid=%04x run=%.1f%% unix=%.1f%% (%.0f/s %.2fus) "
                 "sys=%.1f%% (%.0f/s %.2fus) other=%.1f%% (%u) unix_over_1ms=%.1f%% (%u) resets=%u flushes=%u\n",
                 (unsigned)(uintptr_t)NtCurrentTeb()->ClientId.UniqueThread,
                 100.0 * thread->t_inside / cycles,
                 100.0 * thread->t_unix / cycles, thread->n_unix / seconds,
                 thread->n_unix ? thread->t_unix / per_us / thread->n_unix : 0.0,
                 100.0 * thread->t_sys / cycles, thread->n_sys / seconds,
                 thread->n_sys ? thread->t_sys / per_us / thread->n_sys : 0.0,
                 100.0 * thread->t_other / cycles, thread->n_other,
                 100.0 * thread->t_unix_long / cycles, thread->n_unix_long, thread->n_resets, thread->n_flushes );
    thread->t_window = tsc;
    thread->wall_window = wall;
    thread->t_inside = thread->t_unix = thread->t_sys = thread->t_other = thread->t_unix_long = 0;
    thread->n_unix_long = 0;
    thread->tsc_per_us = per_us;
    thread->n_unix = thread->n_sys = thread->n_other = thread->n_resets = thread->n_flushes = 0;
}

/* At run()'s start: the time since the previous run returned. */
static void timing_enter( struct pw_thread *thread )
{
    uint64_t tsc = __rdtsc(), outside = tsc - thread->t_mark;

    if (!thread->t_window)
    {
        thread->t_window = tsc;
        thread->wall_window = timing_now_ns();
    }
    else if (thread->last_reason == PW_WOW_UNIXCALL)
    {
        /* A call that blocks (a wait for the display, say) rather than works. */
        thread->t_unix += outside;
        thread->n_unix++;
        if (thread->tsc_per_us && outside > 1000 * thread->tsc_per_us)
        {
            thread->t_unix_long += outside;
            thread->n_unix_long++;
        }
    }
    else if (thread->last_reason == PW_WOW_SYSCALL) { thread->t_sys += outside; thread->n_sys++; }
    else { thread->t_other += outside; thread->n_other++; }
    thread->t_mark = tsc;
}

/* At run()'s return; a report about every 2^34 cycles (5 to 10 s). */
static void timing_leave( struct pw_thread *thread, uint32_t reason )
{
    uint64_t tsc = __rdtsc();

    thread->t_inside += tsc - thread->t_mark;
    thread->t_mark = tsc;
    thread->last_reason = reason;
    if (tsc - thread->t_window > (1ull << 34)) timing_report( thread, tsc );
}

static void reset_thread_engine( struct pw_thread *thread )
{
    uint64_t resets = thread->engine.cache.resets;

    pw_x86_engine_reset( &thread->engine, ++thread->cache_epoch );
    if (thread->engine.cache.resets != resets)
        thread->cache_publishes_at_reset = thread->engine.cache.publishes;
}

#ifdef __PROSPERO__
/* Caller-owned views remain valid across Unix/PE boundaries and on refusal. */
static I386_CONTEXT *sync_shadow( struct pw_thread *thread )
{
    return (I386_CONTEXT *)(thread->sync_image +
                           ((16 - offsetof(I386_CONTEXT,ExtendedRegisters) % 16) % 16));
}

static void sync_snapshot( struct pw_thread *thread, I386_CONTEXT *ctx )
{
    I386_CONTEXT *image = sync_shadow(thread);
    pw_x86_commit_canonical_flags(&thread->state);
    memcpy(image,ctx,sizeof(*image));
    store_state(&thread->state,image);
    sync_fp_out(thread,image);
}

static int sync_pending_changes( const struct pw_thread *thread )
{
    return __atomic_load_n(&thread->sync_pending.fields,__ATOMIC_ACQUIRE) ||
           (__atomic_load_n(thread->sync_cpu_flags,__ATOMIC_ACQUIRE) & WOW64_CPURESERVED_FLAG_RESET_STATE);
}

static int sync_memory_begin( struct pw_thread *thread )
{
    uint32_t begun;
    if (thread->sync_memory.state != PW_BOP_MEMORY_EMPTY) { thread->sync_fatal=1; return 0; }
    thread->sync_memory.version=PW_BOP_MEMORY_VERSION;
    thread->sync_memory.size=sizeof(thread->sync_memory);
    begun=sync_memory->begin(&thread->sync_memory);
    if (begun==PW_BOP_MEMORY_HELD) return 1;
    if (begun!=PW_BOP_MEMORY_EMPTY && !sync_loaded_end(&thread->sync_memory)) thread->sync_fatal=1;
    return 0;
}

static int sync_attach( struct pw_thread *thread, I386_CONTEXT *ctx, struct pw_wow_run_params *params )
{
    if (!sync_bound) return 0;
    params->sync_active=0; /* Version 2 was negotiated by initialization. */
    if (thread->sync_attached)
    {
        if (thread->sync_pending.canonical!=(ULONG_PTR)ctx ||
            thread->sync_cpu_flags!=(USHORT *)(ULONG_PTR)params->cpu_flags) thread->sync_fatal=1;
    }
    else if (params->cpu_flags && !ctx->Dr7 && !(ctx->EFlags & (0x100|0x10000)) &&
             (ctx->ContextFlags & CONTEXT_I386_XSTATE)!=CONTEXT_I386_XSTATE && sync_memory_begin(thread))
    {
        thread->sync_pending.version=PW_BOP_PENDING_VERSION;
        thread->sync_pending.size=sizeof(thread->sync_pending);
        thread->sync_pending.canonical=(ULONG_PTR)ctx;
        thread->sync_attached=sync_pending->attach(&thread->sync_pending,sizeof(*ctx));
        thread->sync_cpu_flags=(USHORT *)(ULONG_PTR)params->cpu_flags;
        if (!sync_loaded_end(&thread->sync_memory)) thread->sync_fatal=1;
    }
    thread->sync_canonical=ctx;
    params->sync_active=thread->sync_attached;
    return thread->sync_fatal ? -1 : thread->sync_attached;
}

/* Rare observer edits and incomplete native frames need only a native
 * context checkpoint, never a guest-VM lock. Recovery is bounded. */
static int sync_checkpoint( struct pw_thread *thread, I386_CONTEXT *ctx, UINT teb32, int commit )
{
    unsigned attempt;
    int replaced=0;
    uint32_t result;
    if (!commit && !sync_pending_changes(thread)) return 0;
    for (attempt=0;attempt<8;attempt++)
    {
        sync_snapshot(thread,ctx);
        result=sync_pending->checkpoint(&thread->sync_pending,sync_shadow(thread),sizeof(*ctx));
        if (result==PW_BOP_PENDING_INVALID)
        {
            if (thread->sync_pending.guard) continue; /* restore only */
            thread->sync_fatal=1; return -1;
        }
        replaced|=result==PW_BOP_PENDING_REPLACED;
        load_state(&thread->state,ctx,teb32); sync_fp_in(thread,ctx);
        if (!sync_pending_changes(thread)) return replaced;
    }
    thread->sync_fatal=1;
    return -1;
}

static int sync_revalidate( struct pw_thread *thread, unsigned op, UINT bop )
{
    static const BYTE args[]={12,8,8,8,12};
    BYTE expected[15]={0xb8,0,0,0,0,0xba,0,0,0,0,0xff,0xd2,0xc2,0,0};
    BYTE stub[15],helper[6],dispatcher[4];
    uint32_t id=sync_attestation.bindings.ids[op],target=sync_attestation.helper32;
    unsigned i;
    for(i=0;i<4;i++) { expected[1+i]=(BYTE)(id>>(8*i)); expected[6+i]=(BYTE)(target>>(8*i)); }
    expected[13]=args[op];
    if (!sync_memory->read(&thread->sync_memory,sync_attestation.continuations[op]-12,stub,sizeof(stub)) ||
        memcmp(stub,expected,sizeof(stub)) ||
        !sync_memory->read(&thread->sync_memory,target,helper,sizeof(helper)) ||
        helper[0]!=0xff || helper[1]!=0x25 || pw_wow_sync_read_le32(helper+2)!=sync_attestation.dispatcher32 ||
        !sync_memory->read(&thread->sync_memory,sync_attestation.dispatcher32,dispatcher,sizeof(dispatcher)) ||
        pw_wow_sync_read_le32(dispatcher)!=bop) return 0;
    return 1;
}

static int sync_read( void *opaque, uint32_t address, void *out, size_t bytes )
{
    struct pw_thread *thread=opaque;
    uint32_t *words=out;
    if (bytes>PW_BOP_MEMORY_MAX_BYTES || !sync_memory->read(&thread->sync_memory,address,out,(uint32_t)bytes)) return 0;
    if (address==thread->state.gpr[4] && (bytes==16 || bytes==20))
    {
        if (words[0]!=sync_attestation.continuations[thread->sync_operation]) return 0;
        if (sync_diagnostics && thread->sync_operation==PW_WOW_SYNC_WAIT)
        {
            unsigned i;
            for(i=0;i<16;i++) if (!thread->sync_wait[i].used || thread->sync_wait[i].handle==words[2]) break;
            thread->sync_wait_slot=i;
            if(i<16)
            {
                thread->sync_wait[i].used=1;thread->sync_wait[i].handle=words[2];thread->sync_wait[i].calls++;
                if((BYTE)words[3]) thread->sync_wait[i].alertable++;
                if(!words[4]) thread->sync_wait[i].infinite++;
            }
            else thread->sync_wait_overflow++;
        }
    }
    return 1;
}

static int sync_writable( void *opaque, uint32_t address, size_t bytes )
{
    struct pw_thread *thread=opaque;
    return bytes<=PW_BOP_MEMORY_MAX_BYTES && sync_memory->writable(&thread->sync_memory,address,(uint32_t)bytes);
}

static uint32_t sync_write( void *opaque, uint32_t address, const void *value, size_t bytes )
{
    struct pw_thread *thread=opaque;
    return bytes<=PW_BOP_MEMORY_MAX_BYTES ? sync_memory->write(&thread->sync_memory,address,value,(uint32_t)bytes) : STATUS_ACCESS_VIOLATION;
}

static void sync_registers( const I386_CONTEXT *ctx, struct pw_wow_sync_registers *regs )
{
    regs->gpr[0]=ctx->Eax;regs->gpr[1]=ctx->Ecx;regs->gpr[2]=ctx->Edx;regs->gpr[3]=ctx->Ebx;
    regs->gpr[4]=ctx->Esp;regs->gpr[5]=ctx->Ebp;regs->gpr[6]=ctx->Esi;regs->gpr[7]=ctx->Edi;
    regs->pc=ctx->Eip;regs->flags=ctx->EFlags;
}

static int sync_publish( void *opaque, const struct pw_wow_sync_registers *regs )
{
    struct pw_thread *thread=opaque;
    I386_CONTEXT *image;
    sync_snapshot(thread,thread->sync_canonical);image=sync_shadow(thread);
    image->Eax=regs->gpr[0];image->Ecx=regs->gpr[1];image->Edx=regs->gpr[2];image->Ebx=regs->gpr[3];
    image->Esp=regs->gpr[4];image->Ebp=regs->gpr[5];image->Esi=regs->gpr[6];image->Edi=regs->gpr[7];
    image->Eip=regs->pc;image->EFlags=regs->flags;
    thread->sync_context=(struct pw_sync_bop_context_view){PW_BOP_CONTEXT_VERSION,sizeof(thread->sync_context),0,0,
                                                       (ULONG_PTR)thread->sync_canonical,(ULONG_PTR)image};
    thread->sync_published=sync_context->publish(&thread->sync_context,sizeof(*image));
    return thread->sync_published;
}

static int sync_cached( void *opaque, uint32_t op, uint32_t handle, uint32_t count, uint32_t *previous )
{
    struct pw_thread *thread=opaque;
    int hit=sync_backend->try_cached(op,handle,count,previous);
    thread->sync_backend_called=1;thread->sync_committed=hit;
    if(sync_diagnostics)
    {
        if(hit) thread->sync_hits[op]++; else thread->sync_backend_misses[op]++;
        if(op==PW_WOW_SYNC_WAIT && thread->sync_wait_slot<16)
        {
            if(hit) thread->sync_wait[thread->sync_wait_slot].hits++;
            else thread->sync_wait[thread->sync_wait_slot].misses++;
        }
    }
    return hit;
}

static int sync_finish( void *opaque, enum pw_wow_sync_result result, struct pw_wow_sync_registers *regs )
{
    struct pw_thread *thread=opaque;
    I386_CONTEXT *image=sync_shadow(thread);
    uint32_t done;
    /* Signals are still blocked. A miss has no completed service: queued
     * observers must see the original BOP/stack, not a popped continuation. */
    if(result==PW_WOW_SYNC_MISS) sync_snapshot(thread,thread->sync_canonical);
    else if(!thread->sync_context.changes) image->Eax=regs->gpr[0];
    if(!sync_loaded_end(&thread->sync_memory)) { thread->sync_fatal=1;return 1; }
    done=sync_context->finish(&thread->sync_context,result==PW_WOW_SYNC_MISS ? PW_BOP_CONTEXT_MISS :
                              result==PW_WOW_SYNC_OUTPUT_STATUS ? PW_BOP_CONTEXT_FAULT : PW_BOP_CONTEXT_HIT);
    if(done==PW_BOP_CONTEXT_INVALID) { thread->sync_fatal=1;return 1; }
    thread->sync_published=0;
    if(done==PW_BOP_CONTEXT_REPLACED || sync_pending_changes(thread))
    {
        sync_registers(thread->sync_canonical,regs);
        return 1;
    }
    return 0;
}

static int sync_try( struct pw_thread *thread, I386_CONTEXT *ctx, struct pw_wow_run_params *params )
{
    struct pw_wow_sync_access access={thread,sync_read,sync_writable,sync_write,sync_publish,sync_finish,sync_cached};
    struct pw_wow_sync_registers regs;
    enum pw_wow_sync_result result;
    unsigned op;
    uint32_t ignored=0;
    int replaced;
    for(op=0;op<PW_WOW_SYNC_OPERATIONS;op++) if(thread->state.gpr[0]==sync_attestation.bindings.ids[op]) break;
    if(op==PW_WOW_SYNC_OPERATIONS) return 0;
    if(sync_diagnostics) thread->sync_attempts[op]++;
    thread->sync_operation=op;thread->sync_wait_slot=16;
    thread->sync_canonical=ctx;thread->sync_backend_called=thread->sync_committed=0;
    if(!sync_memory_begin(thread))
    {
        if(sync_diagnostics) thread->sync_lease_misses[op]++;
        return thread->sync_fatal ? -1 : 0;
    }
    if(sync_pending_changes(thread))
    {
        if(!sync_loaded_end(&thread->sync_memory)) { thread->sync_fatal=1;return -1; }
        replaced=sync_checkpoint(thread,ctx,params->teb32,0);
        return replaced<0 ? -1 : 1;
    }
    if(!sync_revalidate(thread,op,params->bop))
    {
        if(!sync_loaded_end(&thread->sync_memory)) thread->sync_fatal=1;
        if(sync_diagnostics) thread->sync_preflight_misses[op]++;
        return thread->sync_fatal ? -1 : 0;
    }
    pw_x86_commit_canonical_flags(&thread->state);
    memcpy(regs.gpr,thread->state.gpr,sizeof(regs.gpr));regs.pc=thread->state.eip;
    regs.flags=(ctx->EFlags & ~0xcd5u)|(thread->state.eflags & 0xcd5u);
    result=pw_wow_sync_try(&sync_attestation.bindings,&access,&regs,&ignored);
    if(thread->sync_fatal) return -1;
    if(!thread->sync_published && thread->sync_memory.state!=PW_BOP_MEMORY_EMPTY)
        if(!sync_loaded_end(&thread->sync_memory)) { thread->sync_fatal=1;return -1; }
    if(result==PW_WOW_SYNC_MISS)
    {
        if(sync_diagnostics && !thread->sync_backend_called) thread->sync_preflight_misses[op]++;
        return 0;
    }
    if(sync_diagnostics && result==PW_WOW_SYNC_OUTPUT_STATUS) thread->sync_output_statuses[op]++;
    /* Native finish owns the complete image, including observer FP changes. */
    load_state(&thread->state,ctx,params->teb32);sync_fp_in(thread,ctx);
    if(result==PW_WOW_SYNC_CONTEXT_RESET)
    {
        if(sync_diagnostics) thread->sync_resets++;
        if(sync_checkpoint(thread,ctx,params->teb32,0)<0) return -1;
    }
    return 1;
}

static int sync_leave( struct pw_thread *thread, I386_CONTEXT *ctx, struct pw_wow_run_params *params )
{
    I386_CONTEXT *image;
    uint32_t done;
    int replaced=0;
    if(sync_pending_changes(thread)) replaced=sync_checkpoint(thread,ctx,params->teb32,1);
    else
    {
        sync_snapshot(thread,ctx);image=sync_shadow(thread);
        thread->sync_context=(struct pw_sync_bop_context_view){PW_BOP_CONTEXT_VERSION,sizeof(thread->sync_context),0,0,
                                                            (ULONG_PTR)ctx,(ULONG_PTR)image};
        thread->sync_published=sync_context->publish(&thread->sync_context,sizeof(*ctx));
        if(thread->sync_published)
        {
            /* FAULT means commit supplied EAX, with no success-status rewrite. */
            done=sync_context->finish(&thread->sync_context,PW_BOP_CONTEXT_FAULT);
            if(done==PW_BOP_CONTEXT_INVALID) { thread->sync_fatal=1;return -1; }
            thread->sync_published=0;replaced=done==PW_BOP_CONTEXT_REPLACED;
            load_state(&thread->state,ctx,params->teb32);sync_fp_in(thread,ctx);
        }
        else replaced=sync_checkpoint(thread,ctx,params->teb32,1);
    }
    if(replaced<0) return -1;
    if(sync_pending_changes(thread))
    {
        int more=sync_checkpoint(thread,ctx,params->teb32,1);
        if(more<0) return -1;
        replaced|=more;
    }
    if(replaced || sync_pending_changes(thread)) params->reason=PW_WOW_RESET;
    return 0;
}

static void sync_report( struct pw_thread *thread, unsigned final )
{
    uint64_t now;
    unsigned op,i;
    if(!sync_diagnostics || !thread->sync_attached) return;
    now=__rdtsc();
    if(!final && thread->sync_report_tsc && now-thread->sync_report_tsc<(1ull<<34)) return;
    thread->sync_report_tsc=now;
    for(op=0;op<PW_WOW_SYNC_OPERATIONS;op++)
        fprintf(stderr,"wowprospero sync_bop: tid=%04x cumulative=1 final=%u op=%u attempts=%llu hits=%llu preflight_misses=%llu backend_misses=%llu output_statuses=%llu lease_misses=%llu resets=%llu\n",
                PtrToUlong(NtCurrentTeb()->ClientId.UniqueThread),final,op,
                (unsigned long long)thread->sync_attempts[op],(unsigned long long)thread->sync_hits[op],
                (unsigned long long)thread->sync_preflight_misses[op],(unsigned long long)thread->sync_backend_misses[op],
                (unsigned long long)thread->sync_output_statuses[op],(unsigned long long)thread->sync_lease_misses[op],
                (unsigned long long)thread->sync_resets);
    for(i=0;i<16;i++) if(thread->sync_wait[i].used)
        fprintf(stderr,"wowprospero sync_bop_wait: tid=%04x cumulative=1 final=%u handle=%x calls=%llu hits=%llu misses=%llu alertable=%llu infinite=%llu overflow=%llu\n",
                PtrToUlong(NtCurrentTeb()->ClientId.UniqueThread),final,thread->sync_wait[i].handle,
                (unsigned long long)thread->sync_wait[i].calls,(unsigned long long)thread->sync_wait[i].hits,
                (unsigned long long)thread->sync_wait[i].misses,(unsigned long long)thread->sync_wait[i].alertable,
                (unsigned long long)thread->sync_wait[i].infinite,(unsigned long long)thread->sync_wait_overflow);
}
static int sync_detach( struct pw_thread *thread )
{
    unsigned attempt;
    uint32_t done;
    if (!thread->sync_attached) return 1;
    if (thread->sync_memory.state != PW_BOP_MEMORY_EMPTY && !sync_loaded_end(&thread->sync_memory)) return 0;
    if (thread->sync_published)
    {
        done=sync_context->finish(&thread->sync_context,PW_BOP_CONTEXT_FAULT);
        if (done==PW_BOP_CONTEXT_INVALID) return 0;
        thread->sync_published=0;
    }
    /* Teardown checkpoints only the native complete image, not guest code. */
    for (attempt=0;attempt<8;attempt++)
    {
        done=sync_pending->checkpoint(&thread->sync_pending,thread->sync_canonical,sizeof(I386_CONTEXT));
        if (done!=PW_BOP_PENDING_INVALID) break;
        if (!thread->sync_pending.guard) return 0;
    }
    if (done==PW_BOP_PENDING_INVALID || !sync_memory_begin(thread)) return 0;
    done=sync_pending->detach(&thread->sync_pending);
    if (!sync_loaded_end(&thread->sync_memory)) return 0;
    if (done) thread->sync_attached=0;
    return done;
}
#endif

static NTSTATUS run( void *args )
{
    struct pw_wow_run_params *params = args;
    I386_CONTEXT *ctx = (I386_CONTEXT *)(ULONG_PTR)params->context;
    struct pw_thread *thread = get_thread();
    PwX86StepReport report;
    PwX86State *state;
    uint64_t generation;
    int status;

    if (!thread)
    {
        params->reason = PW_WOW_ERROR;
        params->status = PW_ERR_VM;
        return STATUS_SUCCESS;
    }
    state = &thread->state;
    if (timing_enabled < 0) timing_init();
    if (timing_enabled) timing_enter( thread );
    generation = __atomic_load_n( &code_generation, __ATOMIC_ACQUIRE );
    if (thread->generation != generation)
    {
        thread->n_flushes++;
        thread->generation = generation;
        reset_thread_engine( thread );
        pw_x86_hostexec_reset( &thread->hostexec );
    }
#ifdef __PROSPERO__
    if (sync_attach(thread,ctx,params)<0) goto sync_stop;
#endif
    load_state( state, ctx, params->teb32 );
    sync_fp_in( thread, ctx );
    for (;;)
    {
#ifdef __PROSPERO__
        if (thread->sync_attached)
        {
            if (sync_checkpoint(thread,ctx,params->teb32,0)<0) goto sync_stop;
            /* A completed fast call stays in Unix. Check notifications which
             * the ordinary PE return would otherwise recheck on reentry. */
            generation=__atomic_load_n(&code_generation,__ATOMIC_ACQUIRE);
            if (thread->generation!=generation)
            {
                pw_x86_engine_fp_sync(&thread->engine,state);
                thread->generation=generation;thread->n_flushes++;
                reset_thread_engine(thread);pw_x86_hostexec_reset(&thread->hostexec);
            }
        }
#endif
        if (state->eip == params->bop)
        {
#ifdef __PROSPERO__
            if (thread->sync_attached)
            {
                int consumed=sync_try(thread,ctx,params);
                if (consumed<0) goto sync_stop;
                if (consumed) continue;
            }
#endif
            params->reason = PW_WOW_SYSCALL; break;
        }
        if (state->eip == params->unix_bop) { params->reason = PW_WOW_UNIXCALL; break; }
        if (thread->trace) thread->ring[thread->ring_pos++ & 63] = state->eip;
        if (thread->prefer_host)
        {
            /* Diagnostic: every instruction the host can execute bypasses the
             * translator, isolating translator semantics from everything else. */
            const uint8_t *source;
            size_t bytes;

            pw_x86_commit_canonical_flags( state );
            pw_x86_engine_fp_sync( &thread->engine, state );
            if (source_view( NULL, state->eip, &source, &bytes ) == PW_OK &&
                pw_x86_hostexec_step( &thread->hostexec, state, source, bytes ) == PW_OK)
                continue;
            pw_x86_engine_set_quantum( &thread->engine, 1 );
        }
        status = pw_x86_engine_step( &thread->engine, state, &report );
        if (status == PW_OK) continue;
        if (status == PW_ERR_UNSUPPORTED)
        {
            const uint8_t *source;
            size_t bytes;

            /* The block stopped before an instruction the translator does not
             * cover; run exactly that instruction on the host. */
            pw_x86_commit_canonical_flags( state );
            pw_x86_engine_fp_sync( &thread->engine, state );
            if (source_view( NULL, state->eip, &source, &bytes ) == PW_OK &&
                pw_x86_hostexec_step( &thread->hostexec, state, source, bytes ) == PW_OK)
                continue;
        }
        if (status == PW_ERR_LIMIT)
        {
            thread->n_resets++;
            pw_x86_engine_fp_sync( &thread->engine, state );
            reset_thread_engine( thread );
            continue;
        }
        pw_wow_report_error(params, status, state->eip, state->fault_address, state->fault_write);
        break;
    }
    pw_x86_commit_canonical_flags( state );
#ifdef __PROSPERO__
    if (thread->sync_attached)
    {
        if (sync_leave(thread,ctx,params)<0) goto sync_stop;
    }
    else
#endif
    {
        store_state( state, ctx );
        sync_fp_out( thread, ctx );
    }
#ifdef __PROSPERO__
    goto sync_done;
sync_stop:
    params->reason=PW_WOW_STOP;
    params->status=STATUS_INTERNAL_ERROR;
sync_done:
    sync_report(thread,0);
#endif
    if (timing_enabled) timing_leave( thread, params->reason );
    profile_maybe_dump();
    return STATUS_SUCCESS;
}

/* A memory notification. The loader protects and frees memory hundreds of
 * times while it maps and relocates DLLs; discarding every translation each
 * time made a game's startup re-translate the same loader code over and
 * over. Translations are discarded only when the range touches a page code
 * was translated from, or its extent is unknown (size 0: an unmapped view
 * or a whole-cache flush).
 *
 * Marks are cleared before the generation moves, under a lock, so a thread
 * that saw the new generation marks pages after the clear: a mark is lost
 * only for a thread that has yet to see the bump, which will discard its
 * translations anyway. */
static NTSTATUS flush( void *args )
{
    const struct pw_wow_flush_params *params = args;

    __atomic_add_fetch( &protect_generation, 1, __ATOMIC_SEQ_CST );
    while (__atomic_exchange_n( &flush_lock, 1, __ATOMIC_ACQUIRE )) __builtin_ia32_pause();
    if (!params || !params->size || pw_x86_code_pages_any( &code_pages, params->address, params->size ))
    {
        pw_x86_code_pages_clear( &code_pages );
        __atomic_add_fetch( &code_generation, 1, __ATOMIC_SEQ_CST );
    }
    __atomic_store_n( &flush_lock, 0, __ATOMIC_RELEASE );
    return STATUS_SUCCESS;
}

static NTSTATUS dump( void *args )
{
    struct pw_thread *thread = self;

    if (!thread) return STATUS_SUCCESS;
    fprintf( stderr, "wowprospero: eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x eip=%08x fl=%08x\n",
             thread->state.gpr[0], thread->state.gpr[1], thread->state.gpr[2], thread->state.gpr[3],
             thread->state.gpr[4], thread->state.gpr[5], thread->state.gpr[6], thread->state.gpr[7],
             thread->state.eip, thread->state.eflags );
    for (uint32_t i = 0; thread->trace && i < 64; i++)
        fprintf( stderr, "wowprospero: ring[%u]=%08x\n", i,
                 thread->ring[(thread->ring_pos + i) & 63] );
    return STATUS_SUCCESS;
}

static NTSTATUS thread_term( void *args )
{
    struct pw_thread *thread = self;

    if (!thread) return STATUS_SUCCESS;
#ifdef __PROSPERO__
    sync_report(thread,1);
    if (!sync_detach(thread)) return STATUS_INTERNAL_ERROR;
#endif
    execution_report( thread );
    if (timing_enabled > 0) cache_report( thread, timing_now_ns(), 1 );
    self = NULL;
    if (thread->engine.fault_markers) register_arena( thread, 0 );
    free(thread->profile);
    pw_x86_hostexec_destroy( &thread->hostexec );
    pw_x86_engine_destroy( &thread->engine );
    release( thread->entries, 0 );
    if (thread->call_stack) release( thread->call_stack, 0 );
    free( thread );
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    process_init,
    run,
    flush,
    thread_term,
    dump,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == pw_wow_funcs_count );
