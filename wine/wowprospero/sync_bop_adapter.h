/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Scalar sync-BOP transaction. Wine owns the memory/context/FP callbacks.
 * This core does not enable interception or prove asynchronous Wine semantics. */
#ifndef PW_WOW_SYNC_BOP_ADAPTER_H
#define PW_WOW_SYNC_BOP_ADAPTER_H
#include <stdint.h>
#include <stddef.h>

#define PW_WOW_SYNC_OPERATIONS 5u
#define PW_WOW_SYNC_BINDINGS_VERSION 1u
#define PW_WOW_SYNC_ID_ABSENT UINT32_MAX

enum pw_wow_sync_operation
{
    PW_WOW_SYNC_WAIT, PW_WOW_SYNC_RELEASE_MUTEX, PW_WOW_SYNC_SET_EVENT,
    PW_WOW_SYNC_RESET_EVENT, PW_WOW_SYNC_RELEASE_SEMAPHORE
};
enum pw_wow_sync_result
{
    PW_WOW_SYNC_MISS, PW_WOW_SYNC_HIT, PW_WOW_SYNC_CONTEXT_RESET,
    PW_WOW_SYNC_OUTPUT_STATUS
};
struct pw_wow_sync_registers
{
    uint32_t gpr[8]; /* eax ecx edx ebx esp ebp esi edi */
    uint32_t pc, flags;
};
struct pw_wow_sync_bindings
{
    uint32_t version, ids[PW_WOW_SYNC_OPERATIONS];
    /* Set only after matching loaded PE32 identities to native/WoW64 metadata.
     * Native module lifetime and all five operations must be established. */
    int attested;
};
struct pw_wow_sync_access
{
    void *opaque;
    int (*read)(void *, uint32_t, void *, size_t);
    int (*writable)(void *, uint32_t, size_t);
    /* Wine's protected store returns zero on success, or the NTSTATUS that
     * the ordinary syscall exception path would return. Never retry CAS. */
    uint32_t (*write)(void *, uint32_t, const void *, size_t);
    /* Publish canonical GPRs plus the guest's complete FP image to Wine's
     * native syscall-frame observers. Failure restores the prior view and has no
     * semantic side effect. Pending/reset/debug contexts must decline. */
    int (*publish)(void *, const struct pw_wow_sync_registers *);
    /* Restore the native observer view. Return nonzero and supply authoritative
     * registers if Wine replaced context; FP reset import is also required.
     * On MISS restore the prior canonical view, unless a reset replaced it.
     * On HIT publish the supplied successful continuation. Called exactly
     * once after every successful publication, including misses and faults. */
    int (*finish)(void *, enum pw_wow_sync_result, struct pw_wow_sync_registers *);
    /* Native locals only. A miss changes neither objects nor result storage.
     * Warm CAS operations only: no cold fill, mask change or callback dispatch. */
    int (*try_cached)(void *, uint32_t, uint32_t, uint32_t, uint32_t *);
};

static inline int pw_wow_sync_bindings_valid(const struct pw_wow_sync_bindings *bindings)
{
    unsigned i, j;
    if (!bindings || bindings->version != PW_WOW_SYNC_BINDINGS_VERSION || !bindings->attested)
        return 0;
    for (i = 0; i < PW_WOW_SYNC_OPERATIONS; i++)
    {
        /* This adapter binds only the NTDLL table, not win32u table aliases. */
        if (bindings->ids[i] >= 0x1000) return 0;
        for (j = 0; j < i; j++) if (bindings->ids[j] == bindings->ids[i]) return 0;
    }
    return 1;
}

static inline int pw_wow_sync_span(uint32_t address, size_t bytes)
{
    return bytes && address >= 0x10000u && address < 0xfffff000u &&
           bytes <= (size_t)(0xfffff000u - address);
}

static inline enum pw_wow_sync_result pw_wow_sync_try(
    const struct pw_wow_sync_bindings *bindings, const struct pw_wow_sync_access *access,
    struct pw_wow_sync_registers *state, uint32_t *fault_address)
{
    uint32_t words[5], previous = 0, output = 0, count = 0, write_status = 0;
    uint64_t timeout;
    unsigned op, nwords;
    struct pw_wow_sync_registers continuation, replacement;
    int hit, reset;

    if (!state || !access || !pw_wow_sync_bindings_valid(bindings) ||
        !access->read || !access->writable || !access->write || !access->publish ||
        !access->finish || !access->try_cached) return PW_WOW_SYNC_MISS;
    for (op = 0; op < PW_WOW_SYNC_OPERATIONS; op++)
        if (state->gpr[0] == bindings->ids[op]) break;
    if (op == PW_WOW_SYNC_OPERATIONS) return PW_WOW_SYNC_MISS;
    nwords = (op == PW_WOW_SYNC_WAIT || op == PW_WOW_SYNC_RELEASE_SEMAPHORE) ? 5 : 4;
    if (!pw_wow_sync_span(state->gpr[4], nwords * sizeof(*words)) ||
        !access->read(access->opaque, state->gpr[4], words, nwords * sizeof(*words)))
        return PW_WOW_SYNC_MISS;
    /* words[0] = stub call return, words[1] = caller return; arguments start
     * at words[2]. Matching ordinary Wow64, BOOLEAN truncates to eight bits. */
    if (op == PW_WOW_SYNC_WAIT)
    {
        if ((uint8_t)words[3]) return PW_WOW_SYNC_MISS;
        if (words[4] && (!pw_wow_sync_span(words[4], sizeof(timeout)) ||
                        !access->read(access->opaque, words[4], &timeout, sizeof(timeout))))
            return PW_WOW_SYNC_MISS;
    }
    else
    {
        if (op == PW_WOW_SYNC_RELEASE_SEMAPHORE) count = words[3];
        output = words[op == PW_WOW_SYNC_RELEASE_SEMAPHORE ? 4 : 3];
        if (output && (!pw_wow_sync_span(output, sizeof(previous)) ||
                       !access->writable(access->opaque, output, sizeof(previous))))
            return PW_WOW_SYNC_MISS;
    }
    continuation = *state;
    continuation.pc = words[0];
    continuation.gpr[4] += sizeof(*words);
    if (!access->publish(access->opaque, &continuation)) return PW_WOW_SYNC_MISS;
    hit = access->try_cached(access->opaque, op, words[2], count, &previous);
    if (hit && output) write_status = access->write(access->opaque, output, &previous, sizeof(previous));
    /* wow64_syscall_handler unwinds to the return path with ExceptionCode
     * as NTSTATUS. BTCpuSimulate installs it unless RESET replaced context. */
    if (hit) continuation.gpr[0] = write_status;
    replacement = continuation;
    reset = access->finish(access->opaque, !hit ? PW_WOW_SYNC_MISS :
                           write_status ? PW_WOW_SYNC_OUTPUT_STATUS : PW_WOW_SYNC_HIT, &replacement);
    if (reset)
    {
        *state = replacement;
        return PW_WOW_SYNC_CONTEXT_RESET;
    }
    if (!hit) return PW_WOW_SYNC_MISS;
    *state = continuation;
    /* A failed store after CAS resumes the ordinary popped continuation
     * with its status. It must neither retry CAS nor raise a guest exception. */
    if (write_status)
    {
        if (fault_address) *fault_address = output;
        return PW_WOW_SYNC_OUTPUT_STATUS;
    }
    /* The ordinary popped continuation and STATUS_SUCCESS are now committed. */
    return PW_WOW_SYNC_HIT;
}
#endif
