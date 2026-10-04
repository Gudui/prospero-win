/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WOW_SERVICE_TIMING_H
#define PW_WOW_SERVICE_TIMING_H
#include <stdint.h>

/* Owner-thread, cumulative wall spans between a syscall BOP return and the
 * next dispatcher entry. No guest memory reads or service execution changes. */
enum { PW_WOW_SERVICE_SLOTS = 128, PW_WOW_SERVICE_TOP = 4,
       PW_WOW_SERVICE_LONG_NS = 500000 };
typedef struct PwWowServiceStats {
    uint64_t calls, wall_ns, max_ns, long_calls, long_wall_ns;
} PwWowServiceStats;
typedef struct PwWowServiceEntry {
    PwWowServiceStats stats;
    uint32_t id;
    unsigned used;
} PwWowServiceEntry;
typedef struct PwWowServiceTiming {
    PwWowServiceEntry entries[PW_WOW_SERVICE_SLOTS];
    PwWowServiceStats total, overflow;
    uint64_t clock_errors, abandoned, begin_ns;
    uint32_t service;
    unsigned pending, saturated;
} PwWowServiceTiming;

static inline uint64_t pw_wow_service_add(PwWowServiceTiming *p, uint64_t a, uint64_t b)
{
    if (b > UINT64_MAX - a) { p->saturated = 1; return UINT64_MAX; }
    return a + b;
}

static inline void pw_wow_service_begin(PwWowServiceTiming *p, uint32_t service, uint64_t now)
{
    if (p->pending) p->abandoned = pw_wow_service_add(p, p->abandoned, 1);
    p->service = service;
    p->begin_ns = now;
    p->pending = 1;
}

static inline void pw_wow_service_record(PwWowServiceTiming *p, PwWowServiceStats *s, uint64_t ns)
{
    s->calls = pw_wow_service_add(p, s->calls, 1);
    s->wall_ns = pw_wow_service_add(p, s->wall_ns, ns);
    if (ns > s->max_ns) s->max_ns = ns;
    if (ns >= PW_WOW_SERVICE_LONG_NS) {
        s->long_calls = pw_wow_service_add(p, s->long_calls, 1);
        s->long_wall_ns = pw_wow_service_add(p, s->long_wall_ns, ns);
    }
}

static inline void pw_wow_service_end(PwWowServiceTiming *p, uint64_t now)
{
    if (!p->pending) return;
    p->pending = 0;
    if (!p->begin_ns || !now || now < p->begin_ns) {
        p->clock_errors = pw_wow_service_add(p, p->clock_errors, 1);
        return;
    }
    const uint64_t ns = now - p->begin_ns;
    pw_wow_service_record(p, &p->total, ns);
    /* Full 32-bit keys: never merge unrelated service tables or alias an
     * overflowing key to an existing entry. Known keys still work when full. */
    const unsigned start = (p->service * 0x9e3779b1u) & (PW_WOW_SERVICE_SLOTS - 1);
    for (unsigned n = 0; n < PW_WOW_SERVICE_SLOTS; n++) {
        PwWowServiceEntry *e = &p->entries[(start + n) & (PW_WOW_SERVICE_SLOTS - 1)];
        if (!e->used || e->id == p->service) {
            e->used = 1; e->id = p->service;
            pw_wow_service_record(p, &e->stats, ns);
            return;
        }
    }
    pw_wow_service_record(p, &p->overflow, ns);
}

static inline unsigned pw_wow_service_top(const PwWowServiceTiming *p,
                                          const PwWowServiceEntry *top[PW_WOW_SERVICE_TOP])
{
    unsigned count = 0;
    for (unsigned i = 0; i < PW_WOW_SERVICE_SLOTS; i++) {
        const PwWowServiceEntry *e = &p->entries[i];
        if (!e->used) continue;
        unsigned at = 0;
        while (at < count && (top[at]->stats.wall_ns > e->stats.wall_ns ||
               (top[at]->stats.wall_ns == e->stats.wall_ns && top[at]->id < e->id))) at++;
        if (at == PW_WOW_SERVICE_TOP) continue;
        if (count < PW_WOW_SERVICE_TOP) count++;
        for (unsigned j = count - 1; j > at; j--) top[j] = top[j - 1];
        top[at] = e;
    }
    return count;
}
#endif
