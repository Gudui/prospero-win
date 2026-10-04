/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Owner-thread report scheduling. TSC only throttles clock probes; the
 * monotonic clock determines report intervals and is never inferred from it.
 * No signal-handler state, calibration, sleeping, or guest pointers. */
#ifndef PW_WOW_PROFILE_CLOCK_H
#define PW_WOW_PROFILE_CLOCK_H
#include <stdint.h>

#define PW_WOW_PROFILE_PROBE_CYCLES (UINT64_C(1) << 28)
#define PW_WOW_PROFILE_REPORT_MS UINT64_C(5000)
typedef struct PwWowProfileClock
{
    uint64_t probe_tsc, last_ms;
    unsigned have_probe, have_window;
} PwWowProfileClock;

static inline int pw_wow_profile_probe_due(PwWowProfileClock *clock, uint64_t tsc)
{
    if (clock->have_probe && tsc - clock->probe_tsc < PW_WOW_PROFILE_PROBE_CYCLES) return 0;
    clock->probe_tsc = tsc;
    clock->have_probe = 1;
    return 1;
}

/* Only called after a successful monotonic clock read. Clock errors preserve
 * the existing window; a backwards clock restarts its origin. An interval
 * output changes only when a report is due. Zero is a valid initial time. */
static inline int pw_wow_profile_report_due(PwWowProfileClock *clock, uint64_t ms, uint64_t *interval)
{
    if (!clock->have_window || ms < clock->last_ms)
    {
        clock->last_ms = ms;
        clock->have_window = 1;
        return 0;
    }
    if (ms - clock->last_ms < PW_WOW_PROFILE_REPORT_MS) return 0;
    *interval = ms - clock->last_ms;
    clock->last_ms = ms;
    return 1;
}
#endif
