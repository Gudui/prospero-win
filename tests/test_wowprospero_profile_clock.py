#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile the exact report gate from unix.c with a controlled native clock.

No Wine, game, signals or hardware timing/performance claims.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / "wine/wowprospero/unix.c").read_text()
    function = source[source.index("static void profile_maybe_dump(void)"):]
    start = function.index("    if(!thread || !thread->profile) return;")
    end = function.index("    tid = HandleToULong(NtCurrentTeb()->ClientId.UniqueThread);")
    gate = function[start:end]
    assert "NtCurrentTeb" not in function[:end]
    assert gate.count("clock_gettime(") == 1
    assert gate.index("pw_wow_profile_probe_due") < gate.index("clock_gettime")
    template = r'''
#include "profile_clock.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
struct pw_thread { void *profile; PwWowProfileClock profile_clock; };
static struct pw_thread enabled={.profile=(void *)1}, *self=&enabled;
static uint64_t tsc, clock_ms, reports, latest_interval, tsc_reads, clock_reads;
static int clock_error;
static uint64_t fixture_tsc(void) { ++tsc_reads; return tsc; }
static int fixture_clock(int id,struct timespec *now) {
    assert(id==CLOCK_MONOTONIC); ++clock_reads;
    if(clock_error) return -1;
    now->tv_sec=(time_t)(clock_ms/1000);
    now->tv_nsec=(long)((clock_ms%1000)*1000000);
    return 0;
}
#define __rdtsc fixture_tsc
#define clock_gettime fixture_clock
static void fixture_exit(void) {
    struct pw_thread *thread=self;
    struct timespec now;
    uint64_t ms,interval;
/* ACTUAL_GATE */
    latest_interval=interval; ++reports;
}
static void reset(void) {
    enabled=(struct pw_thread){.profile=(void *)1};self=&enabled;
    tsc=clock_ms=reports=latest_interval=tsc_reads=clock_reads=0;clock_error=0;
}
static void boundaries(void) {
    PwWowProfileClock c={0}; uint64_t out=91;
    assert(pw_wow_profile_probe_due(&c,0));
    assert(!pw_wow_profile_probe_due(&c,0));
    assert(!pw_wow_profile_probe_due(&c,PW_WOW_PROFILE_PROBE_CYCLES-1));
    assert(pw_wow_profile_probe_due(&c,PW_WOW_PROFILE_PROBE_CYCLES));
    assert(!pw_wow_profile_report_due(&c,0,&out) && out==91);
    assert(!pw_wow_profile_report_due(&c,4999,&out) && out==91);
    assert(pw_wow_profile_report_due(&c,5000,&out) && out==5000);
    assert(!pw_wow_profile_report_due(&c,5001,&out));
    assert(!pw_wow_profile_report_due(&c,4000,&out) && c.last_ms==4000);
    assert(pw_wow_profile_report_due(&c,9000,&out) && out==5000);
    /* Unsigned TSC wrap preserves a short interval. Backwards/large jumps
     * permit a probe but never substitute for a monotonic report interval. */
    c=(PwWowProfileClock){0}; assert(pw_wow_profile_probe_due(&c,UINT64_MAX-255));
    assert(!pw_wow_profile_probe_due(&c,0));
    assert(!pw_wow_profile_probe_due(&c,PW_WOW_PROFILE_PROBE_CYCLES-257));
    assert(pw_wow_profile_probe_due(&c,PW_WOW_PROFILE_PROBE_CYCLES-256));
    c=(PwWowProfileClock){0}; assert(pw_wow_profile_probe_due(&c,1000));
    assert(pw_wow_profile_probe_due(&c,999));
    assert(!pw_wow_profile_report_due(&c,123,&out));
    assert(!pw_wow_profile_report_due(&c,124,&out));
}
int main(void) {
    boundaries(); reset(); self=NULL;
    for(unsigned i=0;i<100000;i++) fixture_exit();
    assert(!tsc_reads && !clock_reads && !reports);
    self=&enabled;enabled.profile=NULL;
    for(unsigned i=0;i<100000;i++) fixture_exit();
    assert(!tsc_reads && !clock_reads && !reports);
    reset();
    /* Synthetic 1GHz TSC and wall clock: two million ordinary exits over
     * forty seconds, with an independent bound on probe count/report delay. */
    for(unsigned i=0;i<=2000000;i++) {
        tsc=(uint64_t)i*20000;clock_ms=tsc/1000000;fixture_exit();
        if(reports) assert(latest_interval>=5000 && latest_interval<=5269);
    }
    assert(reports==7 && clock_reads<=151 && tsc_reads==2000001);
    uint64_t measured_calls=clock_reads;reset();
    fixture_exit();assert(enabled.profile_clock.have_window && !reports && clock_reads==1);
    clock_error=1;tsc=PW_WOW_PROFILE_PROBE_CYCLES;clock_ms=8000;
    fixture_exit();assert(!reports && enabled.profile_clock.last_ms==0);
    clock_error=0;tsc+=PW_WOW_PROFILE_PROBE_CYCLES;fixture_exit();
    assert(reports==1 && latest_interval==8000);
    reset();fixture_exit();tsc=UINT64_C(1)<<40;clock_ms=1;fixture_exit();assert(!reports);
    printf("PASS: actual gate disabled=zero reads, 2000001 exits/%llu clock probes, monotonic window, error/boundary/wrap checks\n",
           (unsigned long long)measured_calls);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="pw-profile-clock-") as temp:
        folder = Path(temp)
        fixture = folder / "fixture.c"
        fixture.write_text(template.replace("/* ACTUAL_GATE */", gate))
        command = shlex.split(os.environ.get("CC", "cc"))
        command += shlex.split(os.environ.get("CFLAGS", "-O2 -g -Wall -Wextra -Werror"))
        command += ["-std=gnu11", "-I", str(ROOT / "wine/wowprospero"), str(fixture), "-o", str(folder / "test")]
        subprocess.run(command, check=True, timeout=60)
        subprocess.run([str(folder / "test")], check=True, timeout=20)


if __name__ == "__main__":
    main()
