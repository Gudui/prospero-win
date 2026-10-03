#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Execute the actual native service/timing functions with deterministic clocks."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "wine/wowprospero/unix.c").read_text()


def function(name):
    match = re.search(r"static (?:void|uint64_t) " + name + r"\([^;]*?\)\s*\{", SOURCE)
    assert match, name
    start = match.start()
    brace = SOURCE.index("{", match.start())
    depth = 1
    end = brace + 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    return SOURCE[start:end]


STRUCT = re.search(r"struct pw_thread\s*\{.*?\n\};", SOURCE, re.S)[0]
HARNESS = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "pw_x86_engine.h"
#include "pw_x86_hostexec.h"
#include "service_timing.h"
typedef uint64_t UINT64;
typedef uint32_t UINT;
typedef int32_t INT;
#include "wowprospero.h"

static uint64_t now=1000000, ticks=100;
static unsigned clock_reads, clock_fail, marker, alloc_fail, alloc_calls;
static unsigned cache_reports, execution_reports;
static const char *env;
static int timing_enabled=-1, service_timing_enabled;
static int mock_clock(int id, struct timespec *ts)
{
    assert(id==CLOCK_MONOTONIC); clock_reads++;
    if(clock_fail) return -1;
    ts->tv_sec=now/1000000000; ts->tv_nsec=now%1000000000; return 0;
}
static char *mock_getenv(const char *name)
{
    return !strcmp(name,"PW_WOW_SERVICE_TIMING")?(char *)env:NULL;
}
static int mock_stat(const char *name, struct stat *st)
{
    (void)st;
    return marker && !strcmp(name,"/data/prospero-win/pw_wow_service_timing")?0:-1;
}
static void *mock_calloc(size_t n, size_t size)
{
    alloc_calls++; return alloc_fail?NULL:calloc(n,size);
}
static struct { struct { void *UniqueThread; } ClientId; } teb={0};
#define NtCurrentTeb() (&teb)
#define clock_gettime(id,ts) mock_clock(id,ts)
#define getenv(name) mock_getenv(name)
#define stat(name,st) mock_stat(name,st)
#define calloc(n,size) mock_calloc(n,size)
#define __rdtsc() (ticks)
#define PW_WOW_TIMING_TRIGGER "/data/prospero-win/pw_wow_timing"
@STRUCT@
static void cache_report(struct pw_thread *thread, uint64_t wall, unsigned final)
{ (void)thread; (void)wall; (void)final; cache_reports++; }
static void execution_report(struct pw_thread *thread)
{ (void)thread; execution_reports++; }
@FUNCTIONS@

int main(void)
{
    struct pw_thread thread={0};
    teb.ClientId.UniqueThread=(void *)(uintptr_t)0x24;
    thread.cache_report_id=7;
    env=NULL; marker=0; timing_init();
    assert(!timing_enabled && !service_timing_enabled);
    service_attach(&thread); service_leave(&thread,PW_WOW_SYSCALL);
    assert(!alloc_calls && !clock_reads && !thread.services_attempted);
    marker=1; timing_init();
    assert(timing_enabled && service_timing_enabled);
    env="0"; timing_init(); assert(!timing_enabled && !service_timing_enabled);
    env=""; timing_init(); assert(!service_timing_enabled);
    env="1"; marker=0; timing_init(); assert(timing_enabled && service_timing_enabled);
    alloc_fail=1; service_attach(&thread); service_attach(&thread);
    assert(thread.services_attempted && !thread.services && alloc_calls==1);
    thread.services_attempted=0; alloc_fail=0; service_attach(&thread);
    assert(thread.services && alloc_calls==2);
    thread.state.gpr[0]=0x1000;
    service_leave(&thread,PW_WOW_UNIXCALL); assert(!thread.services->pending);
    service_leave(&thread,PW_WOW_SYSCALL);
    assert(thread.services->pending && thread.services->service==0x1000);
    thread.state.gpr[0]=0xc0000001; /* Status replaced EAX; original ID survives. */
    now+=235000000000ull; ticks+=100;
    timing_enter(&thread);
    assert(!thread.services->pending && thread.services->total.calls==1 &&
           thread.services->total.wall_ns==235000000000ull);
    service_report(&thread,0);
    thread.state.gpr[0]=7;
    service_leave(&thread,PW_WOW_SYSCALL); clock_fail=1;
    now+=100; ticks+=100; timing_enter(&thread);
    assert(thread.services->clock_errors==1 && thread.services->total.calls==1);
    clock_fail=0;
    now+=500001; ticks+=100;
    timing_report(&thread,ticks);
    assert(cache_reports==1 && execution_reports==1 && !thread.t_inside && !thread.n_sys);
    clock_fail=1; timing_report(&thread,ticks+100);
    assert(cache_reports==1 && execution_reports==1); /* No uninitialized timestamp. */
    clock_fail=0;
    thread.state.gpr[0]=0x1000;
    service_leave(&thread,PW_WOW_SYSCALL); now+=1000; ticks+=100;
    timing_enter(&thread); timing_leave(&thread,PW_WOW_SYSCALL);
    assert(thread.services->total.calls==2 && thread.last_reason==PW_WOW_SYSCALL);
    thread.state.gpr[0]=0x2000; service_leave(&thread,PW_WOW_SYSCALL);
    service_report(&thread,1); /* Still pending, never fabricated as complete. */
    free(thread.services);
    return 0;
}
'''

names = ("timing_now_ns", "timing_init", "service_report", "service_leave", "service_attach",
         "timing_report", "timing_enter", "timing_leave")
code = HARNESS.replace("@STRUCT@", STRUCT).replace("@FUNCTIONS@", "\n".join(function(n) for n in names))
with tempfile.TemporaryDirectory() as directory:
    source = Path(directory) / "native.c"
    binary = Path(directory) / "native"
    source.write_text(code)
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                   shlex.split(os.environ.get("CFLAGS", "-O2 -std=c11 -Wall -Wextra -Werror")) +
                   ["-I" + str(ROOT / "src"), "-I" + str(ROOT / "wine/wowprospero"),
                    str(source), "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    lines = result.stderr.splitlines()
    summaries = [dict(re.findall(r"(\w+)=(\d+)", line)) for line in lines
                 if "wowprospero services:" in line]
    entries = [dict(re.findall(r"(\w+)=(\d+)", line)) for line in lines
               if "wowprospero service:" in line]
    assert summaries[0]["calls"] == "1" and summaries[0]["wall_ns"] == "235000000000"
    assert entries[0]["id"] == "4096" and entries[0]["max_ns"] == "235000000000"
    assert summaries[-1]["final"] == "1" and summaries[-1]["pending"] == "1"
    assert summaries[-1]["pending_id"] == "8192" and summaries[-1]["clock_errors"] == "1"
    assert summaries[-1]["calls"] == "2" and summaries[-1]["instance"] == "7"
    assert "allocation_failed=1" in lines[0]
print("native service timing passed: default off, trigger/env override, allocation failure, BOP ID, "
      "235-second span, bad clocks, real timing integration, cumulative final rows and pending call")
