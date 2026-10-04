#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bounded native checks of the direct-request eligibility prefix.

Compile the patch's actual atomic helpers, whitelist and eligibility prefix
with mock locking and thread lookup. This does not start Wine, acquire real
locks, exercise the server protocol, or reproduce a console deadlock.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "wine/patches/0770-server-ps5-run-sync-requests-on-client-threads.patch"


def after_image_chunks(relative: str) -> str:
    section = PATCH.read_text().split(f"diff --git a/{relative} b/{relative}\n", 1)[1]
    section = section.split("\ndiff --git ", 1)[0]
    return "\n".join(line[1:] for line in section.splitlines()
                     if line.startswith(("+", " ")) and not line.startswith("+++"))


def function(source: str, name: str) -> str:
    start = source.index(name + "(")
    start = source.rfind("\n", 0, start) + 1
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main() -> int:
    header = after_image_chunks("server/request.h")
    request = after_image_chunks("server/request.c")
    helpers = "\n".join(function(header, name) for name in (
        "inprocess_direct_enabled", "inprocess_set_direct_enabled"))
    whitelist = function(request, "is_direct_request")
    direct = function(request, "pw_wineserver_call_direct")
    boundary = "    /* a thread the server has not initialised"
    assert boundary in direct, "Eligibility boundary must precede dispatch"
    prefix = direct.split(boundary, 1)[0]
    prefix += """
    (void)&reply;
    (void)teb;
    (void)ret;
    pthread_mutex_unlock( &inprocess_server_mutex );
    return 0;
}
"""
    names = re.findall(r"case (REQ_\w+):", whitelist)
    assert names and "REQ_create_file" in names and "REQ_get_handle_fd" in names
    fixture = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned int data_size_t;
typedef uint64_t client_ptr_t;
enum request { @ENUM@, REQ_unknown = 255 };
union generic_reply { unsigned int unused; };
struct thread { int unused; };
struct __server_request_info {
    union {
        struct { struct { enum request req; data_size_t request_size; } request_header; } req;
    } u;
    unsigned int data_count;
    struct { const void *ptr; data_size_t size; } data[2];
};
#define DECLSPEC_EXPORT
#define __SERVER_MAX_DATA 2
static int inprocess_direct_ok;
static int inprocess_server_mutex;
static unsigned int locks, unlocks, copies, lookups;
static int disable_on_lock;
@HELPERS@
static void lock_server_for_client(void)
{
    ++locks;
    if (disable_on_lock) inprocess_set_direct_enabled(0);
}
static int mock_unlock(int *mutex)
{
    assert(mutex == &inprocess_server_mutex);
    ++unlocks;
    return 0;
}
static void *mock_copy(void *dst, const void *src, size_t bytes)
{
    ++copies;
    return __builtin_memcpy(dst, src, bytes);
}
static struct thread *get_thread_from_id(unsigned int tid)
{
    static struct thread known;
    ++lookups;
    return tid == 42 ? &known : NULL;
}
#define pthread_mutex_unlock mock_unlock
#define memcpy mock_copy
@WHITELIST@
@PREFIX@
static struct __server_request_info make_request(enum request request)
{
    static const char payload[] = "ok";
    struct __server_request_info info = {0};
    info.u.req.request_header.req = request;
    info.u.req.request_header.request_size = 2;
    info.data_count = 1;
    info.data[0].ptr = payload;
    info.data[0].size = 2;
    return info;
}
static void reset(int enabled)
{
    inprocess_set_direct_enabled(enabled);
    assert(inprocess_direct_enabled() == enabled);
    locks = unlocks = copies = lookups = 0;
    disable_on_lock = 0;
}
int main(void)
{
    struct __server_request_info info;
    /* Disabled mode returns before copying data, locking, or thread lookup. */
    reset(0);
    info = make_request(REQ_create_file);
    assert(pw_wineserver_call_direct(42, 1, &info) == 1);
    assert(!locks && !unlocks && !copies && !lookups);
    /* Re-enabled mode reaches dispatch eligibility exactly once. */
    reset(1);
    info = make_request(REQ_get_handle_fd);
    assert(pw_wineserver_call_direct(42, 1, &info) == 0);
    assert(locks == 1 && unlocks == 1 && copies == 1 && lookups == 1);
    /* The under-lock check remains authoritative after an enabled precheck. */
    reset(1);
    disable_on_lock = 1;
    info = make_request(REQ_create_file);
    assert(pw_wineserver_call_direct(42, 1, &info) == 1);
    assert(locks == 1 && unlocks == 1 && copies == 1 && !lookups);
    reset(1);
    info = make_request(REQ_unknown);
    assert(pw_wineserver_call_direct(42, 1, &info) == 1);
    assert(!locks && !unlocks && !copies && !lookups);
    /* A thread not registered in the server still falls back and unlocks. */
    reset(1);
    info = make_request(REQ_get_handle_fd);
    assert(pw_wineserver_call_direct(0, 1, &info) == 1);
    assert(locks == 1 && unlocks == 1 && copies == 1 && lookups == 1);
    puts("direct eligibility passed: disabled, enabled, changed gate, unsupported, unknown thread");
    return 0;
}
"""
    fixture = fixture.replace("@ENUM@", ", ".join(names))
    fixture = fixture.replace("@HELPERS@", helpers).replace("@WHITELIST@", whitelist)
    fixture = fixture.replace("@PREFIX@", prefix)
    cc = shlex.split(os.environ.get("CC", "cc"))
    flags = shlex.split(os.environ.get("CFLAGS", "-O2 -std=c11 -Wall -Wextra -Werror"))
    with tempfile.TemporaryDirectory(prefix="pw-direct-gate-") as directory:
        source = Path(directory) / "gate.c"
        executable = Path(directory) / "gate"
        source.write_text(fixture)
        subprocess.run([*cc, *flags, str(source), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True, timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
