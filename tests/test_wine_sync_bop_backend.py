#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile the actual warm-only native API with bounded, local cache state.

No guest execution, native faults, Wine, or asynchronous context is exercised.
The later BOP adapter remains a separate runtime validation requirement.
"""
from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_wine_shared_sync_client import ROOT, additions, body, new_side

PATCH = ROOT / "wine/patches/0890-ntdll-ps5-warm-sync-native-api.patch"


def main():
    mutex = ROOT / "wine/patches/0820-ntdll-ps5-shared-mutex-client.patch"
    sync = ROOT / "wine/patches/0887-ntdll-ps5-shared-sync-client.patch"
    source = new_side(PATCH, "dlls/ntdll/unix/server.c")
    functions = ["static inline __attribute__((always_inline)) unsigned int server_try_shared_mutex_cached(",
                 "static unsigned int server_try_shared_mutex(",
                 "static inline __attribute__((always_inline)) unsigned int server_try_shared_sync_cached(",
                 "static unsigned int server_try_shared_sync_inprocess(",
                 "static int try_cached_sync_bop(",
                 "DECLSPEC_EXPORT const struct pw_sync_bop_backend *__wine_ps5_sync_bop_backend("]
    code = "\n".join(body(source, signature) for signature in functions)
    # Ordinary behavior is byte-for-byte the prior helper body after removing
    # the single warm-only early exit and the new parameter/name.
    original_mutex = body(new_side(mutex, "dlls/ntdll/unix/server.c"),
                          "static unsigned int server_try_shared_mutex(")
    original_sync = body(new_side(sync, "dlls/ntdll/unix/server.c"),
                         "static unsigned int server_try_shared_sync_inprocess(")
    actual_mutex = body(source, functions[0]).replace("server_try_shared_mutex_cached(",
                                                    "server_try_shared_mutex(")
    actual_mutex = actual_mutex.replace("LONG *prev_count, int allow_fill )", "LONG *prev_count )")
    actual_sync = body(source, functions[2]).replace("server_try_shared_sync_cached(",
                                                   "server_try_shared_sync_inprocess(")
    actual_sync = actual_sync.replace("unsigned int *previous, int allow_fill)", "unsigned int *previous)")
    declaration = "static inline __attribute__((always_inline)) unsigned int"
    actual_mutex = actual_mutex.replace(declaration, "static unsigned int")
    actual_sync = actual_sync.replace(declaration, "static unsigned int")
    gate = "        if (!allow_fill) return STATUS_NOT_IMPLEMENTED;\n"
    assert actual_mutex.count(gate) == actual_sync.count(gate) == 1
    assert actual_mutex.replace(gate, "") == original_mutex
    assert actual_sync.replace(gate, "") == original_sync
    # The production PRX descriptor must expose the discovery entry.
    assert "__wine_ps5_sync_bop_backend" in (ROOT / "tools/build_wine_ps5.sh").read_text()
    with tempfile.TemporaryDirectory(prefix="pw-sync-bop-api-") as temp:
        folder = Path(temp)
        for patch, name in [
            (ROOT / "wine/patches/0810-server-ps5-shared-mutex-word.patch", "ps5_mutex_word.h"),
            (mutex, "ps5_mutex_backend.h"),
            (ROOT / "wine/patches/0885-server-ps5-shared-sync-word.patch", "ps5_sync_word.h"),
            (sync, "ps5_sync_backend.h"),
            (PATCH, "ps5_sync_bop.h"),
        ]:
            (folder / name).write_text(additions(patch, "include/wine/" + name))
        (folder / "actual_helpers.inc").write_text(code)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        flags = shlex.split(os.environ.get("CFLAGS", "-O2 -g -Wall -Wextra -Werror"))
        executable = folder / "test"
        subprocess.run([*compiler, *flags, "-std=gnu11", "-pthread", "-I", str(folder),
                        str(ROOT / "tests/fixtures/wine_sync_bop_backend.c"), "-o", str(executable)],
                       check=True, timeout=60)
        subprocess.run([str(executable)], check=True, timeout=60)
        # Ordinary non-inprocess builds must expose no compatible backend.
        stub = folder / "stub.c"
        stub.write_text('#include <stddef.h>\n#include "ps5_sync_bop.h"\n#define DECLSPEC_EXPORT\n' +
                        body(source, functions[-1]) +
                        "int main(void) { return __wine_ps5_sync_bop_backend(PW_SYNC_BOP_VERSION) != NULL; }\n")
        subprocess.run([*compiler, *flags, "-Wno-unused-parameter", "-I", str(folder),
                        str(stub), "-o", str(folder / "stub")], check=True, timeout=60)
        subprocess.run([str(folder / "stub")], check=True, timeout=10)


if __name__ == "__main__":
    main()
