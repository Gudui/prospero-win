#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile/run the exact atomic header and added server helper bodies.

Native callbacks model legacy list/refcount operations; this does not run
Wine or prove full integration, signal, termination or exception semantics.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "wine/patches/0810-server-ps5-shared-mutex-word.patch"


def added_header():
    text = PATCH.read_text()
    diffs = text.split("diff --git ")[1:]
    match = [part for part in diffs if part.splitlines()[0].endswith(" b/include/wine/ps5_mutex_word.h")]
    assert len(match) == 1
    return "\n".join(line[1:] for line in match[0].splitlines()
                     if line.startswith("+") and not line.startswith("+++")) + "\n"


def added_server_helpers():
    parts = PATCH.read_text().split("diff --git ")[1:]
    part = next(p for p in parts if p.splitlines()[0].endswith(" b/server/mutex.c"))
    additions = "\n".join(line[1:] for line in part.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
    core = additions[additions.index("/* Native-only cold backend."):]
    core = core[:core.index("\n#endif")]
    cold = additions[additions.index("void ps5_mutex_retire_object("):]
    cold = cold[:cold.index("\n#endif")]
    return core + "\n" + cold + "\n"


def client_addition(file):
    patch = ROOT / "wine/patches/0820-ntdll-ps5-shared-mutex-client.patch"
    parts = patch.read_text().split("diff --git ")[1:]
    part = next(p for p in parts if p.splitlines()[0].endswith(" b/" + file))
    return "\n".join(line[1:] for line in part.splitlines()
                     if line.startswith("+") and not line.startswith("+++")) + "\n"


def added_metadata_policy():
    added = client_addition("server/mutex.c")
    start = added.index("int ps5_describe_mutex_word(")
    brace = added.index("{", start)
    depth = 1
    for end in range(brace + 1, len(added)):
        if added[end] == "{": depth += 1
        if added[end] == "}": depth -= 1
        if not depth: return added[start:end + 1] + "\n"
    raise AssertionError("unterminated metadata policy")


def reconstructed_dump():
    # Complete public Wine function retained as context plus the single 0810
    # addition. Require the exact old function before reconstructing 0840.
    text = PATCH.read_text()
    start = text.index("\n static void mutex_sync_dump( struct object *obj, int verbose )\n {")
    end = text.index("\n@@ ", start)
    body = "\n".join(line[1:] for line in text[start:end].splitlines()
                     if line.startswith((" ", "+"))) + "\n"
    patch = (ROOT / "wine/patches/0840-server-ps5-readonly-mutex-dump.patch").read_text()
    assert patch.count("@@ ") == 1
    assert patch.count("diff --git a/server/mutex.c b/server/mutex.c") == 1
    hunk = patch[patch.index("@@ "):].splitlines()[1:]
    before = "\n".join(line[1:] for line in hunk if line.startswith((" ", "-")))
    after = "\n".join(line[1:] for line in hunk if line.startswith((" ", "+")))
    assert body.rstrip() == before.rstrip()
    return after.rstrip() + "\n"


def main():
    with tempfile.TemporaryDirectory(prefix="pw-shared-mutex-word-") as temp:
        folder = Path(temp)
        (folder / "ps5_mutex_word.h").write_text(added_header())
        (folder / "ps5_mutex_backend.h").write_text(client_addition("include/wine/ps5_mutex_backend.h"))
        (folder / "ps5_mutex_server.inc").write_text(added_server_helpers() + added_metadata_policy())
        (folder / "ps5_mutex_dump.inc").write_text(reconstructed_dump())
        binary = folder / "test"
        command = shlex.split(os.environ.get("CC", "cc"))
        command += shlex.split(os.environ.get("CFLAGS", "-O2 -g -Wall -Wextra -Werror"))
        command += ["-std=gnu11", "-pthread", "-I", str(folder),
                    str(ROOT / "tests/test_wine_shared_mutex_word.c"), "-o", str(binary)]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True, timeout=60)
        server_command = command.copy()
        server_command += ["-DWINE_INPROCESS_SERVER"]
        server_command[server_command.index(str(ROOT / "tests/test_wine_shared_mutex_word.c"))] = str(
            ROOT / "tests/test_wine_shared_mutex_server.c")
        subprocess.run(server_command, check=True)
        subprocess.run([str(binary)], check=True, timeout=60)


if __name__ == "__main__":
    main()
