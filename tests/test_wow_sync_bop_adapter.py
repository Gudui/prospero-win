#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bounded native adapter transactions; no guest/Wine/console execution."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='pw-sync-bop-adapter-') as directory:
        executable = Path(directory) / 'adapter-test'
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        flags = shlex.split(os.environ.get('CFLAGS', '-O2 -g -Wall -Wextra -Werror'))
        subprocess.run([*compiler, *flags, '-std=c11', '-I', str(ROOT),
                        str(ROOT/'tests/fixtures/wow_sync_bop_adapter.c'), '-o', str(executable)],
                       check=True, timeout=60)
        subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == '__main__':
    main()
