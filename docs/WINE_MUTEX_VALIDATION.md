# Ordinary 32-bit mutex validation

`wine-mutex-ordinary.exe` exercises ordinary Win32 operations through the
32-bit Wine/WoW64 syscall path. It is a runtime regression fixture for a
matched module pair, not a performance benchmark or a complete lifecycle
validation suite.

Build without starting Wine:

```sh
python3 tools/build_wine_mutex_ordinary.py --out /tmp/wine-mutex-ordinary
```

The builder requires the MinGW i686 compiler and objdump. It checks that
the result is a PE32 console executable importing only kernel32, and saves
the compiler command, source/executable hashes and PE inspection. The
program resolves `NtReleaseMutant` from ntdll to check its previous-count
output using valid local caller storage. It has no CRT dependency.

The ten groups cover:

- Recursion and native previous-count results.
- Event and semaphore fallback.
- WaitForMultipleObjects any/all after ordinary mutex activation.
- SignalObjectAndWait.
- An alertable wait on a mutex already owned by the same thread.
- Named/opened and initially inheritable mutexes.
- Duplicate aliases, including closing the original while owned.
- Closing an owned mutex and bounded subsequent creation/close.
- Zero-timeout contention and a coordinated ordinary thread handoff.
- Zero-timeout waits on the current thread/process pseudo handles.

The worker releases its mutex and returns normally. Every wait has a
finite timeout; the program requests no forced thread termination, APC
delivery or invalid application memory access. These operations do not
cover abandonment on forced termination, asynchronous signals, exception
delivery or every handle-lifetime race. Those remain separate required
runtime gates for the shared backend.

The console owner runs the same executable with the default pair and with
each candidate pair, keeping the prefix and launch settings fixed. Record
the exact executable/module hashes, switch state, all check results and
the clean Wine exit. For a default-off shared-pair control, both
`pw_mutex_shared` and the older `pw_mutex_fast` switches must be off.

The executable writes `pw-mutex-ordinary.log` in its working directory and
also sends each line to standard output. Acceptance needs all ten groups,
no failing checks, `PW_MUTEX_ORDINARY done ... result=PASS`, exit status zero
and the collector's clean Wine exit. A successful compile or startup line
does not establish this runtime result.

The full performance acceptance remains the fixed GTA IV route at
1920×1080/60 Hz, profiling off, average at least 58 FPS and minimum at least
50 FPS, plus the HL2/load gates and the owner's 600-second stability run.
Ordinary console A/B uses a 480-second script and a matched 200–440-second
window. These goals remain separate from this semantic fixture.
