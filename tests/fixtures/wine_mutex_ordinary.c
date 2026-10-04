/* SPDX-License-Identifier: MIT
 * Bounded ordinary Win32 mutex checks for paired runtime validation.
 * No forced termination, application faults, APC delivery or infinite waits.
 */
#define _WIN32_WINNT 0x0601
#include <windows.h>

typedef LONG (NTAPI *NtReleaseMutantFn)(HANDLE, LONG *);
static NtReleaseMutantFn nt_release;
static HANDLE report_file = INVALID_HANDLE_VALUE;
static unsigned checks, failures, cases;

struct line { char data[512]; unsigned used; };
static void text(struct line *line, const char *value)
{
    while (*value && line->used < sizeof(line->data) - 1)
        line->data[line->used++] = *value++;
}
static void hex(struct line *line, DWORD value)
{
    static const char digits[] = "0123456789abcdef";
    text(line, "0x");
    for (unsigned i = 0; i < 8; ++i)
        if (line->used < sizeof(line->data) - 1)
            line->data[line->used++] = digits[(value >> (28 - 4 * i)) & 15];
}
static void write_line(struct line *line)
{
    DWORD written;
    text(line, "\n");
    if (report_file != INVALID_HANDLE_VALUE)
        (void)WriteFile(report_file, line->data, line->used, &written, NULL);
    (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line->data, line->used, &written, NULL);
}
static void begin_case(const char *name)
{
    struct line line = {{0}, 0};
    ++cases;
    text(&line, "PW_MUTEX_ORDINARY case="); text(&line, name); write_line(&line);
}
static void check(const char *name, DWORD actual, DWORD expected)
{
    struct line line = {{0}, 0};
    ++checks;
    if (actual != expected) ++failures;
    text(&line, "PW_MUTEX_ORDINARY check="); text(&line, name);
    text(&line, " actual="); hex(&line, actual);
    text(&line, " expected="); hex(&line, expected);
    text(&line, actual == expected ? " result=PASS" : " result=FAIL");
    write_line(&line);
}
static BOOL valid(const char *name, HANDLE handle)
{
    BOOL ok = handle && handle != INVALID_HANDLE_VALUE;
    check(name, ok, TRUE);
    return ok;
}
static void close_handle(HANDLE handle)
{
    if (handle && handle != INVALID_HANDLE_VALUE) check("close_handle", CloseHandle(handle), TRUE);
}
static HANDLE mutex(void) { return CreateMutexW(NULL, FALSE, NULL); }
static void take_release(HANDLE handle)
{
    DWORD ret = WaitForSingleObject(handle, 0);
    check("take_free", ret, WAIT_OBJECT_0);
    if (ret == WAIT_OBJECT_0) check("release_taken", ReleaseMutex(handle), TRUE);
}

static void recursion(void)
{
    begin_case("recursion_previous_count");
    HANDLE handle = mutex();
    if (!valid("create_mutex", handle)) return;
    check("first_take", WaitForSingleObject(handle, 0), WAIT_OBJECT_0);
    check("recursive_take", WaitForSingleObject(handle, 0), WAIT_OBJECT_0);
    LONG previous = 99;
    check("first_native_release", (DWORD)nt_release(handle, &previous), 0);
    check("first_previous", (DWORD)previous, (DWORD)-1);
    check("last_native_release", (DWORD)nt_release(handle, &previous), 0);
    check("last_previous", (DWORD)previous, 0);
    take_release(handle); close_handle(handle);
}
static void ordinary_objects(void)
{
    begin_case("event_semaphore_fallback");
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE semaphore = CreateSemaphoreW(NULL, 0, 1, NULL);
    if (valid("create_event", event))
    {
        check("event_empty", WaitForSingleObject(event, 0), WAIT_TIMEOUT);
        check("set_event", SetEvent(event), TRUE);
        check("event_signaled", WaitForSingleObject(event, 0), WAIT_OBJECT_0);
        check("event_consumed", WaitForSingleObject(event, 0), WAIT_TIMEOUT);
    }
    if (valid("create_semaphore", semaphore))
    {
        LONG previous = 99;
        check("semaphore_empty", WaitForSingleObject(semaphore, 0), WAIT_TIMEOUT);
        check("signal_semaphore", ReleaseSemaphore(semaphore, 1, &previous), TRUE);
        check("semaphore_previous", (DWORD)previous, 0);
        check("semaphore_signaled", WaitForSingleObject(semaphore, 0), WAIT_OBJECT_0);
        check("semaphore_consumed", WaitForSingleObject(semaphore, 0), WAIT_TIMEOUT);
    }
    close_handle(event); close_handle(semaphore);
}
static void multiwait(void)
{
    begin_case("multiwait_any_all");
    HANDLE handles[2] = {mutex(), mutex()};
    if (valid("multiwait_first", handles[0]) && valid("multiwait_second", handles[1]))
    {
        take_release(handles[0]); take_release(handles[1]);
        DWORD ret = WaitForMultipleObjects(2, handles, FALSE, 0);
        check("wait_any", ret, WAIT_OBJECT_0);
        if (ret < WAIT_OBJECT_0 + 2) check("release_any", ReleaseMutex(handles[ret]), TRUE);
        ret = WaitForMultipleObjects(2, handles, TRUE, 0);
        check("wait_all", ret, WAIT_OBJECT_0);
        if (ret == WAIT_OBJECT_0)
        {
            check("release_all_first", ReleaseMutex(handles[0]), TRUE);
            check("release_all_second", ReleaseMutex(handles[1]), TRUE);
        }
        take_release(handles[0]); take_release(handles[1]);
    }
    close_handle(handles[0]); close_handle(handles[1]);
}
static void signal_wait(void)
{
    begin_case("signal_object_and_wait");
    HANDLE handle = mutex(), event = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (valid("signal_mutex", handle) && valid("signal_event", event))
    {
        check("signal_take", WaitForSingleObject(handle, 0), WAIT_OBJECT_0);
        check("signal_then_wait", SignalObjectAndWait(handle, event, 0, FALSE), WAIT_OBJECT_0);
        take_release(handle);
    }
    close_handle(event); close_handle(handle);
}
static void alertable_owned(void)
{
    begin_case("alertable_owned");
    HANDLE handle = mutex();
    if (!valid("alertable_mutex", handle)) return;
    check("alertable_initial_take", WaitForSingleObject(handle, 0), WAIT_OBJECT_0);
    check("alertable_recursive_take", WaitForSingleObjectEx(handle, 0, TRUE), WAIT_OBJECT_0);
    check("alertable_release_first", ReleaseMutex(handle), TRUE);
    check("alertable_release_last", ReleaseMutex(handle), TRUE);
    take_release(handle); close_handle(handle);
}
static void named_inherited(void)
{
    begin_case("named_inheritable");
    static const WCHAR name[] = L"pw_mutex_ordinary_named";
    HANDLE named = CreateMutexW(NULL, FALSE, name), opened = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, name);
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
    HANDLE inherited = CreateMutexW(&attributes, FALSE, NULL);
    if (valid("named_mutex", named) && valid("opened_named", opened))
    {
        check("named_take", WaitForSingleObject(named, 0), WAIT_OBJECT_0);
        check("opened_recursive_take", WaitForSingleObject(opened, 0), WAIT_OBJECT_0);
        check("opened_release", ReleaseMutex(opened), TRUE);
        check("named_release", ReleaseMutex(named), TRUE);
    }
    if (valid("inheritable_mutex", inherited)) take_release(inherited);
    close_handle(opened); close_handle(named); close_handle(inherited);
}
static void duplicate(void)
{
    begin_case("duplicate_owned_alias");
    HANDLE original = mutex(), alias = NULL;
    if (!valid("duplicate_mutex", original)) return;
    take_release(original);
    check("duplicate_handle", DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(),
                                               &alias, 0, FALSE, DUPLICATE_SAME_ACCESS), TRUE);
    if (valid("duplicate_alias", alias))
    {
        check("original_take", WaitForSingleObject(original, 0), WAIT_OBJECT_0);
        check("alias_recursive_take", WaitForSingleObject(alias, 0), WAIT_OBJECT_0);
        check("alias_release_recursive", ReleaseMutex(alias), TRUE);
        close_handle(original); original = NULL;
        check("alias_release_after_close", ReleaseMutex(alias), TRUE);
        take_release(alias);
    }
    close_handle(alias); close_handle(original);
}
static void close_reuse(void)
{
    begin_case("close_owned_and_recreate");
    HANDLE handle = mutex();
    if (valid("close_owned_mutex", handle))
    {
        check("close_owned_take", WaitForSingleObject(handle, 0), WAIT_OBJECT_0);
        close_handle(handle); /* Valid Win32 close; no further use of this handle. */
    }
    for (unsigned i = 0; i < 8; ++i)
    {
        handle = mutex();
        if (valid("recreated_mutex", handle)) take_release(handle);
        close_handle(handle);
    }
}
struct handoff { HANDLE mutex, ready, release; };
static DWORD WINAPI worker(void *argument)
{
    struct handoff *handoff = argument;
    if (WaitForSingleObject(handoff->mutex, 5000) != WAIT_OBJECT_0) return 10;
    BOOL notified = SetEvent(handoff->ready);
    DWORD waited = WaitForSingleObject(handoff->release, 5000);
    BOOL released = ReleaseMutex(handoff->mutex);
    return notified && waited == WAIT_OBJECT_0 && released ? 0 : 11;
}
static void contended_handoff(void)
{
    begin_case("zero_timeout_and_handoff");
    static struct handoff handoff;
    handoff.mutex = mutex();
    handoff.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    handoff.release = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE thread = NULL;
    BOOL joined = TRUE;
    if (valid("handoff_mutex", handoff.mutex) && valid("handoff_ready", handoff.ready) &&
        valid("handoff_release", handoff.release))
    {
        take_release(handoff.mutex);
        thread = CreateThread(NULL, 0, worker, &handoff, 0, NULL);
        if (valid("handoff_thread", thread))
        {
            DWORD ready = WaitForSingleObject(handoff.ready, 5000), code = 99;
            if (ready == WAIT_OBJECT_0)
                check("contended_zero_timeout", WaitForSingleObject(handoff.mutex, 0), WAIT_TIMEOUT);
            /* Always let the ordinary worker release its mutex and return. */
            check("allow_handoff_release", SetEvent(handoff.release), TRUE);
            check("worker_ready", ready, WAIT_OBJECT_0);
            check("worker_join", WaitForSingleObject(thread, 10000), WAIT_OBJECT_0);
            check("worker_exit_query", GetExitCodeThread(thread, &code), TRUE);
            check("worker_exit_code", code, 0);
            joined = code != STILL_ACTIVE && code != 99;
            if (joined) take_release(handoff.mutex);
        }
    }
    /* On an unexpected failed join, keep caller storage and all worker
     * handles valid through process cleanup; never close under a live worker. */
    if (joined)
    {
        close_handle(thread); close_handle(handoff.release); close_handle(handoff.ready); close_handle(handoff.mutex);
    }
}
static void pseudo_timeout(void)
{
    begin_case("pseudo_zero_timeout");
    check("current_thread_timeout", WaitForSingleObject(GetCurrentThread(), 0), WAIT_TIMEOUT);
    check("current_process_timeout", WaitForSingleObject(GetCurrentProcess(), 0), WAIT_TIMEOUT);
}

static DWORD WINAPI owning_worker(void *argument)
{
    struct handoff *handoff = argument;
    if (WaitForSingleObject(handoff->mutex, 5000) != WAIT_OBJECT_0) return 20;
    BOOL notified = SetEvent(handoff->ready);
    DWORD waited = WaitForSingleObject(handoff->release, 5000);
    /* Ordinary thread return abandons ownership; no explicit release. */
    return notified && waited == WAIT_OBJECT_0 ? 0 : 21;
}
static void normal_exit_abandonment(void)
{
    begin_case("normal_exit_abandonment");
    static struct handoff handoff;
    handoff.mutex = mutex();
    handoff.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    handoff.release = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE thread = NULL;
    BOOL joined = TRUE;
    if (valid("abandon_mutex", handoff.mutex) && valid("abandon_ready", handoff.ready) &&
        valid("abandon_release", handoff.release))
    {
        /* Exercise warm ownership before the other thread becomes owner. */
        for (unsigned i = 0; i < 8; ++i) take_release(handoff.mutex);
        thread = CreateThread(NULL, 0, owning_worker, &handoff, 0, NULL);
        if (valid("abandon_thread", thread))
        {
            DWORD ready = WaitForSingleObject(handoff.ready, 5000);
            check("abandon_worker_ready", ready, WAIT_OBJECT_0);
            if (ready == WAIT_OBJECT_0)
            {
                DWORD ret = WaitForSingleObject(handoff.mutex, 0);
                check("abandon_live_owner_timeout", ret, WAIT_TIMEOUT);
                if (ret == WAIT_OBJECT_0 || ret == WAIT_ABANDONED_0)
                    check("abandon_unexpected_take_release", ReleaseMutex(handoff.mutex), TRUE);
            }
            check("allow_owning_worker_return", SetEvent(handoff.release), TRUE);
            DWORD wait = WaitForSingleObject(thread, 10000), code = 99;
            check("abandon_worker_join", wait, WAIT_OBJECT_0);
            joined = wait == WAIT_OBJECT_0;
            if (joined)
            {
                check("abandon_exit_query", GetExitCodeThread(thread, &code), TRUE);
                check("abandon_exit_code", code, 0);
                if (ready == WAIT_OBJECT_0 && code == 0)
                {
                    DWORD ret = WaitForSingleObject(handoff.mutex, 5000);
                    check("abandon_transfer", ret, WAIT_ABANDONED_0);
                    if (ret == WAIT_OBJECT_0 || ret == WAIT_ABANDONED_0)
                    {
                        DWORD recursive = WaitForSingleObject(handoff.mutex, 0);
                        check("abandon_recursive_take", recursive, WAIT_OBJECT_0);
                        if (recursive == WAIT_OBJECT_0)
                            check("abandon_release_recursive", ReleaseMutex(handoff.mutex), TRUE);
                        check("abandon_release_transferred", ReleaseMutex(handoff.mutex), TRUE);
                        take_release(handoff.mutex);
                    }
                }
            }
        }
    }
    /* Static caller storage and worker handles survive an unexpected failed join. */
    if (joined)
    {
        close_handle(thread); close_handle(handoff.release); close_handle(handoff.ready); close_handle(handoff.mutex);
    }
}

void WINAPI mainCRTStartup(void)
{
    report_file = CreateFileW(L"pw-mutex-ordinary.log", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    struct line line = {{0}, 0};
    text(&line, "PW_MUTEX_ORDINARY start pointer_bits="); hex(&line, sizeof(void *) * 8); write_line(&line);
    nt_release = (NtReleaseMutantFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReleaseMutant");
    check("native_release_export", nt_release != NULL, TRUE);
    if (nt_release)
    {
        recursion(); ordinary_objects(); multiwait(); signal_wait(); alertable_owned();
        named_inherited(); duplicate(); close_reuse(); contended_handoff(); pseudo_timeout();
        normal_exit_abandonment();
    }
    check("case_count", cases, 11);
    line.used = 0;
    text(&line, "PW_MUTEX_ORDINARY done cases="); hex(&line, cases);
    text(&line, " checks="); hex(&line, checks);
    text(&line, " failures="); hex(&line, failures);
    text(&line, failures ? " result=FAIL" : " result=PASS"); write_line(&line);
    if (report_file != INVALID_HANDLE_VALUE) (void)CloseHandle(report_file);
    ExitProcess(failures ? 1 : 0);
}
