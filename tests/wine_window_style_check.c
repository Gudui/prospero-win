/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Ordinary bounded console UI check of patch 0800: GetWindowLong(GWL_STYLE), IsIconic and IsZoomed
 * answered by user32 from the server's shared window data.
 *
 * Every check compares what user32 answers (GetWindowLongW/A, IsIconic,
 * IsZoomed, and the last error) with what win32u answers through the system
 * call itself (NtUserCallHwndParam(hwnd, GWL_STYLE, GetWindowLongW)), after
 * every kind of style change: ShowWindow (show, minimize, restore, maximize,
 * hide), SetWindowLongW/A, SetWindowPos show/hide, WM_STYLECHANGING edits,
 * CreateWindow with WS_MINIMIZE or WS_MAXIMIZE, another thread's window,
 * message-only and desktop windows, invalid, destroyed, 16-bit and
 * wrong-generation handles, reads from the CBT hook and WM_NCCREATE/WM_CREATE,
 * a bounded writer thread racing a reader, and 32 ordinary windows.
 * Synthetic mapping growth and reservation limits belong to the native
 * fixture, rather than allocating thousands of live console windows.
 *
 * Build both PE architectures with MinGW. The console owner runs each with
 * publication OFF and ON using a complete matching protocol-962 bundle.
 * This does not run as part of `make test` and does not require host Wine.
 * Thread waits fail after ten seconds; the fixture then exits immediately.
 * Optional --bench measures a small per-call workload, not gameplay FPS.
 *
 * Output lines:
 *   stylecheck: name=N ok=0|1 ...        an assertion (counted in failures)
 *   stylecheck: bench name=N ns_per_op_median=X
 *   stylecheck: done failures=N
 *
 * Build: i686-w64-mingw32-gcc -O2 -o stylecheck32.exe wine_window_style_check.c
 *        x86_64-w64-mingw32-gcc -O2 -o stylecheck64.exe wine_window_style_check.c
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define CODE_GETWINDOWLONGA 9
#define CODE_GETWINDOWLONGW 10

static ULONG_PTR (WINAPI *pNtUserCallHwndParam)(HWND, DWORD_PTR, DWORD);
static int failures, checks;
static LARGE_INTEGER freq;

static void report(const char *name, int ok, const char *fmt, ...)
{
    char extra[300] = "";
    va_list args;
    if (fmt) { va_start(args, fmt); vsnprintf(extra, sizeof(extra), fmt, args); va_end(args); }
    printf("stylecheck: name=%s ok=%d %s\n", name, ok, extra);
    fflush(stdout);
    if (!ok) failures++;
}

/* one comparison: user32's answers against win32u's, including the last error */
static int compare(const char *name, HWND hwnd, int quiet)
{
    DWORD ref, ref_err, w, w_err, a, a_err;
    BOOL iconic, zoomed;
    int ok;

    SetLastError(0xdeadbeef);
    ref = (DWORD)pNtUserCallHwndParam(hwnd, (DWORD_PTR)(LONG_PTR)GWL_STYLE, CODE_GETWINDOWLONGW);
    ref_err = GetLastError();
    SetLastError(0xdeadbeef);
    w = GetWindowLongW(hwnd, GWL_STYLE);
    w_err = GetLastError();
    SetLastError(0xdeadbeef);
    a = GetWindowLongA(hwnd, GWL_STYLE);
    a_err = GetLastError();
    iconic = IsIconic(hwnd);
    zoomed = IsZoomed(hwnd);
    ok = w == ref && a == ref && w_err == ref_err && a_err == ref_err &&
         iconic == !!(ref & WS_MINIMIZE) && zoomed == !!(ref & WS_MAXIMIZE);
    checks++;
    if (!ok || !quiet)
        report(name, ok, "hwnd=%p ref=%08lx err=%lu W=%08lx err=%lu A=%08lx err=%lu iconic=%d zoomed=%d",
               hwnd, ref, ref_err, w, w_err, a, a_err, iconic, zoomed);
    return ok;
}

static void expect_bits(const char *name, HWND hwnd, DWORD set, DWORD clear)
{
    DWORD s = GetWindowLongW(hwnd, GWL_STYLE);
    report(name, (s & set) == set && !(s & clear), "style=%08lx want set=%08lx clear=%08lx", s, set, clear);
}

/* ---- window procedure: checks from inside creation and style changes ---- */
static int in_create_ok = 1;
static DWORD forced_bits;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_NCCREATE:
    case WM_CREATE:
        if (!compare(msg == WM_NCCREATE ? "in_nccreate" : "in_create", hwnd, 1)) in_create_ok = 0;
        break;
    case WM_STYLECHANGING:
        if (wp == (WPARAM)GWL_STYLE && forced_bits)
            ((STYLESTRUCT *)lp)->styleNew |= forced_bits;
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int hook_ok = 1, hook_calls;
static LRESULT CALLBACK cbt_hook(int code, WPARAM wp, LPARAM lp)
{
    if (code == HCBT_CREATEWND)
    {
        hook_calls++;
        if (!compare("in_cbt_hook", (HWND)wp, 1)) hook_ok = 0;
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static HWND make_window(DWORD style, HWND parent)
{
    HWND hwnd = CreateWindowExW(0, L"stylecheck", L"stylecheck", style, 10, 10, 200, 150, parent, 0,
                           GetModuleHandleW(NULL), NULL);
    if (!hwnd) { report("create_window", 0, "error=%lu", GetLastError()); ExitProcess(2); }
    return hwnd;
}

static void pump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
}

static void wait_bounded(HANDLE handle, const char *name)
{
    DWORD result = WaitForSingleObject(handle, 10000);
    if (result != WAIT_OBJECT_0)
    {
        report(name, 0, "wait=%lu", result);
        ExitProcess(2);
    }
}

/* ---- another thread's window ---- */
static HWND other_hwnd;
static HANDLE other_ready, other_go, other_done;
static DWORD WINAPI other_thread(void *arg)
{
    other_hwnd = make_window(WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0);
    SetEvent(other_ready);
    wait_bounded(other_go, "other_go_wait");
    ShowWindow(other_hwnd, SW_MINIMIZE);
    pump();
    SetEvent(other_done);
    wait_bounded(other_go, "other_go_wait");
    DestroyWindow(other_hwnd);
    SetEvent(other_done);
    return 0;
}

/* ---- racing writer: owns its window, so SetWindowLong's messages stay on its thread ---- */
static volatile LONG race_stop;
static HWND race_hwnd;
static HANDLE race_ready, race_stop_event;
static DWORD race_a, race_b;
static DWORD WINAPI race_writer(void *arg)
{
    int i = 0;
    DWORD want_a = race_a, want_b = race_b;
    race_hwnd = make_window(WS_OVERLAPPEDWINDOW, 0);
    /* win32u may adjust what is set (WS_CLIPSIBLINGS...): race between what it stores */
    SetWindowLongW(race_hwnd, GWL_STYLE, want_a);
    race_a = GetWindowLongW(race_hwnd, GWL_STYLE);
    SetWindowLongW(race_hwnd, GWL_STYLE, want_b);
    race_b = GetWindowLongW(race_hwnd, GWL_STYLE);
    SetEvent(race_ready);
    while (i < 4096 && !InterlockedCompareExchange(&race_stop, 0, 0))
    {
        SetWindowLongW(race_hwnd, GWL_STYLE, (i++ & 1) ? want_a : want_b);
        Sleep(1);
    }
    wait_bounded(race_stop_event, "race_stop_wait");
    DestroyWindow(race_hwnd);
    return i;
}

static double now_ns(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1e9 / (double)freq.QuadPart;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static volatile DWORD sink;
static void bench(const char *name, HWND hwnd, int which)
{
    enum { REPS = 5, N = 6000 };
    double t[REPS];
    int r, i;
    for (r = 0; r < REPS; r++)
    {
        double t0 = now_ns();
        switch (which)
        {
        case 0: for (i = 0; i < N; i++) sink += IsIconic(hwnd); break;
        case 1: for (i = 0; i < N; i++) sink += GetWindowLongW(hwnd, GWL_STYLE); break;
        case 2: for (i = 0; i < N; i++) sink += (DWORD)pNtUserCallHwndParam(hwnd, (DWORD_PTR)(LONG_PTR)GWL_STYLE, CODE_GETWINDOWLONGW); break;
        case 3: for (i = 0; i < N; i++) sink += GetWindowLongW(hwnd, GWL_EXSTYLE); break;
        }
        t[r] = (now_ns() - t0) / N;
    }
    qsort(t, REPS, sizeof(t[0]), cmp_double);
    printf("stylecheck: bench name=%s ns_per_op_median=%.0f min=%.0f max=%.0f\n", name, t[REPS / 2], t[0], t[REPS - 1]);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    WNDCLASSW cls = {0};
    HWND hwnd, child, msgwnd, mini, *many;
    HHOOK hook;
    HANDLE th;
    DWORD style;
    int i, nmany = 32, many_ok;
    int do_bench = argc == 2 && !strcmp(argv[1], "--bench");

    QueryPerformanceFrequency(&freq);
    pNtUserCallHwndParam = (void *)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserCallHwndParam");
    if (!pNtUserCallHwndParam) { printf("stylecheck: no NtUserCallHwndParam\n"); return 2; }
    printf("stylecheck: start sizeof(void*)=%u\n", (unsigned)sizeof(void *));

    cls.lpfnWndProc = wndproc;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = L"stylecheck";
    RegisterClassW(&cls);

    /* invalid handles before any window exists (first call maps the session) */
    compare("null_hwnd", NULL, 0);
    compare("bogus_hwnd", (HWND)(ULONG_PTR)0x1234, 0);
    compare("bogus_hwnd_low", (HWND)(ULONG_PTR)0x0010, 0);
    compare("bogus_hwnd_high", (HWND)(ULONG_PTR)0xfff0, 0);

    /* creation: CBT hook, WM_NCCREATE, WM_CREATE see what win32u sees */
    hook = SetWindowsHookExW(WH_CBT, cbt_hook, NULL, GetCurrentThreadId());
    hwnd = make_window(WS_OVERLAPPEDWINDOW, 0);
    UnhookWindowsHookEx(hook);
    report("cbt_hook_matches", hook_ok && hook_calls >= 1, "calls=%d", hook_calls);
    report("create_messages_match", in_create_ok, NULL);
    compare("created_hidden", hwnd, 0);

    ShowWindow(hwnd, SW_SHOW); pump();
    compare("shown", hwnd, 0); expect_bits("shown_bits", hwnd, WS_VISIBLE, WS_MINIMIZE);
    ShowWindow(hwnd, SW_MINIMIZE); pump();
    compare("minimized", hwnd, 0); expect_bits("minimized_bits", hwnd, WS_MINIMIZE, 0);
    report("isiconic_after_minimize", IsIconic(hwnd) == TRUE, NULL);
    ShowWindow(hwnd, SW_RESTORE); pump();
    compare("restored", hwnd, 0); expect_bits("restored_bits", hwnd, 0, WS_MINIMIZE | WS_MAXIMIZE);
    report("not_iconic_after_restore", IsIconic(hwnd) == FALSE, NULL);
    ShowWindow(hwnd, SW_MAXIMIZE); pump();
    compare("maximized", hwnd, 0); expect_bits("maximized_bits", hwnd, WS_MAXIMIZE, WS_MINIMIZE);
    report("iszoomed_after_maximize", IsZoomed(hwnd) == TRUE, NULL);
    ShowWindow(hwnd, SW_MINIMIZE); pump();
    compare("minimized_from_max", hwnd, 0);
    ShowWindow(hwnd, SW_RESTORE); pump();
    compare("restored_to_max", hwnd, 0);
    ShowWindow(hwnd, SW_RESTORE); pump();
    ShowWindow(hwnd, SW_HIDE); pump();
    compare("hidden", hwnd, 0); expect_bits("hidden_bits", hwnd, 0, WS_VISIBLE);

    SetWindowPos(hwnd, 0, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    compare("swp_show", hwnd, 0); expect_bits("swp_show_bits", hwnd, WS_VISIBLE, 0);
    SetWindowPos(hwnd, 0, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW);
    compare("swp_hide", hwnd, 0); expect_bits("swp_hide_bits", hwnd, 0, WS_VISIBLE);

    /* SetWindowLong: the value is visible to the very next read */
    style = GetWindowLongW(hwnd, GWL_STYLE);
    SetWindowLongW(hwnd, GWL_STYLE, style | WS_MINIMIZE);
    compare("setlongw_minimize_bit", hwnd, 0);
    report("setlongw_isiconic", IsIconic(hwnd) == TRUE, NULL);
    SetWindowLongA(hwnd, GWL_STYLE, style & ~WS_MINIMIZE);
    compare("setlonga_clear_bit", hwnd, 0);
    SetWindowLongW(hwnd, GWL_STYLE, 0x12345678);
    compare("setlong_odd_value", hwnd, 0);
    SetWindowLongW(hwnd, GWL_STYLE, 0xffffffff & ~(WS_CHILD | WS_VISIBLE));
    compare("setlong_all_bits", hwnd, 0);
    SetWindowLongW(hwnd, GWL_STYLE, 0);
    compare("setlong_zero", hwnd, 0);
    SetWindowLongW(hwnd, GWL_STYLE, style);
    compare("setlong_back", hwnd, 0);

    /* WM_STYLECHANGING edits the new style: both paths see the edited one */
    forced_bits = WS_MAXIMIZE;
    SetWindowLongW(hwnd, GWL_STYLE, style);
    forced_bits = 0;
    compare("stylechanging_edit", hwnd, 0); expect_bits("stylechanging_edit_bits", hwnd, WS_MAXIMIZE, 0);
    SetWindowLongW(hwnd, GWL_STYLE, style);

    /* created minimized / maximized */
    mini = make_window(WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_MINIMIZE, 0);
    pump();
    compare("created_minimized", mini, 0);
    DestroyWindow(mini);
    mini = make_window(WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_MAXIMIZE, 0);
    pump();
    compare("created_maximized", mini, 0);

    /* child, message-only, desktop windows */
    child = make_window(WS_CHILD | WS_VISIBLE | WS_BORDER, hwnd);
    compare("child", child, 0);
    ShowWindow(child, SW_HIDE);
    compare("child_hidden", child, 0);
    msgwnd = CreateWindowExW(0, L"stylecheck", L"msg", 0, 0, 0, 0, 0, HWND_MESSAGE, 0, GetModuleHandleW(NULL), NULL);
    compare("message_only", msgwnd, 0);
    compare("desktop", GetDesktopWindow(), 0);
    compare("message_parent", GetAncestor(msgwnd, GA_PARENT), 0);

    /* handle forms: 16-bit, 0xffff high word, wrong generation */
    compare("handle_low16", (HWND)(ULONG_PTR)LOWORD(hwnd), 0);
    compare("handle_ffff", (HWND)(ULONG_PTR)(LOWORD(hwnd) | 0xffff0000), 0);
    compare("handle_wrong_gen", (HWND)(ULONG_PTR)(LOWORD(hwnd) | ((HIWORD(hwnd) + 1) & 0x7fff) << 16), 0);

    /* destroyed: the handle is invalid at once */
    DestroyWindow(mini);
    compare("destroyed", mini, 0);
    report("destroyed_not_iconic", IsIconic(mini) == FALSE, NULL);

    /* another thread's window: changes made there are seen here */
    other_ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    other_go = CreateEventW(NULL, FALSE, FALSE, NULL);
    other_done = CreateEventW(NULL, FALSE, FALSE, NULL);
    th = CreateThread(NULL, 0, other_thread, NULL, 0, NULL);
    wait_bounded(other_ready, "other_ready_wait");
    compare("other_thread_window", other_hwnd, 0);
    SetEvent(other_go); wait_bounded(other_done, "other_done_wait");
    compare("other_thread_minimized", other_hwnd, 0);
    report("other_thread_isiconic", IsIconic(other_hwnd) == TRUE, NULL);
    SetEvent(other_go); wait_bounded(other_done, "other_done_wait");
    compare("other_thread_destroyed", other_hwnd, 0);
    wait_bounded(th, "thread_join");
    CloseHandle(th);

    /* a writer racing readers: every read is one of the two values */
    race_a = WS_OVERLAPPEDWINDOW | WS_HSCROLL;
    race_b = WS_OVERLAPPEDWINDOW | WS_VSCROLL;
    CloseHandle(other_ready); CloseHandle(other_go); CloseHandle(other_done);
    race_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    race_ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    th = CreateThread(NULL, 0, race_writer, NULL, 0, NULL);
    wait_bounded(race_ready, "race_ready_wait");
    {
        int seen_a = 0, seen_b = 0, bad = 0, iconic = 0;
        DWORD bad_value = 0, s;
        double end = now_ns() + 1.5e9;
        for (int round = 0; round < 150 && now_ns() < end; round++)
        {
            for (i = 0; i < 64; i++)
            {
                s = GetWindowLongW(race_hwnd, GWL_STYLE);
                if (s == race_a) seen_a++;
                else if (s == race_b) seen_b++;
                else { bad++; bad_value = s; }
                iconic += IsIconic(race_hwnd);
            }
            Sleep(1);
        }
        InterlockedExchange(&race_stop, 1);
        SetEvent(race_stop_event);
        wait_bounded(th, "race_join");
        GetExitCodeThread(th, &s);
        report("race_values", !bad && seen_a + seen_b > 0 && race_a != race_b, "a=%d b=%d bad=%d bad_value=%08lx writes=%lu iconic=%d",
               seen_a, seen_b, bad, bad_value, s, iconic);
        compare("race_destroyed", race_hwnd, 0);
        CloseHandle(th); CloseHandle(race_ready); CloseHandle(race_stop_event);
    }

    /* Ordinary window population; synthetic growth is checked natively. */
    many = malloc(nmany * sizeof(*many));
    if (!many) return 2;
    many_ok = 1;
    for (i = 0; i < nmany; i++)
    {
        many[i] = make_window((i & 1) ? WS_OVERLAPPED : WS_OVERLAPPEDWINDOW | WS_MINIMIZE, 0);
        if (!many[i]) { nmany = i; break; }
        if (!compare("many_create", many[i], 1)) many_ok = 0;
    }
    for (i = 0; i < nmany; i += 7)
    {
        SetWindowLongW(many[i], GWL_STYLE, GetWindowLongW(many[i], GWL_STYLE) ^ WS_MINIMIZE);
        if (!compare("many_toggle", many[i], 1)) many_ok = 0;
    }
    report("many_windows", many_ok && nmany == 32, "windows=%d", nmany);
    if (do_bench && nmany) bench("isiconic_last_of_many", many[nmany - 1], 0);
    for (i = 0; i < nmany; i++) DestroyWindow(many[i]);
    free(many);

    /* benchmark on an ordinary visible window */
    ShowWindow(hwnd, SW_SHOW); pump();
    if (do_bench)
    {
    bench("isiconic", hwnd, 0);
    bench("getwindowlongw_style", hwnd, 1);
    bench("syscall_getwindowlongw_style", hwnd, 2);
    bench("getwindowlongw_exstyle", hwnd, 3);
    bench("isiconic_invalid_hwnd", (HWND)(ULONG_PTR)0x1234, 0);
    }

    DestroyWindow(child);
    DestroyWindow(msgwnd);
    DestroyWindow(hwnd);
    UnregisterClassW(L"stylecheck", GetModuleHandleW(NULL));
    printf("stylecheck: checks=%d\n", checks);
    printf("stylecheck: done failures=%d\n", failures);
    fflush(stdout);
    return failures ? 1 : 0;
}
