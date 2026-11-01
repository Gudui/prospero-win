"""Compile the exact production Home-exit function against a host refusal stub."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class HomeExitTests(unittest.TestCase):
    def test_loadexec_success_and_refusal_never_use_process_exit(self):
        root = Path(__file__).resolve().parents[1]
        native = (root / "native/wine64_main.c").read_text()
        function = native.split("static void leave_to_home(const char *reason)", 1)[1]
        function = "static void leave_to_home(const char *reason)" + function.split(
            "/* Replace this process", 1)[0]
        harness = r'''
#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <string.h>
#define PW_HOME_EXIT_LOADEXEC 1
static jmp_buf escape;
static int step, refuse;
static void log_stub(const char *format, ...) { (void)format; }
#define PS5LOG_LOG(...) log_stub(__VA_ARGS__)
static void display_quiesce(const char *reason) {
    assert(!strcmp(reason, "test")); assert(step++ == 0);
}
static void pw_diagnostics_close(const char *reason) {
    assert(!strcmp(reason, "test")); assert(step++ == 1);
}
static int sceSystemServiceLoadExec(const char *path, const void *args) {
    assert(!strcmp(path, "exit")); assert(args == NULL); assert(step++ == 2);
    if (!refuse) longjmp(escape, 1);
    return -1;
}
static void pw_diagnostics_resume(void) { assert(step++ == 3); }
static int usleep(unsigned delay) {
    assert(delay == 100000); assert(step++ == 4); longjmp(escape, 2);
}
'''
        harness += function + r'''
int main(void) {
    int outcome = setjmp(escape);
    if (!outcome) leave_to_home("test");
    assert(outcome == 1 && step == 3);
    refuse = 1; step = 0;
    outcome = setjmp(escape);
    if (!outcome) leave_to_home("test");
    assert(outcome == 2 && step == 5);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "exit.c"
            executable = Path(directory) / "exit-test"
            source.write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(source), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
