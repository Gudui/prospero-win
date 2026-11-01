/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_usb_probe.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char lines[128][256];
static int count;

static void capture(const char *line)
{
    if (count < 128) snprintf(lines[count++], sizeof(lines[0]), "%s", line);
}

static int has(const char *needle)
{
    for (int i = 0; i < count; i++)
        if (strstr(lines[i], needle)) return 1;
    return 0;
}

static void touch(const char *path, mode_t mode)
{
    int fd = open(path, O_CREAT | O_WRONLY, mode);

    assert(fd >= 0);
    close(fd);
}

int main(void)
{
    char root[] = "/tmp/pw_usb_probe_XXXXXX";
    char path[256];

    assert(pw_usb_probe_is_usb_name("ugen2.3"));
    assert(pw_usb_probe_is_usb_name("usb"));
    assert(pw_usb_probe_is_usb_name("uhid0"));
    assert(!pw_usb_probe_is_usb_name("null"));
    assert(!pw_usb_probe_is_usb_name("dmem0"));
    assert(!pw_usb_probe_is_usb_name(NULL));

    /* A missing root is logged, not fatal. */
    assert(pw_usb_probe_run("pre-grant", "/nonexistent-pw-usb-probe", capture) == 0);
    assert(has("opendir=errno2"));
    assert(has("probe stage=pre-grant done tried=0"));

    assert(mkdtemp(root));
    snprintf(path, sizeof(path), "%s/usb", root);
    assert(mkdir(path, 0755) == 0);
    snprintf(path, sizeof(path), "%s/ugen2.3", root);
    touch(path, 0644);
    snprintf(path, sizeof(path), "%s/null", root);
    touch(path, 0644);
    snprintf(path, sizeof(path), "%s/usb/2.3.0", root);
    touch(path, 0644);
    snprintf(path, sizeof(path), "%s/usb/2.4.0", root);
    touch(path, 0000);

    count = 0;
    assert(pw_usb_probe_run("post-grant", root, capture) >= 2);
    assert(has("probe stage=post-grant"));
    assert(has("ugen2.3 mode=644"));
    assert(has("open=ok"));
    assert(has("/usb/2.3.0 mode=644"));
    assert(has("/usb dir"));                 /* the usb directory itself is listed, not opened */
    for (int i = 0; i < count; i++) assert(!strstr(lines[i], "/null"));   /* a non-USB name is skipped */
    assert(has("/usb/2.4.0 mode=0 "));        /* an unreadable node is reported either way (root may open it) */

    /* Null stage or root does nothing; a null logger is accepted. */
    assert(pw_usb_probe_run(NULL, root, capture) == 0);
    assert(pw_usb_probe_run("x", root, NULL) >= 2);

    snprintf(path, sizeof(path), "rm -rf %s", root);
    assert(system(path) == 0);
    puts("test_pw_usb_probe ok");
    return 0;
}
