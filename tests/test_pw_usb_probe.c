/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_usb_probe.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char lines[256][256];
static int count;

static void capture(const char *line)
{
    if (count < 256) snprintf(lines[count++], sizeof(lines[0]), "%s", line);
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
    char desc_out[96];
    /* RedOctane Guitar Hero X-plorer (1430:4748) 18-byte device descriptor */
    const uint8_t xplorer_dev[18] = {
        18, 1, 0x00, 0x02, 0xff, 0xff, 0xff, 8,
        0x30, 0x14, 0x48, 0x47, 0x00, 0x01, 1, 2, 3, 1
    };
    /* Xbox 360 wired interface 0 descriptor: class 0xff, subclass 0x5d, protocol 0x01 */
    const uint8_t xinput_if[9] = {
        9, 4, 0, 0, 2, 0xff, 0x5d, 0x01, 0
    };

    assert(PW_USB_PROBE_MAX_NODES >= 128);
    assert(pw_usb_probe_is_usb_name("ugen2.3"));
    assert(pw_usb_probe_is_usb_name("usb"));
    assert(pw_usb_probe_is_usb_name("uhid0"));
    assert(!pw_usb_probe_is_usb_name("null"));
    assert(!pw_usb_probe_is_usb_name("dmem0"));
    assert(!pw_usb_probe_is_usb_name(NULL));

    pw_usb_probe_format_desc(xplorer_dev, 1, xinput_if, 1, desc_out, sizeof(desc_out));
    assert(strcmp(desc_out, " vid=1430 pid=4748 dclass=ff/ff/ff if=0:ff/5d/01") == 0);
    pw_usb_probe_format_desc(xplorer_dev, 0, xinput_if, 0, desc_out, sizeof(desc_out));
    assert(desc_out[0] == '\0');

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
    /* Populate >32 usb endpoint nodes to ensure 2.3.0 is never truncated at 32. */
    for (int i = 0; i < 40; i++) {
        snprintf(path, sizeof(path), "%s/usb/1.%d.0", root, i);
        touch(path, 0644);
    }
    snprintf(path, sizeof(path), "%s/usb/2.3.0", root);
    touch(path, 0644);
    snprintf(path, sizeof(path), "%s/usb/2.4.0", root);
    touch(path, 0000);

    count = 0;
    assert(pw_usb_probe_run("post-grant", root, capture) >= 43);
    assert(has("probe stage=post-grant"));
    assert(has("ugen2.3 mode=644"));
    assert(has("open=ok rw=ok"));
    assert(has("/usb/2.3.0 mode=644"));
    assert(has("/usb dir"));                 /* the usb directory itself is listed, not opened */
    for (int i = 0; i < count; i++) assert(!strstr(lines[i], "/null"));   /* a non-USB name is skipped */
    assert(has("/usb/2.4.0 mode=0 "));        /* an unreadable node is reported either way (root may open it) */

    /* Null stage or root does nothing; a null logger is accepted. */
    assert(pw_usb_probe_run(NULL, root, capture) == 0);
    assert(pw_usb_probe_run("x", root, NULL) >= 43);

    snprintf(path, sizeof(path), "rm -rf %s", root);
    assert(system(path) == 0);
    puts("test_pw_usb_probe ok");
    return 0;
}
