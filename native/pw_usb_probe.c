/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_usb_probe.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const usb_prefixes[] = { "ugen", "usb", "uhid", "hid", "xhci", "ehci", "ohci", "uhub" };

int pw_usb_probe_is_usb_name(const char *name)
{
    if (!name) return 0;
    for (size_t i = 0; i < sizeof(usb_prefixes) / sizeof(usb_prefixes[0]); i++)
        if (!strncmp(name, usb_prefixes[i], strlen(usb_prefixes[i]))) return 1;
    return 0;
}

static void emit(void (*log)(const char *line), const char *format, ...) __attribute__((format(printf, 2, 3)));

static void emit(void (*log)(const char *line), const char *format, ...)
{
    char line[256];
    va_list args;

    if (!log) return;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    log(line);
}

/* Stats and, for a device node, opens `path` once. Returns 1 when it tried to open. */
static int node(const char *stage, const char *path, void (*log)(const char *line))
{
    struct stat st;
    int fd, opened = 0;

    if (stat(path, &st) != 0) {
        emit(log, "node stage=%s path=%s stat=errno%d", stage, path, errno);
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        emit(log, "node stage=%s path=%s dir mode=%o uid=%u gid=%u", stage, path, (unsigned)(st.st_mode & 07777),
             (unsigned)st.st_uid, (unsigned)st.st_gid);
        return 0;
    }
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd >= 0) {
        emit(log, "node stage=%s path=%s mode=%o uid=%u gid=%u open=ok", stage, path,
             (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid, (unsigned)st.st_gid);
        close(fd);
    } else {
        emit(log, "node stage=%s path=%s mode=%o uid=%u gid=%u open=errno%d", stage, path,
             (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid, (unsigned)st.st_gid, errno);
    }
    opened = 1;
    return opened;
}

static int scan(const char *stage, const char *dir, int only_usb_names, int *tried, void (*log)(const char *line))
{
    DIR *d = opendir(dir);
    struct dirent *entry;
    int entries = 0, listed = 0;

    if (!d) {
        emit(log, "dir stage=%s path=%s opendir=errno%d", stage, dir, errno);
        return -1;
    }
    while ((entry = readdir(d)) != NULL) {
        char path[512];

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        entries++;
        if (only_usb_names && !pw_usb_probe_is_usb_name(entry->d_name)) continue;
        if (listed >= PW_USB_PROBE_MAX_NODES) continue;
        listed++;
        if (snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) >= (int)sizeof(path)) continue;
        *tried += node(stage, path, log);
    }
    closedir(d);
    emit(log, "dir stage=%s path=%s ok entries=%d listed=%d", stage, dir, entries, listed);
    return entries;
}

int pw_usb_probe_run(const char *stage, const char *root, void (*log)(const char *line))
{
    char usb[512];
    int tried = 0;

    if (!stage || !root) return 0;
    emit(log, "probe stage=%s uid=%u gid=%u euid=%u egid=%u", stage, (unsigned)getuid(), (unsigned)getgid(),
         (unsigned)geteuid(), (unsigned)getegid());
    scan(stage, root, 1, &tried, log);
    if (snprintf(usb, sizeof(usb), "%s/usb", root) < (int)sizeof(usb)) scan(stage, usb, 0, &tried, log);
    emit(log, "probe stage=%s done tried=%d", stage, tried);
    return tried;
}
