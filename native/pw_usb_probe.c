/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_usb_probe.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* FreeBSD sys/ioccom.h and dev/usb/usb_ioctl.h copy-out ioctls (zero bus traffic). */
#define PW_FREEBSD_IOC_OUT 0x40000000UL
#define PW_FREEBSD_IOR(group, num, len) \
    ((unsigned long)(PW_FREEBSD_IOC_OUT | (((unsigned long)(len) & 0x1fffUL) << 16) | \
                     (((unsigned long)(group)) << 8) | (unsigned long)(num)))
#define PW_USB_GET_DEVICE_DESC       PW_FREEBSD_IOR('U', 105, 18)
#define PW_USB_GET_RX_INTERFACE_DESC PW_FREEBSD_IOR('U', 107, 9)

static const char *const usb_prefixes[] = { "ugen", "usb", "uhid", "hid", "xhci", "ehci", "ohci", "uhub" };

int pw_usb_probe_is_usb_name(const char *name)
{
    if (!name) return 0;
    for (size_t i = 0; i < sizeof(usb_prefixes) / sizeof(usb_prefixes[0]); i++)
        if (!strncmp(name, usb_prefixes[i], strlen(usb_prefixes[i]))) return 1;
    return 0;
}

void pw_usb_probe_format_desc(const uint8_t *dev_desc, int dev_ok,
                              const uint8_t *if_desc, int if_ok,
                              char *out, size_t cap)
{
    size_t at = 0;

    if (!out || cap == 0) return;
    out[0] = '\0';
    if (dev_ok && dev_desc && dev_desc[0] >= 18) {
        uint16_t vid = (uint16_t)((uint16_t)dev_desc[8] | ((uint16_t)dev_desc[9] << 8));
        uint16_t pid = (uint16_t)((uint16_t)dev_desc[10] | ((uint16_t)dev_desc[11] << 8));
        int n = snprintf(out + at, cap - at, " vid=%04x pid=%04x dclass=%02x/%02x/%02x",
                         (unsigned)vid, (unsigned)pid,
                         (unsigned)dev_desc[4], (unsigned)dev_desc[5], (unsigned)dev_desc[6]);
        if (n > 0 && (size_t)n < cap - at) at += (size_t)n;
    }
    if (if_ok && if_desc && if_desc[0] >= 9) {
        int n = snprintf(out + at, cap - at, " if=%u:%02x/%02x/%02x",
                         (unsigned)if_desc[2], (unsigned)if_desc[5],
                         (unsigned)if_desc[6], (unsigned)if_desc[7]);
        if (n > 0 && (size_t)n < cap - at) at += (size_t)n;
    }
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
    int fd_ro, fd_rw, err_ro = 0, err_rw = 0;
    char rw_tag[24];
    char extra[96];

    if (stat(path, &st) != 0) {
        emit(log, "node stage=%s path=%s stat=errno%d", stage, path, errno);
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        emit(log, "node stage=%s path=%s dir mode=%o uid=%u gid=%u", stage, path, (unsigned)(st.st_mode & 07777),
             (unsigned)st.st_uid, (unsigned)st.st_gid);
        return 0;
    }
    fd_ro = open(path, O_RDONLY | O_NONBLOCK);
    if (fd_ro < 0) err_ro = errno;
    fd_rw = open(path, O_RDWR | O_NONBLOCK);
    if (fd_rw >= 0) {
        close(fd_rw);
        snprintf(rw_tag, sizeof(rw_tag), "ok");
    } else {
        err_rw = errno;
        snprintf(rw_tag, sizeof(rw_tag), "errno%d", err_rw);
    }
    extra[0] = '\0';
    if (fd_ro >= 0) {
        uint8_t dev_desc[18] = { 0 };
        uint8_t if_desc[9] = { 0 };
        int dev_ok = (ioctl(fd_ro, PW_USB_GET_DEVICE_DESC, dev_desc) == 0);
        int if_ok = (ioctl(fd_ro, PW_USB_GET_RX_INTERFACE_DESC, if_desc) == 0);
        pw_usb_probe_format_desc(dev_desc, dev_ok, if_desc, if_ok, extra, sizeof(extra));
        close(fd_ro);
        emit(log, "node stage=%s path=%s mode=%o uid=%u gid=%u open=ok rw=%s%s", stage, path,
             (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid, (unsigned)st.st_gid, rw_tag, extra);
    } else {
        emit(log, "node stage=%s path=%s mode=%o uid=%u gid=%u open=errno%d rw=%s", stage, path,
             (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid, (unsigned)st.st_gid, err_ro, rw_tag);
    }
    return 1;
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
