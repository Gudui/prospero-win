/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Pinned Wine NTDLL identity checks. The caller supplies guarded image reads
 * and resolved named exports from the actual retained PE32/PE64 modules. */
#ifndef PW_WOW_SYNC_BOP_BINDINGS_H
#define PW_WOW_SYNC_BOP_BINDINGS_H
#include "sync_bop_adapter.h"

#define PW_WOW_SYNC_IMAGE_VERSION 1u

struct pw_wow_sync_image
{
    uint64_t base, size;
    void *opaque;
    int (*read)(void *, uint64_t, void *, size_t);
};

struct pw_wow_sync_identity_source
{
    uint32_t version;
    int retained; /* caller holds both actual NTDLL module lifetimes */
    struct pw_wow_sync_image pe32, pe64;
    uint64_t exports32[PW_WOW_SYNC_OPERATIONS], exports64[PW_WOW_SYNC_OPERATIONS];
    uint64_t dispatcher32; /* resolved __wine_syscall_dispatcher data export */
};

struct pw_wow_sync_attestation
{
    struct pw_wow_sync_bindings bindings;
    uint32_t continuations[PW_WOW_SYNC_OPERATIONS];
    uint32_t helper32, dispatcher32;
};

static inline const char *pw_wow_sync_export_name(unsigned operation)
{
    static const char *const names[PW_WOW_SYNC_OPERATIONS] =
    {
        "NtWaitForSingleObject", "NtReleaseMutant", "NtSetEvent",
        "NtResetEvent", "NtReleaseSemaphore"
    };
    return operation < PW_WOW_SYNC_OPERATIONS ? names[operation] : NULL;
}

static inline uint32_t pw_wow_sync_read_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static inline int pw_wow_sync_image_read(const struct pw_wow_sync_image *image,
                                         uint64_t address, void *out, size_t bytes)
{
    if (!image->read || !bytes || image->base < 0x10000 || !image->size ||
        image->size > UINT64_MAX - image->base || address < image->base ||
        bytes > image->size || address - image->base > image->size - bytes)
        return 0;
    return image->read(image->opaque, address, out, bytes);
}

/* Only the pinned non-PIC PE32 and x86-64 Wine forms are recognized. These
 * are read as data, never executed here. Custom/PIC/partial identities fall
 * back to ordinary Wow64. Failure leaves the destination entirely untouched. */
static inline int pw_wow_sync_attest(const struct pw_wow_sync_identity_source *source,
                                     struct pw_wow_sync_attestation *out)
{
    static const uint8_t prefix64[] = {0x4c, 0x8b, 0xd1, 0xb8};
    static const uint8_t suffix64[] =
    {
        0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, 0x75, 0x03,
        0x0f, 0x05, 0xc3, 0xeb, 0x01, 0xc3, 0xff, 0x14, 0x25,
        0x00, 0x10, 0xfe, 0x7f, 0xc3
    };
    static const uint8_t argument_bytes[] = {12, 8, 8, 8, 12};
    struct pw_wow_sync_attestation result = {0};
    uint8_t stub32[15], stub64[32], helper[6];
    uint32_t helper_address = 0, id;
    unsigned i, j;

    if (!source || !out || source->version != PW_WOW_SYNC_IMAGE_VERSION || !source->retained ||
        source->pe32.base >= 0xfffff000u ||
        source->pe32.size > 0xfffff000u - source->pe32.base ||
        source->dispatcher32 < source->pe32.base || source->pe32.size < 4 ||
        source->dispatcher32 - source->pe32.base > source->pe32.size - 4)
        return 0;
    for (i = 0; i < PW_WOW_SYNC_OPERATIONS; i++)
    {
        if (!pw_wow_sync_image_read(&source->pe32, source->exports32[i], stub32, sizeof(stub32)) ||
            !pw_wow_sync_image_read(&source->pe64, source->exports64[i], stub64, sizeof(stub64)))
            return 0;
        /* mov eax,id; mov edx,helper; call edx; ret argument_bytes */
        if (stub32[0] != 0xb8 || stub32[5] != 0xba || stub32[10] != 0xff ||
            stub32[11] != 0xd2 || stub32[12] != 0xc2 ||
            stub32[13] != argument_bytes[i] || stub32[14]) return 0;
        for (j = 0; j < sizeof(prefix64); j++) if (stub64[j] != prefix64[j]) return 0;
        for (j = 0; j < sizeof(suffix64); j++) if (stub64[8 + j] != suffix64[j]) return 0;
        id = pw_wow_sync_read_le32(stub32 + 1);
        if (id >= 0x1000 || id != pw_wow_sync_read_le32(stub64 + 4)) return 0;
        result.bindings.ids[i] = id;
        result.continuations[i] = (uint32_t)source->exports32[i] + 12;
        if (!i) helper_address = pw_wow_sync_read_le32(stub32 + 6);
        else if (helper_address != pw_wow_sync_read_le32(stub32 + 6)) return 0;
    }
    if (!pw_wow_sync_image_read(&source->pe32, helper_address, helper, sizeof(helper)) ||
        helper[0] != 0xff || helper[1] != 0x25 ||
        pw_wow_sync_read_le32(helper + 2) != source->dispatcher32) return 0;
    result.bindings.version = PW_WOW_SYNC_BINDINGS_VERSION;
    result.bindings.attested = 1;
    if (!pw_wow_sync_bindings_valid(&result.bindings)) return 0;
    result.helper32 = helper_address;
    result.dispatcher32 = (uint32_t)source->dispatcher32;
    *out = result;
    return 1;
}
#endif
