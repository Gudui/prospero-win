/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Synthetic ordinary Wine stub data; no instructions or Wine are executed. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wine/wowprospero/sync_bop_bindings.h"

struct image_fixture { uint64_t base; uint8_t bytes[1024]; unsigned reads, refused; };
static const uint32_t ids[] = {101, 102, 103, 104, 105};
static const unsigned argument_bytes[] = {12, 8, 8, 8, 12};
static unsigned total_reads, fail_read;

static void le32(uint8_t *p, uint32_t n)
{ p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); p[2]=(uint8_t)(n>>16); p[3]=(uint8_t)(n>>24); }
static int read_image(void *opaque, uint64_t address, void *out, size_t bytes)
{
    struct image_fixture *image=opaque;
    assert(address>=image->base && address-image->base<=sizeof(image->bytes)-bytes);
    image->reads++; total_reads++;
    if(image->refused || total_reads==fail_read)return 0;
    memcpy(out,image->bytes+(size_t)(address-image->base),bytes); return 1;
}
static struct pw_wow_sync_identity_source prepare(struct image_fixture *a,struct image_fixture *b)
{
    struct pw_wow_sync_identity_source source={0};
    /* Independently encoded standard forms, matching Wine include/wine/asm.h. */
    const uint8_t native[] = {0x4c,0x8b,0xd1,0xb8,0,0,0,0,0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,
                             0x75,0x03,0x0f,0x05,0xc3,0xeb,0x01,0xc3,0xff,0x14,0x25,0,0x10,0xfe,0x7f,0xc3};
    memset(a,0,sizeof(*a));memset(b,0,sizeof(*b));total_reads=fail_read=0;
    a->base=0x7bc00000;b->base=0x170000000;
    source.version=PW_WOW_SYNC_IMAGE_VERSION;source.retained=1;
    source.pe32=(struct pw_wow_sync_image){a->base,sizeof(a->bytes),a,read_image};
    source.pe64=(struct pw_wow_sync_image){b->base,sizeof(b->bytes),b,read_image};
    source.dispatcher32=a->base+904;
    a->bytes[896]=0xff;a->bytes[897]=0x25;le32(a->bytes+898,(uint32_t)source.dispatcher32);
    for(unsigned i=0;i<PW_WOW_SYNC_OPERATIONS;i++)
    {
        unsigned offset=64+i*64;uint8_t *stub=a->bytes+offset;
        source.exports32[i]=a->base+offset;source.exports64[i]=b->base+offset;
        stub[0]=0xb8;le32(stub+1,ids[i]);stub[5]=0xba;le32(stub+6,(uint32_t)a->base+896);
        stub[10]=0xff;stub[11]=0xd2;stub[12]=0xc2;stub[13]=(uint8_t)argument_bytes[i];
        memcpy(b->bytes+offset,native,sizeof(native));le32(b->bytes+offset+4,ids[i]);
    }
    return source;
}
static void miss(const struct pw_wow_sync_identity_source *source)
{
    struct pw_wow_sync_attestation out,prior;
    memset(&out,0x5a,sizeof(out));prior=out;
    assert(!pw_wow_sync_attest(source,&out) && !memcmp(&out,&prior,sizeof(out)));
    assert(total_reads<=11);
}
int main(void)
{
    struct image_fixture a,b;struct pw_wow_sync_attestation out;
    struct pw_wow_sync_identity_source source=prepare(&a,&b);
    const char *names[]={"NtWaitForSingleObject","NtReleaseMutant","NtSetEvent","NtResetEvent","NtReleaseSemaphore"};
    assert(pw_wow_sync_attest(&source,&out) && total_reads==11);
    assert(out.bindings.attested && pw_wow_sync_bindings_valid(&out.bindings));
    for(unsigned i=0;i<PW_WOW_SYNC_OPERATIONS;i++)
    {
        assert(out.bindings.ids[i]==ids[i] && out.continuations[i]==source.exports32[i]+12);
        assert(!strcmp(pw_wow_sync_export_name(i),names[i]));
    }
    assert(out.helper32==a.base+896 && out.dispatcher32==source.dispatcher32);
    assert(!pw_wow_sync_export_name(5));
    /* Every byte of each standard stub is validated, not just the mov ID. */
    unsigned malformed=0;
    for(unsigned i=0;i<5;i++)for(unsigned arch=0;arch<2;arch++)for(unsigned j=0;j<(arch?32u:15u);j++)
    {
        source=prepare(&a,&b);(arch?b.bytes:a.bytes)[64+i*64+j]^=0x80;
        miss(&source);malformed++;
    }
    assert(malformed==235);
    for(unsigned j=0;j<6;j++)
    {source=prepare(&a,&b);a.bytes[896+j]^=0x80;miss(&source);}
    for(fail_read=1;fail_read<=11;)
    {
        unsigned refused=fail_read;source=prepare(&a,&b);fail_read=refused;
        miss(&source);fail_read=refused+1;
    }
    source=prepare(&a,&b);source.retained=0;miss(&source);assert(!total_reads);
    source=prepare(&a,&b);source.version++;miss(&source);assert(!total_reads);
    source=prepare(&a,&b);source.pe32.read=NULL;miss(&source);assert(!total_reads);
    source=prepare(&a,&b);source.pe64.read=NULL;miss(&source);assert(total_reads==1);
    source=prepare(&a,&b);source.exports32[4]=0;miss(&source);
    source=prepare(&a,&b);source.exports64[4]=b.base+sizeof(b.bytes)-31;miss(&source);
    source=prepare(&a,&b);source.dispatcher32=a.base+sizeof(a.bytes)-3;miss(&source);assert(!total_reads);
    source=prepare(&a,&b);source.pe32.size=UINT64_MAX;miss(&source);assert(!total_reads);
    source=prepare(&a,&b);source.pe64.base=UINT64_MAX-64;source.pe64.size=128;miss(&source);
    source=prepare(&a,&b);source.pe32.base=0;miss(&source);assert(!total_reads);
    source=prepare(&a,&b);le32(a.bytes+65,0x1004);le32(b.bytes+68,0x1004);miss(&source);
    source=prepare(&a,&b);le32(a.bytes+129,ids[0]);le32(b.bytes+132,ids[0]);miss(&source);
    /* Consistent IDs are supplied by loaded modules, not fixed platform numbers. */
    source=prepare(&a,&b);
    for(unsigned i=0;i<5;i++){le32(a.bytes+65+i*64,ids[i]+512);le32(b.bytes+68+i*64,ids[i]+512);}
    assert(pw_wow_sync_attest(&source,&out) && out.bindings.ids[0]==ids[0]+512);
    assert(!pw_wow_sync_attest(NULL,&out) && !pw_wow_sync_attest(&source,NULL));
    printf("BOP loaded identity bounds/layout/metadata contracts PASS (%u malformed stubs, 11 mocked read refusals)\n",malformed);
    return 0;
}
