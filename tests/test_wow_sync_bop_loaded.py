#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual CPU/Unix binding bodies with explicit loaded-image/OS mocks."""
from pathlib import Path
import os,shlex,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
def body(s,signature):
 start=s.index(signature);brace=s.index('{',start);depth=1
 for end in range(brace+1,len(s)):
  depth+=(s[end]=='{')-(s[end]=='}')
  if not depth:return s[start:end+1]+'\n'
 raise AssertionError('unterminated function')
def header(patch,name):
 s=(ROOT/'wine/patches'/patch).read_text()
 part=next(x for x in s.split('diff --git ')[1:] if x.splitlines()[0].endswith(' b/include/wine/'+name))
 return '\n'.join(x[1:] for x in part.splitlines() if x.startswith(('+',' ')) and not x.startswith('+++'))+'\n'
HARNESS=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#define WINAPI
#define VOID void
#define FALSE 0
#define TRUE 1
#define WIN32_NO_STATUS
/* Explicit exception-control mock; no real exception is generated. */
#define __TRY if (1)
#define __EXCEPT_PAGE_FAULT else
#define __ENDTRY
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define LDR_ADDREF_DLL_PIN 1
#define STATUS_SUCCESS 0u
#define STATUS_INTERNAL_ERROR 0xc00000e5u
#define BASE32 0x20000u
#define BASE64 0x100000000ull
#define GUEST_LOW 0x10000u
#define GUEST_HIGH 0xfffff000u
typedef uint32_t UINT,ULONG,NTSTATUS;
typedef int INT;
typedef uint64_t UINT64;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef void *HMODULE;
typedef struct { unsigned char bytes[716]; } I386_CONTEXT;
typedef struct { uint32_t version;uint64_t ntdll_handle; } SYSTEM_DLL_INIT_BLOCK;
typedef struct { struct { uint16_t Machine; } FileHeader;struct { uint16_t Magic;uint32_t SizeOfImage; } OptionalHeader; } IMAGE_NT_HEADERS;
#include "wine/wowprospero/wowprospero.h"
#include "wine/ps5_sync_bop.h"
#include "wine/ps5_sync_bop_context.h"
#include "wine/ps5_sync_bop_memory.h"
#include "wine/wowprospero/sync_bop_bindings.h"
_Static_assert(sizeof(struct pw_wow_init_params)==96,"PE/Unix initialization ABI");
_Static_assert(offsetof(struct pw_wow_run_params,cpu_flags)==40,"run ABI tail offset");
static unsigned char image32[4096],image64[4096];
static const uint32_t ids[]={101,102,103,104,105};
static const unsigned argbytes[]={12,8,8,8,12};
static const uint8_t tail64[]={0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,0x75,0x03,0x0f,0x05,0xc3,0xeb,0x01,0xc3,0xff,0x14,0x25,0x00,0x10,0xfe,0x7f,0xc3};
static SYSTEM_DLL_INIT_BLOCK block;
static IMAGE_NT_HEADERS nt;
static unsigned pin_error,pins,read64_error,resolve_missing,resolve_calls,read32_calls,read64_calls;
static unsigned leased,begin_mode,end_refusals,end_calls,api_variant,warm_calls;
static const char *env_value,*file_value;
static unsigned file_error,logs;
static struct pw_sync_bop_memory_view *held_view;
static const struct pw_sync_bop_backend *sync_backend;
static const struct pw_sync_bop_context_backend *sync_context;
static const struct pw_sync_bop_memory_backend *sync_memory;
static struct pw_wow_sync_attestation sync_attestation;
static struct pw_sync_bop_memory_view sync_init_memory;
static int sync_bound;
static void le32(unsigned char *p,uint32_t x){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static NTSTATUS LdrAddRefDll(ULONG flags,HMODULE module){assert(flags==1 && (uintptr_t)module==BASE64);pins++;return pin_error;}
static IMAGE_NT_HEADERS *RtlImageNtHeader(HMODULE module){assert((uintptr_t)module==BASE64);return &nt;}
static void *GetCurrentProcess(void){return (void *)(intptr_t)-1;}
static NTSTATUS NtReadVirtualMemory(void *process,const void *address,void *out,SIZE_T bytes,SIZE_T *read)
{
 assert(process==GetCurrentProcess() && leased);read64_calls++;uint64_t at=(uintptr_t)address;
 if(read64_error || at<BASE64 || at-BASE64>4096 || bytes>4096-(at-BASE64)){*read=0;return 1;}
 memcpy(out,image64+(at-BASE64),bytes);*read=bytes;return 0;
}
static void *RtlFindExportedRoutineByName(HMODULE module,const char *name)
{
 uint64_t base=(uintptr_t)module;
 if(base==BASE64 && !strcmp(name,"LdrSystemDllInitBlock"))return &block;
 if(base==BASE32){assert(leased);resolve_calls++;}
 else assert(base==BASE64);
 for(unsigned i=0;i<5;i++)if(!strcmp(name,pw_wow_sync_export_name(i)))
  return resolve_missing==i+1?NULL:(void *)(uintptr_t)(base+256+64*i);
 if(base==BASE32 && !strcmp(name,"__wine_syscall_dispatcher"))return resolve_missing==6?NULL:(void *)(uintptr_t)(BASE32+704);
 return NULL;
}
#include "cpu.inc"
static const char *mock_getenv(const char *name){assert(!strcmp(name,"PW_WOW_SYNC_BOP"));return env_value;}
static FILE *mock_fopen(const char *path,const char *mode){assert(!strcmp(path,"/data/prospero-win/pw_wow_sync_bop") && !strcmp(mode,"rb"));return file_value?(FILE *)&file_error:NULL;}
static size_t mock_fread(void *out,size_t size,size_t bytes,FILE *file){assert(size==1 && file==(FILE *)&file_error);size_t n=strlen(file_value);n=n<bytes?n:bytes;memcpy(out,file_value,n);return n;}
static int mock_ferror(FILE *file){assert(file==(FILE *)&file_error);return file_error;}
static int mock_fclose(FILE *file){assert(file==(FILE *)&file_error);return 0;}
static int mock_fprintf(FILE *file,const char *fmt,...){assert(file==stderr && fmt);logs++;return 0;}
#define getenv mock_getenv
#define fopen mock_fopen
#define fread mock_fread
#define ferror mock_ferror
#define fclose mock_fclose
#define fprintf mock_fprintf
static int warm(uint32_t op,uint32_t h,uint32_t n,uint32_t *p){(void)op;(void)h;(void)n;(void)p;warm_calls++;return 0;}
static int publish(struct pw_sync_bop_context_view *p,uint32_t n){(void)p;(void)n;assert(0);return 0;}
static uint32_t finish_context(struct pw_sync_bop_context_view *p,uint32_t d){(void)p;(void)d;assert(0);return 0;}
static uint32_t begin(struct pw_sync_bop_memory_view *view)
{
 assert(!leased);assert(view->version==1 && view->size==sizeof(*view));
 if(begin_mode==PW_BOP_MEMORY_EMPTY)return begin_mode;
 leased=1;held_view=view;return begin_mode;
}
static int end(struct pw_sync_bop_memory_view *view)
{
 assert(leased && held_view==view);end_calls++;if(end_refusals){end_refusals--;return 0;}leased=0;held_view=NULL;return 1;
}
static int read32(struct pw_sync_bop_memory_view *view,uint32_t address,void *out,uint32_t bytes)
{
 assert(leased && held_view==view);read32_calls++;
 if(bytes>32 || address<BASE32 || address-BASE32>4096 || bytes>4096-(address-BASE32))return 0;
 memcpy(out,image32+(address-BASE32),bytes);return 1;
}
static int writable(struct pw_sync_bop_memory_view *v,uint32_t a,uint32_t n){(void)v;(void)a;(void)n;assert(0);return 0;}
static uint32_t write32(struct pw_sync_bop_memory_view *v,uint32_t a,const void *p,uint32_t n){(void)v;(void)a;(void)p;(void)n;assert(0);return 1;}
static struct pw_sync_bop_backend backend={1,sizeof(backend),sizeof(void *),0x1f,warm};
static struct pw_sync_bop_context_backend context={1,sizeof(context),sizeof(void *),sizeof(I386_CONTEXT),publish,finish_context};
static struct pw_sync_bop_memory_backend memory={1,sizeof(memory),sizeof(void *),sizeof(struct pw_sync_bop_memory_view),begin,end,read32,writable,write32};
static const struct pw_sync_bop_backend *__wine_ps5_sync_bop_backend(uint32_t v){assert(v==1);return api_variant==1?NULL:&backend;}
static const struct pw_sync_bop_context_backend *__wine_ps5_sync_bop_context_backend(uint32_t v){assert(v==1);return api_variant==2?NULL:&context;}
static const struct pw_sync_bop_memory_backend *__wine_ps5_sync_bop_memory_backend(uint32_t v){assert(v==1);return api_variant==3?NULL:&memory;}
#include "unix.inc"
static void reset(struct pw_wow_init_params *params)
{
 assert(!leased);memset(image32,0,sizeof(image32));memset(image64,0,sizeof(image64));
 image32[0]='M';image32[1]='Z';le32(image32+60,128);memcpy(image32+128,"PE\0\0",4);image32[132]=0x4c;image32[133]=1;image32[148]=224;
 image32[152]=0x0b;image32[153]=1;le32(image32+208,4096);
 for(unsigned i=0;i<5;i++){
  unsigned char *a=image32+256+64*i,*b=image64+256+64*i;
  a[0]=0xb8;le32(a+1,ids[i]);a[5]=0xba;le32(a+6,BASE32+640);a[10]=0xff;a[11]=0xd2;a[12]=0xc2;a[13]=argbytes[i];
  memcpy(b,"\x4c\x8b\xd1\xb8",4);le32(b+4,ids[i]);memcpy(b+8,tail64,sizeof(tail64));
 }
 image32[640]=0xff;image32[641]=0x25;le32(image32+642,BASE32+704);
 pin_error=pins=read64_error=resolve_missing=resolve_calls=read32_calls=read64_calls=0;
 begin_mode=PW_BOP_MEMORY_HELD;end_refusals=end_calls=api_variant=warm_calls=logs=file_error=0;file_value=NULL;env_value="1";
 block.version=0xf0;block.ntdll_handle=BASE32;nt.FileHeader.Machine=0x8664;nt.OptionalHeader.Magic=0x20b;nt.OptionalHeader.SizeOfImage=4096;
 prepare_sync_init((HMODULE)(uintptr_t)BASE64,params);assert(pins==1);
}
static void miss(struct pw_wow_init_params *params)
{
 assert(sync_loaded_init(params)==STATUS_SUCCESS && !sync_bound && !leased && !warm_calls);
}
int main(void)
{
 struct pw_wow_init_params params;reset(&params);
 assert(params.retained64 && params.module32==BASE32 && params.module64==BASE64 && params.module64_size==4096);
 assert(sync_loaded_init(&params)==STATUS_SUCCESS && sync_bound && !leased && !warm_calls && resolve_calls==6);
 for(unsigned i=0;i<5;i++)assert(sync_attestation.bindings.ids[i]==ids[i] && sync_attestation.continuations[i]==BASE32+268+64*i);
 for(unsigned i=0;i<6;i++){reset(&params);resolve_missing=i+1;miss(&params);}
 for(unsigned i=0;i<3;i++){reset(&params);api_variant=i+1;miss(&params);assert(!leased);}
 reset(&params);params.version++;miss(&params);reset(&params);params.size--;miss(&params);reset(&params);params.retained64=0;miss(&params);
 reset(&params);params.module32=0;miss(&params);reset(&params);params.module64_size=0;miss(&params);
 reset(&params);params.read64=0;miss(&params);reset(&params);params.resolve32=0;miss(&params);
 reset(&params);read64_error=1;miss(&params);reset(&params);le32(image64+260,0x1001);miss(&params);
 reset(&params);image32[0]='X';miss(&params);reset(&params);le32(image32+60,0xfffffff0);miss(&params);
 reset(&params);image32[132]=0;miss(&params);reset(&params);image32[153]=2;miss(&params);reset(&params);le32(image32+208,64);miss(&params);
 reset(&params);begin_mode=PW_BOP_MEMORY_EMPTY;miss(&params);assert(!read32_calls);
 reset(&params);begin_mode=PW_BOP_MEMORY_RECOVERY;end_refusals=3;miss(&params);assert(end_calls==4);
 reset(&params);end_refusals=7;assert(sync_loaded_init(&params)==STATUS_SUCCESS && sync_bound && end_calls==8 && !leased);
 reset(&params);end_refusals=8;assert(sync_loaded_init(&params)==STATUS_INTERNAL_ERROR && leased && held_view==&sync_init_memory && !sync_bound);
 assert(end(&sync_init_memory));
 const char *reject[]={"","0","true","1x","1\n"};
 for(unsigned i=0;i<5;i++){reset(&params);env_value=reject[i];file_value="1";miss(&params);assert(!read32_calls && !logs);}
 reset(&params);env_value=NULL;miss(&params);assert(!read32_calls && !logs);
 const char *files[]={"","0","1x","1\nX","1\r\n"};
 for(unsigned i=0;i<5;i++){reset(&params);env_value=NULL;file_value=files[i];miss(&params);assert(!read32_calls);}
 reset(&params);env_value=NULL;file_value="1";assert(sync_loaded_init(&params)==STATUS_SUCCESS && sync_bound);
 reset(&params);env_value=NULL;file_value="1\n";assert(sync_loaded_init(&params)==STATUS_SUCCESS && sync_bound);
 reset(&params);env_value=NULL;file_value="1";file_error=1;miss(&params);
 reset(&params);pin_error=1;prepare_sync_init((HMODULE)(uintptr_t)BASE64,&params);assert(!params.retained64);miss(&params);
 reset(&params);nt.FileHeader.Machine=0x14c;prepare_sync_init((HMODULE)(uintptr_t)BASE64,&params);miss(&params);
 puts("PASS actual CPU/Unix loaded binding, shared ABI, strict selector,5 paired services, bounded mocked lease recovery; no Wine/guest/stub/fault execution");return 0;
}
'''
def main():
 cpu=(ROOT/'wine/wowprospero/cpu.c').read_text();unix=(ROOT/'wine/wowprospero/unix.c').read_text()
 cpus=['static UINT WINAPI read_sync_image64(', 'static UINT64 WINAPI resolve_sync_export32(', 'static void prepare_sync_init(']
 unixes=['static int sync_requested(', 'static int sync_loaded_read32(', 'static int sync_loaded_read64(', 'static int sync_loaded_image32(', 'static int sync_loaded_end(', 'static NTSTATUS sync_loaded_init(']
 assert 'params.cpu_flags = (ULONG_PTR)&cpu->Flags;' in cpu
 assert 'WINE_UNIX_CALL( pw_wow_process_init, &params )' in cpu
 assert 'return sync_loaded_init( args );' in unix
 with tempfile.TemporaryDirectory(prefix='pw-sync-bop-loaded-') as name:
  p=Path(name);(p/'wine').mkdir()
  for patch,h in [('0890-ntdll-ps5-warm-sync-native-api.patch','ps5_sync_bop.h'),('0891-ntdll-ps5-sync-bop-context-view.patch','ps5_sync_bop_context.h'),('0892-ntdll-ps5-sync-bop-memory-lease.patch','ps5_sync_bop_memory.h')]:
   (p/'wine'/h).write_text(header(patch,h))
  (p/'cpu.inc').write_text(''.join(body(cpu,x) for x in cpus));(p/'unix.inc').write_text(''.join(body(unix,x) for x in unixes));(p/'test.c').write_text(HARNESS)
  cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
  subprocess.run([*cc,*flags,'-std=c11','-I',str(p),'-I',str(ROOT),str(p/'test.c'),'-o',str(p/'test')],check=True,timeout=60)
  subprocess.run([str(p/'test')],check=True,timeout=30)
if __name__=='__main__':main()
