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
#include "wine/ps5_sync_bop_pending.h"
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
static int sync_bound,sync_diagnostics;
static const struct pw_sync_bop_pending_backend *sync_pending;
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
static const char *mock_getenv(const char *name){if(!strcmp(name,"PW_WOW_SYNC_BOP_DIAGNOSTICS"))return "0";assert(!strcmp(name,"PW_WOW_SYNC_BOP"));return env_value;}
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
static int pending_attach(struct pw_sync_bop_pending_view *v,uint32_t n){(void)v;(void)n;assert(0);return 0;}
static uint32_t pending_take(struct pw_sync_bop_pending_view *v,const void *p,uint32_t n){(void)v;(void)p;(void)n;assert(0);return 2;}
static int pending_detach(struct pw_sync_bop_pending_view *v){(void)v;assert(0);return 0;}
static struct pw_sync_bop_pending_backend pending={2,sizeof(pending),sizeof(void *),sizeof(struct pw_sync_bop_pending_view),pending_attach,pending_take,pending_detach,pending_take};
static const struct pw_sync_bop_pending_backend *__wine_ps5_sync_bop_pending_backend(uint32_t v){assert(v==2);return api_variant==4?NULL:&pending;}
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
 for(unsigned i=0;i<4;i++){reset(&params);api_variant=i+1;miss(&params);assert(!leased);}
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
 unixes=['static int sync_requested(', 'static int sync_diagnostics_requested(', 'static int sync_loaded_read32(', 'static int sync_loaded_read64(', 'static int sync_loaded_image32(', 'static int sync_loaded_end(', 'static NTSTATUS sync_loaded_init(']
 assert 'params.cpu_flags = (ULONG_PTR)&cpu->Flags;' in cpu
 assert 'WINE_UNIX_CALL( pw_wow_process_init, &params )' in cpu
 assert 'return sync_loaded_init( args );' in unix
 with tempfile.TemporaryDirectory(prefix='pw-sync-bop-loaded-') as name:
  p=Path(name);(p/'wine').mkdir()
  for patch,h in [('0890-ntdll-ps5-warm-sync-native-api.patch','ps5_sync_bop.h'),('0891-ntdll-ps5-sync-bop-context-view.patch','ps5_sync_bop_context.h'),('0892-ntdll-ps5-sync-bop-memory-lease.patch','ps5_sync_bop_memory.h')]:
   (p/'wine'/h).write_text(header(patch,h))
  import test_wine_sync_bop_pending as pending_fixture
  source=p/'source';(source/'dlls/ntdll/unix').mkdir(parents=True);(source/'include/wine').mkdir(parents=True)
  for rel in ['dlls/ntdll/unix/signal_x86_64.c','include/wine/ps5_sync_bop_pending.h']:
   (source/rel).write_text(pending_fixture.side(rel))
  subprocess.run(['patch','-s','--fuzz=0','-p1','-d',str(source),'-i',str(ROOT/'wine/patches/0894-ntdll-ps5-sync-bop-native-checkpoint.patch')],check=True,timeout=30)
  (p/'wine/ps5_sync_bop_pending.h').write_bytes((source/'include/wine/ps5_sync_bop_pending.h').read_bytes())
  (p/'cpu.inc').write_text(''.join(body(cpu,x) for x in cpus));(p/'unix.inc').write_text(''.join(body(unix,x) for x in unixes));(p/'test.c').write_text(HARNESS)
  cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
  subprocess.run([*cc,*flags,'-std=c11','-I',str(p),'-I',str(ROOT),str(p/'test.c'),'-o',str(p/'test')],check=True,timeout=60)
  subprocess.run([str(p/'test')],check=True,timeout=30)
  consumer_fixture(p,unix,cpu)


CONSUMER_HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "pw_x86_engine.h"
#include "pw_x86_hostexec.h"
#define WINAPI
#define DECLSPEC_EXPORT
#define DECLSPEC_ALIGN(n) _Alignas(n)
#define C_ASSERT(x) _Static_assert(x,#x)
#define CONTEXT_i386 0x10000u
#define CONTEXT_I386_CONTROL (CONTEXT_i386|1)
#define CONTEXT_I386_INTEGER (CONTEXT_i386|2)
#define CONTEXT_I386_SEGMENTS (CONTEXT_i386|4)
#define CONTEXT_I386_FLOATING_POINT (CONTEXT_i386|8)
#define CONTEXT_I386_DEBUG_REGISTERS (CONTEXT_i386|16)
#define CONTEXT_I386_EXTENDED_REGISTERS (CONTEXT_i386|32)
#define CONTEXT_I386_XSTATE (CONTEXT_i386|64)
#define CONTEXT_I386_FULL (CONTEXT_i386|7)
#define WOW64_TLS_CPURESERVED 0
#define WOW64_CPURESERVED_FLAG_RESET_STATE 1
#define RESTORE_FLAGS_INCOMPLETE_FRAME_CONTEXT 0x20000u
#define IMAGE_FILE_MACHINE_I386 0x14c
#define PW_FP_IN_CONTEXT 0x8000
#define STATUS_SUCCESS 0u
#define STATUS_INTERNAL_ERROR 0xc00000e5u
#define STATUS_ACCESS_VIOLATION 0xc0000005u
#define EXCEPTION_ACCESS_VIOLATION STATUS_ACCESS_VIOLATION
#define EXCEPTION_ILLEGAL_INSTRUCTION 0xc000001du
#define EXCEPTION_FLT_INVALID_OPERATION 0xc0000090u
#define LOWORD(x) ((uint16_t)(x))
typedef uint32_t UINT,ULONG,NTSTATUS;
typedef uint16_t USHORT;
typedef uint64_t UINT64;
typedef uintptr_t ULONG_PTR,UINT_PTR;
typedef int INT,LONG;
typedef unsigned char BYTE;
typedef struct { uint8_t bytes[112]; } I386_FLOATING_SAVE_AREA;
typedef struct { _Alignas(16) uint8_t bytes[512]; } XSAVE_FORMAT;
typedef struct {
 uint32_t ContextFlags,Dr0,Dr1,Dr2,Dr3,Dr6,Dr7;
 I386_FLOATING_SAVE_AREA FloatSave;
 uint32_t SegGs,SegFs,SegEs,SegDs,Edi,Esi,Ebx,Edx,Ecx,Eax,Ebp,Eip,SegCs,EFlags,Esp,SegSs;
 uint8_t ExtendedRegisters[512];
} I386_CONTEXT;
typedef struct { uint16_t Flags,Machine; } WOW64_CPURESERVED;
_Static_assert(sizeof(I386_CONTEXT)==716,"real context ABI");
_Static_assert(offsetof(I386_CONTEXT,ExtendedRegisters)==204,"real FP alignment offset");
#include "wine/wowprospero/wowprospero.h"
#include "wine/ps5_sync_bop.h"
#include "wine/ps5_sync_bop_context.h"
#include "wine/ps5_sync_bop_memory.h"
#include "wine/ps5_sync_bop_pending.h"
#include "wine/wowprospero/sync_bop_bindings.h"
struct peb { unsigned BeingDebugged; };
struct teb { void *TlsSlots[1];struct peb *Peb;struct { void *UniqueThread; } ClientId; };
struct thread_data { struct teb *teb;void *ps5_sync_bop_context,*ps5_sync_bop_pending,*ps5_sync_bop_memory; };
struct syscall_frame { unsigned restore_flags;struct syscall_frame *prev_frame;XSAVE_FORMAT xsave; };
static _Alignas(16) struct { WOW64_CPURESERVED cpu; I386_CONTEXT ctx; } area;
#define CANONICAL area.ctx
static struct peb peb;
static struct teb teb={{&area.cpu},&peb,{(void *)0x24}};
static struct thread_data data={&teb,NULL,NULL,NULL};
static struct syscall_frame frame;
static struct thread_data *get_thread_data(void){return &data;}
static struct syscall_frame *get_syscall_frame(struct thread_data *p){assert(p==&data);return &frame;}
static void *get_cpu_area(struct thread_data *p,unsigned machine)
{
 assert(p==&data && machine==0x14c);
 if(data.ps5_sync_bop_context){struct pw_sync_bop_context_view *v=data.ps5_sync_bop_context;return (void *)(uintptr_t)(v->phase==PW_BOP_CONTEXT_COMMITTED?v->canonical:v->shadow);}
 return &CANONICAL;
}
/* Explicit conversion/OS mocks: actual Wine FP functions have separate fixtures. */
static void fpux_to_fpu(I386_FLOATING_SAVE_AREA *out,const XSAVE_FORMAT *in){assert(!((uintptr_t)in&15));memcpy(out->bytes,in->bytes,112);}
static void fpu_to_fpux(XSAVE_FORMAT *out,const I386_FLOATING_SAVE_AREA *in){assert(!((uintptr_t)out&15));memcpy(out->bytes,in->bytes,112);}
typedef uint64_t sigset_t;
#define SIG_BLOCK 1
#define SIG_SETMASK 2
static sigset_t server_block_set=7;
static unsigned masked,mask_error,restore_refusals,queued_edit,edit_kind;
static I386_CONTEXT incoming;
void ps5_sync_bop_context_edit(struct thread_data *);
void ps5_sync_bop_pending_edit(struct thread_data *,const I386_CONTEXT *,unsigned);
static void observe(void)
{
 I386_CONTEXT *out=get_cpu_area(&data,0x14c);
 if(edit_kind==1){incoming=*out;incoming.Eax=0xabc;incoming.Eip=0x2e000;incoming.Esp=0x21004;memset(incoming.ExtendedRegisters,0x77,512);*out=incoming;
  ps5_sync_bop_context_edit(&data);ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_INTEGER|CONTEXT_I386_CONTROL|CONTEXT_I386_EXTENDED_REGISTERS);area.cpu.Flags|=1;}
 else {ps5_sync_bop_context_edit(&data);area.cpu.Flags|=1;}
}
static int pthread_sigmask(int how,const sigset_t *set,sigset_t *old)
{
 if(how==SIG_BLOCK){assert(set==&server_block_set && old);if(mask_error)return 1;*old=masked;masked=1;return 0;}
 assert(how==SIG_SETMASK && set && !old);if(restore_refusals){restore_refusals--;return 1;}
 masked=*set;if(!masked && queued_edit){queued_edit=0;observe();}return 0;
}
#include "context.inc"
#include "pending.inc"
enum { GUEST_LOW=0x10000u,GUEST_HIGH=0xfffff000u };
#include "thread.inc"
static struct pw_thread fixture_thread;
static uint64_t code_generation=1;
static int sync_bound=1,sync_diagnostics=1,timing_enabled=0;
static struct pw_wow_sync_attestation sync_attestation;
static const struct pw_sync_bop_backend *sync_backend;
static const struct pw_sync_bop_context_backend *sync_context;
static const struct pw_sync_bop_memory_backend *sync_memory;
static const struct pw_sync_bop_pending_backend *sync_pending;
static unsigned lease_busy,end_refusals,backend_hit,warm_calls,write_status,readonly,steps,resets;
static uint8_t memory_bytes[0x10000],engine_fp[512];
static struct pw_thread *get_thread(void){return &fixture_thread;}
static int memory_span(uint32_t a,uint32_t n){return a>=0x20000 && a-0x20000<=sizeof(memory_bytes) && n<=sizeof(memory_bytes)-(a-0x20000);}
static uint32_t lease_begin(struct pw_sync_bop_memory_view *v)
{
 assert(!masked && !data.ps5_sync_bop_memory);if(lease_busy)return PW_BOP_MEMORY_EMPTY;
 masked=1;v->previous_mask[0]=0;v->state=PW_BOP_MEMORY_HELD;v->locked=1;v->owner=(uintptr_t)&data;data.ps5_sync_bop_memory=v;return v->state;
}
static int lease_end(struct pw_sync_bop_memory_view *v)
{
 assert(data.ps5_sync_bop_memory==v && masked);if(end_refusals){end_refusals--;return 0;}
 data.ps5_sync_bop_memory=NULL;v->state=PW_BOP_MEMORY_EMPTY;v->locked=0;masked=0;
 if(queued_edit){queued_edit=0;observe();}return 1;
}
static int memory_read(struct pw_sync_bop_memory_view *v,uint32_t a,void *out,uint32_t n)
{assert(data.ps5_sync_bop_memory==v && masked);if(!memory_span(a,n))return 0;memcpy(out,memory_bytes+a-0x20000,n);return 1;}
static int memory_writable(struct pw_sync_bop_memory_view *v,uint32_t a,uint32_t n)
{assert(data.ps5_sync_bop_memory==v && masked);return !readonly && memory_span(a,n);}
static uint32_t memory_write(struct pw_sync_bop_memory_view *v,uint32_t a,const void *in,uint32_t n)
{assert(data.ps5_sync_bop_memory==v && masked && memory_span(a,n));if(write_status)return write_status;memcpy(memory_bytes+a-0x20000,in,n);return 0;}
static int warm(uint32_t op,uint32_t h,uint32_t count,uint32_t *out)
{assert(masked && data.ps5_sync_bop_context && op<5 && h==0x44);assert(op!=4 || count==3);warm_calls++;if(backend_hit)*out=7;return backend_hit;}
static struct pw_sync_bop_memory_backend memory_api={1,sizeof(memory_api),sizeof(void *),sizeof(struct pw_sync_bop_memory_view),lease_begin,lease_end,memory_read,memory_writable,memory_write};
static struct pw_sync_bop_backend backend_api={1,sizeof(backend_api),sizeof(void *),0x1f,warm};
/* Engine execution is a bounded, explicit state-transition mock, never game code. */
static void mock_commit(PwX86State *s){s->deferred_flags.known_mask=0;}
static void mock_fp_load(PwX86Engine *e,PwX86State *s,const uint8_t *in){(void)e;(void)s;memcpy(engine_fp,in,512);}
static void mock_fp_store(PwX86Engine *e,PwX86State *s,uint8_t *out){(void)e;(void)s;memcpy(out,engine_fp,512);}
static void mock_fp_sync(PwX86Engine *e,PwX86State *s){(void)e;(void)s;}
static int mock_step(PwX86Engine *e,PwX86State *s,PwX86StepReport *report)
{(void)e;(void)report;assert(++steps<4);s->eip=0x2f000;return PW_OK;}
static void mock_reset(PwX86Engine *e,uint32_t generation){(void)generation;resets++;e->cache.resets++;}
static void mock_host_reset(PwX86HostExec *h){(void)h;}
static int mock_source(void *o,uint32_t a,const uint8_t **s,size_t *n){(void)o;(void)a;(void)s;(void)n;return PW_ERR_NOT_FOUND;}
static int mock_host_step(PwX86HostExec *h,PwX86State *s,const uint8_t *b,size_t n){(void)h;(void)s;(void)b;(void)n;return PW_ERR_UNSUPPORTED;}
static void mock_quantum(PwX86Engine *e,uint32_t n){(void)e;(void)n;}
static void timing_init(void){timing_enabled=0;}
static void timing_enter(struct pw_thread *t){(void)t;}
static void timing_leave(struct pw_thread *t,unsigned r){(void)t;(void)r;}
static void profile_maybe_dump(void){}
static struct teb *NtCurrentTeb(void){return &teb;}
#define PtrToUlong(p) ((uint32_t)(uintptr_t)(p))
static uint64_t __rdtsc(void){return 1;}
#define pw_x86_commit_canonical_flags mock_commit
#define pw_x86_engine_fp_load mock_fp_load
#define pw_x86_engine_fp_store mock_fp_store
#define pw_x86_engine_fp_sync mock_fp_sync
#define pw_x86_engine_step mock_step
#define pw_x86_engine_reset mock_reset
#define pw_x86_hostexec_reset mock_host_reset
#define source_view mock_source
#define pw_x86_hostexec_step mock_host_step
#define pw_x86_engine_set_quantum mock_quantum
#include "state.inc"
#include "consumer.inc"
#include "run.inc"
static void le32(uint32_t at,uint32_t value){assert(memory_span(at,4));for(unsigned i=0;i<4;i++)memory_bytes[at-0x20000+i]=(uint8_t)(value>>(i*8));}
static struct pw_wow_run_params setup(unsigned op)
{
 memset(&fixture_thread,0,sizeof(fixture_thread));memset(&area,0,sizeof(area));memset(memory_bytes,0,sizeof(memory_bytes));memset(&frame,0,sizeof(frame));memset(&incoming,0,sizeof(incoming));memset(&peb,0,sizeof(peb));
 data.ps5_sync_bop_context=data.ps5_sync_bop_pending=data.ps5_sync_bop_memory=NULL;
 masked=mask_error=restore_refusals=queued_edit=edit_kind=lease_busy=end_refusals=warm_calls=write_status=readonly=steps=resets=0;backend_hit=1;sync_bound=sync_diagnostics=1;code_generation=1;fixture_thread.generation=1;
 sync_backend=&backend_api;sync_memory=&memory_api;sync_context=__wine_ps5_sync_bop_context_backend(1);sync_pending=__wine_ps5_sync_bop_pending_backend(2);
 sync_attestation.bindings.version=1;sync_attestation.bindings.attested=1;sync_attestation.helper32=0x20300;sync_attestation.dispatcher32=0x20320;
 for(unsigned i=0;i<5;i++){
  uint32_t a=0x20040+32*i;sync_attestation.bindings.ids[i]=100+i;sync_attestation.continuations[i]=a+12;
  memory_bytes[a-0x20000]=0xb8;le32(a+1,100+i);memory_bytes[a+5-0x20000]=0xba;le32(a+6,0x20300);
  memory_bytes[a+10-0x20000]=0xff;memory_bytes[a+11-0x20000]=0xd2;memory_bytes[a+12-0x20000]=0xc2;memory_bytes[a+13-0x20000]=(i==0||i==4)?12:8;
 }
 memory_bytes[0x300]=0xff;memory_bytes[0x301]=0x25;le32(0x20302,0x20320);le32(0x20320,0x2d000);
 CANONICAL.ContextFlags=CONTEXT_I386_FULL|CONTEXT_I386_FLOATING_POINT|CONTEXT_I386_EXTENDED_REGISTERS;CANONICAL.EFlags=0x202;CANONICAL.Eip=0x2d000;CANONICAL.Esp=0x21000;CANONICAL.Eax=100+op;
 memset(CANONICAL.ExtendedRegisters,0x22,512);frame.restore_flags=RESTORE_FLAGS_INCOMPLETE_FRAME_CONTEXT;memset(frame.xsave.bytes,0xee,512);
 le32(0x21000,sync_attestation.continuations[op]);le32(0x21004,0x2f000);le32(0x21008,0x44);le32(0x2100c,op==4?3:op==0?0:0x21200);le32(0x21010,op==4?0x21200:0);
 return (struct pw_wow_run_params){.context=(uintptr_t)&CANONICAL,.teb32=0x22000,.bop=0x2d000,.unix_bop=0x2f000,.cpu_flags=(uintptr_t)&area.cpu.Flags};
}
static void check_clean(void)
{assert(!masked && !data.ps5_sync_bop_context && !data.ps5_sync_bop_memory);assert(frame.xsave.bytes[0]==0xee);assert(sync_detach(&fixture_thread));assert(!data.ps5_sync_bop_pending && !masked);}
/* Actual CPU return loop uses scripted Unix/service calls and explicit FP
 * save/restore mocks. None of these mocks delivers a native exception. */
static unsigned cpu_case,cpu_calls,syscalls,unixcalls,terminations,fp_saves,fp_restores,guest_exceptions;
static uint8_t bop_storage[32];
static BYTE *bop_page=bop_storage;
static WOW64_CPURESERVED *get_cpu(void){return &area.cpu;}
static I386_CONTEXT *get_context(WOW64_CPURESERVED *p){assert(p==&area.cpu);return &CANONICAL;}
static UINT get_teb32(void){return 0x22000;}
static void copy_fxsave(void *out,const void *in){memcpy(out,in,512);}
static void mock_fxsave(XSAVE_FORMAT *p){fp_saves++;memset(p->bytes,0x33,512);}
static void mock_fxrstor(const XSAVE_FORMAT *p){fp_restores++;assert(p->bytes[0]==0x77 || p->bytes[0]==0x33);}
static void *ULongToPtr(UINT at){assert(memory_span(at,1));return memory_bytes+at-0x20000;}
static void *GetCurrentProcess(void){return (void *)(intptr_t)-1;}
static NTSTATUS NtTerminateProcess(void *p,NTSTATUS s){(void)p;assert(s==STATUS_INTERNAL_ERROR);terminations++;return 0;}
static LONG InterlockedExchange(LONG *p,LONG n){LONG o=*p;*p=n;return o;}
static void mock_err(const char *s,...){assert(s);}
#define ERR mock_err
static void raise_guest_exception(I386_CONTEXT *p,NTSTATUS s,UINT a,UINT w){(void)p;(void)s;(void)a;(void)w;guest_exceptions++;}
typedef uint64_t unixlib_handle_t;
static NTSTATUS Wow64SystemServiceEx(UINT op,UINT *args){assert(op==100 && args==((UINT *)memory_bytes+0x1008/4));syscalls++;return 0x55;}
static NTSTATUS unix_call_dispatcher(unixlib_handle_t h,UINT c,void *a){(void)h;(void)c;(void)a;unixcalls++;return 0;}
static NTSTATUS mock_unix_call(unsigned op,void *opaque)
{
 assert(op==pw_wow_run);struct pw_wow_run_params *p=opaque;cpu_calls++;
 if(cpu_calls==1){
  p->sync_active=1;p->reason=cpu_case==1?PW_WOW_RESET:PW_WOW_SYSCALL;
  if(cpu_case==1||cpu_case==2){area.cpu.Flags|=1;CANONICAL.Eax=0xabc;CANONICAL.Esp=0;memset(CANONICAL.ExtendedRegisters,0x77,512);}
  if(cpu_case==3){p->reason=PW_WOW_STOP;CANONICAL.Esp=0;}
  return 0;
 }
 assert(cpu_calls==2);if(cpu_case==1||cpu_case==2)assert(area.cpu.Flags&PW_FP_IN_CONTEXT);
 p->reason=PW_WOW_STOP;return 0;
}
#define WINE_UNIX_CALL mock_unix_call
#include "cpu-run.inc"
int main(void)
{
 struct pw_wow_run_params params;
 for(unsigned op=0;op<5;op++){
  params=setup(op);assert(run(&params)==0 && params.reason==PW_WOW_UNIXCALL && params.sync_active);
  assert(warm_calls==1 && CANONICAL.Eax==0 && CANONICAL.Esp==0x21004 && CANONICAL.Eip==0x2f000 && steps==1);
  if(op)assert(pw_wow_sync_read_le32(memory_bytes+0x1200)==7);
  assert(fixture_thread.sync_hits[op]==1);check_clean();
  params=setup(op);backend_hit=0;I386_CONTEXT old=CANONICAL;assert(run(&params)==0 && params.reason==PW_WOW_SYSCALL);
  assert(warm_calls==1 && CANONICAL.Eip==old.Eip && CANONICAL.Esp==old.Esp && CANONICAL.Eax==old.Eax && !steps);check_clean();
 }
 params=setup(2);write_status=STATUS_ACCESS_VIOLATION;assert(run(&params)==0 && params.reason==PW_WOW_UNIXCALL && CANONICAL.Eax==write_status && warm_calls==1);check_clean();
 params=setup(2);readonly=1;assert(run(&params)==0 && params.reason==PW_WOW_SYSCALL && !warm_calls && CANONICAL.Esp==0x21000);check_clean();
 params=setup(0);le32(0x2100c,0x101);assert(run(&params)==0 && params.reason==PW_WOW_SYSCALL && !warm_calls);check_clean();
 params=setup(0);le32(0x2100c,0x100);assert(run(&params)==0 && params.reason==PW_WOW_UNIXCALL && warm_calls==1);check_clean();
 for(unsigned mutation=0;mutation<4;mutation++){
  params=setup(0);if(!mutation)memory_bytes[0x40]^=1;else if(mutation==1)memory_bytes[0x300]^=1;else if(mutation==2)le32(0x20320,0x2d004);else le32(0x21000,0x20000);
  assert(run(&params)==0 && params.reason==PW_WOW_SYSCALL && !warm_calls);check_clean();
 }
 params=setup(0);lease_busy=1;assert(run(&params)==0 && !params.sync_active && params.reason==PW_WOW_SYSCALL && !warm_calls);
 assert(!data.ps5_sync_bop_pending && !data.ps5_sync_bop_context);
 params=setup(0);assert(sync_attach(&fixture_thread,&CANONICAL,&params)==1);lease_busy=1;
 assert(run(&params)==0 && params.sync_active && params.reason==PW_WOW_SYSCALL && !warm_calls && fixture_thread.sync_lease_misses[0]==1);lease_busy=0;check_clean();
 params=setup(0);queued_edit=1;edit_kind=1;/* attach end delivers pending edit before engine load */
 assert(run(&params)==0 && params.reason==PW_WOW_UNIXCALL && !warm_calls && CANONICAL.Eax==0xabc && CANONICAL.Esp==0x21004 && CANONICAL.ExtendedRegisters[160]==0x77);check_clean();
 for(unsigned hit=0;hit<2;hit++){
  params=setup(0);assert(sync_attach(&fixture_thread,&CANONICAL,&params)==1);queued_edit=1;edit_kind=2;backend_hit=hit;
  assert(run(&params)==0 && warm_calls==(hit?1:2));
  /* A read-only observer reset during a miss cannot pop/skip the service. */
  assert(hit?CANONICAL.Esp==0x21004:CANONICAL.Esp==0x21000);assert(hit?params.reason==PW_WOW_UNIXCALL:params.reason==PW_WOW_SYSCALL);check_clean();
 }
 params=setup(0);assert(sync_attach(&fixture_thread,&CANONICAL,&params)==1);queued_edit=1;edit_kind=1;
 assert(run(&params)==0 && warm_calls==1 && CANONICAL.Eax==0xabc && CANONICAL.ExtendedRegisters[160]==0x77 && CANONICAL.Esp==0x21004);check_clean();
 params=setup(0);assert(sync_attach(&fixture_thread,&CANONICAL,&params)==1);frame.restore_flags=0;
 assert(run(&params)==0 && params.reason==PW_WOW_SYSCALL && !warm_calls);check_clean();
 params=setup(0);assert(sync_attach(&fixture_thread,&CANONICAL,&params)==1);code_generation=2;
 assert(run(&params)==0 && resets==1 && fixture_thread.generation==2);check_clean();
 for(unsigned c=0;c<4;c++){
  params=setup(0);(void)params;cpu_case=c;cpu_calls=syscalls=unixcalls=terminations=fp_saves=fp_restores=guest_exceptions=0;
  BTCpuSimulate();assert(terminations==2 && !guest_exceptions && !unixcalls);assert(c?syscalls==0:syscalls==1);
  assert(c?fp_restores==0:fp_restores==1);assert(c==3?cpu_calls==1:cpu_calls==2);
 }
 puts("PASS actual BOP consumer/run/CPU bodies: five operations, untouched misses, status continuation, code revalidation, FP/reset imports, VM contention and STOP; bounded state mocks, no Wine/guest/fault execution");return 0;
}

'''

def consumer_fixture(p,unix,cpu):
 import test_wine_sync_bop_context as context_fixture
 signal=(p/'source/dlls/ntdll/unix/signal_x86_64.c').read_text()
 context=context_fixture.side('dlls/ntdll/unix/signal_x86_64.c')
 contexts=['void ps5_sync_bop_context_edit(', 'static int ps5_sync_bop_context_publish(', 'static uint32_t ps5_sync_bop_context_finish(', 'DECLSPEC_EXPORT const struct pw_sync_bop_context_backend *__wine_ps5_sync_bop_context_backend(']
 pendings=['static int ps5_sync_bop_pending_held(', 'static int ps5_sync_bop_pending_attach(', 'void ps5_sync_bop_pending_edit(', 'static uint32_t ps5_sync_bop_pending_merge(', 'static uint32_t ps5_sync_bop_pending_take(', 'static uint32_t ps5_sync_bop_pending_checkpoint(', 'static int ps5_sync_bop_pending_detach(', 'DECLSPEC_EXPORT const struct pw_sync_bop_pending_backend *__wine_ps5_sync_bop_pending_backend(']
 (p/'context.inc').write_text(''.join(body(context,n) for n in contexts))
 (p/'pending.inc').write_text(''.join(body(signal,n) for n in pendings))
 (p/'thread.inc').write_text(body(unix,'struct pw_thread\n{')+';\n')
 states=['static void load_state(', 'static void sync_fp_in(', 'static void sync_fp_out(', 'static void store_state(']
 (p/'state.inc').write_text(''.join(body(unix,n) for n in states))
 funcs=['static int sync_loaded_end(', 'static I386_CONTEXT *sync_shadow(', 'static void sync_snapshot(', 'static int sync_pending_changes(', 'static int sync_memory_begin(', 'static int sync_attach(', 'static int sync_checkpoint(', 'static int sync_revalidate(', 'static int sync_read(', 'static int sync_writable(', 'static uint32_t sync_write(', 'static void sync_registers(', 'static int sync_publish(', 'static int sync_cached(', 'static int sync_finish(', 'static int sync_try(', 'static int sync_leave(', 'static void sync_report(', 'static int sync_detach(']
 (p/'consumer.inc').write_text(''.join(body(unix,n) for n in funcs))
 (p/'run.inc').write_text(body(unix,'static void reset_thread_engine(')+body(unix,'static NTSTATUS run('))
 native_cpu=body(cpu,'void WINAPI BTCpuSimulate(')
 save='__asm__ volatile( "fxsave %0" : "=m" (fp) );'
 restore='__asm__ volatile( "fxrstor %0" : : "m" (fp) );'
 assert native_cpu.count(save)==native_cpu.count(restore)==1
 native_cpu=native_cpu.replace(save,'mock_fxsave(&fp);').replace(restore,'mock_fxrstor(&fp);')
 (p/'cpu-run.inc').write_text(native_cpu)
 (p/'consumer.c').write_text(CONSUMER_HARNESS)
 cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
 subprocess.run([*cc,*flags,'-std=c11','-D__PROSPERO__','-I',str(p),'-I',str(ROOT),'-I',str(ROOT/'src'),str(p/'consumer.c'),'-o',str(p/'consumer')],check=True,timeout=60)
 result=subprocess.run([str(p/'consumer')],capture_output=True,text=True,timeout=30)
 if result.returncode: print(result.stdout, result.stderr[-2500:])
 result.check_returncode()
 assert 'attempts=' in result.stderr and 'lease_misses=' in result.stderr and 'sync_bop_wait:' in result.stderr
 print(result.stdout.strip())

if __name__=='__main__':main()
