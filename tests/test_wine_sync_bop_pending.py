#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual pending-edit bodies; explicit benign contexts, no Wine or faults."""
from pathlib import Path
import os,shlex,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
PATCH=ROOT/'wine/patches/0893-ntdll-ps5-sync-bop-pending-edits.patch'
def side(path,patch=PATCH):
 part=next(p for p in patch.read_text().split('diff --git ')[1:] if p.splitlines()[0].endswith(' b/'+path))
 return '\n'.join(x[1:] for x in part.splitlines() if x.startswith(('+',' ')) and not x.startswith('+++'))+'\n'
def body(source,signature):
 start=source.index(signature);brace=source.index('{',start);depth=1
 for end in range(brace+1,len(source)):
  depth+=(source[end]=='{')-(source[end]=='}')
  if not depth:return source[start:end+1]+'\n'
 raise AssertionError('unterminated body')
HARNESS=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "wine/ps5_sync_bop_pending.h"
#include "wine/ps5_sync_bop_memory.h"
#define DECLSPEC_EXPORT
#define DECLSPEC_ALIGN(n) _Alignas(n)
#define C_ASSERT(x) _Static_assert(x,#x)
#define IMAGE_FILE_MACHINE_I386 0x14c
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
/* Actual I386 field layout; conversion below is an explicit data mock. */
typedef uintptr_t UINT_PTR;
typedef unsigned char BYTE;
typedef struct { uint8_t bytes[112]; } I386_FLOATING_SAVE_AREA;
typedef struct { _Alignas(16) uint8_t bytes[512]; } XSAVE_FORMAT;
typedef struct {
 uint32_t ContextFlags,Dr0,Dr1,Dr2,Dr3,Dr6,Dr7;
 I386_FLOATING_SAVE_AREA FloatSave;
 uint32_t SegGs,SegFs,SegEs,SegDs,Edi,Esi,Ebx,Edx,Ecx,Eax,Ebp,Eip,SegCs,EFlags,Esp,SegSs;
 uint8_t ExtendedRegisters[512];
} I386_CONTEXT;
_Static_assert(sizeof(I386_CONTEXT)==716,"actual guest context size");
_Static_assert(offsetof(I386_CONTEXT,ExtendedRegisters)==204,"actual guest FP offset");
_Static_assert(sizeof(struct pw_sync_bop_pending_view)==656,"stable pending view");
typedef struct { uint16_t Flags,Machine; } WOW64_CPURESERVED;
struct teb { void *TlsSlots[1]; };
struct thread_data { struct teb *teb;void *ps5_sync_bop_pending,*ps5_sync_bop_memory,*ps5_sync_bop_context; };
struct syscall_frame { struct syscall_frame *prev_frame;XSAVE_FORMAT xsave; };
static _Alignas(16) struct { WOW64_CPURESERVED cpu; I386_CONTEXT ctx; } area;
#define CANONICAL area.ctx
static struct teb teb={{&area.cpu}};
static struct thread_data data={&teb,NULL,NULL,NULL};
static struct syscall_frame frame;
static struct pw_sync_bop_memory_view lease;
static _Alignas(16) struct pw_sync_bop_pending_view view;
static I386_CONTEXT fallback,incoming;
static unsigned missing_data,missing_frame,conversions;
static unsigned nested_record;
static struct thread_data *get_thread_data(void){return missing_data?NULL:&data;}
static struct syscall_frame *get_syscall_frame(struct thread_data *p){assert(p==&data);return missing_frame?NULL:&frame;}
static void *get_cpu_area(struct thread_data *p,unsigned machine){assert(p==&data && machine==0x14c);return &CANONICAL;}
static void fpu_to_fpux(XSAVE_FORMAT *to,const I386_FLOATING_SAVE_AREA *from)
{
 assert(!((uintptr_t)to&15));conversions++;
 /* Preserve the independently marked SSE region, as the real conversion does. */
 memcpy(to->bytes,from->bytes,sizeof(from->bytes));
}
static void fpux_to_fpu(I386_FLOATING_SAVE_AREA *to,const XSAVE_FORMAT *from)
{assert(!((uintptr_t)from&15));memcpy(to->bytes,from->bytes,sizeof(to->bytes));}
void ps5_sync_bop_pending_edit(struct thread_data *,const I386_CONTEXT *,unsigned);
static void *fixture_memcpy(void *out,const void *in,size_t bytes)
{
 if(out==view.extended && nested_record)
 {
  nested_record=0;
  ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);
 }
 return memcpy(out,in,bytes);
}
#define memcpy fixture_memcpy
#include "pending.inc"
#undef memcpy
static void reset(void)
{
 memset(&view,0,sizeof(view));memset(&CANONICAL,0x11,sizeof(CANONICAL));memset(&fallback,0x22,sizeof(fallback));memset(&incoming,0x77,sizeof(incoming));
 CANONICAL.ContextFlags=fallback.ContextFlags=incoming.ContextFlags=CONTEXT_I386_FULL|CONTEXT_I386_FLOATING_POINT|CONTEXT_I386_EXTENDED_REGISTERS;
 memset(incoming.FloatSave.bytes,0x66,sizeof(incoming.FloatSave.bytes));
 memset(&frame,0,sizeof(frame));memset(frame.xsave.bytes,0xee,sizeof(frame.xsave.bytes));
 missing_data=missing_frame=conversions=nested_record=0;data.teb=&teb;data.ps5_sync_bop_pending=data.ps5_sync_bop_context=NULL;
 lease=(struct pw_sync_bop_memory_view){.version=1,.size=sizeof(lease),.state=PW_BOP_MEMORY_HELD,.locked=1,.owner=(uintptr_t)&data};data.ps5_sync_bop_memory=&lease;
 area.cpu.Flags=0;view.version=1;view.size=sizeof(view);view.canonical=(uintptr_t)&CANONICAL;
}
static void attach(void){assert(ps5_sync_bop_pending_attach(&view,sizeof(CANONICAL)));}
static void invalid_take(void)
{
 I386_CONTEXT old=CANONICAL;struct pw_sync_bop_pending_view prior=view;uint16_t flags=area.cpu.Flags;
 assert(ps5_sync_bop_pending_take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_INVALID);
 assert(!memcmp(&old,&CANONICAL,sizeof(old)) && !memcmp(&prior,&view,sizeof(prior)) && flags==area.cpu.Flags);
}
int main(void)
{
 const struct pw_sync_bop_pending_backend *api=__wine_ps5_sync_bop_pending_backend(1);
 assert(api && api->pointer_size==sizeof(void *) && api->view_size==sizeof(view));assert(!__wine_ps5_sync_bop_pending_backend(0));
 reset();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FULL);assert(!view.fields);
 for(unsigned fields=0;fields<64;fields++)
 {
  reset();attach();CANONICAL=incoming;
  /* Explicit group requests; unchanged groups must retain the newer engine snapshot. */
  ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_i386|fields);
  area.cpu.Flags=WOW64_CPURESERVED_FLAG_RESET_STATE;
  assert(!api->detach(&view));assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED);
  assert(CANONICAL.Eip==((fields&1)?incoming.Eip:fallback.Eip));
  assert(CANONICAL.Esp==((fields&1)?incoming.Esp:fallback.Esp));
  assert(CANONICAL.Ebp==((fields&1)?incoming.Ebp:fallback.Ebp));
  assert(CANONICAL.EFlags==((fields&1)?incoming.EFlags:fallback.EFlags));
  assert(CANONICAL.SegCs==((fields&1)?incoming.SegCs:fallback.SegCs));
  assert(CANONICAL.SegSs==((fields&1)?incoming.SegSs:fallback.SegSs));
  assert(CANONICAL.Eax==((fields&2)?incoming.Eax:fallback.Eax));
  assert(CANONICAL.Ebx==((fields&2)?incoming.Ebx:fallback.Ebx));
  assert(CANONICAL.Ecx==((fields&2)?incoming.Ecx:fallback.Ecx));
  assert(CANONICAL.Edx==((fields&2)?incoming.Edx:fallback.Edx));
  assert(CANONICAL.Esi==((fields&2)?incoming.Esi:fallback.Esi));
  assert(CANONICAL.Edi==((fields&2)?incoming.Edi:fallback.Edi));
  assert(CANONICAL.SegFs==((fields&4)?incoming.SegFs:fallback.SegFs));
  assert(CANONICAL.SegGs==((fields&4)?incoming.SegGs:fallback.SegGs));
  assert(CANONICAL.SegDs==((fields&4)?incoming.SegDs:fallback.SegDs));
  assert(CANONICAL.SegEs==((fields&4)?incoming.SegEs:fallback.SegEs));
  assert(CANONICAL.Dr0==((fields&16)?incoming.Dr0:fallback.Dr0));
  assert(CANONICAL.Dr1==((fields&16)?incoming.Dr1:fallback.Dr1));
  assert(CANONICAL.Dr2==((fields&16)?incoming.Dr2:fallback.Dr2));
  assert(CANONICAL.Dr3==((fields&16)?incoming.Dr3:fallback.Dr3));
  assert(CANONICAL.Dr6==((fields&16)?incoming.Dr6:fallback.Dr6));
  assert(CANONICAL.Dr7==((fields&16)?incoming.Dr7:fallback.Dr7));
  unsigned fp=(fields&32)?0x77:((fields&8)?0x66:0x22);
  for(unsigned i=0;i<112;i++)assert(CANONICAL.ExtendedRegisters[i]==fp);
  for(unsigned i=160;i<512;i++)assert(CANONICAL.ExtendedRegisters[i]==((fields&32)?0x77:0x22));
  assert(!view.fields && !area.cpu.Flags && view.active && data.ps5_sync_bop_pending==&view);
  assert(frame.xsave.bytes[0]==0xee && frame.xsave.bytes[160]==0xee);
  I386_CONTEXT done=CANONICAL;assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_UNCHANGED);assert(!memcmp(&done,&CANONICAL,sizeof(done)));
  assert(api->detach(&view) && !data.ps5_sync_bop_pending && !view.active);
 }
 /* Legacy changes preserve either latest engine SSE or a preceding explicit extended image. */
 reset();attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);
 assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED && CANONICAL.ExtendedRegisters[160]==0x22);
 reset();attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_EXTENDED_REGISTERS);
 ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);
 assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED && CANONICAL.ExtendedRegisters[0]==0x66 && CANONICAL.ExtendedRegisters[160]==0x77);
 reset();attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);
 ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT|CONTEXT_I386_EXTENDED_REGISTERS);
 memset(&incoming,0xaa,sizeof(incoming)); /* Recorder retained bytes, no caller pointer. */
 assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED && CANONICAL.ExtendedRegisters[0]==0x77 && CANONICAL.ExtendedRegisters[160]==0x77);
 /* Persistent records survive unmasked intervals and an ordinary return boundary. */
 reset();attach();data.ps5_sync_bop_memory=NULL;ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_INTEGER);CANONICAL.Eax=incoming.Eax;
 invalid_take();data.ps5_sync_bop_memory=&lease;assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED && CANONICAL.Eax==incoming.Eax);
 /* Active publication owns its complete view; pending take must wait for finish. */
 reset();attach();data.ps5_sync_bop_context=&frame;invalid_take();data.ps5_sync_bop_context=NULL;
 ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_XSTATE);invalid_take();assert(!api->detach(&view) && view.fields==64);
 reset();attach();nested_record=1;ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_EXTENDED_REGISTERS);
 assert(view.fields & PW_BOP_PENDING_EDIT_CONFLICT);invalid_take();assert(!api->detach(&view));
 reset();area.cpu.Flags=0x8000;attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);area.cpu.Flags|=1;
 assert(api->take(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED && area.cpu.Flags==0x8000);
 /* Bad contracts cannot discard reset or mutate canonical storage. */
 reset();attach();view.version++;invalid_take();reset();attach();view.size--;invalid_take();
 reset();attach();view.owner++;invalid_take();reset();attach();view.active=0;invalid_take();
 reset();attach();lease.locked=0;invalid_take();reset();attach();lease.state=PW_BOP_MEMORY_RECOVERY;invalid_take();
 reset();attach();lease.owner++;invalid_take();reset();attach();data.teb=NULL;invalid_take();reset();attach();missing_data=1;invalid_take();
 reset();view.canonical++;assert(!api->attach(&view,sizeof(CANONICAL)));reset();missing_frame=1;assert(!api->attach(&view,sizeof(CANONICAL)));
 reset();frame.prev_frame=&frame;assert(!api->attach(&view,sizeof(CANONICAL)));reset();area.cpu.Flags=1;assert(!api->attach(&view,sizeof(CANONICAL)));
 reset();data.ps5_sync_bop_memory=NULL;assert(!api->attach(&view,sizeof(CANONICAL)));reset();attach();assert(!api->attach(&view,sizeof(CANONICAL)));
 puts("PASS actual pending guest edits:64 field combinations, ordered extended/legacy FP, native host FP preserved, persistent storage/lease/reset guards; no Wine/signals/faults");return 0;
}
'''
def main():
 signal=side('dlls/ntdll/unix/signal_x86_64.c');thread=side('dlls/ntdll/unix/thread.c')
 names=['static int ps5_sync_bop_pending_held(', 'static int ps5_sync_bop_pending_attach(', 'void ps5_sync_bop_pending_edit(', 'static uint32_t ps5_sync_bop_pending_take(', 'static int ps5_sync_bop_pending_detach(', 'DECLSPEC_EXPORT const struct pw_sync_bop_pending_backend *__wine_ps5_sync_bop_pending_backend(']
 actual=''.join(body(signal,n) for n in names)
 assert 'ps5_sync_bop_pending_edit( data, context, flags );' in signal
 assert 'ps5_sync_bop_pending_edit( get_thread_data(), wow_context, flags );' in thread
 for name in ['CONTROL','INTEGER','SEGMENTS','DEBUG_REGISTERS','EXTENDED_REGISTERS','FLOATING_POINT','YMM_REGISTERS']:
  assert 'SERVER_CTX_'+name in thread
 assert '__wine_ps5_sync_bop_pending_backend' in (ROOT/'tools/build_wine_ps5.sh').read_text()
 with tempfile.TemporaryDirectory(prefix='pw-sync-bop-pending-') as name:
  p=Path(name);(p/'wine').mkdir()
  (p/'wine/ps5_sync_bop_pending.h').write_text(side('include/wine/ps5_sync_bop_pending.h'))
  (p/'wine/ps5_sync_bop_memory.h').write_text(side('include/wine/ps5_sync_bop_memory.h',ROOT/'wine/patches/0892-ntdll-ps5-sync-bop-memory-lease.patch'))
  (p/'pending.inc').write_text(actual);(p/'test.c').write_text(HARNESS)
  cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
  subprocess.run([*cc,*flags,'-std=c11','-I',str(p),str(p/'test.c'),'-o',str(p/'test')],check=True,timeout=60)
  subprocess.run([str(p/'test')],check=True,timeout=30)
if __name__=='__main__':main()
