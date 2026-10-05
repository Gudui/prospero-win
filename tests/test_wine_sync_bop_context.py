#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual native context bodies with bounded mocks; no Wine/signals executed."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT/'wine/patches/0891-ntdll-ps5-sync-bop-context-view.patch'


def side(name):
    part = next(p for p in PATCH.read_text().split('diff --git ')[1:]
                if p.splitlines()[0].endswith(' b/'+name))
    return '\n'.join(line[1:] for line in part.splitlines()
                     if line.startswith(('+',' ')) and not line.startswith('+++'))+'\n'


def body(source, signature):
    start=source.index(signature)
    brace=source.index('{',start)
    depth=1
    for end in range(brace+1,len(source)):
        depth+=(source[end]=='{')-(source[end]=='}')
        if not depth:return source[start:end+1]+'\n'
    raise AssertionError('unterminated function')


HARNESS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wine/ps5_sync_bop_context.h"
#define _WIN64 1
#define WINE_INPROCESS_SERVER 1
#define DECLSPEC_EXPORT
typedef uint64_t ULONG_PTR;
typedef uint32_t ULONG;
typedef uint16_t USHORT;
typedef int sigset_t;
#define SIG_BLOCK 1
#define SIG_SETMASK 2
#define IMAGE_FILE_MACHINE_I386 0x14c
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARMNT 0x1c4
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define CONTEXT_i386 0x10000u
#define CONTEXT_I386_CONTROL (CONTEXT_i386|1)
#define CONTEXT_I386_INTEGER (CONTEXT_i386|2)
#define CONTEXT_I386_FLOATING_POINT (CONTEXT_i386|8)
#define CONTEXT_I386_EXTENDED_REGISTERS (CONTEXT_i386|32)
#define CONTEXT_I386_XSTATE (CONTEXT_i386|64)
#define RESTORE_FLAGS_INCOMPLETE_FRAME_CONTEXT 0x20000u
#define WOW64_TLS_CPURESERVED 0
#define WOW64_CPURESERVED_FLAG_RESET_STATE 1
#define SERVER_CTX_FLOATING_POINT 8
#define SERVER_CTX_EXTENDED_REGISTERS 32
#define STATUS_SUCCESS 0
#define TYPE_ALIGNMENT(type) _Alignof(type)
typedef struct { uint8_t bytes[128]; } FLOAT_SAVE;
typedef struct { _Alignas(16) uint8_t bytes[512]; } XSAVE_FORMAT;
/* Explicit mock layout: real Wine I386/XSAVE ABI is checked by full SDK builds. */
typedef struct {
 uint32_t ContextFlags,EFlags,Eax,Eip,Esp,Dr7;
 FLOAT_SAVE FloatSave;
 _Alignas(16) uint8_t ExtendedRegisters[512];
} I386_CONTEXT;
typedef struct { int ignored; } AMD64_CONTEXT,ARM_CONTEXT,ARM64_NT_CONTEXT;
typedef struct { uint16_t Flags,Machine; } WOW64_CPURESERVED;
struct peb { unsigned BeingDebugged; };
struct teb { void *TlsSlots[1];struct peb *Peb; };
struct thread_data { struct teb *teb;void *ps5_sync_bop_context; };
struct syscall_frame { unsigned restore_flags;struct syscall_frame *prev_frame;XSAVE_FORMAT xsave; };
static struct { _Alignas(16) WOW64_CPURESERVED cpu;_Alignas(16) I386_CONTEXT context; } area;
#define CANONICAL area.context
static I386_CONTEXT shadow;
static struct peb peb;
static struct teb teb={{&area.cpu},&peb};
static struct thread_data data={&teb,NULL};
static struct syscall_frame frame;
static int missing_data,missing_frame,mask_error,masked;
static unsigned blocks,unblocks,copy_interrupts,interrupt_after_commit;
static sigset_t server_block_set=5;
static struct thread_data *get_thread_data(void) { return missing_data?NULL:&data; }
static struct syscall_frame *get_syscall_frame(struct thread_data *d)
{ assert(d==&data);return missing_frame?NULL:&frame; }
static int is_wow64(void) { return 1; }
static void fpux_to_fpu(FLOAT_SAVE *to,const XSAVE_FORMAT *from)
{ memcpy(to->bytes,from->bytes,sizeof(to->bytes)); }
static void fpu_to_fpux(XSAVE_FORMAT *to,const FLOAT_SAVE *from)
{ memcpy(to->bytes,from->bytes,sizeof(from->bytes)); }
static int pthread_sigmask(int how,const sigset_t *set,sigset_t *prior)
{
 if(how==SIG_BLOCK){assert(set==&server_block_set && prior);blocks++;if(mask_error)return mask_error;*prior=masked;masked=1;}
 else {assert(how==SIG_SETMASK && set && !prior);unblocks++;masked=*set;}
 return 0;
}
void *ps5_sync_bop_cpu_area(struct thread_data *);
void ps5_sync_bop_context_edit(struct thread_data *);
void ps5_sync_bop_context_resumed(struct thread_data *,unsigned);
#include "cpu_area.inc"
static void observer(void)
{
 I386_CONTEXT *ctx=ps5_sync_bop_cpu_area(&data);
 assert(ctx);
 ps5_sync_bop_context_edit(&data);
 ctx->Eax=0x7788;ctx->Eip+=5;ctx->ExtendedRegisters[0]=0x7f;
 area.cpu.Flags|=WOW64_CPURESERVED_FLAG_RESET_STATE;
}
static void *fixture_memcpy(void *dst,const void *src,size_t size)
{
 if(dst==&CANONICAL && src==&shadow && copy_interrupts && !masked)
 {
  assert(get_cpu_area(&data,IMAGE_FILE_MACHINE_I386)==&shadow);
  memcpy(dst,src,size/2);observer();copy_interrupts--;memcpy((uint8_t *)dst+size/2,(const uint8_t *)src+size/2,size-size/2);
  return dst;
 }
 return memcpy(dst,src,size);
}
static int fixture_cas(uint32_t *ptr,uint32_t *expected,uint32_t value,int weak,int success,int failure)
{
 int result=__atomic_compare_exchange_n(ptr,expected,value,weak,success,failure);
 if(result && interrupt_after_commit){interrupt_after_commit=0;observer();}
 return result;
}
#define memcpy fixture_memcpy
#define __atomic_compare_exchange_n fixture_cas
#include "context.inc"
#undef memcpy
#undef __atomic_compare_exchange_n
static void reset(struct pw_sync_bop_context_view *view)
{
 memset(&CANONICAL,0,sizeof(CANONICAL));memset(&shadow,0,sizeof(shadow));memset(&frame,0,sizeof(frame));
 frame.restore_flags=RESTORE_FLAGS_INCOMPLETE_FRAME_CONTEXT;
 memset(frame.xsave.bytes,0x33,sizeof(frame.xsave.bytes));
 CANONICAL.ContextFlags=CONTEXT_I386_CONTROL|CONTEXT_I386_INTEGER|CONTEXT_I386_EXTENDED_REGISTERS;
 CANONICAL.EFlags=0x202;CANONICAL.Eax=101;CANONICAL.Eip=0x11000;CANONICAL.Esp=0x12000;
 memset(CANONICAL.ExtendedRegisters,0x11,sizeof(CANONICAL.ExtendedRegisters));
 shadow=CANONICAL;shadow.Eip=0x13000;shadow.Esp+=4;
 memset(shadow.ExtendedRegisters,0x22,sizeof(shadow.ExtendedRegisters));
 data.teb=&teb;data.ps5_sync_bop_context=NULL;area.cpu.Flags=0;area.cpu.Machine=IMAGE_FILE_MACHINE_I386;peb.BeingDebugged=0;
 missing_data=missing_frame=mask_error=masked=0;blocks=unblocks=copy_interrupts=interrupt_after_commit=0;
 *view=(struct pw_sync_bop_context_view){PW_BOP_CONTEXT_VERSION,sizeof(*view),0,0,(uintptr_t)&CANONICAL,(uintptr_t)&shadow};
}
static void negative(struct pw_sync_bop_context_view *view,uint32_t size)
{
 I386_CONTEXT prior=CANONICAL;XSAVE_FORMAT priorfp=frame.xsave;
 assert(!ps5_sync_bop_context_publish(view,size));assert(!data.ps5_sync_bop_context);
 assert(!memcmp(&prior,&CANONICAL,sizeof(prior)) && !memcmp(&priorfp,&frame.xsave,sizeof(priorfp)) && !blocks);
}
int main(void)
{
 struct pw_sync_bop_context_view view;I386_CONTEXT prior;XSAVE_FORMAT original;
 const struct pw_sync_bop_context_backend *api=__wine_ps5_sync_bop_context_backend(PW_BOP_CONTEXT_VERSION);
 assert(api && api->context_size==sizeof(I386_CONTEXT) && api->pointer_size==sizeof(void *));
 assert(!__wine_ps5_sync_bop_context_backend(0));
 for(unsigned disposition=0;disposition<=2;disposition++)
 {
  reset(&view);prior=CANONICAL;original=frame.xsave;
  assert(api->publish(&view,sizeof(shadow)) && get_cpu_area(&data,IMAGE_FILE_MACHINE_I386)==&shadow);
  assert(ps5_sync_bop_fp_area(&data,&frame)==(XSAVE_FORMAT *)shadow.ExtendedRegisters);
  assert(!memcmp(shadow.FloatSave.bytes,shadow.ExtendedRegisters,sizeof(shadow.FloatSave.bytes)));
  assert(!api->publish(&view,sizeof(shadow)));
  assert(api->finish(&view,disposition)==PW_BOP_CONTEXT_UNCHANGED);
  if(disposition==PW_BOP_CONTEXT_MISS)assert(!memcmp(&prior,&CANONICAL,sizeof(prior)));
  else assert(CANONICAL.Eip==shadow.Eip && CANONICAL.Esp==shadow.Esp && CANONICAL.Eax==(disposition==PW_BOP_CONTEXT_HIT?0:101));
  assert(!data.ps5_sync_bop_context && !memcmp(&original,&frame.xsave,sizeof(original)) && !blocks);
  assert(ps5_sync_bop_fp_area(&data,&frame)==&frame.xsave);
 }
 /* Deterministic valid observer edits at active, partial copy and committed phases. */
 for(unsigned disposition=0;disposition<=2;disposition++)
 {
  reset(&view);assert(api->publish(&view,sizeof(shadow)));observer();
  assert(api->finish(&view,disposition)==PW_BOP_CONTEXT_REPLACED);
  assert(CANONICAL.Eax==0x7788 && CANONICAL.Eip==0x13005 && CANONICAL.ExtendedRegisters[0]==0x7f);
 }
 for(unsigned edits=1;edits<=9;edits++)
 {
  reset(&view);assert(api->publish(&view,sizeof(shadow)));copy_interrupts=edits;
  assert(api->finish(&view,PW_BOP_CONTEXT_HIT)==PW_BOP_CONTEXT_REPLACED);
  assert(CANONICAL.Eax==0x7788 && CANONICAL.Eip==0x13000+5*(edits>8?8:edits));
  assert(!data.ps5_sync_bop_context && !masked && blocks==(edits>=8) && unblocks==(edits>=8));
 }
 reset(&view);assert(api->publish(&view,sizeof(shadow)));interrupt_after_commit=1;
 assert(api->finish(&view,PW_BOP_CONTEXT_HIT)==PW_BOP_CONTEXT_REPLACED && CANONICAL.Eax==0x7788);
 reset(&view);assert(api->publish(&view,sizeof(shadow)));memset(shadow.FloatSave.bytes,0x44,sizeof(shadow.FloatSave.bytes));
 ps5_sync_bop_context_edit(&data);ps5_sync_bop_context_resumed(&data,SERVER_CTX_FLOATING_POINT);
 assert(shadow.ExtendedRegisters[0]==0x44 && shadow.ExtendedRegisters[128]==0x22);
 assert(api->finish(&view,PW_BOP_CONTEXT_MISS)==PW_BOP_CONTEXT_REPLACED);
 reset(&view);assert(api->publish(&view,sizeof(shadow)));memset(shadow.ExtendedRegisters,0x55,sizeof(shadow.ExtendedRegisters));
 ps5_sync_bop_context_edit(&data);ps5_sync_bop_context_resumed(&data,SERVER_CTX_FLOATING_POINT|SERVER_CTX_EXTENDED_REGISTERS);
 assert(shadow.ExtendedRegisters[0]==0x55);assert(api->finish(&view,PW_BOP_CONTEXT_FAULT)==PW_BOP_CONTEXT_REPLACED);
 /* Mock mask refusal is bounded; storage stays alive for explicit recovery, no CAS retry. */
 reset(&view);assert(api->publish(&view,sizeof(shadow)));copy_interrupts=9;mask_error=1;
 assert(api->finish(&view,PW_BOP_CONTEXT_HIT)==PW_BOP_CONTEXT_INVALID && data.ps5_sync_bop_context==&view && blocks==1);
 mask_error=0;copy_interrupts=0;assert(api->finish(&view,PW_BOP_CONTEXT_HIT)==PW_BOP_CONTEXT_REPLACED);
 reset(&view);negative(NULL,sizeof(shadow));view.version++;negative(&view,sizeof(shadow));
 reset(&view);view.size--;negative(&view,sizeof(shadow));reset(&view);negative(&view,sizeof(shadow)-1);
 reset(&view);missing_data=1;negative(&view,sizeof(shadow));reset(&view);missing_frame=1;negative(&view,sizeof(shadow));
 reset(&view);data.teb=NULL;negative(&view,sizeof(shadow));reset(&view);frame.restore_flags=0;negative(&view,sizeof(shadow));
 reset(&view);frame.prev_frame=&frame;negative(&view,sizeof(shadow));reset(&view);view.shadow=view.canonical;negative(&view,sizeof(shadow));
 reset(&view);view.canonical++;negative(&view,sizeof(shadow));reset(&view);view.shadow++;negative(&view,sizeof(shadow));
 reset(&view);area.cpu.Flags=WOW64_CPURESERVED_FLAG_RESET_STATE;negative(&view,sizeof(shadow));
 reset(&view);peb.BeingDebugged=1;negative(&view,sizeof(shadow));reset(&view);shadow.Dr7=1;negative(&view,sizeof(shadow));
 reset(&view);shadow.EFlags|=0x100;negative(&view,sizeof(shadow));reset(&view);shadow.EFlags|=0x10000;negative(&view,sizeof(shadow));
 reset(&view);shadow.ContextFlags|=CONTEXT_I386_XSTATE;negative(&view,sizeof(shadow));
 reset(&view);assert(api->finish(&view,0)==PW_BOP_CONTEXT_INVALID);
 assert(api->publish(&view,sizeof(shadow)));assert(api->finish(&view,3)==PW_BOP_CONTEXT_INVALID && data.ps5_sync_bop_context==&view);
 assert(api->finish(&view,0)==PW_BOP_CONTEXT_UNCHANGED);
 puts("BOP native context publication/observer/commit/FP/fallback contracts PASS; ordinary failures mocked");return 0;
}
'''


def main():
    signal=side('dlls/ntdll/unix/signal_x86_64.c')
    thread=side('dlls/ntdll/unix/thread.c')
    funcs=[('void *','ps5_sync_bop_cpu_area'),('void ','ps5_sync_bop_context_edit'),
           ('void ','ps5_sync_bop_context_resumed'),('static XSAVE_FORMAT *','ps5_sync_bop_fp_area'),
           ('static int ','ps5_sync_bop_context_publish'),('static uint32_t ','ps5_sync_bop_context_finish'),
           ('DECLSPEC_EXPORT const struct pw_sync_bop_context_backend *','__wine_ps5_sync_bop_context_backend')]
    actual=''.join(body(signal,prefix+name+'(') for prefix,name in funcs)
    assert 'fp = ps5_sync_bop_fp_area( data, frame );' in signal
    assert signal.count('fp = ps5_sync_bop_fp_area( data, frame );')==2
    assert 'memcpy( fp, context->ExtendedRegisters, sizeof(*fp) );' in signal
    assert 'memcpy( context->ExtendedRegisters, fp, sizeof(context->ExtendedRegisters) );' in signal
    assert 'ps5_sync_bop_context_edit( get_thread_data() );' in thread
    assert 'ps5_sync_bop_context_resumed( get_thread_data(), server_contexts[1].flags );' in thread
    with tempfile.TemporaryDirectory(prefix='pw-sync-bop-context-') as name:
        folder=Path(name);(folder/'wine').mkdir()
        (folder/'wine/ps5_sync_bop_context.h').write_text(side('include/wine/ps5_sync_bop_context.h'))
        (folder/'context.inc').write_text(actual)
        (folder/'cpu_area.inc').write_text(body(thread,'void *get_cpu_area('))
        (folder/'test.c').write_text(HARNESS)
        cc=shlex.split(os.environ.get('CC','cc'))
        flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
        subprocess.run([*cc,*flags,'-std=c11','-I',str(folder),str(folder/'test.c'),'-o',str(folder/'test')],check=True,timeout=60)
        subprocess.run([str(folder/'test')],check=True,timeout=30)


if __name__=='__main__':
    main()
