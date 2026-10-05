#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Replay actual provider patches; native checkpoint with explicit OS mocks."""
from pathlib import Path
import importlib.util,os,shlex,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pending',ROOT/'tests/test_wine_sync_bop_pending.py')
pending=importlib.util.module_from_spec(spec);spec.loader.exec_module(pending)
PATCH=ROOT/'wine/patches/0894-ntdll-ps5-sync-bop-native-checkpoint.patch'
EXTRA=r'''
 /* A checkpoint commits a complete native snapshot without a VM lease. */
 reset();attach();data.ps5_sync_bop_memory=NULL;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_UNCHANGED);
 assert(CANONICAL.Eip==fallback.Eip && CANONICAL.Eax==fallback.Eax && CANONICAL.ExtendedRegisters[160]==0x22 && !masked && blocks==1 && restores==1);
 reset();attach();data.ps5_sync_bop_memory=NULL;CANONICAL.Eip=incoming.Eip;
 ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_CONTROL|CONTEXT_I386_FLOATING_POINT);area.cpu.Flags=0x8001;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED);
 assert(CANONICAL.Eip==incoming.Eip && CANONICAL.Eax==fallback.Eax && CANONICAL.ExtendedRegisters[0]==0x66 && CANONICAL.ExtendedRegisters[160]==0x22 && area.cpu.Flags==0x8000 && !masked);
 /* A refused block leaves the complete native image and pending edit intact. */
 reset();attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);mask_error=1;
 I386_CONTEXT untouched=CANONICAL;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_INVALID && !view.guard && view.fields==8 && !memcmp(&untouched,&CANONICAL,sizeof(untouched)));
 /* A refused restore retains the saved mask; retries restore only. */
 reset();attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_FLOATING_POINT);restore_refusals=2;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_INVALID && view.guard && masked && !view.fields);
 I386_CONTEXT committed=CANONICAL;I386_CONTEXT different;memset(&different,0xbb,sizeof(different));
 assert(!api->detach(&view));
 assert(api->checkpoint(&view,&different,sizeof(different))==PW_BOP_PENDING_INVALID && view.guard && !memcmp(&committed,&CANONICAL,sizeof(committed)));
 assert(api->checkpoint(&view,&different,sizeof(different))==PW_BOP_PENDING_REPLACED && !view.guard && !masked && !memcmp(&committed,&CANONICAL,sizeof(committed)) && blocks==1 && restores==3);
 /* Queued edits delivered on restore remain pending for the next checkpoint. */
 reset();attach();queued_edit=1;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_UNCHANGED && view.fields==2 && CANONICAL.Eax==incoming.Eax);
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_REPLACED && !view.fields && CANONICAL.Eax==incoming.Eax);
 reset();attach();data.ps5_sync_bop_context=&frame;untouched=CANONICAL;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_INVALID && !blocks && !memcmp(&untouched,&CANONICAL,sizeof(untouched)));
 reset();attach();ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_XSTATE);untouched=CANONICAL;
 assert(api->checkpoint(&view,&fallback,sizeof(fallback))==PW_BOP_PENDING_INVALID && view.fields==64 && !masked && !memcmp(&untouched,&CANONICAL,sizeof(untouched)));
'''
def main():
 with tempfile.TemporaryDirectory(prefix='pw-sync-bop-checkpoint-') as name:
  p=Path(name);s=p/'source';(s/'dlls/ntdll/unix').mkdir(parents=True);(s/'include/wine').mkdir(parents=True)
  (s/'dlls/ntdll/unix/signal_x86_64.c').write_text(pending.side('dlls/ntdll/unix/signal_x86_64.c'))
  (s/'include/wine/ps5_sync_bop_pending.h').write_text(pending.side('include/wine/ps5_sync_bop_pending.h'))
  subprocess.run(['patch','-s','--fuzz=0','-p1','-d',str(s),'-i',str(PATCH)],check=True,timeout=30)
  signal=(s/'dlls/ntdll/unix/signal_x86_64.c').read_text()
  names=['static int ps5_sync_bop_pending_held(', 'static int ps5_sync_bop_pending_attach(', 'void ps5_sync_bop_pending_edit(', 'static uint32_t ps5_sync_bop_pending_merge(', 'static uint32_t ps5_sync_bop_pending_take(', 'static uint32_t ps5_sync_bop_pending_checkpoint(', 'static int ps5_sync_bop_pending_detach(', 'DECLSPEC_EXPORT const struct pw_sync_bop_pending_backend *__wine_ps5_sync_bop_pending_backend(']
  (p/'pending.inc').write_text(''.join(pending.body(signal,n) for n in names));(p/'wine').mkdir()
  (p/'wine/ps5_sync_bop_pending.h').write_bytes((s/'include/wine/ps5_sync_bop_pending.h').read_bytes())
  (p/'wine/ps5_sync_bop_memory.h').write_text(pending.side('include/wine/ps5_sync_bop_memory.h',ROOT/'wine/patches/0892-ntdll-ps5-sync-bop-memory-lease.patch'))
  h=pending.HARNESS.replace('==656,"stable pending view"','==696,"stable pending view"').replace('view.version=1;','view.version=PW_BOP_PENDING_VERSION;').replace('__wine_ps5_sync_bop_pending_backend(1)','__wine_ps5_sync_bop_pending_backend(PW_BOP_PENDING_VERSION)')
  marker='void ps5_sync_bop_pending_edit(struct thread_data *,const I386_CONTEXT *,unsigned);'
  h=h.replace(marker,marker+r'''
typedef uint64_t sigset_t;
#define SIG_BLOCK 1
#define SIG_SETMASK 2
static sigset_t server_block_set=7;
static unsigned masked,mask_error,restore_refusals,blocks,restores,queued_edit;
static int pthread_sigmask(int how,const sigset_t *set,sigset_t *old)
{
 if(how==SIG_BLOCK){assert(set==&server_block_set && old);blocks++;if(mask_error)return 1;*old=masked;masked=1;return 0;}
 assert(how==SIG_SETMASK && set && !old);restores++;
 if(restore_refusals){restore_refusals--;return 1;}masked=*set;
 if(queued_edit){queued_edit=0;CANONICAL.Eax=incoming.Eax;ps5_sync_bop_pending_edit(&data,&incoming,CONTEXT_I386_INTEGER);}
 return 0;
}
''')
  h=h.replace('missing_data=missing_frame=conversions=nested_record=0;','missing_data=missing_frame=conversions=nested_record=0;masked=mask_error=restore_refusals=blocks=restores=queued_edit=0;')
  h=h.replace(' puts("PASS actual pending guest edits:',EXTRA+' puts("PASS actual checkpoint and pending guest edits:')
  (p/'test.c').write_text(h)
  cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
  subprocess.run([*cc,*flags,'-std=c11','-I',str(p),str(p/'test.c'),'-o',str(p/'test')],check=True,timeout=60)
  subprocess.run([str(p/'test')],check=True,timeout=30)
if __name__=='__main__':main()
