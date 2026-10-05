#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile actual bounded VM lease bodies with explicit OS/page/context mocks."""
from pathlib import Path
import os,shlex,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
PATCH=ROOT/'wine/patches/0892-ntdll-ps5-sync-bop-memory-lease.patch'
def side(name):
 part=next(x for x in PATCH.read_text().split('diff --git ')[1:] if x.splitlines()[0].endswith(' b/'+name))
 return '\n'.join(x[1:] for x in part.splitlines() if x.startswith(('+',' ')) and not x.startswith('+++'))+'\n'
def body(s,signature):
 start=s.index(signature);brace=s.index('{',start);depth=1
 for end in range(brace+1,len(s)):
  depth+=(s[end]=='{')-(s[end]=='}')
  if not depth:return s[start:end+1]+'\n'
 raise AssertionError('unterminated function')
HARNESS=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "wine/ps5_sync_bop_memory.h"
#include "wine/wowprospero/sync_bop_adapter.h"
#define DECLSPEC_EXPORT
#define STATUS_ACCESS_VIOLATION 0xc0000005u
#define STATUS_SUCCESS 0u
#define VPROT_READ 1u
#define VPROT_WRITE 2u
#define VPROT_WRITECOPY 8u
#define VPROT_GUARD 16u
#define VPROT_COMMITTED 32u
#define VPROT_WRITEWATCH 64u
#define VPROT_SYSTEM 0x200u
#define PROT_READ 1u
#define PROT_WRITE 2u
#define SIG_BLOCK 1
#define SIG_SETMASK 2
#define BASE 0x20000u
#define min(a,b) ((a)<(b)?(a):(b))
typedef uintptr_t UINT_PTR;
typedef size_t SIZE_T;
typedef uint8_t BYTE;
typedef uint32_t sigset_t;
struct thread_data { void *ps5_sync_bop_memory; };
struct file_view { unsigned protect; };
static struct thread_data data;
static struct file_view mapping;
static _Alignas(4096) uint8_t memory[8192];
static unsigned prot[2],pages_checked,blocks,unblocks,locks,unlocks;
static unsigned missing,missing_mapping,busy,block_error,restore_error,unlock_error,locked;
static unsigned observer_on_release,published,observations,backend_calls,finishes,object;
static sigset_t active_mask,server_block_set=0x44;
static const SIZE_T host_page_size=4096,host_page_mask=4095;
static int virtual_mutex;
static struct pw_wow_sync_registers canonical;
static struct thread_data *get_thread_data(void){return missing?NULL:&data;}
static void *to_pointer(uint32_t address)
{
 if(address>=BASE && address-BASE<=sizeof(memory))return memory+(address-BASE);
 return (void *)(uintptr_t)address;
}
#define ULongToPtr(x) to_pointer(x)
static struct file_view *find_view(const void *ptr,SIZE_T bytes)
{
 assert(locked);uintptr_t p=(uintptr_t)ptr,lo=(uintptr_t)memory;
 if(missing_mapping || p<lo || p-lo>sizeof(memory) || bytes>sizeof(memory)-(p-lo))return NULL;
 return &mapping;
}
static BYTE get_host_page_vprot(const void *ptr)
{
 uintptr_t p=(uintptr_t)ptr,lo=(uintptr_t)memory;
 assert(locked && p>=lo && p-lo<sizeof(memory));pages_checked++;
 return prot[(p-lo)/4096];
}
/* Explicit mock conversion; the actual Wine page/OS ABI is covered by SDK builds. */
static int get_unix_prot(BYTE p)
{
 if(!(p&VPROT_COMMITTED) || (p&VPROT_GUARD))return 0;
 return ((p&VPROT_READ)?PROT_READ:0)|((p&(VPROT_WRITE|VPROT_WRITECOPY))?PROT_WRITE:0);
}
static int pthread_sigmask(int how,const sigset_t *in,sigset_t *old)
{
 if(how==SIG_BLOCK){blocks++;if(block_error)return 1;if(old)*old=active_mask;active_mask|=*in;return 0;}
 assert(how==SIG_SETMASK);unblocks++;if(restore_error)return 1;
 assert(!locked);active_mask=*in;
 if(observer_on_release){assert(published);observations++;canonical.gpr[0]=0x99;canonical.pc=0x44000;}
 return 0;
}
static int pthread_mutex_trylock(int *mutex)
{
 assert(mutex==&virtual_mutex && (active_mask&server_block_set)==server_block_set);locks++;
 if(busy)return 1;
 assert(!locked);locked=1;return 0;
}
static int pthread_mutex_unlock(int *mutex)
{
 assert(mutex==&virtual_mutex && locked);unlocks++;if(unlock_error)return 1;locked=0;return 0;
}
#include "memory.inc"
static const struct pw_sync_bop_memory_backend *api;
static struct pw_sync_bop_memory_view lease;
static void reset(void)
{
 assert(!locked && !data.ps5_sync_bop_memory);
 memset(&lease,0,sizeof(lease));lease.version=PW_BOP_MEMORY_VERSION;lease.size=sizeof(lease);
 memset(memory,0x65,sizeof(memory));memset(&canonical,0,sizeof(canonical));
 prot[0]=prot[1]=VPROT_COMMITTED|VPROT_READ|VPROT_WRITE;
 mapping.protect=pages_checked=blocks=unblocks=locks=unlocks=0;
 missing=missing_mapping=busy=block_error=restore_error=unlock_error=0;
 observer_on_release=published=observations=backend_calls=finishes=0;object=7;active_mask=0x12;
}
static int read_guest(void *unused,uint32_t p,void *out,size_t n){(void)unused;return api->read(&lease,p,out,(uint32_t)n);}
static int probe_guest(void *unused,uint32_t p,size_t n){(void)unused;return api->writable(&lease,p,(uint32_t)n);}
static uint32_t write_guest(void *unused,uint32_t p,const void *in,size_t n){(void)unused;assert(published && backend_calls==1);return api->write(&lease,p,in,(uint32_t)n);}
static int publish(void *unused,const struct pw_wow_sync_registers *r){(void)unused;assert(locked && !published);canonical=*r;published=1;return 1;}
static int finish(void *unused,enum pw_wow_sync_result result,struct pw_wow_sync_registers *r)
{
 (void)unused;assert(published && backend_calls==1);finishes++;canonical=*r;
 assert(result==PW_WOW_SYNC_HIT);assert(api->end(&lease));
 if(observations)*r=canonical;
 published=0;return observations!=0;
}
static int cached(void *unused,uint32_t op,uint32_t handle,uint32_t count,uint32_t *previous)
{
 (void)unused;assert(locked && published && handle==0x88);backend_calls++;*previous=object;
 if(op==PW_WOW_SYNC_WAIT || op==PW_WOW_SYNC_RELEASE_MUTEX)object--;
 else if(op==PW_WOW_SYNC_SET_EVENT)object=1;
 else if(op==PW_WOW_SYNC_RESET_EVENT)object=0;
 else {assert(op==PW_WOW_SYNC_RELEASE_SEMAPHORE);object+=count;}
 return 1;
}
int main(void)
{
 api=__wine_ps5_sync_bop_memory_backend(1);assert(api && api->view_size==sizeof(lease) && api->pointer_size==sizeof(void *));
 assert(!__wine_ps5_sync_bop_memory_backend(0));reset();
 assert(!api->begin(NULL));missing=1;assert(!api->begin(&lease));missing=0;
 lease.version++;assert(!api->begin(&lease));lease.version=1;lease.size--;assert(!api->begin(&lease));lease.size=sizeof(lease);
 assert(!blocks && !locks);block_error=1;assert(!api->begin(&lease) && !locks && !data.ps5_sync_bop_memory);reset();
 busy=1;assert(api->begin(&lease)==PW_BOP_MEMORY_EMPTY && !locked && !data.ps5_sync_bop_memory && active_mask==0x12 && blocks==1 && unblocks==1);reset();
 busy=restore_error=1;assert(api->begin(&lease)==PW_BOP_MEMORY_RECOVERY && data.ps5_sync_bop_memory==&lease && !locked);
 assert(!api->read(&lease,BASE,memory+128,4));assert(api->begin(&lease)==PW_BOP_MEMORY_EMPTY);
 restore_error=0;assert(api->end(&lease) && active_mask==0x12);reset();
 assert(api->begin(&lease)==PW_BOP_MEMORY_HELD);unlock_error=1;assert(!api->end(&lease) && locked && lease.state==PW_BOP_MEMORY_RECOVERY);
 assert(!api->writable(&lease,BASE,4));unlock_error=0;restore_error=1;assert(!api->end(&lease) && !locked && data.ps5_sync_bop_memory==&lease);
 restore_error=0;assert(api->end(&lease) && active_mask==0x12);reset();
 assert(api->begin(&lease)==PW_BOP_MEMORY_HELD);struct pw_sync_bop_memory_view alien=lease;assert(!api->end(&alien));
 uint32_t out=0xa5a5a5a5,value=0x87654321;
 assert(!api->read(&lease,0,&out,4) && !api->read(&lease,0xffffefff,&out,4) && !api->read(&lease,BASE,&out,33));
 assert(!api->read(&lease,BASE,NULL,4) && !api->read(&lease,BASE,&out,0) && !api->read(&lease,0x10000,&out,4));
 assert(out==0xa5a5a5a5);missing_mapping=1;assert(!api->writable(&lease,BASE,4));missing_mapping=0;
 mapping.protect=VPROT_SYSTEM;assert(!api->read(&lease,BASE,&out,4));mapping.protect=0;
 const unsigned rejected[]={VPROT_GUARD,VPROT_WRITEWATCH};
 for(unsigned i=0;i<2;i++){prot[0]|=rejected[i];assert(!api->read(&lease,BASE,&out,4) && !api->writable(&lease,BASE,4));prot[0]&=~rejected[i];}
 prot[0]|=VPROT_WRITECOPY;assert(!api->writable(&lease,BASE,4));prot[0]&=~VPROT_WRITECOPY;
 prot[0]&=~VPROT_COMMITTED;assert(!api->read(&lease,BASE,&out,4));prot[0]|=VPROT_COMMITTED;
 prot[0]&=~VPROT_WRITE;assert(api->read(&lease,BASE,&out,4) && !api->writable(&lease,BASE,4));prot[0]|=VPROT_WRITE;
 uint8_t before[32],buffer[32];memcpy(before,memory+4094,32);memset(buffer,0xa5,32);prot[1]=0;
 assert(!api->read(&lease,BASE+4094,buffer,32));for(unsigned i=0;i<32;i++)assert(buffer[i]==0xa5);
 assert(!api->writable(&lease,BASE+4094,4) && api->write(&lease,BASE+4094,&value,4)==STATUS_ACCESS_VIOLATION);
 assert(!memcmp(before,memory+4094,32));prot[1]=prot[0];pages_checked=0;
 assert(api->read(&lease,BASE+4094,buffer,32) && pages_checked==2 && !memcmp(buffer,memory+4094,32));
 assert(api->writable(&lease,BASE+4094,4));assert(!api->write(&lease,BASE+4094,&value,4));
 memcpy(&out,memory+4094,4);assert(out==value);assert(api->end(&lease) && active_mask==0x12 && !api->end(&lease));
 struct pw_wow_sync_bindings bindings={1,{4,0x20,0xe,0xdd,0xa},1};
 struct pw_wow_sync_access access={NULL,read_guest,probe_guest,write_guest,publish,finish,cached};
 unsigned transactions=0;
 for(unsigned op=0;op<5;op++)for(unsigned observe=0;observe<2;observe++){
  reset();uint32_t words[5]={0x41000,0x60000,0x88,BASE+128,0};
  if(op==0){words[3]=0;words[4]=BASE+256;}if(op==4){words[3]=3;words[4]=BASE+128;}
  memcpy(memory,words,sizeof(words));struct pw_wow_sync_registers state={{0},0x40000,0x202};state.gpr[0]=bindings.ids[op];state.gpr[4]=BASE;
  observer_on_release=observe;assert(api->begin(&lease)==PW_BOP_MEMORY_HELD);
  assert(pw_wow_sync_try(&bindings,&access,&state,NULL)==(observe?PW_WOW_SYNC_CONTEXT_RESET:PW_WOW_SYNC_HIT));
  assert(state.gpr[0]==(observe?0x99u:0u) && state.pc==(observe?0x44000u:0x41000u) && state.gpr[4]==BASE+4);
  assert(!published && !locked && !data.ps5_sync_bop_memory && backend_calls==1 && finishes==1 && blocks==1 && unblocks==1);
  if(op){memcpy(&out,memory+128,4);assert(out==7);}transactions++;
 }
 printf("PASS native bounded VM lease, all-page/nonmutating preflight, mocked OS recovery, %u actual scalar-adapter transactions with queued observers; no Wine/signals/faults executed\n",transactions);return 0;
}
'''
def main():
 s=side('dlls/ntdll/unix/virtual.c')
 signatures=['static int ps5_sync_bop_memory_end(', 'static uint32_t ps5_sync_bop_memory_begin(', 'static int ps5_sync_bop_memory_span(', 'static int ps5_sync_bop_memory_read(', 'static int ps5_sync_bop_memory_writable(', 'static uint32_t ps5_sync_bop_memory_write(', 'DECLSPEC_EXPORT const struct pw_sync_bop_memory_backend *__wine_ps5_sync_bop_memory_backend(']
 with tempfile.TemporaryDirectory(prefix='pw-sync-bop-memory-') as name:
  p=Path(name);(p/'wine').mkdir();(p/'wine/ps5_sync_bop_memory.h').write_text(side('include/wine/ps5_sync_bop_memory.h'))
  (p/'memory.inc').write_text(''.join(body(s,x) for x in signatures));(p/'test.c').write_text(HARNESS)
  cc=shlex.split(os.environ.get('CC','cc'));flags=shlex.split(os.environ.get('CFLAGS','-O2 -g -Wall -Wextra -Werror'))
  subprocess.run([*cc,*flags,'-std=c11','-I',str(p),'-I',str(ROOT),str(p/'test.c'),'-o',str(p/'test')],check=True,timeout=60)
  subprocess.run([str(p/'test')],check=True,timeout=30)
if __name__=='__main__':main()
