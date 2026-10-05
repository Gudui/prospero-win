#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Execute actual 0800 bodies against bounded native mocks, without Wine.

The envelope and OS calls are mocks; full SDK/PE and owner console gates are
separate requirements. Concurrent checks touch only the atomic reservation.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'wine/patches/0800-user32-window-style-from-session-shared-memory.patch'


def side(file, additions=False):
    part = next(p for p in PATCH.read_text().split('diff --git ')[1:]
                if p.splitlines()[0].endswith(' b/' + file))
    return '\n'.join(line[1:] for line in part.splitlines()
                     if line.startswith('+' if additions else ('+', ' '))
                     and not line.startswith('+++')) + '\n'


def body(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    for end in range(brace + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1] + '\n'
    raise AssertionError('unterminated actual function')


HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
typedef int BOOL;
typedef int32_t LONG;
typedef int64_t LONG64;
typedef uint32_t UINT, DWORD;
typedef uint64_t UINT64, lparam_t, mod_handle_t, client_ptr_t;
typedef unsigned data_size_t;
typedef size_t SIZE_T;
typedef void *HWND, *HANDLE;
typedef wchar_t WCHAR;
typedef int NTSTATUS;
typedef struct { const WCHAR *name; } UNICODE_STRING;
typedef struct { int unused; } OBJECT_ATTRIBUTES;
typedef union { struct { uint32_t low; int32_t high; } parts; int64_t QuadPart; } LARGE_INTEGER;
#define TRUE 1
#define FALSE 0
#define LOWORD(n) ((uint16_t)(uintptr_t)(n))
#define HIWORD(n) ((uint16_t)((uintptr_t)(n)>>16))
#define MAKELONG(l,h) ((LONG)((uint16_t)(l)|((uint32_t)(uint16_t)(h)<<16)))
#define FIRST_USER_HANDLE 0x20
#define MAX_USER_HANDLES 8 /* bounded mock envelope, not a real ABI assertion */
#define NTUSER_OBJ_WINDOW 1
#define RTL_CONSTANT_STRING(n) {n}
#define InitializeObjectAttributes(a,b,c,d,e) ((void)(a),(void)(b),(void)(c),(void)(d),(void)(e))
#define SECTION_MAP_READ 4
#define ViewUnmap 2
#define PAGE_READONLY 2
#define GetCurrentProcess() ((HANDLE)(uintptr_t)1)
#define GetProcessHeap() ((HANDLE)(uintptr_t)2)
#define GetCurrentProcessId() 42u
#define ReadAcquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define ReadPointerAcquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
static LONG InterlockedCompareExchange(LONG *p,LONG n,LONG old)
{ __atomic_compare_exchange_n(p,&old,n,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);return old; }
static void *InterlockedCompareExchangePointer(void **p,void *n,void *old)
{ __atomic_compare_exchange_n(p,&old,n,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);return old; }
struct obj_locator { uint64_t id,offset; };
struct ratio { unsigned num,den; };
#include "window_layout.inc"
struct user_entry { uint64_t offset; uint32_t tid,pid; uint64_t id; LONG64 uniq; };
typedef volatile struct { struct user_entry user_entries[MAX_USER_HANDLES]; } session_shm_t;
typedef volatile struct { LONG64 seq; uint64_t id; union {window_shm_t window;} shm; } shared_object_t;
static union { max_align_t alignment; char bytes[4096]; } memory;
static SIZE_T map_size;
static unsigned opens,maps,closes,unmaps,allocs,frees;
static int open_error,map_error,alloc_error;
static void *descriptors[32];
static NTSTATUS NtOpenSection(HANDLE *h,unsigned rights,OBJECT_ATTRIBUTES *attr)
{ (void)attr;assert(rights==SECTION_MAP_READ);opens++;*h=(HANDLE)(uintptr_t)3;return open_error; }
static NTSTATUS NtMapViewOfSection(HANDLE h,HANDLE process,void **base,SIZE_T zero,SIZE_T commit,
                                  LARGE_INTEGER *offset,SIZE_T *size,unsigned type,unsigned flags,unsigned protect)
{ assert(h==(HANDLE)(uintptr_t)3 && process==GetCurrentProcess() && !zero && !commit &&
         !offset->QuadPart && type==ViewUnmap && !flags && protect==PAGE_READONLY);
  maps++;*base=memory.bytes;*size=map_size;return map_error; }
static void NtClose(HANDLE h) {assert(h==(HANDLE)(uintptr_t)3);closes++;}
static void NtUnmapViewOfSection(HANDLE h,void *base)
{assert(h==GetCurrentProcess() && base==memory.bytes);unmaps++;}
static void *HeapAlloc(HANDLE h,unsigned flags,SIZE_T size)
{assert(h==GetProcessHeap() && !flags);if(alloc_error)return NULL;
 void *p=malloc(size);assert(p && allocs<32);descriptors[allocs++]=p;return p;}
static void HeapFree(HANDLE h,unsigned flags,void *p)
{assert(h==GetProcessHeap() && !flags);for(unsigned i=0;i<allocs;i++)if(descriptors[i]==p)descriptors[i]=NULL;
 frees++;free(p);}
static unsigned fences, mutate_fence;
static struct user_entry *mutate_entry;
static shared_object_t *mutate_object;
static void fixture_fence(void)
{ __asm__ __volatile__("" ::: "memory");fences++;
 if(fences==mutate_fence){if(mutate_entry)mutate_entry->uniq++;
                        if(mutate_object)mutate_object->seq+=2;} }
#include "reader.inc"
struct window { unsigned style;window_shm_t *shared; };
#define SHARED_WRITE_BEGIN(p,t) { t *shared=(p); assert(!(authority_seq&1));authority_seq++;
#define SHARED_WRITE_END authority_seq++; }
static unsigned authority_seq;
#include "authority.inc"
static int config_dir_fd=7, io_mode;
static unsigned io_opens,io_reads,io_closes;
static const char *selection;
static const char *mock_getenv(const char *key)
{assert(!strcmp(key,"WINE_PS5_WINDOW_STYLE_SHARED"));return selection;}
static int mock_openat(int fd,const char *path,int flags)
{assert(fd==7 && !strcmp(path,"pw_window_style_shared") && flags==O_RDONLY);
 io_opens++;return io_mode==1?-1:8;}
static ssize_t mock_read(int fd,void *buffer,size_t size)
{assert(fd==8);io_reads++;if(io_mode==2)return -1;
 const char *value=io_mode==3?"1":io_mode==4?"1\n":io_mode==5?"1\nX":io_mode==6?"0":"";
 static unsigned position;
 if(position>=strlen(value))return 0;
 /* Deliberately return partial reads, with ordinary valid byte streams. */
 assert(size);*(char *)buffer=value[position++];return 1;}
static int mock_close(int fd){assert(fd==8);io_closes++;return 0;}
#define getenv mock_getenv
#define openat mock_openat
#define read mock_read
#define close mock_close
#include "selector.inc"
#undef getenv
#undef openat
#undef read
#undef close
static void cleanup(void)
{for(unsigned i=0;i<allocs;i++)free(descriptors[i]);memset(descriptors,0,sizeof(descriptors));allocs=0;}
static void reset(void)
{cleanup();memset(&memory,0,sizeof(memory));session_view=NULL;session_view_maps=0;
 opens=maps=closes=unmaps=frees=0;open_error=map_error=alloc_error=0;
 map_size=sizeof(memory.bytes);fences=mutate_fence=0;mutate_entry=NULL;mutate_object=NULL;}
static struct user_entry *prepare(HWND *hwnd,shared_object_t **object)
{reset();struct user_entry *entry=(struct user_entry *)&((session_shm_t *)memory.bytes)->user_entries[1];
 entry->offset=512;entry->id=71;entry->pid=42;entry->uniq=MAKELONG(NTUSER_OBJ_WINDOW,3);
 *object=(shared_object_t *)(memory.bytes+entry->offset);(*object)->id=entry->id;
 (*object)->shm.window.style_valid=WINDOW_STYLE_SHARED_TAG;(*object)->shm.window.style=0;
 *hwnd=(HWND)(uintptr_t)MAKELONG(FIRST_USER_HANDLE+2,3);return entry;}
static void miss(HWND hwnd)
{DWORD out=0x12345678;assert(!get_shared_window_style(hwnd,&out) && out==0x12345678);}
static void *reserve_thread(void *unused)
{(void)unused;return (void *)(uintptr_t)reserve_session_view();}
int main(int argc,char **argv)
{
 if(argc==5 && !strcmp(argv[1],"selector")){
   selection=strcmp(argv[2],"absent")?argv[2]:NULL;io_mode=atoi(argv[3]);if(io_mode==7)config_dir_fd=-1;errno=E2BIG;
   assert(ps5_window_style_shared_enabled()==atoi(argv[4]));assert(errno==E2BIG);
   unsigned prior_opens=io_opens,prior_reads=io_reads;
   unsigned expected_closes=io_opens && io_mode!=1;
   selection="0";io_mode=2;assert(ps5_window_style_shared_enabled()==atoi(argv[4]));
   assert(prior_opens==io_opens && prior_reads==io_reads && io_closes==expected_closes);
   puts("window-style selector PASS");return 0;
 }
 HWND hwnd;shared_object_t *object;struct user_entry *entry=prepare(&hwnd,&object);DWORD value;
 const DWORD styles[]={0,0xffffffffu,0x10000000u,0x20000000u,0x01000000u,0x12345678u};
 struct window win={0,&object->shm.window};
 for(unsigned i=0;i<sizeof(styles)/sizeof(styles[0]);i++){
   set_window_style(&win,styles[i]);assert(win.style==styles[i] && !(authority_seq&1));
   assert(get_shared_window_style(hwnd,&value) && value==styles[i]);}
 assert(opens==1 && maps==1 && closes==1 && session_view_maps==1);
 assert(get_shared_window_style((HWND)(uintptr_t)LOWORD(hwnd),&value));
 assert(get_shared_window_style((HWND)(uintptr_t)(0xffff0000u|LOWORD(hwnd)),&value));
 miss((HWND)(uintptr_t)MAKELONG(LOWORD(hwnd),4));miss(NULL);
 entry->pid=43;miss(hwnd);entry->pid=42;
 object->shm.window.style_valid=0;miss(hwnd);object->shm.window.style_valid=WINDOW_STYLE_SHARED_TAG^1;miss(hwnd);
 object->shm.window.style_valid=WINDOW_STYLE_SHARED_TAG;
 object->id++;miss(hwnd);object->id--;entry->uniq=0;miss(hwnd);entry->uniq=MAKELONG(NTUSER_OBJ_WINDOW,3);
 object->seq=1;miss(hwnd);object->seq=2;
 fences=0;mutate_fence=2;mutate_entry=entry;miss(hwnd);
 entry->uniq=MAKELONG(NTUSER_OBJ_WINDOW,3);mutate_entry=NULL;
 fences=0;mutate_fence=4;mutate_object=object;
 assert(get_shared_window_style(hwnd,&value));assert(object->seq==4);mutate_object=NULL;
 /* Growth with a valid generated object; old descriptor stays valid. */
 prepare(&hwnd,&object);map_size=sizeof(session_shm_t);assert(get_session_view(map_size));
 const struct session_view *old=session_view;map_size=sizeof(memory.bytes);
 assert(get_shared_window_style(hwnd,&value) && session_view!=old && old->size==sizeof(session_shm_t) && !unmaps);
 /* Test budget positions by setting counters, never by exhausting OS resources. */
 reset();session_view_maps=MAX_SESSION_VIEWS-1;assert(get_session_view(sizeof(session_shm_t)));
 assert(session_view_maps==MAX_SESSION_VIEWS && get_session_view(sizeof(session_shm_t)) && maps==1);
 assert(!get_session_view(sizeof(memory.bytes)+1) && maps==1);
 reset();session_view_maps=MAX_SESSION_VIEWS;assert(!get_session_view(sizeof(session_shm_t)) && !opens);
 reset();open_error=1;assert(!get_session_view(sizeof(session_shm_t)) && opens==1 && !maps && !closes);
 reset();map_error=1;assert(!get_session_view(sizeof(session_shm_t)) && maps==1 && closes==1 && !unmaps);
 reset();alloc_error=1;assert(!get_session_view(sizeof(session_shm_t)) && unmaps==1 && closes==1);
 reset();map_size=sizeof(session_shm_t)-1;assert(!get_session_view(sizeof(session_shm_t)) && unmaps==1);
 reset();pthread_t threads[16];unsigned granted=0;
 for(unsigned i=0;i<16;i++)assert(!pthread_create(&threads[i],NULL,reserve_thread,NULL));
 for(unsigned i=0;i<16;i++){void *result;assert(!pthread_join(threads[i],&result));granted+=(unsigned)(uintptr_t)result;}
 assert(granted==MAX_SESSION_VIEWS && session_view_maps==MAX_SESSION_VIEWS && !reserve_session_view());
 cleanup();puts("window-style reader, authority, growth, I/O and concurrent reservation PASS");return 0;
}
'''


def main():
    reader = side('dlls/user32/win.c', True)
    start = reader.index('/* x86 keeps loads in order:')
    reader = reader[start:reader.index('\n#else', start)]
    reader = reader.replace('#define SHARED_READ_FENCE() __asm__ __volatile__( "" ::: "memory" )',
                            '#define SHARED_READ_FENCE() fixture_fence()')
    header = side('include/wine/server_protocol.h')
    window = re.search(r'typedef volatile struct\s*\{[^}]+\} window_shm_t;', header).group()
    info = re.search(r'struct window_info\s*\{[^}]+\};', header).group()
    tag = re.search(r'^#define WINDOW_STYLE_SHARED_TAG .+$', header, re.M).group()
    version = re.search(r'^#define SERVER_PROTOCOL_VERSION \d+$', header, re.M).group()
    server = side('server/window.c')
    protocol = side('server/protocol.def')
    assert tag in protocol and 'style_valid' in protocol
    assert 'shared->style_valid = ps5_window_style_shared_enabled() ? WINDOW_STYLE_SHARED_TAG : 0;' in server
    assert 'shared->style = win->style = req->new_info;' in server
    assert side('dlls/user32/win.c', True).count('if (get_shared_window_style( hwnd, &style )) return style;') == 2
    with tempfile.TemporaryDirectory(prefix='pw-window-style-') as temp:
        folder = Path(temp)
        (folder/'window_layout.inc').write_text(version+'\n'+tag+'\n'+info+'\n'+window+'\n')
        (folder/'reader.inc').write_text(reader)
        (folder/'authority.inc').write_text(body(server, 'static void set_window_style('))
        (folder/'selector.inc').write_text(body(server, 'static int ps5_window_style_shared_enabled('))
        (folder/'test.c').write_text(HARNESS)
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        flags = shlex.split(os.environ.get('CFLAGS', '-O2 -g -Wall -Wextra -Werror'))
        subprocess.run([*compiler,*flags,'-std=gnu11','-pthread','-I',str(folder),str(folder/'test.c'),
                        '-o',str(folder/'test')], check=True, timeout=60)
        subprocess.run([str(folder/'test')], check=True, timeout=30)
        for env, mode, expected in [('absent',0,0),('absent',1,0),('absent',2,0),
                                    ('absent',7,0),('absent',3,1),('absent',4,1),('absent',5,0),('absent',6,0),
                                    ('1',1,1),('0',3,0),('',4,0),('01',3,0),('1\n',3,0)]:
            subprocess.run([str(folder/'test'),'selector',env,str(mode),str(expected)],
                           check=True, timeout=10, stdout=subprocess.DEVNULL)
        print('window-style 13 strict selection cases PASS')


if __name__ == '__main__':
    main()
