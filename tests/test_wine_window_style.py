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
#include "wine/window_style_shared.h"
typedef int BOOL;
typedef int32_t LONG;
typedef uint32_t UINT, DWORD;
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
#define RTL_CONSTANT_STRING(n) {n}
#define InitializeObjectAttributes(a,b,c,d,e) ((void)(a),(void)(b),(void)(c),(void)(d),(void)(e))
#define SECTION_MAP_READ 4
#define ViewUnmap 2
#define PAGE_READONLY 2
#define GetCurrentProcess() ((HANDLE)(uintptr_t)1)
#define GetCurrentProcessId() 42u
#define ReadAcquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define ReadPointerAcquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
static LONG InterlockedCompareExchange(LONG *p,LONG n,LONG old)
{ __atomic_compare_exchange_n(p,&old,n,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);return old; }
static void *force_published_view;
static void *InterlockedCompareExchangePointer(void **p,void *n,void *old)
{ if(force_published_view){__atomic_store_n(p,force_published_view,__ATOMIC_RELEASE);force_published_view=NULL;}
  __atomic_compare_exchange_n(p,&old,n,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);return old; }
static struct pw_window_style_table memory;
static SIZE_T map_size;
static unsigned opens,maps,closes,unmaps;
static int open_error,map_error;
static NTSTATUS NtOpenSection(HANDLE *h,unsigned rights,OBJECT_ATTRIBUTES *attr)
{ (void)attr;assert(rights==SECTION_MAP_READ);opens++;*h=(HANDLE)(uintptr_t)3;return open_error; }
static NTSTATUS NtMapViewOfSection(HANDLE h,HANDLE process,void **base,SIZE_T zero,SIZE_T commit,
                                  LARGE_INTEGER *offset,SIZE_T *size,unsigned type,unsigned flags,unsigned protect)
{ assert(h==(HANDLE)(uintptr_t)3 && process==GetCurrentProcess() && !zero && !commit &&
         !offset->QuadPart && type==ViewUnmap && !flags && protect==PAGE_READONLY);
  maps++;*base=&memory;*size=map_size;return map_error; }
static void NtClose(HANDLE h) {assert(h==(HANDLE)(uintptr_t)3);closes++;}
static void NtUnmapViewOfSection(HANDLE h,void *base)
{assert(h==GetCurrentProcess() && base==&memory);unmaps++;}
static unsigned fences, mutate_fence, keep_mutating;
static volatile struct pw_window_style_entry *mutate_entry;
static void fixture_fence(void)
{ __asm__ __volatile__("" ::: "memory");fences++;
 if(mutate_entry && (keep_mutating || fences==mutate_fence))mutate_entry->seq+=2; }
#include "reader.inc"
struct process { unsigned id; };
struct thread { struct process *process; };
struct window { unsigned style, handle, style_shared_ready; struct thread *thread; };
static unsigned current_error;
static unsigned get_error(void) { return current_error; }
static void set_error(unsigned error) { current_error=error; }
struct object { int unused; };
struct unicode_str { const WCHAR *str; unsigned len; };
struct mapping { int *fd; };
struct mapping_init_data { size_t size; unsigned flags,file_access; };
struct object_params { const void *ops; struct object *root; struct unicode_str name;
                       unsigned attr; const void *sd; struct mapping_init_data *init_data; };
#define SEC_COMMIT 1
#define FILE_READ_DATA 1
#define FILE_WRITE_DATA 2
#define OBJ_PERMANENT 16
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_FAILED ((void *)-1)
static const int mapping_ops;
static const size_t host_page_mask=16383;
static size_t round_size(size_t size,size_t mask) { return (size+mask)&~mask; }
static struct object namespace_root;
static const WCHAR section_name[]=L"__wine_window_styles";
static struct unicode_str section={section_name,sizeof(section_name)};
static unsigned create_calls,fd_calls,mmap_calls,release_calls,allocation_mode;
static int mapping_fd=11;
static struct mapping fixture_mapping={&mapping_fd};
static struct mapping *create_named_object(struct object_params *params)
{ create_calls++;assert(params->ops==&mapping_ops && params->root==&namespace_root &&
  params->name.str==section_name && params->attr==OBJ_PERMANENT && !params->sd &&
  params->init_data->size==1048576 && params->init_data->flags==SEC_COMMIT &&
  params->init_data->file_access==(FILE_READ_DATA|FILE_WRITE_DATA));
  current_error=91;errno=EIO;return allocation_mode==1?NULL:&fixture_mapping; }
static int get_unix_fd(int *fd)
{ fd_calls++;assert(fd==&mapping_fd);current_error=92;errno=EBADF;return allocation_mode==2?-1:*fd; }
static void *mock_mmap(void *base,size_t size,int prot,int flags,int fd,size_t offset)
{ mmap_calls++;assert(!base && size==1048576 && prot==(PROT_READ|PROT_WRITE) &&
  flags==MAP_SHARED && fd==11 && !offset);current_error=93;errno=ENOMEM;
  return allocation_mode==3?MAP_FAILED:&memory; }
static void release_object(struct mapping *mapping)
{ assert(mapping==&fixture_mapping);release_calls++;current_error=94;errno=EINVAL; }
#define mmap mock_mmap
#include "mapping.inc"
#undef mmap
static int config_dir_fd=7,io_mode;
static unsigned io_opens,io_reads,io_closes,io_position;
static const char *selection;
static const char *mock_getenv(const char *key)
{assert(!strcmp(key,"WINE_PS5_WINDOW_STYLE_SHARED"));return selection;}
static int mock_openat(int fd,const char *path,int flags)
{assert(fd==7 && !strcmp(path,"pw_window_style_shared") && flags==O_RDONLY);
 io_opens++;return io_mode==1?-1:8;}
static ssize_t mock_read(int fd,void *buffer,size_t size)
{assert(fd==8);io_reads++;if(io_mode==2)return -1;
 const char *value=io_mode==3?"1":io_mode==4?"1\n":io_mode==5?"1\nX":io_mode==6?"0":"";
 if(io_position>=strlen(value))return 0;
 assert(size);*(char *)buffer=value[io_position++];return 1;}
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
static volatile struct pw_window_style_table *window_style_table;
#include "init.inc"
#include "authority.inc"
static void reset(void)
{ memset(&memory,0,sizeof(memory));memory.magic=PW_WINDOW_STYLE_MAGIC;
 memory.version=PW_WINDOW_STYLE_VERSION;memory.entry_size=sizeof(memory.entries[0]);
 memory.count=PW_WINDOW_STYLE_COUNT;style_view=NULL;style_view_attempts=0;
 force_published_view=NULL;
 opens=maps=closes=unmaps=0;open_error=map_error=0;map_size=sizeof(memory);
 fences=mutate_fence=keep_mutating=0;mutate_entry=NULL;window_style_table=&memory; }
static void miss(HWND hwnd)
{DWORD out=0x12345678;assert(!get_shared_window_style(hwnd,&out) && out==0x12345678);}
static void *reserve_thread(void *unused)
{(void)unused;return (void *)(uintptr_t)reserve_style_view();}
int main(int argc,char **argv)
{
 _Static_assert(sizeof(struct pw_window_style_entry)==32,"fixed stride");
 _Static_assert(offsetof(struct pw_window_style_table,entries)==32,"fixed header");
 _Static_assert(sizeof(memory)==1047840,"full ordinary handle table");
 if(argc==5 && !strcmp(argv[1],"selector")){
   selection=strcmp(argv[2],"absent")?argv[2]:NULL;io_mode=atoi(argv[3]);if(io_mode==7)config_dir_fd=-1;
   errno=E2BIG;current_error=71;allocation_mode=0;
   init_window_style_mapping(&namespace_root,section);
   assert(ps5_window_style_shared_enabled()==atoi(argv[4]));assert(errno==E2BIG && current_error==71);
   assert(create_calls==(unsigned)atoi(argv[4]) && (window_style_table!=NULL)==atoi(argv[4]));
   if(window_style_table)assert(memory.magic==PW_WINDOW_STYLE_MAGIC && memory.count==PW_WINDOW_STYLE_COUNT);
   unsigned prior_opens=io_opens,prior_reads=io_reads;
   unsigned expected_closes=io_opens && io_mode!=1;
   selection="0";io_mode=2;assert(ps5_window_style_shared_enabled()==atoi(argv[4]));
   assert(prior_opens==io_opens && prior_reads==io_reads && io_closes==expected_closes);
   return 0;
 }
 reset();DWORD value;struct process process={42};struct thread thread={&process};
 struct window win={0,(unsigned)MAKELONG(PW_WINDOW_STYLE_FIRST+2,3),0,&thread};
 HWND hwnd=(HWND)(uintptr_t)win.handle;
 /* Creation is never answered early, including valid zero style. */
 set_window_style(&win,0);miss(hwnd);win.style_shared_ready=1;set_window_style(&win,0);
 const DWORD styles[]={0,0xffffffffu,0x10000000u,0x20000000u,0x01000000u,0x12345678u};
 for(unsigned i=0;i<sizeof(styles)/sizeof(styles[0]);i++){
   set_window_style(&win,styles[i]);assert(win.style==styles[i] && !(memory.entries[1].seq&1));
   assert(get_shared_window_style(hwnd,&value) && value==styles[i]);}
 assert(opens==1 && maps==1 && closes==1 && style_view_attempts==1);
 assert(get_shared_window_style((HWND)(uintptr_t)LOWORD(hwnd),&value));
 assert(get_shared_window_style((HWND)(uintptr_t)(0xffff0000u|LOWORD(hwnd)),&value));
 assert(get_shared_window_style((HWND)(uintptr_t)(win.handle|1),&value));
 miss((HWND)(uintptr_t)MAKELONG(LOWORD(hwnd),4));miss(NULL);
 process.id=43;set_window_style(&win,0);miss(hwnd);process.id=42;set_window_style(&win,0);
 memory.entries[1].ready=PW_WINDOW_STYLE_READY^1;miss(hwnd);publish_window_style(&win);
 memory.entries[1].seq|=1;miss(hwnd);memory.entries[1].seq++;
 fences=0;mutate_fence=2;mutate_entry=&memory.entries[1];
 assert(get_shared_window_style(hwnd,&value) && fences==4);
 fences=0;keep_mutating=1;miss(hwnd);assert(fences==32);keep_mutating=0;mutate_entry=NULL;
 /* Retire before reuse or detach: even generation aliases must fall back. */
 retire_window_style(&win);miss(hwnd);miss((HWND)(uintptr_t)LOWORD(hwnd));
 win.handle=(unsigned)MAKELONG(LOWORD(hwnd),4);set_window_style(&win,7);miss(hwnd);
 win.style_shared_ready=1;publish_window_style(&win);miss(hwnd);
 assert(get_shared_window_style((HWND)(uintptr_t)win.handle,&value) && value==7);
 retire_window_style(&win);win.thread=NULL;publish_window_style(&win);miss((HWND)(uintptr_t)win.handle);
 win.thread=&thread;win.style_shared_ready=1;window_style_table=NULL;set_window_style(&win,9);
 assert(win.style==9);miss((HWND)(uintptr_t)win.handle);
 /* Mapping validation and bounded counter positions, no OS resource pressure. */
 reset();style_view_attempts=MAX_STYLE_VIEW_ATTEMPTS-1;assert(get_style_view());
 assert(style_view_attempts==MAX_STYLE_VIEW_ATTEMPTS && get_style_view() && maps==1);
 reset();style_view_attempts=MAX_STYLE_VIEW_ATTEMPTS;assert(!get_style_view() && !opens);
 reset();open_error=1;assert(!get_style_view() && opens==1 && !maps && !closes);
 reset();map_error=1;assert(!get_style_view() && maps==1 && closes==1 && !unmaps);
 reset();map_size=sizeof(memory)-1;assert(!get_style_view() && unmaps==1);
 reset();force_published_view=&memory;assert(get_style_view()==&memory && style_view==&memory && unmaps==1);
 for(unsigned i=0;i<4;i++){
   reset();uint32_t *fields[]={&memory.magic,&memory.version,&memory.entry_size,&memory.count};
   (*fields[i])++;assert(!get_style_view() && unmaps==1 && closes==1 && style_view_attempts==1);}
 reset();pthread_t threads[16];unsigned granted=0;
 for(unsigned i=0;i<16;i++)assert(!pthread_create(&threads[i],NULL,reserve_thread,NULL));
 for(unsigned i=0;i<16;i++){void *result;assert(!pthread_join(threads[i],&result));granted+=(unsigned)(uintptr_t)result;}
 assert(granted==MAX_STYLE_VIEW_ATTEMPTS && style_view_attempts==MAX_STYLE_VIEW_ATTEMPTS && !reserve_style_view());
 /* Ordinary namespace calls mocked: error/failure states are never induced in Wine. */
 for(allocation_mode=0;allocation_mode<4;allocation_mode++){
   create_calls=fd_calls=mmap_calls=release_calls=0;errno=E2BIG;current_error=71;
   volatile void *view=create_window_style_mapping(&namespace_root,section,sizeof(memory));
   assert((view!=NULL)==!allocation_mode && current_error==71 && errno==E2BIG);
   assert(create_calls==1 && fd_calls==(allocation_mode!=1) &&
     mmap_calls==(allocation_mode!=1 && allocation_mode!=2) && release_calls==(allocation_mode!=1));}
 puts("window-style authority/lifetime, bounded reader/mapping and startup failure contracts PASS");return 0;
}
'''


def main():
    reader = side('dlls/user32/win.c', True)
    start = reader.index('#define STYLE_READ_FENCE()')
    reader = reader[start:reader.index('\n#else', start)]
    reader = reader.replace('#define STYLE_READ_FENCE() __asm__ __volatile__( "" ::: "memory" )',
                            '#define STYLE_READ_FENCE() fixture_fence()')
    server = side('server/window.c')
    header = side('include/wine/window_style_shared.h', True)
    mapping = side('server/mapping.c')
    patch_text = PATCH.read_text()
    assert 'b/include/wine/server_protocol.h' not in patch_text
    assert 'b/server/protocol.def' not in patch_text
    assert 'b/dlls/win32u/' not in patch_text
    assert side('dlls/user32/win.c', True).count('if (get_shared_window_style( hwnd, &style )) return style;') == 2
    assert server.count('retire_window_style( win );') == 3  # both frees and detach
    assert server.count('free_user_handle( win->handle );') == 2
    assert server.count('win->style = style;') == 1
    assert not re.search(r'win->style\s*(?:[|&]=|=\s*req)', server)
    assert 'init_window_style_mapping( &dir_kernel->obj, window_styles_str );' in side('server/directory.c')
    with tempfile.TemporaryDirectory(prefix='pw-window-style-') as temp:
        folder = Path(temp)
        (folder/'wine').mkdir()
        (folder/'wine/window_style_shared.h').write_text(header)
        (folder/'reader.inc').write_text(reader)
        (folder/'authority.inc').write_text(''.join(body(server, 'static void '+fn+'(')
                   for fn in ['publish_window_style','retire_window_style','set_window_style']))
        (folder/'selector.inc').write_text(body(server, 'static int ps5_window_style_shared_enabled('))
        (folder/'init.inc').write_text(body(server, 'void init_window_style_mapping('))
        (folder/'mapping.inc').write_text(body(mapping, 'volatile void *create_window_style_mapping('))
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
        print('window-style 13 strict selection/startup cases PASS')


if __name__ == '__main__':
    main()
