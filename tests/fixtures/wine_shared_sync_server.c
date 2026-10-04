/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Actual added helper bodies with independent list/refcount/legacy callbacks.
 * Does not run Wine or establish real wait/APC/handle integration semantics. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct list { struct list *next, *prev; };
#define LIST_INIT(n) { &(n), &(n) }
#define LIST_ENTRY(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
static void list_init(struct list *h) { h->next = h->prev = h; }
static int list_empty(const struct list *h) { return h->next == h; }
static struct list *list_head(struct list *h) { return list_empty(h) ? NULL : h->next; }
static void list_add_tail(struct list *h, struct list *p)
{
    p->prev = h->prev; p->next = h; h->prev->next = p; h->prev = p;
}
static void list_remove(struct list *p) { p->prev->next = p->next; p->next->prev = p->prev; }
struct object_ops { int kind; };
static const struct object_ops event_ops = {1}, event_sync_ops = {2};
static const struct object_ops semaphore_ops = {3}, semaphore_sync_ops = {4};
struct object { unsigned refcount, handle_count; const struct object_ops *ops;
    struct list wait_queue; void *name; };
struct process { int unused; };
struct thread { unsigned state; };
#define TERMINATED 1
typedef unsigned obj_handle_t;
struct wait_queue_entry { struct list entry; };
static int inprocess_direct_ok = 1, debug_level;
static void *grab_object(void *p) { struct object *o = p; assert(o->refcount); ++o->refcount; return p; }
static void release_object(void *p) { struct object *o = p; assert(o->refcount); --o->refcount; }
static int add_queue(struct object *o, struct wait_queue_entry *e)
{
    list_add_tail(&o->wait_queue, &e->entry); return 1;
}
static void remove_queue(struct object *o, struct wait_queue_entry *e) { (void)o; list_remove(&e->entry); }
#define WINE_INPROCESS_SERVER 1
#include "ps5_sync.h"
struct event_sync { struct object obj; unsigned manual, signaled;
    struct ps5_sync_cell *fast; int fast_disabled; };
struct event { struct object obj; struct object *sync; struct list kernel_object; int fast_eligible; };
struct semaphore_sync { struct object obj; unsigned count, max;
    struct ps5_sync_cell *fast; int fast_disabled; };
struct semaphore { struct object obj; struct object *sync; int fast_eligible; };
#include "ps5_sync_server.inc"

static void exercise(unsigned kind)
{
    struct thread thread = {0};
    struct event_sync e = {.obj = {.refcount = 1, .ops = &event_sync_ops},
                          .manual = kind == PW_SYNC_MANUAL_EVENT, .signaled = 1};
    struct semaphore_sync s = {.obj = {.refcount = 1, .ops = &semaphore_sync_ops}, .count = 2, .max = 7};
    struct event event = {.obj = {.refcount = 1, .handle_count = 1, .ops = &event_ops},
                         .sync = &e.obj, .fast_eligible = 1};
    struct semaphore sem = {.obj = {.refcount = 1, .handle_count = 1, .ops = &semaphore_ops},
                            .sync = &s.obj, .fast_eligible = 1};
    struct object *obj = kind == PW_SYNC_SEMAPHORE ? &sem.obj : &event.obj;
    struct object *sync = kind == PW_SYNC_SEMAPHORE ? &s.obj : &e.obj;
    int (*lookup)(struct thread *, struct object *, struct pw_sync_word **) =
        kind == PW_SYNC_SEMAPHORE ? ps5_get_semaphore_word : ps5_get_event_word;
    struct pw_sync_word *word = NULL;
    unsigned previous = 99, expected;
    list_init(&sync->wait_queue);
    list_init(&event.kernel_object);
    /* Cold exclusions preserve outputs, objects and refcounts. */
    obj->name = &thread; assert(!lookup(&thread, obj, &word) && !word && sync->refcount == 1);
    obj->name = NULL; obj->handle_count = 2; assert(!lookup(&thread, obj, &word)); obj->handle_count = 1;
    thread.state = TERMINATED; assert(!lookup(&thread, obj, &word)); thread.state = 0;
    debug_level = 1; assert(!lookup(&thread, obj, &word)); debug_level = 0;
    inprocess_direct_ok = 0; assert(!lookup(&thread, obj, &word)); inprocess_direct_ok = 1;
    event.fast_eligible = sem.fast_eligible = 0; assert(!lookup(&thread, obj, &word));
    event.fast_eligible = sem.fast_eligible = 1;
    if (kind != PW_SYNC_SEMAPHORE)
    {
        struct list associated;
        list_add_tail(&event.kernel_object, &associated);
        assert(!lookup(&thread, obj, &word) && !word);
        list_remove(&associated);
    }
    ps5_sync_server_begin(); ps5_sync_server_begin();
    assert(lookup(&thread, obj, &word) == 1 && (uintptr_t)word % 64 == 0);
    assert(sync->refcount == 2 && (pw_sync_word_load(word) & PW_SYNC_WORD_SLOW));
    ps5_sync_server_end(); assert(pw_sync_word_load(word) & PW_SYNC_WORD_SLOW);
    ps5_sync_server_end(); assert(!(pw_sync_word_load(word) & PW_SYNC_WORD_SLOW));
    struct ps5_sync_cell *cell = kind == PW_SYNC_SEMAPHORE ? s.fast : e.fast;
    for (unsigned i = 0; i < 200; ++i)
    {
        if (kind == PW_SYNC_SEMAPHORE)
        {
            assert(pw_sync_word_try_release(word, 1, &previous));
            expected = previous + 1;
            assert(pw_sync_word_try_wait(word)); --expected;
        }
        else
        {
            assert(pw_sync_word_try_event(word, 1, &previous)); expected = 1;
            assert(pw_sync_word_try_wait(word));
            if (kind == PW_SYNC_AUTO_EVENT) expected = 0;
        }
        ps5_sync_server_begin(); ps5_sync_enter_slow(cell);
        assert((kind == PW_SYNC_SEMAPHORE ? s.count : e.signaled) == expected);
        /* Repeated slow entry must keep modified legacy authority. */
        if (kind == PW_SYNC_SEMAPHORE) s.count = i % 6;
        else e.signaled = i % 2;
        expected = kind == PW_SYNC_SEMAPHORE ? s.count : e.signaled;
        ps5_sync_enter_slow(cell);
        assert((kind == PW_SYNC_SEMAPHORE ? s.count : e.signaled) == expected);
        ps5_sync_server_end(); assert(pw_sync_word_load(word) == expected);
    }
    /* A persistent waiter keeps SLOW even after outer request completion. */
    struct wait_queue_entry entry;
    ps5_sync_server_begin(); ps5_sync_server_begin();
    assert(kind == PW_SYNC_SEMAPHORE ? ps5_semaphore_add_queue(sync, &entry)
                                    : ps5_event_add_queue(sync, &entry));
    ps5_sync_server_end(); ps5_sync_server_end();
    assert(pw_sync_word_load(word) & PW_SYNC_WORD_SLOW);
    previous = 99;
    assert(!pw_sync_word_try_wait(word));
    assert(!pw_sync_word_try_release(word, 1, &previous) && previous == 99);
    assert(!pw_sync_word_try_event(word, 1, &previous) && previous == 99);
    ps5_sync_server_begin();
    if (kind == PW_SYNC_SEMAPHORE) s.count = 3; else e.signaled = 1;
    if (kind == PW_SYNC_SEMAPHORE) ps5_semaphore_remove_queue(sync, &entry);
    else ps5_event_remove_queue(sync, &entry);
    assert(pw_sync_word_load(word) & PW_SYNC_WORD_SLOW);
    ps5_sync_server_end(); assert(pw_sync_word_load(word) == (kind == PW_SYNC_SEMAPHORE ? 3 : 1));
    /* The last close restores current legacy state before dropping the pin. */
    assert(pw_sync_word_try_wait(word));
    expected = kind == PW_SYNC_SEMAPHORE ? 2 : kind == PW_SYNC_MANUAL_EVENT;
    ps5_sync_server_begin();
    assert(kind == PW_SYNC_SEMAPHORE ? ps5_semaphore_close_handle(obj, NULL, 4)
                                    : ps5_event_close_handle(obj, NULL, 4));
    ps5_sync_server_end();
    assert((kind == PW_SYNC_SEMAPHORE ? s.count : e.signaled) == expected);
    assert(sync->refcount == 1 && !cell->sync && !cell->binding && !cell->disabled);
    assert(pw_sync_word_load(word) & PW_SYNC_WORD_SLOW);
    assert(!lookup(&thread, obj, &word));
    assert(kind == PW_SYNC_SEMAPHORE ? (s.fast_disabled && !s.fast && !sem.fast_eligible)
                                    : (e.fast_disabled && !e.fast && !event.fast_eligible));
    assert(list_empty(&ps5_sync_active) && list_empty(&ps5_sync_pending));
    /* Fixture teardown only, after all native readers are gone. */
    free(cell);
}

static void retire_before_activation(void)
{
    struct thread thread = {0};
    struct event_sync e = {.obj = {.refcount = 1, .ops = &event_sync_ops}};
    struct event event = {.obj = {.refcount = 1, .handle_count = 1, .ops = &event_ops},
                         .sync = &e.obj, .fast_eligible = 1};
    struct pw_sync_word *word = NULL;
    list_init(&e.obj.wait_queue);
    list_init(&event.kernel_object);
    ps5_sync_retire_object(&event.obj);
    assert(!event.fast_eligible && e.fast_disabled && !ps5_get_event_word(&thread, &event.obj, &word));
    assert(!word && !e.fast && e.obj.refcount == 1);
}

static void disable_all(void)
{
    struct thread thread = {0};
    struct event_sync e = {.obj = {.refcount = 1, .ops = &event_sync_ops}, .signaled = 1};
    struct event event = {.obj = {.refcount = 1, .handle_count = 1, .ops = &event_ops},
                         .sync = &e.obj, .fast_eligible = 1};
    struct semaphore_sync s = {.obj = {.refcount = 1, .ops = &semaphore_sync_ops}, .count = 2, .max = 7};
    struct semaphore sem = {.obj = {.refcount = 1, .handle_count = 1, .ops = &semaphore_ops},
                            .sync = &s.obj, .fast_eligible = 1};
    struct pw_sync_word *ew, *sw;
    list_init(&e.obj.wait_queue); list_init(&s.obj.wait_queue); list_init(&event.kernel_object);
    ps5_sync_server_begin();
    assert(ps5_get_event_word(&thread, &event.obj, &ew) == 1);
    assert(ps5_get_semaphore_word(&thread, &sem.obj, &sw) == 1);
    ps5_sync_server_end();
    struct ps5_sync_cell *ec = e.fast, *sc = s.fast;
    assert(pw_sync_word_try_wait(ew) && pw_sync_word_try_wait(sw));
    inprocess_direct_ok = 0; ps5_sync_server_disable();
    assert(!e.signaled && s.count == 1 && !e.fast && !s.fast);
    assert(e.fast_disabled && s.fast_disabled && e.obj.refcount == 1 && s.obj.refcount == 1);
    assert((pw_sync_word_load(ew) & PW_SYNC_WORD_SLOW) && (pw_sync_word_load(sw) & PW_SYNC_WORD_SLOW));
    inprocess_direct_ok = 1;
    assert(!ps5_get_event_word(&thread, &event.obj, &ew));
    assert(!ps5_get_semaphore_word(&thread, &sem.obj, &sw));
    assert(list_empty(&ps5_sync_active) && list_empty(&ps5_sync_pending));
    free(ec); free(sc);
}

int main(void)
{
    for (unsigned kind = PW_SYNC_AUTO_EVENT; kind <= PW_SYNC_SEMAPHORE; ++kind) exercise(kind);
    retire_before_activation();
    disable_all();
    assert(!ps5_sync_operation_depth);
    puts("shared sync server PASS: exact cold/helper/queue bodies, 600 authority cycles, "
         "nested request and waiter gates, legacy-state adoption, pin lifetime, close/alias/disable retirement");
    return 0;
}
