#include "fastbed/arena.h"

#include <pthread.h>
#include <stddef.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FB_ARENA_DEFAULT_CAPACITY (16u * 1024u)
#define FB_ARENA_RECYCLE_SLOT_COUNT 7u

struct fb_arena_chunk {
    struct fb_arena_chunk *next;
    size_t capacity;
    size_t used;
    _Alignas(max_align_t) unsigned char data[];
};

typedef struct {
    fb_arena_chunk *slots[FB_ARENA_RECYCLE_SLOT_COUNT];
} fb_arena_recycler;

static pthread_once_t fb_recycler_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t fb_recycler_key;
static int fb_recycler_key_status = -1;
static _Thread_local fb_arena_recycler *fb_recycler;

static void
fb_arena_recycler_destroy(void *opaque)
{
    fb_arena_recycler *recycler = opaque;
    if (recycler == NULL) {
        return;
    }
    for (size_t slot = 0u; slot < FB_ARENA_RECYCLE_SLOT_COUNT; ++slot) {
        free(recycler->slots[slot]);
    }
    free(recycler);
}

static void
fb_arena_recycler_key_initialize(void)
{
    fb_recycler_key_status =
        pthread_key_create(&fb_recycler_key, fb_arena_recycler_destroy);
}

static fb_arena_recycler *
fb_arena_recycler_get(bool create)
{
    fb_arena_recycler *recycler = fb_recycler;
    if (recycler != NULL || !create) {
        return recycler;
    }
    if (pthread_once(&fb_recycler_key_once,
                     fb_arena_recycler_key_initialize) != 0 ||
        fb_recycler_key_status != 0) {
        return NULL;
    }
    recycler = calloc(1u, sizeof(*recycler));
    if (recycler == NULL) {
        return NULL;
    }
    if (pthread_setspecific(fb_recycler_key, recycler) != 0) {
        free(recycler);
        return NULL;
    }
    fb_recycler = recycler;
    return recycler;
}

static size_t
fb_arena_recycle_slot(size_t capacity)
{
    switch (capacity) {
    case 16u * 1024u:
        return 0u;
    case 32u * 1024u:
        return 1u;
    case 64u * 1024u:
        return 2u;
    case 128u * 1024u:
        return 3u;
    case 256u * 1024u:
        return 4u;
    case 512u * 1024u:
        return 5u;
    case 1024u * 1024u:
        return 6u;
    default:
        return SIZE_MAX;
    }
}

static fb_arena_chunk *
fb_arena_chunk_take_recycled(size_t capacity)
{
    const size_t slot = fb_arena_recycle_slot(capacity);
    fb_arena_recycler *recycler = fb_arena_recycler_get(false);
    if (recycler == NULL || slot == SIZE_MAX) {
        return NULL;
    }
    fb_arena_chunk *chunk = recycler->slots[slot];
    if (chunk != NULL) {
        recycler->slots[slot] = NULL;
        chunk->next = NULL;
        chunk->used = 0u;
    }
    return chunk;
}

static void
fb_arena_chunk_recycle(fb_arena_chunk *chunk)
{
    size_t slot;
    fb_arena_recycler *recycler;
    if (chunk == NULL) {
        return;
    }
    slot = fb_arena_recycle_slot(chunk->capacity);
    if (slot == SIZE_MAX) {
        free(chunk);
        return;
    }
    recycler = fb_arena_recycler_get(true);
    if (recycler == NULL || recycler->slots[slot] != NULL) {
        free(chunk);
        return;
    }
    chunk->used = 0u;
    chunk->next = NULL;
    recycler->slots[slot] = chunk;
}

static fb_arena_chunk *
fb_arena_chunk_create(size_t capacity)
{
    size_t allocation_size;
    fb_arena_chunk *chunk = fb_arena_chunk_take_recycled(capacity);
    if (chunk != NULL) {
        return chunk;
    }
    if (capacity == 0u ||
        !fb_size_add(offsetof(fb_arena_chunk, data), capacity,
                     &allocation_size)) {
        return NULL;
    }

    chunk = malloc(allocation_size);
    if (chunk == NULL) {
        return NULL;
    }
    chunk->next = NULL;
    chunk->capacity = capacity;
    chunk->used = 0u;
    return chunk;
}

static void
fb_arena_chunk_chain_destroy(fb_arena_chunk *chunk)
{
    while (chunk != NULL) {
        fb_arena_chunk *next = chunk->next;
        fb_arena_chunk_recycle(chunk);
        chunk = next;
    }
}

static void *
fb_arena_chunk_try_alloc(
    fb_arena_chunk *chunk,
    size_t size,
    size_t alignment
)
{
    if (chunk == NULL || chunk->used > chunk->capacity) {
        return NULL;
    }

    const uintptr_t base = (uintptr_t)chunk->data;
    if (chunk->used > UINTPTR_MAX - base) {
        return NULL;
    }
    const uintptr_t address = base + chunk->used;
    const uintptr_t mask = (uintptr_t)alignment - 1u;
    if (address > UINTPTR_MAX - mask) {
        return NULL;
    }
    const uintptr_t aligned = (address + mask) & ~mask;
    const size_t offset = (size_t)(aligned - base);
    if (offset > chunk->capacity || size > chunk->capacity - offset) {
        return NULL;
    }

    chunk->used = offset + size;
    return (void *)aligned;
}

bool
fb_arena_init(fb_arena *arena, size_t initial_capacity)
{
    if (arena == NULL) {
        return false;
    }
    memset(arena, 0, sizeof(*arena));

    if (initial_capacity == 0u) {
        initial_capacity = FB_ARENA_DEFAULT_CAPACITY;
    }
    fb_arena_chunk *first = fb_arena_chunk_create(initial_capacity);
    if (first == NULL) {
        return false;
    }

    arena->first = first;
    arena->current = first;
    arena->initial_capacity = initial_capacity;
    arena->total_capacity = first->capacity;
    return true;
}

void
fb_arena_reset(fb_arena *arena)
{
    if (arena == NULL) {
        return;
    }
    for (fb_arena_chunk *chunk = arena->first;
         chunk != NULL;
         chunk = chunk->next) {
        chunk->used = 0u;
    }
    arena->current = arena->first;
}

void
fb_arena_destroy(fb_arena *arena)
{
    if (arena == NULL) {
        return;
    }
    fb_arena_chunk_chain_destroy(arena->first);
    memset(arena, 0, sizeof(*arena));
}

void
fb_arena_trim(fb_arena *arena, size_t retain_capacity)
{
    if (arena == NULL || arena->first == NULL) {
        return;
    }

    fb_arena_chunk *last = arena->first;
    last->used = 0u;
    size_t retained = last->capacity;
    while (last->next != NULL) {
        fb_arena_chunk *candidate = last->next;
        if (retained > retain_capacity ||
            candidate->capacity > retain_capacity - retained) {
            fb_arena_chunk_chain_destroy(candidate);
            last->next = NULL;
            break;
        }
        candidate->used = 0u;
        retained += candidate->capacity;
        last = candidate;
    }

    arena->current = arena->first;
    arena->total_capacity = retained;
}

void *
fb_arena_alloc(fb_arena *arena, size_t size, size_t alignment)
{
    if (FB_UNLIKELY(arena == NULL || arena->first == NULL ||
                    alignment == 0u ||
                    (alignment & (alignment - 1u)) != 0u)) {
        return NULL;
    }

    /* Give zero-sized requests a stable, in-arena address. */
    if (size == 0u) {
        size = 1u;
    }

    fb_arena_chunk *chunk = arena->current != NULL
                                ? arena->current
                                : arena->first;
    fb_arena_chunk *last = chunk;
    for (; chunk != NULL; chunk = chunk->next) {
        void *allocation =
            fb_arena_chunk_try_alloc(chunk, size, alignment);
        if (allocation != NULL) {
            arena->current = chunk;
            return allocation;
        }
        last = chunk;
    }

    size_t required;
    if (!fb_size_add(size, alignment - 1u, &required)) {
        return NULL;
    }

    size_t capacity = last != NULL ? last->capacity : arena->initial_capacity;
    if (capacity == 0u) {
        capacity = FB_ARENA_DEFAULT_CAPACITY;
    }
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2u) {
            capacity = required;
            break;
        }
        capacity *= 2u;
    }
    if (arena->total_capacity > SIZE_MAX - capacity) {
        return NULL;
    }

    fb_arena_chunk *added = fb_arena_chunk_create(capacity);
    if (added == NULL) {
        return NULL;
    }
    void *allocation = fb_arena_chunk_try_alloc(added, size, alignment);
    if (allocation == NULL) {
        free(added);
        return NULL;
    }

    if (last != NULL) {
        last->next = added;
    } else {
        arena->first = added;
    }
    arena->current = added;
    arena->total_capacity += capacity;
    return allocation;
}

void *
fb_arena_memdup(
    fb_arena *arena,
    const void *source,
    size_t size,
    size_t alignment
)
{
    if (source == NULL && size != 0u) {
        return NULL;
    }
    void *copy = fb_arena_alloc(arena, size, alignment);
    if (copy != NULL && size != 0u) {
        memcpy(copy, source, size);
    }
    return copy;
}

char *
fb_arena_strndup(fb_arena *arena, const char *source, size_t length)
{
    if (source == NULL && length != 0u) {
        return NULL;
    }
    size_t allocation_size;
    if (!fb_size_add(length, 1u, &allocation_size)) {
        return NULL;
    }
    char *copy = fb_arena_alloc(arena, allocation_size, 1u);
    if (copy == NULL) {
        return NULL;
    }
    if (length != 0u) {
        memcpy(copy, source, length);
    }
    copy[length] = '\0';
    return copy;
}

fb_slice
fb_arena_slice_dup(fb_arena *arena, fb_slice source)
{
    if (!fb_slice_is_valid(source)) {
        return fb_slice_make(NULL, 0u);
    }
    char *copy = fb_arena_strndup(arena, source.ptr, source.len);
    return copy != NULL ? fb_slice_make(copy, source.len)
                        : fb_slice_make(NULL, 0u);
}

size_t
fb_arena_reserved(const fb_arena *arena)
{
    return arena != NULL ? arena->total_capacity : 0u;
}

size_t
fb_arena_used(const fb_arena *arena)
{
    if (arena == NULL) {
        return 0u;
    }
    size_t total = 0u;
    for (const fb_arena_chunk *chunk = arena->first;
         chunk != NULL;
         chunk = chunk->next) {
        if (total > SIZE_MAX - chunk->used) {
            return SIZE_MAX;
        }
        total += chunk->used;
    }
    return total;
}
