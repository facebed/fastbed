#ifndef FASTBED_ARENA_H
#define FASTBED_ARENA_H

#include "fastbed/common.h"

typedef struct fb_arena_chunk fb_arena_chunk;

/*
 * Request-local bump arena. The arena and every pointer returned from it are
 * single-thread-owned. reset and trim invalidate all outstanding allocations.
 */
typedef struct {
    fb_arena_chunk *first;
    fb_arena_chunk *current;
    size_t initial_capacity;
    size_t total_capacity;
} fb_arena;

FB_NODISCARD bool fb_arena_init(fb_arena *arena, size_t initial_capacity);
void fb_arena_reset(fb_arena *arena);
void fb_arena_destroy(fb_arena *arena);

/*
 * Reset and discard tail chunks until no more than retain_capacity bytes are
 * retained. The initial chunk is always kept.
 */
void fb_arena_trim(fb_arena *arena, size_t retain_capacity);

FB_NODISCARD void *fb_arena_alloc(
    fb_arena *arena,
    size_t size,
    size_t alignment
);
FB_NODISCARD void *fb_arena_memdup(
    fb_arena *arena,
    const void *source,
    size_t size,
    size_t alignment
);
FB_NODISCARD char *fb_arena_strndup(
    fb_arena *arena,
    const char *source,
    size_t length
);
FB_NODISCARD fb_slice fb_arena_slice_dup(fb_arena *arena, fb_slice source);

size_t fb_arena_reserved(const fb_arena *arena);
size_t fb_arena_used(const fb_arena *arena);

#endif
