#ifndef FASTBED_CACHE_H
#define FASTBED_CACHE_H

#include "fastbed/arena.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct fb_success_cache fb_success_cache;

typedef enum {
    FB_CACHE_HIT = 0,
    FB_CACHE_OWNER,
    FB_CACHE_BYPASS
} fb_cache_lookup_result;

typedef struct {
    uint64_t hash;
    uint64_t generation;
    bool active;
} fb_cache_reservation;

typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t coalesced_waits;
    uint64_t inserts;
    uint64_t evictions;
    uint64_t bypasses;
    size_t entries;
    size_t bytes;
} fb_cache_stats;

fb_success_cache *fb_success_cache_create(size_t max_entries,
                                          size_t max_bytes,
                                          uint64_t ttl_seconds);
void fb_success_cache_destroy(fb_success_cache *cache);

/*
 * A miss reserves one single-flight slot and returns FB_CACHE_OWNER. Other
 * callers for the same key wait for that owner or a bounded stale deadline.
 * A hit is copied into the request arena before the shard lock is released.
 */
fb_cache_lookup_result fb_success_cache_lookup(
    fb_success_cache *cache,
    fb_arena *arena,
    fb_slice key,
    fb_slice *body,
    fb_slice *log_title,
    fb_cache_reservation *reservation
);

/*
 * The cancellable form is intended for suspended HTTP work.  Cancellation is
 * sampled while coalescing behind another owner; it never revokes an owner
 * reservation that has already been returned to the caller.
 */
fb_cache_lookup_result fb_success_cache_lookup_cancelable(
    fb_success_cache *cache,
    fb_arena *arena,
    fb_slice key,
    fb_slice *body,
    fb_slice *log_title,
    fb_cache_reservation *reservation,
    const atomic_bool *cancel_requested
);

void fb_success_cache_commit(fb_success_cache *cache,
                             fb_cache_reservation *reservation,
                             fb_slice key,
                             fb_slice body,
                             fb_slice log_title);
void fb_success_cache_abort(fb_success_cache *cache,
                            fb_cache_reservation *reservation,
                            fb_slice key);

fb_cache_stats fb_success_cache_get_stats(fb_success_cache *cache);

#endif
