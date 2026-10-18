#include "fastbed/cache.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

enum {
    FB_CACHE_SHARDS = 16,
    FB_CACHE_BUCKETS = 512,
    FB_CACHE_ALIGNMENT = 64,
};

_Static_assert((FB_CACHE_BUCKETS & (FB_CACHE_BUCKETS - 1u)) == 0u,
               "cache bucket count must be a power of two");

typedef enum {
    FB_CACHE_ENTRY_INFLIGHT = 0,
    FB_CACHE_ENTRY_READY,
} fb_cache_entry_state;

typedef struct fb_cache_entry {
    struct fb_cache_entry *bucket_next;
    struct fb_cache_entry *lru_previous;
    struct fb_cache_entry *lru_next;
    uint64_t hash;
    uint64_t generation;
    uint64_t expires_ns;
    fb_cache_entry_state state;
    size_t key_length;
    size_t body_length;
    size_t log_title_length;
    char *key;
    char *body;
    char *log_title;
    pthread_cond_t changed;
    size_t waiters;
    bool condition_ready;
    bool retired;
} fb_cache_entry;

typedef struct {
    _Alignas(FB_CACHE_ALIGNMENT) pthread_mutex_t lock;
    fb_cache_entry *buckets[FB_CACHE_BUCKETS];
    fb_cache_entry *lru_head;
    fb_cache_entry *lru_tail;
    size_t entry_count;
    size_t byte_count;
    size_t max_entries;
    size_t max_bytes;
    uint64_t hits;
    uint64_t misses;
    uint64_t coalesced_waits;
    uint64_t inserts;
    uint64_t evictions;
    uint64_t bypasses;
    uint64_t next_generation;
} fb_cache_shard;

_Static_assert(_Alignof(fb_cache_shard) >= FB_CACHE_ALIGNMENT,
               "cache shards must begin on separate cache lines");
_Static_assert(sizeof(fb_cache_shard) % FB_CACHE_ALIGNMENT == 0u,
               "cache shard stride must preserve cache-line alignment");

struct fb_success_cache {
    fb_cache_shard shards[FB_CACHE_SHARDS];
    pthread_condattr_t condition_attributes;
    uint64_t key[2];
    uint64_t ttl_ns;
    uint64_t inflight_ns;
    uint64_t wait_ns;
    size_t initialized_shards;
    bool condition_attributes_ready;
};

_Static_assert(_Alignof(struct fb_success_cache) >= FB_CACHE_ALIGNMENT,
               "cache allocation must preserve shard alignment");
_Static_assert(sizeof(struct fb_success_cache) % FB_CACHE_ALIGNMENT == 0u,
               "aligned_alloc requires a whole alignment multiple");

enum {
    FB_CACHE_CANCEL_POLL_NS = 100u * 1000u * 1000u,
};

static uint64_t fb_rotate_left(uint64_t value, unsigned count) {
    return (value << count) | (value >> (64u - count));
}

static uint64_t fb_load_u64_le(const unsigned char *bytes) {
    return ((uint64_t)bytes[0]) |
           ((uint64_t)bytes[1] << 8u) |
           ((uint64_t)bytes[2] << 16u) |
           ((uint64_t)bytes[3] << 24u) |
           ((uint64_t)bytes[4] << 32u) |
           ((uint64_t)bytes[5] << 40u) |
           ((uint64_t)bytes[6] << 48u) |
           ((uint64_t)bytes[7] << 56u);
}

#define FB_SIPROUND()                                                          \
    do {                                                                       \
        v0 += v1; v1 = fb_rotate_left(v1, 13u); v1 ^= v0;                     \
        v0 = fb_rotate_left(v0, 32u);                                          \
        v2 += v3; v3 = fb_rotate_left(v3, 16u); v3 ^= v2;                     \
        v0 += v3; v3 = fb_rotate_left(v3, 21u); v3 ^= v0;                     \
        v2 += v1; v1 = fb_rotate_left(v1, 17u); v1 ^= v2;                     \
        v2 = fb_rotate_left(v2, 32u);                                          \
    } while (0)

static uint64_t fb_siphash24(const uint64_t key[2], fb_slice input) {
    const unsigned char *bytes = (const unsigned char *)input.ptr;
    const size_t blocks = input.len / 8u;
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ key[0];
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ key[1];
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ key[0];
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ key[1];
    uint64_t tail = (uint64_t)input.len << 56u;
    size_t index;
    for (index = 0u; index < blocks; ++index) {
        const uint64_t message = fb_load_u64_le(bytes + index * 8u);
        v3 ^= message;
        FB_SIPROUND();
        FB_SIPROUND();
        v0 ^= message;
    }
    bytes += blocks * 8u;
    switch (input.len & 7u) {
    case 7: tail |= (uint64_t)bytes[6] << 48u; /* fall through */
    case 6: tail |= (uint64_t)bytes[5] << 40u; /* fall through */
    case 5: tail |= (uint64_t)bytes[4] << 32u; /* fall through */
    case 4: tail |= (uint64_t)bytes[3] << 24u; /* fall through */
    case 3: tail |= (uint64_t)bytes[2] << 16u; /* fall through */
    case 2: tail |= (uint64_t)bytes[1] << 8u;  /* fall through */
    case 1: tail |= (uint64_t)bytes[0];         /* fall through */
    default: break;
    }
    v3 ^= tail;
    FB_SIPROUND();
    FB_SIPROUND();
    v0 ^= tail;
    v2 ^= UINT64_C(0xff);
    FB_SIPROUND();
    FB_SIPROUND();
    FB_SIPROUND();
    FB_SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}

#undef FB_SIPROUND

static uint64_t fb_monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0u;
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
}

static uint64_t fb_saturating_add_u64(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static uint64_t fb_min_u64(uint64_t left, uint64_t right) {
    return left < right ? left : right;
}

static size_t fb_entry_charge(const fb_cache_entry *entry) {
    size_t result = sizeof(*entry);
    if (!fb_size_add(result, entry->key_length, &result) ||
        !fb_size_add(result, entry->body_length, &result) ||
        !fb_size_add(result, entry->log_title_length, &result)) {
        return SIZE_MAX;
    }
    return result;
}
static size_t fb_bucket_index(uint64_t hash) {
    return (size_t)(hash & (FB_CACHE_BUCKETS - 1u));
}

static size_t fb_shard_index(uint64_t hash) {
    return (size_t)((hash >> 32u) & (FB_CACHE_SHARDS - 1u));
}

static bool fb_entry_matches(const fb_cache_entry *entry,
                             uint64_t hash,
                             fb_slice key) {
    return entry->hash == hash && entry->key_length == key.len &&
           (key.len == 0u || memcmp(entry->key, key.ptr, key.len) == 0);
}

static fb_cache_entry *fb_find_entry(fb_cache_shard *shard,
                                     uint64_t hash,
                                     fb_slice key) {
    fb_cache_entry *entry = shard->buckets[fb_bucket_index(hash)];
    while (entry != NULL && !fb_entry_matches(entry, hash, key)) {
        entry = entry->bucket_next;
    }
    return entry;
}

static void fb_lru_detach(fb_cache_shard *shard, fb_cache_entry *entry) {
    if (entry->lru_previous != NULL) {
        entry->lru_previous->lru_next = entry->lru_next;
    } else if (shard->lru_head == entry) {
        shard->lru_head = entry->lru_next;
    }
    if (entry->lru_next != NULL) {
        entry->lru_next->lru_previous = entry->lru_previous;
    } else if (shard->lru_tail == entry) {
        shard->lru_tail = entry->lru_previous;
    }
    entry->lru_previous = NULL;
    entry->lru_next = NULL;
}

static void fb_lru_front(fb_cache_shard *shard, fb_cache_entry *entry) {
    if (shard->lru_head == entry) {
        return;
    }
    fb_lru_detach(shard, entry);
    entry->lru_next = shard->lru_head;
    if (shard->lru_head != NULL) {
        shard->lru_head->lru_previous = entry;
    } else {
        shard->lru_tail = entry;
    }
    shard->lru_head = entry;
}

static void fb_entry_free(fb_cache_entry *entry) {
    if (entry != NULL) {
        if (entry->condition_ready) {
            (void)pthread_cond_destroy(&entry->changed);
        }
        free(entry->body);
        free(entry->log_title);
        free(entry->key);
        free(entry);
    }
}

static void fb_entry_retire(fb_cache_entry *entry) {
    entry->retired = true;
    if (entry->waiters != 0u) {
        (void)pthread_cond_broadcast(&entry->changed);
    } else {
        fb_entry_free(entry);
    }
}

static void fb_entry_waiter_release(fb_cache_entry *entry) {
    if (entry->waiters != 0u) {
        --entry->waiters;
    }
    if (entry->retired && entry->waiters == 0u) {
        fb_entry_free(entry);
    }
}

static void fb_remove_entry(fb_cache_shard *shard,
                            fb_cache_entry *entry,
                            bool eviction) {
    const size_t bucket = fb_bucket_index(entry->hash);
    fb_cache_entry **cursor = &shard->buckets[bucket];
    const size_t charge = fb_entry_charge(entry);
    while (*cursor != NULL && *cursor != entry) {
        cursor = &(*cursor)->bucket_next;
    }
    if (*cursor == entry) {
        *cursor = entry->bucket_next;
    }
    fb_lru_detach(shard, entry);
    if (shard->entry_count != 0u) {
        --shard->entry_count;
    }
    if (charge <= shard->byte_count) {
        shard->byte_count -= charge;
    } else {
        shard->byte_count = 0u;
    }
    if (eviction) {
        ++shard->evictions;
    }
    fb_entry_retire(entry);
}

static bool fb_evict_for(fb_cache_shard *shard,
                         size_t incoming_entries,
                         size_t incoming_bytes) {
    if (incoming_bytes > shard->max_bytes ||
        incoming_entries > shard->max_entries) {
        return false;
    }
    while ((shard->entry_count + incoming_entries > shard->max_entries ||
            shard->byte_count > shard->max_bytes - incoming_bytes)) {
        fb_cache_entry *victim = shard->lru_tail;
        while (victim != NULL && victim->state == FB_CACHE_ENTRY_INFLIGHT) {
            victim = victim->lru_previous;
        }
        if (victim == NULL) {
            return false;
        }
        fb_remove_entry(shard, victim, true);
    }
    return true;
}

static void fb_cache_seed(uint64_t key[2], const void *address) {
    unsigned char bytes[16];
    ssize_t count = getrandom(bytes, sizeof(bytes), 0);
    if (count == (ssize_t)sizeof(bytes)) {
        key[0] = fb_load_u64_le(bytes);
        key[1] = fb_load_u64_le(bytes + 8u);
        return;
    }
    {
        struct timespec now = {0, 0};
        (void)clock_gettime(CLOCK_REALTIME, &now);
        key[0] = (uint64_t)now.tv_nsec ^ ((uint64_t)now.tv_sec << 21u) ^
                 (uint64_t)(uintptr_t)address;
        key[1] = key[0] ^ ((uint64_t)(unsigned)getpid() << 32u) ^
                 UINT64_C(0xa0761d6478bd642f);
    }
}

fb_success_cache *fb_success_cache_create(size_t max_entries,
                                          size_t max_bytes,
                                          uint64_t ttl_seconds) {
    fb_success_cache *cache;
    size_t initialized = 0u;
    if (max_entries < FB_CACHE_SHARDS || max_bytes < FB_CACHE_SHARDS * 4096u ||
        ttl_seconds == 0u || ttl_seconds > UINT64_MAX / UINT64_C(1000000000)) {
        return NULL;
    }
    cache = aligned_alloc(FB_CACHE_ALIGNMENT, sizeof(*cache));
    if (cache == NULL) {
        return NULL;
    }
    memset(cache, 0, sizeof(*cache));
    fb_cache_seed(cache->key, cache);
    cache->ttl_ns = ttl_seconds * UINT64_C(1000000000);
    cache->inflight_ns = UINT64_C(75) * UINT64_C(1000000000);
    cache->wait_ns = cache->inflight_ns;
    if (pthread_condattr_init(&cache->condition_attributes) != 0) {
        free(cache);
        return NULL;
    }
    cache->condition_attributes_ready = true;
    if (pthread_condattr_setclock(&cache->condition_attributes,
                                  CLOCK_MONOTONIC) != 0) {
        (void)pthread_condattr_destroy(&cache->condition_attributes);
        free(cache);
        return NULL;
    }
    for (size_t index = 0u; index < FB_CACHE_SHARDS; ++index) {
        fb_cache_shard *shard = &cache->shards[index];
        shard->max_entries =
            (max_entries + FB_CACHE_SHARDS - 1u) / FB_CACHE_SHARDS;
        shard->max_bytes =
            (max_bytes + FB_CACHE_SHARDS - 1u) / FB_CACHE_SHARDS;
        if (pthread_mutex_init(&shard->lock, NULL) != 0) {
            break;
        }
        ++initialized;
    }
    cache->initialized_shards = initialized;
    if (initialized != FB_CACHE_SHARDS) {
        fb_success_cache_destroy(cache);
        return NULL;
    }
    return cache;
}

void fb_success_cache_destroy(fb_success_cache *cache) {
    if (cache == NULL) {
        return;
    }
    for (size_t index = 0u; index < cache->initialized_shards; ++index) {
        fb_cache_shard *shard = &cache->shards[index];
        fb_cache_entry *entry = shard->lru_head;
        while (entry != NULL) {
            fb_cache_entry *next = entry->lru_next;
            fb_entry_free(entry);
            entry = next;
        }
        (void)pthread_mutex_destroy(&shard->lock);
    }
    if (cache->condition_attributes_ready) {
        (void)pthread_condattr_destroy(&cache->condition_attributes);
    }
    memset(cache, 0, sizeof(*cache));
    free(cache);
}

static fb_cache_lookup_result fb_success_cache_lookup_impl(
    fb_success_cache *cache,
    fb_arena *arena,
    fb_slice key,
    fb_slice *body,
    fb_slice *log_title,
    fb_cache_reservation *reservation,
    const atomic_bool *cancel_requested) {
    uint64_t hash;
    fb_cache_shard *shard;
    uint64_t caller_deadline = 0u;
    bool wait_recorded = false;
    if (body != NULL) {
        *body = fb_slice_make(NULL, 0u);
    }
    if (log_title != NULL) {
        *log_title = fb_slice_make(NULL, 0u);
    }
    if (reservation != NULL) {
        memset(reservation, 0, sizeof(*reservation));
    }
    if (cache == NULL || arena == NULL || body == NULL || log_title == NULL ||
        reservation == NULL || !fb_slice_is_valid(key) || key.len == 0u) {
        return FB_CACHE_BYPASS;
    }
    hash = fb_siphash24(cache->key, key);
    shard = &cache->shards[fb_shard_index(hash)];
    (void)pthread_mutex_lock(&shard->lock);
    for (;;) {
        const uint64_t now = fb_monotonic_ns();
        fb_cache_entry *entry = fb_find_entry(shard, hash, key);
        if ((cancel_requested != NULL &&
             atomic_load_explicit(cancel_requested, memory_order_relaxed)) ||
            now == 0u) {
            ++shard->bypasses;
            (void)pthread_mutex_unlock(&shard->lock);
            return FB_CACHE_BYPASS;
        }
        if (caller_deadline == 0u) {
            caller_deadline = fb_saturating_add_u64(now, cache->wait_ns);
        }
        if (entry != NULL && entry->expires_ns <= now) {
            fb_remove_entry(shard, entry, true);
            entry = NULL;
        }
        if (entry != NULL && entry->state == FB_CACHE_ENTRY_READY) {
            *body = fb_arena_slice_dup(
                arena, fb_slice_make(entry->body, entry->body_length));
            *log_title = fb_arena_slice_dup(
                arena,
                fb_slice_make(entry->log_title, entry->log_title_length));
            if (!fb_slice_is_valid(*body) ||
                !fb_slice_is_valid(*log_title)) {
                ++shard->bypasses;
                (void)pthread_mutex_unlock(&shard->lock);
                return FB_CACHE_BYPASS;
            }
            fb_lru_front(shard, entry);
            ++shard->hits;
            (void)pthread_mutex_unlock(&shard->lock);
            return FB_CACHE_HIT;
        }
        if (entry != NULL && entry->state == FB_CACHE_ENTRY_INFLIGHT) {
            struct timespec wake;
            int wait_status;
            const uint64_t waited_generation = entry->generation;
            uint64_t wake_ns;
            if (now >= caller_deadline) {
                ++shard->bypasses;
                (void)pthread_mutex_unlock(&shard->lock);
                return FB_CACHE_BYPASS;
            }
            if (!wait_recorded) {
                ++shard->coalesced_waits;
                wait_recorded = true;
            }
            wake_ns = fb_min_u64(caller_deadline, entry->expires_ns);
            if (cancel_requested != NULL) {
                wake_ns = fb_min_u64(
                    wake_ns,
                    fb_saturating_add_u64(now, FB_CACHE_CANCEL_POLL_NS));
            }
            wake.tv_sec = (time_t)(wake_ns / UINT64_C(1000000000));
            wake.tv_nsec = (long)(wake_ns % UINT64_C(1000000000));
            ++entry->waiters;
            wait_status = pthread_cond_timedwait(&entry->changed,
                                                 &shard->lock, &wake);
            fb_entry_waiter_release(entry);
            if (wait_status == 0) {
                continue;
            }
            if (wait_status == ETIMEDOUT) {
                const uint64_t after_wait = fb_monotonic_ns();
                entry = fb_find_entry(shard, hash, key);
                if (entry != NULL && entry->state == FB_CACHE_ENTRY_INFLIGHT &&
                    entry->generation == waited_generation &&
                    after_wait != 0u && entry->expires_ns <= after_wait) {
                    fb_remove_entry(shard, entry, true);
                }
                continue;
            }
            ++shard->bypasses;
            (void)pthread_mutex_unlock(&shard->lock);
            return FB_CACHE_BYPASS;
        }
        {
            fb_cache_entry *created;
            size_t charge;
            if (!fb_size_add(sizeof(*created), key.len, &charge) ||
                charge > shard->max_bytes ||
                !fb_evict_for(shard, 1u, charge)) {
                ++shard->bypasses;
                (void)pthread_mutex_unlock(&shard->lock);
                return FB_CACHE_BYPASS;
            }
            created = calloc(1, sizeof(*created));
            if (created == NULL) {
                ++shard->bypasses;
                (void)pthread_mutex_unlock(&shard->lock);
                return FB_CACHE_BYPASS;
            }
            if (pthread_cond_init(&created->changed,
                                  &cache->condition_attributes) != 0) {
                free(created);
                ++shard->bypasses;
                (void)pthread_mutex_unlock(&shard->lock);
                return FB_CACHE_BYPASS;
            }
            created->condition_ready = true;
            created->key = malloc(key.len);
            if (created->key == NULL) {
                fb_entry_free(created);
                ++shard->bypasses;
                (void)pthread_mutex_unlock(&shard->lock);
                return FB_CACHE_BYPASS;
            }
            memcpy(created->key, key.ptr, key.len);
            created->key_length = key.len;
            created->hash = hash;
            ++shard->next_generation;
            if (shard->next_generation == 0u) {
                ++shard->next_generation;
            }
            created->generation = shard->next_generation;
            created->state = FB_CACHE_ENTRY_INFLIGHT;
            created->expires_ns = fb_saturating_add_u64(now,
                                                        cache->inflight_ns);
            created->bucket_next = shard->buckets[fb_bucket_index(hash)];
            shard->buckets[fb_bucket_index(hash)] = created;
            ++shard->entry_count;
            shard->byte_count += charge;
            fb_lru_front(shard, created);
            ++shard->misses;
            reservation->hash = hash;
            reservation->generation = created->generation;
            reservation->active = true;
            (void)pthread_mutex_unlock(&shard->lock);
            return FB_CACHE_OWNER;
        }
    }
}

fb_cache_lookup_result fb_success_cache_lookup(
    fb_success_cache *cache,
    fb_arena *arena,
    fb_slice key,
    fb_slice *body,
    fb_slice *log_title,
    fb_cache_reservation *reservation) {
    return fb_success_cache_lookup_impl(cache, arena, key, body, log_title,
                                        reservation, NULL);
}

fb_cache_lookup_result fb_success_cache_lookup_cancelable(
    fb_success_cache *cache,
    fb_arena *arena,
    fb_slice key,
    fb_slice *body,
    fb_slice *log_title,
    fb_cache_reservation *reservation,
    const atomic_bool *cancel_requested) {
    return fb_success_cache_lookup_impl(cache, arena, key, body, log_title,
                                        reservation, cancel_requested);
}

void fb_success_cache_commit(fb_success_cache *cache,
                             fb_cache_reservation *reservation,
                             fb_slice key,
                             fb_slice body,
                             fb_slice log_title) {
    fb_cache_shard *shard;
    fb_cache_entry *entry;
    char *body_copy;
    char *title_copy = NULL;
    uint64_t now;
    size_t old_charge;
    size_t new_charge;
    if (cache == NULL || reservation == NULL || !reservation->active ||
        !fb_slice_is_valid(key) || body.ptr == NULL || body.len == 0u ||
        !fb_slice_is_valid(log_title)) {
        return;
    }
    body_copy = malloc(body.len);
    if (body_copy == NULL) {
        fb_success_cache_abort(cache, reservation, key);
        return;
    }
    memcpy(body_copy, body.ptr, body.len);
    if (log_title.len != 0u) {
        title_copy = malloc(log_title.len);
        if (title_copy == NULL) {
            free(body_copy);
            fb_success_cache_abort(cache, reservation, key);
            return;
        }
        memcpy(title_copy, log_title.ptr, log_title.len);
    }
    shard = &cache->shards[fb_shard_index(reservation->hash)];
    (void)pthread_mutex_lock(&shard->lock);
    entry = fb_find_entry(shard, reservation->hash, key);
    if (entry == NULL || entry->state != FB_CACHE_ENTRY_INFLIGHT ||
        entry->generation != reservation->generation) {
        (void)pthread_mutex_unlock(&shard->lock);
        free(title_copy);
        free(body_copy);
        reservation->active = false;
        return;
    }
    now = fb_monotonic_ns();
    if (now == 0u || entry->expires_ns <= now) {
        fb_remove_entry(shard, entry, true);
        (void)pthread_mutex_unlock(&shard->lock);
        free(title_copy);
        free(body_copy);
        reservation->active = false;
        return;
    }
    old_charge = fb_entry_charge(entry);
    if (!fb_size_add(old_charge, body.len, &new_charge) ||
        !fb_size_add(new_charge, log_title.len, &new_charge) ||
        new_charge > shard->max_bytes ||
        shard->byte_count - old_charge > shard->max_bytes - new_charge) {
        fb_remove_entry(shard, entry, false);
        (void)pthread_mutex_unlock(&shard->lock);
        free(title_copy);
        free(body_copy);
        reservation->active = false;
        return;
    }
    entry->body = body_copy;
    entry->body_length = body.len;
    entry->log_title = title_copy;
    entry->log_title_length = log_title.len;
    entry->state = FB_CACHE_ENTRY_READY;
    entry->expires_ns = fb_saturating_add_u64(now, cache->ttl_ns);
    shard->byte_count = shard->byte_count - old_charge + new_charge;
    ++shard->inserts;
    fb_lru_front(shard, entry);
    (void)fb_evict_for(shard, 0u, 0u);
    if (entry->waiters != 0u) {
        (void)pthread_cond_broadcast(&entry->changed);
    }
    (void)pthread_mutex_unlock(&shard->lock);
    reservation->active = false;
}

void fb_success_cache_abort(fb_success_cache *cache,
                            fb_cache_reservation *reservation,
                            fb_slice key) {
    fb_cache_shard *shard;
    fb_cache_entry *entry;
    if (cache == NULL || reservation == NULL || !reservation->active ||
        !fb_slice_is_valid(key)) {
        return;
    }
    shard = &cache->shards[fb_shard_index(reservation->hash)];
    (void)pthread_mutex_lock(&shard->lock);
    entry = fb_find_entry(shard, reservation->hash, key);
    if (entry != NULL && entry->state == FB_CACHE_ENTRY_INFLIGHT &&
        entry->generation == reservation->generation) {
        fb_remove_entry(shard, entry, false);
    }
    (void)pthread_mutex_unlock(&shard->lock);
    reservation->active = false;
}

fb_cache_stats fb_success_cache_get_stats(fb_success_cache *cache) {
    fb_cache_stats result;
    memset(&result, 0, sizeof(result));
    if (cache == NULL) {
        return result;
    }
    for (size_t index = 0u; index < FB_CACHE_SHARDS; ++index) {
        fb_cache_shard *shard = &cache->shards[index];
        (void)pthread_mutex_lock(&shard->lock);
        result.hits += shard->hits;
        result.misses += shard->misses;
        result.coalesced_waits += shard->coalesced_waits;
        result.inserts += shard->inserts;
        result.evictions += shard->evictions;
        result.bypasses += shard->bypasses;
        result.entries += shard->entry_count;
        result.bytes += shard->byte_count;
        (void)pthread_mutex_unlock(&shard->lock);
    }
    return result;
}
