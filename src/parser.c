#include "fastbed/parser.h"

#include "fastbed/document.h"
#include "fastbed/buf.h"
#include "fastbed/url.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define FB_WALK_MAX_DEPTH (FB_DOCUMENT_DEFAULT_MAX_DEPTH + 2u)
#define FB_ID_INITIAL_CAPACITY 8u
#define FB_ID_INITIAL_BUCKETS 16u
#define FB_PAGE_CACHE_CAPACITY 4u
#define FB_WALK_SCRATCH_SLOTS 4u
#define FB_IDENTITY_MEMO_CAPACITY 512u
#define FB_EFFECTIVE_BLOOM_WORDS 4u
#define FB_EFFECTIVE_BLOOM_MAX_KEYS 64u
#define FB_CANCEL_ITEM_INTERVAL ((size_t)256u)
#define FB_STATIC_SLICE(literal) \
    {.ptr = (literal), .len = sizeof(literal) - 1u}

_Static_assert(
    (FB_IDENTITY_MEMO_CAPACITY & (FB_IDENTITY_MEMO_CAPACITY - 1u)) == 0u,
    "identity memo capacity must be a power of two");

static const fb_slice FB_REASON_NONE = FB_STATIC_SLICE("");
static const fb_slice FB_REASON_NO_DATA = FB_STATIC_SLICE("no_data");
static const fb_slice FB_REASON_UNSUPPORTED =
    FB_STATIC_SLICE("unsupported_route");
static const fb_slice FB_REASON_SHARE_FAILED =
    FB_STATIC_SLICE("share_resolution_failed");
static const fb_slice FB_REASON_PARSER = FB_STATIC_SLICE("parser_error");
static const fb_slice FB_REASON_DOCUMENT = FB_STATIC_SLICE("document_error");
static const fb_slice FB_REASON_UPSTREAM = FB_STATIC_SLICE("upstream_error");
static const fb_slice FB_REASON_TRANSPORT =
    FB_STATIC_SLICE("upstream_transport_error");
static const fb_slice FB_REASON_NO_MEMORY = FB_STATIC_SLICE("no_memory");
static const fb_slice FB_REASON_INVALID_ARGUMENT =
    FB_STATIC_SLICE("invalid_argument");
static const fb_slice FB_REASON_CANCELLED = FB_STATIC_SLICE("cancelled");

static const fb_slice FB_SHARE_HEAD_UA =
    FB_STATIC_SLICE("python-requests/2.32.3");
static const fb_slice FB_SHARE_BODY_UA = FB_STATIC_SLICE(
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
);

static int
fb_base64_decode_block(
    unsigned char *output,
    const unsigned char *input,
    size_t input_length
)
{
#if defined(OPENSSL_IS_BORINGSSL)
    return EVP_DecodeBlock(output, input, input_length);
#else
    if (input_length > (size_t)INT_MAX) {
        return -1;
    }
    return EVP_DecodeBlock(output, input, (int)input_length);
#endif
}

typedef struct {
    fb_slice *items;
    size_t len;
    size_t capacity;
    uint32_t *buckets;
    size_t bucket_count;
    uint64_t membership_bits;
    fb_arena *arena;
    fb_slice inline_items[FB_ID_INITIAL_CAPACITY];
    uint32_t inline_buckets[FB_ID_INITIAL_BUCKETS];
} fb_id_set;

typedef struct {
    const yyjson_val *root;
    const fb_slice *ids;
    uint64_t fingerprint;
    uint32_t id_count;
    uint8_t mode;
    bool result;
    bool occupied;
} fb_identity_memo_entry;

typedef struct fb_parser fb_parser;

typedef enum {
    FB_WALK_ENTER = 0,
    FB_WALK_OBJECT_ARRAYS,
    FB_WALK_OBJECT_OBJECTS,
    FB_WALK_ARRAY_OBJECTS,
    FB_WALK_ARRAY_ARRAYS
} fb_walk_phase;

typedef struct {
    yyjson_obj_iter raw;
    fb_parser *parser;
    size_t work_count;
    const yyjson_val *duplicate_keys[4];
    uint8_t duplicate_count;
    bool duplicate_overflow;
    bool raw_keys_unique;
} fb_effective_object_iter;

typedef struct {
    const yyjson_val *value;
    fb_walk_phase phase;
    union {
        fb_effective_object_iter object;
        yyjson_arr_iter array;
    } iterator;
} fb_walk_frame;

typedef struct {
    fb_walk_frame *frames;
    fb_parser *parser;
    size_t depth;
    size_t work_count;
    uint8_t scratch_slot;
    bool overflow;
} fb_object_walk;

static _Thread_local fb_walk_frame
    fb_walk_scratch[FB_WALK_SCRATCH_SLOTS][FB_WALK_MAX_DEPTH];
static _Thread_local uint8_t fb_walk_scratch_mask;

typedef enum {
    FB_PROBE_HAS_DATA = 0,
    FB_PROBE_UNKNOWN,
    FB_PROBE_NO_DATA,
    FB_PROBE_LOGIN_WALL,
    FB_PROBE_TARGET_NOT_FOUND,
    FB_PROBE_TARGET_IDENTITY_MISMATCH,
    FB_PROBE_PRIVATE_GROUP,
    FB_PROBE_TARGET_VIDEO_MISSING,
    FB_PROBE_UNSUPPORTED_PROFILE,
    FB_PROBE_UNSUPPORTED_MARKETPLACE,
    FB_PROBE_UNSUPPORTED_MEDIA_SET
} fb_probe_kind;

typedef struct {
    fb_slice path;
    fb_upstream_response *response;
    fb_document *document;
    fb_probe_kind probe;
} fb_page;

typedef struct {
    bool ok;
    fb_post post;
    fb_parse_error error;
    bool has_document_evidence;
} fb_attempt;

struct fb_parser {
    fb_arena *arena;
    const fb_config *config;
    fb_transport_scope *scope;
    const fb_cancel_token *cancel;
    bool cancelled;
    bool parser_entered;
    fb_page pages[FB_PAGE_CACHE_CAPACITY];
    size_t page_count;
    fb_identity_memo_entry *identity_memo;
};

typedef struct {
    fb_slice path;
    fb_upstream_response *prefetched;
} fb_share_target;

static bool
fb_parser_poll_cancel(fb_parser *parser)
{
    if (parser == NULL) {
        return false;
    }
    if (parser->cancelled || fb_cancel_requested(parser->cancel)) {
        parser->cancelled = true;
        return true;
    }
    return false;
}

static unsigned char
fb_ascii_lower(unsigned char value)
{
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
        return (unsigned char)(value + ((unsigned char)'a' - (unsigned char)'A'));
    }
    return value;
}

static bool
fb_slice_equal_ascii_case(fb_slice left, fb_slice right)
{
    size_t index;

    if (left.len != right.len || !fb_slice_is_valid(left) ||
        !fb_slice_is_valid(right)) {
        return false;
    }
    for (index = 0u; index < left.len; ++index) {
        if (fb_ascii_lower((unsigned char)left.ptr[index]) !=
            fb_ascii_lower((unsigned char)right.ptr[index])) {
            return false;
        }
    }
    return true;
}

static bool
fb_slice_equal_literal(fb_slice value, const char *literal)
{
    size_t length;

    if (literal == NULL || !fb_slice_is_valid(value)) {
        return false;
    }
    length = strlen(literal);
    return value.len == length &&
           (length == 0u || memcmp(value.ptr, literal, length) == 0);
}

static bool
fb_slice_equal_literal_ascii_case(fb_slice value, const char *literal)
{
    return literal != NULL &&
           fb_slice_equal_ascii_case(value, fb_slice_from_cstr(literal));
}

static bool
fb_slice_starts_literal_ascii_case(fb_slice value, const char *prefix)
{
    size_t length;

    if (prefix == NULL) {
        return false;
    }
    length = strlen(prefix);
    return value.len >= length &&
           fb_slice_equal_ascii_case(
               fb_slice_make(value.ptr, length),
               fb_slice_make(prefix, length)
           );
}

static bool
fb_slice_contains_literal_ascii_case(fb_slice value, const char *needle)
{
    size_t needle_length;
    size_t index;

    if (needle == NULL || !fb_slice_is_valid(value)) {
        return false;
    }
    needle_length = strlen(needle);
    if (needle_length == 0u) {
        return true;
    }
    if (needle_length > value.len) {
        return false;
    }
    for (index = 0u; index <= value.len - needle_length; ++index) {
        if (fb_slice_equal_ascii_case(
                fb_slice_make(value.ptr + index, needle_length),
                fb_slice_make(needle, needle_length))) {
            return true;
        }
    }
    return false;
}

static fb_slice
fb_slice_trim(fb_slice value)
{
    size_t first = 0u;
    size_t last = value.len;

    if (value.ptr == NULL) {
        return value;
    }
    while (first < last && isspace((unsigned char)value.ptr[first]) != 0) {
        ++first;
    }
    while (last > first && isspace((unsigned char)value.ptr[last - 1u]) != 0) {
        --last;
    }
    return fb_slice_make(value.ptr + first, last - first);
}

static uint64_t
fb_hash_slice(fb_slice value)
{
    const unsigned char *bytes = (const unsigned char *)value.ptr;
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t index;

    for (index = 0u; index < value.len; ++index) {
        hash ^= bytes[index];
        hash *= UINT64_C(1099511628211);
    }
    hash ^= hash >> 32u;
    return hash;
}

#if defined(__GNUC__) || defined(__clang__)
static fb_slice fb_arena_vformat(
    fb_arena *arena,
    const char *format,
    va_list arguments
) __attribute__((format(printf, 2, 0)));
static fb_slice fb_arena_format(
    fb_arena *arena,
    const char *format,
    ...
) __attribute__((format(printf, 2, 3)));
#endif

static fb_slice
fb_arena_vformat(fb_arena *arena, const char *format, va_list arguments)
{
    va_list copy;
    int needed;
    char *buffer;

    if (arena == NULL || format == NULL) {
        return fb_slice_make(NULL, 0u);
    }
    va_copy(copy, arguments);
    needed = vsnprintf(NULL, 0u, format, copy);
    va_end(copy);
    if (needed < 0) {
        return fb_slice_make(NULL, 0u);
    }
    buffer = fb_arena_alloc(arena, (size_t)needed + 1u, _Alignof(char));
    if (buffer == NULL) {
        return fb_slice_make(NULL, 0u);
    }
    (void)vsnprintf(buffer, (size_t)needed + 1u, format, arguments);
    return fb_slice_make(buffer, (size_t)needed);
}

static fb_slice
fb_arena_format(fb_arena *arena, const char *format, ...)
{
    fb_slice result;
    va_list arguments;

    va_start(arguments, format);
    result = fb_arena_vformat(arena, format, arguments);
    va_end(arguments);
    return result;
}

static bool
fb_id_set_rehash(fb_id_set *set, size_t bucket_count)
{
    uint32_t *buckets;
    size_t bytes;
    size_t index;

    if (set == NULL || set->arena == NULL || bucket_count < 2u ||
        (bucket_count & (bucket_count - 1u)) != 0u ||
        !fb_size_mul(bucket_count, sizeof(*buckets), &bytes)) {
        return false;
    }
    buckets = fb_arena_alloc(set->arena, bytes, _Alignof(uint32_t));
    if (buckets == NULL) {
        return false;
    }
    memset(buckets, 0, bytes);
    for (index = 0u; index < set->len; ++index) {
        size_t slot = (size_t)fb_hash_slice(set->items[index]) &
                      (bucket_count - 1u);
        while (buckets[slot] != 0u) {
            slot = (slot + 1u) & (bucket_count - 1u);
        }
        if (index >= UINT32_MAX) {
            return false;
        }
        buckets[slot] = (uint32_t)index + 1u;
    }
    set->buckets = buckets;
    set->bucket_count = bucket_count;
    return true;
}

static bool
fb_id_set_init(fb_id_set *set, fb_arena *arena)
{
    if (set == NULL || arena == NULL) {
        return false;
    }
    memset(set, 0, sizeof(*set));
    set->arena = arena;
    set->items = set->inline_items;
    set->capacity = FB_ID_INITIAL_CAPACITY;
    set->buckets = set->inline_buckets;
    set->bucket_count = FB_ID_INITIAL_BUCKETS;
    return true;
}

static bool
fb_id_set_find(const fb_id_set *set, fb_slice value, size_t *index_out)
{
    size_t slot;
    size_t probes;
    uint64_t hash;

    if (set == NULL || set->bucket_count == 0u || set->buckets == NULL ||
        !fb_slice_is_valid(value)) {
        return false;
    }
    hash = fb_hash_slice(value);
    if ((set->membership_bits &
         (UINT64_C(1) << (hash & UINT64_C(63)))) == 0u) {
        return false;
    }
    slot = (size_t)hash & (set->bucket_count - 1u);
    for (probes = 0u; probes < set->bucket_count; ++probes) {
        uint32_t entry = set->buckets[slot];
        if (entry == 0u) {
            return false;
        }
        if ((size_t)(entry - 1u) < set->len &&
            fb_slice_equal(set->items[entry - 1u], value)) {
            if (index_out != NULL) {
                *index_out = (size_t)(entry - 1u);
            }
            return true;
        }
        slot = (slot + 1u) & (set->bucket_count - 1u);
    }
    return false;
}

static bool
fb_id_set_add(fb_id_set *set, fb_slice value)
{
    fb_slice *items;
    size_t bytes;
    size_t slot;

    if (set == NULL || value.ptr == NULL || value.len == 0u) {
        return value.len == 0u;
    }
    if (fb_id_set_find(set, value, NULL)) {
        return true;
    }
    if (set->len >= UINT32_MAX) {
        return false;
    }
    if (set->len > (SIZE_MAX - 1u) / 10u ||
        set->bucket_count > SIZE_MAX / 7u) {
        return false;
    }
    if ((set->len + 1u) * 10u >= set->bucket_count * 7u) {
        if (set->bucket_count > SIZE_MAX / 2u ||
            !fb_id_set_rehash(set, set->bucket_count * 2u)) {
            return false;
        }
    }
    if (set->len == set->capacity) {
        size_t capacity = set->capacity * 2u;
        if (capacity < set->capacity ||
            !fb_size_mul(capacity, sizeof(*items), &bytes)) {
            return false;
        }
        items = fb_arena_alloc(set->arena, bytes, _Alignof(fb_slice));
        if (items == NULL) {
            return false;
        }
        memcpy(items, set->items, set->len * sizeof(*items));
        set->items = items;
        set->capacity = capacity;
    }
    set->items[set->len] = value;
    {
        uint64_t hash = fb_hash_slice(value);
        set->membership_bits |=
            UINT64_C(1) << (hash & UINT64_C(63));
        slot = (size_t)hash & (set->bucket_count - 1u);
    }
    while (set->buckets[slot] != 0u) {
        slot = (slot + 1u) & (set->bucket_count - 1u);
    }
    set->buckets[slot] = (uint32_t)set->len + 1u;
    set->len++;
    return true;
}

static bool
fb_id_set_add_set(fb_id_set *destination, const fb_id_set *source)
{
    size_t index;

    if (destination == NULL || source == NULL) {
        return false;
    }
    for (index = 0u; index < source->len; ++index) {
        if (!fb_id_set_add(destination, source->items[index])) {
            return false;
        }
    }
    return true;
}

static bool
fb_id_sets_intersect(const fb_id_set *left, const fb_id_set *right)
{
    const fb_id_set *smaller;
    const fb_id_set *larger;
    size_t index;

    if (left == NULL || right == NULL) {
        return false;
    }
    if ((left->membership_bits & right->membership_bits) == 0u) {
        return false;
    }
    smaller = left->len <= right->len ? left : right;
    larger = left->len <= right->len ? right : left;
    for (index = 0u; index < smaller->len; ++index) {
        if (fb_id_set_find(larger, smaller->items[index], NULL)) {
            return true;
        }
    }
    return false;
}

static bool
fb_id_sets_equal(const fb_id_set *left, const fb_id_set *right)
{
    size_t index;

    if (left == NULL || right == NULL || left->len != right->len) {
        return false;
    }
    for (index = 0u; index < left->len; ++index) {
        if (!fb_id_set_find(right, left->items[index], NULL)) {
            return false;
        }
    }
    return true;
}

static uint64_t
fb_identity_mix(uint64_t value)
{
    value ^= value >> 30u;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27u;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

static uint64_t
fb_id_set_fingerprint(const fb_id_set *ids)
{
    uint64_t fingerprint;
    size_t index;
    if (ids == NULL) {
        return 0u;
    }
    fingerprint = fb_identity_mix(
        ids->membership_bits ^ (uint64_t)ids->len ^
        UINT64_C(0x9e3779b97f4a7c15));
    for (index = 0u; index < ids->len; ++index) {
        const uint64_t item = fb_hash_slice(ids->items[index]);
        fingerprint ^= fb_identity_mix(
            item + (uint64_t)index * UINT64_C(0x9e3779b97f4a7c15));
        fingerprint = (fingerprint << 17u) | (fingerprint >> 47u);
    }
    return fb_identity_mix(fingerprint);
}

static size_t
fb_identity_memo_slot(
    const yyjson_val *root,
    uint64_t fingerprint,
    uint8_t mode
)
{
    uint64_t hash = fb_identity_mix(
        ((uint64_t)(uintptr_t)(const void *)root >> 3u) ^
        fingerprint ^ ((uint64_t)mode << 56u));
    return (size_t)hash & (FB_IDENTITY_MEMO_CAPACITY - 1u);
}

static bool
fb_identity_memo_lookup(
    fb_parser *parser,
    const yyjson_val *root,
    const fb_id_set *ids,
    uint8_t mode,
    bool *result
)
{
    uint64_t fingerprint;
    size_t slot;
    size_t probes;
    if (parser == NULL || parser->identity_memo == NULL || root == NULL ||
        ids == NULL || ids->len == 0u || ids->len > UINT32_MAX) {
        return false;
    }
    fingerprint = fb_id_set_fingerprint(ids);
    slot = fb_identity_memo_slot(root, fingerprint, mode);
    for (probes = 0u; probes < FB_IDENTITY_MEMO_CAPACITY; ++probes) {
        const fb_identity_memo_entry *entry = &parser->identity_memo[slot];
        if (!entry->occupied) {
            return false;
        }
        if (entry->root == root && entry->fingerprint == fingerprint &&
            entry->id_count == (uint32_t)ids->len && entry->mode == mode) {
            size_t index;
            for (index = 0u; index < ids->len; ++index) {
                if (!fb_slice_equal(entry->ids[index], ids->items[index])) {
                    break;
                }
            }
            if (index == ids->len) {
                *result = entry->result;
                return true;
            }
        }
        slot = (slot + 1u) & (FB_IDENTITY_MEMO_CAPACITY - 1u);
    }
    return false;
}

static void
fb_identity_memo_store(
    fb_parser *parser,
    const yyjson_val *root,
    const fb_id_set *ids,
    uint8_t mode,
    bool result
)
{
    uint64_t fingerprint;
    size_t slot;
    size_t probes;
    size_t descriptor_bytes;
    fb_identity_memo_entry *destination = NULL;
    fb_slice *stable_ids;
    if (parser == NULL || root == NULL || ids == NULL || ids->len == 0u ||
        ids->len > UINT32_MAX) {
        return;
    }
    if (parser->identity_memo == NULL) {
        parser->identity_memo = fb_arena_alloc(
            parser->arena,
            FB_IDENTITY_MEMO_CAPACITY * sizeof(*parser->identity_memo),
            _Alignof(fb_identity_memo_entry));
        if (parser->identity_memo == NULL) {
            return;
        }
        memset(parser->identity_memo, 0,
               FB_IDENTITY_MEMO_CAPACITY * sizeof(*parser->identity_memo));
    }
    fingerprint = fb_id_set_fingerprint(ids);
    slot = fb_identity_memo_slot(root, fingerprint, mode);
    for (probes = 0u; probes < FB_IDENTITY_MEMO_CAPACITY; ++probes) {
        fb_identity_memo_entry *entry = &parser->identity_memo[slot];
        if (!entry->occupied) {
            destination = entry;
            break;
        }
        if (entry->root == root && entry->fingerprint == fingerprint &&
            entry->id_count == (uint32_t)ids->len && entry->mode == mode) {
            size_t index;
            for (index = 0u; index < ids->len; ++index) {
                if (!fb_slice_equal(entry->ids[index], ids->items[index])) {
                    break;
                }
            }
            if (index == ids->len) {
                entry->result = result;
                return;
            }
        }
        slot = (slot + 1u) & (FB_IDENTITY_MEMO_CAPACITY - 1u);
    }
    if (destination == NULL ||
        !fb_size_mul(ids->len, sizeof(*stable_ids), &descriptor_bytes)) {
        return;
    }
    stable_ids = fb_arena_memdup(
        parser->arena,
        ids->items,
        descriptor_bytes,
        _Alignof(fb_slice));
    if (stable_ids == NULL) {
        return;
    }
    destination->root = root;
    destination->ids = stable_ids;
    destination->fingerprint = fingerprint;
    destination->id_count = (uint32_t)ids->len;
    destination->mode = mode;
    destination->result = result;
    destination->occupied = true;
}

static bool
fb_id_set_from_url(fb_parser *parser, fb_slice url, fb_id_set *set)
{
    fb_requested_ids ids;
    fb_url_status status;
    size_t index;

    if (!fb_id_set_init(set, parser->arena)) {
        return false;
    }
    status = fb_url_requested_ids(parser->arena, url, &ids);
    if (status != FB_URL_OK) {
        return false;
    }
    for (index = 0u; index < ids.len; ++index) {
        if (!fb_id_set_add(set, fb_requested_id_at(&ids, index))) {
            return false;
        }
    }
    return true;
}

static void
fb_walk_push(fb_object_walk *walk, const yyjson_val *value)
{
    fb_walk_frame *frame;

    if (walk->frames == NULL || walk->depth >= FB_WALK_MAX_DEPTH) {
        walk->overflow = true;
        return;
    }
    frame = &walk->frames[walk->depth++];
    frame->value = value;
    frame->phase = FB_WALK_ENTER;
}

static void
fb_object_walk_init(
    fb_object_walk *walk,
    fb_parser *parser,
    const yyjson_val *root
)
{
    size_t slot;

    walk->frames = NULL;
    walk->parser = parser;
    walk->depth = 0u;
    walk->work_count = 0u;
    walk->scratch_slot = UINT8_MAX;
    walk->overflow = false;
    for (slot = 0u; slot < FB_WALK_SCRATCH_SLOTS; ++slot) {
        uint8_t bit = (uint8_t)(UINT8_C(1) << slot);
        if ((fb_walk_scratch_mask & bit) == 0u) {
            fb_walk_scratch_mask =
                (uint8_t)(fb_walk_scratch_mask | bit);
            walk->frames = fb_walk_scratch[slot];
            walk->scratch_slot = (uint8_t)slot;
            break;
        }
    }
    if (walk->frames == NULL) {
        walk->overflow = true;
        return;
    }
    if (root != NULL) {
        fb_walk_push(walk, root);
    }
}

static void
fb_object_walk_destroy(fb_object_walk *walk)
{
    if (walk != NULL && walk->scratch_slot < FB_WALK_SCRATCH_SLOTS) {
        uint8_t bit =
            (uint8_t)(UINT8_C(1) << walk->scratch_slot);
        fb_walk_scratch_mask =
            (uint8_t)(fb_walk_scratch_mask & (uint8_t)~bit);
        walk->scratch_slot = UINT8_MAX;
        walk->frames = NULL;
        walk->depth = 0u;
    }
}

static void
fb_effective_object_iter_init(
    fb_effective_object_iter *iterator,
    const yyjson_val *object,
    fb_parser *parser
)
{
    const size_t key_count = yyjson_obj_size(object);

    iterator->raw = yyjson_obj_iter_with(object);
    iterator->parser = parser;
    iterator->work_count = 0u;
    iterator->duplicate_count = 0u;
    iterator->duplicate_overflow = false;
    iterator->raw_keys_unique = key_count <= 1u;

    /*
     * Identical keys necessarily reproduce both fingerprint positions.  If
     * no key encounters both positions already set, duplicates are therefore
     * impossible and raw yyjson order already has json.loads semantics.  A
     * collision between distinct keys is only an uncertainty: retain the
     * exact final-value/first-position path below.
     *
     * Bound the proof scan so an adversarial large object never pays an extra
     * full pass before taking the exact path.  The two 256-bit position
     * filters keep false fallback low for small ordinary Facebook objects;
     * their transient storage does not enlarge every traversal frame.
     */
    if (key_count > 1u && key_count <= FB_EFFECTIVE_BLOOM_MAX_KEYS) {
        uint64_t first[FB_EFFECTIVE_BLOOM_WORDS] = {0u, 0u, 0u, 0u};
        uint64_t second[FB_EFFECTIVE_BLOOM_WORDS] = {0u, 0u, 0u, 0u};
        yyjson_obj_iter probe = yyjson_obj_iter_with(object);
        yyjson_val *key;
        bool collision = false;

        while ((key = yyjson_obj_iter_next(&probe)) != NULL) {
            if ((++iterator->work_count &
                 (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                fb_parser_poll_cancel(parser)) {
                return;
            }
            fb_slice text = fb_slice_make(
                yyjson_get_str(key),
                yyjson_get_len(key)
            );
            uint64_t fingerprint = fb_hash_slice(text);
            size_t first_position;
            size_t second_position;
            uint64_t first_bit;
            uint64_t second_bit;

            fingerprint ^= fingerprint >> 33u;
            fingerprint *= UINT64_C(0xff51afd7ed558ccd);
            fingerprint ^= fingerprint >> 33u;
            first_position = (size_t)(fingerprint & UINT64_C(255));
            second_position =
                (size_t)((fingerprint >> 32u) & UINT64_C(255));
            first_bit = UINT64_C(1) << (first_position & 63u);
            second_bit = UINT64_C(1) << (second_position & 63u);
            if ((first[first_position >> 6u] & first_bit) != 0u &&
                (second[second_position >> 6u] & second_bit) != 0u) {
                collision = true;
                break;
            }
            first[first_position >> 6u] |= first_bit;
            second[second_position >> 6u] |= second_bit;
        }
        iterator->raw_keys_unique = !collision;
    }
}

static void
fb_effective_object_iter_reset(fb_effective_object_iter *iterator)
{
    iterator->raw = yyjson_obj_iter_with(iterator->raw.obj);
    iterator->duplicate_count = 0u;
    iterator->duplicate_overflow = false;
    iterator->work_count = 0u;
}

/*
 * json.loads keeps a duplicate key at its first insertion position but uses
 * the final value.  yyjson exposes raw pairs, so skip later duplicate slots
 * and substitute the final value when visiting the first slot.
 */
static bool
fb_effective_object_iter_next(
    fb_effective_object_iter *iterator,
    fb_slice *key_out,
    const yyjson_val **value_out
)
{
    yyjson_val *key;

    if (iterator->raw_keys_unique) {
        if ((++iterator->work_count &
             (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
            fb_parser_poll_cancel(iterator->parser)) {
            return false;
        }
        key = yyjson_obj_iter_next(&iterator->raw);
        if (key == NULL) {
            return false;
        }
        *key_out = fb_slice_make(yyjson_get_str(key), yyjson_get_len(key));
        *value_out = yyjson_obj_iter_get_val(key);
        return true;
    }

    while ((key = yyjson_obj_iter_next(&iterator->raw)) != NULL) {
        const char *key_text = yyjson_get_str(key);
        size_t key_length = yyjson_get_len(key);
        size_t current = iterator->raw.idx - 1u;
        const yyjson_val *raw_value = yyjson_obj_iter_get_val(key);
        const yyjson_val *final_value;
        bool seen = false;
        size_t index;

        if ((++iterator->work_count &
             (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
            fb_parser_poll_cancel(iterator->parser)) {
            return false;
        }

        for (index = 0u; index < iterator->duplicate_count; ++index) {
            const yyjson_val *duplicate = iterator->duplicate_keys[index];
            if (yyjson_get_len(duplicate) == key_length &&
                (key_length == 0u ||
                 memcmp(
                     yyjson_get_str(duplicate),
                     key_text,
                     key_length) == 0)) {
                seen = true;
                break;
            }
        }
        if (seen) {
            continue;
        }
        *key_out = fb_slice_make(key_text, key_length);
        final_value =
            fb_json_object_get_last(iterator->raw.obj, *key_out);
        if (raw_value != final_value) {
            if (iterator->duplicate_count <
                FB_ARRAY_LEN(iterator->duplicate_keys)) {
                iterator->duplicate_keys[
                    iterator->duplicate_count++] = key;
            } else {
                yyjson_obj_iter preceding =
                    yyjson_obj_iter_with(iterator->raw.obj);
                iterator->duplicate_overflow = true;
                for (index = 0u; index < current; ++index) {
                    if ((++iterator->work_count &
                         (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                        fb_parser_poll_cancel(iterator->parser)) {
                        return false;
                    }
                    yyjson_val *earlier =
                        yyjson_obj_iter_next(&preceding);
                    if (earlier == NULL) {
                        break;
                    }
                    if (yyjson_get_len(earlier) == key_length &&
                        (key_length == 0u ||
                         memcmp(
                             yyjson_get_str(earlier),
                             key_text,
                             key_length) == 0)) {
                        seen = true;
                        break;
                    }
                }
                if (seen) {
                    continue;
                }
            }
        } else if (iterator->duplicate_overflow) {
            yyjson_obj_iter preceding =
                yyjson_obj_iter_with(iterator->raw.obj);
            for (index = 0u; index < current; ++index) {
                if ((++iterator->work_count &
                     (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                    fb_parser_poll_cancel(iterator->parser)) {
                    return false;
                }
                yyjson_val *earlier =
                    yyjson_obj_iter_next(&preceding);
                if (earlier == NULL) {
                    break;
                }
                if (yyjson_get_len(earlier) == key_length &&
                    (key_length == 0u ||
                     memcmp(
                         yyjson_get_str(earlier),
                         key_text,
                         key_length) == 0)) {
                    seen = true;
                    break;
                }
            }
            if (seen) {
                continue;
            }
        }
        *value_out = final_value;
        return true;
    }
    return false;
}

/* Exact Jq.enumerate object order: object, list children, object children. */
static const yyjson_val *
fb_object_walk_next(fb_object_walk *walk)
{
    while (walk != NULL && walk->depth != 0u && !walk->overflow) {
        if ((++walk->work_count & (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
            fb_parser_poll_cancel(walk->parser)) {
            return NULL;
        }
        fb_walk_frame *frame = &walk->frames[walk->depth - 1u];

        if (frame->phase == FB_WALK_ENTER) {
            if (yyjson_is_obj(frame->value)) {
                frame->phase = FB_WALK_OBJECT_ARRAYS;
                fb_effective_object_iter_init(
                    &frame->iterator.object, frame->value, walk->parser);
                return frame->value;
            }
            if (yyjson_is_arr(frame->value)) {
                frame->phase = FB_WALK_ARRAY_OBJECTS;
                frame->iterator.array = yyjson_arr_iter_with(frame->value);
                continue;
            }
            walk->depth--;
            continue;
        }
        if (frame->phase == FB_WALK_OBJECT_ARRAYS) {
            fb_slice key;
            const yyjson_val *value = NULL;
            while (fb_effective_object_iter_next(
                       &frame->iterator.object, &key, &value)) {
                if (yyjson_is_arr(value)) {
                    fb_walk_push(walk, value);
                    break;
                }
            }
            if (value != NULL && yyjson_is_arr(value)) {
                continue;
            }
            frame->phase = FB_WALK_OBJECT_OBJECTS;
            fb_effective_object_iter_reset(&frame->iterator.object);
            continue;
        }
        if (frame->phase == FB_WALK_OBJECT_OBJECTS) {
            fb_slice key;
            const yyjson_val *value = NULL;
            while (fb_effective_object_iter_next(
                       &frame->iterator.object, &key, &value)) {
                if (yyjson_is_obj(value)) {
                    fb_walk_push(walk, value);
                    break;
                }
            }
            if (value != NULL && yyjson_is_obj(value)) {
                continue;
            }
            walk->depth--;
            continue;
        }
        if (frame->phase == FB_WALK_ARRAY_OBJECTS) {
            yyjson_val *value;
            while ((value = yyjson_arr_iter_next(&frame->iterator.array)) != NULL) {
                if ((++walk->work_count &
                     (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                    fb_parser_poll_cancel(walk->parser)) {
                    return NULL;
                }
                if (yyjson_is_obj(value)) {
                    fb_walk_push(walk, value);
                    break;
                }
            }
            if (value != NULL) {
                continue;
            }
            frame->phase = FB_WALK_ARRAY_ARRAYS;
            frame->iterator.array = yyjson_arr_iter_with(frame->value);
            continue;
        }
        {
            yyjson_val *value;
            while ((value = yyjson_arr_iter_next(&frame->iterator.array)) != NULL) {
                if ((++walk->work_count &
                     (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                    fb_parser_poll_cancel(walk->parser)) {
                    return NULL;
                }
                if (yyjson_is_arr(value)) {
                    fb_walk_push(walk, value);
                    break;
                }
            }
            if (value != NULL) {
                continue;
            }
            walk->depth--;
        }
    }
    return NULL;
}

static fb_slice
fb_json_string(const yyjson_val *value)
{
    const char *text;

    if (!yyjson_is_str(value)) {
        return fb_slice_make(NULL, 0u);
    }
    text = yyjson_get_str(value);
    return fb_slice_make(text, yyjson_get_len(value));
}

static bool
fb_json_truthy(const yyjson_val *value)
{
    if (value == NULL || yyjson_is_null(value)) {
        return false;
    }
    if (yyjson_is_str(value) || yyjson_is_arr(value) || yyjson_is_obj(value)) {
        return yyjson_get_len(value) != 0u;
    }
    if (yyjson_is_bool(value)) {
        return yyjson_get_bool(value);
    }
    if (yyjson_is_num(value)) {
        return yyjson_get_num(value) != 0.0;
    }
    return true;
}

static const yyjson_val *
fb_object_get(const yyjson_val *object, const char *key)
{
    return fb_json_object_get_last(object, fb_slice_from_cstr(key));
}

typedef fb_json_document_match_cursor fb_document_key_cursor;
typedef fb_json_block_match_cursor fb_block_key_cursor;

static void
fb_document_key_cursor_init(
    fb_document_key_cursor *cursor,
    const fb_document *document,
    const char *key
)
{
    fb_json_document_match_cursor_init(
        cursor,
        document,
        fb_slice_from_cstr(key)
    );
}

static bool
fb_document_key_cursor_next(
    fb_document_key_cursor *cursor,
    fb_json_match *out
)
{
    return fb_json_document_match_cursor_next(cursor, out);
}

static void
fb_block_key_cursor_init(
    fb_block_key_cursor *cursor,
    const fb_json_block *block,
    const char *key
)
{
    fb_json_block_match_cursor_init(
        cursor,
        block,
        fb_slice_from_cstr(key)
    );
}

static bool
fb_block_key_cursor_next(
    fb_block_key_cursor *cursor,
    fb_json_match *out
)
{
    return fb_json_block_match_cursor_next(cursor, out);
}

static const yyjson_val *
fb_subtree_first(
    fb_parser *parser,
    const yyjson_val *root,
    const char *key
)
{
    fb_object_walk walk;
    const yyjson_val *object;

    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        const yyjson_val *value = fb_object_get(object, key);
        if (value != NULL) {
            fb_object_walk_destroy(&walk);
            return value;
        }
    }
    fb_object_walk_destroy(&walk);
    return NULL;
}

static bool
fb_subtree_has(fb_parser *parser, const yyjson_val *root, const char *key)
{
    return fb_subtree_first(parser, root, key) != NULL;
}

static bool
fb_scalar_matches_ids(const yyjson_val *value, const fb_id_set *ids)
{
    char number[32];
    int length;
    fb_slice candidate;

    if (ids == NULL || ids->len == 0u || value == NULL) {
        return false;
    }
    if (yyjson_is_str(value)) {
        return fb_id_set_find(ids, fb_json_string(value), NULL);
    }
    if (yyjson_is_uint(value)) {
        length = snprintf(number, sizeof(number), "%" PRIu64,
                          yyjson_get_uint(value));
    } else if (yyjson_is_sint(value)) {
        length = snprintf(number, sizeof(number), "%" PRId64,
                          yyjson_get_sint(value));
    } else {
        return false;
    }
    if (length <= 0 || (size_t)length >= sizeof(number)) {
        return false;
    }
    candidate = fb_slice_make(number, (size_t)length);
    return fb_id_set_find(ids, candidate, NULL);
}

static bool fb_ascii_digits(fb_slice value);
static bool fb_base64_syntax_valid(fb_slice value);

static bool
fb_scalar_decoded_matches_ids(const yyjson_val *value, const fb_id_set *ids)
{
    unsigned char encoded[1024];
    unsigned char decoded[1024];
    fb_slice text;
    size_t padded;
    int decoded_length;
    size_t decoded_size;

    if (!yyjson_is_str(value) || ids == NULL || ids->len == 0u) {
        return false;
    }
    text = fb_json_string(value);
    if (!fb_base64_syntax_valid(text) || text.len > sizeof(encoded) - 3u) {
        return false;
    }
    padded = (text.len + 3u) & ~(size_t)3u;
    memcpy(encoded, text.ptr, text.len);
    memset(encoded + text.len, '=', padded - text.len);
    decoded_length = fb_base64_decode_block(decoded, encoded, padded);
    if (decoded_length < 0) {
        return false;
    }
    decoded_size = (size_t)decoded_length;
    while (padded != 0u && encoded[padded - 1u] == '=' && decoded_size != 0u) {
        --padded;
        --decoded_size;
    }
    for (size_t id_index = 0u; id_index < ids->len; ++id_index) {
        const fb_slice id = ids->items[id_index];
        if (id.len == decoded_size &&
            memcmp(decoded, id.ptr, id.len) == 0) {
            return true;
        }
        if (!fb_ascii_digits(id) || id.len > decoded_size) {
            continue;
        }
        for (size_t offset = 0u; offset + id.len <= decoded_size; ++offset) {
            const bool left_alphanumeric = offset != 0u &&
                ((decoded[offset - 1u] >= 'A' && decoded[offset - 1u] <= 'Z') ||
                 (decoded[offset - 1u] >= 'a' && decoded[offset - 1u] <= 'z') ||
                 (decoded[offset - 1u] >= '0' && decoded[offset - 1u] <= '9'));
            const bool right_alphanumeric = offset + id.len < decoded_size &&
                ((decoded[offset + id.len] >= 'A' && decoded[offset + id.len] <= 'Z') ||
                 (decoded[offset + id.len] >= 'a' && decoded[offset + id.len] <= 'z') ||
                 (decoded[offset + id.len] >= '0' && decoded[offset + id.len] <= '9'));
            if (!left_alphanumeric && !right_alphanumeric &&
                memcmp(decoded + offset, id.ptr, id.len) == 0) {
                return true;
            }
        }
    }
    return false;
}

static bool
fb_identity_key(fb_slice key)
{
    static const char *const keys[] = {
        "id", "video_id", "videoid", "post_id", "postid",
        "story_fbid", "storyfbid", "story_id", "storyid", "fbid",
        "legacy_fbid", "top_level_post_id", "mf_story_key", "feedback_id"
    };
    size_t index;

    for (index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
        if (fb_slice_equal_literal_ascii_case(key, keys[index])) {
            return true;
        }
    }
    return false;
}

static bool
fb_identity_url_key(fb_slice key)
{
    static const char *const keys[] = {
        "url", "wwwurl", "permalink", "permalink_url", "shareable_url",
        "canonical_url"
    };
    size_t index;

    for (index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
        if (fb_slice_equal_literal_ascii_case(key, keys[index])) {
            return true;
        }
    }
    return false;
}

static bool
fb_url_ids_intersect(fb_parser *parser, fb_slice url, const fb_id_set *ids)
{
    fb_requested_ids parsed;
    static const char *const markers[] = {
        "/posts/", "/videos/", "/reel/", "/watch/", "/v/",
        "/permalink/", "/photos/", "story_fbid=", "fbid=", "v=",
        "multi_permalinks=", "post_id="
    };
    bool plausible = false;
    size_t marker_index;

    if (ids == NULL || ids->len == 0u) {
        return false;
    }
    for (marker_index = 0u;
         marker_index < FB_ARRAY_LEN(markers);
         ++marker_index) {
        if (fb_slice_contains_literal_ascii_case(
                url, markers[marker_index])) {
            plausible = true;
            break;
        }
    }
    if (!plausible ||
        fb_url_requested_ids(parser->arena, url, &parsed) != FB_URL_OK) {
        return false;
    }
    for (marker_index = 0u; marker_index < parsed.len; ++marker_index) {
        if (fb_id_set_find(ids, fb_requested_id_at(&parsed, marker_index), NULL)) {
            return true;
        }
    }
    return false;
}

static bool
fb_direct_contains_exact_id(
    fb_parser *parser,
    const yyjson_val *object,
    const fb_id_set *ids
)
{
    fb_effective_object_iter iterator;
    fb_slice key_text;
    const yyjson_val *value;

    if (!yyjson_is_obj(object) || ids == NULL || ids->len == 0u) {
        return false;
    }
    fb_effective_object_iter_init(&iterator, object, parser);
    while (fb_effective_object_iter_next(
               &iterator, &key_text, &value)) {
        if (!fb_identity_key(key_text)) {
            continue;
        }
        if (fb_scalar_matches_ids(value, ids)) {
            return true;
        }
        if (yyjson_is_arr(value)) {
            yyjson_arr_iter array = yyjson_arr_iter_with(value);
            yyjson_val *part;
            while ((part = yyjson_arr_iter_next(&array)) != NULL) {
                if (fb_scalar_matches_ids(part, ids)) {
                    return true;
                }
            }
        }
    }
    return false;
}

static bool
fb_subtree_contains_exact_id(
    fb_parser *parser,
    const yyjson_val *root,
    const fb_id_set *ids
)
{
    fb_object_walk walk;
    const yyjson_val *object;
    bool cached;

    if (fb_identity_memo_lookup(parser, root, ids, 1u, &cached)) {
        return cached;
    }
    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        if (fb_direct_contains_exact_id(parser, object, ids)) {
            fb_object_walk_destroy(&walk);
            fb_identity_memo_store(parser, root, ids, 1u, true);
            return true;
        }
    }
    fb_object_walk_destroy(&walk);
    fb_identity_memo_store(parser, root, ids, 1u, false);
    return false;
}

static bool
fb_subtree_contains_target_id(
    fb_parser *parser,
    const yyjson_val *root,
    const fb_id_set *ids
)
{
    fb_object_walk walk;
    const yyjson_val *object;
    bool cached;

    if (ids == NULL || ids->len == 0u) {
        return false;
    }
    if (fb_identity_memo_lookup(parser, root, ids, 2u, &cached)) {
        return cached;
    }
    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        fb_effective_object_iter iterator;
        fb_slice key_text;
        const yyjson_val *value;
        if (fb_direct_contains_exact_id(parser, object, ids)) {
            fb_object_walk_destroy(&walk);
            fb_identity_memo_store(parser, root, ids, 2u, true);
            return true;
        }
        fb_effective_object_iter_init(&iterator, object, parser);
        while (fb_effective_object_iter_next(
                   &iterator, &key_text, &value)) {
            if (fb_identity_url_key(key_text) &&
                yyjson_is_str(value) &&
                fb_url_ids_intersect(parser, fb_json_string(value), ids)) {
                fb_object_walk_destroy(&walk);
                fb_identity_memo_store(parser, root, ids, 2u, true);
                return true;
            }
        }
    }
    fb_object_walk_destroy(&walk);
    fb_identity_memo_store(parser, root, ids, 2u, false);
    return false;
}

static bool
fb_id_set_add_scalar(fb_parser *parser, fb_id_set *set, const yyjson_val *value)
{
    fb_slice number;

    if (value == NULL) {
        return true;
    }
    if (yyjson_is_str(value)) {
        return fb_id_set_add(set, fb_json_string(value));
    }
    if (yyjson_is_uint(value)) {
        number = fb_arena_format(parser->arena, "%" PRIu64,
                                 yyjson_get_uint(value));
    } else if (yyjson_is_sint(value)) {
        number = fb_arena_format(parser->arena, "%" PRId64,
                                 yyjson_get_sint(value));
    } else {
        return true;
    }
    return number.ptr != NULL && fb_id_set_add(set, number);
}

static bool
fb_collect_direct_identity_ids(
    fb_parser *parser,
    const yyjson_val *object,
    fb_id_set *set,
    bool include_urls
)
{
    fb_effective_object_iter iterator;
    fb_slice key_text;
    const yyjson_val *value;

    if (!yyjson_is_obj(object)) {
        return true;
    }
    fb_effective_object_iter_init(&iterator, object, parser);
    while (fb_effective_object_iter_next(
               &iterator, &key_text, &value)) {
        if (fb_identity_key(key_text)) {
            if (!fb_id_set_add_scalar(parser, set, value)) {
                return false;
            }
            if (yyjson_is_arr(value)) {
                yyjson_arr_iter array = yyjson_arr_iter_with(value);
                yyjson_val *part;
                while ((part = yyjson_arr_iter_next(&array)) != NULL) {
                    if (!fb_id_set_add_scalar(parser, set, part)) {
                        return false;
                    }
                }
            }
        } else if (include_urls && fb_identity_url_key(key_text) &&
                   yyjson_is_str(value)) {
            fb_id_set url_ids;
            if (!fb_id_set_from_url(parser, fb_json_string(value), &url_ids) ||
                !fb_id_set_add_set(set, &url_ids)) {
                return false;
            }
        }
    }
    return true;
}

static fb_slice
fb_direct_video_url(const yyjson_val *object)
{
    static const char *const keys[] = {
        "browser_native_hd_url", "browser_native_sd_url"
    };
    const yyjson_val *legacy;
    size_t index;

    if (!yyjson_is_obj(object)) {
        return fb_slice_make(NULL, 0u);
    }
    for (index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
        const yyjson_val *value = fb_object_get(object, keys[index]);
        if (yyjson_is_str(value) &&
            fb_url_is_safe_media(fb_json_string(value))) {
            return fb_json_string(value);
        }
    }
    legacy = fb_object_get(object, "videoDeliveryLegacyFields");
    if (yyjson_is_obj(legacy)) {
        for (index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
            const yyjson_val *value = fb_object_get(legacy, keys[index]);
            if (yyjson_is_str(value) &&
                fb_url_is_safe_media(fb_json_string(value))) {
                return fb_json_string(value);
            }
        }
    }
    return fb_slice_make(NULL, 0u);
}

static bool
fb_video_node_matches(
    fb_parser *parser,
    const yyjson_val *object,
    const fb_id_set *ids
)
{
    static const char *const keys[] = {"id", "video_id", "videoid"};
    const yyjson_val *legacy;
    size_t index;
    (void)parser;

    if (!yyjson_is_obj(object) || ids == NULL || ids->len == 0u) {
        return false;
    }
    for (index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
        if (fb_scalar_matches_ids(fb_object_get(object, keys[index]), ids)) {
            return true;
        }
    }
    legacy = fb_object_get(object, "videoDeliveryLegacyFields");
    if (yyjson_is_obj(legacy)) {
        for (index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
            if (fb_scalar_matches_ids(
                    fb_object_get(legacy, keys[index]), ids)) {
                return true;
            }
        }
    }
    return false;
}

static bool
fb_direct_video_ids_equal_single(
    const yyjson_val *object,
    fb_slice expected
)
{
    static const char *const keys[] = {"id", "video_id", "videoid"};
    const yyjson_val *containers[2];
    bool saw = false;
    size_t container_index;

    if (!yyjson_is_obj(object)) {
        return false;
    }
    containers[0] = object;
    containers[1] = fb_object_get(object, "videoDeliveryLegacyFields");
    for (container_index = 0u;
         container_index < FB_ARRAY_LEN(containers);
         ++container_index) {
        size_t key_index;
        if (!yyjson_is_obj(containers[container_index])) {
            continue;
        }
        for (key_index = 0u; key_index < FB_ARRAY_LEN(keys); ++key_index) {
            const yyjson_val *value =
                fb_object_get(containers[container_index], keys[key_index]);
            char number[32];
            fb_slice actual;
            int length;
            if (value == NULL ||
                (!yyjson_is_str(value) && !yyjson_is_int(value))) {
                continue;
            }
            if (yyjson_is_str(value)) {
                actual = fb_json_string(value);
            } else if (yyjson_is_uint(value)) {
                length = snprintf(
                    number, sizeof(number), "%" PRIu64,
                    yyjson_get_uint(value));
                if (length <= 0 || (size_t)length >= sizeof(number)) {
                    return false;
                }
                actual = fb_slice_make(number, (size_t)length);
            } else {
                length = snprintf(
                    number, sizeof(number), "%" PRId64,
                    yyjson_get_sint(value));
                if (length <= 0 || (size_t)length >= sizeof(number)) {
                    return false;
                }
                actual = fb_slice_make(number, (size_t)length);
            }
            saw = true;
            if (!fb_slice_equal(actual, expected)) {
                return false;
            }
        }
    }
    return saw;
}

static fb_attempt
fb_attempt_success(const fb_post *post)
{
    fb_attempt attempt;

    memset(&attempt, 0, sizeof(attempt));
    attempt.ok = true;
    attempt.post = *post;
    return attempt;
}

static fb_attempt
fb_attempt_error(
    fb_parse_error_kind kind,
    fb_slice reason,
    fb_slice detail,
    fb_upstream_response *response,
    bool terminal,
    bool count_as_error,
    bool document_evidence
)
{
    fb_attempt attempt;

    memset(&attempt, 0, sizeof(attempt));
    attempt.error.kind = kind;
    attempt.error.reason = reason;
    attempt.error.detail = detail;
    attempt.error.upstream_response = response;
    attempt.error.terminal = terminal;
    attempt.error.count_as_error = count_as_error;
    attempt.has_document_evidence = document_evidence;
    return attempt;
}

static fb_attempt
fb_error_static(
    fb_parse_error_kind kind,
    fb_slice reason,
    const char *detail,
    fb_upstream_response *response,
    bool terminal
)
{
    return fb_attempt_error(
        kind,
        reason,
        fb_slice_from_cstr(detail),
        response,
        terminal,
        false,
        response != NULL && response->body.len != 0u
    );
}

static fb_attempt
fb_no_memory(void)
{
    return fb_error_static(
        FB_PARSE_ERROR_NO_MEMORY,
        FB_REASON_NO_MEMORY,
        "cannot allocate parser request state",
        NULL,
        true
    );
}

static fb_attempt
fb_cancelled(void)
{
    return fb_attempt_error(
        FB_PARSE_ERROR_CANCELLED,
        FB_REASON_CANCELLED,
        FB_SLICE_LIT("request cancelled"),
        NULL,
        true,
        false,
        false
    );
}

static bool
fb_error_is_specific_no_data(const fb_attempt *attempt)
{
    return attempt != NULL &&
           attempt->error.kind == FB_PARSE_ERROR_NO_DATA &&
           !fb_slice_equal(attempt->error.reason, FB_REASON_NO_DATA);
}

static bool
fb_allow_route_fallback(const fb_attempt *attempt)
{
    long status;

    if (attempt == NULL || attempt->ok ||
        attempt->error.kind == FB_PARSE_ERROR_UNSUPPORTED_ROUTE ||
        attempt->error.kind == FB_PARSE_ERROR_SHARE_RESOLUTION ||
        attempt->error.kind == FB_PARSE_ERROR_NO_MEMORY ||
        attempt->error.kind == FB_PARSE_ERROR_INVALID_ARGUMENT ||
        attempt->error.kind == FB_PARSE_ERROR_CANCELLED ||
        (attempt->error.kind == FB_PARSE_ERROR_NO_DATA &&
         attempt->error.terminal)) {
        return false;
    }
    if (attempt->error.kind != FB_PARSE_ERROR_UPSTREAM) {
        return true;
    }
    if (attempt->error.upstream_response == NULL) {
        return false;
    }
    status = attempt->error.upstream_response->status;
    return status == 403 || status == 404 || status == 500 || status == 502 ||
           status == 503 || status == 504;
}

static bool
fb_allow_parser_fallback(const fb_attempt *attempt)
{
    return attempt != NULL && !attempt->ok &&
           (attempt->error.kind == FB_PARSE_ERROR_DOCUMENT ||
            (attempt->error.kind == FB_PARSE_ERROR_NO_DATA &&
             !attempt->error.terminal));
}

static fb_attempt
fb_prefer_error(fb_attempt first, fb_attempt second)
{
    if (first.error.kind == FB_PARSE_ERROR_CANCELLED) {
        return first;
    }
    if (second.error.kind == FB_PARSE_ERROR_CANCELLED) {
        return second;
    }
    if (first.error.kind == FB_PARSE_ERROR_UNSUPPORTED_ROUTE) {
        return first;
    }
    if (second.error.kind == FB_PARSE_ERROR_UNSUPPORTED_ROUTE) {
        return second;
    }
    if (fb_error_is_specific_no_data(&first)) {
        return first;
    }
    if (fb_error_is_specific_no_data(&second)) {
        return second;
    }
    if (second.error.kind == FB_PARSE_ERROR_DOCUMENT &&
        second.has_document_evidence) {
        return second;
    }
    if (first.error.kind == FB_PARSE_ERROR_DOCUMENT &&
        first.has_document_evidence) {
        return first;
    }
    return second;
}

const char *
fb_parse_error_kind_string(fb_parse_error_kind kind)
{
    switch (kind) {
    case FB_PARSE_ERROR_NONE:
        return "none";
    case FB_PARSE_ERROR_NO_DATA:
        return "no_data";
    case FB_PARSE_ERROR_UNSUPPORTED_ROUTE:
        return "unsupported_route";
    case FB_PARSE_ERROR_SHARE_RESOLUTION:
        return "share_resolution";
    case FB_PARSE_ERROR_DOCUMENT:
        return "document";
    case FB_PARSE_ERROR_UPSTREAM:
        return "upstream";
    case FB_PARSE_ERROR_NO_MEMORY:
        return "no_memory";
    case FB_PARSE_ERROR_INVALID_ARGUMENT:
        return "invalid_argument";
    case FB_PARSE_ERROR_CANCELLED:
        return "cancelled";
    default:
        return "unknown";
    }
}

static bool
fb_status_retries(long status)
{
    return status == 429 || status == 500 || status == 502 || status == 503 ||
           status == 504;
}

static bool
fb_route_name_is(const yyjson_val *route, const char *name)
{
    const yyjson_val *value = fb_object_get(route, "canonicalRouteName");
    return yyjson_is_str(value) &&
           fb_slice_equal_literal(fb_json_string(value), name);
}

static bool
fb_document_has_route(const fb_document *document, const char *name)
{
    size_t index;

    for (index = 0u; index < fb_document_initial_route_count(document); ++index) {
        const fb_json_node_ref *reference =
            fb_document_initial_route_at(document, index);
        if (reference != NULL && fb_route_name_is(reference->value, name)) {
            return true;
        }
    }
    return false;
}

static fb_slice
fb_value_text(fb_parser *parser, const yyjson_val *value)
{
    if (yyjson_is_str(value)) {
        return fb_json_string(value);
    }
    if (yyjson_is_uint(value)) {
        return fb_arena_format(parser->arena, "%" PRIu64,
                               yyjson_get_uint(value));
    }
    if (yyjson_is_sint(value)) {
        return fb_arena_format(parser->arena, "%" PRId64,
                               yyjson_get_sint(value));
    }
    return fb_slice_make(NULL, 0u);
}

static bool
fb_collect_url_ids(fb_parser *parser, fb_slice url, fb_id_set *destination)
{
    fb_id_set source;
    return fb_id_set_from_url(parser, url, &source) &&
           fb_id_set_add_set(destination, &source);
}

static bool
fb_set_is_singleton_value(const fb_id_set *set, fb_slice value)
{
    return set != NULL && set->len == 1u &&
           fb_slice_equal(set->items[0], value);
}

static fb_slice
fb_url_path_only(fb_slice url)
{
    fb_url_view parsed;
    if (fb_url_parse(url, &parsed) != FB_URL_OK) {
        return fb_slice_make(NULL, 0u);
    }
    return parsed.path;
}

static fb_slice
fb_path_without_trailing_slash(fb_slice value)
{
    while (value.len != 0u && value.ptr[value.len - 1u] == '/') {
        value.len--;
    }
    return value;
}

static bool
fb_share_keys_equal(fb_parser *parser, fb_slice left, fb_slice right)
{
    fb_slice normalized_left;
    fb_slice normalized_right;
    fb_slice full_left;
    fb_slice full_right;

    if (fb_url_normalize_facebook_path(parser->arena, left, &normalized_left) !=
            FB_URL_OK ||
        fb_url_normalize_facebook_path(parser->arena, right, &normalized_right) !=
            FB_URL_OK ||
        fb_url_ensure_full(parser->arena, normalized_left, &full_left) !=
            FB_URL_OK ||
        fb_url_ensure_full(parser->arena, normalized_right, &full_right) !=
            FB_URL_OK) {
        return false;
    }
    return fb_slice_equal(
        fb_path_without_trailing_slash(fb_url_path_only(full_left)),
        fb_path_without_trailing_slash(fb_url_path_only(full_right))
    );
}

static bool
fb_declared_urls_consensus(
    fb_parser *parser,
    const fb_document *document,
    fb_declared_url_kind kind,
    fb_slice target_id
)
{
    size_t count = fb_document_declared_url_count(document, kind);
    size_t index;

    if (count == 0u) {
        return false;
    }
    for (index = 0u; index < count; ++index) {
        const fb_declared_url *declared =
            fb_document_declared_url_at(document, kind, index);
        fb_id_set ids;
        if (declared == NULL ||
            !fb_url_is_facebook(declared->value, true) ||
            !fb_id_set_from_url(parser, declared->value, &ids) ||
            !fb_set_is_singleton_value(&ids, target_id)) {
            return false;
        }
    }
    return true;
}

static bool
fb_has_target_video_delivery(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *ids
)
{
    size_t index;

    if (ids == NULL || ids->len == 0u) {
        return false;
    }
    for (index = 0u;
         index < fb_document_video_delivery_candidate_count(document);
         ++index) {
        const fb_json_node_ref *reference =
            fb_document_video_delivery_candidate_at(document, index);
        if (reference != NULL &&
            fb_direct_video_url(reference->value).ptr != NULL &&
            fb_video_node_matches(parser, reference->value, ids)) {
            return true;
        }
    }
    return false;
}

static bool
fb_has_bounded_target_payload(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *ids
)
{
    static const char *const content_keys[] = {
        "actors", "attachments", "comet_sections", "content", "message",
        "owner", "title", "image", "photo_image", "container_story",
        "attached_comment"
    };
    size_t block_index;

    if (ids == NULL || ids->len == 0u) {
        return false;
    }
    for (block_index = 0u;
         block_index < fb_document_json_block_count(document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(document, block_index);
        size_t rank;
        if (block == NULL) {
            continue;
        }
        for (rank = 0u; rank < fb_json_block_object_count(block); ++rank) {
            const yyjson_val *object = fb_json_block_object_at(block, rank);
            size_t key_index;
            if (object == NULL ||
                !fb_direct_contains_exact_id(parser, object, ids)) {
                continue;
            }
            if (fb_direct_video_url(object).ptr != NULL ||
                yyjson_is_obj(fb_object_get(object, "creation_story"))) {
                return true;
            }
            for (key_index = 0u;
                 key_index < FB_ARRAY_LEN(content_keys);
                 ++key_index) {
                if (fb_json_truthy(
                        fb_object_get(object, content_keys[key_index]))) {
                    return true;
                }
            }
        }
    }
    (void)parser;
    return false;
}

static bool
fb_route_collect_candidate_ids(
    fb_parser *parser,
    const yyjson_val *route,
    fb_id_set *candidate_ids,
    fb_id_set *route_url_ids,
    fb_id_set *route_param_ids
)
{
    static const char *const parameter_keys[] = {
        "story_token", "story_fbid", "fbid", "video_id", "v", "post_id"
    };
    static const char *const property_keys[] = {
        "storyID", "videoID", "postID"
    };
    const yyjson_val *route_url = fb_object_get(route, "url");
    const yyjson_val *params = fb_object_get(route, "params");
    size_t index;

    if (yyjson_is_str(route_url) &&
        (!fb_collect_url_ids(parser, fb_json_string(route_url), route_url_ids) ||
         !fb_id_set_add_set(candidate_ids, route_url_ids))) {
        return false;
    }
    if (yyjson_is_obj(params)) {
        for (index = 0u; index < FB_ARRAY_LEN(parameter_keys); ++index) {
            const yyjson_val *value =
                fb_object_get(params, parameter_keys[index]);
            if (!fb_id_set_add_scalar(parser, candidate_ids, value) ||
                !fb_id_set_add_scalar(parser, route_param_ids, value)) {
                return false;
            }
        }
    }
    for (index = 0u; index < 2u; ++index) {
        const yyjson_val *view =
            fb_object_get(route, index == 0u ? "rootView" : "hostableView");
        const yyjson_val *props = fb_object_get(view, "props");
        size_t property_index;
        if (!yyjson_is_obj(props)) {
            continue;
        }
        for (property_index = 0u;
             property_index < FB_ARRAY_LEN(property_keys);
             ++property_index) {
            if (!fb_id_set_add_scalar(
                    parser,
                    candidate_ids,
                    fb_object_get(props, property_keys[property_index]))) {
                return false;
            }
        }
    }
    return true;
}

static bool
fb_route_has_source_share(
    fb_parser *parser,
    const yyjson_val *route,
    fb_slice source_path
)
{
    const yyjson_val *params = fb_object_get(route, "params");
    const yyjson_val *share_url = fb_object_get(params, "share_url");
    const yyjson_val *route_url = fb_object_get(route, "url");
    fb_url_view parsed;
    fb_query query;
    size_t index;

    if (yyjson_is_str(share_url) &&
        fb_share_keys_equal(
            parser, source_path, fb_json_string(share_url))) {
        return true;
    }
    if (!yyjson_is_str(route_url) ||
        fb_url_parse(fb_json_string(route_url), &parsed) != FB_URL_OK ||
        !parsed.has_query ||
        fb_query_parse(parser->arena, parsed.query, false, &query) != FB_URL_OK) {
        return false;
    }
    for (index = 0u; index < query.len; ++index) {
        const fb_query_pair *pair = fb_query_at(&query, index);
        if (pair != NULL &&
            fb_slice_equal_literal(pair->key, "share_url") &&
            fb_share_keys_equal(parser, source_path, pair->value)) {
            return true;
        }
    }
    return false;
}

static bool
fb_media_links_source_to_target(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *raw_ids,
    fb_slice candidate_id
)
{
    fb_document_key_cursor cursor;
    fb_id_set candidate;

    if (!fb_id_set_init(&candidate, parser->arena) ||
        !fb_id_set_add(&candidate, candidate_id)) {
        return false;
    }
    fb_document_key_cursor_init(&cursor, document, "media");
    for (;;) {
        fb_json_match match;
        const yyjson_val *media;
        const yyjson_val *story;
        const yyjson_val *sections;
        const yyjson_val *title;
        const yyjson_val *title_story;
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (!yyjson_is_obj(match.value)) {
            continue;
        }
        media = match.value;
        if (!fb_video_node_matches(parser, media, &candidate)) {
            continue;
        }
        story = fb_object_get(media, "creation_story");
        sections = fb_object_get(story, "comet_sections");
        title = fb_object_get(sections, "title");
        title_story = fb_object_get(title, "story");
        if (yyjson_is_obj(title_story) &&
            fb_scalar_matches_ids(
                fb_object_get(title_story, "post_id"), raw_ids)) {
            return true;
        }
    }
    return false;
}

static bool
fb_response_redirect_proves_source(
    fb_parser *parser,
    const fb_upstream_response *response,
    const fb_id_set *raw_ids
)
{
    fb_id_set first_ids;
    const fb_redirect_hop *first;

    if (response == NULL || response->history_count == 0u ||
        raw_ids == NULL || raw_ids->len == 0u) {
        return false;
    }
    first = &response->history[0];
    return fb_url_is_facebook(first->effective_url, true) &&
           fb_slice_contains_literal_ascii_case(
               fb_url_path_only(first->effective_url), "/posts/") &&
           fb_id_set_from_url(parser, first->effective_url, &first_ids) &&
           fb_id_sets_intersect(&first_ids, raw_ids);
}

static bool
fb_get_target_ids(
    fb_parser *parser,
    const fb_document *document,
    fb_slice post_path,
    const fb_upstream_response *response,
    fb_id_set *selection_ids,
    fb_id_set *route_proven_ids
)
{
    fb_id_set raw_ids;
    fb_id_set response_ids;
    bool source_is_share = fb_url_is_share_path(post_path);
    bool used_post_to_video_alias = false;
    size_t route_index;

    if (!fb_id_set_from_url(parser, post_path, &raw_ids) ||
        !fb_id_set_init(route_proven_ids, parser->arena) ||
        !fb_id_set_init(selection_ids, parser->arena) ||
        !fb_id_set_init(&response_ids, parser->arena)) {
        return false;
    }
    if (response != NULL &&
        !fb_collect_url_ids(parser, response->url, &response_ids)) {
        return false;
    }

    for (route_index = 0u;
         route_index < fb_document_initial_route_count(document);
         ++route_index) {
        const fb_json_node_ref *reference =
            fb_document_initial_route_at(document, route_index);
        const yyjson_val *route;
        const yyjson_val *route_url_value;
        fb_slice route_name = fb_slice_make(NULL, 0u);
        fb_id_set candidates;
        fb_id_set route_url_ids;
        fb_id_set route_param_ids;
        bool route_matches;
        bool opaque_share;
        bool direct_loe_consensus = false;
        bool post_to_video_alias = false;
        fb_slice direct_loe_target = fb_slice_make(NULL, 0u);
        fb_slice final_video_id = fb_slice_make(NULL, 0u);

        if (reference == NULL || !yyjson_is_obj(reference->value) ||
            !fb_id_set_init(&candidates, parser->arena) ||
            !fb_id_set_init(&route_url_ids, parser->arena) ||
            !fb_id_set_init(&route_param_ids, parser->arena)) {
            return false;
        }
        route = reference->value;
        route_url_value = fb_object_get(route, "url");
        if (yyjson_is_str(fb_object_get(route, "canonicalRouteName"))) {
            route_name =
                fb_json_string(fb_object_get(route, "canonicalRouteName"));
        }
        if (!(
                fb_slice_equal_literal(
                    route_name, "comet.fbweb.CometSinglePostDialogRoute") ||
                fb_slice_equal_literal(
                    route_name, "comet.fbweb.CometGroupLoggedOutPermalinkRoute") ||
                fb_slice_equal_literal(
                    route_name, "comet.fbweb.CometFBReelsRoute") ||
                fb_slice_equal_literal(
                    route_name,
                    "comet.fbweb.CometVideoHomeLOEVideoPermalinkRoute") ||
                fb_slice_equal_literal(
                    route_name, "comet.fbweb.CometPhotoRoute") ||
                (yyjson_is_str(route_url_value) &&
                 fb_url_is_post_like_path(fb_json_string(route_url_value))))) {
            continue;
        }
        if (!fb_route_collect_candidate_ids(
                parser, route, &candidates, &route_url_ids,
                &route_param_ids)) {
            return false;
        }
        route_matches = raw_ids.len != 0u &&
                        fb_id_sets_intersect(&raw_ids, &candidates);
        opaque_share = source_is_share && raw_ids.len == 0u &&
                       candidates.len != 0u &&
                       fb_route_has_source_share(parser, route, post_path);

        if (fb_slice_equal_literal(
                route_name,
                "comet.fbweb.CometVideoHomeLOEVideoPermalinkRoute") &&
            route_url_ids.len == 1u &&
            fb_id_sets_equal(&route_url_ids, &route_param_ids)) {
            direct_loe_target = route_url_ids.items[0];
            direct_loe_consensus =
                fb_set_is_singleton_value(&raw_ids, direct_loe_target) &&
                (response == NULL ||
                 fb_url_is_facebook(response->url, true)) &&
                (response_ids.len == 0u ||
                 fb_set_is_singleton_value(
                     &response_ids, direct_loe_target)) &&
                fb_declared_urls_consensus(
                    parser, document, FB_DECLARED_URL_CANONICAL,
                    direct_loe_target) &&
                fb_declared_urls_consensus(
                    parser, document, FB_DECLARED_URL_OG_URL,
                    direct_loe_target);
            if (direct_loe_consensus) {
                fb_id_set direct;
                if (!fb_id_set_init(&direct, parser->arena) ||
                    !fb_id_set_add(&direct, direct_loe_target)) {
                    return false;
                }
                direct_loe_consensus =
                    fb_has_target_video_delivery(parser, document, &direct);
            }
        }
        if (fb_slice_equal_literal(
                route_name,
                "comet.fbweb.CometVideoHomeLOEVideoPermalinkRoute") &&
            route_matches && !direct_loe_consensus) {
            route_matches = false;
        }

        if (response_ids.len == 1u &&
            response_ids.items[0].len != 0u) {
            size_t character;
            bool digits = true;
            for (character = 0u;
                 character < response_ids.items[0].len;
                 ++character) {
                unsigned char byte =
                    (unsigned char)response_ids.items[0].ptr[character];
                if (byte < (unsigned char)'0' ||
                    byte > (unsigned char)'9') {
                    digits = false;
                    break;
                }
            }
            if (digits) {
                final_video_id = response_ids.items[0];
            }
        }
        if (!source_is_share && raw_ids.len != 0u &&
            fb_slice_contains_literal_ascii_case(
                fb_url_path_only(post_path), "/posts/") &&
            response != NULL && response->history_count != 0u &&
            fb_response_redirect_proves_source(parser, response, &raw_ids) &&
            fb_url_is_facebook(response->url, true) &&
            fb_slice_contains_literal_ascii_case(
                fb_url_path_only(response->url), "/videos/") &&
            fb_slice_equal_literal(
                route_name,
                "comet.fbweb.CometVideoHomeLOEVideoPermalinkRoute") &&
            final_video_id.ptr != NULL &&
            fb_set_is_singleton_value(&route_url_ids, final_video_id) &&
            fb_set_is_singleton_value(&route_param_ids, final_video_id) &&
            fb_declared_urls_consensus(
                parser, document, FB_DECLARED_URL_CANONICAL, final_video_id) &&
            fb_declared_urls_consensus(
                parser, document, FB_DECLARED_URL_OG_URL, final_video_id)) {
            fb_id_set final_set;
            bool raw_pfbids = true;
            size_t raw_index;
            for (raw_index = 0u; raw_index < raw_ids.len; ++raw_index) {
                if (!fb_slice_starts_literal_ascii_case(
                        raw_ids.items[raw_index], "pfbid")) {
                    raw_pfbids = false;
                    break;
                }
            }
            if (!fb_id_set_init(&final_set, parser->arena) ||
                !fb_id_set_add(&final_set, final_video_id)) {
                return false;
            }
            post_to_video_alias =
                fb_has_target_video_delivery(
                    parser, document, &final_set) &&
                (raw_pfbids ||
                 fb_media_links_source_to_target(
                     parser, document, &raw_ids, final_video_id));
        }

        if (!(route_matches || opaque_share || post_to_video_alias)) {
            continue;
        }
        if (post_to_video_alias) {
            used_post_to_video_alias = true;
            if (!fb_id_set_add(route_proven_ids, final_video_id)) {
                return false;
            }
        } else if (direct_loe_consensus) {
            if (!fb_id_set_add(route_proven_ids, direct_loe_target)) {
                return false;
            }
        } else if (!fb_id_set_add_set(route_proven_ids, &candidates)) {
            return false;
        }
    }

    if (!fb_id_set_add_set(selection_ids, route_proven_ids) ||
        (!used_post_to_video_alias &&
         !fb_id_set_add_set(selection_ids, &raw_ids))) {
        return false;
    }
    return true;
}

static bool
fb_private_group_surface(fb_parser *parser, const fb_document *document)
{
    fb_document_key_cursor cursor;

    fb_document_key_cursor_init(&cursor, document, "group");
    for (;;) {
        fb_json_match match;
        const yyjson_val *group;
        const yyjson_val *privacy;
        const yyjson_val *title;
        fb_slice viewer = fb_slice_make(NULL, 0u);
        fb_slice forum = fb_slice_make(NULL, 0u);
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (!yyjson_is_obj(match.value)) {
            continue;
        }
        group = match.value;
        if (yyjson_is_str(fb_object_get(group, "viewer_join_state"))) {
            viewer = fb_json_string(
                fb_object_get(group, "viewer_join_state"));
        }
        if (yyjson_is_str(
                fb_object_get(group, "viewer_forum_join_state"))) {
            forum = fb_json_string(
                fb_object_get(group, "viewer_forum_join_state"));
        }
        privacy = fb_object_get(group, "privacy_info");
        title = fb_subtree_first(parser, privacy, "text");
        if ((fb_slice_equal_literal(viewer, "CANNOT_JOIN") ||
             fb_slice_equal_literal(viewer, "CANNOT_JOIN_OR_REQUEST") ||
             fb_slice_equal_literal(forum, "CANNOT_JOIN") ||
             fb_slice_equal_literal(forum, "CANNOT_JOIN_OR_REQUEST")) &&
            yyjson_is_str(title) &&
            fb_slice_equal_literal(fb_json_string(title), "Private group")) {
            return true;
        }
    }
    return false;
}

static bool
fb_has_auth_route(const fb_document *document)
{
    static const char *const names[] = {
        "comet.fbweb.CometLoginRoute",
        "comet.fbweb.CometLoginPageRoute",
        "comet.fbweb.CometCheckpointRoute",
        "comet.fbweb.CometRecoveryRoute"
    };
    size_t index;
    for (index = 0u; index < FB_ARRAY_LEN(names); ++index) {
        if (fb_document_has_route(document, names[index])) {
            return true;
        }
    }
    return false;
}

static bool
fb_declared_urls_all_auth(const fb_document *document)
{
    size_t canonical =
        fb_document_declared_url_count(document, FB_DECLARED_URL_CANONICAL);
    size_t og =
        fb_document_declared_url_count(document, FB_DECLARED_URL_OG_URL);
    size_t index;

    if (canonical + og == 0u) {
        return false;
    }
    for (index = 0u; index < canonical; ++index) {
        const fb_declared_url *url = fb_document_declared_url_at(
            document, FB_DECLARED_URL_CANONICAL, index);
        if (url == NULL || !fb_url_is_auth_control_path(url->value)) {
            return false;
        }
    }
    for (index = 0u; index < og; ++index) {
        const fb_declared_url *url = fb_document_declared_url_at(
            document, FB_DECLARED_URL_OG_URL, index);
        if (url == NULL || !fb_url_is_auth_control_path(url->value)) {
            return false;
        }
    }
    return true;
}

static bool
fb_reel_complete_story(
    fb_parser *parser,
    const fb_document *document,
    fb_slice param_id
)
{
    fb_document_key_cursor cursor;
    fb_id_set expected;

    if (!fb_id_set_init(&expected, parser->arena) ||
        !fb_id_set_add(&expected, param_id)) {
        return false;
    }
    fb_document_key_cursor_init(&cursor, document, "creation_story");
    for (;;) {
        fb_json_match match;
        const yyjson_val *story;
        const yyjson_val *context;
        const yyjson_val *video;
        const yyjson_val *playback;
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (!yyjson_is_obj(match.value)) {
            continue;
        }
        story = match.value;
        if (!fb_scalar_matches_ids(fb_object_get(story, "post_id"), &expected)) {
            continue;
        }
        context = fb_object_get(story, "short_form_video_context");
        video = fb_object_get(context, "video");
        playback = fb_object_get(context, "playback_video");
        if (!yyjson_is_obj(context) || !yyjson_is_obj(video) ||
            !yyjson_is_obj(playback)) {
            continue;
        }
        if (fb_direct_video_ids_equal_single(video, param_id) &&
            fb_direct_video_ids_equal_single(playback, param_id) &&
            fb_direct_video_url(playback).ptr != NULL) {
            return true;
        }
    }
    return false;
}

static bool
fb_reel_consensus_id(
    fb_parser *parser,
    const fb_document *document,
    fb_slice post_path,
    const fb_upstream_response *response,
    fb_slice *out
)
{
    const yyjson_val *reel_route = NULL;
    size_t reel_count = 0u;
    size_t index;
    fb_id_set raw_ids;
    fb_id_set selected_ids;
    fb_id_set route_ids;
    fb_slice param_id;

    for (index = 0u; index < fb_document_initial_route_count(document); ++index) {
        const fb_json_node_ref *reference =
            fb_document_initial_route_at(document, index);
        if (reference != NULL &&
            fb_route_name_is(
                reference->value, "comet.fbweb.CometFBReelsRoute")) {
            reel_route = reference->value;
            reel_count++;
        }
    }
    if (reel_count != 1u ||
        !fb_id_set_from_url(parser, post_path, &raw_ids) ||
        !fb_id_set_init(&selected_ids, parser->arena) ||
        !fb_id_set_init(&route_ids, parser->arena)) {
        return false;
    }
    if (response != NULL &&
        !fb_collect_url_ids(parser, response->url, &selected_ids)) {
        return false;
    }
    {
        const yyjson_val *route_url = fb_object_get(reel_route, "url");
        const yyjson_val *params = fb_object_get(reel_route, "params");
        const yyjson_val *param = fb_object_get(params, "video_id");
        if (!yyjson_is_str(route_url) ||
            !fb_collect_url_ids(
                parser, fb_json_string(route_url), &route_ids)) {
            return false;
        }
        param_id = fb_value_text(parser, param);
    }
    if (param_id.ptr == NULL || param_id.len == 0u ||
        !fb_set_is_singleton_value(&route_ids, param_id) ||
        (raw_ids.len != 0u &&
         !fb_set_is_singleton_value(&raw_ids, param_id)) ||
        (selected_ids.len != 0u &&
         !fb_set_is_singleton_value(&selected_ids, param_id)) ||
        (raw_ids.len == 0u && selected_ids.len == 0u)) {
        return false;
    }
    if (fb_reel_complete_story(parser, document, param_id) ||
        (fb_declared_urls_consensus(
             parser, document, FB_DECLARED_URL_CANONICAL, param_id) &&
         fb_declared_urls_consensus(
             parser, document, FB_DECLARED_URL_OG_URL, param_id))) {
        *out = param_id;
        return true;
    }
    return false;
}

static void
fb_reel_content_state(
    fb_parser *parser,
    const fb_document *document,
    fb_slice reel_id,
    bool *has_context,
    bool *has_missing_stub
)
{
    fb_id_set expected;
    size_t block_index;

    *has_context = false;
    *has_missing_stub = false;
    if (reel_id.ptr == NULL ||
        !fb_id_set_init(&expected, parser->arena) ||
        !fb_id_set_add(&expected, reel_id)) {
        return;
    }
    for (block_index = 0u;
         block_index < fb_document_json_block_count(document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(document, block_index);
        size_t rank;
        if (block == NULL) {
            continue;
        }
        for (rank = 0u; rank < fb_json_block_object_count(block); ++rank) {
            const yyjson_val *object = fb_json_block_object_at(block, rank);
            const yyjson_val *creation;
            if (object == NULL) {
                continue;
            }
            if (yyjson_is_obj(fb_object_get(object, "short_form_video_context")) &&
                fb_subtree_contains_exact_id(parser, object, &expected)) {
                *has_context = true;
            }
            creation = fb_object_get(object, "creation_story");
            if (fb_video_node_matches(parser, object, &expected) &&
                creation != NULL && yyjson_is_null(creation)) {
                *has_missing_stub = true;
            }
            if (fb_subtree_contains_exact_id(parser, object, &expected) &&
                yyjson_is_obj(creation)) {
                *has_context = true;
            }
        }
    }
}

static fb_probe_kind
fb_probe_page(
    fb_parser *parser,
    const fb_document *document,
    fb_slice post_path,
    const fb_upstream_response *response
)
{
    fb_id_set raw_ids;
    fb_id_set target_ids;
    fb_id_set route_ids;
    fb_id_set response_ids;
    const fb_id_set *required;
    bool auth_wall;

    if (fb_document_has_route(
            document, "comet.fbweb.CometProfilePlusLoggedOutRoute") ||
        fb_document_has_route(
            document, "comet.fbweb.CometProfileLoggedOutRoute")) {
        return FB_PROBE_UNSUPPORTED_PROFILE;
    }
    if (fb_document_has_route(
            document, "comet.fbweb.CometMarketplaceHoistedPermalinkRoute")) {
        return FB_PROBE_UNSUPPORTED_MARKETPLACE;
    }
    if (fb_document_has_route(
            document, "comet.fbweb.CometProfileLegacyAlbumViewRoute")) {
        return FB_PROBE_UNSUPPORTED_MEDIA_SET;
    }
    if (!fb_id_set_from_url(parser, post_path, &raw_ids) ||
        !fb_id_set_init(&response_ids, parser->arena) ||
        (response != NULL &&
         !fb_collect_url_ids(
             parser, response->url, &response_ids)) ||
        !fb_get_target_ids(
            parser, document, post_path, response,
            &target_ids, &route_ids)) {
        return FB_PROBE_UNKNOWN;
    }
    required = route_ids.len != 0u
                   ? &route_ids
                   : (raw_ids.len != 0u ? &raw_ids : &target_ids);
    auth_wall =
        (response != NULL &&
         fb_url_is_auth_control_path(response->url)) ||
        fb_has_auth_route(document) ||
        fb_document_has_login_form(document) ||
        fb_declared_urls_all_auth(document);

    if (fb_document_has_route(
            document, "comet.fbweb.CometVideoHomeVideoNotFoundRoute")) {
        return FB_PROBE_TARGET_NOT_FOUND;
    }
    if (fb_document_has_route(
            document, "comet.fbweb.CometGroupAboutRoute")) {
        bool canonical_about = false;
        size_t index;
        for (index = 0u;
             index < fb_document_declared_url_count(
                         document, FB_DECLARED_URL_CANONICAL);
             ++index) {
            const fb_declared_url *declared = fb_document_declared_url_at(
                document, FB_DECLARED_URL_CANONICAL, index);
            fb_path_segments parts;
            if (declared != NULL &&
                fb_url_facebook_path_segments(
                    parser->arena, declared->value, &parts) == FB_URL_OK &&
                parts.len >= 3u &&
                fb_slice_equal_literal_ascii_case(
                    fb_path_segment_at(&parts, 0u), "groups") &&
                fb_slice_equal_literal_ascii_case(
                    fb_path_segment_at(&parts, parts.len - 1u), "about")) {
                canonical_about = true;
                break;
            }
        }
        if ((fb_url_is_post_like_path(post_path) ||
             (response != NULL &&
              fb_url_is_post_like_path(response->url))) &&
            canonical_about && fb_private_group_surface(parser, document) &&
            !fb_has_bounded_target_payload(parser, document, required)) {
            return FB_PROBE_PRIVATE_GROUP;
        }
    }
    if (fb_document_has_route(
            document,
            "comet.fbweb.CometVideoHomeLOEVideoPermalinkRoute") &&
        route_ids.len == 0u &&
        (raw_ids.len != 0u || fb_url_is_post_like_path(post_path))) {
        return FB_PROBE_TARGET_IDENTITY_MISMATCH;
    }
    if (fb_document_has_route(
            document, "comet.fbweb.CometFBReelsRoute")) {
        fb_slice reel_id = fb_slice_make(NULL, 0u);
        bool has_context = false;
        bool has_missing_stub = false;
        bool has_delivery = false;
        if (fb_reel_consensus_id(
                parser, document, post_path, response, &reel_id)) {
            fb_id_set reel;
            fb_reel_content_state(
                parser, document, reel_id,
                &has_context, &has_missing_stub);
            if (fb_id_set_init(&reel, parser->arena) &&
                fb_id_set_add(&reel, reel_id)) {
                has_delivery =
                    fb_has_target_video_delivery(parser, document, &reel);
            }
        }
        if (has_context && has_delivery) {
            return FB_PROBE_HAS_DATA;
        }
        if (auth_wall) {
            return FB_PROBE_LOGIN_WALL;
        }
        if (has_missing_stub && !has_context && !has_delivery) {
            return FB_PROBE_TARGET_VIDEO_MISSING;
        }
        if (reel_id.ptr == NULL &&
            fb_url_is_post_like_path(post_path) &&
            (route_ids.len != 0u || raw_ids.len != 0u ||
             response_ids.len != 0u)) {
            return FB_PROBE_TARGET_IDENTITY_MISMATCH;
        }
    }
    if (fb_has_bounded_target_payload(parser, document, required)) {
        return FB_PROBE_HAS_DATA;
    }
    if (auth_wall) {
        return FB_PROBE_LOGIN_WALL;
    }
    return FB_PROBE_UNKNOWN;
}

static fb_slice
fb_probe_reason(fb_probe_kind probe)
{
    switch (probe) {
    case FB_PROBE_HAS_DATA:
        return FB_SLICE_LIT("has_data");
    case FB_PROBE_UNKNOWN:
        return FB_SLICE_LIT("unknown");
    case FB_PROBE_NO_DATA:
        return FB_REASON_NO_DATA;
    case FB_PROBE_LOGIN_WALL:
        return FB_SLICE_LIT("login_wall");
    case FB_PROBE_TARGET_NOT_FOUND:
        return FB_SLICE_LIT("target_not_found");
    case FB_PROBE_TARGET_IDENTITY_MISMATCH:
        return FB_SLICE_LIT("target_identity_mismatch");
    case FB_PROBE_PRIVATE_GROUP:
        return FB_SLICE_LIT("private_group_post_unavailable");
    case FB_PROBE_TARGET_VIDEO_MISSING:
        return FB_SLICE_LIT("target_video_payload_missing");
    case FB_PROBE_UNSUPPORTED_PROFILE:
        return FB_SLICE_LIT("unsupported_profile_target");
    case FB_PROBE_UNSUPPORTED_MARKETPLACE:
        return FB_SLICE_LIT("unsupported_marketplace_target");
    case FB_PROBE_UNSUPPORTED_MEDIA_SET:
        return FB_SLICE_LIT("unsupported_media_set_target");
    default:
        return FB_REASON_NO_DATA;
    }
}

static fb_attempt
fb_probe_error(
    fb_probe_kind probe,
    fb_upstream_response *response
)
{
    if (probe == FB_PROBE_UNSUPPORTED_PROFILE) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            fb_probe_reason(probe),
            "Facebook share target is a profile rather than a post",
            response,
            true
        );
    }
    if (probe == FB_PROBE_UNSUPPORTED_MARKETPLACE) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            fb_probe_reason(probe),
            "Facebook share target is a Marketplace listing",
            response,
            true
        );
    }
    if (probe == FB_PROBE_UNSUPPORTED_MEDIA_SET) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            fb_probe_reason(probe),
            "Facebook share target is a media-set album",
            response,
            true
        );
    }
    return fb_error_static(
        FB_PARSE_ERROR_NO_DATA,
        fb_probe_reason(probe),
        "Facebook response did not contain usable target data",
        response,
        true
    );
}

static fb_attempt
fb_transport_error(
    fb_parser *parser,
    fb_transport_result transport
)
{
    fb_slice reason = FB_REASON_UPSTREAM;
    fb_slice detail = fb_arena_slice_dup(
        parser->arena, fb_slice_from_cstr(transport.detail));

    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }

    if (transport.code == FB_TRANSPORT_OUT_OF_MEMORY) {
        return fb_no_memory();
    }
    if (detail.ptr == NULL) {
        return fb_no_memory();
    }
    if ((transport.code == FB_TRANSPORT_HTTP_ERROR ||
         transport.code == FB_TRANSPORT_UNSAFE_REDIRECT ||
         transport.code == FB_TRANSPORT_REDIRECT_LOOP ||
         transport.code == FB_TRANSPORT_TOO_MANY_REDIRECTS) &&
        transport.response != NULL) {
        reason = fb_arena_format(
            parser->arena,
            "upstream_http_%ld",
            transport.response->status
        );
        if (reason.ptr == NULL) {
            return fb_no_memory();
        }
    } else if (transport.code == FB_TRANSPORT_CURL_ERROR ||
               transport.code == FB_TRANSPORT_IMPERSONATION_UNAVAILABLE) {
        reason = FB_REASON_TRANSPORT;
    }
    return fb_attempt_error(
        FB_PARSE_ERROR_UPSTREAM,
        reason,
        detail,
        transport.response,
        false,
        false,
        transport.response != NULL &&
            transport.response->body.len != 0u
    );
}

static fb_page *
fb_page_cache_find(
    fb_parser *parser,
    fb_slice path,
    fb_upstream_response *response
)
{
    size_t index;
    for (index = 0u; index < parser->page_count; ++index) {
        if (parser->pages[index].response == response &&
            fb_slice_equal(parser->pages[index].path, path)) {
            return &parser->pages[index];
        }
    }
    return NULL;
}

static fb_attempt
fb_page_load(
    fb_parser *parser,
    fb_slice path,
    fb_upstream_response *prefetched,
    fb_page **out
)
{
    fb_upstream_response *response = prefetched;
    fb_slice full_url;
    fb_document *document = NULL;
    fb_document_error document_error;
    fb_document_status document_status;
    fb_probe_kind probe;
    bool owns_response = prefetched == NULL;
    fb_page *cached;

    *out = NULL;
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    if (fb_url_ensure_full(parser->arena, path, &full_url) != FB_URL_OK) {
        return fb_no_memory();
    }
    if (response == NULL) {
        fb_transport_options options =
            fb_transport_default_options(FB_HTTP_GET);
        fb_transport_result transport;
        options.check_status = false;
        options.retry_status_responses = false;
        transport = fb_transport_request(
            parser->scope, full_url, &options);
        if (transport.code != FB_TRANSPORT_OK) {
            return fb_transport_error(parser, transport);
        }
        response = transport.response;
    }
    if (response == NULL) {
        return fb_error_static(
            FB_PARSE_ERROR_UPSTREAM,
            FB_REASON_TRANSPORT,
            "Facebook request returned no response",
            NULL,
            false
        );
    }
    fb_transport_select_response(parser->scope, response);
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    if (!fb_url_is_facebook(response->url, true)) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            FB_SLICE_LIT("offsite_redirect"),
            "Facebook redirected outside Facebook",
            response,
            true
        );
    }
    cached = fb_page_cache_find(parser, path, response);
    if (cached != NULL) {
        *out = cached;
        return (fb_attempt){.ok = true};
    }
    document_status = fb_document_parse_cancelable(
        parser->arena, response->body, NULL, parser->cancel,
        &document, &document_error);
    if (document_status != FB_DOCUMENT_OK) {
        if (document_status == FB_DOCUMENT_CANCELLED) {
            parser->cancelled = true;
            return fb_cancelled();
        }
        if (document_status == FB_DOCUMENT_NO_MEMORY) {
            return fb_no_memory();
        }
        fb_slice detail = fb_arena_format(
            parser->arena,
            "Facebook document parse failed: %s/%s at byte %zu",
            fb_document_status_string(document_status),
            fb_document_issue_string(document_error.issue),
            document_error.source_offset
        );
        if (detail.ptr == NULL) {
            return fb_no_memory();
        }
        return fb_attempt_error(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_DOCUMENT,
            detail,
            response,
            false,
            false,
            response->body.len != 0u
        );
    }
    probe = fb_probe_page(parser, document, path, response);
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    if (owns_response && fb_status_retries(response->status) &&
        probe != FB_PROBE_HAS_DATA) {
        fb_transport_options options =
            fb_transport_default_options(FB_HTTP_GET);
        fb_transport_result transport;
        options.check_status = false;
        options.retry_status_responses = false;
        options.bypass_cache = true;
        transport = fb_transport_request(
            parser->scope, full_url, &options);
        if (transport.code != FB_TRANSPORT_OK) {
            return fb_transport_error(parser, transport);
        }
        response = transport.response;
        fb_transport_select_response(parser->scope, response);
        if (fb_parser_poll_cancel(parser)) {
            return fb_cancelled();
        }
        if (response == NULL || !fb_url_is_facebook(response->url, true)) {
            return fb_error_static(
                FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
                FB_SLICE_LIT("offsite_redirect"),
                "Facebook redirected outside Facebook",
                response,
                true
            );
        }
        document_status = fb_document_parse_cancelable(
            parser->arena, response->body, NULL, parser->cancel,
            &document, &document_error);
        if (document_status != FB_DOCUMENT_OK) {
            if (document_status == FB_DOCUMENT_CANCELLED) {
                parser->cancelled = true;
                return fb_cancelled();
            }
            if (document_status == FB_DOCUMENT_NO_MEMORY) {
                return fb_no_memory();
            }
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_DOCUMENT,
                "Facebook document could not be parsed",
                response,
                false
            );
        }
        probe = fb_probe_page(parser, document, path, response);
        if (fb_parser_poll_cancel(parser)) {
            return fb_cancelled();
        }
    }
    if (probe == FB_PROBE_LOGIN_WALL ||
        probe == FB_PROBE_PRIVATE_GROUP) {
        return fb_probe_error(probe, response);
    }
    if (response->status >= 400 && probe != FB_PROBE_HAS_DATA) {
        fb_slice reason = fb_arena_format(
            parser->arena, "upstream_http_%ld", response->status);
        fb_slice detail = fb_arena_format(
            parser->arena,
            "Facebook returned HTTP %ld",
            response->status);
        if (reason.ptr == NULL || detail.ptr == NULL) {
            return fb_no_memory();
        }
        return fb_attempt_error(
            FB_PARSE_ERROR_UPSTREAM,
            reason,
            detail,
            response,
            false,
            false,
            response->body.len != 0u
        );
    }
    if (probe != FB_PROBE_HAS_DATA && probe != FB_PROBE_UNKNOWN) {
        return fb_probe_error(probe, response);
    }
    if (parser->page_count >= FB_ARRAY_LEN(parser->pages)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "parser page cache capacity exceeded",
            response,
            false
        );
    }
    parser->pages[parser->page_count] = (fb_page){
        .path = path,
        .response = response,
        .document = document,
        .probe = probe,
    };
    *out = &parser->pages[parser->page_count++];
    return (fb_attempt){.ok = true};
}

static const yyjson_val *
fb_select_subtree_key(
    fb_parser *parser,
    const yyjson_val *root,
    const char *key,
    const fb_id_set *requested
)
{
    fb_object_walk walk;
    const yyjson_val *object;
    const yyjson_val *first = NULL;
    const yyjson_val *url_match = NULL;

    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        const yyjson_val *value = fb_object_get(object, key);
        if (value == NULL) {
            continue;
        }
        if (first == NULL) {
            first = value;
        }
        if (requested != NULL && requested->len != 0u) {
            if (fb_subtree_contains_exact_id(parser, value, requested)) {
                fb_object_walk_destroy(&walk);
                return value;
            }
            if (url_match == NULL &&
                fb_subtree_contains_target_id(parser, value, requested)) {
                url_match = value;
            }
        }
    }
    fb_object_walk_destroy(&walk);
    if (requested != NULL && requested->len != 0u) {
        return url_match;
    }
    return first;
}

static const yyjson_val *
fb_root_from_block(
    fb_parser *parser,
    const fb_json_block *block,
    const fb_id_set *requested
)
{
    const yyjson_val *root = fb_json_block_root(block);
    const yyjson_val *data =
        fb_select_subtree_key(parser, root, "data", requested);
    const yyjson_val *candidate;

    if (yyjson_is_obj(data)) {
        if (fb_object_get(data, "comet_ufi_summary_and_actions_renderer") !=
            NULL) {
            return data;
        }
        candidate = fb_object_get(data, "node_v2");
        if (yyjson_is_obj(candidate) &&
            (fb_object_get(candidate, "comet_sections") != NULL ||
             fb_object_get(candidate, "creation_story") != NULL)) {
            return candidate;
        }
        candidate = fb_object_get(data, "node");
        if (yyjson_is_obj(candidate) &&
            (fb_object_get(candidate, "comet_sections") != NULL ||
             fb_object_get(candidate, "creation_story") != NULL)) {
            return candidate;
        }
        candidate = fb_select_subtree_key(
            parser, data, "short_form_video_context", requested);
        if (yyjson_is_obj(candidate)) {
            return candidate;
        }
    }

    candidate = fb_select_subtree_key(
        parser, root, "group_hoisted_feed", requested);
    if (yyjson_is_obj(candidate)) {
        if (fb_object_get(candidate, "comet_sections") != NULL ||
            fb_object_get(candidate, "creation_story") != NULL) {
            return candidate;
        }
        data = fb_select_subtree_key(
            parser, candidate, "node_v2", requested);
        if (yyjson_is_obj(data)) {
            return data;
        }
    }
    data = fb_select_subtree_key(parser, root, "data", requested);
    if (yyjson_is_obj(data)) {
        const yyjson_val *group = fb_object_get(data, "group");
        if (yyjson_is_obj(group)) {
            if (fb_object_get(group, "comet_sections") != NULL ||
                fb_object_get(group, "creation_story") != NULL) {
                return group;
            }
            candidate = fb_select_subtree_key(
                parser, group, "node_v2", requested);
            if (yyjson_is_obj(candidate)) {
                return candidate;
            }
        }
        if (fb_object_get(data, "creation_story") != NULL &&
            fb_object_get(data, "feedback") != NULL) {
            return data;
        }
        candidate = fb_object_get(data, "node_v2");
        if (yyjson_is_obj(candidate)) {
            return candidate;
        }
    }
    return NULL;
}

static int
fb_block_score(fb_parser *parser, const fb_json_block *block)
{
    const yyjson_val *root = fb_json_block_root(block);
    const yyjson_val *node_v2 = fb_subtree_first(parser, root, "node_v2");
    const yyjson_val *data = fb_subtree_first(parser, root, "data");
    int score = 0;

    if (fb_subtree_has(parser, root, "short_form_video_context")) {
        score += 20;
    }
    if (fb_subtree_has(parser, root, "creation_story")) {
        score += 10;
    }
    if (fb_subtree_has(parser, root, "comet_sections")) {
        score += 5;
    }
    if (fb_subtree_has(parser, root, "group_hoisted_feed")) {
        score += 8;
    }
    if (fb_subtree_has(
            parser, root, "video_home_www_related_videos_section") ||
        fb_subtree_has(
            parser, root, "video_home_www_loe_video_permalink_seo_info")) {
        score -= 20;
    }
    if (yyjson_is_obj(node_v2)) {
        if (fb_json_truthy(fb_object_get(node_v2, "actors"))) {
            score += 30;
        }
        if (yyjson_is_obj(fb_object_get(node_v2, "feedback"))) {
            score += 15;
        }
        if (fb_object_get(node_v2, "comet_sections") != NULL ||
            fb_object_get(node_v2, "creation_story") != NULL) {
            score += 10;
        }
    }
    if (yyjson_is_obj(data)) {
        if (fb_json_truthy(fb_object_get(data, "actors"))) {
            score += 20;
        }
        if (yyjson_is_obj(fb_object_get(data, "feedback"))) {
            score += 10;
        }
    }
    if (fb_object_get(root, "require") != NULL &&
        !yyjson_is_obj(node_v2) && !yyjson_is_obj(data)) {
        score -= 10;
    }
    return score;
}

static const yyjson_val *
fb_select_post_root(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *requested,
    const fb_id_set *required,
    bool *target_shape_seen
)
{
    const yyjson_val *best = NULL;
    int best_required = -1;
    int best_exact = -1;
    int best_target = -1;
    int best_score = INT_MIN;
    size_t block_index;

    *target_shape_seen = false;
    for (block_index = 0u;
         block_index < fb_document_json_block_count(document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(document, block_index);
        const yyjson_val *root;
        int has_required;
        int has_exact;
        int has_target;
        int score;
        if (block == NULL) {
            continue;
        }
        root = fb_root_from_block(parser, block, requested);
        if (!yyjson_is_obj(root)) {
            continue;
        }
        has_required = required != NULL && required->len != 0u
                           ? (fb_subtree_contains_target_id(
                                  parser, root, required) ? 1 : 0)
                           : 0;
        if (required != NULL && required->len != 0u && !has_required) {
            continue;
        }
        if (has_required) {
            *target_shape_seen = true;
        }
        has_exact = requested != NULL && requested->len != 0u
                        ? (fb_subtree_contains_exact_id(
                               parser, root, requested) ? 1 : 0)
                        : 0;
        has_target = requested != NULL && requested->len != 0u
                         ? (fb_subtree_contains_target_id(
                                parser, root, requested) ? 1 : 0)
                         : 0;
        score = fb_block_score(parser, block);
        if (best == NULL || has_required > best_required ||
            (has_required == best_required && has_exact > best_exact) ||
            (has_required == best_required && has_exact == best_exact &&
             has_target > best_target) ||
            (has_required == best_required && has_exact == best_exact &&
             has_target == best_target && score > best_score)) {
            best = root;
            best_required = has_required;
            best_exact = has_exact;
            best_target = has_target;
            best_score = score;
        }
    }
    return best;
}

static const yyjson_val *
fb_select_requested_field(
    fb_parser *parser,
    const fb_document *document,
    const char *field,
    const fb_id_set *requested
)
{
    fb_document_key_cursor cursor;
    const yyjson_val *url_match = NULL;
    const yyjson_val *first_nonempty = NULL;
    size_t best_exact_size = SIZE_MAX;
    size_t best_url_size = SIZE_MAX;

    fb_document_key_cursor_init(&cursor, document, field);
    for (;;) {
        fb_json_match match;
        size_t size;
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (first_nonempty == NULL && fb_json_truthy(match.value)) {
            first_nonempty = match.value;
        }
        if (requested == NULL || requested->len == 0u) {
            continue;
        }
        {
            const bool exact = fb_subtree_contains_exact_id(
                parser, match.object, requested);
            const bool target = !exact && fb_subtree_contains_target_id(
                parser, match.object, requested);
            if (!exact && !target) {
                continue;
            }
            if (yyjson_is_obj(match.object)) {
            char *serialized = yyjson_val_write_opts(
                match.object, YYJSON_WRITE_NOFLAG, NULL, &size, NULL);
            if (serialized == NULL) {
                size = SIZE_MAX;
            } else {
                free(serialized);
            }
        } else {
            size = SIZE_MAX;
        }
            if (exact && size < best_exact_size) {
                first_nonempty = match.value;
                best_exact_size = size;
            } else if (target && size < best_url_size) {
                url_match = match.value;
                best_url_size = size;
            }
        }
    }
    if (requested != NULL && requested->len != 0u) {
        return best_exact_size != SIZE_MAX ? first_nonempty : url_match;
    }
    return first_nonempty;
}

static fb_slice
fb_count_text(fb_parser *parser, const yyjson_val *value, const char *fallback)
{
    const yyjson_val *count;
    fb_slice text;

    if (yyjson_is_obj(value)) {
        count = fb_object_get(value, "count");
        if (count != NULL) {
            value = count;
        }
    }
    text = fb_value_text(parser, value);
    return text.ptr != NULL ? text : fb_slice_from_cstr(fallback);
}

static fb_slice
fb_feedback_comments(fb_parser *parser, const yyjson_val *feedback)
{
    const yyjson_val *value = fb_object_get(feedback, "total_comment_count");
    const yyjson_val *rendering;
    const yyjson_val *comments;
    const yyjson_val *summary;
    if (fb_json_truthy(value)) {
        return fb_count_text(parser, value, "0");
    }
    value = fb_subtree_first(parser, feedback, "total_comment_count");
    if (fb_json_truthy(value)) {
        return fb_count_text(parser, value, "0");
    }
    rendering = fb_object_get(feedback, "comment_rendering_instance");
    if (!yyjson_is_obj(rendering)) {
        rendering = fb_subtree_first(
            parser, feedback, "comment_rendering_instance");
    }
    comments = fb_object_get(rendering, "comments");
    value = fb_object_get(comments, "total_count");
    if (fb_json_truthy(value)) {
        return fb_count_text(parser, value, "0");
    }
    summary = fb_object_get(feedback, "comments_count_summary_renderer");
    if (!yyjson_is_obj(summary)) {
        summary = fb_subtree_first(
            parser, feedback, "comments_count_summary_renderer");
    }
    if (yyjson_is_obj(summary)) {
        const yyjson_val *inner = fb_object_get(summary, "feedback");
        rendering = fb_object_get(inner, "comment_rendering_instance");
        comments = fb_object_get(rendering, "comments");
        value = fb_object_get(comments, "total_count");
        if (fb_json_truthy(value)) {
            return fb_count_text(parser, value, "0");
        }
    }
    return FB_SLICE_LIT("0");
}

static double
fb_reaction_numeric(const yyjson_val *value)
{
    fb_slice text;
    char buffer[64];
    char *end = NULL;
    double number;
    double multiplier = 1.0;
    size_t length;

    if (yyjson_is_num(value)) {
        return yyjson_get_num(value);
    }
    if (!yyjson_is_str(value)) {
        return 0.0;
    }
    text = fb_json_string(value);
    if (text.len == 0u || text.len >= sizeof(buffer)) {
        return 0.0;
    }
    length = 0u;
    for (size_t index = 0u; index < text.len; ++index) {
        if (text.ptr[index] != ',') {
            buffer[length++] = text.ptr[index];
        }
    }
    buffer[length] = '\0';
    if (length != 0u) {
        unsigned char suffix =
            fb_ascii_lower((unsigned char)buffer[length - 1u]);
        if (suffix == (unsigned char)'k' || suffix == (unsigned char)'m' ||
            suffix == (unsigned char)'b') {
            multiplier = suffix == (unsigned char)'k'
                             ? 1000.0
                             : (suffix == (unsigned char)'m'
                                    ? 1000000.0
                                    : 1000000000.0);
            buffer[--length] = '\0';
        }
    }
    number = strtod(buffer, &end);
    return end != buffer && *end == '\0' ? number * multiplier : 0.0;
}

static double
fb_feedback_reaction_score(const yyjson_val *feedback)
{
    const yyjson_val *count;
    if (!yyjson_is_obj(feedback)) {
        return -1.0;
    }
    count = fb_object_get(feedback, "i18n_reaction_count");
    if (count == NULL) {
        count = fb_object_get(feedback, "reaction_count");
        if (yyjson_is_obj(count)) {
            count = fb_object_get(count, "count");
        }
    }
    return count == NULL ? -1.0 : fb_reaction_numeric(count);
}

static fb_slice
fb_reaction_id_for_node(const yyjson_val *node)
{
    static const struct {
        const char *name;
        const char *id;
    } names[] = {
        {"like", "1635855486666999"},
        {"love", "1678524932434102"},
        {"care", "613557422527858"},
        {"haha", "115940658764963"},
        {"wow", "478547315650144"},
        {"sad", "908563459236466"},
        {"angry", "444813342392137"},
    };
    static const char *const known_ids[] = {
        "1635855486666999", "1678524932434102", "613557422527858",
        "115940658764963", "478547315650144", "908563459236466",
        "444813342392137"
    };
    const yyjson_val *value = fb_object_get(node, "id");
    fb_slice id = fb_json_string(value);
    size_t index;

    for (index = 0u; index < FB_ARRAY_LEN(known_ids); ++index) {
        if (fb_slice_equal_literal(id, known_ids[index])) {
            return id;
        }
    }
    value = fb_object_get(node, "localized_name");
    if (!yyjson_is_str(value)) {
        value = fb_object_get(node, "name");
    }
    if (yyjson_is_str(value)) {
        fb_slice name = fb_json_string(value);
        for (index = 0u; index < FB_ARRAY_LEN(names); ++index) {
            if (fb_slice_equal_literal_ascii_case(name, names[index].name)) {
                return fb_slice_from_cstr(names[index].id);
            }
        }
    }
    return fb_slice_make(NULL, 0u);
}

static bool
fb_set_top_reactions(fb_post *post, const yyjson_val *feedback)
{
    const yyjson_val *top = fb_object_get(feedback, "top_reactions");
    const yyjson_val *edges = fb_object_get(top, "edges");
    fb_slice first = fb_slice_make(NULL, 0u);
    fb_slice second = fb_slice_make(NULL, 0u);
    double first_count = -1.0;
    double second_count = -1.0;

    if (!yyjson_is_arr(edges)) {
        return true;
    }
    {
        yyjson_arr_iter iterator = yyjson_arr_iter_with(edges);
        yyjson_val *edge;
        while ((edge = yyjson_arr_iter_next(&iterator)) != NULL) {
            const yyjson_val *node = fb_object_get(edge, "node");
            const yyjson_val *count = fb_object_get(edge, "reaction_count");
            fb_slice id;
            double numeric;
            if (count == NULL) {
                count = fb_object_get(edge, "i18n_reaction_count");
            }
            id = fb_reaction_id_for_node(node);
            numeric = fb_reaction_numeric(count);
            if (id.ptr == NULL || numeric <= 0.0 ||
                fb_slice_equal(id, first) || fb_slice_equal(id, second)) {
                continue;
            }
            if (numeric > first_count) {
                second = first;
                second_count = first_count;
                first = id;
                first_count = numeric;
            } else if (numeric > second_count) {
                second = id;
                second_count = numeric;
            }
        }
    }
    if (first.ptr != NULL && second.ptr != NULL) {
        fb_slice values[2] = {first, second};
        return fb_post_set_top_reactions(post, values, 2u);
    }
    return true;
}

static const yyjson_val *
fb_best_feedback(
    fb_parser *parser,
    const yyjson_val *root,
    const fb_id_set *requested
)
{
    const yyjson_val *direct = fb_object_get(root, "feedback");
    const yyjson_val *best = yyjson_is_obj(direct) ? direct : NULL;
    double best_count = -1.0;
    fb_object_walk walk;
    const yyjson_val *object;

    if (best != NULL &&
        (fb_object_get(best, "i18n_reaction_count") != NULL ||
         fb_object_get(best, "reaction_count") != NULL ||
         fb_object_get(best, "total_comment_count") != NULL ||
         fb_object_get(best, "i18n_share_count") != NULL ||
         fb_object_get(best, "share_count") != NULL ||
         fb_object_get(best, "comment_rendering_instance") != NULL ||
         fb_object_get(best, "comments_count_summary_renderer") != NULL)) {
        return best;
    }
    if (best != NULL) {
        best_count = fb_feedback_reaction_score(best);
    }
    if (requested != NULL && requested->len != 0u) {
        typedef enum {
            FB_FEEDBACK_ENTER = 0,
            FB_FEEDBACK_OBJECT,
            FB_FEEDBACK_ARRAY
        } fb_feedback_phase;
        typedef struct {
            const yyjson_val *value;
            bool inherited_match;
            bool context_match;
            fb_feedback_phase phase;
            union {
                fb_effective_object_iter object;
                yyjson_arr_iter array;
            } iterator;
        } fb_feedback_frame;
        fb_feedback_frame *frames = fb_arena_alloc(
            parser->arena,
            FB_WALK_MAX_DEPTH * sizeof(*frames),
            _Alignof(fb_feedback_frame));
        size_t depth = 0u;
        best = NULL;
        best_count = -1.0;
        if (frames == NULL) {
            return NULL;
        }
        memset(&frames[depth], 0, sizeof(frames[depth]));
        frames[depth++].value = root;
        while (depth != 0u) {
            fb_feedback_frame *frame = &frames[depth - 1u];
            const yyjson_val *child = NULL;
            if (frame->phase == FB_FEEDBACK_ENTER) {
                if (yyjson_is_obj(frame->value)) {
                    fb_effective_object_iter identity;
                    fb_slice key;
                    const yyjson_val *value;
                    bool has_own_identity = false;
                    bool own_matches = false;
                    fb_effective_object_iter_init(
                        &identity, frame->value, parser);
                    while (fb_effective_object_iter_next(
                               &identity, &key, &value)) {
                        if (!fb_identity_key(key) ||
                            !(yyjson_is_str(value) || yyjson_is_int(value) ||
                              yyjson_is_uint(value))) {
                            continue;
                        }
                        has_own_identity = true;
                        if (fb_scalar_matches_ids(value, requested) ||
                            fb_scalar_decoded_matches_ids(value, requested)) {
                            own_matches = true;
                        }
                    }
                    frame->context_match = has_own_identity
                                               ? own_matches
                                               : frame->inherited_match;
                    if (frame->context_match) {
                        const yyjson_val *feedback =
                            fb_object_get(frame->value, "feedback");
                        if (yyjson_is_obj(feedback)) {
                            const double numeric =
                                fb_feedback_reaction_score(feedback);
                            if (best == NULL || numeric > best_count) {
                                best = feedback;
                                best_count = numeric;
                            }
                        }
                    }
                    fb_effective_object_iter_init(
                        &frame->iterator.object, frame->value, parser);
                    frame->phase = FB_FEEDBACK_OBJECT;
                } else if (yyjson_is_arr(frame->value)) {
                    frame->context_match = frame->inherited_match;
                    frame->iterator.array = yyjson_arr_iter_with(frame->value);
                    frame->phase = FB_FEEDBACK_ARRAY;
                } else {
                    --depth;
                }
                continue;
            }
            if (frame->phase == FB_FEEDBACK_OBJECT) {
                fb_slice ignored_key;
                if (!fb_effective_object_iter_next(
                        &frame->iterator.object, &ignored_key, &child)) {
                    --depth;
                    continue;
                }
            } else {
                child = yyjson_arr_iter_next(&frame->iterator.array);
                if (child == NULL) {
                    --depth;
                    continue;
                }
            }
            if (depth >= FB_WALK_MAX_DEPTH) {
                return best;
            }
            memset(&frames[depth], 0, sizeof(frames[depth]));
            frames[depth].value = child;
            frames[depth].inherited_match = frame->context_match;
            ++depth;
        }
        return best;
    }
    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        const yyjson_val *feedback = fb_object_get(object, "feedback");
        double numeric;
        if (!yyjson_is_obj(feedback)) {
            continue;
        }
        numeric = fb_feedback_reaction_score(feedback);
        if (best == NULL || numeric > best_count) {
            best = feedback;
            best_count = numeric;
        }
    }
    fb_object_walk_destroy(&walk);
    return best;
}

static void
fb_extract_interactions(
    fb_parser *parser,
    const yyjson_val *root,
    const fb_id_set *requested,
    fb_post *post
)
{
    const yyjson_val *feedback =
        fb_best_feedback(parser, root, requested);
    const yyjson_val *reaction;
    const yyjson_val *shares;

    post->likes = FB_SLICE_LIT("0");
    post->comments = FB_SLICE_LIT("0");
    post->shares = FB_SLICE_LIT("0");
    if (!yyjson_is_obj(feedback)) {
        return;
    }
    reaction = fb_object_get(feedback, "i18n_reaction_count");
    if (!fb_json_truthy(reaction)) {
        reaction = fb_object_get(feedback, "reaction_count");
    }
    if (!fb_json_truthy(reaction)) {
        reaction = fb_subtree_first(
            parser, feedback, "i18n_reaction_count");
    }
    if (!fb_json_truthy(reaction)) {
        reaction = fb_subtree_first(parser, feedback, "reaction_count");
    }
    shares = fb_object_get(feedback, "i18n_share_count");
    if (!fb_json_truthy(shares)) {
        shares = fb_object_get(feedback, "share_count");
    }
    if (!fb_json_truthy(shares)) {
        shares = fb_subtree_first(parser, feedback, "i18n_share_count");
    }
    if (!fb_json_truthy(shares)) {
        shares = fb_subtree_first(parser, feedback, "share_count");
    }
    post->likes = fb_count_text(parser, reaction, "0");
    post->comments = fb_feedback_comments(parser, feedback);
    post->shares = fb_count_text(parser, shares, "0");
    {
        bool reactions_ok = fb_set_top_reactions(post, feedback);
        (void)reactions_ok;
    }
}

static const yyjson_val *
fb_first_array_object(const yyjson_val *array)
{
    yyjson_arr_iter iterator;
    yyjson_val *value;
    if (!yyjson_is_arr(array)) {
        return NULL;
    }
    iterator = yyjson_arr_iter_with(array);
    while ((value = yyjson_arr_iter_next(&iterator)) != NULL) {
        if (yyjson_is_obj(value)) {
            return value;
        }
    }
    return NULL;
}

static bool
fb_add_attachment_media(
    fb_parser *parser,
    fb_post *post,
    const yyjson_val *attachment
)
{
    const yyjson_val *video_node = attachment;
    const yyjson_val *hd =
        fb_subtree_first(parser, video_node, "browser_native_hd_url");
    const yyjson_val *sd =
        fb_subtree_first(parser, video_node, "browser_native_sd_url");
    const yyjson_val *selected = NULL;

    if (!fb_json_truthy(hd) && !fb_json_truthy(sd)) {
        video_node =
            fb_subtree_first(
                parser, attachment, "videoDeliveryLegacyFields");
        hd = fb_subtree_first(
            parser, video_node, "browser_native_hd_url");
        sd = fb_subtree_first(
            parser, video_node, "browser_native_sd_url");
    }
    if (yyjson_is_str(hd) &&
        fb_url_is_safe_media(fb_json_string(hd))) {
        selected = hd;
    } else if (yyjson_is_str(sd) &&
               fb_url_is_safe_media(fb_json_string(sd))) {
        selected = sd;
    }
    if (selected != NULL &&
        !fb_slice_vec_push_unique(
            &post->video_links,
            parser->arena,
            fb_json_string(selected))) {
        return false;
    }
    return true;
}

static bool
fb_slice_ends_literal(fb_slice value, const char *suffix)
{
    size_t length = strlen(suffix);
    return value.len >= length &&
           (length == 0u ||
            memcmp(
                value.ptr + value.len - length,
                suffix,
                length) == 0);
}

static bool
fb_subtree_is_sticker(fb_parser *parser, const yyjson_val *root)
{
    fb_object_walk walk;
    const yyjson_val *object;
    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        const yyjson_val *typename_value =
            fb_object_get(object, "__typename");
        if (yyjson_is_str(typename_value) &&
            fb_slice_equal_literal(
                fb_json_string(typename_value), "Sticker")) {
            fb_object_walk_destroy(&walk);
            return true;
        }
    }
    fb_object_walk_destroy(&walk);
    return false;
}

static bool
fb_collect_image_key(
    fb_parser *parser,
    fb_post *post,
    const yyjson_val *root,
    const char *key
)
{
    fb_object_walk walk;
    const yyjson_val *object;
    fb_object_walk_init(&walk, parser, root);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        const yyjson_val *image = fb_object_get(object, key);
        const yyjson_val *uri = fb_object_get(image, "uri");
        if (yyjson_is_str(uri) &&
            fb_url_is_safe_media(fb_json_string(uri)) &&
            !fb_slice_vec_push_unique(
                &post->image_links,
                parser->arena,
                fb_json_string(uri))) {
            fb_object_walk_destroy(&walk);
            return false;
        }
    }
    fb_object_walk_destroy(&walk);
    return true;
}

static bool
fb_select_attachment_images(
    fb_parser *parser,
    fb_post *post,
    const yyjson_val *attachment,
    bool *found
)
{
    fb_effective_object_iter iterator;
    fb_slice key;
    const yyjson_val *value;
    size_t maximum_nodes = 0u;

    *found = false;
    if (!yyjson_is_obj(attachment)) {
        return true;
    }
    fb_effective_object_iter_init(&iterator, attachment, parser);
    while (fb_effective_object_iter_next(
               &iterator, &key, &value)) {
        const yyjson_val *nodes;
        if (!fb_slice_ends_literal(key, "subattachments") ||
            !yyjson_is_obj(value)) {
            continue;
        }
        nodes = fb_object_get(value, "nodes");
        if (yyjson_is_arr(nodes) &&
            yyjson_arr_size(nodes) > maximum_nodes) {
            maximum_nodes = yyjson_arr_size(nodes);
        }
    }
    if (maximum_nodes != 0u) {
        fb_effective_object_iter_init(&iterator, attachment, parser);
        while (fb_effective_object_iter_next(
                   &iterator, &key, &value)) {
            const yyjson_val *nodes;
            size_t before = post->image_links.len;
            if (!fb_slice_ends_literal(key, "subattachments") ||
                !yyjson_is_obj(value)) {
                continue;
            }
            nodes = fb_object_get(value, "nodes");
            if (!yyjson_is_arr(nodes) ||
                yyjson_arr_size(nodes) != maximum_nodes ||
                !fb_subtree_has(parser, value, "viewer_image")) {
                continue;
            }
            if (!fb_collect_image_key(
                    parser, post, value, "viewer_image")) {
                return false;
            }
            if (post->image_links.len != before) {
                *found = true;
                return true;
            }
        }
    } else if (yyjson_is_obj(fb_object_get(attachment, "media")) &&
               !fb_subtree_is_sticker(parser, attachment)) {
        size_t before = post->image_links.len;
        if (!fb_collect_image_key(
                parser, post, attachment, "photo_image")) {
            return false;
        }
        if (post->image_links.len != before) {
            *found = true;
        }
    }
    return true;
}

static bool
fb_extract_story_media(
    fb_parser *parser,
    fb_post *post,
    const yyjson_val *story
)
{
    fb_object_walk walk;
    const yyjson_val *object;
    bool saw_attachment = false;
    bool found_images = false;

    fb_object_walk_init(&walk, parser, story);
    while ((object = fb_object_walk_next(&walk)) != NULL) {
        const yyjson_val *attachment = fb_object_get(object, "attachment");
        if (yyjson_is_obj(attachment)) {
            bool found;
            saw_attachment = true;
            if (!fb_add_attachment_media(parser, post, attachment) ||
                (!found_images &&
                 !fb_select_attachment_images(
                     parser, post, attachment, &found))) {
                fb_object_walk_destroy(&walk);
                return false;
            }
            if (!found_images && found) {
                found_images = true;
            }
        } else if (yyjson_is_arr(attachment)) {
            yyjson_arr_iter array = yyjson_arr_iter_with(attachment);
            yyjson_val *item;
            saw_attachment = true;
            while ((item = yyjson_arr_iter_next(&array)) != NULL) {
                if (yyjson_is_obj(item)) {
                    bool found;
                    if (!fb_add_attachment_media(
                            parser, post, item) ||
                        (!found_images &&
                         !fb_select_attachment_images(
                             parser, post, item, &found))) {
                        fb_object_walk_destroy(&walk);
                        return false;
                    }
                    if (!found_images && found) {
                        found_images = true;
                    }
                }
            }
        }
    }
    fb_object_walk_destroy(&walk);
    if (!saw_attachment || !found_images) {
        const yyjson_val *renderer = fb_subtree_first(
            parser, story, "comet_photo_attachment_resolution_renderer");
        const yyjson_val *image = fb_object_get(renderer, "image");
        const yyjson_val *uri = fb_object_get(image, "uri");
        if (yyjson_is_str(uri) &&
            fb_url_is_safe_media(fb_json_string(uri)) &&
            !fb_slice_vec_push_unique(
                &post->image_links, parser->arena,
                fb_json_string(uri))) {
            return false;
        }
    }
    return true;
}

static fb_slice
fb_story_author_name(
    fb_parser *parser,
    const yyjson_val *story,
    const yyjson_val **actor_out
)
{
    const yyjson_val *node_v2 = fb_object_get(story, "node_v2");
    const yyjson_val *actor =
        fb_first_array_object(fb_object_get(story, "actors"));
    const yyjson_val *name;

    if (!yyjson_is_obj(actor) && yyjson_is_obj(node_v2)) {
        actor = fb_first_array_object(fb_object_get(node_v2, "actors"));
    }
    if (actor_out != NULL) {
        *actor_out = actor;
    }
    name = fb_object_get(actor, "name");
    if (yyjson_is_str(name)) {
        return fb_json_string(name);
    }
    name = fb_object_get(node_v2, "name");
    if (yyjson_is_str(name) && yyjson_get_len(name) > 2u) {
        return fb_json_string(name);
    }
    name = fb_object_get(node_v2, "short_name");
    if (yyjson_is_str(name)) {
        return fb_json_string(name);
    }
    name = fb_object_get(story, "name");
    if (yyjson_is_str(name) && yyjson_get_len(name) > 2u) {
        return fb_json_string(name);
    }
    name = fb_subtree_first(parser, story, "name");
    if (!yyjson_is_str(name)) {
        name = fb_subtree_first(parser, story, "localized_name");
    }
    return yyjson_is_str(name)
               ? fb_json_string(name)
               : FB_SLICE_LIT("");
}

static fb_slice
fb_story_text(fb_parser *parser, const yyjson_val *story)
{
    const yyjson_val *message = fb_object_get(story, "message");
    const yyjson_val *text = fb_object_get(message, "text");
    if (!yyjson_is_str(text)) {
        text = fb_object_get(story, "text");
    }
    if (!yyjson_is_str(text)) {
        text = fb_subtree_first(parser, story, "text");
    }
    return yyjson_is_str(text)
               ? fb_json_string(text)
               : FB_SLICE_LIT("");
}

static fb_slice
fb_story_url(const yyjson_val *story)
{
    const yyjson_val *node_v2 = fb_object_get(story, "node_v2");
    const yyjson_val *value = fb_object_get(story, "wwwURL");
    if (!yyjson_is_str(value)) {
        value = fb_object_get(node_v2, "wwwURL");
    }
    if (!yyjson_is_str(value)) {
        value = fb_object_get(story, "url");
    }
    return yyjson_is_str(value)
               ? fb_json_string(value)
               : fb_slice_make(NULL, 0u);
}

static bool
fb_append_attached_story_text(
    fb_parser *parser,
    const yyjson_val *story,
    fb_post *post
)
{
    const yyjson_val *attached = fb_object_get(story, "attached_story");
    fb_slice attached_name;
    fb_slice attached_text;
    size_t total;
    char *combined;
    size_t cursor;

    if (!yyjson_is_obj(attached) ||
        !yyjson_is_arr(fb_object_get(attached, "actors"))) {
        return true;
    }
    attached_name = fb_story_author_name(parser, attached, NULL);
    attached_text = fb_story_text(parser, attached);
    if (!fb_size_add(post->text.len, sizeof("\n╰┈➤ ") - 1u, &total) ||
        !fb_size_add(total, attached_name.len, &total) ||
        !fb_size_add(total, 1u, &total) ||
        !fb_size_add(total, attached_text.len, &total) ||
        !fb_size_add(total, 1u, &cursor)) {
        return false;
    }
    combined = fb_arena_alloc(parser->arena, cursor, _Alignof(char));
    if (combined == NULL) {
        return false;
    }
    cursor = 0u;
    memcpy(combined + cursor, post->text.ptr, post->text.len);
    cursor += post->text.len;
    memcpy(combined + cursor, "\n╰┈➤ ", sizeof("\n╰┈➤ ") - 1u);
    cursor += sizeof("\n╰┈➤ ") - 1u;
    memcpy(combined + cursor, attached_name.ptr, attached_name.len);
    cursor += attached_name.len;
    combined[cursor++] = '\n';
    memcpy(combined + cursor, attached_text.ptr, attached_text.len);
    cursor += attached_text.len;
    combined[cursor] = '\0';
    post->text = fb_slice_make(combined, total);
    return fb_extract_story_media(parser, post, attached);
}

static bool
fb_json_to_i64(const yyjson_val *value, int64_t *out)
{
    fb_slice text;
    char buffer[32];
    char *end = NULL;
    long long number;
    if (yyjson_is_sint(value)) {
        *out = yyjson_get_sint(value);
        return true;
    }
    if (yyjson_is_uint(value)) {
        uint64_t unsigned_value = yyjson_get_uint(value);
        if (unsigned_value <= INT64_MAX) {
            *out = (int64_t)unsigned_value;
            return true;
        }
        return false;
    }
    if (!yyjson_is_str(value)) {
        return false;
    }
    text = fb_json_string(value);
    if (text.len == 0u || text.len >= sizeof(buffer)) {
        return false;
    }
    memcpy(buffer, text.ptr, text.len);
    buffer[text.len] = '\0';
    errno = 0;
    number = strtoll(buffer, &end, 10);
    if (end == buffer || *end != '\0' || errno == ERANGE) {
        return false;
    }
    *out = (int64_t)number;
    return true;
}

static fb_slice
fb_group_name(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *requested
)
{
    const fb_json_block *first = NULL;
    const fb_json_block *url_match = NULL;
    const fb_json_block *selected = NULL;
    size_t block_index;

    for (block_index = 0u;
         block_index < fb_document_json_block_count(document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(document, block_index);
        const yyjson_val *root;
        if (block == NULL ||
            fb_json_block_key_count(
                block, FB_SLICE_LIT("group_member_profiles")) == 0u ||
            fb_json_block_key_count(
                block, FB_SLICE_LIT("formatted_count_text")) == 0u) {
            continue;
        }
        root = fb_json_block_root(block);
        if (first == NULL) {
            first = block;
        }
        if (requested != NULL && requested->len != 0u) {
            if (fb_subtree_contains_exact_id(parser, root, requested)) {
                selected = block;
                break;
            }
            if (url_match == NULL &&
                fb_subtree_contains_target_id(
                    parser, root, requested)) {
                url_match = block;
            }
        }
    }
    if (selected == NULL) {
        selected = requested != NULL && requested->len != 0u
                       ? url_match
                       : first;
    }
    if (selected != NULL) {
        fb_block_key_cursor cursor;
        fb_block_key_cursor_init(&cursor, selected, "group");
        for (;;) {
            fb_json_match match;
            const yyjson_val *name;
            if (!fb_block_key_cursor_next(&cursor, &match)) {
                break;
            }
            if (!yyjson_is_obj(match.value)) {
                continue;
            }
            name = fb_object_get(match.value, "name");
            if (yyjson_is_str(name)) {
                return fb_json_string(name);
            }
        }
    }
    return FB_SLICE_LIT("");
}

static bool
fb_post_set_banned(fb_post *post)
{
    fb_post_init(post);
    post->author_name = FB_SLICE_LIT("Banned");
    post->text =
        FB_SLICE_LIT("This user is banned by the operators of this embed server");
    post->url = FB_SLICE_LIT("https://banned.facebook.com");
    post->date = -1;
    post->likes = FB_SLICE_LIT("null");
    post->comments = FB_SLICE_LIT("null");
    post->shares = FB_SLICE_LIT("null");
    return true;
}

static bool
fb_author_is_banned(
    const fb_parser *parser,
    const yyjson_val *actor
)
{
    fb_slice id;
    const yyjson_val *value;
    if (parser->config == NULL || !yyjson_is_obj(actor)) {
        return false;
    }
    value = fb_object_get(actor, "id");
    id = fb_value_text((fb_parser *)parser, value);
    return id.ptr != NULL && fb_config_is_banned_user(parser->config, id);
}

static bool
fb_story_author_is_banned(
    fb_parser *parser,
    const yyjson_val *story,
    const yyjson_val *actor
)
{
    const yyjson_val *identity = fb_object_get(actor, "id");
    const yyjson_val *node_v2;
    fb_slice id;

    if (parser->config == NULL) {
        return false;
    }
    if (identity == NULL) {
        node_v2 = fb_object_get(story, "node_v2");
        identity = fb_object_get(node_v2, "id");
    }
    if (identity == NULL) {
        identity = fb_subtree_first(parser, story, "id");
    }
    id = fb_value_text(parser, identity);
    return id.ptr != NULL &&
           fb_config_is_banned_user(parser->config, id);
}

static bool fb_ascii_digits(fb_slice value);

static bool
fb_normalize_canonical_post_url(
    fb_parser *parser,
    fb_slice url,
    fb_slice *normalized
)
{
    fb_url_view parsed;
    fb_path_segments parts;
    size_t posts_index = SIZE_MAX;
    size_t numeric_index = SIZE_MAX;
    size_t index;
    fb_buf output;

    *normalized = url;
    if (fb_url_parse(url, &parsed) != FB_URL_OK ||
        !parsed.has_authority ||
        fb_url_facebook_path_segments(
            parser->arena, url, &parts) != FB_URL_OK) {
        return true;
    }
    for (index = 0u; index < parts.len; ++index) {
        fb_slice part = fb_path_segment_at(&parts, index);
        if (posts_index == SIZE_MAX &&
            fb_slice_equal_literal_ascii_case(part, "posts")) {
            posts_index = index;
        } else if (posts_index != SIZE_MAX && fb_ascii_digits(part)) {
            numeric_index = index;
        }
    }
    if (posts_index == SIZE_MAX || numeric_index == SIZE_MAX) {
        return true;
    }
    if (!fb_buf_init(&output, parser->arena, url.len + 1u) ||
        !fb_buf_append(&output, parsed.scheme) ||
        !fb_buf_append_cstr(&output, "://") ||
        !fb_buf_append(&output, parsed.authority)) {
        return false;
    }
    for (index = 0u; index <= posts_index; ++index) {
        if (!fb_buf_append_char(&output, '/') ||
            !fb_buf_append(&output, fb_path_segment_at(&parts, index))) {
            return false;
        }
    }
    if (!fb_buf_append_char(&output, '/') ||
        !fb_buf_append(&output, fb_path_segment_at(&parts, numeric_index))) {
        return false;
    }
    *normalized = fb_buf_view(&output);
    return normalized->ptr != NULL;
}

static fb_attempt
fb_parse_generic(
    fb_parser *parser,
    fb_slice post_path,
    fb_upstream_response *prefetched
)
{
    fb_page *page;
    fb_attempt loaded;
    fb_id_set raw_ids;
    fb_id_set requested;
    fb_id_set route_ids;
    const fb_id_set *required;
    const yyjson_val *root;
    const yyjson_val *story;
    const yyjson_val *actor = NULL;
    bool shape_seen = false;
    fb_post post;
    fb_slice group;
    fb_slice story_url;
    fb_id_set validated;
    fb_id_set interaction_ids;

    loaded = fb_page_load(parser, post_path, prefetched, &page);
    if (!loaded.ok || page == NULL) {
        if (loaded.ok) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "page loader returned no parsed document",
                NULL,
                false
            );
        }
        return loaded;
    }
    if (!fb_id_set_from_url(parser, post_path, &raw_ids) ||
        !fb_get_target_ids(
            parser, page->document, post_path, page->response,
            &requested, &route_ids)) {
        return fb_no_memory();
    }
    if (fb_url_is_share_path(post_path) && raw_ids.len == 0u &&
        route_ids.len == 0u) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_REASON_NO_DATA,
            "Facebook response did not identify the requested share post",
            page->response,
            false
        );
    }
    required = route_ids.len != 0u ? &route_ids : &raw_ids;
    root = fb_select_post_root(
        parser, page->document, &requested, required, &shape_seen);
    if (!yyjson_is_obj(root)) {
        if (required->len != 0u &&
            fb_has_bounded_target_payload(
                parser, page->document, required)) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "Facebook target payload shape is unsupported",
                page->response,
                false
            );
        }
        return fb_error_static(
            required->len != 0u
                ? FB_PARSE_ERROR_NO_DATA
                : FB_PARSE_ERROR_DOCUMENT,
            required->len != 0u
                ? FB_SLICE_LIT("target_payload_missing")
                : FB_REASON_PARSER,
            required->len != 0u
                ? "Facebook response did not contain the requested post"
                : "cannot find post json",
            page->response,
            false
        );
    }
    if (required->len != 0u &&
        !fb_subtree_contains_target_id(parser, root, required)) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_REASON_NO_DATA,
            "Facebook response selected a different post",
            page->response,
            false
        );
    }

    fb_post_init(&post);
    if (!fb_id_set_init(&interaction_ids, parser->arena) ||
        !fb_id_set_add_set(&interaction_ids, &requested) ||
        !fb_collect_direct_identity_ids(
            parser, root, &interaction_ids, false)) {
        return fb_no_memory();
    }
    {
        const yyjson_val *direct_feedback = fb_object_get(root, "feedback");
        if (yyjson_is_obj(direct_feedback) &&
            !fb_collect_direct_identity_ids(
                parser, direct_feedback, &interaction_ids, false)) {
            return fb_no_memory();
        }
    }
    fb_extract_interactions(parser, root, &interaction_ids, &post);
    post.date = -1;
    {
        const yyjson_val *time = fb_subtree_first(
            parser, root, "creation_time");
        if (!fb_json_truthy(time)) {
            time = fb_subtree_first(parser, root, "created_time");
        }
        if (!fb_json_to_i64(time, &post.date)) {
            time = fb_select_requested_field(
                parser, page->document, "creation_time", &requested);
            if (!fb_json_truthy(time)) {
                time = fb_select_requested_field(
                    parser, page->document, "created_time", &requested);
            }
            (void)fb_json_to_i64(time, &post.date);
        }
    }
    story = root;
    if (yyjson_is_obj(fb_object_get(root, "content")) &&
        yyjson_is_obj(fb_object_get(
            fb_object_get(root, "content"), "story"))) {
        story = fb_object_get(fb_object_get(root, "content"), "story");
    } else if (yyjson_is_obj(fb_object_get(root, "creation_story"))) {
        story = fb_object_get(root, "creation_story");
    } else if (yyjson_is_obj(fb_object_get(root, "comet_sections"))) {
        const yyjson_val *content =
            fb_object_get(fb_object_get(root, "comet_sections"), "content");
        const yyjson_val *section_story = fb_object_get(content, "story");
        if (yyjson_is_obj(section_story)) {
            story = section_story;
        }
    }
    post.author_name = fb_story_author_name(parser, story, &actor);
    if (!yyjson_is_obj(actor) &&
        yyjson_is_obj(fb_object_get(root, "owner"))) {
        actor = fb_object_get(root, "owner");
        if (post.author_name.len == 0u &&
            yyjson_is_str(fb_object_get(actor, "name"))) {
            post.author_name =
                fb_json_string(fb_object_get(actor, "name"));
        }
    }
    if (post.author_name.len == 0u) {
        const yyjson_val *owner = fb_select_requested_field(
            parser, page->document, "owner", &requested);
        const yyjson_val *owner_page = fb_object_get(owner, "owner_as_page");
        if (yyjson_is_obj(owner_page) &&
            yyjson_is_str(fb_object_get(owner_page, "name"))) {
            owner = owner_page;
        }
        if (!yyjson_is_obj(owner) ||
            !yyjson_is_str(fb_object_get(owner, "name"))) {
            owner = fb_select_requested_field(
                parser, page->document, "video_owner", &requested);
        }
        if (yyjson_is_obj(owner) &&
            yyjson_is_str(fb_object_get(owner, "name"))) {
            actor = owner;
            post.author_name = fb_json_string(fb_object_get(owner, "name"));
        } else if (yyjson_is_obj(owner) &&
                   yyjson_is_str(fb_object_get(owner, "username"))) {
            actor = owner;
            post.author_name = fb_json_string(
                fb_object_get(owner, "username"));
        }
    }
    post.text = fb_slice_trim(fb_story_text(parser, story));
    if (!fb_extract_story_media(parser, &post, story) ||
        !fb_append_attached_story_text(parser, story, &post)) {
        return fb_no_memory();
    }
    post.text = fb_slice_trim(post.text);
    if (post.video_links.len == 0u) {
        size_t index;
        for (index = 0u;
             index < fb_document_video_delivery_candidate_count(
                         page->document);
             ++index) {
            const fb_json_node_ref *reference =
                fb_document_video_delivery_candidate_at(
                    page->document, index);
            if (reference != NULL &&
                (requested.len == 0u ||
                 fb_video_node_matches(
                     parser, reference->value, &requested))) {
                fb_slice link = fb_direct_video_url(reference->value);
                if (link.ptr != NULL &&
                    !fb_slice_vec_push_unique(
                        &post.video_links, parser->arena, link)) {
                    return fb_no_memory();
                }
                if (link.ptr != NULL) {
                    break;
                }
            }
        }
    }
    group = fb_group_name(parser, page->document, &requested);
    if (group.len != 0u) {
        post.author_name = fb_arena_format(
            parser->arena,
            "%.*s • %.*s",
            (int)post.author_name.len,
            post.author_name.ptr,
            (int)group.len,
            group.ptr
        );
        if (post.author_name.ptr == NULL) {
            return fb_no_memory();
        }
    }
    story_url = fb_story_url(story);
    if (!fb_id_set_init(&validated, parser->arena) ||
        !fb_id_set_add_set(&validated, required) ||
        !fb_collect_direct_identity_ids(
            parser, root, &validated, false) ||
        !fb_collect_direct_identity_ids(
            parser, story, &validated, false)) {
        return fb_no_memory();
    }
    post.url = fb_slice_make(NULL, 0u);
    {
        size_t index;
        for (index = 0u;
             index < fb_document_declared_url_count(
                         page->document, FB_DECLARED_URL_CANONICAL);
             ++index) {
            const fb_declared_url *declared = fb_document_declared_url_at(
                page->document, FB_DECLARED_URL_CANONICAL, index);
            if (declared != NULL &&
                fb_url_is_facebook(declared->value, false) &&
                fb_url_ids_intersect(
                    parser, declared->value, &validated)) {
                if (!fb_normalize_canonical_post_url(
                        parser, declared->value, &post.url)) {
                    return fb_no_memory();
                }
                break;
            }
        }
    }
    if (post.url.ptr == NULL && story_url.ptr != NULL &&
        fb_url_ids_intersect(parser, story_url, &validated)) {
        post.url = story_url;
    }
    if (post.url.ptr == NULL &&
        fb_url_ensure_full(parser->arena, post_path, &post.url) != FB_URL_OK) {
        return fb_no_memory();
    }
    if (fb_story_author_is_banned(parser, story, actor)) {
        fb_post_set_banned(&post);
    }
    (void)shape_seen;
    return fb_attempt_success(&post);
}

static bool
fb_ascii_digits(fb_slice value)
{
    size_t index;
    if (value.len == 0u || value.ptr == NULL) {
        return false;
    }
    for (index = 0u; index < value.len; ++index) {
        if ((unsigned char)value.ptr[index] < (unsigned char)'0' ||
            (unsigned char)value.ptr[index] > (unsigned char)'9') {
            return false;
        }
    }
    return true;
}

static bool
fb_base64_syntax_valid(fb_slice value)
{
    size_t padding = 0u;
    size_t index;

    if (value.len == 0u || value.ptr == NULL) {
        return false;
    }
    for (index = 0u; index < value.len; ++index) {
        unsigned char byte = (unsigned char)value.ptr[index];
        bool alphabet =
            (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
            (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
            (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
            byte == (unsigned char)'+' || byte == (unsigned char)'/';
        if (byte == (unsigned char)'=') {
            padding++;
        } else if (!alphabet || padding != 0u) {
            return false;
        }
    }
    if (padding > 2u || value.len < padding ||
        ((value.len - padding) & 3u) == 1u) {
        return false;
    }
    return true;
}

static bool
fb_comment_decoded_id(
    fb_parser *parser,
    fb_slice encoded,
    fb_slice *out
)
{
    unsigned char input[256];
    unsigned char decoded[256];
    size_t padded;
    int decoded_length;
    size_t prefix_length = sizeof("comment:") - 1u;
    size_t underscore = SIZE_MAX;
    size_t index;

    out->ptr = NULL;
    out->len = 0u;
    if (!fb_base64_syntax_valid(encoded) ||
        encoded.len > sizeof(input) - 4u) {
        return false;
    }
    padded = encoded.len;
    memcpy(input, encoded.ptr, encoded.len);
    while ((padded & 3u) != 0u) {
        input[padded++] = (unsigned char)'=';
    }
    decoded_length = fb_base64_decode_block(decoded, input, padded);
    if (decoded_length < 0) {
        return false;
    }
    while (padded != 0u && input[padded - 1u] == (unsigned char)'=') {
        decoded_length--;
        padded--;
    }
    if (decoded_length <= 0 ||
        (size_t)decoded_length <= prefix_length ||
        memcmp(decoded, "comment:", prefix_length) != 0) {
        return false;
    }
    for (index = prefix_length; index < (size_t)decoded_length; ++index) {
        if (decoded[index] == (unsigned char)'_') {
            if (underscore != SIZE_MAX) {
                return false;
            }
            underscore = index;
        } else if (decoded[index] < (unsigned char)'0' ||
                   decoded[index] > (unsigned char)'9') {
            return false;
        }
    }
    if (underscore <= prefix_length ||
        underscore + 1u >= (size_t)decoded_length) {
        return false;
    }
    *out = fb_arena_slice_dup(
        parser->arena,
        fb_slice_make(
            (const char *)decoded + underscore + 1u,
            (size_t)decoded_length - underscore - 1u
        )
    );
    return out->ptr != NULL;
}

static bool
fb_comment_node_id(
    fb_parser *parser,
    const yyjson_val *node,
    fb_slice *out
)
{
    const yyjson_val *legacy_value = fb_object_get(node, "legacy_fbid");
    const yyjson_val *encoded_value = fb_object_get(node, "id");
    fb_slice legacy = fb_value_text(parser, legacy_value);
    fb_slice encoded = fb_value_text(parser, encoded_value);
    fb_slice decoded = fb_slice_make(NULL, 0u);
    fb_slice decoded_copy = fb_slice_make(NULL, 0u);

    if (encoded.ptr != NULL &&
        !fb_comment_decoded_id(parser, encoded, &decoded)) {
        decoded.ptr = NULL;
        decoded.len = 0u;
    }
    if (decoded.ptr != NULL) {
        decoded_copy = decoded;
    }
    if (legacy.ptr != NULL && decoded_copy.ptr != NULL &&
        !fb_slice_equal(legacy, decoded_copy)) {
        out->ptr = NULL;
        out->len = 0u;
        return true;
    }
    if (legacy.ptr != NULL && fb_ascii_digits(legacy)) {
        *out = legacy;
        return true;
    }
    *out = decoded_copy;
    return true;
}

static bool
fb_comment_url_matches(
    fb_parser *parser,
    fb_slice url,
    const fb_comment_target *target,
    const fb_id_set *post_ids
)
{
    fb_comment_target parsed;
    fb_id_set ids;
    if (!fb_url_is_facebook(url, true) ||
        fb_url_comment_target(parser->arena, url, &parsed) != FB_URL_OK ||
        parsed.kind != FB_COMMENT_TARGET_VALID ||
        !fb_comment_targets_equal(&parsed, target) ||
        !fb_id_set_from_url(parser, url, &ids)) {
        return false;
    }
    return fb_id_sets_intersect(&ids, post_ids);
}

static bool
fb_comment_has_target_url(
    fb_parser *parser,
    const yyjson_val *comment,
    const fb_comment_target *target,
    const fb_id_set *post_ids
)
{
    const yyjson_val *value = fb_object_get(comment, "url");
    const yyjson_val *feedback = fb_object_get(comment, "feedback");
    const yyjson_val *actions = fb_object_get(comment, "comment_action_links");

    if (yyjson_is_str(value) &&
        fb_comment_url_matches(
            parser, fb_json_string(value), target, post_ids)) {
        return true;
    }
    value = fb_object_get(feedback, "url");
    if (yyjson_is_str(value) &&
        fb_comment_url_matches(
            parser, fb_json_string(value), target, post_ids)) {
        return true;
    }
    if (yyjson_is_arr(actions)) {
        yyjson_arr_iter iterator = yyjson_arr_iter_with(actions);
        yyjson_val *action;
        while ((action = yyjson_arr_iter_next(&iterator)) != NULL) {
            const yyjson_val *stamp = fb_object_get(action, "comment");
            fb_slice stamp_id;
            const yyjson_val *url_value;
            if (!yyjson_is_obj(stamp) ||
                !fb_comment_node_id(parser, stamp, &stamp_id) ||
                stamp_id.ptr == NULL ||
                !fb_slice_equal(
                    stamp_id,
                    target->has_reply
                        ? target->reply_comment_id
                        : target->comment_id)) {
                continue;
            }
            url_value = fb_object_get(stamp, "url");
            if (yyjson_is_str(url_value) &&
                fb_comment_url_matches(
                    parser, fb_json_string(url_value),
                    target, post_ids)) {
                return true;
            }
        }
    }
    return false;
}

static const yyjson_val *
fb_select_comment(
    fb_parser *parser,
    const fb_document *document,
    const fb_comment_target *target,
    const fb_id_set *post_ids
)
{
    const yyjson_val *best = NULL;
    unsigned best_score = 0u;
    size_t best_members = 0u;
    fb_slice wanted = target->has_reply
                          ? target->reply_comment_id
                          : target->comment_id;
    size_t index;

    for (index = 0u;
         index < fb_document_comment_candidate_count(document);
         ++index) {
        const fb_json_node_ref *reference =
            fb_document_comment_candidate_at(document, index);
        const yyjson_val *comment;
        const yyjson_val *author;
        const yyjson_val *parent;
        fb_slice id;
        unsigned score;
        size_t members;
        if (reference == NULL || !yyjson_is_obj(reference->value)) {
            continue;
        }
        comment = reference->value;
        if (!fb_comment_node_id(parser, comment, &id) ||
            id.ptr == NULL || !fb_slice_equal(id, wanted)) {
            continue;
        }
        author = fb_object_get(comment, "author");
        if (!yyjson_is_obj(author) ||
            (fb_object_get(comment, "body") == NULL &&
             fb_object_get(comment, "preferred_body") == NULL)) {
            continue;
        }
        parent = fb_object_get(comment, "comment_direct_parent");
        if (target->has_reply && yyjson_is_obj(parent)) {
            fb_slice parent_id;
            if (!fb_comment_node_id(parser, parent, &parent_id) ||
                parent_id.ptr == NULL ||
                !fb_slice_equal(parent_id, target->comment_id)) {
                continue;
            }
        }
        if (!fb_comment_has_target_url(
                parser, comment, target, post_ids)) {
            continue;
        }
        score =
            (fb_object_get(comment, "attachments") != NULL ? 8u : 0u) +
            (fb_object_get(comment, "preferred_body") != NULL ? 4u : 0u) +
            (yyjson_is_obj(fb_object_get(comment, "feedback")) ? 2u : 0u);
        members = yyjson_obj_size(comment);
        if (best == NULL || score > best_score ||
            (score == best_score && members > best_members)) {
            best = comment;
            best_score = score;
            best_members = members;
        }
    }
    return best;
}

static fb_slice
fb_human_count(fb_parser *parser, const yyjson_val *value)
{
    static const char suffixes[] = "\0KMBT";
    uint64_t integer;
    double rounded;
    double amount;
    size_t magnitude = 0u;
    char significant[64];
    char result[64];
    int significant_length;
    int result_length;

    if (yyjson_is_obj(value)) {
        value = fb_object_get(value, "count");
    }
    if (yyjson_is_str(value) && !fb_ascii_digits(fb_json_string(value))) {
        return fb_json_string(value);
    }
    if (yyjson_is_str(value)) {
        fb_slice text = fb_json_string(value);
        char buffer[32];
        char *end = NULL;
        if (text.len >= sizeof(buffer)) {
            return text;
        }
        memcpy(buffer, text.ptr, text.len);
        buffer[text.len] = '\0';
        errno = 0;
        integer = strtoull(buffer, &end, 10);
        if (end == buffer || *end != '\0' || errno == ERANGE) {
            return text;
        }
    } else if (yyjson_is_uint(value)) {
        integer = yyjson_get_uint(value);
    } else if (yyjson_is_sint(value) && yyjson_get_sint(value) >= 0) {
        integer = (uint64_t)yyjson_get_sint(value);
    } else {
        return fb_value_text(parser, value);
    }
    significant_length = snprintf(
        significant, sizeof(significant), "%.3g", (double)integer);
    if (significant_length <= 0 ||
        (size_t)significant_length >= sizeof(significant)) {
        return fb_slice_make(NULL, 0u);
    }
    rounded = strtod(significant, NULL);
    amount = rounded;
    while (amount >= 1000.0 && magnitude < 4u) {
        amount /= 1000.0;
        magnitude++;
    }
    result_length = magnitude == 0u
                        ? snprintf(
                              result, sizeof(result), "%.15g", amount)
                        : snprintf(
                              result, sizeof(result), "%.15g%c",
                              amount, suffixes[magnitude]);
    if (result_length <= 0 ||
        (size_t)result_length >= sizeof(result)) {
        return fb_slice_make(NULL, 0u);
    }
    return fb_arena_slice_dup(
        parser->arena,
        fb_slice_make(result, (size_t)result_length)
    );
}

static bool
fb_comment_media(
    fb_parser *parser,
    const yyjson_val *comment,
    fb_post *post
)
{
    static const char *const image_keys[] = {
        "animated_image", "sticker_image", "image", "photo_image",
        "fallback_image"
    };
    const yyjson_val *attachments = fb_object_get(comment, "attachments");
    yyjson_arr_iter iterator;
    yyjson_val *wrapper;

    if (!yyjson_is_arr(attachments)) {
        return true;
    }
    iterator = yyjson_arr_iter_with(attachments);
    while ((wrapper = yyjson_arr_iter_next(&iterator)) != NULL) {
        const yyjson_val *renderer;
        const yyjson_val *attachment;
        const yyjson_val *media;
        fb_slice video;
        size_t key_index;
        if (!yyjson_is_obj(wrapper)) {
            continue;
        }
        renderer = fb_object_get(wrapper, "style_type_renderer");
        attachment = yyjson_is_obj(renderer)
                         ? fb_object_get(renderer, "attachment")
                         : wrapper;
        media = fb_object_get(attachment, "media");
        if (!yyjson_is_obj(media)) {
            continue;
        }
        video = fb_direct_video_url(media);
        if (video.ptr != NULL) {
            if (!fb_slice_vec_push_unique(
                    &post->video_links, parser->arena, video)) {
                return false;
            }
            continue;
        }
        for (key_index = 0u;
             key_index < FB_ARRAY_LEN(image_keys);
             ++key_index) {
            const yyjson_val *image =
                fb_object_get(media, image_keys[key_index]);
            const yyjson_val *uri = fb_object_get(image, "uri");
            if (yyjson_is_str(uri) &&
                fb_url_is_safe_media(fb_json_string(uri))) {
                if (!fb_slice_vec_push_unique(
                        &post->image_links,
                        parser->arena,
                        fb_json_string(uri))) {
                    return false;
                }
                break;
            }
        }
    }
    return true;
}

static void
fb_comment_counts(
    fb_parser *parser,
    const yyjson_val *comment,
    fb_post *post
)
{
    const yyjson_val *feedback = fb_object_get(comment, "feedback");
    const yyjson_val *reactions = fb_object_get(feedback, "reaction_count");
    const yyjson_val *replies;
    const yyjson_val *reply_count;

    if (reactions == NULL) {
        reactions = fb_object_get(
            fb_object_get(feedback, "reactors"), "count_reduced");
    }
    if (reactions == NULL) {
        reactions = fb_object_get(
            fb_object_get(feedback, "unified_reactors"), "count");
    }
    replies = fb_object_get(feedback, "replies_fields");
    if (!yyjson_is_obj(replies)) {
        replies = fb_object_get(feedback, "replies");
    }
    reply_count = fb_object_get(replies, "total_count");
    if (reply_count == NULL) {
        reply_count = fb_object_get(replies, "count");
    }
    post->likes = reactions != NULL
                      ? fb_human_count(parser, reactions)
                      : FB_SLICE_LIT("null");
    post->comments = reply_count != NULL
                         ? fb_human_count(parser, reply_count)
                         : FB_SLICE_LIT("null");
    post->shares = FB_SLICE_LIT("null");
    {
        bool reactions_ok = fb_set_top_reactions(post, feedback);
        (void)reactions_ok;
    }
}

static fb_attempt
fb_parse_comment(
    fb_parser *parser,
    fb_slice post_path,
    fb_upstream_response *prefetched
)
{
    fb_comment_target target;
    fb_url_status target_status =
        fb_url_comment_target(parser->arena, post_path, &target);
    fb_page *page;
    fb_attempt loaded;
    fb_id_set post_ids;
    fb_id_set route_ids;
    const yyjson_val *comment;
    const yyjson_val *author;
    const yyjson_val *body;
    const yyjson_val *text;
    const yyjson_val *timestamp;
    fb_post post;
    fb_slice author_name;

    if (target_status == FB_URL_NO_MEMORY) {
        return fb_no_memory();
    }
    if (target_status != FB_URL_OK ||
        target.kind == FB_COMMENT_TARGET_INVALID) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("invalid_comment_target"),
            "Invalid or ambiguous Facebook comment identity",
            prefetched,
            true
        );
    }
    if (target.kind != FB_COMMENT_TARGET_VALID) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            FB_REASON_UNSUPPORTED,
            "A comment permalink is required",
            prefetched,
            true
        );
    }
    loaded = fb_page_load(parser, post_path, prefetched, &page);
    if (!loaded.ok || page == NULL) {
        if (loaded.ok) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "page loader returned no parsed document",
                NULL,
                false
            );
        }
        return loaded;
    }
    if (!fb_get_target_ids(
            parser, page->document, post_path, page->response,
            &post_ids, &route_ids)) {
        return fb_no_memory();
    }
    comment = fb_select_comment(
        parser, page->document, &target, &post_ids);
    if (!yyjson_is_obj(comment)) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("comment_payload_missing"),
            "Facebook response did not contain the requested comment",
            page->response,
            true
        );
    }
    author = fb_object_get(comment, "author");
    author_name = fb_json_string(fb_object_get(author, "name"));
    if (author_name.ptr == NULL || author_name.len == 0u) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "Facebook comment has no author name",
            page->response,
            false
        );
    }
    fb_post_init(&post);
    post.author_name = fb_arena_format(
        parser->arena,
        "%.*s (💬)",
        (int)author_name.len,
        author_name.ptr
    );
    if (post.author_name.ptr == NULL) {
        return fb_no_memory();
    }
    body = fb_object_get(comment, "body");
    if (body == NULL || yyjson_is_null(body)) {
        body = fb_object_get(comment, "preferred_body");
    }
    text = fb_object_get(body, "text");
    post.text = yyjson_is_str(text)
                    ? fb_slice_trim(fb_json_string(text))
                    : FB_SLICE_LIT("");
    if (!fb_comment_media(parser, comment, &post)) {
        return fb_no_memory();
    }
    if (post.text.len == 0u && post.image_links.len == 0u &&
        post.video_links.len == 0u) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("comment_content_unavailable"),
            "Requested comment has no available text or media",
            page->response,
            true
        );
    }
    timestamp = fb_object_get(comment, "created_time");
    if (!yyjson_is_int(timestamp)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "Facebook comment has no creation timestamp",
            page->response,
            false
        );
    }
    post.date = yyjson_get_sint(timestamp);
    if (fb_url_ensure_full(
            parser->arena, post_path, &post.url) != FB_URL_OK) {
        return fb_no_memory();
    }
    fb_comment_counts(parser, comment, &post);
    if (fb_author_is_banned(parser, author)) {
        fb_post_set_banned(&post);
    }
    return fb_attempt_success(&post);
}

static bool
fb_block_has_key(const fb_json_block *block, const char *key)
{
    return block != NULL &&
           fb_json_block_key_count(block, fb_slice_from_cstr(key)) != 0u;
}

static const fb_json_block *
fb_select_block_with_keys(
    fb_parser *parser,
    const fb_document *document,
    const char *first_key,
    const char *second_key,
    const fb_id_set *requested,
    bool shortest
)
{
    const fb_json_block *first = NULL;
    const fb_json_block *url_match = NULL;
    const fb_json_block *exact_match = NULL;
    size_t exact_size = SIZE_MAX;
    size_t url_size = SIZE_MAX;
    size_t block_index;

    for (block_index = 0u;
         block_index < fb_document_json_block_count(document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(document, block_index);
        const yyjson_val *root;
        size_t size;
        if (!fb_block_has_key(block, first_key) ||
            (second_key != NULL &&
             !fb_block_has_key(block, second_key))) {
            continue;
        }
        root = fb_json_block_root(block);
        size = fb_json_block_value_count(block);
        if (first == NULL) {
            first = block;
        }
        if (requested != NULL && requested->len != 0u &&
            fb_subtree_contains_exact_id(parser, root, requested) &&
            (!shortest || size < exact_size)) {
            exact_match = block;
            exact_size = size;
        } else if (requested != NULL && requested->len != 0u &&
                   fb_subtree_contains_target_id(
                       parser, root, requested) &&
                   (!shortest || size < url_size)) {
            url_match = block;
            url_size = size;
        }
    }
    if (requested != NULL && requested->len != 0u) {
        return exact_match != NULL ? exact_match : url_match;
    }
    return first;
}

static bool
fb_add_base64_numeric_tail(
    fb_parser *parser,
    fb_id_set *ids,
    fb_slice encoded
)
{
    unsigned char input[1024];
    unsigned char decoded[1024];
    size_t padded;
    int decoded_length;
    size_t run_begin = SIZE_MAX;
    size_t last_begin = SIZE_MAX;
    size_t last_length = 0u;
    size_t index;

    if (!fb_base64_syntax_valid(encoded) ||
        encoded.len > sizeof(input) - 4u) {
        return true;
    }
    memcpy(input, encoded.ptr, encoded.len);
    padded = encoded.len;
    while ((padded & 3u) != 0u) {
        input[padded++] = (unsigned char)'=';
    }
    decoded_length = fb_base64_decode_block(decoded, input, padded);
    if (decoded_length < 0) {
        return true;
    }
    while (padded != 0u && input[padded - 1u] == (unsigned char)'=') {
        decoded_length--;
        padded--;
    }
    if (decoded_length <= 0) {
        return true;
    }
    for (index = 0u; index <= (size_t)decoded_length; ++index) {
        bool digit = index < (size_t)decoded_length &&
                     decoded[index] >= (unsigned char)'0' &&
                     decoded[index] <= (unsigned char)'9';
        if (digit && run_begin == SIZE_MAX) {
            run_begin = index;
        } else if (!digit && run_begin != SIZE_MAX) {
            last_begin = run_begin;
            last_length = index - run_begin;
            run_begin = SIZE_MAX;
        }
    }
    if (last_begin != SIZE_MAX) {
        fb_slice copy = fb_arena_slice_dup(
            parser->arena,
            fb_slice_make(
                (const char *)decoded + last_begin, last_length));
        return copy.ptr != NULL && fb_id_set_add(ids, copy);
    }
    return true;
}

static bool
fb_collect_photo_interaction_ids(
    fb_parser *parser,
    const yyjson_val *object,
    fb_id_set *ids
)
{
    fb_effective_object_iter iterator;
    fb_slice key;
    const yyjson_val *value;

    if (!yyjson_is_obj(object)) {
        return true;
    }
    if (!fb_collect_direct_identity_ids(
            parser, object, ids, false)) {
        return false;
    }
    fb_effective_object_iter_init(&iterator, object, parser);
    while (fb_effective_object_iter_next(
               &iterator, &key, &value)) {
        if (fb_identity_key(key) && yyjson_is_str(value) &&
            !fb_add_base64_numeric_tail(
                parser, ids, fb_json_string(value))) {
            return false;
        }
    }
    return true;
}

static fb_attempt
fb_parse_single_photo(
    fb_parser *parser,
    fb_slice post_path,
    fb_upstream_response *prefetched
)
{
    fb_page *page;
    fb_attempt loaded = fb_page_load(
        parser, post_path, prefetched, &page);
    fb_id_set requested;
    fb_id_set route_ids;
    fb_id_set interaction_ids;
    const fb_json_block *content_block;
    const fb_json_block *interaction_block;
    const fb_json_block *image_block;
    const yyjson_val *content;
    const yyjson_val *owner;
    const yyjson_val *message;
    const yyjson_val *image_list;
    const yyjson_val *image_entry;
    const yyjson_val *image_uri;
    fb_post post;

    if (!loaded.ok || page == NULL) {
        if (loaded.ok) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "page loader returned no parsed document",
                NULL,
                false
            );
        }
        return loaded;
    }
    if (!fb_get_target_ids(
            parser, page->document, post_path, page->response,
            &requested, &route_ids)) {
        return fb_no_memory();
    }
    content_block = fb_select_block_with_keys(
        parser, page->document,
        "message_preferred_body", "container_story",
        &requested, true);
    if (content_block == NULL) {
        return fb_error_static(
            requested.len != 0u
                ? FB_PARSE_ERROR_NO_DATA
                : FB_PARSE_ERROR_DOCUMENT,
            requested.len != 0u
                ? FB_REASON_NO_DATA
                : FB_REASON_PARSER,
            "Facebook response did not contain the requested photo",
            page->response,
            false
        );
    }
    content = fb_select_subtree_key(
        parser, fb_json_block_root(content_block), "data", &requested);
    if (!yyjson_is_obj(content)) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_REASON_NO_DATA,
            "Facebook response did not contain the requested photo",
            page->response,
            false
        );
    }
    if (!fb_id_set_init(&interaction_ids, parser->arena) ||
        !fb_id_set_add_set(&interaction_ids, &requested) ||
        !fb_collect_photo_interaction_ids(
            parser, content, &interaction_ids)) {
        return fb_no_memory();
    }
    {
        const yyjson_val *container =
            fb_subtree_first(parser, content, "container_story");
        const yyjson_val *creation =
            fb_subtree_first(parser, content, "creation_story");
        if ((yyjson_is_obj(container) &&
             !fb_collect_photo_interaction_ids(
                 parser, container, &interaction_ids)) ||
            (yyjson_is_obj(creation) &&
             !fb_collect_photo_interaction_ids(
                 parser, creation, &interaction_ids))) {
            return fb_no_memory();
        }
    }
    interaction_block = fb_select_block_with_keys(
        parser, page->document,
        "comet_ufi_summary_and_actions_renderer", NULL,
        &interaction_ids, true);
    image_block = fb_select_block_with_keys(
        parser, page->document, "prefetch_uris_v2", NULL,
        &requested, true);
    if (image_block == NULL) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "cannot find single image",
            page->response,
            false
        );
    }
    image_list = fb_subtree_first(
        parser, fb_json_block_root(image_block), "prefetch_uris_v2");
    image_entry = yyjson_arr_get(image_list, 0u);
    image_uri = fb_object_get(image_entry, "uri");
    if (!yyjson_is_str(image_uri) ||
        !fb_url_is_safe_media(fb_json_string(image_uri))) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "cannot find single image",
            page->response,
            false
        );
    }
    owner = fb_object_get(content, "owner");
    message = fb_object_get(content, "message");
    fb_post_init(&post);
    post.author_name = fb_json_string(fb_object_get(owner, "name"));
    if (post.author_name.ptr == NULL || post.author_name.len == 0u) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "photo payload has no owner",
            page->response,
            false
        );
    }
    if (message == NULL) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "photo payload has no message field",
            page->response,
            false
        );
    }
    post.text = yyjson_is_obj(message) &&
                        yyjson_is_str(fb_object_get(message, "text"))
                    ? fb_slice_trim(
                          fb_json_string(fb_object_get(message, "text")))
                    : FB_SLICE_LIT("");
    if (!fb_json_to_i64(
            fb_object_get(content, "created_time"), &post.date)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "photo payload has no creation timestamp",
            page->response,
            false
        );
    }
    if (!fb_slice_vec_push(
            &post.image_links, parser->arena,
            fb_json_string(image_uri)) ||
        fb_url_ensure_full(
            parser->arena, post_path, &post.url) != FB_URL_OK) {
        return fb_no_memory();
    }
    if (interaction_block != NULL) {
        fb_extract_interactions(
            parser, fb_json_block_root(interaction_block),
            &interaction_ids, &post);
    } else {
        post.likes = FB_SLICE_LIT("0");
        post.comments = FB_SLICE_LIT("0");
        post.shares = FB_SLICE_LIT("0");
    }
    return fb_attempt_success(&post);
}

static fb_attempt
fb_parse_photocom(
    fb_parser *parser,
    fb_slice post_path,
    fb_upstream_response *prefetched
)
{
    fb_page *page;
    fb_attempt loaded =
        fb_page_load(parser, post_path, prefetched, &page);
    fb_id_set requested;
    fb_id_set route_ids;
    const fb_json_block *content_block = NULL;
    const fb_json_block *media_block = NULL;
    const yyjson_val *content = NULL;
    const yyjson_val *data;
    const yyjson_val *attached;
    const yyjson_val *body;
    const yyjson_val *owner;
    const yyjson_val *current;
    const yyjson_val *feedback;
    const yyjson_val *image;
    const yyjson_val *uri;
    const yyjson_val *url;
    fb_post post;
    size_t block_index;

    if (!loaded.ok || page == NULL) {
        if (loaded.ok) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "page loader returned no parsed document",
                NULL,
                false
            );
        }
        return loaded;
    }
    if (!fb_get_target_ids(
            parser, page->document, post_path, page->response,
            &requested, &route_ids)) {
        return fb_no_memory();
    }
    for (block_index = 0u;
         block_index < fb_document_json_block_count(page->document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(page->document, block_index);
        if (block == NULL || !fb_block_has_key(block, "attached_comment")) {
            continue;
        }
        if (fb_block_has_key(block, "unified_reactors")) {
            if (media_block == NULL &&
                (requested.len == 0u ||
                 fb_subtree_contains_target_id(
                     parser, fb_json_block_root(block), &requested))) {
                media_block = block;
            }
        } else if (content_block == NULL) {
            const yyjson_val *result = fb_select_subtree_key(
                parser, fb_json_block_root(block), "result", &requested);
            if (yyjson_is_obj(result)) {
                content_block = block;
                content = result;
            }
        }
    }
    if (content_block == NULL || media_block == NULL ||
        !yyjson_is_obj(content)) {
        return fb_error_static(
            requested.len != 0u
                ? FB_PARSE_ERROR_NO_DATA
                : FB_PARSE_ERROR_DOCUMENT,
            requested.len != 0u
                ? FB_REASON_NO_DATA
                : FB_REASON_PARSER,
            "Cannot process photocom",
            page->response,
            false
        );
    }
    data = fb_object_get(content, "data");
    attached = fb_object_get(data, "attached_comment");
    body = fb_object_get(attached, "preferred_body");
    owner = fb_object_get(data, "owner");
    current = fb_subtree_first(
        parser, fb_json_block_root(media_block), "currMedia");
    feedback = fb_object_get(
        fb_object_get(current, "attached_comment"), "feedback");
    image = fb_object_get(current, "image");
    uri = fb_object_get(image, "uri");
    url = fb_object_get(feedback, "url");
    if (!yyjson_is_obj(data) || !yyjson_is_obj(current) ||
        !yyjson_is_str(fb_object_get(owner, "name")) ||
        !yyjson_is_str(uri) || !fb_url_is_safe_media(fb_json_string(uri)) ||
        !yyjson_is_str(url)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "Cannot process photocom payload",
            page->response,
            false
        );
    }
    fb_post_init(&post);
    {
        fb_slice name = fb_json_string(fb_object_get(owner, "name"));
        post.author_name = fb_arena_format(
            parser->arena, "%.*s (💬)", (int)name.len, name.ptr);
    }
    if (post.author_name.ptr == NULL) {
        return fb_no_memory();
    }
    post.text = yyjson_is_obj(body) &&
                        yyjson_is_str(fb_object_get(body, "text"))
                    ? fb_json_string(fb_object_get(body, "text"))
                    : FB_SLICE_LIT("");
    if (!fb_json_to_i64(
            fb_object_get(data, "created_time"), &post.date)) {
        post.date = -1;
    }
    post.url = fb_json_string(url);
    if (!fb_slice_vec_push(
            &post.image_links, parser->arena, fb_json_string(uri))) {
        return fb_no_memory();
    }
    {
        const yyjson_val *reactors =
            fb_object_get(feedback, "unified_reactors");
        const yyjson_val *count = fb_object_get(reactors, "count");
        post.likes = count != NULL
                         ? fb_human_count(parser, count)
                         : FB_SLICE_LIT("null");
    }
    post.comments = FB_SLICE_LIT("null");
    post.shares = FB_SLICE_LIT("null");
    {
        bool reactions_ok = fb_set_top_reactions(&post, feedback);
        (void)reactions_ok;
    }
    return fb_attempt_success(&post);
}

static const yyjson_val *
fb_select_reel_content(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *requested
)
{
    static const char *const keys[] = {
        "creation_story", "short_form_video_context"
    };
    const yyjson_val *fallback = NULL;
    const yyjson_val *url_match = NULL;
    size_t block_index;

    for (block_index = 0u;
         block_index < fb_document_json_block_count(document);
         ++block_index) {
        const fb_json_block *block =
            fb_document_json_block_at(document, block_index);
        size_t key_index;
        if (block == NULL) {
            continue;
        }
        for (key_index = 0u;
             key_index < FB_ARRAY_LEN(keys);
             ++key_index) {
            fb_block_key_cursor cursor;
            fb_block_key_cursor_init(
                &cursor, block, keys[key_index]);
            for (;;) {
                fb_json_match match;
                if (!fb_block_key_cursor_next(&cursor, &match)) {
                    break;
                }
                if (!yyjson_is_obj(match.value)) {
                    continue;
                }
                if (fallback == NULL) {
                    fallback = match.value;
                }
                if (requested != NULL && requested->len != 0u) {
                    if (fb_subtree_contains_exact_id(
                            parser, match.value, requested)) {
                        return match.value;
                    }
                    if (url_match == NULL &&
                        fb_subtree_contains_target_id(
                            parser, match.value, requested)) {
                        url_match = match.value;
                    }
                }
            }
        }
    }
    return requested != NULL && requested->len != 0u
               ? url_match
               : fallback;
}

static fb_slice
fb_select_video_link(
    fb_parser *parser,
    const fb_document *document,
    const fb_id_set *requested
)
{
    size_t index;
    if (requested != NULL && requested->len != 0u) {
        for (index = 0u;
             index < fb_document_video_delivery_candidate_count(document);
             ++index) {
            const fb_json_node_ref *reference =
                fb_document_video_delivery_candidate_at(document, index);
            if (reference != NULL &&
                fb_video_node_matches(
                    parser, reference->value, requested)) {
                fb_slice link = fb_direct_video_url(reference->value);
                if (link.ptr != NULL) {
                    return link;
                }
            }
        }
        return fb_slice_make(NULL, 0u);
    }
    for (index = 0u;
         index < fb_document_video_delivery_candidate_count(document);
         ++index) {
        const fb_json_node_ref *reference =
            fb_document_video_delivery_candidate_at(document, index);
        if (reference != NULL) {
            fb_slice link = fb_direct_video_url(reference->value);
            if (link.ptr != NULL) {
                return link;
            }
        }
    }
    return fb_slice_make(NULL, 0u);
}

static const yyjson_val *
fb_reel_feedback(
    fb_parser *parser,
    const fb_document *document,
    const yyjson_val *content,
    const fb_id_set *requested
)
{
    const yyjson_val *feedback = fb_object_get(content, "feedback");
    const yyjson_val *best = NULL;
    double best_count = -1.0;
    fb_document_key_cursor cursor;

    if (yyjson_is_obj(feedback) &&
        fb_object_get(feedback, "unified_reactors") != NULL) {
        return feedback;
    }
    fb_document_key_cursor_init(&cursor, document, "feedback");
    for (;;) {
        fb_json_match match;
        const yyjson_val *reactors;
        const yyjson_val *value;
        double numeric;
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (!yyjson_is_obj(match.value)) {
            continue;
        }
        reactors = fb_object_get(match.value, "unified_reactors");
        if (!yyjson_is_obj(reactors)) {
            continue;
        }
        if (requested != NULL && requested->len != 0u &&
            !fb_subtree_contains_target_id(
                parser, match.object, requested) &&
            !fb_subtree_contains_target_id(
                parser, match.value, requested)) {
            continue;
        }
        value = fb_object_get(reactors, "count");
        numeric = fb_reaction_numeric(value);
        if (best == NULL || numeric > best_count) {
            best = match.value;
            best_count = numeric;
        }
    }
    return best;
}

static const yyjson_val *
fb_reel_companion_feedback(
    fb_parser *parser,
    const fb_document *document,
    const yyjson_val *primary,
    const fb_id_set *target_ids
)
{
    fb_slice primary_id =
        fb_value_text(parser, fb_object_get(primary, "id"));
    const yyjson_val *matching_id = NULL;
    const yyjson_val *contextual = NULL;
    const yyjson_val *cross_matching_id = NULL;
    const yyjson_val *cross_contextual = NULL;
    fb_document_key_cursor cursor;

    fb_document_key_cursor_init(&cursor, document, "feedback");
    for (;;) {
        fb_json_match match;
        const yyjson_val *candidate;
        fb_slice candidate_id;
        bool same_id;
        bool has_counts;
        bool has_cross;
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (!yyjson_is_obj(match.value) ||
            match.value == primary ||
            (target_ids != NULL && target_ids->len != 0u &&
             !fb_subtree_contains_target_id(
                 parser, match.object, target_ids) &&
             !fb_subtree_contains_target_id(
                 parser, match.value, target_ids))) {
            continue;
        }
        candidate = match.value;
        candidate_id =
            fb_value_text(parser, fb_object_get(candidate, "id"));
        same_id = primary_id.ptr != NULL &&
                  candidate_id.ptr != NULL &&
                  fb_slice_equal(primary_id, candidate_id);
        has_counts =
            fb_object_get(candidate, "total_comment_count") != NULL ||
            fb_object_get(candidate, "share_count_reduced") != NULL ||
            fb_object_get(candidate, "share_count") != NULL;
        has_cross =
            fb_object_get(candidate, "cross_universe_feedback_info") != NULL;
        if (same_id && has_counts) {
            matching_id = candidate;
        } else if (has_counts) {
            contextual = candidate;
        }
        if (same_id && has_cross) {
            cross_matching_id = candidate;
        } else if (has_cross) {
            cross_contextual = candidate;
        }
    }
    if (matching_id != NULL) {
        return matching_id;
    }
    if (contextual != NULL) {
        return contextual;
    }
    if (cross_matching_id != NULL) {
        return cross_matching_id;
    }
    if (cross_contextual != NULL) {
        return cross_contextual;
    }
    return primary;
}

static fb_attempt
fb_parse_reel(
    fb_parser *parser,
    fb_slice post_path,
    fb_upstream_response *prefetched
)
{
    fb_page *page;
    fb_attempt loaded =
        fb_page_load(parser, post_path, prefetched, &page);
    fb_id_set requested;
    fb_id_set route_ids;
    fb_id_set reaction_ids;
    const yyjson_val *content;
    const yyjson_val *context;
    const yyjson_val *owner;
    const yyjson_val *feedback;
    const yyjson_val *message;
    fb_slice video_link;
    fb_post post;
    bool is_instagram;

    if (!loaded.ok || page == NULL) {
        if (loaded.ok) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "page loader returned no parsed document",
                NULL,
                false
            );
        }
        return loaded;
    }
    if (!fb_get_target_ids(
            parser, page->document, post_path, page->response,
            &requested, &route_ids)) {
        return fb_no_memory();
    }
    content = fb_select_reel_content(
        parser, page->document, &requested);
    if (!yyjson_is_obj(content)) {
        return fb_error_static(
            requested.len != 0u
                ? FB_PARSE_ERROR_NO_DATA
                : FB_PARSE_ERROR_DOCUMENT,
            requested.len != 0u
                ? FB_REASON_NO_DATA
                : FB_REASON_PARSER,
            "Facebook response did not contain the requested video",
            page->response,
            false
        );
    }
    video_link = fb_select_video_link(
        parser, page->document, &requested);
    if (video_link.ptr == NULL) {
        return fb_error_static(
            requested.len != 0u
                ? FB_PARSE_ERROR_NO_DATA
                : FB_PARSE_ERROR_DOCUMENT,
            requested.len != 0u
                ? FB_REASON_NO_DATA
                : FB_REASON_PARSER,
            "Facebook response did not contain the requested video",
            page->response,
            false
        );
    }
    context = fb_object_get(content, "short_form_video_context");
    owner = fb_object_get(context, "video_owner");
    if (!yyjson_is_obj(owner)) {
        owner = fb_object_get(content, "video_owner");
    }
    if (!yyjson_is_obj(owner)) {
        owner = fb_subtree_first(parser, content, "video_owner");
    }
    if (!yyjson_is_obj(owner)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "reel payload has no owner",
            page->response,
            false
        );
    }
    {
        const yyjson_val *typename_node =
            fb_object_get(owner, "__typename");
        fb_slice typename_value;
        if (!yyjson_is_str(typename_node)) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "reel payload has no owner type",
                page->response,
                false
            );
        }
        typename_value = fb_json_string(typename_node);
        is_instagram = fb_slice_starts_literal_ascii_case(
            typename_value, "InstagramUser");
    }
    fb_post_init(&post);
    {
        const yyjson_val *name = fb_object_get(
            owner, is_instagram ? "username" : "name");
        if (!yyjson_is_str(name)) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "reel payload has no owner name",
                page->response,
                false
            );
        }
        post.author_name = is_instagram
                               ? fb_arena_format(
                                     parser->arena, "📷 @%.*s",
                                     (int)yyjson_get_len(name),
                                     yyjson_get_str(name))
                               : fb_json_string(name);
        if (post.author_name.ptr == NULL) {
            return fb_no_memory();
        }
    }
    {
        const yyjson_val *shareable =
            fb_object_get(context, "shareable_url");
        if (yyjson_is_str(shareable)) {
            post.url = fb_json_string(shareable);
        } else if (fb_url_ensure_full(
                       parser->arena, post_path,
                       &post.url) != FB_URL_OK) {
            return fb_no_memory();
        }
    }
    post.date = -1;
    if (!fb_json_to_i64(
            fb_object_get(content, "creation_time"), &post.date)) {
        const yyjson_val *time = fb_select_requested_field(
            parser, page->document, "creation_time", &requested);
        if (!fb_json_truthy(time)) {
            time = fb_select_requested_field(
                parser, page->document, "created_time", &requested);
        }
        (void)fb_json_to_i64(time, &post.date);
    }
    message = fb_object_get(content, "message");
    post.text = yyjson_is_obj(message) &&
                        yyjson_is_str(fb_object_get(message, "text"))
                    ? fb_json_string(fb_object_get(message, "text"))
                    : FB_SLICE_LIT("");
    if (!fb_slice_vec_push(
            &post.video_links, parser->arena, video_link)) {
        return fb_no_memory();
    }
    if (!fb_id_set_init(&reaction_ids, parser->arena) ||
        !fb_id_set_add_set(&reaction_ids, &requested) ||
        !fb_collect_direct_identity_ids(
            parser, content, &reaction_ids, false)) {
        return fb_no_memory();
    }
    {
        const yyjson_val *content_feedback =
            fb_object_get(content, "feedback");
        if (yyjson_is_obj(content_feedback) &&
            !fb_id_set_add_scalar(
                parser, &reaction_ids,
                fb_object_get(content_feedback, "id"))) {
            return fb_no_memory();
        }
    }
    feedback = fb_reel_feedback(
        parser, page->document, content, &reaction_ids);
    if (!yyjson_is_obj(feedback)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "Cannot associate reactions with requested video",
            page->response,
            false
        );
    }
    post.likes = fb_human_count(
        parser,
        fb_object_get(
            fb_object_get(feedback, "unified_reactors"), "count"));
    {
        const yyjson_val *companion = fb_reel_companion_feedback(
            parser, page->document, feedback, &reaction_ids);
        const yyjson_val *cross =
            fb_object_get(companion, "cross_universe_feedback_info");
        const yyjson_val *comments =
            is_instagram
                ? fb_object_get(cross, "ig_comment_count")
                : fb_object_get(companion, "total_comment_count");
        const yyjson_val *shares =
            fb_object_get(companion, "share_count_reduced");
        if (shares == NULL) {
            shares = fb_object_get(companion, "share_count");
        }
        post.comments = comments != NULL
                            ? fb_human_count(parser, comments)
                            : FB_SLICE_LIT("0");
        post.shares = shares != NULL
                          ? fb_human_count(parser, shares)
                          : FB_SLICE_LIT("0");
    }
    if (post.likes.ptr == NULL || post.comments.ptr == NULL ||
        post.shares.ptr == NULL) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "reel payload has incomplete interaction counts",
            page->response,
            false
        );
    }
    if (fb_author_is_banned(parser, owner)) {
        fb_post_set_banned(&post);
    }
    return fb_attempt_success(&post);
}

static fb_attempt
fb_parse_watch(
    fb_parser *parser,
    fb_slice post_path,
    fb_upstream_response *prefetched
)
{
    fb_page *page;
    fb_attempt loaded =
        fb_page_load(parser, post_path, prefetched, &page);
    fb_id_set requested;
    fb_id_set route_ids;
    const yyjson_val *content = NULL;
    const yyjson_val *url_content = NULL;
    const yyjson_val *owner;
    const yyjson_val *feedback;
    const yyjson_val *title;
    fb_slice video_link;
    fb_post post;
    fb_document_key_cursor cursor;
    size_t index;

    if (!loaded.ok || page == NULL) {
        if (loaded.ok) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "page loader returned no parsed document",
                NULL,
                false
            );
        }
        return loaded;
    }
    if (!fb_get_target_ids(
            parser, page->document, post_path, page->response,
            &requested, &route_ids)) {
        return fb_no_memory();
    }
    fb_document_key_cursor_init(
        &cursor, page->document, "result");
    for (;;) {
        fb_json_match match;
        const yyjson_val *data;
        if (!fb_document_key_cursor_next(&cursor, &match)) {
            break;
        }
        if (!yyjson_is_obj(match.value)) {
            continue;
        }
        data = fb_object_get(match.value, "data");
        if (!yyjson_is_obj(data) ||
            !fb_subtree_has(
                parser, data, "comment_rendering_instance") ||
            !fb_subtree_has(
                parser, data, "video_view_count_renderer")) {
            continue;
        }
        if (requested.len == 0u) {
            content = data;
            break;
        }
        if (fb_subtree_contains_exact_id(parser, data, &requested)) {
            content = data;
            break;
        }
        if (url_content == NULL &&
            fb_subtree_contains_target_id(
                parser, data, &requested)) {
            url_content = data;
        }
    }
    if (content == NULL) {
        content = url_content;
    }
    if (!yyjson_is_obj(content)) {
        size_t canonical_count = fb_document_declared_url_count(
            page->document, FB_DECLARED_URL_CANONICAL);
        for (index = 0u; index < canonical_count; ++index) {
            const fb_declared_url *declared = fb_document_declared_url_at(
                page->document, FB_DECLARED_URL_CANONICAL, index);
            fb_slice path;
            if (declared == NULL) {
                continue;
            }
            path = fb_path_without_trailing_slash(
                fb_url_path_only(declared->value));
            if (fb_slice_equal_literal_ascii_case(path, "/watch")) {
                return fb_error_static(
                    FB_PARSE_ERROR_NO_DATA,
                    FB_REASON_NO_DATA,
                    "Facebook served generic watch feed instead of specific video",
                    page->response,
                    false
                );
            }
        }
        return fb_error_static(
            requested.len != 0u
                ? FB_PARSE_ERROR_NO_DATA
                : FB_PARSE_ERROR_DOCUMENT,
            requested.len != 0u
                ? FB_REASON_NO_DATA
                : FB_REASON_PARSER,
            "Facebook response did not contain the requested video",
            page->response,
            false
        );
    }
    video_link = fb_select_video_link(
        parser, page->document, &requested);
    if (video_link.ptr == NULL) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_REASON_NO_DATA,
            "Facebook response did not contain the requested video",
            page->response,
            false
        );
    }
    owner = fb_object_get(content, "owner");
    if (!yyjson_is_obj(owner) ||
        !yyjson_is_str(fb_object_get(owner, "name"))) {
        owner = fb_subtree_first(parser, content, "owner");
    }
    if (!yyjson_is_obj(owner) ||
        !yyjson_is_str(fb_object_get(owner, "name"))) {
        owner = fb_select_requested_field(
            parser, page->document, "owner", &requested);
    }
    feedback = fb_object_get(content, "feedback");
    if (!yyjson_is_obj(owner) ||
        !yyjson_is_str(fb_object_get(owner, "name")) ||
        !yyjson_is_obj(feedback)) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "Invalid watch payload",
            page->response,
            false
        );
    }
    fb_post_init(&post);
    post.author_name = fb_json_string(fb_object_get(owner, "name"));
    title = fb_object_get(content, "title");
    post.text = yyjson_is_obj(title) &&
                        yyjson_is_str(fb_object_get(title, "text"))
                    ? fb_json_string(fb_object_get(title, "text"))
                    : FB_SLICE_LIT("");
    if (post.text.len == 0u) {
        const yyjson_val *message =
            fb_subtree_first(parser, content, "message");
        if (yyjson_is_obj(message) &&
            yyjson_is_str(fb_object_get(message, "text"))) {
            post.text = fb_json_string(fb_object_get(message, "text"));
        }
    }
    if (fb_url_ensure_full(
            parser->arena, post_path, &post.url) != FB_URL_OK ||
        !fb_slice_vec_push(
            &post.video_links, parser->arena, video_link)) {
        return fb_no_memory();
    }
    post.likes = fb_human_count(
        parser,
        fb_object_get(
            fb_object_get(feedback, "reaction_count"), "count"));
    post.comments = fb_human_count(
        parser, fb_object_get(feedback, "total_comment_count"));
    if (post.likes.ptr == NULL || post.comments.ptr == NULL) {
        return fb_error_static(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_PARSER,
            "watch payload has incomplete interaction counts",
            page->response,
            false
        );
    }
    post.shares = FB_SLICE_LIT("null");
    post.date = -1;
    if (!fb_json_to_i64(
            fb_object_get(content, "creation_time"), &post.date)) {
        const yyjson_val *time = fb_select_requested_field(
            parser, page->document, "creation_time", &requested);
        if (!fb_json_to_i64(time, &post.date)) {
            return fb_error_static(
                FB_PARSE_ERROR_DOCUMENT,
                FB_REASON_PARSER,
                "cannot find date",
                page->response,
                false
            );
        }
    }
    {
        bool reactions_ok = fb_set_top_reactions(&post, feedback);
        (void)reactions_ok;
    }
    return fb_attempt_success(&post);
}

static fb_attempt
fb_share_resolution_error(fb_attempt source)
{
    if (source.error.kind != FB_PARSE_ERROR_NO_DATA) {
        return source;
    }
    source.error.kind = FB_PARSE_ERROR_SHARE_RESOLUTION;
    source.error.count_as_error = false;
    return source;
}

static bool
fb_path_is_video_like(fb_parser *parser, fb_slice path)
{
    fb_path_segments parts;
    size_t index;

    if (fb_url_facebook_path_segments(
            parser->arena, path, &parts) != FB_URL_OK ||
        parts.len == 0u) {
        return false;
    }
    if (fb_slice_equal_literal_ascii_case(
            fb_path_segment_at(&parts, 0u), "watch") ||
        fb_slice_equal_literal_ascii_case(
            fb_path_segment_at(&parts, 0u), "reel")) {
        return true;
    }
    for (index = 0u; index < parts.len; ++index) {
        if (fb_slice_equal_literal_ascii_case(
                fb_path_segment_at(&parts, index), "videos")) {
            return true;
        }
    }
    if (fb_slice_equal_literal_ascii_case(
            fb_path_segment_at(&parts, 0u), "groups")) {
        for (index = 1u; index < parts.len; ++index) {
            if (fb_slice_equal_literal_ascii_case(
                    fb_path_segment_at(&parts, index), "posts") ||
                fb_slice_equal_literal_ascii_case(
                    fb_path_segment_at(&parts, index), "permalink")) {
                return true;
            }
        }
    }
    return false;
}

static bool
fb_share_is_v(fb_parser *parser, fb_slice path)
{
    fb_path_segments parts;
    return fb_url_facebook_path_segments(
               parser->arena, path, &parts) == FB_URL_OK &&
           parts.len >= 2u &&
           fb_slice_equal_literal_ascii_case(
               fb_path_segment_at(&parts, 0u), "share") &&
           fb_slice_equal_literal_ascii_case(
               fb_path_segment_at(&parts, 1u), "v");
}

static bool
fb_declared_target_usable(
    fb_parser *parser,
    fb_slice declared,
    fb_slice *normalized
)
{
    fb_path_segments parts;
    fb_slice first;
    fb_slice full;

    if (fb_url_ensure_full(parser->arena, declared, &full) != FB_URL_OK ||
        !fb_url_is_facebook(full, false) ||
        fb_url_normalize_facebook_path(
            parser->arena, full, normalized) != FB_URL_OK ||
        fb_url_facebook_path_segments(
            parser->arena, full, &parts) != FB_URL_OK ||
        parts.len == 0u ||
        fb_url_is_share_path(*normalized) ||
        fb_url_is_auth_control_path(full) ||
        fb_url_is_group_landing_target(*normalized)) {
        return false;
    }
    first = fb_path_segment_at(&parts, 0u);
    return !fb_slice_equal_literal_ascii_case(first, "login") &&
           !fb_slice_equal_literal_ascii_case(first, "checkpoint") &&
           !fb_slice_equal_literal_ascii_case(first, "recover");
}

static fb_attempt
fb_parse_share_document(
    fb_parser *parser,
    fb_slice source_path,
    fb_upstream_response *response,
    fb_document **document,
    fb_slice *direct_path,
    bool *declared_target,
    bool *response_is_facebook,
    fb_probe_kind *probe
)
{
    fb_document_error error;
    fb_document_status status;
    size_t index;

    *declared_target = false;
    *response_is_facebook = fb_url_is_facebook(response->url, false);
    if (fb_url_normalize_facebook_path(
            parser->arena, response->url, direct_path) != FB_URL_OK) {
        return fb_no_memory();
    }
    status = fb_document_parse_cancelable(
        parser->arena, response->body, NULL, parser->cancel,
        document, &error);
    if (status != FB_DOCUMENT_OK) {
        if (status == FB_DOCUMENT_CANCELLED) {
            parser->cancelled = true;
            return fb_cancelled();
        }
        if (status == FB_DOCUMENT_NO_MEMORY) {
            return fb_no_memory();
        }
        fb_slice detail = fb_arena_format(
            parser->arena,
            "Facebook share document parse failed: %s/%s at byte %zu",
            fb_document_status_string(status),
            fb_document_issue_string(error.issue),
            error.source_offset
        );
        if (detail.ptr == NULL) {
            return fb_no_memory();
        }
        return fb_attempt_error(
            FB_PARSE_ERROR_DOCUMENT,
            FB_REASON_DOCUMENT,
            detail,
            response,
            false,
            false,
            response->body.len != 0u
        );
    }
    for (index = 0u;
         index < fb_document_declared_url_count(
                     *document, FB_DECLARED_URL_CANONICAL);
         ++index) {
        const fb_declared_url *declared = fb_document_declared_url_at(
            *document, FB_DECLARED_URL_CANONICAL, index);
        fb_slice candidate;
        if (declared != NULL &&
            fb_declared_target_usable(
                parser, declared->value, &candidate)) {
            *direct_path = candidate;
            *declared_target = true;
            break;
        }
    }
    if (!*declared_target) {
        for (index = 0u;
             index < fb_document_declared_url_count(
                         *document, FB_DECLARED_URL_OG_URL);
             ++index) {
            const fb_declared_url *declared = fb_document_declared_url_at(
                *document, FB_DECLARED_URL_OG_URL, index);
            fb_slice candidate;
            if (declared != NULL &&
                fb_declared_target_usable(
                    parser, declared->value, &candidate)) {
                *direct_path = candidate;
                *declared_target = true;
                break;
            }
        }
    }
    *probe = FB_PROBE_UNKNOWN;
    if (*response_is_facebook) {
        *probe = fb_probe_page(
            parser, *document, *direct_path, response);
        if (*probe == FB_PROBE_UNKNOWN &&
            !fb_slice_equal(source_path, *direct_path)) {
            *probe = fb_probe_page(
                parser, *document, source_path, response);
        }
    }
    return (fb_attempt){.ok = true};
}

static fb_attempt
fb_resolve_share(
    fb_parser *parser,
    fb_slice source_path,
    fb_share_target *target
)
{
    fb_slice full_url;
    fb_transport_options options;
    fb_transport_result transport;
    fb_upstream_response *head = NULL;
    fb_upstream_response *response;
    bool needs_get = true;
    bool is_share_v;
    fb_document *document;
    fb_slice direct_path;
    bool declared_target;
    bool response_is_facebook;
    fb_probe_kind probe;
    fb_attempt inspected;

    memset(target, 0, sizeof(*target));
    if (fb_url_normalize_facebook_path(
            parser->arena, source_path, &source_path) != FB_URL_OK ||
        fb_url_ensure_full(
            parser->arena, source_path, &full_url) != FB_URL_OK) {
        return fb_no_memory();
    }
    is_share_v = fb_share_is_v(parser, source_path);
    options = fb_transport_default_options(FB_HTTP_HEAD);
    options.user_agent = FB_SHARE_HEAD_UA;
    options.check_status = false;
    transport = fb_transport_request(parser->scope, full_url, &options);
    if (transport.code == FB_TRANSPORT_OK) {
        head = transport.response;
    }
    if (head != NULL) {
        fb_slice head_path;
        bool head_usable;
        if (fb_url_normalize_facebook_path(
                parser->arena, head->url, &head_path) != FB_URL_OK) {
            return fb_no_memory();
        }
        head_usable =
            fb_url_is_facebook(head->url, false) &&
            !fb_url_is_group_landing_target(head_path) &&
            fb_url_is_post_like_path(head_path) &&
            (!is_share_v ||
             fb_path_is_video_like(parser, head_path));
        needs_get =
            head->status >= 400 ||
            fb_url_is_share_path(head_path) ||
            fb_url_is_auth_control_path(head->url) ||
            !head_usable;
        if (!needs_get) {
            target->path = head_path;
            target->prefetched = NULL;
            return (fb_attempt){.ok = true};
        }
    }

    options = fb_transport_default_options(FB_HTTP_GET);
    options.user_agent = FB_SHARE_BODY_UA;
    options.check_status = false;
    options.retry_status_responses = false;
    transport = fb_transport_request(parser->scope, full_url, &options);
    if (transport.code != FB_TRANSPORT_OK) {
        return fb_transport_error(parser, transport);
    }
    response = transport.response;
    inspected = fb_parse_share_document(
        parser, source_path, response, &document, &direct_path,
        &declared_target, &response_is_facebook, &probe);
    if (!inspected.ok) {
        return inspected;
    }
    if (probe != FB_PROBE_HAS_DATA &&
        fb_status_retries(response->status)) {
        options.bypass_cache = true;
        transport = fb_transport_request(
            parser->scope, full_url, &options);
        if (transport.code != FB_TRANSPORT_OK) {
            return fb_transport_error(parser, transport);
        }
        response = transport.response;
        inspected = fb_parse_share_document(
            parser, source_path, response, &document, &direct_path,
            &declared_target, &response_is_facebook, &probe);
        if (!inspected.ok) {
            return inspected;
        }
    }
    if (!response_is_facebook) {
        if (declared_target) {
            if (fb_url_is_group_landing_target(direct_path)) {
                return fb_share_resolution_error(fb_error_static(
                    FB_PARSE_ERROR_NO_DATA,
                    FB_REASON_NO_DATA,
                    "Facebook resolved share link to a group landing page",
                    response,
                    false
                ));
            }
            target->path = direct_path;
            target->prefetched = NULL;
            return (fb_attempt){.ok = true};
        }
        return fb_share_resolution_error(fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_REASON_NO_DATA,
            "Facebook redirected share link outside Facebook",
            response,
            false
        ));
    }
    if (probe == FB_PROBE_LOGIN_WALL ||
        probe == FB_PROBE_PRIVATE_GROUP) {
        return fb_share_resolution_error(
            fb_probe_error(probe, response));
    }
    if (response->status >= 400 && probe != FB_PROBE_HAS_DATA) {
        fb_slice reason = fb_arena_format(
            parser->arena, "upstream_http_%ld", response->status);
        fb_slice detail = fb_arena_format(
            parser->arena,
            "Facebook returned HTTP %ld",
            response->status);
        if (reason.ptr == NULL || detail.ptr == NULL) {
            return fb_no_memory();
        }
        return fb_attempt_error(
            FB_PARSE_ERROR_UPSTREAM,
            reason,
            detail,
            response,
            false,
            false,
            response->body.len != 0u
        );
    }
    if (probe == FB_PROBE_UNSUPPORTED_PROFILE ||
        probe == FB_PROBE_UNSUPPORTED_MARKETPLACE ||
        probe == FB_PROBE_UNSUPPORTED_MEDIA_SET) {
        return fb_probe_error(probe, response);
    }
    if (probe == FB_PROBE_TARGET_VIDEO_MISSING ||
        probe == FB_PROBE_TARGET_NOT_FOUND ||
        probe == FB_PROBE_TARGET_IDENTITY_MISMATCH ||
        probe == FB_PROBE_NO_DATA) {
        return fb_share_resolution_error(
            fb_probe_error(probe, response));
    }
    if (fb_url_is_share_path(direct_path)) {
        if (probe == FB_PROBE_HAS_DATA) {
            target->path = source_path;
            target->prefetched = response;
            return (fb_attempt){.ok = true};
        }
        return fb_share_resolution_error(fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("share_target_unresolved"),
            "Facebook left the share URL unresolved without post data",
            response,
            false
        ));
    }
    if (fb_url_is_auth_control_path(response->url)) {
        if (probe == FB_PROBE_HAS_DATA) {
            target->path = source_path;
            target->prefetched = response;
            return (fb_attempt){.ok = true};
        }
        return fb_share_resolution_error(fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("login_wall"),
            "Facebook redirected share link to authentication",
            response,
            false
        ));
    }
    if (fb_url_is_group_landing_target(direct_path)) {
        return fb_share_resolution_error(fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("private_group_post_unavailable"),
            "Facebook resolved share link to a group landing page",
            response,
            false
        ));
    }
    {
        fb_slice response_path;
        if (fb_url_normalize_facebook_path(
                parser->arena, response->url,
                &response_path) != FB_URL_OK) {
            return fb_no_memory();
        }
        if (probe == FB_PROBE_UNKNOWN && declared_target &&
            !fb_slice_equal(direct_path, response_path)) {
            target->path = direct_path;
            target->prefetched = NULL;
            return (fb_attempt){.ok = true};
        }
    }
    target->path = direct_path;
    target->prefetched =
        probe == FB_PROBE_HAS_DATA || probe == FB_PROBE_UNKNOWN
            ? response
            : NULL;
    if (fb_path_without_trailing_slash(
            fb_url_path_only(direct_path)).len == 0u) {
        return fb_share_resolution_error(fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_REASON_SHARE_FAILED,
            "Facebook share resolution did not produce a post target",
            response,
            false
        ));
    }
    return (fb_attempt){.ok = true};
}

typedef enum {
    FB_CONCRETE_GENERIC = 0,
    FB_CONCRETE_COMMENT,
    FB_CONCRETE_PHOTO,
    FB_CONCRETE_PHOTOCOM,
    FB_CONCRETE_REEL,
    FB_CONCRETE_WATCH
} fb_concrete_parser;

static fb_attempt
fb_invoke_parser(
    fb_parser *parser,
    fb_concrete_parser concrete,
    fb_slice path,
    fb_upstream_response *prefetched
)
{
    fb_attempt attempt;
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    switch (concrete) {
    case FB_CONCRETE_GENERIC:
        attempt = fb_parse_generic(parser, path, prefetched);
        break;
    case FB_CONCRETE_COMMENT:
        attempt = fb_parse_comment(parser, path, prefetched);
        break;
    case FB_CONCRETE_PHOTO:
        attempt = fb_parse_single_photo(parser, path, prefetched);
        break;
    case FB_CONCRETE_PHOTOCOM:
        attempt = fb_parse_photocom(parser, path, prefetched);
        break;
    case FB_CONCRETE_REEL:
        attempt = fb_parse_reel(parser, path, prefetched);
        break;
    case FB_CONCRETE_WATCH:
        attempt = fb_parse_watch(parser, path, prefetched);
        break;
    default:
        attempt = fb_error_static(
            FB_PARSE_ERROR_INVALID_ARGUMENT,
            FB_REASON_INVALID_ARGUMENT,
            "unknown concrete parser",
            prefetched,
            true
        );
        break;
    }
    return fb_parser_poll_cancel(parser) ? fb_cancelled() : attempt;
}

static fb_attempt
fb_parse_with_generic(
    fb_parser *parser,
    fb_concrete_parser concrete,
    fb_slice path,
    fb_upstream_response *prefetched
)
{
    fb_attempt first =
        fb_invoke_parser(parser, concrete, path, prefetched);
    fb_attempt second;
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    if (first.ok || !fb_allow_parser_fallback(&first)) {
        return first;
    }
    if (getenv("FASTBED_TRACE_PARSER") != NULL) {
        (void)fprintf(
            stderr,
            "[DEBUG] parser fallback concrete=%d reason=%.*s detail=%.*s\n",
            (int)concrete,
            (int)(first.error.reason.len > (size_t)INT_MAX
                      ? INT_MAX : first.error.reason.len),
            first.error.reason.ptr == NULL ? "" : first.error.reason.ptr,
            (int)(first.error.detail.len > (size_t)INT_MAX
                      ? INT_MAX : first.error.detail.len),
            first.error.detail.ptr == NULL ? "" : first.error.detail.ptr);
    }
    second = fb_parse_generic(parser, path, prefetched);
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    return second.ok ? second : fb_prefer_error(first, second);
}

static bool
fb_path_has_segment(fb_parser *parser, fb_slice path, const char *name)
{
    fb_path_segments parts;
    size_t index;
    if (fb_url_facebook_path_segments(
            parser->arena, path, &parts) != FB_URL_OK) {
        return false;
    }
    for (index = 0u; index < parts.len; ++index) {
        if (fb_slice_equal_literal_ascii_case(
                fb_path_segment_at(&parts, index), name)) {
            return true;
        }
    }
    return false;
}

static bool
fb_path_starts_segment(
    fb_parser *parser,
    fb_slice path,
    const char *name
)
{
    fb_path_segments parts;
    return fb_url_facebook_path_segments(
               parser->arena, path, &parts) == FB_URL_OK &&
           parts.len != 0u &&
           fb_slice_equal_literal_ascii_case(
               fb_path_segment_at(&parts, 0u), name);
}

static bool
fb_path_starts_segment_with_target(
    fb_parser *parser,
    fb_slice path,
    const char *name
)
{
    fb_path_segments parts;
    return fb_url_facebook_path_segments(
               parser->arena, path, &parts) == FB_URL_OK &&
           parts.len >= 2u &&
           fb_slice_equal_literal_ascii_case(
               fb_path_segment_at(&parts, 0u), name) &&
           fb_path_segment_at(&parts, 1u).len != 0u;
}

static fb_slice
fb_terminal_video_id_from_path(fb_parser *parser, fb_slice path)
{
    fb_path_segments parts;
    size_t index;

    if (fb_url_facebook_path_segments(
            parser->arena, path, &parts) != FB_URL_OK) {
        return fb_slice_make(NULL, 0u);
    }
    for (index = 0u; index < parts.len; ++index) {
        if (fb_slice_equal_literal_ascii_case(
                fb_path_segment_at(&parts, index), "videos")) {
            size_t after = parts.len - index - 1u;
            fb_slice final;
            if (after != 1u && after != 2u) {
                return fb_slice_make(NULL, 0u);
            }
            final = fb_path_segment_at(&parts, parts.len - 1u);
            return fb_ascii_digits(final)
                       ? final
                       : fb_slice_make(NULL, 0u);
        }
    }
    for (index = 0u; index < parts.len; ++index) {
        if (fb_slice_equal_literal_ascii_case(
                fb_path_segment_at(&parts, index), "v") &&
            index + 1u < parts.len &&
            fb_ascii_digits(fb_path_segment_at(&parts, index + 1u))) {
            return fb_path_segment_at(&parts, index + 1u);
        }
    }
    return fb_slice_make(NULL, 0u);
}

static bool
fb_slugged_video_path(fb_parser *parser, fb_slice path)
{
    fb_path_segments parts;
    size_t index;
    if (fb_url_facebook_path_segments(
            parser->arena, path, &parts) != FB_URL_OK) {
        return false;
    }
    for (index = 0u; index < parts.len; ++index) {
        if (fb_slice_equal_literal_ascii_case(
                fb_path_segment_at(&parts, index), "videos")) {
            size_t after = parts.len - index - 1u;
            return after >= 2u &&
                   !fb_slice_starts_literal_ascii_case(
                       fb_path_segment_at(&parts, index + 1u), "pcb.");
        }
    }
    return false;
}

static fb_slice
fb_make_reel_path(
    fb_parser *parser,
    fb_slice source,
    fb_slice video_id
)
{
    fb_url_view parsed;
    size_t length;
    size_t allocation_size;
    char *result;
    size_t cursor = 0u;

    if (fb_url_parse(source, &parsed) != FB_URL_OK ||
        !fb_size_add(sizeof("reel/") - 1u, video_id.len, &length) ||
        (parsed.has_query &&
         (!fb_size_add(length, 1u, &length) ||
          !fb_size_add(length, parsed.query.len, &length)))) {
        return fb_slice_make(NULL, 0u);
    }
    if (!fb_size_add(length, 1u, &allocation_size)) {
        return fb_slice_make(NULL, 0u);
    }
    result = fb_arena_alloc(
        parser->arena, allocation_size, _Alignof(char));
    if (result == NULL) {
        return fb_slice_make(NULL, 0u);
    }
    memcpy(result + cursor, "reel/", sizeof("reel/") - 1u);
    cursor += sizeof("reel/") - 1u;
    memcpy(result + cursor, video_id.ptr, video_id.len);
    cursor += video_id.len;
    if (parsed.has_query) {
        result[cursor++] = '?';
        memcpy(result + cursor, parsed.query.ptr, parsed.query.len);
        cursor += parsed.query.len;
    }
    result[cursor] = '\0';
    return fb_slice_make(result, cursor);
}

static fb_attempt
fb_parse_video_path(
    fb_parser *parser,
    fb_slice path,
    fb_upstream_response *prefetched
)
{
    fb_slice video_id =
        fb_terminal_video_id_from_path(parser, path);
    bool slugged;
    fb_attempt generic = {0};
    fb_attempt generic_error = {0};
    fb_attempt reel;
    fb_attempt watch;
    fb_slice reel_path;
    fb_upstream_response *reel_response = prefetched;

    if (video_id.ptr == NULL) {
        return fb_parse_generic(parser, path, prefetched);
    }
    slugged = fb_slugged_video_path(parser, path);
    if (slugged) {
        generic = fb_parse_generic(parser, path, prefetched);
        if (generic.ok && generic.post.video_links.len != 0u) {
            return generic;
        }
        if (!generic.ok) {
            generic_error = generic;
            if (!fb_allow_route_fallback(&generic_error)) {
                return generic_error;
            }
        }
    }
    reel_path = fb_make_reel_path(parser, path, video_id);
    if (reel_path.ptr == NULL) {
        return fb_no_memory();
    }
    if (prefetched != NULL) {
        fb_slice final_path;
        fb_slice expected_path =
            fb_path_without_trailing_slash(fb_url_path_only(reel_path));
        if (fb_url_normalize_facebook_path(
                parser->arena, prefetched->url,
                &final_path) != FB_URL_OK) {
            return fb_no_memory();
        }
        final_path =
            fb_path_without_trailing_slash(fb_url_path_only(final_path));
        if (!fb_slice_equal(final_path, expected_path)) {
            reel_response = NULL;
        }
    }
    reel = fb_parse_reel(parser, reel_path, reel_response);
    if (reel.ok || !fb_allow_route_fallback(&reel)) {
        return reel;
    }
    if (!slugged) {
        generic = fb_parse_generic(parser, path, prefetched);
        if (generic.ok && generic.post.video_links.len != 0u) {
            return generic;
        }
        if (!generic.ok) {
            generic_error = generic;
            if (!fb_allow_route_fallback(&generic_error)) {
                return generic_error;
            }
        }
    }
    watch = fb_parse_watch(parser, path, prefetched);
    if (watch.ok) {
        return watch;
    }
    if (generic.ok) {
        return generic;
    }
    return fb_prefer_error(
        fb_prefer_error(reel, generic_error), watch);
}

static fb_attempt
fb_ensure_facebook_target(fb_slice path)
{
    fb_url_view parsed;
    if (fb_url_parse(path, &parsed) != FB_URL_OK) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            FB_REASON_UNSUPPORTED,
            "invalid Facebook route",
            NULL,
            true
        );
    }
    if (parsed.has_authority && !fb_url_is_facebook(path, false)) {
        return fb_error_static(
            FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
            FB_REASON_UNSUPPORTED,
            "refusing to fetch non-Facebook host",
            NULL,
            true
        );
    }
    return (fb_attempt){.ok = true};
}

static fb_attempt
fb_dispatch(
    fb_parser *parser,
    fb_slice path,
    fb_upstream_response *prefetched
)
{
    fb_comment_target comment;
    fb_url_status comment_status =
        fb_url_comment_target(parser->arena, path, &comment);
    fb_slice raw_path = fb_url_path_only(path);

    if (comment_status == FB_URL_NO_MEMORY) {
        return fb_no_memory();
    }
    if (comment_status != FB_URL_OK ||
        comment.kind == FB_COMMENT_TARGET_INVALID) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("invalid_comment_target"),
            "Invalid or ambiguous Facebook comment identity",
            prefetched,
            true
        );
    }
    if (comment.kind == FB_COMMENT_TARGET_VALID) {
        parser->parser_entered = true;
        return fb_parse_comment(parser, path, prefetched);
    }
    if (fb_url_is_share_path(path)) {
        parser->parser_entered = true;
        return fb_parse_generic(parser, path, prefetched);
    }
    if (fb_path_has_segment(parser, path, "videos") ||
        (fb_path_has_segment(parser, path, "v") &&
         fb_terminal_video_id_from_path(parser, path).ptr != NULL)) {
        parser->parser_entered = true;
        return fb_parse_video_path(parser, path, prefetched);
    }
    if (fb_path_starts_segment_with_target(parser, path, "reel")) {
        parser->parser_entered = true;
        return fb_parse_with_generic(
            parser, FB_CONCRETE_REEL, path, prefetched);
    }
    raw_path = fb_path_without_trailing_slash(raw_path);
    while (raw_path.len != 0u && raw_path.ptr[0] == '/') {
        raw_path.ptr++;
        raw_path.len--;
    }
    if (fb_slice_equal_literal_ascii_case(raw_path, "photo") ||
        fb_slice_equal_literal_ascii_case(raw_path, "photo.php")) {
        parser->parser_entered = true;
        return fb_parse_with_generic(
            parser, FB_CONCRETE_PHOTO, path, prefetched);
    }
    if (fb_path_starts_segment(parser, path, "watch")) {
        parser->parser_entered = true;
        return fb_parse_with_generic(
            parser, FB_CONCRETE_WATCH, path, prefetched);
    }
    if (fb_url_is_supported_post_route(path)) {
        parser->parser_entered = true;
        return fb_parse_generic(parser, path, prefetched);
    }
    return fb_error_static(
        FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
        FB_REASON_UNSUPPORTED,
        "unsupported Facebook route",
        prefetched,
        true
    );
}

static bool
fb_query_has_type_three(fb_parser *parser, fb_slice path)
{
    fb_url_view parsed;
    fb_query query;
    size_t index;
    if (fb_url_parse(path, &parsed) != FB_URL_OK ||
        !parsed.has_query ||
        fb_query_parse(
            parser->arena, parsed.query, true, &query) != FB_URL_OK) {
        return false;
    }
    for (index = 0u; index < query.len; ++index) {
        const fb_query_pair *pair = fb_query_at(&query, index);
        if (pair != NULL &&
            fb_slice_equal_literal(pair->key, "type") &&
            fb_slice_equal_literal(pair->value, "3")) {
            return true;
        }
    }
    return false;
}

static fb_attempt
fb_run_request(fb_parser *parser, fb_slice input)
{
    fb_attempt valid = fb_ensure_facebook_target(input);
    fb_comment_target source_comment;
    fb_url_status comment_status;
    fb_slice path;
    bool normalized_changed = false;
    fb_slice share_source = fb_slice_make(NULL, 0u);
    fb_upstream_response *prefetched = NULL;
    fb_attempt primary;

    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }

    if (!valid.ok) {
        return valid;
    }
    comment_status = fb_url_comment_target(
        parser->arena, input, &source_comment);
    if (comment_status == FB_URL_NO_MEMORY) {
        return fb_no_memory();
    }
    if (comment_status != FB_URL_OK ||
        source_comment.kind == FB_COMMENT_TARGET_INVALID) {
        return fb_error_static(
            FB_PARSE_ERROR_NO_DATA,
            FB_SLICE_LIT("invalid_comment_target"),
            "Invalid or ambiguous Facebook comment identity",
            NULL,
            true
        );
    }
    if (source_comment.kind == FB_COMMENT_TARGET_NONE &&
        fb_query_has_type_three(parser, input)) {
        fb_attempt photocom;
        parser->parser_entered = true;
        photocom = fb_parse_photocom(parser, input, NULL);
        if (fb_parser_poll_cancel(parser)) {
            return fb_cancelled();
        }
        if (photocom.ok) {
            return photocom;
        }
        if (photocom.error.kind != FB_PARSE_ERROR_DOCUMENT &&
            photocom.error.kind != FB_PARSE_ERROR_NO_DATA) {
            return photocom;
        }
    }
    if (fb_url_normalize_request_path(
            parser->arena, input, &path,
            &normalized_changed) != FB_URL_OK) {
        return fb_no_memory();
    }
    (void)normalized_changed;
    if (fb_url_is_share_path(path)) {
        fb_share_target target;
        fb_attempt resolved;
        share_source = path;
        resolved = fb_resolve_share(parser, path, &target);
        if (fb_parser_poll_cancel(parser)) {
            return fb_cancelled();
        }
        if (!resolved.ok) {
            return resolved;
        }
        path = target.path;
        prefetched = target.prefetched;
        if (source_comment.kind == FB_COMMENT_TARGET_VALID) {
            fb_comment_target resolved_comment;
            fb_url_status resolved_status = fb_url_comment_target(
                parser->arena, path, &resolved_comment);
            if (resolved_status == FB_URL_NO_MEMORY) {
                return fb_no_memory();
            }
            if (resolved_status != FB_URL_OK ||
                resolved_comment.kind == FB_COMMENT_TARGET_INVALID) {
                return fb_error_static(
                    FB_PARSE_ERROR_NO_DATA,
                    FB_SLICE_LIT("invalid_comment_target"),
                    "Invalid or ambiguous Facebook comment identity",
                    prefetched,
                    true
                );
            }
            if (resolved_comment.kind == FB_COMMENT_TARGET_VALID &&
                !fb_comment_targets_equal(
                    &source_comment, &resolved_comment)) {
                return fb_error_static(
                    FB_PARSE_ERROR_NO_DATA,
                    FB_SLICE_LIT("comment_identity_mismatch"),
                    "Share resolution changed the requested comment",
                    prefetched,
                    true
                );
            }
            {
                fb_url_status preserve = fb_url_preserve_comment_target(
                    parser->arena, path, &source_comment, &path);
                if (preserve == FB_URL_NO_MEMORY) {
                    return fb_no_memory();
                }
                if (preserve != FB_URL_OK) {
                    return fb_error_static(
                        FB_PARSE_ERROR_NO_DATA,
                        FB_SLICE_LIT("comment_identity_mismatch"),
                        "Share resolution changed the requested comment",
                        prefetched,
                        true
                    );
                }
            }
        }
    }
    primary = fb_dispatch(parser, path, prefetched);
    if (fb_parser_poll_cancel(parser)) {
        return fb_cancelled();
    }
    if (primary.ok ||
        source_comment.kind == FB_COMMENT_TARGET_VALID ||
        !fb_allow_route_fallback(&primary) ||
        share_source.ptr == NULL ||
        fb_slice_equal(share_source, path)) {
        return primary;
    }
    {
        fb_attempt share_attempt;
        parser->parser_entered = true;
        share_attempt = fb_parse_generic(
            parser, share_source, prefetched);
        if (fb_parser_poll_cancel(parser)) {
            return fb_cancelled();
        }
        if (share_attempt.ok) {
            return share_attempt;
        }
        if (!fb_allow_route_fallback(&share_attempt)) {
            return share_attempt;
        }
        return fb_prefer_error(primary, share_attempt);
    }
}

fb_parse_result
fb_parse_request_cancelable(
    fb_arena *arena,
    const fb_config *config,
    fb_transport_scope *scope,
    fb_slice normalized_path,
    const fb_cancel_token *cancel
)
{
    fb_parse_result result;
    fb_parser parser;
    fb_attempt attempt;

    memset(&result, 0, sizeof(result));
    fb_post_init(&result.post);
    result.error.reason = FB_REASON_NONE;
    result.error.detail = FB_REASON_NONE;
    if (arena == NULL || scope == NULL || scope->arena != arena ||
        scope->transport == NULL || !fb_slice_is_valid(normalized_path) ||
        normalized_path.ptr == NULL || normalized_path.len == 0u) {
        result.error.kind = FB_PARSE_ERROR_INVALID_ARGUMENT;
        result.error.reason = FB_REASON_INVALID_ARGUMENT;
        result.error.detail = FB_SLICE_LIT("invalid parser request");
        return result;
    }
    memset(&parser, 0, sizeof(parser));
    parser.arena = arena;
    parser.config = config;
    parser.scope = scope;
    parser.cancel = cancel;
    if (fb_parser_poll_cancel(&parser)) {
        attempt = fb_cancelled();
    } else {
        attempt = fb_run_request(&parser, normalized_path);
    }
    result.parser_entered = parser.parser_entered;
    result.selected_response = scope->selected_get_response;
    result.last_response = scope->last_get_response;
    if (fb_parser_poll_cancel(&parser)) {
        attempt = fb_cancelled();
    }
    if (attempt.ok) {
        result.post = attempt.post;
        if (!fb_post_is_valid(&result.post)) {
            result.error.kind = FB_PARSE_ERROR_DOCUMENT;
            result.error.reason = FB_REASON_PARSER;
            result.error.detail =
                FB_SLICE_LIT("parser produced an invalid post");
        }
    } else {
        result.error = attempt.error;
        if (result.error.reason.ptr == NULL) {
            result.error.reason = FB_REASON_PARSER;
        }
        if (result.error.detail.ptr == NULL) {
            result.error.detail =
                FB_SLICE_LIT("Facebook parser failed");
        }
        if (result.error.kind == FB_PARSE_ERROR_NO_DATA ||
            result.error.kind == FB_PARSE_ERROR_DOCUMENT ||
            result.error.kind == FB_PARSE_ERROR_UNSUPPORTED_ROUTE) {
            result.error.upstream_response =
                result.selected_response != NULL
                    ? result.selected_response
                    : result.last_response;
        } else if (result.error.upstream_response == NULL) {
            result.error.upstream_response =
                result.selected_response != NULL
                    ? result.selected_response
                    : result.last_response;
        }
    }
    return result;
}

fb_parse_result
fb_parse_request(
    fb_arena *arena,
    const fb_config *config,
    fb_transport_scope *scope,
    fb_slice normalized_path
)
{
    fb_cancel_token cancel = fb_cancel_token_from_flag(
        scope != NULL ? scope->cancel_requested : NULL);
    return fb_parse_request_cancelable(
        arena, config, scope, normalized_path, &cancel);
}
