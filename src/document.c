#include "fastbed/document.h"

#include "fastbed/url.h"

#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if (defined(__x86_64__) || defined(__i386__)) && \
    (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define FB_DOCUMENT_HAVE_X86_AVX2 1
#else
#define FB_DOCUMENT_HAVE_X86_AVX2 0
#endif

#define FB_CHUNK_LARGE_SHIFT 8u
#define FB_CHUNK_LARGE_SIZE ((size_t)1u << FB_CHUNK_LARGE_SHIFT)
#define FB_CHUNK_PREFIX_ITEMS 248u
#define FB_CHUNK_PREFIX_PAGES 5u
#define FB_INDEX_NONE UINT32_MAX
#define FB_CANCEL_BYTE_INTERVAL ((size_t)64u * 1024u)
#define FB_CANCEL_ITEM_INTERVAL ((size_t)256u)

typedef struct {
    void **pages;
    size_t len;
    size_t page_count;
    size_t page_capacity;
    size_t max_pages;
    size_t max_items;
    size_t item_size;
    size_t alignment;
    fb_arena *arena;
} fb_chunk_vec;

typedef struct {
    uint32_t value_ref;
    uint32_t member_first;
    uint32_t member_count;
} fb_object_node;

typedef struct {
    uint32_t value_ref;
} fb_object_member;

typedef struct {
    uint32_t object_rank;
    uint32_t value_ref;
    uint32_t pair_index;
} fb_hot_posting;

typedef struct {
    uint32_t first;
    uint32_t count;
    uint32_t key_ref;
} fb_hot_slot;

typedef enum {
    FB_HOT_INITIAL_ROUTE_INFO = 0,
    FB_HOT_MEDIA,
    FB_HOT_GROUP,
    FB_HOT_CREATION_STORY,
    FB_HOT_SHORT_FORM_VIDEO_CONTEXT,
    FB_HOT_FEEDBACK,
    FB_HOT_RESULT,
    FB_HOT_CREATION_TIME,
    FB_HOT_CREATED_TIME,
    FB_HOT_OWNER,
    FB_HOT_VIDEO_OWNER,
    FB_HOT_GROUP_MEMBER_PROFILES,
    FB_HOT_FORMATTED_COUNT_TEXT,
    FB_HOT_MESSAGE_PREFERRED_BODY,
    FB_HOT_CONTAINER_STORY,
    FB_HOT_UFI_SUMMARY_RENDERER,
    FB_HOT_PREFETCH_URIS_V2,
    FB_HOT_ATTACHED_COMMENT,
    FB_HOT_UNIFIED_REACTORS,
    FB_HOT_COUNT
} fb_hot_key;

struct fb_json_block {
    struct fb_document *owner;
    yyjson_doc *json_document;
    const yyjson_val *root;
    size_t index;
    size_t value_count;
    fb_object_node *objects;
    size_t object_count;
    fb_object_member *members;
    size_t member_count;
    fb_hot_posting *postings;
    size_t posting_count;
    fb_hot_slot hot[FB_HOT_COUNT];
};

typedef struct {
    fb_html_form form;
    size_t control_first;
    size_t parent_form;
} fb_form_record;

struct fb_document {
    fb_arena *arena;
    const fb_cancel_token *cancel;
    fb_slice raw_body;
    fb_document_limits limits;
    uint64_t hash_seed;
    size_t total_json_values;
    size_t invalid_json_count;
    size_t canonical_count;
    size_t og_url_count;
    bool has_login_form;
    bool cancelled;
    void *traversal_stack;
    size_t traversal_stack_capacity;
    size_t traversal_stack_limit;
    fb_chunk_vec scripts;
    fb_chunk_vec blocks;
    fb_chunk_vec declared_urls;
    fb_chunk_vec forms;
    fb_chunk_vec controls;
    fb_chunk_vec initial_routes;
    fb_chunk_vec comment_candidates;
    fb_chunk_vec video_candidates;
};

typedef enum {
    FB_FRAME_ENTER = 0,
    FB_FRAME_OBJECT_LISTS,
    FB_FRAME_OBJECT_OBJECTS,
    FB_FRAME_ARRAY_OBJECTS,
    FB_FRAME_ARRAY_ARRAYS,
    FB_FRAME_DONE
} fb_frame_phase;

typedef struct {
    const yyjson_val *value;
    fb_frame_phase phase;
    size_t depth;
    size_t cursor;
    size_t member_first;
    size_t member_count;
    yyjson_arr_iter array_iterator;
} fb_traversal_frame;

typedef struct {
    fb_hot_posting *items;
    size_t len;
    size_t capacity;
    uint32_t key_ref;
} fb_hot_posting_vec;

typedef struct {
    uint64_t hash;
    uint32_t key_ref;
    uint32_t member_index;
    uint32_t generation;
} fb_object_key_slot;

typedef struct {
    fb_object_node *objects;
    size_t object_count;
    size_t object_capacity;
    fb_object_member *members;
    size_t member_count;
    size_t member_capacity;
    fb_hot_posting_vec hot[FB_HOT_COUNT];
    fb_object_key_slot *key_slots;
    size_t key_slot_capacity;
    uint32_t key_generation;
} fb_block_builder;

typedef struct {
    fb_slice raw;
    fb_slice decoded;
    size_t source_offset;
    bool present;
} fb_attribute;

typedef struct {
    fb_attribute type;
    fb_attribute rel;
    fb_attribute href;
    fb_attribute property;
    fb_attribute content;
    fb_attribute action;
    fb_attribute method;
    fb_attribute id;
    fb_attribute name;
} fb_tag_attributes;

typedef enum {
    FB_SCAN_OK = 0,
    FB_SCAN_NO_MEMORY,
    FB_SCAN_MALFORMED,
    FB_SCAN_LIMIT,
    FB_SCAN_CANCELLED
} fb_scan_status;

static bool
fb_document_poll_cancel(fb_document *document)
{
    if (document == NULL) {
        return false;
    }
    if (document->cancelled || fb_cancel_requested(document->cancel)) {
        document->cancelled = true;
        return true;
    }
    return false;
}

static const char *
fb_document_memchr(
    fb_document *document,
    const char *text,
    unsigned char value,
    size_t length
)
{
    size_t offset = 0u;

    while (offset < length) {
        size_t chunk = length - offset;
        const char *match;
        if (fb_document_poll_cancel(document)) {
            return NULL;
        }
        if (chunk > FB_CANCEL_BYTE_INTERVAL) {
            chunk = FB_CANCEL_BYTE_INTERVAL;
        }
        match = memchr(text + offset, value, chunk);
        if (match != NULL) {
            return match;
        }
        offset += chunk;
    }
    return NULL;
}

static bool
fb_json_string_is(const yyjson_val *value, const char *literal);

static const yyjson_val *
fb_direct_video_url_fields(const yyjson_val *object);

static bool
fb_document_append_node_ref(
    fb_chunk_vec *vector,
    const yyjson_val *value,
    size_t block_index,
    size_t traversal_rank
);

static bool
fb_chunk_page_layout(
    size_t page_index,
    size_t *start,
    size_t *capacity
)
{
    static const size_t prefix_starts[FB_CHUNK_PREFIX_PAGES] = {
        0u, 8u, 24u, 56u, 120u
    };
    static const size_t prefix_capacities[FB_CHUNK_PREFIX_PAGES] = {
        8u, 16u, 32u, 64u, 128u
    };
    size_t tail_page;
    size_t tail_offset;

    if (start == NULL || capacity == NULL) {
        return false;
    }
    if (page_index < FB_CHUNK_PREFIX_PAGES) {
        *start = prefix_starts[page_index];
        *capacity = prefix_capacities[page_index];
        return true;
    }
    tail_page = page_index - FB_CHUNK_PREFIX_PAGES;
    if (!fb_size_mul(tail_page, FB_CHUNK_LARGE_SIZE, &tail_offset) ||
        !fb_size_add(FB_CHUNK_PREFIX_ITEMS, tail_offset, start)) {
        return false;
    }
    *capacity = FB_CHUNK_LARGE_SIZE;
    return true;
}

static bool
fb_chunk_page_for_item(
    size_t item_index,
    size_t *page_index,
    size_t *page_offset
)
{
    if (page_index == NULL || page_offset == NULL) {
        return false;
    }
    if (item_index < 8u) {
        *page_index = 0u;
        *page_offset = item_index;
    } else if (item_index < 24u) {
        *page_index = 1u;
        *page_offset = item_index - 8u;
    } else if (item_index < 56u) {
        *page_index = 2u;
        *page_offset = item_index - 24u;
    } else if (item_index < 120u) {
        *page_index = 3u;
        *page_offset = item_index - 56u;
    } else if (item_index < FB_CHUNK_PREFIX_ITEMS) {
        *page_index = 4u;
        *page_offset = item_index - 120u;
    } else {
        size_t tail = item_index - FB_CHUNK_PREFIX_ITEMS;
        size_t tail_page = tail >> FB_CHUNK_LARGE_SHIFT;
        if (!fb_size_add(FB_CHUNK_PREFIX_PAGES, tail_page, page_index)) {
            return false;
        }
        *page_offset = tail & (FB_CHUNK_LARGE_SIZE - 1u);
    }
    return true;
}

static bool
fb_chunk_max_pages(size_t max_items, size_t *max_pages)
{
    size_t remaining;
    size_t rounded;
    size_t tail_pages;

    if (max_pages == NULL) {
        return false;
    }
    if (max_items == 0u) {
        *max_pages = 0u;
    } else if (max_items <= 8u) {
        *max_pages = 1u;
    } else if (max_items <= 24u) {
        *max_pages = 2u;
    } else if (max_items <= 56u) {
        *max_pages = 3u;
    } else if (max_items <= 120u) {
        *max_pages = 4u;
    } else if (max_items <= FB_CHUNK_PREFIX_ITEMS) {
        *max_pages = FB_CHUNK_PREFIX_PAGES;
    } else {
        remaining = max_items - FB_CHUNK_PREFIX_ITEMS;
        if (!fb_size_add(remaining, FB_CHUNK_LARGE_SIZE - 1u, &rounded)) {
            return false;
        }
        tail_pages = rounded >> FB_CHUNK_LARGE_SHIFT;
        if (!fb_size_add(FB_CHUNK_PREFIX_PAGES, tail_pages, max_pages)) {
            return false;
        }
    }
    return true;
}

static void
fb_error_clear(fb_document_error *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->status = FB_DOCUMENT_OK;
        error->issue = FB_DOCUMENT_ISSUE_NONE;
        error->script_index = SIZE_MAX;
    }
}

static fb_document_status
fb_error_set(
    fb_document_error *error,
    fb_document_status status,
    fb_document_issue issue,
    size_t source_offset,
    size_t script_index,
    yyjson_read_code json_code,
    size_t json_offset
)
{
    if (error != NULL) {
        error->status = status;
        error->issue = issue;
        error->source_offset = source_offset;
        error->script_index = script_index;
        error->json_code = json_code;
        error->json_offset = json_offset;
    }
    return status;
}

static fb_document_status
fb_cancel_error(
    fb_document *document,
    fb_document_error *error,
    size_t source_offset,
    size_t script_index
)
{
    if (document != NULL) {
        document->cancelled = true;
    }
    return fb_error_set(
        error,
        FB_DOCUMENT_CANCELLED,
        FB_DOCUMENT_ISSUE_NONE,
        source_offset,
        script_index,
        YYJSON_READ_SUCCESS,
        0u
    );
}

static bool
fb_chunk_vec_init(
    fb_chunk_vec *vector,
    fb_arena *arena,
    size_t max_items,
    size_t item_size,
    size_t alignment
)
{
    size_t page_bytes;

    if (vector == NULL || arena == NULL || item_size == 0u ||
        alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
        return false;
    }
    memset(vector, 0, sizeof(*vector));
    vector->arena = arena;
    vector->max_items = max_items;
    vector->item_size = item_size;
    vector->alignment = alignment;
    if (!fb_chunk_max_pages(max_items, &vector->max_pages) ||
        !fb_size_mul(item_size, FB_CHUNK_LARGE_SIZE, &page_bytes)) {
        return false;
    }
    return true;
}

static bool
fb_chunk_vec_grow_page_table(fb_chunk_vec *vector)
{
    size_t new_capacity;
    size_t bytes;
    size_t copy_bytes;
    void **pages;

    if (vector == NULL || vector->page_count >= vector->max_pages) {
        return false;
    }
    new_capacity = vector->page_capacity == 0u
                       ? 4u
                       : vector->page_capacity;
    while (new_capacity <= vector->page_count) {
        if (new_capacity > SIZE_MAX / 2u) {
            new_capacity = vector->max_pages;
            break;
        }
        new_capacity *= 2u;
    }
    if (new_capacity > vector->max_pages) {
        new_capacity = vector->max_pages;
    }
    if (new_capacity <= vector->page_count ||
        !fb_size_mul(new_capacity, sizeof(*pages), &bytes)) {
        return false;
    }
    pages = fb_arena_alloc(vector->arena, bytes, _Alignof(void *));
    if (pages == NULL) {
        return false;
    }
    if (vector->page_count != 0u) {
        if (!fb_size_mul(vector->page_count, sizeof(*pages), &copy_bytes)) {
            return false;
        }
        memcpy(pages, vector->pages, copy_bytes);
    }
    vector->pages = pages;
    vector->page_capacity = new_capacity;
    return true;
}

static void *
fb_chunk_vec_append(fb_chunk_vec *vector)
{
    size_t page_index;
    size_t item_index;
    size_t page_start;
    size_t page_capacity;
    size_t remaining_items;
    size_t page_bytes;
    unsigned char *page;
    void *item;

    if (vector == NULL || vector->len >= vector->max_items) {
        return NULL;
    }
    if (!fb_chunk_page_for_item(vector->len, &page_index, &item_index) ||
        !fb_chunk_page_layout(page_index, &page_start, &page_capacity) ||
        page_index >= vector->max_pages || page_start > vector->max_items) {
        return NULL;
    }
    if (page_index == vector->page_count) {
        if (vector->page_count == vector->page_capacity &&
            !fb_chunk_vec_grow_page_table(vector)) {
            return NULL;
        }
        remaining_items = vector->max_items - page_start;
        if (page_capacity > remaining_items) {
            page_capacity = remaining_items;
        }
        if (page_capacity == 0u ||
            !fb_size_mul(vector->item_size, page_capacity, &page_bytes)) {
            return NULL;
        }
        vector->pages[page_index] = fb_arena_alloc(
            vector->arena,
            page_bytes,
            vector->alignment
        );
        if (vector->pages[page_index] == NULL) {
            return NULL;
        }
        vector->page_count++;
    } else if (page_index > vector->page_count) {
        return NULL;
    }
    page = vector->pages[page_index];
    item = page + item_index * vector->item_size;
    memset(item, 0, vector->item_size);
    vector->len++;
    return item;
}

static void *
fb_chunk_vec_at(const fb_chunk_vec *vector, size_t index)
{
    size_t page_index;
    size_t item_index;
    unsigned char *page;

    if (vector == NULL || index >= vector->len) {
        return NULL;
    }
    if (!fb_chunk_page_for_item(index, &page_index, &item_index) ||
        page_index >= vector->page_count) {
        return NULL;
    }
    page = vector->pages[page_index];
    return page + item_index * vector->item_size;
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
fb_ascii_space(unsigned char value)
{
    return value == (unsigned char)' ' || value == (unsigned char)'\t' ||
           value == (unsigned char)'\n' || value == (unsigned char)'\r' ||
           value == (unsigned char)'\f';
}

static bool
fb_is_ascii_alpha(unsigned char value)
{
    return (value >= (unsigned char)'a' && value <= (unsigned char)'z') ||
           (value >= (unsigned char)'A' && value <= (unsigned char)'Z');
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
fb_slice_equal_literal_ascii_case(fb_slice value, const char *literal)
{
    return literal != NULL &&
           fb_slice_equal_ascii_case(value, fb_slice_from_cstr(literal));
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

static uint64_t
fb_hash_mix(uint64_t value)
{
    value ^= value >> 30u;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27u;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

static uint64_t
fb_hash_slice(fb_document *document, fb_slice value, uint64_t seed)
{
    const unsigned char *bytes = (const unsigned char *)value.ptr;
    size_t offset = 0u;
    uint64_t hash = fb_hash_mix(seed ^ (uint64_t)value.len);

    while (value.len - offset >= sizeof(uint64_t)) {
        size_t chunk_end = offset + FB_CANCEL_BYTE_INTERVAL;
        if (chunk_end < offset || chunk_end > value.len) {
            chunk_end = value.len;
        }
        if (value.len >= FB_CANCEL_BYTE_INTERVAL &&
            fb_document_poll_cancel(document)) {
            return 0u;
        }
        while (chunk_end - offset >= sizeof(uint64_t)) {
            uint64_t word;
            memcpy(&word, bytes + offset, sizeof(word));
            hash ^= fb_hash_mix(word + UINT64_C(0x9e3779b97f4a7c15));
            hash = (hash << 27u) | (hash >> 37u);
            hash = hash * UINT64_C(5) + UINT64_C(0x52dce729);
            offset += sizeof(uint64_t);
        }
    }
    if (offset != value.len) {
        uint64_t tail = 0u;
        size_t shift = 0u;
        while (offset < value.len) {
            tail |= (uint64_t)bytes[offset++] << shift;
            shift += CHAR_BIT;
        }
        hash ^= fb_hash_mix(tail);
    }
    return fb_hash_mix(hash);
}

static void *
fb_yyjson_malloc(void *context, size_t size)
{
    return fb_arena_alloc((fb_arena *)context, size, _Alignof(max_align_t));
}

static void *
fb_yyjson_realloc(
    void *context,
    void *pointer,
    size_t old_size,
    size_t size
)
{
    void *replacement;

    if (pointer == NULL) {
        return fb_yyjson_malloc(context, size);
    }
    if (size <= old_size) {
        return pointer;
    }
    replacement = fb_yyjson_malloc(context, size);
    if (replacement != NULL && old_size != 0u) {
        memcpy(replacement, pointer, old_size);
    }
    return replacement;
}

static void
fb_yyjson_free(void *context, void *pointer)
{
    (void)context;
    (void)pointer;
}

void
fb_document_limits_default(fb_document_limits *limits)
{
    if (limits == NULL) {
        return;
    }
    limits->max_body_bytes = FB_DOCUMENT_DEFAULT_MAX_BODY_BYTES;
    limits->max_scripts = FB_DOCUMENT_DEFAULT_MAX_SCRIPTS;
    limits->max_json_bytes = FB_DOCUMENT_DEFAULT_MAX_JSON_BYTES;
    limits->max_json_values = FB_DOCUMENT_DEFAULT_MAX_JSON_VALUES;
    limits->max_total_json_values =
        FB_DOCUMENT_DEFAULT_MAX_TOTAL_JSON_VALUES;
    limits->max_depth = FB_DOCUMENT_DEFAULT_MAX_DEPTH;
    limits->max_declared_urls = FB_DOCUMENT_DEFAULT_MAX_DECLARED_URLS;
    limits->max_forms = FB_DOCUMENT_DEFAULT_MAX_FORMS;
    limits->max_form_controls = FB_DOCUMENT_DEFAULT_MAX_FORM_CONTROLS;
    limits->max_attributes_per_tag =
        FB_DOCUMENT_DEFAULT_MAX_ATTRIBUTES_PER_TAG;
}

static int
fb_hot_key_index(fb_slice key)
{
    if (!fb_slice_is_valid(key) || key.ptr == NULL) {
        return -1;
    }
    switch (key.len) {
    case 5u:
        if (memcmp(key.ptr, "media", 5u) == 0) {
            return FB_HOT_MEDIA;
        }
        if (memcmp(key.ptr, "group", 5u) == 0) {
            return FB_HOT_GROUP;
        }
        if (memcmp(key.ptr, "owner", 5u) == 0) {
            return FB_HOT_OWNER;
        }
        return -1;
    case 6u:
        return memcmp(key.ptr, "result", 6u) == 0 ? FB_HOT_RESULT : -1;
    case 8u:
        return memcmp(key.ptr, "feedback", 8u) == 0
                   ? FB_HOT_FEEDBACK
                   : -1;
    case 11u:
        return memcmp(key.ptr, "video_owner", 11u) == 0
                   ? FB_HOT_VIDEO_OWNER
                   : -1;
    case 12u:
        return memcmp(key.ptr, "created_time", 12u) == 0
                   ? FB_HOT_CREATED_TIME
                   : -1;
    case 13u:
        return memcmp(key.ptr, "creation_time", 13u) == 0
                   ? FB_HOT_CREATION_TIME
                   : -1;
    case 14u:
        return memcmp(key.ptr, "creation_story", 14u) == 0
                   ? FB_HOT_CREATION_STORY
                   : -1;
    case 15u:
        return memcmp(key.ptr, "container_story", 15u) == 0
                   ? FB_HOT_CONTAINER_STORY
                   : -1;
    case 16u:
        if (memcmp(key.ptr, "initialRouteInfo", 16u) == 0) {
            return FB_HOT_INITIAL_ROUTE_INFO;
        }
        if (memcmp(key.ptr, "prefetch_uris_v2", 16u) == 0) {
            return FB_HOT_PREFETCH_URIS_V2;
        }
        if (memcmp(key.ptr, "attached_comment", 16u) == 0) {
            return FB_HOT_ATTACHED_COMMENT;
        }
        if (memcmp(key.ptr, "unified_reactors", 16u) == 0) {
            return FB_HOT_UNIFIED_REACTORS;
        }
        return -1;
    case 20u:
        return memcmp(key.ptr, "formatted_count_text", 20u) == 0
                   ? FB_HOT_FORMATTED_COUNT_TEXT
                   : -1;
    case 21u:
        return memcmp(key.ptr, "group_member_profiles", 21u) == 0
                   ? FB_HOT_GROUP_MEMBER_PROFILES
                   : -1;
    case 22u:
        return memcmp(key.ptr, "message_preferred_body", 22u) == 0
                   ? FB_HOT_MESSAGE_PREFERRED_BODY
                   : -1;
    case 24u:
        return memcmp(key.ptr, "short_form_video_context", 24u) == 0
                   ? FB_HOT_SHORT_FORM_VIDEO_CONTEXT
                   : -1;
    case 38u:
        return memcmp(
                   key.ptr,
                   "comet_ufi_summary_and_actions_renderer",
                   38u) == 0
                   ? FB_HOT_UFI_SUMMARY_RENDERER
                   : -1;
    default:
        return -1;
    }
}

static bool
fb_key_is(fb_slice key, const char *literal, size_t length)
{
    return key.len == length &&
           (length == 0u || memcmp(key.ptr, literal, length) == 0);
}

static bool
fb_block_value_ref(
    const fb_json_block *block,
    const yyjson_val *value,
    uint32_t *reference
)
{
    uintptr_t root_address;
    uintptr_t value_address;
    uintptr_t delta;
    uintptr_t index;

    if (block == NULL || block->root == NULL || value == NULL ||
        reference == NULL) {
        return false;
    }
    root_address = (uintptr_t)(const void *)block->root;
    value_address = (uintptr_t)(const void *)value;
    if (value_address < root_address) {
        return false;
    }
    delta = value_address - root_address;
    if (delta % sizeof(yyjson_val) != 0u) {
        return false;
    }
    index = delta / sizeof(yyjson_val);
    if (index >= block->value_count || index >= (uintptr_t)FB_INDEX_NONE) {
        return false;
    }
    *reference = (uint32_t)index;
    return true;
}

static const yyjson_val *
fb_block_value_at_ref(const fb_json_block *block, uint32_t reference)
{
    if (block == NULL || block->root == NULL ||
        reference == FB_INDEX_NONE ||
        (size_t)reference >= block->value_count) {
        return NULL;
    }
    return block->root + reference;
}

static fb_object_node *
fb_block_object_node_at(const fb_json_block *block, size_t index)
{
    if (block == NULL || index >= block->object_count) {
        return NULL;
    }
    return &block->objects[index];
}

static bool
fb_heap_reserve(
    void **items,
    size_t *capacity,
    size_t required,
    size_t item_size
)
{
    size_t next;
    size_t bytes;
    void *replacement;

    if (items == NULL || capacity == NULL || item_size == 0u) {
        return false;
    }
    if (required <= *capacity) {
        return true;
    }
    next = *capacity == 0u ? 16u : *capacity;
    while (next < required) {
        if (next > SIZE_MAX / 2u) {
            next = required;
            break;
        }
        next *= 2u;
    }
    if (next < required || !fb_size_mul(next, item_size, &bytes)) {
        return false;
    }
    replacement = realloc(*items, bytes);
    if (replacement == NULL) {
        return false;
    }
    *items = replacement;
    *capacity = next;
    return true;
}

static bool
fb_builder_append_object(
    fb_block_builder *builder,
    fb_object_node object
)
{
    if (builder == NULL ||
        !fb_heap_reserve(
            (void **)&builder->objects,
            &builder->object_capacity,
            builder->object_count + 1u,
            sizeof(*builder->objects))) {
        return false;
    }
    builder->objects[builder->object_count++] = object;
    return true;
}

static bool
fb_builder_append_member(
    fb_block_builder *builder,
    fb_object_member member
)
{
    if (builder == NULL ||
        !fb_heap_reserve(
            (void **)&builder->members,
            &builder->member_capacity,
            builder->member_count + 1u,
            sizeof(*builder->members))) {
        return false;
    }
    builder->members[builder->member_count++] = member;
    return true;
}

static bool
fb_builder_append_posting(
    fb_hot_posting_vec *vector,
    fb_hot_posting posting
)
{
    if (vector == NULL ||
        !fb_heap_reserve(
            (void **)&vector->items,
            &vector->capacity,
            vector->len + 1u,
            sizeof(*vector->items))) {
        return false;
    }
    vector->items[vector->len++] = posting;
    return true;
}

static void
fb_block_builder_destroy(fb_block_builder *builder)
{
    if (builder == NULL) {
        return;
    }
    free(builder->objects);
    free(builder->members);
    free(builder->key_slots);
    for (size_t index = 0u; index < FB_HOT_COUNT; ++index) {
        free(builder->hot[index].items);
    }
    memset(builder, 0, sizeof(*builder));
}

static void
fb_block_builder_reset(fb_block_builder *builder)
{
    if (builder == NULL) {
        return;
    }
    builder->object_count = 0u;
    builder->member_count = 0u;
    for (size_t index = 0u; index < FB_HOT_COUNT; ++index) {
        builder->hot[index].len = 0u;
        builder->hot[index].key_ref = FB_INDEX_NONE;
    }
}

static bool
fb_builder_prepare_object_keys(
    fb_block_builder *builder,
    size_t raw_member_count
)
{
    size_t required = 4u;
    size_t target;

    if (builder == NULL ||
        !fb_size_mul(raw_member_count, 2u, &target)) {
        return false;
    }
    while (required < target) {
        if (required > SIZE_MAX / 2u) {
            return false;
        }
        required *= 2u;
    }
    if (required > builder->key_slot_capacity) {
        size_t bytes;
        fb_object_key_slot *replacement;
        if (!fb_size_mul(required, sizeof(*replacement), &bytes)) {
            return false;
        }
        replacement = calloc(1u, bytes);
        if (replacement == NULL) {
            return false;
        }
        free(builder->key_slots);
        builder->key_slots = replacement;
        builder->key_slot_capacity = required;
        builder->key_generation = 0u;
    }
    builder->key_generation++;
    if (builder->key_generation == 0u) {
        memset(
            builder->key_slots,
            0,
            builder->key_slot_capacity * sizeof(*builder->key_slots)
        );
        builder->key_generation = 1u;
    }
    return true;
}

static fb_object_key_slot *
fb_builder_find_object_key(
    const fb_json_block *block,
    fb_block_builder *builder,
    fb_slice key,
    uint64_t hash
)
{
    size_t index;
    size_t probes = 0u;

    if (block == NULL || builder == NULL ||
        builder->key_slot_capacity == 0u) {
        return NULL;
    }
    index = (size_t)hash & (builder->key_slot_capacity - 1u);
    for (;;) {
        if ((++probes & (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
            fb_document_poll_cancel(block->owner)) {
            return NULL;
        }
        fb_object_key_slot *slot = &builder->key_slots[index];
        if (slot->generation != builder->key_generation) {
            return slot;
        }
        if (slot->hash == hash) {
            const yyjson_val *key_value =
                fb_block_value_at_ref(block, slot->key_ref);
            fb_slice previous;
            if (!yyjson_is_str(key_value)) {
                return NULL;
            }
            previous = fb_slice_make(
                yyjson_get_str(key_value), yyjson_get_len(key_value));
            if (fb_slice_equal(previous, key)) {
                return slot;
            }
        }
        index = (index + 1u) & (builder->key_slot_capacity - 1u);
    }
}

static bool
fb_block_index_object(
    fb_json_block *block,
    fb_block_builder *builder,
    const yyjson_val *object,
    size_t *rank_out,
    size_t *member_first_out,
    size_t *member_count_out
)
{
    yyjson_obj_iter iterator;
    yyjson_val *key_value;
    size_t object_rank;
    size_t member_first;
    size_t pair_index = 0u;
    uint32_t object_ref;
    fb_object_node node;
    bool comment_candidate = false;
    bool video_candidate = false;
    const yyjson_val *candidate_type = NULL;
    const yyjson_val *candidate_hd = NULL;
    const yyjson_val *candidate_sd = NULL;
    const yyjson_val *candidate_legacy = NULL;

    if (block == NULL || builder == NULL || !yyjson_is_obj(object) ||
        builder->object_count >= (size_t)FB_INDEX_NONE ||
        builder->member_count >= (size_t)FB_INDEX_NONE ||
        !fb_block_value_ref(block, object, &object_ref) ||
        !fb_builder_prepare_object_keys(builder, yyjson_obj_size(object))) {
        return false;
    }
    object_rank = builder->object_count;
    member_first = builder->member_count;
    node.value_ref = object_ref;
    node.member_first = (uint32_t)member_first;
    node.member_count = 0u;
    if (!fb_builder_append_object(builder, node)) {
        return false;
    }

    iterator = yyjson_obj_iter_with(object);
    while ((key_value = yyjson_obj_iter_next(&iterator)) != NULL) {
        yyjson_val *value = yyjson_obj_iter_get_val(key_value);
        fb_slice key = fb_slice_make(
            yyjson_get_str(key_value),
            yyjson_get_len(key_value)
        );
        uint32_t key_ref;
        uint32_t value_ref;
        uint64_t hash;
        fb_object_key_slot *slot;
        int hot_index;

        if (pair_index >= (size_t)FB_INDEX_NONE ||
            builder->member_count >= (size_t)FB_INDEX_NONE ||
            !fb_block_value_ref(block, key_value, &key_ref) ||
            !fb_block_value_ref(block, value, &value_ref)) {
            return false;
        }
        hash = fb_hash_slice(block->owner, key, block->owner->hash_seed);
        if (block->owner->cancelled) {
            return false;
        }
        slot = fb_builder_find_object_key(block, builder, key, hash);
        if (slot == NULL) {
            return false;
        }
        hot_index = fb_hot_key_index(key);
        if (fb_key_is(key, "__typename", sizeof("__typename") - 1u)) {
            candidate_type = value;
        } else if (fb_key_is(
                       key,
                       "browser_native_hd_url",
                       sizeof("browser_native_hd_url") - 1u)) {
            candidate_hd = value;
        } else if (fb_key_is(
                       key,
                       "browser_native_sd_url",
                       sizeof("browser_native_sd_url") - 1u)) {
            candidate_sd = value;
        } else if (fb_key_is(
                       key,
                       "videoDeliveryLegacyFields",
                       sizeof("videoDeliveryLegacyFields") - 1u)) {
            candidate_legacy = value;
        }
        if (slot->generation != builder->key_generation) {
            const size_t member_index = builder->member_count;
            fb_object_member member = {.value_ref = value_ref};
            if (member_index >= (size_t)FB_INDEX_NONE ||
                !fb_builder_append_member(builder, member)) {
                return false;
            }
            slot->hash = hash;
            slot->key_ref = key_ref;
            slot->member_index = (uint32_t)member_index;
            slot->generation = builder->key_generation;
            if (hot_index >= 0) {
                fb_hot_posting_vec *postings =
                    &builder->hot[(size_t)hot_index];
                fb_hot_posting posting = {
                    .object_rank = (uint32_t)object_rank,
                    .value_ref = value_ref,
                    .pair_index = (uint32_t)pair_index
                };
                if (postings->len == 0u) {
                    postings->key_ref = key_ref;
                }
                if (!fb_builder_append_posting(postings, posting)) {
                    return false;
                }
            }
        } else {
            builder->members[slot->member_index].value_ref = value_ref;
            if (hot_index >= 0) {
                fb_hot_posting_vec *postings =
                    &builder->hot[(size_t)hot_index];
                fb_hot_posting *posting;
                if (postings->len == 0u) {
                    return false;
                }
                posting = &postings->items[postings->len - 1u];
                if (posting->object_rank != (uint32_t)object_rank) {
                    return false;
                }
                posting->value_ref = value_ref;
                posting->pair_index = (uint32_t)pair_index;
            }
        }
        pair_index++;
        if ((pair_index & (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
            fb_document_poll_cancel(block->owner)) {
            return false;
        }
    }

    if (builder->member_count - member_first >= (size_t)FB_INDEX_NONE) {
        return false;
    }
    builder->objects[object_rank].member_count =
        (uint32_t)(builder->member_count - member_first);
    comment_candidate = fb_json_string_is(candidate_type, "Comment");
    if (yyjson_is_str(candidate_hd)) {
        video_candidate = fb_url_is_safe_media(fb_slice_make(
            yyjson_get_str(candidate_hd), yyjson_get_len(candidate_hd)));
    }
    if (!video_candidate && yyjson_is_str(candidate_sd)) {
        video_candidate = fb_url_is_safe_media(fb_slice_make(
            yyjson_get_str(candidate_sd), yyjson_get_len(candidate_sd)));
    }
    if (!video_candidate && yyjson_is_obj(candidate_legacy)) {
        video_candidate =
            fb_direct_video_url_fields(candidate_legacy) != NULL;
    }
    if (comment_candidate &&
        !fb_document_append_node_ref(
            &block->owner->comment_candidates,
            object,
            block->index,
            object_rank)) {
        return false;
    }
    if (video_candidate &&
        !fb_document_append_node_ref(
            &block->owner->video_candidates,
            object,
            block->index,
            object_rank)) {
        return false;
    }

    *rank_out = object_rank;
    *member_first_out = member_first;
    *member_count_out =
        (size_t)builder->objects[object_rank].member_count;
    return true;
}

typedef enum {
    FB_BUILD_OK = 0,
    FB_BUILD_NO_MEMORY,
    FB_BUILD_DEPTH_LIMIT,
    FB_BUILD_INDEX_LIMIT,
    FB_BUILD_CANCELLED
} fb_build_status;

static bool
fb_document_reserve_traversal_stack(
    fb_document *document,
    size_t required,
    size_t used
)
{
    size_t capacity;
    size_t bytes;
    size_t copy_bytes;
    fb_traversal_frame *stack;

    if (document == NULL || required > document->traversal_stack_limit ||
        used > document->traversal_stack_capacity) {
        return false;
    }
    if (required <= document->traversal_stack_capacity) {
        return true;
    }
    capacity = document->traversal_stack_capacity == 0u
                   ? 16u
                   : document->traversal_stack_capacity;
    if (capacity > document->traversal_stack_limit) {
        capacity = document->traversal_stack_limit;
    }
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2u) {
            capacity = document->traversal_stack_limit;
            break;
        }
        capacity *= 2u;
        if (capacity > document->traversal_stack_limit) {
            capacity = document->traversal_stack_limit;
        }
    }
    if (capacity < required ||
        !fb_size_mul(capacity, sizeof(*stack), &bytes)) {
        return false;
    }
    stack = fb_arena_alloc(
        document->arena,
        bytes,
        _Alignof(fb_traversal_frame)
    );
    if (stack == NULL) {
        return false;
    }
    if (used != 0u) {
        if (!fb_size_mul(used, sizeof(*stack), &copy_bytes)) {
            return false;
        }
        memcpy(stack, document->traversal_stack, copy_bytes);
    }
    document->traversal_stack = stack;
    document->traversal_stack_capacity = capacity;
    return true;
}

static fb_build_status
fb_block_build_traversal(
    fb_json_block *block,
    fb_block_builder *builder
)
{
    fb_document *document;
    fb_traversal_frame *stack;
    size_t stack_size = 0u;
    size_t work_count = 0u;

    if (block == NULL || builder == NULL || block->owner == NULL ||
        block->root == NULL) {
        return FB_BUILD_INDEX_LIMIT;
    }
    document = block->owner;
    if (!yyjson_is_obj(block->root) && !yyjson_is_arr(block->root)) {
        return FB_BUILD_OK;
    }
    if (document->traversal_stack_limit < 1u) {
        return FB_BUILD_DEPTH_LIMIT;
    }
    if (!fb_document_reserve_traversal_stack(document, 1u, 0u)) {
        return FB_BUILD_NO_MEMORY;
    }
    stack = document->traversal_stack;
    memset(&stack[0], 0, sizeof(stack[0]));
    stack[0].value = block->root;
    stack[0].phase = FB_FRAME_ENTER;
    stack[0].depth = 1u;
    stack_size = 1u;

    while (stack_size != 0u) {
        fb_traversal_frame *frame = &stack[stack_size - 1u];
        const yyjson_val *child = NULL;

        if (frame->phase == FB_FRAME_ENTER) {
            if (frame->depth > document->limits.max_depth) {
                return FB_BUILD_DEPTH_LIMIT;
            }
            if (yyjson_is_obj(frame->value)) {
                size_t object_rank;
                if (!fb_block_index_object(
                        block,
                        builder,
                        frame->value,
                        &object_rank,
                        &frame->member_first,
                        &frame->member_count)) {
                    if (document->cancelled) {
                        return FB_BUILD_CANCELLED;
                    }
                    if (builder->object_count >= (size_t)FB_INDEX_NONE ||
                        builder->member_count >= (size_t)FB_INDEX_NONE) {
                        return FB_BUILD_INDEX_LIMIT;
                    }
                    return FB_BUILD_NO_MEMORY;
                }
                (void)object_rank;
                frame->cursor = 0u;
                frame->phase = FB_FRAME_OBJECT_LISTS;
            } else if (yyjson_is_arr(frame->value)) {
                frame->array_iterator = yyjson_arr_iter_with(frame->value);
                frame->phase = FB_FRAME_ARRAY_OBJECTS;
            } else {
                frame->phase = FB_FRAME_DONE;
            }
        }

        if (frame->phase == FB_FRAME_OBJECT_LISTS ||
            frame->phase == FB_FRAME_OBJECT_OBJECTS) {
            const bool want_array =
                frame->phase == FB_FRAME_OBJECT_LISTS;
            while (frame->cursor < frame->member_count) {
                const size_t member_index =
                    frame->member_first + frame->cursor;
                const fb_object_member *member =
                    member_index < builder->member_count
                        ? &builder->members[member_index]
                        : NULL;
                const yyjson_val *value = member != NULL
                                              ? fb_block_value_at_ref(
                                                    block,
                                                    member->value_ref)
                                              : NULL;
                frame->cursor++;
                if ((++work_count &
                     (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                    fb_document_poll_cancel(document)) {
                    return FB_BUILD_CANCELLED;
                }
                if (member != NULL &&
                    ((want_array && yyjson_is_arr(value)) ||
                     (!want_array && yyjson_is_obj(value)))) {
                    child = value;
                    break;
                }
            }
            if (child == NULL) {
                if (frame->phase == FB_FRAME_OBJECT_LISTS) {
                    frame->phase = FB_FRAME_OBJECT_OBJECTS;
                    frame->cursor = 0u;
                    continue;
                }
                frame->phase = FB_FRAME_DONE;
            }
        } else if (frame->phase == FB_FRAME_ARRAY_OBJECTS ||
                   frame->phase == FB_FRAME_ARRAY_ARRAYS) {
            const bool want_object =
                frame->phase == FB_FRAME_ARRAY_OBJECTS;
            yyjson_val *item;
            while ((item = yyjson_arr_iter_next(&frame->array_iterator)) != NULL) {
                if ((++work_count &
                     (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                    fb_document_poll_cancel(document)) {
                    return FB_BUILD_CANCELLED;
                }
                if ((want_object && yyjson_is_obj(item)) ||
                    (!want_object && yyjson_is_arr(item))) {
                    child = item;
                    break;
                }
            }
            if (child == NULL) {
                if (frame->phase == FB_FRAME_ARRAY_OBJECTS) {
                    frame->phase = FB_FRAME_ARRAY_ARRAYS;
                    frame->array_iterator = yyjson_arr_iter_with(frame->value);
                    continue;
                }
                frame->phase = FB_FRAME_DONE;
            }
        }

        if (child != NULL) {
            size_t child_depth;
            size_t required_stack;
            if (!fb_size_add(frame->depth, 1u, &child_depth) ||
                !fb_size_add(stack_size, 1u, &required_stack) ||
                required_stack > document->traversal_stack_limit) {
                return FB_BUILD_DEPTH_LIMIT;
            }
            if (!fb_document_reserve_traversal_stack(
                    document,
                    required_stack,
                    stack_size)) {
                return FB_BUILD_NO_MEMORY;
            }
            stack = document->traversal_stack;
            memset(&stack[stack_size], 0, sizeof(stack[stack_size]));
            stack[stack_size].value = child;
            stack[stack_size].phase = FB_FRAME_ENTER;
            stack[stack_size].depth = child_depth;
            stack_size++;
            continue;
        }
        if (frame->phase == FB_FRAME_DONE) {
            stack_size--;
        }
    }
    return FB_BUILD_OK;
}

static bool
fb_block_finalize_indexes(
    fb_json_block *block,
    const fb_block_builder *builder
)
{
    size_t object_bytes;
    size_t member_bytes;
    size_t posting_count = 0u;
    size_t posting_bytes;
    size_t posting_offset = 0u;

    if (block == NULL || builder == NULL || block->owner == NULL ||
        block->value_count == 0u ||
        block->value_count >= (size_t)FB_INDEX_NONE ||
        builder->object_count >= (size_t)FB_INDEX_NONE ||
        builder->member_count >= (size_t)FB_INDEX_NONE ||
        !fb_size_mul(
            builder->object_count, sizeof(*block->objects), &object_bytes) ||
        !fb_size_mul(
            builder->member_count, sizeof(*block->members), &member_bytes)) {
        return false;
    }
    if (fb_document_poll_cancel(block->owner)) {
        return false;
    }
    for (size_t index = 0u; index < FB_HOT_COUNT; ++index) {
        if (builder->hot[index].len >= (size_t)FB_INDEX_NONE ||
            !fb_size_add(
                posting_count,
                builder->hot[index].len,
                &posting_count) ||
            posting_count >= (size_t)FB_INDEX_NONE) {
            return false;
        }
    }
    if (!fb_size_mul(
            posting_count, sizeof(*block->postings), &posting_bytes)) {
        return false;
    }
    if (object_bytes != 0u) {
        block->objects = fb_arena_memdup(
            block->owner->arena,
            builder->objects,
            object_bytes,
            _Alignof(fb_object_node)
        );
        if (block->objects == NULL) {
            return false;
        }
    }
    if (member_bytes != 0u) {
        block->members = fb_arena_memdup(
            block->owner->arena,
            builder->members,
            member_bytes,
            _Alignof(fb_object_member)
        );
        if (block->members == NULL) {
            return false;
        }
    }
    if (posting_bytes != 0u) {
        block->postings = fb_arena_alloc(
            block->owner->arena,
            posting_bytes,
            _Alignof(fb_hot_posting)
        );
        if (block->postings == NULL) {
            return false;
        }
    }
    block->object_count = builder->object_count;
    block->member_count = builder->member_count;
    block->posting_count = posting_count;
    if (fb_document_poll_cancel(block->owner)) {
        return false;
    }
    for (size_t index = 0u; index < FB_HOT_COUNT; ++index) {
        const fb_hot_posting_vec *source = &builder->hot[index];
        fb_hot_slot *slot = &block->hot[index];
        slot->first = (uint32_t)posting_offset;
        slot->count = (uint32_t)source->len;
        slot->key_ref = source->len != 0u
                            ? source->key_ref
                            : FB_INDEX_NONE;
        if (source->len != 0u) {
            memcpy(
                &block->postings[posting_offset],
                source->items,
                source->len * sizeof(*source->items)
            );
        }
        posting_offset += source->len;
    }
    return posting_offset == posting_count;
}

const yyjson_val *
fb_json_object_get_last(const yyjson_val *object, fb_slice key)
{
    yyjson_obj_iter iterator;
    yyjson_val *key_value;
    const yyjson_val *result = NULL;

    if (!yyjson_is_obj(object) || !fb_slice_is_valid(key)) {
        return NULL;
    }
    iterator = yyjson_obj_iter_with(object);
    while ((key_value = yyjson_obj_iter_next(&iterator)) != NULL) {
        const char *text = yyjson_get_str(key_value);
        size_t length = yyjson_get_len(key_value);
        if (length == key.len &&
            (length == 0u || memcmp(text, key.ptr, length) == 0)) {
            result = yyjson_obj_iter_get_val(key_value);
        }
    }
    return result;
}

static bool
fb_json_string_is(const yyjson_val *value, const char *literal)
{
    size_t length;

    if (!yyjson_is_str(value) || literal == NULL) {
        return false;
    }
    length = strlen(literal);
    return yyjson_get_len(value) == length &&
           (length == 0u ||
            memcmp(yyjson_get_str(value), literal, length) == 0);
}

static bool
fb_slice_equal_literal_fold(fb_slice value, const char *literal)
{
    return fb_slice_equal_literal_ascii_case(value, literal);
}

static bool
fb_nonfinite_token_valid(
    fb_slice json,
    size_t start,
    size_t end,
    size_t *bad_offset
)
{
    fb_slice token = fb_slice_make(json.ptr + start, end - start);

    if (fb_slice_equal_literal_fold(token, "nan")) {
        bool exact = fb_slice_equal_literal(token, "NaN");
        bool signed_token = start != 0u &&
            (json.ptr[start - 1u] == '-' || json.ptr[start - 1u] == '+');
        if (!exact || signed_token) {
            if (bad_offset != NULL) {
                *bad_offset = signed_token ? start - 1u : start;
            }
            return false;
        }
    } else if (fb_slice_equal_literal_fold(token, "inf") ||
               fb_slice_equal_literal_fold(token, "infinity")) {
        bool exact = fb_slice_equal_literal(token, "Infinity");
        bool positive_sign = start != 0u && json.ptr[start - 1u] == '+';
        if (!exact || positive_sign) {
            if (bad_offset != NULL) {
                *bad_offset = positive_sign ? start - 1u : start;
            }
            return false;
        }
    }
    return true;
}

static bool
fb_python_nonfinite_spellings_valid_scalar(
    fb_document *document,
    fb_slice json,
    size_t *bad_offset
)
{
    size_t cursor = 0u;
    size_t next_poll = 0u;

    while (cursor < json.len) {
        if (cursor >= next_poll) {
            if (fb_document_poll_cancel(document)) {
                return false;
            }
            next_poll = cursor + FB_CANCEL_BYTE_INTERVAL;
        }
        unsigned char value = (unsigned char)json.ptr[cursor];
        if (value == (unsigned char)'"') {
            cursor++;
            while (cursor < json.len) {
                if (cursor >= next_poll) {
                    if (fb_document_poll_cancel(document)) {
                        return false;
                    }
                    next_poll = cursor + FB_CANCEL_BYTE_INTERVAL;
                }
                value = (unsigned char)json.ptr[cursor++];
                if (value == (unsigned char)'\\') {
                    if (cursor < json.len) {
                        cursor++;
                    }
                } else if (value == (unsigned char)'"') {
                    break;
                }
            }
            continue;
        }
        if (fb_is_ascii_alpha(value)) {
            size_t start = cursor;
            while (cursor < json.len &&
                   fb_is_ascii_alpha((unsigned char)json.ptr[cursor])) {
                cursor++;
            }
            if (!fb_nonfinite_token_valid(
                    json, start, cursor, bad_offset)) {
                return false;
            }
            continue;
        }
        cursor++;
    }
    return true;
}

typedef bool (*fb_nonfinite_scan_fn)(
    fb_document *document,
    fb_slice json,
    size_t *bad_offset
);
typedef const char *(*fb_tag_event_scan_fn)(const char *text, size_t length);

static const char *
fb_find_tag_event_scalar(const char *text, size_t length)
{
    for (size_t index = 0u; index < length; ++index) {
        if (text[index] == '\'' || text[index] == '"' || text[index] == '>') {
            return text + index;
        }
    }
    return NULL;
}

#if FB_DOCUMENT_HAVE_X86_AVX2
__attribute__((target("avx2")))
static bool
fb_python_nonfinite_spellings_valid_avx2(
    fb_document *document,
    fb_slice json,
    size_t *bad_offset
)
{
    const __m256i quote = _mm256_set1_epi8('"');
    const __m256i backslash = _mm256_set1_epi8('\\');
    const __m256i case_bit = _mm256_set1_epi8(0x20);
    const __m256i alpha_first = _mm256_set1_epi8('a');
    const __m256i alpha_last = _mm256_set1_epi8('z');
    size_t cursor = 0u;
    size_t next_poll = 0u;

    while (cursor < json.len) {
        if (cursor >= next_poll) {
            if (fb_document_poll_cancel(document)) {
                return false;
            }
            next_poll = cursor + FB_CANCEL_BYTE_INTERVAL;
        }
        while (json.len - cursor >= 32u) {
            if (cursor >= next_poll) {
                if (fb_document_poll_cancel(document)) {
                    return false;
                }
                next_poll = cursor + FB_CANCEL_BYTE_INTERVAL;
            }
            const __m256i bytes = _mm256_loadu_si256(
                (const __m256i *)(const void *)(json.ptr + cursor)
            );
            const __m256i folded = _mm256_or_si256(bytes, case_bit);
            const __m256i at_or_after_first = _mm256_cmpeq_epi8(
                _mm256_max_epu8(folded, alpha_first), folded
            );
            const __m256i at_or_before_last = _mm256_cmpeq_epi8(
                _mm256_min_epu8(folded, alpha_last), folded
            );
            const __m256i alpha = _mm256_and_si256(
                at_or_after_first, at_or_before_last
            );
            const __m256i event = _mm256_or_si256(
                alpha, _mm256_cmpeq_epi8(bytes, quote)
            );
            unsigned int mask = (unsigned int)_mm256_movemask_epi8(event);
            if (mask != 0u) {
                cursor += (size_t)__builtin_ctz(mask);
                break;
            }
            cursor += 32u;
        }
        if (cursor >= json.len) {
            break;
        }

        unsigned char value = (unsigned char)json.ptr[cursor];
        if (value == (unsigned char)'"') {
            cursor++;
            while (cursor < json.len) {
                while (json.len - cursor >= 32u) {
                    if (cursor >= next_poll) {
                        if (fb_document_poll_cancel(document)) {
                            return false;
                        }
                        next_poll = cursor + FB_CANCEL_BYTE_INTERVAL;
                    }
                    const __m256i bytes = _mm256_loadu_si256(
                        (const __m256i *)(const void *)(json.ptr + cursor)
                    );
                    const __m256i event = _mm256_or_si256(
                        _mm256_cmpeq_epi8(bytes, quote),
                        _mm256_cmpeq_epi8(bytes, backslash)
                    );
                    unsigned int mask =
                        (unsigned int)_mm256_movemask_epi8(event);
                    if (mask != 0u) {
                        cursor += (size_t)__builtin_ctz(mask);
                        break;
                    }
                    cursor += 32u;
                }
                if (cursor >= json.len) {
                    break;
                }
                value = (unsigned char)json.ptr[cursor++];
                if (value == (unsigned char)'\\') {
                    if (cursor < json.len) {
                        cursor++;
                    }
                } else if (value == (unsigned char)'"') {
                    break;
                }
            }
            continue;
        }
        if (fb_is_ascii_alpha(value)) {
            size_t start = cursor;
            while (cursor < json.len &&
                   fb_is_ascii_alpha((unsigned char)json.ptr[cursor])) {
                cursor++;
            }
            if (!fb_nonfinite_token_valid(
                    json, start, cursor, bad_offset)) {
                return false;
            }
            continue;
        }
        cursor++;
    }
    return true;
}

__attribute__((target("avx2")))
static const char *
fb_find_tag_event_avx2(const char *text, size_t length)
{
    const __m256i apostrophe = _mm256_set1_epi8('\'');
    const __m256i quote = _mm256_set1_epi8('"');
    const __m256i greater = _mm256_set1_epi8('>');
    size_t offset = 0u;

    while (length - offset >= 32u) {
        const __m256i bytes = _mm256_loadu_si256(
            (const __m256i *)(const void *)(text + offset)
        );
        const __m256i event = _mm256_or_si256(
            _mm256_cmpeq_epi8(bytes, apostrophe),
            _mm256_or_si256(
                _mm256_cmpeq_epi8(bytes, quote),
                _mm256_cmpeq_epi8(bytes, greater)
            )
        );
        unsigned int mask = (unsigned int)_mm256_movemask_epi8(event);
        if (mask != 0u) {
            return text + offset + (size_t)__builtin_ctz(mask);
        }
        offset += 32u;
    }
    return fb_find_tag_event_scalar(text + offset, length - offset);
}
#endif

static fb_nonfinite_scan_fn fb_nonfinite_scan =
    fb_python_nonfinite_spellings_valid_scalar;
static fb_tag_event_scan_fn fb_tag_event_scan = fb_find_tag_event_scalar;
static pthread_once_t fb_document_scan_once = PTHREAD_ONCE_INIT;

static void
fb_document_select_scanners(void)
{
#if FB_DOCUMENT_HAVE_X86_AVX2
    __builtin_cpu_init();
    if (__builtin_cpu_supports("avx2") != 0) {
        fb_nonfinite_scan = fb_python_nonfinite_spellings_valid_avx2;
        fb_tag_event_scan = fb_find_tag_event_avx2;
    }
#endif
}

static void
fb_document_initialize_scanners(void)
{
    (void)pthread_once(&fb_document_scan_once, fb_document_select_scanners);
}

static bool
fb_python_nonfinite_spellings_valid(
    fb_document *document,
    fb_slice json,
    size_t *bad_offset
)
{
    return fb_nonfinite_scan(document, json, bad_offset);
}

static const yyjson_val *
fb_direct_video_url_fields(const yyjson_val *object)
{
    static const fb_slice keys[] = {
        {.ptr = "browser_native_hd_url",
         .len = sizeof("browser_native_hd_url") - 1u},
        {.ptr = "browser_native_sd_url",
         .len = sizeof("browser_native_sd_url") - 1u}
    };
    if (!yyjson_is_obj(object)) {
        return NULL;
    }
    for (size_t index = 0u; index < FB_ARRAY_LEN(keys); ++index) {
        const yyjson_val *value =
            fb_json_object_get_last(object, keys[index]);
        if (yyjson_is_str(value)) {
            fb_slice url = fb_slice_make(
                yyjson_get_str(value),
                yyjson_get_len(value)
            );
            if (fb_url_is_safe_media(url)) {
                return value;
            }
        }
    }
    return NULL;
}

static bool
fb_document_append_node_ref(
    fb_chunk_vec *vector,
    const yyjson_val *value,
    size_t block_index,
    size_t traversal_rank
)
{
    fb_json_node_ref *reference = fb_chunk_vec_append(vector);
    if (reference == NULL) {
        return false;
    }
    reference->value = value;
    reference->block_index = block_index;
    reference->traversal_rank = traversal_rank;
    return true;
}

static bool
fb_document_route_exists(
    const fb_document *document,
    const yyjson_val *route
)
{
    for (size_t index = 0u; index < document->initial_routes.len; ++index) {
        const fb_json_node_ref *reference =
            fb_chunk_vec_at(&document->initial_routes, index);
        if (reference != NULL && yyjson_equals(reference->value, route)) {
            return true;
        }
    }
    return false;
}

static bool
fb_document_index_candidates(
    fb_document *document,
    const fb_json_block *block
)
{
    fb_json_match initial_route_info;

    if (fb_json_block_key_first(
            block,
            FB_SLICE_LIT("initialRouteInfo"),
            &initial_route_info) &&
        yyjson_is_obj(initial_route_info.value)) {
        const yyjson_val *route = fb_json_object_get_last(
            initial_route_info.value,
            FB_SLICE_LIT("route")
        );
        size_t route_rank;
        if (yyjson_is_obj(route) &&
            !fb_document_route_exists(document, route) &&
            fb_json_block_traversal_rank(block, route, &route_rank) &&
            !fb_document_append_node_ref(
                &document->initial_routes,
                route,
                block->index,
                route_rank)) {
            return false;
        }
    }

    return true;
}

static fb_document_status
fb_document_add_json_script(
    fb_document *document,
    fb_block_builder *builder,
    fb_slice raw_text,
    size_t source_offset,
    fb_document_error *error
)
{
    yyjson_alc allocator;
    yyjson_read_err read_error;
    yyjson_doc *json_document;
    fb_json_script *script;
    size_t script_index;
    size_t value_count;
    size_t total_values;
    fb_json_block *block;
    fb_build_status build_status;

    if (fb_document_poll_cancel(document)) {
        return fb_cancel_error(
            document, error, source_offset, document->scripts.len);
    }

    if (document->scripts.len >= document->limits.max_scripts) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_SCRIPT_LIMIT,
            source_offset,
            document->scripts.len,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    if (raw_text.len > document->limits.max_json_bytes) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_SCRIPT_BYTES_LIMIT,
            source_offset,
            document->scripts.len,
            YYJSON_READ_SUCCESS,
            0u
        );
    }

    script_index = document->scripts.len;
    script = fb_chunk_vec_append(&document->scripts);
    if (script == NULL) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            source_offset,
            script_index,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    script->raw_text = raw_text;
    script->source_offset = source_offset;
    script->status = FB_JSON_SCRIPT_EMPTY;
    if (raw_text.len == 0u) {
        return FB_DOCUMENT_OK;
    }
    {
        size_t bad_offset = 0u;
        if (!fb_python_nonfinite_spellings_valid(
                document, raw_text, &bad_offset)) {
            if (document->cancelled) {
                return fb_cancel_error(
                    document, error, source_offset, script_index);
            }
            script->status = FB_JSON_SCRIPT_INVALID;
            script->read_code = YYJSON_READ_ERROR_LITERAL;
            script->error_offset = bad_offset;
            document->invalid_json_count++;
            return FB_DOCUMENT_OK;
        }
    }

    allocator.malloc = fb_yyjson_malloc;
    allocator.realloc = fb_yyjson_realloc;
    allocator.free = fb_yyjson_free;
    allocator.ctx = document->arena;
    memset(&read_error, 0, sizeof(read_error));
    json_document = yyjson_read_opts(
        (char *)(void *)raw_text.ptr,
        raw_text.len,
        YYJSON_READ_ALLOW_INF_AND_NAN | YYJSON_READ_BIGNUM_AS_RAW,
        &allocator,
        &read_error
    );
    if (fb_document_poll_cancel(document)) {
        return fb_cancel_error(
            document, error, source_offset, script_index);
    }
    if (json_document == NULL) {
        script->status = FB_JSON_SCRIPT_INVALID;
        script->read_code = read_error.code;
        script->error_offset = read_error.pos;
        document->invalid_json_count++;
        if (read_error.code == YYJSON_READ_ERROR_MEMORY_ALLOCATION) {
            return fb_error_set(
                error,
                FB_DOCUMENT_NO_MEMORY,
                FB_DOCUMENT_ISSUE_NONE,
                source_offset,
                script_index,
                read_error.code,
                read_error.pos
            );
        }
        return FB_DOCUMENT_OK;
    }

    value_count = yyjson_doc_get_val_count(json_document);
    if (value_count > document->limits.max_json_values) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_JSON_VALUE_LIMIT,
            source_offset,
            script_index,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    if (!fb_size_add(document->total_json_values, value_count,
                     &total_values) ||
        total_values > document->limits.max_total_json_values) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_JSON_TOTAL_VALUE_LIMIT,
            source_offset,
            script_index,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    if (value_count == 0u || value_count >= (size_t)FB_INDEX_NONE) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_INTERNAL_INDEX_LIMIT,
            source_offset,
            script_index,
            YYJSON_READ_SUCCESS,
            0u
        );
    }

    block = fb_chunk_vec_append(&document->blocks);
    if (block == NULL) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            source_offset,
            script_index,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    block->owner = document;
    block->json_document = json_document;
    block->root = yyjson_doc_get_root(json_document);
    block->index = document->blocks.len - 1u;
    block->value_count = value_count;
    fb_block_builder_reset(builder);
    build_status = fb_block_build_traversal(block, builder);
    if (build_status != FB_BUILD_OK) {
        if (build_status == FB_BUILD_CANCELLED || document->cancelled) {
            return fb_cancel_error(
                document, error, source_offset, script_index);
        }
        fb_document_status status =
            build_status == FB_BUILD_NO_MEMORY
                ? FB_DOCUMENT_NO_MEMORY
                : FB_DOCUMENT_LIMIT_EXCEEDED;
        fb_document_issue issue = FB_DOCUMENT_ISSUE_INTERNAL_INDEX_LIMIT;
        if (build_status == FB_BUILD_DEPTH_LIMIT) {
            issue = FB_DOCUMENT_ISSUE_JSON_DEPTH_LIMIT;
        }
        return fb_error_set(
            error,
            status,
            issue,
            source_offset,
            script_index,
            build_status == FB_BUILD_NO_MEMORY
                ? YYJSON_READ_ERROR_MEMORY_ALLOCATION
                : YYJSON_READ_SUCCESS,
            0u
        );
    }
    if (!fb_block_finalize_indexes(block, builder)) {
        if (document->cancelled) {
            return fb_cancel_error(
                document, error, source_offset, script_index);
        }
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            source_offset,
            script_index,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    if (fb_document_poll_cancel(document)) {
        return fb_cancel_error(
            document, error, source_offset, script_index);
    }

    document->total_json_values = total_values;
    script->status = FB_JSON_SCRIPT_VALID;
    script->read_code = YYJSON_READ_SUCCESS;
    script->block = block;
    if (!fb_document_index_candidates(document, block)) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            source_offset,
            script_index,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    return FB_DOCUMENT_OK;
}

typedef struct {
    uint16_t name_offset;
    uint16_t value_offset;
    uint8_t name_length;
    uint8_t value_length;
    uint8_t flags;
} fb_named_entity;

#include "html_entities_generated.inc"

_Static_assert(
    (FB_HTML_ENTITY_BUCKET_COUNT &
     (FB_HTML_ENTITY_BUCKET_COUNT - 1u)) == 0u,
    "HTML entity bucket count must be a power of two"
);
_Static_assert(
    FB_HTML_ENTITY_SLOT_COUNT <= UINT16_MAX,
    "HTML entity slot indices must fit generated displacements"
);

static uint32_t
fb_named_entity_hash(fb_slice name)
{
    uint32_t hash = UINT32_C(2166136261);

    for (size_t index = 0u; index < name.len; ++index) {
        hash ^= (uint32_t)(unsigned char)name.ptr[index];
        hash *= UINT32_C(16777619);
    }
    return hash;
}

static uint32_t
fb_named_entity_mix(uint32_t value)
{
    value = (value ^ (value >> 16u)) * UINT32_C(0x7feb352d);
    value = (value ^ (value >> 15u)) * UINT32_C(0x846ca68b);
    return value ^ (value >> 16u);
}

static bool
fb_named_entity_value(
    fb_slice name,
    fb_slice *value,
    bool *legacy_without_semicolon
)
{
    uint32_t hash;
    int16_t displacement;
    size_t slot;
    const fb_named_entity *entity;

    if (value == NULL || legacy_without_semicolon == NULL ||
        !fb_slice_is_valid(name) || name.len == 0u || name.len > 31u) {
        return false;
    }
    hash = fb_named_entity_hash(name);
    displacement = fb_html_entity_displacements[
        hash & (FB_HTML_ENTITY_BUCKET_COUNT - 1u)
    ];
    if (displacement < 0) {
        slot = (size_t)(-(int32_t)displacement - 1);
    } else {
        uint32_t displaced = hash ^
            ((uint32_t)(uint16_t)displacement * UINT32_C(0x9e3779b9));
        slot = (size_t)(
            fb_named_entity_mix(displaced) % FB_HTML_ENTITY_SLOT_COUNT
        );
    }
    entity = &fb_html_entities[slot];
    if (name.len != (size_t)entity->name_length ||
        memcmp(
            name.ptr,
            fb_html_entity_name_blob + entity->name_offset,
            name.len
        ) != 0) {
        return false;
    }
    *value = fb_slice_make(
        (const char *)(const void *)(
            fb_html_entity_value_blob + entity->value_offset
        ),
        (size_t)entity->value_length
    );
    *legacy_without_semicolon =
        (entity->flags & FB_HTML_ENTITY_LEGACY) != 0u;
    return true;
}

static uint32_t
fb_html_numeric_codepoint(uint32_t codepoint)
{
    static const uint16_t c1_replacements[32] = {
        0x20acu, 0x0081u, 0x201au, 0x0192u,
        0x201eu, 0x2026u, 0x2020u, 0x2021u,
        0x02c6u, 0x2030u, 0x0160u, 0x2039u,
        0x0152u, 0x008du, 0x017du, 0x008fu,
        0x0090u, 0x2018u, 0x2019u, 0x201cu,
        0x201du, 0x2022u, 0x2013u, 0x2014u,
        0x02dcu, 0x2122u, 0x0161u, 0x203au,
        0x0153u, 0x009du, 0x017eu, 0x0178u
    };

    if (codepoint == 0u || codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
        return 0xfffdu;
    }
    if (codepoint >= 0x80u && codepoint <= 0x9fu) {
        return (uint32_t)c1_replacements[codepoint - 0x80u];
    }
    return codepoint;
}

static size_t
fb_utf8_encode(uint32_t codepoint, char output[4])
{
    if (codepoint <= 0x7fu) {
        output[0] = (char)codepoint;
        return 1u;
    }
    if (codepoint <= 0x7ffu) {
        output[0] = (char)(0xc0u | (codepoint >> 6u));
        output[1] = (char)(0x80u | (codepoint & 0x3fu));
        return 2u;
    }
    if (codepoint <= 0xffffu) {
        output[0] = (char)(0xe0u | (codepoint >> 12u));
        output[1] = (char)(0x80u | ((codepoint >> 6u) & 0x3fu));
        output[2] = (char)(0x80u | (codepoint & 0x3fu));
        return 3u;
    }
    output[0] = (char)(0xf0u | (codepoint >> 18u));
    output[1] = (char)(0x80u | ((codepoint >> 12u) & 0x3fu));
    output[2] = (char)(0x80u | ((codepoint >> 6u) & 0x3fu));
    output[3] = (char)(0x80u | (codepoint & 0x3fu));
    return 4u;
}

static bool
fb_ascii_alphanumeric(unsigned char value)
{
    return (value >= (unsigned char)'a' && value <= (unsigned char)'z') ||
           (value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
           (value >= (unsigned char)'0' && value <= (unsigned char)'9');
}

static bool
fb_decode_html_attribute(
    fb_document *document,
    fb_slice raw,
    fb_slice *decoded
)
{
    const char *ampersand;
    char *output;
    size_t output_capacity;
    size_t input_index = 0u;
    size_t output_index = 0u;

    if (document == NULL || decoded == NULL || !fb_slice_is_valid(raw)) {
        return false;
    }
    ampersand = raw.len == 0u
                    ? NULL
                    : fb_document_memchr(
                          document, raw.ptr, (unsigned char)'&', raw.len);
    if (document->cancelled) {
        return false;
    }
    if (ampersand == NULL) {
        *decoded = raw;
        return true;
    }
    /*
     * Every HTML5 named reference is no longer than its source spelling,
     * except &nLt; and &nGt;: each grows from five bytes to six. Numeric
     * references never grow. Reserve one extra byte per possible five-byte
     * reference, plus the terminator, without doubling attacker-controlled
     * attribute storage.
     */
    if (!fb_size_add(raw.len, raw.len / 5u, &output_capacity) ||
        !fb_size_add(output_capacity, 1u, &output_capacity)) {
        return false;
    }
    output = fb_arena_alloc(document->arena, output_capacity, 1u);
    if (output == NULL) {
        return false;
    }

    while (input_index < raw.len) {
        size_t entity_start;
        size_t cursor;
        size_t consumed = 0u;
        uint32_t codepoint = 0u;
        fb_slice replacement = {0};
        bool decoded_entity = false;

        if (raw.ptr[input_index] != '&') {
            output[output_index++] = raw.ptr[input_index++];
            continue;
        }
        entity_start = input_index;
        cursor = input_index + 1u;
        if (cursor < raw.len && raw.ptr[cursor] == '#') {
            bool hexadecimal = false;
            bool overflow = false;
            size_t digit_count = 0u;
            cursor++;
            if (cursor < raw.len &&
                (raw.ptr[cursor] == 'x' || raw.ptr[cursor] == 'X')) {
                hexadecimal = true;
                cursor++;
            }
            while (cursor < raw.len) {
                unsigned char value = (unsigned char)raw.ptr[cursor];
                uint32_t digit;
                uint32_t base = hexadecimal ? 16u : 10u;
                if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
                    digit = (uint32_t)(value - (unsigned char)'0');
                } else if (hexadecimal && value >= (unsigned char)'a' &&
                           value <= (unsigned char)'f') {
                    digit = (uint32_t)(value - (unsigned char)'a') + 10u;
                } else if (hexadecimal && value >= (unsigned char)'A' &&
                           value <= (unsigned char)'F') {
                    digit = (uint32_t)(value - (unsigned char)'A') + 10u;
                } else {
                    break;
                }
                if (codepoint > (UINT32_MAX - digit) / base) {
                    overflow = true;
                } else if (!overflow) {
                    codepoint = codepoint * base + digit;
                }
                digit_count++;
                cursor++;
            }
            if (digit_count != 0u) {
                if (cursor < raw.len && raw.ptr[cursor] == ';') {
                    cursor++;
                }
                codepoint = fb_html_numeric_codepoint(
                    overflow ? 0x110000u : codepoint
                );
                consumed = cursor - entity_start;
                decoded_entity = true;
            }
        } else {
            size_t name_start = cursor;
            size_t name_length;
            bool has_semicolon;
            bool legacy_without_semicolon = false;
            while (cursor < raw.len &&
                   fb_ascii_alphanumeric((unsigned char)raw.ptr[cursor])) {
                cursor++;
            }
            name_length = cursor - name_start;
            has_semicolon = cursor < raw.len && raw.ptr[cursor] == ';';
            if (name_length != 0u &&
                fb_named_entity_value(
                    fb_slice_make(raw.ptr + name_start, name_length),
                    &replacement,
                    &legacy_without_semicolon)) {
                bool safe_legacy_end =
                    cursor == raw.len ||
                    (!fb_ascii_alphanumeric((unsigned char)raw.ptr[cursor]) &&
                     raw.ptr[cursor] != '=');
                if (has_semicolon ||
                    (legacy_without_semicolon && safe_legacy_end)) {
                    consumed = cursor - entity_start +
                               (has_semicolon ? 1u : 0u);
                    decoded_entity = true;
                }
            }
        }

        if (decoded_entity) {
            if (replacement.ptr != NULL) {
                if (replacement.len >
                    output_capacity - 1u - output_index) {
                    return false;
                }
                memcpy(
                    output + output_index,
                    replacement.ptr,
                    replacement.len
                );
                output_index += replacement.len;
            } else {
                char encoded[4];
                size_t encoded_length = fb_utf8_encode(codepoint, encoded);
                if (encoded_length >
                    output_capacity - 1u - output_index) {
                    return false;
                }
                memcpy(output + output_index, encoded, encoded_length);
                output_index += encoded_length;
            }
            input_index += consumed;
        } else {
            output[output_index++] = raw.ptr[input_index++];
        }
    }
    output[output_index] = '\0';
    *decoded = fb_slice_make(output, output_index);
    return true;
}

#if CHAR_BIT == 8 && defined(__BYTE_ORDER__) && \
    (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
     __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define FB_DOCUMENT_HAVE_ATTRIBUTE_PACKED_ASCII 1
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define FB_ATTRIBUTE_ASCII_PACK2(a, b) \
    ((uint16_t)(unsigned char)(a) | \
     ((uint16_t)(unsigned char)(b) << 8u))
#define FB_ATTRIBUTE_ASCII_PACK4(a, b, c, d) \
    ((uint32_t)FB_ATTRIBUTE_ASCII_PACK2((a), (b)) | \
     ((uint32_t)FB_ATTRIBUTE_ASCII_PACK2((c), (d)) << 16u))
#define FB_ATTRIBUTE_ASCII_PACK8(a, b, c, d, e, f, g, h) \
    ((uint64_t)FB_ATTRIBUTE_ASCII_PACK4((a), (b), (c), (d)) | \
     ((uint64_t)FB_ATTRIBUTE_ASCII_PACK4((e), (f), (g), (h)) << 32u))
#else
#define FB_ATTRIBUTE_ASCII_PACK2(a, b) \
    (((uint16_t)(unsigned char)(a) << 8u) | \
     (uint16_t)(unsigned char)(b))
#define FB_ATTRIBUTE_ASCII_PACK4(a, b, c, d) \
    (((uint32_t)FB_ATTRIBUTE_ASCII_PACK2((a), (b)) << 16u) | \
     (uint32_t)FB_ATTRIBUTE_ASCII_PACK2((c), (d)))
#define FB_ATTRIBUTE_ASCII_PACK8(a, b, c, d, e, f, g, h) \
    (((uint64_t)FB_ATTRIBUTE_ASCII_PACK4((a), (b), (c), (d)) << 32u) | \
     (uint64_t)FB_ATTRIBUTE_ASCII_PACK4((e), (f), (g), (h)))
#endif
#else
#define FB_DOCUMENT_HAVE_ATTRIBUTE_PACKED_ASCII 0
#endif

static fb_attribute *
fb_tag_attribute_slot(fb_tag_attributes *attributes, fb_slice name)
{
#if FB_DOCUMENT_HAVE_ATTRIBUTE_PACKED_ASCII
    switch (name.len) {
    case 2u: {
        uint16_t word;
        memcpy(&word, name.ptr, sizeof(word));
        word |= UINT16_C(0x2020);
        return word == FB_ATTRIBUTE_ASCII_PACK2('i', 'd')
                   ? &attributes->id
                   : NULL;
    }
    case 3u: {
        uint16_t prefix;
        unsigned char last = fb_ascii_lower((unsigned char)name.ptr[2]);
        memcpy(&prefix, name.ptr, sizeof(prefix));
        prefix |= UINT16_C(0x2020);
        return prefix == FB_ATTRIBUTE_ASCII_PACK2('r', 'e') && last == 'l'
                   ? &attributes->rel
                   : NULL;
    }
    case 4u: {
        uint32_t word;
        memcpy(&word, name.ptr, sizeof(word));
        word |= UINT32_C(0x20202020);
        if (word == FB_ATTRIBUTE_ASCII_PACK4('t', 'y', 'p', 'e')) {
            return &attributes->type;
        }
        if (word == FB_ATTRIBUTE_ASCII_PACK4('h', 'r', 'e', 'f')) {
            return &attributes->href;
        }
        if (word == FB_ATTRIBUTE_ASCII_PACK4('n', 'a', 'm', 'e')) {
            return &attributes->name;
        }
        return NULL;
    }
    case 6u: {
        uint32_t prefix;
        uint16_t suffix;
        memcpy(&prefix, name.ptr, sizeof(prefix));
        memcpy(&suffix, name.ptr + sizeof(prefix), sizeof(suffix));
        prefix |= UINT32_C(0x20202020);
        suffix |= UINT16_C(0x2020);
        if (prefix == FB_ATTRIBUTE_ASCII_PACK4('a', 'c', 't', 'i') &&
            suffix == FB_ATTRIBUTE_ASCII_PACK2('o', 'n')) {
            return &attributes->action;
        }
        if (prefix == FB_ATTRIBUTE_ASCII_PACK4('m', 'e', 't', 'h') &&
            suffix == FB_ATTRIBUTE_ASCII_PACK2('o', 'd')) {
            return &attributes->method;
        }
        return NULL;
    }
    case 7u: {
        uint32_t prefix;
        uint16_t middle;
        unsigned char last = fb_ascii_lower((unsigned char)name.ptr[6]);
        memcpy(&prefix, name.ptr, sizeof(prefix));
        memcpy(&middle, name.ptr + sizeof(prefix), sizeof(middle));
        prefix |= UINT32_C(0x20202020);
        middle |= UINT16_C(0x2020);
        return prefix == FB_ATTRIBUTE_ASCII_PACK4('c', 'o', 'n', 't') &&
                       middle == FB_ATTRIBUTE_ASCII_PACK2('e', 'n') &&
                       last == 't'
                   ? &attributes->content
                   : NULL;
    }
    case 8u: {
        uint64_t word;
        memcpy(&word, name.ptr, sizeof(word));
        word |= UINT64_C(0x2020202020202020);
        return word == FB_ATTRIBUTE_ASCII_PACK8(
                           'p', 'r', 'o', 'p', 'e', 'r', 't', 'y')
                   ? &attributes->property
                   : NULL;
    }
    default:
        return NULL;
    }
#else
    if (fb_slice_equal_literal_ascii_case(name, "type")) {
        return &attributes->type;
    }
    if (fb_slice_equal_literal_ascii_case(name, "rel")) {
        return &attributes->rel;
    }
    if (fb_slice_equal_literal_ascii_case(name, "href")) {
        return &attributes->href;
    }
    if (fb_slice_equal_literal_ascii_case(name, "property")) {
        return &attributes->property;
    }
    if (fb_slice_equal_literal_ascii_case(name, "content")) {
        return &attributes->content;
    }
    if (fb_slice_equal_literal_ascii_case(name, "action")) {
        return &attributes->action;
    }
    if (fb_slice_equal_literal_ascii_case(name, "method")) {
        return &attributes->method;
    }
    if (fb_slice_equal_literal_ascii_case(name, "id")) {
        return &attributes->id;
    }
    if (fb_slice_equal_literal_ascii_case(name, "name")) {
        return &attributes->name;
    }
    return NULL;
#endif
}

#if FB_DOCUMENT_HAVE_ATTRIBUTE_PACKED_ASCII
#undef FB_ATTRIBUTE_ASCII_PACK8
#undef FB_ATTRIBUTE_ASCII_PACK4
#undef FB_ATTRIBUTE_ASCII_PACK2
#endif

static fb_scan_status
fb_capture_attribute(
    fb_document *document,
    fb_tag_attributes *attributes,
    fb_slice name,
    fb_slice raw_value,
    size_t source_offset
)
{
    fb_attribute *attribute = fb_tag_attribute_slot(attributes, name);
    fb_slice decoded;

    if (attribute == NULL) {
        return FB_SCAN_OK;
    }
    if (!fb_decode_html_attribute(document, raw_value, &decoded)) {
        return FB_SCAN_NO_MEMORY;
    }
    attribute->raw = raw_value;
    attribute->decoded = decoded;
    attribute->source_offset = source_offset;
    attribute->present = true;
    return FB_SCAN_OK;
}

static fb_scan_status
fb_parse_start_tag(
    fb_document *document,
    size_t attributes_start,
    fb_tag_attributes *attributes,
    size_t *tag_end,
    bool *self_closing,
    fb_document_issue *issue,
    size_t *issue_offset
)
{
    const fb_slice body = document->raw_body;
    size_t cursor = attributes_start;
    size_t attribute_count = 0u;

    memset(attributes, 0, sizeof(*attributes));
    *self_closing = false;
    while (cursor < body.len) {
        size_t name_start;
        size_t name_end;
        size_t value_start;
        size_t value_end;
        fb_slice name;
        fb_slice value;
        fb_scan_status capture_status;

        while (cursor < body.len &&
               fb_ascii_space((unsigned char)body.ptr[cursor])) {
            cursor++;
        }
        if (cursor >= body.len) {
            *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_TAG;
            *issue_offset = attributes_start;
            return FB_SCAN_MALFORMED;
        }
        if (body.ptr[cursor] == '>') {
            *tag_end = cursor + 1u;
            return FB_SCAN_OK;
        }
        if (body.ptr[cursor] == '/' && cursor + 1u < body.len &&
            body.ptr[cursor + 1u] == '>') {
            *self_closing = true;
            *tag_end = cursor + 2u;
            return FB_SCAN_OK;
        }

        name_start = cursor;
        while (cursor < body.len &&
               !fb_ascii_space((unsigned char)body.ptr[cursor]) &&
               body.ptr[cursor] != '=' && body.ptr[cursor] != '>' &&
               body.ptr[cursor] != '<') {
            if (body.ptr[cursor] == '/' && cursor + 1u < body.len &&
                body.ptr[cursor + 1u] == '>') {
                break;
            }
            if (body.ptr[cursor] == '\'' || body.ptr[cursor] == '"') {
                *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_ATTRIBUTE;
                *issue_offset = cursor;
                return FB_SCAN_MALFORMED;
            }
            cursor++;
        }
        name_end = cursor;
        if (name_end == name_start ||
            (cursor < body.len && body.ptr[cursor] == '<')) {
            *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_TAG;
            *issue_offset = cursor;
            return FB_SCAN_MALFORMED;
        }
        attribute_count++;
        if (attribute_count > document->limits.max_attributes_per_tag) {
            *issue = FB_DOCUMENT_ISSUE_TAG_ATTRIBUTE_LIMIT;
            *issue_offset = name_start;
            return FB_SCAN_LIMIT;
        }

        while (cursor < body.len &&
               fb_ascii_space((unsigned char)body.ptr[cursor])) {
            cursor++;
        }
        value_start = cursor;
        value_end = cursor;
        if (cursor < body.len && body.ptr[cursor] == '=') {
            cursor++;
            while (cursor < body.len &&
                   fb_ascii_space((unsigned char)body.ptr[cursor])) {
                cursor++;
            }
            if (cursor >= body.len) {
                *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_ATTRIBUTE;
                *issue_offset = name_start;
                return FB_SCAN_MALFORMED;
            }
            if (body.ptr[cursor] == '\'' || body.ptr[cursor] == '"') {
                char quote = body.ptr[cursor++];
                const char *closing;
                value_start = cursor;
                closing = fb_document_memchr(
                    document,
                    body.ptr + cursor,
                    (unsigned char)quote,
                    body.len - cursor
                );
                if (closing == NULL) {
                    *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_ATTRIBUTE;
                    *issue_offset = value_start;
                    return FB_SCAN_MALFORMED;
                }
                value_end = (size_t)(closing - body.ptr);
                cursor = value_end + 1u;
            } else {
                value_start = cursor;
                while (cursor < body.len &&
                       !fb_ascii_space((unsigned char)body.ptr[cursor]) &&
                       body.ptr[cursor] != '>') {
                    if (body.ptr[cursor] == '<' ||
                        body.ptr[cursor] == '\'' ||
                        body.ptr[cursor] == '"' ||
                        body.ptr[cursor] == '`') {
                        *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_ATTRIBUTE;
                        *issue_offset = cursor;
                        return FB_SCAN_MALFORMED;
                    }
                    cursor++;
                }
                value_end = cursor;
            }
        }
        name = fb_slice_make(body.ptr + name_start, name_end - name_start);
        value = fb_slice_make(body.ptr + value_start, value_end - value_start);
        capture_status = fb_capture_attribute(
            document,
            attributes,
            name,
            value,
            value_start
        );
        if (capture_status != FB_SCAN_OK) {
            return capture_status;
        }
    }
    *issue = FB_DOCUMENT_ISSUE_UNTERMINATED_TAG;
    *issue_offset = attributes_start;
    return FB_SCAN_MALFORMED;
}

static fb_slice
fb_slice_trim_ascii_space(fb_slice value)
{
    size_t start = 0u;
    size_t end = value.len;

    while (start < end &&
           fb_ascii_space((unsigned char)value.ptr[start])) {
        start++;
    }
    while (end > start &&
           fb_ascii_space((unsigned char)value.ptr[end - 1u])) {
        end--;
    }
    return fb_slice_make(value.ptr + start, end - start);
}

static bool
fb_rel_has_canonical(fb_slice rel)
{
    size_t cursor = 0u;

    while (cursor < rel.len) {
        size_t start;
        while (cursor < rel.len &&
               fb_ascii_space((unsigned char)rel.ptr[cursor])) {
            cursor++;
        }
        start = cursor;
        while (cursor < rel.len &&
               !fb_ascii_space((unsigned char)rel.ptr[cursor])) {
            cursor++;
        }
        if (cursor > start &&
            fb_slice_equal_literal_ascii_case(
                fb_slice_make(rel.ptr + start, cursor - start),
                "canonical")) {
            return true;
        }
    }
    return false;
}

static fb_document_status
fb_document_add_declared_url(
    fb_document *document,
    fb_declared_url_kind kind,
    const fb_attribute *attribute,
    fb_document_error *error
)
{
    fb_declared_url *url;

    if (attribute == NULL || !attribute->present ||
        attribute->decoded.len == 0u) {
        return FB_DOCUMENT_OK;
    }
    if (document->declared_urls.len >=
        document->limits.max_declared_urls) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_DECLARED_URL_LIMIT,
            attribute->source_offset,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    url = fb_chunk_vec_append(&document->declared_urls);
    if (url == NULL) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            attribute->source_offset,
            SIZE_MAX,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    url->kind = kind;
    url->value = attribute->decoded;
    url->raw_value = attribute->raw;
    url->source_offset = attribute->source_offset;
    if (kind == FB_DECLARED_URL_CANONICAL) {
        document->canonical_count++;
    } else {
        document->og_url_count++;
    }
    return FB_DOCUMENT_OK;
}

static fb_slice
fb_attribute_value_or_empty(const fb_attribute *attribute)
{
    return attribute != NULL && attribute->present
               ? attribute->decoded
               : FB_SLICE_LIT("");
}

static fb_document_status
fb_document_open_form(
    fb_document *document,
    const fb_tag_attributes *attributes,
    size_t source_offset,
    size_t *active_form,
    fb_document_error *error
)
{
    fb_form_record *record;

    if (document->forms.len >= document->limits.max_forms) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_FORM_LIMIT,
            source_offset,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    {
        size_t parent_form = *active_form;
        *active_form = document->forms.len;
        record = fb_chunk_vec_append(&document->forms);
        if (record == NULL) {
            *active_form = parent_form;
            return fb_error_set(
                error,
                FB_DOCUMENT_NO_MEMORY,
                FB_DOCUMENT_ISSUE_NONE,
                source_offset,
                SIZE_MAX,
                YYJSON_READ_ERROR_MEMORY_ALLOCATION,
                0u
            );
        }
        record->parent_form = parent_form;
    }
    record->form.action = fb_attribute_value_or_empty(&attributes->action);
    record->form.method = fb_attribute_value_or_empty(&attributes->method);
    record->form.id = fb_attribute_value_or_empty(&attributes->id);
    record->form.name = fb_attribute_value_or_empty(&attributes->name);
    record->form.source_offset = source_offset;
    record->form.control_count = 0u;
    record->control_first = document->controls.len;
    return FB_DOCUMENT_OK;
}

static void
fb_document_close_form(fb_document *document, size_t *active_form)
{
    fb_form_record *record;

    if (document == NULL || active_form == NULL ||
        *active_form == SIZE_MAX) {
        return;
    }
    record = fb_chunk_vec_at(&document->forms, *active_form);
    if (record != NULL && record->control_first <= document->controls.len) {
        record->form.control_count =
            document->controls.len - record->control_first;
    }
    *active_form = record != NULL ? record->parent_form : SIZE_MAX;
}

static fb_document_status
fb_document_add_form_control(
    fb_document *document,
    const fb_tag_attributes *attributes,
    size_t source_offset,
    size_t active_form,
    fb_document_error *error
)
{
    fb_html_form_control *control;
    const fb_form_record *form;

    if (active_form == SIZE_MAX) {
        return FB_DOCUMENT_OK;
    }
    if (document->controls.len >= document->limits.max_form_controls) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_FORM_CONTROL_LIMIT,
            source_offset,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    form = fb_chunk_vec_at(&document->forms, active_form);
    if (form == NULL || form->control_first > document->controls.len) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_INTERNAL_INDEX_LIMIT,
            source_offset,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    control = fb_chunk_vec_append(&document->controls);
    if (control == NULL) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            source_offset,
            SIZE_MAX,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    control->name = fb_attribute_value_or_empty(&attributes->name);
    control->type = fb_attribute_value_or_empty(&attributes->type);
    control->id = fb_attribute_value_or_empty(&attributes->id);
    control->source_offset = source_offset;
    return FB_DOCUMENT_OK;
}

static bool
fb_find_sequence(
    fb_document *document,
    fb_slice body,
    size_t start,
    const char *sequence,
    size_t sequence_length,
    size_t *position
)
{
    size_t cursor = start;

    if (sequence_length == 0u || start > body.len) {
        return false;
    }
    while (cursor < body.len) {
        const char *candidate = fb_document_memchr(
            document,
            body.ptr + cursor,
            (unsigned char)sequence[0],
            body.len - cursor
        );
        size_t offset;
        if (candidate == NULL) {
            return false;
        }
        offset = (size_t)(candidate - body.ptr);
        if (sequence_length <= body.len - offset &&
            memcmp(candidate, sequence, sequence_length) == 0) {
            *position = offset;
            return true;
        }
        cursor = offset + 1u;
    }
    return false;
}

static bool
fb_find_tag_end(
    fb_document *document,
    fb_slice body,
    size_t start,
    size_t *end
)
{
    size_t cursor = start;
    char quote = '\0';

    while (cursor < body.len) {
        if (quote != '\0') {
            const char *closing = fb_document_memchr(
                document,
                body.ptr + cursor,
                (unsigned char)quote,
                body.len - cursor
            );
            if (closing == NULL) {
                return false;
            }
            cursor = (size_t)(closing - body.ptr) + 1u;
            quote = '\0';
            continue;
        }

        size_t scan_length = body.len - cursor;
        if (fb_document_poll_cancel(document)) {
            return false;
        }
        if (scan_length > FB_CANCEL_BYTE_INTERVAL) {
            scan_length = FB_CANCEL_BYTE_INTERVAL;
        }
        const char *event = fb_tag_event_scan(
            body.ptr + cursor,
            scan_length
        );
        if (event == NULL) {
            cursor += scan_length;
            continue;
        }
        cursor = (size_t)(event - body.ptr) + 1u;
        if (*event == '>') {
            *end = cursor;
            return true;
        }
        quote = *event;
    }
    return false;
}

static bool
fb_find_raw_text_end(
    fb_document *document,
    fb_slice body,
    size_t content_start,
    fb_slice tag_name,
    size_t *content_end,
    size_t *after_end_tag
)
{
    size_t cursor = content_start;

    while (cursor < body.len) {
        const char *less = fb_document_memchr(
            document, body.ptr + cursor, (unsigned char)'<',
            body.len - cursor);
        size_t offset;
        size_t name_start;
        size_t name_end;
        size_t end;
        if (less == NULL) {
            return false;
        }
        offset = (size_t)(less - body.ptr);
        if (body.len - offset < 2u || body.ptr[offset + 1u] != '/') {
            cursor = offset + 1u;
            continue;
        }
        name_start = offset + 2u;
        if (tag_name.len > body.len - name_start ||
            !fb_slice_equal_ascii_case(
                fb_slice_make(body.ptr + name_start, tag_name.len),
                tag_name)) {
            cursor = offset + 1u;
            continue;
        }
        name_end = name_start + tag_name.len;
        if (name_end < body.len && body.ptr[name_end] != '>' &&
            body.ptr[name_end] != '/' &&
            !fb_ascii_space((unsigned char)body.ptr[name_end])) {
            cursor = offset + 1u;
            continue;
        }
        if (!fb_find_tag_end(document, body, name_end, &end)) {
            return false;
        }
        *content_end = offset;
        *after_end_tag = end;
        return true;
    }
    return false;
}

static bool
fb_raw_start_tag_is_self_closing(
    fb_document *document,
    fb_slice body,
    size_t attributes_start,
    size_t tag_end
)
{
    size_t cursor = attributes_start;
    size_t end;

    if (tag_end == 0u || tag_end > body.len ||
        body.ptr[tag_end - 1u] != '>') {
        return false;
    }
    end = tag_end - 1u;
    while (cursor < end) {
        size_t before;

        while (cursor < end &&
               fb_ascii_space((unsigned char)body.ptr[cursor])) {
            cursor++;
        }
        if (cursor >= end) {
            return false;
        }
        if (body.ptr[cursor] == '/' && cursor + 1u == end) {
            return true;
        }

        before = cursor;
        while (cursor < end &&
               !fb_ascii_space((unsigned char)body.ptr[cursor]) &&
               body.ptr[cursor] != '=' && body.ptr[cursor] != '/' &&
               body.ptr[cursor] != '<') {
            cursor++;
        }
        if (cursor < end && body.ptr[cursor] == '/' &&
            cursor + 1u == end) {
            return true;
        }
        while (cursor < end &&
               fb_ascii_space((unsigned char)body.ptr[cursor])) {
            cursor++;
        }
        if (cursor < end && body.ptr[cursor] == '=') {
            cursor++;
            while (cursor < end &&
                   fb_ascii_space((unsigned char)body.ptr[cursor])) {
                cursor++;
            }
            if (cursor < end &&
                (body.ptr[cursor] == '\'' || body.ptr[cursor] == '"')) {
                char quote = body.ptr[cursor++];
                const char *closing = fb_document_memchr(
                    document,
                    body.ptr + cursor,
                    (unsigned char)quote,
                    end - cursor
                );
                if (closing == NULL) {
                    return false;
                }
                cursor = (size_t)(closing - body.ptr) + 1u;
            } else {
                while (cursor < end &&
                       !fb_ascii_space((unsigned char)body.ptr[cursor])) {
                    cursor++;
                }
            }
        } else if (cursor == before) {
            cursor++;
        }
    }
    return false;
}

typedef enum {
    FB_TAG_OTHER = 0,
    FB_TAG_LINK,
    FB_TAG_META,
    FB_TAG_FORM,
    FB_TAG_INPUT,
    FB_TAG_SCRIPT,
    FB_TAG_RAW_OTHER,
    FB_TAG_PLAINTEXT
} fb_relevant_tag;

static fb_relevant_tag
fb_relevant_tag_kind_scalar(fb_slice tag_name)
{
    if (fb_slice_equal_literal_ascii_case(tag_name, "link")) {
        return FB_TAG_LINK;
    }
    if (fb_slice_equal_literal_ascii_case(tag_name, "meta")) {
        return FB_TAG_META;
    }
    if (fb_slice_equal_literal_ascii_case(tag_name, "form")) {
        return FB_TAG_FORM;
    }
    if (fb_slice_equal_literal_ascii_case(tag_name, "input")) {
        return FB_TAG_INPUT;
    }
    if (fb_slice_equal_literal_ascii_case(tag_name, "script")) {
        return FB_TAG_SCRIPT;
    }
    if (fb_slice_equal_literal_ascii_case(tag_name, "style") ||
        fb_slice_equal_literal_ascii_case(tag_name, "title") ||
        fb_slice_equal_literal_ascii_case(tag_name, "textarea") ||
        fb_slice_equal_literal_ascii_case(tag_name, "xmp") ||
        fb_slice_equal_literal_ascii_case(tag_name, "iframe") ||
        fb_slice_equal_literal_ascii_case(tag_name, "noembed") ||
        fb_slice_equal_literal_ascii_case(tag_name, "noframes")) {
        return FB_TAG_RAW_OTHER;
    }
    if (fb_slice_equal_literal_ascii_case(tag_name, "plaintext")) {
        return FB_TAG_PLAINTEXT;
    }
    return FB_TAG_OTHER;
}

#if CHAR_BIT == 8 && defined(__BYTE_ORDER__) && \
    (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
     __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define FB_DOCUMENT_HAVE_NATIVE_PACKED_ASCII 1
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define FB_ASCII_PACK2(a, b) \
    ((uint16_t)(unsigned char)(a) | \
     ((uint16_t)(unsigned char)(b) << 8u))
#define FB_ASCII_PACK4(a, b, c, d) \
    ((uint32_t)FB_ASCII_PACK2((a), (b)) | \
     ((uint32_t)FB_ASCII_PACK2((c), (d)) << 16u))
#define FB_ASCII_PACK8(a, b, c, d, e, f, g, h) \
    ((uint64_t)FB_ASCII_PACK4((a), (b), (c), (d)) | \
     ((uint64_t)FB_ASCII_PACK4((e), (f), (g), (h)) << 32u))
#else
#define FB_ASCII_PACK2(a, b) \
    (((uint16_t)(unsigned char)(a) << 8u) | \
     (uint16_t)(unsigned char)(b))
#define FB_ASCII_PACK4(a, b, c, d) \
    (((uint32_t)FB_ASCII_PACK2((a), (b)) << 16u) | \
     (uint32_t)FB_ASCII_PACK2((c), (d)))
#define FB_ASCII_PACK8(a, b, c, d, e, f, g, h) \
    (((uint64_t)FB_ASCII_PACK4((a), (b), (c), (d)) << 32u) | \
     (uint64_t)FB_ASCII_PACK4((e), (f), (g), (h)))
#endif
#else
#define FB_DOCUMENT_HAVE_NATIVE_PACKED_ASCII 0
#endif

static fb_relevant_tag
fb_relevant_tag_kind(fb_slice tag_name)
{
#if FB_DOCUMENT_HAVE_NATIVE_PACKED_ASCII
    if (!fb_slice_is_valid(tag_name)) {
        return fb_relevant_tag_kind_scalar(tag_name);
    }
    switch (tag_name.len) {
    case 3u: {
        uint16_t prefix;
        unsigned char last = fb_ascii_lower(
            (unsigned char)tag_name.ptr[2]
        );
        memcpy(&prefix, tag_name.ptr, sizeof(prefix));
        prefix |= UINT16_C(0x2020);
        return prefix == FB_ASCII_PACK2('x', 'm') && last == 'p'
                   ? FB_TAG_RAW_OTHER
                   : FB_TAG_OTHER;
    }
    case 4u: {
        uint32_t word;
        memcpy(&word, tag_name.ptr, sizeof(word));
        word |= UINT32_C(0x20202020);
        if (word == FB_ASCII_PACK4('l', 'i', 'n', 'k')) {
            return FB_TAG_LINK;
        }
        if (word == FB_ASCII_PACK4('m', 'e', 't', 'a')) {
            return FB_TAG_META;
        }
        if (word == FB_ASCII_PACK4('f', 'o', 'r', 'm')) {
            return FB_TAG_FORM;
        }
        return FB_TAG_OTHER;
    }
    case 5u: {
        uint32_t word;
        unsigned char last = fb_ascii_lower(
            (unsigned char)tag_name.ptr[4]
        );
        memcpy(&word, tag_name.ptr, sizeof(word));
        word |= UINT32_C(0x20202020);
        if (word == FB_ASCII_PACK4('i', 'n', 'p', 'u') && last == 't') {
            return FB_TAG_INPUT;
        }
        if ((word == FB_ASCII_PACK4('s', 't', 'y', 'l') && last == 'e') ||
            (word == FB_ASCII_PACK4('t', 'i', 't', 'l') && last == 'e')) {
            return FB_TAG_RAW_OTHER;
        }
        return FB_TAG_OTHER;
    }
    case 6u: {
        uint32_t prefix;
        uint16_t suffix;
        memcpy(&prefix, tag_name.ptr, sizeof(prefix));
        memcpy(&suffix, tag_name.ptr + sizeof(prefix), sizeof(suffix));
        prefix |= UINT32_C(0x20202020);
        suffix |= UINT16_C(0x2020);
        if (prefix == FB_ASCII_PACK4('s', 'c', 'r', 'i') &&
            suffix == FB_ASCII_PACK2('p', 't')) {
            return FB_TAG_SCRIPT;
        }
        if (prefix == FB_ASCII_PACK4('i', 'f', 'r', 'a') &&
            suffix == FB_ASCII_PACK2('m', 'e')) {
            return FB_TAG_RAW_OTHER;
        }
        return FB_TAG_OTHER;
    }
    case 7u: {
        uint32_t prefix;
        uint16_t middle;
        unsigned char last = fb_ascii_lower(
            (unsigned char)tag_name.ptr[6]
        );
        memcpy(&prefix, tag_name.ptr, sizeof(prefix));
        memcpy(&middle, tag_name.ptr + sizeof(prefix), sizeof(middle));
        prefix |= UINT32_C(0x20202020);
        middle |= UINT16_C(0x2020);
        return prefix == FB_ASCII_PACK4('n', 'o', 'e', 'm') &&
                       middle == FB_ASCII_PACK2('b', 'e') && last == 'd'
                   ? FB_TAG_RAW_OTHER
                   : FB_TAG_OTHER;
    }
    case 8u: {
        uint64_t word;
        memcpy(&word, tag_name.ptr, sizeof(word));
        word |= UINT64_C(0x2020202020202020);
        if (word == FB_ASCII_PACK8(
                        't', 'e', 'x', 't', 'a', 'r', 'e', 'a') ||
            word == FB_ASCII_PACK8(
                        'n', 'o', 'f', 'r', 'a', 'm', 'e', 's')) {
            return FB_TAG_RAW_OTHER;
        }
        return FB_TAG_OTHER;
    }
    case 9u: {
        uint64_t prefix;
        unsigned char last = fb_ascii_lower(
            (unsigned char)tag_name.ptr[8]
        );
        memcpy(&prefix, tag_name.ptr, sizeof(prefix));
        prefix |= UINT64_C(0x2020202020202020);
        return prefix == FB_ASCII_PACK8(
                             'p', 'l', 'a', 'i', 'n', 't', 'e', 'x') &&
                       last == 't'
                   ? FB_TAG_PLAINTEXT
                   : FB_TAG_OTHER;
    }
    default:
        return FB_TAG_OTHER;
    }
#else
    return fb_relevant_tag_kind_scalar(tag_name);
#endif
}

#if FB_DOCUMENT_HAVE_NATIVE_PACKED_ASCII
#undef FB_ASCII_PACK8
#undef FB_ASCII_PACK4
#undef FB_ASCII_PACK2
#endif

static void
fb_document_detect_login_form(fb_document *document)
{
    static const fb_slice login_name[] = {
        {.ptr = "login", .len = sizeof("login") - 1u}
    };

    for (size_t form_index = 0u;
         form_index < document->forms.len;
         ++form_index) {
        const fb_form_record *record =
            fb_chunk_vec_at(&document->forms, form_index);
        bool has_password_type = false;
        bool has_login_name = false;
        if (record == NULL ||
            !fb_url_is_control_path(
                record->form.action,
                login_name,
                FB_ARRAY_LEN(login_name))) {
            continue;
        }
        for (size_t index = 0u;
             index < record->form.control_count;
             ++index) {
            if ((index & (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                fb_document_poll_cancel(document)) {
                return;
            }
            const fb_html_form_control *control = fb_chunk_vec_at(
                &document->controls,
                record->control_first + index
            );
            if (control == NULL) {
                continue;
            }
            if (fb_slice_equal_literal_ascii_case(control->type, "password")) {
                has_password_type = true;
            }
            if (fb_slice_equal_literal_ascii_case(control->name, "email") ||
                fb_slice_equal_literal_ascii_case(control->name, "pass") ||
                fb_slice_equal_literal_ascii_case(control->name, "password")) {
                has_login_name = true;
            }
        }
        if (has_password_type && has_login_name) {
            document->has_login_form = true;
            return;
        }
    }
}

static fb_document_status
fb_document_scan_html(
    fb_document *document,
    fb_block_builder *builder,
    fb_document_error *error
)
{
    const fb_slice body = document->raw_body;
    size_t cursor = 0u;
    size_t active_form = SIZE_MAX;

    while (cursor < body.len) {
        const char *less = fb_document_memchr(
            document, body.ptr + cursor, (unsigned char)'<',
            body.len - cursor);
        size_t tag_start;
        size_t name_start;
        size_t name_end;
        fb_slice tag_name;
        fb_relevant_tag tag_kind;
        if (document->cancelled) {
            return fb_cancel_error(document, error, cursor, SIZE_MAX);
        }
        if (less == NULL) {
            break;
        }
        tag_start = (size_t)(less - body.ptr);
        cursor = tag_start + 1u;
        if (cursor >= body.len) {
            break;
        }

        if (body.ptr[cursor] == '!' &&
            body.len - tag_start >= 4u &&
            memcmp(body.ptr + tag_start, "<!--", 4u) == 0) {
            size_t comment_end;
            if (!fb_find_sequence(document, body, tag_start + 4u, "-->", 3u,
                                  &comment_end)) {
                if (document->cancelled) {
                    return fb_cancel_error(
                        document, error, tag_start, SIZE_MAX);
                }
                return fb_error_set(
                    error,
                    FB_DOCUMENT_MALFORMED_HTML,
                    FB_DOCUMENT_ISSUE_UNTERMINATED_COMMENT,
                    tag_start,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }
            cursor = comment_end + 3u;
            continue;
        }
        if (body.ptr[cursor] == '!' || body.ptr[cursor] == '?') {
            size_t end;
            if (!fb_find_tag_end(document, body, cursor + 1u, &end)) {
                if (document->cancelled) {
                    return fb_cancel_error(
                        document, error, tag_start, SIZE_MAX);
                }
                return fb_error_set(
                    error,
                    FB_DOCUMENT_MALFORMED_HTML,
                    FB_DOCUMENT_ISSUE_UNTERMINATED_TAG,
                    tag_start,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }
            cursor = end;
            continue;
        }
        if (body.ptr[cursor] == '/') {
            size_t end;
            cursor++;
            name_start = cursor;
            while (cursor < body.len &&
                   !fb_ascii_space((unsigned char)body.ptr[cursor]) &&
                   body.ptr[cursor] != '>') {
                cursor++;
            }
            name_end = cursor;
            if (!fb_find_tag_end(document, body, cursor, &end)) {
                if (document->cancelled) {
                    return fb_cancel_error(
                        document, error, tag_start, SIZE_MAX);
                }
                return fb_error_set(
                    error,
                    FB_DOCUMENT_MALFORMED_HTML,
                    FB_DOCUMENT_ISSUE_UNTERMINATED_TAG,
                    tag_start,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }
            if (name_end > name_start &&
                fb_slice_equal_literal_ascii_case(
                    fb_slice_make(body.ptr + name_start,
                                  name_end - name_start),
                    "form")) {
                fb_document_close_form(document, &active_form);
            }
            cursor = end;
            continue;
        }
        if (!fb_is_ascii_alpha((unsigned char)body.ptr[cursor])) {
            continue;
        }

        name_start = cursor;
        while (cursor < body.len &&
               !fb_ascii_space((unsigned char)body.ptr[cursor]) &&
               body.ptr[cursor] != '/' && body.ptr[cursor] != '>' &&
               body.ptr[cursor] != '<') {
            cursor++;
        }
        name_end = cursor;
        tag_name = fb_slice_make(body.ptr + name_start, name_end - name_start);
        tag_kind = fb_relevant_tag_kind(tag_name);
        if (tag_kind == FB_TAG_OTHER) {
            size_t tag_end;
            if (!fb_find_tag_end(document, body, cursor, &tag_end)) {
                if (document->cancelled) {
                    return fb_cancel_error(
                        document, error, tag_start, SIZE_MAX);
                }
                return fb_error_set(
                    error,
                    FB_DOCUMENT_MALFORMED_HTML,
                    FB_DOCUMENT_ISSUE_UNTERMINATED_TAG,
                    tag_start,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }
            cursor = tag_end;
            continue;
        }
        if (tag_kind == FB_TAG_RAW_OTHER ||
            tag_kind == FB_TAG_PLAINTEXT) {
            size_t tag_end;
            size_t content_end;
            size_t after_end_tag;
            if (!fb_find_tag_end(document, body, cursor, &tag_end)) {
                if (document->cancelled) {
                    return fb_cancel_error(
                        document, error, tag_start, SIZE_MAX);
                }
                return fb_error_set(
                    error,
                    FB_DOCUMENT_MALFORMED_HTML,
                    FB_DOCUMENT_ISSUE_UNTERMINATED_TAG,
                    tag_start,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }
            if (fb_raw_start_tag_is_self_closing(
                    document, body, cursor, tag_end)) {
                cursor = tag_end;
                continue;
            }
            if (tag_kind == FB_TAG_PLAINTEXT) {
                cursor = body.len;
                continue;
            }
            if (!fb_find_raw_text_end(document, body, tag_end, tag_name,
                                      &content_end, &after_end_tag)) {
                if (document->cancelled) {
                    return fb_cancel_error(
                        document, error, tag_start, SIZE_MAX);
                }
                cursor = body.len;
                continue;
            }
            cursor = after_end_tag;
            continue;
        }
        {
            fb_tag_attributes attributes;
            size_t tag_end = 0u;
            size_t issue_offset = tag_start;
            fb_document_issue issue = FB_DOCUMENT_ISSUE_NONE;
            bool self_closing = false;
            fb_scan_status scan_status = fb_parse_start_tag(
                document,
                cursor,
                &attributes,
                &tag_end,
                &self_closing,
                &issue,
                &issue_offset
            );
            fb_document_status status;
            if (scan_status == FB_SCAN_CANCELLED || document->cancelled) {
                return fb_cancel_error(
                    document, error, issue_offset, SIZE_MAX);
            }
            if (scan_status == FB_SCAN_NO_MEMORY) {
                return fb_error_set(
                    error,
                    FB_DOCUMENT_NO_MEMORY,
                    FB_DOCUMENT_ISSUE_NONE,
                    issue_offset,
                    SIZE_MAX,
                    YYJSON_READ_ERROR_MEMORY_ALLOCATION,
                    0u
                );
            }
            if (scan_status == FB_SCAN_MALFORMED) {
                return fb_error_set(
                    error,
                    FB_DOCUMENT_MALFORMED_HTML,
                    issue,
                    issue_offset,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }
            if (scan_status == FB_SCAN_LIMIT) {
                return fb_error_set(
                    error,
                    FB_DOCUMENT_LIMIT_EXCEEDED,
                    issue,
                    issue_offset,
                    SIZE_MAX,
                    YYJSON_READ_SUCCESS,
                    0u
                );
            }

            if (tag_kind == FB_TAG_LINK &&
                attributes.rel.present &&
                fb_rel_has_canonical(attributes.rel.decoded)) {
                status = fb_document_add_declared_url(
                    document,
                    FB_DECLARED_URL_CANONICAL,
                    &attributes.href,
                    error
                );
                if (status != FB_DOCUMENT_OK) {
                    return status;
                }
            } else if (tag_kind == FB_TAG_META &&
                       attributes.property.present &&
                       fb_slice_equal_literal_ascii_case(
                           fb_slice_trim_ascii_space(
                               attributes.property.decoded),
                           "og:url")) {
                status = fb_document_add_declared_url(
                    document,
                    FB_DECLARED_URL_OG_URL,
                    &attributes.content,
                    error
                );
                if (status != FB_DOCUMENT_OK) {
                    return status;
                }
            }

            if (tag_kind == FB_TAG_FORM) {
                status = fb_document_open_form(
                    document,
                    &attributes,
                    tag_start,
                    &active_form,
                    error
                );
                if (status != FB_DOCUMENT_OK) {
                    return status;
                }
                if (self_closing) {
                    fb_document_close_form(document, &active_form);
                }
            } else if (tag_kind == FB_TAG_INPUT) {
                status = fb_document_add_form_control(
                    document,
                    &attributes,
                    tag_start,
                    active_form,
                    error
                );
                if (status != FB_DOCUMENT_OK) {
                    return status;
                }
            }

            if (tag_kind == FB_TAG_SCRIPT) {
                size_t content_end = tag_end;
                size_t after_end_tag = tag_end;
                if (!self_closing &&
                    !fb_find_raw_text_end(
                        document, body, tag_end, tag_name,
                        &content_end, &after_end_tag)) {
                    if (document->cancelled) {
                        return fb_cancel_error(
                            document, error, tag_start, SIZE_MAX);
                    }
                    content_end = body.len;
                    after_end_tag = body.len;
                }
                if (attributes.type.present &&
                    fb_slice_equal_literal_ascii_case(
                        fb_slice_trim_ascii_space(attributes.type.decoded),
                        "application/json")) {
                    status = fb_document_add_json_script(
                        document,
                        builder,
                        fb_slice_make(
                            body.ptr + tag_end,
                            content_end - tag_end
                        ),
                        tag_end,
                        error
                    );
                    if (status != FB_DOCUMENT_OK) {
                        return status;
                    }
                }
                cursor = after_end_tag;
            } else {
                cursor = tag_end;
            }
        }
    }
    while (active_form != SIZE_MAX) {
        if (fb_document_poll_cancel(document)) {
            return fb_cancel_error(document, error, cursor, SIZE_MAX);
        }
        fb_document_close_form(document, &active_form);
    }
    fb_document_detect_login_form(document);
    if (document->cancelled) {
        return fb_cancel_error(document, error, cursor, SIZE_MAX);
    }
    return FB_DOCUMENT_OK;
}

fb_document_status
fb_document_parse_cancelable(
    fb_arena *arena,
    fb_slice raw_body,
    const fb_document_limits *limits,
    const fb_cancel_token *cancel,
    fb_document **out,
    fb_document_error *error
)
{
    fb_document_limits selected_limits;
    fb_document *document;
    fb_document_status status;
    fb_block_builder builder = {0};

    fb_error_clear(error);
    if (out != NULL) {
        *out = NULL;
    }
    if (arena == NULL || out == NULL || !fb_slice_is_valid(raw_body)) {
        return fb_error_set(
            error,
            FB_DOCUMENT_INVALID_ARGUMENT,
            FB_DOCUMENT_ISSUE_NONE,
            0u,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    if (fb_cancel_requested(cancel)) {
        return fb_error_set(
            error,
            FB_DOCUMENT_CANCELLED,
            FB_DOCUMENT_ISSUE_NONE,
            0u,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }
    fb_document_initialize_scanners();
    if (limits == NULL) {
        fb_document_limits_default(&selected_limits);
    } else {
        selected_limits = *limits;
    }
    if (raw_body.len > selected_limits.max_body_bytes) {
        return fb_error_set(
            error,
            FB_DOCUMENT_LIMIT_EXCEEDED,
            FB_DOCUMENT_ISSUE_BODY_LIMIT,
            selected_limits.max_body_bytes,
            SIZE_MAX,
            YYJSON_READ_SUCCESS,
            0u
        );
    }

    document = fb_arena_alloc(arena, sizeof(*document), _Alignof(fb_document));
    if (document == NULL) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            0u,
            SIZE_MAX,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    memset(document, 0, sizeof(*document));
    document->arena = arena;
    document->cancel = cancel;
    document->raw_body = raw_body;
    document->limits = selected_limits;
    document->hash_seed = fb_hash_mix(
        (uint64_t)(uintptr_t)(const void *)document ^
        (uint64_t)(uintptr_t)(const void *)raw_body.ptr ^
        (uint64_t)raw_body.len ^ UINT64_C(0x6a09e667f3bcc909)
    );

    if (!fb_chunk_vec_init(
            &document->scripts,
            arena,
            selected_limits.max_scripts,
            sizeof(fb_json_script),
            _Alignof(fb_json_script)) ||
        !fb_chunk_vec_init(
            &document->blocks,
            arena,
            selected_limits.max_scripts,
            sizeof(fb_json_block),
            _Alignof(fb_json_block)) ||
        !fb_chunk_vec_init(
            &document->declared_urls,
            arena,
            selected_limits.max_declared_urls,
            sizeof(fb_declared_url),
            _Alignof(fb_declared_url)) ||
        !fb_chunk_vec_init(
            &document->forms,
            arena,
            selected_limits.max_forms,
            sizeof(fb_form_record),
            _Alignof(fb_form_record)) ||
        !fb_chunk_vec_init(
            &document->controls,
            arena,
            selected_limits.max_form_controls,
            sizeof(fb_html_form_control),
            _Alignof(fb_html_form_control)) ||
        !fb_chunk_vec_init(
            &document->initial_routes,
            arena,
            selected_limits.max_total_json_values,
            sizeof(fb_json_node_ref),
            _Alignof(fb_json_node_ref)) ||
        !fb_chunk_vec_init(
            &document->comment_candidates,
            arena,
            selected_limits.max_total_json_values,
            sizeof(fb_json_node_ref),
            _Alignof(fb_json_node_ref)) ||
        !fb_chunk_vec_init(
            &document->video_candidates,
            arena,
            selected_limits.max_total_json_values,
            sizeof(fb_json_node_ref),
            _Alignof(fb_json_node_ref))) {
        return fb_error_set(
            error,
            FB_DOCUMENT_NO_MEMORY,
            FB_DOCUMENT_ISSUE_NONE,
            0u,
            SIZE_MAX,
            YYJSON_READ_ERROR_MEMORY_ALLOCATION,
            0u
        );
    }
    document->traversal_stack_limit = selected_limits.max_depth;

    status = fb_document_scan_html(document, &builder, error);
    fb_block_builder_destroy(&builder);
    if (status != FB_DOCUMENT_OK) {
        return status;
    }
    *out = document;
    return FB_DOCUMENT_OK;
}

fb_document_status
fb_document_parse(
    fb_arena *arena,
    fb_slice raw_body,
    const fb_document_limits *limits,
    fb_document **out,
    fb_document_error *error
)
{
    return fb_document_parse_cancelable(
        arena, raw_body, limits, NULL, out, error);
}

fb_slice
fb_document_raw_body(const fb_document *document)
{
    return document != NULL
               ? document->raw_body
               : fb_slice_make(NULL, 0u);
}

size_t
fb_document_script_count(const fb_document *document)
{
    return document != NULL ? document->scripts.len : 0u;
}

const fb_json_script *
fb_document_script_at(const fb_document *document, size_t index)
{
    return document != NULL
               ? fb_chunk_vec_at(&document->scripts, index)
               : NULL;
}

size_t
fb_document_json_block_count(const fb_document *document)
{
    return document != NULL ? document->blocks.len : 0u;
}

const fb_json_block *
fb_document_json_block_at(const fb_document *document, size_t index)
{
    return document != NULL
               ? fb_chunk_vec_at(&document->blocks, index)
               : NULL;
}

size_t
fb_document_invalid_json_count(const fb_document *document)
{
    return document != NULL ? document->invalid_json_count : 0u;
}

size_t
fb_document_declared_url_count(
    const fb_document *document,
    fb_declared_url_kind kind
)
{
    if (document == NULL) {
        return 0u;
    }
    if (kind == FB_DECLARED_URL_CANONICAL) {
        return document->canonical_count;
    }
    if (kind == FB_DECLARED_URL_OG_URL) {
        return document->og_url_count;
    }
    return 0u;
}

const fb_declared_url *
fb_document_declared_url_at(
    const fb_document *document,
    fb_declared_url_kind kind,
    size_t index
)
{
    size_t found = 0u;

    if (document == NULL ||
        (kind != FB_DECLARED_URL_CANONICAL &&
         kind != FB_DECLARED_URL_OG_URL)) {
        return NULL;
    }
    for (size_t position = 0u;
         position < document->declared_urls.len;
         ++position) {
        const fb_declared_url *url =
            fb_chunk_vec_at(&document->declared_urls, position);
        if (url != NULL && url->kind == kind) {
            if (found == index) {
                return url;
            }
            found++;
        }
    }
    return NULL;
}

size_t
fb_document_form_count(const fb_document *document)
{
    return document != NULL ? document->forms.len : 0u;
}

const fb_html_form *
fb_document_form_at(const fb_document *document, size_t index)
{
    const fb_form_record *record = document != NULL
                                       ? fb_chunk_vec_at(
                                             &document->forms,
                                             index)
                                       : NULL;
    return record != NULL ? &record->form : NULL;
}

const fb_html_form_control *
fb_document_form_control_at(
    const fb_document *document,
    size_t form_index,
    size_t control_index
)
{
    const fb_form_record *record;

    if (document == NULL) {
        return NULL;
    }
    record = fb_chunk_vec_at(&document->forms, form_index);
    if (record == NULL || control_index >= record->form.control_count) {
        return NULL;
    }
    return fb_chunk_vec_at(
        &document->controls,
        record->control_first + control_index
    );
}

bool
fb_document_has_login_form(const fb_document *document)
{
    return document != NULL && document->has_login_form;
}

const yyjson_val *
fb_json_block_root(const fb_json_block *block)
{
    return block != NULL ? block->root : NULL;
}

size_t
fb_json_block_index(const fb_json_block *block)
{
    return block != NULL ? block->index : SIZE_MAX;
}

size_t
fb_json_block_value_count(const fb_json_block *block)
{
    return block != NULL ? block->value_count : 0u;
}

size_t
fb_json_block_object_count(const fb_json_block *block)
{
    return block != NULL ? block->object_count : 0u;
}

const yyjson_val *
fb_json_block_object_at(const fb_json_block *block, size_t traversal_rank)
{
    const fb_object_node *node = block != NULL
                                     ? fb_block_object_node_at(
                                           block,
                                           traversal_rank)
                                     : NULL;
    return node != NULL
               ? fb_block_value_at_ref(block, node->value_ref)
               : NULL;
}

bool
fb_json_block_traversal_rank(
    const fb_json_block *block,
    const yyjson_val *object,
    size_t *rank
)
{
    if (block == NULL || object == NULL || rank == NULL ||
        !yyjson_is_obj(object)) {
        return false;
    }
    for (size_t index = 0u; index < block->object_count; ++index) {
        const fb_object_node *node = fb_block_object_node_at(block, index);
        if (node != NULL &&
            fb_block_value_at_ref(block, node->value_ref) == object) {
            *rank = index;
            return true;
        }
    }
    return false;
}

static size_t
fb_size_accumulate_saturating(size_t total, size_t value);

static bool
fb_block_fill_compact_match(
    const fb_json_block *block,
    uint32_t object_rank,
    const yyjson_val *value,
    fb_slice key,
    size_t pair_index,
    bool effective,
    fb_json_match *out
)
{
    const fb_object_node *object;

    if (block == NULL || value == NULL || out == NULL ||
        (size_t)object_rank >= block->object_count) {
        return false;
    }
    object = fb_block_object_node_at(block, (size_t)object_rank);
    if (object == NULL) {
        return false;
    }
    out->object = fb_block_value_at_ref(block, object->value_ref);
    if (out->object == NULL) {
        return false;
    }
    out->value = value;
    out->key = key;
    out->block_index = block->index;
    out->traversal_rank = (size_t)object_rank;
    out->pair_index = pair_index;
    out->effective = effective;
    return true;
}

static bool
fb_block_scan_object_last(
    const yyjson_val *object,
    fb_slice key,
    const yyjson_val **value_out,
    size_t *pair_out,
    fb_slice *first_key
)
{
    yyjson_obj_iter iterator;
    yyjson_val *key_value;
    size_t pair_index = 0u;
    bool found = false;

    if (!yyjson_is_obj(object) || !fb_slice_is_valid(key) ||
        value_out == NULL || pair_out == NULL) {
        return false;
    }
    iterator = yyjson_obj_iter_with(object);
    while ((key_value = yyjson_obj_iter_next(&iterator)) != NULL) {
        fb_slice candidate = fb_slice_make(
            yyjson_get_str(key_value), yyjson_get_len(key_value));
        if (fb_slice_equal(candidate, key)) {
            if (first_key != NULL && first_key->ptr == NULL) {
                *first_key = candidate;
            }
            *value_out = yyjson_obj_iter_get_val(key_value);
            *pair_out = pair_index;
            found = true;
        }
        pair_index++;
    }
    return found;
}

static bool
fb_block_find_first_source_key(
    const fb_json_block *block,
    fb_slice key,
    fb_slice *source_key
)
{
    if (block == NULL || source_key == NULL || !fb_slice_is_valid(key)) {
        return false;
    }
    for (size_t rank = 0u; rank < block->object_count; ++rank) {
        const fb_object_node *node = fb_block_object_node_at(block, rank);
        const yyjson_val *object = node != NULL
                                       ? fb_block_value_at_ref(
                                             block, node->value_ref)
                                       : NULL;
        yyjson_obj_iter iterator;
        yyjson_val *key_value;
        if (!yyjson_is_obj(object)) {
            return false;
        }
        iterator = yyjson_obj_iter_with(object);
        while ((key_value = yyjson_obj_iter_next(&iterator)) != NULL) {
            fb_slice candidate = fb_slice_make(
                yyjson_get_str(key_value), yyjson_get_len(key_value));
            if (fb_slice_equal(candidate, key)) {
                *source_key = candidate;
                return true;
            }
        }
    }
    return false;
}

static const fb_hot_slot *
fb_block_hot_slot(const fb_json_block *block, fb_slice key)
{
    const int index = fb_hot_key_index(key);
    return block != NULL && index >= 0
               ? &block->hot[(size_t)index]
               : NULL;
}

static fb_slice
fb_block_hot_source_key(
    const fb_json_block *block,
    const fb_hot_slot *slot,
    fb_slice fallback
)
{
    const yyjson_val *key_value = slot != NULL
                                      ? fb_block_value_at_ref(
                                            block, slot->key_ref)
                                      : NULL;
    return yyjson_is_str(key_value)
               ? fb_slice_make(
                     yyjson_get_str(key_value), yyjson_get_len(key_value))
               : fallback;
}

size_t
fb_json_block_key_count(const fb_json_block *block, fb_slice key)
{
    const fb_hot_slot *hot;
    size_t count = 0u;

    if (block == NULL || !fb_slice_is_valid(key)) {
        return 0u;
    }
    hot = fb_block_hot_slot(block, key);
    if (hot != NULL) {
        return (size_t)hot->count;
    }
    for (size_t rank = 0u; rank < block->object_count; ++rank) {
        const fb_object_node *node = fb_block_object_node_at(block, rank);
        const yyjson_val *object = node != NULL
                                       ? fb_block_value_at_ref(
                                             block, node->value_ref)
                                       : NULL;
        const yyjson_val *value = NULL;
        size_t pair_index = 0u;
        if (fb_block_scan_object_last(
                object, key, &value, &pair_index, NULL)) {
            count = fb_size_accumulate_saturating(count, 1u);
        }
    }
    return count;
}

bool
fb_json_block_key_first(
    const fb_json_block *block,
    fb_slice key,
    fb_json_match *out
)
{
    return fb_json_block_key_at(block, key, 0u, out);
}

bool
fb_json_block_key_at(
    const fb_json_block *block,
    fb_slice key,
    size_t index,
    fb_json_match *out
)
{
    const fb_hot_slot *hot;
    fb_slice source_key = fb_slice_make(NULL, 0u);

    if (block == NULL || out == NULL || !fb_slice_is_valid(key)) {
        return false;
    }
    hot = fb_block_hot_slot(block, key);
    if (hot != NULL) {
        size_t posting_index;
        const fb_hot_posting *posting;
        if (index >= (size_t)hot->count ||
            !fb_size_add((size_t)hot->first, index, &posting_index) ||
            posting_index >= block->posting_count) {
            return false;
        }
        posting = &block->postings[posting_index];
        source_key = fb_block_hot_source_key(block, hot, key);
        return fb_block_fill_compact_match(
            block,
            posting->object_rank,
            fb_block_value_at_ref(block, posting->value_ref),
            source_key,
            (size_t)posting->pair_index,
            true,
            out
        );
    }
    for (size_t rank = 0u; rank < block->object_count; ++rank) {
        const fb_object_node *node = fb_block_object_node_at(block, rank);
        const yyjson_val *object = node != NULL
                                       ? fb_block_value_at_ref(
                                             block, node->value_ref)
                                       : NULL;
        const yyjson_val *value = NULL;
        size_t pair_index = 0u;
        if (fb_block_scan_object_last(
                object, key, &value, &pair_index, &source_key)) {
            if (index == 0u) {
                return fb_block_fill_compact_match(
                    block,
                    (uint32_t)rank,
                    value,
                    source_key,
                    pair_index,
                    true,
                    out
                );
            }
            index--;
        }
    }
    return false;
}

void
fb_json_block_match_cursor_init(
    fb_json_block_match_cursor *cursor,
    const fb_json_block *block,
    fb_slice key
)
{
    const fb_hot_slot *hot;

    if (cursor == NULL) {
        return;
    }
    memset(cursor, 0, sizeof(*cursor));
    cursor->block_state = block;
    cursor->key_state = key;
    cursor->next_occurrence_state = FB_INDEX_NONE;
    if (block == NULL || !fb_slice_is_valid(key)) {
        return;
    }
    hot = fb_block_hot_slot(block, key);
    if (hot != NULL) {
        if (hot->count != 0u &&
            (size_t)hot->first < block->posting_count) {
            cursor->entry_state = hot;
            cursor->key_state = fb_block_hot_source_key(block, hot, key);
            cursor->next_occurrence_state = hot->first;
        }
        return;
    }
    if (fb_block_find_first_source_key(block, key, &cursor->key_state)) {
        cursor->entry_state = block;
        cursor->next_occurrence_state = 0u;
    }
}

bool
fb_json_block_match_cursor_next(
    fb_json_block_match_cursor *cursor,
    fb_json_match *out
)
{
    const fb_json_block *block;

    if (cursor == NULL || out == NULL || cursor->block_state == NULL ||
        cursor->entry_state == NULL ||
        cursor->next_occurrence_state == FB_INDEX_NONE) {
        return false;
    }
    block = cursor->block_state;
    if (cursor->entry_state == block) {
        size_t rank = (size_t)cursor->next_occurrence_state;
        while (rank < block->object_count) {
            const fb_object_node *node = fb_block_object_node_at(block, rank);
            const yyjson_val *object = node != NULL
                                           ? fb_block_value_at_ref(
                                                 block, node->value_ref)
                                           : NULL;
            const yyjson_val *value = NULL;
            size_t pair_index = 0u;
            const size_t next_rank = rank + 1u;
            cursor->next_occurrence_state =
                next_rank < block->object_count
                    ? (uint32_t)next_rank
                    : FB_INDEX_NONE;
            if (fb_block_scan_object_last(
                    object,
                    cursor->key_state,
                    &value,
                    &pair_index,
                    NULL)) {
                return fb_block_fill_compact_match(
                    block,
                    (uint32_t)rank,
                    value,
                    cursor->key_state,
                    pair_index,
                    true,
                    out
                );
            }
            rank = next_rank;
        }
        cursor->next_occurrence_state = FB_INDEX_NONE;
        return false;
    }
    {
        const fb_hot_slot *hot = cursor->entry_state;
        const size_t posting_index = cursor->next_occurrence_state;
        size_t end;
        const fb_hot_posting *posting;
        if (!fb_size_add((size_t)hot->first, (size_t)hot->count, &end) ||
            posting_index >= end || posting_index >= block->posting_count) {
            cursor->next_occurrence_state = FB_INDEX_NONE;
            return false;
        }
        posting = &block->postings[posting_index];
        cursor->next_occurrence_state = posting_index + 1u < end
                                            ? (uint32_t)(posting_index + 1u)
                                            : FB_INDEX_NONE;
        return fb_block_fill_compact_match(
            block,
            posting->object_rank,
            fb_block_value_at_ref(block, posting->value_ref),
            cursor->key_state,
            (size_t)posting->pair_index,
            true,
            out
        );
    }
}

size_t
fb_json_block_key_occurrence_count(
    const fb_json_block *block,
    fb_slice key
)
{
    size_t count = 0u;

    if (block == NULL || !fb_slice_is_valid(key)) {
        return 0u;
    }
    for (size_t rank = 0u; rank < block->object_count; ++rank) {
        const fb_object_node *node = fb_block_object_node_at(block, rank);
        const yyjson_val *object = node != NULL
                                       ? fb_block_value_at_ref(
                                             block, node->value_ref)
                                       : NULL;
        yyjson_obj_iter iterator;
        yyjson_val *key_value;
        if (!yyjson_is_obj(object)) {
            return 0u;
        }
        iterator = yyjson_obj_iter_with(object);
        while ((key_value = yyjson_obj_iter_next(&iterator)) != NULL) {
            fb_slice candidate = fb_slice_make(
                yyjson_get_str(key_value), yyjson_get_len(key_value));
            if (fb_slice_equal(candidate, key)) {
                count = fb_size_accumulate_saturating(count, 1u);
            }
        }
    }
    return count;
}

bool
fb_json_block_key_occurrence_at(
    const fb_json_block *block,
    fb_slice key,
    size_t index,
    fb_json_match *out
)
{
    fb_slice source_key = fb_slice_make(NULL, 0u);

    if (block == NULL || out == NULL || !fb_slice_is_valid(key)) {
        return false;
    }
    for (size_t rank = 0u; rank < block->object_count; ++rank) {
        const fb_object_node *node = fb_block_object_node_at(block, rank);
        const yyjson_val *object = node != NULL
                                       ? fb_block_value_at_ref(
                                             block, node->value_ref)
                                       : NULL;
        yyjson_obj_iter iterator;
        yyjson_val *key_value;
        size_t pair_index = 0u;
        if (!yyjson_is_obj(object)) {
            return false;
        }
        iterator = yyjson_obj_iter_with(object);
        while ((key_value = yyjson_obj_iter_next(&iterator)) != NULL) {
            fb_slice candidate = fb_slice_make(
                yyjson_get_str(key_value), yyjson_get_len(key_value));
            if (fb_slice_equal(candidate, key)) {
                if (source_key.ptr == NULL) {
                    source_key = candidate;
                }
                if (index == 0u) {
                    yyjson_obj_iter remaining = iterator;
                    yyjson_val *later_key;
                    bool effective = true;
                    while ((later_key =
                                yyjson_obj_iter_next(&remaining)) != NULL) {
                        fb_slice later = fb_slice_make(
                            yyjson_get_str(later_key),
                            yyjson_get_len(later_key));
                        if (fb_slice_equal(later, key)) {
                            effective = false;
                            break;
                        }
                    }
                    return fb_block_fill_compact_match(
                        block,
                        (uint32_t)rank,
                        yyjson_obj_iter_get_val(key_value),
                        source_key,
                        pair_index,
                        effective,
                        out
                    );
                }
                index--;
            }
            pair_index++;
        }
    }
    return false;
}

static size_t
fb_size_accumulate_saturating(size_t total, size_t value)
{
    return total > SIZE_MAX - value ? SIZE_MAX : total + value;
}

size_t
fb_document_key_count(const fb_document *document, fb_slice key)
{
    size_t total = 0u;

    if (document == NULL || !fb_slice_is_valid(key)) {
        return 0u;
    }
    for (size_t index = 0u; index < document->blocks.len; ++index) {
        const fb_json_block *block =
            fb_chunk_vec_at(&document->blocks, index);
        total = fb_size_accumulate_saturating(
            total,
            fb_json_block_key_count(block, key)
        );
    }
    return total;
}

bool
fb_document_key_first(
    const fb_document *document,
    fb_slice key,
    fb_json_match *out
)
{
    return fb_document_key_at(document, key, 0u, out);
}

bool
fb_document_key_at(
    const fb_document *document,
    fb_slice key,
    size_t index,
    fb_json_match *out
)
{
    if (document == NULL || !fb_slice_is_valid(key) || out == NULL) {
        return false;
    }
    for (size_t block_index = 0u;
         block_index < document->blocks.len;
         ++block_index) {
        const fb_json_block *block =
            fb_chunk_vec_at(&document->blocks, block_index);
        size_t count = fb_json_block_key_count(block, key);
        if (index < count) {
            return fb_json_block_key_at(block, key, index, out);
        }
        index -= count;
    }
    return false;
}

void
fb_json_document_match_cursor_init(
    fb_json_document_match_cursor *cursor,
    const fb_document *document,
    fb_slice key
)
{
    if (cursor == NULL) {
        return;
    }
    memset(cursor, 0, sizeof(*cursor));
    cursor->document_state = document;
    cursor->key_state = key;
}

bool
fb_json_document_match_cursor_next(
    fb_json_document_match_cursor *cursor,
    fb_json_match *out
)
{
    if (cursor == NULL || out == NULL || cursor->document_state == NULL ||
        !fb_slice_is_valid(cursor->key_state)) {
        return false;
    }
    while (cursor->block_index_state < cursor->document_state->blocks.len) {
        if (cursor->block_cursor_state.block_state == NULL) {
            const fb_json_block *block = fb_chunk_vec_at(
                &cursor->document_state->blocks,
                cursor->block_index_state
            );
            fb_json_block_match_cursor_init(
                &cursor->block_cursor_state,
                block,
                cursor->key_state
            );
        }
        if (fb_json_block_match_cursor_next(
                &cursor->block_cursor_state,
                out)) {
            return true;
        }
        cursor->block_index_state++;
        memset(
            &cursor->block_cursor_state,
            0,
            sizeof(cursor->block_cursor_state)
        );
    }
    return false;
}

size_t
fb_document_key_occurrence_count(
    const fb_document *document,
    fb_slice key
)
{
    size_t total = 0u;

    if (document == NULL || !fb_slice_is_valid(key)) {
        return 0u;
    }
    for (size_t index = 0u; index < document->blocks.len; ++index) {
        const fb_json_block *block =
            fb_chunk_vec_at(&document->blocks, index);
        total = fb_size_accumulate_saturating(
            total,
            fb_json_block_key_occurrence_count(block, key)
        );
    }
    return total;
}

bool
fb_document_key_occurrence_at(
    const fb_document *document,
    fb_slice key,
    size_t index,
    fb_json_match *out
)
{
    if (document == NULL || !fb_slice_is_valid(key) || out == NULL) {
        return false;
    }
    for (size_t block_index = 0u;
         block_index < document->blocks.len;
         ++block_index) {
        const fb_json_block *block =
            fb_chunk_vec_at(&document->blocks, block_index);
        size_t count = fb_json_block_key_occurrence_count(block, key);
        if (index < count) {
            return fb_json_block_key_occurrence_at(
                block,
                key,
                index,
                out
            );
        }
        index -= count;
    }
    return false;
}

size_t
fb_document_initial_route_count(const fb_document *document)
{
    return document != NULL ? document->initial_routes.len : 0u;
}

const fb_json_node_ref *
fb_document_initial_route_at(const fb_document *document, size_t index)
{
    return document != NULL
               ? fb_chunk_vec_at(&document->initial_routes, index)
               : NULL;
}

size_t
fb_document_comment_candidate_count(const fb_document *document)
{
    return document != NULL ? document->comment_candidates.len : 0u;
}

const fb_json_node_ref *
fb_document_comment_candidate_at(const fb_document *document, size_t index)
{
    return document != NULL
               ? fb_chunk_vec_at(&document->comment_candidates, index)
               : NULL;
}

size_t
fb_document_video_delivery_candidate_count(const fb_document *document)
{
    return document != NULL ? document->video_candidates.len : 0u;
}

const fb_json_node_ref *
fb_document_video_delivery_candidate_at(
    const fb_document *document,
    size_t index
)
{
    return document != NULL
               ? fb_chunk_vec_at(&document->video_candidates, index)
               : NULL;
}

fb_json_number_kind
fb_json_number_classify(const yyjson_val *value)
{
    if (yyjson_is_uint(value)) {
        return FB_JSON_NUMBER_UINT;
    }
    if (yyjson_is_sint(value)) {
        return FB_JSON_NUMBER_SINT;
    }
    if (yyjson_is_real(value)) {
        double number = yyjson_get_real(value);
        if (isnan(number)) {
            return FB_JSON_NUMBER_NAN;
        }
        if (isinf(number)) {
            return signbit(number)
                       ? FB_JSON_NUMBER_NEG_INFINITY
                       : FB_JSON_NUMBER_POS_INFINITY;
        }
        return FB_JSON_NUMBER_REAL;
    }
    if (yyjson_is_raw(value)) {
        const char *text = yyjson_get_raw(value);
        size_t length = yyjson_get_len(value);
        for (size_t index = 0u; index < length; ++index) {
            if (text[index] == '.' || text[index] == 'e' ||
                text[index] == 'E') {
                return FB_JSON_NUMBER_BIG_REAL;
            }
        }
        return FB_JSON_NUMBER_BIG_INTEGER;
    }
    return FB_JSON_NUMBER_NONE;
}

fb_slice
fb_json_number_text(const yyjson_val *value)
{
    if (!yyjson_is_raw(value)) {
        return fb_slice_make(NULL, 0u);
    }
    return fb_slice_make(yyjson_get_raw(value), yyjson_get_len(value));
}

const char *
fb_document_status_string(fb_document_status status)
{
    switch (status) {
    case FB_DOCUMENT_OK:
        return "ok";
    case FB_DOCUMENT_INVALID_ARGUMENT:
        return "invalid_argument";
    case FB_DOCUMENT_NO_MEMORY:
        return "no_memory";
    case FB_DOCUMENT_MALFORMED_HTML:
        return "malformed_html";
    case FB_DOCUMENT_LIMIT_EXCEEDED:
        return "limit_exceeded";
    case FB_DOCUMENT_CANCELLED:
        return "cancelled";
    }
    return "unknown";
}

const char *
fb_document_issue_string(fb_document_issue issue)
{
    switch (issue) {
    case FB_DOCUMENT_ISSUE_NONE:
        return "none";
    case FB_DOCUMENT_ISSUE_UNTERMINATED_COMMENT:
        return "unterminated_comment";
    case FB_DOCUMENT_ISSUE_UNTERMINATED_TAG:
        return "unterminated_tag";
    case FB_DOCUMENT_ISSUE_UNTERMINATED_ATTRIBUTE:
        return "unterminated_attribute";
    case FB_DOCUMENT_ISSUE_UNTERMINATED_SCRIPT:
        return "unterminated_script";
    case FB_DOCUMENT_ISSUE_NESTED_FORM:
        return "nested_form";
    case FB_DOCUMENT_ISSUE_BODY_LIMIT:
        return "body_limit";
    case FB_DOCUMENT_ISSUE_SCRIPT_LIMIT:
        return "script_limit";
    case FB_DOCUMENT_ISSUE_SCRIPT_BYTES_LIMIT:
        return "script_bytes_limit";
    case FB_DOCUMENT_ISSUE_JSON_VALUE_LIMIT:
        return "json_value_limit";
    case FB_DOCUMENT_ISSUE_JSON_TOTAL_VALUE_LIMIT:
        return "json_total_value_limit";
    case FB_DOCUMENT_ISSUE_JSON_DEPTH_LIMIT:
        return "json_depth_limit";
    case FB_DOCUMENT_ISSUE_DECLARED_URL_LIMIT:
        return "declared_url_limit";
    case FB_DOCUMENT_ISSUE_FORM_LIMIT:
        return "form_limit";
    case FB_DOCUMENT_ISSUE_FORM_CONTROL_LIMIT:
        return "form_control_limit";
    case FB_DOCUMENT_ISSUE_TAG_ATTRIBUTE_LIMIT:
        return "tag_attribute_limit";
    case FB_DOCUMENT_ISSUE_INTERNAL_INDEX_LIMIT:
        return "internal_index_limit";
    }
    return "unknown";
}
