#include "fastbed/transport.h"
#include "fastbed/url.h"

#include <curl/curl.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#if FASTBED_HAS_CURL_IMPERSONATE
extern CURLcode curl_easy_impersonate(CURL *curl,
                                      const char *target,
                                      int default_headers);
#endif

#define FB_DEFAULT_USER_AGENT                                                   \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "           \
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
#define FB_SHARE_HEAD_USER_AGENT "python-requests/2.32.3"
#define FB_SHARE_BODY_USER_AGENT                                                \
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"

enum {
    FB_CONNECT_TIMEOUT_MS = 5000,
    FB_TOTAL_TIMEOUT_MS = 25000,
    FB_MAX_REDIRECT_LIMIT = 10,
    /* Content-Length is untrusted. It may seed one modest allocation, while
     * callback bytes drive all subsequent geometric growth. This value
     * includes the trailing NUL byte kept by fb_body_buffer. */
    FB_CONTENT_LENGTH_INITIAL_STORAGE = 256 * 1024,
    FB_MIN_SCOPE_BODY_STORAGE = 64 * 1024 * 1024,
};

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
    bool failed;
    bool too_large;
    size_t limit;
} fb_heap_buffer;

typedef struct fb_owned_response_body {
    struct fb_owned_response_body *next;
    char data[];
} fb_owned_response_body;

typedef struct {
    fb_owned_response_body *allocation;
    size_t len;
    size_t capacity;
    bool failed;
    bool too_large;
    bool aggregate_too_large;
    size_t limit;
    fb_transport_scope *scope;
} fb_body_buffer;

typedef struct {
    fb_body_buffer body;
    fb_heap_buffer location;
    fb_heap_buffer retry_after;
    fb_heap_buffer content_type;
    fb_heap_buffer fixture_final_url;
    bool body_expected;
} fb_curl_capture;

typedef struct {
    CURL *easy;
    bool leased;
} fb_thread_easy_cache;

typedef struct {
    bool valid;
    unsigned capture_index;
    fb_http_method method;
    fb_slice requested_url;
    fb_slice effective_url;
    long status;
    fb_redirect_hop history[FB_MAX_REDIRECT_LIMIT + 1u];
    size_t history_count;
    unsigned attempt;
} fb_deferred_response;

static pthread_once_t fb_curl_once = PTHREAD_ONCE_INIT;
static CURLcode fb_curl_global_status = CURLE_FAILED_INIT;
static pthread_once_t fb_easy_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t fb_easy_key;
static int fb_easy_key_status = -1;
static pthread_once_t fb_header_profiles_once = PTHREAD_ONCE_INIT;
static struct curl_slist *fb_default_headers;
static struct curl_slist *fb_share_head_headers;
static struct curl_slist *fb_share_body_headers;

static void fb_curl_initialize_once(void) {
    fb_curl_global_status = curl_global_init(CURL_GLOBAL_ALL);
}

static void fb_thread_easy_cache_destroy(void *opaque) {
    fb_thread_easy_cache *cache = opaque;
    if (cache == NULL) {
        return;
    }
    if (cache->easy != NULL) {
        (void)curl_easy_setopt(cache->easy, CURLOPT_COOKIELIST, "ALL");
        curl_easy_reset(cache->easy);
        curl_easy_cleanup(cache->easy);
    }
    free(cache);
}

static void fb_easy_key_initialize_once(void) {
    fb_easy_key_status = pthread_key_create(
        &fb_easy_key, fb_thread_easy_cache_destroy);
}

static void fb_copy_error(char *destination, size_t capacity,
                          const char *format, ...)
    FB_PRINTF_FORMAT(3, 4);
static void fb_copy_error(char *destination, size_t capacity,
                          const char *format, ...) {
    va_list arguments;
    if (destination == NULL || capacity == 0u) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    destination[capacity - 1u] = '\0';
}

static fb_transport_result fb_result(fb_transport_code code,
                                     fb_upstream_response *response,
                                     const char *format, ...)
    FB_PRINTF_FORMAT(3, 4);
static fb_transport_result fb_result(fb_transport_code code,
                                     fb_upstream_response *response,
                                     const char *format, ...) {
    fb_transport_result result;
    va_list arguments;
    memset(&result, 0, sizeof(result));
    result.code = code;
    result.response = response;
    if (format != NULL) {
        va_start(arguments, format);
        (void)vsnprintf(result.detail, sizeof(result.detail), format, arguments);
        va_end(arguments);
        result.detail[sizeof(result.detail) - 1u] = '\0';
    }
    return result;
}

static bool fb_heap_reserve(fb_heap_buffer *buffer, size_t additional) {
    size_t required;
    size_t maximum;
    size_t next;
    char *resized;
    if (buffer == NULL || buffer->failed ||
        !fb_size_add(buffer->len, additional, &required) ||
        !fb_size_add(required, 1u, &required) ||
        !fb_size_add(buffer->limit, 1u, &maximum)) {
        if (buffer != NULL) {
            buffer->failed = true;
        }
        return false;
    }
    if (required > maximum) {
        buffer->failed = true;
        buffer->too_large = true;
        return false;
    }
    if (required <= buffer->capacity) {
        return true;
    }
    next = buffer->capacity == 0u ? 4096u : buffer->capacity;
    while (next < required) {
        if (next > SIZE_MAX / 2u) {
            next = required;
            break;
        }
        next *= 2u;
    }
    if (next > maximum) {
        next = maximum;
    }
    resized = realloc(buffer->data, next);
    if (resized == NULL) {
        buffer->failed = true;
        return false;
    }
    buffer->data = resized;
    buffer->capacity = next;
    return true;
}

static bool fb_body_reserve(fb_body_buffer *buffer, size_t additional) {
    size_t required;
    size_t maximum;
    size_t next;
    size_t old_storage = 0u;
    size_t other_storage;
    size_t available_storage;
    size_t max_capacity;
    size_t allocation_size;
    size_t next_total;
    fb_owned_response_body *resized;
    if (buffer == NULL || buffer->failed ||
        !fb_size_add(buffer->len, additional, &required) ||
        !fb_size_add(required, 1u, &required) ||
        !fb_size_add(buffer->limit, 1u, &maximum)) {
        if (buffer != NULL) {
            buffer->failed = true;
            buffer->too_large = true;
        }
        return false;
    }
    if (required > maximum) {
        buffer->failed = true;
        buffer->too_large = true;
        return false;
    }
    if (required <= buffer->capacity) {
        return true;
    }
    next = buffer->capacity == 0u ? 4096u : buffer->capacity;
    while (next < required) {
        if (next > SIZE_MAX / 2u) {
            next = required;
            break;
        }
        next *= 2u;
    }
    if (next > maximum) {
        next = maximum;
    }
    if (buffer->scope == NULL || buffer->scope->transport == NULL) {
        buffer->failed = true;
        return false;
    }
    if (buffer->allocation != NULL &&
        !fb_size_add(offsetof(fb_owned_response_body, data), buffer->capacity,
                     &old_storage)) {
        buffer->failed = true;
        return false;
    }
    if (buffer->scope->body_storage_bytes < old_storage) {
        buffer->failed = true;
        return false;
    }
    other_storage = buffer->scope->body_storage_bytes - old_storage;
    if (other_storage >=
        buffer->scope->transport->max_scope_body_storage_bytes) {
        buffer->failed = true;
        buffer->aggregate_too_large = true;
        return false;
    }
    available_storage =
        buffer->scope->transport->max_scope_body_storage_bytes - other_storage;
    if (available_storage <= offsetof(fb_owned_response_body, data)) {
        buffer->failed = true;
        buffer->aggregate_too_large = true;
        return false;
    }
    max_capacity =
        available_storage - offsetof(fb_owned_response_body, data);
    if (required > max_capacity) {
        buffer->failed = true;
        buffer->aggregate_too_large = true;
        return false;
    }
    if (next > max_capacity) {
        /* Do not reject a body merely because geometric over-allocation would
         * cross the aggregate bound; reserve the exact remaining capacity. */
        next = max_capacity;
    }
    if (!fb_size_add(offsetof(fb_owned_response_body, data), next,
                     &allocation_size)) {
        buffer->failed = true;
        return false;
    }
    resized = realloc(buffer->allocation, allocation_size);
    if (resized == NULL) {
        buffer->failed = true;
        return false;
    }
    resized->next = NULL;
    buffer->allocation = resized;
    buffer->capacity = next;
    if (!fb_size_add(other_storage, allocation_size, &next_total)) {
        /* The aggregate pre-check makes this unreachable; retain fail-closed
         * behavior if an invariant is ever changed. */
        buffer->failed = true;
        return false;
    }
    buffer->scope->body_storage_bytes = next_total;
    if (buffer->scope->body_storage_peak_bytes < next_total) {
        buffer->scope->body_storage_peak_bytes = next_total;
    }
    return true;
}

static bool fb_body_append(fb_body_buffer *buffer,
                           const char *data,
                           size_t length) {
    if (!fb_body_reserve(buffer, length)) {
        return false;
    }
    if (length != 0u) {
        memcpy(buffer->allocation->data + buffer->len, data, length);
        buffer->len += length;
    }
    buffer->allocation->data[buffer->len] = '\0';
    return true;
}

static void fb_body_clear(fb_body_buffer *buffer) {
    if (buffer == NULL) {
        return;
    }
    buffer->len = 0u;
    buffer->failed = false;
    buffer->too_large = false;
    buffer->aggregate_too_large = false;
    if (buffer->allocation != NULL) {
        buffer->allocation->data[0] = '\0';
    }
}

static void fb_body_destroy(fb_body_buffer *buffer) {
    if (buffer != NULL) {
        size_t storage = 0u;
        if (buffer->allocation != NULL && buffer->scope != NULL &&
            fb_size_add(offsetof(fb_owned_response_body, data),
                        buffer->capacity, &storage) &&
            buffer->scope->body_storage_bytes >= storage) {
            buffer->scope->body_storage_bytes -= storage;
        }
        free(buffer->allocation);
        memset(buffer, 0, sizeof(*buffer));
    }
}

static bool fb_heap_append(fb_heap_buffer *buffer,
                           const char *data,
                           size_t length) {
    if (!fb_heap_reserve(buffer, length)) {
        return false;
    }
    if (length != 0u) {
        memcpy(buffer->data + buffer->len, data, length);
        buffer->len += length;
    }
    buffer->data[buffer->len] = '\0';
    return true;
}

static void fb_heap_clear(fb_heap_buffer *buffer) {
    if (buffer == NULL) {
        return;
    }
    buffer->len = 0u;
    buffer->failed = false;
    buffer->too_large = false;
    if (buffer->data != NULL) {
        buffer->data[0] = '\0';
    }
}

static void fb_heap_destroy(fb_heap_buffer *buffer) {
    if (buffer != NULL) {
        free(buffer->data);
        memset(buffer, 0, sizeof(*buffer));
    }
}

static void fb_capture_init(fb_curl_capture *capture,
                            fb_transport_scope *scope) {
    memset(capture, 0, sizeof(*capture));
    capture->body.limit = scope->transport->max_body_bytes;
    capture->body.scope = scope;
    capture->location.limit = 1024u * 1024u;
    capture->retry_after.limit = 64u * 1024u;
    capture->content_type.limit = 64u * 1024u;
    capture->fixture_final_url.limit = 1024u * 1024u;
}

static void fb_capture_reset(fb_curl_capture *capture) {
    fb_body_clear(&capture->body);
    fb_heap_clear(&capture->location);
    fb_heap_clear(&capture->retry_after);
    fb_heap_clear(&capture->content_type);
    fb_heap_clear(&capture->fixture_final_url);
}

static void fb_capture_destroy(fb_curl_capture *capture) {
    fb_body_destroy(&capture->body);
    fb_heap_destroy(&capture->location);
    fb_heap_destroy(&capture->retry_after);
    fb_heap_destroy(&capture->content_type);
    fb_heap_destroy(&capture->fixture_final_url);
}

static size_t fb_curl_write(char *data, size_t size, size_t count, void *opaque) {
    fb_curl_capture *capture = opaque;
    size_t bytes;
    if (!fb_size_mul(size, count, &bytes) ||
        !fb_body_append(&capture->body, data, bytes)) {
        return 0u;
    }
    return bytes;
}

static bool fb_header_name(const char *line, size_t line_length,
                           const char *name, size_t *value_offset) {
    const size_t name_length = strlen(name);
    size_t offset;
    if (line_length <= name_length || line[name_length] != ':' ||
        strncasecmp(line, name, name_length) != 0) {
        return false;
    }
    offset = name_length + 1u;
    while (offset < line_length &&
           (line[offset] == ' ' || line[offset] == '\t')) {
        ++offset;
    }
    *value_offset = offset;
    return true;
}

static bool fb_header_replace(fb_heap_buffer *buffer,
                              const char *line,
                              size_t line_length,
                              size_t value_offset) {
    while (line_length > value_offset &&
           (line[line_length - 1u] == '\r' || line[line_length - 1u] == '\n' ||
            line[line_length - 1u] == ' ' || line[line_length - 1u] == '\t')) {
        --line_length;
    }
    fb_heap_clear(buffer);
    return fb_heap_append(buffer, line + value_offset, line_length - value_offset);
}

static size_t fb_curl_header(char *data, size_t size, size_t count, void *opaque) {
    fb_curl_capture *capture = opaque;
    size_t bytes;
    size_t value_offset;
    if (!fb_size_mul(size, count, &bytes)) {
        return 0u;
    }
    if (fb_header_name(data, bytes, "Location", &value_offset)) {
        return fb_header_replace(&capture->location, data, bytes, value_offset)
                   ? bytes : 0u;
    }
    if (fb_header_name(data, bytes, "Retry-After", &value_offset)) {
        return fb_header_replace(&capture->retry_after, data, bytes, value_offset)
                   ? bytes : 0u;
    }
    if (fb_header_name(data, bytes, "Content-Type", &value_offset)) {
        return fb_header_replace(&capture->content_type, data, bytes, value_offset)
                   ? bytes : 0u;
    }
    if (fb_header_name(data, bytes, "X-Fastbed-Fixture-Final-Url",
                       &value_offset)) {
        return fb_header_replace(&capture->fixture_final_url, data, bytes,
                                 value_offset)
                   ? bytes : 0u;
    }
    if (capture->body_expected &&
        fb_header_name(data, bytes, "Content-Length", &value_offset)) {
        size_t end = bytes;
        size_t declared = 0u;
        size_t reserve_payload;
        bool valid = value_offset < end;
        while (end > value_offset &&
               (data[end - 1u] == '\r' || data[end - 1u] == '\n' ||
                data[end - 1u] == ' ' || data[end - 1u] == '\t')) {
            --end;
        }
        for (size_t index = value_offset; valid && index < end; ++index) {
            const unsigned char digit = (unsigned char)data[index];
            if (digit < (unsigned char)'0' || digit > (unsigned char)'9' ||
                declared > (SIZE_MAX - (size_t)(digit - (unsigned char)'0')) / 10u) {
                valid = false;
            } else {
                declared = declared * 10u +
                           (size_t)(digit - (unsigned char)'0');
            }
        }
        if (valid) {
            if (declared > capture->body.limit) {
                capture->body.failed = true;
                capture->body.too_large = true;
                return 0u;
            }
            reserve_payload = declared;
            if (reserve_payload >= FB_CONTENT_LENGTH_INITIAL_STORAGE) {
                reserve_payload = FB_CONTENT_LENGTH_INITIAL_STORAGE - 1u;
            }
            if (reserve_payload > capture->body.len &&
                !fb_body_reserve(&capture->body,
                                 reserve_payload - capture->body.len)) {
                return 0u;
            }
        }
    }
    return bytes;
}

static fb_slice fb_capture_copy(fb_arena *arena, const fb_heap_buffer *buffer) {
    if (buffer == NULL || buffer->len == 0u) {
        return FB_SLICE_LIT("");
    }
    return fb_arena_slice_dup(arena, fb_slice_make(buffer->data, buffer->len));
}

static fb_slice fb_capture_take_body(fb_transport_scope *scope,
                                     fb_body_buffer *buffer) {
    fb_owned_response_body *allocation;
    fb_slice result;
    if (buffer == NULL || buffer->len == 0u) {
        return FB_SLICE_LIT("");
    }
    allocation = buffer->allocation;
    if (allocation == NULL) {
        return fb_slice_make(NULL, buffer->len);
    }
    result = fb_slice_make(allocation->data, buffer->len);
    allocation->next = scope->owned_response_bodies;
    scope->owned_response_bodies = allocation;
    scope->retained_body_storage_bytes +=
        offsetof(fb_owned_response_body, data) + buffer->capacity;
    buffer->allocation = NULL;
    buffer->len = 0u;
    buffer->capacity = 0u;
    buffer->failed = false;
    buffer->too_large = false;
    return result;
}

static bool fb_capture_failed(const fb_curl_capture *capture) {
    return capture->body.failed || capture->location.failed ||
           capture->retry_after.failed || capture->content_type.failed;
}

static bool fb_capture_header_too_large(const fb_curl_capture *capture) {
    return capture->location.too_large || capture->retry_after.too_large ||
           capture->content_type.too_large;
}

static bool fb_status_retries(long status) {
    return status == 429 || status == 500 || status == 502 ||
           status == 503 || status == 504;
}

const char *fb_http_method_name(fb_http_method method) {
    return method == FB_HTTP_HEAD ? "HEAD" : "GET";
}

const char *fb_transport_code_name(fb_transport_code code) {
    static const char *const names[] = {
        "ok", "out_of_memory", "impersonation_unavailable", "curl_error",
        "http_error", "body_too_large", "unsafe_redirect", "redirect_loop",
        "too_many_redirects", "invalid_argument",
    };
    const size_t index = (size_t)code;
    return index < FB_ARRAY_LEN(names) ? names[index] : "unknown_transport_error";
}

bool fb_transport_init(fb_transport *transport,
                       size_t max_body_bytes,
                       bool require_impersonation,
                       char *error,
                       size_t error_capacity) {
    size_t maximum_allocation;
    size_t one_body_storage;
    size_t default_scope_storage;
    if (transport == NULL || max_body_bytes == 0u ||
        !fb_size_add(max_body_bytes, 1u, &maximum_allocation) ||
        !fb_size_add(offsetof(fb_owned_response_body, data),
                     maximum_allocation, &one_body_storage)) {
        fb_copy_error(error, error_capacity, "invalid transport configuration");
        return false;
    }
    if (pthread_once(&fb_curl_once, fb_curl_initialize_once) != 0 ||
        fb_curl_global_status != CURLE_OK) {
        fb_copy_error(error, error_capacity, "curl global initialization failed");
        return false;
    }
#if !FASTBED_HAS_CURL_IMPERSONATE
    if (require_impersonation) {
        fb_copy_error(error, error_capacity,
                      "this build has no pinned curl-impersonate backend");
        return false;
    }
#endif
    if (one_body_storage > SIZE_MAX / 2u) {
        default_scope_storage = SIZE_MAX;
    } else {
        default_scope_storage = one_body_storage * 2u;
    }
    if (default_scope_storage < (size_t)FB_MIN_SCOPE_BODY_STORAGE) {
        default_scope_storage = (size_t)FB_MIN_SCOPE_BODY_STORAGE;
    }
    transport->max_body_bytes = max_body_bytes;
    transport->max_scope_body_storage_bytes = default_scope_storage;
    transport->require_impersonation = require_impersonation;
    return true;
}

void fb_transport_cleanup(fb_transport *transport) {
    if (transport != NULL) {
        memset(transport, 0, sizeof(*transport));
    }
}

bool fb_transport_set_scope_body_storage_limit(fb_transport *transport,
                                               size_t max_storage_bytes) {
    if (transport == NULL || max_storage_bytes == 0u) {
        return false;
    }
    transport->max_scope_body_storage_bytes = max_storage_bytes;
    return true;
}

bool fb_transport_set_loopback_replay(fb_transport *transport,
                                      uint16_t http_port,
                                      uint16_t https_port) {
    if (transport == NULL || http_port == 0u || https_port == 0u) {
        return false;
    }
    transport->replay_http_port = http_port;
    transport->replay_https_port = https_port;
    return true;
}

static CURL *fb_easy_acquire(fb_transport_scope *scope) {
    fb_thread_easy_cache *cache = NULL;
    CURL *easy = NULL;
    if (pthread_once(&fb_easy_key_once, fb_easy_key_initialize_once) == 0 &&
        fb_easy_key_status == 0) {
        cache = pthread_getspecific(fb_easy_key);
        if (cache == NULL) {
            cache = calloc(1u, sizeof(*cache));
            if (cache != NULL && pthread_setspecific(fb_easy_key, cache) != 0) {
                free(cache);
                cache = NULL;
            }
        }
        if (cache != NULL && !cache->leased) {
            if (cache->easy == NULL) {
                cache->easy = curl_easy_init();
            }
            if (cache->easy != NULL) {
                cache->leased = true;
                scope->easy_cache = cache;
                easy = cache->easy;
            }
        }
    }
    return easy != NULL ? easy : curl_easy_init();
}

static void fb_easy_release(fb_transport_scope *scope) {
    CURL *easy = scope->easy;
    fb_thread_easy_cache *cache = scope->easy_cache;
    if (easy == NULL) {
        if (cache != NULL) {
            cache->leased = false;
        }
        scope->easy_cache = NULL;
        return;
    }
    (void)curl_easy_setopt(easy, CURLOPT_COOKIELIST, "ALL");
    curl_easy_reset(easy);
    if (cache != NULL && cache->easy == easy) {
        cache->leased = false;
    } else {
        curl_easy_cleanup(easy);
        if (cache != NULL) {
            cache->leased = false;
        }
    }
    scope->easy = NULL;
    scope->easy_cache = NULL;
}

static bool fb_easy_replace(fb_transport_scope *scope) {
    CURL *easy = scope->easy;
    fb_thread_easy_cache *cache = scope->easy_cache;
    if (easy != NULL) {
        curl_easy_reset(easy);
        curl_easy_cleanup(easy);
    }
    easy = curl_easy_init();
    if (cache != NULL) {
        cache->easy = easy;
    }
    scope->easy = easy;
    return easy != NULL;
}

bool fb_transport_scope_init(fb_transport_scope *scope,
                             fb_transport *transport,
                             fb_arena *arena,
                             char *error,
                             size_t error_capacity) {
    CURL *easy;
    if (scope == NULL || transport == NULL || arena == NULL) {
        fb_copy_error(error, error_capacity, "invalid request transport scope");
        return false;
    }
    memset(scope, 0, sizeof(*scope));
    easy = fb_easy_acquire(scope);
    if (easy == NULL) {
        fb_copy_error(error, error_capacity, "cannot create curl easy handle");
        memset(scope, 0, sizeof(*scope));
        return false;
    }
    scope->transport = transport;
    scope->arena = arena;
    scope->easy = easy;
    return true;
}

void fb_transport_scope_destroy(fb_transport_scope *scope) {
    fb_owned_response_body *body;
    if (scope == NULL) {
        return;
    }
    fb_easy_release(scope);
    body = scope->owned_response_bodies;
    while (body != NULL) {
        fb_owned_response_body *next = body->next;
        free(body);
        body = next;
    }
    memset(scope, 0, sizeof(*scope));
}

void fb_transport_scope_set_cancel_flag(
    fb_transport_scope *scope,
    const atomic_bool *cancel_requested) {
    if (scope != NULL) {
        scope->cancel_requested = cancel_requested;
    }
}

fb_transport_options fb_transport_default_options(fb_http_method method) {
    fb_transport_options result;
    result.method = method;
    result.user_agent = FB_SLICE_LIT(FB_DEFAULT_USER_AGENT);
    result.check_status = true;
    result.retry_status_responses = true;
    result.bypass_cache = false;
    result.follow_redirects = true;
    result.max_redirects = FB_MAX_REDIRECT_LIMIT;
    return result;
}

static struct curl_slist *fb_request_headers_build(fb_slice user_agent) {
    static const char *const headers[] = {
        "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language: en-US,en;q=0.9",
        "cache-control: no-cache",
        "pragma: no-cache",
        "priority: u=0, i",
        "sec-fetch-dest: document",
        "sec-fetch-mode: navigate",
        "sec-fetch-site: none",
        "sec-fetch-user: ?1",
        "sec-gpc: 1",
        "upgrade-insecure-requests: 1",
    };
    struct curl_slist *list = NULL;
    size_t index;
    char *user_agent_header;
    size_t header_length;
    for (index = 0; index < FB_ARRAY_LEN(headers); ++index) {
        struct curl_slist *next = curl_slist_append(list, headers[index]);
        if (next == NULL) {
            curl_slist_free_all(list);
            return NULL;
        }
        list = next;
    }
    if (!fb_size_add(sizeof("user-agent: ") - 1u, user_agent.len, &header_length) ||
        !fb_size_add(header_length, 1u, &header_length)) {
        curl_slist_free_all(list);
        return NULL;
    }
    user_agent_header = malloc(header_length);
    if (user_agent_header == NULL) {
        curl_slist_free_all(list);
        return NULL;
    }
    memcpy(user_agent_header, "user-agent: ", sizeof("user-agent: ") - 1u);
    memcpy(user_agent_header + sizeof("user-agent: ") - 1u,
           user_agent.ptr, user_agent.len);
    user_agent_header[header_length - 1u] = '\0';
    {
        struct curl_slist *next = curl_slist_append(list, user_agent_header);
        free(user_agent_header);
        if (next == NULL) {
            curl_slist_free_all(list);
            return NULL;
        }
        list = next;
    }
    return list;
}

static void fb_header_profiles_initialize_once(void) {
    fb_default_headers = fb_request_headers_build(
        FB_SLICE_LIT(FB_DEFAULT_USER_AGENT));
    fb_share_head_headers = fb_request_headers_build(
        FB_SLICE_LIT(FB_SHARE_HEAD_USER_AGENT));
    fb_share_body_headers = fb_request_headers_build(
        FB_SLICE_LIT(FB_SHARE_BODY_USER_AGENT));
}

static struct curl_slist *fb_request_headers(fb_slice user_agent,
                                              bool *owned) {
    struct curl_slist *profile = NULL;
    *owned = false;
    if (pthread_once(&fb_header_profiles_once,
                     fb_header_profiles_initialize_once) == 0) {
        if (fb_slice_equal(user_agent, FB_SLICE_LIT(FB_DEFAULT_USER_AGENT))) {
            profile = fb_default_headers;
        } else if (fb_slice_equal(user_agent,
                                  FB_SLICE_LIT(FB_SHARE_HEAD_USER_AGENT))) {
            profile = fb_share_head_headers;
        } else if (fb_slice_equal(user_agent,
                                  FB_SLICE_LIT(FB_SHARE_BODY_USER_AGENT))) {
            profile = fb_share_body_headers;
        }
    }
    if (profile != NULL) {
        return profile;
    }
    profile = fb_request_headers_build(user_agent);
    *owned = profile != NULL;
    return profile;
}

static struct curl_slist *fb_replay_connect_to(
    const fb_transport *transport,
    fb_slice url
) {
    CURLU *parsed;
    char *scheme = NULL;
    char *host = NULL;
    char *port = NULL;
    struct curl_slist *result = NULL;
    unsigned replay_port;
    size_t required;
    char *mapping;
    int written;

    if (transport == NULL || transport->replay_http_port == 0u ||
        transport->replay_https_port == 0u || url.ptr == NULL) {
        return NULL;
    }
    parsed = curl_url();
    if (parsed == NULL ||
        curl_url_set(parsed, CURLUPART_URL, url.ptr, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) != CURLUE_OK) {
        curl_url_cleanup(parsed);
        curl_free(scheme);
        curl_free(host);
        curl_free(port);
        return NULL;
    }
    replay_port = strcasecmp(scheme, "https") == 0
                      ? (unsigned)transport->replay_https_port
                      : (strcasecmp(scheme, "http") == 0
                             ? (unsigned)transport->replay_http_port : 0u);
    if (replay_port == 0u ||
        !fb_size_add(strlen(host), strlen(port), &required) ||
        !fb_size_add(required, 32u, &required)) {
        goto finished;
    }
    mapping = malloc(required);
    if (mapping == NULL) {
        goto finished;
    }
    written = snprintf(mapping, required, "%s:%s:127.0.0.1:%u",
                       host, port, replay_port);
    if (written > 0 && (size_t)written < required) {
        result = curl_slist_append(NULL, mapping);
    }
    free(mapping);

finished:
    curl_url_cleanup(parsed);
    curl_free(scheme);
    curl_free(host);
    curl_free(port);
    return result;
}

static struct curl_slist *fb_replay_headers(fb_slice user_agent, fb_slice url) {
    static const char prefix[] = "X-Fastbed-Fixture-Requested-Hex: ";
    static const char hex[] = "0123456789abcdef";
    struct curl_slist *headers = fb_request_headers_build(user_agent);
    size_t encoded_length;
    size_t total;
    char *line;
    struct curl_slist *appended;
    if (headers == NULL || !fb_size_mul(url.len, 2u, &encoded_length) ||
        !fb_size_add(sizeof(prefix) - 1u, encoded_length, &total) ||
        !fb_size_add(total, 1u, &total)) {
        curl_slist_free_all(headers);
        return NULL;
    }
    line = malloc(total);
    if (line == NULL) {
        curl_slist_free_all(headers);
        return NULL;
    }
    memcpy(line, prefix, sizeof(prefix) - 1u);
    for (size_t index = 0u; index < url.len; ++index) {
        const unsigned char byte = (unsigned char)url.ptr[index];
        line[sizeof(prefix) - 1u + index * 2u] = hex[byte >> 4u];
        line[sizeof(prefix) - 1u + index * 2u + 1u] = hex[byte & 0x0fu];
    }
    line[total - 1u] = '\0';
    appended = curl_slist_append(headers, line);
    free(line);
    if (appended == NULL) {
        curl_slist_free_all(headers);
        return NULL;
    }
    return appended;
}

static bool fb_transport_cancelled(const fb_transport_scope *scope) {
    return scope != NULL && scope->cancel_requested != NULL &&
           atomic_load_explicit(scope->cancel_requested, memory_order_relaxed);
}

static int fb_curl_progress(void *opaque,
                            curl_off_t download_total,
                            curl_off_t download_now,
                            curl_off_t upload_total,
                            curl_off_t upload_now) {
    const fb_transport_scope *scope = opaque;
    (void)download_total;
    (void)download_now;
    (void)upload_total;
    (void)upload_now;
    return fb_transport_cancelled(scope) ? 1 : 0;
}

static CURLcode fb_configure_easy(CURL *easy,
                                  fb_transport_scope *scope,
                                  fb_curl_capture *capture,
                                  const char *url,
                                  fb_http_method method,
                                  struct curl_slist *headers,
                                  struct curl_slist *connect_to,
                                  bool loopback_replay,
                                  char *curl_error,
                                  bool *impersonation_failed) {
    CURLcode status;
    *impersonation_failed = false;
    curl_easy_reset(easy);
    capture->body_expected = method == FB_HTTP_GET;
#if FASTBED_HAS_CURL_IMPERSONATE
    status = curl_easy_impersonate(easy, "chrome146", 0);
    if (status != CURLE_OK) {
        *impersonation_failed = true;
        return status;
    }
#endif
#define FB_CURL_SET(option, value)                                              \
    do {                                                                        \
        status = curl_easy_setopt(easy, (option), (value));                     \
        if (status != CURLE_OK) {                                               \
            return status;                                                      \
        }                                                                       \
    } while (0)
    FB_CURL_SET(CURLOPT_ERRORBUFFER, curl_error);
    FB_CURL_SET(CURLOPT_COOKIEFILE, "");
    FB_CURL_SET(CURLOPT_COOKIEJAR, NULL);
    FB_CURL_SET(CURLOPT_COOKIE, NULL);
    FB_CURL_SET(CURLOPT_COOKIELIST, "ALL");
    FB_CURL_SET(CURLOPT_URL, url);
    FB_CURL_SET(CURLOPT_HTTPHEADER, headers);
    FB_CURL_SET(CURLOPT_CONNECT_TO, connect_to);
    FB_CURL_SET(CURLOPT_FOLLOWLOCATION, 0L);
    FB_CURL_SET(CURLOPT_MAXREDIRS, 0L);
    FB_CURL_SET(CURLOPT_CONNECTTIMEOUT_MS, (long)FB_CONNECT_TIMEOUT_MS);
    FB_CURL_SET(CURLOPT_TIMEOUT_MS, (long)FB_TOTAL_TIMEOUT_MS);
    FB_CURL_SET(CURLOPT_ACCEPT_ENCODING, "gzip, deflate, br");
    FB_CURL_SET(CURLOPT_PROTOCOLS_STR, "http,https");
    FB_CURL_SET(CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    FB_CURL_SET(CURLOPT_SSL_VERIFYPEER, loopback_replay ? 0L : 1L);
    FB_CURL_SET(CURLOPT_SSL_VERIFYHOST, loopback_replay ? 0L : 2L);
    FB_CURL_SET(CURLOPT_NOSIGNAL, 1L);
    FB_CURL_SET(CURLOPT_TCP_KEEPALIVE, 1L);
    FB_CURL_SET(CURLOPT_TCP_KEEPIDLE, 60L);
    FB_CURL_SET(CURLOPT_TCP_KEEPINTVL, 30L);
    FB_CURL_SET(CURLOPT_DNS_CACHE_TIMEOUT, 300L);
    FB_CURL_SET(CURLOPT_BUFFERSIZE, 256L * 1024L);
    FB_CURL_SET(CURLOPT_WRITEFUNCTION, fb_curl_write);
    FB_CURL_SET(CURLOPT_WRITEDATA, capture);
    FB_CURL_SET(CURLOPT_HEADERFUNCTION, fb_curl_header);
    FB_CURL_SET(CURLOPT_HEADERDATA, capture);
    if (scope->cancel_requested != NULL) {
        FB_CURL_SET(CURLOPT_NOPROGRESS, 0L);
        FB_CURL_SET(CURLOPT_XFERINFOFUNCTION, fb_curl_progress);
        FB_CURL_SET(CURLOPT_XFERINFODATA, scope);
    }
    if (method == FB_HTTP_HEAD) {
        FB_CURL_SET(CURLOPT_NOBODY, 1L);
        FB_CURL_SET(CURLOPT_CUSTOMREQUEST, "HEAD");
    } else {
        FB_CURL_SET(CURLOPT_HTTPGET, 1L);
    }
#undef FB_CURL_SET
    return CURLE_OK;
}

static CURLcode fb_easy_finish_request(CURL *easy) {
    CURLcode status = curl_easy_setopt(easy, CURLOPT_COOKIELIST, "ALL");
    curl_easy_reset(easy);
    return status;
}

static bool fb_trace_append(fb_transport_scope *scope,
                            const fb_physical_request *item) {
    fb_physical_request *items;
    size_t capacity;
    size_t bytes;
    if (scope->physical_count == scope->physical_capacity) {
        capacity = scope->physical_capacity == 0u ? 8u : scope->physical_capacity * 2u;
        if (capacity < scope->physical_capacity ||
            !fb_size_mul(capacity, sizeof(*items), &bytes)) {
            return false;
        }
        items = fb_arena_alloc(scope->arena, bytes, _Alignof(fb_physical_request));
        if (items == NULL) {
            return false;
        }
        if (scope->physical_count != 0u) {
            memcpy(items, scope->physical_requests,
                   scope->physical_count * sizeof(*items));
        }
        scope->physical_requests = items;
        scope->physical_capacity = capacity;
    }
    scope->physical_requests[scope->physical_count++] = *item;
    return true;
}

static bool fb_history_is_valid(const fb_redirect_hop *history, size_t count);

static fb_upstream_response *fb_make_response(
    fb_transport_scope *scope,
    fb_http_method method,
    fb_slice initial_url,
    fb_slice effective_url,
    long status,
    fb_curl_capture *capture,
    const fb_redirect_hop *history,
    size_t history_count,
    unsigned attempt) {
    fb_upstream_response *response;
    size_t history_bytes;
    if (history_count > FB_MAX_REDIRECT_LIMIT + 1u ||
        !fb_history_is_valid(history, history_count)) {
        return NULL;
    }
    response = fb_arena_alloc(scope->arena, sizeof(*response),
                              _Alignof(fb_upstream_response));
    if (response == NULL) {
        return NULL;
    }
    memset(response, 0, sizeof(*response));
    response->method = method;
    response->requested_url = initial_url;
    response->url = effective_url;
    response->content_type = fb_capture_copy(scope->arena, &capture->content_type);
    response->location = fb_capture_copy(scope->arena, &capture->location);
    response->retry_after = fb_capture_copy(scope->arena, &capture->retry_after);
    response->status = status;
    response->attempt = attempt;
    if (response->requested_url.ptr == NULL ||
        response->url.ptr == NULL ||
        (capture->content_type.len != 0u && response->content_type.ptr == NULL) ||
        (capture->location.len != 0u && response->location.ptr == NULL) ||
        (capture->retry_after.len != 0u && response->retry_after.ptr == NULL) ||
        (history_count != 0u && history == NULL)) {
        return NULL;
    }
    if (history_count != 0u) {
        if (!fb_size_mul(history_count, sizeof(*history), &history_bytes)) {
            return NULL;
        }
        response->history = fb_arena_memdup(scope->arena, history, history_bytes,
                                            _Alignof(fb_redirect_hop));
        if (response->history == NULL) {
            return NULL;
        }
        response->history_count = history_count;
    }
    response->body = fb_capture_take_body(scope, &capture->body);
    if (!fb_slice_is_valid(response->body)) {
        return NULL;
    }
    return response;
}

static bool fb_redirect_status(long status) {
    return status == 301 || status == 302 || status == 303 ||
           status == 307 || status == 308;
}

static bool fb_seen_url(const fb_slice *visited, size_t count, fb_slice url) {
    size_t index;
    for (index = 0; index < count; ++index) {
        if (fb_slice_equal(visited[index], url)) {
            return true;
        }
    }
    return false;
}

static bool fb_history_is_valid(const fb_redirect_hop *history, size_t count) {
    size_t index;
    for (index = 0; index < count; ++index) {
        if ((history[index].method != FB_HTTP_GET &&
             history[index].method != FB_HTTP_HEAD) ||
            history[index].requested_url.ptr == NULL ||
            history[index].effective_url.ptr == NULL ||
            history[index].location.ptr == NULL ||
            history[index].location.len == 0u) {
            return false;
        }
    }
    return true;
}

static void fb_sleep_retry(void) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static fb_upstream_response *fb_cache_lookup(fb_transport_scope *scope,
                                              fb_slice url,
                                              const fb_transport_options *options) {
    size_t index;
    for (index = 0; index < scope->cache_count; ++index) {
        const fb_transport_cache_entry *entry = &scope->cache[index];
        if (entry->response != NULL && entry->url.ptr != NULL &&
            entry->user_agent.ptr != NULL &&
            entry->response->method == FB_HTTP_GET &&
            entry->follow_redirects == options->follow_redirects &&
            entry->max_redirects == options->max_redirects &&
            fb_slice_equal(entry->url, url) &&
            fb_slice_equal(entry->user_agent, options->user_agent)) {
            return entry->response;
        }
    }
    return NULL;
}

static bool fb_cache_store(fb_transport_scope *scope,
                           fb_slice url,
                           const fb_transport_options *options,
                           fb_upstream_response *response) {
    fb_transport_cache_entry *entry;
    fb_slice cached_url;
    fb_slice cached_user_agent;
    size_t index;
    if (response == NULL || response->method != FB_HTTP_GET ||
        url.ptr == NULL || url.len == 0u || options->user_agent.ptr == NULL) {
        return false;
    }
    /* Python's request-local dict assignment replaces the prior response even
     * when the refetch deliberately bypassed its lookup. Keep the original
     * copied key storage, but replace its value instead of appending a stale
     * duplicate that lookup would encounter first. */
    for (index = 0u; index < scope->cache_count; ++index) {
        entry = &scope->cache[index];
        if (entry->url.ptr != NULL && entry->user_agent.ptr != NULL &&
            entry->follow_redirects == options->follow_redirects &&
            entry->max_redirects == options->max_redirects &&
            fb_slice_equal(entry->url, url) &&
            fb_slice_equal(entry->user_agent, options->user_agent)) {
            entry->response = response;
            return true;
        }
    }
    if (scope->cache_count == FB_ARRAY_LEN(scope->cache)) {
        return false;
    }
    cached_url = fb_arena_slice_dup(scope->arena, url);
    cached_user_agent = fb_arena_slice_dup(scope->arena, options->user_agent);
    if (cached_url.ptr == NULL || cached_user_agent.ptr == NULL) {
        return false;
    }
    entry = &scope->cache[scope->cache_count];
    entry->url = cached_url;
    entry->user_agent = cached_user_agent;
    entry->follow_redirects = options->follow_redirects;
    entry->max_redirects = options->max_redirects;
    entry->response = response;
    ++scope->cache_count;
    return true;
}

static bool fb_slice_has_no_nul(fb_slice value) {
    return fb_slice_is_valid(value) &&
           (value.len == 0u || memchr(value.ptr, '\0', value.len) == NULL);
}

static bool fb_user_agent_is_valid(fb_slice value) {
    return value.ptr != NULL && fb_slice_has_no_nul(value) &&
           memchr(value.ptr, '\r', value.len) == NULL &&
           memchr(value.ptr, '\n', value.len) == NULL;
}

static void fb_deferred_discard(fb_deferred_response *deferred,
                                fb_curl_capture captures[2]) {
    if (deferred->valid) {
        fb_capture_reset(&captures[deferred->capture_index]);
        memset(deferred, 0, sizeof(*deferred));
    }
}

static bool fb_deferred_set(fb_deferred_response *deferred,
                            unsigned capture_index,
                            fb_http_method method,
                            fb_slice requested_url,
                            fb_slice effective_url,
                            long status,
                            const fb_redirect_hop *history,
                            size_t history_count,
                            unsigned attempt) {
    if (capture_index >= 2u || requested_url.ptr == NULL ||
        effective_url.ptr == NULL ||
        history_count > FB_MAX_REDIRECT_LIMIT + 1u ||
        !fb_history_is_valid(history, history_count)) {
        return false;
    }
    memset(deferred, 0, sizeof(*deferred));
    deferred->valid = true;
    deferred->capture_index = capture_index;
    deferred->method = method;
    deferred->requested_url = requested_url;
    deferred->effective_url = effective_url;
    deferred->status = status;
    if (history_count != 0u) {
        memcpy(deferred->history, history,
               history_count * sizeof(*history));
    }
    deferred->history_count = history_count;
    deferred->attempt = attempt;
    return true;
}

static fb_upstream_response *fb_deferred_materialize(
    fb_transport_scope *scope,
    fb_deferred_response *deferred,
    fb_curl_capture captures[2]) {
    fb_upstream_response *response;
    if (!deferred->valid) {
        return NULL;
    }
    response = fb_make_response(
        scope, deferred->method, deferred->requested_url,
        deferred->effective_url, deferred->status,
        &captures[deferred->capture_index], deferred->history,
        deferred->history_count, deferred->attempt);
    if (response != NULL) {
        memset(deferred, 0, sizeof(*deferred));
    }
    return response;
}

fb_transport_result fb_transport_request(fb_transport_scope *scope,
                                         fb_slice url,
                                         const fb_transport_options *options_input) {
    fb_transport_options defaults;
    const fb_transport_options *options;
    CURL *easy;
    struct curl_slist *headers = NULL;
    bool headers_owned = false;
    fb_slice initial_url = {0};
    fb_curl_capture captures[2];
    fb_deferred_response deferred;
    fb_upstream_response *last_response = NULL;
    fb_transport_result result;
    size_t url_allocation_size;
    unsigned active_capture = 0u;
    unsigned attempt;
    bool captures_initialized = false;
    bool easy_poisoned = false;

    if (scope == NULL || scope->transport == NULL || scope->arena == NULL ||
        scope->easy == NULL || url.ptr == NULL || url.len == 0u) {
        return fb_result(FB_TRANSPORT_INVALID_ARGUMENT, NULL,
                         "invalid transport request");
    }
    if (fb_transport_cancelled(scope)) {
        return fb_result(FB_TRANSPORT_CURL_ERROR, NULL,
                         "transport request cancelled");
    }
    defaults = fb_transport_default_options(FB_HTTP_GET);
    options = options_input == NULL ? &defaults : options_input;
    if ((options->method != FB_HTTP_GET && options->method != FB_HTTP_HEAD) ||
        options->max_redirects > FB_MAX_REDIRECT_LIMIT ||
        !fb_slice_has_no_nul(url) ||
        !fb_user_agent_is_valid(options->user_agent) ||
        !fb_size_add(url.len, 1u, &url_allocation_size)) {
        return fb_result(FB_TRANSPORT_INVALID_ARGUMENT, NULL,
                         "invalid transport options");
    }
    if (options->method == FB_HTTP_GET && !options->bypass_cache) {
        fb_upstream_response *cached = fb_cache_lookup(scope, url, options);
        if (cached != NULL) {
            scope->last_get_response = cached;
            if (options->check_status && cached->status >= 400) {
                return fb_result(FB_TRANSPORT_HTTP_ERROR, cached,
                                 "Facebook returned HTTP %ld", cached->status);
            }
            return fb_result(FB_TRANSPORT_OK, cached, NULL);
        }
    }
#if !FASTBED_HAS_CURL_IMPERSONATE
    if (scope->transport->require_impersonation) {
        return fb_result(FB_TRANSPORT_IMPERSONATION_UNAVAILABLE, NULL,
                         "curl-impersonate is required for live Facebook requests");
    }
#endif
    (void)url_allocation_size;
    initial_url = fb_arena_slice_dup(scope->arena, url);
    if (initial_url.ptr == NULL) {
        return fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL, "cannot copy request URL");
    }
    headers = fb_request_headers(options->user_agent, &headers_owned);
    if (headers == NULL) {
        return fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                         "cannot allocate request headers");
    }
    easy = (CURL *)scope->easy;
    fb_capture_init(&captures[0], scope);
    fb_capture_init(&captures[1], scope);
    captures_initialized = true;
    memset(&deferred, 0, sizeof(deferred));
    result = fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                       "transport request state allocation failed");

    for (attempt = 1u; attempt <= 2u; ++attempt) {
        fb_slice current_url = initial_url;
        fb_slice visited[FB_MAX_REDIRECT_LIMIT + 2u] = {0};
        size_t visited_count = 1u;
        fb_redirect_hop history[FB_MAX_REDIRECT_LIMIT + 1u] = {0};
        size_t history_count = 0u;
        fb_http_method current_method = options->method;
        bool restart = false;
        visited[0] = current_url;

        for (;;) {
            fb_curl_capture *capture = &captures[active_capture];
            char curl_error[CURL_ERROR_SIZE] = {0};
            char *effective_url = NULL;
            long status = 0;
            CURLcode configure_status;
            CURLcode curl_status;
            CURLcode cookie_status;
            struct curl_slist *connect_to = NULL;
            struct curl_slist *replay_headers = NULL;
            struct curl_slist *active_headers = headers;
            fb_physical_request physical;
            bool redirect;
            bool impersonation_failed;
            const bool loopback_replay =
                scope->transport->replay_http_port != 0u;

            if (fb_transport_cancelled(scope)) {
                result = fb_result(FB_TRANSPORT_CURL_ERROR, last_response,
                                   "transport request cancelled");
                goto done;
            }
            fb_capture_reset(capture);
            if (loopback_replay) {
                connect_to = fb_replay_connect_to(
                    scope->transport, current_url);
                replay_headers = fb_replay_headers(
                    options->user_agent, current_url);
                active_headers = replay_headers;
                if (connect_to == NULL || replay_headers == NULL) {
                    curl_slist_free_all(connect_to);
                    curl_slist_free_all(replay_headers);
                    result = fb_result(
                        FB_TRANSPORT_INVALID_ARGUMENT, NULL,
                        "cannot configure replay request");
                    goto done;
                }
            }
            configure_status = fb_configure_easy(
                easy, scope, capture, current_url.ptr, current_method, active_headers,
                connect_to, loopback_replay,
                curl_error, &impersonation_failed);
            if (configure_status != CURLE_OK) {
                curl_slist_free_all(connect_to);
                curl_slist_free_all(replay_headers);
                const bool had_deferred = deferred.valid;
                last_response = fb_deferred_materialize(
                    scope, &deferred, captures);
                if (had_deferred && last_response == NULL) {
                    result = fb_result(
                        FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                        "cannot retain the last upstream response");
                } else if (impersonation_failed) {
                    result = fb_result(
                        FB_TRANSPORT_IMPERSONATION_UNAVAILABLE, last_response,
                        "cannot configure chrome146 impersonation: %s",
                        curl_easy_strerror(configure_status));
                } else {
                    result = fb_result(
                        FB_TRANSPORT_CURL_ERROR, last_response,
                        "cannot configure Facebook request: %s",
                        curl_easy_strerror(configure_status));
                }
                goto done;
            }
            curl_status = curl_easy_perform(easy);
            (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, NULL);
            (void)curl_easy_setopt(easy, CURLOPT_HTTPHEADER, NULL);
            curl_slist_free_all(connect_to);
            curl_slist_free_all(replay_headers);
            (void)curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
            (void)curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &effective_url);
            if (capture->fixture_final_url.len != 0u) {
                effective_url = capture->fixture_final_url.data;
            } else if (effective_url == NULL) {
                effective_url = (char *)current_url.ptr;
            }
            cookie_status = curl_easy_setopt(easy, CURLOPT_COOKIELIST, "ALL");
            memset(&physical, 0, sizeof(physical));
            physical.method = current_method;
            physical.requested_url = current_url;
            physical.effective_url = fb_arena_slice_dup(
                scope->arena, fb_slice_from_cstr(effective_url));
            physical.status = status;
            physical.body_bytes = current_method == FB_HTTP_GET
                                      ? capture->body.len : 0u;
            physical.attempt = attempt;
            physical.redirect_hop = (unsigned)history_count;
            if (physical.requested_url.ptr == NULL ||
                physical.effective_url.ptr == NULL ||
                !fb_trace_append(scope, &physical)) {
                const bool had_deferred = deferred.valid;
                last_response = fb_deferred_materialize(
                    scope, &deferred, captures);
                if (had_deferred && last_response == NULL) {
                    last_response = NULL;
                }
                result = fb_result(FB_TRANSPORT_OUT_OF_MEMORY, last_response,
                                   "cannot retain physical request trace");
                goto done;
            }

            if (capture->body.too_large ||
                capture->body.aggregate_too_large) {
                fb_deferred_discard(&deferred, captures);
                last_response = fb_make_response(
                    scope, options->method, initial_url,
                    physical.effective_url, status, capture,
                    history, history_count, attempt);
                if (last_response == NULL) {
                    result = fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                                       "cannot retain oversized response metadata");
                } else {
                    if (capture->body.aggregate_too_large) {
                        result = fb_result(
                            FB_TRANSPORT_BODY_TOO_LARGE, last_response,
                            "Facebook request response-body storage exceeded %zu bytes",
                            scope->transport->max_scope_body_storage_bytes);
                    } else {
                        result = fb_result(
                            FB_TRANSPORT_BODY_TOO_LARGE, last_response,
                            "Facebook response exceeded %zu bytes",
                            scope->transport->max_body_bytes);
                    }
                }
                if (cookie_status != CURLE_OK) {
                    easy_poisoned = true;
                }
                goto done;
            }
            if (fb_capture_failed(capture)) {
                const bool had_deferred = deferred.valid;
                last_response = fb_deferred_materialize(
                    scope, &deferred, captures);
                if (fb_capture_header_too_large(capture)) {
                    result = fb_result(
                        FB_TRANSPORT_CURL_ERROR, last_response,
                        "Facebook response headers exceeded transport limits");
                } else if (had_deferred && last_response == NULL) {
                    result = fb_result(
                        FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                        "cannot retain the last upstream response");
                } else {
                    result = fb_result(
                        FB_TRANSPORT_OUT_OF_MEMORY, last_response,
                        "cannot allocate Facebook response capture");
                }
                if (cookie_status != CURLE_OK) {
                    easy_poisoned = true;
                }
                goto done;
            }
            if (cookie_status != CURLE_OK) {
                if (curl_status == CURLE_OK) {
                    fb_deferred_discard(&deferred, captures);
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    if (last_response == NULL) {
                        result = fb_result(
                            FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                            "cannot retain upstream response");
                    } else {
                        result = fb_result(
                            FB_TRANSPORT_CURL_ERROR, last_response,
                            "cannot clear Facebook cookie state: %s",
                            curl_easy_strerror(cookie_status));
                    }
                } else {
                    const bool had_deferred = deferred.valid;
                    last_response = fb_deferred_materialize(
                        scope, &deferred, captures);
                    if (had_deferred && last_response == NULL) {
                        result = fb_result(
                            FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                            "cannot retain the last upstream response");
                    } else {
                        result = fb_result(
                            FB_TRANSPORT_CURL_ERROR, last_response,
                            "cannot clear Facebook cookie state: %s",
                            curl_easy_strerror(cookie_status));
                    }
                }
                easy_poisoned = true;
                goto done;
            }
            if (curl_status != CURLE_OK) {
                if (fb_transport_cancelled(scope)) {
                    result = fb_result(FB_TRANSPORT_CURL_ERROR, last_response,
                                       "transport request cancelled");
                    goto done;
                }
                if (attempt < 2u &&
                    (options->method == FB_HTTP_GET || options->method == FB_HTTP_HEAD)) {
                    restart = true;
                }
                if (restart) {
                    fb_sleep_retry();
                    break;
                }
                {
                    const bool had_deferred = deferred.valid;
                    last_response = fb_deferred_materialize(
                        scope, &deferred, captures);
                    if (had_deferred && last_response == NULL) {
                        result = fb_result(
                            FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                            "cannot retain the last upstream response");
                    } else {
                        result = fb_result(
                            FB_TRANSPORT_CURL_ERROR, last_response,
                            "Facebook request failed: %s",
                            curl_error[0] != '\0'
                                ? curl_error
                                : curl_easy_strerror(curl_status));
                    }
                }
                goto done;
            }

            fb_deferred_discard(&deferred, captures);

            redirect = options->follow_redirects &&
                       fb_redirect_status(status) && capture->location.len != 0u;
            if (!redirect) {
                if (options->retry_status_responses && fb_status_retries(status) &&
                    attempt < 2u) {
                    if (!fb_deferred_set(
                            &deferred, active_capture, options->method,
                            initial_url, physical.effective_url, status,
                            history, history_count, attempt)) {
                        last_response = fb_make_response(
                            scope, options->method, initial_url,
                            physical.effective_url, status, capture,
                            history, history_count, attempt);
                        result = fb_result(
                            FB_TRANSPORT_OUT_OF_MEMORY, last_response,
                            "cannot retain retry response state");
                        goto done;
                    }
                    active_capture ^= 1u;
                    restart = true;
                    fb_sleep_retry();
                    break;
                }
                last_response = fb_make_response(
                    scope, options->method, initial_url,
                    physical.effective_url, status, capture,
                    history, history_count, attempt);
                if (last_response == NULL) {
                    result = fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                                       "cannot retain upstream response");
                    goto done;
                }
                goto complete;
            }
            if (history_count >= options->max_redirects) {
                last_response = fb_make_response(
                    scope, options->method, initial_url,
                    physical.effective_url, status, capture,
                    history, history_count, attempt);
                if (last_response == NULL) {
                    result = fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                                       "cannot retain redirect response");
                } else {
                    result = fb_result(
                        FB_TRANSPORT_TOO_MANY_REDIRECTS, last_response,
                        "Facebook exceeded %u redirects",
                        options->max_redirects);
                }
                goto done;
            }
            {
                fb_slice next_url_slice = {0};
                fb_url_status url_status = fb_url_resolve_redirect(
                    scope->arena, physical.effective_url,
                    fb_slice_make(capture->location.data,
                                  capture->location.len),
                    &next_url_slice);
                if (url_status == FB_URL_NO_MEMORY) {
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    result = fb_result(
                        FB_TRANSPORT_OUT_OF_MEMORY, last_response,
                        "cannot retain redirect target");
                    goto done;
                }
                if (url_status != FB_URL_OK || next_url_slice.ptr == NULL ||
                    next_url_slice.len == 0u ||
                    !fb_slice_has_no_nul(next_url_slice)) {
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    if (last_response == NULL) {
                        result = fb_result(
                            FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                            "cannot retain unsafe redirect response");
                    } else {
                        result = fb_result(
                            FB_TRANSPORT_UNSAFE_REDIRECT, last_response,
                            "Facebook returned an unsafe redirect target");
                    }
                    goto done;
                }
                if (fb_seen_url(visited, visited_count, next_url_slice)) {
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    if (last_response == NULL) {
                        result = fb_result(FB_TRANSPORT_OUT_OF_MEMORY, NULL,
                                           "cannot retain redirect loop response");
                    } else {
                        result = fb_result(
                            FB_TRANSPORT_REDIRECT_LOOP, last_response,
                            "Facebook entered a redirect loop");
                    }
                    goto done;
                }
                if (visited_count >= FB_ARRAY_LEN(visited) ||
                    history_count >= FB_ARRAY_LEN(history)) {
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    result = fb_result(
                        FB_TRANSPORT_TOO_MANY_REDIRECTS, last_response,
                        "Facebook exceeded redirect bookkeeping limits");
                    goto done;
                }
                history[history_count].location = fb_capture_copy(
                    scope->arena, &capture->location);
                if (history[history_count].location.ptr == NULL) {
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    result = fb_result(
                        FB_TRANSPORT_OUT_OF_MEMORY, last_response,
                        "cannot retain redirect history");
                    goto done;
                }
                if (!fb_deferred_set(
                        &deferred, active_capture, options->method,
                        initial_url, physical.effective_url, status,
                        history, history_count, attempt)) {
                    last_response = fb_make_response(
                        scope, options->method, initial_url,
                        physical.effective_url, status, capture,
                        history, history_count, attempt);
                    result = fb_result(
                        FB_TRANSPORT_OUT_OF_MEMORY, last_response,
                        "cannot retain redirect response state");
                    goto done;
                }
                history[history_count].method = current_method;
                history[history_count].requested_url = physical.requested_url;
                history[history_count].effective_url = physical.effective_url;
                history[history_count].status = status;
                ++history_count;
                visited[visited_count++] = next_url_slice;
                current_url = next_url_slice;
                active_capture ^= 1u;
                if (status == 303 && current_method != FB_HTTP_HEAD) {
                    current_method = FB_HTTP_GET;
                }
            }
        }

        if (!restart) {
            break;
        }
    }

    goto done;

complete:
    if (options->method == FB_HTTP_GET) {
        scope->last_get_response = last_response;
        (void)fb_cache_store(scope, url, options, last_response);
    }
    if (options->check_status && last_response->status >= 400) {
        result = fb_result(FB_TRANSPORT_HTTP_ERROR, last_response,
                           "Facebook returned HTTP %ld", last_response->status);
    } else {
        result = fb_result(FB_TRANSPORT_OK, last_response, NULL);
    }

done:
    if (easy_poisoned) {
        (void)fb_easy_replace(scope);
    } else if (scope->easy != NULL &&
               fb_easy_finish_request((CURL *)scope->easy) != CURLE_OK) {
        (void)fb_easy_replace(scope);
    }
    if (captures_initialized) {
        fb_capture_destroy(&captures[0]);
        fb_capture_destroy(&captures[1]);
    }
    if (headers_owned) {
        curl_slist_free_all(headers);
    }
    return result;
}

void fb_transport_select_response(fb_transport_scope *scope,
                                  fb_upstream_response *response) {
    if (scope != NULL && response != NULL) {
        scope->selected_get_response = response;
    }
}

