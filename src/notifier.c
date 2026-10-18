#include "fastbed/notifier.h"

#include <curl/curl.h>
#include <openssl/sha.h>
#include <zlib.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FB_DISCORD_WEBHOOK_PREFIX "https://discord.com/api/webhooks/"
#define FB_RESTRICTED_GZIP_THRESHOLD ((size_t)7u * 1024u * 1024u)
#define FB_NOTIFIER_HTTP_TIMEOUT_MS 30000L
#define FB_NOTIFIER_CONNECT_TIMEOUT_MS 10000L
#define FB_NOTIFIER_JSON_LIMIT ((size_t)32u * 1024u)
#define FB_NOTIFIER_RESPONSE_LIMIT ((size_t)64u * 1024u)
#define FB_NOTIFIER_FILENAME_LIMIT 160u
#define FB_NOTIFIER_MAX_WORKERS 32u
#define FB_NOTIFIER_WORKER_STACK_BYTES ((size_t)1024u * 1024u)

typedef enum {
    FB_NOTIFY_DUMP = 0,
    FB_NOTIFY_RESTRICTED
} fb_notify_kind;

typedef struct {
    char *ptr;
    size_t len;
} fb_owned_slice;

typedef struct {
    long status;
    fb_owned_slice url;
} fb_job_history;

typedef struct fb_notifier_job {
    struct fb_notifier_job *next;
    fb_notify_kind kind;
    size_t allocation_bytes;
    size_t budget_bytes;
    struct timespec created_at;
    fb_owned_slice origin_path;
    fb_owned_slice reason;
    fb_owned_slice detail;
    bool has_response;
    long response_status;
    fb_owned_slice response_url;
    fb_owned_slice content_type;
    fb_owned_slice body;
    fb_job_history *history;
    size_t history_count;
} fb_notifier_job;

typedef struct {
    size_t allocation_bytes;
    size_t budget_bytes;
} fb_job_plan;

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
} fb_heap_text;

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
    bool truncated;
} fb_fixed_text;

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t position;
} fb_mime_stream;

typedef struct {
    char body[FB_NOTIFIER_RESPONSE_LIMIT + 1u];
    size_t body_len;
    bool body_truncated;
    bool via;
    char retry_after[96];
    size_t retry_after_len;
} fb_curl_response;

typedef struct {
    bool delivered;
    uint64_t rate_limited;
    uint64_t retries;
} fb_delivery_result;

typedef struct fb_notifier_worker {
    struct fb_notifier *notifier;
    CURL *easy;
} fb_notifier_worker;

struct fb_notifier {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool mutex_ready;
    bool condition_ready;
    bool enabled;
    bool accepting;
    atomic_uint_fast64_t shutdown_deadline_ms;
    char *webhook;
    size_t webhook_len;
    fb_notifier_options options;
    pthread_t *threads;
    fb_notifier_worker *workers;
    size_t worker_count;
    size_t started_workers;
    fb_notifier_job *head;
    fb_notifier_job *tail;
    size_t reservations;
    size_t queued_jobs;
    size_t active_jobs;
    size_t pending_jobs;
    size_t pending_bytes;
    uint64_t enqueued;
    uint64_t delivered;
    uint64_t delivery_failed;
    uint64_t rate_limited;
    uint64_t rate_limit_retries;
    uint64_t rejected_backpressure;
    uint64_t rejected_no_memory;
    uint64_t rejected_closed;
    uint64_t disabled_noops;
};

static pthread_once_t fb_notifier_curl_once = PTHREAD_ONCE_INIT;
static CURLcode fb_notifier_curl_status = CURLE_FAILED_INIT;

static void
fb_notifier_curl_init_once(void)
{
    fb_notifier_curl_status = curl_global_init(CURL_GLOBAL_ALL);
}

static void
fb_notifier_set_error(char *destination, size_t capacity,
                      const char *format, ...)
    FB_PRINTF_FORMAT(3, 4);
static void
fb_notifier_set_error(char *destination, size_t capacity, const char *format, ...)
{
    va_list arguments;

    if (destination == NULL || capacity == 0u) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    destination[capacity - 1u] = '\0';
}

static void
fb_secure_clear(void *memory, size_t size)
{
    volatile unsigned char *cursor = memory;
    size_t index;

    if (cursor == NULL) {
        return;
    }
    for (index = 0u; index < size; ++index) {
        cursor[index] = 0u;
    }
}

static void
fb_counter_add(uint64_t *counter, uint64_t amount)
{
    if (UINT64_MAX - *counter < amount) {
        *counter = UINT64_MAX;
    } else {
        *counter += amount;
    }
}

static bool
fb_monotonic_milliseconds(uint64_t *milliseconds)
{
    struct timespec now;
    uint64_t seconds;

    if (milliseconds == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) {
        return false;
    }
    seconds = (uint64_t)now.tv_sec;
    if (seconds > UINT64_MAX / 1000u) {
        return false;
    }
    *milliseconds = seconds * 1000u + (uint64_t)now.tv_nsec / 1000000u;
    return true;
}

static bool
fb_notifier_shutdown_expired(const fb_notifier *notifier)
{
    const uint64_t deadline = atomic_load_explicit(
        &notifier->shutdown_deadline_ms, memory_order_acquire);
    uint64_t now;

    if (deadline == 0u) {
        return false;
    }
    return !fb_monotonic_milliseconds(&now) || now >= deadline;
}

static struct timespec
fb_monotonic_deadline(uint64_t milliseconds)
{
    struct timespec deadline;

    deadline.tv_sec = (time_t)(milliseconds / 1000u);
    deadline.tv_nsec = (long)((milliseconds % 1000u) * 1000000u);
    return deadline;
}

static bool
fb_notifier_wait_milliseconds(fb_notifier *notifier, uint64_t milliseconds)
{
    uint64_t now;
    uint64_t wait_deadline;
    bool completed = false;

    if (!fb_monotonic_milliseconds(&now) ||
        milliseconds > UINT64_MAX - now) {
        return false;
    }
    wait_deadline = now + milliseconds;
    (void)pthread_mutex_lock(&notifier->mutex);
    for (;;) {
        const uint64_t shutdown_deadline = atomic_load_explicit(
            &notifier->shutdown_deadline_ms, memory_order_acquire);
        uint64_t wake_deadline = wait_deadline;
        struct timespec wake_time;
        int status;

        if (!fb_monotonic_milliseconds(&now)) {
            break;
        }
        if (shutdown_deadline != 0u && now >= shutdown_deadline) {
            break;
        }
        if (now >= wait_deadline) {
            completed = true;
            break;
        }
        if (shutdown_deadline != 0u && shutdown_deadline < wake_deadline) {
            wake_deadline = shutdown_deadline;
        }
        wake_time = fb_monotonic_deadline(wake_deadline);
        status = pthread_cond_timedwait(&notifier->condition,
                                        &notifier->mutex, &wake_time);
        if (status != 0 && status != ETIMEDOUT) {
            break;
        }
    }
    (void)pthread_mutex_unlock(&notifier->mutex);
    return completed;
}

static bool
fb_slice_usable(fb_slice value)
{
    return value.ptr != NULL || value.len == 0u;
}

static bool
fb_slice_equal_literal(fb_owned_slice value, const char *literal)
{
    const size_t length = strlen(literal);
    return value.len == length &&
           (length == 0u || memcmp(value.ptr, literal, length) == 0);
}

static bool
fb_ascii_starts_with(fb_slice value, const char *prefix)
{
    const size_t length = strlen(prefix);
    return value.len >= length && value.ptr != NULL &&
           memcmp(value.ptr, prefix, length) == 0;
}

static bool
fb_ascii_equal_ci(fb_slice value, const char *literal)
{
    const size_t length = strlen(literal);
    size_t index;

    if (value.len != length || (length != 0u && value.ptr == NULL)) {
        return false;
    }
    for (index = 0u; index < length; ++index) {
        unsigned char left = (unsigned char)value.ptr[index];
        unsigned char right = (unsigned char)literal[index];
        if (left >= (unsigned char)'A' && left <= (unsigned char)'Z') {
            left = (unsigned char)(left + ('a' - 'A'));
        }
        if (right >= (unsigned char)'A' && right <= (unsigned char)'Z') {
            right = (unsigned char)(right + ('a' - 'A'));
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

static bool
fb_ascii_prefix_ci(const char *value, size_t value_len, const char *prefix)
{
    const size_t prefix_len = strlen(prefix);
    size_t index;

    if (value_len < prefix_len) {
        return false;
    }
    for (index = 0u; index < prefix_len; ++index) {
        unsigned char left = (unsigned char)value[index];
        unsigned char right = (unsigned char)prefix[index];
        if (left >= (unsigned char)'A' && left <= (unsigned char)'Z') {
            left = (unsigned char)(left + ('a' - 'A'));
        }
        if (right >= (unsigned char)'A' && right <= (unsigned char)'Z') {
            right = (unsigned char)(right + ('a' - 'A'));
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

static bool
fb_is_ascii_space(unsigned char byte)
{
    return byte == (unsigned char)' ' || byte == (unsigned char)'\t' ||
           byte == (unsigned char)'\n' || byte == (unsigned char)'\r' ||
           byte == (unsigned char)'\f' || byte == (unsigned char)'\v';
}

static size_t
fb_utf8_width(const unsigned char *bytes, size_t remaining)
{
    const unsigned char first = bytes[0];

    if (first < 0x80u) {
        return 1u;
    }
    if (first >= 0xc2u && first <= 0xdfu && remaining >= 2u &&
        bytes[1] >= 0x80u && bytes[1] <= 0xbfu) {
        return 2u;
    }
    if (remaining >= 3u &&
        ((first == 0xe0u && bytes[1] >= 0xa0u && bytes[1] <= 0xbfu) ||
         ((first >= 0xe1u && first <= 0xecu) &&
          bytes[1] >= 0x80u && bytes[1] <= 0xbfu) ||
         (first == 0xedu && bytes[1] >= 0x80u && bytes[1] <= 0x9fu) ||
         ((first >= 0xeeu && first <= 0xefu) &&
          bytes[1] >= 0x80u && bytes[1] <= 0xbfu)) &&
        bytes[2] >= 0x80u && bytes[2] <= 0xbfu) {
        return 3u;
    }
    if (remaining >= 4u &&
        ((first == 0xf0u && bytes[1] >= 0x90u && bytes[1] <= 0xbfu) ||
         ((first >= 0xf1u && first <= 0xf3u) &&
          bytes[1] >= 0x80u && bytes[1] <= 0xbfu) ||
         (first == 0xf4u && bytes[1] >= 0x80u && bytes[1] <= 0x8fu)) &&
        bytes[2] >= 0x80u && bytes[2] <= 0xbfu &&
        bytes[3] >= 0x80u && bytes[3] <= 0xbfu) {
        return 4u;
    }
    return 0u;
}

static void
fb_fixed_init(fb_fixed_text *output, char *storage, size_t capacity)
{
    output->data = storage;
    output->len = 0u;
    output->capacity = capacity;
    output->truncated = false;
    if (capacity != 0u) {
        storage[0] = '\0';
    }
}

static bool
fb_fixed_append_bytes(fb_fixed_text *output, const char *bytes, size_t length)
{
    if ((length != 0u && bytes == NULL) || output->capacity == 0u ||
        length > output->capacity - 1u - output->len) {
        output->truncated = true;
        return false;
    }
    if (length != 0u) {
        memcpy(output->data + output->len, bytes, length);
        output->len += length;
    }
    output->data[output->len] = '\0';
    return true;
}

static bool
fb_fixed_append_cstr(fb_fixed_text *output, const char *text)
{
    return fb_fixed_append_bytes(output, text, strlen(text));
}

static size_t
fb_clean_text(char *destination,
              size_t capacity,
              const char *source,
              size_t source_len,
              size_t limit,
              bool collapse_whitespace)
{
    static const char replacement[] = "\xef\xbf\xbd";
    static const char ellipsis[] = "\xe2\x80\xa6";
    size_t cursor = 0u;
    size_t output_len = 0u;
    const size_t maximum = capacity == 0u
        ? 0u : (limit < capacity - 1u ? limit : capacity - 1u);
    bool pending_space = false;
    bool truncated = false;

    if (capacity == 0u) {
        return 0u;
    }
    destination[0] = '\0';
    while (cursor < source_len) {
        const unsigned char byte = (unsigned char)source[cursor];
        size_t width;

        if (byte == 0u) {
            ++cursor;
            continue;
        }
        if (collapse_whitespace && byte < 0x80u && fb_is_ascii_space(byte)) {
            pending_space = output_len != 0u;
            ++cursor;
            continue;
        }
        if (pending_space) {
            if (output_len == maximum) {
                truncated = true;
                break;
            }
            destination[output_len++] = ' ';
            pending_space = false;
        }
        width = fb_utf8_width((const unsigned char *)source + cursor,
                              source_len - cursor);
        if (width == 0u) {
            if (sizeof(replacement) - 1u > maximum - output_len) {
                truncated = true;
                break;
            }
            memcpy(destination + output_len, replacement,
                   sizeof(replacement) - 1u);
            output_len += sizeof(replacement) - 1u;
            ++cursor;
            continue;
        }
        if (width > maximum - output_len) {
            truncated = true;
            break;
        }
        memcpy(destination + output_len, source + cursor, width);
        output_len += width;
        cursor += width;
    }
    if (truncated && maximum >= sizeof(ellipsis) - 1u) {
        size_t cut = maximum - (sizeof(ellipsis) - 1u);
        if (cut > output_len) {
            cut = output_len;
        }
        destination[output_len] = '\0';
        while (cut > 0u &&
               (((unsigned char)destination[cut] & 0xc0u) == 0x80u)) {
            --cut;
        }
        output_len = cut;
        memcpy(destination + output_len, ellipsis, sizeof(ellipsis) - 1u);
        output_len += sizeof(ellipsis) - 1u;
    }
    destination[output_len] = '\0';
    return output_len;
}

static bool
fb_heap_reserve(fb_heap_text *output, size_t additional)
{
    size_t required;
    size_t capacity;
    char *grown;

    if (!fb_size_add(output->len, additional, &required) ||
        !fb_size_add(required, 1u, &required) ||
        required > FB_NOTIFIER_JSON_LIMIT) {
        return false;
    }
    if (required <= output->capacity) {
        return true;
    }
    capacity = output->capacity == 0u ? 4096u : output->capacity;
    while (capacity < required) {
        const size_t next = capacity <= FB_NOTIFIER_JSON_LIMIT / 2u
            ? capacity * 2u : FB_NOTIFIER_JSON_LIMIT;
        if (next <= capacity) {
            return false;
        }
        capacity = next;
    }
    grown = realloc(output->data, capacity);
    if (grown == NULL) {
        return false;
    }
    output->data = grown;
    output->capacity = capacity;
    return true;
}

static bool
fb_heap_append(fb_heap_text *output, const char *bytes, size_t length)
{
    if (length != 0u && bytes == NULL) {
        return false;
    }
    if (!fb_heap_reserve(output, length)) {
        return false;
    }
    if (output->data == NULL) {
        return false;
    }
    if (length != 0u) {
        memcpy(output->data + output->len, bytes, length);
        output->len += length;
    }
    output->data[output->len] = '\0';
    return true;
}

static bool
fb_heap_append_cstr(fb_heap_text *output, const char *text)
{
    return fb_heap_append(output, text, strlen(text));
}

static bool
fb_json_string(fb_heap_text *output, const char *text, size_t length)
{
    static const char hex[] = "0123456789abcdef";
    size_t index;

    if (!fb_heap_append_cstr(output, "\"")) {
        return false;
    }
    for (index = 0u; index < length; ++index) {
        const unsigned char byte = (unsigned char)text[index];
        char escaped[6];
        if (byte == (unsigned char)'\"' || byte == (unsigned char)'\\') {
            escaped[0] = '\\';
            escaped[1] = (char)byte;
            if (!fb_heap_append(output, escaped, 2u)) {
                return false;
            }
        } else if (byte == (unsigned char)'\b') {
            if (!fb_heap_append_cstr(output, "\\b")) {
                return false;
            }
        } else if (byte == (unsigned char)'\f') {
            if (!fb_heap_append_cstr(output, "\\f")) {
                return false;
            }
        } else if (byte == (unsigned char)'\n') {
            if (!fb_heap_append_cstr(output, "\\n")) {
                return false;
            }
        } else if (byte == (unsigned char)'\r') {
            if (!fb_heap_append_cstr(output, "\\r")) {
                return false;
            }
        } else if (byte == (unsigned char)'\t') {
            if (!fb_heap_append_cstr(output, "\\t")) {
                return false;
            }
        } else if (byte < 0x20u) {
            escaped[0] = '\\';
            escaped[1] = 'u';
            escaped[2] = '0';
            escaped[3] = '0';
            escaped[4] = hex[byte >> 4u];
            escaped[5] = hex[byte & 0x0fu];
            if (!fb_heap_append(output, escaped, sizeof(escaped))) {
                return false;
            }
        } else if (!fb_heap_append(output, (const char *)&text[index], 1u)) {
            return false;
        }
    }
    return fb_heap_append_cstr(output, "\"");
}

static bool
fb_json_field(fb_heap_text *output,
              bool *first,
              const char *name,
              const char *value,
              size_t value_len,
              bool inline_field)
{
    if ((!*first && !fb_heap_append_cstr(output, ",")) ||
        !fb_heap_append_cstr(output, "{\"name\":") ||
        !fb_json_string(output, name, strlen(name)) ||
        !fb_heap_append_cstr(output, ",\"value\":") ||
        !fb_json_string(output, value, value_len) ||
        !fb_heap_append_cstr(output, inline_field
            ? ",\"inline\":true}" : ",\"inline\":false}")) {
        return false;
    }
    *first = false;
    return true;
}

static fb_slice
fb_url_path(fb_slice value)
{
    size_t start = 0u;
    size_t end;
    size_t index;

    if (!fb_slice_usable(value) || value.len == 0u) {
        return fb_slice_make(NULL, 0u);
    }
    for (index = 0u; index + 2u < value.len; ++index) {
        if (value.ptr[index] == ':' && value.ptr[index + 1u] == '/' &&
            value.ptr[index + 2u] == '/') {
            start = index + 3u;
            while (start < value.len && value.ptr[start] != '/' &&
                   value.ptr[start] != '?' && value.ptr[start] != '#') {
                ++start;
            }
            break;
        }
    }
    if (index + 2u >= value.len) {
        const char *slash = memchr(value.ptr, '/', value.len);
        if (slash != NULL) {
            const size_t host_len = (size_t)(slash - value.ptr);
            fb_slice host = fb_slice_make(value.ptr, host_len);
            if (fb_ascii_equal_ci(host, "facebook.com") ||
                fb_ascii_equal_ci(host, "www.facebook.com") ||
                fb_ascii_equal_ci(host, "web.facebook.com") ||
                fb_ascii_equal_ci(host, "m.facebook.com") ||
                fb_ascii_equal_ci(host, "mbasic.facebook.com")) {
                start = host_len;
            }
        }
    }
    while (start < value.len && value.ptr[start] == '/') {
        ++start;
    }
    end = start;
    while (end < value.len && value.ptr[end] != '?' && value.ptr[end] != '#') {
        ++end;
    }
    return fb_slice_make(value.ptr + start, end - start);
}

static fb_slice
fb_path_segment(fb_slice path, size_t requested)
{
    size_t segment = 0u;
    size_t start = 0u;
    size_t end;

    while (start < path.len) {
        while (start < path.len && path.ptr[start] == '/') {
            ++start;
        }
        if (start == path.len) {
            break;
        }
        end = start;
        while (end < path.len && path.ptr[end] != '/') {
            ++end;
        }
        if (segment == requested) {
            return fb_slice_make(path.ptr + start, end - start);
        }
        ++segment;
        start = end;
    }
    return fb_slice_make(NULL, 0u);
}

static const char *
fb_path_kind(fb_slice segment)
{
    if (fb_ascii_equal_ci(segment, "reel")) {
        return "reel";
    }
    if (fb_ascii_equal_ci(segment, "videos") ||
        fb_ascii_equal_ci(segment, "watch") ||
        fb_ascii_equal_ci(segment, "v")) {
        return "video";
    }
    if (fb_ascii_equal_ci(segment, "posts") ||
        fb_ascii_equal_ci(segment, "permalink") ||
        fb_ascii_equal_ci(segment, "story.php") ||
        fb_ascii_equal_ci(segment, "permalink.php")) {
        return "post";
    }
    if (fb_ascii_equal_ci(segment, "photo.php") ||
        fb_ascii_equal_ci(segment, "photo") ||
        fb_ascii_equal_ci(segment, "photos")) {
        return "photo";
    }
    if (fb_ascii_equal_ci(segment, "marketplace")) {
        return "marketplace";
    }
    if (fb_ascii_equal_ci(segment, "media")) {
        return "album";
    }
    return NULL;
}

static const char *
fb_page_type_for_path(fb_owned_slice candidate)
{
    const fb_slice path = fb_url_path(fb_slice_make(candidate.ptr, candidate.len));
    const fb_slice first = fb_path_segment(path, 0u);
    const fb_slice second = fb_path_segment(path, 1u);
    const char *kind;

    if (first.len == 0u || fb_ascii_equal_ci(first, "login") ||
        fb_ascii_equal_ci(first, "checkpoint") ||
        fb_ascii_equal_ci(first, "recover")) {
        return NULL;
    }
    if (fb_ascii_equal_ci(first, "groups")) {
        return "group_post";
    }
    if (fb_ascii_equal_ci(first, "share")) {
        return "share";
    }
    kind = fb_path_kind(first);
    if (kind != NULL) {
        return kind;
    }
    kind = fb_path_kind(second);
    if (kind != NULL &&
        (fb_ascii_equal_ci(second, "posts") ||
         fb_ascii_equal_ci(second, "videos") ||
         fb_ascii_equal_ci(second, "photos") ||
         fb_ascii_equal_ci(second, "v"))) {
        return kind;
    }
    if (second.len == 0u || fb_ascii_equal_ci(first, "people") ||
        fb_ascii_equal_ci(first, "p")) {
        return "profile";
    }
    return NULL;
}

static const char *
fb_restricted_page_type(const fb_notifier_job *job,
                        char *storage,
                        size_t storage_capacity)
{
    static const char unsupported_prefix[] = "unsupported_";
    static const char target_suffix[] = "_target";
    const char *kind;

    if (job->reason.len > sizeof(unsupported_prefix) - 1u +
                              sizeof(target_suffix) - 1u &&
        memcmp(job->reason.ptr, unsupported_prefix,
               sizeof(unsupported_prefix) - 1u) == 0 &&
        memcmp(job->reason.ptr + job->reason.len -
                   (sizeof(target_suffix) - 1u),
               target_suffix, sizeof(target_suffix) - 1u) == 0) {
        const char *middle = job->reason.ptr + sizeof(unsupported_prefix) - 1u;
        const size_t middle_len = job->reason.len -
            (sizeof(unsupported_prefix) - 1u) - (sizeof(target_suffix) - 1u);
        if (middle_len == sizeof("media_set") - 1u &&
            memcmp(middle, "media_set", middle_len) == 0) {
            return "album";
        }
        if (middle_len < storage_capacity) {
            memcpy(storage, middle, middle_len);
            storage[middle_len] = '\0';
            return storage;
        }
    }
    if (fb_slice_equal_literal(job->reason,
                               "private_group_post_unavailable")) {
        return "group_post";
    }
    if (fb_slice_equal_literal(job->reason, "target_video_payload_missing")) {
        return "reel";
    }
    if (job->has_response) {
        kind = fb_page_type_for_path(job->response_url);
        if (kind != NULL) {
            return kind;
        }
    }
    kind = fb_page_type_for_path(job->origin_path);
    return kind == NULL ? "unknown" : kind;
}

static bool
fb_origin_is_absolute(fb_owned_slice origin)
{
    const fb_slice view = fb_slice_make(origin.ptr, origin.len);
    return fb_ascii_starts_with(view, "https://") ||
           fb_ascii_starts_with(view, "http://");
}

static size_t
fb_origin_url_length(fb_owned_slice origin)
{
    static const char prefix[] = "https://www.facebook.com/";
    size_t start = 0u;
    size_t result;

    if (fb_origin_is_absolute(origin)) {
        return origin.len;
    }
    while (start < origin.len && origin.ptr[start] == '/') {
        ++start;
    }
    if (!fb_size_add(sizeof(prefix) - 1u, origin.len - start, &result)) {
        return SIZE_MAX;
    }
    return result;
}

static bool
fb_write_origin_url(fb_owned_slice origin,
                    char *destination,
                    size_t capacity,
                    size_t *written)
{
    static const char prefix[] = "https://www.facebook.com/";
    const size_t length = fb_origin_url_length(origin);
    size_t start = 0u;

    if (written != NULL) {
        *written = length;
    }
    if (length == SIZE_MAX || length >= capacity) {
        return false;
    }
    if (fb_origin_is_absolute(origin)) {
        if (length != 0u) {
            memcpy(destination, origin.ptr, length);
        }
    } else {
        while (start < origin.len && origin.ptr[start] == '/') {
            ++start;
        }
        memcpy(destination, prefix, sizeof(prefix) - 1u);
        if (origin.len != start) {
            memcpy(destination + sizeof(prefix) - 1u,
                   origin.ptr + start, origin.len - start);
        }
    }
    destination[length] = '\0';
    return true;
}

static bool
fb_filename_allowed(unsigned char byte)
{
    return (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
           (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
           (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
           byte == (unsigned char)'.' || byte == (unsigned char)'_' ||
           byte == (unsigned char)'-';
}

static size_t
fb_filename_component(char *destination,
                      size_t capacity,
                      const char *source,
                      size_t source_len,
                      size_t limit)
{
    size_t length = 0u;
    size_t index;

    for (index = 0u; index < source_len && length < limit &&
                    length + 1u < capacity; ++index) {
        const unsigned char byte = (unsigned char)source[index];
        destination[length++] = fb_filename_allowed(byte) ? (char)byte : '_';
    }
    while (length != 0u && (destination[0] == '.' || destination[0] == '_' ||
                            destination[0] == '-')) {
        memmove(destination, destination + 1u, --length);
    }
    while (length != 0u &&
           (destination[length - 1u] == '.' || destination[length - 1u] == '_' ||
            destination[length - 1u] == '-')) {
        --length;
    }
    destination[length] = '\0';
    return length;
}

static bool
fb_dump_filename(const fb_notifier_job *job,
                 char destination[FB_NOTIFIER_FILENAME_LIMIT])
{
    size_t length = 0u;
    size_t index;
    static const char suffix[] = "_dump.html";

    for (index = 0u; index < job->origin_path.len && index < 80u; ++index) {
        const unsigned char byte = (unsigned char)job->origin_path.ptr[index];
        destination[length++] =
            ((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
             (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
             (byte >= (unsigned char)'0' && byte <= (unsigned char)'9'))
                ? (char)byte : '_';
    }
    if (length + sizeof(suffix) > FB_NOTIFIER_FILENAME_LIMIT) {
        return false;
    }
    memcpy(destination + length, suffix, sizeof(suffix));
    return true;
}

static bool
fb_restricted_filename(const fb_notifier_job *job,
                       const unsigned char digest[SHA256_DIGEST_LENGTH],
                       bool compressed,
                       char destination[FB_NOTIFIER_FILENAME_LIMIT])
{
    const fb_slice path = fb_url_path(
        fb_slice_make(job->origin_path.ptr, job->origin_path.len));
    size_t path_start = 0u;
    size_t path_end = path.len;
    char stem[53];
    char reason[25];
    char digest_text[13];
    size_t stem_len;
    size_t reason_len;
    fb_fixed_text output;
    size_t index;

    while (path_start < path_end && path.ptr[path_start] == '/') {
        ++path_start;
    }
    while (path_end > path_start && path.ptr[path_end - 1u] == '/') {
        --path_end;
    }
    if (path_end == path_start) {
        memcpy(stem, "facebook", sizeof("facebook"));
        stem_len = sizeof("facebook") - 1u;
    } else {
        stem_len = fb_filename_component(
            stem, sizeof(stem), path.ptr + path_start,
            path_end - path_start, 52u);
    }
    reason_len = fb_filename_component(reason, sizeof(reason), job->reason.ptr,
                                       job->reason.len, 24u);
    for (index = 0u; index < 6u; ++index) {
        static const char hex[] = "0123456789abcdef";
        digest_text[index * 2u] = hex[digest[index] >> 4u];
        digest_text[index * 2u + 1u] = hex[digest[index] & 0x0fu];
    }
    digest_text[12] = '\0';
    fb_fixed_init(&output, destination, FB_NOTIFIER_FILENAME_LIMIT);
    if (stem_len == 0u && reason_len == 0u) {
        if (!fb_fixed_append_cstr(&output, "facebook_")) {
            return false;
        }
    } else {
        if (stem_len != 0u &&
            (!fb_fixed_append_bytes(&output, stem, stem_len) ||
             !fb_fixed_append_cstr(&output, "_"))) {
            return false;
        }
        if (reason_len != 0u &&
            (!fb_fixed_append_bytes(&output, reason, reason_len) ||
             !fb_fixed_append_cstr(&output, "_"))) {
            return false;
        }
    }
    return fb_fixed_append_bytes(&output, digest_text, 12u) &&
           fb_fixed_append_cstr(&output, compressed ? ".html.gz" : ".html");
}

static bool
fb_gzip_capacity(size_t source_len, size_t *capacity)
{
    uLong bound;
    size_t result;

    if (source_len > (size_t)ULONG_MAX) {
        return false;
    }
    bound = compressBound((uLong)source_len);
    if ((uLong)(size_t)bound != bound ||
        !fb_size_add((size_t)bound, 64u, &result)) {
        return false;
    }
    *capacity = result;
    return true;
}

static bool
fb_gzip_level6(const unsigned char *source,
               size_t source_len,
               unsigned char **destination,
               size_t *destination_len)
{
    z_stream stream;
    gz_header header;
    unsigned char *output = NULL;
    size_t capacity;
    size_t input_cursor = 0u;
    size_t output_cursor = 0u;
    int status;
    bool initialized = false;
    bool success = false;

    *destination = NULL;
    *destination_len = 0u;
    if (!fb_gzip_capacity(source_len, &capacity)) {
        return false;
    }
    output = malloc(capacity);
    if (output == NULL) {
        return false;
    }
    memset(&stream, 0, sizeof(stream));
    memset(&header, 0, sizeof(header));
    status = deflateInit2(&stream, 6, Z_DEFLATED, 15 + 16, 8,
                          Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        goto finished;
    }
    initialized = true;
    header.time = 0u;
    header.os = 255;
    if (deflateSetHeader(&stream, &header) != Z_OK) {
        goto finished;
    }
    while (input_cursor < source_len) {
        const size_t input_chunk = source_len - input_cursor > (size_t)UINT_MAX
            ? (size_t)UINT_MAX : source_len - input_cursor;
        stream.next_in = (Bytef *)(uintptr_t)(source + input_cursor);
        stream.avail_in = (uInt)input_chunk;
        while (stream.avail_in != 0u) {
            const size_t available = capacity - output_cursor;
            const size_t output_chunk = available > (size_t)UINT_MAX
                ? (size_t)UINT_MAX : available;
            uInt before;
            if (output_chunk == 0u) {
                goto finished;
            }
            stream.next_out = output + output_cursor;
            stream.avail_out = (uInt)output_chunk;
            before = stream.avail_out;
            status = deflate(&stream, Z_NO_FLUSH);
            output_cursor += (size_t)(before - stream.avail_out);
            if (status != Z_OK) {
                goto finished;
            }
        }
        input_cursor += input_chunk;
    }
    do {
        const size_t available = capacity - output_cursor;
        const size_t output_chunk = available > (size_t)UINT_MAX
            ? (size_t)UINT_MAX : available;
        uInt before;
        if (output_chunk == 0u) {
            goto finished;
        }
        stream.next_out = output + output_cursor;
        stream.avail_out = (uInt)output_chunk;
        before = stream.avail_out;
        status = deflate(&stream, Z_FINISH);
        output_cursor += (size_t)(before - stream.avail_out);
        if (status != Z_OK && status != Z_STREAM_END) {
            goto finished;
        }
    } while (status != Z_STREAM_END);
    success = true;

finished:
    if (initialized) {
        (void)deflateEnd(&stream);
    }
    if (!success) {
        free(output);
        return false;
    }
    *destination = output;
    *destination_len = output_cursor;
    return true;
}

static void
fb_human_bytes(size_t size, char destination[48])
{
    static const char *const units[] = {"B", "KiB", "MiB", "GiB"};
    size_t unit = 0u;
    size_t divisor = 1u;

    while (unit + 1u < FB_ARRAY_LEN(units) && size / divisor >= 1024u &&
           divisor <= SIZE_MAX / 1024u) {
        divisor *= 1024u;
        ++unit;
    }
    if (unit == 0u) {
        (void)snprintf(destination, 48u, "%zu B", size);
    } else {
        size_t whole = size / divisor;
        const size_t remainder = size % divisor;
        size_t tenth = (remainder * 10u + divisor / 2u) / divisor;
        if (tenth == 10u) {
            ++whole;
            tenth = 0u;
        }
        (void)snprintf(destination, 48u, "%zu.%zu %s",
                       whole, tenth, units[unit]);
    }
}

static bool
fb_job_plan_slice(size_t *bytes, fb_slice value, bool terminate)
{
    size_t amount = value.len;

    if (!fb_slice_usable(value) ||
        (terminate && !fb_size_add(amount, 1u, &amount))) {
        return false;
    }
    return fb_size_add(*bytes, amount, bytes);
}

static bool
fb_make_job_plan(fb_notify_kind kind,
                 fb_slice origin_path,
                 fb_slice reason,
                 fb_slice detail,
                 const fb_upstream_response *response,
                 fb_job_plan *plan)
{
    size_t bytes = sizeof(fb_notifier_job);
    size_t history_bytes = 0u;
    size_t gzip_bytes = 0u;
    size_t index;

    if (!fb_job_plan_slice(&bytes, origin_path, true) ||
        !fb_job_plan_slice(&bytes, reason, true) ||
        !fb_job_plan_slice(&bytes, detail, true)) {
        return false;
    }
    if (response != NULL) {
        if (!fb_slice_usable(response->url) ||
            !fb_slice_usable(response->content_type) ||
            !fb_slice_usable(response->body) ||
            (response->history_count != 0u && response->history == NULL) ||
            !fb_size_mul(response->history_count, sizeof(fb_job_history),
                         &history_bytes) ||
            !fb_size_add(bytes, history_bytes, &bytes) ||
            !fb_job_plan_slice(&bytes, response->url, true) ||
            !fb_job_plan_slice(&bytes, response->content_type, true) ||
            !fb_job_plan_slice(&bytes, response->body, false)) {
            return false;
        }
        for (index = 0u; index < response->history_count; ++index) {
            if (!fb_job_plan_slice(&bytes,
                    response->history[index].effective_url, true)) {
                return false;
            }
        }
        if (kind == FB_NOTIFY_RESTRICTED &&
            response->body.len > FB_RESTRICTED_GZIP_THRESHOLD &&
            !fb_gzip_capacity(response->body.len, &gzip_bytes)) {
            return false;
        }
    }
    plan->allocation_bytes = bytes;
    return fb_size_add(bytes, gzip_bytes, &plan->budget_bytes);
}

static fb_owned_slice
fb_job_copy_slice(char **cursor, fb_slice source, bool terminate)
{
    fb_owned_slice result;

    result.ptr = *cursor;
    result.len = source.len;
    if (source.len != 0u) {
        memcpy(*cursor, source.ptr, source.len);
        *cursor += source.len;
    }
    if (terminate) {
        *(*cursor)++ = '\0';
    }
    return result;
}

static fb_notifier_job *
fb_job_create(fb_notify_kind kind,
              fb_slice origin_path,
              fb_slice reason,
              fb_slice detail,
              const fb_upstream_response *response,
              const fb_job_plan *plan)
{
    fb_notifier_job *job = malloc(plan->allocation_bytes);
    char *cursor;
    size_t index;

    if (job == NULL) {
        return NULL;
    }
    memset(job, 0, sizeof(*job));
    job->kind = kind;
    job->allocation_bytes = plan->allocation_bytes;
    job->budget_bytes = plan->budget_bytes;
    (void)clock_gettime(CLOCK_REALTIME, &job->created_at);
    job->history = (fb_job_history *)(job + 1);
    job->history_count = response == NULL ? 0u : response->history_count;
    if (job->history_count != 0u) {
        memset(job->history, 0, job->history_count * sizeof(*job->history));
    }
    cursor = (char *)(job->history + job->history_count);
    job->origin_path = fb_job_copy_slice(&cursor, origin_path, true);
    job->reason = fb_job_copy_slice(&cursor, reason, true);
    job->detail = fb_job_copy_slice(&cursor, detail, true);
    if (response != NULL) {
        job->has_response = true;
        job->response_status = response->status;
        job->response_url = fb_job_copy_slice(&cursor, response->url, true);
        job->content_type = fb_job_copy_slice(&cursor,
                                              response->content_type, true);
        job->body = fb_job_copy_slice(&cursor, response->body, false);
        for (index = 0u; index < response->history_count; ++index) {
            job->history[index].status = response->history[index].status;
            job->history[index].url = fb_job_copy_slice(
                &cursor, response->history[index].effective_url, true);
        }
    }
    return job;
}

static size_t
fb_origin_text(fb_owned_slice origin,
               char *destination,
               size_t capacity,
               size_t limit)
{
    static const char prefix[] = "https://www.facebook.com/";
    fb_fixed_text output;
    char clean[4097];
    size_t clean_len;
    size_t start = 0u;
    size_t remaining;

    fb_fixed_init(&output, destination, capacity);
    if (capacity == 0u || limit == 0u) {
        return 0u;
    }
    if (fb_origin_is_absolute(origin)) {
        return fb_clean_text(destination, capacity, origin.ptr, origin.len,
                             limit, false);
    }
    if (!fb_fixed_append_cstr(&output, prefix)) {
        return output.len;
    }
    while (start < origin.len && origin.ptr[start] == '/') {
        ++start;
    }
    remaining = limit > output.len ? limit - output.len : 0u;
    clean_len = fb_clean_text(clean, sizeof(clean),
                              origin.ptr == NULL ? "" : origin.ptr + start,
                              origin.len - start, remaining, false);
    (void)fb_fixed_append_bytes(&output, clean, clean_len);
    return output.len;
}

static size_t
fb_display_path_text(fb_owned_slice origin,
                     char *destination,
                     size_t capacity,
                     size_t limit)
{
    fb_slice path = fb_url_path(fb_slice_make(origin.ptr, origin.len));
    fb_fixed_text output;
    char clean[2049];
    size_t clean_len;

    while (path.len != 0u && path.ptr[0] == '/') {
        ++path.ptr;
        --path.len;
    }
    fb_fixed_init(&output, destination, capacity);
    if (limit == 0u || !fb_fixed_append_cstr(&output, "/")) {
        return output.len;
    }
    clean_len = fb_clean_text(clean, sizeof(clean), path.ptr, path.len,
                              limit - 1u, false);
    (void)fb_fixed_append_bytes(&output, clean, clean_len);
    return output.len;
}

static bool
fb_build_dump_json(const fb_notifier_job *job,
                   const char *filename,
                   char **json,
                   size_t *json_len)
{
    fb_heap_text output = {0};
    char display_path[1201];
    char origin[2201];
    char description[3601];
    char filename_value[FB_NOTIFIER_FILENAME_LIMIT + 3u];
    char response_size[64];
    char final_url[1028];
    char status[48];
    fb_fixed_text description_output;
    fb_fixed_text filename_output;
    size_t display_len;
    size_t origin_len;
    size_t final_url_len;
    bool first = true;

    *json = NULL;
    *json_len = 0u;
    display_len = fb_display_path_text(job->origin_path, display_path,
                                       sizeof(display_path), 1000u);
    origin_len = fb_origin_text(job->origin_path, origin, sizeof(origin), 2000u);
    fb_fixed_init(&description_output, description, sizeof(description));
    if (!fb_fixed_append_cstr(&description_output, "\xf0\x9f\x94\x97 [`") ||
        !fb_fixed_append_bytes(&description_output, display_path, display_len) ||
        !fb_fixed_append_cstr(&description_output, "](") ||
        !fb_fixed_append_bytes(&description_output, origin, origin_len) ||
        !fb_fixed_append_cstr(&description_output,
                              ")\n\xf0\x9f\x93\x8b Manual dump requested by user")) {
        goto failed;
    }
    fb_fixed_init(&filename_output, filename_value, sizeof(filename_value));
    if (!fb_fixed_append_cstr(&filename_output, "`") ||
        !fb_fixed_append_cstr(&filename_output, filename) ||
        !fb_fixed_append_cstr(&filename_output, "`")) {
        goto failed;
    }
    (void)snprintf(response_size, sizeof(response_size), "%zu bytes",
                   job->body.len);
    final_url_len = fb_clean_text(final_url, sizeof(final_url),
        job->response_url.len == 0u ? origin : job->response_url.ptr,
        job->response_url.len == 0u ? origin_len : job->response_url.len,
        1024u, false);
    (void)snprintf(status, sizeof(status), "%ld", job->response_status);

    if (!fb_heap_append_cstr(&output, "{\"embeds\":[{\"title\":") ||
        !fb_json_string(&output, "manual dump report",
                        sizeof("manual dump report") - 1u) ||
        !fb_heap_append_cstr(&output, ",\"description\":") ||
        !fb_json_string(&output, description, description_output.len) ||
        !fb_heap_append_cstr(&output,
                             ",\"color\":3447003,\"fields\":[") ||
        !fb_json_field(&output, &first, "Attached Payload", filename_value,
                       filename_output.len, true) ||
        !fb_json_field(&output, &first, "Response Size", response_size,
                       strlen(response_size), true) ||
        !fb_json_field(&output, &first, "Final URL", final_url,
                       final_url_len, true) ||
        !fb_json_field(&output, &first, "Status", status, strlen(status), true) ||
        !fb_heap_append_cstr(&output, "]}]}")) {
        goto failed;
    }
    *json = output.data;
    *json_len = output.len;
    return true;

failed:
    free(output.data);
    return false;
}

static const char *
fb_restricted_title(fb_owned_slice reason)
{
    if (fb_slice_equal_literal(reason, "login_wall")) {
        return "Facebook login wall detected";
    }
    if (fb_slice_equal_literal(reason, "private_group_post_unavailable")) {
        return "Restricted Facebook page detected";
    }
    return "Facebook content unavailable or restricted";
}

static void
fb_iso_timestamp(struct timespec created_at, char destination[32])
{
    struct tm utc;
    time_t seconds = created_at.tv_sec;

    if (gmtime_r(&seconds, &utc) == NULL ||
        strftime(destination, 32u, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0u) {
        memcpy(destination, "1970-01-01T00:00:00Z",
               sizeof("1970-01-01T00:00:00Z"));
    }
}

static size_t
fb_redirect_chain(const fb_notifier_job *job,
                  char *destination,
                  size_t capacity)
{
    fb_fixed_text output;
    size_t index;

    fb_fixed_init(&output, destination, capacity);
    for (index = 0u; index <= job->history_count; ++index) {
        const long status = index < job->history_count
            ? job->history[index].status : job->response_status;
        const fb_owned_slice url = index < job->history_count
            ? job->history[index].url : job->response_url;
        char status_text[48];
        char clean_url[854];
        size_t clean_len;

        if (index != 0u && !fb_fixed_append_cstr(&output, "\n")) {
            break;
        }
        (void)snprintf(status_text, sizeof(status_text), "`%ld` ", status);
        if (!fb_fixed_append_cstr(&output, status_text)) {
            break;
        }
        clean_len = fb_clean_text(clean_url, sizeof(clean_url), url.ptr, url.len,
                                  850u, false);
        if (!fb_fixed_append_bytes(&output, clean_url, clean_len)) {
            break;
        }
    }
    if (output.truncated && output.capacity >= 4u) {
        static const char ellipsis[] = "\xe2\x80\xa6";
        size_t cut = output.capacity - 1u - (sizeof(ellipsis) - 1u);
        if (cut > output.len) {
            cut = output.len;
        }
        while (cut > 0u &&
               (((unsigned char)output.data[cut] & 0xc0u) == 0x80u)) {
            --cut;
        }
        output.len = cut;
        memcpy(output.data + output.len, ellipsis, sizeof(ellipsis) - 1u);
        output.len += sizeof(ellipsis) - 1u;
        output.data[output.len] = '\0';
    }
    return output.len;
}

static bool
fb_build_restricted_json(const fb_notifier_job *job,
                         char **json,
                         size_t *json_len)
{
    fb_heap_text output = {0};
    char description[1504];
    char timestamp[32];
    char origin_url[2049];
    char origin_field[904];
    char reason_clean[124];
    char reason_value[128];
    char page_type_storage[128];
    char page_type_value[136];
    char upstream[384];
    char final_url[904];
    char redirect_chain[901];
    char redirect_name[64];
    char human_size[48];
    char content_type[254];
    const char *page_type;
    size_t description_len;
    size_t origin_total;
    size_t origin_field_len;
    size_t reason_len;
    size_t page_type_len;
    size_t final_url_len;
    size_t redirect_len;
    bool have_embed_url;
    bool first = true;

    *json = NULL;
    *json_len = 0u;
    description_len = fb_clean_text(description, sizeof(description),
                                    job->detail.ptr, job->detail.len,
                                    1500u, true);
    fb_iso_timestamp(job->created_at, timestamp);
    origin_total = fb_origin_url_length(job->origin_path);
    have_embed_url = origin_total <= 2048u &&
        fb_write_origin_url(job->origin_path, origin_url, sizeof(origin_url), NULL);
    origin_field_len = fb_origin_text(job->origin_path, origin_field,
                                      sizeof(origin_field), 900u);
    reason_len = fb_clean_text(reason_clean, sizeof(reason_clean),
                               job->reason.ptr, job->reason.len, 120u, false);
    reason_value[0] = '`';
    memcpy(reason_value + 1u, reason_clean, reason_len);
    reason_value[reason_len + 1u] = '`';
    reason_value[reason_len + 2u] = '\0';
    page_type = fb_restricted_page_type(job, page_type_storage,
                                        sizeof(page_type_storage));
    page_type_len = strlen(page_type);
    page_type_value[0] = '`';
    memcpy(page_type_value + 1u, page_type, page_type_len);
    page_type_value[page_type_len + 1u] = '`';
    page_type_value[page_type_len + 2u] = '\0';

    if (!fb_heap_append_cstr(&output, "{\"embeds\":[{\"title\":") ||
        !fb_json_string(&output, fb_restricted_title(job->reason),
                        strlen(fb_restricted_title(job->reason))) ||
        !fb_heap_append_cstr(&output, ",\"description\":") ||
        !fb_json_string(&output, description, description_len) ||
        !fb_heap_append_cstr(&output, ",\"color\":15548997") ||
        (have_embed_url &&
         (!fb_heap_append_cstr(&output, ",\"url\":") ||
          !fb_json_string(&output, origin_url, origin_total))) ||
        !fb_heap_append_cstr(&output, ",\"timestamp\":") ||
        !fb_json_string(&output, timestamp, strlen(timestamp)) ||
        !fb_heap_append_cstr(&output, ",\"footer\":{\"text\":") ||
        !fb_json_string(&output,
                        "facebed notifier \xe2\x80\xa2 exact upstream response attached",
                        sizeof("facebed notifier \xe2\x80\xa2 exact upstream response attached") - 1u) ||
        !fb_heap_append_cstr(&output, "},\"fields\":[") ||
        !fb_json_field(&output, &first, "Detection", reason_value,
                       reason_len + 2u, true) ||
        !fb_json_field(&output, &first, "Page type", page_type_value,
                       page_type_len + 2u, true) ||
        !fb_json_field(&output, &first, "Origin URL", origin_field,
                       origin_field_len, false)) {
        goto failed;
    }
    if (!job->has_response) {
        static const char unavailable[] =
            "No body-bearing upstream response was captured.";
        if (!fb_json_field(&output, &first, "Upstream response", unavailable,
                           sizeof(unavailable) - 1u, false)) {
            goto failed;
        }
    } else {
        if (job->content_type.len != 0u) {
            (void)fb_clean_text(content_type, sizeof(content_type),
                                job->content_type.ptr, job->content_type.len,
                                250u, false);
        }
        if (job->content_type.len == 0u) {
            memcpy(content_type, "unknown", sizeof("unknown"));
        }
        fb_human_bytes(job->body.len, human_size);
        (void)snprintf(upstream, sizeof(upstream), "HTTP `%ld` \xe2\x80\xa2 `%s` \xe2\x80\xa2 `%s`",
                       job->response_status, content_type, human_size);
        if (!fb_json_field(&output, &first, "Upstream response", upstream,
                           strlen(upstream), false)) {
            goto failed;
        }
        final_url_len = job->response_url.len == 0u
            ? origin_field_len
            : fb_clean_text(final_url, sizeof(final_url), job->response_url.ptr,
                            job->response_url.len, 900u, false);
        if (job->response_url.len == 0u) {
            memcpy(final_url, origin_field, origin_field_len + 1u);
        }
        if (!fb_json_field(&output, &first, "Final upstream URL", final_url,
                           final_url_len, false)) {
            goto failed;
        }
        if (job->history_count != 0u) {
            redirect_len = fb_redirect_chain(job, redirect_chain,
                                             sizeof(redirect_chain));
            (void)snprintf(redirect_name, sizeof(redirect_name),
                           "Redirect chain (%zu hop(s))", job->history_count);
            if (!fb_json_field(&output, &first, redirect_name, redirect_chain,
                               redirect_len, false)) {
                goto failed;
            }
        }
    }
    if (!fb_heap_append_cstr(&output, "]}]}")) {
        goto failed;
    }
    *json = output.data;
    *json_len = output.len;
    return true;

failed:
    free(output.data);
    return false;
}

static size_t
fb_curl_write(char *bytes, size_t size, size_t count, void *context)
{
    fb_curl_response *response = context;
    size_t length;
    size_t available;
    size_t copied;

    if (size != 0u && count > SIZE_MAX / size) {
        return 0u;
    }
    length = size * count;
    available = FB_NOTIFIER_RESPONSE_LIMIT - response->body_len;
    copied = length < available ? length : available;
    if (copied != 0u) {
        memcpy(response->body + response->body_len, bytes, copied);
        response->body_len += copied;
        response->body[response->body_len] = '\0';
    }
    if (copied != length) {
        response->body_truncated = true;
    }
    return length;
}

static void
fb_curl_response_reset(fb_curl_response *response)
{
    response->body_len = 0u;
    response->body_truncated = false;
    response->via = false;
    response->retry_after_len = 0u;
    response->body[0] = '\0';
    response->retry_after[0] = '\0';
}

static size_t
fb_curl_header(char *bytes, size_t size, size_t count, void *context)
{
    fb_curl_response *response = context;
    size_t length;

    if (size != 0u && count > SIZE_MAX / size) {
        return 0u;
    }
    length = size * count;
    if (fb_ascii_prefix_ci(bytes, length, "Via:")) {
        response->via = true;
    } else if (fb_ascii_prefix_ci(bytes, length, "Retry-After:")) {
        size_t start = sizeof("Retry-After:") - 1u;
        size_t end = length;
        size_t copied;
        while (start < end && fb_is_ascii_space((unsigned char)bytes[start])) {
            ++start;
        }
        while (end > start && fb_is_ascii_space((unsigned char)bytes[end - 1u])) {
            --end;
        }
        copied = end - start;
        if (copied >= sizeof(response->retry_after)) {
            copied = sizeof(response->retry_after) - 1u;
        }
        if (copied != 0u) {
            memcpy(response->retry_after, bytes + start, copied);
        }
        response->retry_after[copied] = '\0';
        response->retry_after_len = copied;
    }
    return length;
}

static size_t
fb_mime_read(char *destination, size_t size, size_t count, void *context)
{
    fb_mime_stream *stream = context;
    size_t requested;
    size_t remaining;
    size_t copied;

    if (size != 0u && count > SIZE_MAX / size) {
        return CURL_READFUNC_ABORT;
    }
    requested = size * count;
    remaining = stream->len - stream->position;
    copied = requested < remaining ? requested : remaining;
    if (copied != 0u) {
        memcpy(destination, stream->data + stream->position, copied);
        stream->position += copied;
    }
    return copied;
}

static int
fb_mime_seek(void *context, curl_off_t offset, int origin)
{
    fb_mime_stream *stream = context;

    if (origin != SEEK_SET || offset < 0 ||
        (uintmax_t)offset > (uintmax_t)stream->len) {
        return CURL_SEEKFUNC_CANTSEEK;
    }
    stream->position = (size_t)offset;
    return CURL_SEEKFUNC_OK;
}

static bool
fb_curl_off_from_size(size_t value, curl_off_t *converted)
{
    const curl_off_t result = (curl_off_t)value;
    if (result < 0 || (size_t)result != value) {
        return false;
    }
    *converted = result;
    return true;
}

static bool
fb_parse_seconds_ms(const char *text, size_t length, uint64_t *milliseconds)
{
    size_t cursor = 0u;
    uint64_t seconds = 0u;
    uint64_t fraction = 0u;
    unsigned fraction_digits = 0u;
    bool saw_digit = false;
    bool round_up = false;
    bool quoted = false;

    while (cursor < length && fb_is_ascii_space((unsigned char)text[cursor])) {
        ++cursor;
    }
    if (cursor < length && text[cursor] == '"') {
        quoted = true;
        ++cursor;
    }
    while (cursor < length && text[cursor] >= '0' && text[cursor] <= '9') {
        const unsigned digit = (unsigned)(text[cursor] - '0');
        if (seconds > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        seconds = seconds * 10u + digit;
        saw_digit = true;
        ++cursor;
    }
    if (cursor < length && text[cursor] == '.') {
        ++cursor;
        while (cursor < length && text[cursor] >= '0' && text[cursor] <= '9') {
            const unsigned digit = (unsigned)(text[cursor] - '0');
            if (fraction_digits < 3u) {
                fraction = fraction * 10u + digit;
                ++fraction_digits;
            } else if (digit != 0u) {
                round_up = true;
            }
            saw_digit = true;
            ++cursor;
        }
    }
    while (fraction_digits < 3u) {
        fraction *= 10u;
        ++fraction_digits;
    }
    if (quoted && cursor < length && text[cursor] == '"') {
        ++cursor;
    }
    while (cursor < length && fb_is_ascii_space((unsigned char)text[cursor])) {
        ++cursor;
    }
    if (!saw_digit || cursor != length || seconds > UINT64_MAX / 1000u ||
        fraction > UINT64_MAX - seconds * 1000u) {
        return false;
    }
    *milliseconds = seconds * 1000u + fraction;
    if (round_up && *milliseconds != UINT64_MAX) {
        ++*milliseconds;
    }
    return true;
}

static bool
fb_json_retry_delay(const fb_curl_response *response, uint64_t *milliseconds)
{
    static const char key[] = "\"retry_after\"";
    size_t index;

    for (index = 0u; index + sizeof(key) - 1u <= response->body_len; ++index) {
        size_t cursor;
        size_t start;
        bool quoted;
        if (memcmp(response->body + index, key, sizeof(key) - 1u) != 0) {
            continue;
        }
        cursor = index + sizeof(key) - 1u;
        while (cursor < response->body_len &&
               fb_is_ascii_space((unsigned char)response->body[cursor])) {
            ++cursor;
        }
        if (cursor == response->body_len || response->body[cursor] != ':') {
            continue;
        }
        ++cursor;
        while (cursor < response->body_len &&
               fb_is_ascii_space((unsigned char)response->body[cursor])) {
            ++cursor;
        }
        start = cursor;
        quoted = cursor < response->body_len && response->body[cursor] == '"';
        if (quoted) {
            ++cursor;
        }
        while (cursor < response->body_len &&
               ((response->body[cursor] >= '0' && response->body[cursor] <= '9') ||
                response->body[cursor] == '.')) {
            ++cursor;
        }
        if (quoted && cursor < response->body_len &&
            response->body[cursor] == '"') {
            ++cursor;
        }
        if (fb_parse_seconds_ms(response->body + start, cursor - start,
                                milliseconds)) {
            return true;
        }
    }
    return response->retry_after_len != 0u &&
           fb_parse_seconds_ms(response->retry_after,
                               response->retry_after_len, milliseconds);
}

static bool
fb_curl_header_add(struct curl_slist **headers, const char *header)
{
    struct curl_slist *grown = curl_slist_append(*headers, header);
    if (grown == NULL) {
        return false;
    }
    *headers = grown;
    return true;
}

static int
fb_curl_progress(void *context,
                 curl_off_t download_total,
                 curl_off_t download_now,
                 curl_off_t upload_total,
                 curl_off_t upload_now)
{
    fb_notifier *notifier = context;

    (void)download_total;
    (void)download_now;
    (void)upload_total;
    (void)upload_now;
    return fb_notifier_shutdown_expired(notifier) ? 1 : 0;
}

static fb_delivery_result
fb_post_webhook(fb_notifier *notifier,
                CURL *easy,
                const char *json,
                size_t json_len,
                const unsigned char *attachment,
                size_t attachment_len,
                const char *filename,
                const char *attachment_type)
{
    fb_delivery_result result = {false, 0u, 0u};
    struct curl_slist *headers = NULL;
    curl_mime *mime = NULL;
    curl_mimepart *part;
    fb_mime_stream stream;
    fb_curl_response response;
    curl_off_t json_size;
    curl_off_t attachment_size = 0;
    CURLcode curl_status;
    long http_status = 0L;
    unsigned retries = 0u;

    if (!fb_curl_off_from_size(json_len, &json_size) ||
        (attachment != NULL &&
         !fb_curl_off_from_size(attachment_len, &attachment_size))) {
        return result;
    }
    curl_easy_reset(easy);
    if (!fb_curl_header_add(&headers, "Accept: application/json") ||
        !fb_curl_header_add(&headers, "Expect:")) {
        goto finished;
    }
#define FB_CURL_OPTION(option, value)                                      \
    do {                                                                   \
        if (curl_easy_setopt(easy, (option), (value)) != CURLE_OK) {       \
            goto finished;                                                 \
        }                                                                  \
    } while (0)
    FB_CURL_OPTION(CURLOPT_URL, notifier->webhook);
    FB_CURL_OPTION(CURLOPT_HTTPHEADER, headers);
    FB_CURL_OPTION(CURLOPT_USERAGENT, "fastbed-notifier/1");
    FB_CURL_OPTION(CURLOPT_ACCEPT_ENCODING, "");
    FB_CURL_OPTION(CURLOPT_NOSIGNAL, 1L);
    FB_CURL_OPTION(CURLOPT_FOLLOWLOCATION, 0L);
    FB_CURL_OPTION(CURLOPT_MAXREDIRS, 0L);
    FB_CURL_OPTION(CURLOPT_CONNECTTIMEOUT_MS, FB_NOTIFIER_CONNECT_TIMEOUT_MS);
    FB_CURL_OPTION(CURLOPT_TIMEOUT_MS, FB_NOTIFIER_HTTP_TIMEOUT_MS);
    FB_CURL_OPTION(CURLOPT_TCP_KEEPALIVE, 1L);
    FB_CURL_OPTION(CURLOPT_TCP_NODELAY, 1L);
    FB_CURL_OPTION(CURLOPT_SSL_VERIFYPEER, 1L);
    FB_CURL_OPTION(CURLOPT_SSL_VERIFYHOST, 2L);
    /*
     * Discord uploads are not browser-impersonated traffic. Keep their
     * established HTTP/1.1 transport isolated from the Facebook-facing H2
     * fingerprint and its connection/priority state.
     */
    FB_CURL_OPTION(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    FB_CURL_OPTION(CURLOPT_WRITEFUNCTION, fb_curl_write);
    FB_CURL_OPTION(CURLOPT_HEADERFUNCTION, fb_curl_header);
    FB_CURL_OPTION(CURLOPT_NOPROGRESS, 0L);
    FB_CURL_OPTION(CURLOPT_XFERINFOFUNCTION, fb_curl_progress);
    FB_CURL_OPTION(CURLOPT_XFERINFODATA, notifier);
    if (attachment != NULL) {
        mime = curl_mime_init(easy);
        if (mime == NULL) {
            goto finished;
        }
        part = curl_mime_addpart(mime);
        if (part == NULL || curl_mime_name(part, "payload_json") != CURLE_OK ||
            curl_mime_type(part, "application/json") != CURLE_OK ||
            curl_mime_data(part, json, json_len) != CURLE_OK) {
            goto finished;
        }
        part = curl_mime_addpart(mime);
        stream.data = attachment;
        stream.len = attachment_len;
        stream.position = 0u;
        if (part == NULL || curl_mime_name(part, "files[0]") != CURLE_OK ||
            curl_mime_filename(part, filename) != CURLE_OK ||
            curl_mime_type(part, attachment_type) != CURLE_OK ||
            curl_mime_data_cb(part, attachment_size, fb_mime_read,
                              fb_mime_seek, NULL, &stream) != CURLE_OK) {
            goto finished;
        }
        FB_CURL_OPTION(CURLOPT_MIMEPOST, mime);
    } else {
        if (!fb_curl_header_add(&headers, "Content-Type: application/json")) {
            goto finished;
        }
        FB_CURL_OPTION(CURLOPT_HTTPHEADER, headers);
        FB_CURL_OPTION(CURLOPT_POST, 1L);
        FB_CURL_OPTION(CURLOPT_POSTFIELDS, json);
        FB_CURL_OPTION(CURLOPT_POSTFIELDSIZE_LARGE, json_size);
    }
    for (;;) {
        uint64_t delay_ms;

        if (fb_notifier_shutdown_expired(notifier)) {
            break;
        }
        fb_curl_response_reset(&response);
        if (attachment != NULL) {
            stream.position = 0u;
        }
        FB_CURL_OPTION(CURLOPT_WRITEDATA, &response);
        FB_CURL_OPTION(CURLOPT_HEADERDATA, &response);
        curl_status = curl_easy_perform(easy);
        if (curl_status != CURLE_OK ||
            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_status) !=
                CURLE_OK) {
            break;
        }
        if (http_status == 200L || http_status == 204L) {
            result.delivered = true;
            break;
        }
        if (http_status != 429L) {
            break;
        }
        fb_counter_add(&result.rate_limited, 1u);
        if (!response.via || retries >= notifier->options.max_rate_limit_retries ||
            !fb_json_retry_delay(&response, &delay_ms) ||
            delay_ms > UINT64_MAX - 150u) {
            break;
        }
        delay_ms += 150u;
        if (delay_ms > notifier->options.max_rate_limit_delay_ms) {
            break;
        }
        if (!fb_notifier_wait_milliseconds(notifier, delay_ms)) {
            break;
        }
        ++retries;
        fb_counter_add(&result.retries, 1u);
    }

finished:
    /* Drop libcurl's internal URL copy while retaining its connection cache. */
    curl_easy_reset(easy);
    curl_mime_free(mime);
    curl_slist_free_all(headers);
#undef FB_CURL_OPTION
    return result;
}

static fb_delivery_result
fb_deliver_job(fb_notifier *notifier, CURL *easy, const fb_notifier_job *job)
{
    fb_delivery_result result = {false, 0u, 0u};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char *compressed = NULL;
    size_t compressed_len = 0u;
    const unsigned char *attachment = NULL;
    size_t attachment_len = 0u;
    const char *attachment_type = NULL;
    char filename[FB_NOTIFIER_FILENAME_LIMIT];
    char *json = NULL;
    size_t json_len = 0u;
    bool compressed_attachment = false;

    if (fb_notifier_shutdown_expired(notifier)) {
        goto finished;
    }
    if (job->has_response) {
        attachment = (const unsigned char *)job->body.ptr;
        attachment_len = job->body.len;
        if (job->kind == FB_NOTIFY_RESTRICTED) {
            if (SHA256(attachment, attachment_len, digest) == NULL) {
                goto finished;
            }
            if (attachment_len > FB_RESTRICTED_GZIP_THRESHOLD) {
                if (!fb_gzip_level6(attachment, attachment_len,
                                    &compressed, &compressed_len)) {
                    goto finished;
                }
                attachment = compressed;
                attachment_len = compressed_len;
                compressed_attachment = true;
            }
            if (!fb_restricted_filename(job, digest, compressed_attachment,
                                        filename)) {
                goto finished;
            }
            attachment_type = compressed_attachment
                ? "application/gzip" : "text/html";
        } else {
            if (!fb_dump_filename(job, filename)) {
                goto finished;
            }
            attachment_type = "text/html";
        }
    }
    if (job->kind == FB_NOTIFY_DUMP) {
        if (!job->has_response ||
            !fb_build_dump_json(job, filename, &json, &json_len)) {
            goto finished;
        }
    } else if (!fb_build_restricted_json(job, &json, &json_len)) {
        goto finished;
    }
    if (fb_notifier_shutdown_expired(notifier)) {
        goto finished;
    }
    result = fb_post_webhook(notifier, easy, json, json_len,
                             attachment, attachment_len,
                             job->has_response ? filename : NULL,
                             attachment_type);

finished:
    free(json);
    free(compressed);
    return result;
}

static void *
fb_notifier_worker_main(void *argument)
{
    fb_notifier_worker *worker = argument;
    fb_notifier *notifier = worker->notifier;

    for (;;) {
        fb_notifier_job *job;
        fb_delivery_result delivery = {false, 0u, 0u};
        size_t budget_bytes;

        (void)pthread_mutex_lock(&notifier->mutex);
        while (notifier->head == NULL &&
               (notifier->accepting || notifier->reservations != 0u)) {
            (void)pthread_cond_wait(&notifier->condition, &notifier->mutex);
        }
        if (notifier->head == NULL) {
            (void)pthread_mutex_unlock(&notifier->mutex);
            break;
        }
        job = notifier->head;
        notifier->head = job->next;
        if (notifier->head == NULL) {
            notifier->tail = NULL;
        }
        --notifier->queued_jobs;
        ++notifier->active_jobs;
        (void)pthread_mutex_unlock(&notifier->mutex);

        budget_bytes = job->budget_bytes;
        if (!fb_notifier_shutdown_expired(notifier)) {
            delivery = fb_deliver_job(notifier, worker->easy, job);
        }
        free(job);

        (void)pthread_mutex_lock(&notifier->mutex);
        --notifier->active_jobs;
        --notifier->pending_jobs;
        notifier->pending_bytes -= budget_bytes;
        fb_counter_add(&notifier->rate_limited, delivery.rate_limited);
        fb_counter_add(&notifier->rate_limit_retries, delivery.retries);
        if (delivery.delivered) {
            fb_counter_add(&notifier->delivered, 1u);
        } else {
            fb_counter_add(&notifier->delivery_failed, 1u);
        }
        (void)pthread_cond_broadcast(&notifier->condition);
        (void)pthread_mutex_unlock(&notifier->mutex);
    }
    return NULL;
}

fb_notifier_options
fb_notifier_default_options(void)
{
    fb_notifier_options options;
    options.worker_threads = 1u;
    options.max_pending_jobs = 64u;
    options.max_pending_bytes = (size_t)128u * 1024u * 1024u;
    options.max_rate_limit_retries = 8u;
    options.max_rate_limit_delay_ms = UINT64_C(5) * 60u * 1000u;
    options.shutdown_grace_ms = UINT64_C(30) * 1000u;
    return options;
}

static bool
fb_webhook_valid(fb_slice webhook)
{
    const size_t prefix_len = sizeof(FB_DISCORD_WEBHOOK_PREFIX) - 1u;
    size_t index;

    if (!fb_slice_usable(webhook) || webhook.len <= prefix_len ||
        memcmp(webhook.ptr, FB_DISCORD_WEBHOOK_PREFIX, prefix_len) != 0) {
        return false;
    }
    for (index = 0u; index < webhook.len; ++index) {
        const unsigned char byte = (unsigned char)webhook.ptr[index];
        if (byte <= 0x20u || byte == 0x7fu) {
            return false;
        }
    }
    return true;
}

static void
fb_notifier_release(fb_notifier *notifier)
{
    size_t index;
    fb_notifier_job *job;

    if (notifier == NULL) {
        return;
    }
    job = notifier->head;
    while (job != NULL) {
        fb_notifier_job *next = job->next;
        free(job);
        job = next;
    }
    for (index = 0u; index < notifier->worker_count; ++index) {
        if (notifier->workers != NULL && notifier->workers[index].easy != NULL) {
            curl_easy_reset(notifier->workers[index].easy);
            curl_easy_cleanup(notifier->workers[index].easy);
        }
    }
    free(notifier->threads);
    free(notifier->workers);
    if (notifier->webhook != NULL) {
        fb_secure_clear(notifier->webhook, notifier->webhook_len + 1u);
        free(notifier->webhook);
    }
    if (notifier->condition_ready) {
        (void)pthread_cond_destroy(&notifier->condition);
    }
    if (notifier->mutex_ready) {
        (void)pthread_mutex_destroy(&notifier->mutex);
    }
    fb_secure_clear(notifier, sizeof(*notifier));
    free(notifier);
}

bool
fb_notifier_init(fb_notifier **out,
                 const fb_config *config,
                 const fb_notifier_options *options,
                 char *error,
                 size_t error_capacity)
{
    fb_notifier_options selected = options == NULL
        ? fb_notifier_default_options() : *options;
    fb_slice webhook;
    fb_notifier *notifier = NULL;
    pthread_condattr_t condition_attributes;
    pthread_attr_t worker_attributes;
    long page_size;
    size_t bytes;
    size_t index;

    if (out == NULL || config == NULL) {
        fb_notifier_set_error(error, error_capacity,
                              "invalid notifier configuration");
        return false;
    }
    *out = NULL;
    if (error != NULL && error_capacity != 0u) {
        error[0] = '\0';
    }
    if (selected.worker_threads == 0u ||
        selected.worker_threads > FB_NOTIFIER_MAX_WORKERS ||
        selected.max_pending_jobs == 0u || selected.max_pending_bytes == 0u ||
        selected.shutdown_grace_ms == 0u ||
        selected.shutdown_grace_ms >
            UINT64_C(24) * 60u * 60u * 1000u ||
        (selected.max_rate_limit_retries != 0u &&
         (selected.max_rate_limit_delay_ms == 0u ||
          selected.max_rate_limit_delay_ms >
              UINT64_C(24) * 60u * 60u * 1000u))) {
        fb_notifier_set_error(error, error_capacity,
                              "invalid notifier queue configuration");
        return false;
    }
    notifier = calloc(1u, sizeof(*notifier));
    if (notifier == NULL) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot allocate notifier state");
        return false;
    }
    notifier->options = selected;
    atomic_init(&notifier->shutdown_deadline_ms, 0u);
    if (pthread_mutex_init(&notifier->mutex, NULL) != 0) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot initialize notifier lock");
        fb_notifier_release(notifier);
        return false;
    }
    notifier->mutex_ready = true;
    if (pthread_condattr_init(&condition_attributes) != 0) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot initialize notifier condition attributes");
        fb_notifier_release(notifier);
        return false;
    }
    if (pthread_condattr_setclock(&condition_attributes, CLOCK_MONOTONIC) != 0) {
        (void)pthread_condattr_destroy(&condition_attributes);
        fb_notifier_set_error(error, error_capacity,
                              "cannot select notifier condition clock");
        fb_notifier_release(notifier);
        return false;
    }
    if (pthread_cond_init(&notifier->condition, &condition_attributes) != 0) {
        (void)pthread_condattr_destroy(&condition_attributes);
        fb_notifier_set_error(error, error_capacity,
                              "cannot initialize notifier condition");
        fb_notifier_release(notifier);
        return false;
    }
    (void)pthread_condattr_destroy(&condition_attributes);
    notifier->condition_ready = true;
    webhook = fb_config_notifier_webhook(config);
    if (!fb_webhook_valid(webhook)) {
        *out = notifier;
        return true;
    }
    if (!fb_size_add(webhook.len, 1u, &bytes)) {
        fb_notifier_set_error(error, error_capacity,
                              "notifier secret is too large");
        fb_notifier_release(notifier);
        return false;
    }
    notifier->webhook = malloc(bytes);
    if (notifier->webhook == NULL) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot allocate notifier secret");
        fb_notifier_release(notifier);
        return false;
    }
    memcpy(notifier->webhook, webhook.ptr, webhook.len);
    notifier->webhook[webhook.len] = '\0';
    notifier->webhook_len = webhook.len;
    if (pthread_once(&fb_notifier_curl_once, fb_notifier_curl_init_once) != 0 ||
        fb_notifier_curl_status != CURLE_OK) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot initialize notifier HTTP client");
        fb_notifier_release(notifier);
        return false;
    }
    if (!fb_size_mul((size_t)selected.worker_threads,
                     sizeof(*notifier->threads), &bytes)) {
        fb_notifier_set_error(error, error_capacity,
                              "notifier worker count is too large");
        fb_notifier_release(notifier);
        return false;
    }
    notifier->threads = calloc(1u, bytes);
    if (!fb_size_mul((size_t)selected.worker_threads,
                     sizeof(*notifier->workers), &bytes)) {
        fb_notifier_set_error(error, error_capacity,
                              "notifier worker count is too large");
        fb_notifier_release(notifier);
        return false;
    }
    notifier->workers = calloc(1u, bytes);
    if (notifier->threads == NULL || notifier->workers == NULL) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot allocate notifier workers");
        fb_notifier_release(notifier);
        return false;
    }
    notifier->worker_count = selected.worker_threads;
    for (index = 0u; index < notifier->worker_count; ++index) {
        notifier->workers[index].notifier = notifier;
        notifier->workers[index].easy = curl_easy_init();
        if (notifier->workers[index].easy == NULL) {
            fb_notifier_set_error(error, error_capacity,
                                  "cannot create notifier HTTP client");
            fb_notifier_release(notifier);
            return false;
        }
    }
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (uintmax_t)page_size > (uintmax_t)SIZE_MAX ||
        FB_NOTIFIER_WORKER_STACK_BYTES < (size_t)PTHREAD_STACK_MIN) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot determine notifier worker stack layout");
        fb_notifier_release(notifier);
        return false;
    }
    if (pthread_attr_init(&worker_attributes) != 0) {
        fb_notifier_set_error(error, error_capacity,
                              "cannot initialize notifier worker attributes");
        fb_notifier_release(notifier);
        return false;
    }
    if (pthread_attr_setstacksize(&worker_attributes,
                                  FB_NOTIFIER_WORKER_STACK_BYTES) != 0 ||
        pthread_attr_setguardsize(&worker_attributes, (size_t)page_size) != 0) {
        (void)pthread_attr_destroy(&worker_attributes);
        fb_notifier_set_error(error, error_capacity,
                              "cannot configure notifier worker stack");
        fb_notifier_release(notifier);
        return false;
    }
    notifier->enabled = true;
    notifier->accepting = true;
    for (index = 0u; index < notifier->worker_count; ++index) {
        if (pthread_create(&notifier->threads[index], &worker_attributes,
                           fb_notifier_worker_main,
                           &notifier->workers[index]) != 0) {
            size_t joined;
            (void)pthread_mutex_lock(&notifier->mutex);
            notifier->accepting = false;
            (void)pthread_cond_broadcast(&notifier->condition);
            (void)pthread_mutex_unlock(&notifier->mutex);
            for (joined = 0u; joined < notifier->started_workers; ++joined) {
                (void)pthread_join(notifier->threads[joined], NULL);
            }
            notifier->started_workers = 0u;
            (void)pthread_attr_destroy(&worker_attributes);
            fb_notifier_set_error(error, error_capacity,
                                  "cannot start notifier worker");
            fb_notifier_release(notifier);
            return false;
        }
        ++notifier->started_workers;
    }
    (void)pthread_attr_destroy(&worker_attributes);
    *out = notifier;
    return true;
}

static fb_notifier_enqueue_result
fb_notifier_enqueue(fb_notifier *notifier,
                    fb_notify_kind kind,
                    fb_slice origin_path,
                    fb_slice reason,
                    fb_slice detail,
                    const fb_upstream_response *response)
{
    fb_job_plan plan;
    fb_notifier_job *job;

    if (notifier == NULL) {
        return FB_NOTIFIER_ENQUEUE_INVALID_ARGUMENT;
    }
    if (!notifier->enabled) {
        (void)pthread_mutex_lock(&notifier->mutex);
        fb_counter_add(&notifier->disabled_noops, 1u);
        (void)pthread_mutex_unlock(&notifier->mutex);
        return FB_NOTIFIER_ENQUEUE_DISABLED;
    }
    if ((kind == FB_NOTIFY_DUMP && response == NULL) ||
        !fb_slice_usable(origin_path) || !fb_slice_usable(reason) ||
        !fb_slice_usable(detail) ||
        !fb_make_job_plan(kind, origin_path, reason, detail, response, &plan)) {
        return FB_NOTIFIER_ENQUEUE_INVALID_ARGUMENT;
    }

    (void)pthread_mutex_lock(&notifier->mutex);
    if (!notifier->accepting) {
        fb_counter_add(&notifier->rejected_closed, 1u);
        (void)pthread_mutex_unlock(&notifier->mutex);
        return FB_NOTIFIER_ENQUEUE_CLOSED;
    }
    if (notifier->pending_jobs >= notifier->options.max_pending_jobs ||
        plan.budget_bytes > notifier->options.max_pending_bytes ||
        plan.budget_bytes > notifier->options.max_pending_bytes -
                                notifier->pending_bytes) {
        fb_counter_add(&notifier->rejected_backpressure, 1u);
        (void)pthread_mutex_unlock(&notifier->mutex);
        return FB_NOTIFIER_ENQUEUE_BACKPRESSURE;
    }
    ++notifier->pending_jobs;
    notifier->pending_bytes += plan.budget_bytes;
    ++notifier->reservations;
    (void)pthread_mutex_unlock(&notifier->mutex);

    job = fb_job_create(kind, origin_path, reason, detail, response, &plan);

    (void)pthread_mutex_lock(&notifier->mutex);
    --notifier->reservations;
    if (job == NULL) {
        --notifier->pending_jobs;
        notifier->pending_bytes -= plan.budget_bytes;
        fb_counter_add(&notifier->rejected_no_memory, 1u);
        (void)pthread_cond_broadcast(&notifier->condition);
        (void)pthread_mutex_unlock(&notifier->mutex);
        return FB_NOTIFIER_ENQUEUE_NO_MEMORY;
    }
    if (notifier->tail == NULL) {
        notifier->head = job;
    } else {
        notifier->tail->next = job;
    }
    notifier->tail = job;
    ++notifier->queued_jobs;
    fb_counter_add(&notifier->enqueued, 1u);
    (void)pthread_cond_signal(&notifier->condition);
    (void)pthread_mutex_unlock(&notifier->mutex);
    return FB_NOTIFIER_ENQUEUE_QUEUED;
}

fb_notifier_enqueue_result
fb_notifier_enqueue_dump(fb_notifier *notifier,
                         fb_slice origin_path,
                         const fb_upstream_response *response)
{
    return fb_notifier_enqueue(notifier, FB_NOTIFY_DUMP, origin_path,
                               fb_slice_make(NULL, 0u),
                               fb_slice_make(NULL, 0u), response);
}

fb_notifier_enqueue_result
fb_notifier_enqueue_restricted(fb_notifier *notifier,
                               fb_slice origin_path,
                               fb_slice reason,
                               fb_slice detail,
                               const fb_upstream_response *response)
{
    if (reason.len == 0u && fb_slice_usable(reason)) {
        reason = FB_SLICE_LIT("no_data");
    }
    return fb_notifier_enqueue(notifier, FB_NOTIFY_RESTRICTED, origin_path,
                               reason, detail, response);
}

fb_notifier_stats
fb_notifier_get_stats(fb_notifier *notifier)
{
    fb_notifier_stats stats;

    memset(&stats, 0, sizeof(stats));
    if (notifier == NULL) {
        return stats;
    }
    (void)pthread_mutex_lock(&notifier->mutex);
    stats.enabled = notifier->enabled;
    stats.accepting = notifier->accepting;
    stats.queued_jobs = notifier->queued_jobs;
    stats.active_jobs = notifier->active_jobs;
    stats.pending_jobs = notifier->pending_jobs;
    stats.pending_bytes = notifier->pending_bytes;
    stats.enqueued = notifier->enqueued;
    stats.delivered = notifier->delivered;
    stats.delivery_failed = notifier->delivery_failed;
    stats.rate_limited = notifier->rate_limited;
    stats.rate_limit_retries = notifier->rate_limit_retries;
    stats.rejected_backpressure = notifier->rejected_backpressure;
    stats.rejected_no_memory = notifier->rejected_no_memory;
    stats.rejected_closed = notifier->rejected_closed;
    stats.disabled_noops = notifier->disabled_noops;
    (void)pthread_mutex_unlock(&notifier->mutex);
    return stats;
}

void
fb_notifier_shutdown(fb_notifier *notifier)
{
    size_t index;

    if (notifier == NULL) {
        return;
    }
    if (notifier->enabled) {
        uint64_t now;
        uint64_t deadline = 1u;

        if (fb_monotonic_milliseconds(&now) &&
            notifier->options.shutdown_grace_ms <= UINT64_MAX - now) {
            deadline = now + notifier->options.shutdown_grace_ms;
        }
        (void)pthread_mutex_lock(&notifier->mutex);
        notifier->accepting = false;
        atomic_store_explicit(&notifier->shutdown_deadline_ms, deadline,
                              memory_order_release);
        (void)pthread_cond_broadcast(&notifier->condition);
        (void)pthread_mutex_unlock(&notifier->mutex);
        for (index = 0u; index < notifier->started_workers; ++index) {
            (void)pthread_join(notifier->threads[index], NULL);
        }
        notifier->started_workers = 0u;
    }
    fb_notifier_release(notifier);
}

const char *
fb_notifier_enqueue_result_string(fb_notifier_enqueue_result result)
{
    static const char *const names[] = {
        "queued", "disabled", "backpressure", "closed", "no_memory",
        "invalid_argument",
    };
    const size_t index = (size_t)result;
    return index < FB_ARRAY_LEN(names) ? names[index] : "unknown";
}




