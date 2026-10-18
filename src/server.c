#include "fastbed/server.h"

#include <arpa/inet.h>
#include <microhttpd.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint16_t name_offset;
    uint16_t value_offset;
    uint8_t name_length;
    uint8_t value_length;
    uint8_t flags;
} fb_named_entity;

#include "html_entities_generated.inc"

#if defined(__GNUC__) || defined(__clang__)
#define FB_LOG_NOINLINE __attribute__((noinline))
#else
#define FB_LOG_NOINLINE
#endif

_Static_assert(
    (FB_HTML_ENTITY_BUCKET_COUNT &
     (FB_HTML_ENTITY_BUCKET_COUNT - 1u)) == 0u,
    "HTML entity bucket count must be a power of two");
_Static_assert(FB_HTML_ENTITY_SLOT_COUNT <= UINT16_MAX,
               "HTML entity slot indices must fit generated displacements");

typedef enum {
    FB_REQUEST_SYNC = 0,
    FB_REQUEST_QUEUED,
    FB_REQUEST_RUNNING,
    FB_REQUEST_RESUMED_READY,
    FB_REQUEST_RESUMED_FORCED,
    FB_REQUEST_RESPONSE_QUEUED,
} fb_request_phase;

typedef enum {
    FB_FORCE_NONE = 0,
    FB_FORCE_SHUTDOWN,
    FB_FORCE_QUEUE_TIMEOUT,
    FB_FORCE_REQUEST_TIMEOUT,
} fb_force_reason;

typedef struct fb_connection_request {
    struct fb_server *server;
    struct fb_connection_request *queue_next;
    struct fb_connection_request *async_previous;
    struct fb_connection_request *async_next;
    atomic_uint references;
    atomic_bool cancel_requested;
    fb_arena arena;
    fb_slice raw_target;
    fb_http_request request;
    fb_http_response response;
    struct MHD_Connection *connection;
    struct timespec queue_deadline;
    struct timespec request_deadline;
    fb_request_phase phase;
    fb_force_reason force_reason;
    fb_slice access_method;
    fb_slice access_remote_address;
    fb_slice access_log_title;
    unsigned access_status;
    bool arena_initialized;
    bool target_too_large;
    bool handled;
    bool async_tracked;
    bool resume_releases_job;
    bool request_tracked;
    bool admission_decided;
    bool admitted;
    bool access_started;
    bool access_identity_captured;
    bool response_queued;
} fb_connection_request;

struct fb_server {
    struct MHD_Daemon *daemon;
    fb_server_options options;
    fb_http_handler handler;
    fb_http_should_defer should_defer;
    void *handler_context;
    struct sockaddr_storage address;
    socklen_t address_length;
    uint16_t bound_port;
    pthread_mutex_t work_mutex;
    pthread_cond_t work_available;
    pthread_cond_t state_changed;
    pthread_cond_t deadline_changed;
    bool work_mutex_ready;
    bool work_available_ready;
    bool state_changed_ready;
    bool deadline_changed_ready;
    bool accepting_work;
    bool forcing_work;
    bool workers_stopping;
    bool deadline_worker_stopping;
    pthread_t *workers;
    size_t started_workers;
    pthread_t deadline_worker;
    bool deadline_worker_started;
    fb_connection_request *queue_head;
    fb_connection_request *queue_tail;
    fb_connection_request *async_head;
    size_t queued_work;
    size_t active_work;
    size_t suspended_count;
    size_t resume_inflight;
    size_t request_count;
    bool sendfile_supported;
};

static void *fb_deadline_worker_main(void *opaque);
static void fb_deadline_worker_stop(fb_server *server);
static const struct timespec *fb_request_phase_deadline(
    const fb_connection_request *request);
static fb_force_reason fb_request_timeout_reason(
    const fb_connection_request *request);

static void fb_server_error(char *destination, size_t capacity,
                            const char *format, ...)
    FB_PRINTF_FORMAT(3, 4);
static void fb_server_error(char *destination, size_t capacity,
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

fb_server_options fb_server_default_options(void) {
    fb_server_options options;
    options.host = "0.0.0.0";
    options.port = 9812u;
    options.io_threads = 2u;
    options.worker_threads = 8u;
    options.work_queue_limit = 64u;
    options.connection_limit = 1024u;
    options.per_ip_connection_limit = 64u;
    options.connection_timeout_seconds = 30u;
    options.graceful_shutdown_seconds = 30u;
    options.forced_shutdown_seconds = 5u;
    options.queue_timeout_seconds = 30u;
    options.request_timeout_seconds = 3600u;
    options.request_arena_bytes = (size_t)16u * 1024u;
    options.max_request_target_bytes = (size_t)64u * 1024u;
    return options;
}

static void fb_request_retain(fb_connection_request *request) {
    (void)atomic_fetch_add_explicit(&request->references, 1u,
                                    memory_order_relaxed);
}

static void fb_request_release(fb_connection_request *request) {
    if (request == NULL) {
        return;
    }
    if (atomic_fetch_sub_explicit(&request->references, 1u,
                                  memory_order_acq_rel) != 1u) {
        return;
    }
    if (request->arena_initialized) {
        fb_arena_destroy(&request->arena);
    }
    free(request);
}

static void fb_response_text(fb_http_response *response,
                             unsigned status,
                             const char *text) {
    memset(response, 0, sizeof(*response));
    response->status = status;
    response->body = fb_slice_from_cstr(text);
    response->content_type = FB_SLICE_LIT("text/plain; charset=utf-8");
    response->cache_control = FB_SLICE_LIT("no-store");
}

static struct timespec fb_deadline_after(unsigned seconds) {
    struct timespec deadline = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        return deadline;
    }
    deadline.tv_sec += (time_t)seconds;
    return deadline;
}

static int fb_timespec_compare(const struct timespec *left,
                               const struct timespec *right) {
    if (left->tv_sec != right->tv_sec) {
        return left->tv_sec < right->tv_sec ? -1 : 1;
    }
    if (left->tv_nsec != right->tv_nsec) {
        return left->tv_nsec < right->tv_nsec ? -1 : 1;
    }
    return 0;
}

static bool fb_deadline_expired_at(const struct timespec *deadline,
                                   const struct timespec *now) {
    return (deadline->tv_sec == 0 && deadline->tv_nsec == 0) ||
           fb_timespec_compare(now, deadline) >= 0;
}

static bool fb_deadline_expired(const struct timespec *deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return true;
    }
    return fb_deadline_expired_at(deadline, &now);
}

static void fb_request_track(fb_connection_request *request) {
    fb_server *server = request->server;
    request->request_deadline = fb_deadline_after(
        server->options.request_timeout_seconds);
    (void)pthread_mutex_lock(&server->work_mutex);
    ++server->request_count;
    request->request_tracked = true;
    (void)pthread_mutex_unlock(&server->work_mutex);
}

static void fb_async_link_locked(fb_server *server,
                                 fb_connection_request *request) {
    request->async_previous = NULL;
    request->async_next = server->async_head;
    if (server->async_head != NULL) {
        server->async_head->async_previous = request;
    }
    server->async_head = request;
    request->async_tracked = true;
    ++server->suspended_count;
}

static void fb_async_unlink_locked(fb_server *server,
                                   fb_connection_request *request) {
    if (!request->async_tracked) {
        return;
    }
    if (request->async_previous != NULL) {
        request->async_previous->async_next = request->async_next;
    } else {
        server->async_head = request->async_next;
    }
    if (request->async_next != NULL) {
        request->async_next->async_previous = request->async_previous;
    }
    request->async_previous = NULL;
    request->async_next = NULL;
    request->async_tracked = false;
    if (server->suspended_count != 0u) {
        --server->suspended_count;
    }
}

static void fb_async_prepare_resume_locked(
    fb_server *server,
    fb_connection_request *request,
    fb_request_phase phase,
    bool release_job) {
    fb_async_unlink_locked(server, request);
    request->phase = phase;
    request->resume_releases_job = release_job;
    ++server->resume_inflight;
}

static void fb_async_resume(fb_connection_request *request) {
    fb_server *server = request->server;
    const bool release_job = request->resume_releases_job;
    MHD_resume_connection(request->connection);
    (void)pthread_mutex_lock(&server->work_mutex);
    if (server->resume_inflight != 0u) {
        --server->resume_inflight;
    }
    (void)pthread_cond_signal(&server->state_changed);
    (void)pthread_mutex_unlock(&server->work_mutex);
    if (release_job) {
        fb_request_release(request);
    }
}

static void *fb_application_worker(void *opaque) {
    fb_server *server = opaque;
    for (;;) {
        fb_connection_request *request;
        bool handled;
        bool resume = false;

        (void)pthread_mutex_lock(&server->work_mutex);
        while (server->queue_head == NULL && !server->workers_stopping) {
            (void)pthread_cond_wait(&server->work_available,
                                    &server->work_mutex);
        }
        if (server->queue_head == NULL) {
            (void)pthread_mutex_unlock(&server->work_mutex);
            break;
        }
        request = server->queue_head;
        server->queue_head = request->queue_next;
        if (server->queue_head == NULL) {
            server->queue_tail = NULL;
        }
        request->queue_next = NULL;
        if (server->queued_work != 0u) {
            --server->queued_work;
        }
        {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
                fb_deadline_expired_at(
                    fb_request_phase_deadline(request), &now)) {
                atomic_store_explicit(&request->cancel_requested, true,
                                      memory_order_relaxed);
                request->force_reason = fb_request_timeout_reason(request);
                fb_async_prepare_resume_locked(
                    server, request, FB_REQUEST_RESUMED_FORCED, true);
                (void)pthread_mutex_unlock(&server->work_mutex);
                fb_async_resume(request);
                continue;
            }
        }
        request->phase = FB_REQUEST_RUNNING;
        ++server->active_work;
        (void)pthread_mutex_unlock(&server->work_mutex);

        memset(&request->response, 0, sizeof(request->response));
        handled = server->handler(server->handler_context, &request->arena,
                                  &request->request, &request->response);
        if (!handled) {
            fb_response_text(&request->response,
                             MHD_HTTP_INTERNAL_SERVER_ERROR,
                             "internal server error\n");
        } else if (request->response.status < 100u ||
                   request->response.status > 599u) {
            fb_response_text(&request->response,
                             MHD_HTTP_INTERNAL_SERVER_ERROR,
                             "invalid application response\n");
        }

        (void)pthread_mutex_lock(&server->work_mutex);
        if (server->active_work != 0u) {
            --server->active_work;
        }
        if (request->phase == FB_REQUEST_RUNNING) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
                fb_deadline_expired_at(&request->request_deadline, &now)) {
                atomic_store_explicit(&request->cancel_requested, true,
                                      memory_order_relaxed);
                request->force_reason = FB_FORCE_REQUEST_TIMEOUT;
                fb_async_prepare_resume_locked(
                    server, request, FB_REQUEST_RESUMED_FORCED, true);
            } else {
                fb_async_prepare_resume_locked(
                    server, request, FB_REQUEST_RESUMED_READY, true);
            }
            resume = true;
        }
        (void)pthread_cond_signal(&server->state_changed);
        (void)pthread_mutex_unlock(&server->work_mutex);

        if (resume) {
            fb_async_resume(request);
        } else {
            fb_request_release(request);
        }
    }
    return NULL;
}

static bool fb_bind_address(fb_server *server, char *error, size_t error_capacity) {
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *item;
    char service[16];
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
    (void)snprintf(service, sizeof(service), "%u", (unsigned)server->options.port);
    status = getaddrinfo(server->options.host, service, &hints, &addresses);
    if (status != 0) {
        fb_server_error(error, error_capacity, "cannot resolve listen address: %s",
                        gai_strerror(status));
        return false;
    }
    for (item = addresses; item != NULL; item = item->ai_next) {
        if (item->ai_addrlen <= sizeof(server->address) &&
            (item->ai_family == AF_INET || item->ai_family == AF_INET6)) {
            memcpy(&server->address, item->ai_addr, item->ai_addrlen);
            server->address_length = item->ai_addrlen;
            break;
        }
    }
    freeaddrinfo(addresses);
    if (server->address_length == 0u) {
        fb_server_error(error, error_capacity, "listen address has no TCP endpoint");
        return false;
    }
    return true;
}

static void *fb_uri_logger(void *opaque,
                           const char *uri,
                           struct MHD_Connection *connection) {
    fb_server *server = opaque;
    fb_connection_request *request;
    size_t length;
    (void)connection;
    request = calloc(1, sizeof(*request));
    if (request == NULL) {
        return NULL;
    }
    request->server = server;
    atomic_init(&request->references, 1u);
    atomic_init(&request->cancel_requested, false);
    if (!fb_arena_init(&request->arena, server->options.request_arena_bytes)) {
        free(request);
        return NULL;
    }
    request->arena_initialized = true;
    length = uri == NULL ? 0u : strlen(uri);
    if (length > server->options.max_request_target_bytes) {
        request->target_too_large = true;
        request->raw_target = FB_SLICE_LIT("<request-target-too-long>");
        fb_request_track(request);
        return request;
    }
    request->raw_target = fb_arena_slice_dup(
        &request->arena, fb_slice_make(uri == NULL ? "" : uri, length));
    if (!fb_slice_is_valid(request->raw_target)) {
        fb_arena_destroy(&request->arena);
        free(request);
        return NULL;
    }
    fb_request_track(request);
    return request;
}

static fb_slice fb_header(struct MHD_Connection *connection, const char *name) {
    const char *value = NULL;
    size_t value_length = 0u;
    if (MHD_lookup_connection_value_n(connection, MHD_HEADER_KIND,
                                      name, strlen(name),
                                      &value, &value_length) != MHD_YES) {
        return fb_slice_make(NULL, 0u);
    }
    return fb_slice_make(value, value_length);
}

static fb_slice fb_remote_address(struct MHD_Connection *connection,
                                  fb_arena *arena) {
    const union MHD_ConnectionInfo *info;
    char host[NI_MAXHOST];
    socklen_t length;
    int status;
    info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (info == NULL || info->client_addr == NULL) {
        return fb_slice_make(NULL, 0u);
    }
    length = info->client_addr->sa_family == AF_INET6
                 ? (socklen_t)sizeof(struct sockaddr_in6)
                 : (socklen_t)sizeof(struct sockaddr_in);
    status = getnameinfo(info->client_addr, length, host, sizeof(host),
                         NULL, 0, NI_NUMERICHOST);
    if (status != 0) {
        return fb_slice_make(NULL, 0u);
    }
    return fb_arena_slice_dup(arena, fb_slice_from_cstr(host));
}

static uint32_t fb_log_entity_hash(fb_slice name) {
    uint32_t hash = UINT32_C(2166136261);
    for (size_t index = 0u; index < name.len; ++index) {
        hash ^= (uint32_t)(unsigned char)name.ptr[index];
        hash *= UINT32_C(16777619);
    }
    return hash;
}

static uint32_t fb_log_entity_mix(uint32_t value) {
    value = (value ^ (value >> 16u)) * UINT32_C(0x7feb352d);
    value = (value ^ (value >> 15u)) * UINT32_C(0x846ca68b);
    return value ^ (value >> 16u);
}

static bool fb_log_entity_value(fb_slice name,
                                fb_slice *value,
                                bool *legacy_without_semicolon) {
    uint32_t hash;
    int16_t displacement;
    size_t slot;
    const fb_named_entity *entity;
    if (value == NULL || legacy_without_semicolon == NULL ||
        !fb_slice_is_valid(name) || name.len == 0u || name.len > 31u) {
        return false;
    }
    hash = fb_log_entity_hash(name);
    displacement = fb_html_entity_displacements[
        hash & (FB_HTML_ENTITY_BUCKET_COUNT - 1u)];
    if (displacement < 0) {
        slot = (size_t)(-(int32_t)displacement - 1);
    } else {
        const uint32_t displaced = hash ^
            ((uint32_t)(uint16_t)displacement * UINT32_C(0x9e3779b9));
        slot = (size_t)(fb_log_entity_mix(displaced) %
                        FB_HTML_ENTITY_SLOT_COUNT);
    }
    entity = &fb_html_entities[slot];
    if (name.len != (size_t)entity->name_length ||
        memcmp(name.ptr,
               fb_html_entity_name_blob + entity->name_offset,
               name.len) != 0) {
        return false;
    }
    *value = fb_slice_make(
        (const char *)(const void *)(fb_html_entity_value_blob +
                                    entity->value_offset),
        (size_t)entity->value_length);
    *legacy_without_semicolon =
        (entity->flags & FB_HTML_ENTITY_LEGACY) != 0u;
    return true;
}

static size_t fb_log_utf8_encode(uint32_t codepoint, char output[4]) {
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

static bool fb_log_utf8_next(const unsigned char *input,
                             size_t length,
                             size_t *consumed,
                             uint32_t *codepoint) {
    const unsigned char first = length == 0u ? 0u : input[0];
    if (length == 0u || consumed == NULL || codepoint == NULL) {
        return false;
    }
    if (first < 0x80u) {
        *consumed = 1u;
        *codepoint = first;
        return true;
    }
    if (first >= 0xc2u && first <= 0xdfu && length >= 2u &&
        input[1] >= 0x80u && input[1] <= 0xbfu) {
        *consumed = 2u;
        *codepoint = ((uint32_t)(first & 0x1fu) << 6u) |
                     (uint32_t)(input[1] & 0x3fu);
        return true;
    }
    if (first >= 0xe0u && first <= 0xefu && length >= 3u &&
        input[1] >= (first == 0xe0u ? 0xa0u : 0x80u) &&
        input[1] <= (first == 0xedu ? 0x9fu : 0xbfu) &&
        input[2] >= 0x80u && input[2] <= 0xbfu) {
        *consumed = 3u;
        *codepoint = ((uint32_t)(first & 0x0fu) << 12u) |
                     ((uint32_t)(input[1] & 0x3fu) << 6u) |
                     (uint32_t)(input[2] & 0x3fu);
        return true;
    }
    if (first >= 0xf0u && first <= 0xf4u && length >= 4u &&
        input[1] >= (first == 0xf0u ? 0x90u : 0x80u) &&
        input[1] <= (first == 0xf4u ? 0x8fu : 0xbfu) &&
        input[2] >= 0x80u && input[2] <= 0xbfu &&
        input[3] >= 0x80u && input[3] <= 0xbfu) {
        *consumed = 4u;
        *codepoint = ((uint32_t)(first & 0x07u) << 18u) |
                     ((uint32_t)(input[1] & 0x3fu) << 12u) |
                     ((uint32_t)(input[2] & 0x3fu) << 6u) |
                     (uint32_t)(input[3] & 0x3fu);
        return true;
    }
    return false;
}

static bool fb_log_html_numeric(uint32_t input,
                                uint32_t *output,
                                bool *omit) {
    static const uint16_t c1_replacements[32] = {
        0x20acu, 0x0081u, 0x201au, 0x0192u,
        0x201eu, 0x2026u, 0x2020u, 0x2021u,
        0x02c6u, 0x2030u, 0x0160u, 0x2039u,
        0x0152u, 0x008du, 0x017du, 0x008fu,
        0x0090u, 0x2018u, 0x2019u, 0x201cu,
        0x201du, 0x2022u, 0x2013u, 0x2014u,
        0x02dcu, 0x2122u, 0x0161u, 0x203au,
        0x0153u, 0x009du, 0x017eu, 0x0178u,
    };
    *omit = false;
    if (input == 0u) {
        *output = 0xfffdu;
        return true;
    }
    if (input >= 0x80u && input <= 0x9fu) {
        *output = (uint32_t)c1_replacements[input - 0x80u];
        return true;
    }
    if (input > 0x10ffffu ||
        (input >= 0xd800u && input <= 0xdfffu)) {
        *output = 0xfffdu;
        return true;
    }
    if ((input >= 0x1u && input <= 0x8u) || input == 0x0bu ||
        (input >= 0x0eu && input <= 0x1fu) || input == 0x7fu ||
        (input >= 0xfdd0u && input <= 0xfdefu) ||
        ((input & 0xffffu) >= 0xfffeu)) {
        *output = 0u;
        *omit = true;
        return true;
    }
    *output = input;
    return true;
}

static bool fb_log_html_name_character(unsigned char value) {
    return value != (unsigned char)'\t' && value != (unsigned char)'\n' &&
           value != (unsigned char)'\f' && value != (unsigned char)' ' &&
           value != (unsigned char)'<' && value != (unsigned char)'&' &&
           value != (unsigned char)'#' && value != (unsigned char)';';
}

static char *fb_log_html_unescape(fb_slice input, size_t *output_length) {
    size_t capacity;
    size_t input_index = 0u;
    size_t output_index = 0u;
    char *output;
    if (output_length == NULL || !fb_slice_is_valid(input) ||
        !fb_size_mul(input.len, 2u, &capacity) ||
        !fb_size_add(capacity, 1u, &capacity)) {
        return NULL;
    }
    output = malloc(capacity);
    if (output == NULL) {
        return NULL;
    }
    while (input_index < input.len) {
        size_t consumed = 0u;
        fb_slice replacement = {0};
        bool decoded = false;
        bool omit = false;
        uint32_t codepoint = 0u;
        if (input.ptr[input_index] != '&') {
            output[output_index++] = input.ptr[input_index++];
            continue;
        }
        if (input_index + 2u < input.len &&
            input.ptr[input_index + 1u] == '#') {
            size_t cursor = input_index + 2u;
            unsigned base = 10u;
            size_t digits = 0u;
            bool overflow = false;
            if (cursor < input.len &&
                (input.ptr[cursor] == 'x' || input.ptr[cursor] == 'X')) {
                base = 16u;
                ++cursor;
            }
            while (cursor < input.len) {
                const unsigned char value =
                    (unsigned char)input.ptr[cursor];
                unsigned digit;
                if (value >= (unsigned char)'0' &&
                    value <= (unsigned char)'9') {
                    digit = (unsigned)(value - (unsigned char)'0');
                } else if (base == 16u && value >= (unsigned char)'a' &&
                           value <= (unsigned char)'f') {
                    digit = (unsigned)(value - (unsigned char)'a') + 10u;
                } else if (base == 16u && value >= (unsigned char)'A' &&
                           value <= (unsigned char)'F') {
                    digit = (unsigned)(value - (unsigned char)'A') + 10u;
                } else {
                    break;
                }
                if (codepoint >
                    (UINT32_MAX - (uint32_t)digit) / (uint32_t)base) {
                    overflow = true;
                } else if (!overflow) {
                    codepoint = codepoint * (uint32_t)base +
                                (uint32_t)digit;
                }
                ++digits;
                ++cursor;
            }
            if (digits != 0u) {
                if (cursor < input.len && input.ptr[cursor] == ';') {
                    ++cursor;
                }
                (void)fb_log_html_numeric(
                    overflow ? UINT32_MAX : codepoint, &codepoint, &omit);
                consumed = cursor - input_index;
                decoded = true;
            }
        } else {
            size_t cursor = input_index + 1u;
            const size_t name_start = cursor;
            size_t name_length;
            bool has_semicolon;
            while (cursor < input.len && cursor - name_start < 32u &&
                   fb_log_html_name_character(
                       (unsigned char)input.ptr[cursor])) {
                ++cursor;
            }
            name_length = cursor - name_start;
            has_semicolon = cursor < input.len && input.ptr[cursor] == ';';
            for (size_t candidate = name_length;
                 candidate != 0u;
                 --candidate) {
                bool legacy = false;
                if (!fb_log_entity_value(
                        fb_slice_make(input.ptr + name_start, candidate),
                        &replacement, &legacy)) {
                    continue;
                }
                if ((candidate == name_length && has_semicolon) || legacy) {
                    consumed = 1u + candidate +
                               ((candidate == name_length && has_semicolon)
                                    ? 1u : 0u);
                    decoded = true;
                    break;
                }
            }
        }
        if (!decoded) {
            output[output_index++] = input.ptr[input_index++];
            continue;
        }
        if (!omit) {
            if (replacement.ptr != NULL) {
                memcpy(output + output_index,
                       replacement.ptr, replacement.len);
                output_index += replacement.len;
            } else {
                char encoded[4];
                const size_t encoded_length =
                    fb_log_utf8_encode(codepoint, encoded);
                memcpy(output + output_index, encoded, encoded_length);
                output_index += encoded_length;
            }
        }
        input_index += consumed;
    }
    output[output_index] = '\0';
    *output_length = output_index;
    return output;
}

static int fb_log_hex_value(unsigned char value) {
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F') {
        return (int)(value - (unsigned char)'A') + 10;
    }
    return -1;
}

static bool fb_log_parse_hex(const char *input,
                             size_t length,
                             uint32_t *value) {
    uint32_t result = 0u;
    if (input == NULL || value == NULL) {
        return false;
    }
    for (size_t index = 0u; index < length; ++index) {
        const int digit = fb_log_hex_value((unsigned char)input[index]);
        if (digit < 0) {
            return false;
        }
        result = (result << 4u) | (uint32_t)digit;
    }
    *value = result;
    return true;
}

static char *fb_log_decode_unicode_escapes(fb_slice input,
                                           size_t *output_length) {
    char *output;
    size_t input_index = 0u;
    size_t output_index = 0u;
    if (output_length == NULL || !fb_slice_is_valid(input) ||
        input.len == SIZE_MAX) {
        return NULL;
    }
    output = malloc(input.len + 1u);
    if (output == NULL) {
        return NULL;
    }
    while (input_index < input.len) {
        if (input.ptr[input_index] == '\\' &&
            input_index + 6u <= input.len &&
            input.ptr[input_index + 1u] == 'u') {
            size_t end = input_index;
            size_t cursor;
            size_t rollback = output_index;
            bool valid = true;
            while (end + 6u <= input.len && input.ptr[end] == '\\' &&
                   input.ptr[end + 1u] == 'u') {
                uint32_t ignored;
                if (!fb_log_parse_hex(input.ptr + end + 2u, 4u, &ignored)) {
                    break;
                }
                end += 6u;
            }
            cursor = input_index;
            while (cursor < end) {
                uint32_t codepoint = 0u;
                char encoded[4];
                size_t encoded_length;
                (void)fb_log_parse_hex(input.ptr + cursor + 2u,
                                       4u, &codepoint);
                if (codepoint >= 0xd800u && codepoint <= 0xdbffu &&
                    cursor + 12u <= end) {
                    uint32_t low = 0u;
                    (void)fb_log_parse_hex(input.ptr + cursor + 8u,
                                           4u, &low);
                    if (low >= 0xdc00u && low <= 0xdfffu) {
                        codepoint = UINT32_C(0x10000) +
                            ((codepoint - UINT32_C(0xd800)) << 10u) +
                            (low - UINT32_C(0xdc00));
                        cursor += 12u;
                    } else {
                        valid = false;
                        break;
                    }
                } else {
                    cursor += 6u;
                    if (codepoint >= 0xd800u && codepoint <= 0xdfffu) {
                        valid = false;
                        break;
                    }
                }
                if (codepoint < 32u ||
                    (codepoint >= 0x7fu && codepoint < 0xa0u)) {
                    valid = false;
                    break;
                }
                encoded_length = fb_log_utf8_encode(codepoint, encoded);
                memcpy(output + output_index, encoded, encoded_length);
                output_index += encoded_length;
            }
            if (valid && end != input_index) {
                input_index = end;
                continue;
            }
            output_index = rollback;
        } else if (input.ptr[input_index] == '\\' &&
                   input_index + 10u <= input.len &&
                   input.ptr[input_index + 1u] == 'U') {
            uint32_t codepoint;
            if (fb_log_parse_hex(input.ptr + input_index + 2u,
                                 8u, &codepoint) &&
                codepoint <= 0x10ffffu &&
                !(codepoint >= 0xd800u && codepoint <= 0xdfffu) &&
                codepoint >= 32u &&
                !(codepoint >= 0x7fu && codepoint < 0xa0u)) {
                char encoded[4];
                const size_t encoded_length =
                    fb_log_utf8_encode(codepoint, encoded);
                memcpy(output + output_index, encoded, encoded_length);
                output_index += encoded_length;
                input_index += 10u;
                continue;
            }
        }
        output[output_index++] = input.ptr[input_index++];
    }
    output[output_index] = '\0';
    *output_length = output_index;
    return output;
}

static bool fb_log_unicode_whitespace(uint32_t codepoint) {
    return (codepoint >= 0x09u && codepoint <= 0x0du) ||
           (codepoint >= 0x1cu && codepoint <= 0x20u) ||
           codepoint == 0x85u || codepoint == 0xa0u ||
           codepoint == 0x1680u ||
           (codepoint >= 0x2000u && codepoint <= 0x200au) ||
           codepoint == 0x2028u || codepoint == 0x2029u ||
           codepoint == 0x202fu || codepoint == 0x205fu ||
           codepoint == 0x3000u;
}

static char *fb_log_prepare_title(fb_slice input, size_t *output_length) {
    char *first;
    char *unicode;
    char *second;
    char *output;
    size_t first_length;
    size_t unicode_length;
    size_t second_length;
    size_t capacity;
    size_t input_index = 0u;
    size_t output_index = 0u;
    bool pending_space = false;
    if (output_length == NULL || !fb_slice_is_valid(input)) {
        return NULL;
    }
    first = fb_log_html_unescape(input, &first_length);
    if (first == NULL) {
        return NULL;
    }
    unicode = fb_log_decode_unicode_escapes(
        fb_slice_make(first, first_length), &unicode_length);
    free(first);
    if (unicode == NULL) {
        return NULL;
    }
    second = fb_log_html_unescape(
        fb_slice_make(unicode, unicode_length), &second_length);
    free(unicode);
    if (second == NULL || !fb_size_mul(second_length, 6u, &capacity) ||
        !fb_size_add(capacity, 1u, &capacity)) {
        free(second);
        return NULL;
    }
    output = malloc(capacity);
    if (output == NULL) {
        free(second);
        return NULL;
    }
    while (input_index < second_length) {
        size_t consumed;
        uint32_t codepoint;
        if (!fb_log_utf8_next(
                (const unsigned char *)second + input_index,
                second_length - input_index, &consumed, &codepoint)) {
            if (pending_space && output_index != 0u) {
                output[output_index++] = ' ';
                pending_space = false;
            }
            output_index += (size_t)snprintf(
                output + output_index, capacity - output_index,
                "\\x%02X", (unsigned)(unsigned char)second[input_index]);
            ++input_index;
            continue;
        }
        if (fb_log_unicode_whitespace(codepoint)) {
            pending_space = output_index != 0u;
            input_index += consumed;
            continue;
        }
        if (pending_space && output_index != 0u) {
            output[output_index++] = ' ';
        }
        pending_space = false;
        if (codepoint < 32u ||
            (codepoint >= 0x7fu && codepoint < 0xa0u)) {
            output_index += (size_t)snprintf(
                output + output_index, capacity - output_index,
                "\\u%04X", (unsigned)codepoint);
        } else {
            memcpy(output + output_index, second + input_index, consumed);
            output_index += consumed;
        }
        input_index += consumed;
    }
    output[output_index] = '\0';
    *output_length = output_index;
    free(second);
    return output;
}

static bool fb_log_url_codepoint_safe(uint32_t codepoint) {
    return codepoint >= 32u &&
           !(codepoint >= 0x7fu && codepoint < 0xa0u) &&
           codepoint != 0x2028u && codepoint != 0x2029u;
}

static char *fb_log_percent_decode(fb_slice input, size_t *output_length) {
    char *output;
    size_t input_index = 0u;
    size_t output_index = 0u;
    if (output_length == NULL || !fb_slice_is_valid(input) ||
        input.len == SIZE_MAX) {
        return NULL;
    }
    output = malloc(input.len + 1u);
    if (output == NULL) {
        return NULL;
    }
    while (input_index < input.len) {
        if (input.ptr[input_index] == '%' && input_index + 2u < input.len &&
            fb_log_hex_value((unsigned char)input.ptr[input_index + 1u]) >= 0 &&
            fb_log_hex_value((unsigned char)input.ptr[input_index + 2u]) >= 0) {
            const size_t run_start = input_index;
            const size_t output_start = output_index;
            bool valid = true;
            while (input_index + 2u < input.len &&
                   input.ptr[input_index] == '%') {
                const int high = fb_log_hex_value(
                    (unsigned char)input.ptr[input_index + 1u]);
                const int low = fb_log_hex_value(
                    (unsigned char)input.ptr[input_index + 2u]);
                if (high < 0 || low < 0) {
                    break;
                }
                output[output_index++] =
                    (char)((unsigned)high * 16u + (unsigned)low);
                input_index += 3u;
            }
            for (size_t cursor = output_start; cursor < output_index;) {
                size_t consumed;
                uint32_t codepoint;
                if (!fb_log_utf8_next(
                        (const unsigned char *)output + cursor,
                        output_index - cursor, &consumed, &codepoint) ||
                    !fb_log_url_codepoint_safe(codepoint)) {
                    valid = false;
                    break;
                }
                cursor += consumed;
            }
            if (valid) {
                continue;
            }
            output_index = output_start;
            memcpy(output + output_index, input.ptr + run_start,
                   input_index - run_start);
            output_index += input_index - run_start;
            continue;
        }
        output[output_index++] = input.ptr[input_index++];
    }
    output[output_index] = '\0';
    *output_length = output_index;
    return output;
}

static bool fb_log_ascii_equal(fb_slice value, const char *literal) {
    const size_t length = strlen(literal);
    if (value.len != length) {
        return false;
    }
    for (size_t index = 0u; index < length; ++index) {
        unsigned char actual = (unsigned char)value.ptr[index];
        unsigned char expected = (unsigned char)literal[index];
        if (actual >= (unsigned char)'A' && actual <= (unsigned char)'Z') {
            actual = (unsigned char)(actual + ('a' - 'A'));
        }
        if (actual != expected) {
            return false;
        }
    }
    return true;
}

static bool fb_log_ascii_ends_with(fb_slice value, const char *literal) {
    const size_t length = strlen(literal);
    if (value.len < length) {
        return false;
    }
    return fb_log_ascii_equal(
        fb_slice_make(value.ptr + value.len - length, length), literal);
}

static bool fb_log_sensitive_query_key(fb_slice key) {
    static const char *const names[] = {
        "access_token", "accesstoken", "api_key", "apikey", "auth",
        "authorization", "client_secret", "clientsecret", "code", "cookie",
        "credential", "id_token", "key", "passwd", "password",
        "refresh_token", "secret", "session", "sessionid", "sig",
        "signature", "token", "webhook", "webhook_url",
    };
    static const char *const suffixes[] = {
        "_key", "-key", "_passwd", "-passwd", "_password", "-password",
        "_secret", "-secret", "_signature", "-signature",
        "_token", "-token",
    };
    while (key.len >= 2u && key.ptr[key.len - 2u] == '[' &&
           key.ptr[key.len - 1u] == ']') {
        key.len -= 2u;
    }
    for (size_t index = 0u; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (fb_log_ascii_equal(key, names[index])) {
            return true;
        }
    }
    for (size_t index = 0u;
         index < sizeof(suffixes) / sizeof(suffixes[0]);
         ++index) {
        if (fb_log_ascii_ends_with(key, suffixes[index])) {
            return true;
        }
    }
    return false;
}

static bool fb_log_origin_boundary(unsigned char value) {
    return !((value >= (unsigned char)'a' && value <= (unsigned char)'z') ||
             (value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
             (value >= (unsigned char)'0' && value <= (unsigned char)'9') ||
             value == (unsigned char)'_' || value == (unsigned char)'.' ||
             value == (unsigned char)'@' || value == (unsigned char)':' ||
             value == (unsigned char)'-');
}

static void fb_log_shorten_origin(char *input, size_t *input_length) {
    static const char *const origins[] = {
        "http://facebook.com", "http://www.facebook.com",
        "https://facebook.com", "https://www.facebook.com",
        "http://facebed.com", "http://www.facebed.com",
        "https://facebed.com", "https://www.facebed.com",
    };
    for (size_t item = 0u;
         item < sizeof(origins) / sizeof(origins[0]);
         ++item) {
        const size_t origin_length = strlen(origins[item]);
        size_t remainder = origin_length;
        bool equal = input != NULL && input_length != NULL &&
                     *input_length >= origin_length;
        for (size_t index = 0u; equal && index < origin_length; ++index) {
            unsigned char actual = (unsigned char)input[index];
            unsigned char expected = (unsigned char)origins[item][index];
            if (actual >= (unsigned char)'A' && actual <= (unsigned char)'Z') {
                actual = (unsigned char)(actual + ('a' - 'A'));
            }
            if (actual != expected) {
                equal = false;
            }
        }
        if (!equal || (*input_length > origin_length &&
                       !fb_log_origin_boundary(
                           (unsigned char)input[origin_length]))) {
            continue;
        }
        while (remainder < *input_length && input[remainder] == '/') {
            ++remainder;
        }
        if (remainder < *input_length) {
            memmove(input + 1u, input + remainder,
                    *input_length - remainder);
        }
        input[0] = '/';
        *input_length = 1u + (*input_length - remainder);
        input[*input_length] = '\0';
        return;
    }
}

static char *fb_log_redact_url(fb_slice input, size_t *output_length) {
    static const char replacement[] = "[REDACTED]";
    size_t capacity;
    size_t input_index = 0u;
    size_t output_index = 0u;
    char *output;
    if (output_length == NULL || !fb_slice_is_valid(input) ||
        !fb_size_mul(input.len, 4u, &capacity) ||
        !fb_size_add(capacity, 1u, &capacity)) {
        return NULL;
    }
    output = malloc(capacity);
    if (output == NULL) {
        return NULL;
    }
    {
        size_t authority_start = 0u;
        if (input.len >= 7u &&
            fb_log_ascii_equal(fb_slice_make(input.ptr, 7u), "http://")) {
            authority_start = 7u;
        } else if (input.len >= 8u &&
                   fb_log_ascii_equal(
                       fb_slice_make(input.ptr, 8u), "https://")) {
            authority_start = 8u;
        }
        if (authority_start != 0u) {
            size_t authority_end = authority_start;
            size_t at = SIZE_MAX;
            while (authority_end < input.len &&
                   input.ptr[authority_end] != '/' &&
                   input.ptr[authority_end] != '?' &&
                   input.ptr[authority_end] != '#') {
                if (input.ptr[authority_end] == '@') {
                    at = authority_end;
                }
                ++authority_end;
            }
            if (at != SIZE_MAX) {
                memcpy(output, input.ptr, authority_start);
                output_index = authority_start;
                memcpy(output + output_index, replacement,
                       sizeof(replacement) - 1u);
                output_index += sizeof(replacement) - 1u;
                output[output_index++] = '@';
                input_index = at + 1u;
            }
        }
    }
    while (input_index < input.len) {
        const char delimiter = input.ptr[input_index];
        if (delimiter == '?' || delimiter == '&' || delimiter == ';') {
            const size_t key_start = input_index + 1u;
            size_t cursor = key_start;
            output[output_index++] = delimiter;
            ++input_index;
            while (cursor < input.len && input.ptr[cursor] != '=' &&
                   input.ptr[cursor] != '?' && input.ptr[cursor] != '&' &&
                   input.ptr[cursor] != ';' && input.ptr[cursor] != '#') {
                ++cursor;
            }
            if (cursor < input.len && input.ptr[cursor] == '=' &&
                fb_log_sensitive_query_key(
                    fb_slice_make(input.ptr + key_start,
                                  cursor - key_start))) {
                memcpy(output + output_index, input.ptr + key_start,
                       cursor - key_start + 1u);
                output_index += cursor - key_start + 1u;
                memcpy(output + output_index, replacement,
                       sizeof(replacement) - 1u);
                output_index += sizeof(replacement) - 1u;
                input_index = cursor + 1u;
                while (input_index < input.len &&
                       input.ptr[input_index] != '?' &&
                       input.ptr[input_index] != '&' &&
                       input.ptr[input_index] != ';' &&
                       input.ptr[input_index] != '#') {
                    ++input_index;
                }
                continue;
            }
            continue;
        }
        output[output_index++] = input.ptr[input_index++];
    }
    output[output_index] = '\0';
    *output_length = output_index;
    return output;
}

static char *fb_log_sanitize_url(fb_slice input, size_t *output_length) {
    static const char hex[] = "0123456789ABCDEF";
    size_t capacity;
    size_t input_index = 0u;
    size_t output_index = 0u;
    char *output;
    if (output_length == NULL || !fb_slice_is_valid(input) ||
        !fb_size_mul(input.len, 3u, &capacity) ||
        !fb_size_add(capacity, 1u, &capacity)) {
        return NULL;
    }
    output = malloc(capacity);
    if (output == NULL) {
        return NULL;
    }
    while (input_index < input.len) {
        size_t consumed;
        uint32_t codepoint;
        bool safe = fb_log_utf8_next(
            (const unsigned char *)input.ptr + input_index,
            input.len - input_index, &consumed, &codepoint);
        if (safe) {
            safe = fb_log_url_codepoint_safe(codepoint);
        } else {
            consumed = 1u;
        }
        if (safe) {
            memcpy(output + output_index, input.ptr + input_index, consumed);
            output_index += consumed;
        } else {
            for (size_t index = 0u; index < consumed; ++index) {
                const unsigned char value =
                    (unsigned char)input.ptr[input_index + index];
                output[output_index++] = '%';
                output[output_index++] = hex[value >> 4u];
                output[output_index++] = hex[value & 0x0fu];
            }
        }
        input_index += consumed;
    }
    output[output_index] = '\0';
    *output_length = output_index;
    return output;
}

static char *fb_log_prepare_url(fb_slice raw_target, size_t *output_length) {
    char *decoded;
    char *redacted;
    char *sanitized;
    size_t decoded_length;
    size_t redacted_length;
    decoded = fb_log_percent_decode(raw_target, &decoded_length);
    if (decoded == NULL) {
        return NULL;
    }
    fb_log_shorten_origin(decoded, &decoded_length);
    redacted = fb_log_redact_url(
        fb_slice_make(decoded, decoded_length), &redacted_length);
    free(decoded);
    if (redacted == NULL) {
        return NULL;
    }
    sanitized = fb_log_sanitize_url(
        fb_slice_make(redacted, redacted_length), output_length);
    free(redacted);
    return sanitized;
}

static bool fb_log_url_display_ready(fb_slice input) {
    size_t index = 0u;
    if (!fb_slice_is_valid(input) || input.ptr == NULL) {
        return false;
    }
    if ((input.len >= 7u &&
         fb_log_ascii_equal(fb_slice_make(input.ptr, 7u), "http://")) ||
        (input.len >= 8u &&
         fb_log_ascii_equal(fb_slice_make(input.ptr, 8u), "https://"))) {
        return false;
    }
    while (index < input.len) {
        size_t consumed;
        uint32_t codepoint;
        if (input.ptr[index] == '%') {
            return false;
        }
        if (!fb_log_utf8_next(
                (const unsigned char *)input.ptr + index,
                input.len - index, &consumed, &codepoint) ||
            !fb_log_url_codepoint_safe(codepoint)) {
            return false;
        }
        if (input.ptr[index] == '?' || input.ptr[index] == '&' ||
            input.ptr[index] == ';') {
            const size_t key_start = index + 1u;
            size_t cursor = key_start;
            while (cursor < input.len && input.ptr[cursor] != '=' &&
                   input.ptr[cursor] != '?' && input.ptr[cursor] != '&' &&
                   input.ptr[cursor] != ';' && input.ptr[cursor] != '#') {
                ++cursor;
            }
            if (cursor < input.len && input.ptr[cursor] == '=' &&
                fb_log_sensitive_query_key(
                    fb_slice_make(input.ptr + key_start,
                                  cursor - key_start))) {
                return false;
            }
        }
        index += consumed;
    }
    return true;
}

static bool fb_log_title_display_ready(fb_slice input) {
    size_t index = 0u;
    bool previous_space = false;
    if (!fb_slice_is_valid(input) || input.ptr == NULL || input.len == 0u) {
        return input.len == 0u;
    }
    while (index < input.len) {
        size_t consumed;
        uint32_t codepoint;
        if (input.ptr[index] == '&' ||
            (input.ptr[index] == '\\' && index + 1u < input.len &&
             (input.ptr[index + 1u] == 'u' ||
              input.ptr[index + 1u] == 'U'))) {
            return false;
        }
        if (!fb_log_utf8_next(
                (const unsigned char *)input.ptr + index,
                input.len - index, &consumed, &codepoint) ||
            codepoint < 32u ||
            (codepoint >= 0x7fu && codepoint < 0xa0u)) {
            return false;
        }
        if (fb_log_unicode_whitespace(codepoint)) {
            if (codepoint != 0x20u || index == 0u || previous_space ||
                index + consumed == input.len) {
                return false;
            }
            previous_space = true;
        } else {
            previous_space = false;
        }
        index += consumed;
    }
    return true;
}

static void fb_access_capture_identity(fb_connection_request *state,
                                       struct MHD_Connection *connection,
                                       const char *method) {
    fb_slice remote;
    fb_slice method_copy;
    if (state == NULL || state->access_identity_captured) {
        return;
    }
    method_copy = fb_arena_slice_dup(
        &state->arena,
        fb_slice_from_cstr(method == NULL ? "-" : method));
    remote = fb_remote_address(connection, &state->arena);
    state->access_method = fb_slice_is_valid(method_copy) &&
                                   method_copy.ptr != NULL
                               ? method_copy
                               : FB_SLICE_LIT("-");
    state->access_remote_address = fb_slice_is_valid(remote) &&
                                           remote.ptr != NULL
                                       ? remote
                                       : FB_SLICE_LIT("-");
    state->access_identity_captured = true;
}

static void fb_access_mark_response(fb_connection_request *state,
                                    unsigned status,
                                    fb_slice log_title) {
    if (state == NULL) {
        return;
    }
    state->access_status = status;
    state->access_log_title = log_title;
    state->response_queued = true;
}

static FB_LOG_NOINLINE void
fb_access_log_completed(const fb_connection_request *state) {
    char timestamp[32] = "0000-00-00 00:00:00";
    char *allocated_url;
    const char *display_url;
    char *allocated_title = NULL;
    const char *display_title = NULL;
    size_t display_url_length = 0u;
    size_t display_title_length = 0u;
    const char *reason;
    time_t now;
    struct tm local;
    if (state == NULL || !state->response_queued) {
        return;
    }
    if (fb_log_url_display_ready(state->raw_target)) {
        allocated_url = NULL;
        display_url = state->raw_target.ptr;
        display_url_length = state->raw_target.len;
    } else {
        allocated_url = fb_log_prepare_url(state->raw_target,
                                           &display_url_length);
        if (allocated_url == NULL) {
            display_url = "<log-display-unavailable>";
            display_url_length = sizeof("<log-display-unavailable>") - 1u;
        } else {
            display_url = allocated_url;
        }
    }
    if (state->access_log_title.ptr != NULL &&
        state->access_log_title.len != 0u) {
        if (fb_log_title_display_ready(state->access_log_title)) {
            display_title = state->access_log_title.ptr;
            display_title_length = state->access_log_title.len;
        } else {
            allocated_title = fb_log_prepare_title(state->access_log_title,
                                                   &display_title_length);
            display_title = allocated_title;
        }
    }
    now = time(NULL);
    if (now != (time_t)-1 && localtime_r(&now, &local) != NULL) {
        (void)strftime(timestamp, sizeof(timestamp),
                       "%Y-%m-%d %H:%M:%S", &local);
    }
    reason = MHD_get_reason_phrase_for(state->access_status);
    if (reason == NULL) {
        reason = "";
    }
    flockfile(stderr);
    (void)fprintf(stderr,
                  "[INFO] [%s] %.*s %.*s %.*s %u %s",
                  timestamp,
                  (int)(state->access_remote_address.len > (size_t)INT_MAX
                            ? INT_MAX : state->access_remote_address.len),
                  state->access_remote_address.ptr == NULL
                      ? "-" : state->access_remote_address.ptr,
                  (int)(state->access_method.len > (size_t)INT_MAX
                            ? INT_MAX : state->access_method.len),
                  state->access_method.ptr == NULL
                      ? "-" : state->access_method.ptr,
                  (int)(display_url_length > (size_t)INT_MAX
                            ? INT_MAX : display_url_length),
                  display_url,
                  state->access_status, reason);
    if (display_title != NULL && display_title_length != 0u) {
        (void)fprintf(stderr, " %.*s",
                      (int)(display_title_length > (size_t)INT_MAX
                                ? INT_MAX : display_title_length),
                      display_title);
    }
    (void)fputc('\n', stderr);
    funlockfile(stderr);
    free(allocated_title);
    free(allocated_url);
}

#undef FB_LOG_NOINLINE

static enum MHD_Result fb_add_header(struct MHD_Response *response,
                                     const char *name,
                                     fb_slice value) {
    char *temporary;
    enum MHD_Result result;
    if (value.ptr == NULL || value.len == 0u) {
        return MHD_YES;
    }
    temporary = malloc(value.len + 1u);
    if (temporary == NULL) {
        return MHD_NO;
    }
    memcpy(temporary, value.ptr, value.len);
    temporary[value.len] = '\0';
    result = MHD_add_response_header(response, name, temporary);
    free(temporary);
    return result;
}

static struct MHD_Response *
fb_create_response(const fb_connection_request *state,
                   const fb_http_response *specification) {
    static const char empty[] = "";
    const void *body = specification->body.ptr == NULL
                           ? (const void *)empty
                           : (const void *)specification->body.ptr;

    if (specification->body_source == FB_HTTP_BODY_MEMORY) {
        return MHD_create_response_from_buffer(
            specification->body.len, (void *)body, MHD_RESPMEM_PERSISTENT);
    }
    if (specification->body_source != FB_HTTP_BODY_BORROWED_FD ||
        specification->body_fd < 0 ||
        (specification->body.ptr == NULL && specification->body.len != 0u)) {
        return NULL;
    }
    if (state != NULL && state->server != NULL &&
        state->server->sendfile_supported) {
        const int duplicate = fcntl(specification->body_fd,
                                    F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        if (duplicate >= 0) {
            struct MHD_Response *response = MHD_create_response_from_fd64(
                (uint64_t)specification->body.len, duplicate);
            if (response != NULL) {
                return response;
            }
            (void)close(duplicate);
        }
    }
    return MHD_create_response_from_buffer(
        specification->body.len, (void *)body, MHD_RESPMEM_PERSISTENT);
}

static enum MHD_Result fb_queue(struct MHD_Connection *connection,
                                fb_connection_request *state,
                                const fb_http_response *specification) {
    struct MHD_Response *response = fb_create_response(state, specification);
    enum MHD_Result result;
    if (response == NULL) {
        return MHD_NO;
    }
    if (fb_add_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
                      specification->content_type) != MHD_YES ||
        fb_add_header(response, MHD_HTTP_HEADER_CACHE_CONTROL,
                      specification->cache_control) != MHD_YES ||
        fb_add_header(response, MHD_HTTP_HEADER_LOCATION,
                      specification->location) != MHD_YES ||
        fb_add_header(response, MHD_HTTP_HEADER_RETRY_AFTER,
                      specification->retry_after) != MHD_YES ||
        (specification->close_connection &&
         MHD_add_response_header(response, MHD_HTTP_HEADER_CONNECTION,
                                 "close") != MHD_YES) ||
        (specification->vary_user_agent &&
         MHD_add_response_header(response, MHD_HTTP_HEADER_VARY,
                                 "User-Agent") != MHD_YES)) {
        MHD_destroy_response(response);
        return MHD_NO;
    }
    result = MHD_queue_response(connection, specification->status, response);
    MHD_destroy_response(response);
    if (result == MHD_YES) {
        fb_access_mark_response(state, specification->status,
                                specification->log_title);
    }
    return result;
}

static enum MHD_Result fb_queue_text(struct MHD_Connection *connection,
                                     fb_connection_request *state,
                                     unsigned status,
                                     const char *text) {
    fb_http_response response;
    memset(&response, 0, sizeof(response));
    response.status = status;
    response.body = fb_slice_from_cstr(text);
    response.content_type = FB_SLICE_LIT("text/plain; charset=utf-8");
    response.cache_control = FB_SLICE_LIT("no-store");
    return fb_queue(connection, state, &response);
}

static enum MHD_Result fb_queue_overload(struct MHD_Connection *connection,
                                         fb_connection_request *state,
                                         const char *text,
                                         bool close_connection) {
    fb_http_response response;
    fb_response_text(&response, MHD_HTTP_SERVICE_UNAVAILABLE, text);
    response.retry_after = FB_SLICE_LIT("1");
    response.close_connection = close_connection;
    return fb_queue(connection, state, &response);
}

static enum MHD_Result fb_queue_forced(struct MHD_Connection *connection,
                                       fb_connection_request *state,
                                       fb_force_reason reason) {
    if (reason == FB_FORCE_QUEUE_TIMEOUT) {
        return fb_queue_overload(connection, state, "server busy\n", false);
    }
    if (reason == FB_FORCE_REQUEST_TIMEOUT) {
        return fb_queue_text(connection, state, MHD_HTTP_GATEWAY_TIMEOUT,
                             "request timed out\n");
    }
    return fb_queue_overload(connection, state,
                             "server shutting down\n", true);
}

static bool fb_copy_optional_slice(fb_arena *arena,
                                   fb_slice source,
                                   fb_slice *destination) {
    if (source.ptr == NULL) {
        *destination = fb_slice_make(NULL, 0u);
        return source.len == 0u;
    }
    *destination = fb_arena_slice_dup(arena, source);
    return destination->ptr != NULL;
}

static bool fb_copy_request_for_worker(fb_connection_request *state,
                                       const fb_http_request *request) {
    state->request = *request;
    state->request.raw_target = state->raw_target;
    state->request.cancel_requested = &state->cancel_requested;
    return fb_copy_optional_slice(&state->arena, request->path,
                                  &state->request.path) &&
           fb_copy_optional_slice(&state->arena, request->method,
                                  &state->request.method) &&
           fb_copy_optional_slice(&state->arena, request->version,
                                  &state->request.version) &&
           fb_copy_optional_slice(&state->arena, request->user_agent,
                                  &state->request.user_agent) &&
           fb_copy_optional_slice(&state->arena, request->host,
                                  &state->request.host);
}

static enum MHD_Result fb_defer_request(fb_server *server,
                                        struct MHD_Connection *connection,
                                        fb_connection_request *state,
                                        const fb_http_request *request) {
    if (!fb_copy_request_for_worker(state, request)) {
        return fb_queue_text(connection, state,
                             MHD_HTTP_INTERNAL_SERVER_ERROR,
                             "out of memory\n");
    }
    state->connection = connection;
    (void)pthread_mutex_lock(&server->work_mutex);
    if (server->forcing_work) {
        (void)pthread_mutex_unlock(&server->work_mutex);
        return fb_queue_overload(connection, state,
                                 "server shutting down\n", true);
    }
    if (server->queued_work >= server->options.work_queue_limit) {
        (void)pthread_mutex_unlock(&server->work_mutex);
        return fb_queue_overload(connection, state, "server busy\n", false);
    }
    fb_request_retain(state);
    state->phase = FB_REQUEST_QUEUED;
    state->queue_deadline = fb_deadline_after(
        server->options.queue_timeout_seconds);
    fb_async_link_locked(server, state);
    if (server->queue_tail == NULL) {
        server->queue_head = state;
    } else {
        server->queue_tail->queue_next = state;
    }
    server->queue_tail = state;
    ++server->queued_work;
    MHD_suspend_connection(connection);
    (void)pthread_cond_signal(&server->work_available);
    (void)pthread_cond_signal(&server->deadline_changed);
    (void)pthread_mutex_unlock(&server->work_mutex);
    return MHD_YES;
}

static enum MHD_Result fb_access(void *opaque,
                                 struct MHD_Connection *connection,
                                 const char *url,
                                 const char *method,
                                 const char *version,
                                 const char *upload_data,
                                 size_t *upload_data_size,
                                 void **request_context) {
    fb_server *server = opaque;
    fb_connection_request *state = *request_context;
    fb_http_request request;
    fb_http_response response;
    const char *query;
    bool supported_method;
    bool admitted;
    (void)upload_data;

    if (state == NULL) {
        state = fb_uri_logger(server, url, connection);
        if (state == NULL) {
            return fb_queue_text(connection, NULL,
                                 MHD_HTTP_INTERNAL_SERVER_ERROR,
                                 "out of memory\n");
        }
        *request_context = state;
    }
    fb_access_capture_identity(state, connection, method);
    {
        fb_request_phase phase;
        fb_force_reason force_reason;
        fb_http_response completed_response;
        (void)pthread_mutex_lock(&server->work_mutex);
        phase = state->phase;
        if (phase == FB_REQUEST_SYNC && !state->admission_decided) {
            state->admission_decided = true;
            state->admitted = server->accepting_work;
        }
        admitted = state->admitted;
        force_reason = state->force_reason;
        if (phase == FB_REQUEST_RESUMED_READY) {
            completed_response = state->response;
            completed_response.close_connection = !server->accepting_work;
            state->phase = FB_REQUEST_RESPONSE_QUEUED;
        } else if (phase == FB_REQUEST_RESUMED_FORCED) {
            state->phase = FB_REQUEST_RESPONSE_QUEUED;
        }
        (void)pthread_mutex_unlock(&server->work_mutex);
        if (phase == FB_REQUEST_RESUMED_READY) {
            return fb_queue(connection, state, &completed_response);
        }
        if (phase == FB_REQUEST_RESUMED_FORCED) {
            return fb_queue_forced(connection, state, force_reason);
        }
        if (phase == FB_REQUEST_QUEUED || phase == FB_REQUEST_RUNNING ||
            phase == FB_REQUEST_RESPONSE_QUEUED) {
            return MHD_YES;
        }
    }
    if (state->handled) {
        return MHD_YES;
    }
    if (!admitted) {
        state->handled = true;
        return fb_queue_overload(connection, state,
                                 "server shutting down\n", true);
    }
    if (!state->access_started) {
        state->access_started = true;
        return MHD_YES;
    }
    if (upload_data_size != NULL && *upload_data_size != 0u) {
        *upload_data_size = 0u;
        return MHD_YES;
    }
    state->handled = true;
    if (state->target_too_large) {
        return fb_queue_text(connection, state, MHD_HTTP_URI_TOO_LONG,
                             "request target too long\n");
    }
    supported_method = method != NULL &&
                       (strcmp(method, MHD_HTTP_METHOD_GET) == 0 ||
                        strcmp(method, MHD_HTTP_METHOD_HEAD) == 0);
    if (!supported_method) {
        struct MHD_Response *method_response;
        enum MHD_Result result;
        static const char body[] = "method not allowed\n";
        method_response = MHD_create_response_from_buffer(
            sizeof(body) - 1u, (void *)body, MHD_RESPMEM_PERSISTENT);
        if (method_response == NULL) {
            return MHD_NO;
        }
        (void)MHD_add_response_header(method_response, MHD_HTTP_HEADER_ALLOW,
                                      "GET, HEAD");
        (void)MHD_add_response_header(method_response, MHD_HTTP_HEADER_CACHE_CONTROL,
                                      "no-store");
        result = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                                    method_response);
        MHD_destroy_response(method_response);
        if (result == MHD_YES) {
            fb_access_mark_response(state, MHD_HTTP_METHOD_NOT_ALLOWED,
                                    fb_slice_make(NULL, 0u));
        }
        return result;
    }

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    request.raw_target = state->raw_target;
    query = memchr(state->raw_target.ptr, '?', state->raw_target.len);
    request.path = fb_slice_from_cstr(url);
    if (query != NULL) {
        request.query = fb_slice_make(query + 1,
                                      state->raw_target.len -
                                          (size_t)(query - state->raw_target.ptr) - 1u);
    }
    request.method = fb_slice_from_cstr(method);
    request.version = fb_slice_from_cstr(version);
    request.user_agent = fb_header(connection, MHD_HTTP_HEADER_USER_AGENT);
    request.host = fb_header(connection, MHD_HTTP_HEADER_HOST);
    request.remote_address = fb_remote_address(connection, &state->arena);
    request.cancel_requested = &state->cancel_requested;
    request.is_head = strcmp(method, MHD_HTTP_METHOD_HEAD) == 0;

    if (server->should_defer != NULL &&
        server->should_defer(server->handler_context, &request)) {
        return fb_defer_request(server, connection, state, &request);
    }
    if (!server->handler(server->handler_context, &state->arena,
                         &request, &response)) {
        return fb_queue_text(connection, state,
                             MHD_HTTP_INTERNAL_SERVER_ERROR,
                             "internal server error\n");
    }
    if (response.status < 100u || response.status > 599u) {
        return fb_queue_text(connection, state,
                             MHD_HTTP_INTERNAL_SERVER_ERROR,
                             "invalid application response\n");
    }
    return fb_queue(connection, state, &response);
}

static void fb_completed(void *opaque,
                         struct MHD_Connection *connection,
                         void **request_context,
                         enum MHD_RequestTerminationCode termination) {
    fb_connection_request *state;
    (void)opaque;
    (void)connection;
    (void)termination;
    if (request_context == NULL || *request_context == NULL) {
        return;
    }
    state = *request_context;
    *request_context = NULL;
    fb_access_log_completed(state);
    if (state->request_tracked) {
        fb_server *server = state->server;
        (void)pthread_mutex_lock(&server->work_mutex);
        state->request_tracked = false;
        if (server->request_count != 0u) {
            --server->request_count;
        }
        (void)pthread_cond_signal(&server->state_changed);
        (void)pthread_mutex_unlock(&server->work_mutex);
    }
    fb_request_release(state);
}

static int fb_hex_value(unsigned char value) {
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F') {
        return (int)(value - (unsigned char)'A') + 10;
    }
    return -1;
}

/* Match urllib's tolerant path decoding: valid %HH bytes are decoded while
 * malformed or truncated percent sequences remain literal input. */
static size_t fb_uri_unescape(void *opaque,
                              struct MHD_Connection *connection,
                              char *text) {
    size_t input = 0u;
    size_t output = 0u;
    (void)opaque;
    (void)connection;
    while (text[input] != '\0') {
        if (text[input] == '%' && text[input + 1u] != '\0' &&
            text[input + 2u] != '\0') {
            const int high = fb_hex_value((unsigned char)text[input + 1u]);
            const int low = fb_hex_value((unsigned char)text[input + 2u]);
            if (high >= 0 && low >= 0) {
                text[output++] = (char)((unsigned)high * 16u + (unsigned)low);
                input += 3u;
                continue;
            }
        }
        text[output++] = text[input++];
    }
    text[output] = '\0';

    /* Bottle follows PEP-3333 by re-decoding PATH_INFO as UTF-8 with
     * errors="ignore". Reproduce that exact malformed-input behavior. */
    input = 0u;
    {
        const size_t decoded_length = output;
        output = 0u;
        while (input < decoded_length) {
            const unsigned char first = (unsigned char)text[input];
            size_t length = 0u;
            if (first < 0x80u) {
                length = 1u;
            } else if (first >= 0xc2u && first <= 0xdfu &&
                       input + 1u < decoded_length &&
                       (unsigned char)text[input + 1u] >= 0x80u &&
                       (unsigned char)text[input + 1u] <= 0xbfu) {
                length = 2u;
            } else if (first >= 0xe0u && first <= 0xefu &&
                       input + 2u < decoded_length) {
                const unsigned char second = (unsigned char)text[input + 1u];
                const unsigned char third = (unsigned char)text[input + 2u];
                if (second >= (first == 0xe0u ? 0xa0u : 0x80u) &&
                    second <= (first == 0xedu ? 0x9fu : 0xbfu) &&
                    third >= 0x80u && third <= 0xbfu) {
                    length = 3u;
                }
            } else if (first >= 0xf0u && first <= 0xf4u &&
                       input + 3u < decoded_length) {
                const unsigned char second = (unsigned char)text[input + 1u];
                const unsigned char third = (unsigned char)text[input + 2u];
                const unsigned char fourth = (unsigned char)text[input + 3u];
                if (second >= (first == 0xf0u ? 0x90u : 0x80u) &&
                    second <= (first == 0xf4u ? 0x8fu : 0xbfu) &&
                    third >= 0x80u && third <= 0xbfu &&
                    fourth >= 0x80u && fourth <= 0xbfu) {
                    length = 4u;
                }
            }
            if (length == 0u) {
                ++input;
                continue;
            }
            memmove(text + output, text + input, length);
            output += length;
            input += length;
        }
    }
    text[output] = '\0';
    return output;
}

static struct MHD_Daemon *fb_start_mhd(fb_server *server,
                                       unsigned int flags,
                                       bool tcp_fastopen) {
    struct MHD_OptionItem conditional_options[2] = {
        {MHD_OPTION_END, 0, NULL},
        {MHD_OPTION_END, 0, NULL},
    };
    const fb_server_options *options = &server->options;

    if (tcp_fastopen) {
        conditional_options[0].option = MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE;
        conditional_options[0].value = (intptr_t)256;
    }
    return MHD_start_daemon(
        flags,
        options->port,
        NULL, NULL,
        fb_access, server,
        MHD_OPTION_SOCK_ADDR_LEN, (socklen_t)server->address_length,
            (const struct sockaddr *)&server->address,
        MHD_OPTION_THREAD_POOL_SIZE, options->io_threads,
        MHD_OPTION_CONNECTION_LIMIT, options->connection_limit,
        MHD_OPTION_PER_IP_CONNECTION_LIMIT, options->per_ip_connection_limit,
        MHD_OPTION_CONNECTION_TIMEOUT, options->connection_timeout_seconds,
        MHD_OPTION_THREAD_STACK_SIZE, (size_t)(1024u * 1024u),
        MHD_OPTION_LISTEN_BACKLOG_SIZE, (unsigned int)1024u,
        MHD_OPTION_URI_LOG_CALLBACK, fb_uri_logger, server,
        MHD_OPTION_UNESCAPE_CALLBACK, fb_uri_unescape, server,
        MHD_OPTION_NOTIFY_COMPLETED, fb_completed, server,
        MHD_OPTION_ARRAY, conditional_options,
        MHD_OPTION_END);
}

static bool fb_workers_start(fb_server *server,
                             char *error,
                             size_t error_capacity) {
    pthread_condattr_t condition_attributes;
    pthread_attr_t worker_attributes;
    size_t bytes;
    size_t index;

    if (pthread_mutex_init(&server->work_mutex, NULL) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot initialize application worker lock");
        return false;
    }
    server->work_mutex_ready = true;
    if (pthread_condattr_init(&condition_attributes) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot initialize application worker condition");
        return false;
    }
    if (pthread_condattr_setclock(&condition_attributes, CLOCK_MONOTONIC) != 0 ||
        pthread_cond_init(&server->work_available, &condition_attributes) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot initialize application worker condition");
        (void)pthread_condattr_destroy(&condition_attributes);
        return false;
    }
    server->work_available_ready = true;
    if (pthread_cond_init(&server->state_changed, &condition_attributes) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot initialize application state condition");
        (void)pthread_condattr_destroy(&condition_attributes);
        return false;
    }
    server->state_changed_ready = true;
    if (pthread_cond_init(&server->deadline_changed, &condition_attributes) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot initialize application deadline condition");
        (void)pthread_condattr_destroy(&condition_attributes);
        return false;
    }
    server->deadline_changed_ready = true;
    (void)pthread_condattr_destroy(&condition_attributes);

    if (!fb_size_mul((size_t)server->options.worker_threads,
                     sizeof(*server->workers), &bytes)) {
        fb_server_error(error, error_capacity,
                        "application worker count is too large");
        return false;
    }
    server->workers = calloc(1u, bytes);
    if (server->workers == NULL) {
        fb_server_error(error, error_capacity,
                        "cannot allocate application workers");
        return false;
    }
    if (pthread_attr_init(&worker_attributes) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot configure application worker stack");
        return false;
    }
    if (pthread_attr_setstacksize(&worker_attributes,
                                  (size_t)(1024u * 1024u)) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot configure application worker stack");
        (void)pthread_attr_destroy(&worker_attributes);
        return false;
    }
    server->accepting_work = true;
    server->workers_stopping = false;
    for (index = 0u; index < server->options.worker_threads; ++index) {
        if (pthread_create(&server->workers[index], &worker_attributes,
                           fb_application_worker, server) != 0) {
            fb_server_error(error, error_capacity,
                            "cannot start application worker");
            (void)pthread_attr_destroy(&worker_attributes);
            return false;
        }
        ++server->started_workers;
    }
    if (pthread_create(&server->deadline_worker, &worker_attributes,
                       fb_deadline_worker_main, server) != 0) {
        fb_server_error(error, error_capacity,
                        "cannot start application deadline worker");
        (void)pthread_attr_destroy(&worker_attributes);
        return false;
    }
    server->deadline_worker_started = true;
    (void)pthread_attr_destroy(&worker_attributes);
    return true;
}

static void fb_workers_stop(fb_server *server) {
    if (server->work_mutex_ready) {
        (void)pthread_mutex_lock(&server->work_mutex);
        server->accepting_work = false;
        server->forcing_work = true;
        server->workers_stopping = true;
        if (server->work_available_ready) {
            (void)pthread_cond_broadcast(&server->work_available);
        }
        if (server->deadline_changed_ready) {
            server->deadline_worker_stopping = true;
            (void)pthread_cond_broadcast(&server->deadline_changed);
        }
        (void)pthread_mutex_unlock(&server->work_mutex);
    }
    fb_deadline_worker_stop(server);
    for (size_t index = 0u; index < server->started_workers; ++index) {
        (void)pthread_join(server->workers[index], NULL);
    }
    server->started_workers = 0u;
    free(server->workers);
    server->workers = NULL;
    if (server->deadline_changed_ready) {
        (void)pthread_cond_destroy(&server->deadline_changed);
        server->deadline_changed_ready = false;
    }
    if (server->state_changed_ready) {
        (void)pthread_cond_destroy(&server->state_changed);
        server->state_changed_ready = false;
    }
    if (server->work_available_ready) {
        (void)pthread_cond_destroy(&server->work_available);
        server->work_available_ready = false;
    }
    if (server->work_mutex_ready) {
        (void)pthread_mutex_destroy(&server->work_mutex);
        server->work_mutex_ready = false;
    }
}

static void fb_resume_chain(fb_connection_request *head) {
    while (head != NULL) {
        fb_connection_request *next = head->queue_next;
        head->queue_next = NULL;
        fb_async_resume(head);
        head = next;
    }
}

static fb_connection_request *fb_cancel_queued_locked(
    fb_server *server,
    fb_force_reason reason) {
    fb_connection_request *request = server->queue_head;
    fb_connection_request *resume_head = NULL;
    server->queue_head = NULL;
    server->queue_tail = NULL;
    server->queued_work = 0u;
    while (request != NULL) {
        fb_connection_request *next = request->queue_next;
        atomic_store_explicit(&request->cancel_requested, true,
                              memory_order_relaxed);
        request->force_reason = reason;
        fb_async_prepare_resume_locked(
            server, request, FB_REQUEST_RESUMED_FORCED, true);
        request->queue_next = resume_head;
        resume_head = request;
        request = next;
    }
    return resume_head;
}

static fb_connection_request *fb_force_active_locked(
    fb_server *server,
    fb_force_reason reason) {
    fb_connection_request *request = server->async_head;
    fb_connection_request *resume_head = NULL;
    while (request != NULL) {
        fb_connection_request *next = request->async_next;
        if (request->phase == FB_REQUEST_RUNNING) {
            atomic_store_explicit(&request->cancel_requested, true,
                                  memory_order_relaxed);
            request->force_reason = reason;
            fb_async_prepare_resume_locked(
                server, request, FB_REQUEST_RESUMED_FORCED, false);
            request->queue_next = resume_head;
            resume_head = request;
        }
        request = next;
    }
    return resume_head;
}

static bool fb_queue_remove_locked(fb_server *server,
                                   fb_connection_request *target) {
    fb_connection_request *previous = NULL;
    fb_connection_request *request = server->queue_head;
    while (request != NULL && request != target) {
        previous = request;
        request = request->queue_next;
    }
    if (request == NULL) {
        return false;
    }
    if (previous == NULL) {
        server->queue_head = request->queue_next;
    } else {
        previous->queue_next = request->queue_next;
    }
    if (server->queue_tail == request) {
        server->queue_tail = previous;
    }
    request->queue_next = NULL;
    if (server->queued_work != 0u) {
        --server->queued_work;
    }
    return true;
}

static const struct timespec *fb_request_phase_deadline(
    const fb_connection_request *request) {
    if (request->phase == FB_REQUEST_QUEUED &&
        fb_timespec_compare(&request->queue_deadline,
                            &request->request_deadline) < 0) {
        return &request->queue_deadline;
    }
    return &request->request_deadline;
}

static fb_force_reason fb_request_timeout_reason(
    const fb_connection_request *request) {
    if (request->phase == FB_REQUEST_QUEUED &&
        fb_timespec_compare(&request->queue_deadline,
                            &request->request_deadline) < 0) {
        return FB_FORCE_QUEUE_TIMEOUT;
    }
    return FB_FORCE_REQUEST_TIMEOUT;
}

static fb_connection_request *fb_expire_async_locked(
    fb_server *server,
    const struct timespec *now,
    struct timespec *next_deadline) {
    fb_connection_request *request = server->async_head;
    fb_connection_request *resume_head = NULL;
    *next_deadline = (struct timespec){0, 0};
    while (request != NULL) {
        fb_connection_request *next = request->async_next;
        const struct timespec *deadline = fb_request_phase_deadline(request);
        if (fb_deadline_expired_at(deadline, now) &&
            (request->phase == FB_REQUEST_QUEUED ||
             request->phase == FB_REQUEST_RUNNING)) {
            const bool queued = request->phase == FB_REQUEST_QUEUED;
            if (!queued || fb_queue_remove_locked(server, request)) {
                atomic_store_explicit(&request->cancel_requested, true,
                                      memory_order_relaxed);
                request->force_reason = fb_request_timeout_reason(request);
                fb_async_prepare_resume_locked(
                    server, request, FB_REQUEST_RESUMED_FORCED, queued);
                request->queue_next = resume_head;
                resume_head = request;
            }
        } else if ((next_deadline->tv_sec == 0 &&
                    next_deadline->tv_nsec == 0) ||
                   fb_timespec_compare(deadline, next_deadline) < 0) {
            *next_deadline = *deadline;
        }
        request = next;
    }
    return resume_head;
}

static void *fb_deadline_worker_main(void *opaque) {
    fb_server *server = opaque;
    (void)pthread_mutex_lock(&server->work_mutex);
    while (!server->deadline_worker_stopping) {
        struct timespec now;
        struct timespec next_deadline;
        fb_connection_request *resume_head = NULL;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            resume_head = fb_expire_async_locked(server, &now,
                                                 &next_deadline);
        } else {
            next_deadline = (struct timespec){0, 0};
        }
        if (resume_head != NULL) {
            (void)pthread_cond_signal(&server->state_changed);
            (void)pthread_mutex_unlock(&server->work_mutex);
            fb_resume_chain(resume_head);
            (void)pthread_mutex_lock(&server->work_mutex);
            continue;
        }
        if (server->deadline_worker_stopping) {
            break;
        }
        if (next_deadline.tv_sec == 0 && next_deadline.tv_nsec == 0) {
            (void)pthread_cond_wait(&server->deadline_changed,
                                    &server->work_mutex);
        } else {
            (void)pthread_cond_timedwait(&server->deadline_changed,
                                         &server->work_mutex,
                                         &next_deadline);
        }
    }
    (void)pthread_mutex_unlock(&server->work_mutex);
    return NULL;
}

static void fb_async_shutdown(fb_server *server,
                              const struct timespec *deadline) {
    fb_connection_request *queued_resume = NULL;
    fb_connection_request *active_resume = NULL;
    bool forced;
    (void)pthread_mutex_lock(&server->work_mutex);
    server->accepting_work = false;
    (void)pthread_cond_broadcast(&server->work_available);
    while (server->request_count != 0u &&
           !fb_deadline_expired(deadline)) {
        const int status = pthread_cond_timedwait(
            &server->state_changed, &server->work_mutex, deadline);
        if (status == ETIMEDOUT) {
            break;
        }
    }
    server->forcing_work = true;
    forced = server->request_count != 0u;
    if (forced) {
        queued_resume = fb_cancel_queued_locked(server, FB_FORCE_SHUTDOWN);
        active_resume = fb_force_active_locked(server, FB_FORCE_SHUTDOWN);
    }
    (void)pthread_mutex_unlock(&server->work_mutex);
    fb_resume_chain(queued_resume);
    fb_resume_chain(active_resume);

    (void)pthread_mutex_lock(&server->work_mutex);
    while (server->suspended_count != 0u || server->resume_inflight != 0u) {
        (void)pthread_cond_wait(&server->state_changed, &server->work_mutex);
    }
    if (forced && server->request_count != 0u) {
        const struct timespec forced_deadline = fb_deadline_after(
            server->options.forced_shutdown_seconds);
        while (server->request_count != 0u &&
               !fb_deadline_expired(&forced_deadline)) {
            const int status = pthread_cond_timedwait(
                &server->state_changed, &server->work_mutex,
                &forced_deadline);
            if (status == ETIMEDOUT) {
                break;
            }
        }
    }
    (void)pthread_mutex_unlock(&server->work_mutex);
}

static void fb_deadline_worker_stop(fb_server *server) {
    if (!server->deadline_worker_started) {
        return;
    }
    (void)pthread_mutex_lock(&server->work_mutex);
    server->deadline_worker_stopping = true;
    (void)pthread_cond_broadcast(&server->deadline_changed);
    (void)pthread_mutex_unlock(&server->work_mutex);
    (void)pthread_join(server->deadline_worker, NULL);
    server->deadline_worker_started = false;
}

fb_server *fb_server_start(const fb_server_options *options_input,
                           fb_http_handler handler,
                           fb_http_should_defer should_defer,
                           void *handler_context,
                           char *error,
                           size_t error_capacity) {
    fb_server_options defaults;
    const fb_server_options *options;
    fb_server *server;
    unsigned int flags;
    bool tcp_fastopen;
    defaults = fb_server_default_options();
    options = options_input == NULL ? &defaults : options_input;
    if (handler == NULL || options->host == NULL || options->io_threads == 0u ||
        options->worker_threads == 0u || options->work_queue_limit == 0u ||
        options->connection_limit == 0u ||
        options->forced_shutdown_seconds == 0u ||
        options->queue_timeout_seconds == 0u ||
        options->request_timeout_seconds == 0u ||
        options->request_arena_bytes < 4096u ||
        options->max_request_target_bytes < 1024u) {
        fb_server_error(error, error_capacity, "invalid server configuration");
        return NULL;
    }
    server = calloc(1, sizeof(*server));
    if (server == NULL) {
        fb_server_error(error, error_capacity, "cannot allocate server state");
        return NULL;
    }
    server->options = *options;
    server->handler = handler;
    server->should_defer = should_defer;
    server->handler_context = handler_context;
    server->sendfile_supported =
        MHD_is_feature_supported(MHD_FEATURE_SENDFILE) == MHD_YES;
    if (!fb_bind_address(server, error, error_capacity)) {
        free(server);
        return NULL;
    }
    if (!fb_workers_start(server, error, error_capacity)) {
        fb_workers_stop(server);
        free(server);
        return NULL;
    }
    flags = MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG |
            MHD_ALLOW_SUSPEND_RESUME | MHD_USE_TURBO;
    if (MHD_is_feature_supported(MHD_FEATURE_EPOLL) == MHD_YES) {
        flags |= MHD_USE_EPOLL;
    } else if (MHD_is_feature_supported(MHD_FEATURE_POLL) == MHD_YES) {
        flags |= MHD_USE_POLL;
    }
    tcp_fastopen = MHD_is_feature_supported(MHD_FEATURE_TCP_FASTOPEN) == MHD_YES;
    if (tcp_fastopen) {
        flags |= MHD_USE_TCP_FASTOPEN;
    }
    if (server->address.ss_family == AF_INET6) {
        flags |= MHD_USE_IPv6;
    }
    server->daemon = fb_start_mhd(server, flags, tcp_fastopen);
    if (server->daemon == NULL && tcp_fastopen) {
        /* Build-time support does not guarantee support in the running kernel. */
        flags &= ~(unsigned int)MHD_USE_TCP_FASTOPEN;
        server->daemon = fb_start_mhd(server, flags, false);
    }
    if (server->daemon == NULL) {
        fb_server_error(error, error_capacity,
                        "libmicrohttpd could not start on %s:%u",
                        options->host, (unsigned)options->port);
        fb_workers_stop(server);
        free(server);
        return NULL;
    }
    {
        const union MHD_DaemonInfo *info = MHD_get_daemon_info(
            server->daemon, MHD_DAEMON_INFO_BIND_PORT);
        server->bound_port = info == NULL ? options->port : info->port;
    }
    return server;
}

void fb_server_stop(fb_server *server) {
    if (server == NULL) {
        return;
    }
    if (server->daemon != NULL) {
        const struct timespec deadline = fb_deadline_after(
            server->options.graceful_shutdown_seconds);
        MHD_socket listen_socket;
        (void)pthread_mutex_lock(&server->work_mutex);
        server->accepting_work = false;
        (void)pthread_mutex_unlock(&server->work_mutex);
        listen_socket = MHD_quiesce_daemon(server->daemon);
        fb_async_shutdown(server, &deadline);
        fb_deadline_worker_stop(server);
        MHD_stop_daemon(server->daemon);
        if (listen_socket != MHD_INVALID_SOCKET) {
            (void)close(listen_socket);
        }
    }
    fb_workers_stop(server);
    free(server);
}

uint16_t fb_server_port(const fb_server *server) {
    return server == NULL ? 0u : server->bound_port;
}
