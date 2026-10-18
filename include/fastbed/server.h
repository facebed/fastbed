#ifndef FASTBED_SERVER_H
#define FASTBED_SERVER_H

#include "fastbed/arena.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct {
    fb_slice raw_target;
    fb_slice path;
    fb_slice query;
    fb_slice method;
    fb_slice version;
    fb_slice user_agent;
    fb_slice host;
    fb_slice remote_address;
    const atomic_bool *cancel_requested;
    bool user_agent_classified;
    bool user_agent_is_bot;
    bool is_head;
} fb_http_request;

typedef enum {
    FB_HTTP_BODY_MEMORY = 0,
    FB_HTTP_BODY_BORROWED_FD,
} fb_http_body_source;

typedef struct {
    unsigned status;
    /*
     * body.len is the exact representation length. For a borrowed descriptor,
     * body.ptr is the persistent mapped fallback and body_fd remains owned by
     * the application.
     */
    fb_slice body;
    fb_http_body_source body_source;
    int body_fd;
    fb_slice content_type;
    fb_slice cache_control;
    fb_slice location;
    fb_slice retry_after;
    /* Request-owned display metadata; never serialized as an HTTP header. */
    fb_slice log_title;
    bool vary_user_agent;
    bool close_connection;
} fb_http_response;

typedef bool (*fb_http_handler)(void *context,
                                fb_arena *request_arena,
                                const fb_http_request *request,
                                fb_http_response *response);

/*
 * Return true only when the handler may block. The callback runs on an MHD I/O
 * thread and may annotate request-local classification fields, but must not do
 * network or filesystem I/O.
 */
typedef bool (*fb_http_should_defer)(void *context,
                                     fb_http_request *request);

typedef struct {
    const char *host;
    uint16_t port;
    unsigned io_threads;
    unsigned worker_threads;
    size_t work_queue_limit;
    unsigned connection_limit;
    unsigned per_ip_connection_limit;
    unsigned connection_timeout_seconds;
    unsigned graceful_shutdown_seconds;
    unsigned forced_shutdown_seconds;
    unsigned queue_timeout_seconds;
    unsigned request_timeout_seconds;
    size_t request_arena_bytes;
    size_t max_request_target_bytes;
} fb_server_options;

typedef struct fb_server fb_server;

fb_server_options fb_server_default_options(void);
fb_server *fb_server_start(const fb_server_options *options,
                           fb_http_handler handler,
                           fb_http_should_defer should_defer,
                           void *handler_context,
                           char *error,
                           size_t error_capacity);
void fb_server_stop(fb_server *server);
uint16_t fb_server_port(const fb_server *server);

#endif
