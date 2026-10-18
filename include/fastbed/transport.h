#ifndef FASTBED_TRANSPORT_H
#define FASTBED_TRANSPORT_H

#include "fastbed/arena.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef enum {
    FB_HTTP_GET = 0,
    FB_HTTP_HEAD = 1,
} fb_http_method;

typedef enum {
    FB_TRANSPORT_OK = 0,
    FB_TRANSPORT_OUT_OF_MEMORY,
    FB_TRANSPORT_IMPERSONATION_UNAVAILABLE,
    FB_TRANSPORT_CURL_ERROR,
    FB_TRANSPORT_HTTP_ERROR,
    FB_TRANSPORT_BODY_TOO_LARGE,
    FB_TRANSPORT_UNSAFE_REDIRECT,
    FB_TRANSPORT_REDIRECT_LOOP,
    FB_TRANSPORT_TOO_MANY_REDIRECTS,
    FB_TRANSPORT_INVALID_ARGUMENT,
} fb_transport_code;

typedef struct {
    fb_http_method method;
    fb_slice requested_url;
    fb_slice effective_url;
    long status;
    size_t body_bytes;
    unsigned attempt;
    unsigned redirect_hop;
} fb_physical_request;

typedef struct {
    fb_http_method method;
    fb_slice requested_url;
    fb_slice effective_url;
    long status;
    fb_slice location;
} fb_redirect_hop;

typedef struct fb_upstream_response {
    fb_http_method method;
    fb_slice requested_url;
    fb_slice url;
    long status;
    fb_slice body;
    fb_slice content_type;
    fb_slice location;
    fb_slice retry_after;
    fb_redirect_hop *history;
    size_t history_count;
    unsigned attempt;
} fb_upstream_response;

typedef struct {
    fb_http_method method;
    fb_slice user_agent;
    bool check_status;
    bool retry_status_responses;
    bool bypass_cache;
    bool follow_redirects;
    unsigned max_redirects;
} fb_transport_options;

typedef struct {
    fb_transport_code code;
    fb_upstream_response *response;
    char detail[256];
} fb_transport_result;

typedef struct {
    size_t max_body_bytes;
    /* Aggregate allocation bound for response bodies owned by one request
     * scope, including both in-flight curl captures and retained responses. */
    size_t max_scope_body_storage_bytes;
    bool require_impersonation;
    uint16_t replay_http_port;
    uint16_t replay_https_port;
} fb_transport;

typedef struct {
    fb_slice url;
    fb_slice user_agent;
    bool follow_redirects;
    unsigned max_redirects;
    fb_upstream_response *response;
} fb_transport_cache_entry;

typedef struct {
    fb_transport *transport;
    fb_arena *arena;
    /* Private transport state; response bodies remain valid until destroy. */
    void *easy;
    void *easy_cache;
    void *owned_response_bodies;
    const atomic_bool *cancel_requested;
    fb_transport_cache_entry cache[16];
    size_t cache_count;
    fb_physical_request *physical_requests;
    size_t physical_count;
    size_t physical_capacity;
    /* Observable request-scope accounting for owned body allocations. */
    size_t body_storage_bytes;
    size_t retained_body_storage_bytes;
    size_t body_storage_peak_bytes;
    fb_upstream_response *last_get_response;
    fb_upstream_response *selected_get_response;
} fb_transport_scope;

bool fb_transport_init(fb_transport *transport,
                       size_t max_body_bytes,
                       bool require_impersonation,
                       char *error,
                       size_t error_capacity);
void fb_transport_cleanup(fb_transport *transport);
/* Configure before creating request scopes. A smaller value deliberately
 * tightens the aggregate limit independently of the per-response body cap. */
bool fb_transport_set_scope_body_storage_limit(fb_transport *transport,
                                               size_t max_storage_bytes);
bool fb_transport_set_loopback_replay(fb_transport *transport,
                                      uint16_t http_port,
                                      uint16_t https_port);

bool fb_transport_scope_init(fb_transport_scope *scope,
                             fb_transport *transport,
                             fb_arena *arena,
                             char *error,
                             size_t error_capacity);
void fb_transport_scope_destroy(fb_transport_scope *scope);
void fb_transport_scope_set_cancel_flag(fb_transport_scope *scope,
                                        const atomic_bool *cancel_requested);

fb_transport_options fb_transport_default_options(fb_http_method method);
fb_transport_result fb_transport_request(fb_transport_scope *scope,
                                         fb_slice url,
                                         const fb_transport_options *options);

void fb_transport_select_response(fb_transport_scope *scope,
                                  fb_upstream_response *response);
const char *fb_http_method_name(fb_http_method method);
const char *fb_transport_code_name(fb_transport_code code);

#endif

