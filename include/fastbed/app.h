#ifndef FASTBED_APP_H
#define FASTBED_APP_H

#include "fastbed/config.h"
#include "fastbed/server.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct fb_app fb_app;

typedef struct {
    const char *asset_directory;
    const char *crawler_database;
    size_t max_upstream_body_bytes;
    bool require_curl_impersonation;
    uint16_t replay_http_port;
    uint16_t replay_https_port;
    bool enable_internal_cache;
} fb_app_options;

fb_app *fb_app_create(const fb_config *config,
                      const fb_app_options *options,
                      char *error,
                      size_t error_capacity);
void fb_app_destroy(fb_app *app);

bool fb_app_http_should_defer(void *context,
                              fb_http_request *request);

bool fb_app_handle_http(void *context,
                        fb_arena *request_arena,
                        const fb_http_request *request,
                        fb_http_response *response);

#endif

