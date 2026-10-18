#include "fastbed/app.h"

#include "fastbed/assets.h"
#include "fastbed/cache.h"
#include "fastbed/crawler.h"
#include "fastbed/metrics.h"
#include "fastbed/notifier.h"
#include "fastbed/parser.h"
#include "fastbed/render.h"
#include "fastbed/transport.h"

#include <stdarg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fb_app {
    const fb_config *config;
    fb_assets assets;
    fb_crawler_db *crawler_database;
    fb_transport transport;
    fb_notifier *notifier;
    fb_success_cache *success_cache;
    fb_metrics metrics;
};

static void fb_app_error(char *destination, size_t capacity,
                         const char *format, ...)
    FB_PRINTF_FORMAT(3, 4);
static void fb_app_error(char *destination, size_t capacity,
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

fb_app *fb_app_create(const fb_config *config,
                      const fb_app_options *options,
                      char *error,
                      size_t error_capacity) {
    fb_app *app;
    fb_crawler_stats crawler_stats;
    char subsystem_error[512] = {0};
    if (config == NULL || options == NULL ||
        options->max_upstream_body_bytes == 0u) {
        fb_app_error(error, error_capacity, "invalid application configuration");
        return NULL;
    }
    {
        const size_t alignment = _Alignof(fb_app);
        size_t allocation_size = sizeof(*app);
        const size_t remainder = allocation_size % alignment;
        if (remainder != 0u &&
            !fb_size_add(allocation_size, alignment - remainder,
                         &allocation_size)) {
            fb_app_error(error, error_capacity, "application state size overflow");
            return NULL;
        }
        app = aligned_alloc(alignment, allocation_size);
        if (app != NULL) {
            memset(app, 0, allocation_size);
        }
    }
    if (app == NULL) {
        fb_app_error(error, error_capacity, "cannot allocate application state");
        return NULL;
    }
    if (options->enable_internal_cache) {
        app->success_cache = fb_success_cache_create(
            4096u, 64u * 1024u * 1024u, 900u);
    }
    if (options->enable_internal_cache && app->success_cache == NULL) {
        fb_app_error(error, error_capacity,
                     "success cache initialization failed");
        fb_app_destroy(app);
        return NULL;
    }
    app->config = config;
    fb_metrics_init(&app->metrics);
    if (!fb_assets_load(&app->assets, options->asset_directory,
                        subsystem_error, sizeof(subsystem_error))) {
        fb_app_error(error, error_capacity, "asset initialization failed: %s",
                     subsystem_error);
        fb_app_destroy(app);
        return NULL;
    }
#if defined(FASTBED_VERIFICATION_BUILD)
    app->crawler_database = options->crawler_database == NULL
        ? fb_crawler_db_load_embedded(
            subsystem_error, sizeof(subsystem_error))
        : fb_crawler_db_load(
            options->crawler_database, subsystem_error,
            sizeof(subsystem_error));
#else
    app->crawler_database = fb_crawler_db_load_embedded(
        subsystem_error, sizeof(subsystem_error));
#endif
    if (app->crawler_database == NULL) {
        fb_app_error(error, error_capacity,
                     "crawler database initialization failed: %s",
                     subsystem_error);
        fb_app_destroy(app);
        return NULL;
    }
    crawler_stats = fb_crawler_db_stats(app->crawler_database);
    if (crawler_stats.pattern_count == 0u ||
        crawler_stats.chunk_count == 0u) {
        fb_app_error(error, error_capacity, "crawler database is empty");
        fb_app_destroy(app);
        return NULL;
    }
    if (!fb_transport_init(&app->transport,
                           options->max_upstream_body_bytes,
                           options->require_curl_impersonation,
                           subsystem_error, sizeof(subsystem_error))) {
        fb_app_error(error, error_capacity, "transport initialization failed: %s",
                     subsystem_error);
        fb_app_destroy(app);
        return NULL;
    }
    if ((options->replay_http_port != 0u ||
         options->replay_https_port != 0u) &&
        !fb_transport_set_loopback_replay(
            &app->transport, options->replay_http_port,
            options->replay_https_port)) {
        fb_app_error(error, error_capacity,
                     "both loopback replay ports must be configured");
        fb_app_destroy(app);
        return NULL;
    }
    {
        fb_notifier_options notifier_options = fb_notifier_default_options();
        if (!fb_notifier_init(&app->notifier, config, &notifier_options,
                              subsystem_error, sizeof(subsystem_error))) {
            fb_app_error(error, error_capacity,
                         "notifier initialization failed: %s", subsystem_error);
            fb_app_destroy(app);
            return NULL;
        }
    }
    (void)fprintf(stderr,
                  "[INFO] crawler database patterns=%zu chunks=%zu jit=%zu combined=%s\n",
                  crawler_stats.pattern_count, crawler_stats.chunk_count,
                  crawler_stats.jit_chunk_count,
                  crawler_stats.combined_jit ? "jit" : "chunked");
    return app;
}

void fb_app_destroy(fb_app *app) {
    if (app == NULL) {
        return;
    }
    fb_notifier_shutdown(app->notifier);
    fb_success_cache_destroy(app->success_cache);
    fb_transport_cleanup(&app->transport);
    fb_crawler_db_free(app->crawler_database);
    fb_assets_destroy(&app->assets);
    free(app);
}

static bool fb_path_equal(fb_slice path, const char *literal) {
    const size_t length = strlen(literal);
    return path.len == length && path.ptr != NULL &&
           memcmp(path.ptr, literal, length) == 0;
}

static bool fb_request_cancelled(const fb_http_request *request) {
    return request != NULL && request->cancel_requested != NULL &&
           atomic_load_explicit(request->cancel_requested,
                                memory_order_relaxed);
}

static bool fb_cancelled_response(fb_http_response *response) {
    if (response == NULL) {
        return false;
    }
    memset(response, 0, sizeof(*response));
    response->status = 503u;
    response->body = FB_SLICE_LIT("server shutting down\n");
    response->content_type = FB_SLICE_LIT("text/plain; charset=utf-8");
    response->cache_control = FB_SLICE_LIT("no-store");
    response->retry_after = FB_SLICE_LIT("1");
    return true;
}

bool fb_app_http_should_defer(void *context,
                              fb_http_request *request) {
    fb_app *app = context;
    if (app == NULL || request == NULL) {
        return false;
    }
    if (fb_path_equal(request->path, "/healthz") ||
        fb_path_equal(request->path, "/favicon.ico") ||
        fb_path_equal(request->path, "/banner.png") ||
        fb_path_equal(request->path, "/")) {
        return false;
    }
    request->user_agent_is_bot = fb_crawler_is_bot(
        app->crawler_database, request->user_agent.ptr, request->user_agent.len);
    request->user_agent_classified = true;
    return request->user_agent_is_bot;
}

static bool fb_health(fb_app *app,
                      fb_arena *arena,
                      fb_http_response *response) {
    fb_metrics_snapshot snapshot = fb_metrics_read(&app->metrics);
    fb_buf output;
    if (!fb_buf_init(&output, arena, 128u) ||
        !fb_buf_append_cstr(&output, "{\"status\": \"ok\", \"uptime_secs\": ") ||
        !fb_buf_append_u64(&output, snapshot.uptime_seconds) ||
        !fb_buf_append_cstr(&output, ", \"requests\": ") ||
        !fb_buf_append_u64(&output, snapshot.requests) ||
        !fb_buf_append_cstr(&output, ", \"errors\": ") ||
        !fb_buf_append_u64(&output, snapshot.errors) ||
        !fb_buf_append_char(&output, '}')) {
        return false;
    }
    response->status = 200u;
    response->body = fb_buf_view(&output);
    response->content_type = FB_SLICE_LIT("application/json");
    response->cache_control = FB_SLICE_LIT("no-store");
    return true;
}

static bool fb_browser_target(fb_arena *arena,
                              fb_slice raw_target,
                              fb_slice *target) {
    fb_buf output;
    if (!fb_buf_init(&output, arena, raw_target.len + 32u) ||
        !fb_buf_append_cstr(&output, "https://www.facebook.com")) {
        return false;
    }
    if (raw_target.len == 0u || raw_target.ptr[0] != '/') {
        if (!fb_buf_append_char(&output, '/')) {
            return false;
        }
    }
    if (!fb_buf_append(&output, raw_target)) {
        return false;
    }
    *target = fb_buf_view(&output);
    return true;
}

static bool fb_ascii_ends_with_dump(fb_slice path, size_t *prefix_length) {
    size_t end = path.len;
    size_t start;
    static const char word[] = "dump";
    while (end > 0u && path.ptr[end - 1u] == '/') {
        --end;
    }
    if (end < sizeof(word) - 1u) {
        return false;
    }
    start = end - (sizeof(word) - 1u);
    for (size_t index = 0; index < sizeof(word) - 1u; ++index) {
        unsigned char value = (unsigned char)path.ptr[start + index];
        if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
            value = (unsigned char)(value + ('a' - 'A'));
        }
        if (value != (unsigned char)word[index]) {
            return false;
        }
    }
    if (start != 0u && path.ptr[start - 1u] != '/') {
        return false;
    }
    *prefix_length = start == 0u ? 0u : start - 1u;
    return true;
}

static bool fb_parser_path(fb_arena *arena,
                           const fb_http_request *request,
                           fb_slice *path,
                           bool *dump_requested) {
    size_t path_length = request->path.len;
    size_t without_dump = 0u;
    fb_buf output;
    *dump_requested = fb_ascii_ends_with_dump(request->path, &without_dump);
    if (*dump_requested) {
        path_length = without_dump;
    }
    while (path_length > 0u && request->path.ptr[path_length - 1u] == '/') {
        --path_length;
    }
    if (!fb_buf_init(&output, arena,
                     path_length + request->query.len + 2u)) {
        return false;
    }
    if (path_length > 0u) {
        size_t offset = request->path.ptr[0] == '/' ? 1u : 0u;
        if (offset < path_length &&
            !fb_buf_append(&output,
                           fb_slice_make(request->path.ptr + offset,
                                         path_length - offset))) {
            return false;
        }
    }
    if (request->query.ptr != NULL) {
        if (!fb_buf_append_char(&output, '?') ||
            !fb_buf_append(&output, request->query)) {
            return false;
        }
    }
    *path = fb_buf_view(&output);
    return true;
}

static bool fb_original_facebook_url(fb_arena *arena,
                                     fb_slice parser_path,
                                     fb_slice *url) {
    fb_buf output;
    if (!fb_buf_init(&output, arena, parser_path.len + 32u) ||
        !fb_buf_append_cstr(&output, "https://www.facebook.com/") ||
        !fb_buf_append(&output, parser_path)) {
        return false;
    }
    *url = fb_buf_view(&output);
    return true;
}

static void fb_record_parse_metrics(fb_app *app,
                                    const fb_parse_result *result) {
    if (result->error.kind == FB_PARSE_ERROR_CANCELLED) {
        return;
    }
    if (result->error.kind == FB_PARSE_ERROR_NONE) {
        fb_metrics_record_request(&app->metrics);
        return;
    }
    if (result->error.kind == FB_PARSE_ERROR_UNSUPPORTED_ROUTE) {
        return;
    }
    if (!result->parser_entered &&
        result->error.kind == FB_PARSE_ERROR_SHARE_RESOLUTION) {
        if (result->error.count_as_error) {
            fb_metrics_record_error(&app->metrics);
        }
        return;
    }
    fb_metrics_record_request(&app->metrics);
    fb_metrics_record_error(&app->metrics);
}

static void fb_log_fallback(const fb_http_request *request,
                            fb_slice original_url,
                            const fb_parse_result *result) {
    enum { FB_FALLBACK_DETAIL_MAX = 240 };
    fb_slice reason = result->error.reason.ptr == NULL ||
                              result->error.reason.len == 0u
                          ? FB_SLICE_LIT("internal_error")
                          : result->error.reason;
    size_t url_length = original_url.len;
    bool query_redacted = false;
    char detail[FB_FALLBACK_DETAIL_MAX + 1u];
    size_t detail_length = 0u;
    size_t detail_index = 0u;
    bool pending_space = false;
    if (original_url.ptr != NULL) {
        const char *query = memchr(original_url.ptr, '?', original_url.len);
        if (query != NULL) {
            url_length = (size_t)(query - original_url.ptr);
            query_redacted = true;
        }
    }
    for (;
         detail_index < result->error.detail.len &&
         detail_length < FB_FALLBACK_DETAIL_MAX;
         ++detail_index) {
        const unsigned char value =
            (unsigned char)result->error.detail.ptr[detail_index];
        if (value <= 0x20u || value == 0x7fu) {
            pending_space = detail_length != 0u;
            continue;
        }
        if (pending_space && detail_length < FB_FALLBACK_DETAIL_MAX) {
            detail[detail_length++] = ' ';
        }
        pending_space = false;
        detail[detail_length++] = (char)value;
    }
    detail[detail_length] = '\0';
    (void)fprintf(stderr,
                  "[WARNING] embed fallback type=unknown reason=%.*s "
                  "url=%.*s%s detail=%.*s%s\n",
                  (int)(reason.len > (size_t)INT_MAX ? INT_MAX : reason.len),
                  reason.ptr,
                  (int)(url_length > (size_t)INT_MAX ? INT_MAX : url_length),
                  original_url.ptr == NULL ? "" : original_url.ptr,
                  query_redacted ? "?[redacted]" : "",
                  (int)(detail_length > (size_t)INT_MAX
                            ? INT_MAX : detail_length),
                  detail,
                  detail_index < result->error.detail.len ? "..." : "");
    (void)request;
}

bool fb_app_handle_http(void *context,
                        fb_arena *request_arena,
                        const fb_http_request *request,
                        fb_http_response *response) {
    fb_app *app = context;
    fb_slice target;
    fb_slice parser_path;
    fb_slice original_url;
    fb_slice rendered;
    fb_slice cached_log_title = {0};
    bool dump_requested;
    fb_transport_scope transport_scope;
    fb_parse_result parsed;
    fb_cancel_token cancel;
    fb_cache_reservation cache_reservation = {0};
    fb_cache_lookup_result cache_result = FB_CACHE_BYPASS;
    char transport_error[256] = {0};
    if (app == NULL || request_arena == NULL || request == NULL || response == NULL) {
        return false;
    }
    cancel = fb_cancel_token_from_flag(request->cancel_requested);
    memset(response, 0, sizeof(*response));
    if (fb_path_equal(request->path, "/healthz")) {
        return fb_health(app, request_arena, response);
    }
    if (fb_path_equal(request->path, "/favicon.ico")) {
        const int descriptor = fb_assets_favicon_fd(&app->assets);
        response->status = 200u;
        response->body = fb_assets_favicon(&app->assets);
        if (descriptor >= 0) {
            response->body_source = FB_HTTP_BODY_BORROWED_FD;
            response->body_fd = descriptor;
        }
        response->content_type = FB_SLICE_LIT("image/vnd.microsoft.icon");
        return true;
    }
    if (fb_path_equal(request->path, "/banner.png")) {
        const int descriptor = fb_assets_banner_fd(&app->assets);
        response->status = 200u;
        response->body = fb_assets_banner(&app->assets);
        if (descriptor >= 0) {
            response->body_source = FB_HTTP_BODY_BORROWED_FD;
            response->body_fd = descriptor;
        }
        response->content_type = FB_SLICE_LIT("image/png");
        return true;
    }
    if (fb_path_equal(request->path, "/")) {
        response->status = 200u;
        response->body = fb_assets_index(&app->assets);
        response->content_type = FB_SLICE_LIT("text/html; charset=UTF-8");
        return true;
    }
    if (fb_request_cancelled(request)) {
        return fb_cancelled_response(response);
    }
    response->vary_user_agent = true;
    response->cache_control = FB_SLICE_LIT("no-store");
    if (!(request->user_agent_classified
              ? request->user_agent_is_bot
              : fb_crawler_is_bot(app->crawler_database,
                                  request->user_agent.ptr,
                                  request->user_agent.len))) {
        if (!fb_browser_target(request_arena, request->raw_target, &target) ||
            !fb_render_browser_redirect(request_arena, target, &rendered)) {
            return false;
        }
        response->status = 302u;
        response->body = rendered;
        response->content_type = FB_SLICE_LIT("text/html; charset=UTF-8");
        response->location = target;
        return true;
    }
    if (!fb_parser_path(request_arena, request, &parser_path, &dump_requested) ||
        !fb_original_facebook_url(request_arena, parser_path, &original_url)) {
        return false;
    }
    if (!dump_requested && app->success_cache != NULL) {
        cache_result = fb_success_cache_lookup_cancelable(
            app->success_cache, request_arena, parser_path, &rendered,
            &cached_log_title, &cache_reservation,
            request->cancel_requested);
        if (fb_request_cancelled(request)) {
            fb_success_cache_abort(app->success_cache, &cache_reservation,
                                   parser_path);
            return fb_cancelled_response(response);
        }
        if (cache_result == FB_CACHE_HIT) {
            fb_metrics_record_request(&app->metrics);
            response->status = 200u;
            response->body = rendered;
            response->content_type = FB_SLICE_LIT("text/html; charset=UTF-8");
            response->cache_control = FB_SLICE_LIT("public, max-age=900");
            response->log_title = cached_log_title;
            return true;
        }
    }
    if (!fb_transport_scope_init(&transport_scope, &app->transport,
                                 request_arena, transport_error,
                                 sizeof(transport_error))) {
        fb_success_cache_abort(app->success_cache, &cache_reservation,
                               parser_path);
        if (fb_request_cancelled(request)) {
            return fb_cancelled_response(response);
        }
        if (!fb_render_fallback(request_arena, original_url, &rendered)) {
            return false;
        }
        fb_metrics_record_request(&app->metrics);
        fb_metrics_record_error(&app->metrics);
        response->status = 200u;
        response->body = rendered;
        response->content_type = FB_SLICE_LIT("text/html; charset=UTF-8");
        return true;
    }
    fb_transport_scope_set_cancel_flag(&transport_scope,
                                       request->cancel_requested);
    parsed = fb_parse_request_cancelable(
        request_arena, app->config, &transport_scope, parser_path, &cancel);
    if (parsed.error.kind == FB_PARSE_ERROR_CANCELLED ||
        fb_cancel_requested(&cancel)) {
        fb_success_cache_abort(app->success_cache, &cache_reservation,
                               parser_path);
        fb_transport_scope_destroy(&transport_scope);
        return fb_cancelled_response(response);
    }
    fb_record_parse_metrics(app, &parsed);
    if (parsed.error.kind == FB_PARSE_ERROR_NONE) {
        fb_render_status render_status = fb_render_post_cancelable(
            request_arena, &parsed.post,
            fb_config_timezone(app->config), &cancel, &rendered);
        if (render_status == FB_RENDER_CANCELLED) {
            fb_success_cache_abort(app->success_cache, &cache_reservation,
                                   parser_path);
            fb_transport_scope_destroy(&transport_scope);
            return fb_cancelled_response(response);
        }
        if (render_status != FB_RENDER_OK) {
            fb_success_cache_abort(app->success_cache, &cache_reservation,
                                   parser_path);
            fb_transport_scope_destroy(&transport_scope);
            return false;
        }
        if (fb_cancel_requested(&cancel)) {
            fb_success_cache_abort(app->success_cache, &cache_reservation,
                                   parser_path);
            fb_transport_scope_destroy(&transport_scope);
            return fb_cancelled_response(response);
        }
        response->status = 200u;
        response->body = rendered;
        response->content_type = FB_SLICE_LIT("text/html; charset=UTF-8");
        response->cache_control = dump_requested
                                      ? FB_SLICE_LIT("no-store")
                                      : FB_SLICE_LIT("public, max-age=900");
        response->log_title = parsed.post.author_name;
        if (cache_result == FB_CACHE_OWNER) {
            fb_success_cache_commit(app->success_cache, &cache_reservation,
                                    parser_path, rendered,
                                    parsed.post.author_name);
        }
    } else {
        fb_success_cache_abort(app->success_cache, &cache_reservation,
                               parser_path);
        if (fb_request_cancelled(request)) {
            fb_transport_scope_destroy(&transport_scope);
            return fb_cancelled_response(response);
        }
        fb_log_fallback(request, original_url, &parsed);
        if (parsed.error.kind == FB_PARSE_ERROR_NO_DATA ||
            parsed.error.kind == FB_PARSE_ERROR_SHARE_RESOLUTION) {
            fb_notifier_enqueue_result notify_result =
                fb_notifier_enqueue_restricted(
                    app->notifier, parser_path, parsed.error.reason,
                    parsed.error.detail,
                    parsed.error.upstream_response != NULL
                        ? parsed.error.upstream_response
                        : parsed.selected_response);
            if (notify_result != FB_NOTIFIER_ENQUEUE_QUEUED &&
                notify_result != FB_NOTIFIER_ENQUEUE_DISABLED) {
                (void)fprintf(stderr,
                              "[WARNING] restricted report not queued: %s\n",
                              fb_notifier_enqueue_result_string(notify_result));
            }
        }
        if (!fb_render_fallback(request_arena, original_url, &rendered)) {
            fb_transport_scope_destroy(&transport_scope);
            return false;
        }
        response->status = 200u;
        response->body = rendered;
        response->content_type = FB_SLICE_LIT("text/html; charset=UTF-8");
    }
    if (fb_request_cancelled(request)) {
        fb_transport_scope_destroy(&transport_scope);
        return fb_cancelled_response(response);
    }
    if (dump_requested) {
        fb_notifier_enqueue_result notify_result = fb_notifier_enqueue_dump(
            app->notifier, parser_path,
            parsed.selected_response != NULL
                ? parsed.selected_response : parsed.last_response);
        if (notify_result != FB_NOTIFIER_ENQUEUE_QUEUED &&
            notify_result != FB_NOTIFIER_ENQUEUE_DISABLED &&
            notify_result != FB_NOTIFIER_ENQUEUE_INVALID_ARGUMENT) {
            (void)fprintf(stderr, "[WARNING] dump report not queued: %s\n",
                          fb_notifier_enqueue_result_string(notify_result));
        }
    }
    fb_transport_scope_destroy(&transport_scope);
    return true;
}
