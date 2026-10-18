#ifndef FASTBED_PARSER_H
#define FASTBED_PARSER_H

#include <stdbool.h>

#include "fastbed/arena.h"
#include "fastbed/cancel.h"
#include "fastbed/config.h"
#include "fastbed/model.h"
#include "fastbed/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Public error algebra for one Facebook parse attempt.  `reason` is the
 * stable Facebed reason code (for example `login_wall` or
 * `upstream_http_503`); `detail` is diagnostic text and must not be used for
 * control flow.  Both slices are request-arena-owned or static.
 */
typedef enum {
    FB_PARSE_ERROR_NONE = 0,
    FB_PARSE_ERROR_NO_DATA,
    FB_PARSE_ERROR_UNSUPPORTED_ROUTE,
    FB_PARSE_ERROR_SHARE_RESOLUTION,
    FB_PARSE_ERROR_DOCUMENT,
    FB_PARSE_ERROR_UPSTREAM,
    FB_PARSE_ERROR_NO_MEMORY,
    FB_PARSE_ERROR_INVALID_ARGUMENT,
    FB_PARSE_ERROR_CANCELLED
} fb_parse_error_kind;

typedef struct {
    fb_parse_error_kind kind;
    fb_slice reason;
    fb_slice detail;
    fb_upstream_response *upstream_response;
    bool terminal;
    bool count_as_error;
} fb_parse_error;

typedef struct {
    fb_post post;
    fb_parse_error error;
    fb_upstream_response *selected_response;
    fb_upstream_response *last_response;
    bool parser_entered;
} fb_parse_result;

/*
 * Parse one normalized Facebed route.  Relative paths and full Facebook URLs
 * are accepted.  Share resolution, parser dispatch, route fallbacks, target
 * identity validation, and banned-user substitution happen inside this call.
 * The returned post and diagnostic slices remain valid until `arena` resets.
 */
FB_NODISCARD fb_parse_result fb_parse_request(
    fb_arena *arena,
    const fb_config *config,
    fb_transport_scope *scope,
    fb_slice normalized_path
);

FB_NODISCARD fb_parse_result fb_parse_request_cancelable(
    fb_arena *arena,
    const fb_config *config,
    fb_transport_scope *scope,
    fb_slice normalized_path,
    const fb_cancel_token *cancel
);

static inline bool
fb_parse_ok(const fb_parse_result *result)
{
    return result != NULL && result->error.kind == FB_PARSE_ERROR_NONE;
}

const char *fb_parse_error_kind_string(fb_parse_error_kind kind);

#ifdef __cplusplus
}
#endif

#endif
