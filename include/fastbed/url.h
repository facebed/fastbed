#ifndef FASTBED_URL_H
#define FASTBED_URL_H

#include <stdbool.h>
#include <stddef.h>

#include "fastbed/arena.h"
#include "fastbed/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Small-vector sizes cover every normal Facebook route without an allocation. */
#define FB_URL_INLINE_SEGMENTS 8u
#define FB_URL_INLINE_QUERY_PAIRS 12u
#define FB_URL_INLINE_IDS 8u

typedef enum {
    FB_URL_OK = 0,
    FB_URL_INVALID,
    FB_URL_UNSAFE,
    FB_URL_NO_MEMORY,
    FB_URL_LIMIT
} fb_url_status;

/*
 * A borrowed, length-aware URL view.  `path` follows urllib.parse.urlparse:
 * a semicolon parameter on the final path component is split into `params`.
 */
typedef struct {
    fb_slice source;
    fb_slice scheme;
    fb_slice authority;
    fb_slice host;
    fb_slice path;
    fb_slice params;
    fb_slice query;
    fb_slice fragment;
    bool has_authority;
    bool has_userinfo;
    bool has_params;
    bool has_query;
    bool has_fragment;
} fb_url_view;

typedef struct {
    fb_slice key;
    fb_slice value;
} fb_query_pair;

typedef struct {
    size_t len;
    fb_query_pair inline_pairs[FB_URL_INLINE_QUERY_PAIRS];
    fb_query_pair *overflow;
} fb_query;

typedef struct {
    size_t len;
    fb_slice inline_items[FB_URL_INLINE_SEGMENTS];
    fb_slice *overflow;
} fb_path_segments;

typedef struct {
    size_t len;
    fb_slice inline_items[FB_URL_INLINE_IDS];
    fb_slice *overflow;
} fb_requested_ids;

typedef enum {
    FB_COMMENT_TARGET_NONE = 0,
    FB_COMMENT_TARGET_VALID,
    FB_COMMENT_TARGET_INVALID
} fb_comment_target_kind;

typedef struct {
    fb_comment_target_kind kind;
    fb_slice comment_id;
    fb_slice reply_comment_id;
    bool has_reply;
} fb_comment_target;

/* Parsing borrows `input`; constructed and decoded results below use `arena`. */
fb_url_status fb_url_parse(fb_slice input, fb_url_view *out);

fb_url_status fb_query_parse(
    fb_arena *arena,
    fb_slice raw_query,
    bool keep_blank_values,
    fb_query *out
);
const fb_query_pair *fb_query_at(const fb_query *query, size_t index);
size_t fb_query_count(const fb_query *query, fb_slice key);

fb_url_status fb_url_ensure_full(
    fb_arena *arena,
    fb_slice input,
    fb_slice *out
);
fb_url_status fb_url_normalize_facebook_path(
    fb_arena *arena,
    fb_slice input,
    fb_slice *out
);

bool fb_url_is_facebook(fb_slice url, bool require_https);
bool fb_url_is_safe_media(fb_slice url);
bool fb_url_is_safe_redirect(fb_slice url);

fb_url_status fb_url_facebook_path_segments(
    fb_arena *arena,
    fb_slice input,
    fb_path_segments *out
);
fb_slice fb_path_segment_at(const fb_path_segments *segments, size_t index);

bool fb_url_is_control_path(
    fb_slice input,
    const fb_slice *names,
    size_t name_count
);
bool fb_url_is_auth_control_path(fb_slice input);
bool fb_url_is_post_like_path(fb_slice input);
bool fb_url_is_share_path(fb_slice input);
bool fb_url_is_group_landing_target(fb_slice input);
bool fb_url_is_supported_post_route(fb_slice input);

fb_url_status fb_url_requested_ids(
    fb_arena *arena,
    fb_slice post_path,
    fb_requested_ids *out
);
fb_slice fb_requested_id_at(const fb_requested_ids *ids, size_t index);

/* Mirrors CommentParser.get_target, including duplicate and blank handling. */
fb_url_status fb_url_comment_target(
    fb_arena *arena,
    fb_slice post_path,
    fb_comment_target *out
);
bool fb_comment_targets_equal(
    const fb_comment_target *left,
    const fb_comment_target *right
);

/*
 * Validate a resolved share target and carry the source comment identity onto
 * it.  A conflicting resolved identity returns FB_URL_INVALID.
 */
fb_url_status fb_url_preserve_comment_target(
    fb_arena *arena,
    fb_slice resolved_url,
    const fb_comment_target *source_target,
    fb_slice *out
);

/* Direct story.php and watch?v= request canonicalization. */
fb_url_status fb_url_normalize_request_path(
    fb_arena *arena,
    fb_slice input,
    fb_slice *out,
    bool *changed
);

/* RFC-3986-style resolution used for explicit, cookie-free redirect hops. */
fb_url_status fb_url_join(
    fb_arena *arena,
    fb_slice base,
    fb_slice reference,
    fb_slice *out
);
fb_url_status fb_url_resolve_redirect(
    fb_arena *arena,
    fb_slice base,
    fb_slice location,
    fb_slice *out
);

const char *fb_url_status_string(fb_url_status status);

#ifdef __cplusplus
}
#endif

#endif
