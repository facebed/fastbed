#ifndef FASTBED_DOCUMENT_H
#define FASTBED_DOCUMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fastbed/arena.h"
#include "fastbed/cancel.h"
#include "fastbed/common.h"
#include "yyjson.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defaults are deliberately above the retained Facebed corpus high-water
 * marks.  They remain finite because every input byte is controlled by an
 * upstream HTTP peer.  A caller may supply tighter request-specific limits.
 */
#define FB_DOCUMENT_DEFAULT_MAX_BODY_BYTES (64u * 1024u * 1024u)
#define FB_DOCUMENT_DEFAULT_MAX_SCRIPTS 8192u
#define FB_DOCUMENT_DEFAULT_MAX_JSON_BYTES (32u * 1024u * 1024u)
#define FB_DOCUMENT_DEFAULT_MAX_JSON_VALUES (4u * 1024u * 1024u)
#define FB_DOCUMENT_DEFAULT_MAX_TOTAL_JSON_VALUES (8u * 1024u * 1024u)
#define FB_DOCUMENT_DEFAULT_MAX_DEPTH 256u
#define FB_DOCUMENT_DEFAULT_MAX_DECLARED_URLS 4096u
#define FB_DOCUMENT_DEFAULT_MAX_FORMS 1024u
#define FB_DOCUMENT_DEFAULT_MAX_FORM_CONTROLS 32768u
#define FB_DOCUMENT_DEFAULT_MAX_ATTRIBUTES_PER_TAG 2048u

typedef struct fb_document fb_document;
typedef struct fb_json_block fb_json_block;

typedef struct {
    size_t max_body_bytes;
    size_t max_scripts;
    size_t max_json_bytes;
    size_t max_json_values;
    size_t max_total_json_values;
    size_t max_depth;
    size_t max_declared_urls;
    size_t max_forms;
    size_t max_form_controls;
    size_t max_attributes_per_tag;
} fb_document_limits;

typedef enum {
    FB_DOCUMENT_OK = 0,
    FB_DOCUMENT_INVALID_ARGUMENT,
    FB_DOCUMENT_NO_MEMORY,
    FB_DOCUMENT_MALFORMED_HTML,
    FB_DOCUMENT_LIMIT_EXCEEDED,
    FB_DOCUMENT_CANCELLED
} fb_document_status;

typedef enum {
    FB_DOCUMENT_ISSUE_NONE = 0,
    FB_DOCUMENT_ISSUE_UNTERMINATED_COMMENT,
    FB_DOCUMENT_ISSUE_UNTERMINATED_TAG,
    FB_DOCUMENT_ISSUE_UNTERMINATED_ATTRIBUTE,
    FB_DOCUMENT_ISSUE_UNTERMINATED_SCRIPT,
    FB_DOCUMENT_ISSUE_NESTED_FORM,
    FB_DOCUMENT_ISSUE_BODY_LIMIT,
    FB_DOCUMENT_ISSUE_SCRIPT_LIMIT,
    FB_DOCUMENT_ISSUE_SCRIPT_BYTES_LIMIT,
    FB_DOCUMENT_ISSUE_JSON_VALUE_LIMIT,
    FB_DOCUMENT_ISSUE_JSON_TOTAL_VALUE_LIMIT,
    FB_DOCUMENT_ISSUE_JSON_DEPTH_LIMIT,
    FB_DOCUMENT_ISSUE_DECLARED_URL_LIMIT,
    FB_DOCUMENT_ISSUE_FORM_LIMIT,
    FB_DOCUMENT_ISSUE_FORM_CONTROL_LIMIT,
    FB_DOCUMENT_ISSUE_TAG_ATTRIBUTE_LIMIT,
    FB_DOCUMENT_ISSUE_INTERNAL_INDEX_LIMIT
} fb_document_issue;

typedef struct {
    fb_document_status status;
    fb_document_issue issue;
    size_t source_offset;
    size_t script_index;
    yyjson_read_code json_code;
    size_t json_offset;
} fb_document_error;

typedef enum {
    FB_JSON_SCRIPT_VALID = 0,
    FB_JSON_SCRIPT_EMPTY,
    FB_JSON_SCRIPT_INVALID
} fb_json_script_status;

typedef struct {
    fb_slice raw_text;
    size_t source_offset;
    fb_json_script_status status;
    yyjson_read_code read_code;
    size_t error_offset;
    const fb_json_block *block;
} fb_json_script;

typedef enum {
    FB_DECLARED_URL_CANONICAL = 1,
    FB_DECLARED_URL_OG_URL = 2
} fb_declared_url_kind;

typedef struct {
    fb_declared_url_kind kind;
    /* Decoded like an HTML attribute; may borrow raw_body when unchanged. */
    fb_slice value;
    /* Exact attribute bytes inside raw_body, without surrounding quotes. */
    fb_slice raw_value;
    size_t source_offset;
} fb_declared_url;

typedef struct {
    fb_slice action;
    fb_slice method;
    fb_slice id;
    fb_slice name;
    size_t source_offset;
    size_t control_count;
} fb_html_form;

typedef struct {
    fb_slice name;
    fb_slice type;
    fb_slice id;
    size_t source_offset;
} fb_html_form_control;

/*
 * A semantic match is one Python would observe after json.loads(): a duplicate
 * key keeps its first insertion position but its final value.  pair_index is
 * the raw pair that supplied that final value.
 */
typedef struct {
    const yyjson_val *object;
    const yyjson_val *value;
    fb_slice key;
    size_t block_index;
    size_t traversal_rank;
    size_t pair_index;
    bool effective;
} fb_json_match;

typedef struct {
    const yyjson_val *value;
    size_t block_index;
    size_t traversal_rank;
} fb_json_node_ref;

/* Stateful effective-match cursors; key storage is borrowed for cursor lifetime. */
typedef struct {
    const fb_json_block *block_state;
    const void *entry_state;
    fb_slice key_state;
    uint32_t next_occurrence_state;
} fb_json_block_match_cursor;

typedef struct {
    const fb_document *document_state;
    fb_slice key_state;
    size_t block_index_state;
    fb_json_block_match_cursor block_cursor_state;
} fb_json_document_match_cursor;

typedef enum {
    FB_JSON_NUMBER_NONE = 0,
    FB_JSON_NUMBER_UINT,
    FB_JSON_NUMBER_SINT,
    FB_JSON_NUMBER_REAL,
    FB_JSON_NUMBER_BIG_INTEGER,
    FB_JSON_NUMBER_BIG_REAL,
    FB_JSON_NUMBER_NAN,
    FB_JSON_NUMBER_POS_INFINITY,
    FB_JSON_NUMBER_NEG_INFINITY
} fb_json_number_kind;

void fb_document_limits_default(fb_document_limits *limits);

/*
 * The document, decoded attributes, yyjson documents, indexes, and candidates
 * are request-arena-owned. raw_body itself is borrowed and is never modified;
 * its storage must outlive the arena-backed document.
 */
FB_NODISCARD fb_document_status fb_document_parse(
    fb_arena *arena,
    fb_slice raw_body,
    const fb_document_limits *limits,
    fb_document **out,
    fb_document_error *error
);

FB_NODISCARD fb_document_status fb_document_parse_cancelable(
    fb_arena *arena,
    fb_slice raw_body,
    const fb_document_limits *limits,
    const fb_cancel_token *cancel,
    fb_document **out,
    fb_document_error *error
);

fb_slice fb_document_raw_body(const fb_document *document);
size_t fb_document_script_count(const fb_document *document);
const fb_json_script *fb_document_script_at(
    const fb_document *document,
    size_t index
);
size_t fb_document_json_block_count(const fb_document *document);
const fb_json_block *fb_document_json_block_at(
    const fb_document *document,
    size_t index
);
size_t fb_document_invalid_json_count(const fb_document *document);

size_t fb_document_declared_url_count(
    const fb_document *document,
    fb_declared_url_kind kind
);
const fb_declared_url *fb_document_declared_url_at(
    const fb_document *document,
    fb_declared_url_kind kind,
    size_t index
);

size_t fb_document_form_count(const fb_document *document);
const fb_html_form *fb_document_form_at(
    const fb_document *document,
    size_t index
);
const fb_html_form_control *fb_document_form_control_at(
    const fb_document *document,
    size_t form_index,
    size_t control_index
);
bool fb_document_has_login_form(const fb_document *document);

const yyjson_val *fb_json_block_root(const fb_json_block *block);
size_t fb_json_block_index(const fb_json_block *block);
size_t fb_json_block_value_count(const fb_json_block *block);
size_t fb_json_block_object_count(const fb_json_block *block);
const yyjson_val *fb_json_block_object_at(
    const fb_json_block *block,
    size_t traversal_rank
);
bool fb_json_block_traversal_rank(
    const fb_json_block *block,
    const yyjson_val *object,
    size_t *rank
);

/* Python-compatible, final-duplicate-value lookup for one yyjson object. */
const yyjson_val *fb_json_object_get_last(
    const yyjson_val *object,
    fb_slice key
);

/* Python Jq.first/Jq.all semantics, accelerated by the per-block key index. */
size_t fb_json_block_key_count(const fb_json_block *block, fb_slice key);
bool fb_json_block_key_first(
    const fb_json_block *block,
    fb_slice key,
    fb_json_match *out
);
bool fb_json_block_key_at(
    const fb_json_block *block,
    fb_slice key,
    size_t index,
    fb_json_match *out
);
void fb_json_block_match_cursor_init(
    fb_json_block_match_cursor *cursor,
    const fb_json_block *block,
    fb_slice key
);
bool fb_json_block_match_cursor_next(
    fb_json_block_match_cursor *cursor,
    fb_json_match *out
);

/* Raw occurrence APIs retain duplicate pairs in traversal/pair order. */
size_t fb_json_block_key_occurrence_count(
    const fb_json_block *block,
    fb_slice key
);
bool fb_json_block_key_occurrence_at(
    const fb_json_block *block,
    fb_slice key,
    size_t index,
    fb_json_match *out
);

/* Document queries concatenate blocks in source-script order. */
size_t fb_document_key_count(const fb_document *document, fb_slice key);
bool fb_document_key_first(
    const fb_document *document,
    fb_slice key,
    fb_json_match *out
);
bool fb_document_key_at(
    const fb_document *document,
    fb_slice key,
    size_t index,
    fb_json_match *out
);
void fb_json_document_match_cursor_init(
    fb_json_document_match_cursor *cursor,
    const fb_document *document,
    fb_slice key
);
bool fb_json_document_match_cursor_next(
    fb_json_document_match_cursor *cursor,
    fb_json_match *out
);
size_t fb_document_key_occurrence_count(
    const fb_document *document,
    fb_slice key
);
bool fb_document_key_occurrence_at(
    const fb_document *document,
    fb_slice key,
    size_t index,
    fb_json_match *out
);

size_t fb_document_initial_route_count(const fb_document *document);
const fb_json_node_ref *fb_document_initial_route_at(
    const fb_document *document,
    size_t index
);
size_t fb_document_comment_candidate_count(const fb_document *document);
const fb_json_node_ref *fb_document_comment_candidate_at(
    const fb_document *document,
    size_t index
);
size_t fb_document_video_delivery_candidate_count(const fb_document *document);
const fb_json_node_ref *fb_document_video_delivery_candidate_at(
    const fb_document *document,
    size_t index
);

/* Bignums are retained as exact raw lexemes instead of rounded doubles. */
fb_json_number_kind fb_json_number_classify(const yyjson_val *value);
fb_slice fb_json_number_text(const yyjson_val *value);

const char *fb_document_status_string(fb_document_status status);
const char *fb_document_issue_string(fb_document_issue issue);

#ifdef __cplusplus
}
#endif

#endif
