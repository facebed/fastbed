#include "fastbed/url.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define FB_URL_MAX_QUERY_PAIRS 4096u
#define FB_URL_MAX_REQUESTED_IDS (FB_URL_MAX_QUERY_PAIRS + 8u)

static const char FB_WWW_FACEBOOK[] = "https://www.facebook.com";

static fb_slice
slice_make(const char *ptr, size_t len)
{
    fb_slice value;
    value.ptr = ptr;
    value.len = len;
    return value;
}

static bool
size_add(size_t left, size_t right, size_t *out)
{
    if (left > SIZE_MAX - right) {
        return false;
    }
    *out = left + right;
    return true;
}

static bool
size_accumulate(size_t *total, size_t value, size_t extra)
{
    size_t amount;
    return size_add(value, extra, &amount) && size_add(*total, amount, total);
}

static bool
slice_equal(fb_slice left, fb_slice right)
{
    return left.len == right.len &&
           (left.len == 0 || memcmp(left.ptr, right.ptr, left.len) == 0);
}

static unsigned char
ascii_lower(unsigned char value)
{
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
        return (unsigned char)(value + ('a' - 'A'));
    }
    return value;
}

static bool
slice_equal_icase(fb_slice left, fb_slice right)
{
    size_t index;

    if (left.len != right.len) {
        return false;
    }
    for (index = 0; index < left.len; ++index) {
        if (ascii_lower((unsigned char)left.ptr[index]) !=
            ascii_lower((unsigned char)right.ptr[index])) {
            return false;
        }
    }
    return true;
}

static bool
slice_equal_lit(fb_slice value, const char *literal)
{
    const size_t len = strlen(literal);
    return value.len == len && (len == 0 || memcmp(value.ptr, literal, len) == 0);
}

static bool
slice_equal_lit_icase(fb_slice value, const char *literal)
{
    return slice_equal_icase(value, slice_make(literal, strlen(literal)));
}

static bool
slice_starts_lit(fb_slice value, const char *prefix)
{
    const size_t len = strlen(prefix);
    return value.len >= len && (len == 0 || memcmp(value.ptr, prefix, len) == 0);
}

static bool
slice_starts_lit_icase(fb_slice value, const char *prefix)
{
    const size_t len = strlen(prefix);
    return value.len >= len &&
           slice_equal_icase(slice_make(value.ptr, len), slice_make(prefix, len));
}

static bool
slice_ends_lit(fb_slice value, const char *suffix)
{
    const size_t len = strlen(suffix);
    return value.len >= len &&
           (len == 0 || memcmp(value.ptr + value.len - len, suffix, len) == 0);
}

static fb_url_status
arena_copy(fb_arena *arena, fb_slice input, fb_slice *out)
{
    char *copy;

    if (arena == NULL || out == NULL || (input.ptr == NULL && input.len != 0)) {
        return FB_URL_INVALID;
    }
    if (input.len == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    copy = fb_arena_strndup(arena, input.ptr != NULL ? input.ptr : "", input.len);
    if (copy == NULL) {
        return FB_URL_NO_MEMORY;
    }
    *out = slice_make(copy, input.len);
    return FB_URL_OK;
}

static bool
scheme_first(unsigned char value)
{
    return (value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
           (value >= (unsigned char)'a' && value <= (unsigned char)'z');
}

static bool
scheme_rest(unsigned char value)
{
    return scheme_first(value) ||
           (value >= (unsigned char)'0' && value <= (unsigned char)'9') ||
           value == (unsigned char)'+' || value == (unsigned char)'-' ||
           value == (unsigned char)'.';
}

fb_url_status
fb_url_parse(fb_slice input, fb_url_view *out)
{
    size_t logical_end;
    size_t query_at = SIZE_MAX;
    size_t fragment_at = SIZE_MAX;
    size_t scheme_at = SIZE_MAX;
    size_t path_at = 0;
    size_t path_end;
    size_t index;

    if (out == NULL || (input.ptr == NULL && input.len != 0)) {
        return FB_URL_INVALID;
    }
    if (input.len == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    memset(out, 0, sizeof(*out));
    out->source = input;

    for (index = 0; index < input.len; ++index) {
        if (input.ptr[index] == '#') {
            fragment_at = index;
            out->has_fragment = true;
            out->fragment = slice_make(input.ptr + index + 1, input.len - index - 1);
            break;
        }
    }
    logical_end = fragment_at == SIZE_MAX ? input.len : fragment_at;
    for (index = 0; index < logical_end; ++index) {
        if (input.ptr[index] == '?') {
            query_at = index;
            out->has_query = true;
            out->query = slice_make(input.ptr + index + 1, logical_end - index - 1);
            break;
        }
    }
    path_end = query_at == SIZE_MAX ? logical_end : query_at;

    if (path_end != 0 && scheme_first((unsigned char)input.ptr[0])) {
        for (index = 1; index < path_end; ++index) {
            const unsigned char value = (unsigned char)input.ptr[index];
            if (value == (unsigned char)':') {
                scheme_at = index;
                break;
            }
            if (!scheme_rest(value)) {
                break;
            }
        }
    }
    if (scheme_at != SIZE_MAX) {
        out->scheme = slice_make(input.ptr, scheme_at);
        path_at = scheme_at + 1;
    }

    if (path_at + 1 < path_end && input.ptr[path_at] == '/' &&
        input.ptr[path_at + 1] == '/') {
        size_t authority_end = path_at + 2;
        const char *authority_ptr;
        size_t authority_len;
        size_t host_at;
        size_t host_end;
        size_t at = SIZE_MAX;

        out->has_authority = true;
        while (authority_end < path_end && input.ptr[authority_end] != '/') {
            ++authority_end;
        }
        authority_ptr = input.ptr + path_at + 2;
        authority_len = authority_end - (path_at + 2);
        out->authority = slice_make(authority_ptr, authority_len);
        path_at = authority_end;

        for (index = 0; index < authority_len; ++index) {
            if (authority_ptr[index] == '@') {
                at = index;
            }
        }
        host_at = at == SIZE_MAX ? 0 : at + 1;
        out->has_userinfo = at != SIZE_MAX;
        host_end = authority_len;

        if (host_at < authority_len && authority_ptr[host_at] == '[') {
            size_t close = host_at + 1;
            while (close < authority_len && authority_ptr[close] != ']') {
                ++close;
            }
            if (close == authority_len ||
                (close + 1 < authority_len && authority_ptr[close + 1] != ':')) {
                return FB_URL_INVALID;
            }
            out->host = slice_make(authority_ptr + host_at + 1,
                                   close - host_at - 1);
        } else {
            size_t colon = SIZE_MAX;
            for (index = host_at; index < authority_len; ++index) {
                if (authority_ptr[index] == ':') {
                    colon = index;
                    break;
                }
            }
            if (colon != SIZE_MAX) {
                host_end = colon;
            }
            out->host = slice_make(authority_ptr + host_at, host_end - host_at);
        }
    }

    out->path = slice_make(input.ptr == NULL ? NULL : input.ptr + path_at,
                           path_end - path_at);
    if (out->path.len != 0) {
        size_t final_slash = SIZE_MAX;
        size_t semicolon = SIZE_MAX;
        for (index = 0; index < out->path.len; ++index) {
            if (out->path.ptr[index] == '/') {
                final_slash = index;
            }
        }
        for (index = final_slash == SIZE_MAX ? 0 : final_slash + 1;
             index < out->path.len; ++index) {
            if (out->path.ptr[index] == ';') {
                semicolon = index;
                break;
            }
        }
        if (semicolon != SIZE_MAX) {
            out->has_params = true;
            out->params = slice_make(out->path.ptr + semicolon + 1,
                                     out->path.len - semicolon - 1);
            out->path.len = semicolon;
        }
    }
    return FB_URL_OK;
}

static bool
host_is_facebook(fb_slice host)
{
    static const char suffix[] = ".facebook.com";
    const size_t suffix_len = sizeof(suffix) - 1;

    if (slice_equal_lit_icase(host, "facebook.com")) {
        return true;
    }
    return host.len >= suffix_len &&
           slice_equal_icase(slice_make(host.ptr + host.len - suffix_len, suffix_len),
                             slice_make(suffix, suffix_len));
}

static bool
bare_facebook_path(fb_slice input, fb_url_view *path_view)
{
    static const char *const prefixes[] = {
        "facebook.com/", "www.facebook.com/", "web.facebook.com/",
        "m.facebook.com/", "mbasic.facebook.com/"
    };
    size_t index;

    for (index = 0; index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        const size_t prefix_len = strlen(prefixes[index]);
        if (input.len >= prefix_len &&
            slice_equal_icase(slice_make(input.ptr, prefix_len),
                              slice_make(prefixes[index], prefix_len))) {
            return fb_url_parse(slice_make(input.ptr + prefix_len,
                                           input.len - prefix_len),
                                path_view) == FB_URL_OK;
        }
    }
    return false;
}

static fb_slice
path_without_leading_slashes(fb_slice path)
{
    while (path.len != 0 && path.ptr[0] == '/') {
        ++path.ptr;
        --path.len;
    }
    return path;
}

static fb_slice
path_without_edge_slashes(fb_slice path)
{
    path = path_without_leading_slashes(path);
    while (path.len != 0 && path.ptr[path.len - 1] == '/') {
        --path.len;
    }
    return path;
}

static fb_slice
raw_relative_path(fb_slice input)
{
    size_t end = input.len;
    size_t index;
    size_t final_slash = SIZE_MAX;

    for (index = 0; index < end; ++index) {
        if (input.ptr[index] == '?' || input.ptr[index] == '#') {
            end = index;
            break;
        }
    }
    for (index = 0; index < end; ++index) {
        if (input.ptr[index] == '/') {
            final_slash = index;
        }
    }
    for (index = final_slash == SIZE_MAX ? 0 : final_slash + 1;
         index < end; ++index) {
        if (input.ptr[index] == ';') {
            end = index;
            break;
        }
    }
    return slice_make(input.ptr, end);
}

static fb_url_status
copy_path_and_query(
    fb_arena *arena,
    fb_slice path,
    fb_slice query,
    bool include_query,
    fb_slice *out
)
{
    size_t len = path.len;
    size_t query_part;
    char *buffer;
    size_t used = 0;

    if (include_query) {
        if (!size_add(query.len, 1, &query_part) ||
            !size_add(len, query_part, &len)) {
            return FB_URL_LIMIT;
        }
    }
    if (len == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    buffer = fb_arena_alloc(arena, len + 1, 1);
    if (buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    if (path.len != 0) {
        memcpy(buffer, path.ptr, path.len);
        used = path.len;
    }
    if (include_query) {
        buffer[used++] = '?';
        if (query.len != 0) {
            memcpy(buffer + used, query.ptr, query.len);
            used += query.len;
        }
    }
    buffer[used] = '\0';
    *out = slice_make(buffer, used);
    return FB_URL_OK;
}

fb_url_status
fb_url_normalize_facebook_path(fb_arena *arena, fb_slice input, fb_slice *out)
{
    fb_url_view parsed;
    fb_url_view bare;
    fb_slice path;
    fb_url_status status;

    if (arena == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    status = fb_url_parse(input, &parsed);
    if (status != FB_URL_OK) {
        return status;
    }
    if (parsed.authority.len != 0) {
        if (!host_is_facebook(parsed.host)) {
            return arena_copy(arena, input, out);
        }
        path = path_without_leading_slashes(parsed.path);
        return copy_path_and_query(arena, path, parsed.query,
                                   parsed.query.len != 0, out);
    }
    if (bare_facebook_path(input, &bare)) {
        path = path_without_leading_slashes(bare.path);
        return copy_path_and_query(arena, path, bare.query,
                                   bare.query.len != 0, out);
    }
    path = path_without_leading_slashes(input);
    return arena_copy(arena, path, out);
}

fb_url_status
fb_url_ensure_full(fb_arena *arena, fb_slice input, fb_slice *out)
{
    fb_url_view parsed;
    fb_url_view bare;
    fb_slice path;
    fb_slice suffix;
    fb_url_status status;
    size_t total;
    char *buffer;

    if (arena == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    status = fb_url_parse(input, &parsed);
    if (status != FB_URL_OK) {
        return status;
    }
    if (parsed.authority.len != 0 && !host_is_facebook(parsed.host)) {
        return arena_copy(arena, input, out);
    }
    if (parsed.authority.len != 0) {
        path = path_without_leading_slashes(parsed.path);
        status = copy_path_and_query(arena, path, parsed.query,
                                     parsed.query.len != 0, &suffix);
    } else if (bare_facebook_path(input, &bare)) {
        path = path_without_leading_slashes(bare.path);
        status = copy_path_and_query(arena, path, bare.query,
                                     bare.query.len != 0, &suffix);
    } else {
        path = input;
        if (path.len != 0 && path.ptr[0] == '/') {
            ++path.ptr;
            --path.len;
        }
        status = arena_copy(arena, path, &suffix);
    }
    if (status != FB_URL_OK) {
        return status;
    }
    if (suffix.len == SIZE_MAX ||
        !size_add(sizeof(FB_WWW_FACEBOOK), suffix.len, &total) ||
        total == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    buffer = fb_arena_alloc(arena, total + 1, 1);
    if (buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    memcpy(buffer, FB_WWW_FACEBOOK, sizeof(FB_WWW_FACEBOOK) - 1);
    buffer[sizeof(FB_WWW_FACEBOOK) - 1] = '/';
    if (suffix.len != 0) {
        memcpy(buffer + sizeof(FB_WWW_FACEBOOK), suffix.ptr, suffix.len);
    }
    buffer[total] = '\0';
    *out = slice_make(buffer, total);
    return FB_URL_OK;
}

bool
fb_url_is_facebook(fb_slice url, bool require_https)
{
    fb_url_view parsed;

    if (fb_url_parse(url, &parsed) != FB_URL_OK || parsed.authority.len == 0 ||
        !host_is_facebook(parsed.host)) {
        return false;
    }
    if (require_https) {
        return slice_equal_lit_icase(parsed.scheme, "https");
    }
    return slice_equal_lit_icase(parsed.scheme, "http") ||
           slice_equal_lit_icase(parsed.scheme, "https");
}

static bool
url_is_safe_with_schemes(fb_slice url, bool https_only)
{
    fb_url_view parsed;
    size_t index;

    if (fb_url_parse(url, &parsed) != FB_URL_OK || parsed.host.len == 0 ||
        parsed.has_userinfo) {
        return false;
    }
    for (index = 0; index < parsed.authority.len; ++index) {
        const unsigned char byte = (unsigned char)parsed.authority.ptr[index];
        if (byte <= 0x20u || byte == 0x7fu || byte == (unsigned char)'\\') {
            return false;
        }
    }
    if (slice_equal_lit_icase(parsed.scheme, "https")) {
        return true;
    }
    return !https_only && slice_equal_lit_icase(parsed.scheme, "http");
}

bool
fb_url_is_safe_media(fb_slice url)
{
    return url_is_safe_with_schemes(url, true);
}

bool
fb_url_is_safe_redirect(fb_slice url)
{
    return url_is_safe_with_schemes(url, false);
}

static fb_url_status
decode_query_component(fb_arena *arena, fb_slice raw, fb_slice *out)
{
    char *decoded;
    size_t source = 0;
    size_t target = 0;

    if (raw.len == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    decoded = fb_arena_alloc(arena, raw.len + 1, 1);
    if (decoded == NULL) {
        return FB_URL_NO_MEMORY;
    }
    while (source < raw.len) {
        unsigned char value = (unsigned char)raw.ptr[source];
        if (value == (unsigned char)'+') {
            decoded[target++] = ' ';
            ++source;
            continue;
        }
        if (value == (unsigned char)'%' && source + 2 < raw.len) {
            unsigned char high = (unsigned char)raw.ptr[source + 1];
            unsigned char low = (unsigned char)raw.ptr[source + 2];
            int high_value;
            int low_value;
            if (high >= '0' && high <= '9') {
                high_value = high - '0';
            } else if (ascii_lower(high) >= 'a' && ascii_lower(high) <= 'f') {
                high_value = ascii_lower(high) - 'a' + 10;
            } else {
                high_value = -1;
            }
            if (low >= '0' && low <= '9') {
                low_value = low - '0';
            } else if (ascii_lower(low) >= 'a' && ascii_lower(low) <= 'f') {
                low_value = ascii_lower(low) - 'a' + 10;
            } else {
                low_value = -1;
            }
            if (high_value >= 0 && low_value >= 0) {
                decoded[target++] = (char)((high_value << 4) | low_value);
                source += 3;
                continue;
            }
        }
        decoded[target++] = (char)value;
        ++source;
    }
    decoded[target] = '\0';
    *out = slice_make(decoded, target);
    return FB_URL_OK;
}

static fb_query_pair *
query_slot(fb_query *query, size_t index)
{
    if (index < FB_URL_INLINE_QUERY_PAIRS) {
        return &query->inline_pairs[index];
    }
    return &query->overflow[index - FB_URL_INLINE_QUERY_PAIRS];
}

const fb_query_pair *
fb_query_at(const fb_query *query, size_t index)
{
    if (query == NULL || index >= query->len) {
        return NULL;
    }
    if (index < FB_URL_INLINE_QUERY_PAIRS) {
        return &query->inline_pairs[index];
    }
    return &query->overflow[index - FB_URL_INLINE_QUERY_PAIRS];
}

fb_url_status
fb_query_parse(
    fb_arena *arena,
    fb_slice raw_query,
    bool keep_blank_values,
    fb_query *out
)
{
    size_t fields = 0;
    size_t begin = 0;
    size_t index;

    if (arena == NULL || out == NULL ||
        (raw_query.ptr == NULL && raw_query.len != 0)) {
        return FB_URL_INVALID;
    }
    if (raw_query.len == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    memset(out, 0, sizeof(*out));
    for (index = 0; index <= raw_query.len; ++index) {
        if (index == raw_query.len || raw_query.ptr[index] == '&') {
            if (index != begin) {
                ++fields;
            }
            begin = index + 1;
        }
    }
    if (fields > FB_URL_MAX_QUERY_PAIRS) {
        return FB_URL_LIMIT;
    }
    if (fields > FB_URL_INLINE_QUERY_PAIRS) {
        if (fields - FB_URL_INLINE_QUERY_PAIRS >
            SIZE_MAX / sizeof(*out->overflow)) {
            return FB_URL_LIMIT;
        }
        out->overflow = fb_arena_alloc(
            arena,
            (fields - FB_URL_INLINE_QUERY_PAIRS) * sizeof(*out->overflow),
            _Alignof(fb_query_pair)
        );
        if (out->overflow == NULL) {
            return FB_URL_NO_MEMORY;
        }
    }

    begin = 0;
    for (index = 0; index <= raw_query.len; ++index) {
        size_t equal_at;
        fb_slice raw_key;
        fb_slice raw_value;
        fb_query_pair *pair;
        fb_url_status status;

        if (index != raw_query.len && raw_query.ptr[index] != '&') {
            continue;
        }
        if (index == begin) {
            begin = index + 1;
            continue;
        }
        equal_at = begin;
        while (equal_at < index && raw_query.ptr[equal_at] != '=') {
            ++equal_at;
        }
        raw_key = slice_make(raw_query.ptr + begin, equal_at - begin);
        raw_value = equal_at < index
            ? slice_make(raw_query.ptr + equal_at + 1, index - equal_at - 1)
            : slice_make(raw_query.ptr + index, 0);
        begin = index + 1;
        if (!keep_blank_values && raw_value.len == 0) {
            continue;
        }
        pair = query_slot(out, out->len);
        status = decode_query_component(arena, raw_key, &pair->key);
        if (status != FB_URL_OK) {
            return status;
        }
        status = decode_query_component(arena, raw_value, &pair->value);
        if (status != FB_URL_OK) {
            return status;
        }
        ++out->len;
    }
    return FB_URL_OK;
}

size_t
fb_query_count(const fb_query *query, fb_slice key)
{
    size_t count = 0;
    size_t index;

    if (query == NULL) {
        return 0;
    }
    for (index = 0; index < query->len; ++index) {
        const fb_query_pair *pair = fb_query_at(query, index);
        if (slice_equal(pair->key, key)) {
            ++count;
        }
    }
    return count;
}

static bool
facebook_path_view(fb_slice input, fb_slice *out)
{
    fb_url_view parsed;
    fb_url_view bare;

    if (fb_url_parse(input, &parsed) != FB_URL_OK) {
        return false;
    }
    if (parsed.authority.len != 0) {
        if (!host_is_facebook(parsed.host)) {
            return false;
        }
        *out = parsed.path;
        return true;
    }
    if (bare_facebook_path(input, &bare)) {
        *out = bare.path;
        return true;
    }
    *out = raw_relative_path(input);
    return true;
}

static size_t
path_segment_count(fb_slice path)
{
    size_t count = 0;
    size_t index = 0;

    while (index < path.len) {
        while (index < path.len && path.ptr[index] == '/') {
            ++index;
        }
        if (index == path.len) {
            break;
        }
        ++count;
        while (index < path.len && path.ptr[index] != '/') {
            ++index;
        }
    }
    return count;
}

static fb_slice *
path_segment_slot(fb_path_segments *segments, size_t index)
{
    if (index < FB_URL_INLINE_SEGMENTS) {
        return &segments->inline_items[index];
    }
    return &segments->overflow[index - FB_URL_INLINE_SEGMENTS];
}

fb_slice
fb_path_segment_at(const fb_path_segments *segments, size_t index)
{
    if (segments == NULL || index >= segments->len) {
        return slice_make(NULL, 0);
    }
    if (index < FB_URL_INLINE_SEGMENTS) {
        return segments->inline_items[index];
    }
    return segments->overflow[index - FB_URL_INLINE_SEGMENTS];
}

fb_url_status
fb_url_facebook_path_segments(
    fb_arena *arena,
    fb_slice input,
    fb_path_segments *out
)
{
    fb_slice path;
    char *copy;
    size_t index = 0;
    size_t item = 0;

    if (arena == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (!facebook_path_view(input, &path)) {
        return FB_URL_OK;
    }
    out->len = path_segment_count(path);
    if (out->len == 0) {
        return FB_URL_OK;
    }
    if (out->len > FB_URL_INLINE_SEGMENTS) {
        if (out->len - FB_URL_INLINE_SEGMENTS >
            SIZE_MAX / sizeof(*out->overflow)) {
            return FB_URL_LIMIT;
        }
        out->overflow = fb_arena_alloc(
            arena,
            (out->len - FB_URL_INLINE_SEGMENTS) * sizeof(*out->overflow),
            _Alignof(fb_slice)
        );
        if (out->overflow == NULL) {
            return FB_URL_NO_MEMORY;
        }
    }
    copy = fb_arena_strndup(arena, path.ptr, path.len);
    if (copy == NULL) {
        return FB_URL_NO_MEMORY;
    }
    while (index < path.len) {
        size_t begin;
        while (index < path.len && copy[index] == '/') {
            ++index;
        }
        if (index == path.len) {
            break;
        }
        begin = index;
        while (index < path.len && copy[index] != '/') {
            ++index;
        }
        *path_segment_slot(out, item++) = slice_make(copy + begin, index - begin);
    }
    return FB_URL_OK;
}

static bool
first_path_segment(fb_slice input, fb_slice *first)
{
    fb_slice path;
    size_t index;

    if (!facebook_path_view(input, &path)) {
        return false;
    }
    index = 0;
    while (index < path.len && path.ptr[index] == '/') {
        ++index;
    }
    if (index == path.len) {
        return false;
    }
    first->ptr = path.ptr + index;
    first->len = 0;
    while (index + first->len < path.len && path.ptr[index + first->len] != '/') {
        ++first->len;
    }
    return first->len != 0;
}

static fb_slice
without_php_suffix(fb_slice value)
{
    if (value.len >= 4 &&
        slice_equal_lit_icase(slice_make(value.ptr + value.len - 4, 4), ".php")) {
        value.len -= 4;
    }
    return value;
}

bool
fb_url_is_control_path(
    fb_slice input,
    const fb_slice *names,
    size_t name_count
)
{
    fb_slice first;
    size_t index;

    if ((names == NULL && name_count != 0) || !first_path_segment(input, &first)) {
        return false;
    }
    first = without_php_suffix(first);
    for (index = 0; index < name_count; ++index) {
        if (slice_equal_icase(first, without_php_suffix(names[index]))) {
            return true;
        }
    }
    return false;
}

bool
fb_url_is_auth_control_path(fb_slice input)
{
    static const fb_slice names[] = {
        {"login", 5}, {"checkpoint", 10}, {"recover", 7}
    };
    return fb_url_is_control_path(input, names, sizeof(names) / sizeof(names[0]));
}

bool
fb_url_is_post_like_path(fb_slice input)
{
    static const char *const kinds[] = {
        "posts", "permalink", "reel", "watch", "videos", "v", "photos"
    };
    fb_slice path;
    size_t index = 0;

    if (!facebook_path_view(input, &path)) {
        /* normalize_facebook_path leaves foreign absolute URLs untouched;
         * the oracle then reparses that entire value as a relative path. */
        path = raw_relative_path(input);
    }
    while (index < path.len) {
        size_t begin;
        size_t kind;
        fb_slice segment;

        while (index < path.len && path.ptr[index] == '/') {
            ++index;
        }
        if (index == path.len) {
            break;
        }
        begin = index;
        while (index < path.len && path.ptr[index] != '/') {
            ++index;
        }
        segment = slice_make(path.ptr + begin, index - begin);
        for (kind = 0; kind < sizeof(kinds) / sizeof(kinds[0]); ++kind) {
            if (slice_equal_lit_icase(segment, kinds[kind])) {
                return true;
            }
        }
    }
    if (path.len != 0 && path.ptr[0] == '/') {
        ++path.ptr;
        --path.len;
    }
    if (path.len != 0 && path.ptr[path.len - 1] == '/') {
        --path.len;
    }
    return slice_equal_lit_icase(path, "story.php") ||
           slice_equal_lit_icase(path, "permalink.php") ||
           slice_equal_lit_icase(path, "photo.php");
}

bool
fb_url_is_share_path(fb_slice input)
{
    fb_url_view parsed;
    fb_slice path;
    size_t index = 0;
    size_t begin;

    if (fb_url_parse(input, &parsed) != FB_URL_OK) {
        return false;
    }
    path = parsed.path;
    if (index < path.len && path.ptr[index] == '/') {
        ++index;
    }
    begin = index;
    while (index < path.len && path.ptr[index] != '/') {
        ++index;
    }
    return index > begin &&
           slice_equal_lit_icase(slice_make(path.ptr + begin, index - begin), "share");
}

static fb_slice
ensured_path_view(fb_slice input)
{
    fb_url_view parsed;
    fb_url_view bare;

    if (fb_url_parse(input, &parsed) != FB_URL_OK) {
        return slice_make(NULL, 0);
    }
    if (parsed.authority.len != 0) {
        return parsed.path;
    }
    if (bare_facebook_path(input, &bare)) {
        return bare.path;
    }
    return raw_relative_path(input);
}

bool
fb_url_is_group_landing_target(fb_slice input)
{
    fb_slice path = path_without_edge_slashes(ensured_path_view(input));
    size_t parts = 1;
    size_t index;

    if (!slice_starts_lit(path, "groups/")) {
        return false;
    }
    if (slice_ends_lit(path, "/about")) {
        return true;
    }
    for (index = 0; index < path.len; ++index) {
        if (path.ptr[index] == '/') {
            ++parts;
        }
    }
    return parts <= 2;
}

static bool
route_slug_char(unsigned char value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') ||
           value == '-' || value == '.' || value == '_';
}

bool
fb_url_is_supported_post_route(fb_slice input)
{
    fb_url_view parsed;
    fb_slice path;
    size_t slug_end;

    if (fb_url_parse(input, &parsed) != FB_URL_OK) {
        return false;
    }
    if (parsed.authority.len != 0) {
        if (!host_is_facebook(parsed.host)) {
            return false;
        }
        path = parsed.path;
    } else {
        path = raw_relative_path(input);
    }
    path = path_without_leading_slashes(path);

    if (slice_starts_lit(path, "permalink.php") ||
        slice_starts_lit(path, "story.php") ||
        slice_starts_lit(path, "photo")) {
        return true;
    }
    if (slice_starts_lit(path, "groups/")) {
        return true;
    }

    slug_end = 0;
    while (slug_end < path.len && route_slug_char((unsigned char)path.ptr[slug_end])) {
        ++slug_end;
    }
    if (slug_end < path.len && path.ptr[slug_end] == '/') {
        const fb_slice tail = slice_make(path.ptr + slug_end + 1,
                                         path.len - slug_end - 1);
        if (slice_starts_lit(tail, "posts")) {
            return true;
        }
        if (slice_starts_lit(tail, "photos") &&
            (tail.len == 6 || (tail.len > 6 && tail.ptr[6] == '/'))) {
            return true;
        }
    }
    return false;
}

static fb_slice *
requested_id_slot(fb_requested_ids *ids, size_t index)
{
    if (index < FB_URL_INLINE_IDS) {
        return &ids->inline_items[index];
    }
    return &ids->overflow[index - FB_URL_INLINE_IDS];
}

fb_slice
fb_requested_id_at(const fb_requested_ids *ids, size_t index)
{
    if (ids == NULL || index >= ids->len) {
        return slice_make(NULL, 0);
    }
    if (index < FB_URL_INLINE_IDS) {
        return ids->inline_items[index];
    }
    return ids->overflow[index - FB_URL_INLINE_IDS];
}

static fb_url_status
requested_id_push(fb_arena *arena, fb_requested_ids *ids, fb_slice value)
{
    size_t index;
    fb_slice copy;
    fb_url_status status;

    if (value.len == 0) {
        return FB_URL_OK;
    }
    for (index = 0; index < ids->len; ++index) {
        if (slice_equal(fb_requested_id_at(ids, index), value)) {
            return FB_URL_OK;
        }
    }
    if (ids->len >= FB_URL_MAX_REQUESTED_IDS) {
        return FB_URL_LIMIT;
    }
    status = arena_copy(arena, value, &copy);
    if (status != FB_URL_OK) {
        return status;
    }
    *requested_id_slot(ids, ids->len++) = copy;
    return FB_URL_OK;
}

static bool
all_ascii_digits(fb_slice value)
{
    size_t index;
    if (value.len == 0) {
        return false;
    }
    for (index = 0; index < value.len; ++index) {
        if (value.ptr[index] < '0' || value.ptr[index] > '9') {
            return false;
        }
    }
    return true;
}

static bool
next_segment(fb_slice path, size_t *cursor, fb_slice *segment, size_t *begin_out)
{
    size_t begin;

    while (*cursor < path.len && path.ptr[*cursor] == '/') {
        ++*cursor;
    }
    if (*cursor == path.len) {
        return false;
    }
    begin = *cursor;
    while (*cursor < path.len && path.ptr[*cursor] != '/') {
        ++*cursor;
    }
    *segment = slice_make(path.ptr + begin, *cursor - begin);
    if (begin_out != NULL) {
        *begin_out = begin;
    }
    return true;
}

static fb_slice
terminal_video_id(fb_slice path)
{
    size_t cursor = 0;
    bool found = false;
    fb_slice after[3];
    size_t after_count = 0;
    fb_slice segment;

    while (next_segment(path, &cursor, &segment, NULL)) {
        if (!found) {
            if (slice_equal_lit_icase(segment, "videos")) {
                found = true;
            }
            continue;
        }
        if (after_count < sizeof(after) / sizeof(after[0])) {
            after[after_count] = segment;
        }
        ++after_count;
    }
    if ((after_count == 1 || after_count == 2) &&
        all_ascii_digits(after[after_count - 1])) {
        return after[after_count - 1];
    }
    return slice_make(NULL, 0);
}

static fb_slice
posts_requested_id(fb_slice path)
{
    size_t cursor = 0;
    fb_slice segment;
    bool found = false;
    fb_slice first = {NULL, 0};
    fb_slice pfbid = {NULL, 0};
    fb_slice last_numeric = {NULL, 0};

    while (next_segment(path, &cursor, &segment, NULL)) {
        if (!found) {
            if (slice_equal_lit_icase(segment, "posts")) {
                found = true;
            }
            continue;
        }
        if (first.len == 0) {
            first = segment;
        }
        if (pfbid.len == 0 && slice_starts_lit_icase(segment, "pfbid")) {
            pfbid = segment;
        }
        if (all_ascii_digits(segment)) {
            last_numeric = segment;
        }
    }
    if (!found) {
        return slice_make(NULL, 0);
    }
    if (pfbid.len != 0) {
        return pfbid;
    }
    if (last_numeric.len != 0) {
        return last_numeric;
    }
    return first;
}

static fb_slice
segment_after_kind(fb_slice path, const char *kind)
{
    size_t cursor = 0;
    fb_slice segment;

    while (next_segment(path, &cursor, &segment, NULL)) {
        if (slice_equal_lit_icase(segment, kind)) {
            fb_slice next;
            if (next_segment(path, &cursor, &next, NULL)) {
                return next;
            }
            return slice_make(NULL, 0);
        }
    }
    return slice_make(NULL, 0);
}

static fb_slice
numeric_v_requested_id(fb_slice path)
{
    size_t slash;

    for (slash = 0; slash <= path.len; ++slash) {
        size_t value_at;
        size_t end;
        const bool virtual_leading = slash == 0 &&
            (path.len == 0 || path.ptr[0] != '/');
        if (!virtual_leading &&
            (slash >= path.len || path.ptr[slash] != '/')) {
            continue;
        }
        value_at = virtual_leading ? 0 : slash + 1;
        if (value_at + 2 > path.len ||
            ascii_lower((unsigned char)path.ptr[value_at]) != 'v' ||
            path.ptr[value_at + 1] != '/') {
            continue;
        }
        if (!virtual_leading && slash >= 5 &&
            slice_equal_lit_icase(slice_make(path.ptr + slash - 5, 5), "share")) {
            continue;
        }
        value_at += 2;
        end = value_at;
        while (end < path.len && path.ptr[end] >= '0' && path.ptr[end] <= '9') {
            ++end;
        }
        if (end > value_at && (end == path.len || path.ptr[end] == '/')) {
            return slice_make(path.ptr + value_at, end - value_at);
        }
    }
    return slice_make(NULL, 0);
}

static fb_slice
photos_requested_id(fb_slice path)
{
    size_t slash;

    for (slash = 0; slash < path.len; ++slash) {
        size_t cursor;
        size_t first_at;
        size_t first_end;
        size_t second_at;
        size_t second_end;
        size_t kind_at;
        const bool virtual_leading = slash == 0 && path.ptr[0] != '/';

        if (!virtual_leading && path.ptr[slash] != '/') {
            continue;
        }
        kind_at = virtual_leading ? 0 : slash + 1;
        if (kind_at + 7 > path.len ||
            !slice_equal_lit_icase(slice_make(path.ptr + kind_at, 6), "photos") ||
            path.ptr[kind_at + 6] != '/') {
            continue;
        }
        cursor = kind_at + 7;
        first_at = cursor;
        while (cursor < path.len && path.ptr[cursor] != '/') {
            ++cursor;
        }
        first_end = cursor;
        if (first_end == first_at) {
            continue;
        }
        if (cursor == path.len || (cursor + 1 == path.len)) {
            return slice_make(path.ptr + first_at, first_end - first_at);
        }
        second_at = ++cursor;
        while (cursor < path.len && path.ptr[cursor] != '/') {
            ++cursor;
        }
        second_end = cursor;
        if (second_end == second_at ||
            (cursor != path.len && cursor + 1 != path.len)) {
            continue;
        }
        return slice_make(path.ptr + second_at, second_end - second_at);
    }
    return slice_make(NULL, 0);
}

fb_url_status
fb_url_requested_ids(
    fb_arena *arena,
    fb_slice post_path,
    fb_requested_ids *out
)
{
    static const char *const query_keys[] = {
        "story_fbid", "fbid", "v", "multi_permalinks", "post_id"
    };
    fb_url_view parsed;
    fb_url_view bare;
    fb_query query;
    fb_slice path;
    fb_slice candidate;
    size_t capacity;
    size_t key;
    size_t index;
    fb_url_status status;

    if (arena == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    memset(out, 0, sizeof(*out));
    status = fb_url_parse(post_path, &parsed);
    if (status != FB_URL_OK) {
        return status;
    }
    path = parsed.path;
    if (parsed.authority.len == 0) {
        if (bare_facebook_path(post_path, &bare)) {
            path = bare.path;
            parsed.query = bare.query;
        } else {
            path = raw_relative_path(post_path);
        }
    }
    status = fb_query_parse(arena, parsed.query, false, &query);
    if (status != FB_URL_OK) {
        return status;
    }
    capacity = query.len + 7;
    if (capacity > FB_URL_MAX_REQUESTED_IDS) {
        return FB_URL_LIMIT;
    }
    if (capacity > FB_URL_INLINE_IDS) {
        if (capacity - FB_URL_INLINE_IDS >
            SIZE_MAX / sizeof(*out->overflow)) {
            return FB_URL_LIMIT;
        }
        out->overflow = fb_arena_alloc(
            arena,
            (capacity - FB_URL_INLINE_IDS) * sizeof(*out->overflow),
            _Alignof(fb_slice)
        );
        if (out->overflow == NULL) {
            return FB_URL_NO_MEMORY;
        }
    }

    for (key = 0; key < sizeof(query_keys) / sizeof(query_keys[0]); ++key) {
        for (index = 0; index < query.len; ++index) {
            const fb_query_pair *pair = fb_query_at(&query, index);
            if (slice_equal_lit(pair->key, query_keys[key])) {
                status = requested_id_push(arena, out, pair->value);
                if (status != FB_URL_OK) {
                    return status;
                }
            }
        }
    }

    candidate = posts_requested_id(path);
    status = requested_id_push(arena, out, candidate);
    if (status != FB_URL_OK) {
        return status;
    }
    candidate = terminal_video_id(path);
    status = requested_id_push(arena, out, candidate);
    if (status != FB_URL_OK) {
        return status;
    }
    candidate = segment_after_kind(path, "reel");
    status = requested_id_push(arena, out, candidate);
    if (status != FB_URL_OK) {
        return status;
    }
    candidate = segment_after_kind(path, "watch");
    status = requested_id_push(arena, out, candidate);
    if (status != FB_URL_OK) {
        return status;
    }
    candidate = numeric_v_requested_id(path);
    status = requested_id_push(arena, out, candidate);
    if (status != FB_URL_OK) {
        return status;
    }
    candidate = segment_after_kind(path, "permalink");
    status = requested_id_push(arena, out, candidate);
    if (status != FB_URL_OK) {
        return status;
    }
    candidate = photos_requested_id(path);
    return requested_id_push(arena, out, candidate);
}

fb_url_status
fb_url_comment_target(
    fb_arena *arena,
    fb_slice post_path,
    fb_comment_target *out
)
{
    fb_url_view parsed;
    fb_query query;
    size_t comment_count = 0;
    size_t reply_count = 0;
    fb_slice comment = {NULL, 0};
    fb_slice reply = {NULL, 0};
    size_t index;
    fb_url_status status;

    if (arena == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (fb_url_parse(post_path, &parsed) != FB_URL_OK) {
        return FB_URL_INVALID;
    }
    status = fb_query_parse(arena, parsed.query, true, &query);
    if (status != FB_URL_OK) {
        return status;
    }
    for (index = 0; index < query.len; ++index) {
        const fb_query_pair *pair = fb_query_at(&query, index);
        if (slice_equal_lit(pair->key, "comment_id")) {
            ++comment_count;
            comment = pair->value;
        } else if (slice_equal_lit(pair->key, "reply_comment_id")) {
            ++reply_count;
            reply = pair->value;
        }
    }
    if (comment_count == 0 && reply_count == 0) {
        out->kind = FB_COMMENT_TARGET_NONE;
        return FB_URL_OK;
    }
    if (comment_count != 1 || !all_ascii_digits(comment) || reply_count > 1 ||
        (reply_count == 1 && (!all_ascii_digits(reply) || slice_equal(comment, reply)))) {
        out->kind = FB_COMMENT_TARGET_INVALID;
        return FB_URL_OK;
    }
    out->kind = FB_COMMENT_TARGET_VALID;
    out->comment_id = comment;
    out->has_reply = reply_count == 1;
    if (out->has_reply) {
        out->reply_comment_id = reply;
    }
    return FB_URL_OK;
}

bool
fb_comment_targets_equal(
    const fb_comment_target *left,
    const fb_comment_target *right
)
{
    if (left == NULL || right == NULL ||
        left->kind != FB_COMMENT_TARGET_VALID ||
        right->kind != FB_COMMENT_TARGET_VALID ||
        left->has_reply != right->has_reply ||
        !slice_equal(left->comment_id, right->comment_id)) {
        return false;
    }
    return !left->has_reply ||
           slice_equal(left->reply_comment_id, right->reply_comment_id);
}

static bool
quote_safe(unsigned char value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') ||
           value == '_' || value == '-' || value == '.' || value == '~';
}

static bool
quoted_size(fb_slice value, size_t *out)
{
    size_t total = 0;
    size_t index;

    for (index = 0; index < value.len; ++index) {
        const size_t amount = value.ptr[index] == ' ' ||
                              quote_safe((unsigned char)value.ptr[index]) ? 1 : 3;
        if (!size_add(total, amount, &total)) {
            return false;
        }
    }
    *out = total;
    return true;
}

static void
write_quoted(char *buffer, size_t *used, fb_slice value)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t index;

    for (index = 0; index < value.len; ++index) {
        const unsigned char byte = (unsigned char)value.ptr[index];
        if (byte == (unsigned char)' ') {
            buffer[(*used)++] = '+';
        } else if (quote_safe(byte)) {
            buffer[(*used)++] = (char)byte;
        } else {
            buffer[(*used)++] = '%';
            buffer[(*used)++] = hex[byte >> 4];
            buffer[(*used)++] = hex[byte & 15];
        }
    }
}

typedef struct {
    fb_slice key;
    fb_slice value;
} query_replacement;

typedef uint32_t query_index;

#define FB_QUERY_INDEX_NONE UINT32_MAX

enum {
    FB_QUERY_GROUP_INLINE_SLOTS = 32
};

typedef struct {
    query_index first;
    query_index last;
} query_group;

typedef struct {
    query_group *groups;
    query_index *next;
    query_index *slots;
    size_t group_count;
    query_group inline_groups[FB_URL_INLINE_QUERY_PAIRS];
    query_index inline_next[FB_URL_INLINE_QUERY_PAIRS];
    query_index inline_slots[FB_QUERY_GROUP_INLINE_SLOTS];
} query_group_index;

static uint64_t
query_key_hash(fb_slice key)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t index;

    for (index = 0; index < key.len; ++index) {
        hash ^= (unsigned char)key.ptr[index];
        hash *= UINT64_C(1099511628211);
    }
    hash ^= (uint64_t)key.len;
    hash ^= hash >> 33;
    hash *= UINT64_C(0xff51afd7ed558ccd);
    hash ^= hash >> 33;
    return hash;
}

static fb_url_status
build_query_group_index(
    fb_arena *arena,
    const fb_query *query,
    query_group_index *out
)
{
    size_t pair_index;
    size_t slot_count = FB_QUERY_GROUP_INLINE_SLOTS;

    memset(out, 0, sizeof(*out));
    if (query->len == 0) {
        return FB_URL_OK;
    }
    if (query->len >= UINT32_MAX || query->len > SIZE_MAX / 2u) {
        return FB_URL_LIMIT;
    }
    while (slot_count < query->len * 2u) {
        if (slot_count > SIZE_MAX / 2u) {
            return FB_URL_LIMIT;
        }
        slot_count *= 2u;
    }

    if (query->len <= FB_URL_INLINE_QUERY_PAIRS) {
        out->groups = out->inline_groups;
        out->next = out->inline_next;
        out->slots = out->inline_slots;
    } else {
        if (query->len > SIZE_MAX / sizeof(*out->groups) ||
            query->len > SIZE_MAX / sizeof(*out->next) ||
            slot_count > SIZE_MAX / sizeof(*out->slots)) {
            return FB_URL_LIMIT;
        }
        out->groups = fb_arena_alloc(
            arena, query->len * sizeof(*out->groups), _Alignof(query_group));
        out->next = fb_arena_alloc(
            arena, query->len * sizeof(*out->next), _Alignof(query_index));
        out->slots = fb_arena_alloc(
            arena, slot_count * sizeof(*out->slots), _Alignof(query_index));
        if (out->groups == NULL || out->next == NULL || out->slots == NULL) {
            return FB_URL_NO_MEMORY;
        }
        memset(out->slots, 0, slot_count * sizeof(*out->slots));
    }
    for (pair_index = 0; pair_index < query->len; ++pair_index) {
        const fb_query_pair *pair = fb_query_at(query, pair_index);
        size_t slot = (size_t)query_key_hash(pair->key) & (slot_count - 1u);
        query_index group_number;
        const query_index current = (query_index)pair_index;

        while ((group_number = out->slots[slot]) != 0u) {
            const query_group *group = &out->groups[group_number - 1u];
            const fb_query_pair *first = fb_query_at(query, group->first);
            if (slice_equal(first->key, pair->key)) {
                break;
            }
            slot = (slot + 1u) & (slot_count - 1u);
        }
        out->next[current] = FB_QUERY_INDEX_NONE;
        if (group_number == 0u) {
            query_group *group = &out->groups[out->group_count];
            group->first = current;
            group->last = current;
            ++out->group_count;
            out->slots[slot] = (query_index)out->group_count;
        } else {
            query_group *group = &out->groups[group_number - 1u];
            out->next[group->last] = current;
            group->last = current;
        }
    }
    return FB_URL_OK;
}

static const query_replacement *
find_replacement(
    const query_replacement *replacements,
    size_t replacement_count,
    fb_slice key
)
{
    size_t index;
    for (index = 0; index < replacement_count; ++index) {
        if (slice_equal(replacements[index].key, key)) {
            return &replacements[index];
        }
    }
    return NULL;
}

static bool
query_has_key(const fb_query *query, fb_slice key)
{
    size_t index;
    for (index = 0; index < query->len; ++index) {
        if (slice_equal(fb_query_at(query, index)->key, key)) {
            return true;
        }
    }
    return false;
}

static bool
key_is_selected(fb_slice key, const fb_slice *only_keys, size_t only_count)
{
    size_t index;
    if (only_count == 0) {
        return true;
    }
    for (index = 0; index < only_count; ++index) {
        if (slice_equal(key, only_keys[index])) {
            return true;
        }
    }
    return false;
}

typedef struct {
    size_t pairs;
    size_t bytes;
} encoded_query_size;

static bool
add_encoded_pair_size(encoded_query_size *size, fb_slice key, fb_slice value)
{
    size_t key_size;
    size_t value_size;
    size_t amount;

    if (!quoted_size(key, &key_size) || !quoted_size(value, &value_size) ||
        !size_add(key_size, value_size, &amount) ||
        !size_add(amount, 1, &amount) ||
        (size->pairs != 0 && !size_add(amount, 1, &amount)) ||
        !size_add(size->bytes, amount, &size->bytes)) {
        return false;
    }
    ++size->pairs;
    return true;
}

static void
write_encoded_pair(
    char *buffer,
    size_t *used,
    size_t *pairs,
    fb_slice key,
    fb_slice value
)
{
    if (*pairs != 0) {
        buffer[(*used)++] = '&';
    }
    write_quoted(buffer, used, key);
    buffer[(*used)++] = '=';
    write_quoted(buffer, used, value);
    ++*pairs;
}

static fb_url_status
encode_grouped_query(
    fb_arena *arena,
    const fb_query *query,
    const fb_slice *only_keys,
    size_t only_count,
    const query_replacement *replacements,
    size_t replacement_count,
    bool append_missing_replacements,
    fb_slice *out
)
{
    encoded_query_size size = {0, 0};
    query_group_index grouped;
    size_t outer;
    size_t inner;
    char *buffer;
    size_t used = 0;
    size_t written_pairs = 0;

    if (only_count == 0) {
        const fb_url_status status =
            build_query_group_index(arena, query, &grouped);
        if (status != FB_URL_OK) {
            return status;
        }
    }

    if (only_count != 0) {
        for (outer = 0; outer < only_count; ++outer) {
            const query_replacement *replacement =
                find_replacement(replacements, replacement_count, only_keys[outer]);
            if (replacement != NULL) {
                if (query_has_key(query, only_keys[outer]) &&
                    !add_encoded_pair_size(&size, replacement->key,
                                           replacement->value)) {
                    return FB_URL_LIMIT;
                }
                continue;
            }
            for (inner = 0; inner < query->len; ++inner) {
                const fb_query_pair *pair = fb_query_at(query, inner);
                if (slice_equal(pair->key, only_keys[outer]) &&
                    !add_encoded_pair_size(&size, pair->key, pair->value)) {
                    return FB_URL_LIMIT;
                }
            }
        }
    } else {
        for (outer = 0; outer < grouped.group_count; ++outer) {
            const query_group *group = &grouped.groups[outer];
            const fb_query_pair *pair = fb_query_at(query, group->first);
            const query_replacement *replacement;
            query_index item;

            replacement = find_replacement(replacements, replacement_count, pair->key);
            if (replacement != NULL) {
                if (!add_encoded_pair_size(&size, replacement->key,
                                           replacement->value)) {
                    return FB_URL_LIMIT;
                }
                continue;
            }
            for (item = group->first; item != FB_QUERY_INDEX_NONE;
                 item = grouped.next[item]) {
                const fb_query_pair *value = fb_query_at(query, item);
                if (!add_encoded_pair_size(&size, value->key, value->value)) {
                    return FB_URL_LIMIT;
                }
            }
        }
    }
    if (append_missing_replacements) {
        for (outer = 0; outer < replacement_count; ++outer) {
            if (!query_has_key(query, replacements[outer].key) &&
                key_is_selected(replacements[outer].key, only_keys, only_count) &&
                !add_encoded_pair_size(&size, replacements[outer].key,
                                       replacements[outer].value)) {
                return FB_URL_LIMIT;
            }
        }
    }

    if (size.bytes == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    buffer = fb_arena_alloc(arena, size.bytes + 1, 1);
    if (buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    if (only_count != 0) {
        for (outer = 0; outer < only_count; ++outer) {
            const query_replacement *replacement =
                find_replacement(replacements, replacement_count, only_keys[outer]);
            if (replacement != NULL) {
                if (query_has_key(query, only_keys[outer])) {
                    write_encoded_pair(buffer, &used, &written_pairs,
                                       replacement->key, replacement->value);
                }
                continue;
            }
            for (inner = 0; inner < query->len; ++inner) {
                const fb_query_pair *pair = fb_query_at(query, inner);
                if (slice_equal(pair->key, only_keys[outer])) {
                    write_encoded_pair(buffer, &used, &written_pairs,
                                       pair->key, pair->value);
                }
            }
        }
    } else {
        for (outer = 0; outer < grouped.group_count; ++outer) {
            const query_group *group = &grouped.groups[outer];
            const fb_query_pair *pair = fb_query_at(query, group->first);
            const query_replacement *replacement;
            query_index item;
            replacement = find_replacement(replacements, replacement_count, pair->key);
            if (replacement != NULL) {
                write_encoded_pair(buffer, &used, &written_pairs,
                                   replacement->key, replacement->value);
                continue;
            }
            for (item = group->first; item != FB_QUERY_INDEX_NONE;
                 item = grouped.next[item]) {
                const fb_query_pair *value = fb_query_at(query, item);
                write_encoded_pair(buffer, &used, &written_pairs,
                                   value->key, value->value);
            }
        }
    }
    if (append_missing_replacements) {
        for (outer = 0; outer < replacement_count; ++outer) {
            if (!query_has_key(query, replacements[outer].key) &&
                key_is_selected(replacements[outer].key, only_keys, only_count)) {
                write_encoded_pair(buffer, &used, &written_pairs,
                                   replacements[outer].key,
                                   replacements[outer].value);
            }
        }
    }
    buffer[used] = '\0';
    *out = slice_make(buffer, used);
    return FB_URL_OK;
}

static fb_url_status
rebuild_url(
    fb_arena *arena,
    const fb_url_view *parsed,
    fb_slice path,
    fb_slice query,
    fb_slice *out
)
{
    size_t total = 0;
    size_t used = 0;
    size_t index;
    char *buffer;
    const bool have_query = query.len != 0;
    const bool have_fragment = parsed->fragment.len != 0;

    if (!size_accumulate(&total, parsed->scheme.len,
                         parsed->scheme.len != 0 ? 1 : 0) ||
        (parsed->authority.len != 0 &&
         !size_accumulate(&total, parsed->authority.len, 2)) ||
        !size_accumulate(&total, path.len, 0) ||
        (parsed->has_params && !size_accumulate(&total, parsed->params.len, 1)) ||
        (have_query && !size_accumulate(&total, query.len, 1)) ||
        (have_fragment &&
         !size_accumulate(&total, parsed->fragment.len, 1)) ||
        total == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    buffer = fb_arena_alloc(arena, total + 1, 1);
    if (buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    for (index = 0; index < parsed->scheme.len; ++index) {
        buffer[used++] = (char)ascii_lower((unsigned char)parsed->scheme.ptr[index]);
    }
    if (parsed->scheme.len != 0) {
        buffer[used++] = ':';
    }
    if (parsed->authority.len != 0) {
        buffer[used++] = '/';
        buffer[used++] = '/';
        memcpy(buffer + used, parsed->authority.ptr, parsed->authority.len);
        used += parsed->authority.len;
    }
    if (path.len != 0) {
        memcpy(buffer + used, path.ptr, path.len);
        used += path.len;
    }
    if (parsed->has_params) {
        buffer[used++] = ';';
        if (parsed->params.len != 0) {
            memcpy(buffer + used, parsed->params.ptr, parsed->params.len);
            used += parsed->params.len;
        }
    }
    if (have_query) {
        buffer[used++] = '?';
        memcpy(buffer + used, query.ptr, query.len);
        used += query.len;
    }
    if (have_fragment) {
        buffer[used++] = '#';
        memcpy(buffer + used, parsed->fragment.ptr, parsed->fragment.len);
        used += parsed->fragment.len;
    }
    buffer[used] = '\0';
    *out = slice_make(buffer, used);
    return FB_URL_OK;
}

fb_url_status
fb_url_preserve_comment_target(
    fb_arena *arena,
    fb_slice resolved_url,
    const fb_comment_target *source_target,
    fb_slice *out
)
{
    fb_comment_target resolved_target;
    fb_url_view parsed;
    fb_query query;
    query_replacement replacements[2];
    size_t replacement_count = 1;
    fb_slice encoded;
    fb_url_status status;

    if (arena == NULL || source_target == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    if (source_target->kind == FB_COMMENT_TARGET_NONE) {
        return arena_copy(arena, resolved_url, out);
    }
    if (source_target->kind != FB_COMMENT_TARGET_VALID) {
        return FB_URL_INVALID;
    }
    status = fb_url_comment_target(arena, resolved_url, &resolved_target);
    if (status != FB_URL_OK) {
        return status;
    }
    if (resolved_target.kind == FB_COMMENT_TARGET_INVALID ||
        (resolved_target.kind == FB_COMMENT_TARGET_VALID &&
         !fb_comment_targets_equal(source_target, &resolved_target))) {
        return FB_URL_INVALID;
    }
    status = fb_url_parse(resolved_url, &parsed);
    if (status != FB_URL_OK) {
        return status;
    }
    status = fb_query_parse(arena, parsed.query, true, &query);
    if (status != FB_URL_OK) {
        return status;
    }
    replacements[0].key = slice_make("comment_id", 10);
    replacements[0].value = source_target->comment_id;
    if (source_target->has_reply) {
        replacements[1].key = slice_make("reply_comment_id", 16);
        replacements[1].value = source_target->reply_comment_id;
        replacement_count = 2;
    }
    status = encode_grouped_query(arena, &query, NULL, 0, replacements,
                                  replacement_count, true, &encoded);
    if (status != FB_URL_OK) {
        return status;
    }
    return rebuild_url(arena, &parsed, parsed.path, encoded, out);
}

static const fb_query_pair *
single_query_value(const fb_query *query, const char *key, size_t *count)
{
    const fb_query_pair *result = NULL;
    size_t index;
    *count = 0;
    for (index = 0; index < query->len; ++index) {
        const fb_query_pair *pair = fb_query_at(query, index);
        if (slice_equal_lit(pair->key, key)) {
            result = pair;
            ++*count;
        }
    }
    return result;
}

static bool
valid_story_id(fb_slice value)
{
    size_t index;
    if (all_ascii_digits(value)) {
        return true;
    }
    if (!slice_starts_lit(value, "pfbid") || value.len == 5) {
        return false;
    }
    for (index = 5; index < value.len; ++index) {
        const unsigned char byte = (unsigned char)value.ptr[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9'))) {
            return false;
        }
    }
    return true;
}

static bool
watch_value(fb_slice value, fb_slice *numeric)
{
    size_t index = 0;
    while (index < value.len && value.ptr[index] >= '0' && value.ptr[index] <= '9') {
        ++index;
    }
    if (index == 0 || index == value.len) {
        return false;
    }
    numeric->ptr = value.ptr;
    numeric->len = index;
    while (index < value.len) {
        const unsigned char byte = (unsigned char)value.ptr[index++];
        if (!(byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n' ||
              byte == '\f' || byte == '\v' || byte == '/')) {
            return false;
        }
    }
    return true;
}

fb_url_status
fb_url_normalize_request_path(
    fb_arena *arena,
    fb_slice input,
    fb_slice *out,
    bool *changed
)
{
    static const fb_slice comment_keys[] = {
        {"comment_id", 10}, {"reply_comment_id", 16}
    };
    fb_url_view parsed;
    fb_query query;
    fb_slice route;
    fb_url_status status;

    if (arena == NULL || out == NULL || changed == NULL) {
        return FB_URL_INVALID;
    }
    *changed = false;
    status = fb_url_parse(input, &parsed);
    if (status != FB_URL_OK) {
        return status;
    }
    route = path_without_edge_slashes(parsed.path);
    if (!slice_equal_lit(route, "story.php") && !slice_equal_lit(route, "watch")) {
        return arena_copy(arena, input, out);
    }
    status = fb_query_parse(arena, parsed.query, true, &query);
    if (status != FB_URL_OK) {
        return status;
    }

    if (slice_equal_lit(route, "story.php")) {
        size_t owner_count;
        size_t story_count;
        const fb_query_pair *owner = single_query_value(&query, "id", &owner_count);
        const fb_query_pair *story = single_query_value(&query, "story_fbid", &story_count);
        fb_slice encoded;
        fb_slice new_path;
        size_t path_len;
        char *path_buffer;

        if (owner_count != 1 || story_count != 1 ||
            !all_ascii_digits(owner->value) || !valid_story_id(story->value)) {
            return arena_copy(arena, input, out);
        }
        status = encode_grouped_query(arena, &query, comment_keys,
                                      sizeof(comment_keys) / sizeof(comment_keys[0]),
                                      NULL, 0, false, &encoded);
        if (status != FB_URL_OK) {
            return status;
        }
        if (!size_add(owner->value.len, story->value.len, &path_len) ||
            !size_add(path_len, 8, &path_len) || path_len == SIZE_MAX) {
            return FB_URL_LIMIT;
        }
        path_buffer = fb_arena_alloc(arena, path_len + 1, 1);
        if (path_buffer == NULL) {
            return FB_URL_NO_MEMORY;
        }
        path_buffer[0] = '/';
        memcpy(path_buffer + 1, owner->value.ptr, owner->value.len);
        memcpy(path_buffer + 1 + owner->value.len, "/posts/", 7);
        memcpy(path_buffer + 8 + owner->value.len, story->value.ptr, story->value.len);
        path_buffer[path_len] = '\0';
        new_path = slice_make(path_buffer, path_len);
        status = rebuild_url(arena, &parsed, new_path, encoded, out);
        if (status != FB_URL_OK) {
            return status;
        }
        while (out->len != 0 && out->ptr[0] == '/') {
            ++out->ptr;
            --out->len;
        }
        *changed = true;
        return FB_URL_OK;
    }

    {
        size_t video_count;
        const fb_query_pair *video = single_query_value(&query, "v", &video_count);
        fb_slice numeric;
        query_replacement replacement;
        fb_slice encoded;

        if (video_count != 1 || !watch_value(video->value, &numeric)) {
            return arena_copy(arena, input, out);
        }
        replacement.key = slice_make("v", 1);
        replacement.value = numeric;
        status = encode_grouped_query(arena, &query, NULL, 0, &replacement, 1,
                                      false, &encoded);
        if (status != FB_URL_OK) {
            return status;
        }
        status = rebuild_url(arena, &parsed, parsed.path, encoded, out);
        if (status == FB_URL_OK) {
            *changed = true;
        }
        return status;
    }
}

static fb_slice
raw_path_from_view(const fb_url_view *view)
{
    size_t len = view->path.len;
    if (view->has_params) {
        len += view->params.len + 1;
    }
    return slice_make(view->path.ptr, len);
}

static fb_url_status
remove_dot_segments(fb_arena *arena, fb_slice path, fb_slice *out)
{
    const bool absolute = path.len != 0 && path.ptr[0] == '/';
    bool trailing = path.len != 0 && path.ptr[path.len - 1] == '/';
    size_t segment_bound = 1;
    size_t index;
    size_t cursor = 0;
    size_t used = 0;
    size_t depth = 0;
    size_t *marks;
    char *buffer;

    for (index = 0; index < path.len; ++index) {
        if (path.ptr[index] == '/') {
            if (segment_bound == SIZE_MAX) {
                return FB_URL_LIMIT;
            }
            ++segment_bound;
        }
    }
    if (segment_bound > SIZE_MAX / sizeof(*marks) || path.len > SIZE_MAX - 2) {
        return FB_URL_LIMIT;
    }
    marks = fb_arena_alloc(arena, segment_bound * sizeof(*marks),
                           _Alignof(size_t));
    buffer = fb_arena_alloc(arena, path.len + 2, 1);
    if (marks == NULL || buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    if (absolute) {
        buffer[used++] = '/';
    }
    while (cursor < path.len) {
        size_t begin;
        fb_slice segment;

        while (cursor < path.len && path.ptr[cursor] == '/') {
            ++cursor;
        }
        if (cursor == path.len) {
            break;
        }
        begin = cursor;
        while (cursor < path.len && path.ptr[cursor] != '/') {
            ++cursor;
        }
        segment = slice_make(path.ptr + begin, cursor - begin);
        if (slice_equal_lit(segment, ".")) {
            trailing = true;
            continue;
        }
        if (slice_equal_lit(segment, "..")) {
            trailing = true;
            if (depth != 0) {
                used = marks[--depth];
            } else if (!absolute) {
                const size_t mark = used;
                if (used != 0 && buffer[used - 1] != '/') {
                    buffer[used++] = '/';
                }
                marks[depth++] = mark;
                buffer[used++] = '.';
                buffer[used++] = '.';
            }
            continue;
        }
        {
            const size_t mark = used;
            if (used != 0 && buffer[used - 1] != '/') {
                buffer[used++] = '/';
            }
            marks[depth++] = mark;
            memcpy(buffer + used, segment.ptr, segment.len);
            used += segment.len;
            trailing = cursor < path.len && cursor + 1 == path.len;
        }
    }
    if (trailing && used != 0 && buffer[used - 1] != '/') {
        buffer[used++] = '/';
    }
    buffer[used] = '\0';
    *out = slice_make(buffer, used);
    return FB_URL_OK;
}

static fb_url_status
merge_paths(
    fb_arena *arena,
    const fb_url_view *base,
    fb_slice reference_path,
    fb_slice *out
)
{
    fb_slice base_path = raw_path_from_view(base);
    size_t prefix = 0;
    size_t index;
    size_t total;
    char *buffer;
    fb_slice merged;

    for (index = 0; index < base_path.len; ++index) {
        if (base_path.ptr[index] == '/') {
            prefix = index + 1;
        }
    }
    if (base->authority.len != 0 && base_path.len == 0) {
        prefix = 1;
    }
    if (!size_add(prefix, reference_path.len, &total)) {
        return FB_URL_LIMIT;
    }
    if (total == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    buffer = fb_arena_alloc(arena, total + 1, 1);
    if (buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    if (base_path.len != 0 && prefix != 0) {
        memcpy(buffer, base_path.ptr, prefix);
    } else if (prefix == 1) {
        buffer[0] = '/';
    }
    if (reference_path.len != 0) {
        memcpy(buffer + prefix, reference_path.ptr, reference_path.len);
    }
    buffer[total] = '\0';
    merged = slice_make(buffer, total);
    return remove_dot_segments(arena, merged, out);
}

static fb_url_status
build_joined_url(
    fb_arena *arena,
    fb_slice scheme,
    fb_slice authority,
    fb_slice path,
    fb_slice query,
    fb_slice fragment,
    fb_slice *out
)
{
    size_t total = 0;
    size_t used = 0;
    size_t index;
    char *buffer;

    if (!size_accumulate(&total, scheme.len, scheme.len != 0 ? 1 : 0) ||
        (authority.len != 0 && !size_accumulate(&total, authority.len, 2)) ||
        !size_accumulate(&total, path.len, 0) ||
        (query.len != 0 && !size_accumulate(&total, query.len, 1)) ||
        (fragment.len != 0 && !size_accumulate(&total, fragment.len, 1)) ||
        total == SIZE_MAX) {
        return FB_URL_LIMIT;
    }
    buffer = fb_arena_alloc(arena, total + 1, 1);
    if (buffer == NULL) {
        return FB_URL_NO_MEMORY;
    }
    for (index = 0; index < scheme.len; ++index) {
        buffer[used++] = (char)ascii_lower((unsigned char)scheme.ptr[index]);
    }
    if (scheme.len != 0) {
        buffer[used++] = ':';
    }
    if (authority.len != 0) {
        buffer[used++] = '/';
        buffer[used++] = '/';
        memcpy(buffer + used, authority.ptr, authority.len);
        used += authority.len;
    }
    if (path.len != 0) {
        memcpy(buffer + used, path.ptr, path.len);
        used += path.len;
    }
    if (query.len != 0) {
        buffer[used++] = '?';
        memcpy(buffer + used, query.ptr, query.len);
        used += query.len;
    }
    if (fragment.len != 0) {
        buffer[used++] = '#';
        memcpy(buffer + used, fragment.ptr, fragment.len);
        used += fragment.len;
    }
    buffer[used] = '\0';
    *out = slice_make(buffer, used);
    return FB_URL_OK;
}

fb_url_status
fb_url_join(
    fb_arena *arena,
    fb_slice base,
    fb_slice reference,
    fb_slice *out
)
{
    fb_url_view base_view;
    fb_url_view reference_view;
    fb_slice scheme;
    fb_slice authority;
    fb_slice path;
    fb_slice query;
    fb_slice fragment;
    fb_slice reference_path;
    fb_url_status status;

    if (arena == NULL || out == NULL) {
        return FB_URL_INVALID;
    }
    if (reference.len == 0) {
        return arena_copy(arena, base, out);
    }
    status = fb_url_parse(base, &base_view);
    if (status != FB_URL_OK) {
        return status;
    }
    status = fb_url_parse(reference, &reference_view);
    if (status != FB_URL_OK) {
        return status;
    }
    if (reference_view.scheme.len != 0 &&
        !slice_equal_icase(reference_view.scheme, base_view.scheme)) {
        return arena_copy(arena, reference, out);
    }

    scheme = reference_view.scheme.len != 0
        ? reference_view.scheme : base_view.scheme;
    fragment = reference_view.has_fragment
        ? reference_view.fragment : slice_make(NULL, 0);
    reference_path = raw_path_from_view(&reference_view);

    if (reference_view.authority.len != 0) {
        authority = reference_view.authority;
        status = remove_dot_segments(arena, reference_path, &path);
        if (status != FB_URL_OK) {
            return status;
        }
        query = reference_view.query;
        return build_joined_url(arena, scheme, authority, path, query, fragment, out);
    }

    authority = base_view.authority;
    if (reference_path.len == 0) {
        path = raw_path_from_view(&base_view);
        query = reference_view.has_query ? reference_view.query : base_view.query;
    } else {
        if (reference_path.ptr[0] == '/') {
            status = remove_dot_segments(arena, reference_path, &path);
        } else {
            status = merge_paths(arena, &base_view, reference_path, &path);
        }
        if (status != FB_URL_OK) {
            return status;
        }
        query = reference_view.query;
    }
    return build_joined_url(arena, scheme, authority, path, query, fragment, out);
}

fb_url_status
fb_url_resolve_redirect(
    fb_arena *arena,
    fb_slice base,
    fb_slice location,
    fb_slice *out
)
{
    fb_url_status status = fb_url_join(arena, base, location, out);
    if (status != FB_URL_OK) {
        return status;
    }
    return fb_url_is_safe_redirect(*out) ? FB_URL_OK : FB_URL_UNSAFE;
}

const char *
fb_url_status_string(fb_url_status status)
{
    switch (status) {
    case FB_URL_OK:
        return "ok";
    case FB_URL_INVALID:
        return "invalid URL";
    case FB_URL_UNSAFE:
        return "unsafe URL";
    case FB_URL_NO_MEMORY:
        return "out of memory";
    case FB_URL_LIMIT:
        return "URL limit exceeded";
    }
    return "unknown URL error";
}
