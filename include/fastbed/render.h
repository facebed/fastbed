#ifndef FASTBED_RENDER_H
#define FASTBED_RENDER_H

#include "fastbed/buf.h"
#include "fastbed/cancel.h"
#include "fastbed/model.h"

#define FB_CREDIT "facebed by pi.kt"

typedef enum {
    FB_RENDER_OK = 0,
    FB_RENDER_ERROR,
    FB_RENDER_CANCELLED
} fb_render_status;

/* Python-compatible html.escape(value, quote=quote). */
FB_NODISCARD bool fb_buf_append_html_escape(
    fb_buf *output,
    fb_slice value,
    bool quote
);

/* Facebed's deliberately narrow per-character URL quoting operation. */
FB_NODISCARD bool fb_buf_append_facebed_quote(
    fb_buf *output,
    fb_slice value
);

/* Longest prefix containing at most max_codepoints complete UTF-8 values. */
fb_slice fb_utf8_prefix(fb_slice value, size_t max_codepoints);

/* Empty output for negative timestamps, as in the pinned Python service. */
FB_NODISCARD bool fb_format_timestamp(
    fb_buf *output,
    int64_t epoch_seconds,
    int utc_offset_hours
);

/* Python Utils.human_format compatibility for ASCII decimal inputs. */
FB_NODISCARD bool fb_format_human_count(fb_buf *output, fb_slice value);

FB_NODISCARD bool fb_format_reactions(
    fb_buf *output,
    fb_slice likes,
    fb_slice comments,
    fb_slice shares,
    const fb_slice *top_reaction_ids,
    size_t top_reaction_count
);

/* All returned slices are NUL-terminated and owned by arena. */
FB_NODISCARD bool fb_render_video_post(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    fb_slice *result
);
FB_NODISCARD bool fb_render_image_post(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    fb_slice *result
);
FB_NODISCARD bool fb_render_post(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    fb_slice *result
);
FB_NODISCARD fb_render_status fb_render_post_cancelable(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    const fb_cancel_token *cancel,
    fb_slice *result
);
FB_NODISCARD bool fb_render_fallback(
    fb_arena *arena,
    fb_slice original_url,
    fb_slice *result
);
FB_NODISCARD bool fb_render_browser_redirect(
    fb_arena *arena,
    fb_slice url,
    fb_slice *result
);

#endif
