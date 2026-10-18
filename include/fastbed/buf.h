#ifndef FASTBED_BUF_H
#define FASTBED_BUF_H

#include "fastbed/arena.h"

/* Arena-owned, always-NUL-terminated byte builder. len excludes the NUL. */
typedef struct {
    fb_arena *arena;
    char *data;
    size_t len;
    size_t capacity;
    bool failed;
} fb_buf;

FB_NODISCARD bool fb_buf_init(
    fb_buf *buffer,
    fb_arena *arena,
    size_t initial_capacity
);
void fb_buf_reset(fb_buf *buffer);
FB_NODISCARD bool fb_buf_reserve(fb_buf *buffer, size_t additional);
FB_NODISCARD bool fb_buf_append(fb_buf *buffer, fb_slice value);
FB_NODISCARD bool fb_buf_append_cstr(fb_buf *buffer, const char *value);
FB_NODISCARD bool fb_buf_append_char(fb_buf *buffer, char value);
FB_NODISCARD bool fb_buf_append_repeat(
    fb_buf *buffer,
    char value,
    size_t count
);
FB_NODISCARD bool fb_buf_append_u64(fb_buf *buffer, uint64_t value);
FB_NODISCARD bool fb_buf_append_i64(fb_buf *buffer, int64_t value);

static inline bool
fb_buf_ok(const fb_buf *buffer)
{
    return buffer != NULL && !buffer->failed;
}

static inline fb_slice
fb_buf_view(const fb_buf *buffer)
{
    return buffer != NULL && !buffer->failed
               ? fb_slice_make(buffer->data, buffer->len)
               : fb_slice_make(NULL, 0u);
}

static inline const char *
fb_buf_cstr(const fb_buf *buffer)
{
    return buffer != NULL && !buffer->failed ? buffer->data : NULL;
}

#endif
