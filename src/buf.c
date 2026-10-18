#include "fastbed/buf.h"

#include <string.h>

#define FB_BUF_DEFAULT_CAPACITY 256u

static bool
fb_buf_fail(fb_buf *buffer)
{
    if (buffer != NULL) {
        buffer->failed = true;
    }
    return false;
}

bool
fb_buf_init(fb_buf *buffer, fb_arena *arena, size_t initial_capacity)
{
    if (buffer == NULL || arena == NULL) {
        return false;
    }
    memset(buffer, 0, sizeof(*buffer));
    buffer->arena = arena;
    if (initial_capacity == 0u) {
        initial_capacity = FB_BUF_DEFAULT_CAPACITY;
    }

    size_t allocation_size;
    if (!fb_size_add(initial_capacity, 1u, &allocation_size)) {
        return fb_buf_fail(buffer);
    }
    buffer->data = fb_arena_alloc(arena, allocation_size, 1u);
    if (buffer->data == NULL) {
        return fb_buf_fail(buffer);
    }
    buffer->capacity = initial_capacity;
    buffer->data[0] = '\0';
    return true;
}

void
fb_buf_reset(fb_buf *buffer)
{
    if (buffer == NULL || buffer->data == NULL) {
        return;
    }
    buffer->len = 0u;
    buffer->failed = false;
    buffer->data[0] = '\0';
}

bool
fb_buf_reserve(fb_buf *buffer, size_t additional)
{
    if (buffer == NULL || buffer->failed || buffer->arena == NULL ||
        buffer->data == NULL) {
        return fb_buf_fail(buffer);
    }

    size_t required;
    if (!fb_size_add(buffer->len, additional, &required)) {
        return fb_buf_fail(buffer);
    }
    if (required <= buffer->capacity) {
        return true;
    }

    size_t capacity = buffer->capacity != 0u
                          ? buffer->capacity
                          : FB_BUF_DEFAULT_CAPACITY;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2u) {
            capacity = required;
            break;
        }
        capacity *= 2u;
    }

    size_t allocation_size;
    if (!fb_size_add(capacity, 1u, &allocation_size)) {
        return fb_buf_fail(buffer);
    }
    char *replacement =
        fb_arena_alloc(buffer->arena, allocation_size, 1u);
    if (replacement == NULL) {
        return fb_buf_fail(buffer);
    }
    memcpy(replacement, buffer->data, buffer->len + 1u);
    buffer->data = replacement;
    buffer->capacity = capacity;
    return true;
}

bool
fb_buf_append(fb_buf *buffer, fb_slice value)
{
    if (!fb_slice_is_valid(value) || !fb_buf_reserve(buffer, value.len)) {
        return fb_buf_fail(buffer);
    }
    if (value.len != 0u) {
        memcpy(buffer->data + buffer->len, value.ptr, value.len);
        buffer->len += value.len;
        buffer->data[buffer->len] = '\0';
    }
    return true;
}

bool
fb_buf_append_cstr(fb_buf *buffer, const char *value)
{
    if (value == NULL) {
        return fb_buf_fail(buffer);
    }
    return fb_buf_append(buffer, fb_slice_from_cstr(value));
}

bool
fb_buf_append_char(fb_buf *buffer, char value)
{
    if (!fb_buf_reserve(buffer, 1u)) {
        return false;
    }
    buffer->data[buffer->len++] = value;
    buffer->data[buffer->len] = '\0';
    return true;
}

bool
fb_buf_append_repeat(fb_buf *buffer, char value, size_t count)
{
    if (!fb_buf_reserve(buffer, count)) {
        return false;
    }
    if (count != 0u) {
        memset(buffer->data + buffer->len, (unsigned char)value, count);
        buffer->len += count;
        buffer->data[buffer->len] = '\0';
    }
    return true;
}

bool
fb_buf_append_u64(fb_buf *buffer, uint64_t value)
{
    char digits[20];
    size_t count = 0u;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0u);

    if (!fb_buf_reserve(buffer, count)) {
        return false;
    }
    while (count != 0u) {
        buffer->data[buffer->len++] = digits[--count];
    }
    buffer->data[buffer->len] = '\0';
    return true;
}

bool
fb_buf_append_i64(fb_buf *buffer, int64_t value)
{
    if (value >= 0) {
        return fb_buf_append_u64(buffer, (uint64_t)value);
    }
    const uint64_t magnitude = (uint64_t)(-(value + 1)) + 1u;
    return fb_buf_append_char(buffer, '-') &&
           fb_buf_append_u64(buffer, magnitude);
}
