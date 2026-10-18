#ifndef FASTBED_COMMON_H
#define FASTBED_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define FB_LIKELY(expr) __builtin_expect(!!(expr), 1)
#define FB_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define FB_HOT __attribute__((hot))
#define FB_COLD __attribute__((cold))
#define FB_NODISCARD __attribute__((warn_unused_result))
#define FB_PRINTF_FORMAT(format_index, argument_index) \
    __attribute__((format(printf, format_index, argument_index)))
#else
#define FB_LIKELY(expr) (!!(expr))
#define FB_UNLIKELY(expr) (!!(expr))
#define FB_HOT
#define FB_COLD
#define FB_NODISCARD
#define FB_PRINTF_FORMAT(format_index, argument_index)
#endif

#define FB_ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

/* A slice never implies ownership and need not be NUL terminated. */
typedef struct {
    const char *ptr;
    size_t len;
} fb_slice;

#define FB_SLICE_LIT(literal) \
    ((fb_slice){.ptr = (literal), .len = sizeof(literal) - 1u})

static inline fb_slice
fb_slice_make(const char *ptr, size_t len)
{
    return (fb_slice){.ptr = ptr, .len = len};
}

static inline fb_slice
fb_slice_from_cstr(const char *str)
{
    return str != NULL ? fb_slice_make(str, strlen(str))
                       : fb_slice_make(NULL, 0u);
}

static inline bool
fb_slice_is_valid(fb_slice value)
{
    return value.ptr != NULL || value.len == 0u;
}

static inline bool
fb_slice_equal(fb_slice left, fb_slice right)
{
    return left.len == right.len &&
           (left.len == 0u ||
            (left.ptr != NULL && right.ptr != NULL &&
             memcmp(left.ptr, right.ptr, left.len) == 0));
}

static inline bool
fb_size_add(size_t left, size_t right, size_t *result)
{
    if (FB_UNLIKELY(result == NULL || left > SIZE_MAX - right)) {
        return false;
    }
    *result = left + right;
    return true;
}

static inline bool
fb_size_mul(size_t left, size_t right, size_t *result)
{
    if (FB_UNLIKELY(result == NULL ||
                    (left != 0u && right > SIZE_MAX / left))) {
        return false;
    }
    *result = left * right;
    return true;
}

#endif
