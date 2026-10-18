#include "fastbed/render.h"

#include <limits.h>
#include <string.h>

#if defined(__x86_64__) && \
    (defined(__GNUC__) || defined(__clang__))
#define FB_RENDER_X86_SIMD 1
#include <immintrin.h>
#else
#define FB_RENDER_X86_SIMD 0
#endif

typedef struct {
    fb_slice id;
    fb_slice emoji;
} fb_reaction_entry;

#define FB_STATIC_SLICE(literal) \
    {.ptr = (literal), .len = sizeof(literal) - 1u}
#define FB_CANCEL_BYTE_INTERVAL ((size_t)64u * 1024u)
#define FB_CANCEL_ITEM_INTERVAL ((size_t)256u)

static const fb_reaction_entry FB_REACTIONS[] = {
    {FB_STATIC_SLICE("1635855486666999"),
     FB_STATIC_SLICE("\xF0\x9F\x91\x8D")},
    {FB_STATIC_SLICE("1678524932434102"),
     FB_STATIC_SLICE("\xE2\x9D\xA4\xEF\xB8\x8F")},
    {FB_STATIC_SLICE("613557422527858"),
     FB_STATIC_SLICE("\xF0\x9F\xA4\x97")},
    {FB_STATIC_SLICE("115940658764963"),
     FB_STATIC_SLICE("\xF0\x9F\x98\x82")},
    {FB_STATIC_SLICE("478547315650144"),
     FB_STATIC_SLICE("\xF0\x9F\x98\xAE")},
    {FB_STATIC_SLICE("908563459236466"),
     FB_STATIC_SLICE("\xF0\x9F\x98\xA2")},
    {FB_STATIC_SLICE("444813342392137"),
     FB_STATIC_SLICE("\xF0\x9F\x98\xA1")},
};

static const fb_slice FB_DEFAULT_REACTION =
    FB_STATIC_SLICE("\xE2\x9D\xA4\xEF\xB8\x8F");

static bool
fb_append_literal(fb_buf *output, fb_slice literal)
{
    if (output != NULL && !output->failed && output->data != NULL &&
        output->len <= output->capacity &&
        literal.len <= output->capacity - output->len) {
        if (literal.len != 0u) {
            memcpy(output->data + output->len, literal.ptr, literal.len);
            output->len += literal.len;
            output->data[output->len] = '\0';
        }
        return true;
    }
    return fb_buf_append(output, literal);
}

static bool
fb_append_span(fb_buf *output, const char *pointer, size_t length)
{
    return length == 0u ||
           fb_append_literal(output, fb_slice_make(pointer, length));
}

static bool
fb_append_self_span(fb_buf *output, size_t offset, size_t length)
{
    if (output == NULL || offset > output->len ||
        length > output->len - offset ||
        !fb_buf_reserve(output, length)) {
        return false;
    }
    if (length != 0u) {
        memcpy(output->data + output->len, output->data + offset, length);
        output->len += length;
        output->data[output->len] = '\0';
    }
    return true;
}

static size_t
fb_html_replacement(
    unsigned char value,
    bool quote,
    const char **replacement
)
{
    switch (value) {
    case '&':
        *replacement = "&amp;";
        return 5u;
    case '<':
        *replacement = "&lt;";
        return 4u;
    case '>':
        *replacement = "&gt;";
        return 4u;
    case '"':
        if (quote) {
            *replacement = "&quot;";
            return 6u;
        }
        break;
    case '\'':
        if (quote) {
            *replacement = "&#x27;";
            return 6u;
        }
        break;
    default:
        break;
    }
    *replacement = NULL;
    return 0u;
}

static bool
fb_html_reserve(fb_buf *output, fb_slice value, bool quote)
{
    size_t maximum;
    if (!fb_size_mul(value.len, 6u, &maximum)) {
        return false;
    }
    const size_t available =
        output != NULL && output->data != NULL && !output->failed &&
                output->len <= output->capacity
            ? output->capacity - output->len
            : 0u;
    size_t required = maximum;
    if (maximum > available) {
        required = value.len;
        for (size_t index = 0u; index < value.len; ++index) {
            const char *replacement;
            const size_t replacement_length = fb_html_replacement(
                (unsigned char)value.ptr[index], quote, &replacement
            );
            if (replacement_length != 0u &&
                !fb_size_add(required, replacement_length - 1u,
                             &required)) {
                return false;
            }
        }
    }
    return fb_buf_reserve(output, required);
}

static void
fb_html_emit_special(
    char **destination,
    fb_slice value,
    size_t position,
    size_t *run,
    bool quote
)
{
    const size_t raw_length = position - *run;
    if (raw_length != 0u) {
        memcpy(*destination, value.ptr + *run, raw_length);
        *destination += raw_length;
    }
    const char *replacement;
    const size_t replacement_length = fb_html_replacement(
        (unsigned char)value.ptr[position], quote, &replacement
    );
    memcpy(*destination, replacement, replacement_length);
    *destination += replacement_length;
    *run = position + 1u;
}

static bool
fb_html_finish_direct(
    fb_buf *output,
    fb_slice value,
    size_t run,
    char *destination
)
{
    if (run < value.len) {
        const size_t raw_length = value.len - run;
        memcpy(destination, value.ptr + run, raw_length);
        destination += raw_length;
    }
    output->len = (size_t)(destination - output->data);
    output->data[output->len] = '\0';
    return true;
}

#if FB_RENDER_X86_SIMD
static bool
fb_buf_append_html_escape_sse2(fb_buf *output, fb_slice value, bool quote)
{
    if (!fb_html_reserve(output, value, quote)) {
        return false;
    }
    char *destination = output->data + output->len;
    const __m128i amp = _mm_set1_epi8('&');
    const __m128i less = _mm_set1_epi8('<');
    const __m128i greater = _mm_set1_epi8('>');
    const __m128i double_quote = _mm_set1_epi8('"');
    const __m128i single_quote = _mm_set1_epi8('\'');
    size_t index = 0u;
    size_t run = 0u;
    while (value.len - index >= 16u) {
        const __m128i bytes =
            _mm_loadu_si128((const __m128i *)(value.ptr + index));
        __m128i matches = _mm_or_si128(
            _mm_cmpeq_epi8(bytes, amp),
            _mm_cmpeq_epi8(bytes, less)
        );
        matches = _mm_or_si128(matches, _mm_cmpeq_epi8(bytes, greater));
        if (quote) {
            matches = _mm_or_si128(
                matches,
                _mm_cmpeq_epi8(bytes, double_quote)
            );
            matches = _mm_or_si128(
                matches,
                _mm_cmpeq_epi8(bytes, single_quote)
            );
        }
        unsigned mask = (unsigned)_mm_movemask_epi8(matches);
        while (mask != 0u) {
            const size_t position =
                index + (size_t)__builtin_ctz(mask);
            fb_html_emit_special(&destination, value, position, &run, quote);
            mask &= mask - 1u;
        }
        index += 16u;
    }
    for (; index < value.len; ++index) {
        const char *replacement;
        if (fb_html_replacement((unsigned char)value.ptr[index], quote,
                                &replacement) != 0u) {
            fb_html_emit_special(&destination, value, index, &run, quote);
        }
    }
    return fb_html_finish_direct(output, value, run, destination);
}

__attribute__((target("avx2")))
static bool
fb_buf_append_html_escape_avx2(fb_buf *output, fb_slice value, bool quote)
{
    if (!fb_html_reserve(output, value, quote)) {
        return false;
    }
    char *destination = output->data + output->len;
    const __m256i amp = _mm256_set1_epi8('&');
    const __m256i less = _mm256_set1_epi8('<');
    const __m256i greater = _mm256_set1_epi8('>');
    const __m256i double_quote = _mm256_set1_epi8('"');
    const __m256i single_quote = _mm256_set1_epi8('\'');
    size_t index = 0u;
    size_t run = 0u;
    while (value.len - index >= 32u) {
        const __m256i bytes =
            _mm256_loadu_si256((const __m256i *)(value.ptr + index));
        __m256i matches = _mm256_or_si256(
            _mm256_cmpeq_epi8(bytes, amp),
            _mm256_cmpeq_epi8(bytes, less)
        );
        matches = _mm256_or_si256(
            matches,
            _mm256_cmpeq_epi8(bytes, greater)
        );
        if (quote) {
            matches = _mm256_or_si256(
                matches,
                _mm256_cmpeq_epi8(bytes, double_quote)
            );
            matches = _mm256_or_si256(
                matches,
                _mm256_cmpeq_epi8(bytes, single_quote)
            );
        }
        unsigned mask = (unsigned)_mm256_movemask_epi8(matches);
        while (mask != 0u) {
            const size_t position =
                index + (size_t)__builtin_ctz(mask);
            fb_html_emit_special(&destination, value, position, &run, quote);
            mask &= mask - 1u;
        }
        index += 32u;
    }
    for (; index < value.len; ++index) {
        const char *replacement;
        if (fb_html_replacement((unsigned char)value.ptr[index], quote,
                                &replacement) != 0u) {
            fb_html_emit_special(&destination, value, index, &run, quote);
        }
    }
    return fb_html_finish_direct(output, value, run, destination);
}
#endif

bool
fb_buf_append_html_escape(fb_buf *output, fb_slice value, bool quote)
{
    if (output == NULL || !fb_slice_is_valid(value)) {
        return false;
    }
    if (value.len == 0u) {
        return true;
    }

#if FB_RENDER_X86_SIMD
    if (value.len >= 32u &&
#if defined(__AVX2__)
        true
#else
        __builtin_cpu_supports("avx2")
#endif
    ) {
        return fb_buf_append_html_escape_avx2(output, value, quote);
    }
    if (value.len >= 16u) {
        return fb_buf_append_html_escape_sse2(output, value, quote);
    }
#endif

    size_t run = 0u;
    for (size_t index = 0u; index < value.len; ++index) {
        fb_slice replacement = fb_slice_make(NULL, 0u);
        switch ((unsigned char)value.ptr[index]) {
        case '&':
            replacement = FB_SLICE_LIT("&amp;");
            break;
        case '<':
            replacement = FB_SLICE_LIT("&lt;");
            break;
        case '>':
            replacement = FB_SLICE_LIT("&gt;");
            break;
        case '"':
            if (quote) {
                replacement = FB_SLICE_LIT("&quot;");
            }
            break;
        case '\'':
            if (quote) {
                replacement = FB_SLICE_LIT("&#x27;");
            }
            break;
        default:
            break;
        }
        if (replacement.ptr == NULL) {
            continue;
        }
        if (!fb_append_span(output, value.ptr + run, index - run) ||
            !fb_buf_append(output, replacement)) {
            return false;
        }
        run = index + 1u;
    }
    return fb_append_span(output, value.ptr + run, value.len - run);
}

static fb_slice
fb_facebed_quote_replacement(unsigned char byte)
{
    switch (byte) {
    case '<':
        return FB_SLICE_LIT("%3C");
    case '>':
        return FB_SLICE_LIT("%3E");
    case '"':
        return FB_SLICE_LIT("%22");
    case '\'':
        return FB_SLICE_LIT("%27");
    case '#':
        return FB_SLICE_LIT("%23");
    case '%':
        return FB_SLICE_LIT("%25");
    case '{':
        return FB_SLICE_LIT("%7B");
    case '}':
        return FB_SLICE_LIT("%7D");
    case '[':
        return FB_SLICE_LIT("%5B");
    case ']':
        return FB_SLICE_LIT("%5D");
    case '|':
        return FB_SLICE_LIT("%7C");
    case '\\':
        return FB_SLICE_LIT("%5C");
    case '^':
        return FB_SLICE_LIT("%5E");
    case '`':
        return FB_SLICE_LIT("%60");
    default:
        /* urllib.parse.quote("~") leaves it unchanged. */
        return fb_slice_make(NULL, 0u);
    }
}

bool
fb_buf_append_facebed_quote(fb_buf *output, fb_slice value)
{
    if (output == NULL || !fb_slice_is_valid(value)) {
        return false;
    }
    if (value.len == 0u) {
        return true;
    }
    size_t run = 0u;
    for (size_t index = 0u; index < value.len; ++index) {
        const fb_slice replacement =
            fb_facebed_quote_replacement((unsigned char)value.ptr[index]);
        if (replacement.ptr == NULL) {
            continue;
        }
        if (!fb_append_span(output, value.ptr + run, index - run) ||
            !fb_buf_append(output, replacement)) {
            return false;
        }
        run = index + 1u;
    }
    return fb_append_span(output, value.ptr + run, value.len - run);
}

/* html.escape(quote(url), quote=True), fused to avoid a temporary buffer. */
static bool
fb_append_facebed_url_attribute(fb_buf *output, fb_slice value)
{
    if (output == NULL || !fb_slice_is_valid(value)) {
        return false;
    }
    if (value.len == 0u) {
        return true;
    }
    size_t run = 0u;
    for (size_t index = 0u; index < value.len; ++index) {
        fb_slice replacement = fb_facebed_quote_replacement(
            (unsigned char)value.ptr[index]);
        if (replacement.ptr == NULL && value.ptr[index] == '&') {
            replacement = FB_SLICE_LIT("&amp;");
        }
        if (replacement.ptr == NULL) {
            continue;
        }
        if (!fb_append_span(output, value.ptr + run, index - run) ||
            !fb_buf_append(output, replacement)) {
            return false;
        }
        run = index + 1u;
    }
    return fb_append_span(output, value.ptr + run, value.len - run);
}

static bool
fb_append_html_escape_cancelable(
    fb_buf *output,
    fb_slice value,
    bool quote,
    const fb_cancel_token *cancel
)
{
    size_t offset = 0u;
    while (offset < value.len) {
        size_t length = value.len - offset;
        if (fb_cancel_requested(cancel)) {
            return false;
        }
        if (length > FB_CANCEL_BYTE_INTERVAL) {
            length = FB_CANCEL_BYTE_INTERVAL;
        }
        if (!fb_buf_append_html_escape(
                output, fb_slice_make(value.ptr + offset, length), quote)) {
            return false;
        }
        offset += length;
    }
    return !fb_cancel_requested(cancel);
}

static bool
fb_append_url_attribute_cancelable(
    fb_buf *output,
    fb_slice value,
    const fb_cancel_token *cancel
)
{
    size_t offset = 0u;
    while (offset < value.len) {
        size_t length = value.len - offset;
        if (fb_cancel_requested(cancel)) {
            return false;
        }
        if (length > FB_CANCEL_BYTE_INTERVAL) {
            length = FB_CANCEL_BYTE_INTERVAL;
        }
        if (!fb_append_facebed_url_attribute(
                output, fb_slice_make(value.ptr + offset, length))) {
            return false;
        }
        offset += length;
    }
    return !fb_cancel_requested(cancel);
}

static size_t
fb_utf8_decode_one(const unsigned char *bytes, size_t available, uint32_t *value)
{
    const unsigned char first = bytes[0];
    if (first < 0x80u) {
        *value = first;
        return 1u;
    }
    if (first >= 0xC2u && first <= 0xDFu && available >= 2u &&
        (bytes[1] & 0xC0u) == 0x80u) {
        *value = ((uint32_t)(first & 0x1Fu) << 6u) |
                 (uint32_t)(bytes[1] & 0x3Fu);
        return 2u;
    }
    if (first >= 0xE0u && first <= 0xEFu && available >= 3u &&
        (bytes[1] & 0xC0u) == 0x80u && (bytes[2] & 0xC0u) == 0x80u &&
        !(first == 0xE0u && bytes[1] < 0xA0u) &&
        !(first == 0xEDu && bytes[1] >= 0xA0u)) {
        *value = ((uint32_t)(first & 0x0Fu) << 12u) |
                 ((uint32_t)(bytes[1] & 0x3Fu) << 6u) |
                 (uint32_t)(bytes[2] & 0x3Fu);
        return 3u;
    }
    if (first >= 0xF0u && first <= 0xF4u && available >= 4u &&
        (bytes[1] & 0xC0u) == 0x80u && (bytes[2] & 0xC0u) == 0x80u &&
        (bytes[3] & 0xC0u) == 0x80u &&
        !(first == 0xF0u && bytes[1] < 0x90u) &&
        !(first == 0xF4u && bytes[1] > 0x8Fu)) {
        *value = ((uint32_t)(first & 0x07u) << 18u) |
                 ((uint32_t)(bytes[1] & 0x3Fu) << 12u) |
                 ((uint32_t)(bytes[2] & 0x3Fu) << 6u) |
                 (uint32_t)(bytes[3] & 0x3Fu);
        return 4u;
    }

    /* Preserve malformed input byte-for-byte and count it as one value. */
    *value = first;
    return 1u;
}

fb_slice
fb_utf8_prefix(fb_slice value, size_t max_codepoints)
{
    if (!fb_slice_is_valid(value) || value.len == 0u) {
        return value;
    }
    /* Every decoded value consumes at least one byte, including malformed. */
    if (value.len <= max_codepoints) {
        return value;
    }
    size_t offset = 0u;
    size_t count = 0u;
    while (offset < value.len && count < max_codepoints) {
        uint32_t ignored;
        offset += fb_utf8_decode_one(
            (const unsigned char *)value.ptr + offset,
            value.len - offset,
            &ignored
        );
        ++count;
    }
    return fb_slice_make(value.ptr, offset);
}

bool
fb_format_timestamp(
    fb_buf *output,
    int64_t epoch_seconds,
    int utc_offset_hours
)
{
    if (output == NULL || utc_offset_hours < -12 || utc_offset_hours > 14) {
        return false;
    }
    if (epoch_seconds < 0) {
        return true;
    }

    int64_t days = epoch_seconds / 86400;
    int64_t seconds = epoch_seconds % 86400;
    seconds += (int64_t)utc_offset_hours * 3600;
    if (seconds < 0) {
        seconds += 86400;
        --days;
    } else if (seconds >= 86400) {
        seconds -= 86400;
        ++days;
    }

    /* Proleptic Gregorian conversion, with 1970-01-01 as day zero. */
    const int64_t shifted = days + 719468;
    const int64_t era =
        (shifted >= 0 ? shifted : shifted - 146096) / 146097;
    const unsigned day_of_era = (unsigned)(shifted - era * 146097);
    const unsigned year_of_era =
        (day_of_era - day_of_era / 1460u + day_of_era / 36524u -
         day_of_era / 146096u) /
        365u;
    int64_t year = (int64_t)year_of_era + era * 400;
    const unsigned day_of_year =
        day_of_era - (365u * year_of_era + year_of_era / 4u -
                      year_of_era / 100u);
    const unsigned month_prime = (5u * day_of_year + 2u) / 153u;
    const unsigned day =
        day_of_year - (153u * month_prime + 2u) / 5u + 1u;
    const unsigned month = month_prime < 10u
                               ? month_prime + 3u
                               : month_prime - 9u;
    year += month <= 2u;
    if (year < 1 || year > 9999) {
        return false;
    }

    const unsigned hour = (unsigned)(seconds / 3600);
    const unsigned minute = (unsigned)(seconds % 3600 / 60);
    const unsigned second = (unsigned)(seconds % 60);
    const unsigned offset_magnitude =
        (unsigned)(utc_offset_hours < 0 ? -utc_offset_hours
                                       : utc_offset_hours);

    char timestamp[30] = {
        '\xE2', '\x8C', '\x9A', ' ',
        '0', '0', '0', '0', '/', '0', '0', '/', '0', '0', ' ',
        '0', '0', ':', '0', '0', ':', '0', '0',
        ' ', 'U', 'T', 'C', '+', '0', '0',
    };
    timestamp[4] = (char)('0' + ((unsigned)year / 1000u) % 10u);
    timestamp[5] = (char)('0' + ((unsigned)year / 100u) % 10u);
    timestamp[6] = (char)('0' + ((unsigned)year / 10u) % 10u);
    timestamp[7] = (char)('0' + (unsigned)year % 10u);
    timestamp[9] = (char)('0' + (month / 10u) % 10u);
    timestamp[10] = (char)('0' + month % 10u);
    timestamp[12] = (char)('0' + (day / 10u) % 10u);
    timestamp[13] = (char)('0' + day % 10u);
    timestamp[15] = (char)('0' + (hour / 10u) % 10u);
    timestamp[16] = (char)('0' + hour % 10u);
    timestamp[18] = (char)('0' + (minute / 10u) % 10u);
    timestamp[19] = (char)('0' + minute % 10u);
    timestamp[21] = (char)('0' + (second / 10u) % 10u);
    timestamp[22] = (char)('0' + second % 10u);
    timestamp[27] = utc_offset_hours < 0 ? '-' : '+';
    timestamp[28] =
        (char)('0' + (offset_magnitude / 10u) % 10u);
    timestamp[29] = (char)('0' + offset_magnitude % 10u);
    return fb_append_literal(
        output,
        fb_slice_make(timestamp, sizeof(timestamp))
    );
}

bool
fb_format_human_count(fb_buf *output, fb_slice value)
{
    if (output == NULL || !fb_slice_is_valid(value)) {
        return false;
    }
    if (value.len == 0u) {
        return true;
    }
    for (size_t index = 0u; index < value.len; ++index) {
        if (value.ptr[index] < '0' || value.ptr[index] > '9') {
            return fb_buf_append(output, value);
        }
    }

    size_t first = 0u;
    while (first < value.len && value.ptr[first] == '0') {
        ++first;
    }
    if (first == value.len) {
        return fb_buf_append_char(output, '0');
    }

    const size_t digit_count = value.len - first;
    const size_t kept = digit_count < 3u ? digit_count : 3u;
    unsigned coefficient = 0u;
    for (size_t index = 0u; index < kept; ++index) {
        coefficient = coefficient * 10u +
                      (unsigned)(value.ptr[first + index] - '0');
    }

    size_t effective_digits = digit_count;
    if (digit_count > 3u) {
        const unsigned next = (unsigned)(value.ptr[first + 3u] - '0');
        bool trailing_nonzero = false;
        for (size_t index = first + 4u; index < value.len; ++index) {
            trailing_nonzero |= value.ptr[index] != '0';
        }
        if (next > 5u ||
            (next == 5u && (trailing_nonzero || (coefficient & 1u) != 0u))) {
            ++coefficient;
        }
        if (coefficient == 1000u) {
            coefficient = 100u;
            if (effective_digits == SIZE_MAX) {
                return false;
            }
            ++effective_digits;
        }
    }

    const size_t magnitude = (effective_digits - 1u) / 3u;
    static const char suffixes[] = {'\0', 'K', 'M', 'B', 'T'};
    if (magnitude >= FB_ARRAY_LEN(suffixes)) {
        /* The Python oracle raises here because its suffix list ends at T. */
        return false;
    }

    char digits[3];
    const size_t coefficient_digits = digit_count < 3u ? digit_count : 3u;
    unsigned divisor = coefficient_digits == 3u
                           ? 100u
                           : coefficient_digits == 2u ? 10u : 1u;
    for (size_t index = 0u; index < coefficient_digits; ++index) {
        digits[index] = (char)('0' + coefficient / divisor % 10u);
        divisor /= 10u;
    }

    const size_t integer_digits = effective_digits - magnitude * 3u;
    if (integer_digits >= coefficient_digits) {
        if (!fb_buf_append(output,
                           fb_slice_make(digits, coefficient_digits)) ||
            !fb_buf_append_repeat(output, '0',
                                  integer_digits - coefficient_digits)) {
            return false;
        }
    } else {
        size_t fractional_end = coefficient_digits;
        while (fractional_end > integer_digits &&
               digits[fractional_end - 1u] == '0') {
            --fractional_end;
        }
        if (!fb_buf_append(output, fb_slice_make(digits, integer_digits)) ||
            (fractional_end > integer_digits &&
             (!fb_buf_append_char(output, '.') ||
              !fb_buf_append(
                  output,
                  fb_slice_make(digits + integer_digits,
                                fractional_end - integer_digits))))) {
            return false;
        }
    }

    return suffixes[magnitude] == '\0' ||
           fb_buf_append_char(output, suffixes[magnitude]);
}

static fb_slice
fb_reaction_emoji(fb_slice reaction_id)
{
    for (size_t index = 0u; index < FB_ARRAY_LEN(FB_REACTIONS); ++index) {
        if (fb_slice_equal(reaction_id, FB_REACTIONS[index].id)) {
            return FB_REACTIONS[index].emoji;
        }
    }
    return fb_slice_make(NULL, 0u);
}

static bool
fb_append_reaction_value(
    fb_buf *output,
    fb_slice value,
    bool html_escape
)
{
    if (value.len == 0u) {
        return true;
    }
    size_t run = 0u;
    for (size_t index = 0u; index < value.len; ++index) {
        fb_slice replacement = fb_slice_make(NULL, 0u);
        switch ((unsigned char)value.ptr[index]) {
        case ',':
            replacement = FB_SLICE_LIT(".");
            break;
        case '&':
            if (html_escape) {
                replacement = FB_SLICE_LIT("&amp;");
            }
            break;
        case '<':
            if (html_escape) {
                replacement = FB_SLICE_LIT("&lt;");
            }
            break;
        case '>':
            if (html_escape) {
                replacement = FB_SLICE_LIT("&gt;");
            }
            break;
        case '"':
            if (html_escape) {
                replacement = FB_SLICE_LIT("&quot;");
            }
            break;
        case '\'':
            if (html_escape) {
                replacement = FB_SLICE_LIT("&#x27;");
            }
            break;
        default:
            break;
        }
        if (replacement.ptr == NULL) {
            continue;
        }
        if (!fb_append_span(output, value.ptr + run, index - run) ||
            !fb_buf_append(output, replacement)) {
            return false;
        }
        run = index + 1u;
    }
    return fb_append_span(output, value.ptr + run, value.len - run);
}

static bool
fb_format_reactions_internal(
    fb_buf *output,
    fb_slice likes,
    fb_slice comments,
    fb_slice shares,
    const fb_slice *top_reaction_ids,
    size_t top_reaction_count,
    bool html_escape
)
{
    if (output == NULL || !fb_slice_is_valid(likes) ||
        !fb_slice_is_valid(comments) || !fb_slice_is_valid(shares) ||
        (top_reaction_count != 0u && top_reaction_ids == NULL)) {
        return false;
    }
    for (size_t index = 0u; index < top_reaction_count; ++index) {
        if (!fb_slice_is_valid(top_reaction_ids[index])) {
            return false;
        }
    }

    fb_slice emojis[2];
    size_t emoji_count = 0u;
    for (size_t index = 0u;
         index < top_reaction_count && emoji_count < FB_ARRAY_LEN(emojis);
         ++index) {
        const fb_slice emoji = fb_reaction_emoji(top_reaction_ids[index]);
        if (emoji.ptr == NULL ||
            (emoji_count != 0u && fb_slice_equal(emojis[0], emoji))) {
            continue;
        }
        emojis[emoji_count++] = emoji;
    }

    const bool have_likes = !fb_slice_equal(likes, FB_SLICE_LIT("null"));
    const bool have_comments =
        !fb_slice_equal(comments, FB_SLICE_LIT("null"));
    const bool have_shares = !fb_slice_equal(shares, FB_SLICE_LIT("null"));
    bool have_part = false;

    if (have_likes) {
        if (emoji_count >= 2u) {
            if (!fb_buf_append(output, emojis[0]) ||
                !fb_buf_append_char(output, ' ') ||
                !fb_buf_append(output, emojis[1])) {
                return false;
            }
        } else if (!fb_buf_append(output, FB_DEFAULT_REACTION)) {
            return false;
        }
        if (!fb_buf_append_char(output, ' ') ||
            !fb_append_reaction_value(output, likes, html_escape)) {
            return false;
        }
        have_part = true;
    }
    if (have_comments) {
        if ((have_part &&
             !fb_append_literal(output, FB_SLICE_LIT(" \xE2\x80\xA2 "))) ||
            !fb_append_literal(output, FB_SLICE_LIT("\xF0\x9F\x92\xAC ")) ||
            !fb_append_reaction_value(output, comments, html_escape)) {
            return false;
        }
        have_part = true;
    }
    if (have_shares) {
        if ((have_part &&
             !fb_append_literal(output, FB_SLICE_LIT(" \xE2\x80\xA2 "))) ||
            !fb_append_literal(output, FB_SLICE_LIT("\xF0\x9F\x94\x81 ")) ||
            !fb_append_reaction_value(output, shares, html_escape)) {
            return false;
        }
    }
    return true;
}

bool
fb_format_reactions(
    fb_buf *output,
    fb_slice likes,
    fb_slice comments,
    fb_slice shares,
    const fb_slice *top_reaction_ids,
    size_t top_reaction_count
)
{
    return fb_format_reactions_internal(
        output,
        likes,
        comments,
        shares,
        top_reaction_ids,
        top_reaction_count,
        false
    );
}

static bool
fb_estimate_scaled(size_t *total, size_t length, size_t scale)
{
    size_t contribution;
    return fb_size_mul(length, scale, &contribution) &&
           fb_size_add(*total, contribution, total);
}

static bool
fb_estimate_success_capacity(
    const fb_post *post,
    fb_slice description,
    bool video,
    const fb_cancel_token *cancel,
    size_t *capacity
)
{
    size_t total = 1024u;
    if (!fb_estimate_scaled(&total, post->author_name.len, 6u) ||
        !fb_estimate_scaled(&total, description.len, 6u) ||
        !fb_estimate_scaled(&total, post->url.len, 15u) ||
        !fb_estimate_scaled(&total, post->likes.len, 6u) ||
        !fb_estimate_scaled(&total, post->comments.len, 6u) ||
        !fb_estimate_scaled(&total, post->shares.len, 6u)) {
        return false;
    }

    if (video) {
        if (!fb_estimate_scaled(&total, post->video_links.len, 192u)) {
            return false;
        }
        for (size_t index = 0u; index < post->video_links.len; ++index) {
            if ((index & (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
                fb_cancel_requested(cancel)) {
                return false;
            }
            if (!fb_estimate_scaled(&total,
                                    post->video_links.items[index].len,
                                    18u)) {
                return false;
            }
        }
    } else {
        const size_t image_count =
            post->image_links.len < 4u ? post->image_links.len : 4u;
        if (!fb_estimate_scaled(&total, image_count, 80u)) {
            return false;
        }
        for (size_t index = 0u; index < image_count; ++index) {
            if (!fb_estimate_scaled(&total,
                                    post->image_links.items[index].len,
                                    6u)) {
                return false;
            }
        }
    }
    *capacity = total;
    return true;
}

static bool
fb_append_success_prefix(
    fb_buf *output,
    const fb_post *post,
    fb_slice description,
    int utc_offset_hours,
    bool image_counter,
    const fb_cancel_token *cancel,
    size_t *escaped_url_offset,
    size_t *escaped_url_length
)
{
    if (!(
        fb_append_literal(output, FB_SLICE_LIT(
            "<!DOCTYPE html>\n"
            "<html lang=\"\">\n"
            "    <head>\n"
            "        <title>\n"
            "            " FB_CREDIT "\n"
            "        </title>\n"
            "        <meta charset=\"UTF-8\"/>\n"
            "        <meta property=\"og:title\" content=\"")) &&
        fb_append_html_escape_cancelable(
            output, post->author_name, true, cancel) &&
        fb_append_literal(output, FB_SLICE_LIT(
            "\"/>\n"
            "        <meta property=\"og:description\" content=\"")) &&
        fb_append_html_escape_cancelable(
            output, description, true, cancel) &&
        fb_append_literal(output, FB_SLICE_LIT(
            "\"/>\n"
            "        <meta property=\"og:site_name\" content=\""
            FB_CREDIT "\n")) &&
        fb_format_timestamp(output, post->date, utc_offset_hours) &&
        fb_buf_append_char(output, '\n') &&
        fb_format_reactions_internal(
            output,
            post->likes,
            post->comments,
            post->shares,
            post->top_reaction_ids,
            post->top_reaction_count,
            true
        ) &&
        (!image_counter ||
         fb_append_literal(output, FB_SLICE_LIT("\ncontains 4+ images"))) &&
        fb_append_literal(output, FB_SLICE_LIT(
            "\"/>\n"
            "        <meta property=\"og:url\" content=\"")))) {
        return false;
    }
    *escaped_url_offset = output->len;
    if (!fb_append_url_attribute_cancelable(
            output, post->url, cancel)) {
        return false;
    }
    *escaped_url_length = output->len - *escaped_url_offset;
    return fb_append_literal(output, FB_SLICE_LIT("\"/>\n"));
}

static bool
fb_append_success_suffix(
    fb_buf *output,
    size_t escaped_url_offset,
    size_t escaped_url_length,
    bool video
)
{
    return
        fb_append_literal(output, FB_SLICE_LIT(
            "        <link rel=\"canonical\" href=\"")) &&
        fb_append_self_span(output, escaped_url_offset, escaped_url_length) &&
        fb_append_literal(output, FB_SLICE_LIT(
            "\"/>\n"
            "        <meta http-equiv=\"refresh\" content=\"0;url=")) &&
        fb_append_self_span(output, escaped_url_offset, escaped_url_length) &&
        fb_append_literal(
            output,
            video
                ? FB_SLICE_LIT(
                      "\"/>\n"
                      "        <meta name=\"twitter:card\" content=\"player\"/>\n"
                      "        <meta name=\"theme-color\" content=\"#0866ff\"/>\n"
                      "    </head>\n"
                      "</html>")
                : FB_SLICE_LIT(
                      "\"/>\n"
                      "        <meta name=\"twitter:card\" content=\"summary_large_image\"/>\n"
                      "        <meta name=\"theme-color\" content=\"#0866ff\"/>\n"
                      "    </head>\n"
                      "</html>"));
}

#define FB_RENDER_SCRATCH_CAPACITY 8192u
_Static_assert(FB_RENDER_SCRATCH_CAPACITY >= 1024u,
               "render scratch must hold the fixed template");

/* fb_buf_reserve transparently spills this borrowed storage into the arena. */
static bool
fb_buf_init_borrowed(
    fb_buf *output,
    fb_arena *arena,
    char *storage,
    size_t capacity
)
{
    if (output == NULL || arena == NULL || storage == NULL || capacity == 0u) {
        return false;
    }
    memset(output, 0, sizeof(*output));
    output->arena = arena;
    output->data = storage;
    output->capacity = capacity;
    storage[0] = '\0';
    return true;
}

static bool
fb_prepare_render(
    fb_arena *arena,
    const fb_post *post,
    bool video,
    const fb_cancel_token *cancel,
    fb_slice *result,
    fb_buf *output,
    fb_slice *description,
    char *scratch
)
{
    if (result != NULL) {
        *result = fb_slice_make(NULL, 0u);
    }
    size_t capacity;
    if (arena == NULL || result == NULL || output == NULL ||
        description == NULL || scratch == NULL || !fb_post_is_valid(post)) {
        return false;
    }
    if (fb_cancel_requested(cancel)) {
        return false;
    }
    *description = fb_utf8_prefix(post->text, 1024u);
    if (!fb_estimate_success_capacity(
            post, *description, video, cancel, &capacity)) {
        return false;
    }
    (void)capacity;
    return fb_buf_init_borrowed(
        output,
        arena,
        scratch,
        FB_RENDER_SCRATCH_CAPACITY
    );
}

static bool
fb_finish_render(
    fb_arena *arena,
    fb_buf *output,
    const char *scratch,
    const fb_cancel_token *cancel,
    fb_slice *result
)
{
    if (!fb_buf_ok(output) || fb_cancel_requested(cancel)) {
        return false;
    }
    if (output->data != scratch) {
        *result = fb_buf_view(output);
        return true;
    }
    char *persistent = fb_arena_strndup(arena, output->data, output->len);
    if (persistent == NULL || fb_cancel_requested(cancel)) {
        return false;
    }
    *result = fb_slice_make(persistent, output->len);
    return true;
}

static bool
fb_render_video_post_impl(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    const fb_cancel_token *cancel,
    fb_slice *result
)
{
    char scratch[FB_RENDER_SCRATCH_CAPACITY + 1u];
    fb_buf output;
    fb_slice description;
    size_t escaped_url_offset;
    size_t escaped_url_length;
    if (!fb_prepare_render(arena, post, true, cancel, result, &output,
                           &description, scratch) ||
        !fb_append_success_prefix(&output, post, description,
                                  utc_offset_hours, false,
                                  cancel,
                                  &escaped_url_offset,
                                  &escaped_url_length) ||
        !fb_append_literal(&output, FB_SLICE_LIT(
            "        <meta property=\"og:video:type\" content=\"video/mp4\"/>\n"
            "        <meta property=\"twitter:player:stream:content_type\" content=\"video/mp4\"/>\n"))) {
        return false;
    }

    for (size_t index = 0u; index < post->video_links.len; ++index) {
        if ((index & (FB_CANCEL_ITEM_INTERVAL - 1u)) == 0u &&
            fb_cancel_requested(cancel)) {
            return false;
        }
        const fb_slice link = post->video_links.items[index];
        if (!fb_append_literal(&output, FB_SLICE_LIT(
                "        <meta property=\"twitter:player:stream\" content=\""))) {
            return false;
        }
        const size_t escaped_offset = output.len;
        if (!fb_append_html_escape_cancelable(
                &output, link, true, cancel)) {
            return false;
        }
        const size_t escaped_length = output.len - escaped_offset;
        if (
            !fb_append_literal(&output, FB_SLICE_LIT(
                "\"/>\n"
                "        <meta property=\"og:video\" content=\"")) ||
            !fb_append_self_span(&output, escaped_offset, escaped_length) ||
            !fb_append_literal(&output, FB_SLICE_LIT(
                "\"/>\n"
                "        <meta property=\"og:video:secure_url\" content=\"")) ||
            !fb_append_self_span(&output, escaped_offset, escaped_length) ||
            !fb_append_literal(&output, FB_SLICE_LIT("\"/>\n"))) {
            return false;
        }
    }

    if (!fb_append_success_suffix(&output, escaped_url_offset,
                                  escaped_url_length, true)) {
        return false;
    }
    return fb_finish_render(arena, &output, scratch, cancel, result);
}

bool
fb_render_video_post(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    fb_slice *result
)
{
    return fb_render_video_post_impl(
        arena, post, utc_offset_hours, NULL, result);
}

static bool
fb_render_image_post_impl(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    const fb_cancel_token *cancel,
    fb_slice *result
)
{
    char scratch[FB_RENDER_SCRATCH_CAPACITY + 1u];
    fb_buf output;
    fb_slice description;
    size_t escaped_url_offset;
    size_t escaped_url_length;
    if (!fb_prepare_render(arena, post, false, cancel, result, &output,
                           &description, scratch) ||
        !fb_append_success_prefix(&output, post, description,
                                  utc_offset_hours,
                                  post->image_links.len > 4u,
                                  cancel,
                                  &escaped_url_offset,
                                  &escaped_url_length)) {
        return false;
    }

    const size_t image_count =
        post->image_links.len < 4u ? post->image_links.len : 4u;
    for (size_t index = 0u; index < image_count; ++index) {
        if (!fb_append_literal(&output, FB_SLICE_LIT(
                "        <meta property=\"og:image\" content=\"")) ||
            !fb_append_html_escape_cancelable(
                &output,
                post->image_links.items[index],
                true,
                cancel
            ) ||
            !fb_append_literal(&output, FB_SLICE_LIT("\"/>\n"))) {
            return false;
        }
    }

    if (!fb_append_success_suffix(&output, escaped_url_offset,
                                  escaped_url_length, false)) {
        return false;
    }
    return fb_finish_render(arena, &output, scratch, cancel, result);
}

bool
fb_render_image_post(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    fb_slice *result
)
{
    return fb_render_image_post_impl(
        arena, post, utc_offset_hours, NULL, result);
}

fb_render_status
fb_render_post_cancelable(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    const fb_cancel_token *cancel,
    fb_slice *result
)
{
    bool rendered;
    if (fb_cancel_requested(cancel)) {
        if (result != NULL) {
            *result = fb_slice_make(NULL, 0u);
        }
        return FB_RENDER_CANCELLED;
    }
    if (post == NULL) {
        if (result != NULL) {
            *result = fb_slice_make(NULL, 0u);
        }
        return FB_RENDER_ERROR;
    }
    rendered = post->video_links.len != 0u
                   ? fb_render_video_post_impl(
                         arena, post, utc_offset_hours, cancel, result)
                   : fb_render_image_post_impl(
                         arena, post, utc_offset_hours, cancel, result);
    if (fb_cancel_requested(cancel)) {
        if (result != NULL) {
            *result = fb_slice_make(NULL, 0u);
        }
        return FB_RENDER_CANCELLED;
    }
    return rendered ? FB_RENDER_OK : FB_RENDER_ERROR;
}

bool
fb_render_post(
    fb_arena *arena,
    const fb_post *post,
    int utc_offset_hours,
    fb_slice *result
)
{
    return fb_render_post_cancelable(
               arena, post, utc_offset_hours, NULL, result) == FB_RENDER_OK;
}

bool
fb_render_fallback(
    fb_arena *arena,
    fb_slice original_url,
    fb_slice *result
)
{
    if (result != NULL) {
        *result = fb_slice_make(NULL, 0u);
    }
    size_t capacity = 512u;
    fb_buf output;
    if (arena == NULL || result == NULL || !fb_slice_is_valid(original_url) ||
        !fb_estimate_scaled(&capacity, original_url.len, 5u) ||
        !fb_buf_init(&output, arena, capacity) ||
        !fb_append_literal(&output, FB_SLICE_LIT(
            "<!DOCTYPE html>\n"
            "<html lang=\"\">\n"
            "    <head>\n"
            "        <meta charset=\"UTF-8\" />\n"
            "        <meta name=\"theme-color\" content=\"#2c3048f\" />\n"
            "        <meta property=\"og:title\" content=\"Log in or sign up to view\"/>\n"
            "        <meta property=\"og:description\" content=\"See posts, photos and more on Facebook.\"/>\n"
            "        <meta http-equiv=\"refresh\" content=\"0;url=")) ||
        !fb_append_facebed_url_attribute(&output, original_url) ||
        !fb_append_literal(&output, FB_SLICE_LIT(
            "\"/>\n"
            "    </head>\n"
            "</html>"))) {
        return false;
    }
    *result = fb_buf_view(&output);
    return true;
}

static bool
fb_append_json_hex_escape(fb_buf *output, uint16_t value)
{
    static const char hex[] = "0123456789abcdef";
    char escaped[6] = {
        '\\', 'u',
        hex[(value >> 12u) & 0xFu],
        hex[(value >> 8u) & 0xFu],
        hex[(value >> 4u) & 0xFu],
        hex[value & 0xFu],
    };
    return fb_buf_append(output, fb_slice_make(escaped, sizeof(escaped)));
}

static bool
fb_append_json_string(fb_buf *output, fb_slice value)
{
    if (!fb_buf_append_char(output, '"')) {
        return false;
    }
    size_t offset = 0u;
    while (offset < value.len) {
        size_t safe_end = offset;
        while (safe_end < value.len) {
            const unsigned char byte =
                (unsigned char)value.ptr[safe_end];
            if (byte < 0x20u || byte > 0x7Eu || byte == '"' ||
                byte == '\\' || byte == '<' || byte == '>' || byte == '&') {
                break;
            }
            ++safe_end;
        }
        if (safe_end != offset) {
            if (!fb_append_span(output, value.ptr + offset,
                                safe_end - offset)) {
                return false;
            }
            offset = safe_end;
            if (offset == value.len) {
                break;
            }
        }
        uint32_t codepoint;
        const size_t width = fb_utf8_decode_one(
            (const unsigned char *)value.ptr + offset,
            value.len - offset,
            &codepoint
        );
        offset += width;

        if (codepoint == '"') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\\""))) {
                return false;
            }
        } else if (codepoint == '\\') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\\\"))) {
                return false;
            }
        } else if (codepoint == '\b') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\b"))) {
                return false;
            }
        } else if (codepoint == '\f') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\f"))) {
                return false;
            }
        } else if (codepoint == '\n') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\n"))) {
                return false;
            }
        } else if (codepoint == '\r') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\r"))) {
                return false;
            }
        } else if (codepoint == '\t') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\t"))) {
                return false;
            }
        } else if (codepoint == '<') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\u003c"))) {
                return false;
            }
        } else if (codepoint == '>') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\u003e"))) {
                return false;
            }
        } else if (codepoint == '&') {
            if (!fb_append_literal(output, FB_SLICE_LIT("\\u0026"))) {
                return false;
            }
        } else if (codepoint >= 0x20u && codepoint <= 0x7Eu) {
            if (!fb_buf_append_char(output, (char)codepoint)) {
                return false;
            }
        } else if (codepoint <= 0xFFFFu) {
            if (!fb_append_json_hex_escape(output, (uint16_t)codepoint)) {
                return false;
            }
        } else {
            const uint32_t scalar = codepoint - 0x10000u;
            const uint16_t high =
                (uint16_t)(0xD800u + (scalar >> 10u));
            const uint16_t low =
                (uint16_t)(0xDC00u + (scalar & 0x3FFu));
            if (!fb_append_json_hex_escape(output, high) ||
                !fb_append_json_hex_escape(output, low)) {
                return false;
            }
        }
    }
    return fb_buf_append_char(output, '"');
}

bool
fb_render_browser_redirect(
    fb_arena *arena,
    fb_slice url,
    fb_slice *result
)
{
    if (result != NULL) {
        *result = fb_slice_make(NULL, 0u);
    }
    size_t capacity = 512u;
    fb_buf output;
    if (arena == NULL || result == NULL || !fb_slice_is_valid(url) ||
        !fb_estimate_scaled(&capacity, url.len, 11u) ||
        !fb_buf_init(&output, arena, capacity) ||
        !fb_append_literal(&output, FB_SLICE_LIT(
            "<!DOCTYPE HTML>\n"
            "<html lang=\"en-US\">\n"
            "    <head>\n"
            "        <meta charset=\"UTF-8\">\n"
            "        <meta http-equiv=\"refresh\" content=\"0; url=")) ||
        !fb_append_facebed_url_attribute(&output, url) ||
        !fb_append_literal(&output, FB_SLICE_LIT(
            "\">\n"
            "        <script type=\"text/javascript\">\n"
            "            window.location.href = ")) ||
        !fb_append_json_string(&output, url) ||
        !fb_append_literal(&output, FB_SLICE_LIT(
            "\n"
            "        </script>\n"
            "        <title>\n"
            "            redirecting...\n"
            "        </title>\n"
            "    </head>\n"
            "    <body></body>\n"
            "</html>"))) {
        return false;
    }
    *result = fb_buf_view(&output);
    return true;
}
