#include "fastbed/config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

typedef struct {
    const char *ptr;
    size_t len;
    uint64_t hash;
} fb_banned_user;

typedef enum {
    FB_SCALAR_IMPLICIT = 0,
    FB_SCALAR_STRING,
    FB_SCALAR_INTEGER,
    FB_SCALAR_OTHER
} fb_scalar_kind;

typedef struct {
    size_t source_index;
    fb_scalar_kind kind;
} fb_explicit_scalar;

typedef struct {
    fb_explicit_scalar *items;
    size_t len;
    size_t capacity;
} fb_yaml_resolution;

struct fb_config {
    char *host;
    size_t host_len;
    int port;
    int timezone;
    fb_banned_user *banned_users;
    size_t banned_user_count;
    char *banned_storage;
    char *notifier_webhook;
    size_t notifier_webhook_len;
};

static const char DEFAULT_HOST[] = "0.0.0.0";
static const char DEFAULT_WEBHOOK[] = "";

static fb_slice
config_slice(const char *ptr, size_t len)
{
    fb_slice value;
    value.ptr = ptr;
    value.len = len;
    return value;
}

static void
clear_error(fb_config_error *error)
{
    if (error != NULL) {
        error->status = FB_CONFIG_OK;
        error->line = 0;
        error->column = 0;
        error->message = "ok";
    }
}

static fb_config_status
set_error(
    fb_config_error *error,
    fb_config_status status,
    const char *message,
    const yaml_node_t *node
)
{
    if (error != NULL) {
        error->status = status;
        error->message = message;
        if (node != NULL) {
            error->line = node->start_mark.line + 1;
            error->column = node->start_mark.column + 1;
        } else {
            error->line = 0;
            error->column = 0;
        }
    }
    return status;
}

static fb_config_status
scan_yaml_resolution(
    FILE *file,
    fb_yaml_resolution *resolution,
    fb_config_error *error
)
{
    yaml_parser_t parser;
    yaml_event_t event;
    bool parser_ready = false;
    bool event_ready = false;
    fb_config_status status = FB_CONFIG_OK;

    memset(resolution, 0, sizeof(*resolution));
    if (!yaml_parser_initialize(&parser)) {
        return set_error(error, FB_CONFIG_NO_MEMORY, "out of memory", NULL);
    }
    parser_ready = true;
    yaml_parser_set_input_file(&parser, file);
    for (;;) {
        fb_scalar_kind kind;
        if (!yaml_parser_parse(&parser, &event)) {
            if (error != NULL) {
                error->status = FB_CONFIG_YAML_ERROR;
                error->message = "invalid YAML configuration";
                error->line = parser.problem_mark.line + 1;
                error->column = parser.problem_mark.column + 1;
            }
            status = FB_CONFIG_YAML_ERROR;
            break;
        }
        event_ready = true;
        if (event.type == YAML_SCALAR_EVENT &&
            !event.data.scalar.plain_implicit &&
            !event.data.scalar.quoted_implicit) {
            if (event.data.scalar.tag != NULL &&
                strcmp((const char *)event.data.scalar.tag, YAML_STR_TAG) == 0) {
                kind = FB_SCALAR_STRING;
            } else if (event.data.scalar.tag != NULL &&
                       strcmp((const char *)event.data.scalar.tag, YAML_INT_TAG) == 0) {
                kind = FB_SCALAR_INTEGER;
            } else {
                kind = FB_SCALAR_OTHER;
            }
            if (resolution->len == resolution->capacity) {
                size_t new_capacity = resolution->capacity == 0
                    ? 8 : resolution->capacity * 2;
                fb_explicit_scalar *items;
                if (new_capacity < resolution->capacity ||
                    new_capacity > SIZE_MAX / sizeof(*items)) {
                    status = set_error(error, FB_CONFIG_NO_MEMORY,
                                       "configuration is too large", NULL);
                    break;
                }
                items = realloc(resolution->items,
                                new_capacity * sizeof(*items));
                if (items == NULL) {
                    status = set_error(error, FB_CONFIG_NO_MEMORY,
                                       "out of memory", NULL);
                    break;
                }
                resolution->items = items;
                resolution->capacity = new_capacity;
            }
            resolution->items[resolution->len].source_index = event.start_mark.index;
            resolution->items[resolution->len].kind = kind;
            ++resolution->len;
        }
        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            event_ready = false;
            break;
        }
        yaml_event_delete(&event);
        event_ready = false;
    }
    if (event_ready) {
        yaml_event_delete(&event);
    }
    if (parser_ready) {
        yaml_parser_delete(&parser);
    }
    if (status != FB_CONFIG_OK) {
        free(resolution->items);
        memset(resolution, 0, sizeof(*resolution));
        return status;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        free(resolution->items);
        memset(resolution, 0, sizeof(*resolution));
        return set_error(error, FB_CONFIG_FILE_ERROR,
                         "cannot reread configuration file", NULL);
    }
    clearerr(file);
    return FB_CONFIG_OK;
}

static char *
copy_bytes(const unsigned char *value, size_t len)
{
    char *copy;

    if (len == SIZE_MAX) {
        return NULL;
    }
    copy = malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }
    if (len != 0) {
        memcpy(copy, value, len);
    }
    copy[len] = '\0';
    return copy;
}

static uint64_t
hash_bytes(const char *value, size_t len)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t index;

    for (index = 0; index < len; ++index) {
        hash ^= (unsigned char)value[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static bool
yaml_tag_is(const yaml_node_t *node, const char *tag)
{
    return node != NULL && node->tag != NULL &&
           strcmp((const char *)node->tag, tag) == 0;
}

static bool
bytes_equal(const unsigned char *value, size_t len, const char *literal)
{
    const size_t literal_len = strlen(literal);
    return len == literal_len &&
           (len == 0 || memcmp(value, literal, len) == 0);
}

static fb_scalar_kind
explicit_scalar_kind(const fb_yaml_resolution *resolution, const yaml_node_t *node)
{
    size_t index;
    if (resolution == NULL || node == NULL) {
        return FB_SCALAR_IMPLICIT;
    }
    for (index = 0; index < resolution->len; ++index) {
        if (resolution->items[index].source_index == node->start_mark.index) {
            return resolution->items[index].kind;
        }
    }
    return FB_SCALAR_IMPLICIT;
}

static bool
ascii_case_equal(const unsigned char *value, size_t len, const char *literal)
{
    size_t index;
    if (len != strlen(literal)) {
        return false;
    }
    for (index = 0; index < len; ++index) {
        unsigned char left = value[index];
        unsigned char right = (unsigned char)literal[index];
        if (left >= 'A' && left <= 'Z') {
            left = (unsigned char)(left + ('a' - 'A'));
        }
        if (right >= 'A' && right <= 'Z') {
            right = (unsigned char)(right + ('a' - 'A'));
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

static bool
plain_yaml_integer(const unsigned char *value, size_t len)
{
    size_t cursor = 0;
    size_t index;

    if (len == 0) {
        return false;
    }
    if (value[cursor] == '+' || value[cursor] == '-') {
        if (++cursor == len) {
            return false;
        }
    }
    if (value[cursor] == '0') {
        if (cursor + 1 == len) {
            return true;
        }
        if (value[cursor + 1] == 'b') {
            if (cursor + 2 == len) {
                return false;
            }
            for (index = cursor + 2; index < len; ++index) {
                if (value[index] != '0' && value[index] != '1' &&
                    value[index] != '_') {
                    return false;
                }
            }
            return true;
        }
        if (value[cursor + 1] == 'x') {
            if (cursor + 2 == len) {
                return false;
            }
            for (index = cursor + 2; index < len; ++index) {
                const unsigned char byte = value[index];
                if (!((byte >= '0' && byte <= '9') ||
                      (byte >= 'a' && byte <= 'f') ||
                      (byte >= 'A' && byte <= 'F') || byte == '_')) {
                    return false;
                }
            }
            return true;
        }
        for (index = cursor + 1; index < len; ++index) {
            if (!((value[index] >= '0' && value[index] <= '7') ||
                  value[index] == '_')) {
                return false;
            }
        }
        return true;
    }
    if (value[cursor] < '1' || value[cursor] > '9') {
        return false;
    }
    for (index = cursor + 1; index < len && value[index] != ':'; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              value[index] == '_')) {
            return false;
        }
    }
    if (index == len) {
        return true;
    }
    while (index < len) {
        size_t digits = 0;
        unsigned group = 0;
        if (value[index++] != ':') {
            return false;
        }
        while (index < len && value[index] != ':') {
            if (value[index] < '0' || value[index] > '9' || digits == 2) {
                return false;
            }
            group = group * 10u + (unsigned)(value[index] - '0');
            ++digits;
            ++index;
        }
        if (digits == 0 || group > 59) {
            return false;
        }
    }
    return true;
}

static bool
plain_yaml_float(const unsigned char *value, size_t len)
{
    size_t cursor = 0;
    bool saw_digit = false;
    bool saw_colon = false;

    if (len == 0) {
        return false;
    }
    if (value[cursor] == '+' || value[cursor] == '-') {
        if (++cursor == len) {
            return false;
        }
    }
    if (ascii_case_equal(value + cursor, len - cursor, ".inf")) {
        return true;
    }
    if (cursor == 0 && ascii_case_equal(value, len, ".nan")) {
        return true;
    }
    while (cursor < len &&
           ((value[cursor] >= '0' && value[cursor] <= '9') ||
            value[cursor] == '_' || value[cursor] == ':')) {
        saw_digit = saw_digit || (value[cursor] >= '0' && value[cursor] <= '9');
        saw_colon = saw_colon || value[cursor] == ':';
        ++cursor;
    }
    if (cursor >= len || value[cursor] != '.') {
        return false;
    }
    ++cursor;
    while (cursor < len &&
           ((value[cursor] >= '0' && value[cursor] <= '9') ||
            value[cursor] == '_')) {
        saw_digit = saw_digit || (value[cursor] >= '0' && value[cursor] <= '9');
        ++cursor;
    }
    if (!saw_digit || (saw_colon && cursor == 1)) {
        return false;
    }
    if (cursor < len && (value[cursor] == 'e' || value[cursor] == 'E')) {
        ++cursor;
        if (cursor == len || (value[cursor] != '+' && value[cursor] != '-')) {
            return false;
        }
        ++cursor;
        if (cursor == len) {
            return false;
        }
        while (cursor < len && value[cursor] >= '0' && value[cursor] <= '9') {
            ++cursor;
        }
    }
    return cursor == len;
}

static bool
plain_yaml_timestamp(const unsigned char *value, size_t len)
{
    size_t index;
    if (len < 10 || value[4] != '-') {
        return false;
    }
    for (index = 0; index < 4; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    /* PyYAML's timestamp alternatives both require another date dash. */
    for (index = 5; index < len && index < 9; ++index) {
        if (value[index] == '-') {
            return true;
        }
        if (value[index] != ' ' && (value[index] < '0' || value[index] > '9')) {
            return false;
        }
    }
    return false;
}

static fb_scalar_kind
implicit_scalar_kind(const yaml_node_t *node)
{
    const unsigned char *value = node->data.scalar.value;
    const size_t len = node->data.scalar.length;

    if (plain_yaml_integer(value, len)) {
        return FB_SCALAR_INTEGER;
    }
    if (len == 0 || bytes_equal(value, len, "~") ||
        ascii_case_equal(value, len, "null") ||
        ascii_case_equal(value, len, "yes") ||
        ascii_case_equal(value, len, "no") ||
        ascii_case_equal(value, len, "true") ||
        ascii_case_equal(value, len, "false") ||
        ascii_case_equal(value, len, "on") ||
        ascii_case_equal(value, len, "off") ||
        bytes_equal(value, len, "<<") || bytes_equal(value, len, "=") ||
        plain_yaml_float(value, len) || plain_yaml_timestamp(value, len)) {
        return FB_SCALAR_OTHER;
    }
    return FB_SCALAR_STRING;
}

static bool
yaml_string(const fb_yaml_resolution *resolution, const yaml_node_t *node)
{
    const fb_scalar_kind explicit_kind = explicit_scalar_kind(resolution, node);
    if (node == NULL || node->type != YAML_SCALAR_NODE) {
        return false;
    }
    if (explicit_kind != FB_SCALAR_IMPLICIT) {
        return explicit_kind == FB_SCALAR_STRING;
    }
    if (!yaml_tag_is(node, YAML_STR_TAG)) {
        return false;
    }
    if (node->data.scalar.style != YAML_PLAIN_SCALAR_STYLE) {
        return true;
    }
    return implicit_scalar_kind(node) == FB_SCALAR_STRING;
}

static bool
yaml_integer(const fb_yaml_resolution *resolution, const yaml_node_t *node)
{
    const fb_scalar_kind explicit_kind = explicit_scalar_kind(resolution, node);
    if (node == NULL || node->type != YAML_SCALAR_NODE) {
        return false;
    }
    if (explicit_kind != FB_SCALAR_IMPLICIT) {
        return explicit_kind == FB_SCALAR_INTEGER;
    }
    if (yaml_tag_is(node, YAML_INT_TAG)) {
        return true;
    }
    return yaml_tag_is(node, YAML_STR_TAG) &&
           node->data.scalar.style == YAML_PLAIN_SCALAR_STYLE &&
           implicit_scalar_kind(node) == FB_SCALAR_INTEGER;
}

static bool
scalar_equal(
    const fb_yaml_resolution *resolution,
    const yaml_node_t *node,
    const char *value
)
{
    const size_t len = strlen(value);
    return yaml_string(resolution, node) && node->data.scalar.length == len &&
           (len == 0 || memcmp(node->data.scalar.value, value, len) == 0);
}

static int
digit_for_base(unsigned char value, unsigned base)
{
    unsigned digit;

    if (value >= '0' && value <= '9') {
        digit = (unsigned)(value - '0');
    } else if (value >= 'a' && value <= 'f') {
        digit = (unsigned)(value - 'a') + 10;
    } else if (value >= 'A' && value <= 'F') {
        digit = (unsigned)(value - 'A') + 10;
    } else {
        return -1;
    }
    return digit < base ? (int)digit : -1;
}

static bool
accumulate_digit(uint64_t *value, unsigned base, unsigned digit, uint64_t limit)
{
    if (*value > (limit - digit) / base) {
        return false;
    }
    *value = *value * base + digit;
    return true;
}

static bool
parse_yaml_integer(
    const fb_yaml_resolution *resolution,
    const yaml_node_t *node,
    int64_t *out
)
{
    char compact[128];
    size_t compact_len = 0;
    size_t index;
    size_t cursor = 0;
    bool negative = false;
    uint64_t magnitude = 0;
    uint64_t limit;
    bool has_colon = false;

    if (!yaml_integer(resolution, node) || node->data.scalar.length == 0 ||
        node->data.scalar.length >= sizeof(compact)) {
        return false;
    }
    for (index = 0; index < node->data.scalar.length; ++index) {
        const unsigned char byte = node->data.scalar.value[index];
        if (byte != '_') {
            compact[compact_len++] = (char)byte;
            has_colon = has_colon || byte == ':';
        }
    }
    if (compact_len == 0) {
        return false;
    }
    if (compact[cursor] == '+' || compact[cursor] == '-') {
        negative = compact[cursor] == '-';
        if (++cursor == compact_len) {
            return false;
        }
    }
    limit = negative ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;

    if (has_colon) {
        bool first_group = true;
        while (cursor < compact_len) {
            unsigned group = 0;
            size_t digits = 0;
            while (cursor < compact_len && compact[cursor] != ':') {
                if (compact[cursor] < '0' || compact[cursor] > '9') {
                    return false;
                }
                if (group > (UINT_MAX - (unsigned)(compact[cursor] - '0')) / 10u) {
                    return false;
                }
                group = group * 10u + (unsigned)(compact[cursor] - '0');
                ++cursor;
                ++digits;
            }
            if (digits == 0 || (!first_group && (digits > 2 || group > 59)) ||
                !accumulate_digit(&magnitude, 60, group, limit)) {
                return false;
            }
            first_group = false;
            if (cursor < compact_len) {
                ++cursor;
                if (cursor == compact_len) {
                    return false;
                }
            }
        }
    } else {
        unsigned base = 10;
        bool any = false;

        if (cursor + 2 <= compact_len && compact[cursor] == '0') {
            if (cursor + 1 < compact_len &&
                (compact[cursor + 1] == 'x' || compact[cursor + 1] == 'X')) {
                base = 16;
                cursor += 2;
            } else if (cursor + 1 < compact_len &&
                       (compact[cursor + 1] == 'b' || compact[cursor + 1] == 'B')) {
                base = 2;
                cursor += 2;
            } else if (cursor + 1 < compact_len) {
                base = 8;
                ++cursor;
                any = true;
            }
        }
        while (cursor < compact_len) {
            const int digit = digit_for_base((unsigned char)compact[cursor++], base);
            if (digit < 0 ||
                !accumulate_digit(&magnitude, base, (unsigned)digit, limit)) {
                return false;
            }
            any = true;
        }
        if (!any) {
            return false;
        }
    }

    if (negative) {
        *out = magnitude == (uint64_t)INT64_MAX + 1u
            ? INT64_MIN : -(int64_t)magnitude;
    } else {
        *out = (int64_t)magnitude;
    }
    return true;
}

static fb_config_status
allocate_config(
    const yaml_node_t *host_node,
    const yaml_node_t *port_node,
    const yaml_node_t *timezone_node,
    const yaml_node_t *banned_node,
    const yaml_node_t *webhook_node,
    const yaml_document_t *document,
    const fb_yaml_resolution *resolution,
    fb_config **out,
    fb_config_error *error
)
{
    const unsigned char *host_value = (const unsigned char *)DEFAULT_HOST;
    size_t host_len = sizeof(DEFAULT_HOST) - 1;
    const unsigned char *webhook_value = (const unsigned char *)DEFAULT_WEBHOOK;
    size_t webhook_len = 0;
    int64_t port = 9812;
    int64_t timezone = 7;
    size_t banned_count = 0;
    size_t banned_bytes = 0;
    yaml_node_item_t *item;
    fb_config *config;
    size_t target = 0;
    char *storage_cursor;

    if (host_node != NULL) {
        if (!yaml_string(resolution, host_node)) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "host must be a string", host_node);
        }
        host_value = host_node->data.scalar.value;
        host_len = host_node->data.scalar.length;
    }
    if (port_node != NULL) {
        if (!parse_yaml_integer(resolution, port_node, &port)) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "port must be an integer", port_node);
        }
        if (port < 1 || port > 65535) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "port must be between 1 and 65535", port_node);
        }
    }
    if (timezone_node != NULL) {
        if (!parse_yaml_integer(resolution, timezone_node, &timezone)) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "timezone must be an integer", timezone_node);
        }
        if (timezone < -12 || timezone > 14) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "timezone must be between -12 and 14", timezone_node);
        }
    }
    if (banned_node != NULL) {
        if (banned_node->type != YAML_SEQUENCE_NODE ||
            !yaml_tag_is(banned_node, YAML_SEQ_TAG)) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "banned_users must be a sequence", banned_node);
        }
        for (item = banned_node->data.sequence.items.start;
             item < banned_node->data.sequence.items.top; ++item) {
            const yaml_node_t *node = yaml_document_get_node(
                (yaml_document_t *)document, *item
            );
            if (!yaml_string(resolution, node)) {
                continue;
            }
            if (node->data.scalar.length > SIZE_MAX - banned_bytes - 1) {
                return set_error(error, FB_CONFIG_NO_MEMORY,
                                 "configuration is too large", node);
            }
            banned_bytes += node->data.scalar.length + 1;
            ++banned_count;
        }
    }
    if (webhook_node != NULL) {
        if (!yaml_string(resolution, webhook_node)) {
            return set_error(error, FB_CONFIG_SCHEMA_ERROR,
                             "notifier_webhook must be a string", webhook_node);
        }
        webhook_value = webhook_node->data.scalar.value;
        webhook_len = webhook_node->data.scalar.length;
    }

    config = calloc(1, sizeof(*config));
    if (config == NULL) {
        return set_error(error, FB_CONFIG_NO_MEMORY, "out of memory", NULL);
    }
    config->host = copy_bytes(host_value, host_len);
    config->notifier_webhook = copy_bytes(webhook_value, webhook_len);
    if (config->host == NULL || config->notifier_webhook == NULL) {
        fb_config_destroy(config);
        return set_error(error, FB_CONFIG_NO_MEMORY, "out of memory", NULL);
    }
    config->host_len = host_len;
    config->notifier_webhook_len = webhook_len;
    config->port = (int)port;
    config->timezone = (int)timezone;

    if (banned_count != 0) {
        config->banned_users = calloc(banned_count, sizeof(*config->banned_users));
        config->banned_storage = malloc(banned_bytes);
        if (config->banned_users == NULL || config->banned_storage == NULL) {
            fb_config_destroy(config);
            return set_error(error, FB_CONFIG_NO_MEMORY, "out of memory", NULL);
        }
        storage_cursor = config->banned_storage;
        for (item = banned_node->data.sequence.items.start;
             item < banned_node->data.sequence.items.top; ++item) {
            const yaml_node_t *node = yaml_document_get_node(
                (yaml_document_t *)document, *item
            );
            fb_banned_user *entry;
            if (!yaml_string(resolution, node)) {
                continue;
            }
            entry = &config->banned_users[target++];
            entry->ptr = storage_cursor;
            entry->len = node->data.scalar.length;
            if (entry->len != 0) {
                memcpy(storage_cursor, node->data.scalar.value, entry->len);
            }
            storage_cursor[entry->len] = '\0';
            entry->hash = hash_bytes(entry->ptr, entry->len);
            storage_cursor += entry->len + 1;
        }
        config->banned_user_count = target;
    }
    *out = config;
    clear_error(error);
    return FB_CONFIG_OK;
}

fb_config_status
fb_config_create_default(fb_config **out, fb_config_error *error)
{
    if (out == NULL) {
        return set_error(error, FB_CONFIG_INVALID_ARGUMENT,
                         "invalid configuration destination", NULL);
    }
    *out = NULL;
    return allocate_config(NULL, NULL, NULL, NULL, NULL, NULL, NULL, out, error);
}

fb_config_status
fb_config_load_file(const char *path, fb_config **out, fb_config_error *error)
{
    FILE *file;
    fb_yaml_resolution resolution = {0};
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_document_t trailing_document;
    yaml_node_t *root;
    yaml_node_t *host_node = NULL;
    yaml_node_t *port_node = NULL;
    yaml_node_t *timezone_node = NULL;
    yaml_node_t *banned_node = NULL;
    yaml_node_t *webhook_node = NULL;
    yaml_node_pair_t *pair;
    fb_config_status status;
    bool parser_ready = false;
    bool document_ready = false;
    bool trailing_ready = false;

    if (path == NULL || out == NULL) {
        return set_error(error, FB_CONFIG_INVALID_ARGUMENT,
                         "invalid configuration argument", NULL);
    }
    *out = NULL;
    clear_error(error);
    file = fopen(path, "rb");
    if (file == NULL) {
        return set_error(error, FB_CONFIG_FILE_ERROR,
                         "cannot open configuration file", NULL);
    }
    status = scan_yaml_resolution(file, &resolution, error);
    if (status != FB_CONFIG_OK) {
        fclose(file);
        return status;
    }
    if (!yaml_parser_initialize(&parser)) {
        free(resolution.items);
        fclose(file);
        return set_error(error, FB_CONFIG_NO_MEMORY, "out of memory", NULL);
    }
    parser_ready = true;
    yaml_parser_set_input_file(&parser, file);
    if (!yaml_parser_load(&parser, &document)) {
        status = set_error(error, FB_CONFIG_YAML_ERROR,
                           "invalid YAML configuration", NULL);
        goto done;
    }
    document_ready = true;
    if (!yaml_parser_load(&parser, &trailing_document)) {
        status = set_error(error, FB_CONFIG_YAML_ERROR,
                           "invalid YAML configuration", NULL);
        goto done;
    }
    trailing_ready = true;
    if (yaml_document_get_root_node(&trailing_document) != NULL) {
        status = set_error(error, FB_CONFIG_SCHEMA_ERROR,
                           "configuration must contain one document", NULL);
        goto done;
    }

    root = yaml_document_get_root_node(&document);
    if (root == NULL || root->type != YAML_MAPPING_NODE ||
        !yaml_tag_is(root, YAML_MAP_TAG)) {
        status = set_error(error, FB_CONFIG_SCHEMA_ERROR,
                           "configuration root must be a mapping", root);
        goto done;
    }
    for (pair = root->data.mapping.pairs.start;
         pair < root->data.mapping.pairs.top; ++pair) {
        yaml_node_t *key = yaml_document_get_node(&document, pair->key);
        yaml_node_t *value = yaml_document_get_node(&document, pair->value);

        if (scalar_equal(&resolution, key, "host")) {
            host_node = value;
        } else if (scalar_equal(&resolution, key, "port")) {
            port_node = value;
        } else if (scalar_equal(&resolution, key, "timezone")) {
            timezone_node = value;
        } else if (scalar_equal(&resolution, key, "banned_users")) {
            banned_node = value;
        } else if (scalar_equal(&resolution, key, "notifier_webhook")) {
            webhook_node = value;
        } else {
            status = set_error(error, FB_CONFIG_SCHEMA_ERROR,
                               "unknown configuration entry", key);
            goto done;
        }
    }
    status = allocate_config(host_node, port_node, timezone_node, banned_node,
                             webhook_node, &document, &resolution, out, error);

done:
    if (trailing_ready) {
        yaml_document_delete(&trailing_document);
    }
    if (document_ready) {
        yaml_document_delete(&document);
    }
    if (parser_ready) {
        yaml_parser_delete(&parser);
    }
    free(resolution.items);
    fclose(file);
    return status;
}

void
fb_config_destroy(fb_config *config)
{
    if (config == NULL) {
        return;
    }
    if (config->notifier_webhook != NULL && config->notifier_webhook_len != 0) {
        volatile unsigned char *secret =
            (volatile unsigned char *)config->notifier_webhook;
        size_t index;
        for (index = 0; index < config->notifier_webhook_len; ++index) {
            secret[index] = 0;
        }
    }
    free(config->host);
    free(config->banned_users);
    free(config->banned_storage);
    free(config->notifier_webhook);
    free(config);
}

fb_slice
fb_config_host(const fb_config *config)
{
    return config == NULL
        ? config_slice(NULL, 0) : config_slice(config->host, config->host_len);
}

int
fb_config_port(const fb_config *config)
{
    return config == NULL ? 0 : config->port;
}

int
fb_config_timezone(const fb_config *config)
{
    return config == NULL ? 0 : config->timezone;
}

size_t
fb_config_banned_user_count(const fb_config *config)
{
    return config == NULL ? 0 : config->banned_user_count;
}

fb_slice
fb_config_banned_user_at(const fb_config *config, size_t index)
{
    if (config == NULL || index >= config->banned_user_count) {
        return config_slice(NULL, 0);
    }
    return config_slice(config->banned_users[index].ptr,
                        config->banned_users[index].len);
}

bool
fb_config_is_banned_user(const fb_config *config, fb_slice user_id)
{
    const uint64_t hash = hash_bytes(user_id.ptr != NULL ? user_id.ptr : "",
                                     user_id.ptr != NULL ? user_id.len : 0);
    size_t index;

    if (config == NULL || (user_id.ptr == NULL && user_id.len != 0)) {
        return false;
    }
    for (index = 0; index < config->banned_user_count; ++index) {
        const fb_banned_user *candidate = &config->banned_users[index];
        if (candidate->hash == hash && candidate->len == user_id.len &&
            (user_id.len == 0 ||
             memcmp(candidate->ptr, user_id.ptr, user_id.len) == 0)) {
            return true;
        }
    }
    return false;
}

fb_slice
fb_config_notifier_webhook(const fb_config *config)
{
    return config == NULL
        ? config_slice(NULL, 0)
        : config_slice(config->notifier_webhook, config->notifier_webhook_len);
}

const char *
fb_config_status_string(fb_config_status status)
{
    switch (status) {
    case FB_CONFIG_OK:
        return "ok";
    case FB_CONFIG_INVALID_ARGUMENT:
        return "invalid argument";
    case FB_CONFIG_FILE_ERROR:
        return "configuration file error";
    case FB_CONFIG_YAML_ERROR:
        return "invalid YAML";
    case FB_CONFIG_SCHEMA_ERROR:
        return "invalid configuration schema";
    case FB_CONFIG_NO_MEMORY:
        return "out of memory";
    }
    return "unknown configuration error";
}
