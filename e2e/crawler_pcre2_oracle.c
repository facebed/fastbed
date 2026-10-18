#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pcre2.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yyjson.h"

enum {
    ORACLE_MAX_DATABASE_BYTES = 16 * 1024 * 1024,
    ORACLE_MAX_PATTERNS = 100000,
    ORACLE_MAX_CASE_LINE_BYTES = 2 * 1024 * 1024,
    ORACLE_MAX_CASES = 1000000,
    ORACLE_MATCH_LIMIT = 100000,
    ORACLE_DEPTH_LIMIT = 1000,
    ORACLE_HEAP_LIMIT_KIB = 256,
};

typedef struct {
    pcre2_code *code;
} oracle_pattern;

typedef struct {
    oracle_pattern *patterns;
    size_t len;
    char *json_bytes;
    yyjson_doc *json_document;
} oracle_database;

static unsigned char ascii_lower(unsigned char value) {
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
        return (unsigned char)(value + ((unsigned char)'a' - (unsigned char)'A'));
    }
    return value;
}

static void database_destroy(oracle_database *database) {
    size_t index;
    if (database == NULL) {
        return;
    }
    for (index = 0; index < database->len; ++index) {
        pcre2_code_free(database->patterns[index].code);
    }
    free(database->patterns);
    yyjson_doc_free(database->json_document);
    free(database->json_bytes);
    memset(database, 0, sizeof(*database));
}

static bool read_file(const char *path, char **bytes, size_t *length) {
    FILE *stream;
    long measured;
    size_t size;
    size_t bytes_read;
    int close_status;
    char *result;
    stream = fopen(path, "rb");
    if (stream == NULL) {
        (void)fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return false;
    }
    if (fseek(stream, 0, SEEK_END) != 0 ||
        (measured = ftell(stream)) < 0 ||
        fseek(stream, 0, SEEK_SET) != 0) {
        (void)fprintf(stderr, "cannot size %s\n", path);
        (void)fclose(stream);
        return false;
    }
    if ((unsigned long)measured > ORACLE_MAX_DATABASE_BYTES) {
        (void)fprintf(stderr, "database exceeds oracle size bound\n");
        (void)fclose(stream);
        return false;
    }
    size = (size_t)measured;
    result = malloc(size + YYJSON_PADDING_SIZE);
    if (result == NULL) {
        (void)fprintf(stderr, "cannot allocate database buffer\n");
        (void)fclose(stream);
        return false;
    }
    bytes_read = fread(result, 1, size, stream);
    close_status = fclose(stream);
    if (bytes_read != size || close_status != 0) {
        (void)fprintf(stderr, "cannot read %s\n", path);
        free(result);
        return false;
    }
    memset(result + size, 0, YYJSON_PADDING_SIZE);
    *bytes = result;
    *length = size;
    return true;
}

static bool database_load(const char *path, oracle_database *database) {
    size_t json_length = 0;
    yyjson_val *root;
    yyjson_val *entry;
    size_t index;
    size_t count;
    if (!read_file(path, &database->json_bytes, &json_length)) {
        return false;
    }
    database->json_document = yyjson_read_opts(
        database->json_bytes, json_length, YYJSON_READ_INSITU, NULL, NULL);
    if (database->json_document == NULL ||
        !yyjson_is_arr(root = yyjson_doc_get_root(database->json_document))) {
        (void)fprintf(stderr, "crawler database root is not an array\n");
        return false;
    }
    count = yyjson_arr_size(root);
    if (count == 0 || count > ORACLE_MAX_PATTERNS) {
        (void)fprintf(stderr, "invalid crawler pattern count: %zu\n", count);
        return false;
    }
    database->patterns = calloc(count, sizeof(*database->patterns));
    if (database->patterns == NULL) {
        (void)fprintf(stderr, "cannot allocate pattern table\n");
        return false;
    }
    database->len = count;
    yyjson_arr_foreach(root, index, count, entry) {
        yyjson_val *pattern_value;
        const char *pattern;
        size_t pattern_length;
        char *folded;
        int error_code = 0;
        PCRE2_SIZE error_offset = 0;
        PCRE2_UCHAR error_message[192];
        size_t offset;
        if (!yyjson_is_obj(entry) ||
            !yyjson_is_str(pattern_value = yyjson_obj_get(entry, "pattern"))) {
            (void)fprintf(stderr, "entry %zu has no string pattern\n", index);
            return false;
        }
        pattern = yyjson_get_str(pattern_value);
        pattern_length = yyjson_get_len(pattern_value);
        folded = malloc(pattern_length == 0 ? 1u : pattern_length);
        if (folded == NULL) {
            (void)fprintf(stderr, "cannot allocate folded pattern %zu\n", index);
            return false;
        }
        for (offset = 0; offset < pattern_length; ++offset) {
            folded[offset] = (char)ascii_lower((unsigned char)pattern[offset]);
        }
        database->patterns[index].code = pcre2_compile(
            (PCRE2_SPTR)folded, (PCRE2_SIZE)pattern_length,
            PCRE2_UTF | PCRE2_UCP | PCRE2_MATCH_INVALID_UTF,
            &error_code, &error_offset, NULL);
        free(folded);
        if (database->patterns[index].code == NULL) {
            (void)pcre2_get_error_message(
                error_code, error_message, sizeof(error_message));
            (void)fprintf(stderr,
                          "pattern %zu failed at byte %zu: %s\n",
                          index, (size_t)error_offset,
                          (const char *)error_message);
            return false;
        }
    }
    return true;
}

static int hex_nibble(unsigned char value) {
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    value = ascii_lower(value);
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return 10 + (int)(value - (unsigned char)'a');
    }
    return -1;
}

static bool decode_hex(const char *hex, size_t hex_length,
                       unsigned char **bytes, size_t *length) {
    unsigned char *result;
    size_t index;
    if ((hex_length & 1u) != 0u) {
        return false;
    }
    result = malloc(hex_length == 0 ? 1u : hex_length / 2u);
    if (result == NULL) {
        return false;
    }
    for (index = 0; index < hex_length; index += 2u) {
        const int high = hex_nibble((unsigned char)hex[index]);
        const int low = hex_nibble((unsigned char)hex[index + 1u]);
        if (high < 0 || low < 0) {
            free(result);
            return false;
        }
        result[index / 2u] = (unsigned char)((high << 4) | low);
    }
    *bytes = result;
    *length = hex_length / 2u;
    return true;
}

static bool valid_case_id(const char *value, size_t length) {
    size_t index;
    if (length == 0 || length > 240u) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (!(isalnum(byte) != 0 || byte == (unsigned char)'-' ||
              byte == (unsigned char)'_' || byte == (unsigned char)'.')) {
            return false;
        }
    }
    return true;
}

static bool write_case_result(FILE *output,
                              const char *case_id,
                              const oracle_database *database,
                              pcre2_match_data *match_data,
                              pcre2_match_context *match_context,
                              size_t *matched_indices,
                              unsigned char *subject,
                              size_t subject_length,
                              size_t *error_count) {
    size_t index;
    size_t match_count = 0;
    bool first = true;
    for (index = 0; index < subject_length; ++index) {
        subject[index] = ascii_lower(subject[index]);
    }
    if (fprintf(output,
                "{\"case_id\":\"%s\",\"is_crawler\":",
                case_id) < 0) {
        return false;
    }
    for (index = 0; index < database->len; ++index) {
        const int result = pcre2_match(
            database->patterns[index].code,
            (PCRE2_SPTR)subject, (PCRE2_SIZE)subject_length,
            0, 0, match_data, match_context);
        if (result >= 0) {
            matched_indices[match_count++] = index;
        } else if (result != PCRE2_ERROR_NOMATCH) {
            (void)fprintf(stderr,
                          "oracle match error case=%s pattern=%zu code=%d\n",
                          case_id, index, result);
            ++*error_count;
        }
    }
    if (fprintf(output, "%s,\"match_count\":%zu,\"matching_pattern_indices\":[",
                match_count == 0 ? "false" : "true", match_count) < 0) {
        return false;
    }
    for (index = 0; index < match_count; ++index) {
        if (fprintf(output, "%s%zu", first ? "" : ",",
                    matched_indices[index]) < 0) {
            return false;
        }
        first = false;
    }
    return fprintf(output, "],\"subject_bytes\":%zu}\n", subject_length) >= 0;
}

static bool runtime_config_string(uint32_t selector,
                                  char *buffer,
                                  size_t capacity) {
    if (capacity == 0) {
        return false;
    }
    buffer[0] = '\0';
    if (pcre2_config(selector, buffer) < 0) {
        return false;
    }
    buffer[capacity - 1u] = '\0';
    return buffer[0] != '\0';
}

static bool write_metadata(const char *path,
                           size_t pattern_count,
                           size_t case_count,
                           size_t oracle_error_count) {
    FILE *output;
    char runtime_version[128] = {0};
    char unicode_version[128] = {0};
    if (!runtime_config_string(PCRE2_CONFIG_VERSION,
                               runtime_version, sizeof(runtime_version)) ||
        !runtime_config_string(PCRE2_CONFIG_UNICODE_VERSION,
                               unicode_version, sizeof(unicode_version))) {
        (void)fprintf(stderr, "cannot read PCRE2 runtime configuration\n");
        return false;
    }
    output = fopen(path, "wb");
    if (output == NULL) {
        (void)fprintf(stderr, "cannot create %s: %s\n", path, strerror(errno));
        return false;
    }
    if (fprintf(
            output,
            "{\"case_count\":%zu,\"casefold\":\"ascii-lower-pattern-and-subject\","
            "\"compile_flags\":[\"PCRE2_UTF\",\"PCRE2_UCP\","
            "\"PCRE2_MATCH_INVALID_UTF\"],\"depth_limit\":%u,"
            "\"heap_limit_kib\":%u,\"match_engine\":\"interpreter\","
            "\"match_limit\":%u,\"oracle_error_count\":%zu,"
            "\"pattern_count\":%zu,\"pcre2_header_version\":\"%d.%d\","
            "\"pcre2_runtime_version\":\"%s\",\"unicode_version\":\"%s\"}\n",
            case_count, ORACLE_DEPTH_LIMIT, ORACLE_HEAP_LIMIT_KIB,
            ORACLE_MATCH_LIMIT, oracle_error_count, pattern_count,
            PCRE2_MAJOR, PCRE2_MINOR, runtime_version, unicode_version) < 0 ||
        fclose(output) != 0) {
        (void)fprintf(stderr, "cannot write oracle metadata\n");
        return false;
    }
    return true;
}

int main(int argc, char **argv) {
    oracle_database database = {0};
    FILE *cases = NULL;
    FILE *output = NULL;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    size_t line_number = 0;
    size_t case_count = 0;
    size_t oracle_error_count = 0;
    pcre2_match_data *match_data = NULL;
    pcre2_match_context *match_context = NULL;
    size_t *matched_indices = NULL;
    int exit_code = EXIT_FAILURE;

    if (argc != 5) {
        (void)fprintf(stderr,
                      "usage: %s VENDOR_JSON CASES_TSV RESULTS_JSONL METADATA_JSON\n",
                      argv[0]);
        return EXIT_FAILURE;
    }
    if (!database_load(argv[1], &database)) {
        goto finished;
    }
    match_data = pcre2_match_data_create(1, NULL);
    match_context = pcre2_match_context_create(NULL);
    if (match_data == NULL || match_context == NULL ||
        pcre2_set_match_limit(match_context, ORACLE_MATCH_LIMIT) != 0 ||
        pcre2_set_depth_limit(match_context, ORACLE_DEPTH_LIMIT) != 0 ||
        pcre2_set_heap_limit(match_context, ORACLE_HEAP_LIMIT_KIB) != 0) {
        (void)fprintf(stderr, "cannot initialize bounded PCRE2 context\n");
        goto finished;
    }
    matched_indices = malloc(database.len * sizeof(*matched_indices));
    if (matched_indices == NULL) {
        (void)fprintf(stderr, "cannot allocate match index buffer\n");
        goto finished;
    }
    cases = fopen(argv[2], "rb");
    if (cases == NULL) {
        (void)fprintf(stderr, "cannot open %s: %s\n", argv[2], strerror(errno));
        goto finished;
    }
    output = fopen(argv[3], "wb");
    if (output == NULL) {
        (void)fprintf(stderr, "cannot create %s: %s\n", argv[3], strerror(errno));
        goto finished;
    }
    while ((line_length = getline(&line, &line_capacity, cases)) >= 0) {
        char *tab;
        unsigned char *subject = NULL;
        size_t subject_length = 0;
        size_t id_length;
        ++line_number;
        if ((size_t)line_length > ORACLE_MAX_CASE_LINE_BYTES ||
            case_count >= ORACLE_MAX_CASES) {
            (void)fprintf(stderr, "cases input exceeds oracle bounds\n");
            goto finished;
        }
        while (line_length > 0 &&
               (line[line_length - 1] == '\n' ||
                line[line_length - 1] == '\r')) {
            line[--line_length] = '\0';
        }
        tab = memchr(line, '\t', (size_t)line_length);
        if (tab == NULL) {
            (void)fprintf(stderr, "cases line %zu has no tab\n", line_number);
            goto finished;
        }
        id_length = (size_t)(tab - line);
        if (!valid_case_id(line, id_length)) {
            (void)fprintf(stderr, "cases line %zu has invalid id\n", line_number);
            goto finished;
        }
        *tab = '\0';
        if (!decode_hex(tab + 1,
                        (size_t)line_length - id_length - 1u,
                        &subject, &subject_length)) {
            (void)fprintf(stderr, "cases line %zu has invalid hex\n", line_number);
            free(subject);
            goto finished;
        }
        if (!write_case_result(output, line, &database,
                               match_data, match_context,
                               matched_indices,
                               subject, subject_length,
                               &oracle_error_count)) {
            (void)fprintf(stderr, "cannot write oracle case %s\n", line);
            free(subject);
            goto finished;
        }
        free(subject);
        ++case_count;
    }
    {
        const int cases_error = ferror(cases);
        const int flush_status = fflush(output);
        const int close_status = fclose(output);
        output = NULL;
        if (cases_error != 0 || flush_status != 0 || close_status != 0) {
            (void)fprintf(stderr, "oracle I/O failure\n");
            goto finished;
        }
    }
    if (fclose(cases) != 0) {
        cases = NULL;
        (void)fprintf(stderr, "cannot close cases input\n");
        goto finished;
    }
    cases = NULL;
    if (oracle_error_count != 0 ||
        !write_metadata(argv[4], database.len, case_count,
                        oracle_error_count)) {
        goto finished;
    }
    exit_code = EXIT_SUCCESS;

finished:
    free(line);
    free(matched_indices);
    if (cases != NULL) {
        (void)fclose(cases);
    }
    if (output != NULL) {
        (void)fclose(output);
    }
    pcre2_match_data_free(match_data);
    pcre2_match_context_free(match_context);
    database_destroy(&database);
    return exit_code;
}
