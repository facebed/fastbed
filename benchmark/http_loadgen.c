/*
 * Independent epoll HTTP/1.1 load generator for Fastbed performance evidence.
 * It has no dependency on Fastbed. Complete response bodies are streamed through
 * SHA-256 and compared with pinned allowed (status, digest) pairs.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HEADER_LIMIT (64u * 1024u)
#define HEADER_BUFFER (HEADER_LIMIT + 64u * 1024u)
#define READ_BUFFER (64u * 1024u)
#define CHUNK_LINE_LIMIT 8192u
#define MAX_EXPECTED 8u
#define MAX_SOURCES 64u
#define MAX_EVENTS 1024
#define NO_REQUEST UINT64_MAX

typedef enum { MODE_CLOSED = 0, MODE_OPEN } schedule_mode;
typedef enum { CONN_KEEPALIVE = 0, CONN_FIN, CONN_RST } connection_mode;
typedef enum { SLOT_IDLE = 0, SLOT_CONNECTING, SLOT_SENDING, SLOT_RECEIVING } slot_state;
typedef enum { BODY_LENGTH = 0, BODY_CHUNKED, BODY_CLOSE } body_mode;
typedef enum { CHUNK_SIZE = 0, CHUNK_DATA, CHUNK_DATA_CRLF, CHUNK_TRAILER } chunk_state;
typedef enum {
    OUT_UNSET = 0,
    OUT_OK,
    OUT_STATUS_MISMATCH,
    OUT_HASH_MISMATCH,
    OUT_PROTOCOL_ERROR,
    OUT_TRANSPORT_ERROR,
    OUT_TIMEOUT,
    OUT_CLIENT_RST,
    OUT_CANCELED
} outcome;

typedef struct {
    int status;
    unsigned char digest[32];
} expected_response;

typedef struct {
    char *path;
    char *label;
    expected_response expected[MAX_EXPECTED];
    size_t expected_count;
    char *request_keepalive;
    size_t request_keepalive_length;
    char *request_close;
    size_t request_close_length;
} target;

typedef struct {
    uint64_t sequence;
    uint64_t scheduled_ns;
    uint64_t started_ns;
    uint64_t connected_ns;
    uint64_t first_byte_ns;
    uint64_t end_ns;
    uint64_t body_bytes;
    uint64_t connection_id;
    uint32_t target_index;
    uint32_t source_index;
    uint32_t reuse_ordinal;
    uint32_t stale_retries;
    int status;
    int matched_alternative;
    outcome result;
    bool digest_valid;
    unsigned char digest[32];
} record;

typedef struct {
    const char *host;
    const char *host_header;
    const char *requests_path;
    const char *records_path;
    const char *summary_path;
    const char *user_agent;
    unsigned port;
    uint64_t request_count;
    size_t concurrency;
    schedule_mode mode;
    long double rate;
    connection_mode connection;
    uint64_t timeout_ns;
    uint64_t max_body_bytes;
    uint64_t seed;
    char *source_text[MAX_SOURCES];
    size_t source_count;
} options;

typedef struct {
    int fd;
    slot_state state;
    uint32_t generation;
    uint64_t request_sequence;
    uint64_t connection_id;
    uint32_t source_index;
    uint32_t reuse_ordinal;
    const char *request;
    size_t request_length;
    size_t request_sent;
    unsigned char header_buffer[HEADER_BUFFER];
    size_t header_length;
    bool headers_complete;
    bool response_close;
    body_mode body_framing;
    uint64_t body_remaining;
    chunk_state chunk_parser;
    uint64_t chunk_remaining;
    unsigned chunk_crlf_offset;
    unsigned char chunk_line[CHUNK_LINE_LIMIT];
    size_t chunk_line_length;
    EVP_MD_CTX *digest_context;
    bool stale_retry_used;
} client_slot;

typedef struct {
    options opt;
    int epoll_fd;
    struct sockaddr_storage remote_address;
    socklen_t remote_length;
    int address_family;
    struct sockaddr_storage source_addresses[MAX_SOURCES];
    socklen_t source_lengths[MAX_SOURCES];
    target *targets;
    size_t target_count;
    record *records;
    client_slot *slots;
    uint64_t next_closed_sequence;
    uint64_t open_arrived;
    uint64_t open_assigned;
    uint64_t active;
    uint64_t completed;
    uint64_t next_connection_id;
    uint64_t max_pending;
    uint64_t run_start_ns;
    uint64_t run_end_ns;
} app;

static volatile sig_atomic_t interrupted = 0;

static void signal_handler(int signal_number) {
    (void)signal_number;
    interrupted = 1;
}

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0) {
        (void)fprintf(stderr, "clock_gettime(CLOCK_MONOTONIC_RAW): %s\n",
                      strerror(errno));
        exit(2);
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
           (uint64_t)value.tv_nsec;
}

static const char *schedule_name(schedule_mode mode) {
    return mode == MODE_OPEN ? "open" : "closed";
}

static const char *connection_name(connection_mode mode) {
    switch (mode) {
    case CONN_KEEPALIVE: return "keepalive";
    case CONN_FIN: return "fin";
    case CONN_RST: return "rst";
    }
    return "unknown";
}

static const char *outcome_name(outcome value) {
    switch (value) {
    case OUT_OK: return "ok";
    case OUT_STATUS_MISMATCH: return "status_mismatch";
    case OUT_HASH_MISMATCH: return "hash_mismatch";
    case OUT_PROTOCOL_ERROR: return "protocol_error";
    case OUT_TRANSPORT_ERROR: return "transport_error";
    case OUT_TIMEOUT: return "timeout";
    case OUT_CLIENT_RST: return "client_rst";
    case OUT_CANCELED: return "canceled";
    case OUT_UNSET: return "unset";
    }
    return "unknown";
}

static bool parse_u64(const char *text, uint64_t minimum, uint64_t maximum,
                      uint64_t *result) {
    char *end = NULL;
    unsigned long long value;
    if (text == NULL || text[0] == '\0' || text[0] == '-') return false;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < minimum || value > maximum) return false;
    *result = (uint64_t)value;
    return true;
}

static bool parse_rate(const char *text, long double *result) {
    char *end = NULL;
    long double value;
    if (text == NULL || text[0] == '\0' || text[0] == '-') return false;
    errno = 0;
    value = strtold(text, &end);
    if (errno != 0 || end == text || *end != '\0' ||
        !(value > 0.0L) || value > 1000000000.0L) return false;
    *result = value;
    return true;
}

static void usage(FILE *stream, const char *program) {
    (void)fprintf(stream,
        "usage: %s --host HOST --port PORT --requests-file FILE --requests N\n"
        "          --concurrency N --records FILE --summary FILE [options]\n\n"
        "  --mode closed|open              scheduling model (default: closed)\n"
        "  --rate REQUESTS_PER_SECOND      required for open loop\n"
        "  --connection-mode keepalive|fin|rst (default: keepalive)\n"
        "  --source-address NUMERIC_ADDR   repeatable explicit bind address\n"
        "  --timeout-ms N                  per-request timeout (default: 30000)\n"
        "  --max-body-bytes N              response cap (default: 67108864)\n"
        "  --host-header VALUE             HTTP Host override\n"
        "  --user-agent VALUE              default: Discordbot/2.0\n"
        "  --seed N                        deterministic target order\n", program);
}

static bool safe_header_value(const char *value) {
    if (value == NULL || value[0] == '\0') return false;
    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor != '\0'; ++cursor) {
        if (*cursor == '\r' || *cursor == '\n' || *cursor < 0x20u ||
            *cursor == 0x7fu) return false;
    }
    return true;
}

static bool parse_options(int argc, char **argv, options *opt) {
    static const struct option long_options[] = {
        {"host", required_argument, NULL, 1000},
        {"port", required_argument, NULL, 1001},
        {"requests-file", required_argument, NULL, 1002},
        {"requests", required_argument, NULL, 1003},
        {"concurrency", required_argument, NULL, 1004},
        {"records", required_argument, NULL, 1005},
        {"summary", required_argument, NULL, 1006},
        {"mode", required_argument, NULL, 1007},
        {"rate", required_argument, NULL, 1008},
        {"connection-mode", required_argument, NULL, 1009},
        {"source-address", required_argument, NULL, 1010},
        {"timeout-ms", required_argument, NULL, 1011},
        {"max-body-bytes", required_argument, NULL, 1012},
        {"host-header", required_argument, NULL, 1013},
        {"user-agent", required_argument, NULL, 1014},
        {"seed", required_argument, NULL, 1015},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;
    uint64_t parsed;
    memset(opt, 0, sizeof(*opt));
    opt->mode = MODE_CLOSED;
    opt->connection = CONN_KEEPALIVE;
    opt->timeout_ns = UINT64_C(30000) * UINT64_C(1000000);
    opt->max_body_bytes = UINT64_C(64) * UINT64_C(1024) * UINT64_C(1024);
    opt->seed = UINT64_C(1);
    opt->user_agent = "Discordbot/2.0";
    while ((option = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (option) {
        case 1000: opt->host = optarg; break;
        case 1001:
            if (!parse_u64(optarg, 1u, 65535u, &parsed)) return false;
            opt->port = (unsigned)parsed;
            break;
        case 1002: opt->requests_path = optarg; break;
        case 1003:
            if (!parse_u64(optarg, 1u, UINT64_C(10000000),
                           &opt->request_count)) return false;
            break;
        case 1004:
            if (!parse_u64(optarg, 1u, UINT64_C(4096), &parsed)) return false;
            opt->concurrency = (size_t)parsed;
            break;
        case 1005: opt->records_path = optarg; break;
        case 1006: opt->summary_path = optarg; break;
        case 1007:
            if (strcmp(optarg, "closed") == 0) opt->mode = MODE_CLOSED;
            else if (strcmp(optarg, "open") == 0) opt->mode = MODE_OPEN;
            else return false;
            break;
        case 1008:
            if (!parse_rate(optarg, &opt->rate)) return false;
            break;
        case 1009:
            if (strcmp(optarg, "keepalive") == 0) opt->connection = CONN_KEEPALIVE;
            else if (strcmp(optarg, "fin") == 0) opt->connection = CONN_FIN;
            else if (strcmp(optarg, "rst") == 0) opt->connection = CONN_RST;
            else return false;
            break;
        case 1010:
            if (opt->source_count == MAX_SOURCES) return false;
            opt->source_text[opt->source_count++] = optarg;
            break;
        case 1011:
            if (!parse_u64(optarg, 1u, UINT64_C(3600000), &parsed)) return false;
            opt->timeout_ns = parsed * UINT64_C(1000000);
            break;
        case 1012:
            if (!parse_u64(optarg, 1u, UINT64_MAX, &opt->max_body_bytes))
                return false;
            break;
        case 1013: opt->host_header = optarg; break;
        case 1014: opt->user_agent = optarg; break;
        case 1015:
            if (!parse_u64(optarg, 0u, UINT64_MAX, &opt->seed)) return false;
            break;
        case 'h': usage(stdout, argv[0]); exit(0);
        default: return false;
        }
    }
    if (optind != argc || opt->host == NULL || opt->port == 0u ||
        opt->requests_path == NULL || opt->records_path == NULL ||
        opt->summary_path == NULL || opt->request_count == 0u ||
        opt->concurrency == 0u || !safe_header_value(opt->host) ||
        (opt->records_path != NULL && opt->summary_path != NULL &&
         strcmp(opt->records_path, opt->summary_path) == 0) ||
        !safe_header_value(opt->user_agent) ||
        (opt->host_header != NULL && !safe_header_value(opt->host_header)) ||
        (opt->mode == MODE_OPEN && !(opt->rate > 0.0L)) ||
        (opt->mode == MODE_CLOSED && opt->rate > 0.0L)) return false;
    if (opt->concurrency > opt->request_count)
        opt->concurrency = (size_t)opt->request_count;
    if (opt->mode == MODE_OPEN) {
        const long double span =
            ((long double)(opt->request_count - 1u) * 1000000000.0L) /
            opt->rate;
        if (span > 86400.0L * 1000000000.0L) return false;
    }
    return true;
}

static int hex_value(unsigned char value) {
    if (value >= '0' && value <= '9') return (int)(value - '0');
    value = (unsigned char)tolower(value);
    if (value >= 'a' && value <= 'f') return (int)(value - 'a') + 10;
    return -1;
}

static bool parse_digest(const char *text, unsigned char output[32]) {
    if (strlen(text) != 64u) return false;
    for (size_t index = 0u; index < 32u; ++index) {
        const int high = hex_value((unsigned char)text[index * 2u]);
        const int low = hex_value((unsigned char)text[index * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        output[index] = (unsigned char)((high << 4) | low);
    }
    return true;
}

static void digest_hex(const unsigned char digest[32], char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0u; index < 32u; ++index) {
        output[index * 2u] = digits[digest[index] >> 4];
        output[index * 2u + 1u] = digits[digest[index] & 0x0fu];
    }
    output[64] = '\0';
}

static bool parse_expected(char *text, target *entry) {
    char *save = NULL;
    char *token = strtok_r(text, ",", &save);
    while (token != NULL) {
        char *colon = strchr(token, ':');
        uint64_t status;
        if (entry->expected_count == MAX_EXPECTED || colon == NULL) return false;
        *colon = '\0';
        if (!parse_u64(token, 100u, 599u, &status) ||
            !parse_digest(colon + 1u,
                          entry->expected[entry->expected_count].digest))
            return false;
        entry->expected[entry->expected_count].status = (int)status;
        ++entry->expected_count;
        token = strtok_r(NULL, ",", &save);
    }
    return entry->expected_count != 0u;
}

static bool safe_path(const char *path) {
    if (path == NULL || path[0] != '/' || strlen(path) > 16384u) return false;
    for (const unsigned char *cursor = (const unsigned char *)path;
         *cursor != '\0'; ++cursor) {
        if (*cursor == '\r' || *cursor == '\n' || *cursor == '\t' ||
            *cursor <= 0x20u || *cursor >= 0x7fu) return false;
    }
    return true;
}

static char *default_host_header(const options *opt) {
    const bool ipv6 = strchr(opt->host, ':') != NULL;
    const size_t length = strlen(opt->host) + 32u;
    char *result = malloc(length);
    if (result == NULL) return NULL;
    if (ipv6) (void)snprintf(result, length, "[%s]:%u", opt->host, opt->port);
    else (void)snprintf(result, length, "%s:%u", opt->host, opt->port);
    return result;
}

static bool build_request(target *entry, const options *opt,
                          const char *host_header, bool close_connection) {
    const char *connection = close_connection ? "close" : "keep-alive";
    const int length = snprintf(NULL, 0,
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
        "Accept: */*\r\nConnection: %s\r\n\r\n",
        entry->path, host_header, opt->user_agent, connection);
    char **destination = close_connection
        ? &entry->request_close : &entry->request_keepalive;
    size_t *destination_length = close_connection
        ? &entry->request_close_length : &entry->request_keepalive_length;
    if (length <= 0) return false;
    *destination = malloc((size_t)length + 1u);
    if (*destination == NULL) return false;
    (void)snprintf(*destination, (size_t)length + 1u,
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
        "Accept: */*\r\nConnection: %s\r\n\r\n",
        entry->path, host_header, opt->user_agent, connection);
    *destination_length = (size_t)length;
    return true;
}

static bool load_targets(app *state) {
    FILE *stream = fopen(state->opt.requests_path, "r");
    char *line = NULL;
    size_t capacity = 0u, allocated = 0u, line_number = 0u;
    ssize_t length;
    char *generated_host = NULL;
    const char *host_header = state->opt.host_header;
    if (stream == NULL) {
        (void)fprintf(stderr, "open requests file: %s\n", strerror(errno));
        return false;
    }
    if (host_header == NULL) {
        generated_host = default_host_header(&state->opt);
        host_header = generated_host;
    }
    if (host_header == NULL) {
        (void)fclose(stream);
        return false;
    }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char *expected_text, *label, *first_tab, *second_tab;
        target entry;
        ++line_number;
        while (length > 0 && (line[(size_t)length - 1u] == '\n' ||
                              line[(size_t)length - 1u] == '\r'))
            line[--length] = '\0';
        if (length == 0 || line[0] == '#') continue;
        first_tab = strchr(line, '\t');
        if (first_tab == NULL) goto malformed;
        *first_tab = '\0';
        expected_text = first_tab + 1u;
        second_tab = strchr(expected_text, '\t');
        if (second_tab != NULL) {
            *second_tab = '\0';
            label = second_tab + 1u;
        } else {
            label = line;
        }
        if (!safe_path(line) || label[0] == '\0' || strchr(label, '\t') != NULL)
            goto malformed;
        memset(&entry, 0, sizeof(entry));
        entry.path = strdup(line);
        entry.label = strdup(label);
        if (entry.path == NULL || entry.label == NULL ||
            !parse_expected(expected_text, &entry) ||
            !build_request(&entry, &state->opt, host_header, false) ||
            !build_request(&entry, &state->opt, host_header, true)) {
            free(entry.path); free(entry.label);
            free(entry.request_keepalive); free(entry.request_close);
            goto malformed;
        }
        if (state->target_count == allocated) {
            const size_t next = allocated == 0u ? 16u : allocated * 2u;
            target *resized = realloc(state->targets, next * sizeof(*resized));
            if (resized == NULL) {
                free(entry.path); free(entry.label);
                free(entry.request_keepalive); free(entry.request_close);
                goto malformed;
            }
            state->targets = resized;
            allocated = next;
        }
        state->targets[state->target_count++] = entry;
        continue;
malformed:
        (void)fprintf(stderr, "invalid workload line %zu\n", line_number);
        free(line); free(generated_host); (void)fclose(stream);
        return false;
    }
    const bool read_failed = ferror(stream) != 0;
    const bool close_failed = fclose(stream) != 0;
    free(line); free(generated_host);
    if (read_failed || close_failed || state->target_count == 0u) {
        (void)fprintf(stderr, "requests file is empty or unreadable\n");
        return false;
    }
    return true;
}

static void free_targets(app *state) {
    for (size_t index = 0u; index < state->target_count; ++index) {
        free(state->targets[index].path);
        free(state->targets[index].label);
        free(state->targets[index].request_keepalive);
        free(state->targets[index].request_close);
    }
    free(state->targets);
}

static bool resolve_addresses(app *state) {
    struct addrinfo hints, *addresses = NULL, *selected = NULL;
    char service[16];
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    (void)snprintf(service, sizeof(service), "%u", state->opt.port);
    status = getaddrinfo(state->opt.host, service, &hints, &addresses);
    if (status != 0) {
        (void)fprintf(stderr, "resolve host: %s\n", gai_strerror(status));
        return false;
    }
    for (struct addrinfo *cursor = addresses; cursor != NULL;
         cursor = cursor->ai_next) {
        if ((cursor->ai_family == AF_INET || cursor->ai_family == AF_INET6) &&
            cursor->ai_addrlen <= sizeof(state->remote_address)) {
            selected = cursor;
            break;
        }
    }
    if (selected == NULL) {
        freeaddrinfo(addresses);
        (void)fprintf(stderr, "host has no usable TCP address\n");
        return false;
    }
    memcpy(&state->remote_address, selected->ai_addr, selected->ai_addrlen);
    state->remote_length = (socklen_t)selected->ai_addrlen;
    state->address_family = selected->ai_family;
    freeaddrinfo(addresses);
    for (size_t index = 0u; index < state->opt.source_count; ++index) {
        struct addrinfo source_hints, *source = NULL;
        memset(&source_hints, 0, sizeof(source_hints));
        source_hints.ai_family = state->address_family;
        source_hints.ai_socktype = SOCK_STREAM;
        source_hints.ai_flags = AI_NUMERICHOST;
        status = getaddrinfo(state->opt.source_text[index], "0",
                             &source_hints, &source);
        if (status != 0 || source == NULL ||
            source->ai_addrlen > sizeof(state->source_addresses[index])) {
            (void)fprintf(stderr, "invalid source address %s: %s\n",
                state->opt.source_text[index],
                status == 0 ? "wrong address family" : gai_strerror(status));
            if (source != NULL) freeaddrinfo(source);
            return false;
        }
        memcpy(&state->source_addresses[index], source->ai_addr,
               source->ai_addrlen);
        state->source_lengths[index] = (socklen_t)source->ai_addrlen;
        freeaddrinfo(source);
    }
    return true;
}

static uint64_t mix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static uint64_t event_key(size_t slot_index, uint32_t generation) {
    return ((uint64_t)generation << 32) | (uint64_t)(uint32_t)slot_index;
}

static bool epoll_set(app *state, size_t slot_index, int operation,
                      uint32_t events) {
    struct epoll_event event;
    client_slot *slot = &state->slots[slot_index];
    memset(&event, 0, sizeof(event));
    event.events = events | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    event.data.u64 = event_key(slot_index, slot->generation);
    return epoll_ctl(state->epoll_fd, operation, slot->fd, &event) == 0;
}

static void close_slot(app *state, size_t slot_index, bool reset) {
    client_slot *slot = &state->slots[slot_index];
    if (slot->fd >= 0) {
        if (reset) {
            struct linger value = {1, 0};
            (void)setsockopt(slot->fd, SOL_SOCKET, SO_LINGER,
                             &value, sizeof(value));
        }
        (void)epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, slot->fd, NULL);
        (void)close(slot->fd);
        slot->fd = -1;
    }
    slot->connection_id = 0u;
    slot->reuse_ordinal = 0u;
    slot->source_index = UINT32_MAX;
}

static void reset_response(client_slot *slot) {
    slot->header_length = 0u;
    slot->headers_complete = false;
    slot->response_close = false;
    slot->body_framing = BODY_LENGTH;
    slot->body_remaining = 0u;
    slot->chunk_parser = CHUNK_SIZE;
    slot->chunk_remaining = 0u;
    slot->chunk_crlf_offset = 0u;
    slot->chunk_line_length = 0u;
}

static void finish_record(app *state, size_t slot_index, outcome result,
                          bool close_connection, bool reset_connection) {
    client_slot *slot = &state->slots[slot_index];
    record *entry = &state->records[slot->request_sequence];
    entry->end_ns = now_ns();
    entry->result = result;
    if (close_connection || result != OUT_OK) {
        close_slot(state, slot_index, reset_connection);
    } else if (!epoll_set(state, slot_index, EPOLL_CTL_MOD, EPOLLIN)) {
        close_slot(state, slot_index, false);
    }
    slot->state = SLOT_IDLE;
    slot->request_sequence = NO_REQUEST;
    slot->request = NULL;
    slot->request_length = 0u;
    slot->request_sent = 0u;
    --state->active;
    ++state->completed;
}

static void finish_error(app *state, size_t slot_index, outcome result) {
    finish_record(state, slot_index, result, true, false);
}

static void finish_rst(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    struct linger value = {1, 0};
    if (slot->fd < 0 ||
        setsockopt(slot->fd, SOL_SOCKET, SO_LINGER,
                   &value, sizeof(value)) != 0) {
        finish_error(state, slot_index, OUT_TRANSPORT_ERROR);
        return;
    }
    finish_record(state, slot_index, OUT_CLIENT_RST, true, false);
}

static void finish_response(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    record *entry = &state->records[slot->request_sequence];
    target *request_target = &state->targets[entry->target_index];
    unsigned int digest_length = 0u;
    bool status_seen = false;
    outcome result = OUT_STATUS_MISMATCH;
    if (EVP_DigestFinal_ex(slot->digest_context, entry->digest,
                           &digest_length) != 1 || digest_length != 32u) {
        finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
        return;
    }
    entry->digest_valid = true;
    entry->matched_alternative = -1;
    for (size_t index = 0u; index < request_target->expected_count; ++index) {
        if (request_target->expected[index].status == entry->status) {
            status_seen = true;
            if (memcmp(request_target->expected[index].digest,
                       entry->digest, 32u) == 0) {
                entry->matched_alternative = (int)index;
                result = OUT_OK;
                break;
            }
        }
    }
    if (result != OUT_OK && status_seen) result = OUT_HASH_MISMATCH;
    finish_record(state, slot_index, result,
        state->opt.connection != CONN_KEEPALIVE || slot->response_close, false);
}

static bool header_name_equal(const unsigned char *name, size_t length,
                              const char *expected) {
    const size_t expected_length = strlen(expected);
    return length == expected_length &&
           strncasecmp((const char *)name, expected, length) == 0;
}

static bool header_has_token(const unsigned char *value, size_t length,
                             const char *token) {
    const size_t token_length = strlen(token);
    size_t offset = 0u;
    while (offset < length) {
        size_t start, end;
        while (offset < length &&
               (value[offset] == ',' || isspace(value[offset]))) ++offset;
        start = offset;
        while (offset < length && value[offset] != ',') ++offset;
        end = offset;
        while (end > start && isspace(value[end - 1u])) --end;
        if (end - start == token_length &&
            strncasecmp((const char *)value + start, token, token_length) == 0)
            return true;
    }
    return false;
}

static bool header_is_exact_token(const unsigned char *value, size_t length,
                                  const char *token) {
    size_t start = 0u, end = length;
    const size_t token_length = strlen(token);
    while (start < end && (value[start] == ' ' || value[start] == '\t')) ++start;
    while (end > start &&
           (value[end - 1u] == ' ' || value[end - 1u] == '\t')) --end;
    return end - start == token_length &&
        strncasecmp((const char *)value + start, token, token_length) == 0;
}

static bool parse_decimal_slice(const unsigned char *value, size_t length,
                                uint64_t *result) {
    uint64_t parsed = 0u;
    size_t start = 0u, end = length;
    while (start < end && isspace(value[start])) ++start;
    while (end > start && isspace(value[end - 1u])) --end;
    if (start == end) return false;
    for (size_t index = start; index < end; ++index) {
        const unsigned digit = (unsigned)(value[index] - '0');
        if (digit > 9u || parsed > (UINT64_MAX - digit) / 10u) return false;
        parsed = parsed * 10u + digit;
    }
    *result = parsed;
    return true;
}

static bool parse_headers(app *state, size_t slot_index, size_t header_end) {
    client_slot *slot = &state->slots[slot_index];
    record *entry = &state->records[slot->request_sequence];
    const unsigned char *buffer = slot->header_buffer;
    const unsigned char *limit = buffer + header_end;
    const unsigned char *line_end = NULL, *cursor;
    bool http_10 = false, connection_keep_alive = false;
    bool content_length_seen = false, transfer_encoding_seen = false;
    bool chunked = false;
    uint64_t content_length = 0u;
    for (cursor = buffer; cursor + 1u < limit; ++cursor) {
        if (cursor[0] == '\r' && cursor[1] == '\n') {
            line_end = cursor;
            break;
        }
    }
    if (line_end == NULL || (size_t)(line_end - buffer) < 12u ||
        memcmp(buffer, "HTTP/1.", 7u) != 0 ||
        (buffer[7] != '0' && buffer[7] != '1') || buffer[8] != ' ' ||
        !isdigit(buffer[9]) || !isdigit(buffer[10]) || !isdigit(buffer[11]) ||
        (line_end - buffer > 12 && buffer[12] != ' ')) return false;
    http_10 = buffer[7] == '0';
    entry->status = ((int)buffer[9] - '0') * 100 +
                    ((int)buffer[10] - '0') * 10 +
                    ((int)buffer[11] - '0');
    cursor = line_end + 2u;
    while (cursor + 1u < limit) {
        const unsigned char *end = NULL, *colon, *value;
        size_t name_length, value_length;
        if (cursor[0] == '\r' && cursor[1] == '\n') {
            cursor += 2u;
            break;
        }
        for (const unsigned char *scan = cursor; scan + 1u < limit; ++scan) {
            if (scan[0] == '\r' && scan[1] == '\n') {
                end = scan;
                break;
            }
        }
        if (end == NULL) return false;
        colon = memchr(cursor, ':', (size_t)(end - cursor));
        if (colon == NULL || colon == cursor) return false;
        name_length = (size_t)(colon - cursor);
        value = colon + 1u;
        while (value < end && (*value == ' ' || *value == '\t')) ++value;
        value_length = (size_t)(end - value);
        if (header_name_equal(cursor, name_length, "content-length")) {
            uint64_t parsed;
            if (!parse_decimal_slice(value, value_length, &parsed) ||
                (content_length_seen && parsed != content_length)) return false;
            content_length = parsed;
            content_length_seen = true;
        } else if (header_name_equal(cursor, name_length,
                                     "transfer-encoding")) {
            if (transfer_encoding_seen ||
                !header_is_exact_token(value, value_length, "chunked"))
                return false;
            transfer_encoding_seen = true;
            chunked = true;
        } else if (header_name_equal(cursor, name_length, "connection")) {
            if (header_has_token(value, value_length, "close"))
                slot->response_close = true;
            if (header_has_token(value, value_length, "keep-alive"))
                connection_keep_alive = true;
        }
        cursor = end + 2u;
    }
    if (cursor != limit || (chunked && content_length_seen)) return false;
    if (http_10 && !connection_keep_alive) slot->response_close = true;
    if ((entry->status >= 100 && entry->status < 200) ||
        entry->status == 204 || entry->status == 304) {
        slot->body_framing = BODY_LENGTH;
        slot->body_remaining = 0u;
    } else if (chunked) {
        slot->body_framing = BODY_CHUNKED;
        slot->chunk_parser = CHUNK_SIZE;
    } else if (content_length_seen) {
        if (content_length > state->opt.max_body_bytes) return false;
        slot->body_framing = BODY_LENGTH;
        slot->body_remaining = content_length;
    } else {
        slot->body_framing = BODY_CLOSE;
        slot->response_close = true;
    }
    slot->headers_complete = true;
    return true;
}

static bool hash_body(app *state, size_t slot_index,
                      const unsigned char *data, size_t length) {
    client_slot *slot = &state->slots[slot_index];
    record *entry = &state->records[slot->request_sequence];
    if ((uint64_t)length > state->opt.max_body_bytes - entry->body_bytes ||
        EVP_DigestUpdate(slot->digest_context, data, length) != 1) return false;
    entry->body_bytes += (uint64_t)length;
    return true;
}

static bool is_tchar(unsigned char value) {
    return isalnum(value) ||
        value == '!' || value == '#' || value == '$' || value == '%' ||
        value == '&' || value == '\'' || value == '*' || value == '+' ||
        value == '-' || value == '.' || value == '^' || value == '_' ||
        value == 0x60u || value == '|' || value == '~';
}

static bool parse_chunk_size(const unsigned char *line, size_t length,
                             uint64_t *result) {
    uint64_t value = 0u;
    size_t digits = 0u, index = 0u;
    while (index < length && line[index] != ';') {
        int digit;
        digit = hex_value(line[index]);
        if (digit < 0 || value > (UINT64_MAX - (unsigned)digit) / 16u)
            return false;
        value = value * 16u + (unsigned)digit;
        ++digits;
        ++index;
    }
    if (digits == 0u) return false;
    while (index < length) {
        size_t name_start;
        if (line[index++] != ';') return false;
        name_start = index;
        while (index < length && is_tchar(line[index])) ++index;
        if (index == name_start) return false;
        if (index < length && line[index] == '=') {
            ++index;
            if (index == length) return false;
            if (line[index] == '"') {
                bool closed = false;
                ++index;
                while (index < length) {
                    const unsigned char value_byte = line[index++];
                    if (value_byte == '"') {
                        closed = true;
                        break;
                    }
                    if (value_byte == '\\') {
                        if (index == length) return false;
                        const unsigned char escaped = line[index++];
                        if (escaped < 0x20u || escaped == 0x7fu) return false;
                    } else if (
                        value_byte != '\t' &&
                        (value_byte < 0x20u || value_byte == 0x7fu)
                    ) {
                        return false;
                    }
                }
                if (!closed) return false;
            } else {
                const size_t value_start = index;
                while (index < length && is_tchar(line[index])) ++index;
                if (index == value_start) return false;
            }
        }
        if (index < length && line[index] != ';') return false;
    }
    *result = value;
    return true;
}

static bool valid_trailer_line(const unsigned char *line, size_t length) {
    size_t index = 0u;
    while (index < length && line[index] != ':') {
        if (!is_tchar(line[index])) return false;
        ++index;
    }
    if (index == 0u || index == length) return false;
    ++index;
    while (index < length) {
        const unsigned char value = line[index++];
        if (value != '\t' && (value < 0x20u || value == 0x7fu))
            return false;
    }
    return true;
}

static bool process_chunked(app *state, size_t slot_index,
                            const unsigned char *data, size_t length) {
    client_slot *slot = &state->slots[slot_index];
    size_t offset = 0u;
    while (offset < length) {
        if (slot->chunk_parser == CHUNK_DATA) {
            const uint64_t available = (uint64_t)(length - offset);
            const size_t take = slot->chunk_remaining < available
                ? (size_t)slot->chunk_remaining : length - offset;
            if (!hash_body(state, slot_index, data + offset, take)) {
                finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                return false;
            }
            offset += take;
            slot->chunk_remaining -= (uint64_t)take;
            if (slot->chunk_remaining == 0u) {
                slot->chunk_parser = CHUNK_DATA_CRLF;
                slot->chunk_crlf_offset = 0u;
            }
            continue;
        }
        if (slot->chunk_parser == CHUNK_DATA_CRLF) {
            const unsigned char expected[2] = {'\r', '\n'};
            if (data[offset] != expected[slot->chunk_crlf_offset]) {
                finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                return false;
            }
            ++offset;
            ++slot->chunk_crlf_offset;
            if (slot->chunk_crlf_offset == 2u) {
                slot->chunk_parser = CHUNK_SIZE;
                slot->chunk_line_length = 0u;
            }
            continue;
        }
        if (slot->chunk_line_length == CHUNK_LINE_LIMIT) {
            finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
            return false;
        }
        slot->chunk_line[slot->chunk_line_length++] = data[offset++];
        if (slot->chunk_line_length >= 2u &&
            slot->chunk_line[slot->chunk_line_length - 2u] == '\r' &&
            slot->chunk_line[slot->chunk_line_length - 1u] == '\n') {
            const size_t line_length = slot->chunk_line_length - 2u;
            if (slot->chunk_parser == CHUNK_SIZE) {
                uint64_t chunk_size;
                if (!parse_chunk_size(slot->chunk_line, line_length, &chunk_size) ||
                    chunk_size > state->opt.max_body_bytes ||
                    chunk_size > state->opt.max_body_bytes -
                        state->records[slot->request_sequence].body_bytes) {
                    finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                    return false;
                }
                slot->chunk_line_length = 0u;
                if (chunk_size == 0u) slot->chunk_parser = CHUNK_TRAILER;
                else {
                    slot->chunk_remaining = chunk_size;
                    slot->chunk_parser = CHUNK_DATA;
                }
            } else if (slot->chunk_parser == CHUNK_TRAILER) {
                slot->chunk_line_length = 0u;
                if (line_length == 0u) {
                    if (offset != length)
                        finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                    else
                        finish_response(state, slot_index);
                    return false;
                }
                if (!valid_trailer_line(slot->chunk_line, line_length)) {
                    finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                    return false;
                }
            }
        }
    }
    return true;
}

static bool process_body(app *state, size_t slot_index,
                         const unsigned char *data, size_t length) {
    client_slot *slot = &state->slots[slot_index];
    if (slot->body_framing == BODY_CLOSE) {
        if (!hash_body(state, slot_index, data, length)) {
            finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
            return false;
        }
        return true;
    }
    if (slot->body_framing == BODY_CHUNKED)
        return process_chunked(state, slot_index, data, length);
    if ((uint64_t)length > slot->body_remaining) {
        finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
        return false;
    }
    if (!hash_body(state, slot_index, data, length)) {
        finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
        return false;
    }
    slot->body_remaining -= (uint64_t)length;
    if (slot->body_remaining == 0u) {
        finish_response(state, slot_index);
        return false;
    }
    return true;
}

static bool process_received(app *state, size_t slot_index,
                             const unsigned char *data, size_t length) {
    client_slot *slot = &state->slots[slot_index];
    if (!slot->headers_complete) {
        size_t header_end = 0u;
        const size_t scan_start = slot->header_length < 3u
            ? 3u : slot->header_length;
        if (length > HEADER_BUFFER - slot->header_length) {
            finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
            return false;
        }
        memcpy(slot->header_buffer + slot->header_length, data, length);
        slot->header_length += length;
        for (size_t index = scan_start; index < slot->header_length; ++index) {
            if (slot->header_buffer[index - 3u] == '\r' &&
                slot->header_buffer[index - 2u] == '\n' &&
                slot->header_buffer[index - 1u] == '\r' &&
                slot->header_buffer[index] == '\n') {
                header_end = index + 1u;
                break;
            }
        }
        if (header_end == 0u) {
            if (slot->header_length > HEADER_LIMIT) {
                finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                return false;
            }
            return true;
        }
        if (header_end > HEADER_LIMIT ||
            !parse_headers(state, slot_index, header_end)) {
            finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
            return false;
        }
        if (state->records[slot->request_sequence].status >= 100 &&
            state->records[slot->request_sequence].status < 200) {
            const size_t remainder = slot->header_length - header_end;
            if (state->records[slot->request_sequence].status == 101) {
                finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
                return false;
            }
            memmove(slot->header_buffer,
                    slot->header_buffer + header_end, remainder);
            reset_response(slot);
            state->records[slot->request_sequence].status = 0;
            slot->header_length = remainder;
            if (remainder == 0u) return true;
            return process_received(
                state, slot_index, slot->header_buffer, 0u
            );
        }
        return process_body(state, slot_index,
            slot->header_buffer + header_end,
            slot->header_length - header_end);
    }
    return process_body(state, slot_index, data, length);
}

static bool reopen_stale_connection(app *state, size_t slot_index);

static void transport_error(app *state, size_t slot_index) {
    if (!reopen_stale_connection(state, slot_index))
        finish_error(state, slot_index, OUT_TRANSPORT_ERROR);
}

static void receive_response(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    unsigned char buffer[READ_BUFFER];
    unsigned read_count = 0u;
    for (;;) {
        const ssize_t received = recv(slot->fd, buffer, sizeof(buffer), 0);
        if (received > 0) {
            record *entry = &state->records[slot->request_sequence];
            if (entry->first_byte_ns == 0u) entry->first_byte_ns = now_ns();
            if (!process_received(state, slot_index, buffer, (size_t)received))
                return;
            if (++read_count == 16u) return;
            continue;
        }
        if (received == 0) {
            if (slot->headers_complete && slot->body_framing == BODY_CLOSE)
                finish_response(state, slot_index);
            else
                transport_error(state, slot_index);
            return;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        transport_error(state, slot_index);
        return;
    }
}

static void send_request(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    while (slot->request_sent < slot->request_length) {
        const ssize_t sent = send(slot->fd, slot->request + slot->request_sent,
                                  slot->request_length - slot->request_sent,
                                  MSG_NOSIGNAL);
        if (sent > 0) {
            slot->request_sent += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!epoll_set(state, slot_index, EPOLL_CTL_MOD, EPOLLOUT))
                transport_error(state, slot_index);
            return;
        }
        transport_error(state, slot_index);
        return;
    }
    if (state->opt.connection == CONN_RST) {
        finish_rst(state, slot_index);
        return;
    }
    slot->state = SLOT_RECEIVING;
    if (!epoll_set(state, slot_index, EPOLL_CTL_MOD, EPOLLIN))
        transport_error(state, slot_index);
}

static void connected(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    record *entry = &state->records[slot->request_sequence];
    entry->connected_ns = now_ns();
    slot->state = SLOT_SENDING;
    send_request(state, slot_index);
}

static bool open_connection(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    int result, enabled = 1;
    slot->fd = socket(state->address_family,
                      SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (slot->fd < 0) return false;
    (void)setsockopt(slot->fd, IPPROTO_TCP, TCP_NODELAY,
                     &enabled, sizeof(enabled));
    slot->connection_id = ++state->next_connection_id;
    slot->reuse_ordinal = 0u;
    slot->source_index = UINT32_MAX;
    if (state->opt.source_count != 0u) {
        const size_t source_index =
            (size_t)((slot->connection_id - 1u) % state->opt.source_count);
        slot->source_index = (uint32_t)source_index;
        if (slot->request_sequence != NO_REQUEST) {
            record *entry = &state->records[slot->request_sequence];
            entry->connection_id = slot->connection_id;
            entry->source_index = slot->source_index;
            entry->reuse_ordinal = 0u;
        }
        if (bind(slot->fd,
                 (const struct sockaddr *)&state->source_addresses[source_index],
                 state->source_lengths[source_index]) != 0) {
            close_slot(state, slot_index, false);
            return false;
        }
    } else if (slot->request_sequence != NO_REQUEST) {
        record *entry = &state->records[slot->request_sequence];
        entry->connection_id = slot->connection_id;
        entry->source_index = slot->source_index;
        entry->reuse_ordinal = 0u;
    }
    ++slot->generation;
    if (slot->generation == 0u) ++slot->generation;
    if (!epoll_set(state, slot_index, EPOLL_CTL_ADD, EPOLLOUT)) {
        close_slot(state, slot_index, false);
        return false;
    }
    result = connect(slot->fd,
                     (const struct sockaddr *)&state->remote_address,
                     state->remote_length);
    if (result == 0) {
        connected(state, slot_index);
        return true;
    }
    if (errno != EINPROGRESS) {
        close_slot(state, slot_index, false);
        return false;
    }
    slot->state = SLOT_CONNECTING;
    return true;
}

static bool reopen_stale_connection(app *state, size_t slot_index) {
    client_slot *slot = &state->slots[slot_index];
    record *entry;
    if (slot->request_sequence == NO_REQUEST) return false;
    entry = &state->records[slot->request_sequence];
    if (state->opt.connection != CONN_KEEPALIVE ||
        entry->reuse_ordinal == 0u || slot->stale_retry_used ||
        entry->first_byte_ns != 0u || slot->header_length != 0u)
        return false;
    slot->stale_retry_used = true;
    ++entry->stale_retries;
    close_slot(state, slot_index, false);
    reset_response(slot);
    entry->status = 0;
    entry->body_bytes = 0u;
    entry->connected_ns = 0u;
    entry->connection_id = 0u;
    entry->source_index = UINT32_MAX;
    entry->reuse_ordinal = 0u;
    entry->digest_valid = false;
    entry->matched_alternative = -1;
    slot->request_sent = 0u;
    if (EVP_DigestInit_ex(slot->digest_context, EVP_sha256(), NULL) != 1) {
        finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
        return true;
    }
    if (!open_connection(state, slot_index))
        finish_error(state, slot_index, OUT_TRANSPORT_ERROR);
    return true;
}

static uint64_t open_schedule(const app *state, uint64_t sequence) {
    const long double offset =
        ((long double)sequence * 1000000000.0L) / state->opt.rate;
    if (offset >= (long double)(UINT64_MAX - state->run_start_ns))
        return UINT64_MAX;
    return state->run_start_ns + (uint64_t)offset;
}

static bool start_request(app *state, size_t slot_index, uint64_t sequence,
                          uint64_t scheduled_ns) {
    client_slot *slot = &state->slots[slot_index];
    record *entry = &state->records[sequence];
    const uint64_t mixed = mix64(state->opt.seed ^ sequence);
    const size_t target_index = (size_t)(mixed % state->target_count);
    target *request_target = &state->targets[target_index];
    memset(entry, 0, sizeof(*entry));
    entry->sequence = sequence;
    entry->scheduled_ns = scheduled_ns;
    entry->started_ns = now_ns();
    entry->target_index = (uint32_t)target_index;
    entry->source_index = UINT32_MAX;
    entry->matched_alternative = -1;
    slot->request_sequence = sequence;
    slot->request_sent = 0u;
    slot->stale_retry_used = false;
    reset_response(slot);
    ++state->active;
    if (EVP_DigestInit_ex(slot->digest_context, EVP_sha256(), NULL) != 1) {
        finish_error(state, slot_index, OUT_PROTOCOL_ERROR);
        return false;
    }
    if (state->opt.connection == CONN_FIN) {
        slot->request = request_target->request_close;
        slot->request_length = request_target->request_close_length;
    } else {
        slot->request = request_target->request_keepalive;
        slot->request_length = request_target->request_keepalive_length;
    }
    if (slot->fd >= 0 && state->opt.connection == CONN_KEEPALIVE) {
        entry->connection_id = slot->connection_id;
        entry->source_index = slot->source_index;
        entry->reuse_ordinal = ++slot->reuse_ordinal;
        slot->state = SLOT_SENDING;
        send_request(state, slot_index);
        return true;
    }
    if (slot->fd >= 0) close_slot(state, slot_index, false);
    if (!open_connection(state, slot_index)) {
        finish_error(state, slot_index, OUT_TRANSPORT_ERROR);
        return false;
    }
    return true;
}

static size_t find_idle(const app *state) {
    for (size_t index = 0u; index < state->opt.concurrency; ++index) {
        if (state->slots[index].state == SLOT_IDLE &&
            state->slots[index].request_sequence == NO_REQUEST) return index;
    }
    return SIZE_MAX;
}

static void dispatch_closed(app *state) {
    while (state->next_closed_sequence < state->opt.request_count) {
        const size_t slot_index = find_idle(state);
        uint64_t scheduled;
        if (slot_index == SIZE_MAX) return;
        scheduled = now_ns();
        (void)start_request(state, slot_index,
                            state->next_closed_sequence, scheduled);
        ++state->next_closed_sequence;
    }
}

static void arrive_open(app *state, uint64_t now) {
    while (state->open_arrived < state->opt.request_count &&
           open_schedule(state, state->open_arrived) <= now) {
        state->records[state->open_arrived].scheduled_ns =
            open_schedule(state, state->open_arrived);
        ++state->open_arrived;
    }
    if (state->open_arrived - state->open_assigned > state->max_pending)
        state->max_pending = state->open_arrived - state->open_assigned;
}

static void dispatch_open(app *state) {
    while (state->open_assigned < state->open_arrived) {
        const size_t slot_index = find_idle(state);
        const uint64_t sequence = state->open_assigned;
        if (slot_index == SIZE_MAX) return;
        (void)start_request(state, slot_index, sequence,
                            state->records[sequence].scheduled_ns);
        ++state->open_assigned;
    }
}

static void check_timeouts(app *state, uint64_t now) {
    for (size_t index = 0u; index < state->opt.concurrency; ++index) {
        client_slot *slot = &state->slots[index];
        if (slot->request_sequence != NO_REQUEST) {
            const record *entry = &state->records[slot->request_sequence];
            if (now - entry->started_ns >= state->opt.timeout_ns)
                finish_error(state, index, OUT_TIMEOUT);
        }
    }
}

static int wait_timeout_ms(const app *state, uint64_t now) {
    uint64_t wait_ns = UINT64_C(100000000);
    if (state->opt.mode == MODE_OPEN &&
        state->open_arrived < state->opt.request_count) {
        const uint64_t next = open_schedule(state, state->open_arrived);
        if (next <= now) return 0;
        if (next - now < wait_ns) wait_ns = next - now;
    }
    for (size_t index = 0u; index < state->opt.concurrency; ++index) {
        const client_slot *slot = &state->slots[index];
        if (slot->request_sequence != NO_REQUEST) {
            const record *entry = &state->records[slot->request_sequence];
            const uint64_t deadline = entry->started_ns + state->opt.timeout_ns;
            if (deadline <= now) return 0;
            if (deadline - now < wait_ns) wait_ns = deadline - now;
        }
    }
    return (int)((wait_ns + UINT64_C(999999)) / UINT64_C(1000000));
}

static void handle_event(app *state, const struct epoll_event *event) {
    const size_t slot_index = (size_t)(uint32_t)event->data.u64;
    const uint32_t generation = (uint32_t)(event->data.u64 >> 32);
    client_slot *slot;
    if (slot_index >= state->opt.concurrency) return;
    slot = &state->slots[slot_index];
    if (slot->generation != generation || slot->fd < 0) return;
    if (slot->state == SLOT_IDLE) {
        if ((event->events &
             (EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR)) != 0u)
            close_slot(state, slot_index, false);
        return;
    }
    if (slot->state == SLOT_CONNECTING &&
        (event->events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) != 0u) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(slot->fd, SOL_SOCKET, SO_ERROR,
                       &error, &length) != 0 || error != 0) {
            finish_error(state, slot_index, OUT_TRANSPORT_ERROR);
            return;
        }
        connected(state, slot_index);
        return;
    }
    if (slot->state == SLOT_SENDING && (event->events & EPOLLOUT) != 0u) {
        send_request(state, slot_index);
        return;
    }
    if (slot->state == SLOT_RECEIVING &&
        (event->events &
         (EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR)) != 0u) {
        receive_response(state, slot_index);
        if (slot->state == SLOT_IDLE && slot->fd >= 0 &&
            (event->events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) != 0u)
            close_slot(state, slot_index, false);
        return;
    }
    if ((event->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0u)
        transport_error(state, slot_index);
}

static bool run_load(app *state) {
    struct epoll_event events[MAX_EVENTS];
    bool event_loop_failed = false;
    state->run_start_ns = now_ns() +
        (state->opt.mode == MODE_OPEN ? UINT64_C(10000000) : 0u);
    if (state->opt.mode == MODE_CLOSED) dispatch_closed(state);
    while (state->completed < state->opt.request_count && !interrupted) {
        uint64_t now = now_ns();
        int event_count;
        check_timeouts(state, now);
        if (state->opt.mode == MODE_OPEN) {
            arrive_open(state, now);
            dispatch_open(state);
        } else {
            dispatch_closed(state);
        }
        if (state->completed == state->opt.request_count) break;
        now = now_ns();
        event_count = epoll_wait(state->epoll_fd, events, MAX_EVENTS,
                                 wait_timeout_ms(state, now));
        if (event_count < 0) {
            if (errno == EINTR) continue;
            (void)fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
            event_loop_failed = true;
            break;
        }
        for (int index = 0; index < event_count; ++index)
            handle_event(state, &events[index]);
    }
    if (interrupted || state->completed != state->opt.request_count) {
        for (size_t index = 0u; index < state->opt.concurrency; ++index) {
            if (state->slots[index].request_sequence != NO_REQUEST)
                finish_error(state, index, OUT_CANCELED);
            else
                close_slot(state, index, false);
        }
        uint64_t *next = state->opt.mode == MODE_OPEN
            ? &state->open_assigned : &state->next_closed_sequence;
        while (*next < state->opt.request_count) {
            record *entry = &state->records[*next];
            memset(entry, 0, sizeof(*entry));
            entry->sequence = *next;
            if (state->opt.mode == MODE_OPEN)
                entry->scheduled_ns = open_schedule(state, *next);
            entry->end_ns = now_ns();
            entry->source_index = UINT32_MAX;
            entry->matched_alternative = -1;
            entry->result = OUT_CANCELED;
            ++*next;
            ++state->completed;
        }
    }
    state->run_end_ns = now_ns();
    return !interrupted && !event_loop_failed;
}

static FILE *open_exclusive(const char *path) {
    const int descriptor = open(path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    FILE *stream;
    if (descriptor < 0) return NULL;
    stream = fdopen(descriptor, "w");
    if (stream == NULL) (void)close(descriptor);
    return stream;
}

static bool write_records(const app *state) {
    FILE *stream = open_exclusive(state->opt.records_path);
    if (stream == NULL) {
        (void)fprintf(stderr, "create records: %s\n", strerror(errno));
        return false;
    }
    (void)setvbuf(stream, NULL, _IOFBF, (size_t)1024u * (size_t)1024u);
    (void)fprintf(stream,
        "# fastbed-http-loadgen-records-v1 clock=CLOCK_MONOTONIC_RAW\n"
        "sequence\ttarget_index\tsource_index\tscheduled_ns\tstarted_ns\t"
        "connected_ns\tfirst_byte_ns\tend_ns\tqueue_delay_ns\tservice_ns\t"
        "status\tbody_bytes\tconnection_id\treuse_ordinal\t"
        "stale_retries\tmatched_alternative\toutcome\tactual_sha256\n");
    for (uint64_t index = 0u; index < state->opt.request_count; ++index) {
        const record *entry = &state->records[index];
        char digest[65] = "-";
        const uint64_t queue_delay = entry->started_ns >= entry->scheduled_ns
            ? entry->started_ns - entry->scheduled_ns : 0u;
        const uint64_t service = entry->end_ns >= entry->started_ns
            ? entry->end_ns - entry->started_ns : 0u;
        if (entry->digest_valid) digest_hex(entry->digest, digest);
        (void)fprintf(stream, "%" PRIu64 "\t%" PRIu32 "\t",
                      entry->sequence, entry->target_index);
        if (entry->source_index == UINT32_MAX) (void)fputs("-1\t", stream);
        else (void)fprintf(stream, "%" PRIu32 "\t", entry->source_index);
        (void)fprintf(stream,
            "%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%d\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu32 "\t%" PRIu32 "\t%d\t%s\t%s\n",
            entry->scheduled_ns, entry->started_ns, entry->connected_ns,
            entry->first_byte_ns, entry->end_ns, queue_delay, service,
            entry->status, entry->body_bytes, entry->connection_id,
            entry->reuse_ordinal, entry->stale_retries,
            entry->matched_alternative,
            outcome_name(entry->result), digest);
    }
    if (fclose(stream) != 0) {
        (void)fprintf(stderr, "close records: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static void json_string(FILE *stream, const char *value) {
    (void)fputc('"', stream);
    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor != '\0'; ++cursor) {
        switch (*cursor) {
        case '"': (void)fputs("\\\"", stream); break;
        case '\\': (void)fputs("\\\\", stream); break;
        case '\b': (void)fputs("\\b", stream); break;
        case '\f': (void)fputs("\\f", stream); break;
        case '\n': (void)fputs("\\n", stream); break;
        case '\r': (void)fputs("\\r", stream); break;
        case '\t': (void)fputs("\\t", stream); break;
        default:
            if (*cursor < 0x20u)
                (void)fprintf(stream, "\\u%04x", (unsigned)*cursor);
            else
                (void)fputc((int)*cursor, stream);
            break;
        }
    }
    (void)fputc('"', stream);
}

static bool write_summary(const app *state, bool run_completed,
                          uint64_t counts[OUT_CANCELED + 1u],
                          uint64_t total_body_bytes,
                          uint64_t total_stale_retries) {
    FILE *stream = open_exclusive(state->opt.summary_path);
    const uint64_t errors = state->opt.request_count -
        counts[OUT_OK] - counts[OUT_CLIENT_RST];
    if (stream == NULL) {
        (void)fprintf(stderr, "create summary: %s\n", strerror(errno));
        return false;
    }
    (void)fputs(
        "{\n  \"schema\": \"fastbed-http-loadgen-summary-v1\",\n"
        "  \"clock\": \"CLOCK_MONOTONIC_RAW\",\n", stream);
    (void)fprintf(stream, "  \"run_completed\": %s,\n",
                  run_completed ? "true" : "false");
    (void)fputs("  \"host\": ", stream);
    json_string(stream, state->opt.host);
    (void)fprintf(stream,
        ",\n  \"port\": %u,\n  \"mode\": \"%s\",\n"
        "  \"connection_mode\": \"%s\",\n"
        "  \"seed\": %" PRIu64 ",\n"
        "  \"target_count\": %zu,\n"
        "  \"concurrency\": %zu,\n"
        "  \"requests_planned\": %" PRIu64 ",\n"
        "  \"requests_completed\": %" PRIu64 ",\n"
        "  \"ok\": %" PRIu64 ",\n"
        "  \"status_mismatch\": %" PRIu64 ",\n"
        "  \"hash_mismatch\": %" PRIu64 ",\n"
        "  \"protocol_error\": %" PRIu64 ",\n"
        "  \"transport_error\": %" PRIu64 ",\n"
        "  \"timeout\": %" PRIu64 ",\n"
        "  \"client_rst\": %" PRIu64 ",\n"
        "  \"canceled\": %" PRIu64 ",\n"
        "  \"errors\": %" PRIu64 ",\n"
        "  \"body_bytes\": %" PRIu64 ",\n"
        "  \"connections_opened\": %" PRIu64 ",\n"
        "  \"stale_keepalive_retries\": %" PRIu64 ",\n"
        "  \"max_pending\": %" PRIu64 ",\n"
        "  \"run_start_ns\": %" PRIu64 ",\n"
        "  \"run_end_ns\": %" PRIu64 ",\n"
        "  \"elapsed_ns\": %" PRIu64 ",\n",
        state->opt.port, schedule_name(state->opt.mode),
        connection_name(state->opt.connection), state->opt.seed,
        state->target_count, state->opt.concurrency, state->opt.request_count,
        state->completed, counts[OUT_OK], counts[OUT_STATUS_MISMATCH],
        counts[OUT_HASH_MISMATCH], counts[OUT_PROTOCOL_ERROR],
        counts[OUT_TRANSPORT_ERROR], counts[OUT_TIMEOUT],
        counts[OUT_CLIENT_RST], counts[OUT_CANCELED], errors,
        total_body_bytes, state->next_connection_id, total_stale_retries,
        state->max_pending,
        state->run_start_ns, state->run_end_ns,
        state->run_end_ns >= state->run_start_ns
            ? state->run_end_ns - state->run_start_ns : 0u);
    if (state->opt.mode == MODE_OPEN)
        (void)fprintf(stream, "  \"rate\": %.9Lf,\n", state->opt.rate);
    else
        (void)fputs("  \"rate\": null,\n", stream);
    (void)fputs("  \"source_addresses\": [", stream);
    for (size_t index = 0u; index < state->opt.source_count; ++index) {
        if (index != 0u) (void)fputs(", ", stream);
        json_string(stream, state->opt.source_text[index]);
    }
    (void)fputs("]\n}\n", stream);
    if (fclose(stream) != 0) {
        (void)fprintf(stderr, "close summary: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static void cleanup(app *state) {
    if (state->slots != NULL) {
        for (size_t index = 0u; index < state->opt.concurrency; ++index) {
            close_slot(state, index, false);
            EVP_MD_CTX_free(state->slots[index].digest_context);
        }
    }
    if (state->epoll_fd >= 0) (void)close(state->epoll_fd);
    free(state->slots);
    free(state->records);
    free_targets(state);
}

int main(int argc, char **argv) {
    app state;
    struct sigaction action;
    bool run_completed, records_written, summary_written;
    uint64_t counts[OUT_CANCELED + 1u] = {0u};
    uint64_t total_body_bytes = 0u;
    uint64_t total_stale_retries = 0u;
    memset(&state, 0, sizeof(state));
    state.epoll_fd = -1;
    if (!parse_options(argc, argv, &state.opt)) {
        usage(stderr, argv[0]);
        return 2;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    (void)sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)signal(SIGPIPE, SIG_IGN);
    if (!load_targets(&state) || !resolve_addresses(&state)) {
        cleanup(&state);
        return 2;
    }
    if (state.target_count > UINT32_MAX) {
        (void)fprintf(stderr, "too many workload targets\n");
        cleanup(&state);
        return 2;
    }
    if (state.opt.request_count > SIZE_MAX / sizeof(*state.records)) {
        (void)fprintf(stderr, "request record allocation is too large\n");
        cleanup(&state);
        return 2;
    }
    state.records = calloc((size_t)state.opt.request_count,
                           sizeof(*state.records));
    state.slots = calloc(state.opt.concurrency, sizeof(*state.slots));
    state.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (state.records == NULL || state.slots == NULL || state.epoll_fd < 0) {
        (void)fprintf(stderr, "load generator allocation/setup failed\n");
        cleanup(&state);
        return 2;
    }
    for (size_t index = 0u; index < state.opt.concurrency; ++index) {
        state.slots[index].fd = -1;
        state.slots[index].request_sequence = NO_REQUEST;
        state.slots[index].source_index = UINT32_MAX;
    }
    for (size_t index = 0u; index < state.opt.concurrency; ++index) {
        state.slots[index].digest_context = EVP_MD_CTX_new();
        if (state.slots[index].digest_context == NULL) {
            (void)fprintf(stderr, "SHA-256 context allocation failed\n");
            cleanup(&state);
            return 2;
        }
    }
    run_completed = run_load(&state);
    for (uint64_t index = 0u; index < state.opt.request_count; ++index) {
        const record *entry = &state.records[index];
        if (entry->result <= OUT_CANCELED) ++counts[entry->result];
        total_body_bytes += entry->body_bytes;
        total_stale_retries += entry->stale_retries;
    }
    records_written = write_records(&state);
    summary_written = write_summary(&state, run_completed, counts,
                                     total_body_bytes, total_stale_retries);
    const uint64_t errors = state.opt.request_count -
                            counts[OUT_OK] - counts[OUT_CLIENT_RST];
    const bool expected_rst = state.opt.connection == CONN_RST &&
        counts[OUT_CLIENT_RST] == state.opt.request_count;
    const bool success = records_written && summary_written && run_completed &&
        errors == 0u &&
        (expected_rst || counts[OUT_OK] == state.opt.request_count);
    cleanup(&state);
    return success ? 0 : 1;
}
