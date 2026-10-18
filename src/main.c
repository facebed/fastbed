#include "fastbed/app.h"
#include "fastbed/config.h"
#include "fastbed/server.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

#ifndef FASTBED_VERSION
#define FASTBED_VERSION "development"
#endif

#define FB_MAX_WORKERS 256u
#define FB_MAX_AFFINITY_CPUS (1024u * 1024u)
#define FB_SHUTDOWN_WATCHDOG_SECONDS 75u
#define FB_SHUTDOWN_WATCHDOG_EXIT_CODE 124

typedef struct {
    const char *config_path;
#if defined(FASTBED_VERIFICATION_BUILD)
    const char *asset_directory;
    const char *crawler_database;
#endif
    unsigned workers;
    size_t max_body_bytes;
#if defined(FASTBED_VERIFICATION_BUILD)
    bool allow_stock_curl;
    unsigned replay_http_port;
    unsigned replay_https_port;
#endif
    unsigned request_timeout_seconds;
    unsigned graceful_shutdown_seconds;
    bool internal_cache;
} fb_cli;

typedef struct {
    pthread_t thread;
    struct timespec deadline;
} fb_shutdown_watchdog;

static bool fb_harden_process(char *error, size_t error_capacity) {
#if defined(__linux__)
    const struct rlimit core_limit = {0, 0};
    int core_error = 0;
    int dumpable_error = 0;

    if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
        core_error = errno;
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        dumpable_error = errno;
    }
    if (core_error != 0 && dumpable_error != 0) {
        (void)snprintf(error, error_capacity,
                       "cannot disable core dumps: %s; cannot make process "
                       "non-dumpable: %s",
                       strerror(core_error), strerror(dumpable_error));
        return false;
    }
    if (core_error != 0) {
        (void)snprintf(error, error_capacity,
                       "cannot disable core dumps: %s",
                       strerror(core_error));
        return false;
    }
    if (dumpable_error != 0) {
        (void)snprintf(error, error_capacity,
                       "cannot make process non-dumpable: %s",
                       strerror(dumpable_error));
        return false;
    }
#else
    (void)error;
    (void)error_capacity;
#endif
    return true;
}

static _Noreturn void fb_hardening_failure(const char *detail) {
    char message[640];
    const int length = snprintf(message, sizeof(message),
                                "process hardening error: %s\n", detail);
    const int flags = fcntl(STDERR_FILENO, F_GETFL, 0);
    int nonblocking = -1;

    if (flags >= 0) {
        nonblocking = fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK);
    }
    if (nonblocking == 0 && length > 0) {
        const size_t bytes = (size_t)length < sizeof(message)
            ? (size_t)length : sizeof(message) - 1u;
        /* O_NONBLOCK has no effect on every file type; bound even a hung sink. */
        (void)alarm(1u);
        const ssize_t written = write(STDERR_FILENO, message, bytes);
        (void)written;
    }
    _Exit(EXIT_FAILURE);
}

static _Noreturn void fb_shutdown_watchdog_expire(void) {
    /* Do not risk blocking on logging or touch state owned by stuck threads. */
    _Exit(FB_SHUTDOWN_WATCHDOG_EXIT_CODE);
}

static void *fb_shutdown_watchdog_main(void *opaque) {
    fb_shutdown_watchdog *watchdog = opaque;
    int status;

    do {
        status = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                                 &watchdog->deadline, NULL);
        if (status != 0 && status != EINTR) {
            fb_shutdown_watchdog_expire();
        }
    } while (status == EINTR);
    fb_shutdown_watchdog_expire();
}

static bool fb_shutdown_watchdog_start(fb_shutdown_watchdog *watchdog) {
    memset(watchdog, 0, sizeof(*watchdog));
    if (clock_gettime(CLOCK_MONOTONIC, &watchdog->deadline) != 0) {
        return false;
    }
    watchdog->deadline.tv_sec += (time_t)FB_SHUTDOWN_WATCHDOG_SECONDS;
    return pthread_create(&watchdog->thread, NULL,
                          fb_shutdown_watchdog_main, watchdog) == 0;
}

static void fb_usage(FILE *stream, const char *program) {
    (void)fprintf(stream,
        "usage: %s [-c FILE] [options]\n"
        "\n"
        "  -c, --config FILE       strict Facebed-compatible YAML config\n"
        "  -w, --workers N         HTTP workers (default: affinity/cgroup sized)\n"
        "      --max-body-mib N    upstream response cap (default: 32 MiB)\n"
        "      --request-timeout-seconds N request deadline, 1..86400 (default: 3600)\n"
        "      --graceful-shutdown-seconds N drain grace, 1..30 (default: 30)\n"
        "      --internal-cache    enable bounded internal post cache (default: off)\n",
        program);
#if defined(FASTBED_VERIFICATION_BUILD)
    (void)fprintf(stream,
        "\n"
        "verification-build controls:\n"
        "      --assets DIR           override embedded assets\n"
        "      --crawler-db FILE      override embedded crawler database\n"
        "      --allow-stock-curl     allow non-impersonating transport\n"
        "      --replay-http-port N   loopback HTTP upstream\n"
        "      --replay-https-port N  loopback HTTPS upstream\n");
#endif
    (void)fprintf(stream,
        "  -V, --version           print version\n"
        "  -h, --help              show this help\n");
}

static bool fb_parse_unsigned(const char *text, unsigned *value) {
    char *end = NULL;
    unsigned long parsed;
    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return false;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT_MAX) {
        return false;
    }
    *value = (unsigned)parsed;
    return true;
}

static bool fb_safe_absolute_path(char *path) {
    size_t length;
    const char *component;
    if (path == NULL || path[0] != '/') {
        return false;
    }
    length = strlen(path);
    while (length > 1u && path[length - 1u] == '/') {
        path[--length] = '\0';
    }
    component = path + 1u;
    while (*component != '\0') {
        const char *slash = strchr(component, '/');
        const size_t component_length = slash == NULL
            ? strlen(component) : (size_t)(slash - component);
        if (component_length == 0u ||
            (component_length == 1u && component[0] == '.') ||
            (component_length == 2u && component[0] == '.' &&
             component[1] == '.')) {
            return false;
        }
        if (slash == NULL) {
            break;
        }
        component = slash + 1u;
    }
    return true;
}

static bool fb_decode_mount_path(const char *encoded, char *decoded,
                                 size_t capacity) {
    size_t output = 0u;
    if (encoded == NULL || capacity == 0u) {
        return false;
    }
    for (size_t input = 0u; encoded[input] != '\0'; ++input) {
        unsigned value;
        if (output + 1u >= capacity) {
            return false;
        }
        if (encoded[input] != '\\') {
            decoded[output++] = encoded[input];
            continue;
        }
        if (encoded[input + 1u] == '\0' || encoded[input + 2u] == '\0' ||
            encoded[input + 3u] == '\0' ||
            encoded[input + 1u] < '0' || encoded[input + 1u] > '7' ||
            encoded[input + 2u] < '0' || encoded[input + 2u] > '7' ||
            encoded[input + 3u] < '0' || encoded[input + 3u] > '7') {
            return false;
        }
        value = (unsigned)(encoded[input + 1u] - '0') * 64u +
                (unsigned)(encoded[input + 2u] - '0') * 8u +
                (unsigned)(encoded[input + 3u] - '0');
        if (value == 0u || value > UCHAR_MAX) {
            return false;
        }
        decoded[output++] = (char)value;
        input += 3u;
    }
    decoded[output] = '\0';
    return fb_safe_absolute_path(decoded);
}

static bool fb_path_has_prefix(const char *path, const char *prefix) {
    const size_t prefix_length = strlen(prefix);
    if (prefix_length == 1u && prefix[0] == '/') {
        return path[0] == '/';
    }
    return strncmp(path, prefix, prefix_length) == 0 &&
           (path[prefix_length] == '\0' || path[prefix_length] == '/');
}

static bool fb_read_cgroup_path(char *path, size_t capacity) {
    FILE *stream = fopen("/proc/self/cgroup", "r");
    char *line = NULL;
    size_t line_capacity = 0u;
    bool found = false;
    if (stream == NULL) {
        return false;
    }
    while (getline(&line, &line_capacity, stream) >= 0) {
        size_t length;
        if (strncmp(line, "0::/", 4u) != 0) {
            continue;
        }
        length = strlen(line + 3u);
        if (length > 0u && line[3u + length - 1u] == '\n') {
            --length;
        }
        if (length == 0u || length >= capacity) {
            break;
        }
        memcpy(path, line + 3u, length);
        path[length] = '\0';
        found = fb_safe_absolute_path(path);
        break;
    }
    free(line);
    (void)fclose(stream);
    return found;
}

static bool fb_find_cgroup2_mount(const char *cgroup_path,
                                  char *mount_root, size_t root_capacity,
                                  char *mount_point, size_t point_capacity) {
    FILE *stream = fopen("/proc/self/mountinfo", "r");
    char *line = NULL;
    size_t line_capacity = 0u;
    size_t best_root_length = 0u;
    bool found = false;
    if (stream == NULL) {
        return false;
    }
    while (getline(&line, &line_capacity, stream) >= 0) {
        char *save = NULL;
        char *token = strtok_r(line, " \n", &save);
        const char *encoded_root = NULL;
        const char *encoded_point = NULL;
        char root[PATH_MAX];
        char point[PATH_MAX];
        size_t field = 0u;
        bool cgroup2 = false;
        while (token != NULL) {
            if (field == 3u) {
                encoded_root = token;
            } else if (field == 4u) {
                encoded_point = token;
            } else if (strcmp(token, "-") == 0) {
                token = strtok_r(NULL, " \n", &save);
                cgroup2 = token != NULL && strcmp(token, "cgroup2") == 0;
                break;
            }
            ++field;
            token = strtok_r(NULL, " \n", &save);
        }
        if (!cgroup2 || encoded_root == NULL || encoded_point == NULL ||
            !fb_decode_mount_path(encoded_root, root, sizeof(root)) ||
            !fb_decode_mount_path(encoded_point, point, sizeof(point)) ||
            !fb_path_has_prefix(cgroup_path, root)) {
            continue;
        }
        if (!found || strlen(root) > best_root_length) {
            const size_t root_length = strlen(root);
            const size_t point_length = strlen(point);
            if (root_length >= root_capacity || point_length >= point_capacity) {
                continue;
            }
            memcpy(mount_root, root, root_length + 1u);
            memcpy(mount_point, point, point_length + 1u);
            best_root_length = root_length;
            found = true;
        }
    }
    free(line);
    (void)fclose(stream);
    return found;
}

static bool fb_uint64_token(const char *token, uint64_t *value) {
    uint64_t parsed = 0u;
    if (token == NULL || token[0] == '\0') {
        return false;
    }
    for (size_t index = 0u; token[index] != '\0'; ++index) {
        const unsigned digit = (unsigned)(token[index] - '0');
        if (token[index] < '0' || token[index] > '9' ||
            parsed > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        parsed = parsed * 10u + digit;
    }
    *value = parsed;
    return true;
}

static bool fb_cpu_max_ceiling(const char *directory, unsigned *ceiling) {
    char path[PATH_MAX];
    char line[192];
    char quota_token[64];
    char period_token[64];
    char extra[2];
    uint64_t quota;
    uint64_t period;
    uint64_t cpus;
    FILE *stream;
    const int length = snprintf(path, sizeof(path), "%s%s%s", directory,
                                strcmp(directory, "/") == 0 ? "" : "/",
                                "cpu.max");
    if (length < 0 || (size_t)length >= sizeof(path)) {
        return false;
    }
    stream = fopen(path, "r");
    if (stream == NULL) {
        return false;
    }
    if (fgets(line, sizeof(line), stream) == NULL ||
        (strchr(line, '\n') == NULL && !feof(stream))) {
        (void)fclose(stream);
        return false;
    }
    (void)fclose(stream);
    if (sscanf(line, " %63s %63s %1s", quota_token, period_token, extra) != 2 ||
        !fb_uint64_token(period_token, &period) || period == 0u) {
        return false;
    }
    if (strcmp(quota_token, "max") == 0) {
        return false;
    }
    if (!fb_uint64_token(quota_token, &quota) || quota == 0u) {
        return false;
    }
    cpus = quota / period;
    if (quota % period != 0u) {
        ++cpus;
    }
    *ceiling = cpus > FB_MAX_WORKERS ? FB_MAX_WORKERS : (unsigned)cpus;
    return true;
}

static unsigned fb_cgroup_worker_ceiling(void) {
    char cgroup_path[PATH_MAX];
    char mount_root[PATH_MAX];
    char mount_point[PATH_MAX];
    char directory[PATH_MAX];
    const char *suffix;
    size_t mount_length;
    unsigned tightest = 0u;
    if (!fb_read_cgroup_path(cgroup_path, sizeof(cgroup_path)) ||
        !fb_find_cgroup2_mount(cgroup_path, mount_root, sizeof(mount_root),
                               mount_point, sizeof(mount_point))) {
        return 0u;
    }
    suffix = strcmp(mount_root, "/") == 0
        ? cgroup_path : cgroup_path + strlen(mount_root);
    if (strcmp(suffix, "/") == 0) {
        suffix = "";
    }
    {
        const int length = strcmp(mount_point, "/") == 0
            ? snprintf(directory, sizeof(directory), "%s",
                       suffix[0] == '\0' ? "/" : suffix)
            : snprintf(directory, sizeof(directory), "%s%s",
                       mount_point, suffix);
        if (length < 0 || (size_t)length >= sizeof(directory) ||
            !fb_safe_absolute_path(directory) ||
            !fb_path_has_prefix(directory, mount_point)) {
            return 0u;
        }
    }
    mount_length = strlen(mount_point);
    for (;;) {
        unsigned ceiling;
        if (fb_cpu_max_ceiling(directory, &ceiling) &&
            (tightest == 0u || ceiling < tightest)) {
            tightest = ceiling;
        }
        if (strcmp(directory, mount_point) == 0) {
            break;
        }
        {
            char *slash = strrchr(directory, '/');
            if (slash == NULL) {
                break;
            }
            if (slash == directory) {
                if (strcmp(mount_point, "/") != 0) {
                    break;
                }
                directory[1u] = '\0';
            } else {
                if ((size_t)(slash - directory) < mount_length) {
                    break;
                }
                *slash = '\0';
            }
        }
    }
    return tightest;
}

static unsigned fb_affinity_worker_ceiling(void) {
    size_t cpu_capacity = (size_t)CPU_SETSIZE;
    const long configured = sysconf(_SC_NPROCESSORS_CONF);
    if (configured > 0 && (uint64_t)configured <= FB_MAX_AFFINITY_CPUS &&
        (size_t)configured > cpu_capacity) {
        cpu_capacity = (size_t)configured;
    }
    for (;;) {
        const size_t set_size = CPU_ALLOC_SIZE(cpu_capacity);
        cpu_set_t *affinity = CPU_ALLOC(cpu_capacity);
        int affinity_error;
        unsigned count = 0u;
        if (affinity == NULL) {
            return 1u;
        }
        CPU_ZERO_S(set_size, affinity);
        if (sched_getaffinity(0, set_size, affinity) == 0) {
            for (size_t cpu = 0u; cpu < cpu_capacity && count < FB_MAX_WORKERS;
                 ++cpu) {
                if (CPU_ISSET_S(cpu, set_size, affinity)) {
                    ++count;
                }
            }
            CPU_FREE(affinity);
            return count == 0u ? 1u : count;
        }
        affinity_error = errno;
        CPU_FREE(affinity);
        if (affinity_error != EINVAL || cpu_capacity >= FB_MAX_AFFINITY_CPUS) {
            return 1u;
        }
        cpu_capacity = cpu_capacity > FB_MAX_AFFINITY_CPUS / 2u
            ? FB_MAX_AFFINITY_CPUS : cpu_capacity * 2u;
    }
}

static unsigned fb_default_workers(void) {
    unsigned workers = fb_affinity_worker_ceiling();
    const unsigned cgroup_ceiling = fb_cgroup_worker_ceiling();
    if (cgroup_ceiling != 0u && cgroup_ceiling < workers) {
        workers = cgroup_ceiling;
    }
    return workers;
}

static bool fb_cli_parse(int argc, char **argv, fb_cli *cli) {
    static const struct option options[] = {
        {"config", required_argument, NULL, 'c'},
#if defined(FASTBED_VERIFICATION_BUILD)
        {"assets", required_argument, NULL, 1000},
        {"crawler-db", required_argument, NULL, 1001},
#endif
        {"workers", required_argument, NULL, 'w'},
        {"max-body-mib", required_argument, NULL, 1002},
#if defined(FASTBED_VERIFICATION_BUILD)
        {"allow-stock-curl", no_argument, NULL, 1003},
        {"replay-http-port", required_argument, NULL, 1004},
        {"replay-https-port", required_argument, NULL, 1005},
#endif
        {"internal-cache", no_argument, NULL, 1006},
        {"request-timeout-seconds", required_argument, NULL, 1007},
        {"graceful-shutdown-seconds", required_argument, NULL, 1008},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;
    memset(cli, 0, sizeof(*cli));
#if defined(FASTBED_VERIFICATION_BUILD)
    cli->asset_directory = getenv("FASTBED_ASSET_DIR");
    cli->crawler_database = getenv("FASTBED_CRAWLER_DB");
    if (cli->asset_directory != NULL && cli->asset_directory[0] == '\0') {
        cli->asset_directory = NULL;
    }
    if (cli->crawler_database != NULL && cli->crawler_database[0] == '\0') {
        cli->crawler_database = NULL;
    }
#endif
    cli->workers = fb_default_workers();
    cli->max_body_bytes = 32u * 1024u * 1024u;
    cli->request_timeout_seconds = 3600u;
    cli->graceful_shutdown_seconds = 30u;
    while ((option = getopt_long(argc, argv, "c:w:Vh", options, NULL)) != -1) {
        unsigned parsed;
        switch (option) {
        case 'c':
            cli->config_path = optarg;
            break;
        case 'w':
            if (!fb_parse_unsigned(optarg, &parsed) || parsed == 0u ||
                parsed > FB_MAX_WORKERS) {
                (void)fprintf(stderr, "invalid worker count\n");
                return false;
            }
            cli->workers = parsed;
            break;
        case 'V':
            (void)printf("fastbed %s\n", FASTBED_VERSION);
            exit(EXIT_SUCCESS);
        case 'h':
            fb_usage(stdout, argv[0]);
            exit(EXIT_SUCCESS);
#if defined(FASTBED_VERIFICATION_BUILD)
        case 1000:
            cli->asset_directory = optarg;
            break;
        case 1001:
            cli->crawler_database = optarg;
            break;
#endif
        case 1002:
            if (!fb_parse_unsigned(optarg, &parsed) || parsed == 0u || parsed > 1024u) {
                (void)fprintf(stderr, "invalid upstream body cap\n");
                return false;
            }
            cli->max_body_bytes = (size_t)parsed * 1024u * 1024u;
            break;
#if defined(FASTBED_VERIFICATION_BUILD)
        case 1003:
            cli->allow_stock_curl = true;
            break;
        case 1004:
            if (!fb_parse_unsigned(optarg, &parsed) || parsed == 0u ||
                parsed > 65535u) {
                (void)fprintf(stderr, "invalid replay HTTP port\n");
                return false;
            }
            cli->replay_http_port = parsed;
            break;
        case 1005:
            if (!fb_parse_unsigned(optarg, &parsed) || parsed == 0u ||
                parsed > 65535u) {
                (void)fprintf(stderr, "invalid replay HTTPS port\n");
                return false;
            }
            cli->replay_https_port = parsed;
            break;
#endif
        case 1006:
            cli->internal_cache = true;
            break;
        case 1007:
            if (!fb_parse_unsigned(optarg, &parsed) || parsed == 0u ||
                parsed > 86400u) {
                (void)fprintf(stderr, "invalid request timeout\n");
                return false;
            }
            cli->request_timeout_seconds = parsed;
            break;
        case 1008:
            if (!fb_parse_unsigned(optarg, &parsed) || parsed == 0u ||
                parsed > 30u) {
                (void)fprintf(stderr, "invalid graceful shutdown timeout\n");
                return false;
            }
            cli->graceful_shutdown_seconds = parsed;
            break;
        default:
            return false;
        }
    }
    if (optind != argc) {
        (void)fprintf(stderr, "unexpected positional argument\n");
        return false;
    }
    return true;
}

static char *fb_slice_to_cstr(fb_slice value) {
    char *result;
    if (value.ptr == NULL || value.len == 0u || value.len == SIZE_MAX) {
        return NULL;
    }
    result = malloc(value.len + 1u);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, value.ptr, value.len);
    result[value.len] = '\0';
    return result;
}

static bool fb_prepare_signals(sigset_t *signals) {
    struct sigaction ignore_pipe;
    memset(&ignore_pipe, 0, sizeof(ignore_pipe));
    ignore_pipe.sa_handler = SIG_IGN;
    (void)sigemptyset(&ignore_pipe.sa_mask);
    if (sigaction(SIGPIPE, &ignore_pipe, NULL) != 0) {
        return false;
    }
    (void)sigemptyset(signals);
    (void)sigaddset(signals, SIGINT);
    (void)sigaddset(signals, SIGTERM);
    return pthread_sigmask(SIG_BLOCK, signals, NULL) == 0;
}

static int fb_wait_for_shutdown_signal(const sigset_t *signals) {
    int selected = 0;
    return sigwait(signals, &selected) == 0 ? selected : -1;
}

int main(int argc, char **argv) {
    fb_cli cli;
    fb_config *config = NULL;
    fb_config_error config_error;
    fb_config_status config_status;
    fb_app_options app_options;
    fb_app *app = NULL;
    fb_server_options server_options;
    fb_server *server = NULL;
    char *host = NULL;
    char error[512] = {0};
    sigset_t shutdown_signals;
    static fb_shutdown_watchdog shutdown_watchdog;
    int exit_code = EXIT_FAILURE;

    if (!fb_cli_parse(argc, argv, &cli)) {
        fb_usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }
    if (!fb_harden_process(error, sizeof(error))) {
        fb_hardening_failure(error);
    }
    if (!fb_prepare_signals(&shutdown_signals)) {
        (void)fprintf(stderr, "cannot initialize signal handling\n");
        return EXIT_FAILURE;
    }
    memset(&config_error, 0, sizeof(config_error));
    config_status = cli.config_path == NULL
                        ? fb_config_create_default(&config, &config_error)
                        : fb_config_load_file(cli.config_path, &config, &config_error);
    if (config_status != FB_CONFIG_OK) {
        (void)fprintf(stderr, "configuration error at %zu:%zu: %s\n",
                      config_error.line, config_error.column,
                      config_error.message == NULL
                          ? fb_config_status_string(config_status)
                          : config_error.message);
        goto finished;
    }
    host = fb_slice_to_cstr(fb_config_host(config));
    if (host == NULL) {
        (void)fprintf(stderr, "cannot allocate listen address\n");
        goto finished;
    }
#if defined(FASTBED_VERIFICATION_BUILD)
    app_options.asset_directory = cli.asset_directory;
    app_options.crawler_database = cli.crawler_database;
#else
    app_options.asset_directory = NULL;
    app_options.crawler_database = NULL;
#endif
    app_options.max_upstream_body_bytes = cli.max_body_bytes;
#if defined(FASTBED_VERIFICATION_BUILD)
    app_options.require_curl_impersonation = !cli.allow_stock_curl;
    app_options.replay_http_port = (uint16_t)cli.replay_http_port;
    app_options.replay_https_port = (uint16_t)cli.replay_https_port;
#else
    app_options.require_curl_impersonation = true;
    app_options.replay_http_port = 0u;
    app_options.replay_https_port = 0u;
#endif
    app_options.enable_internal_cache = cli.internal_cache;
    app = fb_app_create(config, &app_options, error, sizeof(error));
    if (app == NULL) {
        (void)fprintf(stderr, "startup error: %s\n", error);
        goto finished;
    }
    server_options = fb_server_default_options();
    server_options.host = host;
    server_options.port = (uint16_t)fb_config_port(config);
    server_options.worker_threads = cli.workers;
    server_options.request_timeout_seconds = cli.request_timeout_seconds;
    server_options.graceful_shutdown_seconds =
        cli.graceful_shutdown_seconds;
    server = fb_server_start(&server_options, fb_app_handle_http,
                             fb_app_http_should_defer, app,
                             error, sizeof(error));
    if (server == NULL) {
        (void)fprintf(stderr, "startup error: %s\n", error);
        goto finished;
    }
    (void)fprintf(stderr,
                  "[INFO] fastbed %s listening on %s:%u with %u application "
                  "workers and %u I/O threads; internal cache %s\n",
                  FASTBED_VERSION, host, (unsigned)fb_server_port(server),
                  cli.workers, server_options.io_threads,
                  cli.internal_cache ? "enabled" : "disabled");
    if (fb_wait_for_shutdown_signal(&shutdown_signals) < 0) {
        (void)fprintf(stderr, "signal wait failed\n");
        goto finished;
    }
    if (!fb_shutdown_watchdog_start(&shutdown_watchdog)) {
        /* A diagnostic write could itself block on the failed cleanup sink. */
        _Exit(FB_SHUTDOWN_WATCHDOG_EXIT_CODE);
    }
    (void)fprintf(stderr, "[INFO] shutting down\n");
    exit_code = EXIT_SUCCESS;

finished:
    fb_server_stop(server);
    fb_app_destroy(app);
    fb_config_destroy(config);
    free(host);
    return exit_code;
}

