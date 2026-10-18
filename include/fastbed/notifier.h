#ifndef FASTBED_NOTIFIER_H
#define FASTBED_NOTIFIER_H

#include "fastbed/common.h"
#include "fastbed/config.h"
#include "fastbed/transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fb_notifier fb_notifier;

typedef struct {
    unsigned worker_threads;
    size_t max_pending_jobs;
    /* Owned job bytes plus reserved worst-case gzip workspace. */
    size_t max_pending_bytes;
    unsigned max_rate_limit_retries;
    uint64_t max_rate_limit_delay_ms;
    /* Grace period for accepted work before shutdown cancels delivery. */
    uint64_t shutdown_grace_ms;
} fb_notifier_options;

typedef enum {
    FB_NOTIFIER_ENQUEUE_QUEUED = 0,
    FB_NOTIFIER_ENQUEUE_DISABLED,
    FB_NOTIFIER_ENQUEUE_BACKPRESSURE,
    FB_NOTIFIER_ENQUEUE_CLOSED,
    FB_NOTIFIER_ENQUEUE_NO_MEMORY,
    FB_NOTIFIER_ENQUEUE_INVALID_ARGUMENT
} fb_notifier_enqueue_result;

typedef struct {
    bool enabled;
    bool accepting;
    size_t queued_jobs;
    size_t active_jobs;
    size_t pending_jobs;
    /* Current charge against max_pending_bytes, including active jobs. */
    size_t pending_bytes;
    uint64_t enqueued;
    uint64_t delivered;
    uint64_t delivery_failed;
    uint64_t rate_limited;
    uint64_t rate_limit_retries;
    uint64_t rejected_backpressure;
    uint64_t rejected_no_memory;
    uint64_t rejected_closed;
    uint64_t disabled_noops;
} fb_notifier_stats;

fb_notifier_options fb_notifier_default_options(void);

/*
 * The webhook secret is copied into notifier-owned storage. Empty or invalid
 * Facebed webhook configuration creates a disabled notifier: enqueue calls
 * then return FB_NOTIFIER_ENQUEUE_DISABLED without inspecting request data.
 */
FB_NODISCARD bool fb_notifier_init(
    fb_notifier **out,
    const fb_config *config,
    const fb_notifier_options *options,
    char *error,
    size_t error_capacity
);

/* `response` is the selected body-bearing GET and is copied before return. */
FB_NODISCARD fb_notifier_enqueue_result fb_notifier_enqueue_dump(
    fb_notifier *notifier,
    fb_slice origin_path,
    const fb_upstream_response *response
);

/* `response` may be NULL when no body-bearing upstream response was captured. */
FB_NODISCARD fb_notifier_enqueue_result fb_notifier_enqueue_restricted(
    fb_notifier *notifier,
    fb_slice origin_path,
    fb_slice reason,
    fb_slice detail,
    const fb_upstream_response *response
);

fb_notifier_stats fb_notifier_get_stats(fb_notifier *notifier);

/*
 * Stop admission and drain accepted work for at most `shutdown_grace_ms`.
 * At the deadline, active transfers/retry waits are cancelled and remaining
 * queued jobs are released as failed before workers are joined.
 */
void fb_notifier_shutdown(fb_notifier *notifier);

const char *fb_notifier_enqueue_result_string(
    fb_notifier_enqueue_result result
);

#ifdef __cplusplus
}
#endif

#endif
