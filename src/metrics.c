#include "fastbed/metrics.h"

#include <stddef.h>

typedef struct {
    const fb_metrics *owner;
    unsigned index;
} fb_metrics_tls_slot;

static _Thread_local fb_metrics_tls_slot fb_metrics_tls;

static fb_metrics_shard *fb_metrics_local_shard(fb_metrics *metrics) {
    if (fb_metrics_tls.owner != metrics) {
        const unsigned ticket = atomic_fetch_add_explicit(
            &metrics->next_shard, 1u, memory_order_relaxed);
        fb_metrics_tls.owner = metrics;
        fb_metrics_tls.index = ticket % FB_METRICS_SHARDS;
    }
    return &metrics->shards[fb_metrics_tls.index];
}

static uint64_t fb_elapsed_seconds(const struct timespec *start,
                                   const struct timespec *now) {
    if (now->tv_sec < start->tv_sec) {
        return 0;
    }
    return (uint64_t)(now->tv_sec - start->tv_sec);
}

void fb_metrics_init(fb_metrics *metrics) {
    if (metrics == NULL) {
        return;
    }
    for (size_t index = 0u; index < FB_METRICS_SHARDS; ++index) {
        atomic_init(&metrics->shards[index].requests, 0);
        atomic_init(&metrics->shards[index].errors, 0);
    }
    atomic_init(&metrics->next_shard, 0u);
    if (clock_gettime(CLOCK_MONOTONIC, &metrics->started) != 0) {
        metrics->started.tv_sec = 0;
        metrics->started.tv_nsec = 0;
    }
}

void fb_metrics_record_request(fb_metrics *metrics) {
    if (metrics != NULL) {
        fb_metrics_shard *shard = fb_metrics_local_shard(metrics);
        (void)atomic_fetch_add_explicit(&shard->requests, 1,
                                        memory_order_relaxed);
    }
}

void fb_metrics_record_error(fb_metrics *metrics) {
    if (metrics != NULL) {
        fb_metrics_shard *shard = fb_metrics_local_shard(metrics);
        (void)atomic_fetch_add_explicit(&shard->errors, 1,
                                        memory_order_relaxed);
    }
}

fb_metrics_snapshot fb_metrics_read(const fb_metrics *metrics) {
    fb_metrics_snapshot result = {0, 0, 0};
    struct timespec now = {0, 0};
    if (metrics == NULL) {
        return result;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        result.uptime_seconds = fb_elapsed_seconds(&metrics->started, &now);
    }
    for (size_t index = 0u; index < FB_METRICS_SHARDS; ++index) {
        result.requests += atomic_load_explicit(
            &metrics->shards[index].requests, memory_order_relaxed);
        result.errors += atomic_load_explicit(
            &metrics->shards[index].errors, memory_order_relaxed);
    }
    return result;
}

