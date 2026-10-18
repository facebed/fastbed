#ifndef FASTBED_METRICS_H
#define FASTBED_METRICS_H

#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

#ifndef FB_CACHELINE_SIZE
#define FB_CACHELINE_SIZE 64u
#endif

#define FB_METRICS_SHARDS 64u

typedef struct {
    _Alignas(FB_CACHELINE_SIZE) atomic_uint_fast64_t requests;
    atomic_uint_fast64_t errors;
} fb_metrics_shard;

typedef struct {
    _Alignas(FB_CACHELINE_SIZE) fb_metrics_shard shards[FB_METRICS_SHARDS];
    _Alignas(FB_CACHELINE_SIZE) atomic_uint next_shard;
    _Alignas(FB_CACHELINE_SIZE) struct timespec started;
} fb_metrics;

typedef struct {
    uint64_t uptime_seconds;
    uint64_t requests;
    uint64_t errors;
} fb_metrics_snapshot;

void fb_metrics_init(fb_metrics *metrics);
void fb_metrics_record_request(fb_metrics *metrics);
void fb_metrics_record_error(fb_metrics *metrics);
fb_metrics_snapshot fb_metrics_read(const fb_metrics *metrics);

#endif

