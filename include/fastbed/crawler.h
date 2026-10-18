#ifndef FASTBED_CRAWLER_H
#define FASTBED_CRAWLER_H

#include <stdbool.h>
#include <stddef.h>

typedef struct fb_crawler_db fb_crawler_db;

typedef struct {
    size_t pattern_count;
    size_t chunk_count;
    size_t jit_chunk_count;
    bool combined_jit;
} fb_crawler_stats;

#if defined(FASTBED_VERIFICATION_BUILD)
fb_crawler_db *fb_crawler_db_load(const char *json_path,
                                  char *error,
                                  size_t error_capacity);
#endif
fb_crawler_db *fb_crawler_db_load_embedded(char *error,
                                           size_t error_capacity);
void fb_crawler_db_free(fb_crawler_db *database);
bool fb_crawler_is_bot(const fb_crawler_db *database,
                       const char *user_agent,
                       size_t user_agent_length);
fb_crawler_stats fb_crawler_db_stats(const fb_crawler_db *database);

#endif

