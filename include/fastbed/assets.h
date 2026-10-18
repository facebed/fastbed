#ifndef FASTBED_ASSETS_H
#define FASTBED_ASSETS_H

#include "fastbed/common.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    void *index_mapping;
    size_t index_mapping_length;
    char *index_rendered;
    size_t index_rendered_length;
    void *favicon_mapping;
    size_t favicon_length;
    int favicon_fd;
    void *banner_mapping;
    size_t banner_length;
    int banner_fd;
    bool retained_fds_initialized;
    bool embedded;
} fb_assets;

bool fb_assets_load(fb_assets *assets,
                    const char *directory,
                    char *error,
                    size_t error_capacity);
void fb_assets_destroy(fb_assets *assets);

fb_slice fb_assets_index(const fb_assets *assets);
fb_slice fb_assets_favicon(const fb_assets *assets);
fb_slice fb_assets_banner(const fb_assets *assets);

/* Borrowed descriptors remain owned by fb_assets and must not be closed. */
int fb_assets_favicon_fd(const fb_assets *assets);
int fb_assets_banner_fd(const fb_assets *assets);

#endif

