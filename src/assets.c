#include "fastbed/assets.h"

#include "fastbed/embedded_resources.h"
#include "fastbed/render.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(FASTBED_VERIFICATION_BUILD)
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(FASTBED_VERIFICATION_BUILD)
enum {
    FB_MAX_ASSET_BYTES = 32 * 1024 * 1024,
};
#endif

static void fb_asset_error(char *destination, size_t capacity,
                           const char *format, ...)
    FB_PRINTF_FORMAT(3, 4);
static void fb_asset_error(char *destination, size_t capacity,
                           const char *format, ...) {
    va_list arguments;
    if (destination == NULL || capacity == 0u) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    destination[capacity - 1u] = '\0';
}

#if defined(FASTBED_VERIFICATION_BUILD)
static bool fb_map_asset(int directory_fd,
                         const char *name,
                         void **mapping,
                         size_t *length,
                         int *retained_descriptor,
                         char *error,
                         size_t error_capacity) {
    int descriptor;
    struct stat metadata;
    void *address;
    descriptor = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        fb_asset_error(error, error_capacity, "cannot open asset %s: %s",
                       name, strerror(errno));
        return false;
    }
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size < 0 ||
        (uintmax_t)metadata.st_size > (uintmax_t)FB_MAX_ASSET_BYTES) {
        fb_asset_error(error, error_capacity, "asset %s is not a bounded regular file",
                       name);
        (void)close(descriptor);
        return false;
    }
    if (metadata.st_size == 0) {
        *mapping = NULL;
        *length = 0u;
        if (retained_descriptor == NULL) {
            (void)close(descriptor);
        } else {
            *retained_descriptor = descriptor;
        }
        return true;
    }
    address = mmap(NULL, (size_t)metadata.st_size, PROT_READ, MAP_PRIVATE,
                   descriptor, 0);
    if (address == MAP_FAILED) {
        const int mapping_error = errno;
        (void)close(descriptor);
        fb_asset_error(error, error_capacity, "cannot map asset %s: %s",
                       name, strerror(mapping_error));
        return false;
    }
    if (retained_descriptor == NULL) {
        (void)close(descriptor);
    } else {
        *retained_descriptor = descriptor;
    }
    *mapping = address;
    *length = (size_t)metadata.st_size;
    return true;
}
#endif

static const char *fb_find_bytes(const char *haystack,
                                 size_t haystack_length,
                                 const char *needle,
                                 size_t needle_length) {
    size_t index;
    if (needle_length == 0u || needle_length > haystack_length) {
        return NULL;
    }
    for (index = 0; index <= haystack_length - needle_length; ++index) {
        if (memcmp(haystack + index, needle, needle_length) == 0) {
            return haystack + index;
        }
    }
    return NULL;
}

static bool fb_render_index(fb_assets *assets,
                            char *error,
                            size_t error_capacity) {
    static const char marker[] = "{|CREDIT|}";
    static const char credit[] = FB_CREDIT;
    const char *source = assets->index_mapping;
    const char *position;
    size_t prefix;
    size_t suffix;
    size_t output_size;
    position = fb_find_bytes(source, assets->index_mapping_length,
                             marker, sizeof(marker) - 1u);
    if (position == NULL) {
        fb_asset_error(error, error_capacity,
                       "index asset has no credit placeholder");
        return false;
    }
    if (fb_find_bytes(position + sizeof(marker) - 1u,
                      assets->index_mapping_length -
                          (size_t)(position - source) - (sizeof(marker) - 1u),
                      marker, sizeof(marker) - 1u) != NULL) {
        fb_asset_error(error, error_capacity,
                       "index asset has multiple credit placeholders");
        return false;
    }
    prefix = (size_t)(position - source);
    suffix = assets->index_mapping_length - prefix - (sizeof(marker) - 1u);
    if (!fb_size_add(prefix, sizeof(credit) - 1u, &output_size) ||
        !fb_size_add(output_size, suffix, &output_size) ||
        output_size == SIZE_MAX) {
        fb_asset_error(error, error_capacity, "index asset size overflow");
        return false;
    }
    assets->index_rendered = malloc(output_size + 1u);
    if (assets->index_rendered == NULL) {
        fb_asset_error(error, error_capacity, "cannot allocate rendered index");
        return false;
    }
    memcpy(assets->index_rendered, source, prefix);
    memcpy(assets->index_rendered + prefix, credit, sizeof(credit) - 1u);
    memcpy(assets->index_rendered + prefix + sizeof(credit) - 1u,
           position + sizeof(marker) - 1u, suffix);
    assets->index_rendered[output_size] = '\0';
    assets->index_rendered_length = output_size;
    return true;
}

bool fb_assets_load(fb_assets *assets,
                    const char *directory,
                    char *error,
                    size_t error_capacity) {
#if defined(FASTBED_VERIFICATION_BUILD)
    int directory_fd;
#endif
    if (assets == NULL) {
        fb_asset_error(error, error_capacity, "asset state is missing");
        return false;
    }
    memset(assets, 0, sizeof(*assets));
    assets->favicon_fd = -1;
    assets->banner_fd = -1;
    assets->retained_fds_initialized = true;
#if !defined(FASTBED_VERIFICATION_BUILD)
    (void)directory;
    directory = NULL;
#endif
    if (directory == NULL) {
        assets->index_mapping = (void *)fb_embedded_index_html;
        assets->index_mapping_length = fb_embedded_index_html_length;
        assets->favicon_mapping = (void *)fb_embedded_favicon_ico;
        assets->favicon_length = fb_embedded_favicon_ico_length;
        assets->banner_mapping = (void *)fb_embedded_banner_png;
        assets->banner_length = fb_embedded_banner_png_length;
        assets->embedded = true;
        if (!fb_render_index(assets, error, error_capacity)) {
            fb_assets_destroy(assets);
            return false;
        }
        return true;
    }
#if defined(FASTBED_VERIFICATION_BUILD)
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0) {
        fb_asset_error(error, error_capacity, "cannot open asset directory %s: %s",
                       directory, strerror(errno));
        return false;
    }
    if (!fb_map_asset(directory_fd, "index.html", &assets->index_mapping,
                      &assets->index_mapping_length, NULL,
                      error, error_capacity) ||
        !fb_map_asset(directory_fd, "favicon.ico", &assets->favicon_mapping,
                      &assets->favicon_length, &assets->favicon_fd,
                      error, error_capacity) ||
        !fb_map_asset(directory_fd, "banner.png", &assets->banner_mapping,
                      &assets->banner_length, &assets->banner_fd,
                      error, error_capacity) ||
        !fb_render_index(assets, error, error_capacity)) {
        (void)close(directory_fd);
        fb_assets_destroy(assets);
        return false;
    }
    (void)close(directory_fd);
    return true;
#else
    return false;
#endif
}

void fb_assets_destroy(fb_assets *assets) {
    if (assets == NULL) {
        return;
    }
#if defined(FASTBED_VERIFICATION_BUILD)
    if (!assets->embedded && assets->index_mapping != NULL) {
        (void)munmap(assets->index_mapping, assets->index_mapping_length);
    }
    if (!assets->embedded && assets->favicon_mapping != NULL) {
        (void)munmap(assets->favicon_mapping, assets->favicon_length);
    }
    if (!assets->embedded && assets->banner_mapping != NULL) {
        (void)munmap(assets->banner_mapping, assets->banner_length);
    }
    if (assets->retained_fds_initialized && assets->favicon_fd >= 0) {
        (void)close(assets->favicon_fd);
    }
    if (assets->retained_fds_initialized && assets->banner_fd >= 0) {
        (void)close(assets->banner_fd);
    }
#endif
    free(assets->index_rendered);
    memset(assets, 0, sizeof(*assets));
}

fb_slice fb_assets_index(const fb_assets *assets) {
    return assets == NULL
               ? fb_slice_make(NULL, 0u)
               : fb_slice_make(assets->index_rendered,
                               assets->index_rendered_length);
}

fb_slice fb_assets_favicon(const fb_assets *assets) {
    return assets == NULL
               ? fb_slice_make(NULL, 0u)
               : fb_slice_make(assets->favicon_mapping, assets->favicon_length);
}

fb_slice fb_assets_banner(const fb_assets *assets) {
    return assets == NULL
               ? fb_slice_make(NULL, 0u)
               : fb_slice_make(assets->banner_mapping, assets->banner_length);
}

int fb_assets_favicon_fd(const fb_assets *assets) {
    return assets == NULL || !assets->retained_fds_initialized
               ? -1
               : assets->favicon_fd;
}

int fb_assets_banner_fd(const fb_assets *assets) {
    return assets == NULL || !assets->retained_fds_initialized
               ? -1
               : assets->banner_fd;
}

