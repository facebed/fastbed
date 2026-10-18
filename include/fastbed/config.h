#ifndef FASTBED_CONFIG_H
#define FASTBED_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fastbed/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fb_config fb_config;

typedef enum {
    FB_CONFIG_OK = 0,
    FB_CONFIG_INVALID_ARGUMENT,
    FB_CONFIG_FILE_ERROR,
    FB_CONFIG_YAML_ERROR,
    FB_CONFIG_SCHEMA_ERROR,
    FB_CONFIG_NO_MEMORY
} fb_config_status;

/* Messages are static and never contain configuration values or secrets. */
typedef struct {
    fb_config_status status;
    size_t line;
    size_t column;
    const char *message;
} fb_config_error;

fb_config_status fb_config_create_default(
    fb_config **out,
    fb_config_error *error
);
fb_config_status fb_config_load_file(
    const char *path,
    fb_config **out,
    fb_config_error *error
);
void fb_config_destroy(fb_config *config);

fb_slice fb_config_host(const fb_config *config);
int fb_config_port(const fb_config *config);
int fb_config_timezone(const fb_config *config);
size_t fb_config_banned_user_count(const fb_config *config);
fb_slice fb_config_banned_user_at(const fb_config *config, size_t index);
bool fb_config_is_banned_user(const fb_config *config, fb_slice user_id);

/* Explicit secret accessor.  Do not include this value in logs or artifacts. */
fb_slice fb_config_notifier_webhook(const fb_config *config);

const char *fb_config_status_string(fb_config_status status);

#ifdef __cplusplus
}
#endif

#endif
