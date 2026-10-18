#ifndef FASTBED_MODEL_H
#define FASTBED_MODEL_H

#include "fastbed/arena.h"

#define FB_MAX_TOP_REACTIONS 2u

typedef struct {
    fb_slice *items;
    size_t len;
    size_t capacity;
} fb_slice_vec;

/*
 * Slices stored in a post are borrowed. Helpers ending in _copy duplicate the
 * corresponding bytes into the supplied request arena. Vector backing arrays
 * allocated by these helpers are arena-owned.
 */
typedef struct {
    fb_slice author_name;
    fb_slice text;
    fb_slice url;
    int64_t date;

    fb_slice likes;
    fb_slice comments;
    fb_slice shares;

    fb_slice_vec image_links;
    fb_slice_vec video_links;
    fb_slice top_reaction_ids[FB_MAX_TOP_REACTIONS];
    size_t top_reaction_count;
} fb_post;

void fb_slice_vec_init(fb_slice_vec *vector);
FB_NODISCARD bool fb_slice_vec_reserve(
    fb_slice_vec *vector,
    fb_arena *arena,
    size_t capacity
);
FB_NODISCARD bool fb_slice_vec_push(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
);
FB_NODISCARD bool fb_slice_vec_push_unique(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
);
FB_NODISCARD bool fb_slice_vec_push_copy(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
);
FB_NODISCARD bool fb_slice_vec_push_unique_copy(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
);

void fb_post_init(fb_post *post);
FB_NODISCARD bool fb_post_add_image(
    fb_post *post,
    fb_arena *arena,
    fb_slice url
);
FB_NODISCARD bool fb_post_add_video(
    fb_post *post,
    fb_arena *arena,
    fb_slice url
);
FB_NODISCARD bool fb_post_add_image_copy(
    fb_post *post,
    fb_arena *arena,
    fb_slice url
);
FB_NODISCARD bool fb_post_add_video_copy(
    fb_post *post,
    fb_arena *arena,
    fb_slice url
);
FB_NODISCARD bool fb_post_set_top_reactions(
    fb_post *post,
    const fb_slice *reaction_ids,
    size_t count
);
FB_NODISCARD bool fb_post_clone(
    fb_post *destination,
    const fb_post *source,
    fb_arena *arena
);
FB_NODISCARD bool fb_post_is_valid(const fb_post *post);

#endif
