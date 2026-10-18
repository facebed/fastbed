#include "fastbed/model.h"

#include <string.h>

static bool
fb_slice_vec_contains(const fb_slice_vec *vector, fb_slice value)
{
    if (vector == NULL || vector->len > vector->capacity ||
        (vector->capacity != 0u && vector->items == NULL)) {
        return false;
    }
    for (size_t index = 0u; index < vector->len; ++index) {
        if (fb_slice_equal(vector->items[index], value)) {
            return true;
        }
    }
    return false;
}

void
fb_slice_vec_init(fb_slice_vec *vector)
{
    if (vector != NULL) {
        memset(vector, 0, sizeof(*vector));
    }
}

bool
fb_slice_vec_reserve(
    fb_slice_vec *vector,
    fb_arena *arena,
    size_t capacity
)
{
    if (vector == NULL || arena == NULL || vector->len > vector->capacity ||
        (vector->capacity != 0u && vector->items == NULL)) {
        return false;
    }
    if (capacity <= vector->capacity) {
        return true;
    }

    size_t bytes;
    if (!fb_size_mul(capacity, sizeof(*vector->items), &bytes)) {
        return false;
    }
    fb_slice *items = fb_arena_alloc(arena, bytes, _Alignof(fb_slice));
    if (items == NULL) {
        return false;
    }
    if (vector->len != 0u) {
        memcpy(items, vector->items, vector->len * sizeof(*items));
    }
    vector->items = items;
    vector->capacity = capacity;
    return true;
}

bool
fb_slice_vec_push(fb_slice_vec *vector, fb_arena *arena, fb_slice value)
{
    if (vector == NULL || arena == NULL || !fb_slice_is_valid(value) ||
        vector->len > vector->capacity ||
        (vector->capacity != 0u && vector->items == NULL)) {
        return false;
    }
    if (vector->len == vector->capacity) {
        size_t capacity = vector->capacity != 0u ? vector->capacity : 4u;
        if (vector->capacity != 0u) {
            if (capacity > SIZE_MAX / 2u) {
                return false;
            }
            capacity *= 2u;
        }
        if (!fb_slice_vec_reserve(vector, arena, capacity)) {
            return false;
        }
    }
    vector->items[vector->len++] = value;
    return true;
}

bool
fb_slice_vec_push_unique(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
)
{
    return fb_slice_vec_contains(vector, value) ||
           fb_slice_vec_push(vector, arena, value);
}

bool
fb_slice_vec_push_copy(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
)
{
    if (!fb_slice_is_valid(value)) {
        return false;
    }
    fb_slice copy = fb_arena_slice_dup(arena, value);
    if (copy.ptr == NULL) {
        return false;
    }
    return fb_slice_vec_push(vector, arena, copy);
}

bool
fb_slice_vec_push_unique_copy(
    fb_slice_vec *vector,
    fb_arena *arena,
    fb_slice value
)
{
    return fb_slice_vec_contains(vector, value) ||
           fb_slice_vec_push_copy(vector, arena, value);
}

void
fb_post_init(fb_post *post)
{
    if (post == NULL) {
        return;
    }
    memset(post, 0, sizeof(*post));
    post->author_name = FB_SLICE_LIT("");
    post->text = FB_SLICE_LIT("");
    post->url = FB_SLICE_LIT("");
    post->date = -1;
    post->likes = FB_SLICE_LIT("null");
    post->comments = FB_SLICE_LIT("null");
    post->shares = FB_SLICE_LIT("null");
}

bool
fb_post_add_image(fb_post *post, fb_arena *arena, fb_slice url)
{
    return post != NULL &&
           fb_slice_vec_push(&post->image_links, arena, url);
}

bool
fb_post_add_video(fb_post *post, fb_arena *arena, fb_slice url)
{
    return post != NULL &&
           fb_slice_vec_push(&post->video_links, arena, url);
}

bool
fb_post_add_image_copy(fb_post *post, fb_arena *arena, fb_slice url)
{
    return post != NULL &&
           fb_slice_vec_push_copy(&post->image_links, arena, url);
}

bool
fb_post_add_video_copy(fb_post *post, fb_arena *arena, fb_slice url)
{
    return post != NULL &&
           fb_slice_vec_push_copy(&post->video_links, arena, url);
}

bool
fb_post_set_top_reactions(
    fb_post *post,
    const fb_slice *reaction_ids,
    size_t count
)
{
    if (post == NULL || count > FB_MAX_TOP_REACTIONS ||
        (count != 0u && reaction_ids == NULL)) {
        return false;
    }
    for (size_t index = 0u; index < count; ++index) {
        if (!fb_slice_is_valid(reaction_ids[index])) {
            return false;
        }
    }
    for (size_t index = 0u; index < count; ++index) {
        post->top_reaction_ids[index] = reaction_ids[index];
    }
    for (size_t index = count; index < FB_MAX_TOP_REACTIONS; ++index) {
        post->top_reaction_ids[index] = FB_SLICE_LIT("");
    }
    post->top_reaction_count = count;
    return true;
}

static bool
fb_clone_slice(fb_arena *arena, fb_slice source, fb_slice *destination)
{
    if (destination == NULL || !fb_slice_is_valid(source)) {
        return false;
    }
    *destination = fb_arena_slice_dup(arena, source);
    return destination->ptr != NULL;
}

bool
fb_post_clone(fb_post *destination, const fb_post *source, fb_arena *arena)
{
    if (destination == NULL || source == NULL || destination == source ||
        arena == NULL ||
        !fb_post_is_valid(source)) {
        return false;
    }
    fb_post_init(destination);
    destination->date = source->date;

    if (!fb_clone_slice(arena, source->author_name,
                        &destination->author_name) ||
        !fb_clone_slice(arena, source->text, &destination->text) ||
        !fb_clone_slice(arena, source->url, &destination->url) ||
        !fb_clone_slice(arena, source->likes, &destination->likes) ||
        !fb_clone_slice(arena, source->comments, &destination->comments) ||
        !fb_clone_slice(arena, source->shares, &destination->shares) ||
        !fb_slice_vec_reserve(&destination->image_links, arena,
                              source->image_links.len) ||
        !fb_slice_vec_reserve(&destination->video_links, arena,
                              source->video_links.len)) {
        return false;
    }

    for (size_t index = 0u; index < source->image_links.len; ++index) {
        if (!fb_slice_vec_push_copy(&destination->image_links, arena,
                                    source->image_links.items[index])) {
            return false;
        }
    }
    for (size_t index = 0u; index < source->video_links.len; ++index) {
        if (!fb_slice_vec_push_copy(&destination->video_links, arena,
                                    source->video_links.items[index])) {
            return false;
        }
    }
    for (size_t index = 0u; index < source->top_reaction_count; ++index) {
        if (!fb_clone_slice(arena, source->top_reaction_ids[index],
                            &destination->top_reaction_ids[index])) {
            return false;
        }
    }
    destination->top_reaction_count = source->top_reaction_count;
    return true;
}

static bool
fb_slice_vec_is_valid(const fb_slice_vec *vector)
{
    if (vector == NULL || vector->len > vector->capacity ||
        (vector->capacity != 0u && vector->items == NULL)) {
        return false;
    }
    for (size_t index = 0u; index < vector->len; ++index) {
        if (!fb_slice_is_valid(vector->items[index])) {
            return false;
        }
    }
    return true;
}

bool
fb_post_is_valid(const fb_post *post)
{
    if (post == NULL || !fb_slice_is_valid(post->author_name) ||
        !fb_slice_is_valid(post->text) || !fb_slice_is_valid(post->url) ||
        !fb_slice_is_valid(post->likes) ||
        !fb_slice_is_valid(post->comments) ||
        !fb_slice_is_valid(post->shares) ||
        post->top_reaction_count > FB_MAX_TOP_REACTIONS ||
        !fb_slice_vec_is_valid(&post->image_links) ||
        !fb_slice_vec_is_valid(&post->video_links)) {
        return false;
    }
    for (size_t index = 0u; index < post->top_reaction_count; ++index) {
        if (!fb_slice_is_valid(post->top_reaction_ids[index])) {
            return false;
        }
    }
    return true;
}
